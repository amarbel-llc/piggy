#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the `piggy tool` key-surface ops of piggy#289
# Phase 3.4: `write-cert` (milestone 3.4a) and `generate` (3.4b). These
# mutate slot material, so each test gets its OWN fresh fibby card (setup ->
# fibby_up, teardown -> fibby_down; factory 3DES admin key, seeded 9D cert,
# and a pinned scalar for GENERATE on slot 9A so keygen is deterministic).
# The contract is checked against C pivy-tool:
#   - write-cert: piggy writes the cert object C writes for the same cert
#     (read from fibby's wire log), so each reads back what the other wrote,
#     and piggy reads back exactly the written cert; a wrong current admin
#     key fails;
#   - generate: with the 9A scalar pinned, both impls' GENERATE returns the
#     same key, so `generate 9a -a eccp256` prints the identical pubkey line
#     (the self-signed cert side effect has a random serial and legitimately
#     differs, so only the printed pubkey is compared).
#   - generate -i/-t (piggy#303): with a PIN and touch policy, both impls send
#     the same GENERATE ASYMMETRIC header and data field (the AA/AB policy
#     tags), read from fibby's wire log;
#   - import: both install the same slot key.
# Both are ported for the 9A/9C/9D/9E cert slots; generate models the EC
# algorithms (eccp256/eccp384) only.
#
# C's answers and wire bytes are frozen fixtures (piggy#285,
# lib/pivy_oracle.bash); `just codemod-capture-pivy-oracle-tool-keys-fibby`
# re-records them, giving piggy a fresh card again after each C call.
#
# Required env (set by test-bats-conformance-tool-keys-fibby):
#   FIBBY_BIN, PIGGY; to capture, PIGGY_ORACLE_MODE=capture with
#   REAL_PIVY_TOOL and PIVY_ORACLE_CAPTURE_DIR.

# RFC 6979 §A.2.5 P-256 private scalar — a known test key with a known pubkey.
GEN_9A_SCALAR=c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721

# Expected public key (ecdsa-sha2-nistp256 type + base64, no comment) of the
# throwaway P-256 test key embedded in import_installs_same_key_as_c.
IMPORT_PUB="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC6+EqXFg1uIJbWoqn6xLnMzWvCZapGuw72uZB5Y/lRkDOXkqwomEj+zFr/bRhjDLhlh8eJv2XYHIeOI81eoNOA="

FIBBY_SEEDS=(--seed-rfc5903-slot-9d-cert --seed-chuid
  --generate-slot-9a-priv "$GEN_9A_SCALAR")

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  load "$PIGGY_BATS_DIR/lib/pivy_oracle.bash"
  export output
  PIVY_ORACLE_LANE=tool-keys-fibby
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  fibby_up "${FIBBY_SEEDS[@]}"
}

teardown() {
  fibby_down
}

pivy_oracle_reset_card() {
  fibby_down
  fibby_up "${FIBBY_SEEDS[@]}"
}

# A 24-byte 3DES admin key that is NOT the factory key (differs in non-parity
# key bits — see piggy_tool_admin_fibby.bats for the DES parity subtlety).
WRONG_KEY=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7

# The seeded 9D cert as C reads it, into FILE.
_c_cert_9d_into() {
  pivy_oracle cert_9d cert 9d >"$1" || fail "C could not read the seeded 9D cert"
  [[ -s $1 ]] || fail "no seeded 9D cert to start"
}

# The data field of every PUT DATA the card was sent, one per line,
# reassembled across command chaining (CLA 10 continues, CLA 00 ends) so a
# chained short write and an extended one compare equal.
_put_data_fields() {
  local apdu data=""
  while IFS= read -r apdu; do
    [[ -n $apdu ]] || continue
    data+="$(_apdu_header_and_data "$apdu" | cut -d' ' -f2)"
    if [[ ${apdu:0:2} != 10 ]]; then
      printf '%s\n' "$data"
      data=""
    fi
  done < <(_command_apdus_with_ins db)
}

# The last 9D cert object (tag 5FC10B) written to the card.
_sent_9d_cert_object() { _put_data_fields | grep '^5c035fc10b' | tail -1; }

# piggy and C write byte-identical 9D cert objects for the same cert, so
# each reads back what the other wrote; piggy's read of its own write
# closes the loop.
function write_cert_writes_what_c_writes_and_reads_it_back { # @test
  local certfile="$BATS_TEST_TMPDIR/orig9d.pem" c_wire
  _c_cert_9d_into "$certfile"
  pivy_oracle write_cert_9d write-cert 9d <"$certfile" >"$BATS_TEST_TMPDIR/c.out" ||
    fail "C write-cert 9d failed"
  c_wire="$(pivy_oracle_note write_cert_9d.wire _sent_9d_cert_object)" ||
    fail "no recorded C cert object"
  pivy_oracle_fresh_card
  run "$PIGGY" tool delete-cert 9d
  assert_success
  run "$PIGGY" tool cert 9d
  assert_failure
  # piggy writes the cert back (mgmt auth with the factory key, then PUT DATA).
  run "$PIGGY" tool write-cert 9d <"$certfile"
  assert_success
  assert_output "$(<"$BATS_TEST_TMPDIR/c.out")"
  assert_equal "$(_sent_9d_cert_object)" "$c_wire"
  run "$PIGGY" tool cert 9d
  assert_success
  assert_output "$(<"$certfile")"
}

function write_cert_wrong_admin_key_fails { # @test
  # A wrong current admin key fails the mgmt auth, so the slot is untouched.
  local certfile="$BATS_TEST_TMPDIR/orig9d.pem"
  _c_cert_9d_into "$certfile"
  run bash -c "'$PIGGY' tool -K '$WRONG_KEY' write-cert 9d < '$certfile'"
  assert_failure
  # The original 9D cert is still readable — the failed write did not replace it.
  run "$PIGGY" tool cert 9d
  assert_success
}

function generate_9a_matches_c { # @test
  # The 9A generated scalar is pinned (--generate-slot-9a-priv in setup), so
  # both impls' GENERATE returns the same pubkey. Compare the printed
  # public-key line (stderr stripped; the self-signed cert side effect
  # legitimately differs by random serial and is not compared).
  local c_out
  c_out="$(pivy_oracle generate_9a -P 123456 -a eccp256 generate 9a 2>/dev/null)" ||
    fail "C generate 9a failed"
  pivy_oracle_fresh_card
  run bash -c "'$PIGGY' tool -P 123456 -a eccp256 generate 9a 2>/dev/null"
  assert_success
  [[ "$output" == "$c_out" ]] || fail "generate pubkey differs: C=[$c_out] piggy=[$output]"
  # Sanity: a P-256 pubkey line with the bare slot/GUID comment (no subject).
  [[ "$output" == "ecdsa-sha2-nistp256 "*" PIV_slot_9A@"* ]] \
    || fail "unexpected generate output: $output"
}

# Every command APDU with instruction byte INS (two lowercase hex digits) in
# fibby's wire log, one per line as contiguous hex. The log hex-dumps each
# command as `[fibby:apdu>] OFFSET  b0 b1 ... |ascii|`, 16 bytes a line, so
# an APDU is the `0000` line plus the `apdu>` lines that follow it.
_command_apdus_with_ins() {
  awk -v ins="$1" '
    $1 == "[fibby:apdu>]" {
      if ($2 == "0000") {
        if (grab) print ""
        grab = ($4 == ins)
      }
      if (grab) for (i = 3; i <= NF && $i !~ /^\|/; i++) printf "%s", $i
      next
    }
    grab { print ""; grab = 0 }
    END { if (grab) print "" }
  ' "$FIBBY_LOG"
}

# Diagnostic only: a command APDU (contiguous hex) reduced to `CLA INS P1 P2`
# and its data field, whichever length encoding it used (short `Lc`, or
# extended `00 LcHi LcLo`). Lets a failure message say whether two APDUs
# that differ byte for byte still carry the same command.
_apdu_header_and_data() {
  local apdu="$1" header body lc
  header="${apdu:0:8}"
  body="${apdu:8}"
  if [[ ${body:0:2} == 00 && ${#body} -gt 6 ]]; then
    lc=$((16#${body:2:4}))
    printf '%s %s' "$header" "${body:6:lc*2}"
  else
    lc=$((16#${body:0:2}))
    printf '%s %s' "$header" "${body:2:lc*2}"
  fi
}

# A fresh card for one side of generate_9c_with_policy_matches_c: both sides
# get the same seeds and the same pinned 9C scalar. --auto-touch because the
# self-signed cert is signed by the new touch-always key.
_fresh_card_for_9c_generate() {
  fibby_down
  fibby_up --auto-touch --seed-rfc5903-slot-9d-cert --seed-chuid \
    --generate-slot-9c-priv "$GEN_9A_SCALAR"
}

function generate_9c_with_policy_matches_c { # @test
  # piggy#303: `-i <pin-policy>` / `-t <touch-policy>` are pivy-tool's own
  # options (vendor/pivy/src/pivy-tool.c: `case 'i'` / `case 't'`), and they
  # reach the card as the YubicoPIV AA/AB tags of GENERATE ASYMMETRIC. Each
  # tool generates 9C with PIN always + touch always on its own fresh card;
  # the printed key and the GENERATE command APDU must be identical.
  #
  # C's default 9C cert template (user-email) needs an `email` cert variable,
  # hence its -D; that only shapes the self-signed cert, which is not compared.
  _fresh_card_for_9c_generate
  local c_out c_apdu
  c_out="$(pivy_oracle generate_9c -P 123456 -a eccp256 -i always -t always \
    -D email=piggy-test@example.invalid generate 9c 2>"$BATS_TEST_TMPDIR/c.err")" ||
    fail "C generate 9c failed: $(cat "$BATS_TEST_TMPDIR/c.err"; tail -40 "$FIBBY_LOG")"
  c_apdu="$(pivy_oracle_note generate_9c.wire _command_apdus_with_ins 47)" ||
    fail "no recorded C GENERATE"

  _fresh_card_for_9c_generate
  run bash -c "'$PIGGY' tool -P 123456 -a eccp256 -i always -t always generate 9c \
    2>'$BATS_TEST_TMPDIR/piggy.err'"
  local p_status="$status" p_out="$output" p_apdu
  p_apdu="$(_command_apdus_with_ins 47)"

  # Exactly one GENERATE each, for slot 9C, carrying AA 01 03 (PIN always)
  # and AB 01 02 (touch always).
  [[ -n $c_apdu && $c_apdu != *$'\n'* ]] || fail "C sent not exactly one GENERATE: [$c_apdu]"
  [[ $c_apdu == 0047009c* && $c_apdu == *aa0103* && $c_apdu == *ab0102* ]] \
    || fail "C's GENERATE does not carry the 9C policy tags: $c_apdu"

  # Every check below runs, so one failure does not hide another.
  local problems=()
  # Compared as header + data field. The framing legitimately differs: C sends
  # every command extended-length with an Le to a card that advertises it,
  # piggy sends a short APDU; what the card is asked to do is the same bytes.
  [[ "$(_apdu_header_and_data "$p_apdu")" == "$(_apdu_header_and_data "$c_apdu")" ]] || problems+=(
    "GENERATE differs: C=[$c_apdu] piggy=[$p_apdu] (header+data field: C=[$(_apdu_header_and_data "$c_apdu")] piggy=[$(_apdu_header_and_data "$p_apdu")])"
  )
  # The card stored what piggy's APDU asked for.
  [[ $(grep -c 'GENERATE slot=0x9c ECCP256 -> 9000 (.*policy pin=03 touch=02)' "$FIBBY_LOG") -eq 1 ]] ||
    problems+=("piggy's card did not record one 9C GENERATE with pin=03 touch=02")
  [[ $p_status -eq 0 ]] ||
    problems+=("piggy tool generate 9c exited $p_status: $(cat "$BATS_TEST_TMPDIR/piggy.err")")
  [[ "$p_out" == "$c_out" ]] ||
    problems+=("generate pubkey differs: C=[$c_out] piggy=[$p_out]")
  [[ "$p_out" == "ecdsa-sha2-nistp256 "*" PIV_slot_9C@"* ]] ||
    problems+=("unexpected generate output: $p_out")
  [[ ${#problems[@]} -eq 0 ]] || fail "$(printf '%s\n' "${problems[@]}")"
}

function import_installs_same_key_as_c { # @test
  # A throwaway (non-secret) OpenSSH P-256 test key. Both impls import it and
  # self-sign; the resulting slot public key must match each other and the
  # key's known public half.
  local keyfile="$BATS_TEST_TMPDIR/import_key"
  cat >"$keyfile" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQuvhKlxYNbiCW1qKp+sS5zM1rwmWqR
rsO9rmQeWP5UZAzl5KsKJhI/sxa/20YYwy4ZYfHib9l2ByHjiPNXqDTgAAAAsC4Q+wUuEP
sFAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC6+EqXFg1uIJbWo
qn6xLnMzWvCZapGuw72uZB5Y/lRkDOXkqwomEj+zFr/bRhjDLhlh8eJv2XYHIeOI81eoNO
AAAAAhANElI+A+9hPHp5bGZiB3v/rs7w8+8AgFzGJYWlE1mxLTAAAAEXBpZ2d5LXRlc3Qt
aW1wb3J0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
EOF
  chmod 600 "$keyfile"
  # Import into 9A: C's slot-9C/9E cert templates require an `email` cert var
  # that pivy-tool's import path leaves unset, so 9A (PIV Auth, no such
  # requirement — see the generate lane) is the differentiable slot. Its
  # generate-override seed is unused by IMPORT (which installs the key
  # directly). Capture the resulting slot public key (key blob only — the
  # self-signed cert subject naturally differs per impl).
  pivy_oracle import_9a -P 123456 import 9a <"$keyfile" >/dev/null ||
    fail "C import 9a failed"
  local c_key
  c_key=$(pivy_oracle import_9a_pubkey pubkey 9a | awk '{print $1, $2}')
  pivy_oracle_fresh_card
  # piggy imports the SAME key into 9A of a fresh card; the slot key must
  # match (piggy's `pubkey` is held to C's by the tool-fibby lane).
  run "$PIGGY" tool -P 123456 import 9a <"$keyfile"
  assert_success
  assert_output ""
  local p_key
  p_key=$("$PIGGY" tool pubkey 9a | awk '{print $1, $2}')
  [[ -n $c_key && "$c_key" == "$p_key" ]] \
    || fail "import key mismatch: C=[$c_key] piggy=[$p_key]"
  # And it is exactly the imported key's public key.
  [[ "$p_key" == "$IMPORT_PUB" ]] || fail "unexpected imported key: $p_key"
}
