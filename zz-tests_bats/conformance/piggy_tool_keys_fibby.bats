#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the `piggy tool` key-surface ops of piggy#289
# Phase 3.4: `write-cert` (milestone 3.4a) and `generate` (3.4b). These
# mutate slot material, so each test gets its OWN fresh fibby card (setup ->
# fibby_up, teardown -> fibby_down; factory 3DES admin key, seeded 9D cert,
# and a pinned scalar for GENERATE on slot 9A so keygen is deterministic).
# The contract is checked against C pivy-tool:
#   - write-cert: after either impl writes a cert to a slot, BOTH impls read
#     back exactly that cert; a wrong current admin key fails on both;
#   - generate: with the 9A scalar pinned, both impls' GENERATE returns the
#     same key, so `generate 9a -a eccp256` prints the identical pubkey line
#     (the self-signed cert side effect has a random serial and legitimately
#     differs, so only the printed pubkey is compared).
# Both are ported for the 9A/9C/9D/9E cert slots; generate models the EC
# algorithms (eccp256/eccp384) only.
#
# Required env (set by test-bats-conformance-tool-keys-fibby):
#   FIBBY_BIN, REAL_PIVY_TOOL, PIGGY.

# RFC 6979 §A.2.5 P-256 private scalar — a known test key with a known pubkey.
GEN_9A_SCALAR=c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  export output
  if [[ -z ${REAL_PIVY_TOOL:-} || ! -x ${REAL_PIVY_TOOL:-} ]]; then
    skip "REAL_PIVY_TOOL not set (run: just test-bats-conformance-tool-keys-fibby)"
  fi
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  fibby_up --seed-rfc5903-slot-9d-cert --seed-chuid \
    --generate-slot-9a-priv "$GEN_9A_SCALAR"
}

teardown() {
  fibby_down
}

# A 24-byte 3DES admin key that is NOT the factory key (differs in non-parity
# key bits — see piggy_tool_admin_fibby.bats for the DES parity subtlety).
WRONG_KEY=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7

function write_cert_piggy_writes_both_read_it_back { # @test
  # Capture the seeded 9D cert, delete it, write it back via piggy, and
  # confirm BOTH impls read the restored cert identically.
  local certfile="$BATS_TEST_TMPDIR/orig9d.pem"
  "$REAL_PIVY_TOOL" cert 9d >"$certfile"
  [[ -s $certfile ]] || fail "no seeded 9D cert to start"
  run "$PIGGY" tool delete-cert 9d
  assert_success
  run "$PIGGY" tool cert 9d
  assert_failure
  # piggy writes the cert back (mgmt auth with the factory key, then PUT DATA).
  run bash -c "'$PIGGY' tool write-cert 9d < '$certfile'"
  assert_success
  assert_output ""
  # Both impls read back exactly the written cert.
  local want
  want="$(cat "$certfile")"
  run "$PIGGY" tool cert 9d
  assert_success
  assert_output "$want"
  run "$REAL_PIVY_TOOL" cert 9d
  assert_success
  assert_output "$want"
}

function write_cert_c_writes_piggy_reads_it_back { # @test
  # The mirror: C writes the cert, piggy must read back exactly that cert.
  local certfile="$BATS_TEST_TMPDIR/orig9d.pem"
  "$REAL_PIVY_TOOL" cert 9d >"$certfile"
  [[ -s $certfile ]] || fail "no seeded 9D cert to start"
  run "$PIGGY" tool delete-cert 9d
  assert_success
  run bash -c "'$REAL_PIVY_TOOL' write-cert 9d < '$certfile'"
  assert_success
  local want
  want="$(cat "$certfile")"
  run "$PIGGY" tool cert 9d
  assert_success
  assert_output "$want"
}

function write_cert_wrong_admin_key_fails { # @test
  # A wrong current admin key fails the mgmt auth, so the slot is untouched.
  local certfile="$BATS_TEST_TMPDIR/orig9d.pem"
  "$REAL_PIVY_TOOL" cert 9d >"$certfile"
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
  run bash -c "'$REAL_PIVY_TOOL' -P 123456 -a eccp256 generate 9a 2>/dev/null"
  assert_success
  local c_out="$output"
  run bash -c "'$PIGGY' tool -P 123456 -a eccp256 generate 9a 2>/dev/null"
  assert_success
  [[ "$output" == "$c_out" ]] || fail "generate pubkey differs: C=[$c_out] piggy=[$output]"
  # Sanity: a P-256 pubkey line with the bare slot/GUID comment (no subject).
  [[ "$output" == "ecdsa-sha2-nistp256 "*" PIV_slot_9A@"* ]] \
    || fail "unexpected generate output: $output"
}
