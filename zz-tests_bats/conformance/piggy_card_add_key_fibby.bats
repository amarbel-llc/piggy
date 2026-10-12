#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#303 (FDR 0006) — `piggy card add-key` adds one key to an already
# provisioned card: 9C, the operator-act key (PIN always, touch always), or a
# regenerated 9A. It never touches 9D, refuses an occupied slot without
# `--replace`, and needs the card's CURRENT management key and PIN.
#
# Each case runs against a virtual fibby card that is already provisioned the
# way an older piggy left one: a CHUID, a seeded 9A and 9D, the factory PIN
# (123456) and the default management key. fibby runs with `--auto-touch`:
# the new key signs its own certificate, and a touch-policy key would
# otherwise wait for a touch (piggy_card_init_fibby.bats covers the wait).
#
# What is asserted is read back from the card through `piggy list`: the slot
# records' `id` (the public key, so a changed id is a changed key) and the
# `pin_policy` / `touch_policy` a generated key's attestation carries. The
# seeded 9A and 9D cannot attest, so their records carry no policy at all.
#
# Required env (supplied by test-bats-conformance-card-add-key-fibby):
#   FIBBY_BIN          = /path/to/fibby          (nix build .#fibby)
#   PIGGY_BIN          = /path/to/piggy          (nix build .#default)
#   PIGGY_IDS_BIN      = /path/to/piggy-ids      (the from-store case)
#   MANAGE_CLIENT_BIN  = /path/to/manage-client  (cargo build, jsonrpc cases)

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-card-add-key-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  WORKDIR="$(mktemp -d -t addkey.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=

  # Every card op is direct-PCSC to fibby; nothing reaches an ambient agent.
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK

  # Refusing askpass by default (piggy-testing(7) PIN PROMPT SAFETY NET); the
  # tty cases set PIGGY_TEST_FIB_PIN / PIGGY_TEST_FIB_MGMT_KEY per command.
  local askpass="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $askpass ]] || skip "piggy-test-askpass.sh not found at $askpass"
  export SSH_ASKPASS="$askpass"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset PIGGY_TEST_FIB_PIN PIGGY_TEST_FIB_MGMT_KEY
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && wait "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# A 24-byte 3DES key that is not the card's (differs from the default key in
# non-parity bits, so it cannot pass as an equivalent key).
WRONG_MGMT_KEY=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7

# The already-provisioned card: CHUID + seeded 9A and 9D, empty 9C. Sets GUID.
_spawn_provisioned_card() {
  spawn_fibby --auto-touch --model yk5 \
    --seed-chuid --seed-rfc5903-slot-9d-cert --seed-rfc6979-slot-9a-cert
  GUID=$(_list_ndjson | sed -n 's/.*"guid":"\([0-9A-F]\{32\}\)".*"slot":"9D".*/\1/p' | head -1)
  [[ $GUID =~ ^[0-9A-F]{32}$ ]] || {
    echo "could not read the seeded card's GUID from piggy list" >&2
    _list_ndjson >&2 || true
    return 1
  }
  if [[ -n $(_slot_record 9C) ]]; then
    echo "the seeded card already has a 9C key" >&2
    return 1
  fi
}

_list_ndjson() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" list --format=ndjson
}

# The `piggy list` record for the card's SLOT (`9A`); empty when it has none.
_slot_record() {
  _list_ndjson | grep -F "\"guid\":\"$GUID\"" | grep -F "\"slot\":\"$1\"" || true
}

# The `id` of the card's SLOT record: its public key as a markl id.
_slot_id() {
  _slot_record "$1" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'
}

assert_slot_policy() {
  local slot="$1" pin="$2" touch="$3" record
  record=$(_slot_record "$slot")
  [[ $record == *"\"pin_policy\":\"$pin\""* && $record == *"\"touch_policy\":\"$touch\""* ]] || {
    echo "slot $slot is not PIN $pin / touch $touch: '$record'" >&2
    return 1
  }
}

_fail_with_output() {
  echo "$1" >&2
  printf 'status: %s\nstdout: %s\nstderr: %s\n' "$status" "$output" "${stderr:-}" >&2
  tail -60 "$FIBBY_LOG" >&2 || true
  return 1
}

# `piggy card add-key ARGS` through the tty frontend. `setsid -w` gives the
# process no controlling tty, so the confirmation is read from stdin ("y");
# the management key and the PIN come from the test askpass.
_add_key_tty() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_TEST_FIB_PIN=123456 \
    PIGGY_TEST_FIB_MGMT_KEY="${MGMT_KEY:-default}" \
    run --separate-stderr setsid -w "$PIGGY_BIN" card add-key "$@" <<<"y"
}

# `card.add_key` over stdio through the scripted manage-client; extra args
# pass through to it.
_add_key_rpc() {
  [[ -x ${MANAGE_CLIENT_BIN:-/nonexistent} ]] ||
    skip "MANAGE_CLIENT_BIN unset; run via just test-bats-conformance-card-add-key-fibby"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run --separate-stderr "$MANAGE_CLIENT_BIN" --spawn "$PIGGY_BIN" \
    --method card.add_key --pin 123456 --current-mgmt-key default "$@"
}

function add_key_9c_adds_the_operator_act_key_and_leaves_9a_9d_alone { # @test
  _spawn_provisioned_card
  local before_9a before_9d
  before_9a=$(_slot_record 9A)
  before_9d=$(_slot_record 9D)
  [[ -n $before_9a && -n $before_9d ]] || {
    echo "the seeded card is missing its 9A or 9D record" >&2
    return 1
  }

  _add_key_tty 9c
  [[ $status -eq 0 ]] || _fail_with_output "card add-key 9c failed"

  # stdout is exactly the new key as one OpenSSH line.
  [[ $output =~ ^ecdsa-sha2-nistp256\ AAAA[A-Za-z0-9+/=]+\ PIV_slot_9C@${GUID}$ ]] ||
    _fail_with_output "stdout is not one OpenSSH line ending PIV_slot_9C@$GUID"
  printf '%s\n' "$stderr" | grep -qF "Touch the card now to sign the 9C certificate" ||
    _fail_with_output "no touch instruction on stderr"
  if printf '%s\n' "$stderr" | grep -q "cannot serve operator acts"; then
    _fail_with_output "a PIN-always, touch-always 9C was reported as unable to serve operator acts"
  fi

  assert_slot_policy 9C always always
  # The card itself saw one GENERATE, for 9C, carrying PIN always (03) and
  # touch always (02).
  [[ $(grep -c 'GENERATE slot=' "$FIBBY_LOG") -eq 1 ]] ||
    _fail_with_output "expected exactly one GENERATE on the card"
  grep -q 'GENERATE slot=0x9c ECCP256 -> 9000 (.*policy pin=03 touch=02)' "$FIBBY_LOG" ||
    _fail_with_output "the card did not generate 9C with PIN always / touch always"
  # The printed key is the key now in the slot.
  local printed_key
  printed_key=$(printf '%s\n' "$output" | awk '{print $2}')
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" list --format=ssh | grep -qF "$printed_key" ||
    _fail_with_output "the printed key is not one piggy list --format=ssh shows"

  [[ $(_slot_record 9A) == "$before_9a" ]] ||
    _fail_with_output "add-key 9c changed the 9A record (was: $before_9a)"
  [[ $(_slot_record 9D) == "$before_9d" ]] ||
    _fail_with_output "add-key 9c changed the 9D record (was: $before_9d)"
}

function add_key_refuses_an_occupied_9c_without_replace { # @test
  _spawn_provisioned_card
  _add_key_tty 9c
  [[ $status -eq 0 ]] || _fail_with_output "the first card add-key 9c failed"
  local first_id
  first_id=$(_slot_id 9C)
  [[ -n $first_id ]] || _fail_with_output "no 9C id after the first add-key"

  _add_key_tty 9c
  [[ $status -eq 1 ]] || _fail_with_output "add-key on an occupied 9C should exit 1"
  printf '%s\n' "$stderr" | grep -qF -- "--replace" ||
    _fail_with_output "the refusal does not mention --replace"
  [[ $(_slot_id 9C) == "$first_id" ]] ||
    _fail_with_output "the refused add-key changed the 9C key"

  _add_key_tty 9c --replace
  [[ $status -eq 0 ]] || _fail_with_output "card add-key 9c --replace failed"
  local second_id
  second_id=$(_slot_id 9C)
  [[ -n $second_id && $second_id != "$first_id" ]] ||
    _fail_with_output "--replace did not change the 9C key ($first_id -> $second_id)"
  assert_slot_policy 9C always always
}

function add_key_9a_needs_replace_and_never_touches_9d { # @test
  _spawn_provisioned_card
  local before_9a before_9d
  before_9a=$(_slot_id 9A)
  before_9d=$(_slot_id 9D)
  [[ -n $before_9a && -n $before_9d ]] || {
    echo "the seeded card is missing its 9A or 9D id" >&2
    return 1
  }

  _add_key_tty 9a
  [[ $status -eq 1 ]] || _fail_with_output "add-key on the seeded 9A should exit 1"
  printf '%s\n' "$stderr" | grep -qF -- "--replace" ||
    _fail_with_output "the refusal does not mention --replace"
  [[ $(_slot_id 9A) == "$before_9a" ]] ||
    _fail_with_output "the refused add-key changed the 9A key"

  _add_key_tty 9a --replace
  [[ $status -eq 0 ]] || _fail_with_output "card add-key 9a --replace failed"
  [[ $output =~ ^ecdsa-sha2-nistp256\ AAAA[A-Za-z0-9+/=]+\ PIV_slot_9A@${GUID}$ ]] ||
    _fail_with_output "stdout is not one OpenSSH line ending PIV_slot_9A@$GUID"
  local after_9a
  after_9a=$(_slot_id 9A)
  [[ -n $after_9a && $after_9a != "$before_9a" ]] ||
    _fail_with_output "--replace did not change the 9A key"
  assert_slot_policy 9A once cached
  [[ $(_slot_id 9D) == "$before_9d" ]] ||
    _fail_with_output "add-key 9a --replace changed the 9D key"
}

# A slot add-key never takes is a usage error (exit 2) whatever is plugged
# in, and nothing is written.
_assert_slot_is_a_usage_error() {
  local slot="$1" needle="$2"
  _spawn_provisioned_card
  local before
  before=$(_list_ndjson)

  _add_key_tty "$slot" --replace
  [[ $status -eq 2 ]] || _fail_with_output "add-key $slot should exit 2"
  printf '%s\n' "$stderr" | grep -qF "$needle" ||
    _fail_with_output "the refusal of $slot does not say: $needle"
  [[ $(_list_ndjson) == "$before" ]] ||
    _fail_with_output "add-key $slot changed the card"
  if grep -q 'GENERATE slot=' "$FIBBY_LOG"; then
    _fail_with_output "add-key $slot sent a GENERATE"
  fi
}

function add_key_9d_is_a_usage_error { # @test
  _assert_slot_is_a_usage_error 9d "never regenerated"
}

function add_key_unknown_slot_is_a_usage_error { # @test
  _assert_slot_is_a_usage_error 9e "add-key takes 9c or 9a"
}

function add_key_wrong_management_key_writes_nothing { # @test
  _spawn_provisioned_card
  local before
  before=$(_list_ndjson)

  MGMT_KEY="$WRONG_MGMT_KEY" _add_key_tty 9c
  [[ $status -ne 0 ]] || _fail_with_output "add-key with a wrong management key succeeded"
  # It is the CARD that refuses the key (a well-formed but wrong one), not a
  # parse error or a prompt that never got answered.
  grep -q 'card error' <<<"$stderr" ||
    _fail_with_output "the failure is not the card rejecting the management key"
  [[ $(_list_ndjson) == "$before" ]] ||
    _fail_with_output "a wrong management key still changed the card"
  if grep -q 'GENERATE slot=.* -> 9000' "$FIBBY_LOG"; then
    _fail_with_output "the card generated a key under a wrong management key"
  fi
}

function add_key_9c_pin_policy_once_reads_back_and_warns { # @test
  _spawn_provisioned_card

  _add_key_tty 9c --pin-policy once
  [[ $status -eq 0 ]] || _fail_with_output "card add-key 9c --pin-policy once failed"
  assert_slot_policy 9C once always
  printf '%s\n' "$stderr" | grep -q "cannot serve operator acts" ||
    _fail_with_output "no operator-acts warning for a PIN-once 9C"
}

# --- card export-attestation (RFC 0012 section 5) ----------------------------

_export_attestation() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run --separate-stderr "$PIGGY_BIN" card export-attestation "$@"
}

function export_attestation_prints_the_bundle_for_a_generated_9c { # @test
  _spawn_provisioned_card
  _add_key_tty 9c
  [[ $status -eq 0 ]] || _fail_with_output "card add-key 9c failed"
  local key
  key=$(printf '%s\n' "$output" | awk '{print $1, $2}')

  _export_attestation
  [[ $status -eq 0 ]] || _fail_with_output "card export-attestation failed"
  local bundle="$output" guid8
  guid8=$(printf '%s' "${GUID:0:8}" | tr 'A-F' 'a-f')
  [[ $(sed -n 1p <<<"$bundle") == "# piggy-attestation-bundle v1" ]] ||
    _fail_with_output "line 1 is not the bundle header"
  [[ $(sed -n 2p <<<"$bundle") == "# key "?* ]] ||
    _fail_with_output "line 2 is not a '# key <markl-id>' line"
  [[ $(sed -n 3p <<<"$bundle") == "$key PIV_slot_9C card:$guid8" ]] ||
    _fail_with_output "line 3 is not the 9C key with comment 'PIV_slot_9C card:$guid8' (want key: $key)"
  # Then exactly two PEM certificates, and nothing else.
  local rest
  rest=$(sed -n '4,$p' <<<"$bundle" | grep -n -e '-----BEGIN' -e '-----END' | sed 's/^[0-9]*://' | tr '\n' ' ')
  [[ $rest == "-----BEGIN CERTIFICATE----- -----END CERTIFICATE----- -----BEGIN CERTIFICATE----- -----END CERTIFICATE----- " ]] ||
    _fail_with_output "the bundle does not end with exactly two PEM certificates: $rest"
  [[ $(sed -n 4p <<<"$bundle") == "-----BEGIN CERTIFICATE-----" && $(tail -1 <<<"$bundle") == "-----END CERTIFICATE-----" ]] ||
    _fail_with_output "there is text around the two certificates"

  # An explicit slot is the same bundle; 9d is a usage error.
  _export_attestation 9c
  [[ $status -eq 0 && $output == "$bundle" ]] ||
    _fail_with_output "export-attestation 9c differs from the default"
  _export_attestation 9d
  [[ $status -eq 2 ]] || _fail_with_output "export-attestation 9d should exit 2"
  [[ -z $output ]] || _fail_with_output "export-attestation 9d printed to stdout"
}

# A 9C key that was not generated on the card cannot be attested.
function export_attestation_refuses_a_seeded_9c { # @test
  spawn_fibby --auto-touch --model yk5 \
    --seed-chuid --seed-rfc5903-slot-9d-cert --seed-slot-9c-cert

  _export_attestation
  [[ $status -eq 1 ]] || _fail_with_output "export-attestation of a seeded 9C should exit 1"
  [[ -z $output ]] || _fail_with_output "a refused export-attestation printed to stdout"
  grep -q 'will not attest slot 9C' <<<"$stderr" ||
    _fail_with_output "the refusal is not the card declining to attest the key"
}

# --- JSON-RPC: card.add_key over `piggy manage --jsonrpc` (RFC 0007 §5.4) ----

function rpc_add_key_9c_returns_the_key_and_reports_the_touch { # @test
  _spawn_provisioned_card

  _add_key_rpc --slot 9c
  [[ $status -eq 0 ]] || _fail_with_output "card.add_key 9c failed"
  [[ $output == *'"serves_operator_acts":true'* ]] ||
    _fail_with_output "card.add_key 9c did not return serves_operator_acts: true"
  [[ $output == *"\"public_key\":\"ecdsa-sha2-nistp256 AAAA"*" PIV_slot_9C@$GUID\""* ]] ||
    _fail_with_output "card.add_key 9c returned no public_key for PIV_slot_9C@$GUID"
  [[ $output == *"\"guid\":\"$GUID\""* && $output == *'"slot":"9c"'* ]] ||
    _fail_with_output "card.add_key 9c result does not name the card and slot"
  printf '%s\n' "$stderr" | grep -qxF "manage-client: progress touch-9c" ||
    _fail_with_output "the client saw no touch-9c progress notification"
  if printf '%s\n' "$stderr" | grep -qF "progress no-operator-acts"; then
    _fail_with_output "an operator-act 9C was reported as no-operator-acts"
  fi
  assert_slot_policy 9C always always

  # A second request for the now-occupied slot, without replace: -32050.
  local first_id
  first_id=$(_slot_id 9C)
  _add_key_rpc --slot 9c
  [[ $status -ne 0 ]] || _fail_with_output "card.add_key on an occupied 9C succeeded"
  [[ $output == *'"code":-32050'* ]] ||
    _fail_with_output "an occupied slot without replace is not error -32050"
  [[ $(_slot_id 9C) == "$first_id" ]] ||
    _fail_with_output "the refused card.add_key changed the 9C key"
}

function rpc_add_key_9d_is_invalid_params { # @test
  _spawn_provisioned_card
  local before
  before=$(_list_ndjson)

  _add_key_rpc --slot 9d
  [[ $status -ne 0 ]] || _fail_with_output "card.add_key 9d succeeded"
  [[ $output == *'"code":-32602'* ]] ||
    _fail_with_output "card.add_key 9d is not error -32602"
  [[ $(_list_ndjson) == "$before" ]] ||
    _fail_with_output "card.add_key 9d changed the card"
}

function rpc_add_key_policy_param_reports_no_operator_acts { # @test
  _spawn_provisioned_card

  _add_key_rpc --slot 9c --params-json '{"touch_policy":"cached"}'
  [[ $status -eq 0 ]] || _fail_with_output "card.add_key 9c touch_policy=cached failed"
  [[ $output == *'"serves_operator_acts":false'* ]] ||
    _fail_with_output "a touch-cached 9C did not return serves_operator_acts: false"
  printf '%s\n' "$stderr" | grep -qxF "manage-client: progress no-operator-acts" ||
    _fail_with_output "the client saw no no-operator-acts progress notification"
  assert_slot_policy 9C always cached
}

# --- --management-key-from-store ---------------------------------------------
#
# Card A is provisioned by `card init --seal-management-key`, which escrows
# its random management key to the store, sealed to backup card B. add-key
# then reads that key back through the normal decrypt path (card B's PIN)
# instead of asking for it. Both cards share PIN 123456 so one askpass
# answer serves card B's decrypt and card A's PIN verify.

READER_A="Virtual PCD fibby A 00 00"
READER_B="Virtual PCD fibby B 00 00"
GUID_B="B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"

function add_key_reads_the_management_key_from_the_store { # @test
  [[ -x ${PIGGY_IDS_BIN:-/nonexistent} ]] ||
    skip "PIGGY_IDS_BIN unset; run via just test-bats-conformance-card-add-key-fibby"
  spawn_fibby --auto-touch --model yk5 \
    --card "$READER_A" \
    --card "$READER_B" --seed-rfc5903-slot-9d-cert --seed-chuid-guid "$GUID_B"
  local b_id
  b_id=$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_IDS_BIN" detect-pubkey --guid "$GUID_B")
  printf '%s\n' "$b_id" >"$PIGGY_STORE_DIR/piggy-ids"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_TEST_FIB_PIN=123456 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card init \
    --reader "$READER_A" --seal-management-key <<<"y"
  [[ $status -eq 0 ]] || _fail_with_output "card init --seal-management-key failed"
  GUID="$output"
  [[ -f "$PIGGY_STORE_DIR/piv/$GUID/management-key.ebox" ]] ||
    _fail_with_output "card init did not seal the management key"
  local first_id
  first_id=$(_slot_id 9C)
  [[ -n $first_id ]] || _fail_with_output "card init left no 9C key"

  # No PIGGY_TEST_FIB_MGMT_KEY: were the key asked for, the askpass would
  # answer with the PIN, which is not a management key, and add-key would fail.
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_TEST_FIB_PIN=123456 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card add-key 9c --replace \
    --guid "$GUID" --management-key-from-store <<<"y"
  [[ $status -eq 0 ]] || _fail_with_output "add-key --management-key-from-store failed"
  local second_id
  second_id=$(_slot_id 9C)
  [[ -n $second_id && $second_id != "$first_id" ]] ||
    _fail_with_output "--management-key-from-store did not replace the 9C key"

  # The same request with the escrow gone has no key to read: it fails and
  # the slot keeps its key.
  rm -f "$PIGGY_STORE_DIR/piv/$GUID/management-key.ebox"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_TEST_FIB_PIN=123456 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card add-key 9c --replace \
    --guid "$GUID" --management-key-from-store <<<"y"
  [[ $status -ne 0 ]] || _fail_with_output "add-key succeeded with no sealed management key"
  [[ $(_slot_id 9C) == "$second_id" ]] ||
    _fail_with_output "a failed add-key replaced the 9C key"
}
