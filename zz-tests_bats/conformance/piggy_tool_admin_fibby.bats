#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the state-modifying admin write ops
# `piggy tool set-admin` (milestone 3.3a), `delete-cert` (3.3b), and
# `update-keyhist` (3.3b) of piggy#289 Phase 3. All mutate the card (the
# mgmt key / a slot cert / the Key History object), so each test gets its
# OWN fresh fibby card (setup -> fibby_up, teardown -> fibby_down; factory
# 3DES admin key, seeded 9D cert). The contract is checked BOTH ways:
#   - observable output: piggy tool exits and prints as C pivy-tool did for
#     the same operation on a fresh card (exit 0 and nothing on a success,
#     a failure on a wrong current admin key);
#   - card state / wire: piggy's write lands (a rotated key authenticates,
#     a deleted cert reads as gone), and piggy sends the card the same data
#     C sent for the same operation, read from fibby's wire trace: the new
#     management key, the emptied 9D cert object, the Key History object.
#     Equal bytes on the card are what make "C deletes, piggy reads it gone"
#     and its mirror hold without running C.
# C's answers and wire bytes are frozen fixtures (piggy#285,
# lib/pivy_oracle.bash); `just codemod-capture-pivy-oracle-tool-admin-fibby`
# re-records them, giving piggy a fresh card again after each C call.
# set-admin is 3DES-only; delete-cert is ported for the 9A/9C/9D/9E cert
# slots.
#
# Required env (set by test-bats-conformance-tool-admin-fibby):
#   FIBBY_BIN, PIGGY; to capture, PIGGY_ORACLE_MODE=capture with
#   REAL_PIVY_TOOL and PIVY_ORACLE_CAPTURE_DIR.

FIBBY_SEEDS=(--seed-rfc5903-slot-9d-cert --seed-chuid)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  load "$PIGGY_BATS_DIR/lib/pivy_oracle.bash"
  export output
  PIVY_ORACLE_LANE=tool-admin-fibby
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

# Two distinct 24-byte (48 hex) 3DES admin keys, neither the factory key
# (0102030405060708 x3). They differ from the factory key AND each other in
# non-parity key bits — DES ignores the low (parity) bit of each byte, so a
# key that differs only there is the SAME effective key (a subtlety the
# differential lane caught when these were 0102..09 / 0102..0a).
KEY_A=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7
KEY_B=c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7

# Every APDU data byte sent to the card so far, as one lowercase hex string.
_sent_hex() {
  sed -nE 's/^\[fibby:apdu>\] [0-9a-f]{4}  (.*) \|.*\|$/\1/p' "$FIBBY_LOG" | tr -d ' \n'
}

# The objects written: the 3DES management key (`03 9B 18 <key>`), the 9D
# cert object's PUT DATA head (`5C 03 5F C1 0B 53 <len>`), and the Key
# History object (`5C 03 5F C1 0C 53 06 <body>`). Framing around them
# differs (C uses extended-length APDUs, piggy short ones); the data does
# not.
_sent_mgmt_key() { _sent_hex | grep -oE '039b18[0-9a-f]{48}' | tail -1; }
_sent_9d_cert_put() { _sent_hex | grep -oE '5c035fc10b53[0-9a-f]{2}' | tail -1; }
_sent_keyhist() { _sent_hex | grep -oE '5c035fc10c5306[0-9a-f]{12}' | tail -1; }

# Run C (the oracle) for CASE with ARGS on the fresh card, record what it
# wrote with the WIRE helper, then give piggy a fresh card and run `piggy
# tool ARGS`: same success or failure, same output on a success. Leaves C's
# wire bytes in $C_WIRE.
_assert_like_c() {
  local case="$1" wire="$2"
  shift 2
  local c_file="$BATS_TEST_TMPDIR/$case.c" c_status=0
  pivy_oracle "$case" "$@" >"$c_file" || c_status=$?
  ((c_status != 99)) || fail "pivy_oracle had no fixture for $case"
  C_WIRE=""
  if [[ -n $wire ]]; then
    C_WIRE="$(pivy_oracle_note "$case.wire" "$wire")" ||
      fail "no recorded C wire bytes for $case"
  fi
  pivy_oracle_fresh_card
  local c_output
  c_output="$(<"$c_file")"
  run "$PIGGY" tool "$@"
  if (((status == 0) != (c_status == 0))); then
    fail "piggy tool $* exited $status; C exited $c_status"
  fi
  if ((c_status == 0)); then
    assert_output "$c_output"
  fi
}

function set_admin_rotates_key_matches_c_and_takes_effect { # @test
  _assert_like_c set_admin _sent_mgmt_key -K default set-admin "$KEY_A"
  assert_output ""
  # piggy installed the same key C did.
  assert_equal "$(_sent_mgmt_key)" "$C_WIRE"
  [[ $C_WIRE == 039b18$KEY_A ]] || fail "C wrote an unexpected key object: $C_WIRE"
  # And it took: KEY_A now authenticates, then KEY_B does.
  run "$PIGGY" tool -K "$KEY_A" set-admin "$KEY_B"
  assert_success
  assert_output ""
  run "$PIGGY" tool -K "$KEY_B" set-admin default
  assert_success
  assert_output ""
}

function set_admin_wrong_current_key_fails_like_c { # @test
  # The card holds the factory key; authenticating with KEY_A fails on both
  # (a failed mgmt-key auth rotates nothing).
  _assert_like_c set_admin_wrong "" -K "$KEY_A" set-admin "$KEY_B"
  assert_failure
  # The factory key still works — piggy can rotate FACTORY -> KEY_A.
  run "$PIGGY" tool -K default set-admin "$KEY_A"
  assert_success
  assert_output ""
}

function set_admin_default_current_key_is_the_factory_key { # @test
  # With no -K, piggy defaults the current key to factory 3DES, matching C's
  # `-K default`. A fresh card rotates FACTORY -> KEY_A with no -K given.
  run "$PIGGY" tool set-admin "$KEY_A"
  assert_success
  assert_output ""
  # And the factory key is no longer accepted afterwards.
  run "$PIGGY" tool -K default set-admin "$KEY_B"
  assert_failure
}

function cert_9d_reads_like_c_before_a_delete { # @test
  _assert_like_c cert_9d "" cert 9d
  assert_success
}

# piggy and C empty the 9D cert object with the same PUT DATA, so either
# one's delete reads as gone to both: this covers piggy deleting what C
# reads and C deleting what piggy reads.
function delete_cert_writes_what_c_writes_and_reads_gone { # @test
  _assert_like_c delete_cert_9d _sent_9d_cert_put delete-cert 9d
  assert_output ""
  assert_equal "$(_sent_9d_cert_put)" "$C_WIRE"
  run "$PIGGY" tool cert 9d
  assert_failure
}

function delete_cert_wrong_admin_key_fails { # @test
  # A wrong current admin key fails the mgmt auth, so the cert is untouched.
  run "$PIGGY" tool -K "$KEY_A" delete-cert 9d
  assert_failure
  # The 9D cert is still readable — the failed delete did not clear it.
  run "$PIGGY" tool cert 9d
  assert_success
}

# update-keyhist has no ported read-back path (piggy#290), so the
# differential is on the write: the Key History object piggy writes is
# byte-identical to C's.
function update_keyhist_wire_matches_c { # @test
  _assert_like_c update_keyhist _sent_keyhist update-keyhist
  assert_output ""
  assert_equal "$(_sent_keyhist)" "$C_WIRE"
  # The expected fresh-card object: 53 06 C1 01 00 (oncard=0) C2 01 00
  # (offcard=0), no URL.
  assert_equal "$C_WIRE" "5c035fc10c5306c10100c20100"
}
