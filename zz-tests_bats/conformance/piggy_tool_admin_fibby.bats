#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the state-modifying admin write ops
# `piggy tool set-admin` (milestone 3.3a) and `delete-cert` (milestone
# 3.3b) of piggy#289 Phase 3. Both mutate the card (the mgmt key / a slot
# cert object), so each test gets its OWN fresh fibby card (setup ->
# fibby_up, teardown -> fibby_down; factory 3DES admin key, seeded 9D
# cert). The contract is checked BOTH ways:
#   - observable output: both C pivy-tool and piggy tool exit 0 and print
#     nothing on a successful rotation/delete, and both fail on a wrong
#     current admin key;
#   - card state: after C rotates FACTORY -> KEY_A, piggy can only rotate
#     KEY_A -> KEY_B if KEY_A is genuinely the active key (mgmt-key mutual
#     auth); after either impl deletes the 9D cert, BOTH impls read it as
#     gone.
# set-admin is 3DES-only (AES/`random`/`@file`/`-R` fall through to C);
# delete-cert is ported for the 9A/9C/9D/9E cert slots.
#
# Required env (set by test-bats-conformance-tool-admin-fibby):
#   FIBBY_BIN, REAL_PIVY_TOOL, PIGGY.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  export output
  if [[ -z ${REAL_PIVY_TOOL:-} || ! -x ${REAL_PIVY_TOOL:-} ]]; then
    skip "REAL_PIVY_TOOL not set (run: just test-bats-conformance-tool-admin-fibby)"
  fi
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  fibby_up --seed-rfc5903-slot-9d-cert --seed-chuid
}

teardown() {
  fibby_down
}

# Two distinct 24-byte (48 hex) 3DES admin keys, neither the factory key
# (0102030405060708 x3). They differ from the factory key AND each other in
# non-parity key bits — DES ignores the low (parity) bit of each byte, so a
# key that differs only there is the SAME effective key (a subtlety the
# differential lane caught when these were 0102..09 / 0102..0a).
KEY_A=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7
KEY_B=c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7

function set_admin_rotates_key_matches_c_and_takes_effect { # @test
  # C rotates FACTORY -> KEY_A (exit 0, no output).
  run "$REAL_PIVY_TOOL" -K default set-admin "$KEY_A"
  assert_success
  assert_output ""
  # piggy rotates KEY_A -> KEY_B on the same card. This can only authenticate
  # if C's rotation actually installed KEY_A — so success proves it took.
  run "$PIGGY" tool -K "$KEY_A" set-admin "$KEY_B"
  assert_success
  assert_output ""
  # piggy rotates KEY_B -> default, proving KEY_B is now the active key.
  run "$PIGGY" tool -K "$KEY_B" set-admin default
  assert_success
  assert_output ""
}

function set_admin_wrong_current_key_fails_like_c { # @test
  # The card still holds the factory key; authenticating with KEY_A must fail
  # on both impls (a failed mgmt-key auth does not rotate anything).
  run "$REAL_PIVY_TOOL" -K "$KEY_A" set-admin "$KEY_B"
  assert_failure
  run "$PIGGY" tool -K "$KEY_A" set-admin "$KEY_B"
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

function delete_cert_clears_the_9d_slot_both_see_it_gone { # @test
  # The seeded 9D cert is readable by both impls to start.
  run "$PIGGY" tool cert 9d
  assert_success
  run "$REAL_PIVY_TOOL" cert 9d
  assert_success
  # piggy deletes the 9D cert (mgmt auth with the factory key, then PUT DATA
  # empty at the cert tag). Silent success, matching C.
  run "$PIGGY" tool delete-cert 9d
  assert_success
  assert_output ""
  # Now BOTH impls read the slot as having no certificate — piggy's delete
  # cleared the object in the same way C recognises as empty.
  run "$PIGGY" tool cert 9d
  assert_failure
  run "$REAL_PIVY_TOOL" cert 9d
  assert_failure
}

function delete_cert_c_delete_piggy_sees_it_gone { # @test
  # The mirror: C deletes the 9D cert, piggy must then read it as gone.
  run "$REAL_PIVY_TOOL" delete-cert 9d
  assert_success
  run "$PIGGY" tool cert 9d
  assert_failure
  run "$REAL_PIVY_TOOL" cert 9d
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
