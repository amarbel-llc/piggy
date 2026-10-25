#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the state-modifying `piggy tool change-pin`
# / `change-puk` (milestone 3.2a) and `reset-pin` (milestone 3.2b) of
# piggy#289 Phase 3. These rotate card credentials, so each test gets its
# OWN fresh fibby card (setup -> fibby_up, teardown -> fibby_down; PIN
# 123456 / PUK 12345678 at start). The contract is checked BOTH ways:
#   - observable output: piggy tool exits and prints as C pivy-tool did for
#     the same operation on a fresh card (exit 0 and nothing on a success, a
#     failure on a wrong old secret);
#   - card state: after piggy changes the PIN, the NEW pin verifies (a
#     `sign` succeeds with it) and the OLD one is rejected.
# C's answers are frozen fixtures (piggy#285, lib/pivy_oracle.bash);
# `just codemod-capture-pivy-oracle-tool-pin-fibby` re-records them, giving
# piggy a fresh card again after each C call. The current + new secrets are
# supplied as two repeated `-P` options (pivy-tool's non-interactive form;
# its prompt path is tty-only).
#
# Required env (set by test-bats-conformance-tool-pin-fibby):
#   FIBBY_BIN, PIGGY, and the test askpass env; to capture,
#   PIGGY_ORACLE_MODE=capture with REAL_PIVY_TOOL and PIVY_ORACLE_CAPTURE_DIR.

FIBBY_SEEDS=(--seed-rfc6979-slot-9a-cert --seed-chuid)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  load "$PIGGY_BATS_DIR/lib/pivy_oracle.bash"
  export output
  PIVY_ORACLE_LANE=tool-pin-fibby
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  # A signing key so we can prove a changed PIN actually took effect.
  fibby_up "${FIBBY_SEEDS[@]}"
}

teardown() {
  fibby_down
}

# Capture only: C changed the card; give piggy the fresh card C started on.
pivy_oracle_reset_card() {
  fibby_down
  fibby_up "${FIBBY_SEEDS[@]}"
}

# `piggy tool ARGS` exits and prints as C pivy-tool did for ARGS (case CASE),
# from the same fresh card.
_assert_like_c() {
  local case="$1"
  shift
  local c_file="$BATS_TEST_TMPDIR/$case.c" c_status=0
  pivy_oracle "$case" "$@" >"$c_file" || c_status=$?
  ((c_status != 99)) || fail "pivy_oracle had no fixture for $case"
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

_sign_with_pin() {
  printf 'x' | "$PIGGY" tool -P "$1" sign 9a >/dev/null
}

function change_pin_matches_c_and_takes_effect { # @test
  _assert_like_c change_pin -P 123456 -P 654321 change-pin
  assert_output ""
  # The new PIN works and the old one is rejected — piggy's change took.
  _sign_with_pin 654321 || fail "new PIN did not verify"
  run _sign_with_pin 123456
  assert_failure
}

function change_pin_wrong_old_fails_like_c { # @test
  _assert_like_c change_pin_wrong_old -P 000000 -P 654321 change-pin
  assert_failure
  # The real PIN still works (the failed change consumed a retry but did
  # not rotate the PIN).
  _sign_with_pin 123456 || fail "original PIN no longer verifies"
}

function change_puk_matches_c { # @test
  # PUK starts at 12345678; both rotate it silently.
  _assert_like_c change_puk -P 12345678 -P 87654321 change-puk
  assert_output ""
}

function change_puk_wrong_old_fails { # @test
  run "$PIGGY" tool -P 00000000 -P 87654321 change-puk
  assert_failure
}

function reset_pin_matches_c_and_takes_effect { # @test
  # reset-pin installs a new PIN under PUK authority (RESET RETRY COUNTER).
  _assert_like_c reset_pin -P 12345678 -P 654321 reset-pin
  assert_output ""
  # The new PIN works and the original one is rejected — piggy's reset took.
  _sign_with_pin 654321 || fail "reset PIN did not verify"
  run _sign_with_pin 123456
  assert_failure
}

function reset_pin_wrong_puk_fails_like_c { # @test
  _assert_like_c reset_pin_wrong_puk -P 00000000 -P 654321 reset-pin
  assert_failure
  # The original PIN still works (a failed reset consumed a PUK retry but
  # left the PIN untouched).
  _sign_with_pin 123456 || fail "original PIN no longer verifies"
}

function reset_pin_unblocks_a_blocked_pin { # @test
  # Exhaust the PIN retry counter with wrong-PIN sign attempts.
  for _ in 1 2 3; do
    run _sign_with_pin 999999
    assert_failure
  done
  # The correct original PIN is now blocked — a sign with it fails.
  run _sign_with_pin 123456
  assert_failure
  # reset-pin with the correct PUK unblocks the PIN and installs a new one.
  run "$PIGGY" tool -P 12345678 -P 222222 reset-pin
  assert_success
  assert_output ""
  # The new PIN verifies — the counter was reset, not merely the value.
  _sign_with_pin 222222 || fail "PIN not unblocked after reset"
}
