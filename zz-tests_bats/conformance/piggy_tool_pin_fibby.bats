#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the state-modifying `piggy tool change-pin`
# / `change-puk` (milestone 3.2a) and `reset-pin` (milestone 3.2b) of
# piggy#289 Phase 3. These rotate card credentials, so each test gets its
# OWN fresh fibby card (setup ->
# fibby_up, teardown -> fibby_down; PIN 123456 / PUK 12345678 at start).
# The contract is checked BOTH ways:
#   - observable output: both C pivy-tool and piggy tool exit 0 and print
#     nothing on a successful change, and both fail on a wrong old secret;
#   - card state: after piggy changes the PIN, the NEW pin verifies (a
#     `sign` succeeds with it) and the OLD one is rejected.
# The current + new secrets are supplied as two repeated `-P` options
# (pivy-tool's non-interactive form; its prompt path is tty-only).
#
# Required env (set by test-bats-conformance-tool-pin-fibby):
#   FIBBY_BIN, REAL_PIVY_TOOL, PIGGY, and the test askpass env.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  export output
  if [[ -z ${REAL_PIVY_TOOL:-} || ! -x ${REAL_PIVY_TOOL:-} ]]; then
    skip "REAL_PIVY_TOOL not set (run: just test-bats-conformance-tool-pin-fibby)"
  fi
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  # A signing key so we can prove a changed PIN actually took effect.
  fibby_up --seed-rfc6979-slot-9a-cert --seed-chuid
}

teardown() {
  fibby_down
}

function change_pin_matches_c_and_takes_effect { # @test
  # C changes 123456 -> 654321 (exit 0, no output).
  run "$REAL_PIVY_TOOL" -P 123456 -P 654321 change-pin
  assert_success
  assert_output ""
  # piggy changes 654321 -> 111111 (exit 0, no output) on the same card.
  run "$PIGGY" tool -P 654321 -P 111111 change-pin
  assert_success
  assert_output ""
  # The new PIN works and the old one is rejected — piggy's change took.
  printf 'x' | "$PIGGY" tool -P 111111 sign 9a >/dev/null || fail "new PIN did not verify"
  run bash -c "printf 'x' | '$PIGGY' tool -P 654321 sign 9a"
  assert_failure
}

function change_pin_wrong_old_fails_like_c { # @test
  run "$REAL_PIVY_TOOL" -P 000000 -P 654321 change-pin
  assert_failure
  run "$PIGGY" tool -P 000000 -P 654321 change-pin
  assert_failure
  # The real PIN still works (the failed change consumed a retry but did
  # not rotate the PIN).
  printf 'x' | "$PIGGY" tool -P 123456 sign 9a >/dev/null || fail "original PIN no longer verifies"
}

function change_puk_matches_c { # @test
  # PUK starts at 12345678. C rotates it, then piggy rotates it again;
  # both succeed silently.
  run "$REAL_PIVY_TOOL" -P 12345678 -P 87654321 change-puk
  assert_success
  assert_output ""
  run "$PIGGY" tool -P 87654321 -P 11112222 change-puk
  assert_success
  assert_output ""
}

function change_puk_wrong_old_fails { # @test
  run "$PIGGY" tool -P 00000000 -P 87654321 change-puk
  assert_failure
}

function reset_pin_matches_c_and_takes_effect { # @test
  # reset-pin installs a new PIN under PUK authority (RESET RETRY COUNTER).
  # The PUK (12345678) is unchanged, so both tools can reset in turn.
  # C resets the PIN to 654321 (exit 0, no output).
  run "$REAL_PIVY_TOOL" -P 12345678 -P 654321 reset-pin
  assert_success
  assert_output ""
  # piggy resets the PIN again to 111111 on the same card (exit 0, no output).
  run "$PIGGY" tool -P 12345678 -P 111111 reset-pin
  assert_success
  assert_output ""
  # The new PIN works and the intermediate one is rejected — piggy's reset took.
  printf 'x' | "$PIGGY" tool -P 111111 sign 9a >/dev/null || fail "reset PIN did not verify"
  run bash -c "printf 'x' | '$PIGGY' tool -P 654321 sign 9a"
  assert_failure
}

function reset_pin_wrong_puk_fails_like_c { # @test
  run "$REAL_PIVY_TOOL" -P 00000000 -P 654321 reset-pin
  assert_failure
  run "$PIGGY" tool -P 00000000 -P 654321 reset-pin
  assert_failure
  # The original PIN still works (a failed reset consumed a PUK retry but
  # left the PIN untouched).
  printf 'x' | "$PIGGY" tool -P 123456 sign 9a >/dev/null || fail "original PIN no longer verifies"
}

function reset_pin_unblocks_a_blocked_pin { # @test
  # Exhaust the PIN retry counter with wrong-PIN sign attempts.
  for _ in 1 2 3; do
    run bash -c "printf 'x' | '$PIGGY' tool -P 999999 sign 9a"
    assert_failure
  done
  # The correct original PIN is now blocked — a sign with it fails.
  run bash -c "printf 'x' | '$PIGGY' tool -P 123456 sign 9a"
  assert_failure
  # reset-pin with the correct PUK unblocks the PIN and installs a new one.
  run "$PIGGY" tool -P 12345678 -P 222222 reset-pin
  assert_success
  assert_output ""
  # The new PIN verifies — the counter was reset, not merely the value.
  printf 'x' | "$PIGGY" tool -P 222222 sign 9a >/dev/null || fail "PIN not unblocked after reset"
}
