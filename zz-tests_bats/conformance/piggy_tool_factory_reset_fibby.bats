#! /usr/bin/env bats
# bats file_tags=hardware
#
# Conformance for `piggy tool factory-reset` (piggy#289 Phase 3 Tier 2 /
# piggy#291): the YubicoPIV RESET (INS 0xFB) that wipes the PIV applet.
#
# C `pivy-tool factory-reset` gates the reset behind a tty-ONLY `YES` prompt
# (RPP_REQUIRE_TTY), so it cannot be driven headless — a piped `YES` makes it a
# silent no-op. So this is NOT a byte differential of the reset call; instead:
#   - piggy performs the reset (via `--yes` headless, or the tty prompt driven
#     by `expect`), then BOTH C pivy-tool and piggy read the card as blank —
#     a STATE differential (each op erased the same keys/certs C agrees are gone);
#   - the precondition (both PIN and PUK must be blocked, else SW 6985) and the
#     piggy-native confirmation gate (a typed `YES` on /dev/tty, or `--yes`) are
#     checked directly.
#
# The reset mutates card state, so each test gets its OWN fresh fibby, seeded
# with a slot-9A key + CHUID and (for the tests that expect a successful reset)
# with the PIN and PUK already blocked (`--seed-pin-puk-blocked`).
#
# Required env (set by test-bats-conformance-tool-factory-reset-fibby):
#   FIBBY_BIN, REAL_PIVY_TOOL, PIGGY, and the test askpass env; `expect` on PATH.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  export output
  if [[ -z ${REAL_PIVY_TOOL:-} || ! -x ${REAL_PIVY_TOOL:-} ]]; then
    skip "REAL_PIVY_TOOL not set (run: just test-bats-conformance-tool-factory-reset-fibby)"
  fi
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  if ! command -v expect >/dev/null 2>&1; then
    skip "expect not on PATH (needed to drive the tty confirmation prompt)"
  fi
}

teardown() {
  fibby_down
}

# A slot-9A-keyed, CHUID-bearing card with the PIN and PUK already blocked —
# the state in which YubicoPIV RESET is permitted.
up_blocked() {
  fibby_up --seed-rfc6979-slot-9a-cert --seed-chuid --seed-pin-puk-blocked
}

# Assert the card reads BLANK on both C pivy-tool and piggy: neither can read a
# slot-9A public key any more (the reset erased the key + cert).
assert_card_blank() {
  run "$REAL_PIVY_TOOL" pubkey 9a
  assert_failure
  refute_output --partial "ecdsa-sha2-nistp256"
  run "$PIGGY" tool pubkey 9a
  assert_failure
  refute_output --partial "ecdsa-sha2-nistp256"
}

function factory_reset_yes_flag_wipes_card { # @test
  up_blocked
  # Precondition: the seeded 9A key is readable before the reset.
  run "$PIGGY" tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
  # Reset non-interactively with the piggy-native --yes bypass.
  run "$PIGGY" tool --yes factory-reset
  assert_success
  # State differential: both impls now see a blank card.
  assert_card_blank
}

function factory_reset_refused_when_pin_puk_not_blocked { # @test
  # Same seed, but PIN/PUK are at their factory defaults (not blocked).
  fibby_up --seed-rfc6979-slot-9a-cert --seed-chuid
  run "$PIGGY" tool --yes factory-reset
  assert_failure
  assert_output --partial "must be blocked"
  # The card is UNCHANGED — both impls still read the 9A key.
  run "$PIGGY" tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
  run "$REAL_PIVY_TOOL" pubkey 9a
  assert_success
}

function factory_reset_no_tty_and_no_yes_refuses { # @test
  up_blocked
  # No --yes and no controlling tty (stdin from /dev/null): the gate refuses
  # rather than resetting, and the card is untouched.
  run "$PIGGY" tool factory-reset </dev/null
  assert_failure
  assert_output --partial "no controlling tty"
  run "$PIGGY" tool pubkey 9a
  assert_success
}

function factory_reset_tty_prompt_yes_confirms { # @test
  up_blocked
  # Drive the interactive /dev/tty prompt with expect: typing YES resets.
  # PIGGY / PCSCLITE_CSOCK_NAME are inherited from the environment by the
  # expect-spawned process. Match "to continue" to dodge the apostrophes in
  # the prompt's literal "Type 'YES' to continue:".
  run expect -c '
    set timeout 30
    spawn $env(PIGGY) tool factory-reset
    expect {
      "to continue" { send "YES\r" }
      timeout { exit 3 }
    }
    expect eof
    catch wait result
    exit [lindex $result 3]
  '
  assert_success
  assert_card_blank
}

function factory_reset_tty_prompt_non_yes_aborts { # @test
  up_blocked
  # Typing anything other than YES aborts (non-zero) and leaves the card alone.
  run expect -c '
    set timeout 30
    spawn $env(PIGGY) tool factory-reset
    expect {
      "to continue" { send "no\r" }
      timeout { exit 3 }
    }
    expect eof
    catch wait result
    exit [lindex $result 3]
  '
  assert_failure
  # Card unchanged: the 9A key is still there.
  run "$PIGGY" tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
}
