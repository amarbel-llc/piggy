#! /usr/bin/env bats
# bats file_tags=hardware
#
# Conformance for `piggy tool factory-reset` (piggy#289 Phase 3 Tier 2 /
# piggy#291): the YubicoPIV RESET (INS 0xFB) that wipes the PIV applet.
#
#   - a wire differential: piggy sends the card the same RESET command C
#     pivy-tool sends, read from fibby's wire log, and the card then reads
#     blank. C gates its reset behind a tty-ONLY `YES` prompt
#     (RPP_REQUIRE_TTY; a piped `YES` is a silent no-op), so its side is
#     driven through `expect`. C's command is a frozen fixture (piggy#285,
#     lib/pivy_oracle.bash); `just
#     codemod-capture-pivy-oracle-tool-factory-reset-fibby` re-records it;
#   - the precondition (both PIN and PUK must be blocked, else SW 6985) and the
#     piggy-native confirmation gate (a typed `YES` on /dev/tty, or `--yes`) are
#     checked directly. piggy deliberately differs from C on a non-YES answer:
#     C returns success without resetting, piggy fails.
#
# The reset mutates card state, so each test gets its OWN fresh fibby, seeded
# with a slot-9A key + CHUID and (for the tests that expect a successful reset)
# with the PIN and PUK already blocked (`--seed-pin-puk-blocked`).
#
# Required env (set by test-bats-conformance-tool-factory-reset-fibby):
#   FIBBY_BIN, PIGGY, and the test askpass env; `expect` on PATH; to
#   capture, PIGGY_ORACLE_MODE=capture with REAL_PIVY_TOOL and
#   PIVY_ORACLE_CAPTURE_DIR.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  load "$PIGGY_BATS_DIR/lib/pivy_oracle.bash"
  export output
  PIVY_ORACLE_LANE=tool-factory-reset-fibby
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

pivy_oracle_reset_card() {
  fibby_down
  up_blocked
}

# Run CMD... (a factory-reset) under expect, answering ANSWER at its
# "Type 'YES' to continue:" tty prompt; exits with CMD's status. Matches "to
# continue" to dodge the prompt's apostrophes. PCSCLITE_CSOCK_NAME reaches
# the spawned process through the environment.
_expect_factory_reset() {
  local answer="$1"
  shift
  expect -c "
    set timeout 30
    spawn $*
    expect {
      \"to continue\" { send \"$answer\\r\" }
      timeout { exit 3 }
    }
    expect eof
    catch wait result
    exit [lindex \$result 3]
  "
}

# The `CLA INS P1 P2` of every RESET command the card was sent.
_sent_reset_headers() {
  fibby_command_apdus fb | cut -c1-8
}

# Capture only: C resets the card at its tty prompt; prints its RESET
# command headers.
_c_factory_reset_headers() {
  _expect_factory_reset YES "$REAL_PIVY_TOOL" factory-reset >/dev/null ||
    return
  _sent_reset_headers
}

# The card reads blank: no slot-9A public key any more (the reset erased the
# key + cert). piggy's `pubkey` is held to C's by the tool-fibby lane.
assert_card_blank() {
  run "$PIGGY" tool pubkey 9a
  assert_failure
  refute_output --partial "ecdsa-sha2-nistp256"
}

function factory_reset_yes_flag_sends_what_c_sends_and_wipes_card { # @test
  up_blocked
  local c_reset
  c_reset="$(pivy_oracle_note factory_reset.wire _c_factory_reset_headers)" ||
    fail "no recorded C RESET"
  [[ $c_reset == 00fb0000 ]] || fail "C sent an unexpected RESET: [$c_reset]"
  pivy_oracle_fresh_card
  # Precondition: the seeded 9A key is readable before the reset.
  run "$PIGGY" tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
  # Reset non-interactively with the piggy-native --yes bypass.
  run "$PIGGY" tool --yes factory-reset
  assert_success
  assert_equal "$(_sent_reset_headers)" "$c_reset"
  assert_card_blank
}

function factory_reset_refused_when_pin_puk_not_blocked { # @test
  # Same seed, but PIN/PUK are at their factory defaults (not blocked).
  fibby_up --seed-rfc6979-slot-9a-cert --seed-chuid
  run "$PIGGY" tool --yes factory-reset
  assert_failure
  assert_output --partial "must be blocked"
  # The card is UNCHANGED — the 9A key still reads.
  run "$PIGGY" tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
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
  run _expect_factory_reset YES "$PIGGY" tool factory-reset
  assert_success
  assert_card_blank
}

function factory_reset_tty_prompt_non_yes_aborts { # @test
  up_blocked
  # Typing anything other than YES aborts (non-zero) and leaves the card alone.
  run _expect_factory_reset no "$PIGGY" tool factory-reset
  assert_failure
  # Card unchanged: the 9A key is still there.
  run "$PIGGY" tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
}
