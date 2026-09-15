#!/usr/bin/env bats
#
# The harness card (piggy#281, piggy#164): common.bash brings up fibby
# (the pure-Rust virtual PIV card) per test on a private socket and
# exports PCSCLITE_CSOCK_NAME, so the default lane runs real crypto with
# no pcscd, no agent and no `hardware` tag. This file pins that
# contract: the real piggy-ids encrypts to the card's slot-9D recipient,
# the in-process decrypt (`piggy box stream decrypt`, agentless:
# CardEcdhOracle over PC/SC, PIN from the test askpass) recovers the
# plaintext, and PIGGY_TEST_RECIPIENT is what the card actually reports.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  [[ -x ${PIGGY_IDS_REAL:-} ]] || skip "PIGGY_IDS_REAL not built"
}

function harness_recipient_constant_is_the_virtual_cards_slot_9d { # @test
  # create_test_template writes PIGGY_TEST_RECIPIENT blind; this is the
  # one place it is checked against the card. A fibby seed change fails
  # here, not as a hundred "unlock failed" tests.
  run "$PIGGY_IDS_REAL" detect-pubkey
  assert_success
  assert_output "$PIGGY_TEST_RECIPIENT"
}

function real_encrypt_then_agentless_in_process_decrypt_against_fibby { # @test
  local ids ebox plaintext recovered
  ids="$BATS_TEST_TMPDIR/piggy-ids"
  ebox="$BATS_TEST_TMPDIR/secret.ebox"
  echo "$PIGGY_TEST_RECIPIENT" >"$ids"
  plaintext='piggy#281: real RFC 0002 ebox, decrypted in-process inside the sandbox'
  printf '%s' "$plaintext" | "$PIGGY_IDS_REAL" encrypt "$ids" >"$ebox"

  # No agent anywhere: the only way to the key is the direct card path.
  recovered="$(env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox")"
  assert_equal "$recovered" "$plaintext"

  # And it really went through the card: one slot-9D ECDH on fibby's wire log.
  run grep -c 'GA ECDH 9D -> 9000' "$FIBBY_LOG"
  assert_output "1"
}

# piggy#284: `fibby ctl fault` makes the NEXT matching APDU answer a chosen
# status word without touching the card's state, so the client's handling
# of each PIV error path is asserted deterministically — here the
# in-process decrypt's PIN errors.
function injected_wrong_pin_fault_reports_retries_remaining { # @test
  local ids ebox
  ids="$BATS_TEST_TMPDIR/piggy-ids"
  ebox="$BATS_TEST_TMPDIR/secret.ebox"
  echo "$PIGGY_TEST_RECIPIENT" >"$ids"
  printf 'x' | "$PIGGY_IDS_REAL" encrypt "$ids" >"$ebox"

  fibby_ctl fault 20 63C2
  run env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox"
  assert_failure
  assert_output --partial "wrong PIN, 2 retries remaining"
  run grep -c 'INS 20 -> 63C2 (injected fault' "$FIBBY_LOG"
  assert_output "1"

  # The fault was consumed and the card's own retry counter was never
  # touched: the same PIN now unlocks.
  run env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox"
  assert_success
  assert_output "x"
}

function injected_blocked_pin_fault_reports_pin_blocked { # @test
  local ids ebox
  ids="$BATS_TEST_TMPDIR/piggy-ids"
  ebox="$BATS_TEST_TMPDIR/secret.ebox"
  echo "$PIGGY_TEST_RECIPIENT" >"$ids"
  printf 'x' | "$PIGGY_IDS_REAL" encrypt "$ids" >"$ebox"

  fibby_ctl fault 20 6983
  run env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox"
  assert_failure
  assert_output --partial "PIN blocked"
}

function wrong_pin_is_refused_by_the_card_not_the_harness { # @test
  local ids ebox
  ids="$BATS_TEST_TMPDIR/piggy-ids"
  ebox="$BATS_TEST_TMPDIR/secret.ebox"
  echo "$PIGGY_TEST_RECIPIENT" >"$ids"
  printf 'x' | "$PIGGY_IDS_REAL" encrypt "$ids" >"$ebox"

  PIGGY_TEST_FIB_PIN=000000 run env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox"
  assert_failure
  assert_output --partial "unlock failed"
  # The wrong PIN reached the card (a VERIFY that did not return 9000).
  run grep -c 'VERIFY' "$FIBBY_LOG"
  refute_output "0"
}
