#!/usr/bin/env bats
#
# piggy#281 spike: a real card in the DEFAULT lane. fibby (the pure-Rust
# virtual PIV card) is brought up per test on a private socket, the real
# piggy-ids encrypts to the card's slot-9D recipient, and the Rust
# in-process decrypt (`piggy box stream decrypt`, agentless: no agent
# socket, CardEcdhOracle over PC/SC, PIN from the test askpass) recovers
# the plaintext. Deliberately NOT tagged `hardware`: it must run under
# `nix build .#bats-default`. This is the harness the Phase 1 decrypt
# re-point (piggy#164/#154) relies on instead of the base64 mocks.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  [[ -x ${PIGGY_IDS_REAL:-} ]] || skip "PIGGY_IDS_REAL not built"
  # Installed copy, not the source file: the sandbox has no /usr/bin/env
  # for the helper's shebang (the same reason common.bash copies the
  # pivy mocks), and a silently failing askpass looks exactly like a
  # card that refuses the PIN.
  piggy_install_helper_as piggy-test-askpass.sh piggy-test-askpass
  export SSH_ASKPASS="$BATS_TEST_TMPDIR/piggy-test-askpass" \
    SSH_ASKPASS_REQUIRE=force DISPLAY="" PIGGY_TEST_FIB_PIN=123456
  fibby_up
}

teardown() {
  fibby_down
}

function real_encrypt_then_agentless_in_process_decrypt_against_fibby { # @test
  local recipient ids ebox plaintext recovered
  recipient="$("$PIGGY_IDS_REAL" detect-pubkey)"
  [[ $recipient == piggy-recipient-v1@pivy_ecdh_p256_pub-* ]] || fail "unexpected recipient: $recipient"

  ids="$BATS_TEST_TMPDIR/piggy-ids"
  ebox="$BATS_TEST_TMPDIR/secret.ebox"
  echo "$recipient" >"$ids"
  plaintext='piggy#281: real RFC 0002 ebox, decrypted in-process inside the sandbox'
  printf '%s' "$plaintext" | "$PIGGY_IDS_REAL" encrypt "$ids" >"$ebox"

  # No agent anywhere: the only way to the key is the direct card path.
  recovered="$(env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox")"
  assert_equal "$recovered" "$plaintext"

  # And it really went through the card: one slot-9D ECDH on fibby's wire log.
  run grep -c 'GA ECDH 9D -> 9000' "$FIBBY_LOG"
  assert_output "1"
}

function wrong_pin_is_refused_by_the_card_not_the_harness { # @test
  local recipient ids ebox
  recipient="$("$PIGGY_IDS_REAL" detect-pubkey)"
  ids="$BATS_TEST_TMPDIR/piggy-ids"
  ebox="$BATS_TEST_TMPDIR/secret.ebox"
  echo "$recipient" >"$ids"
  printf 'x' | "$PIGGY_IDS_REAL" encrypt "$ids" >"$ebox"

  PIGGY_TEST_FIB_PIN=000000 run env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK "$PIGGY" box stream decrypt <"$ebox"
  assert_failure
  assert_output --partial "unlock failed"
  # The wrong PIN reached the card (a VERIFY that did not return 9000).
  run grep -c 'VERIFY' "$FIBBY_LOG"
  refute_output "0"
}
