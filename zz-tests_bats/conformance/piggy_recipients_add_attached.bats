#! /usr/bin/env bats
# bats file_tags=hardware
#
# Conformance tier-2 tests for piggy pass recipients add --all-attached
# against the real fib virtual PIV card. Multi-card permutations
# (mixed supported+unsupported, dedup across N cards) live in the
# tier-1 mock bats at zz-tests_bats/t0610-recipients-add-attached.bats
# because fib is single-card by construction; see amarbel-llc/piggy#83.
#
# Driven by `just test-bats-conformance-recipients-add-attached` which
# brings up fib, generates a P-256 key in slot 9D, exports
# PCSCLITE_CSOCK_NAME, and runs bats with --allow-unix-sockets
# --allow-local-binding plus the askpass safety net.
#
# Tests skip gracefully when fib env vars are absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-recipients-add-attached)"
  fi

  # Replace common.bash's mock-piggy-ids symlink with the real Rust
  # binary so detect-pubkey / detect-all-pubkeys actually talk to the
  # fib card via piggy-piv. Scoped to BATS_TEST_TMPDIR.
  if [[ -x "$REPO_ROOT/target/debug/piggy-ids" ]]; then
    ln -sf "$REPO_ROOT/target/debug/piggy-ids" "$BATS_TEST_TMPDIR/piggy-ids"
  elif [[ -x "$REPO_ROOT/target/release/piggy-ids" ]]; then
    ln -sf "$REPO_ROOT/target/release/piggy-ids" "$BATS_TEST_TMPDIR/piggy-ids"
  else
    skip "piggy-ids binary not found (run: just build-rust)"
  fi

  # Same treatment for pivy-tool: test 3 calls `pivy-tool -P ... -a
  # rsa2048 generate 9d` to re-key fib's slot 9D. The mock at
  # zz-tests_bats/helpers/mock-pivy-tool.sh only knows `pubkey` and
  # `list` and errors on `-P`. Remove the mock symlink so the dev-shell
  # pivy-tool (the real C binary) on PATH is found.
  rm -f "$BATS_TEST_TMPDIR/pivy-tool"

  init_test_git

  # Detect the live card's markl ID once; pin for later asserts.
  # CARD_ID is consumed by tests 1 and 2: test 1 asserts the live card
  # was added; test 2 inits the store with the card's own ID to verify
  # the noop case.
  CARD_ID="$(piggy-ids detect-pubkey)"
  [[ -n $CARD_ID ]] || skip "piggy-ids detect-pubkey returned empty (no card?)"
  export CARD_ID
}

# Foreign recipient (canonical RFC 0002 non-trivial vector). Used to
# initialize stores with a markl ID that's NOT the live card's, so
# --all-attached adds the live card on top.
FOREIGN_RECIPIENT="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"

function fib_attached_adds_the_card { # @test
  "$PIGGY" pass init -k "$FOREIGN_RECIPIENT"

  run "$PIGGY" pass recipients add --all-attached
  assert_success

  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$CARD_ID"
  assert_output --partial "$FOREIGN_RECIPIENT"
}

function fib_attached_already_a_recipient_is_noop { # @test
  "$PIGGY" pass init -k "$CARD_ID"
  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  assert_output --partial "already a recipient: $CARD_ID"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit"
}

function fib_attached_rsa_in_9d_is_unsupported { # @test
  # Re-key slot 9D as RSA. The card is then unsupported for piggy.
  # NOTE: this test leaves the card in RSA state. The just recipe
  # re-generates EcP256 before each lane invocation, so re-running
  # the lane is safe; running THIS test alone (without re-init)
  # would leave fib in an RSA-9D state. That's why this is the LAST
  # test in this file.
  pivy-tool -P "${PIGGY_TEST_FIB_PIN:-123456}" -K default -a rsa2048 generate 9d >/dev/null

  "$PIGGY" pass init -k "$FOREIGN_RECIPIENT"

  run "$PIGGY" pass recipients add --all-attached --yes
  assert_success
  assert_output --partial "Cannot encrypt to 1 attached card"
  assert_output --partial "Rsa"  # algorithm-name substring (Rsa2048, RsaP2048, etc.)
  assert_output --partial "nothing to add"
}
