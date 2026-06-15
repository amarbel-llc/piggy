#! /usr/bin/env bats
# bats file_tags=hardware
#
# Conformance tier-2 tests for piggy pass recipients add --all-attached
# against a real virtual PIV card. Multi-card permutations (mixed
# supported+unsupported, dedup across N cards) live in the tier-1 mock
# bats at zz-tests_bats/t0610-recipients-add-attached.bats because both
# fib and fibby are single-card by construction; see amarbel-llc/piggy#83.
#
# Driven by `just test-bats-conformance-recipients-add-attached-fibby`
# (fibby, virtual slot 9D) — or the legacy fib recipe — which exports
# PCSCLITE_CSOCK_NAME and runs bats with --allow-local-binding plus the
# askpass safety net.
#
# Tests skip gracefully when the card env vars are absent.

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

# NOTE: the RSA-in-9D "unsupported card" case used to live here, re-keying
# slot 9D to RSA via `pivy-tool -a rsa2048 generate 9d`. It was dropped when
# this lane moved to fibby: fibby is P-256-only (GENERATE rejects RSA 0x07),
# and the rejection logic is already covered deterministically without a
# card — classify_slot_9d(Rsa2048) → Unsupported
# (crates/piggy-ids/tests/classify.rs::rsa_in_9d_is_unsupported),
# detect-all-pubkeys emits the unsupported line (piggy-ids main.rs tests),
# and `recipients add` reports "Cannot encrypt" (recipients.rs
# parse_detect_supported_and_unsupported). So the hardware confirmation was
# redundant. See the fib→fibby retirement plan + #176.
