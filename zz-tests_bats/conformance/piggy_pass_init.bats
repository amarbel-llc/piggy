#! /usr/bin/env bats
# bats file_tags=hardware
#
# Conformance tier-2 tests for `piggy pass init`'s auto-detect path
# against the real fib virtual PIV card. The mock-driven coverage
# (declarative -k path, key shape validation, atomic write, mock
# detect-pubkey dispatch) lives at
# zz-tests_bats/t0002-init-piggy-ids.bats.
#
# Driven by `just test-bats-conformance-init` which brings up fib,
# generates a P-256 key in slot 9D, exports PCSCLITE_CSOCK_NAME, and
# runs bats with --allow-local-binding plus the askpass safety net.
#
# Tests skip gracefully when fib env vars are absent (same pattern
# as conformance/piggy_recipients_add_attached.bats).

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-init)"
  fi

  # Replace common.bash's mock-piggy-ids symlink with the real Rust
  # binary so detect-pubkey actually talks to the fib card via
  # piggy-piv. Scoped to BATS_TEST_TMPDIR.
  if [[ -x "$REPO_ROOT/target/debug/piggy-ids" ]]; then
    ln -sf "$REPO_ROOT/target/debug/piggy-ids" "$BATS_TEST_TMPDIR/piggy-ids"
  elif [[ -x "$REPO_ROOT/target/release/piggy-ids" ]]; then
    ln -sf "$REPO_ROOT/target/release/piggy-ids" "$BATS_TEST_TMPDIR/piggy-ids"
  else
    skip "piggy-ids binary not found (run: just build-rust)"
  fi

  # Test 2 calls `pivy-tool list` to discover the fib card's GUID.
  # The mock at helpers/mock-pivy-tool.sh is incomplete; remove the
  # mock symlink so the dev-shell pivy-tool (real C binary) is found.
  rm -f "$BATS_TEST_TMPDIR/pivy-tool"

  init_test_git

  # Pin the live card's markl ID for the asserts below. detect-pubkey
  # is now the REAL binary (via the symlink swap above), talking to
  # the fib card through pcscd.
  CARD_ID="$(piggy-ids detect-pubkey)"
  [[ -n $CARD_ID ]] || skip "piggy-ids detect-pubkey returned empty (no card?)"
  export CARD_ID
}

function init_no_args_auto_detects_attached_card { # @test
  run "$PIGGY" pass init
  assert_success
  assert_output --partial "Password store initialized"

  [[ -f "$PIGGY_STORE_DIR/piggy-ids" ]] || fail "piggy-ids not written"

  # Recipient line equals the live card's markl ID. Header lines are
  # asserted byte-for-byte by t0002 (mocked); here we focus on the
  # auto-detect path producing the live card's ID end-to-end.
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$CARD_ID"
}

function init_with_explicit_guid_auto_detects { # @test
  # Discover the fib card's GUID — pivy-tool prints uppercase, so the
  # grep must be case-insensitive. Mirrors the same dance in
  # test-bats-conformance-interop.
  local guid
  guid="$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)"
  [[ -n $guid ]] || skip "no GUID found from pivy-tool list"

  run "$PIGGY" pass init -g "$guid"
  assert_success
  assert_output --partial "Password store initialized"

  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$CARD_ID"
}
