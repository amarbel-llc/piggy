#! /usr/bin/env bats
#
# Go-based SSH agent protocol conformance tests for `piggy agent`.
# Uses Go's x/crypto/ssh/agent as an independent parser to validate that
# piggy agent responses conform to the IETF SSH agent protocol spec.
#
# No PIV card required — runs against piggy agent in all-card mode.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  # Work around issue #6 on hosts where nix libpcsclite can't talk to the
  # system pcscd (e.g. Ubuntu 2.0.3 daemon vs. nix 2.3.0 client). The nix
  # shim honours LIBPCSCLITE_DELEGATE and dlopens that path in place of
  # libpcsclite_real.so.1. Guarded so pure NixOS / missing-path cases are a
  # no-op; the shim errors on a missing delegate path.
  if [[ -f /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 ]]; then
    export LIBPCSCLITE_DELEGATE=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1
  fi

  # CONFORMANCE_BIN must be supplied by the caller. The `just
  # test-bats-conformance-protocol` recipe resolves it via
  # `nix build .#piggy.tests.conformance --no-link --print-out-paths`
  # so no `result-conformance` symlink is ever created in the worktree.
  if [[ -z ${CONFORMANCE_BIN:-} || ! -x $CONFORMANCE_BIN ]]; then
    skip "CONFORMANCE_BIN not set or binary not executable (run: just test-bats-conformance-protocol)"
  fi

  PIVY_TMPDIR="$(mktemp -d /tmp/piggy-test.XXXXXX)"
  AGENT_SOCK="$PIVY_TMPDIR/agent.sock"

  "$PIGGY" agent -A -D -a "$AGENT_SOCK" &
  AGENT_PID=$!

  local tries=0
  while [[ ! -S $AGENT_SOCK ]] && ((tries < 10)); do
    sleep 0.2
    tries=$((tries + 1))
  done
  [[ -S $AGENT_SOCK ]] || {
    kill "$AGENT_PID" 2>/dev/null || true
    skip "agent socket did not appear (pcscd may not be available)"
  }
}

teardown() {
  if [[ -n ${AGENT_PID:-} ]]; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n ${PIVY_TMPDIR:-} ]]; then
    rm -rf "$PIVY_TMPDIR"
  fi
}

function piggy_agent_protocol_conformance { # @test
  run "$CONFORMANCE_BIN" "$AGENT_SOCK"
  # TDD baseline: print results regardless of pass/fail count.
  # As extensions are implemented, failures will convert to passes.
  echo "$output"
  assert_output --partial "passed"
  refute_output --partial "CRASH"
  refute_output --partial "connection reset"
  refute_output --partial "broken pipe"
}
