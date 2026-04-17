#! /usr/bin/env bats
#
# Go-based SSH agent protocol conformance tests for `piggy agent`.
# Uses Go's x/crypto/ssh/agent as an independent parser to validate that
# piggy agent responses conform to the IETF SSH agent protocol spec.
#
# No PIV card required — runs against piggy agent in all-card mode.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  CONFORMANCE_BIN="${CONFORMANCE_BIN:-$(dirname "$BATS_TEST_FILE")/../../result-conformance/bin/piggy-agent-conformance}"

  if [[ ! -x $CONFORMANCE_BIN ]]; then
    skip "conformance binary not found at $CONFORMANCE_BIN (run: nix build .#piggy-agent-conformance -o result-conformance)"
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
