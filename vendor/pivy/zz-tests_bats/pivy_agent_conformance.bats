#! /usr/bin/env bats
#
# Go-based SSH agent conformance tests.
# Uses Go's x/crypto/ssh/agent as an independent parser to validate that
# pivy-agent responses conform to the IETF SSH agent protocol spec.
#
# No PIV card required — runs against pivy-agent in all-card mode.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  PIVY_DIR="${PIVY_DIR:-$(dirname "$BATS_TEST_FILE")/../result}"
  CONFORMANCE_DIR="${CONFORMANCE_DIR:-$(dirname "$BATS_TEST_FILE")/../result-conformance}"
  PIVY_AGENT="$PIVY_DIR/bin/pivy-agent"
  CONFORMANCE_BIN="$CONFORMANCE_DIR/bin/pivy-agent-conformance"

  if [[ ! -x $PIVY_AGENT ]]; then
    skip "pivy not found at $PIVY_DIR (run: nix build)"
  fi
  if [[ ! -x $CONFORMANCE_BIN ]]; then
    skip "conformance binary not found (run: nix build .#pivy-agent-conformance -o result-conformance)"
  fi

  PIVY_TMPDIR="$(mktemp -d /tmp/pivy-test.XXXXXX)"
  AGENT_SOCK="$PIVY_TMPDIR/agent.sock"

  "$PIVY_AGENT" -A -D -a "$AGENT_SOCK" &
  AGENT_PID=$!

  local tries=0
  while [[ ! -S $AGENT_SOCK ]] && ((tries < 10)); do
    sleep 0.2
    tries=$((tries + 1))
  done
  [[ -S $AGENT_SOCK ]] || {
    kill "$AGENT_PID" 2>/dev/null || true
    skip "agent socket did not appear"
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

function go_conformance_tests_pass { # @test
  run "$CONFORMANCE_BIN" "$AGENT_SOCK"
  assert_success
  assert_output --partial "passed"
  refute_output --partial "FAIL"
}
