#! /usr/bin/env bats
#
# piggy#299 — a sealed pigpen document opens through the real Rust
# `piggy agent`, with the ECDH done by the card behind it.
#
# This is the path a consumer of go/pkgs/pigpen + go/pkgs/agent takes to
# unlock a key sealed to a PIV recipient: pigpen.Document.Open with
# agent.AgentECDHOracle. The Go unit tests cover it against an in-process
# stand-in agent; here the agent is the real one and the card is fibby, so
# the reply framing, the PIN-on-demand unlock and the slot-9D ECDH are the
# shipped ones.
#
# Required env (supplied by the `test-bats-conformance-pigpen-open-fibby`
# recipe):
#   FIBBY_BIN=/path/to/fibby                           (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy                           (nix build .#default)
#   CONFORMANCE_BIN=/path/to/piggy-agent-conformance   (.#piggy.tests.conformance)
#
# When invoked via the conformance glob without those env vars set, the
# suite gracefully skips — same convention as piggy_agent_pin_on_demand.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-pigpen-open-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  if [[ -z ${CONFORMANCE_BIN:-} ]] || [[ ! -x ${CONFORMANCE_BIN:-/nonexistent} ]]; then
    skip "CONFORMANCE_BIN unset or not executable"
  fi

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456

  # Short-path workdir under /tmp — $BATS_TEST_TMPDIR can overrun AF_UNIX
  # sun_path's 108-byte limit under deep nix sandbox prefixes.
  WORKDIR="$(mktemp -d -t pigopen.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Spawn the Rust `piggy agent` pointed at fibby on the private AGENT_SOCK.
_spawn_rust_agent() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent -A -a "$AGENT_SOCK" \
    >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  cat "$AGENT_LOG" >&2 || true
  cat "$FIBBY_LOG" >&2 || true
  return 1
}

_dump_logs() {
  printf '%s\n' "$output" >&2
  echo "--- agent log tail ---" >&2
  tail -60 "$AGENT_LOG" >&2 || true
  echo "--- fibby log tail ---" >&2
  tail -60 "$FIBBY_LOG" >&2 || true
}

function pigpen_document_opens_through_the_rust_agent { # @test
  # Slot 9D only: the one P-256 key the agent lists is the ECDH key, so
  # the document can only have been opened by the card's slot-9D ECDH.
  spawn_fibby --seed-rfc5903-slot-9d-cert --seed-chuid
  _spawn_rust_agent

  run "$CONFORMANCE_BIN" pigpen-open "$AGENT_SOCK"
  [[ $status -eq 0 ]] || {
    echo "pigpen-open exited $status" >&2
    _dump_logs
    return 1
  }
  [[ $output == *"PASS: pigpen-open — sealed to 1 agent key(s)"* ]] || {
    echo "the round trip did not report sealing to exactly the slot-9D key" >&2
    _dump_logs
    return 1
  }
  [[ $output == *"PASS: pigpen-open (key not held)"* ]] || {
    echo "a document for a key the agent does not hold was not an agent error" >&2
    _dump_logs
    return 1
  }

  # The secret came from the card, not from anything in software.
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "fibby saw no successful slot-9D ECDH" >&2
    _dump_logs
    return 1
  }
}
