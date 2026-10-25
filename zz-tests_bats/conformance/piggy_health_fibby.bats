#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#158 — `piggy health` all green against fibby and a Rust `piggy
# agent`, and the cross-check that fails when the agent serves no
# identities while a provisioned card is attached. The degraded paths (no
# pcscd, no agent socket) are zz-tests_bats/t0800-health.bats.
#
# The agent self-reports an absent service unit (--service-name), so the
# service point SKIPs instead of reading the host's own unit (piggy#243).
#
# Required env (supplied by `test-bats-conformance-health-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-health-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  WORKDIR="$(mktemp -d -t hlth.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_SOCK="$WORKDIR/a.sock"
  AGENT_LOG="$WORKDIR/agent.log"
  BLANK_SOCK="$WORKDIR/blank.comm"
  FIBBY_PID=
  BLANK_PID=
  AGENT_PID=

  # Health is PIN-free; the safety net still catches an escaped prompt.
  export SSH_ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  export SSH_ASKPASS_REQUIRE=force DISPLAY="" PIGGY_TEST_FIB_PIN=123456
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  for pid in "${AGENT_PID:-}" "${BLANK_PID:-}" "${FIBBY_PID:-}"; do
    [[ -n $pid ]] && kill "$pid" 2>/dev/null || true
  done
  for pid in "${AGENT_PID:-}" "${BLANK_PID:-}" "${FIBBY_PID:-}"; do
    [[ -n $pid ]] && wait "$pid" 2>/dev/null || true
  done
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
}

# Start a piggy agent on AGENT_SOCK talking to the PC/SC socket $1.
_spawn_agent_on() {
  PCSCLITE_CSOCK_NAME="$1" "$PIGGY_BIN" agent -A \
    --service-name piggy-agent-conformance-absent.service \
    -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  cat "$AGENT_LOG" >&2 || true
  return 1
}

# Run `piggy health ARGS` with the agent and the provisioned card.
_health() {
  PIGGY_AUTH_SOCK="$AGENT_SOCK" PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$PIGGY_BIN" health "$@"
}

_show() {
  printf '%s\n' "$output" >&2
  tail -30 "$AGENT_LOG" >&2 || true
}

function health_is_all_green_against_a_provisioned_card_and_its_agent { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert --seed-chuid
  _spawn_agent_on "$FIBBY_SOCK"

  _health --format tap
  [[ $status -eq 0 ]] || {
    echo "piggy health --format tap exited $status" >&2
    _show
    return 1
  }
  if grep -q '^not ok ' <<<"$output"; then
    echo "a health point failed:" >&2
    _show
    return 1
  fi
  for point in \
    "agent: socket resolved" \
    "agent: socket exists" \
    "agent: answers request_identities" \
    "agent: advertises ecdh extension" \
    "pcsc: daemon reachable" \
    "card: PIV card attached" \
    "card: key-management slot 9D populated" \
    "agent serves attached card"; do
    grep -E "^ok [0-9]+ - $point\$" <<<"$output" >/dev/null || {
      echo "point not passed (or skipped): $point" >&2
      _show
      return 1
    }
  done

  _health --format ndjson
  [[ $status -eq 0 ]] || {
    echo "piggy health --format ndjson exited $status" >&2
    _show
    return 1
  }
  local summary
  summary=$(grep '"type":"summary"' <<<"$output") || {
    echo "no summary record" >&2
    _show
    return 1
  }
  [[ $summary == *'"failed":0'* && $summary == *'"valid":true'* ]] || {
    echo "summary is not all green: $summary" >&2
    return 1
  }
}

# The agent serves a blank card (no identities) while health sees the
# provisioned one: the cross-check fails with the restart hint.
function agent_with_no_identities_beside_a_provisioned_card_fails_the_cross_check { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert --seed-chuid
  FIBBY_LOG=info "$FIBBY_BIN" --socket "$BLANK_SOCK" --backend virtual \
    >"$WORKDIR/blank.log" 2>&1 3>&- &
  BLANK_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $BLANK_SOCK ]] && break
    sleep 0.1
  done
  _spawn_agent_on "$BLANK_SOCK"

  _health --format tap
  [[ $status -ne 0 ]] || {
    echo "piggy health passed although the agent serves no identities" >&2
    _show
    return 1
  }
  grep -E '^not ok [0-9]+ - agent serves attached card' <<<"$output" >/dev/null || {
    echo "the cross-check point did not fail" >&2
    _show
    return 1
  }
  grep -q 'restart piggy-agent' <<<"$output" || {
    echo "the failure does not carry the restart hint" >&2
    _show
    return 1
  }
}
