# Shared fibby + pivy-agent lifecycle helpers for the conformance lane.
#
# Consumers `load` this from setup() after setting:
#   FIBBY_BIN  / PIVY_AGENT          — binaries (from the just recipe env)
#   FIBBY_SOCK / FIBBY_LOG           — fibby's pcscd.comm socket + wire log
#   AGENT_SOCK / AGENT_LOG           — pivy-agent socket + log
#   WORKDIR                          — short /tmp dir (AF_UNIX sun_path limit)
# and having exported the test askpass env (SSH_ASKPASS / SSH_ASKPASS_REQUIRE
# / DISPLAY). spawn_fibby/spawn_agent set FIBBY_PID/AGENT_PID for teardown.

# Spawn fibby in the virtual backend on the per-test socket. Tracing is set
# to `wire` so callers can grep the trace. Extra args (e.g.
# `--seed-rfc5903-slot-9d-cert`) pass through verbatim after the standard
# `--socket` / `--backend` flags.
spawn_fibby() {
  FIBBY_LOG=wire "$FIBBY_BIN" --socket "$FIBBY_SOCK" --backend virtual "$@" \
    >"$FIBBY_LOG" 2>&1 &
  FIBBY_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $FIBBY_SOCK ]] && return 0
    sleep 0.1
  done
  echo "fibby socket never appeared at $FIBBY_SOCK" >&2
  echo "--- fibby log ---" >&2
  cat "$FIBBY_LOG" >&2 || true
  return 1
}

# Bring up ONE seeded virtual card for the calling test, inside or outside
# the nix sandbox (piggy#281), and point PC/SC clients at it:
#
#   fibby_up [extra fibby args…]   # default seed: --seed-rfc5903-slot-9d-cert
#   fibby_down                     # from teardown()
#
# Resolves FIBBY_BIN (the lane injects it; local runs fall back to
# target/debug/fibby), skips where an AF_UNIX socket cannot be bound
# (darwin sandbox, piggy#208), keeps the socket under a SHORT /tmp dir
# (sun_path limit), and exports PCSCLITE_CSOCK_NAME + FIBBY_SOCK/FIBBY_LOG
# for the test. The default card's PIN is 123456, which the test askpass
# supplies through PIGGY_TEST_FIB_PIN; callers export the askpass env
# themselves (piggy-testing(7) PIN PROMPT SAFETY NET) — pointing
# SSH_ASKPASS at a `piggy_install_helper_as` copy, because the helper's
# `/usr/bin/env` shebang does not resolve inside the nix sandbox.
fibby_up() {
  if [[ -z ${FIBBY_BIN:-} ]]; then
    if [[ -x $REPO_ROOT/target/debug/fibby ]]; then
      FIBBY_BIN="$REPO_ROOT/target/debug/fibby"
    else
      skip "FIBBY_BIN unset and target/debug/fibby not built (just build-rust)"
    fi
  fi
  [[ -x $FIBBY_BIN ]] || skip "FIBBY_BIN ($FIBBY_BIN) not executable"
  # Only darwin denies AF_UNIX bind in its sandbox (piggy#208); the Linux
  # nix sandbox allows it, and the probe needs python3, which the local
  # devShell does not carry — so gate the probe on the platform.
  if [[ $(uname -s) == Darwin ]]; then
    skip_unless_af_unix_bind
  fi
  # /tmp keeps the socket path short (sun_path); the nix sandbox has a
  # writable /tmp too, but fall back to TMPDIR if it ever does not.
  local base=/tmp
  [[ -w /tmp ]] || base="${TMPDIR:-/tmp}"
  FIBBY_WORKDIR="$(mktemp -d "$base/pf.XXXXXX")"
  FIBBY_SOCK="$FIBBY_WORKDIR/pcscd.comm"
  FIBBY_LOG="$FIBBY_WORKDIR/fibby.log"
  export FIBBY_WORKDIR FIBBY_SOCK FIBBY_LOG
  if [[ $# -eq 0 ]]; then
    set -- --seed-rfc5903-slot-9d-cert
  fi
  spawn_fibby "$@" || fail "fibby did not come up"
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"
}

fibby_down() {
  if [[ -n ${FIBBY_PID:-} ]]; then
    kill "$FIBBY_PID" 2>/dev/null || true
    wait "$FIBBY_PID" 2>/dev/null || true
  fi
  [[ -n ${FIBBY_WORKDIR:-} ]] && rm -rf "$FIBBY_WORKDIR"
  return 0
}

# Spawn pivy-agent pointing at fibby's pcscd.comm socket. -A (all cards) so
# we don't have to predict a GUID; -D for foreground; -a for the private
# socket.
spawn_agent() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    "$PIVY_AGENT" -A -D -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  echo "--- fibby log ---" >&2
  cat "$FIBBY_LOG" >&2 || true
  return 1
}
