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
