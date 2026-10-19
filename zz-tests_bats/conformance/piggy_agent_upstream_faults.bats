#! /usr/bin/env bats
#
# piggy#326 — a proxying `piggy agent` facing a broken upstream must stay up
# and keep its descriptors. On a fleet host a proxy-only agent hit an
# upstream that accepted and closed at once, ran out of descriptors within
# about 120 ms (`Too many open files`) and exited, taking every key it
# fronted with it.
#
# The stacks here need no card: `piggy agent --proxy-only` against
#   - an upstream that accepts every connection and closes it at once
#     (python3), listed hundreds of times;
#   - a second proxy-only agent that proxies back to the first, so every
#     listing loops between the two (the shape that exhausts descriptors
#     fastest), run under a low descriptor limit;
#   - its own socket named as an upstream, which must be refused at start.
# The client is a few lines of python3 speaking the agent protocol's
# REQUEST_IDENTITIES, so the lane needs no OpenSSH.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  command -v python3 >/dev/null || skip "python3 not on PATH"
  [[ -d /proc/self/fd ]] || skip "needs /proc to count an agent's descriptors"

  # Short-path workdir under /tmp: AF_UNIX sun_path is 108 bytes.
  WORKDIR="$(mktemp -d -t agfault.XXXXXX)"
  PIDS=()
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  local pid
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# An upstream at SOCK that accepts every connection and closes it at once.
_spawn_closing_upstream() {
  local sock="$1"
  python3 -c '
import os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(64)
while True:
    conn, _ = s.accept()
    conn.close()
' "$sock" &
  PIDS+=($!)
  _wait_for_socket "$sock"
}

# Start `piggy agent --proxy-only -a SOCK` with the given --upstream specs,
# its pid in AGENT_PID. NOFILE, when set, is the descriptor limit it runs
# under. PCSCLITE_CSOCK_NAME points nowhere: a proxy-only agent never opens
# PC/SC.
_spawn_proxy() {
  local sock="$1" log="$2"
  shift 2
  local args=() spec
  for spec in "$@"; do args+=(--upstream "$spec"); done
  (
    [[ -n ${NOFILE:-} ]] && ulimit -n "$NOFILE"
    exec env PCSCLITE_CSOCK_NAME="$WORKDIR/no-such-pcscd" \
      "$PIGGY" agent --proxy-only --agent-timeout 2 "${args[@]}" -a "$sock"
  ) >"$log" 2>&1 &
  AGENT_PID=$!
  PIDS+=("$AGENT_PID")
}

_wait_for_socket() {
  local sock="$1" _
  for _ in $(seq 1 100); do
    [[ -S $sock ]] && return 0
    sleep 0.05
  done
  echo "socket never appeared at $sock" >&2
  return 1
}

# Ask the agent at SOCK for its identities COUNT times, one connection each;
# prints how many answered. Each answer must be a well-formed
# IDENTITIES_ANSWER (type 12) or a FAILURE (type 5); anything else, or no
# answer within the timeout, stops the loop.
_list_identities() {
  local sock="$1" count="${2:-1}"
  python3 -c '
import socket, struct, sys
sock, count = sys.argv[1], int(sys.argv[2])
answered = 0
for _ in range(count):
    c = socket.socket(socket.AF_UNIX)
    c.settimeout(10)
    c.connect(sock)
    c.sendall(struct.pack(">IB", 1, 11))
    head = c.recv(5, socket.MSG_WAITALL)
    c.close()
    if len(head) < 5 or head[4] not in (5, 12):
        break
    answered += 1
print(answered)
' "$sock" "$count"
}

_open_descriptors() {
  find "/proc/$1/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l
}

_assert_alive() {
  local pid="$1" what="$2" log="$3"
  kill -0 "$pid" 2>/dev/null || {
    echo "$what exited; its log:" >&2
    cat "$log" >&2 || true
    return 1
  }
}

function closing_upstream_neither_leaks_descriptors_nor_kills_the_proxy { # @test
  _spawn_closing_upstream "$WORKDIR/flap.sock"
  _spawn_proxy "$WORKDIR/p.sock" "$WORKDIR/p.log" "flap=$WORKDIR/flap.sock"
  _wait_for_socket "$WORKDIR/p.sock"

  [[ $(_list_identities "$WORKDIR/p.sock") == 1 ]] || {
    echo "the proxy did not answer a first listing" >&2
    cat "$WORKDIR/p.log" >&2
    return 1
  }
  local before after answered
  before=$(_open_descriptors "$AGENT_PID")
  answered=$(_list_identities "$WORKDIR/p.sock" 300)
  after=$(_open_descriptors "$AGENT_PID")

  _assert_alive "$AGENT_PID" "the proxy" "$WORKDIR/p.log"
  [[ $answered == 300 ]] || {
    echo "only $answered of 300 listings were answered" >&2
    return 1
  }
  ((after < before + 20)) || {
    echo "300 listings against a closing upstream took the proxy's descriptors from $before to $after" >&2
    return 1
  }
}

function an_upstream_cycle_neither_exhausts_descriptors_nor_kills_the_proxy { # @test
  # A proxies to B and B to A, under a limit a cycle without a bound runs
  # through at once: every hop holds sockets open while it waits on the next.
  NOFILE=256 _spawn_proxy "$WORKDIR/a.sock" "$WORKDIR/a.log" "b=$WORKDIR/b.sock"
  local a_pid="$AGENT_PID"
  NOFILE=256 _spawn_proxy "$WORKDIR/b.sock" "$WORKDIR/b.log" "a=$WORKDIR/a.sock"
  local b_pid="$AGENT_PID"
  _wait_for_socket "$WORKDIR/a.sock"
  _wait_for_socket "$WORKDIR/b.sock"

  [[ $(_list_identities "$WORKDIR/a.sock") == 1 ]] || {
    echo "a listing through the cycle got no answer" >&2
    cat "$WORKDIR/a.log" "$WORKDIR/b.log" >&2
    return 1
  }
  _assert_alive "$a_pid" "agent A" "$WORKDIR/a.log"
  _assert_alive "$b_pid" "agent B" "$WORKDIR/b.log"
  if grep -q 'Too many open files' "$WORKDIR/a.log" "$WORKDIR/b.log"; then
    echo "the cycle ran an agent out of descriptors:" >&2
    grep -h 'Too many open files' "$WORKDIR/a.log" "$WORKDIR/b.log" | head -5 >&2
    return 1
  fi
  # And both still answer afterwards.
  [[ $(_list_identities "$WORKDIR/b.sock" 3) == 3 ]] || {
    echo "agent B stopped answering after the cycle" >&2
    return 1
  }
}

function an_upstream_at_the_agents_own_socket_is_refused { # @test
  run env PCSCLITE_CSOCK_NAME="$WORKDIR/no-such-pcscd" \
    "$PIGGY" agent --proxy-only --upstream "self=$WORKDIR/own.sock" -a "$WORKDIR/own.sock"
  [[ $status -ne 0 ]] || {
    echo "an agent proxying to its own socket started" >&2
    return 1
  }
  [[ $output == *"own socket"* ]] || {
    echo "the refusal does not say why: $output" >&2
    return 1
  }
}
