#! /usr/bin/env bats
#
# piggy#213 — a burst of concurrent SSH SIGN requests against the Rust
# `piggy agent` must ALL succeed (serially is fine), never mass-fail with
# "agent refused operation".
#
# Field repro: eng's `just update-repos` fans out ~18 parallel `git pull`s,
# each authenticating over SSH via the agent's slot-9A key. Most of the
# burst got SSH_AGENT_FAILURE while serial operations succeeded 100% of
# the time. Cause: the agent handled each request's card work (fresh PCSC
# connect, SELECT PIV, CHUID read, txn, VERIFY, GA SIGN, ResetCard
# disposition) with no cross-request serialization, so concurrent
# requests raced each other's card state and errored instead of queueing.
#
# The scenario here is the same shape, hardware-free over fibby: seed
# fibby's slot 9A (RFC 6979 P-256) + CHUID, start the Rust agent, warm it
# up with one serial sign (proves the stack; caches the PIN so the burst
# measures card contention, not prompt serialization), then fire an
# N-wide simultaneous `ssh-keygen -Y sign -U` burst. Every signer must
# exit 0 and every signature must verify.
#
# Required env (supplied by the
# `test-bats-conformance-agent-concurrent-sign` recipe):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)
#
# When invoked via the conformance glob without those env vars set, the
# suite gracefully skips — same convention as piggy_agent_pin_on_demand.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-agent-concurrent-sign"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456

  # Short-path workdir under /tmp — $BATS_TEST_TMPDIR can overrun AF_UNIX
  # sun_path's 108-byte limit under deep nix sandbox prefixes.
  WORKDIR="$(mktemp -d -t agburst.XXXXXX)"
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
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  echo "--- fibby log ---" >&2
  cat "$FIBBY_LOG" >&2 || true
  return 1
}

# All N members of a simultaneous SIGN burst must succeed. Before the
# piggy#213 fix, most of the burst failed ("agent refused operation")
# because concurrent requests raced each other's unserialized card
# sessions; the agent must instead queue them and complete every one.
function rust_piggy_agent_serves_concurrent_sign_burst { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-chuid
  _spawn_rust_agent
  export SSH_AUTH_SOCK="$AGENT_SOCK"

  # The agent's advertised slot-9A public key.
  run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status; expected the 9A identity" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep '^ecdsa-sha2-nistp256 ' >"$WORKDIR/id.pub"
  [[ -s $WORKDIR/id.pub ]] || {
    echo "no ecdsa-sha2-nistp256 identity in ssh-add -L output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  local ktype kdata _rest
  read -r ktype kdata _rest <"$WORKDIR/id.pub"
  printf 'burst@fibby %s %s\n' "$ktype" "$kdata" >"$WORKDIR/allowed_signers"

  # Warmup: one serial sign must succeed (proves the whole stack works
  # outside contention) and caches the PIN via the on-demand askpass, so
  # the burst below measures card contention, not prompt serialization.
  echo "warmup" >"$WORKDIR/warmup"
  run ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/warmup"
  [[ $status -eq 0 && -f $WORKDIR/warmup.sig ]] || {
    echo "serial warmup sign failed (status $status) — stack broken before concurrency" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The burst: N simultaneous SIGN requests, mirroring a parallel
  # multi-repo git fan-out. Every one must eventually succeed.
  local n=12
  local -a pids=()
  local i
  for i in $(seq 1 "$n"); do
    echo "burst-payload-$i" >"$WORKDIR/data$i"
  done
  for i in $(seq 1 "$n"); do
    ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/data$i" \
      >"$WORKDIR/sign$i.log" 2>&1 &
    pids+=("$!")
  done

  local fails=0
  for i in $(seq 1 "$n"); do
    if ! wait "${pids[i - 1]}"; then
      fails=$((fails + 1))
      echo "--- signer $i failed ---" >&2
      cat "$WORKDIR/sign$i.log" >&2 || true
    fi
  done
  [[ $fails -eq 0 ]] || {
    echo "$fails/$n concurrent signs failed (piggy#213 mass-refusal)" >&2
    echo "--- agent log tail ---" >&2
    tail -80 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # Every signature must exist and verify — success means real card
  # crypto, not a blank exit status.
  for i in $(seq 1 "$n"); do
    [[ -f "$WORKDIR/data$i.sig" ]] || {
      echo "signer $i exited 0 but produced no signature file" >&2
      return 1
    }
    ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I "burst@fibby" \
      -n file -s "$WORKDIR/data$i.sig" <"$WORKDIR/data$i" >/dev/null 2>&1 || {
      echo "signature $i does not verify against the 9A key" >&2
      return 1
    }
  done

  # The agent must have survived the burst.
  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "agent died during the concurrent burst" >&2
    tail -80 "$AGENT_LOG" >&2 || true
    return 1
  }

  # Belt-and-suspenders: warmup + all N burst signs reached fibby's
  # slot-9A GA ECDSA handler and returned 9000.
  local signs
  signs=$(grep -c "GA ECDSA 9A -> 9000" "$FIBBY_LOG" || true)
  [[ $signs -ge $((n + 1)) ]] || {
    echo "expected >= $((n + 1)) successful GA ECDSA 9A signs in fibby trace, saw $signs" >&2
    tail -120 "$FIBBY_LOG" >&2 || true
    return 1
  }
}
