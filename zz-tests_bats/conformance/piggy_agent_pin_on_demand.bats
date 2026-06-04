#! /usr/bin/env bats
#
# piggy#58 — prompt-on-demand PIN entry parity between the C `pivy-agent`
# and the Rust `piggy agent`.
#
# The agent must prompt for the PIV PIN ON DEMAND via SSH_ASKPASS when a
# decrypt needs a PIN and none has been pushed via `ssh-add -X`. The C
# pivy-agent does this ("get PIN at first use"); the Rust agent grows the
# same behavior in piggy#58. This file pins the behavior against the C
# agent first (the baseline) so the Rust impl can be held to it.
#
# The scenario is the slot-9D ECDH decrypt path, hardware-free over fibby:
# seed fibby's 9D slot, start the agent WITHOUT pre-seeding a PIN, then run
# `piggy pass show` routed at the agent via PIGGY_AUTH_SOCK. The decrypt
# reaches the agent's ecdh-rebox handler, which — with no cached PIN —
# must fork SSH_ASKPASS. The test askpass supplies the VirtualCard default
# PIN (123456) non-interactively, so a successful decrypt proves the
# on-demand prompt fired and was answered.
#
# Required env (supplied by the
# `test-bats-conformance-agent-pin-on-demand` recipe):
#   PIVY_AGENT=/path/to/pivy-agent  (nix build .#pivy)
#   FIBBY_BIN=/path/to/fibby        (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy        (nix build .#default — real pivy-box)
#
# When invoked via the conformance glob without those env vars set, the
# suite gracefully skips — same convention as piggy_fibby_pivy_agent_smoke.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${PIVY_AGENT:-} ]] || [[ ! -x ${PIVY_AGENT:-/nonexistent} ]]; then
    skip "PIVY_AGENT unset or not executable; run via just test-bats-conformance-agent-pin-on-demand"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  # PIGGY_TEST_FIB_PIN is set per-test (the scenario legitimately reaches a
  # PIN-gated path and supplies the VirtualCard PIN through the test askpass).

  # Short-path workdir under /tmp — $BATS_TEST_TMPDIR can overrun AF_UNIX
  # sun_path's 108-byte limit under deep nix sandbox prefixes.
  WORKDIR="$(mktemp -d -t agpod.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  # No ambient agent / decrypt-socket bleed-through: the scenario must drive
  # the decrypt at OUR agent (via PIGGY_AUTH_SOCK), and init/insert must talk
  # to fibby directly (via PCSCLITE_CSOCK_NAME), never an ambient agent.
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

# Spawn an agent (C pivy-agent or Rust `piggy agent`) pointed at fibby,
# binding the private AGENT_SOCK. $@ is the agent command + flags, sans
# `-a <socket>` (appended here). Both agents honor -A (all cards) and -a.
_spawn_agent_cmd() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$@" -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 &
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

# Drive the prompt-on-demand decrypt scenario against the agent spawned by
# the given command. Asserts the decrypt succeeds via an on-demand askpass
# prompt (NOT a pre-pushed PIN): the secret round-trips, fibby's slot-9D GA
# ECDH ran, the test askpass actually supplied a PIN (so the prompt fired),
# and the agent never hit the refusal path or died.
_pin_on_demand_scenario() {
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert
  _spawn_agent_cmd "$@"

  local store="$WORKDIR/store"
  local secret="pin-on-demand-secret"

  # init + insert talk to fibby directly (pubkey read + offline encrypt): no
  # agent, no PIN. Gitless store -> the post-write commit is skipped.
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  printf '%s\n' "$secret" | PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_STORE_DIR="$store" "$PIGGY_BIN" pass insert -e foo/bar
  local ins=$?
  [[ $ins -eq 0 && -f "$store/foo/bar.ebox" ]] || {
    echo "piggy pass insert exited $ins (ebox present: $([[ -f $store/foo/bar.ebox ]] && echo yes || echo no))" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The crux: NO `ssh-add -X` here. With no cached PIN, the decrypt's rebox
  # against the agent must trigger an on-demand SSH_ASKPASS prompt, which the
  # test askpass answers with PIGGY_TEST_FIB_PIN.
  PIGGY_AUTH_SOCK="$AGENT_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass show foo/bar
  [[ $status -eq 0 ]] || {
    echo "piggy pass show exited $status (prompt-on-demand decrypt failed)" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
  # `run` merges pivy-box's stderr into $output; assert the secret as a line.
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "decrypt output missing the secret line '$secret'" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }

  # The on-demand prompt actually fired: the test askpass supplied a PIN.
  # (If the PIN had been pre-pushed via ssh-add -X, no askpass would run.)
  grep -q "\[piggy-test-askpass\] supplying" "$AGENT_LOG" || {
    echo "no on-demand askpass invocation in agent log (PIN was not prompted)" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  # ...and it must not have hit the refusal path.
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
  # The GA ECDH must have reached fibby's slot 9D and returned 9000, and the
  # agent must still be alive.
  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "agent died during the prompt-on-demand decrypt" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9D GA ECDH in fibby trace" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
}

# Baseline: the C pivy-agent prompts for the PIN on demand via SSH_ASKPASS
# and completes the slot-9D decrypt. This is the behavior the Rust agent
# must match (piggy#58).
function c_pivy_agent_prompts_for_pin_on_demand_via_askpass { # @test
  _pin_on_demand_scenario "$PIVY_AGENT" -A -D
}

# Parity: the Rust `piggy agent` (now on the dispatch path, piggy#58) must
# match the C baseline — prompt for the PIN on demand and complete the
# slot-9D decrypt — AND additionally propagate request context to the
# askpass child via PIGGY_ASKPASS_CONTEXT (#33/#35), plus spawn the
# card-presence probe loop (piggy#59).
function rust_piggy_agent_prompts_on_demand_and_propagates_context { # @test
  _pin_on_demand_scenario "$PIGGY_BIN" agent -A

  # piggy#58: unlike the C agent, the Rust agent sets PIGGY_ASKPASS_CONTEXT
  # when it forks askpass; the test askpass echoes it into its banner.
  grep -q "context: piggy-agent:ecdh-rebox" "$AGENT_LOG" || {
    echo "Rust agent did not propagate PIGGY_ASKPASS_CONTEXT to the askpass child" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }

  # piggy#59: the card-presence probe loop is spawned for the primary card.
  grep -q "spawning card-presence probe loop" "$AGENT_LOG" || {
    echo "Rust agent did not spawn the card-presence probe loop" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
}

# piggy#142: a wrong PIN entered at the on-demand prompt must re-prompt within
# the same operation (C-parity bounded retry), not fail the decrypt outright.
# The wrong-first askpass hands out a bad PIN on the first call and the correct
# one on the second; the decrypt should still succeed.
function rust_piggy_agent_retries_on_wrong_pin { # @test
  export PIGGY_TEST_FIB_PIN=123456
  export PIGGY_TEST_ASKPASS_MARKER="$WORKDIR/askpass-marker"
  export SSH_ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass-wrong-first.sh"
  [[ -x $SSH_ASKPASS ]] || skip "piggy-test-askpass-wrong-first.sh not found at $SSH_ASKPASS"

  spawn_fibby --seed-rfc5903-slot-9d-cert
  _spawn_agent_cmd "$PIGGY_BIN" agent -A

  local store="$WORKDIR/store"
  local secret="retry-on-wrong-pin"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$secret" | PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_STORE_DIR="$store" "$PIGGY_BIN" pass insert -e foo/bar
  local ins=$?
  [[ $ins -eq 0 && -f "$store/foo/bar.ebox" ]] || {
    echo "piggy pass insert exited $ins" >&2
    return 1
  }

  # First prompt supplies a WRONG PIN; the agent must re-prompt and the second
  # (correct) PIN must complete the decrypt.
  PIGGY_AUTH_SOCK="$AGENT_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass show foo/bar
  [[ $status -eq 0 ]] || {
    echo "piggy pass show exited $status (no retry after wrong PIN?)" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "decrypt output missing the secret line '$secret'" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }

  # Both prompts must have fired: the wrong one first, then the correct retry.
  # (Guards against a trivially-green test that never supplied the wrong PIN.)
  grep -q "supplying WRONG PIN" "$AGENT_LOG" || {
    echo "the wrong PIN was never supplied — test did not exercise the retry path" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  grep -q "supplying correct PIN" "$AGENT_LOG" || {
    echo "the agent did not re-prompt with the correct PIN after the wrong one" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9D GA ECDH after the retry" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
}
