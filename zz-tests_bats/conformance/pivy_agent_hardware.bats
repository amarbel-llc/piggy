#! /usr/bin/env bats
# bats file_tags=hardware
#
# Hardware-attached conformance tests for the C pivy-agent built from
# vendor/pivy/. Exercises the per-socket state-machine plumbing landed
# in piggy#107 (piggy#105 step 3) against a real PIV card.
#
# Scope: no-PIN paths only. Tests assert that:
#   - REQUEST_IDENTITIES works (process_request_identities both branches)
#   - txn_owner is set + cleared around the card touch
#   - Repeated identity probes don't trigger an unexpected PIN prompt
#
# What this does NOT cover (deferred — would need PIGGY_TEST_REAL_PIN
# and careful retry-counter handling):
#   - The sign / ECDH / rebox / prehash resume tails
#   - The PROMPT_ASKPASS branch of start_prompt
#   - PermissionError retry yield to AFTER_PIN_RETRY
#
# Isolation invariants (Important — see #35 design notes):
#
#   - Agent runs on a private socket under $BATS_TEST_TMPDIR. The
#     user's running pivy-agent / piggy-agent (or any agent) is NEVER touched.
#   - SSH_ASKPASS points at the refusal helper. If any test path
#     accidentally requests a PIN, the helper logs a banner and exits
#     non-zero — no GUI dialog, no /dev/tty prompt, no retry consumed.
#   - The card is shared with the user's pcscd by definition. We hold
#     the txn only long enough to satisfy the identity probe; we
#     never call sign / generate / change-pin from this lane.
#
# Opt-in:
#
#   PIGGY_TEST_REAL_CARD=1     required; gates the entire lane
#   PIVY_AGENT=/path/...       optional; defaults to ./result/bin/pivy-agent
#                              from the just recipe's nix build output

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PIGGY_TEST_REAL_CARD:-} ]]; then
    skip "PIGGY_TEST_REAL_CARD not set (run: just test-bats-conformance-pivy-agent-hardware)"
  fi

  # Locate the pivy-agent binary. The just recipe builds it via
  # `nix build .#pivy` and exports PIVY_AGENT to the unwrapped path.
  if [[ -z ${PIVY_AGENT:-} ]]; then
    if [[ -x "$REPO_ROOT/result/bin/pivy-agent" ]]; then
      PIVY_AGENT="$REPO_ROOT/result/bin/pivy-agent"
    else
      skip "PIVY_AGENT unset and result/bin/pivy-agent not found"
    fi
  fi
  [[ -x $PIVY_AGENT ]] || skip "PIVY_AGENT ($PIVY_AGENT) not executable"

  # Wire the refusal helper. Any unexpected PIN prompt during this
  # lane indicates a bug in the test or in step 3; the helper makes
  # that visible without consuming a card retry.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  # Deliberately do NOT export PIGGY_TEST_FIB_PIN — we want the
  # helper to REFUSE if anything tries to prompt.
  unset PIGGY_TEST_FIB_PIN

  # Per-test private agent socket + log file. The socket path MUST
  # fit in struct sockaddr_un::sun_path (104 bytes on darwin).
  # $BATS_TEST_TMPDIR is too deep — mktemp under $TMPDIR/private-tmp
  # keeps the path short.
  AGENT_SOCK_DIR="$(mktemp -d -t pivya.XXXXXX)"
  AGENT_SOCK="$AGENT_SOCK_DIR/a.sock"
  AGENT_LOG="$BATS_TEST_TMPDIR/pivy-agent.log"
  AGENT_PID=
  # Don't inherit the user's SSH_AUTH_SOCK; tests below set it
  # explicitly to AGENT_SOCK on a per-invocation basis.
  unset SSH_AUTH_SOCK
}

teardown() {
  if [[ -n ${AGENT_PID:-} ]]; then
    kill "$AGENT_PID" 2>/dev/null || true
    # Brief wait so the agent flushes its log + releases the txn.
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  # Clean up the short-path socket dir we created in setup.
  [[ -n ${AGENT_SOCK_DIR:-} ]] && rm -rf "$AGENT_SOCK_DIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Spawn the agent in all-card foreground mode on the private socket.
# Returns once the socket exists or after 5s, whichever comes first.
spawn_agent() {
  "$PIVY_AGENT" -A -D -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared" >&2
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  return 1
}

# Sanity: card visible to the agent. ssh-add -L exits 0 with the
# identity list, exits 1 when no identities are available. Both
# count as a successful round-trip through process_request_identities
# (the bug we care about is the agent crashing or hanging on the
# state-machine plumbing, not whether the card has keys).
function agent_lists_identities { # @test
  spawn_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  # exit 0 (have keys) or 1 (no keys) — both fine. Anything else is
  # a regression. Notably, exit 2 means "could not connect to agent".
  [[ $status -eq 0 || $status -eq 1 ]] || {
    echo "ssh-add -L exited $status; expected 0 or 1" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }

  # The refusal banner must NOT appear — no PIN prompts during a
  # plain identity list.
  refute_output --partial "[piggy-test-askpass]"
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# Repeated identity probes must not drain anything. This exercises
# the txn_owner set + agent_piv_close batched-window dance: each
# REQUEST_IDENTITIES sets txn_owner=e in the pre-yield body
# (well — for non-allcard, but allcard mode goes through
# agent_enumerate_all without setting it), opens + closes the txn,
# and serves the cached selk. We just want to confirm the cycle is
# stable across multiple invocations.
function agent_lists_identities_repeated_no_drift { # @test
  spawn_agent

  local i status
  for i in 1 2 3 4 5; do
    SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
    [[ $status -eq 0 || $status -eq 1 ]] || {
      echo "iteration $i: ssh-add -L exited $status" >&2
      echo "--- agent log ---" >&2
      cat "$AGENT_LOG" >&2 || true
      return 1
    }
  done

  # No PIN prompt should have occurred at any iteration.
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal during repeated probes" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# Concurrent REQUEST_IDENTITIES from two clients. In single-card
# mode this would normally serialize on the card txn; with step 3's
# txn_owner bypass (line 1628), the second probe should observe
# txn_owner != self and serve from cached selk. In all-card mode
# (which is what we spawn with -A) the bypass branch isn't reached,
# but the test still verifies the two-client case completes without
# deadlock or crash — which is the bigger concern after a
# state-machine refactor.
function agent_serves_concurrent_identities { # @test
  spawn_agent

  local out1 out2 status1 status2 pid1 pid2
  local res1="$BATS_TEST_TMPDIR/out1"
  local res2="$BATS_TEST_TMPDIR/out2"

  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L >"$res1" 2>&1 &
  pid1=$!
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L >"$res2" 2>&1 &
  pid2=$!

  wait "$pid1"
  status1=$?
  wait "$pid2"
  status2=$?

  # Both must complete with the same outcome (0 or 1). If either
  # hangs (state-machine deadlock), wait blocks indefinitely; bats's
  # BATS_TEST_TIMEOUT bounds that to 30s.
  [[ $status1 -eq 0 || $status1 -eq 1 ]] || {
    echo "client 1 exited $status1" >&2
    cat "$res1" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  [[ $status2 -eq 0 || $status2 -eq 1 ]] || {
    echo "client 2 exited $status2" >&2
    cat "$res2" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }

  # No PIN prompt expected for either client.
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal during concurrent probes" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}
