#! /usr/bin/env bats
#
# FDR 0006 phase (c), piggy#382 item 2: the agent's Ed25519 PIV path, end
# to end. The FDR's open question "does the agent's Ed25519 PIV path work
# end to end?" is answered here, over fibby's yk5.7 model (the only one
# that does PIV algorithm E0, as only firmware 5.7+ does on silicon).
#
# fibby seeds slot 9A with an Ed25519 key, a self-signed certificate over
# it and the canonical CHUID (`--seed-slot-9a-ed25519`); the Rust agent
# must list it as an ssh-ed25519 identity, sign with it (GENERAL
# AUTHENTICATE alg E0, the whole message, not a prehash), and the sshsig
# must verify. On the yk5 model the same seeded key must fail to sign:
# fibby answers 6A80 to E0 there, as pre-5.7 silicon does.
#
# Required env (supplied by `just test-bats-conformance-agent-ed25519`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

# A fixed test seed; the key is a fixture, never a real one.
ED25519_SEED=4242424242424242424242424242424242424242424242424242424242424242

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  # `just test-bats-file` runs against the cargo build (build-rust).
  if [[ -z ${FIBBY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/fibby ]]; then
    FIBBY_BIN="$REPO_ROOT/target/debug/fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/piggy ]]; then
    PIGGY_BIN="$REPO_ROOT/target/debug/piggy"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-agent-ed25519"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset WAYLAND_DISPLAY
  export PIGGY_TEST_FIB_PIN=123456

  # Short-path workdir under /tmp (AF_UNIX sun_path limit).
  WORKDIR="$(mktemp -d -t aged.XXXXXX)"
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
  cat "$AGENT_LOG" "$FIBBY_LOG" >&2 || true
  return 1
}

# Lists the agent's ssh-ed25519 identity into $WORKDIR/id.pub.
_ed25519_identity() {
  run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep '^ssh-ed25519 ' >"$WORKDIR/id.pub" || {
    echo "no ssh-ed25519 identity in ssh-add -L output:" >&2
    printf '%s\n' "$output" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
}

function rust_piggy_agent_signs_with_an_ed25519_piv_key_on_yk5_7 { # @test
  spawn_fibby --model yk5.7 --seed-slot-9a-ed25519 "$ED25519_SEED"
  _spawn_rust_agent
  export SSH_AUTH_SOCK="$AGENT_SOCK"
  _ed25519_identity

  local ktype kdata _rest
  read -r ktype kdata _rest <"$WORKDIR/id.pub"
  printf 'piggy-test@fibby %s %s\n' "$ktype" "$kdata" >"$WORKDIR/allowed_signers"

  echo "piggy-test: ed25519 over the agent" >"$WORKDIR/data"
  run ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/data"
  [[ $status -eq 0 && -f $WORKDIR/data.sig ]] || {
    echo "sign failed (status $status)" >&2
    printf '%s\n' "$output" >&2
    cat "$AGENT_LOG" >&2 || true
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
  run ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I piggy-test@fibby \
    -n file -s "$WORKDIR/data.sig" <"$WORKDIR/data"
  [[ $status -eq 0 ]] || {
    echo "the sshsig does not verify against the slot's key" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  grep -q "GA ED25519 9A -> 9000" "$FIBBY_LOG" || {
    echo "fibby saw no successful Ed25519 GENERAL AUTHENTICATE on 9A" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
}

function an_ed25519_piv_key_does_not_sign_on_firmware_before_5_7 { # @test
  spawn_fibby --model yk5 --seed-slot-9a-ed25519 "$ED25519_SEED"
  _spawn_rust_agent
  export SSH_AUTH_SOCK="$AGENT_SOCK"
  _ed25519_identity

  echo "piggy-test: refused" >"$WORKDIR/data"
  run ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/data"
  [[ $status -ne 0 ]] || {
    echo "signed on the yk5 model, which has no Ed25519" >&2
    return 1
  }
  grep -q "GA ED25519 9A -> 6A80" "$FIBBY_LOG" || {
    echo "fibby did not refuse E0 with 6A80" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
}
