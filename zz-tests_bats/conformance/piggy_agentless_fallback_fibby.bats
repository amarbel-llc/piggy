#! /usr/bin/env bats
# bats file_tags=hardware
#
# Agentless-host fallback: when a host has NO local PCSC card but a piggy-agent
# is reachable (forwarded auth socket), `piggy sign-bytes` and
# `piggy pass show-batch` must fall back to that agent instead of failing.
#
# Both paths are card-first: the local card is used when present. Here we make
# the local card UNreachable by pointing PCSCLITE_CSOCK_NAME at a dead socket
# for the sign/decrypt process, while a piggy-agent (spawned earlier with the
# real fibby socket) holds the card and is reached via PIGGY_AUTH_SOCK. The PIN
# is supplied on demand through the agent's own SSH_ASKPASS (the agent owns the
# prompt on this path), exactly as in piggy_agent_pin_on_demand.bats.
#
# Required env (supplied by the `test-bats-conformance-agentless-fallback-fibby`
# recipe); the suite skips gracefully without them:
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default — real pivy-box)
#
# `run --separate-stderr` (show-batch test) needs bats 1.5.0+.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-agentless-fallback-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"

  # The agent prompts for the PIN on demand; the in-tree test askpass supplies
  # fibby's default PIN non-interactively and refuses any unexpected prompt (#35).
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456

  # Short-path workdir under /tmp (AF_UNIX sun_path 108-byte limit).
  WORKDIR="$(mktemp -d -t aglf.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  # The "agentless host" sees no PCSC: the sign/decrypt process is pointed at a
  # socket path that never exists, so PivContext::new()/enumerate fails and the
  # agent fallback fires. The agent itself was spawned with the real FIBBY_SOCK.
  DEAD_PCSC="$WORKDIR/no-pcscd.sock"

  # No ambient socket bleed-through: the fallback must route at OUR agent.
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

# Spawn the Rust `piggy agent` pointed at fibby, binding the private AGENT_SOCK.
_spawn_agent() {
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

# The agentless host's only view of the card is the agent: read the served
# slot-9A pubkey via `ssh-add -L` and write its PKCS8 PEM to $WORKDIR/pub.pem.
_agent_slot9a_pubkey_pem() {
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L against the agent exited $status" >&2
    printf '%s\n' "$output" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  local line
  line=$(printf '%s\n' "$output" | grep '^ecdsa-sha2-nistp256 ' | head -1)
  [[ -n $line ]] || {
    echo "no slot-9A ecdsa identity served by the agent" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$line" | awk '{print $1, $2}' >"$WORKDIR/k.pub"
  ssh-keygen -e -m PKCS8 -f "$WORKDIR/k.pub" >"$WORKDIR/pub.pem"
}

# sign-bytes with NO local PCSC must fall back to the forwarded agent, which
# signs slot-9A on demand. openssl verifies the DER signature against the
# agent-served 9A pubkey: real card crypto reached purely through the agent.
function sign_bytes_falls_back_to_forwarded_agent { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-chuid
  _spawn_agent
  _agent_slot9a_pubkey_pem
  printf 'agentless-receipt-bytes' >"$WORKDIR/msg"

  PCSCLITE_CSOCK_NAME="$DEAD_PCSC" PIGGY_AUTH_SOCK="$AGENT_SOCK" \
    "$PIGGY_BIN" sign-bytes --slot 9a --format der \
    <"$WORKDIR/msg" >"$WORKDIR/sig.der"
  local rc=$?
  [[ $rc -eq 0 && -s "$WORKDIR/sig.der" ]] || {
    echo "agentless sign-bytes failed (rc=$rc)" >&2
    cat "$AGENT_LOG" >&2 || true
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  run openssl dgst -sha256 -verify "$WORKDIR/pub.pem" \
    -signature "$WORKDIR/sig.der" "$WORKDIR/msg"
  [[ $status -eq 0 ]] || {
    echo "openssl failed to verify the agent-produced signature (status $status)" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q "Verified OK" || {
    echo "openssl did not report 'Verified OK'" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # The PIN was prompted on demand through the agent's askpass (the agent owns
  # the prompt on this path — sign-bytes was given no -P and no frontend).
  grep -q "\[piggy-test-askpass\] supplying" "$AGENT_LOG" || {
    echo "no on-demand askpass invocation in agent log (agent path not exercised?)" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
}

# show-batch with NO local PCSC must fall back to the forwarded agent for the
# slot-9D ECDH decrypt (instead of bailing "PCSC unavailable"). Seed + insert
# happen via direct PCSC first; the decrypt is then driven agent-only.
function show_batch_falls_back_to_forwarded_agent { # @test
  spawn_fibby --seed-rfc5903-slot-9d-cert
  _spawn_agent

  local store="$WORKDIR/store"
  local out_dir="$WORKDIR/out"
  local secret="agentless-batch-secret"

  # init + insert read the 9D pubkey + offline-encrypt via direct PCSC (no PIN,
  # no agent). Gitless store -> no post-write commit.
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
    echo "piggy pass insert exited $ins" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The crux: no PCSC for show-batch (dead socket), only the forwarded agent.
  PCSCLITE_CSOCK_NAME="$DEAD_PCSC" PIGGY_AUTH_SOCK="$AGENT_SOCK" \
    PIGGY_STORE_DIR="$store" \
    run --separate-stderr "$PIGGY_BIN" pass show-batch \
    --format ndjson --out-dir "$out_dir" foo/bar
  [[ $status -eq 0 ]] || {
    echo "agentless show-batch exited $status (fell back to bail instead of agent?)" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  printf '%s\n' "$output" | grep -q '"ok":true' || {
    echo "no decrypt-ok record in show-batch output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q '"type":"bail-out"' && {
    echo "show-batch bailed out instead of using the agent fallback" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  # The plaintext landed on disk with the right contents.
  [[ -f "$out_dir/foo/bar" ]] || {
    echo "no plaintext written at $out_dir/foo/bar" >&2
    return 1
  }
  run cat "$out_dir/foo/bar"
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "decrypted plaintext missing the secret line '$secret'" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }

  # The slot-9D GA ECDH actually ran on fibby through the agent.
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9D GA ECDH in fibby trace" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
}
