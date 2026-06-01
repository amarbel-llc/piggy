#! /usr/bin/env bats
#
# piggy#135 Phase D: end-to-end SSH-forwarded decrypt — the realistic
# deployment shape this whole arc targets. The full stack, no hardware:
#
#   fibby (virtual, seeded slot-9D ECDH cert)
#     <- pcsc -> pivy-agent (advertises ecdh-rebox@joyent.com)
#                  <- ssh agent forwarding -> piggy-test-sshd
#                                               -> remote `piggy pass show`
#
# A "remote" `piggy pass show` runs over `ssh -A`, so its
# `pivy-box stream decrypt` reaches the agent through the FORWARDED socket
# (an SSH channel back to the local pivy-agent), not a direct path. This is
# the path #119/#123/#138 all live on; before #138's fix the forwarded
# rebox SIGABRT'd the agent. Companion to the local (transport-free)
# decrypt gate piggy_rebox_decrypts_via_seeded_fibby_slot_9d.
#
# Required env (supplied by the
# `test-bats-conformance-piggy-ssh-via-fibby` recipe):
#   PIVY_AGENT  (nix build .#pivy)
#   FIBBY_BIN   (nix build .#fibby)
#   PIGGY_BIN   (nix build .#default — wrapped piggy: real pivy-box on PATH
#                + real piggy-ids via PIGGY_IDS_PATH, so common.bash's mock
#                crypto is bypassed)
#   SSHD_BIN    (nix build .#piggy-test-sshd)
#
# Without those (e.g. the sandboxed bats-default lane) the suite skips,
# same convention as piggy_fibby_pivy_agent_smoke.bats.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/ssh.bash"
  export output

  local bin
  for bin in PIVY_AGENT FIBBY_BIN PIGGY_BIN SSHD_BIN; do
    [[ -n ${!bin:-} && -x ${!bin:-/nonexistent} ]] ||
      skip "$bin unset or not executable; run via just test-bats-conformance-piggy-ssh-via-fibby"
  done
  command -v ssh >/dev/null || skip "ssh not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  # The agent unlocks slot 9D on-demand during the (forwarded) rebox via
  # the test askpass — it runs at the local agent process, the SSH channel
  # only proxies the agent protocol.
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456
  # The remote must use the FORWARDED SSH_AUTH_SOCK, not a local override.
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK

  # Short /tmp workdir: the forwarded-agent socket piggy-test-sshd arms must
  # fit AF_UNIX sun_path (108 bytes), which $BATS_TEST_TMPDIR overruns under
  # the nix sandbox prefixes. Same trick as the smoke + hardware lanes.
  WORKDIR="$(mktemp -d -t sshfib.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  STORE="$WORKDIR/store"
  FIBBY_PID=
  AGENT_PID=
  SSHD_PID=
}

teardown() {
  stop_test_sshd 2>/dev/null || true
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# The remote `piggy pass show`, run over `ssh -A`, must decrypt the ebox via
# the forwarded agent and return the plaintext — without crashing the agent
# (the #138 SIGABRT manifested as -26 at the client; over forwarding it
# would tear down the channel). Init + insert build the store directly
# against fibby (offline encrypt + 9D pubkey read, no agent, no PIN); only
# the forwarded `show` exercises the rebox decrypt path.
function piggy_pass_show_decrypts_over_ssh_forwarded_agent { # @test
  spawn_fibby --seed-rfc5903-slot-9d-cert
  spawn_agent

  local secret="ssh-forwarded-decrypt-135d"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$STORE" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  printf '%s\n' "$secret" | PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_STORE_DIR="$STORE" "$PIGGY_BIN" pass insert -e foo/bar
  local ins=$?
  [[ $ins -eq 0 && -f "$STORE/foo/bar.ebox" ]] || {
    echo "piggy pass insert exited $ins (ebox present: $([[ -f $STORE/foo/bar.ebox ]] && echo yes || echo no))" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  start_test_sshd || return 1

  # `ssh -A` forwards SSH_AUTH_SOCK=$AGENT_SOCK; the server injects the
  # forwarded socket into the remote env. PIGGY_AUTH_SOCK is unset, so the
  # remote piggy decrypts through the forwarded socket -> pivy-agent -> fibby.
  run ssh_agent_exec "$AGENT_SOCK" \
    "PIGGY_STORE_DIR=$STORE $PIGGY_BIN pass show foo/bar"
  [[ $status -eq 0 ]] || {
    echo "remote pass show exited $status (forwarded rebox decrypt failed)" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    echo "--- sshd stderr ---" >&2
    cat "$SSHD_ERR" >&2 || true
    return 1
  }

  # ssh interleaves the remote stderr ("Using key ...") and its own warnings
  # into $output; assert the decrypted secret appears as its own line.
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "forwarded decrypt missing the secret line '$secret'" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }

  # The agent must have survived the forwarded rebox (a SIGABRT would reap
  # it), and the GA ECDH must have actually reached fibby's slot 9D.
  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "pivy-agent died during the forwarded rebox decrypt" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9D GA ECDH in fibby trace" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}
