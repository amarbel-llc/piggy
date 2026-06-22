#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#194 — `piggy card init` provisions a factory-blank PIV card end to end,
# exercised against a virtual fibby card through BOTH interaction frontends
# (RFC 0006): the default tty/askpass binding and the JSON-RPC binding driven by
# a scripted frontend server over an AF_UNIX socket.
#
# Each lane: spawn a blank yk5 fibby → run `piggy card init` against it →
# assert `piggy list` now shows that exact card provisioned (its CHUID GUID,
# not uninitialized, with a 9D key-management recipient record). That proves
# the whole write path through the real (virtual) card: admin-auth, CHUID
# write, on-card 9D+9A keygen, and self-signed cert build/sign/write.
#
# A `piggy box` round-trip to the freshly-generated 9D key (proving the
# generated key also decrypts, with the newly-set PIN) is a deferred stretch —
# the seeded-9D ECDH path is already covered by piggy_list_blank_fibby /
# age_plugin_piggy_fibby; here the new surface is the *provisioning writes*.
#
# Required env (supplied by the just recipes):
#   FIBBY_BIN          = /path/to/fibby           (nix build .#fibby)
#   PIGGY_BIN          = /path/to/piggy           (nix build .#default)
#   CARD_FRONTEND_BIN  = /path/to/card-frontend-server  (cargo build, jsonrpc lane)

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-card-init-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  WORKDIR="$(mktemp -d -t cardinit.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=
  RPC_PID=

  # The provisioning PIN/PUK secrets flow via the frontend; unset agent sockets
  # so nothing reaches an ambient agent — all card I/O is direct-PCSC to fibby
  # via PCSCLITE_CSOCK_NAME.
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK

  # Refusing askpass by default (the jsonrpc lane never prompts; the tty lane
  # overrides PIGGY_TEST_FIB_PIN to supply the new PIN/PUK). The helper lives
  # at the canonical absolute path common.bash exports — SSH_ASKPASS must be
  # absolute since piggy spawns it from its own cwd.
  local askpass="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $askpass ]] || skip "piggy-test-askpass.sh not found at $askpass"
  export SSH_ASKPASS="$askpass"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset PIGGY_TEST_FIB_PIN
}

teardown() {
  [[ -n ${RPC_PID:-} ]] && kill "$RPC_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && wait "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Assert the card behind FIBBY_SOCK is now provisioned with the given GUID and a
# 9D recipient record (not uninitialized).
assert_provisioned() {
  local want_guid="$1"
  local out
  # The env prefix must sit on the `piggy list` SIMPLE command inside the
  # substitution — `VAR=x out=$(...)` would set VAR as a plain (unexported)
  # shell var and `piggy list` would hit the ambient pcscd, not fibby.
  out=$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" list --format=ndjson) || {
    echo "piggy list after init failed" >&2
    printf '%s\n' "$out" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  if printf '%s\n' "$out" | grep -q '"uninitialized":true'; then
    echo "card still reported uninitialized after card init" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  printf '%s\n' "$out" | grep -q "\"guid\":\"${want_guid}\"" || {
    echo "list does not show the provisioned GUID ${want_guid}" >&2
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$out" | grep -q '"slot":"9D"' || {
    echo "provisioned card did not surface its 9D recipient record" >&2
    printf '%s\n' "$out" >&2
    return 1
  }
}

# tty/askpass lane: the new PIN/PUK come from the test askpass; the confirm
# prompt is answered "y" on stdin. We run under `setsid -w` so the process has
# NO controlling tty — then the tty frontend's confirm deterministically falls
# back to stdin (it would otherwise block reading an empty /dev/tty in an
# environment that has one). `-w` makes setsid wait and propagate piggy's exit
# code + output to `run`. The mgmt key rotates random (tty default).
function card_init_tty_provisions_blank_card { # @test
  spawn_fibby --model yk5

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_TEST_FIB_PIN=654321 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card init <<<"y"

  [[ $status -eq 0 ]] || {
    echo "piggy card init (tty) exited $status" >&2
    printf 'stdout: %s\n' "$output" >&2
    printf 'stderr: %s\n' "$stderr" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # stdout is exactly the provisioned GUID (32 uppercase hex).
  local guid="$output"
  [[ $guid =~ ^[0-9A-F]{32}$ ]] || {
    echo "card init stdout was not a bare GUID: '$guid'" >&2
    printf 'stderr: %s\n' "$stderr" >&2
    return 1
  }
  # Random mgmt key is displayed once on stderr.
  printf '%s\n' "$stderr" | grep -q "management key" || {
    echo "tty lane did not display the rotated management key" >&2
    printf 'stderr: %s\n' "$stderr" >&2
    return 1
  }

  assert_provisioned "$guid"
}

# JSON-RPC lane: a scripted frontend server answers every interaction over an
# AF_UNIX socket; piggy connects as the client. No askpass, no tty.
function card_init_jsonrpc_provisions_blank_card { # @test
  if [[ -z ${CARD_FRONTEND_BIN:-} ]] || [[ ! -x ${CARD_FRONTEND_BIN:-/nonexistent} ]]; then
    skip "CARD_FRONTEND_BIN unset; run via just test-bats-conformance-card-init-fibby"
  fi
  spawn_fibby --model yk5

  local rpc_sock="$WORKDIR/frontend.sock"
  local rpc_log="$WORKDIR/frontend.log"
  "$CARD_FRONTEND_BIN" --socket "$rpc_sock" \
    --pin 654321 --puk 87654321 --mgmt-source random >"$rpc_log" 2>&1 &
  RPC_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $rpc_sock ]] && break
    sleep 0.1
  done
  [[ -S $rpc_sock ]] || {
    echo "frontend server socket never appeared at $rpc_sock" >&2
    cat "$rpc_log" >&2 || true
    return 1
  }

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run --separate-stderr "$PIGGY_BIN" card init --frontend jsonrpc --socket "$rpc_sock"

  [[ $status -eq 0 ]] || {
    echo "piggy card init (jsonrpc) exited $status" >&2
    printf 'stdout: %s\n' "$output" >&2
    printf 'stderr: %s\n' "$stderr" >&2
    echo "--- frontend log ---" >&2
    cat "$rpc_log" >&2 || true
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local guid="$output"
  [[ $guid =~ ^[0-9A-F]{32}$ ]] || {
    echo "card init stdout was not a bare GUID: '$guid'" >&2
    return 1
  }
  assert_provisioned "$guid"
}

# --allow-reprovision (piggy#204): a CHUID-stamped card at factory creds presents
# as initialized, so plain `card init` refuses it; `--allow-reprovision` accepts
# it and re-provisions to a fresh GUID + 9D recipient. The seeded card keeps its
# factory-default PIN/mgmt key, so the engine's default admin-auth succeeds (the
# case-A path; a creds-rotated card would fail at admin-auth, by design).
function card_init_allow_reprovision_reinits_an_initialized_card { # @test
  spawn_fibby --model yk5 --seed-chuid

  # Without the flag: an initialized card is not a blank card → refused, no writes.
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_TEST_FIB_PIN=654321 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card init <<<"y"
  [[ $status -ne 0 ]] || {
    echo "plain card init should refuse an already-initialized card" >&2
    printf 'stdout: %s\n' "$output" >&2
    return 1
  }

  # With the flag: reprovisions to a fresh GUID.
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_TEST_FIB_PIN=654321 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card init --allow-reprovision <<<"y"
  [[ $status -eq 0 ]] || {
    echo "card init --allow-reprovision exited $status" >&2
    printf 'stdout: %s\n' "$output" >&2
    printf 'stderr: %s\n' "$stderr" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local guid="$output"
  [[ $guid =~ ^[0-9A-F]{32}$ ]] || {
    echo "reprovision stdout was not a bare GUID: '$guid'" >&2
    return 1
  }
  assert_provisioned "$guid"
}
