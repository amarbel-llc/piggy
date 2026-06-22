#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#201 — `piggy manage --jsonrpc` drives piggy's management primitives
# headless over a single JSON-RPC connection (RFC 0007), exercised against a
# virtual fibby card through BOTH transports (stdio and an AF_UNIX socket) and
# all three v1 methods.
#
# The scripted `manage-client` test peer (crates/manage-client) is the JSON-RPC
# *client*: it invokes a method on piggy (the server) and answers the RFC 0006
# interaction requests piggy issues back over the same connection. A green lane
# proves the bidirectional command+interaction flow end-to-end on a real
# (virtual) card:
#
#   - card.init   — provisions a blank yk5 fibby; `piggy list` then shows it
#                   provisioned (CHUID GUID + 9D recipient). Run over BOTH stdio
#                   (--spawn) and --socket, satisfying RFC 0007 §3.
#   - sign_bytes  — a real slot-9A sign whose DER output openssl verifies against
#                   the 9A pubkey (read back via `piggy list --format=ssh`).
#   - card.list   — returns the attached card's slot records as JSON.
#
# Required env (supplied by the test-bats-conformance-manage-fibby recipe):
#   FIBBY_BIN          = /path/to/fibby          (nix build .#fibby)
#   PIGGY_BIN          = /path/to/piggy          (nix build .#default)
#   MANAGE_CLIENT_BIN  = /path/to/manage-client  (cargo build -p manage-client)

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-manage-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  if [[ -z ${MANAGE_CLIENT_BIN:-} ]] || [[ ! -x ${MANAGE_CLIENT_BIN:-/nonexistent} ]]; then
    skip "MANAGE_CLIENT_BIN unset; run via just test-bats-conformance-manage-fibby"
  fi

  # Short-path workdir under /tmp (AF_UNIX sun_path 108-byte limit).
  WORKDIR="$(mktemp -d -t mngf.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=
  SERVER_PID=

  # No ambient agent: every card op is direct-PCSC to fibby. A refusing askpass
  # guards against any unexpected prompt popping a GUI (#35) — the manage flow
  # routes all secrets through the JSON-RPC frontend, never askpass.
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
  local askpass="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  export SSH_ASKPASS="$askpass"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset PIGGY_TEST_FIB_PIN
}

teardown() {
  [[ -n ${SERVER_PID:-} ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n ${SERVER_PID:-} ]] && wait "$SERVER_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && wait "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Extract a top-level string field from the compact JSON `manage-client` prints.
_json_field() {
  local field="$1" json="$2"
  printf '%s' "$json" | sed -n "s/.*\"${field}\":\"\([^\"]*\)\".*/\1/p"
}

# Assert the card behind FIBBY_SOCK is now provisioned with the given GUID and a
# 9D recipient record (not uninitialized).
assert_provisioned() {
  local want_guid="$1" out
  out=$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" list --format=ndjson) || {
    echo "piggy list after init failed" >&2
    printf '%s\n' "$out" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  if printf '%s\n' "$out" | grep -q '"uninitialized":true'; then
    echo "card still reported uninitialized after card.init" >&2
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

# Seed fibby's slot 9A (RFC 6979 §A.2.5 P-256) + CHUID and write its public key
# to $WORKDIR/pub.pem, read back via `piggy list --format=ssh` + ssh-keygen.
_seed_9a_and_pubkey() {
  command -v openssl >/dev/null || skip "openssl not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-chuid

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$PIGGY_BIN" list --format=ssh
  [[ $status -eq 0 ]] || {
    echo "piggy list --format=ssh exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  local line
  line=$(printf '%s\n' "$output" | grep '^ecdsa-sha2-nistp256 ' | head -1)
  [[ -n $line ]] || {
    echo "no slot-9A ecdsa authorized_keys line in piggy list output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$line" | awk '{print $1, $2}' >"$WORKDIR/k.pub"
  ssh-keygen -e -m PKCS8 -f "$WORKDIR/k.pub" >"$WORKDIR/pub.pem"
}

# card.init over stdio: manage-client spawns `piggy manage --jsonrpc` and drives
# a full provision, answering confirm + new PIN/PUK + mgmt_key over the child's
# stdin/stdout. The child inherits PCSCLITE_CSOCK_NAME, so it talks to fibby.
function card_init_over_stdio_provisions_blank_card { # @test
  spawn_fibby --model yk5

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$MANAGE_CLIENT_BIN" --spawn "$PIGGY_BIN" --method card.init \
    --pin 654321 --puk 87654321 --mgmt-source random
  [[ $status -eq 0 ]] || {
    echo "manage-client card.init (stdio) exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local guid
  guid=$(_json_field guid "$output")
  [[ $guid =~ ^[0-9A-F]{32}$ ]] || {
    echo "card.init result had no 32-hex guid: '$output'" >&2
    return 1
  }
  assert_provisioned "$guid"
}

# card.init over an AF_UNIX socket: piggy manage listens; manage-client connects.
# Same provision workflow as the stdio lane (RFC 0007 §3 — same workflow, both
# transports).
function card_init_over_socket_provisions_blank_card { # @test
  spawn_fibby --model yk5

  local sock="$WORKDIR/manage.sock"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" manage --jsonrpc --socket "$sock" \
    >"$WORKDIR/server.log" 2>&1 &
  SERVER_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $sock ]] && break
    sleep 0.1
  done
  [[ -S $sock ]] || {
    echo "manage server socket never appeared at $sock" >&2
    cat "$WORKDIR/server.log" >&2 || true
    return 1
  }

  run "$MANAGE_CLIENT_BIN" --socket "$sock" --method card.init \
    --pin 654321 --puk 87654321 --mgmt-source random
  [[ $status -eq 0 ]] || {
    echo "manage-client card.init (socket) exited $status" >&2
    printf '%s\n' "$output" >&2
    cat "$WORKDIR/server.log" >&2 || true
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local guid
  guid=$(_json_field guid "$output")
  [[ $guid =~ ^[0-9A-F]{32}$ ]] || {
    echo "card.init (socket) result had no 32-hex guid: '$output'" >&2
    return 1
  }
  assert_provisioned "$guid"
}

# sign_bytes over stdio: a real slot-9A sign, PIN supplied via the JSON-RPC
# secret.request, whose DER output openssl verifies against the 9A pubkey —
# real card crypto driven entirely headless.
function sign_bytes_over_stdio_verifies_against_slot_9a { # @test
  _seed_9a_and_pubkey
  printf 'manage-sign-message' >"$WORKDIR/msg"
  local msg_b64
  msg_b64=$(base64 -w0 <"$WORKDIR/msg")

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$MANAGE_CLIENT_BIN" --spawn "$PIGGY_BIN" --method sign_bytes \
    --slot 9a --message-b64 "$msg_b64" --format der --pin 123456
  [[ $status -eq 0 ]] || {
    echo "manage-client sign_bytes (stdio) exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local sig_b64
  sig_b64=$(_json_field signature "$output")
  [[ -n $sig_b64 ]] || {
    echo "sign_bytes result had no signature: '$output'" >&2
    return 1
  }
  printf '%s' "$sig_b64" | base64 -d >"$WORKDIR/sig.der"

  run openssl dgst -sha256 -verify "$WORKDIR/pub.pem" \
    -signature "$WORKDIR/sig.der" "$WORKDIR/msg"
  [[ $status -eq 0 ]] || {
    echo "openssl failed to verify the headless sign_bytes signature (status $status)" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q "Verified OK" || {
    echo "openssl did not report 'Verified OK'" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# card.list over stdio: returns the attached card's slot records (read-only,
# PIN-free; no interactions issued).
function card_list_over_stdio_returns_card { # @test
  _seed_9a_and_pubkey

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$MANAGE_CLIENT_BIN" --spawn "$PIGGY_BIN" --method card.list
  [[ $status -eq 0 ]] || {
    echo "manage-client card.list (stdio) exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The seeded 9A card surfaces a slot-9A record inside the cards array.
  printf '%s\n' "$output" | grep -q '"cards"' || {
    echo "card.list result missing 'cards' key: '$output'" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q '"slot":"9A"' || {
    echo "card.list did not surface the seeded 9A slot record: '$output'" >&2
    return 1
  }
}
