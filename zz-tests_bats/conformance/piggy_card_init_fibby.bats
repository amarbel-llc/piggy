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

# --- piggy#258: sealing the generated management key into the store ---------
#
# Card A is factory-blank (the provision target); card B carries a seeded 9D
# key and plays the backup card the escrow is sealed to. The store's piggy-ids
# lists only card B, so recovering the key proves it survives the loss or
# reset of the card it belongs to.

READER_A="Virtual PCD fibby A 00 00"
READER_B="Virtual PCD fibby B 00 00"
GUID_B="B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"

# Spawn both cards and make card B the store's only recipient.
_spawn_cards_with_backup_recipient() {
  [[ -x ${PIGGY_IDS_BIN:-/nonexistent} ]] ||
    skip "PIGGY_IDS_BIN unset; run via just test-bats-conformance-card-init-fibby"
  spawn_fibby --model yk5 \
    --card "$READER_A" \
    --card "$READER_B" --seed-rfc5903-slot-9d-cert --seed-chuid-guid "$GUID_B"
  local b_id
  b_id=$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_IDS_BIN" detect-pubkey --guid "$GUID_B") || {
    echo "detect-pubkey on the backup card failed" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$b_id" >"$PIGGY_STORE_DIR/piggy-ids"
}

# Decrypt a sealed management key with the backup card (factory PIN).
_recover_sealed_key() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_TEST_FIB_PIN=123456 \
    "$PIGGY_BIN" box stream decrypt <"$1"
}

_fail_with_card_init_output() {
  echo "$1" >&2
  printf 'status: %s\nstdout: %s\nstderr: %s\n' "$status" "$output" "$stderr" >&2
  tail -60 "$FIBBY_LOG" >&2 || true
  return 1
}

# `piggy card init ARGS` through the tty frontend (see the tty lane above for
# why `setsid -w`); stdin answers the confirmations.
_card_init_tty() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_TEST_FIB_PIN=654321 \
    run --separate-stderr setsid -w "$PIGGY_BIN" card init "$@"
}

function card_init_seal_flag_escrows_key_recoverable_by_backup_card { # @test
  [[ -x ${PIVY_TOOL:-/nonexistent} ]] ||
    skip "PIVY_TOOL unset; run via just test-bats-conformance-card-init-fibby"
  _spawn_cards_with_backup_recipient

  _card_init_tty --reader "$READER_A" --seal-management-key <<<"y"
  [[ $status -eq 0 ]] || _fail_with_card_init_output "card init --seal-management-key failed"

  local guid="$output"
  [[ $guid =~ ^[0-9A-F]{32}$ ]] || _fail_with_card_init_output "stdout was not a bare GUID"
  printf '%s\n' "$stderr" | grep -q "sealed to piv/$guid/management-key" ||
    _fail_with_card_init_output "no seal confirmation on stderr"
  if printf '%s\n' "$stderr" | grep -q "record this"; then
    _fail_with_card_init_output "the sealed key was also displayed"
  fi

  local ebox="$PIGGY_STORE_DIR/piv/$guid/management-key.ebox"
  [[ -f $ebox ]] || _fail_with_card_init_output "no sealed ebox at $ebox"

  local key
  key=$(_recover_sealed_key "$ebox") || {
    echo "the backup card could not decrypt the escrow" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  [[ $key =~ ^[0-9A-F]{48}$ ]] || {
    echo "recovered escrow is not a 24-byte hex key: '$key'" >&2
    return 1
  }

  # The recovered key admin-authenticates card A: set-admin rewrites it to
  # itself (-R skips the PIN-gated printed-info write) ...
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$PIVY_TOOL" -g "$guid" -A 3des -K "$key" -R set-admin "$key"
  [[ $status -eq 0 ]] || {
    echo "the recovered key failed admin auth on card A: $output" >&2
    return 1
  }
  # ... and a wrong key does not, so the check discriminates.
  local wrong
  wrong=$(printf '11%.0s' {1..24})
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$PIVY_TOOL" -g "$guid" -A 3des -K "$wrong" -R set-admin "$wrong"
  [[ $status -ne 0 ]] || {
    echo "a wrong management key passed admin auth on card A" >&2
    return 1
  }
}

# The tty flow offers the seal when the store can take it; accepting seals.
function card_init_accepted_seal_offer_escrows_key { # @test
  _spawn_cards_with_backup_recipient

  _card_init_tty --reader "$READER_A" <<<$'y\ny'
  [[ $status -eq 0 ]] || _fail_with_card_init_output "card init with an accepted seal offer failed"

  local guid="$output"
  printf '%s\n' "$stderr" | grep -q "into the password store at piv/$guid/management-key" ||
    _fail_with_card_init_output "the seal was not offered"
  [[ -f "$PIGGY_STORE_DIR/piv/$guid/management-key.ebox" ]] ||
    _fail_with_card_init_output "accepting the offer did not seal the key"
  if printf '%s\n' "$stderr" | grep -q "record this"; then
    _fail_with_card_init_output "the sealed key was also displayed"
  fi
}

# Declining the offer keeps the display-once behaviour and writes no escrow.
function card_init_declined_seal_offer_displays_key { # @test
  _spawn_cards_with_backup_recipient

  _card_init_tty --reader "$READER_A" <<<$'y\nn'
  [[ $status -eq 0 ]] || _fail_with_card_init_output "card init with a declined seal offer failed"

  printf '%s\n' "$stderr" | grep -q "record this" ||
    _fail_with_card_init_output "a declined offer did not display the key"
  [[ ! -e "$PIGGY_STORE_DIR/piv" ]] ||
    _fail_with_card_init_output "a declined offer still wrote an escrow"
}

# An explicit seal with nowhere to seal to refuses before the destructive
# confirm, leaving the card factory-blank.
function card_init_seal_flag_without_recipients_refuses_before_touching_card { # @test
  spawn_fibby --model yk5

  _card_init_tty --seal-management-key <<<"y"
  [[ $status -ne 0 ]] || _fail_with_card_init_output "seal with no piggy-ids should refuse"
  printf '%s\n' "$stderr" | grep -q "piggy-ids" ||
    _fail_with_card_init_output "the refusal does not name the missing piggy-ids"
  if printf '%s\n' "$stderr" | grep -q "Provision card"; then
    _fail_with_card_init_output "the refusal came after the destructive confirm"
  fi

  local out
  out=$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" list --format=ndjson)
  printf '%s\n' "$out" | grep -q '"uninitialized":true' || {
    echo "the card was touched despite the refusal" >&2
    printf '%s\n' "$out" >&2
    return 1
  }
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
