#! /usr/bin/env bats
#
# piggy#130 — fibby runtime hot-plug from bash. A spawned fibby's control
# socket + the `fibby ctl` client toggle a card's presence at runtime, and a
# fresh pcsc enumerate (`piggy agent -A -i`, print-keys-and-exit) reflects it:
# a removed card drops out of the listing, a re-inserted one returns.
#
# This proves the `fibby ctl` client end to end from bash (the in-process
# loopback test covers the server side). It is the substrate the piggy#244
# per-card lifecycle test drives to remove a card mid-run.
#
# Required env (supplied by test-bats-conformance-fibby-hotplug):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-fibby-hotplug"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  WORKDIR="$(mktemp -d -t fibhp.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=
  READER="Virtual PCD fibby A 00 00"

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && wait "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
}

# Count the PIV keys a fresh `piggy agent -A -i` enumerate reports. `-i`
# prints one line per key as `<slot> <Alg> <openssh-pubkey>`, e.g.
# `9A EcdsaSha2Nistp256 ecdsa-sha2-nistp256 AAAA...`; the lowercase-hyphen
# key type appears only in the openssh portion, once per key.
_agent_key_count() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent -A -i 2>/dev/null \
    | grep -c 'ecdsa-sha2-nistp256' || true
}

function fibby_ctl_toggles_card_presence_end_to_end { # @test
  spawn_fibby --control-socket "$FIBBY_CTL" \
    --card "$READER" --seed-rfc6979-slot-9a-cert

  # The control socket appears (spawn_fibby only waits for the pcsc socket).
  local _
  for _ in $(seq 1 50); do
    [[ -S $FIBBY_CTL ]] && break
    sleep 0.1
  done
  [[ -S $FIBBY_CTL ]] || {
    echo "control socket never appeared at $FIBBY_CTL" >&2
    cat "$FIBBY_LOG" >&2 || true
    return 1
  }

  # Present at start: one key.
  [[ "$(_agent_key_count)" -eq 1 ]] || {
    echo "expected 1 key while present, got $(_agent_key_count)" >&2
    cat "$FIBBY_LOG" >&2 || true
    return 1
  }

  # Remove -> the card drops out of a fresh enumerate.
  "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" remove "$READER" || {
    echo "fibby ctl remove failed" >&2
    return 1
  }
  [[ "$(_agent_key_count)" -eq 0 ]] || {
    echo "expected 0 keys after remove, got $(_agent_key_count)" >&2
    cat "$FIBBY_LOG" >&2 || true
    return 1
  }

  # Re-insert -> the card (and its key) returns.
  "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" insert "$READER" || {
    echo "fibby ctl insert failed" >&2
    return 1
  }
  [[ "$(_agent_key_count)" -eq 1 ]] || {
    echo "expected 1 key after re-insert, got $(_agent_key_count)" >&2
    cat "$FIBBY_LOG" >&2 || true
    return 1
  }
}
