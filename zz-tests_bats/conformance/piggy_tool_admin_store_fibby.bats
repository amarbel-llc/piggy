#! /usr/bin/env bats
#
# piggy#396, the management key off argv, over fibby: `piggy tool auth-test`
# (the mutual authentication alone: nothing written, no PIN, exit 0 or 1),
# `set-admin -` (the new key as one hex line on stdin), and `-K @store` (the
# current key read from the password store's sealed entry, decrypted through
# the card under the askpass safety net, before the card session opens).
# fibby starts on its factory 3DES key with a seeded slot 9D, which the
# store's piggy-ids names, so the sealed entry decrypts against the same
# card the key is for, as on a real host.
#
# The differential admin lane (piggy_tool_admin_fibby.bats) replays frozen C
# answers; these forms have no C counterpart, so they live here.
#
# Required env (supplied by `just test-bats-conformance-tool-admin-store-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/fibby ]]; then
    FIBBY_BIN="$REPO_ROOT/target/debug/fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/piggy ]]; then
    PIGGY_BIN="$REPO_ROOT/target/debug/piggy"
    # `pass insert` execs `piggy-ids` from PATH: the one built with this
    # piggy, not whichever the shell has (`just build-rust -p piggy-ids`).
    export PATH="$REPO_ROOT/target/debug:$PATH"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-tool-admin-store-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  # piggy-testing(7) PIN PROMPT SAFETY NET: the store read decrypts through
  # the card, so the PIN is supplied by the test askpass, never a prompt.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK

  WORKDIR="$(mktemp -d -t tooladm.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=
  STORE="$WORKDIR/store"
  mkdir -p "$STORE"
  unset GIT_DIR GIT_WORK_TREE
  export GIT_CEILING_DIRECTORIES="$WORKDIR"
  init_test_git

  spawn_fibby --seed-rfc5903-slot-9d-cert
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Two 3DES keys that differ from the factory key and from each other in
# non-parity bits (see piggy_tool_admin_fibby.bats).
KEY_A=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7
KEY_B=c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7

_tool() {
  PIGGY_STORE_DIR="$STORE" run "$PIGGY_BIN" tool "$@"
}

_pass() {
  PIGGY_STORE_DIR="$STORE" "$PIGGY_BIN" pass "$@"
}

# Every APDU data byte sent to the card so far, one lowercase hex string.
_sent_hex() {
  sed -nE 's/^\[fibby:apdu>\] [0-9a-f]{4}  (.*) \|.*\|$/\1/p' "$FIBBY_LOG" | tr -d ' \n'
}

_show() {
  printf '%s\n' "$output" >&2
  tail -30 "$FIBBY_LOG" >&2 || true
}

function auth_test_authenticates_and_writes_nothing { # @test
  _tool -K default auth-test
  [[ $status -eq 0 && -z $output ]] || { echo "default: want exit 0, silent; got $status" >&2; _show; return 1; }
  _tool -K "$KEY_A" auth-test
  [[ $status -eq 1 && $output == *"failed to authenticate with current admin key"* ]] || {
    echo "wrong key: want exit 1 naming the failure; got $status" >&2; _show; return 1; }
  # No SET MANAGEMENT KEY (data 03 9b 18 <key>) and no PUT DATA (APDU
  # 00 DB 3F FF ...) went to the card: the op is read-only. (GET DATA,
  # 00 CB 3F FF, carries the same 5C object tags and is a read.)
  if _sent_hex | grep -qE '039b18|00db3fff'; then
    echo "auth-test wrote to the card" >&2; _show; return 1
  fi
  # The factory key still authenticates: a failed try changed nothing.
  _tool -K default auth-test
  [[ $status -eq 0 ]] || { echo "the factory key no longer authenticates after a failed try" >&2; _show; return 1; }
  # A card that is not there is its own failure, not an auth failure.
  _tool -g 00000000000000000000000000000000 -K default auth-test
  [[ $status -eq 1 && $output == *"no PIV token matches"* ]] || {
    echo "-g miss: want exit 1 naming the GUID; got $status: $output" >&2; return 1; }
}

function set_admin_takes_the_new_key_from_stdin { # @test
  # A malformed line changes nothing and is not echoed back.
  _tool -K default set-admin - <<<"0102"
  [[ $status -eq 2 && $output == *"48 hex digits"* && $output != *"0102"* ]] || {
    echo "short line: want exit 2 naming the rule, not the line; got $status: $output" >&2; return 1; }
  _tool -K default set-admin - </dev/null
  [[ $status -eq 2 && $output == *"no key line"* ]] || { echo "empty stdin: got $status: $output" >&2; return 1; }
  _tool -K default auth-test
  [[ $status -eq 0 ]] || { echo "a refused set-admin changed the key" >&2; _show; return 1; }

  _tool -K default set-admin - <<<"$KEY_A"
  [[ $status -eq 0 && -z $output ]] || { echo "set-admin -: want exit 0, silent; got $status" >&2; _show; return 1; }
  _tool -K "$KEY_A" auth-test
  [[ $status -eq 0 ]] || { echo "the new key does not authenticate" >&2; _show; return 1; }
  _tool -K default auth-test
  [[ $status -eq 1 ]] || { echo "the factory key still authenticates after the rotation" >&2; _show; return 1; }
  # The key reached the card: the SET MANAGEMENT KEY object carries it.
  [[ $(_sent_hex) == *"039b18$KEY_A"* ]] || { echo "the card did not receive KEY_A" >&2; _show; return 1; }
}

function the_current_key_comes_from_the_store { # @test
  # A store whose recipient is this card's slot 9D, with its own git repo
  # first so piggy's commits never walk up to the worktree's.
  _pass git init >/dev/null 2>&1 || { echo "pass git init failed" >&2; return 1; }
  _pass init >/dev/null 2>&1 || { echo "pass init failed" >&2; _show; return 1; }
  local guid
  guid="$("$PIGGY_BIN" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)"
  [[ -n $guid ]] || { echo "no GUID from piggy tool -j list" >&2; return 1; }

  # Rotate to KEY_B, then seal KEY_B at the entry `card init` would use.
  _tool -K default set-admin - <<<"$KEY_B"
  [[ $status -eq 0 ]] || { echo "rotation to KEY_B failed: $output" >&2; _show; return 1; }
  printf '%s\n' "$KEY_B" | _pass insert -m "piv/$guid/management-key" >/dev/null || {
    echo "pass insert failed" >&2; return 1; }

  # The bare form finds the selected card's entry; the named form the same
  # entry by name; the current key never appears on the command line.
  # (The store read goes through the card, so the test askpass announces
  # the PIN it supplies on stderr: the op itself prints nothing.)
  _tool -K @store auth-test
  [[ $status -eq 0 && $output != *"failed to authenticate"* ]] || {
    echo "@store: want exit 0; got $status" >&2; _show; return 1; }
  _tool -K "@store:piv/$guid/management-key" auth-test
  [[ $status -eq 0 ]] || { echo "@store:<name>: got $status: $output" >&2; _show; return 1; }
  _tool -K @store:piv/nope/management-key auth-test
  [[ $status -eq 1 && $output == *"piv/nope/management-key"* ]] || {
    echo "a missing entry: want exit 1 naming it; got $status: $output" >&2; return 1; }
  _tool -K default auth-test
  [[ $status -eq 1 ]] || { echo "the factory key authenticates although the card was rotated" >&2; _show; return 1; }

  # The store-held key authenticates a write op too: rotate back to the
  # factory key with it, the rollback a rotation ends with if ever wanted.
  _tool -K @store set-admin default
  [[ $status -eq 0 && $output != *"failed to"* ]] || { echo "@store set-admin default: got $status" >&2; _show; return 1; }
  _tool -K default auth-test
  [[ $status -eq 0 ]] || { echo "the factory key does not authenticate after the rollback" >&2; _show; return 1; }
  # The store read was a card decrypt under the safety net: no escaped prompt.
  if grep -q "REFUSING to prompt" "$FIBBY_LOG" 2>/dev/null; then
    echo "a prompt escaped" >&2; return 1
  fi
}
