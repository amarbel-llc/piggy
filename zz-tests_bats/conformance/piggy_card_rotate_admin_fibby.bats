#! /usr/bin/env bats
#
# `piggy card rotate-admin` over fibby (docs/plans/2026-11-19-card-rotate-admin-design.md;
# circus#448): the management-key rotation as one verb. fibby starts on its
# factory 3DES key with a seeded slot 9D, which the store's piggy-ids names,
# so the sealed entry decrypts against the same card the key is for, as on
# a real host. The typed word comes on stdin (the tty frontend reads stdin
# when it is not a terminal); the one 9D PIN of the read-back comes from the
# test askpass under the safety net.
#
# Rows: the first rotation (sealed, read back, rotated, proven both ways,
# `-K @store` authenticates afterwards); a word other than `seal` changes
# nothing (exit 4); a later rotation seals at the pending entry and promotes
# it after the proof; a refused PIN at the read-back rolls the seal back
# with the card untouched. No key ever appears in the output.
#
# Required env (supplied by `just test-bats-conformance-card-rotate-admin-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-card-rotate-admin-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  # piggy-testing(7) PIN PROMPT SAFETY NET: the read-back decrypts through
  # the card, so the PIN is supplied by the test askpass, never a prompt.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK

  WORKDIR="$(mktemp -d -t rotadm.XXXXXX)"
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

  # A store whose recipient is this card's slot 9D, with its own git repo
  # first so piggy's commits never walk up to the worktree's.
  _pass git init >/dev/null 2>&1 || { echo "pass git init failed" >&2; return 1; }
  _pass init >/dev/null 2>&1 || { echo "pass init failed" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  GUID="$("$PIGGY_BIN" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)"
  [[ -n $GUID ]] || { echo "no GUID from piggy tool -j list" >&2; return 1; }
  ENTRY="$STORE/piv/$GUID/management-key.ebox"
  PENDING="$STORE/piv/$GUID/management-key.pending.ebox"
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

_tool() {
  PIGGY_STORE_DIR="$STORE" run "$PIGGY_BIN" tool "$@"
}

_pass() {
  PIGGY_STORE_DIR="$STORE" "$PIGGY_BIN" pass "$@"
}

# rotate-admin with WORD on stdin (the tty frontend's answer channel when
# stdin is not a terminal).
_rotate() {
  local word="$1"
  PIGGY_STORE_DIR="$STORE" run "$PIGGY_BIN" card rotate-admin --guid "$GUID" <<<"$word"
}

_show() {
  printf '%s\n' "$output" >&2
  tail -30 "$FIBBY_LOG" >&2 || true
}

# No 48-hex-digit string (a management key) anywhere in what was printed.
_no_key_printed() {
  if grep -qE '(^|[^0-9a-fA-F])[0-9a-fA-F]{48}([^0-9a-fA-F]|$)' <<<"$output"; then
    echo "a 48-hex-digit string was printed" >&2; return 1
  fi
}

function the_first_rotation_seals_reads_back_rotates_and_proves { # @test
  _rotate seal
  [[ $status -eq 0 ]] || { echo "want exit 0, got $status" >&2; _show; return 1; }
  _no_key_printed || { _show; return 1; }
  # A TAP plan with every point ok, naming the steps.
  [[ $output == *"1.."* && $output != *"not ok"* ]] || { echo "the TAP is not all ok" >&2; _show; return 1; }
  for want in "the operator typed the word" "the sealed copy reads back identical" \
    "the card takes the new key" "the old key no longer authenticates"; do
    [[ $output == *"$want"* ]] || { echo "no point '$want'" >&2; _show; return 1; }
  done
  [[ -s $ENTRY ]] || { echo "no sealed entry at $ENTRY" >&2; _show; return 1; }
  [[ ! -e $PENDING ]] || { echo "a pending entry after a first rotation" >&2; return 1; }
  # The proof, read-only, as the sitting's checklist ends.
  _tool -K @store auth-test
  [[ $status -eq 0 ]] || { echo "the sealed key does not authenticate: $output" >&2; _show; return 1; }
  _tool -K default auth-test
  [[ $status -eq 1 ]] || { echo "the factory key still authenticates" >&2; _show; return 1; }
  # The read-back went through the card under the safety net: no escaped prompt.
  if grep -q "REFUSING to prompt" "$FIBBY_LOG" 2>/dev/null; then
    echo "a prompt escaped" >&2; return 1
  fi
}

function a_word_other_than_seal_changes_nothing { # @test
  _rotate no
  [[ $status -eq 4 ]] || { echo "want exit 4 (declined), got $status" >&2; _show; return 1; }
  [[ $output == *"not ok"* && $output == *"typed the word"* ]] || {
    echo "the TAP does not name the word point" >&2; _show; return 1; }
  [[ ! -e $ENTRY ]] || { echo "an entry was sealed without the word" >&2; return 1; }
  _tool -K default auth-test
  [[ $status -eq 0 ]] || { echo "the card changed without the word" >&2; _show; return 1; }
}

function a_later_rotation_seals_at_pending_and_promotes_after_the_proof { # @test
  _rotate seal
  [[ $status -eq 0 ]] || { echo "first rotation: want exit 0, got $status" >&2; _show; return 1; }
  local first_sha
  first_sha=$(sha256sum "$ENTRY" | cut -d' ' -f1)

  _rotate seal
  [[ $status -eq 0 ]] || { echo "later rotation: want exit 0, got $status" >&2; _show; return 1; }
  _no_key_printed || { _show; return 1; }
  [[ $output == *"the pending entry is promoted over the entry"* ]] || {
    echo "no promotion point" >&2; _show; return 1; }
  [[ ! -e $PENDING ]] || { echo "the pending entry was not promoted away" >&2; return 1; }
  [[ $(sha256sum "$ENTRY" | cut -d' ' -f1) != "$first_sha" ]] || {
    echo "the entry still holds the first key" >&2; return 1; }
  # The promoted key is the card's; the first one and the factory key are not.
  _tool -K @store auth-test
  [[ $status -eq 0 ]] || { echo "the promoted key does not authenticate: $output" >&2; _show; return 1; }
  _tool -K default auth-test
  [[ $status -eq 1 ]] || { echo "the factory key authenticates after two rotations" >&2; return 1; }
}

function a_refused_pin_at_the_read_back_rolls_the_seal_back { # @test
  # Without the test PIN the askpass refuses, so the read-back (a 9D decrypt)
  # fails after the seal: the entry is removed and the card is untouched.
  unset PIGGY_TEST_FIB_PIN
  _rotate seal
  [[ $status -ne 0 ]] || { echo "a refused read-back ended 0" >&2; _show; return 1; }
  [[ $output == *"the sealed copy reads back identical"* && $output == *"card is untouched"* ]] || {
    echo "the TAP does not name the read-back stop" >&2; _show; return 1; }
  [[ ! -e $ENTRY ]] || { echo "the seal was not rolled back" >&2; return 1; }
  export PIGGY_TEST_FIB_PIN=123456
  _tool -K default auth-test
  [[ $status -eq 0 ]] || { echo "the card changed although the read-back failed" >&2; _show; return 1; }
}
