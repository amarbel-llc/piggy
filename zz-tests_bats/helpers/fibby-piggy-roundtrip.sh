#!/usr/bin/env bash
# fibby tier-4 differential gate (piggy layer): pass init + insert + show
# round-trip against a real PIV card, routed entirely through fibby's
# pcsc-lite daemon implementation. Companion to fibby-roundtrip.sh,
# which exercises the same crypto path at the pivy-box level — this one
# adds piggy's wrapper (piggy-ids detect-pubkey, store layout, ebox
# write, the find_inner_git_dir-then-skip "gitless" branch).
#
# Invoked as the CLIENT_CMD to `just debug-fibby-proxy bash <thispath>`,
# which sets PCSCLITE_CSOCK_NAME to a fibby socket pointed at the real
# reader and tears fibby down on exit.
#
# Prereqs (same as fibby-roundtrip.sh):
# - A PIV card inserted with an ECDH-capable key already generated in
#   slot 9D. Bootstrap a throwaway via:
#     just debug-fibby-proxy pivy-tool -K default init
#     just debug-fibby-proxy pivy-tool -P 123456 -K default -a eccp256 generate 9d
# - PIGGY_TEST_FIB_PIN env var set to the card's PIN (default 123456).
# - The debug build of piggy + piggy-ids (run `just build-rust` if missing).
#
# Non-destructive on the card: read-only (insert encrypts client-side,
# show does ECDH decrypt).
set -uo pipefail

unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK 2>/dev/null || true

# In-repo askpass stub (CLAUDE.md). Returns PIGGY_TEST_FIB_PIN non-
# interactively; never prompts, never touches /dev/tty, never zenity.
export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
export SSH_ASKPASS_REQUIRE=force
: "${PIGGY_TEST_FIB_PIN:=123456}"
export PIGGY_TEST_FIB_PIN
export DISPLAY=

PIGGY_BIN="$PWD/target/debug/piggy"
export PIGGY_IDS_PATH="$PWD/target/debug/piggy-ids"
[[ -x $PIGGY_BIN ]] || {
  echo "missing $PIGGY_BIN — run 'just build-rust' first" >&2
  exit 1
}
[[ -x $PIGGY_IDS_PATH ]] || {
  echo "missing $PIGGY_IDS_PATH — run 'just build-rust' first" >&2
  exit 1
}

echo "=== discover card GUID via pivy-tool list (through fibby) ==="
guid=$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
[[ -n $guid ]] || {
  echo "no GUID found; is slot 9D initialized?"
  exit 1
}
echo "  guid: $guid"

PIGGY_STORE_DIR=$(mktemp -d /tmp/piggy-fibby-store.XXXXXX)
export PIGGY_STORE_DIR
trap 'rm -rf "$PIGGY_STORE_DIR"' EXIT
echo "  store: $PIGGY_STORE_DIR (gitless — find_inner_git_dir returns None, piggy skips commits)"

echo
echo "=== piggy pass init -g $guid ==="
"$PIGGY_BIN" pass init -g "$guid"
echo "  piggy-ids written:"
sed 's/^/    /' "$PIGGY_STORE_DIR/piggy-ids"

plaintext="secret-via-fibby-tier4"

echo
echo "=== piggy pass insert -e foo/bar (stdin: '$plaintext') ==="
# `-e`/`--echo` reads exactly one line from stdin (piggy preserves
# passwordstore convention: the secret is the first line + a trailing
# newline). Stderr prompt is decorative; the actual bytes come from
# the pipe.
printf '%s\n' "$plaintext" | "$PIGGY_BIN" pass insert -e foo/bar

echo
echo "=== piggy pass show foo/bar ==="
got=$("$PIGGY_BIN" pass show foo/bar 2>"$PIGGY_STORE_DIR/show.err") || {
  echo "  show failed; stderr:"
  cat "$PIGGY_STORE_DIR/show.err"
  exit 1
}
echo "  got: '$got'"

echo
if [[ $got == "$plaintext" ]]; then
  echo "=== PIGGY ROUND-TRIP OK ==="
  exit 0
else
  echo "=== MISMATCH ==="
  echo "  expected: '$plaintext'"
  echo "  got:      '$got'"
  exit 1
fi
