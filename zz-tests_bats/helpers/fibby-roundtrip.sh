#!/usr/bin/env bash
# fibby tier-4 differential gate: pivy-box stream encrypt + decrypt
# round-trip against a real PIV card (slot 9D) routed entirely through
# fibby's pcsc-lite daemon implementation. Exercises every command in
# fibby's server.rs dispatch table that piggy's read path needs (SELECT,
# GET DATA, VERIFY, GENERAL AUTHENTICATE ECDH) plus the full ebox
# AES-256-GCM payload round-trip.
#
# Invoked as the CLIENT_CMD to `just debug-fibby-proxy bash <thispath>`,
# which sets PCSCLITE_CSOCK_NAME to a fibby socket pointed at the
# real reader and tears fibby down on exit.
#
# Prereqs:
# - A PIV card inserted with an ECDH-capable key already generated in
#   slot 9D. Bootstrap a throwaway card by running, in order:
#     just debug-fibby-proxy pivy-tool -K default init
#     just debug-fibby-proxy pivy-tool -P 123456 -K default -a eccp256 generate 9d
# - PIGGY_TEST_FIB_PIN env var set to the card's PIN (default 123456).
#
# Non-destructive on the card: only reads slot 9D's cert + does ECDH.
set -uo pipefail

unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK 2>/dev/null || true

# In-repo askpass stub (CLAUDE.md). Returns PIGGY_TEST_FIB_PIN non-
# interactively; never prompts, never touches /dev/tty, never zenity.
export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
export SSH_ASKPASS_REQUIRE=force
: "${PIGGY_TEST_FIB_PIN:=123456}"
export PIGGY_TEST_FIB_PIN
export DISPLAY=

tpl_dir=$(mktemp -d /tmp/fibby-tpl.XXXXXX)
tpl="$tpl_dir/throwaway.tpl"
ebox="$tpl_dir/secret.ebox"
trap 'rm -rf "$tpl_dir"' EXIT

echo "=== discover card GUID via pivy-tool list (through fibby) ==="
guid=$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
[[ -n $guid ]] || {
  echo "no GUID found from pivy-tool list — is slot 9D initialized?"
  exit 1
}
echo "  guid: $guid"

plaintext="hello-from-fibby-validation"

echo
echo "=== tpl create (primary local-guid $guid) ==="
# pivy-box CLI shape: <type> <op> [options]. Global flags AFTER op.
pivy-box tpl create -b -f "$tpl" primary local-guid "$guid"
echo "  tpl: $(wc -c <"$tpl") bytes"

echo
echo "=== stream encrypt ==="
printf '%s' "$plaintext" | pivy-box stream encrypt -b -r -R -f "$tpl" >"$ebox"
echo "  ebox: $(wc -c <"$ebox") bytes"

echo
# Decrypt runs WITHOUT -b so pivy-box falls back to SSH_ASKPASS for
# PIN — we have no /dev/tty in this pipeline. -b on encrypt is fine
# (encrypt doesn't touch the card).
echo "=== stream decrypt (SSH_ASKPASS supplies PIN) ==="
decrypted=$(pivy-box stream decrypt -r -R <"$ebox" 2>"$tpl_dir/decrypt.err") || {
  echo "  decrypt failed; stderr:"
  cat "$tpl_dir/decrypt.err"
  exit 1
}
echo "  decrypted: '$decrypted'"

echo
if [[ $decrypted == "$plaintext" ]]; then
  echo "=== ROUND-TRIP OK ==="
  exit 0
else
  echo "=== ROUND-TRIP MISMATCH ==="
  echo "  expected: '$plaintext'"
  echo "  got:      '$decrypted'"
  exit 1
fi
