#!/usr/bin/env bash
#
# piggy-test-askpass-wrong-first: a test askpass that supplies a WRONG PIN on
# its first invocation, then the correct PIGGY_TEST_FIB_PIN on every
# subsequent call. Exercises the agent's bounded PIN-retry path (piggy#142):
# the first verify fails with PinIncorrect, the agent re-prompts, and the
# second prompt supplies the right PIN so the operation completes.
#
# Requires:
#   PIGGY_TEST_ASKPASS_MARKER  a writable path used to remember that the first
#                              (wrong) PIN was already handed out
#   PIGGY_TEST_FIB_PIN         the correct PIN (fibby default 123456)
# Optional:
#   PIGGY_TEST_WRONG_PIN       the wrong PIN to supply first (default 000000)
#
# Like the sibling piggy-test-askpass.sh it NEVER prompts interactively and
# NEVER touches /dev/tty; all stderr is tagged so test logs can be grepped.

set -euo pipefail

prompt="${1:-<no prompt supplied>}"
marker="${PIGGY_TEST_ASKPASS_MARKER:?PIGGY_TEST_ASKPASS_MARKER must be set}"
: "${PIGGY_TEST_FIB_PIN:?PIGGY_TEST_FIB_PIN must be set}"
ctx="${PIGGY_ASKPASS_CONTEXT:-<unset>}"

banner() {
  printf '[piggy-test-askpass-wrong-first] %s\n' "$*" >&2
}

if [[ -e $marker ]]; then
  banner "supplying correct PIN for prompt: $prompt (context: $ctx)"
  printf '%s\n' "$PIGGY_TEST_FIB_PIN"
else
  : >"$marker"
  banner "supplying WRONG PIN for prompt: $prompt (context: $ctx)"
  printf '%s\n' "${PIGGY_TEST_WRONG_PIN:-000000}"
fi
