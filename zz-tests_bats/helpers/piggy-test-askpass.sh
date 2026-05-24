#!/usr/bin/env bash
#
# piggy-test-askpass: non-interactive askpass for piggy's test harnesses.
#
# Purpose: prevent PIN prompts from escaping to real interactive dialogs
# (zenity, kdialog, /dev/tty, osascript, etc) during piggy test runs.
# When a just recipe or bats harness sets:
#
#     SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
#     SSH_ASKPASS_REQUIRE=force
#     DISPLAY=""
#
# …any pivy-box / ssh-add / pivy-agent path that would normally prompt
# instead invokes THIS script. Depending on how the recipe authorized
# automation, one of two things happens:
#
#   (a) The recipe exported PIGGY_TEST_FIB_PIN. This script supplies it
#       on stdout non-interactively, and stderr gets an identifying
#       banner so the test log shows which prompt was answered.
#
#   (b) The recipe did NOT export PIGGY_TEST_FIB_PIN. This script refuses
#       and exits non-zero, with the prompt text echoed to stderr. NO
#       interactive fallback. NO /dev/tty. NO GUI.
#
# Either way:
#
#   * No real user is ever asked for a PIN from within a test.
#   * No real card PIN retry is ever consumed.
#   * Any dialog that somehow rendered before this script ran was for a
#     test, not a real unlock — the text in the prompt carries the
#     `piggy-test:` part-name prefix (see bffa22a / CLAUDE.md) so the
#     operator can tell even from the raw dialog.
#
# Design notes: tracked in #35 (test-harness safety net). The bundled
# end-user askpass with rich process/context metadata is #33.
#
# Usage from inside a recipe (escape layer):
#
#     askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
#     export SSH_ASKPASS="$askpass" \
#            SSH_ASKPASS_REQUIRE=force \
#            DISPLAY="" \
#            PIGGY_TEST_FIB_PIN=123456
#     <run bats / ssh-add -X / pivy-box here>

set -euo pipefail

# Argv[1] is the prompt text (ssh-add and pivy-box both pass it).
prompt="${1:-<no prompt supplied>}"

banner() {
  # All stderr output from this script is tagged so test logs can be
  # grepped for `piggy-test-askpass` to find every invocation.
  printf '[piggy-test-askpass] %s\n' "$*" >&2
}

if [[ -n ${PIGGY_TEST_FIB_PIN:-} ]]; then
  banner "supplying PIGGY_TEST_FIB_PIN for prompt: $prompt"
  # No trailing newline manipulation: ssh-add and pivy-box both trim the
  # first line via strcspn / similar. A plain echo is the simplest.
  printf '%s\n' "$PIGGY_TEST_FIB_PIN"
  exit 0
fi

banner "REFUSING to prompt interactively."
banner ""
banner "A process inside the piggy test harness tried to open a PIN"
banner "prompt without PIGGY_TEST_FIB_PIN set. This is almost certainly"
banner "a test-harness setup bug, not a real unlock."
banner ""
banner "Prompt text was:"
banner "  $prompt"
banner ""
banner "To authorize non-interactive PIN entry from tests, set in the"
banner "recipe that owns the harness:"
banner ""
banner "  export PIGGY_TEST_FIB_PIN=<fib-pin, typically 123456>"
banner ""
banner "See zz-tests_bats/helpers/piggy-test-askpass.sh for details,"
banner "and amarbel-llc/piggy#35 for the broader safety-net policy."
exit 2
