#!/usr/bin/env bash
#
# piggy-askpass: user-facing PIN-prompt helper for piggy.
#
# Set in your shell or via piggy-agent's env to add piggy-aware
# context to PIN prompts:
#
#     export SSH_ASKPASS="$HOME/repos/piggy/contrib/piggy-askpass.sh"
#     export SSH_ASKPASS_REQUIRE=force   # optional, force askpass
#
# Then any path that goes through ssh-add / pivy-agent / etc and looks
# up SSH_ASKPASS will receive a prompt that includes:
#
#   * The parent process name + PID — answers "who asked?"
#   * The PIGGY_ASKPASS_CONTEXT env var — caller-supplied free-form
#     context such as "scripted-batch-unlock" or "interop-tpl-create".
#   * A visible [TEST] banner when either PIGGY_ASKPASS_CONTEXT starts
#     with "piggy-test:" or the prompt itself contains that prefix
#     (which it does for every test fixture per CLAUDE.md's
#     "Test-fixture ebox part names" policy, bffa22a).
#   * The original prompt text, unchanged.
#
# Render targets (in priority order):
#
#   /dev/tty  — terminal-attached sessions; reads with echo disabled.
#   zenity    — graphical sessions ($DISPLAY set, zenity installed).
#   error     — neither available; refuses with stderr explanation.
#
# This is the user-facing sibling to
# zz-tests_bats/helpers/piggy-test-askpass.sh, which is the
# *test-harness* askpass that NEVER prompts. The two are explicitly
# different: this one is for real human-facing PIN entry; that one
# refuses unless PIGGY_TEST_FIB_PIN is set.
#
# See piggy#33 for the design discussion. To smoke-test without
# entering a PIN, set PIGGY_ASKPASS_DRY_RUN=1 — the script will emit
# the rendered context to stderr and exit 0 without reading.

set -euo pipefail

prompt="${1:-<no prompt supplied>}"
context="${PIGGY_ASKPASS_CONTEXT:-}"

# Parent-process info. ps is universal on Linux + Darwin and avoids
# the /proc-vs-no-/proc split. Tolerate ps failing (chrooted, etc).
parent_pid="$PPID"
parent_comm="$(ps -o comm= -p "$parent_pid" 2>/dev/null | tr -d '[:space:]')"
[[ -z "$parent_comm" ]] && parent_comm="?"

# [TEST] heuristic: caller env OR prompt itself carries the test marker.
test_tag=""
if [[ "$context" == piggy-test:* ]] || [[ "$prompt" == *piggy-test:* ]]; then
  test_tag="[TEST]"
fi

# Multi-line context block, used by all render targets.
render_context() {
  if [[ -n "$test_tag" ]]; then
    printf '%s\n' "$test_tag"
  fi
  printf 'Parent: %s (PID %s)\n' "$parent_comm" "$parent_pid"
  if [[ -n "$context" ]]; then
    printf 'Context: %s\n' "$context"
  fi
  printf '\n%s\n' "$prompt"
}

# Dry-run: emit the rendered context to stderr and exit. No PIN read.
# Used by the bats test in zz-tests_bats/conformance/piggy_askpass.bats.
if [[ "${PIGGY_ASKPASS_DRY_RUN:-}" == "1" ]]; then
  render_context >&2
  exit 0
fi

# Render target 1: /dev/tty. Most reliable in terminal sessions —
# stdin/stdout may be piped to the parent (ssh-add does this), but
# the controlling terminal usually still answers. read -s suppresses
# echo without an external dep.
if [[ -e /dev/tty ]] && exec 3</dev/tty 4>/dev/tty 2>/dev/null; then
  render_context >&4
  pin=""
  IFS= read -r -s pin <&3
  echo >&4   # newline after the (silent) input
  exec 3<&- 4>&-
  printf '%s\n' "$pin"
  exit 0
fi

# Render target 2: zenity (graphical sessions).
if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]] && command -v zenity >/dev/null 2>&1; then
  body="$(render_context)"
  # zenity --entry --hide-text reads a single line of obscured input
  # and writes it to stdout; non-zero exit on cancel.
  pin="$(zenity --entry --hide-text --title="piggy PIV PIN" --text="$body" 2>/dev/null)" || exit $?
  printf '%s\n' "$pin"
  exit 0
fi

# Neither render target available. Refuse; explain why.
{
  printf '[piggy-askpass] no render target available.\n'
  printf '[piggy-askpass] /dev/tty unreadable AND no zenity-on-$DISPLAY.\n'
  printf '[piggy-askpass] prompt was: %s\n' "$prompt"
  printf '[piggy-askpass] context:    %s\n' "${context:-(unset)}"
  printf '[piggy-askpass] parent:     %s (PID %s)\n' "$parent_comm" "$parent_pid"
} >&2
exit 2
