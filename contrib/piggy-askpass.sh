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
#   zenity    — graphical sessions (zenity installed; we don't gate
#               on $DISPLAY/$WAYLAND_DISPLAY, since macOS zenity finds
#               the Aqua session without either, and launchd-spawned
#               agents reach this script with a scrubbed env).
#   error     — neither available; refuses with stderr explanation.
#
# SSH_ASKPASS_REQUIRE (piggy#166) makes the routing caller-selectable,
# following OpenSSH's semantics:
#
#   force          — skip the /dev/tty branch entirely; always render
#                    via zenity. For agent-driven / scripted contexts
#                    that must never steal a stray terminal.
#   never          — tty-or-nothing; never fall through to zenity. If
#                    /dev/tty is unusable, refuse with exit 2. For
#                    interactive callers that must never get a
#                    surprise GUI dialog.
#   unset / prefer — the priority order above (tty first, then
#                    zenity).
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
#
# Env vars consumed by the zenity render target (piggy#103):
#
#   PIGGY_ASKPASS_TIMEOUT   Seconds before zenity self-cancels.
#                           Default 30. Bounds head-of-line blocking
#                           when a zenity window appears off-screen
#                           or the user is AFK. On timeout zenity
#                           exits non-zero (5), which propagates as
#                           auth-denied — the request that triggered
#                           the prompt fails, but the agent's poll
#                           loop is freed within the deadline.
#
#   PIGGY_ASKPASS_NOTIFIER  Path to a `notify-send`-style dispatcher
#                           (argv: title, message). When set, fired
#                           detached just before zenity opens so the
#                           user sees a heads-up even if zenity
#                           itself is hidden / off-screen / on a
#                           different display. Falls back to
#                           $SSH_NOTIFY_SEND (the same env-var
#                           piggy-agent's nix module already plumbs),
#                           then `terminal-notifier` (darwin) /
#                           `notify-send` (linux) on PATH. Best-
#                           effort: skipped silently when no
#                           dispatcher is reachable. Detached so a
#                           hanging notifier cannot wedge the
#                           prompt.
#
# Operator acts (RFC 0012 §2.6): when the agent is about to sign an
# operator act it sets PIGGY_ASKPASS_KIND to the act's display class
# (quote, escalation or certificate) and puts the namespace and the exact
# text being signed in PIGGY_ASKPASS_CONTEXT. Each class then gets its own
# banner, window title, confirm button and dialog, so the prompt cannot be
# mistaken for a routine PIN prompt, nor an escalation for a quote. In
# zenity every class is a form whose text opens with a coloured band
# carrying the class's symbol, so the class is recognisable before a word
# of the text is read (piggy#319):
#
#   quote        blue band, ❝; one PIN field; button "Sign quote".
#   certificate  amber band, ✎; one PIN field; button "Issue certificate".
#   escalation   red band, ⚠; the PIN field and a second field in which the
#                word ESCALATE must be typed; button "Grant escalation".
#                On a tty the word is asked for on a line of its own.
#
# The text is shown whole or the prompt fails; an unknown class fails too.
# A PIN dialog does not scroll, so an act whose rendered text is taller than
# $operator_act_scroll_lines lines is first shown in a scrollable, read-only
# zenity --text-info window (plain text, never markup) with an "I have read
# the whole text" box that must be ticked before OK; cancelling it, or
# letting it time out, cancels the act. The per-class PIN dialog follows.
# Reading a text takes longer than typing a PIN, so the zenity timeout
# defaults to 120 seconds for these. With PIGGY_ASKPASS_KIND unset nothing
# here applies and the prompt is the routine one.
#
# Diagnostic log: zenity's stderr and a per-invocation header are
# appended to $XDG_LOG_HOME/piggy/askpass.log (default
# $HOME/.local/log/piggy/askpass.log per XDG_LOG_HOME(7)). Safe to
# delete at any time.

set -euo pipefail

prompt="${1:-<no prompt supplied>}"
context="${PIGGY_ASKPASS_CONTEXT:-}"
kind="${PIGGY_ASKPASS_KIND:-}"
require="${SSH_ASKPASS_REQUIRE:-}"

# The word an escalation makes the operator type, on top of the PIN.
escalation_word="ESCALATE"

# The tallest operator-act text, in lines of the rendered prompt (banner,
# parent, context and prompt), shown in the PIN dialog alone. Fifteen lines
# fit a zenity PIN dialog on a small laptop screen; anything taller is read
# in a scrolling window first, so no part of it can sit below the screen's
# edge unseen (RFC 0012 §2.6).
operator_act_scroll_lines=15

# What sets one class of operator act apart from the others and from a
# routine prompt: the banner over the text, the window title, the confirm
# button, and in zenity a band in the class's colour with its symbol. One
# function per class, so a class can grow its own rendering without
# touching the others; the dialogs themselves are the zenity_<class>
# functions further down. The symbols are BMP dingbats, which the common
# desktop fonts carry; colour emoji are not relied on.
class_quote() {
  class_banner="=== OPERATOR ACT: QUOTE — you are signing words already on record ==="
  class_title="piggy operator act: QUOTE"
  class_ok_label="Sign quote"
  class_band="❝  QUOTE — signing words already on record"
  class_band_background="#1c71d8"
  class_band_foreground="#ffffff"
}

class_escalation() {
  class_banner="!!! OPERATOR ACT: ESCALATION — you are GRANTING AUTHORITY !!!"
  class_title="piggy operator act: ESCALATION (grants authority)"
  class_ok_label="Grant escalation"
  class_band="⚠  ESCALATION — you are GRANTING AUTHORITY  ⚠"
  class_band_background="#c01c28"
  class_band_foreground="#ffffff"
}

class_certificate() {
  class_banner="=== OPERATOR ACT: CERTIFICATE — you are certifying a key ==="
  class_title="piggy operator act: CERTIFICATE"
  class_ok_label="Issue certificate"
  class_band="✎  CERTIFICATE — certifying a key"
  class_band_background="#e5a50a"
  class_band_foreground="#000000"
}

class_banner=""
class_title="piggy PIV PIN"
class_ok_label=""
class_band=""
class_band_background=""
class_band_foreground=""
default_timeout=30
case "$kind" in
  "") ;;
  quote | escalation | certificate)
    "class_$kind"
    default_timeout=120
    ;;
  *)
    # A class this helper does not know how to present. Rendering it as a
    # routine prompt would hide what kind of act the PIN authorizes.
    printf '[piggy-askpass] unknown PIGGY_ASKPASS_KIND %q; refusing to prompt.\n' "$kind" >&2
    exit 2
    ;;
esac
zenity_timeout="${PIGGY_ASKPASS_TIMEOUT:-$default_timeout}"

# Parent-process info. ps is universal on Linux + Darwin and avoids
# the /proc-vs-no-/proc split. Tolerate ps failing (chrooted, etc).
#
# `|| true` is load-bearing: under `set -euo pipefail`, a pipeline
# that exits non-zero would propagate to the assignment, trip `set
# -e`, and exit the whole script with the pipeline's exit code
# (silently, without writing anything to stderr — bash exits at the
# assignment, before the next line runs). This bit us on macOS-15
# CI under `env -i` where one of ps/tr exits 126 — see #92. The
# trailing `|| true` matches the "Tolerate ps failing" intent stated
# above.
parent_pid="$PPID"
parent_comm="$(ps -o comm= -p "$parent_pid" 2>/dev/null | tr -d '[:space:]' || true)"
[[ -z $parent_comm ]] && parent_comm="?"

# [TEST] heuristic: caller env OR prompt itself carries the test marker.
test_tag=""
if [[ $context == piggy-test:* ]] || [[ $prompt == *piggy-test:* ]]; then
  test_tag="[TEST]"
fi

# Multi-line context block, used by all render targets.
render_context() {
  if [[ -n $test_tag ]]; then
    printf '%s\n' "$test_tag"
  fi
  if [[ -n $class_banner ]]; then
    printf '%s\n' "$class_banner"
  fi
  printf 'Parent: %s (PID %s)\n' "$parent_comm" "$parent_pid"
  if [[ -n $context ]]; then
    printf 'Context: %s\n' "$context"
  fi
  printf '\n%s\n' "$prompt"
}

# Dry-run: emit the rendered context to stderr and exit. No PIN read.
# Used by the bats test in zz-tests_bats/conformance/piggy_askpass.bats.
if [[ ${PIGGY_ASKPASS_DRY_RUN:-} == "1" ]]; then
  render_context >&2
  exit 0
fi

# Render target 1: /dev/tty. Most reliable in terminal sessions —
# stdin/stdout may be piped to the parent (ssh-add does this), but
# the controlling terminal usually still answers. read -s suppresses
# echo without an external dep.
#
# Skipped entirely under SSH_ASKPASS_REQUIRE=force (piggy#166):
# agent-driven / scripted callers export force so the prompt always
# lands on zenity, never on whatever stray tty they happen to hold.
#
# Probe /dev/tty before the real `exec` redirect: when there's no
# controlling terminal (pivy-agent fork, launchd-spawned context),
# bash emits "/dev/tty: Device not configured" on stderr *before*
# any `2>/dev/null` on the same `exec` line takes effect. A subshell
# probe contains that noise so it never reaches pivy-agent's logs.
if [[ $require != force ]] && [[ -e /dev/tty ]] && (: >/dev/tty) 2>/dev/null; then
  exec 3</dev/tty 4>/dev/tty
  render_context >&4
  pin=""
  IFS= read -r -s pin <&3
  echo >&4 # newline after the (silent) input
  if [[ $kind == escalation ]]; then
    typed=""
    printf 'Type %s to grant this escalation: ' "$escalation_word" >&4
    IFS= read -r typed <&3
    if [[ $typed != "$escalation_word" ]]; then
      printf 'Not granted.\n' >&4
      exit 1
    fi
  fi
  exec 3<&- 4>&-
  printf '%s\n' "$pin"
  exit 0
fi

# SSH_ASKPASS_REQUIRE=never is tty-or-nothing (piggy#166): reaching
# this point means the tty branch didn't render, so refuse rather
# than fall through to zenity. Exit 2 matches the no-render-target
# refusal below.
if [[ $require == never ]]; then
  {
    printf '[piggy-askpass] SSH_ASKPASS_REQUIRE=never but /dev/tty is unusable.\n'
    printf '[piggy-askpass] refusing to fall through to zenity under the never policy.\n'
    printf '[piggy-askpass] prompt was: %s\n' "$prompt"
  } >&2
  exit 2
fi

# Resolve a heads-up notifier (piggy#103). Priority order:
#   1. $PIGGY_ASKPASS_NOTIFIER (explicit caller override)
#   2. $SSH_NOTIFY_SEND        (set by piggy-agent's nix module)
#   3. terminal-notifier       (darwin nix-pkg)
#   4. notify-send             (linux libnotify)
# Empty result = silent skip. The dispatcher is invoked detached
# (subshell + background) so a hanging notify implementation cannot
# block the zenity prompt or wedge the agent further.
resolve_notifier() {
  if [[ -n ${PIGGY_ASKPASS_NOTIFIER:-} ]]; then
    printf '%s\n' "$PIGGY_ASKPASS_NOTIFIER"
    return 0
  fi
  if [[ -n ${SSH_NOTIFY_SEND:-} ]]; then
    printf '%s\n' "$SSH_NOTIFY_SEND"
    return 0
  fi
  local cand
  for cand in terminal-notifier notify-send; do
    if command -v "$cand" >/dev/null 2>&1; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}

fire_heads_up() {
  local notifier title body
  notifier="$(resolve_notifier)" || return 0
  title="piggy-agent: PIN required"
  if [[ -n $kind ]]; then
    title="piggy-agent: operator act ($kind) awaits your PIN"
  fi
  body="${prompt} (${parent_comm} PID ${parent_pid})"
  # Detached: subshell with backgrounded invocation. stderr/stdout
  # silenced so a broken notifier cannot pollute pivy-agent's logs.
  # The outer subshell exits immediately; the inner process is
  # adopted by init / launchd and runs to completion or death on
  # its own.
  ("$notifier" "$title" "$body" >/dev/null 2>&1 &) >/dev/null 2>&1 || true
}

# Reattach to the live graphical session before rendering via zenity.
#
# piggy-agent is a long-lived `systemd --user` service whose environment is
# frozen at unit-start. If it started before the compositor published
# WAYLAND_DISPLAY/DISPLAY into the user-manager env (early-boot ordering), or
# the compositor was restarted after the agent came up, the inherited env is
# empty or stale. Because the PIN prompt only spawns zenity lazily at sign
# time, every signature is then refused for the agent's *entire* lifetime with
# `Gtk-WARNING: Failed to open display` (zenity exit 1), until a manual
# restart re-inherits a populated env. See amarbel-llc/piggy#179.
#
# The prompt is lazy, so by the time we reach here the display IS available
# even though piggy's frozen env predates it — re-derive it now, most-
# authoritative source first. No-op when the env already carries a display
# (the common case) and on macOS (no systemctl, no XDG_RUNTIME_DIR, so both
# branches skip and zenity reaches the Aqua session on its own).
if [[ -z ${WAYLAND_DISPLAY:-} && -z ${DISPLAY:-} ]]; then
  # 1. The systemd user-manager environment, which the compositor refreshes
  #    via `systemctl --user import-environment` after the agent forked. This
  #    is authoritative — it's the display the session actually registered.
  if command -v systemctl >/dev/null 2>&1; then
    eval "$(systemctl --user show-environment 2>/dev/null |
      grep -E '^(WAYLAND_DISPLAY|DISPLAY|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS)=' |
      sed 's/^/export /')" || true
  fi
  # 2. Fallback: discover the Wayland socket directly. XDG_RUNTIME_DIR is set
  #    by pam_systemd at login and is present even in the display-blind env,
  #    so this still works when systemctl is unavailable. The `-S` test skips
  #    the sibling `wayland-N.lock` regular files.
  if [[ -z ${WAYLAND_DISPLAY:-} && -n ${XDG_RUNTIME_DIR:-} ]]; then
    for _sock in "$XDG_RUNTIME_DIR"/wayland-*; do
      [[ -S $_sock ]] || continue
      export WAYLAND_DISPLAY="${_sock##*/}"
      break
    done
  fi
fi

# The zenity dialogs: the routine PIN prompt and one per operator-act
# class. Each reads $body and $zenity_timeout, prints the PIN on stdout
# and returns zenity's exit status, so a cancel or a timeout propagates.

zenity_routine() {
  zenity --timeout="$zenity_timeout" --entry --hide-text --title="$class_title" --text="$body"
}

# An operator act's text must reach the operator's eyes literally (RFC 0012
# §2.6), and zenity does not show --text literally. As read in zenity
# 4.2.1's source: every dialog runs it through g_strcompress, which turns
# backslash escapes into the characters they name; --forms then parses the
# result as Pango markup, where `<`, `>` and `&` are syntax and a malformed
# tag blanks the whole label. The function below undoes exactly that.
# (The routine prompt predates this and is left byte-for-byte as it was.)

# `\&` because bash 5.2+ reads a bare `&` in the replacement as "the match".
literal_for_zenity_forms() {
  local text="$1"
  text="${text//\\/\\\\}"
  text="${text//&/\&amp;}"
  text="${text//</\&lt;}"
  text="${text//>/\&gt;}"
  printf '%s' "$text"
}

# The form text of an operator act: the class's coloured band, which is the
# only markup in it and is built from the script's own constants, then the
# act's text, escaped to show literally.
operator_act_form_text() {
  printf '<span size="x-large" weight="bold" background="%s" foreground="%s"> %s </span>\n\n%s' \
    "$class_band_background" "$class_band_foreground" "$class_band" \
    "$(literal_for_zenity_forms "$body")"
}

zenity_quote() {
  zenity --timeout="$zenity_timeout" --forms \
    --title="$class_title" --ok-label="$class_ok_label" \
    --text="$(operator_act_form_text)" \
    --add-password="PIV PIN"
}

zenity_certificate() {
  zenity --timeout="$zenity_timeout" --forms \
    --title="$class_title" --ok-label="$class_ok_label" \
    --text="$(operator_act_form_text)" \
    --add-password="PIV PIN"
}

# The form answers its two fields on two lines: the PIN, then the word.
zenity_escalation() {
  local answer typed_pin typed_word
  answer="$(zenity --timeout="$zenity_timeout" --forms \
    --title="$class_title" --ok-label="$class_ok_label" \
    --text="$(operator_act_form_text)" \
    --separator=$'\n' \
    --add-password="PIV PIN" \
    --add-entry="Type $escalation_word to grant")" || return
  {
    IFS= read -r typed_pin || true
    IFS= read -r typed_word || true
  } <<<"$answer"
  if [[ $typed_word != "$escalation_word" ]]; then
    printf '[piggy-askpass] escalation not confirmed: %s was not typed.\n' "$escalation_word" >&2
    return 1
  fi
  printf '%s\n' "$typed_pin"
}

# Whether $body is too tall for a PIN dialog alone. Counted in bash: the
# script's hard dependencies stay zenity and coreutils' basics.
body_is_too_tall_for_a_pin_dialog() {
  local newlines="${body//[^$'\n']/}"
  ((${#newlines} + 1 > operator_act_scroll_lines))
}

# The scrolling read of a tall operator act. --text-info shows what it reads
# on stdin as plain text (no Pango markup, no backslash escapes), so the
# text needs none of the escaping the PIN dialogs do. OK stays disabled
# until the box is ticked; cancel and timeout both fail, which cancels the
# act. A non-editable --text-info prints nothing on OK.
zenity_read_whole_text() {
  printf '%s\n' "$body" | zenity --timeout="$zenity_timeout" --text-info \
    --title="$class_title" --width=720 --height=560 \
    --checkbox="I have read the whole text" >/dev/null
}

# Render target 2: zenity. We don't gate on $DISPLAY/$WAYLAND_DISPLAY —
# macOS zenity reaches the Aqua session without either var being set,
# and launchd-spawned agents (pivy-agent) reach this script with a
# scrubbed env. The previous gate caused pivy-agent's SSH_CONFIRM fork
# to exit 2, which pivy-agent (pivy-agent.c:1067) treats as a confirm
# failure → AUTHZ_DENIED → every signature refused. Trust zenity itself
# to fail with a clear nonzero exit if there's truly no GUI to talk to.
if command -v zenity >/dev/null 2>&1; then
  body="$(render_context)"
  # Heads-up: fire BEFORE zenity opens. When the zenity window is
  # hidden / off-screen / on a non-focused display this is the only
  # in-band signal the user gets that the agent is waiting.
  fire_heads_up
  # Capture zenity's stderr to $XDG_LOG_HOME/piggy/askpass.log (default
  # $HOME/.local/log per XDG_LOG_HOME(7)). Without this, a silently-
  # failing zenity in the launchd/pivy-agent-spawned env leaves no
  # diagnostic — the agent gets a nonzero exit and reports auth-denied
  # with no clue what GTK/wayland/zenity emitted.
  log_path="${XDG_LOG_HOME:-$HOME/.local/log}/piggy/askpass.log"
  mkdir -p "$(dirname "$log_path")"
  {
    date '+--- %Y-%m-%dT%H:%M:%S%z ---'
    printf 'parent=%s pid=%s context=%q prompt=%q\n' \
      "$parent_comm" "$parent_pid" "$context" "$prompt"
  } >>"$log_path"
  # zenity --entry --hide-text reads a single line of obscured input
  # and writes it to stdout; non-zero exit on cancel. --timeout
  # bounds the wait: zenity self-cancels with exit 5 after
  # $zenity_timeout seconds, which propagates here as a normal
  # auth-denied — the agent's poll loop is freed even if the user
  # never saw the window. See piggy#103 and companion piggy#104 for
  # the agent-side backstop.
  # NB: `$?` inside the failure branch must be read from the `else`
  # of a non-inverted `if cmd; ...`. Under `if ! cmd; then ...; fi`
  # the `then`-body sees `$?` as the exit of `! cmd` (always 0 when
  # entered), masking zenity's real exit. After the `fi` of any `if`
  # statement, `$?` is 0 regardless. Only the `else` branch preserves
  # cmd's unmodified exit code.
  if [[ -n $kind ]] && body_is_too_tall_for_a_pin_dialog; then
    if zenity_read_whole_text 2>>"$log_path"; then
      printf 'zenity text-info exit=0\n' >>"$log_path"
    else
      rc=$?
      printf 'zenity text-info exit=%s\n' "$rc" >>"$log_path"
      exit "$rc"
    fi
  fi
  if pin="$("zenity_${kind:-routine}" 2>>"$log_path")"; then
    printf 'zenity exit=0\n' >>"$log_path"
    printf '%s\n' "$pin"
    exit 0
  else
    rc=$?
    printf 'zenity exit=%s\n' "$rc" >>"$log_path"
    exit "$rc"
  fi
fi

# Neither render target available. Refuse; explain why.
{
  printf '[piggy-askpass] no render target available.\n'
  printf '[piggy-askpass] /dev/tty unreadable AND zenity not on PATH.\n'
  printf '[piggy-askpass] prompt was: %s\n' "$prompt"
  printf '[piggy-askpass] context:    %s\n' "${context:-(unset)}"
  printf '[piggy-askpass] parent:     %s (PID %s)\n' "$parent_comm" "$parent_pid"
} >&2
exit 2
