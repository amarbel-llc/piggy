#! /usr/bin/env bats
#
# Tests for contrib/piggy-askpass.sh — the user-facing PIN-prompt
# helper. See piggy#33.
#
# These tests exercise the dry-run path (PIGGY_ASKPASS_DRY_RUN=1),
# which emits the rendered context to stderr and exits without
# reading a PIN. The render targets themselves (/dev/tty, zenity) are
# integration territory and intentionally not covered here.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  # Repo-rooted absolute path to the helper. PWD when bats runs is
  # the repo root (set by `just test-bats-conformance`).
  ASKPASS="$PWD/contrib/piggy-askpass.sh"
  if [[ ! -x "$ASKPASS" ]]; then
    skip "contrib/piggy-askpass.sh missing or not executable: $ASKPASS"
  fi

  # Ensure each test starts from a known env. Unset vars the helper
  # introspects; the test sets them back per-case as needed.
  unset PIGGY_ASKPASS_CONTEXT
  unset PIGGY_TEST_FIB_PIN
  export PIGGY_ASKPASS_DRY_RUN=1
}

@test "dry_run_emits_prompt_and_parent_to_stderr" {
  run "$ASKPASS" "Enter PIV PIN for token AABB:"

  assert_success
  assert_output --partial "Enter PIV PIN for token AABB:"
  # bats spawns subprocesses under bash; the helper's $PPID points at
  # bats's runner process, whose name lives in /proc/$PPID/comm and
  # is read via ps. Whatever the comm is, the line shape must match.
  assert_output --partial "Parent: "
  assert_output --partial "(PID "
}

@test "test_tag_emitted_when_context_has_piggy_test_prefix" {
  PIGGY_ASKPASS_CONTEXT="piggy-test:bats-coverage" \
    run "$ASKPASS" "Enter PIV PIN for token CAFE:"

  assert_success
  assert_output --partial "[TEST]"
  assert_output --partial "Context: piggy-test:bats-coverage"
}

@test "test_tag_emitted_when_prompt_contains_piggy_test" {
  # No PIGGY_ASKPASS_CONTEXT set; prompt itself carries the marker
  # via the EboxTplPart name policy (CLAUDE.md / bffa22a).
  run "$ASKPASS" "Enter PIV PIN for token DEAD (piggy-test:stream-fixture):"

  assert_success
  assert_output --partial "[TEST]"
  refute_output --partial "Context:"
}

@test "no_test_tag_for_real_prompt" {
  # A "real" prompt — no piggy-test marker anywhere.
  run "$ASKPASS" "Enter PIV PIN for token 9D5C (work-yubikey):"

  assert_success
  refute_output --partial "[TEST]"
  assert_output --partial "Enter PIV PIN for token 9D5C (work-yubikey):"
}

@test "missing_argv1_renders_placeholder" {
  run "$ASKPASS"

  assert_success
  assert_output --partial "<no prompt supplied>"
}

@test "context_displayed_without_test_tag_for_non_test_context" {
  PIGGY_ASKPASS_CONTEXT="scripted-batch-unlock" \
    run "$ASKPASS" "Enter PIV PIN for token 9D5C:"

  assert_success
  assert_output --partial "Context: scripted-batch-unlock"
  refute_output --partial "[TEST]"
}

@test "ps_failure_falls_through_to_question_mark_parent_marker" {
  # Regression guard for the `|| true` defense added in #92 (commit
  # 5b22031). When ps fails — chrooted, hardened-runtime env on
  # darwin, /usr/bin/ps stripped/missing, etc — the askpass must NOT
  # silently die under `set -euo pipefail`. parent_comm should fall
  # through to "?" and the rest of the prompt should render.
  #
  # We exercise the failure path with a stub ps that always exits 1.
  # Without the `|| true` patch this would propagate through pipefail,
  # trip set -e, and exit the whole script (with the symptom shape
  # observed on macos-15 CI: silent 126 + no stderr).
  local stub_dir
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-failps.XXXXXX")"
  cat >"$stub_dir/ps" <<'STUB_EOF'
#!/usr/bin/env bash
exit 1
STUB_EOF
  chmod +x "$stub_dir/ps"
  # tr is still needed for the second leg of the pipeline; symlink the
  # real one rather than stubbing so this test exercises only the
  # ps-failure path, not a compound failure.
  ln -s "$(command -v tr)" "$stub_dir/tr"

  PATH="$stub_dir:$PATH" run "$ASKPASS" "Enter PIV PIN for token 9D5C:"

  assert_success
  assert_output --partial "Enter PIV PIN for token 9D5C:"
  assert_output --partial "Parent: ?"
}

@test "launchd_env_uses_zenity_branch_when_tty_unreachable" {
  # Regression for the bug where the script's $DISPLAY/$WAYLAND_DISPLAY
  # gate caused exit=2 under pivy-agent's fork+pipe env (no controlling
  # TTY, scrubbed env). pivy-agent.c:1067 treats exit!=0 && exit!=1 as
  # "executing confirm failed" → AUTHZ_DENIED → every signature refused.
  # The fix removed the env-var gate; this test pins it in place by
  # detaching the TTY and verifying the script reaches the zenity
  # branch (here stubbed) and exits 0 with the canned PIN.
  unset PIGGY_ASKPASS_DRY_RUN

  # Stub zenity that echoes a canned PIN on stdout, mimicking what real
  # zenity does on Enter.
  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-stub.XXXXXX")"
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
echo "stubbed-pin-9D5C"
STUB_EOF
  chmod +x "$stub_dir/zenity"

  # Detach the controlling TTY before exec so the /dev/tty branch fails
  # the way pivy-agent's fork+pipe context does. setsid is Linux-only,
  # so we shell out to python3 (present on macOS + most Linuxes) and
  # call os.setsid() before execve. < /dev/null mimics pivy-agent
  # closing stdin (pivy-agent.c:1040).
  #
  # Resolve python3 to absolute path BEFORE `env -i` because on darwin
  # /usr/bin/python3 is an xcrun shim that needs TMPDIR to write its
  # cache at /var/folders/.../xcrun_db-* — `env -i` strips TMPDIR and
  # the shim exits 126 with EPERM. Calling python3 by absolute path
  # (nix-store or any non-shim path) sidesteps xcrun entirely. The
  # sibling tests below already do this; test 8 was missed. See #91.
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir:/usr/bin:/bin" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "A new client is trying to use PIV token 9D5C" </dev/null

  assert_success
  assert_output "stubbed-pin-9D5C"
}

@test "launchd_env_refuses_with_exit_2_when_neither_target_available" {
  # Pre-condition mirror of the bug case: TTY-less AND no zenity on PATH
  # → exit 2 with the refuse-branch banner. This is the *expected*
  # failure mode (script honestly reports no render target); pivy-agent
  # still sees a nonzero exit and denies, but at least the script's
  # behavior is what the comments at lines 105-113 promise.
  #
  # A prior version of this test set PATH=/usr/bin:/bin and assumed
  # zenity wasn't installed system-wide — which silently broke on
  # Linux hosts where /usr/bin/zenity exists (the script entered the
  # zenity branch, zenity exited 1 because $DISPLAY was unset, and
  # the script propagated exit 1 instead of the refuse-branch exit 2).
  # To make the precondition deterministic across hosts, build a
  # minimal stub dir with just the tools the askpass script needs
  # (bash for the `#!/usr/bin/env bash` shebang, ps + tr for the
  # parent-process banner) and deliberately omit zenity, then invoke
  # python3 by absolute path so env -i doesn't need PATH for its own
  # lookup.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-nozenity.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  [[ "$status" -eq 2 ]] || {
    echo "expected exit 2, got $status"
    echo "stdout: $output"
    return 1
  }
  assert_output --partial "no render target available"
}

@test "launchd_env_zenity_no_display_propagates_zenity_exit" {
  # Pin commit 3b95620's deliberate behavior: when zenity is findable
  # but cannot reach a display, the script trusts zenity to fail with
  # a clear nonzero exit and propagates it. The previous design gated
  # on $DISPLAY ourselves and exited 2 — which pivy-agent.c:1067
  # treats as confirm-failure → AUTHZ_DENIED → every signature refused
  # under the launchd fork env (scrubbed $DISPLAY). A future
  # maintainer must not silently re-add the $DISPLAY gate; this test
  # catches that regression.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-zenityfail.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  # Stub zenity that mimics real zenity when DISPLAY is unset: writes
  # the Gtk-WARNING to stderr and exits 1. The script must propagate
  # this exit 1 (NOT transform it into the refuse-branch exit 2).
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
echo "Gtk-WARNING **: cannot open display: " >&2
exit 1
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  [[ "$status" -eq 1 ]] || {
    echo "expected exit 1 (zenity's exit, propagated), got $status"
    echo "stdout: $output"
    return 1
  }
  refute_output --partial "no render target available"
}

@test "zenity_timeout_propagates_zenity_exit_when_prompt_self_cancels" {
  # piggy#103: zenity is invoked with --timeout=$PIGGY_ASKPASS_TIMEOUT so
  # an off-screen / unnoticed prompt cannot wedge the agent forever. On
  # timeout expiry zenity exits non-zero (5 in real zenity); the script
  # must propagate that exit so pivy-agent gets a deterministic auth-
  # denied signal in bounded time. We stub zenity to exit 5 immediately
  # regardless of args — what the test pins is "script honors the
  # timeout fork by propagating its non-zero exit", not zenity's own
  # wall-clock behavior.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-timeout.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
# Mimic real zenity's --timeout behavior: exit 5 on timer expiry.
exit 5
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" PIGGY_ASKPASS_TIMEOUT=1 \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  [[ "$status" -eq 5 ]] || {
    echo "expected exit 5 (zenity timeout propagated), got $status"
    echo "stdout: $output"
    return 1
  }
}

@test "zenity_invocation_includes_timeout_flag" {
  # Pin that --timeout=$PIGGY_ASKPASS_TIMEOUT is actually on the zenity
  # argv. A future maintainer who drops the flag silently re-introduces
  # the head-of-line-blocking failure mode from piggy#103. This test
  # uses a zenity stub that records its argv to a sentinel file and
  # echoes a canned PIN, so we can assert on the recorded argv after
  # the script exits.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path argv_log
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-argv.XXXXXX")"
  argv_log="$stub_dir/argv.log"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$argv_log"
echo "stubbed-pin-timeout-check"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" PIGGY_ASKPASS_TIMEOUT=7 \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  assert_output "stubbed-pin-timeout-check"
  [[ -f "$argv_log" ]] || {
    echo "expected argv log at $argv_log, missing"
    return 1
  }
  grep -qx -- "--timeout=7" "$argv_log" || {
    echo "expected --timeout=7 in zenity argv; got:"
    cat "$argv_log"
    return 1
  }
}

@test "zenity_timeout_defaults_to_30_when_env_var_unset" {
  # Pin the default value advertised in the header comment. If the
  # default changes, this test must be updated in lockstep with the
  # comment — they're the contract.
  unset PIGGY_ASKPASS_DRY_RUN
  unset PIGGY_ASKPASS_TIMEOUT

  local stub_dir python3_path argv_log
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-default.XXXXXX")"
  argv_log="$stub_dir/argv.log"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$argv_log"
echo "stubbed-pin-default-timeout"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  grep -qx -- "--timeout=30" "$argv_log" || {
    echo "expected default --timeout=30 in zenity argv; got:"
    cat "$argv_log"
    return 1
  }
}

@test "notifier_invoked_before_zenity_when_PIGGY_ASKPASS_NOTIFIER_set" {
  # piggy#103: when a notifier is configured, it must fire BEFORE
  # zenity opens so the user sees a heads-up even if the zenity window
  # is hidden or off-screen. The notifier is fired detached so a
  # hanging notifier cannot block the prompt — this test verifies the
  # fork-and-detach also reliably DOES run the notifier (i.e. the
  # detach isn't so eager that it loses the invocation).
  #
  # The notifier writes a sentinel file from a subshell. Because it's
  # detached, the file may appear AFTER the askpass exits; the test
  # polls briefly to absorb that race.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path notifier_log argv_log
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-notify.XXXXXX")"
  notifier_log="$stub_dir/notifier.log"
  argv_log="$stub_dir/argv.log"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf 'zenity\n' >"$argv_log"
echo "stubbed-pin-notify"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  cat >"$stub_dir/notifier" <<STUB_EOF
#!/usr/bin/env bash
printf 'title=%s\nbody=%s\n' "\${1:-}" "\${2:-}" >"$notifier_log"
STUB_EOF
  chmod +x "$stub_dir/notifier"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    PIGGY_ASKPASS_NOTIFIER="$stub_dir/notifier" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN for token 9D5C" </dev/null

  assert_success
  assert_output "stubbed-pin-notify"

  # Poll up to 2s for the detached notifier to land its sentinel.
  local waited=0
  while [[ ! -s "$notifier_log" && "$waited" -lt 20 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done

  [[ -s "$notifier_log" ]] || {
    echo "notifier never wrote sentinel within 2s"
    ls -la "$stub_dir"
    return 1
  }
  grep -q '^title=piggy-agent: PIN required' "$notifier_log" || {
    echo "notifier title mismatch; got:"
    cat "$notifier_log"
    return 1
  }
  grep -q 'Enter PIV PIN for token 9D5C' "$notifier_log" || {
    echo "notifier body missing prompt text; got:"
    cat "$notifier_log"
    return 1
  }
}

@test "ssh_notify_send_env_var_used_when_PIGGY_ASKPASS_NOTIFIER_unset" {
  # The fallback chain: $PIGGY_ASKPASS_NOTIFIER > $SSH_NOTIFY_SEND >
  # terminal-notifier/notify-send on PATH. piggy-agent's nix module
  # already exports SSH_NOTIFY_SEND when services.piggy-agent.notifySend
  # is configured (see nix/hm/piggy-agent.nix), so honoring it here
  # means no extra config is needed when the module is in use.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path notifier_log
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-ssh-notify.XXXXXX")"
  notifier_log="$stub_dir/notifier.log"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
echo "stubbed-pin-ssh-notify"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  cat >"$stub_dir/notifier-from-ssh" <<STUB_EOF
#!/usr/bin/env bash
printf 'from-ssh-notify-send\n' >"$notifier_log"
STUB_EOF
  chmod +x "$stub_dir/notifier-from-ssh"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    SSH_NOTIFY_SEND="$stub_dir/notifier-from-ssh" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success

  local waited=0
  while [[ ! -s "$notifier_log" && "$waited" -lt 20 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done

  [[ -s "$notifier_log" ]] || {
    echo "SSH_NOTIFY_SEND-resolved notifier never fired"
    return 1
  }
  grep -q 'from-ssh-notify-send' "$notifier_log" || {
    echo "wrong notifier ran; expected SSH_NOTIFY_SEND. got:"
    cat "$notifier_log"
    return 1
  }
}

@test "require_force_skips_tty_branch_even_when_tty_available" {
  # piggy#166: SSH_ASKPASS_REQUIRE=force must bypass the /dev/tty
  # render target entirely — agent-driven / scripted contexts export
  # it so the PIN prompt always lands on zenity, never on whatever
  # stray tty the caller happens to hold. We allocate a real pty via
  # python3's stdlib pty.spawn and feed it a line the tty branch WOULD
  # read; the stubbed-zenity answer in the output proves the tty
  # branch was skipped. (The fed line may still appear in the output
  # via pty echo — assert on the zenity pin, not on its absence.)
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-force.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
echo "stubbed-pin-force"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" SSH_ASKPASS_REQUIRE=force \
    "$python3_path" -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' \
    "$ASKPASS" "Enter PIV PIN" <<<"tty-pin-should-be-ignored"

  assert_success
  assert_output --partial "stubbed-pin-force"
}

@test "require_never_refuses_zenity_when_tty_unreachable" {
  # piggy#166: SSH_ASKPASS_REQUIRE=never means tty-or-nothing. In a
  # tty-less env with zenity on PATH the helper must NOT fall through
  # to zenity — it refuses with exit 2 and a banner naming the policy,
  # so an interactive-only caller never gets a surprise GUI dialog.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-never.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
echo "stubbed-pin-never-should-not-render"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" SSH_ASKPASS_REQUIRE=never \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  [[ "$status" -eq 2 ]] || {
    echo "expected exit 2 (refuse, never policy), got $status"
    echo "stdout: $output"
    return 1
  }
  assert_output --partial "SSH_ASKPASS_REQUIRE=never"
  refute_output --partial "stubbed-pin-never-should-not-render"
}

@test "require_never_still_reads_tty_when_available" {
  # piggy#166 companion pin: `never` forbids zenity, not the tty — a
  # human at a terminal still gets the terminal prompt. pty.spawn
  # supplies the tty; no zenity is present in the stub PATH so any
  # accidental zenity fall-through would fail loudly instead.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-never-tty.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" SSH_ASKPASS_REQUIRE=never \
    "$python3_path" -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' \
    "$ASKPASS" "Enter PIV PIN" <<<"pty-pin-never"

  assert_success
  assert_output --partial "pty-pin-never"
}

@test "missing_notifier_does_not_block_or_fail_prompt" {
  # When no notifier is reachable (no env var, no terminal-notifier /
  # notify-send on PATH), the script must silently skip the heads-up
  # and proceed straight to zenity. The script's hard deps stay
  # zenity + coreutils — adding a soft notifier must not break the
  # contract that the script works in a minimal stub env.
  unset PIGGY_ASKPASS_DRY_RUN
  unset PIGGY_ASKPASS_NOTIFIER
  unset SSH_NOTIFY_SEND

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-no-notifier.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  # Deliberately omit terminal-notifier and notify-send so resolve_notifier
  # falls through all paths.
  cat >"$stub_dir/zenity" <<'STUB_EOF'
#!/usr/bin/env bash
echo "stubbed-pin-no-notifier"
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  assert_output "stubbed-pin-no-notifier"
}
