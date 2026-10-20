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
  if [[ ! -x $ASKPASS ]]; then
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

  # Symlink the real tools the askpass script needs (bash for the
  # `#!/usr/bin/env bash` shebang, ps + tr for the parent banner, plus
  # dirname/mkdir/date) into the stub dir, resolved via `command -v` so
  # they point at the dev-shell/nix-store binaries. PATH is then just
  # "$stub_dir" — matching the sibling launchd tests below. Previously
  # this test set PATH=$stub_dir:/usr/bin:/bin and relied on bash living
  # in /usr/bin or /bin, which is false on NixOS hosts: the shebang's
  # `env bash` lookup failed with exit 127 before the script could run.
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done

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

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
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

  [[ $status -eq 2 ]] || {
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

  [[ $status -eq 1 ]] || {
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

  [[ $status -eq 5 ]] || {
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
  [[ -f $argv_log ]] || {
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
  while [[ ! -s $notifier_log && $waited -lt 20 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done

  [[ -s $notifier_log ]] || {
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
  while [[ ! -s $notifier_log && $waited -lt 20 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done

  [[ -s $notifier_log ]] || {
    echo "SSH_NOTIFY_SEND-resolved notifier never fired"
    return 1
  }
  grep -q 'from-ssh-notify-send' "$notifier_log" || {
    echo "wrong notifier ran; expected SSH_NOTIFY_SEND. got:"
    cat "$notifier_log"
    return 1
  }
}

# bats test_tags=pty
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
    BATS_RUN_TMPDIR="$BATS_RUN_TMPDIR" \
    "$python3_path" "$PWD/zz-tests_bats/helpers/pty-spawn.py" \
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

  [[ $status -eq 2 ]] || {
    echo "expected exit 2 (refuse, never policy), got $status"
    echo "stdout: $output"
    return 1
  }
  assert_output --partial "SSH_ASKPASS_REQUIRE=never"
  refute_output --partial "stubbed-pin-never-should-not-render"
}

# bats test_tags=pty
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
    BATS_RUN_TMPDIR="$BATS_RUN_TMPDIR" \
    "$python3_path" "$PWD/zz-tests_bats/helpers/pty-spawn.py" \
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

@test "reattach_globs_wayland_socket_when_env_display_blind" {
  # piggy#179: a display-blind agent env (frozen at unit-start before the
  # compositor published WAYLAND_DISPLAY) must re-derive the display before
  # zenity, or every sign is refused with "Failed to open display". Source 2:
  # the Wayland socket is discoverable under XDG_RUNTIME_DIR (present even in
  # the frozen env). We assert the value zenity actually inherited.
  unset PIGGY_ASKPASS_DRY_RUN
  # Binds a real AF_UNIX socket for the script's `-S` test; the darwin nix
  # sandbox denies bind(2) (piggy#208).
  skip_unless_af_unix_bind

  local stub_dir runtime python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-reattach.XXXXXX")"
  runtime="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-xdg.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"
  # A real AF_UNIX socket so the script's `-S` test matches; a bind()-ed path
  # stays a socket inode after the process exits (nothing unlinks it).
  "$python3_path" -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' \
    "$runtime/wayland-7"
  # Stub zenity records the WAYLAND_DISPLAY it inherited, then echoes a PIN.
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s' "\${WAYLAND_DISPLAY-}" > "$stub_dir/seen-wayland"
echo "stubbed-pin-reattach"
STUB_EOF
  chmod +x "$stub_dir/zenity"

  # env -i scrubs WAYLAND_DISPLAY/DISPLAY but keeps XDG_RUNTIME_DIR; systemctl
  # is absent from the stub PATH so source 1 is skipped and source 2 (glob)
  # resolves. setsid detaches the tty so the /dev/tty branch is skipped.
  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" XDG_RUNTIME_DIR="$runtime" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  assert_output "stubbed-pin-reattach"
  [[ "$(cat "$stub_dir/seen-wayland")" == "wayland-7" ]] || {
    echo "expected zenity to inherit WAYLAND_DISPLAY=wayland-7; saw [$(cat "$stub_dir/seen-wayland")]"
    return 1
  }
}

@test "reattach_imports_display_from_systemctl_user_environment" {
  # piggy#179 source 1 (authoritative): import WAYLAND_DISPLAY/DISPLAY from
  # `systemctl --user show-environment`, which the compositor refreshes after
  # the agent froze its env. Stub systemctl emits a canned block; no
  # XDG_RUNTIME_DIR is passed, so a pass proves the import came from source 1.
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-systemctl.XXXXXX")"
  for tool in bash ps tr dirname mkdir date grep sed; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"
  cat >"$stub_dir/systemctl" <<'STUB_EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--user" && "${2:-}" == "show-environment" ]]; then
  printf 'WAYLAND_DISPLAY=wayland-3\nDISPLAY=:0\nXDG_RUNTIME_DIR=/run/user/9999\n'
fi
STUB_EOF
  chmod +x "$stub_dir/systemctl"
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s' "\${WAYLAND_DISPLAY-}" > "$stub_dir/seen-wayland"
echo "stubbed-pin-systemctl"
STUB_EOF
  chmod +x "$stub_dir/zenity"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  assert_output "stubbed-pin-systemctl"
  [[ "$(cat "$stub_dir/seen-wayland")" == "wayland-3" ]] || {
    echo "expected import from systemctl (wayland-3); saw [$(cat "$stub_dir/seen-wayland")]"
    return 1
  }
}

@test "reattach_is_noop_when_no_display_source_available" {
  # Negative control: display-blind env, no systemctl, no Wayland socket under
  # XDG_RUNTIME_DIR → no reattach, WAYLAND_DISPLAY stays empty. The script must
  # NOT fabricate a bogus display (it falls through to "trust zenity to fail").
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir runtime python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-nosrc.XXXXXX")"
  runtime="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-xdg-empty.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s' "\${WAYLAND_DISPLAY-}" > "$stub_dir/seen-wayland"
echo "stubbed-pin-nosrc"
STUB_EOF
  chmod +x "$stub_dir/zenity"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" XDG_RUNTIME_DIR="$runtime" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  [[ -z "$(cat "$stub_dir/seen-wayland")" ]] || {
    echo "expected no reattach; zenity saw WAYLAND_DISPLAY=[$(cat "$stub_dir/seen-wayland")]"
    return 1
  }
}

@test "reattach_does_not_override_present_display" {
  # The reattach is guarded on an EMPTY display env: when WAYLAND_DISPLAY is
  # already set (the common, healthy case) it must be left untouched even if a
  # different socket is discoverable under XDG_RUNTIME_DIR.
  unset PIGGY_ASKPASS_DRY_RUN
  # Binds a real AF_UNIX socket for the script's `-S` test; the darwin nix
  # sandbox denies bind(2) (piggy#208).
  skip_unless_af_unix_bind

  local stub_dir runtime python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-present.XXXXXX")"
  runtime="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-xdg-present.XXXXXX")"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"
  "$python3_path" -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' \
    "$runtime/wayland-7"
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s' "\${WAYLAND_DISPLAY-}" > "$stub_dir/seen-wayland"
echo "stubbed-pin-present"
STUB_EOF
  chmod +x "$stub_dir/zenity"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" XDG_RUNTIME_DIR="$runtime" \
    WAYLAND_DISPLAY=wayland-existing \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  assert_success
  [[ "$(cat "$stub_dir/seen-wayland")" == "wayland-existing" ]] || {
    echo "reattach clobbered a present display; saw [$(cat "$stub_dir/seen-wayland")]"
    return 1
  }
}

# -------- operator acts: PIGGY_ASKPASS_KIND (RFC 0012 §2.6) --------
#
# The agent names an operator act's display class in PIGGY_ASKPASS_KIND.
# Each class must look different from a routine prompt and from the other
# classes, and a routine prompt must not change at all.

# Run the helper tty-less against a zenity stub that records its argv and
# answers with $1 (printf format). The rest of the arguments are NAME=value
# pairs for the helper's environment. Sets ZENITY_ARGV to the argv log.
run_askpass_against_zenity_stub() {
  local answer="$1"
  shift
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-kind.XXXXXX")"
  ZENITY_ARGV="$stub_dir/argv.log"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$ZENITY_ARGV"
printf '$answer'
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" "$@" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "PIN for card 5DA19C98 to sign this operator act" </dev/null
}

assert_zenity_argv_has() {
  grep -qxF -- "$1" "$ZENITY_ARGV" || {
    echo "expected $1 in the zenity argv; got:"
    cat "$ZENITY_ARGV"
    return 1
  }
}

refute_zenity_argv_has() {
  if grep -qF -- "$1" "$ZENITY_ARGV"; then
    echo "did not expect $1 in the zenity argv; got:"
    cat "$ZENITY_ARGV"
    return 1
  fi
}

@test "kind_banner_names_the_class_above_the_verbatim_text" {
  export PIGGY_ASKPASS_KIND=escalation
  export PIGGY_ASKPASS_CONTEXT=$'operator act: escalation\nnamespace piggy-escalation-v1\n\ngrant: merge to master'
  run "$ASKPASS" "PIN for card 5DA19C98 to sign this operator act"

  assert_success
  assert_output --partial "OPERATOR ACT: ESCALATION"
  assert_output --partial "namespace piggy-escalation-v1"
  assert_output --partial "grant: merge to master"
}

@test "kind_banners_differ_per_class_and_a_routine_prompt_has_none" {
  local class
  for class in quote escalation certificate; do
    PIGGY_ASKPASS_KIND="$class" run "$ASKPASS" "Enter PIV PIN"
    assert_success
    assert_output --partial "OPERATOR ACT: ${class^^}"
  done

  unset PIGGY_ASKPASS_KIND
  run "$ASKPASS" "Enter PIV PIN"
  assert_success
  refute_output --partial "OPERATOR ACT"
}

@test "unknown_kind_refuses_rather_than_prompting_as_routine" {
  PIGGY_ASKPASS_KIND=blessing run "$ASKPASS" "Enter PIV PIN"

  assert_failure 2
  assert_output --partial "unknown PIGGY_ASKPASS_KIND"
}

@test "routine_prompt_zenity_argv_is_unchanged_by_the_kind_support" {
  run_askpass_against_zenity_stub '123456\n'

  assert_success
  assert_output "123456"
  assert_zenity_argv_has "--entry"
  assert_zenity_argv_has "--hide-text"
  assert_zenity_argv_has "--title=piggy PIV PIN"
  assert_zenity_argv_has "--timeout=30"
  refute_zenity_argv_has "--ok-label"
  refute_zenity_argv_has "--forms"
}

@test "quote_is_a_form_with_its_own_title_and_button" {
  run_askpass_against_zenity_stub '123456\n' PIGGY_ASKPASS_KIND=quote

  assert_success
  assert_output "123456"
  assert_zenity_argv_has "--forms"
  assert_zenity_argv_has "--add-password=PIV PIN"
  refute_zenity_argv_has "--entry"
  assert_zenity_argv_has "--title=piggy operator act: QUOTE"
  assert_zenity_argv_has "--ok-label=Sign quote"
  # Reading the text takes longer than typing a PIN.
  assert_zenity_argv_has "--timeout=120"
}

@test "certificate_is_a_form_with_its_own_title_and_button" {
  run_askpass_against_zenity_stub '123456\n' PIGGY_ASKPASS_KIND=certificate

  assert_success
  assert_output "123456"
  assert_zenity_argv_has "--forms"
  assert_zenity_argv_has "--add-password=PIV PIN"
  assert_zenity_argv_has "--title=piggy operator act: CERTIFICATE"
  assert_zenity_argv_has "--ok-label=Issue certificate"
  refute_zenity_argv_has "--add-entry"
}

@test "escalation_form_demands_the_typed_word_and_yields_only_the_pin" {
  run_askpass_against_zenity_stub '123456\nESCALATE\n' PIGGY_ASKPASS_KIND=escalation

  assert_success
  assert_output "123456"
  assert_zenity_argv_has "--forms"
  assert_zenity_argv_has "--add-entry=Type ESCALATE to grant"
  assert_zenity_argv_has "--title=piggy operator act: ESCALATION (grants authority)"
  assert_zenity_argv_has "--ok-label=Grant escalation"
}

@test "escalation_without_the_typed_word_fails_and_yields_no_pin" {
  run_askpass_against_zenity_stub '123456\nyes\n' PIGGY_ASKPASS_KIND=escalation

  assert_failure 1
  refute_output --partial "123456"
}

# piggy#319: the class is recognisable before the text is read, by a band
# in the class's own colour carrying its own symbol, and no two classes
# share either.
@test "each_class_opens_its_form_with_its_own_coloured_band_and_symbol" {
  local class band seen_bands=""
  for class in quote certificate escalation; do
    run_askpass_against_zenity_stub '123456\nESCALATE\n' PIGGY_ASKPASS_KIND="$class"
    assert_success
    band=$(grep -o -m1 '<span [^>]*background="#[0-9a-f]*"[^>]*> [^ ]*' "$ZENITY_ARGV") || {
      echo "no coloured band opens the $class form; got:"
      cat "$ZENITY_ARGV"
      return 1
    }
    [[ $seen_bands != *"$band"* ]] || {
      echo "the $class band repeats another class's colour and symbol: $band"
      return 1
    }
    seen_bands+="$band|"
  done
  case "$seen_bands" in
    *'#c01c28'*'⚠'*) ;;
    *)
      echo "escalation is not the red ⚠ band: $seen_bands"
      return 1
      ;;
  esac
}

# zenity does not show --text literally (see the script): the forms dialogs
# parse Pango markup and interpret backslash escapes. The text of an act
# must survive both.
TRICKY_TEXT='grant <b>bold</b> & more; id ecdsa_p256_sig; path a\nb'

assert_zenity_text_has() {
  grep -qF -- "$1" "$ZENITY_ARGV" || {
    echo "expected the zenity --text to contain: $1" >&2
    cat "$ZENITY_ARGV" >&2
    return 1
  }
}

@test "forms_dialogs_escape_markup_and_backslashes_so_the_text_shows_literally" {
  local class
  for class in quote escalation certificate; do
    run_askpass_against_zenity_stub '123456\nESCALATE\n' \
      PIGGY_ASKPASS_KIND="$class" PIGGY_ASKPASS_CONTEXT="$TRICKY_TEXT"
    assert_success
    assert_zenity_text_has 'grant &lt;b&gt;bold&lt;/b&gt; &amp; more; id ecdsa_p256_sig; path a\\nb'
    refute_zenity_argv_has '<b>'
  done
}

# -------- tall operator-act texts: refused (RFC 0012 §2.6, piggy#322) --------
#
# A PIN dialog does not scroll, and the dialog that takes the PIN must show
# the whole text. An operator act whose rendered prompt is taller than the
# script's operator_act_max_lines (24, long lines counting as the lines they
# wrap to at 80 characters) is refused before any dialog opens: exit 3, the
# reason on stdout naming the limit. A routine prompt is never refused for
# its height. These run the real script against a stub, so what is pinned
# is the zenity argv and the exit, not what a real dialog draws.

# Like run_askpass_against_zenity_stub, but the stub logs every call (its
# argv to ZENITY_CALLS after a `--- zenity call` marker) and always answers
# the PIN 123456.
run_askpass_against_logging_zenity_stub() {
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-tall.XXXXXX")"
  ZENITY_CALLS="$stub_dir/calls.log"
  for tool in bash ps tr dirname mkdir date; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf -- '--- zenity call\n' >>"$ZENITY_CALLS"
printf '%s\n' "\$@" >>"$ZENITY_CALLS"
printf '123456\n'
STUB_EOF
  chmod +x "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" "$@" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "PIN for card 5DA19C98 to sign this operator act" </dev/null
}

zenity_call_count() {
  if [[ -e $ZENITY_CALLS ]]; then
    grep -c '^--- zenity call$' "$ZENITY_CALLS"
  else
    printf '0'
  fi
}

# Thirty lines of act text, the last one full of what zenity would mangle.
tall_act_text() {
  printf 'grant line %d\n' $(seq 1 30)
  printf '%s' "$TRICKY_TEXT"
}

@test "tall_operator_act_text_is_refused_before_any_dialog_with_the_limit_named" {
  local class
  for class in quote certificate escalation; do
    run_askpass_against_logging_zenity_stub \
      PIGGY_ASKPASS_KIND="$class" PIGGY_ASKPASS_CONTEXT="$(tall_act_text)"

    assert_failure 3
    refute_output --partial "123456"
    assert_output --partial "too tall for the PIN dialog"
    assert_output --partial "at most 24"
    assert_equal "$(zenity_call_count)" 0
  done
}

@test "one_long_line_counts_as_the_lines_it_wraps_to" {
  local long_line
  long_line="$(printf 'x%.0s' $(seq 1 2000))"
  run_askpass_against_logging_zenity_stub \
    PIGGY_ASKPASS_KIND=quote PIGGY_ASKPASS_CONTEXT="grant: $long_line"

  assert_failure 3
  assert_output --partial "too tall for the PIN dialog"
  assert_equal "$(zenity_call_count)" 0
}

@test "short_operator_act_text_goes_straight_to_the_pin_dialog" {
  run_askpass_against_logging_zenity_stub \
    PIGGY_ASKPASS_KIND=certificate PIGGY_ASKPASS_CONTEXT=$'issue cert\nfor key X'

  assert_success
  assert_output "123456"
  assert_equal "$(zenity_call_count)" 1
  ZENITY_ARGV="$ZENITY_CALLS"
  assert_zenity_argv_has "--forms"
}

@test "tall_routine_prompt_is_never_refused_for_its_height" {
  run_askpass_against_logging_zenity_stub \
    PIGGY_ASKPASS_CONTEXT="$(tall_act_text)"

  assert_success
  assert_output "123456"
  assert_equal "$(zenity_call_count)" 1
  ZENITY_ARGV="$ZENITY_CALLS"
  assert_zenity_argv_has "--title=piggy PIV PIN"
}

@test "explicit_timeout_still_wins_for_an_operator_act" {
  run_askpass_against_zenity_stub '123456\n' PIGGY_ASKPASS_KIND=quote PIGGY_ASKPASS_TIMEOUT=9

  assert_success
  assert_zenity_argv_has "--timeout=9"
}

# -------- operator acts in piggy-askpass-gtk --------
#
# With PIGGY_ASKPASS_GTK=1 and piggy-askpass-gtk on PATH the operator-act
# dialogs are its, not zenity's. These run the real script against a stub of the helper that logs
# its argv and stdin, answers 123456 and exits with $1, beside the logging
# zenity stub, so what is pinned is which dialog runs and what it is handed.

# $1: the helper stub's exit status. The rest: NAME=value pairs for the script.
run_askpass_against_gtk_helper_stub() {
  local helper_exit="$1"
  shift
  unset PIGGY_ASKPASS_DRY_RUN

  local stub_dir python3_path
  stub_dir="$(mktemp -d "${BATS_TEST_TMPDIR:-/tmp}/piggy-askpass-gtk.XXXXXX")"
  HELPER_ARGV="$stub_dir/helper-argv.log"
  HELPER_STDIN="$stub_dir/helper-stdin.log"
  ZENITY_CALLS="$stub_dir/zenity-calls.log"
  for tool in bash ps tr dirname mkdir date cat; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  cat >"$stub_dir/piggy-askpass-gtk" <<STUB_EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$HELPER_ARGV"
cat >"$HELPER_STDIN"
printf '123456\n'
exit $helper_exit
STUB_EOF
  cat >"$stub_dir/zenity" <<STUB_EOF
#!/usr/bin/env bash
printf -- '--- zenity call\n' >>"$ZENITY_CALLS"
printf '123456\nESCALATE\n'
STUB_EOF
  chmod +x "$stub_dir/piggy-askpass-gtk" "$stub_dir/zenity"
  python3_path="$(command -v python3)"

  run env -i HOME="$BATS_TEST_TMPDIR" PATH="$stub_dir" PIGGY_ASKPASS_GTK=1 "$@" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "PIN for card 5DA19C98 to sign this operator act" </dev/null
}

# The value the helper stub was given for option $1 (the argument after it).
helper_option() {
  grep -A1 -xF -- "$1" "$HELPER_ARGV" | tail -n1
}

@test "operator_acts_use_the_gtk_helper_with_their_class_and_never_zenity" {
  local class title
  for class in quote certificate escalation; do
    run_askpass_against_gtk_helper_stub 0 PIGGY_ASKPASS_KIND="$class"

    assert_success
    assert_output "123456"
    assert_equal "$(zenity_call_count)" 0
    title="piggy operator act: ${class^^}"
    [[ $class == escalation ]] && title+=" (grants authority)"
    assert_equal "$(helper_option --title)" "$title"
    assert_equal "$(helper_option --timeout)" 120
    [[ $(helper_option --band-background) == '#'?????? ]]
    [[ $(helper_option --band-foreground) == '#'?????? ]]
  done
}

@test "only_an_escalation_asks_the_gtk_helper_for_the_typed_word" {
  run_askpass_against_gtk_helper_stub 0 PIGGY_ASKPASS_KIND=escalation
  assert_success
  assert_equal "$(helper_option --confirm-word)" ESCALATE
  assert_equal "$(helper_option --ok-label)" "Grant escalation"
  assert_equal "$(helper_option --band-background)" "#c01c28"

  run_askpass_against_gtk_helper_stub 0 PIGGY_ASKPASS_KIND=quote
  assert_success
  if grep -qxF -- --confirm-word "$HELPER_ARGV"; then
    echo "a quote asked for the typed word"
    return 1
  fi
}

# The helper sets the text as plain text, so the script hands it over
# unescaped, on stdin, never in an argument.
@test "the_gtk_helper_gets_the_act_text_unescaped_on_stdin" {
  run_askpass_against_gtk_helper_stub 0 \
    PIGGY_ASKPASS_KIND=quote PIGGY_ASKPASS_CONTEXT="$TRICKY_TEXT"

  assert_success
  grep -qF -- "$TRICKY_TEXT" "$HELPER_STDIN" || {
    echo "the text did not reach the helper literally; got:"
    cat "$HELPER_STDIN"
    return 1
  }
  if grep -qF -- 'ecdsa_p256_sig' "$HELPER_ARGV"; then
    echo "the text was passed in the helper's arguments"
    return 1
  fi
}

@test "a_cancelled_or_timed_out_gtk_dialog_propagates_its_status_and_no_pin" {
  local status_code
  for status_code in 1 5; do
    run_askpass_against_gtk_helper_stub "$status_code" PIGGY_ASKPASS_KIND=certificate
    assert_failure "$status_code"
    assert_equal "$(zenity_call_count)" 0
  done
}

@test "the_routine_prompt_never_uses_the_gtk_helper" {
  run_askpass_against_gtk_helper_stub 0

  assert_success
  assert_equal "$(zenity_call_count)" 1
  [[ ! -e $HELPER_ARGV ]]
}

# The helper is opt-in while it is being tried: on PATH but not asked for,
# it is not used.
@test "without_piggy_askpass_gtk_1_the_zenity_dialogs_stay" {
  run_askpass_against_gtk_helper_stub 0 PIGGY_ASKPASS_KIND=escalation PIGGY_ASKPASS_GTK=

  assert_success
  assert_output "123456"
  assert_equal "$(zenity_call_count)" 1
  [[ ! -e $HELPER_ARGV ]]
}

@test "tall_operator_act_text_is_refused_before_the_gtk_helper_opens" {
  run_askpass_against_gtk_helper_stub 0 \
    PIGGY_ASKPASS_KIND=quote PIGGY_ASKPASS_CONTEXT="$(tall_act_text)"

  assert_failure 3
  assert_output --partial "too tall for the PIN dialog"
  [[ ! -e $HELPER_ARGV ]]
}
