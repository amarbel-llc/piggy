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

  run env -i HOME="$HOME" PATH="$stub_dir:/usr/bin:/bin" \
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
  for tool in bash ps tr; do
    ln -s "$(command -v "$tool")" "$stub_dir/$tool"
  done
  python3_path="$(command -v python3)"

  run env -i HOME="$HOME" PATH="$stub_dir" \
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
  for tool in bash ps tr; do
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

  run env -i HOME="$HOME" PATH="$stub_dir" \
    "$python3_path" -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    "$ASKPASS" "Enter PIV PIN" </dev/null

  [[ "$status" -eq 1 ]] || {
    echo "expected exit 1 (zenity's exit, propagated), got $status"
    echo "stdout: $output"
    return 1
  }
  refute_output --partial "no render target available"
}
