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
