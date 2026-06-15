#! /usr/bin/env bats
# bats file_tags=hardware
#
# Wrapper-integrity smoke tests for `piggy box`. Confirms argv- and
# template-path forwarding from the Rust clap dispatcher in
# `crates/piggy/src/main.rs` to C `pivy-box` survives intact.
#
# History. This file was originally a cross-language *template*-format
# compat probe (Rust `piggy box` ↔ C `pivy-box`) — see #29 / #41 / #55.
# After commit `79658e1` (2026-04-28), `piggy box` itself exec's into C
# `pivy-box` via what is now `exec::exec_pivy`, so both sides of the original
# tests reach the same binary. The cipher interop tests (`rust_encrypt_
# c_decrypt` and the reverse) were deleted in #41; their bodies live in
# git at `38df53c`. The remaining template tests have been relabeled
# here as wrapper smoke tests — what they verify today is that
# `piggy box tpl create` and `piggy box tpl show` reach `pivy-box`
# unmolested, NOT anything about cross-language template format
# compatibility (the latter no longer has two sides). See #55 for the
# disposition discussion.
#
# Mock override. `common.bash` symlinks `zz-tests_bats/helpers/
# mock-pivy-box.sh` as `pivy-box` in the test PATH so unit-test bats
# files run without a real card. That mock errors on `tpl create`,
# which would mask wrapper-integrity bugs here — `piggy box` would
# reach the mock, hit the error, and the test would fail with a
# misleading message. setup() below replaces that symlink with
# $REAL_PIVY_BOX for this file's tests only (each bats test gets a
# fresh BATS_TEST_TMPDIR).
#
# Requires a virtual PIV card (just test-bats-conformance-interop-fibby).
# The recipe brings up fibby with a seeded slot-9D key, captures the
# real C pivy-box path BEFORE bats prepends the mock to PATH, and sets
# PCSCLITE_CSOCK_NAME + REAL_PIVY_BOX + INTEROP_GUID before invoking
# bats. Tests skip gracefully when these are absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-interop-fibby)"
  fi
  if [[ -z ${REAL_PIVY_BOX:-} || ! -x ${REAL_PIVY_BOX:-} ]]; then
    skip "REAL_PIVY_BOX not set (run: just test-bats-conformance-interop-fibby)"
  fi

  # Replace common.bash's mock pivy-box symlink with the real C
  # binary — wrapper smoke tests need `piggy box` (which exec's
  # `pivy-box` from PATH via exec::exec_pivy) to reach the real
  # binary. Scoped to BATS_TEST_TMPDIR, so other bats files keep the
  # mock.
  ln -sf "$REAL_PIVY_BOX" "$BATS_TEST_TMPDIR/pivy-box"
}

# `piggy box tpl create` must forward argv + write its output where C
# `pivy-box` would. Roundtrips the produced file through `pivy-box tpl
# show` directly (bypassing piggy) to confirm format integrity.
function piggy_box_tpl_create_forwards_to_pivy_box { # @test
  [[ -n ${INTEROP_GUID:-} ]] || skip "INTEROP_GUID not set"

  local tpl_dir="$BATS_TEST_TMPDIR/tpl"
  mkdir -p "$tpl_dir"

  # XDG_CONFIG_HOME is pinned because pivy's primary user template
  # path is `$XDG_CONFIG_HOME/pivy/tpl/$TPL` (vendor/pivy/src/ebox-cmd.c:67).
  # Without this override the operator's real $XDG_CONFIG_HOME leaks
  # through and pivy-box writes outside BATS_TEST_TMPDIR.
  HOME="$BATS_TEST_TMPDIR" \
    XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
    run "$PIGGY" box tpl create rust-interop primary local-guid "$INTEROP_GUID"
  assert_success

  local tpl_file
  if [[ -f "$BATS_TEST_TMPDIR/.config/pivy/tpl/rust-interop" ]]; then
    tpl_file="$BATS_TEST_TMPDIR/.config/pivy/tpl/rust-interop"
  elif [[ -f "$BATS_TEST_TMPDIR/.pivy/tpl/rust-interop" ]]; then
    tpl_file="$BATS_TEST_TMPDIR/.pivy/tpl/rust-interop"
  elif [[ -f "$BATS_TEST_TMPDIR/Library/Preferences/pivy/tpl/rust-interop" ]]; then
    tpl_file="$BATS_TEST_TMPDIR/Library/Preferences/pivy/tpl/rust-interop"
  else
    fail "template file not found after tpl create"
  fi

  run "$REAL_PIVY_BOX" tpl show "$tpl_file"
  assert_success
}

# `piggy box tpl show` must forward a template-path positional arg to
# C `pivy-box` correctly. Creates the input via direct `pivy-box`
# (bypassing piggy) so the test failure surface is the wrapper, not
# tpl-create.
function piggy_box_tpl_show_forwards_to_pivy_box { # @test
  [[ -n ${INTEROP_GUID:-} ]] || skip "INTEROP_GUID not set"

  local tpl_file="$BATS_TEST_TMPDIR/c-interop.tpl"

  # -f writes to the given absolute path instead of ~/.ebox-tpl/<name>.
  # See vendor/pivy/src/pivy-box.c:1944 and vendor/pivy/zz-tests_bats/
  # pivy_ext_interop.bats for the canonical usage.
  run "$REAL_PIVY_BOX" tpl create -f "$tpl_file" primary local-guid "$INTEROP_GUID"
  if [[ $status -ne 0 ]]; then
    skip "C pivy-box tpl create failed (may require interactive mode): $output"
  fi

  run "$PIGGY" box tpl show "$tpl_file"
  assert_success
  assert_output --partial "template"
}
