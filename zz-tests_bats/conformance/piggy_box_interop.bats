#! /usr/bin/env bats
# bats file_tags=hardware
#
# Template-format interop between the Rust `piggy box tpl create`/`tpl
# show` (which are FIRST-PARTY Rust, not a hop to C — piggy#165) and the C
# `pivy-box`. Both directions:
#   - piggy_box_tpl_create_forwards_to_pivy_box: Rust writes a template,
#     C `pivy-box tpl show` reads it (Rust output stays C-readable).
#   - piggy_box_tpl_show_forwards_to_pivy_box: C writes a template, Rust
#     `piggy box tpl show` reads it (C output stays Rust-readable).
# `piggy box tpl create` reads the card's slot-9D pubkey, so this needs a
# real (fibby) card; the recipe sets PCSCLITE_CSOCK_NAME + REAL_PIVY_BOX +
# INTEROP_GUID. Tests skip gracefully when absent. These are the last
# tests using C `pivy-box` as a live oracle; piggy#289 Phase 5 (which
# drops the pivy build) turns them into fixture replays.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-interop-fibby)"
  fi
  if [[ -z ${REAL_PIVY_BOX:-} || ! -x ${REAL_PIVY_BOX:-} ]]; then
    skip "REAL_PIVY_BOX not set (run: just test-bats-conformance-interop-fibby)"
  fi
  # No PATH shim: `piggy box tpl create`/`show` are Rust and never exec
  # `pivy-box`; the tests invoke the C side through $REAL_PIVY_BOX directly.
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
