#! /usr/bin/env bats
# bats file_tags=hardware
#
# Template-format interop between the Rust `piggy box tpl create`/`tpl
# show` (which are FIRST-PARTY Rust, not a hop to C — piggy#165) and the C
# `pivy-box`. Both directions:
#   - piggy_box_tpl_create_is_c_readable: the template Rust writes is one C
#     `pivy-box tpl show` reads (Rust output stays C-readable).
#   - piggy_box_tpl_show_reads_c_template: C writes a template, Rust
#     `piggy box tpl show` reads it (C output stays Rust-readable).
# `piggy box tpl create` reads the card's slot-9D pubkey, so this needs a
# (fibby) card; its seeded key and GUID make every template reproducible.
#
# C's side is frozen (piggy#285, lib/pivy_oracle.bash): the template C
# wrote, and C's verdict on the template piggy wrote, with that template's
# bytes, so a replay holds piggy to the exact template C read. `just
# codemod-capture-pivy-oracle-box-interop-fibby` re-records them.
#
# Required env (set by test-bats-conformance-box-interop-fibby):
#   FIBBY_BIN, PIGGY; to capture, PIGGY_ORACLE_MODE=capture with
#   REAL_PIVY_BOX and PIVY_ORACLE_CAPTURE_DIR.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$PIGGY_BATS_DIR/lib/fibby.bash"
  load "$PIGGY_BATS_DIR/lib/pivy_oracle.bash"
  export output
  PIVY_ORACLE_LANE=box-interop-fibby
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
  fibby_up --seed-rfc5903-slot-9d-cert
  INTEROP_GUID="$("$PIGGY" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)"
  [[ -n $INTEROP_GUID ]] || fail "no GUID from piggy tool -j list"
}

teardown() {
  fibby_down
}

_hex_of() { od -An -v -tx1 "$1" | tr -d ' \n'; }
_file_from_hex() { printf '%b' "$(sed 's/../\\x&/g' <<<"$1")" >"$2"; }

# Capture only: C `pivy-box tpl show` on FILE (its stdout).
_c_tpl_show() { "$REAL_PIVY_BOX" tpl show "$1"; }

# Capture only: the bytes of the template C `pivy-box tpl create` writes.
_c_tpl_create_hex() {
  local tpl="$BATS_TEST_TMPDIR/c-capture.tpl"
  "$REAL_PIVY_BOX" tpl create -f "$tpl" primary local-guid "$INTEROP_GUID" >/dev/null ||
    return
  _hex_of "$tpl"
}

function piggy_box_tpl_create_is_c_readable { # @test
  # XDG_CONFIG_HOME is pinned because the primary user template path is
  # `$XDG_CONFIG_HOME/pivy/tpl/$TPL` (vendor/pivy/src/ebox-cmd.c:67), so
  # the operator's real config dir does not leak in.
  HOME="$BATS_TEST_TMPDIR" \
    XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
    run "$PIGGY" box tpl create rust-interop primary local-guid "$INTEROP_GUID"
  assert_success
  local tpl_file="" candidate
  for candidate in .config/pivy/tpl .pivy/tpl Library/Preferences/pivy/tpl; do
    if [[ -f $BATS_TEST_TMPDIR/$candidate/rust-interop ]]; then
      tpl_file="$BATS_TEST_TMPDIR/$candidate/rust-interop"
      break
    fi
  done
  [[ -n $tpl_file ]] || fail "template file not found after tpl create"

  # C read exactly this template and accepted it.
  local c_read
  c_read="$(pivy_oracle_note tpl_create_piggy.hex _hex_of "$tpl_file")" ||
    fail "no recorded template C read"
  assert_equal "$(_hex_of "$tpl_file")" "$c_read"
  run pivy_oracle_note tpl_show_piggy _c_tpl_show "$tpl_file"
  assert_success
}

function piggy_box_tpl_show_reads_c_template { # @test
  local c_hex tpl_file="$BATS_TEST_TMPDIR/c-interop.tpl"
  c_hex="$(pivy_oracle_note tpl_create_c.hex _c_tpl_create_hex)" ||
    fail "no recorded C template"
  _file_from_hex "$c_hex" "$tpl_file"
  run "$PIGGY" box tpl show "$tpl_file"
  assert_success
  assert_output --partial "template"
}
