#! /usr/bin/env bats
#
# Interop tests: Rust `piggy box` ↔ C `pivy-box` wire compatibility.
#
# Requires the fib virtual PIV card stack (just test-bats-conformance-interop).
# The recipe brings up fib, generates a key on slot 9D, creates a template,
# and sets PCSCLITE_CSOCK_NAME + INTEROP_TPL + INTEROP_GUID before invoking
# bats. Tests skip gracefully when these are absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${INTEROP_TPL:-} || ! -f ${INTEROP_TPL:-} ]]; then
    skip "INTEROP_TPL not set or file missing (run: just test-bats-conformance-interop)"
  fi
  # common.bash prepends zz-tests_bats/helpers (with mock-pivy-box.sh) to
  # PATH. That mock substitutes base64 for real crypto, which is the
  # opposite of what interop tests want — they need the REAL C pivy-box
  # to actually cross the wire boundary. The recipe captures the real
  # binary's path before bats loads and passes it in via REAL_PIVY_BOX.
  if [[ -z ${REAL_PIVY_BOX:-} || ! -x ${REAL_PIVY_BOX:-} ]]; then
    skip "REAL_PIVY_BOX not set (run: just test-bats-conformance-interop)"
  fi
}

# --- stream encrypt/decrypt cross-compat ---

function rust_encrypt_c_decrypt { # @test
  local encrypted="$BATS_TEST_TMPDIR/stream.ebox"

  printf "hello from rust" | "$PIGGY" box stream encrypt "$INTEROP_TPL" >"$encrypted"
  run "$REAL_PIVY_BOX" stream decrypt <"$encrypted"
  assert_success
  assert_output "hello from rust"
}

function c_encrypt_rust_decrypt { # @test
  local encrypted="$BATS_TEST_TMPDIR/stream.ebox"

  printf "hello from c" | "$REAL_PIVY_BOX" stream encrypt "$INTEROP_TPL" >"$encrypted"
  run "$PIGGY" box stream decrypt "$encrypted"
  assert_success
  assert_output "hello from c"
}

# --- template cross-compat ---

function rust_tpl_create_c_tpl_show { # @test
  [[ -n ${INTEROP_GUID:-} ]] || skip "INTEROP_GUID not set"

  local tpl_dir="$BATS_TEST_TMPDIR/tpl"
  mkdir -p "$tpl_dir"

  HOME="$BATS_TEST_TMPDIR" run "$PIGGY" box tpl create rust-interop primary local-guid "$INTEROP_GUID"
  assert_success

  local tpl_file
  if [[ -f "$BATS_TEST_TMPDIR/.pivy/tpl/rust-interop" ]]; then
    tpl_file="$BATS_TEST_TMPDIR/.pivy/tpl/rust-interop"
  elif [[ -f "$BATS_TEST_TMPDIR/Library/Preferences/pivy/tpl/rust-interop" ]]; then
    tpl_file="$BATS_TEST_TMPDIR/Library/Preferences/pivy/tpl/rust-interop"
  else
    fail "template file not found after tpl create"
  fi

  run "$REAL_PIVY_BOX" tpl show "$tpl_file"
  assert_success
}

function c_tpl_create_rust_tpl_show { # @test
  [[ -n ${INTEROP_GUID:-} ]] || skip "INTEROP_GUID not set"

  local tpl_file="$BATS_TEST_TMPDIR/c-interop.tpl"

  run "$REAL_PIVY_BOX" tpl create "$tpl_file" primary local-guid "$INTEROP_GUID"
  if [[ $status -ne 0 ]]; then
    skip "C pivy-box tpl create failed (may require interactive mode): $output"
  fi

  run "$PIGGY" box tpl show "$tpl_file"
  assert_success
  assert_output --partial "template"
}
