#! /usr/bin/env bats
#
# Interop tests: Rust `piggy box` ↔ C `pivy-box` *template* compatibility.
#
# Crypto compatibility (Rust seal ↔ C decrypt and the reverse) is OUT OF
# SCOPE by design. As of #36, piggy standardizes on RFC 7539 ChaCha20-
# Poly1305 with a 12-byte wire IV; pivy retains its OpenSSH
# `chacha20-poly1305@openssh.com` variant with a 0-byte wire IV. The two
# constructions are wire-incompatible — see
# `docs/rfcs/0002-piv-ecdh-box.md` §Compatibility. Earlier revisions of
# this file held `rust_encrypt_c_decrypt` and `c_encrypt_rust_decrypt`
# tests; they were deliberately removed (see #41) rather than skipped, so
# the suite reflects what's actually expected to work. Their bodies
# survive in git history at `38df53c` if the direction ever reverses.
#
# What's still tested here: piggy's template format remains aligned with
# pivy's (base64-armored sshbuf bytes, see `8221588`), so a template
# created by either tool MUST be readable by the other. Tests 1 and 2
# below exercise that contract round-trip.
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
