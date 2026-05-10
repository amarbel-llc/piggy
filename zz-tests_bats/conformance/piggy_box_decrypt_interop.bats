#! /usr/bin/env bats
#
# Phase 3 close-out (#73 last bullet): pipe a Rust-`piggy-ids encrypt`
# ebox into real C `pivy-box stream decrypt` against fib. Validates
# two compat claims that crates/piggy-box's e2e tests can't reach:
#
# 1. The patched ebox parser in vendor/pivy/src/ebox.c accepts the
#    guid-less wire format that piggy's recipients shim emits (#70).
# 2. `local_unlock`'s fall-through to PCSC enumeration matches by
#    pubkey alone (no GUID hint), proving the runtime path that the
#    encode side targets actually opens in the C runtime: parse →
#    enumerate → token match → PIN unlock → ECDH → piv_box parse.
#
# A full plaintext round-trip is NOT asserted — that's blocked by
# #81 (cipher-name collision: piggy's RFC 7539 chacha20-poly1305 vs
# pivy's openssh-compat alias). The decrypt fails at the cipher-IV
# length check inside `piv_box_open_common`; that failure proves
# everything up to and INCLUDING piv_box parsing succeeded. The
# negative-shape assertion is exact: stderr must contain the
# IV-length-mismatch line AND must NOT contain any of the
# pre-cipher error tokens (parse / enumerate / unlock / PIN /
# ECDH / shared-secret).
#
# Requires the fib virtual PIV card stack
# (`just test-bats-conformance-interop`). Tests skip when those
# env vars are absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${REAL_PIVY_BOX:-} || ! -x ${REAL_PIVY_BOX:-} ]]; then
    skip "REAL_PIVY_BOX not set (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${INTEROP_GUID:-} ]]; then
    skip "INTEROP_GUID not set (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${PIGGY_IDS_REAL:-} || ! -x ${PIGGY_IDS_REAL:-} ]]; then
    skip "PIGGY_IDS_REAL not set or not built"
  fi
}

function rust_encrypt_reaches_pivy_box_cipher_layer_via_fib { # @test
  # 1. Read fib's 9D pubkey through piggy-ids detect-pubkey
  #    (real PCSC, no mock); produces a canonical markl ID.
  local recipient
  recipient="$("$PIGGY_IDS_REAL" detect-pubkey --guid "$INTEROP_GUID")"
  [[ -n $recipient ]] || fail "detect-pubkey returned empty markl ID"

  # 2. Build a single-recipient .piggy-ids and encrypt to a temp file.
  local piggy_ids="$BATS_TEST_TMPDIR/decrypt-interop.piggy-ids"
  local ebox="$BATS_TEST_TMPDIR/decrypt-interop.ebox"
  echo "$recipient" >"$piggy_ids"
  printf '%s' 'phase 3 c-decrypt interop' |
    "$PIGGY_IDS_REAL" encrypt "$piggy_ids" >"$ebox" ||
    fail "Rust encrypt failed (status $?)"

  # 3. Pipe the Rust-encrypted ebox through real C pivy-box.
  #    Expected to FAIL at the cipher-IV layer (#81); we capture
  #    stderr and assert the failure shape.
  local stderr_log="$BATS_TEST_TMPDIR/pivy-box.stderr"
  local rc=0
  "$REAL_PIVY_BOX" stream decrypt <"$ebox" >/dev/null 2>"$stderr_log" || rc=$?
  [[ $rc -ne 0 ]] || fail "pivy-box stream decrypt unexpectedly succeeded; #81 was meant to be blocking"

  local stderr
  stderr="$(<"$stderr_log")"

  # Positive assertion: the failure happened at the cipher-IV check
  # inside piv_box_open_common (proves parse + ECDH all succeeded).
  [[ "$stderr" == *"IV length"*"chacha20-poly1305"* ]] ||
    fail "expected cipher-IV-length failure (per #81); got stderr: $stderr"

  # Negative assertions: NONE of the pre-cipher failure modes fired.
  # If any of these appear, #73's principal claim regressed.
  for token in \
    "BadMagic" \
    "UnsupportedVersion" \
    "InvalidGuid" \
    "EnumerationError" \
    "no token found" \
    "PinIncorrect" \
    "PinBlocked" \
    "PinAuthError" \
    "ECDHError" \
    "SharedSecretError"; do
    if [[ "$stderr" == *"$token"* ]]; then
      fail "regression: stderr contains pre-cipher error '$token' — \
the parser-patch (#70) or local_unlock fall-through must be broken. stderr:
$stderr"
    fi
  done
}
