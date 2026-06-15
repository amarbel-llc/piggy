#! /usr/bin/env bats
# bats file_tags=hardware
#
# Phase 3 close-out (#73): Rust `piggy-ids encrypt` -> real C
# `pivy-box stream decrypt` via fib. Validates the full Rust->C
# round-trip end-to-end:
#
# 1. The patched ebox parser in vendor/pivy/src/ebox.c accepts the
#    guid-less wire format that piggy's recipients shim emits (#70).
# 2. `local_unlock`'s fall-through to PCSC enumeration matches by
#    pubkey alone (no GUID hint).
# 3. piv_box decrypt succeeds — exercises pivy's RFC 7539 ChaCha20-
#    Poly1305 cipher entry registered under
#    `chacha20-poly1305@piggy.amarbel.net` by vendor/pivy/openssh.patch
#    (#81).
# 4. The recovered plaintext matches the input byte-for-byte.
#
# Requires the fib virtual PIV card stack
# (`just test-bats-conformance-interop`). Tests skip when env vars
# are absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-interop-fibby)"
  fi
  if [[ -z ${REAL_PIVY_BOX:-} || ! -x ${REAL_PIVY_BOX:-} ]]; then
    skip "REAL_PIVY_BOX not set (run: just test-bats-conformance-interop-fibby)"
  fi
  if [[ -z ${INTEROP_GUID:-} ]]; then
    skip "INTEROP_GUID not set (run: just test-bats-conformance-interop-fibby)"
  fi
  if [[ -z ${PIGGY_IDS_REAL:-} || ! -x ${PIGGY_IDS_REAL:-} ]]; then
    skip "PIGGY_IDS_REAL not set or not built"
  fi
}

function rust_encrypt_through_pivy_box_stream_decrypt_via_fib { # @test
  # 1. Read fib's 9D pubkey through piggy-ids detect-pubkey (real
  #    PCSC, no mock); produces a canonical markl ID.
  local recipient
  recipient="$("$PIGGY_IDS_REAL" detect-pubkey --guid "$INTEROP_GUID")"
  [[ -n $recipient ]] || fail "detect-pubkey returned empty markl ID"

  # 2. Build a single-recipient piggy-ids and encrypt to a temp file.
  local piggy_ids="$BATS_TEST_TMPDIR/decrypt-interop-piggy-ids"
  local ebox="$BATS_TEST_TMPDIR/decrypt-interop.ebox"
  echo "$recipient" >"$piggy_ids"
  local plaintext='phase 3 c-decrypt interop: rust encrypt -> pivy-box stream decrypt'
  printf '%s' "$plaintext" |
    "$PIGGY_IDS_REAL" encrypt "$piggy_ids" >"$ebox" ||
    fail "Rust encrypt failed (status $?)"

  # 3. Decrypt with real C pivy-box (talks to fib via PCSC + PIN
  #    via askpass) and assert the recovered plaintext matches.
  local recovered
  recovered="$("$REAL_PIVY_BOX" stream decrypt <"$ebox")" ||
    fail "pivy-box stream decrypt failed (status $?)"

  [[ "$recovered" == "$plaintext" ]] ||
    fail "round-trip lost the plaintext; got: '$recovered'"
}
