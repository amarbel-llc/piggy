#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#190 — `piggy sign-bytes` real-card signing over fibby.
#
# sign-bytes is a direct-PCSC primitive (no agent), so this drives it straight
# at fibby via PCSCLITE_CSOCK_NAME. We seed fibby's slot 9A (the canonical
# RFC 6979 §A.2.5 P-256 keypair), sign a message, and prove the signature is
# real card crypto by verifying it with openssl against the slot-9A public key
# read back via `piggy list --format=ssh`. This also stands in as the fibby DER
# framing confirmation requested during the papi#15 co-design (the DER `sign`
# output verifies end-to-end).
#
# Required env (supplied by the `test-bats-conformance-sign-bytes-fibby`
# recipe); the suite skips gracefully without them:
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-sign-bytes-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  # Safety net: these tests pass the PIN via -P (no askpass fires), but pin a
  # refusing askpass so any unexpected prompt path can't pop a GUI (#35).
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""

  # Short-path workdir under /tmp (AF_UNIX sun_path 108-byte limit).
  WORKDIR="$(mktemp -d -t sbf.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=

  # No ambient agent: sign-bytes talks to fibby directly via PCSCLITE_CSOCK_NAME.
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Seed fibby's slot 9A and write its public key to $WORKDIR/pub.pem (PEM
# SubjectPublicKeyInfo), read back via `piggy list --format=ssh` + ssh-keygen.
_seed_and_pubkey() {
  # --seed-chuid presents the card as initialized so piggy-piv's CHUID-based
  # enumeration finds it. Unlike the 9D/9E cert seeds, the 9A cert seed does
  # NOT bundle a CHUID (a fibby asymmetry), so we add it explicitly.
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-chuid

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$PIGGY_BIN" list --format=ssh
  [[ $status -eq 0 ]] || {
    echo "piggy list --format=ssh exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  local line
  line=$(printf '%s\n' "$output" | grep '^ecdsa-sha2-nistp256 ' | head -1)
  [[ -n $line ]] || {
    echo "no slot-9A ecdsa authorized_keys line in piggy list output" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$line" | awk '{print $1, $2}' >"$WORKDIR/k.pub"
  ssh-keygen -e -m PKCS8 -f "$WORKDIR/k.pub" >"$WORKDIR/pub.pem"
}

# `sign-bytes --format der` produces a DER ECDSA signature that openssl
# verifies against the slot-9A public key: real card crypto end-to-end, and
# the DER-framing confirmation from the papi#15 co-design.
function sign_bytes_der_verifies_against_slot_9a_pubkey { # @test
  _seed_and_pubkey
  printf 'enrollment-receipt-bytes' >"$WORKDIR/msg"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    "$PIGGY_BIN" sign-bytes --slot 9a -P 123456 --format der \
    <"$WORKDIR/msg" >"$WORKDIR/sig.der"
  [[ -s "$WORKDIR/sig.der" ]] || {
    echo "sign-bytes produced no DER signature" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  run openssl dgst -sha256 -verify "$WORKDIR/pub.pem" \
    -signature "$WORKDIR/sig.der" "$WORKDIR/msg"
  [[ $status -eq 0 ]] || {
    echo "openssl failed to verify the DER signature (status $status)" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q "Verified OK" || {
    echo "openssl did not report 'Verified OK'" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# `sign-bytes` default `--format raw` emits a 64-byte r‖s payload — the markl
# `…@ecdsa_p256_sig` form a downstream consumer (papi) blech32-wraps. The
# length contract is what papi depends on; the faithful DER→raw reframing is
# pinned by the `ecdsa_sig` unit tests, and the signature's cryptographic
# validity by the sibling DER test above.
function sign_bytes_raw_is_64_byte_rs { # @test
  _seed_and_pubkey
  printf 'enrollment-receipt-bytes' >"$WORKDIR/msg"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    "$PIGGY_BIN" sign-bytes --slot 9a -P 123456 \
    <"$WORKDIR/msg" >"$WORKDIR/sig.raw"
  local n
  n=$(wc -c <"$WORKDIR/sig.raw")
  [[ $n -eq 64 ]] || {
    echo "expected a 64-byte raw r‖s signature, got $n bytes" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
}
