#! /usr/bin/env bats
# bats file_tags=hardware
#
# Differential conformance for the Rust `piggy tool` port (piggy#289
# Phase 3, milestone 3.1a). For each read-only op, run BOTH the Rust
# `piggy tool` and the C `pivy-tool` against the SAME fibby card and
# assert their output agrees — C `pivy-tool` is the external contract the
# port must satisfy. Covers `pubkey <slot>` (OpenSSH format) and `cert
# <slot>` (PEM) against fibby's seeded slot 9A (RFC 6979 cert) and 9D
# (RFC 5903 cert). No PIN is needed for either op.
#
# Required env (set by test-bats-conformance-tool-fibby):
#   PCSCLITE_CSOCK_NAME  fibby's pcsc socket
#   REAL_PIVY_TOOL       C pivy-tool (nix build .#pivy)
#   PIGGY                the Rust piggy binary (target/debug/piggy)
# Skips gracefully when absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-tool-fibby)"
  fi
  if [[ -z ${REAL_PIVY_TOOL:-} || ! -x ${REAL_PIVY_TOOL:-} ]]; then
    skip "REAL_PIVY_TOOL not set (run: just test-bats-conformance-tool-fibby)"
  fi
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable"
  fi
}

# Assert `piggy tool <args>` and `pivy-tool <args>` produce the same
# stdout (command substitution strips trailing newlines from both, which
# is exactly the sshkey_write-has-no-newline normalization we want).
_assert_tool_matches() {
  local rust c
  rust="$("$PIGGY" tool "$@")" || fail "piggy tool $* failed (status $?)"
  c="$("$REAL_PIVY_TOOL" "$@")" || fail "pivy-tool $* failed (status $?)"
  assert_equal "$rust" "$c"
}

function pubkey_9d_matches_c { # @test
  _assert_tool_matches pubkey 9d
}

function pubkey_9a_matches_c { # @test
  _assert_tool_matches pubkey 9a
}

function cert_9d_matches_c { # @test
  _assert_tool_matches cert 9d
}

function cert_9a_matches_c { # @test
  _assert_tool_matches cert 9a
}

function pubkey_output_is_openssh_ecdsa_p256 { # @test
  # Pin the shape independently of the C oracle: fibby's 9D key is P-256.
  run "$PIGGY" tool pubkey 9d
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256 "
}

function cert_output_is_pem { # @test
  run "$PIGGY" tool cert 9d
  assert_success
  assert_line --index 0 "-----BEGIN CERTIFICATE-----"
  assert_output --partial "-----END CERTIFICATE-----"
}

# fibby signs with RFC 6979 deterministic ECDSA, so the same input +
# digest yields the same signature bytes from both impls. The PIN is
# supplied with `-P` because C pivy-tool, unlike piggy, will not use
# SSH_ASKPASS for the PIN when stdin is a pipe carrying the data — so
# `-P` is the portable way to drive both. piggy's own askpass path is
# checked separately below.
function sign_9a_matches_c { # @test
  local msg="piggy tool sign differential payload"
  local r="$BATS_TEST_TMPDIR/r.sig" c="$BATS_TEST_TMPDIR/c.sig"
  printf '%s' "$msg" | "$PIGGY" tool -P 123456 sign 9a >"$r" || fail "piggy tool sign failed"
  printf '%s' "$msg" | "$REAL_PIVY_TOOL" -P 123456 sign 9a >"$c" || fail "pivy-tool sign failed"
  assert [ -s "$r" ]
  run cmp "$r" "$c"
  assert_success
}

function sign_askpass_path_matches_dash_p { # @test
  # piggy's PIN-via-SSH_ASKPASS path (no -P) must produce the same
  # deterministic signature as -P, proving the askpass prompt is wired.
  local msg="askpass path"
  local a="$BATS_TEST_TMPDIR/a.sig" p="$BATS_TEST_TMPDIR/p.sig"
  printf '%s' "$msg" | "$PIGGY" tool sign 9a >"$a" || fail "piggy tool sign (askpass) failed"
  printf '%s' "$msg" | "$PIGGY" tool -P 123456 sign 9a >"$p" || fail "piggy tool sign (-P) failed"
  run cmp "$a" "$p"
  assert_success
}

function ecdh_9d_matches_c { # @test
  # ECDH(9D_priv, peer) is deterministic. Use the card's own 9A public key
  # as the peer, fed to both impls; compare the raw shared secret. `-P`
  # for the PIN, same reason as sign.
  local peer="$BATS_TEST_TMPDIR/peer.pub"
  "$REAL_PIVY_TOOL" pubkey 9a >"$peer" || fail "pubkey 9a for peer failed"
  local r="$BATS_TEST_TMPDIR/r.ss" c="$BATS_TEST_TMPDIR/c.ss"
  "$PIGGY" tool -P 123456 ecdh 9d <"$peer" >"$r" || fail "piggy tool ecdh failed"
  "$REAL_PIVY_TOOL" -P 123456 ecdh 9d <"$peer" >"$c" || fail "pivy-tool ecdh failed"
  assert [ -s "$r" ]
  run cmp "$r" "$c"
  assert_success
}

function ecdh_non_ec_slot_rejected { # @test
  # 9B is the management key slot (no EC key / cert); ecdh must refuse.
  run "$PIGGY" tool ecdh 9b
  assert_failure
}

function attest_imported_key_fails_like_c { # @test
  # fibby's slot keys are imported (seeded scalars), so INS_ATTEST returns
  # 6A80: attestation is unavailable. Both impls must fail (non-zero) and
  # neither should emit a certificate. The two-PEM happy path is the
  # hardware lane's job (a generated, attestable key).
  run "$PIGGY" tool attest 9d
  assert_failure
  refute_output --partial "BEGIN CERTIFICATE"
  run "$REAL_PIVY_TOOL" attest 9d
  assert_failure
  refute_output --partial "BEGIN CERTIFICATE"
}

function pubkey_empty_slot_fails_like_c { # @test
  # Slot 9C is not seeded on this card: both impls must fail (non-zero),
  # neither should print a key.
  run "$PIGGY" tool pubkey 9c
  assert_failure
  refute_output --partial "ecdsa-sha2-nistp256"
  run "$REAL_PIVY_TOOL" pubkey 9c
  assert_failure
}

function unported_op_is_a_usage_error_not_a_c_fallthrough { # @test
  # As of the 3.6 cutover (piggy#289) `piggy tool` no longer falls back to C:
  # an unported op like `list` is a usage error (exit 2) that points at the
  # `piggy pivy tool` escape hatch, NOT a silent hop to `pivy-tool`.
  run "$PIGGY" tool list
  assert_failure 2
  assert_output --partial "piggy pivy tool"
  refute_output --partial "guid:"
  # The full C surface stays reachable via the explicit passthrough, which
  # execs `pivy-tool` from PATH (common.bash's mock in this lane).
  run "$PIGGY" pivy tool list
  assert_success
  assert_output --partial "guid:"
}
