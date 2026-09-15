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

function unported_op_falls_through_to_c { # @test
  # `list` is not ported yet, so `piggy tool list` execs `pivy-tool list`
  # by PATH name (which in this lane is common.bash's mock — that is fine:
  # it proves the Some/None fallback still reaches a pivy-tool). Both real
  # and mock print a `guid:` line.
  run "$PIGGY" tool list
  assert_success
  assert_output --partial "guid:"
}
