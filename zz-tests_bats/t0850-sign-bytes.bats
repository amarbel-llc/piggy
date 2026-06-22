setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  # PIN-prompt safety net (#35): every test here exercises a path that
  # errors BEFORE any card access (slot validation / clap parse), so no
  # prompt should ever fire. But pin a refusing askpass anyway — if a
  # future reordering let a path reach the PIN prompt on a dev machine
  # with a card attached, it must refuse loudly, never pop a GUI. The
  # real card-signing happy path is hardware-only; see
  # conformance/piggy_sign_bytes_fibby.bats.
  export SSH_ASKPASS="$(dirname "$BATS_TEST_FILE")/helpers/piggy-test-askpass.sh"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset PIGGY_TEST_FIB_PIN
}

# `--slot` is required; clap rejects its absence before any work.
function sign_bytes_requires_slot { # @test
  run "$PIGGY" sign-bytes </dev/null
  assert_failure
  assert_output --partial "--slot"
}

# Slot 9D is Key Management (ECDH) — not a signing slot. Rejected at
# argument-validation time, before touching a card.
function sign_bytes_rejects_ecdh_slot_9d { # @test
  run "$PIGGY" sign-bytes --slot 9d </dev/null
  assert_failure
  assert_output --partial "9d"
  assert_output --partial "cannot sign"
}

# An unknown slot is rejected with the supported-slot hint, card-free.
function sign_bytes_rejects_unknown_slot { # @test
  run "$PIGGY" sign-bytes --slot 9e </dev/null
  assert_failure
  assert_output --partial "unsupported slot"
}

# `--help` reaches sign-bytes' own clap parser (the top-level dispatch
# passes flags through) and lists the flags. No card access.
function sign_bytes_help_lists_flags { # @test
  run "$PIGGY" sign-bytes --help
  assert_success
  assert_output --partial "--slot"
  assert_output --partial "--format"
  assert_output --partial "--frontend"
}

# `--frontend jsonrpc` without `--socket` fails before any card op (RFC 0006
# §6): the frontend channel is built before card enumeration, so a missing
# socket is rejected card-free.
function sign_bytes_jsonrpc_requires_socket { # @test
  run "$PIGGY" sign-bytes --slot 9a --frontend jsonrpc </dev/null
  assert_failure
  assert_output --partial "--socket"
}
