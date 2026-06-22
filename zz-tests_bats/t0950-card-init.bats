setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  # PIN-prompt safety net (#35): the paths exercised here error BEFORE any
  # card access (clap parse / frontend-channel validation), so no prompt
  # fires. Pin a refusing askpass anyway so a future reordering that reached
  # a prompt on a dev machine with a card attached refuses loudly. The real
  # provisioning happy path is hardware-only — see
  # conformance/piggy_card_init_fibby.bats. We deliberately do NOT run a bare
  # `piggy card init` here: with a blank card attached it would provision it.
  export SSH_ASKPASS="$(dirname "$BATS_TEST_FILE")/helpers/piggy-test-askpass.sh"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset PIGGY_TEST_FIB_PIN
}

# `--frontend jsonrpc` without `--socket` fails before any card op (RFC 0006
# §6): the frontend channel is built first, and a missing socket is rejected.
function card_init_jsonrpc_requires_socket { # @test
  run "$PIGGY" card init --frontend jsonrpc </dev/null
  assert_failure
  assert_output --partial "--socket"
}

# `piggy card init --help` reaches the subcommand's clap parser and lists its
# flags. No card access.
function card_init_help_lists_flags { # @test
  run "$PIGGY" card init --help
  assert_success
  assert_output --partial "--serial"
  assert_output --partial "--frontend"
  assert_output --partial "--socket"
}

# `piggy card --help` lists the `init` subcommand.
function card_help_lists_init { # @test
  run "$PIGGY" card --help
  assert_success
  assert_output --partial "init"
}
