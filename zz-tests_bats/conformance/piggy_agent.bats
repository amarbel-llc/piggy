#! /usr/bin/env bats
#
# Conformance tests for `piggy agent` (rust SSH agent subcommand).
#
# Adapted from pivy/zz-tests_bats/pivy_agent_rust.bats. The original
# invoked the standalone `pivy-agent-rust` binary; here every test goes
# through the top-level `piggy` dispatcher to exercise the full
# rust → cmd::agent path.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

# --- help ---

function help_flag_prints_help_and_succeeds { # @test
  run "$PIGGY" agent --help
  assert_success
  assert_output --partial "PIV-backed SSH agent"
}

function short_help_flag_prints_help_and_succeeds { # @test
  run "$PIGGY" agent -h
  assert_success
  assert_output --partial "PIV-backed SSH agent"
}

function help_shows_guid_option { # @test
  run "$PIGGY" agent --help
  assert_success
  assert_output --partial "GUID of the PIV card to use"
}

function help_shows_all_cards_option { # @test
  run "$PIGGY" agent --help
  assert_success
  assert_output --partial "All-card mode"
}

function help_shows_slot_spec_option { # @test
  run "$PIGGY" agent --help
  assert_success
  assert_output --partial "Slot spec"
}

# --- bad options ---

function bad_option_fails { # @test
  run "$PIGGY" agent -Q
  assert_failure
  assert_output --partial "unexpected argument"
}

function bad_long_option_fails { # @test
  run "$PIGGY" agent --nonexistent
  assert_failure
  assert_output --partial "unexpected argument"
}

# --- kill mode ---

function kill_without_pid_fails { # @test
  unset SSH_AGENT_PID
  run "$PIGGY" agent -k
  assert_failure
  assert_output --partial "SSH_AGENT_PID not set"
}

function kill_with_invalid_pid_fails { # @test
  SSH_AGENT_PID="notanumber" run "$PIGGY" agent -k
  assert_failure
  assert_output --partial "invalid SSH_AGENT_PID"
}

# --- mutual exclusion ---

function all_cards_and_guid_conflict { # @test
  run "$PIGGY" agent -A -g 1234
  assert_failure
  assert_output --partial "cannot be used with"
}

# --- socket path ---

function help_shows_socket_option { # @test
  run "$PIGGY" agent --help
  assert_success
  assert_output --partial "Socket path"
}

# --- slot spec ---

function help_shows_slot_spec_format { # @test
  run "$PIGGY" agent --help
  assert_success
  assert_output --partial "9a,9e"
}

function slot_spec_rejects_non_hex { # @test
  run "$PIGGY" agent -S "zz"
  assert_failure
  assert_output --partial "invalid slot in -S spec"
}

function slot_spec_rejects_out_of_range_slot { # @test
  run "$PIGGY" agent -S "ff"
  assert_failure
  assert_output --partial "unknown PIV slot 0xff"
}

function slot_spec_rejects_mixed_valid_and_invalid { # @test
  run "$PIGGY" agent -S "9a,ff"
  assert_failure
  assert_output --partial "unknown PIV slot 0xff"
}

function slot_spec_rejects_zero { # @test
  run "$PIGGY" agent -S "00"
  assert_failure
  assert_output --partial "unknown PIV slot 0x00"
}
