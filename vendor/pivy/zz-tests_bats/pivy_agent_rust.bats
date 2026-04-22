#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  # Locate Rust pivy-agent binary
  if [[ -n ${PIVY_AGENT_RUST:-} ]]; then
    PIVY_AGENT="$PIVY_AGENT_RUST"
  else
    PIVY_AGENT="$(dirname "$BATS_TEST_FILE")/../result-rust/bin/pivy-agent-rust"
  fi

  if [[ ! -x $PIVY_AGENT ]]; then
    skip "pivy-agent-rust not found at $PIVY_AGENT (run: nix build .#pivy-rust)"
  fi
}

teardown() {
  teardown_test_home
}

# --- help ---

function help_flag_prints_help_and_succeeds { # @test
  run "$PIVY_AGENT" --help
  assert_success
  assert_output --partial "PIV-backed SSH agent"
}

function short_help_flag_prints_help_and_succeeds { # @test
  run "$PIVY_AGENT" -h
  assert_success
  assert_output --partial "PIV-backed SSH agent"
}

function help_shows_guid_option { # @test
  run "$PIVY_AGENT" --help
  assert_success
  assert_output --partial "GUID of the PIV card to use"
}

function help_shows_all_cards_option { # @test
  run "$PIVY_AGENT" --help
  assert_success
  assert_output --partial "All-card mode"
}

function help_shows_slot_spec_option { # @test
  run "$PIVY_AGENT" --help
  assert_success
  assert_output --partial "Slot spec"
}

# --- bad options ---

function bad_option_fails { # @test
  run "$PIVY_AGENT" -Q
  assert_failure
  assert_output --partial "unexpected argument"
}

function bad_long_option_fails { # @test
  run "$PIVY_AGENT" --nonexistent
  assert_failure
  assert_output --partial "unexpected argument"
}

# --- kill mode ---

function kill_without_pid_fails { # @test
  unset SSH_AGENT_PID
  run "$PIVY_AGENT" -k
  assert_failure
  assert_output --partial "SSH_AGENT_PID not set"
}

function kill_with_invalid_pid_fails { # @test
  SSH_AGENT_PID="notanumber" run "$PIVY_AGENT" -k
  assert_failure
  assert_output --partial "invalid SSH_AGENT_PID"
}
