#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

teardown() {
  teardown_test_home
}

function no_args_prints_usage_and_fails { # @test
  run pivy-box
  assert_failure
  assert_output --partial "type and operation required"
}

function type_without_op_prints_usage_and_fails { # @test
  run pivy-box key
  assert_failure
  assert_output --partial "operation required"
}

function bad_type_and_op_fails { # @test
  run pivy-box nonexistent badop
  assert_failure
}

# --- SSH_ASKPASS support (issue #8) ---

resolve_unwrapped() {
  local cmd="$1"
  local bin_path
  bin_path="$(command -v "$cmd")"
  # Follow symlinks to the nix store wrapper
  bin_path="$(readlink -f "$bin_path")"
  # Extract the unwrapped binary path from the wrapper script
  local unwrapped
  unwrapped="$(grep -o '/nix/store/[^ ]*\.'"$cmd"'-unwrapped' "$bin_path")" ||
    unwrapped=""
  if [[ -n $unwrapped && -x $unwrapped ]]; then
    echo "$unwrapped"
  else
    # Not a wrapper script — binary is the command itself
    echo "$bin_path"
  fi
}

function pivy_box_binary_references_ssh_askpass { # @test
  local binary
  binary="$(resolve_unwrapped pivy-box)"

  # Pipe through grep to avoid loading the full strings output into bats'
  # lines array — the thousands of entries overflow ARG_MAX and cause E2BIG
  # on subsequent execve() calls.
  run bats_pipe strings "$binary" \| grep SSH_ASKPASS
  assert_success
}

function pivy_agent_binary_references_ssh_askpass { # @test
  local binary
  binary="$(resolve_unwrapped pivy-agent)"

  run bats_pipe strings "$binary" \| grep SSH_ASKPASS
  assert_success
}
