#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

teardown() {
  teardown_test_home
}

function no_args_prints_usage_and_fails { # @test
  run pivy-tool
  assert_failure
  assert_output --partial "usage: pivy-tool"
}

# TODO: pivy-tool version requires pcscd even though it only prints a
# string; it crashes (SIGSEGV) without the daemon. Re-enable once virtual
# PIV is available or the code is patched to short-circuit before
# piv_open().

function bad_option_fails { # @test
  run pivy-tool -Z
  assert_failure
  assert_output --partial "usage: pivy-tool"
}

function bad_subcommand_fails { # @test
  run pivy-tool nonexistent-command
  assert_failure
}
