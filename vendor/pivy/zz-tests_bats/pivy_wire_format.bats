#! /usr/bin/env bats
#
# Wire format compliance tests for SSH agent extension responses.
# Runs pivy-wire-test unit mode (no card or agent needed).

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  PIVY_DIR="${PIVY_DIR:-$(dirname "$BATS_TEST_FILE")/../result}"
  WIRE_TEST="$PIVY_DIR/bin/pivy-wire-test"

  if [[ ! -x $WIRE_TEST ]]; then
    skip "pivy-wire-test not found at $PIVY_DIR (run: nix build)"
  fi
}

function wire_format_unit_tests { # @test
  run "$WIRE_TEST" unit
  assert_success
  assert_output --partial "8 passed, 0 failed"
}
