setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

function piggy_help_mentions_piggy { # @test
  run "$PIGGY" --help
  assert_success
  assert_output --partial "piggy"
}

function initialize_test_store { # @test
  create_test_template
  assert [ -e "$PIGGY_STORE_DIR/.pivy-id" ]
}
