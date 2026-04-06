setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function remove_password { # @test
  "$PIGGY" generate cred1 19
  assert [ -e "$PIGGY_STORE_DIR/cred1.ebox" ]
  run "$PIGGY" rm -f cred1
  assert_success
  assert [ ! -e "$PIGGY_STORE_DIR/cred1.ebox" ]
}

function remove_password_with_spaces { # @test
  "$PIGGY" generate "hello i have spaces" 19
  assert [ -e "$PIGGY_STORE_DIR/hello i have spaces.ebox" ]
  run "$PIGGY" rm -f "hello i have spaces"
  assert_success
  assert [ ! -e "$PIGGY_STORE_DIR/hello i have spaces.ebox" ]
}

function remove_nonexistent_password_fails { # @test
  run "$PIGGY" rm -f does-not-exist
  assert_failure
}
