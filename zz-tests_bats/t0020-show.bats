setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function show_generated_password { # @test
  "$PIGGY" generate cred1 19
  run "$PIGGY" show cred1
  assert_success
}

function show_password_with_spaces { # @test
  echo "BLAH!!" | "$PIGGY" insert -e "I am a cred with lots of spaces"
  run "$PIGGY" show "I am a cred with lots of spaces"
  assert_success
  assert_output "BLAH!!"
}

function show_password_with_unicode { # @test
  "$PIGGY" generate "🏠" 19
  run "$PIGGY" show
  assert_success
  assert_output --partial "🏠"
}

function show_nonexistent_password_fails { # @test
  run "$PIGGY" show cred2
  assert_failure
}
