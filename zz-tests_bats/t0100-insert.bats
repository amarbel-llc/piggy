setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function insert_and_show_password { # @test
  echo "Hello world" | "$PIGGY" pass insert -e cred1
  run "$PIGGY" pass show cred1
  assert_success
  assert_output "Hello world"
}
