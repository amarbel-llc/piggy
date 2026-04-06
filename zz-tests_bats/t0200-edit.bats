setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function edit_existing_password { # @test
  echo "original password" | "$PIGGY" insert -e cred1

  export FAKE_EDITOR_PASSWORD="big fat fake password"
  export EDITOR="$REPO_ROOT/tests/fake-editor-change-password.sh"

  "$PIGGY" edit cred1

  run "$PIGGY" show cred1
  assert_success
  assert_output "big fat fake password"
}
