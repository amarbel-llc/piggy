setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function edit_existing_password { # @test
  echo "original password" | "$PIGGY" pass insert -e cred1

  export FAKE_EDITOR_PASSWORD="big fat fake password"
  # Install the editor through the standard helper so its shebang is
  # rewritten to a portable bash path — `#!/usr/bin/env bash` fails
  # inside the nix sandbox where /usr/bin/env doesn't exist.
  piggy_install_helper_as fake-editor-change-password.sh fake-editor
  export EDITOR="$BATS_TEST_TMPDIR/fake-editor"

  "$PIGGY" pass edit cred1

  run "$PIGGY" pass show cred1
  assert_success
  assert_output "big fat fake password"
}
