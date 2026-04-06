INITIAL_PASSWORD="bla bla bla will we make it!!"

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  init_test_git
  "$PIGGY" git init
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e cred1
}

function basic_copy { # @test
  run "$PIGGY" cp cred1 cred2
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/cred1.ebox" ]
  assert [ -e "$PIGGY_STORE_DIR/cred2.ebox" ]
}

function copy_preserves_original_content { # @test
  "$PIGGY" cp cred1 cred2
  run "$PIGGY" show cred1
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function copy_destination_has_same_content { # @test
  "$PIGGY" cp cred1 cred2
  run "$PIGGY" show cred2
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function copy_into_directory { # @test
  run "$PIGGY" cp cred1 directory/
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/directory" ]
  assert [ -e "$PIGGY_STORE_DIR/directory/cred1.ebox" ]
}

function copy_with_rename_into_new_directory { # @test
  run "$PIGGY" cp cred1 "new directory"/newcred
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/new directory" ]
  assert [ -e "$PIGGY_STORE_DIR/new directory/newcred.ebox" ]
}

function copy_directory_recursively { # @test
  "$PIGGY" cp cred1 directory/
  run "$PIGGY" cp directory targetdir
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/targetdir/cred1.ebox" ]
  assert [ -e "$PIGGY_STORE_DIR/directory/cred1.ebox" ]
}

function force_overwrite_existing { # @test
  "$PIGGY" cp cred1 cred2
  run "$PIGGY" cp -f cred1 cred2
  assert_success
  run "$PIGGY" show cred2
  assert_output "$INITIAL_PASSWORD"
}

function original_intact_after_all_copies { # @test
  "$PIGGY" cp cred1 cred2
  "$PIGGY" cp cred1 directory/
  "$PIGGY" cp cred1 "new directory"/newcred
  run "$PIGGY" show cred1
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function git_consistent_after_copies { # @test
  "$PIGGY" cp cred1 cred2
  "$PIGGY" cp cred1 directory/
  "$PIGGY" cp -f cred1 cred2
  run git status --porcelain
  assert_output ""
}
