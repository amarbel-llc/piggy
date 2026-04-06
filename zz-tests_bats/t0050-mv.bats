INITIAL_PASSWORD="bla bla bla will we make it!!"

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  init_test_git
  "$PIGGY" git init
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e cred1
}

function basic_move { # @test
  run "$PIGGY" mv cred1 cred2
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/cred2.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/cred1.ebox" ]
}

function move_into_directory { # @test
  "$PIGGY" mv cred1 cred2
  run "$PIGGY" mv cred2 directory/
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/directory" ]
  assert [ -e "$PIGGY_STORE_DIR/directory/cred2.ebox" ]
}

function move_with_rename_and_empty_directory_removal { # @test
  "$PIGGY" mv cred1 cred2
  "$PIGGY" mv cred2 directory/
  run "$PIGGY" mv directory/cred2 "new directory with spaces"/cred
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/new directory with spaces" ]
  assert [ -e "$PIGGY_STORE_DIR/new directory with spaces/cred.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/directory" ]
}

function directory_rename { # @test
  "$PIGGY" mv cred1 cred2
  "$PIGGY" mv cred2 directory/
  "$PIGGY" mv directory/cred2 "new directory with spaces"/cred
  run "$PIGGY" mv "new directory with spaces" anotherdirectory
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/anotherdirectory" ]
  assert [ -e "$PIGGY_STORE_DIR/anotherdirectory/cred.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/new directory with spaces" ]
}

function directory_move_into_new_directory { # @test
  "$PIGGY" mv cred1 cred2
  "$PIGGY" mv cred2 directory/
  "$PIGGY" mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" mv "new directory with spaces" anotherdirectory
  run "$PIGGY" mv anotherdirectory "new directory with spaces"/
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/new directory with spaces/anotherdirectory" ]
  assert [ -e "$PIGGY_STORE_DIR/new directory with spaces/anotherdirectory/cred.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/anotherdirectory" ]
}

function multi_directory_creation_and_removal { # @test
  "$PIGGY" mv cred1 cred2
  "$PIGGY" mv cred2 directory/
  "$PIGGY" mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" mv "new directory with spaces" anotherdirectory
  "$PIGGY" mv anotherdirectory "new directory with spaces"/
  run bash -c '"$1" mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred && "$1" mv new1/new2/new3/new4/thecred cred' _ "$PIGGY"
  assert_success
  assert [ ! -d "$PIGGY_STORE_DIR/new directory with spaces/anotherdirectory" ]
  assert [ ! -d "$PIGGY_STORE_DIR/new1/new2/new3/new4" ]
  assert [ -e "$PIGGY_STORE_DIR/cred.ebox" ]
}

function password_survives_all_moves { # @test
  "$PIGGY" mv cred1 cred2
  "$PIGGY" mv cred2 directory/
  "$PIGGY" mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" mv "new directory with spaces" anotherdirectory
  "$PIGGY" mv anotherdirectory "new directory with spaces"/
  "$PIGGY" mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred
  "$PIGGY" mv new1/new2/new3/new4/thecred cred
  run "$PIGGY" show cred
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function git_consistent_after_moves { # @test
  "$PIGGY" mv cred1 cred2
  "$PIGGY" mv cred2 directory/
  "$PIGGY" mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" mv "new directory with spaces" anotherdirectory
  "$PIGGY" mv anotherdirectory "new directory with spaces"/
  "$PIGGY" mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred
  "$PIGGY" mv new1/new2/new3/new4/thecred cred
  run git status --porcelain
  assert_output ""
}
