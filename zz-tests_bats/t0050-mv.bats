INITIAL_PASSWORD="bla bla bla will we make it!!"

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  init_test_git
  "$PIGGY" pass git init
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e cred1
}

function basic_move { # @test
  run "$PIGGY" pass mv cred1 cred2
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/cred2.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/cred1.ebox" ]
}

function move_into_directory { # @test
  "$PIGGY" pass mv cred1 cred2
  run "$PIGGY" pass mv cred2 directory/
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/directory" ]
  assert [ -e "$PIGGY_STORE_DIR/directory/cred2.ebox" ]
}

function move_with_rename_and_empty_directory_removal { # @test
  "$PIGGY" pass mv cred1 cred2
  "$PIGGY" pass mv cred2 directory/
  run "$PIGGY" pass mv directory/cred2 "new directory with spaces"/cred
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/new directory with spaces" ]
  assert [ -e "$PIGGY_STORE_DIR/new directory with spaces/cred.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/directory" ]
}

function directory_rename { # @test
  "$PIGGY" pass mv cred1 cred2
  "$PIGGY" pass mv cred2 directory/
  "$PIGGY" pass mv directory/cred2 "new directory with spaces"/cred
  run "$PIGGY" pass mv "new directory with spaces" anotherdirectory
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/anotherdirectory" ]
  assert [ -e "$PIGGY_STORE_DIR/anotherdirectory/cred.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/new directory with spaces" ]
}

function directory_move_into_new_directory { # @test
  "$PIGGY" pass mv cred1 cred2
  "$PIGGY" pass mv cred2 directory/
  "$PIGGY" pass mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" pass mv "new directory with spaces" anotherdirectory
  run "$PIGGY" pass mv anotherdirectory "new directory with spaces"/
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/new directory with spaces/anotherdirectory" ]
  assert [ -e "$PIGGY_STORE_DIR/new directory with spaces/anotherdirectory/cred.ebox" ]
  assert [ ! -e "$PIGGY_STORE_DIR/anotherdirectory" ]
}

function multi_directory_creation_and_removal { # @test
  "$PIGGY" pass mv cred1 cred2
  "$PIGGY" pass mv cred2 directory/
  "$PIGGY" pass mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" pass mv "new directory with spaces" anotherdirectory
  "$PIGGY" pass mv anotherdirectory "new directory with spaces"/
  run bash -c '"$1" pass mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred && "$1" pass mv new1/new2/new3/new4/thecred cred' _ "$PIGGY"
  assert_success
  assert [ ! -d "$PIGGY_STORE_DIR/new directory with spaces/anotherdirectory" ]
  assert [ ! -d "$PIGGY_STORE_DIR/new1/new2/new3/new4" ]
  assert [ -e "$PIGGY_STORE_DIR/cred.ebox" ]
}

function password_survives_all_moves { # @test
  "$PIGGY" pass mv cred1 cred2
  "$PIGGY" pass mv cred2 directory/
  "$PIGGY" pass mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" pass mv "new directory with spaces" anotherdirectory
  "$PIGGY" pass mv anotherdirectory "new directory with spaces"/
  "$PIGGY" pass mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred
  "$PIGGY" pass mv new1/new2/new3/new4/thecred cred
  run "$PIGGY" pass show cred
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function git_consistent_after_moves { # @test
  "$PIGGY" pass mv cred1 cred2
  "$PIGGY" pass mv cred2 directory/
  "$PIGGY" pass mv directory/cred2 "new directory with spaces"/cred
  "$PIGGY" pass mv "new directory with spaces" anotherdirectory
  "$PIGGY" pass mv anotherdirectory "new directory with spaces"/
  "$PIGGY" pass mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred
  "$PIGGY" pass mv new1/new2/new3/new4/thecred cred
  run git status --porcelain
  assert_output ""
}
