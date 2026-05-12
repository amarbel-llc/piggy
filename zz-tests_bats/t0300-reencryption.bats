INITIAL_PASSWORD="will this password live? a big question indeed..."

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  init_test_git
  "$PIGGY" pass git init
}

function insert_credential { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  assert [ -f "$PIGGY_STORE_DIR/folder/cred1.ebox" ]
}

function reencryption_after_template_change_preserves_content { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  # Change template (triggers reencryption)
  create_test_template
  run "$PIGGY" pass show folder/cred1
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

function reencryption_subfolder_copy { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  run "$PIGGY" pass cp folder/cred1 anotherfolder/
  assert_success
  assert [ -f "$PIGGY_STORE_DIR/anotherfolder/cred1.ebox" ]
}

function reencryption_subfolder_move { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  "$PIGGY" pass cp folder/cred1 anotherfolder/
  create_test_template "$PIGGY_STORE_DIR/anotherfolder2"
  git -C "$PIGGY_STORE_DIR" add anotherfolder2/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder2 template."
  run "$PIGGY" pass mv -f anotherfolder anotherfolder2/
  assert_success
  assert [ -f "$PIGGY_STORE_DIR/anotherfolder2/anotherfolder/cred1.ebox" ]
}

function reencryption_skips_links { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  ln -s "$PIGGY_STORE_DIR/folder/cred1.ebox" "$PIGGY_STORE_DIR/folder/symlink.ebox"
  assert [ -L "$PIGGY_STORE_DIR/folder/symlink.ebox" ]
  create_test_template "$PIGGY_STORE_DIR/folder"
  git -C "$PIGGY_STORE_DIR" add folder/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add folder template."
  # Symlink should still be a symlink after reencryption
  assert [ -L "$PIGGY_STORE_DIR/folder/symlink.ebox" ]
}

function password_survives_all_transformations { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  "$PIGGY" pass cp folder/cred1 anotherfolder/
  create_test_template "$PIGGY_STORE_DIR/anotherfolder2"
  git -C "$PIGGY_STORE_DIR" add anotherfolder2/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder2 template."
  "$PIGGY" pass mv -f anotherfolder anotherfolder2/
  run "$PIGGY" pass show anotherfolder2/anotherfolder/cred1
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

function git_consistent_after_reencryption { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  "$PIGGY" pass cp folder/cred1 anotherfolder/
  create_test_template "$PIGGY_STORE_DIR/anotherfolder2"
  git -C "$PIGGY_STORE_DIR" add anotherfolder2/piggy-ids
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder2 template."
  "$PIGGY" pass mv -f anotherfolder anotherfolder2/
  run git status --porcelain
  assert_output ""
}
