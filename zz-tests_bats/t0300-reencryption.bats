INITIAL_PASSWORD="will this password live? a big question indeed..."

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  "$PIGGY" git init
}

function insert_credential { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  assert [ -f "$PIGGY_STORE_DIR/folder/cred1.ebox" ]
}

function reencryption_after_template_change_preserves_content { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  # Change template (triggers reencryption)
  create_test_template
  run "$PIGGY" show folder/cred1
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

function reencryption_subfolder_copy { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  run "$PIGGY" cp folder/cred1 anotherfolder/
  assert_success
  assert [ -f "$PIGGY_STORE_DIR/anotherfolder/cred1.ebox" ]
}

function reencryption_subfolder_move { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  "$PIGGY" cp folder/cred1 anotherfolder/
  create_test_template "$PIGGY_STORE_DIR/anotherfolder2"
  git -C "$PIGGY_STORE_DIR" add anotherfolder2/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder2 template."
  run "$PIGGY" mv -f anotherfolder anotherfolder2/
  assert_success
  assert [ -f "$PIGGY_STORE_DIR/anotherfolder2/anotherfolder/cred1.ebox" ]
}

function reencryption_skips_links { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  ln -s "$PIGGY_STORE_DIR/folder/cred1.ebox" "$PIGGY_STORE_DIR/folder/symlink.ebox"
  assert [ -L "$PIGGY_STORE_DIR/folder/symlink.ebox" ]
  create_test_template "$PIGGY_STORE_DIR/folder"
  git -C "$PIGGY_STORE_DIR" add folder/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add folder template."
  # Symlink should still be a symlink after reencryption
  assert [ -L "$PIGGY_STORE_DIR/folder/symlink.ebox" ]
}

function password_survives_all_transformations { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  "$PIGGY" cp folder/cred1 anotherfolder/
  create_test_template "$PIGGY_STORE_DIR/anotherfolder2"
  git -C "$PIGGY_STORE_DIR" add anotherfolder2/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder2 template."
  "$PIGGY" mv -f anotherfolder anotherfolder2/
  run "$PIGGY" show anotherfolder2/anotherfolder/cred1
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

function git_consistent_after_reencryption { # @test
  echo "$INITIAL_PASSWORD" | "$PIGGY" insert -e folder/cred1
  create_test_template "$PIGGY_STORE_DIR/anotherfolder"
  git -C "$PIGGY_STORE_DIR" add anotherfolder/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder template."
  "$PIGGY" cp folder/cred1 anotherfolder/
  create_test_template "$PIGGY_STORE_DIR/anotherfolder2"
  git -C "$PIGGY_STORE_DIR" add anotherfolder2/.pivy-id
  git -C "$PIGGY_STORE_DIR" commit -m "Add anotherfolder2 template."
  "$PIGGY" mv -f anotherfolder anotherfolder2/
  run git status --porcelain
  assert_output ""
}
