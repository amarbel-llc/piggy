INITIAL_PASSWORD="bla bla bla will we make it!!"

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  init_test_git
  "$PIGGY" pass git init
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e cred1
}

function basic_copy { # @test
  run "$PIGGY" pass cp cred1 cred2
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/cred1.ebox" ]
  assert [ -e "$PIGGY_STORE_DIR/cred2.ebox" ]
}

function copy_preserves_original_content { # @test
  "$PIGGY" pass cp cred1 cred2
  run "$PIGGY" pass show cred1
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function copy_destination_has_same_content { # @test
  "$PIGGY" pass cp cred1 cred2
  run "$PIGGY" pass show cred2
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function copy_into_directory { # @test
  run "$PIGGY" pass cp cred1 directory/
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/directory" ]
  assert [ -e "$PIGGY_STORE_DIR/directory/cred1.ebox" ]
}

function copy_with_rename_into_new_directory { # @test
  run "$PIGGY" pass cp cred1 "new directory"/newcred
  assert_success
  assert [ -d "$PIGGY_STORE_DIR/new directory" ]
  assert [ -e "$PIGGY_STORE_DIR/new directory/newcred.ebox" ]
}

function copy_directory_recursively { # @test
  "$PIGGY" pass cp cred1 directory/
  run "$PIGGY" pass cp directory targetdir
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/targetdir/cred1.ebox" ]
  assert [ -e "$PIGGY_STORE_DIR/directory/cred1.ebox" ]
}

function force_overwrite_existing { # @test
  "$PIGGY" pass cp cred1 cred2
  run "$PIGGY" pass cp -f cred1 cred2
  assert_success
  run "$PIGGY" pass show cred2
  assert_output "$INITIAL_PASSWORD"
}

function original_intact_after_all_copies { # @test
  "$PIGGY" pass cp cred1 cred2
  "$PIGGY" pass cp cred1 directory/
  "$PIGGY" pass cp cred1 "new directory"/newcred
  run "$PIGGY" pass show cred1
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

# piggy#149: copying an entry that is a symlink (a store kept as a symlink
# farm into a tracked tree) makes an independent copy. The re-encryption the
# copy triggers for its new folder's recipients rewrites the copy only, never
# the source's backing file.
function copy_of_a_symlinked_entry_leaves_the_source_untouched { # @test
  local tracked="$BATS_TEST_TMPDIR/tracked"
  mkdir -p "$tracked"
  mv "$PIGGY_STORE_DIR/cred1.ebox" "$tracked/cred1.ebox"
  ln -s "$tracked/cred1.ebox" "$PIGGY_STORE_DIR/cred1.ebox"
  cp "$tracked/cred1.ebox" "$BATS_TEST_TMPDIR/before.ebox"

  # A subfolder with a different recipient set, so the copy is re-encrypted.
  local secondary="piggy-recipient-v1@pivy_ecdh_p256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfve2jwdn"
  mkdir -p "$PIGGY_STORE_DIR/other"
  printf '%s\n%s\n' "$PIGGY_TEST_RECIPIENT" "$secondary" >"$PIGGY_STORE_DIR/other/piggy-ids"
  git -C "$PIGGY_STORE_DIR" add -A >/dev/null
  git -C "$PIGGY_STORE_DIR" commit -q -m "piggy-test: other/ recipients" >/dev/null

  run "$PIGGY" pass cp -f cred1 other/cred1
  assert_success
  cmp "$tracked/cred1.ebox" "$BATS_TEST_TMPDIR/before.ebox" ||
    fail "the copy rewrote the source's backing file"
  [[ -L $PIGGY_STORE_DIR/cred1.ebox ]] || fail "the source is no longer a symlink"
  [[ ! -L $PIGGY_STORE_DIR/other/cred1.ebox ]] || fail "the copy is a symlink to the source"

  run "$PIGGY" pass show other/cred1
  assert_success
  assert_output "$INITIAL_PASSWORD"
}

function git_consistent_after_copies { # @test
  "$PIGGY" pass cp cred1 cred2
  "$PIGGY" pass cp cred1 directory/
  "$PIGGY" pass cp -f cred1 cred2
  run git status --porcelain
  assert_output ""
}
