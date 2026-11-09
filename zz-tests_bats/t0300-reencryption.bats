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

function reencryption_preserves_links_and_rewrites_target { # @test
  # reencrypt no longer SKIPS symlinks — it follows them, rewrites the
  # real target, and leaves the link in place. (Was
  # `reencryption_skips_links`; the old skip made `recipients sync` a
  # no-op on symlink-farm stores. See crates/piggy/src/reencrypt.rs.)
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e folder/cred1
  ln -s "$PIGGY_STORE_DIR/folder/cred1.ebox" "$PIGGY_STORE_DIR/folder/symlink.ebox"
  assert [ -L "$PIGGY_STORE_DIR/folder/symlink.ebox" ]

  # Actually drive a reencryption pass over the subtree containing both
  # the real file and its alias.
  run "$PIGGY" pass recipients sync
  assert_success

  # The link is still a link (not clobbered into a regular file).
  assert [ -L "$PIGGY_STORE_DIR/folder/symlink.ebox" ]
  # The real file is still a real file.
  assert [ -f "$PIGGY_STORE_DIR/folder/cred1.ebox" ]
  assert [ ! -L "$PIGGY_STORE_DIR/folder/cred1.ebox" ]
  # Both names still decrypt to the original content.
  run "$PIGGY" pass show folder/cred1
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
  run "$PIGGY" pass show folder/symlink
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

# piggy#148: a link in one recipient scope whose target lives in another
# scope of the same store is re-encrypted to the recipients of the scope
# that holds the TARGET, never the link's. Here work/ declares only the
# harness card and personal/ adds a second recipient; re-encrypting work/
# must leave personal/real.ebox encrypted to personal's set (so it is
# already current and untouched), and the TAP line says where the
# recipients came from.
function cross_scope_link_uses_the_targets_recipients { # @test
  local secondary="piggy-recipient-v1@pivy_ecdh_p256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfve2jwdn"
  mkdir -p "$PIGGY_STORE_DIR/work" "$PIGGY_STORE_DIR/personal"
  printf '%s\n' "$PIGGY_TEST_RECIPIENT" >"$PIGGY_STORE_DIR/work/piggy-ids"
  printf '%s\n%s\n' "$PIGGY_TEST_RECIPIENT" "$secondary" >"$PIGGY_STORE_DIR/personal/piggy-ids"
  git -C "$PIGGY_STORE_DIR" add -A >/dev/null
  git -C "$PIGGY_STORE_DIR" commit -q -m "piggy-test: two scopes" >/dev/null

  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e personal/real
  ln -s ../personal/real.ebox "$PIGGY_STORE_DIR/work/shared.ebox"
  git -C "$PIGGY_STORE_DIR" add -A >/dev/null
  git -C "$PIGGY_STORE_DIR" commit -q -m "piggy-test: cross-scope link" >/dev/null
  cp "$PIGGY_STORE_DIR/personal/real.ebox" "$BATS_TEST_TMPDIR/before.ebox"

  run "$PIGGY" pass recipients sync -p work
  assert_success
  assert_line "# cross-scope: work/shared -> personal/real, recipients from personal/piggy-ids"
  assert_output --regexp 'ok [0-9]+ - work/shared # SKIP'

  cmp "$PIGGY_STORE_DIR/personal/real.ebox" "$BATS_TEST_TMPDIR/before.ebox" ||
    fail "the target was re-encrypted to the link's scope"
  run "$PIGGY" pass show personal/real
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

# piggy#148: a target an earlier (link-side) walk left encrypted to the
# link's scope is repaired to its own scope's recipients, and reported.
function cross_scope_link_repairs_a_target_encrypted_to_the_links_scope { # @test
  local secondary="piggy-recipient-v1@pivy_ecdh_p256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfve2jwdn"
  mkdir -p "$PIGGY_STORE_DIR/work" "$PIGGY_STORE_DIR/personal"
  printf '%s\n' "$PIGGY_TEST_RECIPIENT" >"$PIGGY_STORE_DIR/work/piggy-ids"
  # personal/real is first encrypted while personal/ has work's set ...
  printf '%s\n' "$PIGGY_TEST_RECIPIENT" >"$PIGGY_STORE_DIR/personal/piggy-ids"
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e personal/real
  # ... then personal/ gains a recipient without a walk, so the file is
  # still encrypted to the link's (work's) set.
  printf '%s\n%s\n' "$PIGGY_TEST_RECIPIENT" "$secondary" >"$PIGGY_STORE_DIR/personal/piggy-ids"
  ln -s ../personal/real.ebox "$PIGGY_STORE_DIR/work/shared.ebox"
  git -C "$PIGGY_STORE_DIR" add -A >/dev/null
  git -C "$PIGGY_STORE_DIR" commit -q -m "piggy-test: stale cross-scope target" >/dev/null

  run "$PIGGY" pass recipients sync -p work
  assert_success
  assert_line "# cross-scope: work/shared -> personal/real, recipients from personal/piggy-ids"
  assert_output --regexp 'ok [0-9]+ - work/shared$'

  # Now encrypted to personal's set: a walk of personal/ has nothing to do.
  run "$PIGGY" pass recipients sync -p personal
  assert_success
  assert_output --regexp 'ok [0-9]+ - personal/real # SKIP'
  run "$PIGGY" pass show personal/real
  assert_success
  assert_output --partial "$INITIAL_PASSWORD"
}

# piggy#148: a link to a file outside the store keeps the link's scope, and
# the walk says so.
function out_of_store_link_uses_the_links_recipients_and_says_so { # @test
  local outside="$BATS_TEST_TMPDIR/outside"
  mkdir -p "$outside" "$PIGGY_STORE_DIR/work"
  printf '%s\n' "$PIGGY_TEST_RECIPIENT" >"$PIGGY_STORE_DIR/work/piggy-ids"
  echo "$INITIAL_PASSWORD" | "$PIGGY" pass insert -e work/tmp
  mv "$PIGGY_STORE_DIR/work/tmp.ebox" "$outside/real.ebox"
  ln -s "$outside/real.ebox" "$PIGGY_STORE_DIR/work/linked.ebox"
  git -C "$PIGGY_STORE_DIR" add -A >/dev/null
  git -C "$PIGGY_STORE_DIR" commit -q -m "piggy-test: out-of-store link" >/dev/null

  run "$PIGGY" pass recipients sync -p work
  assert_success
  assert_output --regexp '# cross-scope: work/linked -> .*/outside/real\.ebox \(outside the store\), recipients from work/piggy-ids'
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
