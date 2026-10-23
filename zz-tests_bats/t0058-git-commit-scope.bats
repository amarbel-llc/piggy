#! /usr/bin/env bats
#
# piggy#294 — piggy's automatic commits record only the paths the command
# touched. A store inside a larger working repository (circus keeps one in
# its checkout) must not sweep the operator's unrelated staged files into
# "Add generated password for ..." commits.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  init_test_git
  "$PIGGY" pass git init
  echo "unrelated" >"$PIGGY_STORE_DIR/notes.txt"
  git add "$PIGGY_STORE_DIR/notes.txt"
}

assert_unrelated_file_left_staged() {
  run git show --stat --format= HEAD
  refute_output --partial "notes.txt"
  run git diff --cached --name-only
  assert_output --partial "notes.txt"
}

function generate_commits_only_the_new_entry { # @test
  run "$PIGGY" pass generate some/entry 16
  assert_success
  run git show --stat --format= HEAD
  assert_output --partial "some/entry.ebox"
  assert_unrelated_file_left_staged
}

function insert_commits_only_the_new_entry { # @test
  echo "secret" | "$PIGGY" pass insert -e cred1
  run git show --stat --format= HEAD
  assert_output --partial "cred1.ebox"
  assert_unrelated_file_left_staged
}

function mv_records_the_rename_in_one_commit_of_its_own_paths { # @test
  echo "secret" | "$PIGGY" pass insert -e cred1
  run "$PIGGY" pass mv cred1 cred2
  assert_success
  run git show --stat --format=%s HEAD
  assert_output --partial "Rename cred1 to cred2."
  assert_output --partial "cred2.ebox"
  run git status --porcelain -- "$PIGGY_STORE_DIR/cred1.ebox" "$PIGGY_STORE_DIR/cred2.ebox"
  assert_output ""
  assert_unrelated_file_left_staged
}

function rm_commits_only_the_removed_entry { # @test
  echo "secret" | "$PIGGY" pass insert -e cred1
  run "$PIGGY" pass rm -f cred1
  assert_success
  run git show --stat --format= HEAD
  assert_output --partial "cred1.ebox"
  assert_unrelated_file_left_staged
}
