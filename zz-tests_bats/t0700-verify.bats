setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

# Helper: write a valid (mock-decryptable) ebox: mock-pivy-box's
# `stream decrypt` runs base64 -d, so any base64 payload decodes
# successfully.
seed_ok() {
  local relpath="$1"
  local target="$PIGGY_STORE_DIR/$relpath.ebox"
  mkdir -p "$(dirname "$target")"
  printf 'hello\n' | base64 >"$target"
}

# Helper: write an ebox whose contents are NOT valid base64; mock
# decrypt will exit nonzero, which is what we want for "not ok".
seed_fail() {
  local relpath="$1"
  local target="$PIGGY_STORE_DIR/$relpath.ebox"
  mkdir -p "$(dirname "$target")"
  printf '!!!garbage-not-base64!!!\n' >"$target"
}

function verify_empty_store_succeeds_with_no_output { # @test
  run "$PIGGY" pass verify
  assert_success
  assert_output ""
}

function verify_single_ok_entry { # @test
  seed_ok foo
  run "$PIGGY" pass verify
  assert_success
  assert_output --partial "ok     foo"
  # The leaf name should NOT include the .ebox extension.
  refute_output --partial "foo.ebox"
}

function verify_single_failing_entry_exits_one { # @test
  seed_fail bad
  run "$PIGGY" pass verify
  assert_failure
  assert_equal "$status" 1
  assert_output --partial "not ok bad"
}

function verify_mixed_tree { # @test
  seed_ok work/aws/prod
  seed_ok work/aws/staging
  seed_fail work/aws/old-key
  seed_ok personal/email

  run "$PIGGY" pass verify
  assert_failure
  assert_equal "$status" 1
  # Top-level directories appear at column 0.
  assert_line "personal"
  assert_line "work"
  # Per-leaf decoration is present.
  assert_output --partial "ok     prod"
  assert_output --partial "ok     staging"
  assert_output --partial "not ok old-key"
  assert_output --partial "ok     email"
}

function verify_subpath_filter { # @test
  seed_ok work/aws/prod
  seed_ok personal/email

  run "$PIGGY" pass verify work
  assert_success
  assert_output --partial "ok     prod"
  refute_output --partial "personal"
  refute_output --partial "email"
}

function verify_subpath_parent_traversal_is_rejected { # @test
  run "$PIGGY" pass verify ../etc
  assert_failure
  assert_equal "$status" 2
  assert_output --partial "escapes the store"
}

function verify_subpath_absolute_is_rejected { # @test
  run "$PIGGY" pass verify /etc/passwd
  assert_failure
  assert_equal "$status" 2
  assert_output --partial "relative"
}

function verify_skips_dot_git { # @test
  seed_ok visible
  mkdir -p "$PIGGY_STORE_DIR/.git"
  printf '!!!garbage!!!\n' >"$PIGGY_STORE_DIR/.git/hidden.ebox"

  run "$PIGGY" pass verify
  assert_success
  assert_output --partial "ok     visible"
  refute_output --partial "hidden"
  refute_output --partial ".git"
}

function verify_follows_symlinks { # @test
  mkdir -p "$PIGGY_STORE_DIR/elsewhere"
  printf 'hi\n' | base64 >"$PIGGY_STORE_DIR/elsewhere/payload.ebox"
  ln -s elsewhere "$PIGGY_STORE_DIR/link"

  run "$PIGGY" pass verify
  assert_success
  assert_output --partial "ok     payload"
}
