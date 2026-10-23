#! /usr/bin/env bats
#
# piggy#330 — PIGGY_STORE_DIR as a colon-separated list of stores. Reads
# take the first store holding an entry; every write goes to the first
# store (the write store); an entry only a later store holds is never
# changed in place. The later store here is made read-only, the shape of
# a home-manager store path.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  RW="$PIGGY_STORE_DIR"
  RO="$BATS_TEST_TMPDIR/ro-store"
  create_test_template "$RW"
  create_test_template "$RO"
  # Each store keeps its own git repository, so piggy's git bookkeeping
  # runs in the store a write landed in and never reaches a repository
  # enclosing the test dir.
  unset GIT_DIR GIT_WORK_TREE
  git init -q "$RW"
  git init -q "$RO"

  echo "ro both" | PIGGY_STORE_DIR="$RO" "$PIGGY" pass insert -e both
  echo "ro only" | PIGGY_STORE_DIR="$RO" "$PIGGY" pass insert -e tent/only-ro
  echo "rw both" | PIGGY_STORE_DIR="$RW" "$PIGGY" pass insert -e both
  chmod -R a-w "$RO"
  export PIGGY_STORE_DIR="$RW:$RO"
}

teardown() {
  chmod -R u+w "$RO" 2>/dev/null || true
}

function show_takes_the_first_store_holding_the_entry { # @test
  run "$PIGGY" pass show both
  assert_success
  assert_output "rw both"
  run "$PIGGY" pass show tent/only-ro
  assert_success
  assert_output "ro only"
}

function ls_lists_each_store_and_marks_shadowed_entries { # @test
  run "$PIGGY" pass ls
  assert_success
  assert_output - <<EOF
Password Store ($RW)
└── both
Password Store ($RO)
├── both  [shadowed by $RW]
└── tent
    └── only-ro
EOF
}

function find_heads_each_store_s_matches_with_its_path { # @test
  run "$PIGGY" pass find only
  assert_success
  assert_line --index 0 "Search Terms: only"
  assert_line --index 1 "$RW"
  assert_line "$RO"
  assert_output --partial "only-ro"
}

function insert_goes_to_the_write_store_and_notes_the_shadow { # @test
  run "$PIGGY" pass insert -e tent/only-ro <<<"rw now"
  assert_success
  assert_output --partial "tent/only-ro in $RO is now shadowed by the write store $RW"
  assert [ -e "$RW/tent/only-ro.ebox" ]
  run "$PIGGY" pass show tent/only-ro
  assert_output "rw now"
}

function edit_of_a_later_store_entry_is_refused_naming_both_stores { # @test
  EDITOR=true run "$PIGGY" pass edit tent/only-ro
  assert_failure
  assert_output --partial "tent/only-ro is in $RO, not in the write store $RW"
  assert_output --partial "piggy pass cp tent/only-ro tent/only-ro"
}

function rm_and_mv_of_a_later_store_entry_are_refused { # @test
  run "$PIGGY" pass rm -f tent/only-ro
  assert_failure
  assert_output --partial "To remove it"
  run "$PIGGY" pass mv tent/only-ro moved
  assert_failure
  assert_output --partial "To move it"
  assert [ -e "$RO/tent/only-ro.ebox" ]
}

function cp_copies_an_entry_up_from_a_read_only_later_store { # @test
  run "$PIGGY" pass cp tent/only-ro tent/only-ro
  assert_success
  assert [ -e "$RW/tent/only-ro.ebox" ]
  run "$PIGGY" pass show tent/only-ro
  assert_output "ro only"
  # Now in the write store, it is the write store's to change.
  run "$PIGGY" pass rm -f tent/only-ro
  assert_success
  assert [ -e "$RO/tent/only-ro.ebox" ]
}

function cp_of_a_directory_from_a_read_only_store_is_writable_after { # @test
  run "$PIGGY" pass cp tent copied
  assert_success
  echo "fresh" | "$PIGGY" pass insert -e copied/new
  run "$PIGGY" pass show copied/new
  assert_output "fresh"
}

function a_read_only_write_store_refuses_writes_and_says_what_to_do { # @test
  export PIGGY_STORE_DIR="$RO:$RW"
  run "$PIGGY" pass insert -e fresh <<<"x"
  assert_failure
  assert_output --partial "the write store $RO (the first store in PIGGY_STORE_DIR) is read-only"
  assert_output --partial "Put a writable store first in PIGGY_STORE_DIR"
}

function a_single_store_lists_as_before { # @test
  export PIGGY_STORE_DIR="$RW"
  run "$PIGGY" pass ls
  assert_success
  assert_line --index 0 "Password Store"
}
