#! /usr/bin/env bats
#
# piggy#76: a store holding only a piggy 1.x `.pivy-id` template, and no
# piggy-ids, is refused with a one-line error that names piggy-ids.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

function insert_refuses_a_store_with_only_a_legacy_pivy_id { # @test
  printf 'legacy template\n' >"$PIGGY_STORE_DIR/.pivy-id"
  run "$PIGGY" pass insert -e cred1 <<<"secret"
  assert_failure
  assert_output --partial ".pivy-id"
  assert_output --partial "piggy-ids"
  [[ ${#lines[@]} -eq 1 ]] || {
    echo "expected a one-line error, got ${#lines[@]} lines" >&2
    return 1
  }
  [[ ! -e $PIGGY_STORE_DIR/cred1.ebox ]]
}

function a_nested_legacy_pivy_id_is_refused_too { # @test
  mkdir -p "$PIGGY_STORE_DIR/team"
  printf 'legacy template\n' >"$PIGGY_STORE_DIR/team/.pivy-id"
  run "$PIGGY" pass insert -e team/cred1 <<<"secret"
  assert_failure
  assert_output --partial "team/.pivy-id"
}

function piggy_ids_wins_over_a_leftover_pivy_id { # @test
  create_test_template
  printf 'legacy template\n' >"$PIGGY_STORE_DIR/.pivy-id"
  run "$PIGGY" pass insert -e cred1 <<<"secret"
  assert_success
  [[ -f $PIGGY_STORE_DIR/cred1.ebox ]]
}
