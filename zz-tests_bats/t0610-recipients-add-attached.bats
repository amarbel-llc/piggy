setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  init_test_git
  "$PIGGY" pass init -k "$RECIPIENT_PRIMARY"
}

RECIPIENT_PRIMARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
RECIPIENT_SECONDARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qvqq6x38x3q5ukmgwkpgl89fkmpaph027uzpz83t8pz4yhmv0xrfxgs3lef"

function add_attached_with_positional_id_is_usage_error { # @test
  run "$PIGGY" pass recipients add --all-attached "$RECIPIENT_SECONDARY"
  assert_failure
  assert_output --partial "mutually exclusive"
}

function add_attached_happy_path_one_new_card { # @test
  # Store is initialized with RECIPIENT_PRIMARY; mock emits a
  # different card so --all-attached has something to add.
  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$'piggy-recipient-v1@pivy_ecdh_p256_pub-qvqq6x38x3q5ukmgwkpgl89fkmpaph027uzpz83t8pz4yhmv0xrfxgs3lef\tdeadbeef00000000aabbccddeeff0011'

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  assert_output --partial "$RECIPIENT_SECONDARY"  # new card
  assert_output --partial "$RECIPIENT_PRIMARY"    # original still present
}
