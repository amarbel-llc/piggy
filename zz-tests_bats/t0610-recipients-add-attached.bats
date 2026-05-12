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
