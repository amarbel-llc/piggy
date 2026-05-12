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

function add_attached_already_present_prints_info_line { # @test
  # Mock emits exactly the recipient the store was init'd with.
  # GUID must be 32 uppercase hex chars to match the real binary's
  # hex::encode_upper output (mock normalizes via ${guid^^}).
  local guid="CAFEF00D00000000DDEE000112233444"
  export PIGGY_TEST_DETECT_ALL_SUPPORTED="$RECIPIENT_PRIMARY"$'\t'"$guid"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  assert_output --partial "already a recipient: $RECIPIENT_PRIMARY"
  assert_output --partial "GUID $guid"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no new commit when all attached cards are already recipients"
}

function add_attached_unsupported_without_yes_aborts { # @test
  local sup_guid="DEADBEEF00000000AABBCCDDEEFF0011"
  local unsup_guid="CAFEF00D11223344556677889900AABB"
  export PIGGY_TEST_DETECT_ALL_SUPPORTED="$RECIPIENT_SECONDARY"$'\t'"$sup_guid"
  export PIGGY_TEST_DETECT_ALL_UNSUPPORTED="$unsup_guid"$'\t'"slot 9D is Rsa2048"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached
  assert_failure
  assert_output --partial "Cannot encrypt to 1 attached card"
  assert_output --partial "$unsup_guid: slot 9D is Rsa2048"
  assert_output --partial "stdin is not a TTY"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit when aborted"
}

function add_attached_unsupported_with_yes_adds_supported_only { # @test
  local sup_guid="DEADBEEF00000000AABBCCDDEEFF0011"
  local unsup_guid="CAFEF00D11223344556677889900AABB"
  export PIGGY_TEST_DETECT_ALL_SUPPORTED="$RECIPIENT_SECONDARY"$'\t'"$sup_guid"
  export PIGGY_TEST_DETECT_ALL_UNSUPPORTED="$unsup_guid"$'\t'"slot 9D is Rsa2048"

  run "$PIGGY" pass recipients add --all-attached --yes
  assert_success
  assert_output --partial "Cannot encrypt to 1 attached card"
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$RECIPIENT_SECONDARY"
}

function add_attached_only_unsupported_yes_is_nothing_to_add { # @test
  local unsup_guid="CAFEF00D11223344556677889900AABB"
  unset PIGGY_TEST_DETECT_ALL_SUPPORTED
  export PIGGY_TEST_DETECT_ALL_UNSUPPORTED="$unsup_guid"$'\t'"slot 9D is Rsa2048"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached --yes
  assert_success
  assert_output --partial "Cannot encrypt to 1 attached card"
  assert_output --partial "nothing to add"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit when nothing to add"
}

function add_attached_no_cards_errors { # @test
  unset PIGGY_TEST_DETECT_ALL_SUPPORTED PIGGY_TEST_DETECT_ALL_UNSUPPORTED || true
  run "$PIGGY" pass recipients add --all-attached
  assert_failure
  assert_output --partial "no PIV cards detected"
}
