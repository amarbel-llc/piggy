setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  init_test_git
  "$PIGGY" pass init -k "$RECIPIENT_PRIMARY"
}

# Two real markl IDs minted from RFC 0002 vectors. PRIMARY is the
# canonical pivy_ecdh_p256_pub/non_trivial vector pinned by the
# fixture at madder fd53684. SECONDARY is generated from
# pivy_pubkey_payload() in piggy-markl tests (a deterministic 33-byte
# SEC1-compressed point).
RECIPIENT_PRIMARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
RECIPIENT_SECONDARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qvqq6x38x3q5ukmgwkpgl89fkmpaph027uzpz83t8pz4yhmv0xrfxgs3lef"
WRONG_FORMAT="sha256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s7lcgm6"

function recipients_list_prints_recipients { # @test
  run "$PIGGY" pass recipients list
  assert_success
  assert_output --partial "$RECIPIENT_PRIMARY"
}

function recipients_add_appends_canonical_form { # @test
  local bare="pivy_ecdh_p256_pub-qvqq6x38x3q5ukmgwkpgl89fkmpaph027uzpz83t8pz4yhmv0xrfxgs3lef"
  run "$PIGGY" pass recipients add "$bare"
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  assert_output --partial "$RECIPIENT_SECONDARY"
}

function recipients_remove_drops_matching_id { # @test
  "$PIGGY" pass recipients add "$RECIPIENT_SECONDARY"
  run "$PIGGY" pass recipients remove "$RECIPIENT_SECONDARY"
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  refute_output --partial "$RECIPIENT_SECONDARY"
  assert_output --partial "$RECIPIENT_PRIMARY"
}

function recipients_sync_from_empty_replaces_set { # @test
  local desired="$BATS_TEST_TMPDIR/desired-piggy-ids"
  echo "$RECIPIENT_SECONDARY" >"$desired"
  run "$PIGGY" pass recipients sync "$desired"
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  assert_output --partial "$RECIPIENT_SECONDARY"
  refute_output --partial "$RECIPIENT_PRIMARY"
}

function recipients_sync_to_declared_subset { # @test
  "$PIGGY" pass recipients add "$RECIPIENT_SECONDARY"
  local desired="$BATS_TEST_TMPDIR/desired-piggy-ids"
  echo "$RECIPIENT_PRIMARY" >"$desired"
  run "$PIGGY" pass recipients sync "$desired"
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  assert_output --partial "$RECIPIENT_PRIMARY"
  refute_output --partial "$RECIPIENT_SECONDARY"
}

function recipients_sync_idempotent { # @test
  local desired="$BATS_TEST_TMPDIR/desired-piggy-ids"
  echo "$RECIPIENT_PRIMARY" >"$desired"
  local before
  before="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  run "$PIGGY" pass recipients sync "$desired"
  assert_success
  local after
  after="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  assert_equal "$before" "$after"
}

function recipients_sync_rejects_wrong_format { # @test
  local desired="$BATS_TEST_TMPDIR/desired-piggy-ids"
  echo "$WRONG_FORMAT" >"$desired"
  run "$PIGGY" pass recipients sync "$desired"
  assert_failure
  assert_output --partial "validation"
}

function recipients_add_commits_piggy_ids_change { # @test
  # `add` lands a commit for the piggy-ids change. Under real
  # crypto a second commit lands for the reencryption pass too, but
  # the bats mock's base64 round-trips bit-identically so re-encryption
  # is a content no-op that git won't commit.
  echo "secret content" | "$PIGGY" pass insert -e folder/cred1
  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  run "$PIGGY" pass recipients add "$RECIPIENT_SECONDARY"
  assert_success
  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" != "$after_sha" ]] || fail "expected a new commit after recipients add"
  run git -C "$PIGGY_STORE_DIR" log -1 --pretty=%s
  assert_output --partial "Add recipient(s) to piggy-ids."
}
