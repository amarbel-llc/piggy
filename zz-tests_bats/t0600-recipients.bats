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

function recipients_sync_no_file_reencrypts_whole_store { # @test
  # No <file>: re-encrypt every ebox to the recipients already in piggy-ids.
  # The base64 mock round-trips bit-identically, so this asserts the dispatch
  # path succeeds and the plaintext survives. The real-crypto proof (ciphertext
  # actually re-encrypted, decryptable via the card, commit landed) lives in
  # zz-tests_bats/conformance/piggy_recipients_sync_fibby.bats.
  echo "secret-one" | "$PIGGY" pass insert -e foo/bar
  echo "secret-two" | "$PIGGY" pass insert -e baz
  run "$PIGGY" pass recipients sync
  assert_success
  run "$PIGGY" pass show foo/bar
  assert_success
  assert_output --partial "secret-one"
  run "$PIGGY" pass show baz
  assert_success
  assert_output --partial "secret-two"
}

function recipients_sync_no_file_with_p_scopes { # @test
  # `sync -p <subfolder>` (no file) re-encrypts only that subtree; the other
  # subtree is left alone. Both must still decrypt afterward.
  echo "scoped-secret" | "$PIGGY" pass insert -e work/cred
  echo "other-secret" | "$PIGGY" pass insert -e personal/cred
  run "$PIGGY" pass recipients sync -p work
  assert_success
  run "$PIGGY" pass show work/cred
  assert_success
  assert_output --partial "scoped-secret"
  run "$PIGGY" pass show personal/cred
  assert_success
  assert_output --partial "other-secret"
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

function recipients_add_invalid_id_does_not_corrupt_piggy_ids { # @test
  # Regression: append-before-validate. Previously, an invalid markl ID
  # got appended to piggy-ids and canonicalize then failed — leaving
  # the file corrupted. Now we validate via a tempfile first.
  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  local before_contents
  before_contents="$(cat "$PIGGY_STORE_DIR/piggy-ids")"

  # 'pivy_ecdh_p256_pub-bogus' starts with the right HRP but has only
  # 5 charset chars in the body — below the 7-char minimum. canonicalize
  # rejects.
  run "$PIGGY" pass recipients add "pivy_ecdh_p256_pub-bogus"
  assert_failure
  assert_output --partial "invalid recipient"

  # File MUST be unchanged.
  local after_contents
  after_contents="$(cat "$PIGGY_STORE_DIR/piggy-ids")"
  [[ "$before_contents" = "$after_contents" ]] || fail "piggy-ids was modified despite the canonicalize rejection"

  # No new commit lands.
  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit when add fails validation"
}
