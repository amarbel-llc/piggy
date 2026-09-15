setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  init_test_git
  # PRIMARY is the harness card's own slot-9D key, so inserts encrypt to
  # something the in-process decrypt can unwrap.
  RECIPIENT_PRIMARY="$PIGGY_TEST_RECIPIENT"
  "$PIGGY" pass init -k "$RECIPIENT_PRIMARY"
}

# SECONDARY is the P-256 generator point as a recipient (the same point
# t0800's 9A SSH-auth ID carries, in the 9D format): a valid curve point
# nobody holds the private half of, so the store can encrypt to it (the
# real piggy-ids rejects an off-curve point) but only the harness card
# can decrypt.
RECIPIENT_SECONDARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfve2jwdn"
WRONG_FORMAT="sha256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s7lcgm6"

function recipients_list_prints_recipients { # @test
  run "$PIGGY" pass recipients list
  assert_success
  assert_output --partial "$RECIPIENT_PRIMARY"
}

function recipients_add_appends_canonical_form { # @test
  local bare="${RECIPIENT_SECONDARY#piggy-recipient-v1@}"
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
  # Both eboxes already encrypt to exactly that set, so the walk's offline
  # recipients-match check SKIPs each point without touching the card. The
  # rewrite-and-commit proof for a changed set lives in
  # zz-tests_bats/conformance/piggy_recipients_sync_fibby.bats.
  echo "secret-one" | "$PIGGY" pass insert -e foo/bar
  echo "secret-two" | "$PIGGY" pass insert -e baz
  run "$PIGGY" pass recipients sync
  assert_success
  # The walk emits a TAP-14 stream: version + a 1..2 plan (one point per ebox).
  assert_output --partial "TAP version 14"
  assert_output --partial "1..2"
  assert_output --partial "# SKIP recipients already current"
  run "$PIGGY" pass show foo/bar
  assert_success
  assert_output --partial "secret-one"
  run "$PIGGY" pass show baz
  assert_success
  assert_output --partial "secret-two"
}

function recipients_sync_no_file_follows_symlink_into_external_dir { # @test
  # Mirrors the real-world rcm symlink-farm store: the store entry is a
  # symlink pointing at an ebox that lives OUTSIDE the store (an rcm
  # checkout). reencrypt must follow the link, rewrite the real target,
  # and leave the link in place — not skip it (the old behavior, which
  # made `recipients sync` a no-op on such stores). This proves the link
  # survives and the target still decrypts; the changed-recipient-set
  # rewrite proof lives in the fibby conformance lane.
  local ext="$BATS_TEST_TMPDIR/external-store"
  mkdir -p "$ext"
  # Create the real ebox inside the store, then relocate it outside and
  # symlink it back in — the same shape as a store entry pointing into
  # rcm.
  echo "linked-secret" | "$PIGGY" pass insert -e linked
  mv "$PIGGY_STORE_DIR/linked.ebox" "$ext/linked.ebox"
  ln -s "$ext/linked.ebox" "$PIGGY_STORE_DIR/linked.ebox"
  assert [ -L "$PIGGY_STORE_DIR/linked.ebox" ]

  run "$PIGGY" pass recipients sync
  assert_success

  # The store entry is STILL a symlink (not clobbered into a regular
  # file) and still points at the external target.
  assert [ -L "$PIGGY_STORE_DIR/linked.ebox" ]
  run readlink "$PIGGY_STORE_DIR/linked.ebox"
  assert_output "$ext/linked.ebox"
  # The external target still decrypts to the original plaintext.
  run "$PIGGY" pass show linked
  assert_success
  assert_output --partial "linked-secret"
}

function recipients_sync_no_file_dedups_symlink_beside_target { # @test
  # A symlink sitting beside its own target (both inside the store, both
  # resolving to the same file) must be re-encrypted exactly once and
  # both names must still resolve afterward.
  echo "dup-secret" | "$PIGGY" pass insert -e original
  ln -s "$PIGGY_STORE_DIR/original.ebox" "$PIGGY_STORE_DIR/alias.ebox"
  assert [ -L "$PIGGY_STORE_DIR/alias.ebox" ]

  run "$PIGGY" pass recipients sync
  assert_success

  # Real file stays a real file; alias stays a link to it.
  assert [ -f "$PIGGY_STORE_DIR/original.ebox" ]
  assert [ ! -L "$PIGGY_STORE_DIR/original.ebox" ]
  assert [ -L "$PIGGY_STORE_DIR/alias.ebox" ]
  run "$PIGGY" pass show original
  assert_success
  assert_output --partial "dup-secret"
  run "$PIGGY" pass show alias
  assert_success
  assert_output --partial "dup-secret"
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
  # `add` lands a commit for the piggy-ids change and a second one for
  # the re-encryption pass (the ebox now carries a second recipient part,
  # so its bytes change). The entry must still decrypt via the card.
  echo "secret content" | "$PIGGY" pass insert -e folder/cred1
  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  run "$PIGGY" pass recipients add "$RECIPIENT_SECONDARY"
  assert_success
  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ $before_sha != "$after_sha" ]] || fail "expected a new commit after recipients add"
  run git -C "$PIGGY_STORE_DIR" log --pretty=%s
  assert_line --index 0 "Reencrypt password store after adding recipient(s)."
  assert_line --index 1 "Add recipient(s) to piggy-ids."
  run "$PIGGY" pass show folder/cred1
  assert_success
  assert_output "secret content"
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
  [[ $before_contents == "$after_contents" ]] || fail "piggy-ids was modified despite the canonicalize rejection"

  # No new commit lands.
  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ $before_sha == "$after_sha" ]] || fail "expected no commit when add fails validation"
}
