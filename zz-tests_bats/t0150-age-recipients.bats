setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

# Markl IDs sourced from piggy-markl's canonical RFC 0002 test
# vectors (crates/piggy-markl/testdata/0002-markl-id-format-vectors.json).
# Each format has its own blech32 checksum binding the format-id and
# payload, so encoded suffixes are NOT interchangeable across formats.
PIVY_RECIPIENT="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
AGE_RECIPIENT_BARE="age_x25519_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0scveleg"
AGE_RECIPIENT_TAGGED="piggy-recipient-v1@age_x25519_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0scveleg"

function pass_init_k_rejects_age_recipient_at_bash_prefix_check { # @test
  # piggy.sh::cmd_init has a bash-side prefix check that predates the
  # markl/piggy-ids broadening (PR #94). Until that check is widened,
  # `piggy pass init -k <age-...>` MUST fail with the
  # "format=pivy_ecdh_p256_pub" message, NOT silently succeed and
  # later fail at re-encrypt. This test pins that behavior so a
  # follow-up that fixes cmd_init has to update this test too.
  init_test_git
  run "$PIGGY" pass init -k "$AGE_RECIPIENT_BARE"
  assert_failure
  assert_output --partial "must be a markl ID with format=pivy_ecdh_p256_pub"
}

function piggy_ids_canonicalize_accepts_mixed_recipients { # @test
  # The real piggy-ids canonicalize must accept a mixed pivy+age
  # piggy-ids file. This is the markl/parser layer that PR #94
  # broadened; it lands today regardless of pipeline readiness.
  local tmp="$BATS_TEST_TMPDIR/mixed-piggy-ids"
  cat >"$tmp" <<-_EOF
		$PIVY_RECIPIENT  # primary
		$AGE_RECIPIENT_BARE  # age (bare format on input)
		_EOF
  run "$PIGGY_IDS_REAL" canonicalize "$tmp"
  assert_success
  # Bare age form must be promoted to purpose-tagged on rewrite.
  run cat "$tmp"
  assert_success
  assert_output --partial "$AGE_RECIPIENT_TAGGED"
}

function pass_insert_into_age_only_store_emits_unsupported_error { # @test
  # piggy_encrypt sees an age-only piggy-ids, mock-piggy-ids exits
  # with the UnsupportedRecipientFormat error the real binary would
  # emit. The error reaches stderr.
  #
  # IMPORTANT: today the encrypt failure does NOT propagate to a
  # nonzero exit because piggy.sh's cmd_insert pipelines
  # `echo ... | piggy_encrypt ...` and `die` exits the pipeline
  # subshell only — git_add_file then commits the empty .ebox.
  # See amarbel-llc/piggy#98. Once that's fixed, replace
  # `assert_output --partial` checks with `assert_failure` AND
  # `assert [ ! -e "$PIGGY_STORE_DIR/age-only-cred.ebox" ]`.
  init_test_git
  printf '%s\n' "$AGE_RECIPIENT_TAGGED" >"$PIGGY_STORE_DIR/piggy-ids"
  run bash -c "echo secret | '$PIGGY' pass insert -e age-only-cred 2>&1"
  assert_output --partial "AgeX25519Pub not yet wired"
  assert_output --partial "Encryption aborted"
}

function pass_insert_into_mixed_store_emits_unsupported_error { # @test
  # Mixed piggy-ids: one pivy + one age recipient. The encrypt path
  # fails on the first age part it sees (mirroring the Rust-side
  # template_with_mixed_recipients_fails_on_age_part test).
  #
  # Same #98 caveat as above: error visible on stderr, but the
  # exit-status propagation through the pipeline is broken.
  init_test_git
  cat >"$PIGGY_STORE_DIR/piggy-ids" <<-_EOF
		$PIVY_RECIPIENT
		$AGE_RECIPIENT_TAGGED
		_EOF
  run bash -c "echo secret | '$PIGGY' pass insert -e mixed-cred 2>&1"
  assert_output --partial "AgeX25519Pub not yet wired"
  assert_output --partial "Encryption aborted"
}

function pass_recipients_add_age_into_pivy_store_reencrypt_emits_error { # @test
  # `recipients add` flow:
  #   1. canonicalize candidate piggy-ids — accepts age line
  #   2. install candidate over PIGGY_IDS
  #   3. reencrypt_path → piggy_encrypt → mock detects age → fails
  #
  # reencrypt_path (piggy.sh:101) is `pivy-box stream decrypt |
  # piggy-ids encrypt >$tmp && mv || rm` — same pipeline-exit-status
  # bug as cmd_insert (see amarbel-llc/piggy#98): the encrypt error
  # is on stderr but the function continues, the command exits 0,
  # and the existing .ebox is left unchanged.
  init_test_git
  printf '%s\n' "$PIVY_RECIPIENT" >"$PIGGY_STORE_DIR/piggy-ids"
  echo "secret" | "$PIGGY" pass insert -e existing-cred
  assert [ -e "$PIGGY_STORE_DIR/existing-cred.ebox" ]

  run "$PIGGY" pass recipients add "$AGE_RECIPIENT_BARE"
  assert_output --partial "AgeX25519Pub not yet wired"

  # piggy-ids did get updated (step 2 completed before reencrypt failed).
  run grep -F "$AGE_RECIPIENT_TAGGED" "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
}
