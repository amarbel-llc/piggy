setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

# A real markl ID for piggy 2.x recipient use, sourced from madder
# RFC 0002's official test fixture
# (go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json
# at madder commit fd53684, post-#159 split-HRP revert). The 33-byte
# payload is the canonical non-trivial sequence 00..20.
RECIPIENT_BARE="pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"

function pass_init_with_k_writes_piggy_ids { # @test
  init_test_git
  run "$PIGGY" pass init -k "$RECIPIENT_BARE"
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/piggy-ids" ]
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  assert_output --partial "$RECIPIENT_BARE"
}

function pass_init_without_k_uses_auto_detect { # @test
  # With no -k, cmd_init shells to `piggy-ids detect-pubkey` (mocked
  # to emit the canonical RFC 0002 vector). The piggy-ids file
  # ends up with the auto-detected recipient.
  init_test_git
  run "$PIGGY" pass init
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/piggy-ids" ]
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$RECIPIENT_BARE"
}

function pass_init_without_k_no_card_dies_helpfully { # @test
  # PIGGY_TEST_DETECT_FAIL flips the mock detect-pubkey to a failure;
  # cmd_init's fall-through reports it.
  init_test_git
  PIGGY_TEST_DETECT_FAIL="no PIV cards detected" \
    run "$PIGGY" pass init
  assert_failure
  assert_output --partial "piggy-ids detect-pubkey failed"
}

function pass_init_k_and_g_are_mutually_exclusive { # @test
  init_test_git
  run "$PIGGY" pass init -k "$RECIPIENT_BARE" -g 0102030405060708090a0b0c0d0e0f10
  assert_failure
  assert_output --partial "mutually exclusive"
}

function pass_init_rejects_wrong_format_id { # @test
  init_test_git
  # sha256 vector — wrong format for a piggy recipient.
  local wrong="sha256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s7lcgm6"
  run "$PIGGY" pass init -k "$wrong"
  assert_failure
  assert_output --partial "must be a markl ID with format=pivy_ecdh_p256_pub"
}

function pass_init_with_p_creates_subfolder_template { # @test
  init_test_git
  run "$PIGGY" pass init -p team-a -k "$RECIPIENT_BARE"
  assert_success
  assert [ -e "$PIGGY_STORE_DIR/team-a/piggy-ids" ]
  assert [ ! -e "$PIGGY_STORE_DIR/piggy-ids" ]
}

function pass_init_accepts_purpose_tagged_form_unchanged { # @test
  # Purpose-tagged form must round-trip byte-for-byte through
  # cmd_init's writer. Under RFC 0002 §3.3 (post-#159 split-HRP
  # rule) the blech32 portion of `piggy-recipient-v1@<bare>` is
  # byte-identical to the bare-format encoding — purpose is
  # textually prepended after blech32, so the checksum binds to
  # `pivy_ecdh_p256_pub` only. cmd_init only checks the prefix
  # shape; piggy pass recipients (#75) will run the full codec.
  init_test_git
  local tagged="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
  run "$PIGGY" pass init -k "$tagged"
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$tagged"
}

function pass_init_commits_to_git { # @test
  init_test_git
  run "$PIGGY" pass init -k "$RECIPIENT_BARE"
  assert_success
  run git -C "$PIGGY_STORE_DIR" log --oneline
  assert_success
  assert_output --partial "Set piggy recipients"
}
