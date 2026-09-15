setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function show_generated_password { # @test
  "$PIGGY" pass generate cred1 19
  run "$PIGGY" pass show cred1
  assert_success
}

function show_password_with_spaces { # @test
  echo "BLAH!!" | "$PIGGY" pass insert -e "I am a cred with lots of spaces"
  run "$PIGGY" pass show "I am a cred with lots of spaces"
  assert_success
  assert_output "BLAH!!"
}

function show_password_with_unicode { # @test
  "$PIGGY" pass generate "🏠" 19
  run "$PIGGY" pass show
  assert_success
  assert_output --partial "🏠"
}

function show_nonexistent_password_fails { # @test
  run "$PIGGY" pass show cred2
  assert_failure
}

function show_recipients_flag_renders_tree { # @test
  # `pass show -r` renders the store tree with each ebox annotated by
  # its recipients, read offline from the ebox wire header (no card
  # traffic). Every leaf names the harness card's recipient, rendered as
  # its shortest-unique prefix; an unparseable ebox would show the [?]
  # sentinel instead.
  "$PIGGY" pass generate etsy/jira.env 19
  "$PIGGY" pass generate top-level 19
  run "$PIGGY" pass show -r
  assert_success
  assert_output --partial "Password Store"
  assert_output --partial "etsy"
  assert_output --partial "jira.env"
  assert_output --partial "top-level"
  assert_output --partial "[piggy-re"
  refute_output --partial "[?]"
}

function show_recipients_long_flag_is_accepted { # @test
  "$PIGGY" pass generate cred1 19
  run "$PIGGY" pass show --recipients
  assert_success
  assert_output --partial "Password Store"
  assert_output --partial "cred1"
}
