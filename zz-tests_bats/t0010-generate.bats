setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function generate_password_with_specified_length { # @test
  run "$PIGGY" pass generate cred 19
  assert_success

  run "$PIGGY" pass show cred
  assert_success
  # 19 chars + newline = 20 bytes
  assert [ "$(echo "$output" | wc -m | tr -d ' ')" -eq 20 ]
}

function generate_in_place_replaces_first_line { # @test
  local initial_password="will this password live? a big question indeed..."
  echo "$initial_password" | "$PIGGY" pass insert -e cred1
  # Add a second line
  {
    echo "replaced-first-line"
    echo "second line"
  } | "$PIGGY" pass insert -f -m cred1

  run "$PIGGY" pass generate -i cred1 23
  assert_success

  run "$PIGGY" pass show cred1
  assert_success
  # First line should be 23 chars, second line preserved
  local first_line
  first_line="$(echo "$output" | head -1)"
  assert [ "${#first_line}" -eq 23 ]
  assert_output --partial "second line"
}
