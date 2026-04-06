setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function grep_finds_matching_lines { # @test
  echo "hello" | "$PIGGY" insert -e blah1
  echo "my name is" | "$PIGGY" insert -e blah2
  echo "I hate computers" | "$PIGGY" insert -e folder/blah3
  echo "me too!" | "$PIGGY" insert -e blah4
  echo "They are hell" | "$PIGGY" insert -e folder/where/blah5

  run "$PIGGY" grep hell
  assert_success
  assert_output --partial "blah5"
  assert_output --partial "blah1"
  assert_output --partial "They are"
}

function grep_case_insensitive { # @test
  echo "I wonder..." | "$PIGGY" insert -e blah1
  echo "Will it ignore" | "$PIGGY" insert -e blah2
  echo "case when searching?" | "$PIGGY" insert -e blah3
  echo "Yes, it does. Wonderful!" | "$PIGGY" insert -e folder/blah4

  run "$PIGGY" grep -i wonder
  assert_success
  assert_output --partial "blah1"
  assert_output --partial "blah4"
}
