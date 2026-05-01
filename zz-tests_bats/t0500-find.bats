setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
}

function find_resolves_matching_files { # @test
  "$PIGGY" pass generate Something/neat 19
  "$PIGGY" pass generate Anotherthing/okay 19
  "$PIGGY" pass generate Fish 19
  "$PIGGY" pass generate Fishies 19
  "$PIGGY" pass generate Fishthings/stuff 19
  "$PIGGY" pass generate Fishthings/otherstuff 19

  run "$PIGGY" pass find fish
  assert_success
  assert_output --partial "Fish"
  assert_output --partial "Fishies"
  assert_output --partial "Fishthings"
}
