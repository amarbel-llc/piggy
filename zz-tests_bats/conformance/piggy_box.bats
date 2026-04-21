#! /usr/bin/env bats
#
# CLI conformance tests for `piggy box` (rust pivy-box replacement).
#
# Every error/usage path in crates/piggy/src/cmd/pivy_box.rs is covered.
# No PIV card or fib stack needed — these are pure argument validation
# tests. Supersedes the old pivy_box.bats.skip placeholder.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

# --- no args / usage ---

function no_args_prints_usage_and_fails { # @test
  run "$PIGGY" box
  assert_failure
  assert_output --partial "type and operation required"
  assert_output --partial "Types: stream, tpl"
}

function unknown_type_fails { # @test
  run "$PIGGY" box nonexistent badop
  assert_failure
  assert_output --partial "unknown type: nonexistent"
}

# --- stream ---

function stream_no_op_fails { # @test
  run "$PIGGY" box stream
  assert_failure
  assert_output --partial "operation required"
  assert_output --partial "Operations: encrypt, decrypt"
}

function stream_unknown_op_fails { # @test
  run "$PIGGY" box stream badop
  assert_failure
  assert_output --partial "unknown operation: badop"
}

function stream_encrypt_no_template_fails { # @test
  run "$PIGGY" box stream encrypt
  assert_failure
  assert_output --partial "template path required"
}

function stream_encrypt_missing_template_fails { # @test
  run "$PIGGY" box stream encrypt /nonexistent/path/tpl
  assert_failure
  assert_output --partial "cannot read template"
}

function stream_encrypt_invalid_template_fails { # @test
  echo "garbage" > "$BATS_TEST_TMPDIR/bad.tpl"
  run "$PIGGY" box stream encrypt "$BATS_TEST_TMPDIR/bad.tpl"
  assert_failure
  assert_output --partial "invalid template"
}

# --- tpl ---

function tpl_no_op_fails { # @test
  run "$PIGGY" box tpl
  assert_failure
  assert_output --partial "operation required"
  assert_output --partial "Operations: create, show"
}

function tpl_unknown_op_fails { # @test
  run "$PIGGY" box tpl badop
  assert_failure
  assert_output --partial "unknown operation: badop"
}

function tpl_edit_not_implemented { # @test
  run "$PIGGY" box tpl edit
  assert_failure
  assert_output --partial "not yet implemented"
}

# --- tpl create ---

function tpl_create_no_args_fails { # @test
  run "$PIGGY" box tpl create
  assert_failure
  assert_output --partial "usage: piggy box tpl create"
}

function tpl_create_insufficient_args_fails { # @test
  run "$PIGGY" box tpl create myname
  assert_failure
  assert_output --partial "usage: piggy box tpl create"
}

function tpl_create_wrong_config_type_fails { # @test
  run "$PIGGY" box tpl create myname recovery local-guid abcd1234abcd1234abcd1234abcd1234
  assert_failure
  assert_output --partial "only 'primary' config type"
}

function tpl_create_wrong_source_fails { # @test
  run "$PIGGY" box tpl create myname primary remote abcd1234abcd1234abcd1234abcd1234
  assert_failure
  assert_output --partial "only 'local-guid' source"
}

function tpl_create_invalid_guid_fails { # @test
  run "$PIGGY" box tpl create myname primary local-guid ZZZZ
  assert_failure
  assert_output --partial "invalid GUID"
}

function tpl_create_interactive_not_implemented { # @test
  run "$PIGGY" box tpl create -i
  assert_failure
  assert_output --partial "interactive mode not yet implemented"
}

# --- tpl show ---

function tpl_show_missing_file_fails { # @test
  run "$PIGGY" box tpl show /nonexistent/path/tpl
  assert_failure
  assert_output --partial "cannot read"
}

function tpl_show_invalid_template_fails { # @test
  echo "garbage" > "$BATS_TEST_TMPDIR/bad.tpl"
  run "$PIGGY" box tpl show "$BATS_TEST_TMPDIR/bad.tpl"
  assert_failure
  assert_output --partial "invalid template"
}

# --- stream decrypt ---

function stream_decrypt_invalid_stream_fails { # @test
  echo "garbage" > "$BATS_TEST_TMPDIR/bad.ebox"
  run "$PIGGY" box stream decrypt "$BATS_TEST_TMPDIR/bad.ebox"
  assert_failure
  assert_output --partial "invalid stream"
}
