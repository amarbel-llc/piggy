#! /usr/bin/env bats
#
# Conformance tests for the `piggy pivy <tool> [args...]` passthrough.
#
# Uses `run -N` to assert specific exit codes; that syntax requires
# bats 1.5.0+.
bats_require_minimum_version 1.5.0
#
#
# Verifies the v1.0 escape hatch (#48) reaches the C `pivy-<tool>` binary
# from $PATH (in tests, the mocks under `helpers/`). Differs from the
# top-level shortcuts:
#   - `piggy box`   → rust pivy-box reimplementation
#   - `piggy tool`  → C pivy-tool (via fallback)
#   - `piggy pivy box`  → ALWAYS C pivy-box, regardless of the top-level
#     rust impl
#   - `piggy pivy tool` → identical effect to `piggy tool` for now;
#     diverges once `tool` ports to rust (#3)
#
# All tests go through the top-level rust `piggy` dispatcher (the bats
# parent `common.bash` resolves `$PIGGY` to `target/debug/piggy` and
# symlinks mock pivy-tool / pivy-box into the test PATH).

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

# --- usage / argument validation ---

function pivy_no_tool_prints_usage_and_fails { # @test
  run "$PIGGY" pivy
  assert_failure
  assert_output --partial "missing tool name"
  assert_output --partial "Usage: piggy pivy"
}

function pivy_invalid_tool_name_with_slash_fails { # @test
  run "$PIGGY" pivy "../bash"
  assert_failure
  assert_output --partial "invalid pivy tool name"
}

function pivy_invalid_tool_name_with_metachar_fails { # @test
  run "$PIGGY" pivy "box;rm"
  assert_failure
  assert_output --partial "invalid pivy tool name"
}

function pivy_nonexistent_tool_errors_clearly { # @test
  # Tool name is well-formed but no `pivy-<thiswillneverexist>` binary
  # is installed — we expect a clean failure-to-launch message and the
  # standard 127 ("command not found") exit code, NOT a panic or empty
  # output. Use `run -127` so bats does not flag the exit code via
  # BW01.
  run -127 "$PIGGY" pivy "thiswillneverexist"
  assert_output --partial "failed to launch pivy-thiswillneverexist"
}

# --- happy path through the mock pivy-* binaries ---

function pivy_tool_list_reaches_mock_pivy_tool { # @test
  # The common.bash harness symlinks mock-pivy-tool.sh into $PATH as
  # `pivy-tool`; `piggy pivy tool list` should reach it and print the
  # mock's deterministic stdout.
  run "$PIGGY" pivy tool list
  assert_success
  assert_output --partial "card: TESTGUID"
  assert_output --partial "guid: TESTGUID1234567890ABCDEF"
}

function pivy_tool_pubkey_forwards_positional_arg { # @test
  # Positional arg ("9a") needs to reach the mock unchanged.
  run "$PIGGY" pivy tool pubkey 9a
  assert_success
  assert_output --partial "ecdsa-sha2-nistp256"
  assert_output --partial "PIV_slot_9a@TESTGUID"
}
