#! /usr/bin/env bats

# Exploratory tests for pivy-box tpl create
#
# Finding: pivy-box tpl create treats its first arg as a template NAME,
# not a file path. It searches ebox_tpl_path for a writable location:
#   1. $HOME/.pivy/tpl/$TPL (or ~/Library/Preferences/pivy/tpl/$TPL)
#   2. $HOME/.ebox/tpl/$TPL (legacy)
#   3. entries from $PIVY_EBOX_TPL_PATH
#
# For reads (F_OK), it tries the arg as a direct path first.
# For writes (W_OK), it ONLY searches the path list.
#
# With HOME redirected to the test tmpdir (via setup_test_home),
# the default path resolves inside the sandbox.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  TEST_STORE="$BATS_TEST_TMPDIR/store"
  mkdir -p "$TEST_STORE"
}

# --- Assumption: arg is a file path (DISPROVED) ---

function tpl_create_absolute_path_not_written_to_given_path { # @test
  detect_guid_or_skip
  run "$PIVY_BOX_BIN" tpl create "$TEST_STORE/.pivy-id" primary local-guid "$DETECTED_GUID"
  # pivy-box succeeds but writes to $HOME/.pivy/tpl/<name>, NOT to the given path
  assert_success
  refute [ -f "$TEST_STORE/.pivy-id" ]
}

# --- Template name resolution via PIVY_EBOX_TPL_PATH ---

function tpl_create_with_tpl_path_env_writes_file { # @test
  detect_guid_or_skip
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  run "$PIVY_BOX_BIN" tpl create ".pivy-id" primary local-guid "$DETECTED_GUID"
  assert_success
  [ -f "$TEST_STORE/.pivy-id" ]
}

function tpl_create_with_tpl_path_env_file_is_nonempty { # @test
  detect_guid_or_skip
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  "$PIVY_BOX_BIN" tpl create ".pivy-id" primary local-guid "$DETECTED_GUID"
  [ -s "$TEST_STORE/.pivy-id" ]
}

function tpl_create_with_tpl_path_env_readable_by_tpl_show { # @test
  detect_guid_or_skip
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  "$PIVY_BOX_BIN" tpl create ".pivy-id" primary local-guid "$DETECTED_GUID"
  run "$PIVY_BOX_BIN" tpl show "$TEST_STORE/.pivy-id"
  assert_success
  assert_output --partial "guid:"
}

# --- Verify tpl show reads direct paths (F_OK path) ---

function tpl_show_reads_direct_path { # @test
  detect_guid_or_skip
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  "$PIVY_BOX_BIN" tpl create ".pivy-id" primary local-guid "$DETECTED_GUID"
  run "$PIVY_BOX_BIN" tpl show "$TEST_STORE/.pivy-id"
  assert_success
  assert_output --partial "slot:"
}

# --- Explicit guid + slot + key ---

function tpl_create_explicit_key_with_tpl_path { # @test
  detect_guid_or_skip
  local pubkey
  pubkey="$("$PIVY_TOOL_BIN" pubkey 9d | awk '{print $1, $2}')"
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  run "$PIVY_BOX_BIN" tpl create ".pivy-id" \
    primary guid "$DETECTED_GUID" slot 9d key "$pubkey"
  assert_success
  [ -f "$TEST_STORE/.pivy-id" ]
}

# --- Error cases ---

function tpl_create_invalid_guid_fails { # @test
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  run "$PIVY_BOX_BIN" tpl create ".pivy-id" primary local-guid DEADBEEF
  assert_failure
  refute [ -f "$TEST_STORE/.pivy-id" ]
}

function tpl_create_no_builder_args_creates_no_file { # @test
  export PIVY_EBOX_TPL_PATH="$TEST_STORE/\$TPL"
  run "$PIVY_BOX_BIN" tpl create ".pivy-id"
  # No builder = no config = should it still create an empty template?
  if [ -f "$TEST_STORE/.pivy-id" ]; then
    echo "# empty builder created a file" >&3
  else
    echo "# empty builder created no file" >&3
  fi
}
