#!/usr/bin/env bats
#
# `piggy luks` (piggy#277): the store secret's first line is the
# passphrase handed to `cryptsetup … --key-file -` on stdin. Uses the
# mock cryptsetup (argv + stdin recorded) over the harness card, so no
# root or block device is needed. The real cryptsetup path is proven by
# the LUKS VM lane (`just test-vm-luks`).
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template

  piggy_install_helper_as mock-cryptsetup.sh cryptsetup
  export CRYPTSETUP_ARGV_FILE="$BATS_TEST_TMPDIR/cryptsetup.argv"
  export CRYPTSETUP_STDIN_FILE="$BATS_TEST_TMPDIR/cryptsetup.stdin"

  # A two-line entry: only the first line is the passphrase.
  printf 'hunter2-first-line\nsecond line is not the key\n' |
    "$PIGGY" pass insert -m luks/vol1 >/dev/null
}

function luks_open_pipes_first_line_without_newline { # @test
  run "$PIGGY" luks open /dev/vdb pigcrypt --secret luks/vol1
  assert_success
  run cat "$CRYPTSETUP_ARGV_FILE"
  assert_output "open --key-file - /dev/vdb pigcrypt"
  # Exact bytes: the first line only, no trailing newline (18 bytes).
  assert_equal "$(cat "$CRYPTSETUP_STDIN_FILE")" "hunter2-first-line"
  assert_equal "$(wc -c <"$CRYPTSETUP_STDIN_FILE" | tr -d ' ')" "18"
}

function luks_format_forwards_extra_args_before_device { # @test
  run "$PIGGY" luks format /dev/vdb --secret luks/vol1 -- -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000
  assert_success
  run cat "$CRYPTSETUP_ARGV_FILE"
  assert_output "luksFormat --type luks2 --key-file - -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vdb"
  assert_equal "$(cat "$CRYPTSETUP_STDIN_FILE")" "hunter2-first-line"
}

function luks_add_key_authorises_with_secret_and_appends_file { # @test
  printf %s second-slot > "$BATS_TEST_TMPDIR/pw2"
  run "$PIGGY" luks add-key /dev/vdb "$BATS_TEST_TMPDIR/pw2" --secret luks/vol1 -- -q
  assert_success
  run cat "$CRYPTSETUP_ARGV_FILE"
  assert_output "luksAddKey --key-file - -q /dev/vdb $BATS_TEST_TMPDIR/pw2"
  assert_equal "$(cat "$CRYPTSETUP_STDIN_FILE")" "hunter2-first-line"
}

function luks_close_needs_no_secret_and_no_stdin { # @test
  run "$PIGGY" luks close pigcrypt </dev/null
  assert_success
  run cat "$CRYPTSETUP_ARGV_FILE"
  assert_output "close pigcrypt"
}

function luks_open_missing_entry_fails_before_cryptsetup { # @test
  run "$PIGGY" luks open /dev/vdb pigcrypt --secret luks/nope
  assert_failure
  assert_output --partial "is not in the password store"
  assert [ ! -e "$CRYPTSETUP_ARGV_FILE" ]
}

function luks_open_rejects_sneaky_secret_name { # @test
  run "$PIGGY" luks open /dev/vdb pigcrypt --secret ../luks/vol1
  assert_failure
  assert_output --partial "sneaky path"
  assert [ ! -e "$CRYPTSETUP_ARGV_FILE" ]
}

function luks_propagates_cryptsetup_exit_code { # @test
  CRYPTSETUP_MOCK_EXIT=2 run "$PIGGY" luks open /dev/vdb pigcrypt --secret luks/vol1
  assert_equal "$status" 2
}

function luks_secret_flag_is_required_for_open { # @test
  run "$PIGGY" luks open /dev/vdb pigcrypt
  assert_failure
  assert_output --partial "--secret"
  assert [ ! -e "$CRYPTSETUP_ARGV_FILE" ]
}
