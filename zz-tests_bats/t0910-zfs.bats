#!/usr/bin/env bats
#
# `piggy zfs` (piggy#279): the store secret's first line is the passphrase
# handed to `zfs … -o keylocation=prompt` / `zfs load-key -L prompt` on
# stdin. Uses the mock zfs (argv + stdin recorded) and the mock pivy-box,
# so no root, pool, or card is needed. The real zfs path is proven by the
# ZFS VM lane (`just test-vm-zfs`).
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template

  piggy_install_helper_as mock-zfs.sh zfs
  export ZFS_ARGV_FILE="$BATS_TEST_TMPDIR/zfs.argv"
  export ZFS_STDIN_FILE="$BATS_TEST_TMPDIR/zfs.stdin"

  printf 'correct-horse-battery\nsecond line is not the key\n' |
    "$PIGGY" pass insert -m zfs/pool1 >/dev/null
}

function zfs_load_key_prompts_first_line_plus_newline { # @test
  run "$PIGGY" zfs load-key pigpool/enc --secret zfs/pool1
  assert_success
  run cat "$ZFS_ARGV_FILE"
  assert_output "load-key -L prompt pigpool/enc"
  # zfs reads one line: the first line, newline-terminated, nothing else.
  assert_equal "$(cat "$ZFS_STDIN_FILE")" "correct-horse-battery"
  assert_equal "$(wc -l <"$ZFS_STDIN_FILE" | tr -d ' ')" "1"
}

function zfs_create_pins_encryption_options_and_forwards_extra { # @test
  run "$PIGGY" zfs create pigpool/enc --secret zfs/pool1 -- -o mountpoint=/mnt/enc
  assert_success
  run cat "$ZFS_ARGV_FILE"
  assert_output "create -o encryption=aes-256-gcm -o keyformat=passphrase -o keylocation=prompt -o mountpoint=/mnt/enc pigpool/enc"
  assert_equal "$(cat "$ZFS_STDIN_FILE")" "correct-horse-battery"
}

function zfs_missing_entry_fails_before_zfs { # @test
  run "$PIGGY" zfs load-key pigpool/enc --secret zfs/nope
  assert_failure
  assert_output --partial "is not in the password store"
  assert [ ! -e "$ZFS_ARGV_FILE" ]
}

function zfs_propagates_exit_code { # @test
  ZFS_MOCK_EXIT=3 run "$PIGGY" zfs load-key pigpool/enc --secret zfs/pool1
  assert_equal "$status" 3
}

function zfs_secret_flag_is_required { # @test
  run "$PIGGY" zfs create pigpool/enc
  assert_failure
  assert_output --partial "--secret"
  assert [ ! -e "$ZFS_ARGV_FILE" ]
}
