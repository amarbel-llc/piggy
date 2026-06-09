setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  # Install the ssh-copy-id mock on PATH (common.bash already prepends
  # $BATS_TEST_TMPDIR). It records argv + the rendered key file to these
  # sentinels instead of contacting a host.
  piggy_install_helper_as mock-ssh-copy-id.sh ssh-copy-id
  export SSH_COPY_ID_ARGV_FILE="$BATS_TEST_TMPDIR/ssh-copy-id.argv"
  export SSH_COPY_ID_KEYS_FILE="$BATS_TEST_TMPDIR/ssh-copy-id.keys"
}

# A canonical 9D encryption recipient (madder RFC 0002 vector) — present in
# the store to prove `ssh-copy-id` ignores it.
RECIPIENT_9D="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"

# A 9A SSH-auth markl ID over the P-256 generator point (captured from the
# piggy-ids `openssh_authorized_key` renderer), and the authorized_keys
# line it must render to. The two are pinned together: a renderer change
# that drifts the wire blob fails the assertion.
SSH_9A="piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfv47nat8"
SSH_9A_LINE_PREFIX="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU="

function ssh_copy_id_installs_9a_keys_and_ignores_9d { # @test
  cat >"$PIGGY_STORE_DIR/piggy-ids" <<-EOF
		$RECIPIENT_9D  # decrypt key (9D)
		$SSH_9A  # alice login (9A)
	EOF

  run "$PIGGY" ssh-copy-id alice@example.invalid
  assert_success

  # ssh-copy-id was invoked with `-f -i <file>` and the host last.
  run cat "$SSH_COPY_ID_ARGV_FILE"
  assert_output --regexp '^-f -i .* alice@example\.invalid$'

  # The rendered key file holds exactly the 9A line (comment carried
  # through) and nothing derived from the 9D recipient.
  run cat "$SSH_COPY_ID_KEYS_FILE"
  assert_output "$SSH_9A_LINE_PREFIX alice login (9A)"
  refute_output --partial "pivy_ecdh_p256_pub"
}

function ssh_copy_id_errors_when_no_ssh_auth_keys { # @test
  # A 9D-only piggy-ids has no SSH-login keys; the command must refuse
  # with guidance rather than invoke ssh-copy-id.
  cat >"$PIGGY_STORE_DIR/piggy-ids" <<-EOF
		$RECIPIENT_9D
	EOF

  run "$PIGGY" ssh-copy-id alice@example.invalid
  assert_failure
  assert_output --partial "no SSH-auth"
  # ssh-copy-id must not have run.
  assert [ ! -e "$SSH_COPY_ID_ARGV_FILE" ]
}

function ssh_copy_id_reads_ids_override { # @test
  # --ids points at an out-of-store piggy-ids file.
  local custom="$BATS_TEST_TMPDIR/custom-ids"
  cat >"$custom" <<-EOF
		$SSH_9A  # bob
	EOF

  run "$PIGGY" ssh-copy-id --ids "$custom" bob@example.invalid
  assert_success
  run cat "$SSH_COPY_ID_KEYS_FILE"
  assert_output "$SSH_9A_LINE_PREFIX bob"
}

function ssh_copy_id_requires_a_host { # @test
  cat >"$PIGGY_STORE_DIR/piggy-ids" <<-EOF
		$SSH_9A  # alice
	EOF
  run "$PIGGY" ssh-copy-id
  assert_failure
  assert_output --partial "missing [user@]host"
}
