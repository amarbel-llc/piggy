#! /usr/bin/env bats
#
# PIGGY_AUTH_SOCK routing (#123): `piggy pass show` should decrypt against
# piggy's own agent socket (PIGGY_AUTH_SOCK) when set, falling back to the
# ambient SSH_AUTH_SOCK otherwise. The mock pivy-box records the
# SSH_AUTH_SOCK each `stream decrypt` invocation saw (PIGGY_TEST_SOCK_RECORD
# hook), so we can assert which socket the decrypt was routed at without a
# real agent or card.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  create_test_template
  echo "secret-content" | "$PIGGY" pass insert -e cred-auth-sock

  SOCK_RECORD="$BATS_TEST_TMPDIR/sock-record"
  : >"$SOCK_RECORD"
  export PIGGY_TEST_SOCK_RECORD="$SOCK_RECORD"
}

function decrypt_routes_at_piggy_auth_sock_when_set { # @test
  export PIGGY_AUTH_SOCK="/sentinel/piggy-agent.sock"
  export SSH_AUTH_SOCK="/sentinel/mux-agent.sock"

  run "$PIGGY" pass show cred-auth-sock
  assert_success
  assert_output "secret-content"

  run cat "$SOCK_RECORD"
  assert_output "/sentinel/piggy-agent.sock"
}

function decrypt_falls_back_to_ssh_auth_sock_when_unset { # @test
  unset PIGGY_AUTH_SOCK
  export SSH_AUTH_SOCK="/sentinel/mux-agent.sock"

  run "$PIGGY" pass show cred-auth-sock
  assert_success
  assert_output "secret-content"

  run cat "$SOCK_RECORD"
  assert_output "/sentinel/mux-agent.sock"
}

function decrypt_falls_back_when_piggy_auth_sock_empty { # @test
  export PIGGY_AUTH_SOCK=""
  export SSH_AUTH_SOCK="/sentinel/mux-agent.sock"

  run "$PIGGY" pass show cred-auth-sock
  assert_success
  assert_output "secret-content"

  run cat "$SOCK_RECORD"
  assert_output "/sentinel/mux-agent.sock"
}
