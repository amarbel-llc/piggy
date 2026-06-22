#! /usr/bin/env bats
#
# piggy#201 — `piggy manage` card-free surface (RFC 0007). The end-to-end
# command/interaction flow against a real (virtual) card lives in the
# hardware-tagged conformance/piggy_manage_fibby.bats; here we cover only the
# paths that never touch a card: argv validation, the stdio clean-shutdown on
# EOF, and the unknown-method wire error.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

# `piggy manage` without `--jsonrpc` is rejected (the only v1 protocol must be
# named explicitly). No card access.
function manage_requires_jsonrpc_flag { # @test
  run "$PIGGY" manage </dev/null
  assert_failure
  assert_output --partial "--jsonrpc"
}

# `piggy manage --help` reaches the subcommand parser and lists its flags.
function manage_help_lists_flags { # @test
  run "$PIGGY" manage --help
  assert_success
  assert_output --partial "--jsonrpc"
  assert_output --partial "--socket"
}

# `piggy manage --jsonrpc` over stdio with immediate EOF (no requests) is a
# clean shutdown: exit 0, nothing written to stdout.
function manage_stdio_clean_eof_exits_zero { # @test
  run "$PIGGY" manage --jsonrpc </dev/null
  assert_success
  assert_output ""
}

# An unknown method after a valid handshake returns JSON-RPC -32601 (method not
# found) — the dispatch wire path, card-free.
function manage_unknown_method_is_method_not_found { # @test
  local init='{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocol":"piggy-mgmt/1"}}'
  local bogus='{"jsonrpc":"2.0","id":1,"method":"does.not.exist","params":{}}'
  run bash -c "printf '%s\n%s\n' '$init' '$bogus' | '$PIGGY' manage --jsonrpc"
  assert_success
  # First line acknowledges initialize; second carries the method-not-found error.
  assert_output --partial '"protocol":"piggy-mgmt/1"'
  assert_output --partial '-32601'
}

# A first request that is not `initialize` is rejected with -32600 (initialize
# must come first), before any method runs.
function manage_method_before_initialize_is_invalid_request { # @test
  local early='{"jsonrpc":"2.0","id":1,"method":"card.list","params":{}}'
  run bash -c "printf '%s\n' '$early' | '$PIGGY' manage --jsonrpc"
  assert_success
  assert_output --partial '-32600'
}
