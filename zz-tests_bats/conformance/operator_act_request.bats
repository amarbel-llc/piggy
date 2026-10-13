#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.1 — a request that is not exactly a version 1 request is
# answered `bad-request` (status 7), in a SUCCESS-class extension response,
# and never reaches the prompt: version ≠ 1, an unknown hash algorithm,
# flags ≠ 0, trailing bytes, a truncated payload.
#
# Stack and required env: zz-tests_bats/lib/operator_act.bash.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  operator_act_setup
}

teardown() {
  operator_act_teardown
}

_assert_bad_request_without_a_prompt() {
  local what="$1"
  shift
  operator_act_probe "$AGENT_SOCK" "$@"
  grep -qx 'reply 29 extension-response' <<<"$output" ||
    operator_act_fail "$what: a refusal must be an extension response, not an agent failure"
  assert_probe_status 7 "bad-request: $what"
  grep -qx 'sshsig-hex ' <<<"$output" || operator_act_fail "$what: a refusal carried a signature"
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 0 ]] ||
    operator_act_fail "$what: a malformed request raised a PIN prompt"
}

function well_formed_request_is_the_control { # @test
  operator_act_stack_up
  operator_act_probe "$AGENT_SOCK" --slot 9C
  assert_probe_status 0 signed
  grep -qx 'version 1' <<<"$output" || operator_act_fail "the response is not version 1"
}

function version_other_than_1_is_bad_request { # @test
  operator_act_stack_up
  _assert_bad_request_without_a_prompt "version 2" --slot 9C --version 2
  _assert_bad_request_without_a_prompt "version 0" --slot 9C --version 0
}

function unknown_hash_algorithm_is_bad_request { # @test
  operator_act_stack_up
  _assert_bad_request_without_a_prompt "hash md5" --slot 9C --hash md5
  _assert_bad_request_without_a_prompt "hash SHA512 (case)" --slot 9C --hash SHA512
}

function nonzero_flags_are_bad_request { # @test
  operator_act_stack_up
  _assert_bad_request_without_a_prompt "flags 1" --slot 9C --flags 1
}

function trailing_bytes_are_bad_request { # @test
  operator_act_stack_up
  _assert_bad_request_without_a_prompt "one trailing byte" --slot 9C --trailing-hex 00
}

function truncated_payload_is_bad_request { # @test
  operator_act_stack_up
  # An outer string that promises four bytes and holds a lone version field.
  _assert_bad_request_without_a_prompt "truncated contents" --details-hex 0000000400000001
  _assert_bad_request_without_a_prompt "no payload" --details-hex ""
}
