#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.8 — a proxy agent (FDR 0001, `piggy agent --proxy-only`)
# forwards an operator act to the upstream that serves the key and relays the
# answer unchanged. It displays nothing and prompts for nothing: the prompt
# fires in the agent next to the card. This is the forwarded-agent case: the
# caller talks only to the front.
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

TEXT="piggy-test: grant through the front"

_stack_with_front() {
  operator_act_stack_up
  spawn_proxy_front
}

_assert_front_never_prompted() {
  [[ $(operator_act_prompt_count "$FRONT_LOG") -eq 0 ]] ||
    operator_act_fail "the proxy front raised a PIN prompt"
  if grep -q 'piggy-test-askpass' "$FRONT_LOG"; then
    operator_act_fail "the proxy front ran an askpass"
  fi
}

function act_through_the_front_signs_and_prompts_only_at_the_card_agent { # @test
  _stack_with_front

  operator_sign_via "$FRONT_SOCK" "$TEXT" --namespace piggy-escalation-v1
  [[ $status -eq 0 ]] || operator_act_fail "operator-sign through the front failed"
  printf '%s\n' "$output" >"$WORKDIR/act.sig"
  assert_sshsig_verifies "$WORKDIR/act.sig" "$TEXT" piggy-escalation-v1 9C

  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 1 ]] ||
    operator_act_fail "the card agent should have prompted exactly once"
  grep -qx '\[piggy-test-askpass\] operator act kind: escalation' "$AGENT_LOG" ||
    operator_act_fail "the card agent's prompt was not classed"
  _assert_front_never_prompted
}

# Refusals are deterministic, so the relayed bytes can be compared with what
# the card agent answers when asked directly.
function front_relays_the_card_agents_answer_byte_for_byte { # @test
  _stack_with_front
  local flags direct
  for flags in "--slot 9C --namespace git" "--slot 9A" "--slot 9C --text-hex 611b62" "--slot 9C --version 2"; do
    # shellcheck disable=SC2086
    operator_act_probe "$AGENT_SOCK" $flags
    direct=$(grep '^raw ' <<<"$output")
    [[ -n $direct ]] || operator_act_fail "no raw answer from the card agent for: $flags"
    # shellcheck disable=SC2086
    operator_act_probe "$FRONT_SOCK" $flags
    [[ $(grep '^raw ' <<<"$output") == "$direct" ]] ||
      operator_act_fail "the front's answer differs from the card agent's for: $flags"
  done
  _assert_front_never_prompted
}

function front_answers_no_such_key_when_no_upstream_serves_it { # @test
  _stack_with_front
  operator_act_probe "$FRONT_SOCK" \
    --key-hex "0000000b7373682d6564323535313900000020$(printf '07%.0s' $(seq 1 32))"
  assert_probe_status 1 "no-such-key"
  _assert_front_never_prompted
}

# The front advertises the extension because its upstream does (§2.8), which
# `ssh-add`-style clients read from the `query` extension; a front with no
# card agent behind it does not serve an act at all.
function front_without_a_live_card_agent_serves_no_act { # @test
  _stack_with_front
  kill "$AGENT_PID"
  wait "$AGENT_PID" 2>/dev/null || true
  AGENT_PID=

  operator_sign_via "$FRONT_SOCK" "$TEXT" --namespace piggy-escalation-v1
  [[ $status -ne 0 ]] || operator_act_fail "an act was signed with no card agent alive"
  [[ -z $output ]] || operator_act_fail "stdout is not empty"
  _assert_front_never_prompted
}
