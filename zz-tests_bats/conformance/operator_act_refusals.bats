#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.3 and §3 — the refusals. Statuses 2 to 4 (policy, namespace,
# text) are decided before any prompt, so a refusal never costs the operator
# a PIN: the askpass safety net records no prompt. The namespace registry is
# closed: `git`, `file`, `email`, `piggy-record-v1` and anything unregistered
# are `refused-namespace` with no override. A key nobody serves is
# `no-such-key`; an operator who declines the prompt is `cancelled`.
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

# An ssh-ed25519 key blob no agent here holds: string "ssh-ed25519", then a
# 32-byte string of 0x07.
FOREIGN_KEY_HEX="0000000b7373682d6564323535313900000020$(printf '07%.0s' $(seq 1 32))"

_assert_no_prompt() {
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 0 ]] ||
    operator_act_fail "$1 raised a PIN prompt"
}

function unregistered_namespaces_are_refused_before_any_prompt { # @test
  operator_act_stack_up
  local namespace
  for namespace in git file email piggy-record-v1 piggy-escalation-v2 escalation ""; do
    operator_act_probe "$AGENT_SOCK" --slot 9C --namespace "$namespace"
    assert_probe_status 3 "refused-namespace for '$namespace'"
  done
  _assert_no_prompt "a namespace refusal"
}

function undisplayable_text_is_refused_before_any_prompt { # @test
  operator_act_stack_up
  operator_act_probe "$AGENT_SOCK" --slot 9C --text ""
  assert_probe_status 4 "refused-text"
  _assert_no_prompt "a text refusal"
}

function slot_that_cannot_attest_is_refused_before_any_prompt { # @test
  operator_act_stack_up
  operator_act_probe "$AGENT_SOCK" --slot 9A
  assert_probe_status 2 "refused-policy"
  _assert_no_prompt "a policy refusal"
}

function key_nobody_serves_is_no_such_key { # @test
  operator_act_stack_up
  operator_act_probe "$AGENT_SOCK" --key-hex "$FOREIGN_KEY_HEX"
  assert_probe_status 1 "no-such-key"
  _assert_no_prompt "an unserved key"
}

function declined_prompt_is_cancelled_and_nothing_is_signed { # @test
  spawn_operator_card
  OPERATOR_ACT_AGENT_REFUSES_PROMPTS=1 spawn_card_agent

  operator_act_probe "$AGENT_SOCK" --slot 9C
  assert_probe_status 5 "cancelled"
  grep -qx 'sshsig-hex ' <<<"$output" || operator_act_fail "a cancelled act carried a signature"
  # The prompt was raised (and refused): the text was put in front of the
  # operator before the card was asked for anything.
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 1 ]] ||
    operator_act_fail "expected exactly one (declined) prompt"
  if grep -q 'TOUCH needed 9C' <(sed -n '/operator act/,$p' "$FIBBY_LOG"); then
    operator_act_fail "the card was asked to sign after the prompt was declined"
  fi
}

# The CLI reports a refusal with the RFC's status name and exit 1, and keeps
# stdout empty; it refuses what it can tell is wrong before asking the agent.
function cli_reports_refusals_by_name { # @test
  operator_act_stack_up

  operator_sign_via "$AGENT_SOCK" "piggy-test: text" --namespace piggy-escalation-v1 --slot 9a
  [[ $status -eq 1 ]] || operator_act_fail "a policy refusal should exit 1"
  [[ -z $output ]] || operator_act_fail "a refusal wrote to stdout"
  [[ $stderr == *"refused-policy"* && $stderr == *"slot 9A"* ]] ||
    operator_act_fail "stderr does not name refused-policy and the slot"

  operator_sign_via "$AGENT_SOCK" "piggy-test: text" --namespace git
  [[ $status -eq 1 && -z $output ]] || operator_act_fail "namespace git should be refused"
  [[ $stderr == *"not an operator-act namespace"* ]] ||
    operator_act_fail "stderr does not explain the namespace"
  _assert_no_prompt "a CLI refusal"
}

# An agent that predates the extension answers with a failure, which the CLI
# tells apart from a refusal (RFC 0012 §2.2): exit 3, not 1.
function agent_without_the_extension_is_not_a_refusal { # @test
  command -v ssh-agent >/dev/null || skip "ssh-agent not on PATH"
  ssh-agent -D -a "$WORKDIR/stock.sock" >/dev/null 2>&1 3>&- &
  AGENT_PID=$!
  _wait_for_socket "$WORKDIR/stock.sock" /dev/null
  ssh-keygen -t ecdsa -N '' -q -C "PIV_slot_9C FFFFFFFF" -f "$WORKDIR/soft" </dev/null
  SSH_AUTH_SOCK="$WORKDIR/stock.sock" ssh-add -q "$WORKDIR/soft" 2>/dev/null

  operator_sign_via "$WORKDIR/stock.sock" "piggy-test: text" --namespace piggy-escalation-v1
  [[ $status -eq 3 ]] || operator_act_fail "expected exit 3 (not served), got $status"
  [[ -z $output ]] || operator_act_fail "an unserved act wrote to stdout"
  [[ $stderr == *"did not serve operator-act@piggy"* ]] ||
    operator_act_fail "stderr does not say the agent does not serve the extension"
}
