#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.4 — only a slot the card ATTESTS as PIN always and touch always
# serves an operator act, and the policy is read from the card on every
# request. A key that cannot be attested is refused (fail closed), and so is
# an attested key with any weaker policy: 9A as `piggy card init` enrolls it
# (PIN once, touch cached), or a 9C made with a weaker PIN policy.
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

# `piggy card add-key ARGS` on the running card (which is --auto-touch here).
_add_key() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_TEST_FIB_PIN="$OPERATOR_ACT_PIN" \
    PIGGY_TEST_FIB_MGMT_KEY=default \
    setsid -w "$PIGGY_BIN" card add-key "$@" <<<"y" >/dev/null 2>"$WORKDIR/add-key.err" || {
    cat "$WORKDIR/add-key.err" >&2
    operator_act_fail "card add-key $* failed"
  }
}

_assert_refused_policy() {
  local slot="$1" detail="$2"
  operator_act_probe "$AGENT_SOCK" --slot "$slot"
  assert_probe_status 2 "refused-policy for slot $slot"
  grep -q "^detail .*$detail" <<<"$output" ||
    operator_act_fail "the refusal detail does not say: $detail"
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 0 ]] ||
    operator_act_fail "a policy refusal raised a PIN prompt"
}

function attested_pin_always_touch_always_slot_serves_the_act { # @test
  operator_act_stack_up
  operator_act_probe "$AGENT_SOCK" --slot 9C
  assert_probe_status 0 signed
}

# A seeded key was not generated on the card: ATTEST fails and the slot is
# refused, whatever anyone configured.
function key_the_card_cannot_attest_is_refused { # @test
  operator_act_stack_up
  _assert_refused_policy 9A "slot 9A: the card did not attest the key"
}

# 9A as `piggy card add-key 9a` (and `card init`) enrolls it: attested, but
# PIN once and touch cached.
function attested_pin_once_touch_cached_slot_is_refused { # @test
  spawn_operator_card
  _add_key 9a --replace
  spawn_card_agent
  _assert_refused_policy 9A "slot 9A: PIN once, touch cached"
}

function attested_9c_with_a_weaker_pin_policy_is_refused { # @test
  spawn_operator_card
  _add_key 9c --replace --pin-policy once
  spawn_card_agent
  _assert_refused_policy 9C "slot 9C: PIN once, touch always"
}

# The policy is not remembered: the same agent serves 9C, the key is replaced
# by a weaker one behind its back, and the next request is judged afresh.
function policy_is_read_from_the_card_at_request_time { # @test
  operator_act_stack_up
  operator_act_probe "$AGENT_SOCK" --slot 9C
  assert_probe_status 0 signed

  _add_key 9c --replace --touch-policy never
  # The agent still lists the OLD 9C key until its next reconcile; either
  # answer is a refusal, and neither is a signature.
  operator_act_probe "$AGENT_SOCK" --slot 9C
  if grep -qx 'status 0' <<<"$output"; then
    operator_act_fail "the agent signed with a slot whose key no longer attests PIN always, touch always"
  fi
  grep -qx 'sshsig-hex ' <<<"$output" || operator_act_fail "a refusal carried a signature"
}
