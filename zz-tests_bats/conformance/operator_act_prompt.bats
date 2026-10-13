#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.6 — the prompt that takes the PIN carries the act: the display
# class in PIGGY_ASKPASS_KIND, and in PIGGY_ASKPASS_CONTEXT the card, the
# slot, the namespace and the text, verbatim. A routine PIN prompt carries no
# kind. The test askpass writes what it was given to the agent's log, which
# is where these cases read it. How a real askpass renders each class is
# piggy_askpass.bats.
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

function prompt_kind_is_the_namespaces_display_class { # @test
  operator_act_stack_up
  local pair namespace class
  for pair in piggy-quote-v1=quote piggy-escalation-v1=escalation piggy-certificate-v1=certificate; do
    namespace=${pair%%=*}
    class=${pair##*=}
    : >"$AGENT_LOG"
    operator_sign_via "$AGENT_SOCK" "piggy-test: act under $namespace" --namespace "$namespace"
    [[ $status -eq 0 ]] || operator_act_fail "operator-sign under $namespace failed"
    grep -qx "\[piggy-test-askpass\] operator act kind: $class" "$AGENT_LOG" ||
      operator_act_fail "the prompt for $namespace did not carry kind $class"
    [[ $(grep -c 'operator act kind:' "$AGENT_LOG") -eq 1 ]] ||
      operator_act_fail "expected exactly one classed prompt for $namespace"
  done
}

function prompt_shows_card_slot_namespace_and_the_text_verbatim { # @test
  operator_act_stack_up
  local guid8
  guid8=$(operator_act_public_key 9C | awk '{print $NF}')
  [[ $guid8 =~ ^[0-9A-F]{8}$ ]] || operator_act_fail "could not read the card id from the 9C comment"

  local text=$'piggy-test: grant merge to master\n\twith   spacing kept\nrequest piggy-record-digest-v1@sha256-example'
  operator_sign_via "$AGENT_SOCK" "$text" --namespace piggy-escalation-v1
  [[ $status -eq 0 ]] || operator_act_fail "operator-sign failed"

  grep -qF "PIN for card $guid8 to sign this operator act" "$AGENT_LOG" ||
    operator_act_fail "the prompt does not name the card"
  grep -qF "(context: operator act: escalation" "$AGENT_LOG" ||
    operator_act_fail "the context does not open with the display class"
  grep -qxF "card $guid8, slot 9C" "$AGENT_LOG" || operator_act_fail "the context does not name card and slot"
  grep -qxF "namespace piggy-escalation-v1" "$AGENT_LOG" ||
    operator_act_fail "the context does not name the namespace"
  local line
  while IFS= read -r line; do
    grep -qxF -- "$line" "$AGENT_LOG" ||
      operator_act_fail "the context is missing this line of the text, verbatim: '$line'"
  done <<<"$text"
}

# Once the PIN is in, the card waits for a touch and the dialog is gone: the
# agent must say so where the operator will see it, naming card and slot,
# while the card is still waiting.
function touch_wait_is_announced_with_card_and_slot { # @test
  operator_act_stack_up --touch-timeout-ms 10000
  local guid8 before
  guid8=$(operator_act_public_key 9C | awk '{print $NF}')
  before=$(operator_act_touches_needed 9C)

  PIGGY_AUTH_SOCK="$AGENT_SOCK" "$PIGGY_BIN" operator-sign \
    --namespace piggy-escalation-v1 <<<"piggy-test: announce the touch" \
    >"$WORKDIR/act.sig" 2>"$WORKDIR/act.err" 3>&- &
  local sign_pid=$! _
  for _ in $(seq 1 100); do
    (($(operator_act_touches_needed 9C) > before)) && [[ -s $NOTICES ]] && break
    sleep 0.1
  done
  # Read before the touch is granted: the notice came during the wait.
  local notice
  notice=$(cat "$NOTICES" 2>/dev/null || true)
  operator_act_touch_when_needed 9C $((before + 1)) || true
  wait "$sign_pid" || operator_act_fail "operator-sign failed after the touch"

  [[ $notice == "piggy-agent: touch your card | card $guid8, slot 9C: touch it now to sign the escalation operator act" ]] ||
    operator_act_fail "no touch notice naming card and slot during the wait; got: '$notice'"
  grep -q 'touch your card' "$AGENT_LOG" ||
    operator_act_fail "the notice is not also on the agent's stderr"
}

# The same agent, the same card, an ordinary SSH signature: no kind.
function routine_pin_prompt_carries_no_kind { # @test
  operator_act_stack_up
  operator_act_public_key 9A >"$WORKDIR/9a.pub"
  printf 'piggy-test: an ordinary file\n' >"$WORKDIR/file"

  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-keygen -Y sign -f "$WORKDIR/9a.pub" -U -n file "$WORKDIR/file"
  [[ $status -eq 0 ]] || operator_act_fail "an ordinary 9A signature failed"
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 1 ]] ||
    operator_act_fail "expected the one routine PIN prompt"
  if grep -q 'operator act kind:' "$AGENT_LOG"; then
    operator_act_fail "a routine PIN prompt carried PIGGY_ASKPASS_KIND"
  fi
}
