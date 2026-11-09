#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0013 §3.2, §3.3, §4.8: `piggy act seal` for a card act, over fibby.
# The canonical form is the operator-act text (RFC 0012), signed by the
# card's 9C key through `operator-act@piggy`; the producer normalizes the
# card's ECDSA signature to low-S, seals the act, and the sealed act passes
# `piggy act verify --seal-only` and `ssh-keygen -Y verify`. A kind the
# namespace forbids is refused before any prompt.
#
# PIN PROMPT SAFETY NET (piggy-testing(7)): the whole stack runs under the
# test askpass from lib/operator_act.bash; prompts are counted from the card
# agent's log. Stack and required env: zz-tests_bats/lib/operator_act.bash.

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

# An unsealed card root in namespace $1 (default piggy-certificate-v1), keyed
# to the card agent's 9C key.
_card_root() {
  operator_act_public_key 9C >"$WORKDIR/9c.pub"
  ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/subject"
  local card principal
  card=$("$PIGGY_BIN" act key --card "$WORKDIR/9c.pub")
  principal=$("$PIGGY_BIN" act key "$WORKDIR/subject.pub")
  cat <<EOF
---
# piggy-test: root for session 72dca00c
- kind = root
- producer = troupe:root-v1
- subject = clown:72dca00c
- subject-key = $principal
- issuer = operator
- issuer-key = $card
- right = spinclass:check
- right = spinclass:merge
- not-after = 2026-11-09T23:00:00Z
- issued-at = 2026-11-08T23:00:00Z
- assurance = piggy:hardware
- key = $card
- namespace = ${1:-piggy-certificate-v1}
- hash = sha256
! piggy-act-v1
---
EOF
}

function a_card_root_seals_through_the_card_and_verifies { # @test
  operator_act_stack_up
  _card_root >"$WORKDIR/act"

  PIGGY_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr "$PIGGY_BIN" act seal "$WORKDIR/act"
  [[ $status -eq 0 ]] || operator_act_fail "act seal failed"
  printf '%s\n' "$output" >"$WORKDIR/sealed"
  grep -q -- '^- signature = piggy-record-sig-v1@ecdsa_p256_sig-' "$WORKDIR/sealed" ||
    operator_act_fail "no P-256 signature line in the sealed act"

  run "$PIGGY_BIN" act verify --seal-only "$WORKDIR/sealed"
  [[ $status -eq 0 && $output == "valid piggy-record-digest-v1@blake2b256-"* ]] ||
    operator_act_fail "the sealed act does not verify"

  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 1 ]] ||
    operator_act_fail "want exactly one PIN prompt for one card act"

  # The detached form is what any verifier with the card's key checks.
  "$PIGGY_BIN" act detach --signature "$WORKDIR/act.sig" "$WORKDIR/sealed" >"$WORKDIR/canonical"
  assert_sshsig_verifies "$WORKDIR/act.sig" "$(cat "$WORKDIR/canonical")" piggy-certificate-v1 9C
}

function a_kind_the_namespace_forbids_raises_no_prompt { # @test
  operator_act_stack_up
  # A root under the approval namespace parses, and §4.8 forbids it.
  _card_root piggy-approval-v1 >"$WORKDIR/act"

  PIGGY_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr "$PIGGY_BIN" act seal "$WORKDIR/act"
  [[ $status -eq 1 && $stderr == *"refused (namespace-pairing)"* ]] ||
    operator_act_fail "want a namespace-pairing refusal"
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 0 ]] ||
    operator_act_fail "a forbidden act raised a PIN prompt"
}

function a_cancelled_prompt_exits_4_and_writes_nothing { # @test
  OPERATOR_ACT_AGENT_REFUSES_PROMPTS=1 operator_act_stack_up
  _card_root >"$WORKDIR/act"

  PIGGY_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr "$PIGGY_BIN" act seal "$WORKDIR/act"
  [[ $status -eq 4 && -z $output ]] ||
    operator_act_fail "want exit 4 and no sealed act after a cancelled prompt"
}
