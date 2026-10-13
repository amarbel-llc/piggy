#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.7 — an operator act yields an sshsig that verifies under
# `ssh-keygen -Y verify` with the slot key and the namespace, the hash is the
# agent's own over the text, and the card's touch gates it (§2.6: a touch
# timeout is `cancelled`). `piggy-quote-v1` is signed here as a namespace
# only: a real quote names a ledger stanza nothing can form yet (RFC 0012,
# "Quotes never introduce words"), and that is the verifier's check, not the
# agent's.
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

TEXT="piggy-test: grant merge to master
request piggy-record-digest-v1@sha256-example"

_sign_and_verify() {
  local namespace="$1"
  shift
  operator_sign_via "$AGENT_SOCK" "$TEXT" --namespace "$namespace" "$@"
  [[ $status -eq 0 ]] || operator_act_fail "operator-sign under $namespace failed"
  [[ $output == "-----BEGIN SSH SIGNATURE-----"* ]] ||
    operator_act_fail "stdout is not an armored sshsig"
  printf '%s\n' "$output" >"$WORKDIR/act.sig"
  assert_sshsig_verifies "$WORKDIR/act.sig" "$TEXT" "$namespace" 9C
}

function each_operator_act_namespace_signs_and_verifies { # @test
  operator_act_stack_up
  local namespace
  for namespace in piggy-escalation-v1 piggy-certificate-v1 piggy-quote-v1; do
    _sign_and_verify "$namespace"
  done
}

function signature_is_bound_to_its_namespace_and_its_text { # @test
  operator_act_stack_up
  _sign_and_verify piggy-escalation-v1

  # The same signature is not a certificate, and not a grant of other words.
  if assert_sshsig_verifies "$WORKDIR/act.sig" "$TEXT" piggy-certificate-v1 9C 2>/dev/null; then
    operator_act_fail "an escalation signature verified as a certificate"
  fi
  if assert_sshsig_verifies "$WORKDIR/act.sig" "$TEXT and more" piggy-escalation-v1 9C 2>/dev/null; then
    operator_act_fail "the signature verified over a different text"
  fi
}

function sha256_is_honoured_when_asked_for { # @test
  operator_act_stack_up
  _sign_and_verify piggy-escalation-v1 --hash sha256
}

# The PIN is asked for every act, whatever the agent has cached (§2.6): two
# acts, two prompts.
function every_act_prompts_for_the_pin { # @test
  operator_act_stack_up
  _sign_and_verify piggy-escalation-v1
  _sign_and_verify piggy-escalation-v1
  local prompts
  prompts=$(operator_act_prompt_count "$AGENT_LOG")
  [[ $prompts -eq 2 ]] || operator_act_fail "expected 2 PIN prompts for 2 acts, saw $prompts"
}

# Touch is real: the act waits for it, and the touch lets exactly it through.
function act_completes_when_the_card_is_touched { # @test
  operator_act_stack_up --touch-timeout-ms 10000
  local before
  before=$(operator_act_touches_needed 9C)

  PIGGY_AUTH_SOCK="$AGENT_SOCK" "$PIGGY_BIN" operator-sign \
    --namespace piggy-escalation-v1 <<<"$TEXT" >"$WORKDIR/act.sig" 2>"$WORKDIR/act.err" 3>&- &
  local sign_pid=$!
  operator_act_touch_when_needed 9C $((before + 1)) || {
    kill "$sign_pid" 2>/dev/null || true
    operator_act_fail "the act never reached the touch wait"
  }
  wait "$sign_pid" || {
    cat "$WORKDIR/act.err" >&2 || true
    operator_act_fail "operator-sign failed after the touch"
  }
  assert_sshsig_verifies "$WORKDIR/act.sig" "$TEXT" piggy-escalation-v1 9C
}

function act_without_a_touch_is_cancelled { # @test
  operator_act_stack_up --touch-timeout-ms 400
  operator_sign_via "$AGENT_SOCK" "$TEXT" --namespace piggy-escalation-v1
  [[ $status -eq 4 ]] || operator_act_fail "expected exit 4 (not signed this time; retryable)"
  [[ -z $output ]] || operator_act_fail "a cancelled act wrote a signature"
  [[ $stderr == *"cancelled"* ]] || operator_act_fail "stderr does not say cancelled"
  grep -q 'TOUCH timeout 9C' "$FIBBY_LOG" || operator_act_fail "fibby did not time the touch out"
}

# What `ssh-keygen -Y sign` sends is an ordinary sign request; the agent
# refuses one shaped like an operator act, so `operator-act@piggy` and its
# prompt are the only way to such a signature.
function ordinary_sign_request_cannot_mint_an_operator_act { # @test
  operator_act_stack_up
  operator_act_public_key 9C >"$WORKDIR/9c.pub"
  printf '%s\n' "$TEXT" >"$WORKDIR/text"

  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-keygen -Y sign -f "$WORKDIR/9c.pub" -U \
    -n piggy-escalation-v1 "$WORKDIR/text"
  [[ $status -ne 0 ]] || operator_act_fail "ssh-keygen -Y sign minted an escalation"
  [[ ! -e $WORKDIR/text.sig ]] || operator_act_fail "a signature file was written"
  grep -q 'signed only through operator-act@piggy' "$AGENT_LOG" ||
    operator_act_fail "the agent log does not explain the refusal"
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 0 ]] ||
    operator_act_fail "the refused sign request still raised a PIN prompt"
}

# The same rule for piggy's own byte-signer, which reaches the card directly
# (RFC 0012 §2.7): given the PIN and the card, it still will not sign sshsig
# data under an operator-act namespace, and still signs anything else.
function sign_bytes_cannot_mint_an_operator_act { # @test
  spawn_operator_card
  # The card runs --auto-touch, so each 9C signature it makes logs one grant.
  _card_signatures() { grep -c 'TOUCH auto-granted 9C' "$FIBBY_LOG" || true; }
  local touches
  touches=$(_card_signatures)
  # "SSHSIG", then string "piggy-escalation-v1": the prefix is what matters.
  printf 'SSHSIG\0\0\0\x13piggy-escalation-v1\0\0\0\0\0\0\0\x06sha512' >"$WORKDIR/act-data"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run --separate-stderr \
    "$PIGGY_BIN" sign-bytes --slot 9c -P "$OPERATOR_ACT_PIN" <"$WORKDIR/act-data"
  [[ $status -ne 0 ]] || operator_act_fail "sign-bytes signed operator-act data"
  [[ -z $output ]] || operator_act_fail "sign-bytes wrote a signature"
  [[ $stderr == *"signed only through operator-act@piggy"* ]] ||
    operator_act_fail "sign-bytes does not explain the refusal"
  # The refusal came before the card was asked for anything.
  [[ $(_card_signatures) -eq $touches ]] ||
    operator_act_fail "the card was asked to sign the refused data"

  printf 'SSHSIG\0\0\0\x04file\0\0\0\0\0\0\0\x06sha512' >"$WORKDIR/file-data"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" sign-bytes --slot 9c --format der \
    -P "$OPERATOR_ACT_PIN" <"$WORKDIR/file-data" >"$WORKDIR/file.sig" 2>"$WORKDIR/file.err" || {
    cat "$WORKDIR/file.err" >&2
    operator_act_fail "sign-bytes refused sshsig data under the file namespace"
  }
  [[ -s $WORKDIR/file.sig ]] || operator_act_fail "sign-bytes wrote no signature for the file namespace"
  (($(_card_signatures) == touches + 1)) ||
    operator_act_fail "the allowed signature did not reach the card"
}
