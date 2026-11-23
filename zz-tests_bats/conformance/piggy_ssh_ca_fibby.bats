#! /usr/bin/env bats
#
# The SSH certificate authority, slot 83 (lane 1 of the delegation sprint,
# operator ruling 2026-11-22), over fibby and a card `piggy agent`:
# `ssh-keygen -U -s` signs an OpenSSH user certificate with the key in slot
# 83 (generated on the card, PIN always and touch always), behind a PIN
# dialog of kind ssh-certificate whose context says what is certified; the
# certificate verifies as a real CA signature (an sshsig by the certified key
# checked against a cert-authority line). The PIN of slot 83 is asked every
# time, while an ordinary slot's (9A) is still cached. Refused before any
# prompt: a lifetime over 24 hours, one with no end, a host certificate, one
# with no principal; slot 82 refuses an OpenSSH certificate; slot 83 refuses
# an sshsig and anything else that is not a certificate.
#
# Required env (supplied by `just test-bats-conformance-ssh-ca-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-ssh-ca-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN="$OPERATOR_ACT_PIN"
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK PIGGY_TEST_FIB_MGMT_KEY

  WORKDIR="$(mktemp -d -t sshca.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_SOCK="$WORKDIR/a.sock"
  AGENT_LOG="$WORKDIR/agent.log"
  FRONT_SOCK="$WORKDIR/front.sock"
  FRONT_LOG="$WORKDIR/front.log"
  FIBBY_PID=
  AGENT_PID=
  FRONT_PID=

  NOTICES="$WORKDIR/notices"
  cat >"$WORKDIR/notifier" <<NOTIFIER_EOF
#!/usr/bin/env bash
printf '%s | %s\n' "\$1" "\$2" >>"$NOTICES"
NOTIFIER_EOF
  chmod +x "$WORKDIR/notifier"
  export PIGGY_ASKPASS_NOTIFIER="$WORKDIR/notifier"

  spawn_operator_card --auto-touch
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"
  for slot in 82 83; do
    "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a eccp256 -i always -t always generate "$slot" >/dev/null || {
      echo "generate $slot failed" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  done
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L >"$WORKDIR/all.pub"
  grep " PIV_slot_83" "$WORKDIR/all.pub" >"$WORKDIR/ca83.pub"
  grep " PIV_slot_82" "$WORKDIR/all.pub" >"$WORKDIR/ca82.pub"
  grep " PIV_slot_9A" "$WORKDIR/all.pub" >"$WORKDIR/k9a.pub"
  [[ -s $WORKDIR/ca83.pub && -s $WORKDIR/ca82.pub && -s $WORKDIR/k9a.pub ]] || {
    echo "the agent does not offer slots 82, 83 and 9A:" >&2; cat "$WORKDIR/all.pub" >&2; return 1; }
  ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/user" -C "ssh-ca-test"
}

teardown() {
  operator_act_teardown
}

_show() {
  printf 'status: %s\noutput: %s\nstderr: %s\n' "${status:-}" "${output:-}" "${stderr:-}" >&2
  operator_act_dump_logs
}

# `ssh-keygen -U -s CA ARGS... user.pub` through the agent.
_certify() {
  local ca="$1"
  shift
  run --separate-stderr env SSH_AUTH_SOCK="$AGENT_SOCK" ssh-keygen -q -U -s "$ca" "$@" "$WORKDIR/user.pub"
}

_prompts() {
  grep -c '^\[piggy-test-askpass\] supplying' "$AGENT_LOG" || true
}

function slot_83_signs_a_certificate_behind_a_dialog_that_says_what_it_certifies { # @test
  _certify "$WORKDIR/ca83.pub" -I grant-1 -n deploy-site,restart-service -V +2h \
    -O force-command=/usr/bin/true -O no-pty
  [[ $status -eq 0 ]] || { echo "ssh-keygen failed" >&2; _show; return 1; }
  [[ -s $WORKDIR/user-cert.pub ]]

  # One prompt, of the certificate's kind, whose context is the summary.
  [[ $(_prompts) -eq 1 ]] || { echo "want one prompt, got $(_prompts)" >&2; _show; return 1; }
  grep -q '^\[piggy-test-askpass\] operator act kind: ssh-certificate' "$AGENT_LOG" || {
    echo "the prompt was not of kind ssh-certificate" >&2; _show; return 1; }
  for want in "OpenSSH user certificate" "Key id: grant-1" "Principal: deploy-site" "Principal: restart-service" \
    "Certified key: SHA256:" "Signed by CA: SHA256:" 'Critical option: force-command:' '"/usr/bin/true"' "slot 83"; do
    grep -qF -- "$want" "$AGENT_LOG" || { echo "the dialog context lacks: $want" >&2; _show; return 1; }
  done

  # The fingerprints in the dialog are the real ones.
  local cert_fp ca_fp
  cert_fp="$(ssh-keygen -lf "$WORKDIR/user.pub" | cut -d' ' -f2)"
  ca_fp="$(ssh-keygen -lf "$WORKDIR/ca83.pub" | cut -d' ' -f2)"
  grep -qF "Certified key: $cert_fp" "$AGENT_LOG" || { echo "wrong certified-key fingerprint" >&2; _show; return 1; }
  grep -qF "Signed by CA: $ca_fp" "$AGENT_LOG" || { echo "wrong CA fingerprint" >&2; _show; return 1; }

  # A real CA signature: an sshsig by the certified key, verified the way
  # `ssh-keygen -Y verify` does against a cert-authority line.
  printf 'nonce action args\n' >"$WORKDIR/msg"
  ssh-keygen -q -Y sign -f "$WORKDIR/user-cert.pub" -n hogtie-v1 "$WORKDIR/msg" 2>/dev/null
  printf '* cert-authority,namespaces="hogtie-v1" %s\n' "$(cut -d' ' -f1,2 "$WORKDIR/ca83.pub")" >"$WORKDIR/allowed"
  run ssh-keygen -Y verify -f "$WORKDIR/allowed" -I deploy-site -n hogtie-v1 -s "$WORKDIR/msg.sig" <"$WORKDIR/msg"
  [[ $status -eq 0 && $output == *"Good \"hogtie-v1\" signature for deploy-site"* ]] || {
    echo "the certificate does not verify against the CA line: $output" >&2; return 1; }
  run ssh-keygen -Y verify -f "$WORKDIR/allowed" -I not-a-principal -n hogtie-v1 -s "$WORKDIR/msg.sig" <"$WORKDIR/msg"
  [[ $status -ne 0 ]]
}

function slot_83_asks_for_the_pin_every_time_and_9a_still_caches_its { # @test
  rm -f "$WORKDIR/user-cert.pub"
  _certify "$WORKDIR/ca83.pub" -I one -n a -V +1h
  [[ $status -eq 0 ]] || { _show; return 1; }
  rm -f "$WORKDIR/user-cert.pub"
  _certify "$WORKDIR/ca83.pub" -I two -n a -V +1h
  [[ $status -eq 0 ]] || { _show; return 1; }
  [[ $(_prompts) -eq 2 ]] || { echo "slot 83: want 2 prompts for 2 certificates, got $(_prompts)" >&2; _show; return 1; }

  # An ordinary slot is unchanged: its PIN is asked once and cached.
  printf 'one\n' >"$WORKDIR/m1"
  printf 'two\n' >"$WORKDIR/m2"
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-keygen -q -Y sign -f "$WORKDIR/k9a.pub" -n file "$WORKDIR/m1" 2>/dev/null
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-keygen -q -Y sign -f "$WORKDIR/k9a.pub" -n file "$WORKDIR/m2" 2>/dev/null
  [[ -s $WORKDIR/m1.sig && -s $WORKDIR/m2.sig ]] || { echo "9A did not sign" >&2; _show; return 1; }
  [[ $(_prompts) -eq 3 ]] || { echo "9A: want one more prompt in total (3), got $(_prompts)" >&2; _show; return 1; }

  # And slot 83 still asks with the card's PIN in the cache: the cache is
  # never read for it, not just never written.
  rm -f "$WORKDIR/user-cert.pub"
  _certify "$WORKDIR/ca83.pub" -I three -n a -V +1h
  [[ $status -eq 0 ]] || { _show; return 1; }
  [[ $(_prompts) -eq 4 ]] || { echo "slot 83 read the cached PIN: want 4 prompts in total, got $(_prompts)" >&2; _show; return 1; }
}

function a_certificate_naming_another_ca_or_starting_years_ahead_is_refused_before_any_prompt { # @test
  # `-V 20300101:20300102` is a one-day certificate, valid only years ahead.
  _certify "$WORKDIR/ca83.pub" -I later -n a -V 20300101:20300102
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "a certificate valid only from 2030 was signed" >&2; _show; return 1; }
  # (A certificate naming a CA other than the key asked to sign it takes a
  # hand-made sign request: the unit tests', refuse_certificate_naming_another_ca.)
  [[ $(_prompts) -eq 0 ]] || { echo "a refused certificate raised $(_prompts) prompt(s)" >&2; _show; return 1; }
}

function a_certificate_the_ca_may_not_sign_is_refused_before_any_prompt { # @test
  local case_name
  # 25 hours is over the 24-hour limit plus ssh-keygen's back-dating.
  _certify "$WORKDIR/ca83.pub" -I long -n a -V +25h
  [[ $status -ne 0 ]] || { echo "a 25-hour certificate was signed" >&2; _show; return 1; }
  [[ ! -e $WORKDIR/user-cert.pub ]]
  # No end at all.
  _certify "$WORKDIR/ca83.pub" -I forever -n a -V always:forever
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "an endless certificate was signed" >&2; _show; return 1; }
  # A host certificate.
  _certify "$WORKDIR/ca83.pub" -h -I host -n example.org -V +1h
  [[ $status -ne 0 && ! -e $WORKDIR/user-host-cert.pub && ! -e $WORKDIR/user-cert.pub ]] || {
    echo "a host certificate was signed" >&2; _show; return 1; }
  # No principal: valid for every user.
  _certify "$WORKDIR/ca83.pub" -I nobody -V +1h
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "a certificate with no principal was signed" >&2; _show; return 1; }
  # None of it reached a PIN prompt.
  [[ $(_prompts) -eq 0 ]] || { echo "a refused certificate raised $(_prompts) prompt(s)" >&2; _show; return 1; }
  case_name=done
  [[ $case_name == done ]]
}

function the_longest_lifetime_ssh_keygen_can_ask_for_is_signed { # @test
  # 24 hours is the limit itself; ssh-keygen back-dates by a minute.
  _certify "$WORKDIR/ca83.pub" -I day -n a -V +24h
  [[ $status -eq 0 ]] || { echo "a 24-hour certificate was refused" >&2; _show; return 1; }
}

function slot_82_refuses_an_openssh_certificate_and_slot_83_refuses_everything_else { # @test
  _certify "$WORKDIR/ca82.pub" -I wrong-ca -n a -V +1h
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "slot 82 signed an OpenSSH certificate" >&2; _show; return 1; }
  # Slot 83 signs no sshsig (any namespace) and no other bytes.
  printf 'hello\n' >"$WORKDIR/m"
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-keygen -q -Y sign -f "$WORKDIR/ca83.pub" -n file "$WORKDIR/m"
  [[ $status -ne 0 && ! -e $WORKDIR/m.sig ]] || { echo "slot 83 signed an sshsig" >&2; return 1; }
  # Piggy#405: slot 82 signs no other bytes either, an sshsig included.
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-keygen -q -Y sign -f "$WORKDIR/ca82.pub" -n file "$WORKDIR/m"
  [[ $status -ne 0 && ! -e $WORKDIR/m.sig ]] || { echo "slot 82 signed an sshsig" >&2; return 1; }
  # Nor does a plain ssh-agent-protocol sign of non-certificate data (what a
  # login challenge is) go through: ssh-keygen -Y check is the sshsig above;
  # the agent's refusal of the rest is the unit tests' (gate_data_for_slot).
  [[ $(_prompts) -eq 0 ]] || { echo "a refusal raised $(_prompts) prompt(s)" >&2; _show; return 1; }
}

# The Fable review of c7dd0561, finding 1: a CA slot signs only a key whose
# ATTESTED policy is PIN always and touch always, and raises its dialog
# whatever the agent's own idea of the key's PIN policy. A key generated with
# a laxer policy (the card's default is PIN once, touch never) signs nothing
# and raises no prompt: before the fix, `never` signed with no dialog at all.
function a_ca_key_not_attested_pin_always_and_touch_always_signs_nothing { # @test
  local slot policy pin touch
  for slot in 83 82; do
    for policy in "never never" "once never" "always never" "once always" "never always"; do
      read -r pin touch <<<"$policy"
      "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a eccp256 -i "$pin" -t "$touch" generate "$slot" >/dev/null || {
        echo "generate $slot ($policy) failed" >&2; return 1; }
      kill "$AGENT_PID" 2>/dev/null || true
      wait "$AGENT_PID" 2>/dev/null || true
      rm -f "$AGENT_SOCK"
      spawn_card_agent
      SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L | grep " PIV_slot_$slot" >"$WORKDIR/weak.pub"
      [[ -s $WORKDIR/weak.pub ]] || { echo "the agent does not offer the new slot-$slot key" >&2; return 1; }
      rm -f "$WORKDIR/user-cert.pub" "$WORKDIR/m.sig"
      if [[ $slot == 83 ]]; then
        _certify "$WORKDIR/weak.pub" -I weak -n a -V +1h
        [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || {
          echo "slot 83 ($policy) signed a certificate" >&2; _show; return 1; }
      else
        printf 'hello\n' >"$WORKDIR/m"
        SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-keygen -q -Y sign -f "$WORKDIR/weak.pub" -n file "$WORKDIR/m"
        [[ $status -ne 0 && ! -e $WORKDIR/m.sig ]] || {
          echo "slot 82 ($policy) signed" >&2; _show; return 1; }
      fi
      [[ $(_prompts) -eq 0 ]] || { echo "slot $slot ($policy): a refusal raised $(_prompts) prompt(s)" >&2; _show; return 1; }
    done
  done
}

# Finding 5: the certificate's content is shown only by an askpass that
# understands the kind. A generic askpass (a PIN and nothing else) is not
# believed: nothing is signed with its PIN.
function a_generic_askpass_cannot_stand_in_for_the_certificate_dialog { # @test
  printf '#!/bin/sh\nprintf "%%s\\n" "$PIGGY_TEST_FIB_PIN"\n' >"$WORKDIR/generic-askpass.sh"
  chmod +x "$WORKDIR/generic-askpass.sh"
  kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  rm -f "$AGENT_SOCK"
  SSH_ASKPASS="$WORKDIR/generic-askpass.sh" spawn_card_agent
  _certify "$WORKDIR/ca83.pub" -I generic -n a -V +1h
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || {
    echo "a certificate was signed behind a generic askpass" >&2; _show; return 1; }
  grep -q "did not acknowledge" "$AGENT_LOG" || { echo "the agent did not say why" >&2; _show; return 1; }
}

# The second Fable review: the attestation check and the signature are
# different card sessions, with the dialog between them. A card whose slot-83
# key is replaced (a new key, same PIN always / touch always policy) while the
# dialog is open must not sign: the check is repeated in the signing session
# against the key the request named. The hook runs inside the open prompt.
function a_slot_key_replaced_while_the_dialog_is_open_signs_nothing { # @test
  cat >"$WORKDIR/swap-hook.sh" <<HOOK
#!/usr/bin/env bash
"$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a eccp256 -i always -t always generate 83 >/dev/null
HOOK
  chmod +x "$WORKDIR/swap-hook.sh"
  kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  rm -f "$AGENT_SOCK"
  PIGGY_TEST_ASKPASS_BEFORE_PIN="$WORKDIR/swap-hook.sh" spawn_card_agent
  _certify "$WORKDIR/ca83.pub" -I swapped -n a -V +1h
  grep -q "running PIGGY_TEST_ASKPASS_BEFORE_PIN" "$AGENT_LOG" || {
    echo "the hook did not run inside the prompt" >&2; _show; return 1; }
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || {
    echo "a certificate was signed after the card's key was replaced" >&2; _show; return 1; }
  grep -q "attestation is for a different key" "$AGENT_LOG" || {
    echo "the agent did not refuse on the key comparison" >&2; _show; return 1; }
}

# A proxy-only front over the card agent (a forwarded card agent, FDR 0001):
# the front has no card, no PIN and its askpass would answer if asked, so any
# prompt there would be counted in its own log; the checks and the dialog are
# the card agent's, on its host.
_certify_via_front() {
  local ca="$1"
  shift
  run --separate-stderr env SSH_AUTH_SOCK="$FRONT_SOCK" ssh-keygen -q -U -s "$ca" "$@" "$WORKDIR/user.pub"
}

function through_a_proxy_only_front_the_certificate_is_signed_behind_the_card_agents_dialog { # @test
  spawn_proxy_front
  # The front lists the card agent's keys, slot 83's included.
  SSH_AUTH_SOCK="$FRONT_SOCK" ssh-add -L | grep -q " PIV_slot_83" || {
    echo "the front does not list slot 83" >&2; cat "$FRONT_LOG" >&2; return 1; }
  _certify_via_front "$WORKDIR/ca83.pub" -I fwd-1 -n deploy-site -V +2h -O force-command=/usr/bin/true
  [[ $status -eq 0 ]] || { echo "ssh-keygen through the front failed" >&2; _show; cat "$FRONT_LOG" >&2; return 1; }
  [[ -s $WORKDIR/user-cert.pub ]]
  # The dialog was the card agent's, of the certificate's kind, with the
  # context; the front raised no prompt of its own.
  grep -q '^\[piggy-test-askpass\] operator act kind: ssh-certificate' "$AGENT_LOG" || {
    echo "the card agent showed no ssh-certificate dialog" >&2; _show; return 1; }
  grep -qF "Key id: fwd-1" "$AGENT_LOG" || { echo "the dialog context lacks the key id" >&2; _show; return 1; }
  [[ $(grep -c '^\[piggy-test-askpass\]' "$FRONT_LOG" || true) -eq 0 ]] || {
    echo "the proxy-only front raised a prompt" >&2; cat "$FRONT_LOG" >&2; return 1; }
  # And it is a real CA signature.
  printf 'nonce action\n' >"$WORKDIR/msg"
  ssh-keygen -q -Y sign -f "$WORKDIR/user-cert.pub" -n hogtie-v1 "$WORKDIR/msg" 2>/dev/null
  printf '* cert-authority,namespaces="hogtie-v1" %s\n' "$(cut -d' ' -f1,2 "$WORKDIR/ca83.pub")" >"$WORKDIR/allowed"
  run ssh-keygen -Y verify -f "$WORKDIR/allowed" -I deploy-site -n hogtie-v1 -s "$WORKDIR/msg.sig" <"$WORKDIR/msg"
  [[ $status -eq 0 ]] || { echo "the forwarded certificate does not verify: $output" >&2; return 1; }
}

function through_a_proxy_only_front_the_card_agents_refusals_hold_and_no_prompt_is_raised { # @test
  spawn_proxy_front
  _certify_via_front "$WORKDIR/ca83.pub" -I long -n a -V +25h
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "a 25-hour certificate was signed through the front" >&2; _show; return 1; }
  _certify_via_front "$WORKDIR/ca83.pub" -h -I host -n example.org -V +1h
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "a host certificate was signed through the front" >&2; _show; return 1; }
  _certify_via_front "$WORKDIR/ca82.pub" -I wrong-ca -n a -V +1h
  [[ $status -ne 0 && ! -e $WORKDIR/user-cert.pub ]] || { echo "slot 82 signed an OpenSSH certificate through the front" >&2; _show; return 1; }
  printf 'hello\n' >"$WORKDIR/m"
  SSH_AUTH_SOCK="$FRONT_SOCK" run ssh-keygen -q -Y sign -f "$WORKDIR/ca83.pub" -n file "$WORKDIR/m"
  [[ $status -ne 0 && ! -e $WORKDIR/m.sig ]] || { echo "slot 83 signed an sshsig through the front" >&2; return 1; }
  [[ $(_prompts) -eq 0 ]] || { echo "a refusal raised $(_prompts) prompt(s) at the card agent" >&2; _show; return 1; }
  [[ $(grep -c '^\[piggy-test-askpass\]' "$FRONT_LOG" || true) -eq 0 ]] || { echo "the front raised a prompt" >&2; return 1; }
}

function a_plain_9a_signature_through_a_proxy_only_front_works_with_the_pin_asked_on_the_card_side { # @test
  spawn_proxy_front
  printf 'one\n' >"$WORKDIR/m1"
  SSH_AUTH_SOCK="$FRONT_SOCK" ssh-keygen -q -Y sign -f "$WORKDIR/k9a.pub" -n file "$WORKDIR/m1" 2>"$WORKDIR/sign.err"
  [[ -s $WORKDIR/m1.sig ]] || { echo "9A did not sign through the front:" >&2; cat "$WORKDIR/sign.err" >&2; _show; cat "$FRONT_LOG" >&2; return 1; }
  [[ $(_prompts) -eq 1 ]] || { echo "want the one PIN prompt at the card agent, got $(_prompts)" >&2; _show; return 1; }
  [[ $(grep -c '^\[piggy-test-askpass\]' "$FRONT_LOG" || true) -eq 0 ]] || { echo "the front prompted" >&2; return 1; }
}
