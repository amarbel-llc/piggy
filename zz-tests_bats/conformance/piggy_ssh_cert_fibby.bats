#! /usr/bin/env bats
#
# EXPLORATORY (delegation proof, no code under test changes): can
# `ssh-keygen -U -s` sign an OpenSSH user certificate with a CA key held in
# fibby's retired slot 83 through a card `piggy agent`, as the code stands?
# A P-256 key is generated on the card in slot 83 (PIN always, touch always,
# piggy#399), the agent offers it as PIV_slot_83, and ssh-keygen signs a
# forced-command user certificate for a key made on this host. The lane
# records what the agent's PIN prompt shows (the test askpass logs the
# prompt and PIGGY_ASKPASS_CONTEXT) and what `ssh-keygen -L` says about the
# certificate; it asserts only what is true today.
#
# Required env (supplied by `just explore-ssh-cert-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just explore-ssh-cert-fibby"
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

  WORKDIR="$(mktemp -d -t sshcert.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_SOCK="$WORKDIR/a.sock"
  AGENT_LOG="$WORKDIR/agent.log"
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
}

teardown() {
  operator_act_teardown
}

_show() {
  printf 'status: %s\noutput: %s\nstderr: %s\n' "${status:-}" "${output:-}" "${stderr:-}" >&2
  operator_act_dump_logs
}

# Slot 83 holds a card-generated P-256 key, PIN always, touch always.
_generate_83() {
  "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a eccp256 -i always -t always generate 83 >/dev/null || {
    echo "generate 83 failed" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
}

# The delegation proof's three certificates for a key made elsewhere
# (PROOF_USER_PUB, one public line): A (2h, principal coordinator) and B (40m,
# signed last, to show expiry) as the host should accept, C (principal
# intruder) as it should refuse. Public material only goes to PROOF_DIR: the
# CA line, the three certificates, their `ssh-keygen -L` and the prompts.
function the_delegation_proof_signs_three_certificates_for_a_given_key { # @test
  [[ -n ${PROOF_USER_PUB:-} && -n ${PROOF_DIR:-} ]] || skip "PROOF_USER_PUB / PROOF_DIR unset"
  _generate_83
  spawn_card_agent
  mkdir -p "$PROOF_DIR"
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L | grep " PIV_slot_83" >"$PROOF_DIR/ca83.pub"
  [[ $(wc -l <"$PROOF_DIR/ca83.pub") -eq 1 ]] || { echo "want one 83 key" >&2; return 1; }
  printf '%s\n' "$PROOF_USER_PUB" >"$PROOF_DIR/coordinator.pub"

  local id principal validity
  for spec in "A coordinator +2h" "C intruder +2h" "B coordinator +40m"; do
    read -r id principal validity <<<"$spec"
    SSH_AUTH_SOCK="$AGENT_SOCK" ssh-keygen -q -U -s "$PROOF_DIR/ca83.pub" \
      -I "coordinator-proof-$id" -n "$principal" -V "$validity" \
      -O no-agent-forwarding -O no-port-forwarding -O no-x11-forwarding -O no-pty \
      "$PROOF_DIR/coordinator.pub" || { echo "signing $id failed" >&2; _show; return 1; }
    mv "$PROOF_DIR/coordinator-cert.pub" "$PROOF_DIR/cert-$id.pub"
    ssh-keygen -L -f "$PROOF_DIR/cert-$id.pub" >"$PROOF_DIR/cert-$id.txt"
  done
  grep -E 'supplying|operator act kind' "$AGENT_LOG" >"$PROOF_DIR/prompts.txt" || true
  # Recorded, not asserted: the first run showed ONE PIN prompt for three
  # signatures on a PIN-always key (the agent's PIN cache re-verifies).
  grep -c supplying "$PROOF_DIR/prompts.txt" >"$PROOF_DIR/prompt-count.txt" || true
}

function slot_83_signs_a_forced_command_user_certificate_through_the_agent { # @test
  _generate_83
  spawn_card_agent

  # The CA public key as the agent offers it.
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L >"$WORKDIR/all.pub"
  grep " PIV_slot_83" "$WORKDIR/all.pub" >"$WORKDIR/ca83.pub" || {
    echo "the agent does not offer slot 83:" >&2; cat "$WORKDIR/all.pub" >&2; return 1; }
  [[ $(wc -l <"$WORKDIR/ca83.pub") -eq 1 ]] || { echo "want one 83 key" >&2; return 1; }

  # The user key, made here, never sent anywhere.
  ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/user" -C "proof-user"

  # The signature, as the operator would run it.
  run --separate-stderr env SSH_AUTH_SOCK="$AGENT_SOCK" ssh-keygen -U -s "$WORKDIR/ca83.pub" \
    -I "proof-1" -n "proofuser" -V +1h \
    -O "force-command=/usr/bin/true" -O no-agent-forwarding -O no-port-forwarding \
    -O no-x11-forwarding -O no-pty \
    "$WORKDIR/user.pub"
  # What was seen goes to PROOF_OUT (a passing lane's output is swallowed).
  local proof="${PROOF_OUT:-$WORKDIR/proof.txt}"
  {
    echo "--- ssh-keygen -s: status=$status"
    echo "--- ssh-keygen -s stdout: $output"
    echo "--- ssh-keygen -s stderr: $stderr"
    echo "--- ssh-keygen -L:"
    ssh-keygen -L -f "$WORKDIR/user-cert.pub"
    echo "--- the agent's prompt as the askpass saw it:"
    grep -E 'supplying|operator act kind|touch|TOUCH' "$AGENT_LOG" || true
    echo "--- touch notices:"
    cat "$NOTICES" 2>/dev/null || true
    echo "--- fibby touch asks on 83:"
    grep -c "TOUCH needed 83" "$FIBBY_LOG" || true
    echo "--- the agent log:"
    cat "$AGENT_LOG"
  } >"$proof" 2>&1
  [[ $status -eq 0 ]] || { _show; return 1; }

  ssh-keygen -L -f "$WORKDIR/user-cert.pub" | grep -q 'Signing CA: ECDSA' || {
    echo "the certificate is not signed by an ECDSA CA" >&2; return 1; }
  ssh-keygen -L -f "$WORKDIR/user-cert.pub" | grep -q 'force-command' || {
    echo "no force-command on the certificate" >&2; return 1; }
}
