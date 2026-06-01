#! /usr/bin/env bats
#
# piggy#135 Phase 0 smoke: pivy-agent over fibby's virtual PIV card,
# no hardware. Asserts the pcsc-lite substrate is wired correctly:
# pivy-agent must come up against fibby, enumerate readers, SELECT PIV,
# walk the standard slot cert tags, and respond to `ssh-add -L`
# without crashing or leaking a PIN prompt.
#
# Documents what pivy-agent expects from a PIV card so the rest of
# #135's capability work (slot 9A ECDSA, GENERATE, CLI seed flags,
# etc.) can be sequenced against real observed behavior.
#
# Required env (supplied by the
# `test-bats-conformance-fibby-pivy-agent-smoke` recipe):
#   PIVY_AGENT=/path/to/pivy-agent  (nix build .#pivy)
#   FIBBY_BIN=/path/to/fibby        (target/debug/fibby via build-rust)
#
# When invoked via the conformance lane's glob without those env vars
# set, the suite gracefully skips — same convention as
# `pivy_agent_hardware.bats`.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PIVY_AGENT:-} ]] || [[ ! -x ${PIVY_AGENT:-/nonexistent} ]]; then
    skip "PIVY_AGENT unset or not executable; run via just test-bats-conformance-fibby-pivy-agent-smoke"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable"
  fi

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  # Deliberately do NOT export PIGGY_TEST_FIB_PIN — the smoke must not
  # reach a PIN-gated path, so the refusal helper should never be
  # invoked.
  unset PIGGY_TEST_FIB_PIN

  # Short-path workdir under /tmp because $BATS_TEST_TMPDIR can overrun
  # AF_UNIX sun_path's 108-byte limit (104 on darwin) when bats sits
  # deep under nix sandbox prefixes. Same trick as the hardware lane.
  WORKDIR="$(mktemp -d -t fbsmk.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  unset SSH_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Spawn fibby in the virtual backend on the per-test socket. Tracing
# is set to `wire` so other tests in this file can grep the trace.
# Extra args (e.g. `--seed-rfc6979-slot-9a-cert`) pass through verbatim
# after the standard `--socket` / `--backend` flags.
spawn_fibby() {
  FIBBY_LOG=wire "$FIBBY_BIN" --socket "$FIBBY_SOCK" --backend virtual "$@" \
    >"$FIBBY_LOG" 2>&1 &
  FIBBY_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $FIBBY_SOCK ]] && return 0
    sleep 0.1
  done
  echo "fibby socket never appeared at $FIBBY_SOCK" >&2
  echo "--- fibby log ---" >&2
  cat "$FIBBY_LOG" >&2 || true
  return 1
}

# Spawn pivy-agent pointing at fibby's pcscd.comm socket. -A (all
# cards) so we don't have to predict a GUID; -D for foreground; -a
# for the private socket.
spawn_agent() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    "$PIVY_AGENT" -A -D -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  echo "--- fibby log ---" >&2
  cat "$FIBBY_LOG" >&2 || true
  return 1
}

# Empty VirtualCard exposes no identities — pivy-agent returns
# `The agent has no identities` with exit 1. exit 2 = "could not
# connect" which would be a regression in fibby's pcsc-lite plumbing
# or in pivy-agent's PCSCLITE_CSOCK_NAME handling.
function pivy_agent_against_empty_fibby_lists_no_identities { # @test
  spawn_fibby
  spawn_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 || $status -eq 1 ]] || {
    echo "ssh-add -L exited $status; expected 0 or 1" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -50 "$FIBBY_LOG" >&2 || true
    return 1
  }
  refute_output --partial "[piggy-test-askpass]"
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# pivy-agent's identity-listing walks the standard PIV cert object
# tags. Verifying these probes happened against fibby tells us the
# pcsc-lite path is wired end-to-end and pivy-agent is doing the
# work we expect — independent of whether the slots are populated.
#
# Tags (slot↔object map per pivy `PIV_TAG_CERT_*` / pivy-piv slot.rs):
#   5FC10C  Card Capability Container (CCC)
#   5FC101  Slot 9E (Card Authentication) cert
#   5FC105  Slot 9A (PIV Authentication) cert
#   5FC10A  Slot 9C (Digital Signature) cert
#   5FC10B  Slot 9D (Key Management) cert
#
# (CHUID at 5FC102 is NOT probed by pivy-agent's identity flow — that
# simplifies the seeding story: only cert tags matter for #135's
# follow-up CLI work.)
function pivy_agent_probes_standard_piv_cert_tags { # @test
  spawn_fibby
  spawn_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  # The cert-tag walks must all show up in fibby's wire trace.
  local tag
  for tag in 5FC10C 5FC101 5FC105 5FC10A 5FC10B; do
    grep -qi "GET DATA tag=$tag" "$FIBBY_LOG" || {
      echo "missing GET DATA probe for tag $tag in fibby trace" >&2
      echo "--- fibby log ---" >&2
      cat "$FIBBY_LOG" >&2 || true
      return 1
    }
  done
}

# With fibby's `--seed-rfc6979-slot-9a-cert` flag, VirtualCard exposes
# the canonical slot 9A cert built over the RFC 6979 §A.2.5 P-256
# keypair. pivy-agent's identity-listing flow then surfaces one SSH
# identity (`ecdsa-sha2-nistp256 …`) whose public key is the RFC test
# vector. This closes the loop on the empty-card smoke above —
# substrate works AND the seeded-cert path produces a usable SSH
# identity end-to-end.
#
# Asserts:
#   - ssh-add -L exits 0 (has identities)
#   - exactly one identity line in stdout
#   - the key type prefix is `ecdsa-sha2-nistp256` (matches the P-256
#     curve the cert advertises)
function pivy_agent_against_seeded_fibby_lists_one_ecdsa_identity { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert
  spawn_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status; expected 0 (have identities)" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
  local count
  count=$(printf '%s\n' "$output" | grep -c '^ecdsa-sha2-nistp256 ' || true)
  [[ $count -eq 1 ]] || {
    echo "expected 1 ecdsa-sha2-nistp256 identity, got $count" >&2
    echo "ssh-add -L output:" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  refute_output --partial "[piggy-test-askpass]"
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# With `--seed-rfc6979-slot-9a-cert`, fibby's slot 9A holds both the cert
# (enumerable identity) AND the matching RFC 6979 §A.2.5 private key
# (signable). This drives a real signature through the whole stack:
# ssh-keygen asks pivy-agent to sign, pivy-agent unlocks fibby's PIN and
# runs GA ECDSA on slot 9A, and we verify the returned SSH signature
# against the agent's advertised public key. Proves the slot-9A sign path
# (piggy#135) works end-to-end via pivy-agent, not just at the unit level.
#
# Unlike the no-prompt smokes above, this test legitimately reaches a
# PIN-gated path (slot 9A default PIN policy is "once"), so it supplies
# the VirtualCard default PIN (123456) non-interactively via the test
# askpass — the only test in this file that sets PIGGY_TEST_FIB_PIN.
function pivy_agent_signs_and_verifies_via_seeded_fibby_slot_9a { # @test
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc6979-slot-9a-cert
  spawn_agent
  export SSH_AUTH_SOCK="$AGENT_SOCK"

  # The agent's advertised slot-9A public key.
  run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status; expected 0 (have identities)" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep '^ecdsa-sha2-nistp256 ' >"$WORKDIR/id.pub"
  [[ -s $WORKDIR/id.pub ]] || {
    echo "no ecdsa-sha2-nistp256 identity in ssh-add -L output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # Message to sign + an allow-list keyed on that public key (type+data
  # only, so a trailing key comment can't confuse the allowed_signers
  # parser).
  echo "phase0-fibby-slot-9a-sign-smoke" >"$WORKDIR/data"
  local ktype kdata _rest
  read -r ktype kdata _rest <"$WORKDIR/id.pub"
  printf 'smoke@fibby %s %s\n' "$ktype" "$kdata" >"$WORKDIR/allowed_signers"

  # Sign via the agent: -U treats -f as a public key and pulls the
  # matching private key from ssh-agent — i.e. fibby's slot 9A, reached
  # through pivy-agent. This is the first call to hit the PIN-gated sign
  # path, so pivy-agent unlocks via the test askpass here.
  run ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/data"
  [[ $status -eq 0 && -f $WORKDIR/data.sig ]] || {
    echo "ssh-keygen -Y sign -U exited $status (data.sig present: $([[ -f $WORKDIR/data.sig ]] && echo yes || echo no))" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log ---" >&2
    cat "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # Verify the signature cryptographically against the allow-list.
  run ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I "smoke@fibby" \
    -n file -s "$WORKDIR/data.sig" <"$WORKDIR/data"
  [[ $status -eq 0 ]] || {
    echo "ssh-keygen -Y verify exited $status; expected 0 (good signature)" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # Belt-and-suspenders: the signature must have come from fibby's slot-9A
  # GA ECDSA handler. The wire trace records the handler firing and
  # returning 9000 (see virtual_card.rs::handle_general_authenticate_ecdsa_slot_9a).
  grep -q "GA ECDSA 9A -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9A GA ECDSA sign in fibby trace" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The askpass supplied the PIN; it must not have refused.
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# pivy-agent on top of fibby must survive multiple identity probes
# back-to-back without drifting or wedging — mirrors the hardware
# lane's `agent_lists_identities_repeated_no_drift` test against the
# software substrate.
function pivy_agent_against_empty_fibby_serves_repeated_probes { # @test
  spawn_fibby
  spawn_agent
  local i status_each
  for i in 1 2 3 4 5; do
    SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
    status_each=$status
    [[ $status_each -eq 0 || $status_each -eq 1 ]] || {
      echo "iteration $i: ssh-add -L exited $status_each" >&2
      cat "$AGENT_LOG" >&2 || true
      return 1
    }
  done
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal during repeated probes" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}
