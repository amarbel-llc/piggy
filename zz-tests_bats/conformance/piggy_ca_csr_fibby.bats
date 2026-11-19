#! /usr/bin/env bats
#
# FDR 0007 phase (iii-a), piggy#392: the certificate request for a
# holder-held intermediate key. A holder agent over fibby defines the
# scope `piggy-ca-intermediate-v1 = cgroup:<this test's own cgroup>` (the
# unit-bound rule of FDR 0006 phase (d), with the test standing in for the
# issuance unit); a P-256 key is minted under it; `piggy ca csr` signs a
# PKCS#10 request for it through the agent's ordinary sign path, with no
# PIN; openssl verifies the request, reads back the CN, and the request's
# public key equals the minted key. An Ed25519 key and a key the agent does
# not serve are refused by name.
#
# Required env (supplied by `just test-bats-conformance-ca-csr-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/fibby ]]; then
    FIBBY_BIN="$REPO_ROOT/target/debug/fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/piggy ]]; then
    PIGGY_BIN="$REPO_ROOT/target/debug/piggy"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-ca-csr-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET, with no PIN to supply: the
  # request must be signed with none.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset WAYLAND_DISPLAY PIGGY_TEST_FIB_PIN

  WORKDIR="$(mktemp -d -t cacsr.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/ctl.sock"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  CGROUP_ROOT="$WORKDIR/cgroup"
  FIBBY_PID=
  AGENT_PID=

  OWN_CGROUP="$(sed -n 's/^0:://p' /proc/self/cgroup | head -n1)"
  [[ -n $OWN_CGROUP ]] || skip "no cgroup v2 line in /proc/self/cgroup"
  mkdir -p "$CGROUP_ROOT$OWN_CGROUP"

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# A holder whose intermediate scope is a fixed cgroup: this test's own, so
# the test can mint under it the way the issuance unit does from inside
# its unit (piggy-ca.service).
_spawn_holder() {
  spawn_fibby --model yk5.7 --control-socket "$FIBBY_CTL" 3>&-
  "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" destroy "Virtual PCD piggy fibby 00 00" >/dev/null
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" \
    --scope "piggy-ca-intermediate-v1=cgroup:$OWN_CGROUP" \
    --cgroup-root "$CGROUP_ROOT" --scope-poll-interval 1 \
    -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 3>&- &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && { export SSH_AUTH_SOCK="$AGENT_SOCK"; return 0; }
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  cat "$AGENT_LOG" "$FIBBY_LOG" >&2 || true
  return 1
}

_dump_logs() {
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  echo "--- fibby log (tail) ---" >&2
  tail -40 "$FIBBY_LOG" >&2 || true
}

function a_request_for_the_unit_bound_p256_key_verifies_and_carries_the_key_and_cn { # @test
  _spawn_holder
  run "$PIGGY_BIN" holder mint --scope piggy-ca-intermediate-v1 --type p256
  [[ $status -eq 0 && $output == ecdsa-sha2-nistp256* ]] || {
    echo "mint failed ($status): $output" >&2; _dump_logs; return 1; }
  printf '%s\n' "$output" >"$WORKDIR/int.pub"

  run "$PIGGY_BIN" ca csr --key "$WORKDIR/int.pub" --cn piggy-ca-intermediate --out "$WORKDIR/int.csr"
  [[ $status -eq 0 ]] || { echo "csr failed ($status): $output" >&2; _dump_logs; return 1; }

  run openssl req -in "$WORKDIR/int.csr" -noout -verify -subject
  [[ $status -eq 0 && $output == *"verify OK"* && $output == *"CN"*"piggy-ca-intermediate"* ]] || {
    echo "openssl did not verify the request: $output" >&2; cat "$WORKDIR/int.csr" >&2; return 1; }

  # The request's key is the minted key: compare the SubjectPublicKeyInfo.
  openssl req -in "$WORKDIR/int.csr" -noout -pubkey >"$WORKDIR/from-csr.pem"
  ssh-keygen -e -m PKCS8 -f "$WORKDIR/int.pub" >"$WORKDIR/from-mint.pem"
  cmp -s "$WORKDIR/from-csr.pem" "$WORKDIR/from-mint.pem" || {
    echo "the request's key differs from the minted key" >&2
    cat "$WORKDIR/from-csr.pem" "$WORKDIR/from-mint.pem" >&2
    return 1
  }
  # No PIN reached the card.
  if grep -q "VERIFY" "$FIBBY_LOG"; then
    echo "a PIN was verified for a PIN-never key" >&2; _dump_logs; return 1
  fi
  # The CSR goes to stdout when --out is absent, as PEM.
  run "$PIGGY_BIN" ca csr --key "$WORKDIR/int.pub"
  [[ $status -eq 0 && $output == "-----BEGIN CERTIFICATE REQUEST-----"* ]] || {
    echo "stdout form failed ($status): $output" >&2; return 1; }
}

function an_ed25519_key_and_an_unserved_key_are_refused_by_name { # @test
  _spawn_holder
  "$PIGGY_BIN" holder mint --scope piggy-ca-intermediate-v1 >"$WORKDIR/ed.pub"
  run "$PIGGY_BIN" ca csr --key "$WORKDIR/ed.pub"
  [[ $status -eq 2 && $output == *"ssh-ed25519"* && $output == *"--type p256"* ]] || {
    echo "ed25519: want exit 2 naming the type, got $status: $output" >&2; return 1; }

  # A P-256 key nobody serves: a fresh software key.
  ssh-keygen -t ecdsa -b 256 -N "" -q -f "$WORKDIR/soft" -C soft
  run "$PIGGY_BIN" ca csr --key "$WORKDIR/soft.pub"
  [[ $status -eq 1 && $output == *"does not hold"* ]] || {
    echo "unserved key: want exit 1 (not held), got $status: $output" >&2; return 1; }

  run env SSH_AUTH_SOCK=/nonexistent "$PIGGY_BIN" ca csr --key "$WORKDIR/soft.pub"
  [[ $status -eq 3 ]] || { echo "no agent: want exit 3, got $status: $output" >&2; return 1; }
}
