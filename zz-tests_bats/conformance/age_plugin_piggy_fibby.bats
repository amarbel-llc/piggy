#! /usr/bin/env bats
# bats file_tags=hardware
#
# age-plugin-piggy end-to-end over fibby.
#
# Derive the age recipient + identity from fib's slot-9D public key
# (`age-plugin-piggy generate`), encrypt a secret with `age`, then decrypt it
# back through piggy-agent's `ecdh@joyent.com` extension against fib, with the
# PIN supplied on-demand. A successful round-trip is the hardware-crypto
# confirmation of the load-bearing assumption the unit tests can only pin in
# software: that the agent's ECDH output is the X-coordinate the piv-p256
# stanza KDF consumes. If this passes, the plugin's encrypt and decrypt agree
# against a real card-side scalar-mult.
#
# Required env (supplied by the `test-bats-conformance-age-plugin-piggy`
# recipe):
#   FIBBY_BIN=/path/to/fibby        (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy        (nix build .#default — provides
#                                    age-plugin-piggy alongside piggy in bin/)
#   PIVY_AGENT=/path/to/pivy-agent  (nix build .#pivy)
#   AGE_BIN=/path/to/age            (nix build .#age — plugin-capable, >=1.1)
#
# Without those env vars the suite skips, matching the other hardware lanes.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  local v p
  for v in FIBBY_BIN PIGGY_BIN PIVY_AGENT AGE_BIN; do
    p="${!v:-}"
    [[ -n $p && -x $p ]] ||
      skip "$v unset or not executable; run via just test-bats-conformance-age-plugin-piggy"
  done

  AGE_PLUGIN_PIGGY="$(dirname "$PIGGY_BIN")/age-plugin-piggy"
  [[ -x $AGE_PLUGIN_PIGGY ]] ||
    skip "age-plugin-piggy not found next to piggy at $AGE_PLUGIN_PIGGY"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""

  # Short-path workdir under /tmp — deep nix prefixes overrun AF_UNIX's
  # 108-byte sun_path limit.
  WORKDIR="$(mktemp -d -t applg.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  # age discovers the plugin by PATH name (`age-plugin-piggy`); expose both it
  # and `age` on PATH for the age invocations below.
  export PATH="$(dirname "$PIGGY_BIN"):$(dirname "$AGE_BIN"):$PATH"

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${AGENT_PID:-} ]] && wait "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && wait "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

function age_plugin_piggy_round_trips_a_secret_through_fib { # @test
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert

  # 1. Derive the age recipient + identity from fib's slot-9D public key.
  #    Read-only, PIN-free: no agent yet, just a cert read off fibby.
  local idfile="$WORKDIR/identity.txt"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$AGE_PLUGIN_PIGGY" generate
  [[ $status -eq 0 ]] || {
    echo "age-plugin-piggy generate exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" >"$idfile"
  local recipient
  recipient="$(printf '%s\n' "$output" | sed -n 's/^# recipient: //p')"
  [[ -n $recipient ]] || {
    echo "generate printed no '# recipient:' line" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q '^AGE-PLUGIN-PIGGY-' || {
    echo "generate printed no AGE-PLUGIN-PIGGY identity line" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # 2. Encrypt with age -> the plugin's recipient-v1 (pure software, no card).
  local secret="age-plugin-piggy-roundtrip"
  local cipher="$WORKDIR/secret.age"
  printf '%s\n' "$secret" | "$AGE_BIN" -r "$recipient" -o "$cipher"
  local enc=$?
  [[ $enc -eq 0 && -s $cipher ]] || {
    echo "age encrypt exited $enc (cipher present: $([[ -s $cipher ]] && echo yes || echo no))" >&2
    return 1
  }

  # 3. Start the agent against fib and decrypt -> the plugin's identity-v1
  #    drives ecdh@joyent.com at the agent; the PIN is prompted on-demand.
  spawn_agent
  PIGGY_AUTH_SOCK="$AGENT_SOCK" run "$AGE_BIN" -d -i "$idfile" "$cipher"
  [[ $status -eq 0 ]] || {
    echo "age decrypt exited $status (agent/plugin decrypt failed)" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "decrypt output missing the secret line '$secret'" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }

  # 4. The decrypt really reached fib's slot-9D ECDH via an on-demand prompt.
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9D GA ECDH in fibby trace" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
  grep -q "\[piggy-test-askpass\] supplying" "$AGENT_LOG" || {
    echo "no on-demand askpass invocation in agent log (PIN was not prompted)" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
}
