#! /usr/bin/env bats
# bats file_tags=hardware
#
# `piggy papi` end-to-end over fibby: sign a PAPI document with the real
# slot-9A key on a virtual card, then verify the §10 signature back through
# `piggy papi verify`. This is the hardware-crypto confirmation of the §10.4
# wire contract the unit tests can only pin in software — that the bytes
# `piggy papi sign` emits from a real card-side RFC 6979 ECDSA signature
# round-trip through the verifier (and, by the same wire blob, through the
# amarbel-llc/papi validator). Companion to age_plugin_piggy_fibby.bats.
#
# Required env (supplied by the `test-bats-conformance-papi-fibby` recipe):
#   FIBBY_BIN=/path/to/fibby        (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy        (nix build .#default)
#   PIVY_AGENT=/path/to/pivy-agent  (nix build .#pivy)
# Without those the suite skips, matching the other hardware lanes.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  local v p
  for v in FIBBY_BIN PIGGY_BIN PIVY_AGENT; do
    p="${!v:-}"
    [[ -n $p && -x $p ]] ||
      skip "$v unset or not executable; run via just test-bats-conformance-papi-fibby"
  done
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456

  # mock curl so `papi verify` reads our locally-signed document.
  piggy_install_helper_as mock-curl.sh curl
  export MOCK_CURL_DIR="$BATS_TEST_TMPDIR/curl-fixtures"
  mkdir -p "$MOCK_CURL_DIR"

  # Short-path workdir (AF_UNIX sun_path 108-byte limit).
  WORKDIR="$(mktemp -d -t papifib.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

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

mock_fixture() {
  local url="$1" body="$2" key
  key="$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
  printf '%s' "$body" >"$MOCK_CURL_DIR/$key"
}

function papi_sign_then_verify_round_trips_via_fib_slot_9a { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert
  spawn_agent

  # The slot-9A signing key's authorized_keys line, straight from the agent
  # (enumeration is PIN-free). Reduce to "<keytype> <base64>" (drop comment).
  local raw keyline
  raw="$(SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L 2>/dev/null | grep -m1 '^ecdsa-sha2-nistp256 ')"
  [[ -n $raw ]] || {
    echo "no slot-9A ecdsa key advertised by the agent" >&2
    tail -40 "$AGENT_LOG" >&2 || true
    return 1
  }
  keyline="$(awk '{print $1 " " $2}' <<<"$raw")"

  # A minimal PAPI document publishing that 9A key.
  local doc
  doc="$(printf '{"piggy":{"ssh_authorized_keys":["%s"]}}' "$keyline")"

  # Sign over the agent → real RFC 6979 ECDSA on fib slot 9A; inline-merge the
  # signature into the document. The PIN is supplied on demand via the test
  # askpass.
  local signed
  signed="$(printf '%s' "$doc" |
    PIGGY_AUTH_SOCK="$AGENT_SOCK" "$PIGGY_BIN" papi sign --ssh-key "$keyline" --inline)"
  local rc=$?
  [[ $rc -eq 0 ]] || {
    echo "papi sign exited $rc" >&2
    printf '%s\n' "$signed" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  grep -q '"ssh-9a"' <<<"$signed" || {
    echo "signed doc carries no ssh-9a signature" >&2
    printf '%s\n' "$signed" >&2
    return 1
  }

  # Serve the signed doc (+ empty proofs) and verify → signed-and-valid.
  mock_fixture "https://fib.test/papi" "$signed"
  mock_fixture "https://fib.test/papi/proofs" '{"data":[]}'

  run "$PIGGY_BIN" papi verify fib.test --json
  [[ $status -eq 0 ]] || {
    echo "papi verify exited $status (expected signed-and-valid)" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  # The signature point must be present and not a failure.
  grep -q '"signature"' <<<"$output" || {
    echo "verify output has no signature verdict" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  ! grep -qi 'REFUSING to prompt' "$AGENT_LOG" || {
    echo "unexpected askpass refusal during the 9A sign" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}
