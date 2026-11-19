#! /usr/bin/env bats
#
# piggy#397 over fibby: `piggy tool attest-verify <slot>` checks a slot's
# attestation instead of printing it: signed by the card's F9 certificate,
# F9 chained to the root (fibby's F9 is self-signed, so its own certificate
# is passed as `--root`; without it the embedded Yubico root is the anchor
# and a fibby chain fails that point, as it should), the attested key equal
# to the slot's key, the policy decoded and asserted, and a saved
# attestation compared by what it states. fibby attests only keys generated
# on it, so the lane generates its keys first. Also `card export-attestation`
# for a slot other than 9a/9c (the lift).
#
# Required env (supplied by `just test-bats-conformance-tool-attest-verify-fibby`):
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
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-tool-attest-verify-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  # piggy-testing(7) PIN PROMPT SAFETY NET: `generate` self-signs with the
  # PIN; attest-verify itself never prompts.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK

  WORKDIR="$(mktemp -d -t attver.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=

  # --auto-touch: a touch-always key's self-signed certificate at generate
  # time would otherwise wait for `fibby ctl touch`.
  spawn_fibby --seed-rfc5903-slot-9d-cert --auto-touch
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

_tool() {
  run "$PIGGY_BIN" tool "$@"
}

_show() {
  printf '%s\n' "$output" >&2
  tail -30 "$FIBBY_LOG" >&2 || true
}

# Generate an attestable key in SLOT with the given PIN and touch policy.
_generate() {
  "$PIGGY_BIN" tool -K default -P 123456 -a eccp256 -i "$2" -t "$3" generate "$1" >/dev/null || {
    echo "generate $1 failed" >&2; _show; return 1; }
}

function a_generated_key_verifies_against_the_cards_own_root { # @test
  _generate 9c always always
  "$PIGGY_BIN" tool cert f9 >"$WORKDIR/f9.pem"

  _tool --root "$WORKDIR/f9.pem" --expect-pin always --expect-touch always attest-verify 9c
  [[ $status -eq 0 ]] || { echo "want exit 0, got $status" >&2; _show; return 1; }
  [[ $output == "TAP version 14"* ]] || { echo "not TAP: $output" >&2; return 1; }
  for point in \
    "attestation signed by the card's F9 certificate" \
    "F9 certificate chains to the root" \
    "attested key is the slot's key" \
    "attested policy: PIN always, touch always"; do
    grep -qE "^ok [0-9]+ - $point" <<<"$output" || {
      echo "point not passed: $point" >&2; _show; return 1; }
  done
  if grep -q '^not ok' <<<"$output"; then echo "a point failed" >&2; _show; return 1; fi
  # The plan names every point; the firmware/serial point is fibby's to
  # pass or skip, never to fail.
  grep -q '^1\.\.5$' <<<"$output" || { echo "no plan line for 5 points" >&2; _show; return 1; }

  # JSON lines carry the same verdict.
  _tool -j --root "$WORKDIR/f9.pem" attest-verify 9c
  [[ $status -eq 0 && $(grep -c '"ok":true' <<<"$output") -ge 4 ]] || {
    echo "json form: got $status" >&2; _show; return 1; }
}

function the_embedded_yubico_root_is_the_default_and_fibby_does_not_chain_to_it { # @test
  _generate 9c always always
  _tool attest-verify 9c
  [[ $status -eq 1 ]] || { echo "want exit 1 (fibby's F9 is not Yubico's), got $status" >&2; _show; return 1; }
  grep -qE '^not ok [0-9]+ - F9 certificate chains to the root' <<<"$output" || {
    echo "the chain point did not fail" >&2; _show; return 1; }
  grep -q 'root_source: "embedded Yubico PIV Root CA Serial 263751"' <<<"$output" || {
    echo "the diagnostics do not name the embedded root" >&2; _show; return 1; }
  grep -q '63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46' <<<"$output" || {
    echo "the pinned fingerprint is not shown" >&2; _show; return 1; }
  # Every other point still passes: the verdict is about the root alone.
  grep -qE "^ok [0-9]+ - attestation signed" <<<"$output" || { echo "signed point failed" >&2; _show; return 1; }
  grep -qE "^ok [0-9]+ - attested key" <<<"$output" || { echo "key point failed" >&2; _show; return 1; }
}

function a_wrong_expectation_and_a_saved_mismatch_fail_their_points { # @test
  _generate 9c always always
  _generate 9a once cached
  "$PIGGY_BIN" tool cert f9 >"$WORKDIR/f9.pem"
  "$PIGGY_BIN" tool attest 9c >"$WORKDIR/9c-attest.pem"
  "$PIGGY_BIN" tool attest 9a >"$WORKDIR/9a-attest.pem"

  _tool --root "$WORKDIR/f9.pem" --expect-touch never attest-verify 9c
  [[ $status -eq 1 ]] || { echo "want exit 1 on a policy mismatch, got $status" >&2; _show; return 1; }
  grep -qE '^not ok [0-9]+ - attested policy: PIN always, touch always' <<<"$output" || {
    echo "the policy point did not fail by name" >&2; _show; return 1; }
  grep -q 'expected: "PIN any, touch never"' <<<"$output" || { echo "no expected line" >&2; _show; return 1; }

  # The saved attestation of the SAME slot agrees (a fresh attestation
  # differs only in its signature); another slot's does not.
  _tool --root "$WORKDIR/f9.pem" --saved "$WORKDIR/9c-attest.pem" attest-verify 9c
  [[ $status -eq 0 ]] || { echo "saved same-slot: want exit 0, got $status" >&2; _show; return 1; }
  grep -qE '^ok [0-9]+ - saved attestation agrees' <<<"$output" || { echo "no saved point" >&2; _show; return 1; }
  _tool --root "$WORKDIR/f9.pem" --saved "$WORKDIR/9a-attest.pem" attest-verify 9c
  [[ $status -eq 1 ]] || { echo "saved other-slot: want exit 1, got $status" >&2; _show; return 1; }
  grep -q 'differs: "key, policy"' <<<"$output" || { echo "the differences are not named" >&2; _show; return 1; }

  # Usage errors are exit 2 and touch no card.
  _tool --root "$WORKDIR/nope.pem" attest-verify 9c
  [[ $status -eq 2 && $output == *"--root"* ]] || { echo "missing --root file: got $status: $output" >&2; return 1; }
  _tool attest-verify f9
  [[ $status -eq 2 ]] || { echo "F9: want usage exit 2, got $status" >&2; return 1; }
}

function export_attestation_names_attest_verify_for_a_key_management_slot { # @test
  # A key-management slot has no SSH markl id, so no bundle: the refusal
  # points at attest-verify, which does take it. (9E, the one slot the lift
  # adds, fibby does not generate into; the hardware lane proves it.)
  _generate 9d never never
  run "$PIGGY_BIN" card export-attestation 9d
  [[ $status -ne 0 && $output == *"attest-verify 9d"* ]] || {
    echo "export-attestation 9d: want a refusal naming attest-verify, got $status: $output" >&2; return 1; }
  "$PIGGY_BIN" tool cert f9 >"$WORKDIR/f9.pem"
  _tool --root "$WORKDIR/f9.pem" --expect-pin never --expect-touch never attest-verify 9d
  [[ $status -eq 0 ]] || { echo "attest-verify 9d: want exit 0, got $status" >&2; _show; return 1; }
  run "$PIGGY_BIN" card export-attestation f9
  [[ $status -ne 0 && $output == *"9a, 9c or 9e"* ]] || { echo "F9 export: got $status: $output" >&2; return 1; }
}
