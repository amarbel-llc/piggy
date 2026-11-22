#! /usr/bin/env bats
#
# `piggy ca root-cert --profile NAME` (FDR 0007 phase (ii), piggy#391) on
# a card: fibby's slot 82 (piggy#399) holds a P-256 key generated on the
# card with PIN always and touch always, the profile names fibby and slot
# 82, and the root comes out signed by that key. Every root signature also
# leaves a sealed `piggy-certificate-v1` act (RFC 0012 §3.2), signed by the
# same card's slot 9C through `piggy agent`, so the stack is the operator-act
# lanes': fibby with a 9C key from `card add-key 9c`, a card agent over it
# as SSH_AUTH_SOCK, and root-cert on the local card beside it. Two PINs: the
# certificate's (root-cert's askpass), then the act's (the agent's, under
# the `certificate` banner).
#
# The root is checked with openssl (self-signed, CA, keyCertSign, the
# profile's names as permitted DNS constraints, slot 82's key), the act
# with `piggy act` (seal valid, kind root, right piggy:x509-ca, subject
# piggy:ca:<profile>, not-after the certificate's notAfter, the DER's
# sha256 in its description), and the root is written back with
# `piggy tool write-cert 82` and read again.
#
# fibby's F9 certificate is self-signed, not Yubico's, so the profile's
# `[issuer] attestation_root` names fibby's own F9 PEM; a profile without
# it is refused (exit 6) on the chain point. Refused before any PIN prompt,
# nothing written: an empty slot 82, an imported key (fibby attests only
# keys generated on it), a generated key with the wrong policy (exit 6); no agent,
# or an agent that does not serve operator-act@piggy (exit 6). A P-384 slot
# (exit 1: RFC 0013 §2 names P-256 subject keys only) is the unit tests':
# fibby's yk5 model generates P-256 only. Cancelled
# at the act's prompt: the certificate is dropped (exit 6), no PEM, no act.
#
# Leaves under this root wait for `piggy ca sign`/`issue` (phase (ii));
# the builders' leaves are the x509-profile lane's.
#
# Required env (supplied by `just test-bats-conformance-ca-root-cert-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

# `run --separate-stderr` (the happy path's notices) needs bats 1.5.0+.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  export output

  # No target/debug fallback: test-bats-conformance's glob leaves PIGGY_BIN
  # unset so the agent-backed fibby lanes run only via their own recipes.
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-ca-root-cert-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET: generate, root-cert's
  # certificate prompt and the card agent's act prompt each take the PIN
  # from the test askpass, never a GUI prompt.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN="$OPERATOR_ACT_PIN"
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK PIGGY_TEST_FIB_MGMT_KEY

  # Short-path workdir: AF_UNIX sun_path is 108 bytes.
  WORKDIR="$(mktemp -d -t rcfib.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_SOCK="$WORKDIR/a.sock"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=
  FRONT_PID=
  PLAIN_AGENT_PID=
  CONFIG="$WORKDIR/config"
  mkdir -p "$CONFIG/ca-profiles"
  export PIGGY_CONFIG_HOME="$CONFIG"

  # Touch notices (the agent's and root-cert's) go to a recorder, never to
  # this host's desktop.
  NOTICES="$WORKDIR/notices"
  cat >"$WORKDIR/notifier" <<NOTIFIER_EOF
#!/usr/bin/env bash
printf '%s | %s\n' "\$1" "\$2" >>"$NOTICES"
NOTIFIER_EOF
  chmod +x "$WORKDIR/notifier"
  export PIGGY_ASKPASS_NOTIFIER="$WORKDIR/notifier"

  # fibby with 9C provisioned by `card add-key 9c` (PIN always, touch
  # always) and --auto-touch: slot 82's key is touch-always too, at
  # generate time (its self-signed certificate) and when it signs the root.
  spawn_operator_card --auto-touch
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"

  GUID="$("$PIGGY_BIN" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)"
  [[ -n $GUID ]] || { echo "no GUID from piggy tool -j list" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  "$PIGGY_BIN" tool cert f9 >"$WORKDIR/f9.pem"
}

teardown() {
  [[ -n ${PLAIN_AGENT_PID:-} ]] && kill "$PLAIN_AGENT_PID" 2>/dev/null || true
  operator_act_teardown
}

_show() {
  printf 'status: %s\noutput: %s\nstderr: %s\n' "${status:-}" "${output:-}" "${stderr:-}" >&2
  operator_act_dump_logs
}

# A root profile NAME for fibby's slot 82; ATTESTATION_ROOT, when given,
# is the [issuer] attestation_root line's path.
_root_profile() {
  local name="$1" attestation_root="${2:-}"
  cat >"$CONFIG/ca-profiles/$name.toml" <<EOF
kind = "root"
common_name = "piggy-test fibby root"
names = ["github.com", "api.github.com"]
lifetime_hours = 87600
[issuer]
slot = "82"
guid = "$GUID"
EOF
  if [[ -n $attestation_root ]]; then
    printf 'attestation_root = "%s"\n' "$attestation_root" >>"$CONFIG/ca-profiles/$name.toml"
  fi
}

# Generate a key in slot 82 on the card: ALG, PIN policy, touch policy.
_generate_82() {
  "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a "$1" -i "$2" -t "$3" generate 82 >/dev/null || {
    echo "generate 82 ($*) failed" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
}

_pubkey_of() {
  openssl x509 -in "$1" -noout -pubkey
}

_der_sha256() {
  openssl x509 -in "$1" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
}

# root-cert with the PEM to root.pem and so the act to root.pem.act.
_root_cert() {
  run "$PIGGY_BIN" ca root-cert --profile "$1" --out "$WORKDIR/root.pem"
}

# A refusal: exit WANT, nothing certified, no prompt by root-cert, nothing
# written, no act prompt raised by the card agent.
_assert_refusal() {
  local want="$1" why="$2"
  [[ $status -eq $want ]] || { echo "$why: want exit $want, got $status" >&2; _show; return 1; }
  [[ $output != *"BEGIN CERTIFICATE"* ]] || { echo "$why: a refusal printed a certificate" >&2; return 1; }
  [[ $output != *"piggy-test-askpass"* ]] || { echo "$why: a refusal reached the PIN prompt" >&2; return 1; }
  [[ ! -e $WORKDIR/root.pem ]] || { echo "$why: a refusal wrote the PEM" >&2; return 1; }
  [[ ! -e $WORKDIR/root.pem.act ]] || { echo "$why: a refusal wrote an act" >&2; return 1; }
  if [[ -n ${AGENT_PID:-} ]] && (($(operator_act_prompt_count "$AGENT_LOG") > 0)); then
    echo "$why: the card agent raised a prompt" >&2; _show; return 1
  fi
}

function a_key_generated_in_slot_82_signs_its_root_and_seals_its_act { # @test
  _generate_82 eccp256 always always
  "$PIGGY_BIN" tool cert 82 >"$WORKDIR/generated.pem"
  _root_profile fibby "$WORKDIR/f9.pem"
  spawn_card_agent

  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca root-cert --profile fibby --out "$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "root-cert: want exit 0, got $status" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "--out given, yet stdout carried: $output" >&2; return 1; }

  # The override is announced with the root's subject and fingerprint.
  local fp
  fp=$(openssl x509 -in "$WORKDIR/f9.pem" -noout -fingerprint -sha256 | cut -d= -f2)
  [[ $stderr == *"the attestation root is the profile's attestation_root, not the embedded Yubico root: subject "* ]] || {
    echo "no override line on stderr" >&2; _show; return 1; }
  [[ $stderr == *"sha256 $fp"* ]] || { echo "the override line does not carry $fp" >&2; _show; return 1; }
  [[ $stderr == *"slot 82 signs the root CN=piggy-test fibby root (CA, pathlen 1)"* ]] || {
    echo "the notice does not describe the certificate" >&2; _show; return 1; }

  # Two PINs: root-cert's for the certificate, the agent's for the act,
  # the latter under the certificate banner with the act's head as text.
  local der_hex
  der_hex=$(_der_sha256 "$WORKDIR/root.pem")
  [[ $(grep -c '^\[piggy-test-askpass\] supplying' <<<"$stderr") -eq 1 ]] || {
    echo "root-cert did not prompt exactly once" >&2; _show; return 1; }
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 1 ]] || {
    echo "the card agent did not prompt exactly once" >&2; _show; return 1; }
  grep -q '^\[piggy-test-askpass\] operator act kind: certificate$' "$AGENT_LOG" || {
    echo "the act's prompt is not under the certificate banner" >&2; _show; return 1; }
  grep -q "DER sha256 $der_hex" "$AGENT_LOG" || {
    echo "the act's prompt does not show the DER's sha256" >&2; _show; return 1; }

  # Self-signed, and openssl takes it as its own anchor.
  run openssl verify -CAfile "$WORKDIR/root.pem" "$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "openssl verify: $output" >&2; return 1; }
  # An explicit -nameopt: openssl's default subject spelling differs
  # between versions (`CN = x` before 3.x, `CN=x` in 3.5).
  local subject
  subject=$(openssl x509 -in "$WORKDIR/root.pem" -noout -subject -nameopt RFC2253)
  [[ $subject == "subject=CN=piggy-test fibby root" ]] || { echo "subject: $subject" >&2; return 1; }
  local text want
  text=$(openssl x509 -in "$WORKDIR/root.pem" -noout -text)
  for want in "CA:TRUE" "Certificate Sign" "Permitted:" "DNS:github.com" "DNS:api.github.com"; do
    [[ $text == *"$want"* ]] || { echo "root lacks '$want':" >&2; echo "$text" >&2; return 1; }
  done
  # The root certifies slot 82's key: the key of the certificate generate made.
  [[ $(_pubkey_of "$WORKDIR/root.pem") == "$(_pubkey_of "$WORKDIR/generated.pem")" ]] || {
    echo "the root's key is not slot 82's key" >&2; return 1; }

  # The act: sealed, and every field read from the certificate.
  [[ -s $WORKDIR/root.pem.act ]] || { echo "no act beside the PEM" >&2; return 1; }
  run "$PIGGY_BIN" act verify --seal-only "$WORKDIR/root.pem.act"
  [[ $status -eq 0 && $output == "valid piggy-record-digest-v1@"* ]] || {
    echo "the act's seal does not verify: $status: $output" >&2; return 1; }
  run "$PIGGY_BIN" act canon "$WORKDIR/root.pem.act"
  [[ $status -eq 0 ]] || { echo "act canon: $status: $output" >&2; return 1; }
  local canon="$output" not_after
  not_after=$(openssl x509 -in "$WORKDIR/root.pem" -noout -enddate -dateopt iso_8601 | cut -d= -f2 | tr ' ' T)
  for want in \
    "- kind = root" \
    "- producer = piggy:ca" \
    "- subject = piggy:ca:fibby" \
    "- right = piggy:x509-ca" \
    "- records = piggy-record-digest-v1@sha256-" \
    "- not-after = $not_after" \
    "- namespace = piggy-certificate-v1" \
    "; DER sha256 $der_hex"; do
    [[ $canon == *"$want"* ]] || { echo "the act lacks '$want':" >&2; echo "$canon" >&2; return 1; }
  done

  # root-cert writes nothing back; write-cert does, and the slot serves it.
  "$PIGGY_BIN" tool cert 82 >"$WORKDIR/before.pem"
  cmp -s "$WORKDIR/before.pem" "$WORKDIR/generated.pem" || {
    echo "root-cert changed slot 82's certificate" >&2; return 1; }
  run "$PIGGY_BIN" tool write-cert 82 <"$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "write-cert 82: got $status" >&2; _show; return 1; }
  "$PIGGY_BIN" tool cert 82 >"$WORKDIR/served.pem"
  [[ $(_der_sha256 "$WORKDIR/served.pem") == "$der_hex" ]] || {
    echo "slot 82 does not serve the root written to it" >&2; return 1; }
}

function cancelling_the_acts_prompt_drops_the_signed_certificate { # @test
  _generate_82 eccp256 always always
  _root_profile fibby "$WORKDIR/f9.pem"
  OPERATOR_ACT_AGENT_REFUSES_PROMPTS=1 spawn_card_agent

  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca root-cert --profile fibby --out "$WORKDIR/root.pem"
  [[ $status -eq 6 ]] || { echo "want exit 6, got $status" >&2; _show; return 1; }
  [[ $stderr == *"the card's signature over the certificate was made and is dropped"* ]] || {
    echo "the refusal does not say the signature was dropped" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "stdout carried: $output" >&2; return 1; }
  [[ ! -e $WORKDIR/root.pem && ! -e $WORKDIR/root.pem.act ]] || {
    echo "a cancelled act left a file" >&2; ls -l "$WORKDIR" >&2; return 1; }
  grep -q '^\[piggy-test-askpass\] REFUSING' "$AGENT_LOG" || {
    echo "the card agent's act prompt was never refused" >&2; _show; return 1; }
}

function without_attestation_root_fibbys_f9_does_not_chain_to_yubico { # @test
  _generate_82 eccp256 always always
  _root_profile yubico
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" _root_cert yubico
  _assert_refusal 6 "no attestation_root"
  [[ $output == *"F9 certificate chains to the root"* ]] || {
    echo "the refusal does not name the chain point: $output" >&2; return 1; }
  [[ $output != *"not the embedded Yubico root"* ]] || {
    echo "an override was announced with none configured: $output" >&2; return 1; }
}

function a_plain_ssh_agent_cannot_seal_the_act { # @test
  command -v ssh-agent >/dev/null || skip "ssh-agent not on PATH"
  _generate_82 eccp256 always always
  _root_profile fibby "$WORKDIR/f9.pem"
  local plain="$WORKDIR/plain.sock"
  ssh-agent -D -a "$plain" >/dev/null 2>&1 3>&- &
  PLAIN_AGENT_PID=$!
  _wait_for_socket "$plain" /dev/null

  SSH_AUTH_SOCK="$plain" _root_cert fibby
  _assert_refusal 6 "a plain ssh-agent"
  [[ $output == *"does not serve operator-act@piggy"* ]] || {
    echo "the refusal does not name operator-act@piggy: $output" >&2; return 1; }

  # No agent at all is the same refusal, before any prompt.
  _root_cert fibby
  _assert_refusal 6 "no agent"
}

function an_empty_slot_82_is_exit_6 { # @test
  _root_profile fibby "$WORKDIR/f9.pem"
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" _root_cert fibby
  _assert_refusal 6 "empty slot 82"
  [[ $output == *"slot 82"* ]] || { echo "the slot is not named: $output" >&2; return 1; }
}

function an_imported_key_in_slot_82_is_exit_6 { # @test
  # A throwaway (non-secret) OpenSSH P-256 test key, as in the tool-keys
  # lane: fibby will not attest an imported key, so it never signs a root.
  local keyfile="$WORKDIR/import_key"
  cat >"$keyfile" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQuvhKlxYNbiCW1qKp+sS5zM1rwmWqR
rsO9rmQeWP5UZAzl5KsKJhI/sxa/20YYwy4ZYfHib9l2ByHjiPNXqDTgAAAAsC4Q+wUuEP
sFAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC6+EqXFg1uIJbWo
qn6xLnMzWvCZapGuw72uZB5Y/lRkDOXkqwomEj+zFr/bRhjDLhlh8eJv2XYHIeOI81eoNO
AAAAAhANElI+A+9hPHp5bGZiB3v/rs7w8+8AgFzGJYWlE1mxLTAAAAEXBpZ2d5LXRlc3Qt
aW1wb3J0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
EOF
  chmod 600 "$keyfile"
  run "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" import 82 <"$keyfile"
  [[ $status -eq 0 ]] || { echo "import 82: got $status" >&2; _show; return 1; }

  _root_profile fibby "$WORKDIR/f9.pem"
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" _root_cert fibby
  _assert_refusal 6 "imported key in slot 82"
  [[ $output == *"will not attest slot 82"* ]] || {
    echo "the refusal does not say the card will not attest it: $output" >&2; return 1; }
}

function a_generated_key_without_pin_and_touch_always_is_exit_6 { # @test
  _generate_82 eccp256 once never
  _root_profile fibby "$WORKDIR/f9.pem"
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" _root_cert fibby
  _assert_refusal 6 "a PIN-once, touch-never key"
  [[ $output == *"attested policy"* ]] || {
    echo "the refusal does not name the policy point: $output" >&2; return 1; }
}
