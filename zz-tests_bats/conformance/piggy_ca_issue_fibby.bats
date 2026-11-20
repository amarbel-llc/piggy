#! /usr/bin/env bats
#
# `piggy ca sign` and `piggy ca issue` (FDR 0007 phase (ii), piggy#391) on a
# card: fibby's slot 82 (piggy#399) holds a P-256 root, made here by the
# real `piggy ca root-cert` and written back with `piggy tool write-cert`,
# so the verbs sign under the certificate the slot serves. As in
# piggy_ca_root_cert_fibby.bats the stack is the operator-act lanes': fibby
# with a 9C key from `card add-key 9c`, a card agent over it as
# SSH_AUTH_SOCK, and the verb on the local card beside it. Every card
# signature takes two PINs: the certificate's (the verb's askpass), then the
# certificate act's (the agent's, under the `certificate` banner).
#
# The leaf and the intermediate are checked with openssl (chain to the
# root, key equal to the request's, the profile's names), the act with
# `piggy act` (seal valid, kind link, right piggy:x509-leaf or
# piggy:x509-ca, subject piggy:ca:<profile>, not-after the certificate's,
# the DER's sha256 in its description). The state under PIGGY_CA_STATE is
# checked too: a rate-limit stamp and one audit line per certificate.
#
# Refused with nothing written, no certificate on stdout and no PIN prompt
# by the verb or the card agent: an unknown profile (exit 3); a profile of
# the wrong kind for the verb (exit 2, the usage code `ca_issue` gives it);
# a request that is empty, not PKCS#10 or holds an Ed25519 key (exit 4); a
# request naming something outside the profile (exit 5); a P-384 request
# (exit 1: RFC 0013 §2 names P-256 subject keys only); an act path that is
# taken (exit 1); a second run inside the ten-minute window (exit 7, before
# the request is even read).
#
# What this lane does not do: a cancelled act prompt dropping the signed
# certificate is piggy_ca_root_cert_fibby.bats's, the same code path
# (`seal_and_write`); a leaf under an intermediate waits for a later phase.
#
# Required env (supplied by `just test-bats-conformance-ca-issue-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

# `run --separate-stderr` needs bats 1.5.0+.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  export output

  # No target/debug fallback: test-bats-conformance's glob leaves PIGGY_BIN
  # unset so the agent-backed fibby lanes run only via their own recipes.
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-ca-issue-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET: generate, the verbs'
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
  WORKDIR="$(mktemp -d -t cai.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_SOCK="$WORKDIR/a.sock"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=
  FRONT_PID=
  CONFIG="$WORKDIR/config"
  STATE="$WORKDIR/state"
  mkdir -p "$CONFIG/ca-profiles"
  export PIGGY_CONFIG_HOME="$CONFIG"
  export PIGGY_CA_STATE="$STATE"

  # Touch notices go to a recorder, never to this host's desktop.
  NOTICES="$WORKDIR/notices"
  cat >"$WORKDIR/notifier" <<NOTIFIER_EOF
#!/usr/bin/env bash
printf '%s | %s\n' "\$1" "\$2" >>"$NOTICES"
NOTIFIER_EOF
  chmod +x "$WORKDIR/notifier"
  export PIGGY_ASKPASS_NOTIFIER="$WORKDIR/notifier"

  # fibby with 9C provisioned by `card add-key 9c` (PIN always, touch
  # always) and --auto-touch: slot 82's key is touch-always too.
  spawn_operator_card --auto-touch
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"

  GUID="$("$PIGGY_BIN" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)"
  [[ -n $GUID ]] || { echo "no GUID from piggy tool -j list" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  "$PIGGY_BIN" tool cert f9 >"$WORKDIR/f9.pem"
}

teardown() {
  operator_act_teardown
}

_show() {
  printf 'status: %s\noutput: %s\nstderr: %s\n' "${status:-}" "${output:-}" "${stderr:-}" >&2
  operator_act_dump_logs
}

# The three profiles, all issued by fibby's slot 82; the issuer names
# fibby's own F9 as the attestation root (it is self-signed, not Yubico's).
_root_profile() {
  cat >"$CONFIG/ca-profiles/root.toml" <<EOF
kind = "root"
common_name = "piggy-test fibby root"
names = ["github.com", "api.github.com"]
lifetime_hours = 87600
[issuer]
slot = "82"
guid = "$GUID"
attestation_root = "$WORKDIR/f9.pem"
EOF
}

_leaf_profile() {
  cat >"$CONFIG/ca-profiles/${1:-leaf}.toml" <<EOF
kind = "leaf"
names = ["github.com", "api.github.com"]
lifetime_hours = 720
[issuer]
slot = "82"
guid = "$GUID"
attestation_root = "$WORKDIR/f9.pem"
EOF
}

_inter_profile() {
  cat >"$CONFIG/ca-profiles/inter.toml" <<EOF
kind = "intermediate"
common_name = "piggy-test intermediate"
names = ["github.com", "api.github.com"]
lifetime_hours = 24
[issuer]
slot = "82"
guid = "$GUID"
attestation_root = "$WORKDIR/f9.pem"
EOF
}

# A request for a fresh key: NAME (the file stem), the subject, and extra
# `openssl req` arguments (a P-384 request needs -sha384).
_csr() {
  local name="$1" subject="$2"
  shift 2
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/$name.key" 2>/dev/null
  openssl req -new -key "$WORKDIR/$name.key" -subj "$subject" "$@" -out "$WORKDIR/$name.csr"
}

# A card with a root in slot 82, made by the real verb and written back,
# and the card agent up. The root's own act is the agent's first prompt, so
# the prompt count is taken after it.
_root_in_slot_82() {
  "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a eccp256 -i always -t always generate 82 >/dev/null || {
    echo "generate 82 failed" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  _root_profile
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca root-cert --profile root --out "$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "root-cert: want exit 0, got $status" >&2; _show; return 1; }
  run "$PIGGY_BIN" tool write-cert 82 <"$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "write-cert 82: got $status" >&2; _show; return 1; }
  PROMPTS_BEFORE=$(operator_act_prompt_count "$AGENT_LOG")
}

# `piggy ca VERB --profile PROFILE` on the request file CSR, the PEM to
# $WORKDIR/PROFILE.pem (so the act to PROFILE.pem.act), under the card agent
# and the lane's state directory. EXTRA arguments follow.
_ca() {
  local verb="$1" profile="$2" csr="$3"
  shift 3
  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca "$verb" --profile "$profile" --out "$WORKDIR/$profile.pem" "$@" <"$csr"
}

_der_sha256() {
  openssl x509 -in "$1" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
}

# A refusal: exit WANT, nothing certified, no prompt by the verb, nothing
# written, no act prompt raised by the card agent, no rate-limit stamp.
_assert_refusal() {
  local want="$1" why="$2" profile="$3"
  [[ $status -eq $want ]] || { echo "$why: want exit $want, got $status" >&2; _show; return 1; }
  [[ $output != *"BEGIN CERTIFICATE"* ]] || { echo "$why: a refusal printed a certificate" >&2; return 1; }
  [[ -z $output ]] || { echo "$why: a refusal wrote to stdout: $output" >&2; return 1; }
  [[ $stderr != *"[piggy-test-askpass]"* ]] || { echo "$why: a refusal reached the PIN prompt" >&2; _show; return 1; }
  [[ ! -e $WORKDIR/$profile.pem ]] || { echo "$why: a refusal wrote the PEM" >&2; return 1; }
  [[ ! -e $WORKDIR/$profile.pem.act ]] || { echo "$why: a refusal wrote an act" >&2; return 1; }
  [[ ! -e $STATE/rate/$profile ]] || { echo "$why: a refusal armed the rate limit" >&2; return 1; }
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq $PROMPTS_BEFORE ]] || {
    echo "$why: the card agent raised a prompt" >&2; _show; return 1; }
}

# The shared checks of a card-signed certificate: each of the verb's two
# PINs asked once (the verb's, then the agent's under the certificate
# banner with the DER's sha256), the act sealed and carrying KIND, RIGHT
# and SUBJECT and the certificate's not-after, the audit line and the stamp.
_assert_certified() {
  local profile="$1" right="$2" der_hex not_after canon want
  der_hex=$(_der_sha256 "$WORKDIR/$profile.pem")
  [[ $(grep -c '^\[piggy-test-askpass\] supplying' <<<"$stderr") -eq 1 ]] || {
    echo "the verb did not prompt exactly once" >&2; _show; return 1; }
  [[ $(($(operator_act_prompt_count "$AGENT_LOG") - PROMPTS_BEFORE)) -eq 1 ]] || {
    echo "the card agent did not prompt exactly once" >&2; _show; return 1; }
  # One banner per prompt, the root's included: this certificate's is the
  # one after PROMPTS_BEFORE.
  [[ $(grep -c '^\[piggy-test-askpass\] operator act kind: certificate$' "$AGENT_LOG") -eq $((PROMPTS_BEFORE + 1)) ]] || {
    echo "the act's prompt is not under the certificate banner" >&2; _show; return 1; }
  grep -q "DER sha256 $der_hex" "$AGENT_LOG" || {
    echo "the act's prompt does not show the DER's sha256" >&2; _show; return 1; }

  [[ -s $WORKDIR/$profile.pem.act ]] || { echo "no act beside the PEM" >&2; return 1; }
  run "$PIGGY_BIN" act verify --seal-only "$WORKDIR/$profile.pem.act"
  [[ $status -eq 0 && $output == "valid piggy-record-digest-v1@"* ]] || {
    echo "the act's seal does not verify: $status: $output" >&2; return 1; }
  run "$PIGGY_BIN" act canon "$WORKDIR/$profile.pem.act"
  [[ $status -eq 0 ]] || { echo "act canon: $status: $output" >&2; return 1; }
  canon="$output"
  not_after=$(openssl x509 -in "$WORKDIR/$profile.pem" -noout -enddate -dateopt iso_8601 | cut -d= -f2 | tr ' ' T)
  for want in \
    "- kind = link" \
    "- producer = piggy:ca" \
    "- subject = piggy:ca:$profile" \
    "- right = $right" \
    "- not-after = $not_after" \
    "- namespace = piggy-certificate-v1" \
    "; DER sha256 $der_hex"; do
    [[ $canon == *"$want"* ]] || { echo "the act lacks '$want':" >&2; echo "$canon" >&2; return 1; }
  done

  # The stamp is a Unix time; one audit line names the profile and the
  # certificate and request digests.
  [[ $(cat "$STATE/rate/$profile") =~ ^[0-9]+$ ]] || {
    echo "the rate-limit stamp is not a number: $(cat "$STATE/rate/$profile")" >&2; return 1; }
  [[ $(wc -l <"$STATE/audit") -eq 1 ]] || { echo "want one audit line:" >&2; cat "$STATE/audit" >&2; return 1; }
  for want in "piggy-ca issued profile=$profile " "cert=piggy-record-digest-v1@blake2b256-" "csr=piggy-record-digest-v1@blake2b256-"; do
    [[ $(cat "$STATE/audit") == *"$want"* ]] || { echo "the audit line lacks '$want':" >&2; cat "$STATE/audit" >&2; return 1; }
  done
}

function a_leaf_is_issued_under_the_root_and_its_act_sealed { # @test
  _root_in_slot_82
  _leaf_profile
  _csr leaf /CN=github.com
  _ca issue leaf "$WORKDIR/leaf.csr"
  [[ $status -eq 0 ]] || { echo "issue: want exit 0, got $status" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "--out given, yet stdout carried: $output" >&2; return 1; }
  [[ $stderr == *"signs a leaf certificate under profile leaf"* ]] || {
    echo "the notice does not describe the certificate" >&2; _show; return 1; }

  _assert_certified leaf piggy:x509-leaf

  # The leaf chains to the root slot 82 serves, carries the request's key
  # and the profile's whole name set, whatever the request asked.
  run openssl verify -CAfile "$WORKDIR/root.pem" "$WORKDIR/leaf.pem"
  [[ $status -eq 0 ]] || { echo "openssl verify: $output" >&2; return 1; }
  [[ $(openssl x509 -in "$WORKDIR/leaf.pem" -noout -pubkey) == "$(openssl req -in "$WORKDIR/leaf.csr" -noout -pubkey)" ]] || {
    echo "the leaf's key is not the request's key" >&2; return 1; }
  local text want
  text=$(openssl x509 -in "$WORKDIR/leaf.pem" -noout -text)
  for want in "DNS:github.com" "DNS:api.github.com"; do
    [[ $text == *"$want"* ]] || { echo "leaf lacks '$want':" >&2; echo "$text" >&2; return 1; }
  done
  [[ $text != *"CA:TRUE"* ]] || { echo "a leaf is a CA:" >&2; echo "$text" >&2; return 1; }
  # The issuer's certificate in slot 82 is the root, untouched.
  "$PIGGY_BIN" tool cert 82 >"$WORKDIR/served.pem"
  [[ $(_der_sha256 "$WORKDIR/served.pem") == "$(_der_sha256 "$WORKDIR/root.pem")" ]] || {
    echo "issue changed slot 82's certificate" >&2; return 1; }
}

function an_intermediate_is_signed_under_the_root_and_its_act_sealed { # @test
  _root_in_slot_82
  _inter_profile
  _csr inter "/CN=piggy-test intermediate"
  _ca sign inter "$WORKDIR/inter.csr"
  [[ $status -eq 0 ]] || { echo "sign: want exit 0, got $status" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "--out given, yet stdout carried: $output" >&2; return 1; }
  [[ $stderr == *"intermediate certificate under profile inter"* ]] || {
    echo "the notice does not describe the certificate" >&2; _show; return 1; }

  _assert_certified inter piggy:x509-ca

  run openssl verify -CAfile "$WORKDIR/root.pem" "$WORKDIR/inter.pem"
  [[ $status -eq 0 ]] || { echo "openssl verify: $output" >&2; return 1; }
  [[ $(openssl x509 -in "$WORKDIR/inter.pem" -noout -pubkey) == "$(openssl req -in "$WORKDIR/inter.csr" -noout -pubkey)" ]] || {
    echo "the intermediate's key is not the request's key" >&2; return 1; }
  local text want subject
  subject=$(openssl x509 -in "$WORKDIR/inter.pem" -noout -subject -nameopt RFC2253)
  [[ $subject == "subject=CN=piggy-test intermediate" ]] || { echo "subject: $subject" >&2; return 1; }
  text=$(openssl x509 -in "$WORKDIR/inter.pem" -noout -text)
  for want in "CA:TRUE" "Certificate Sign" "Permitted:" "DNS:github.com" "DNS:api.github.com"; do
    [[ $text == *"$want"* ]] || { echo "intermediate lacks '$want':" >&2; echo "$text" >&2; return 1; }
  done
}

function a_second_issue_inside_the_window_is_exit_7_before_any_prompt { # @test
  _root_in_slot_82
  _leaf_profile
  _csr first /CN=github.com
  _ca issue leaf "$WORKDIR/first.csr"
  [[ $status -eq 0 ]] || { echo "first issue: want exit 0, got $status" >&2; _show; return 1; }
  local stamp audit prompts
  stamp=$(cat "$STATE/rate/leaf")
  audit=$(cat "$STATE/audit")
  prompts=$(operator_act_prompt_count "$AGENT_LOG")

  # The limit is per profile, checked before the request is read: even an
  # empty stdin answers 7, and the first leaf and its act are untouched.
  cp "$WORKDIR/leaf.pem" "$WORKDIR/first.pem"
  _csr second /CN=github.com
  _ca issue leaf "$WORKDIR/second.csr" --act-out "$WORKDIR/second.act"
  [[ $status -eq 7 ]] || { echo "second issue: want exit 7, got $status" >&2; _show; return 1; }
  [[ $stderr == *"rate limited"* ]] || { echo "the refusal does not say rate limited: $stderr" >&2; return 1; }
  [[ -z $output ]] || { echo "a rate-limited run wrote to stdout: $output" >&2; return 1; }
  [[ $stderr != *"[piggy-test-askpass]"* ]] || { echo "a rate-limited run reached the PIN prompt" >&2; _show; return 1; }
  [[ ! -e $WORKDIR/second.act ]] || { echo "a rate-limited run wrote an act" >&2; return 1; }
  cmp -s "$WORKDIR/first.pem" "$WORKDIR/leaf.pem" || { echo "a rate-limited run rewrote the first leaf" >&2; return 1; }
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq $prompts ]] || {
    echo "the card agent raised a prompt" >&2; _show; return 1; }
  [[ $(cat "$STATE/rate/leaf") == "$stamp" && $(cat "$STATE/audit") == "$audit" ]] || {
    echo "a rate-limited run changed the state" >&2; return 1; }
}

function an_unknown_profile_is_exit_3 { # @test
  _root_in_slot_82
  _csr leaf /CN=github.com
  _ca issue missing "$WORKDIR/leaf.csr"
  _assert_refusal 3 "an unknown profile" missing
  [[ $stderr == *"$CONFIG/ca-profiles/missing.toml"* ]] || {
    echo "the path tried is not named: $stderr" >&2; return 1; }
}

function a_profile_of_the_wrong_kind_is_exit_2 { # @test
  _root_in_slot_82
  _leaf_profile
  _inter_profile
  _csr leaf /CN=github.com
  _ca sign leaf "$WORKDIR/leaf.csr"
  _assert_refusal 2 "sign with a leaf profile" leaf
  [[ $stderr == *"issues a"* ]] || { echo "the refusal does not name the kind: $stderr" >&2; return 1; }
  _csr inter "/CN=piggy-test intermediate"
  _ca issue inter "$WORKDIR/inter.csr"
  _assert_refusal 2 "issue with an intermediate profile" inter
  # `root-cert` is the root's verb: sign and issue take no root profile. Its
  # own --out: the root's PEM and act are already in $WORKDIR/root.pem*, and
  # a taken act path is refused first (exit 1).
  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca issue --profile root --out "$WORKDIR/wrongroot.pem" <"$WORKDIR/leaf.csr"
  _assert_refusal 2 "issue with the root profile" wrongroot
}

function a_request_that_is_not_a_p256_pkcs10_request_is_refused_before_any_prompt { # @test
  _root_in_slot_82
  _leaf_profile
  # Empty stdin and a stdin that is not a request: exit 4.
  _ca issue leaf /dev/null
  _assert_refusal 4 "an empty request" leaf
  [[ $stderr == *"no request on stdin"* ]] || { echo "the refusal does not say why: $stderr" >&2; return 1; }
  printf 'hello\n' >"$WORKDIR/junk.csr"
  _ca issue leaf "$WORKDIR/junk.csr"
  _assert_refusal 4 "a request that is not PKCS#10" leaf
  # An Ed25519 key is a valid request the profile cannot certify: exit 4.
  openssl genpkey -algorithm ed25519 -out "$WORKDIR/ed.key" 2>/dev/null
  openssl req -new -key "$WORKDIR/ed.key" -subj /CN=github.com -out "$WORKDIR/ed.csr"
  _ca issue leaf "$WORKDIR/ed.csr"
  _assert_refusal 4 "an Ed25519 request" leaf
  # A P-384 request has no act (RFC 0013 §2): exit 1, before the card is
  # touched.
  openssl ecparam -name secp384r1 -genkey -noout -out "$WORKDIR/p384.key" 2>/dev/null
  openssl req -new -sha384 -key "$WORKDIR/p384.key" -subj /CN=github.com -out "$WORKDIR/p384.csr"
  _ca issue leaf "$WORKDIR/p384.csr"
  _assert_refusal 1 "a P-384 request" leaf
  [[ $stderr == *"RFC 0013"* ]] || { echo "the refusal does not name RFC 0013: $stderr" >&2; return 1; }
}

function a_request_naming_outside_the_profile_is_exit_5 { # @test
  _root_in_slot_82
  _leaf_profile
  _inter_profile
  # A leaf: a CN, or a SAN, outside the profile's names.
  _csr evil /CN=evil.example
  _ca issue leaf "$WORKDIR/evil.csr"
  _assert_refusal 5 "a CN outside the profile" leaf
  [[ $stderr == *"not permitted"* ]] || { echo "the refusal does not say why: $stderr" >&2; return 1; }
  _csr san /CN=github.com -addext "subjectAltName=DNS:evil.example"
  _ca issue leaf "$WORKDIR/san.csr"
  _assert_refusal 5 "a SAN outside the profile" leaf
  # An intermediate: a CN other than the profile's, or any SAN at all.
  _csr other /CN=somebody-else
  _ca sign inter "$WORKDIR/other.csr"
  _assert_refusal 5 "an intermediate with another CN" inter
  [[ $stderr == *"is not the profile's"* ]] || { echo "the refusal does not name the profile's CN: $stderr" >&2; return 1; }
  _csr intsan "/CN=piggy-test intermediate" -addext "subjectAltName=DNS:github.com"
  _ca sign inter "$WORKDIR/intsan.csr"
  _assert_refusal 5 "an intermediate asking for a SAN" inter
}

function an_act_path_that_is_taken_is_refused_and_never_overwritten { # @test
  _root_in_slot_82
  _leaf_profile
  _csr leaf /CN=github.com
  echo keep >"$WORKDIR/taken.act"
  _ca issue leaf "$WORKDIR/leaf.csr" --act-out "$WORKDIR/taken.act"
  _assert_refusal 1 "an act path that exists" leaf
  [[ $stderr == *"exists"* ]] || { echo "the refusal does not say the path exists: $stderr" >&2; return 1; }
  [[ $(cat "$WORKDIR/taken.act") == keep ]] || { echo "the existing act file was touched" >&2; return 1; }
}
