#! /usr/bin/env bats
#
# The whole FDR 0007 chain on virtual cards, the holder issuing the leaf
# (phase (iii-b), piggy#392): fibby #1 is the operator's card (slot 82
# root made by `piggy ca root-cert` and written back, 9C for the acts, a
# card agent over it); fibby #2 is a holder with the intermediate scope
# bound to this test's own cgroup, as piggy_ca_csr_fibby.bats runs it. The
# holder mints the intermediate key, `piggy ca csr` requests, the card
# `piggy ca sign`s it under a one-hour intermediate profile (two PINs),
# `piggy ca leaf-csr` makes the leaf's key and request, and `piggy ca
# issue` with a holder profile (`[issuer] holder_key` + `issuer_cert`)
# signs the leaf through the holder: no PIN, no act, the leaf then the
# intermediate out, the leaf's notAfter the intermediate's (the profile
# asked for 720 hours). `piggy ca verify` and openssl both accept the
# chain under the root.
#
# Refused with nothing written: the card agent (not a holder) on the
# socket (exit 6), a holder_key the holder does not serve (6), --act-out
# (2), `sign` with the holder profile (3), a holder profile naming outside
# the intermediate's constraints (3, before the request is read).
#
# Required env (supplied by `just test-bats-conformance-ca-issue-holder-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-ca-issue-holder-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN="$OPERATOR_ACT_PIN"
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK PIGGY_TEST_FIB_MGMT_KEY

  WORKDIR="$(mktemp -d -t caih.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_SOCK="$WORKDIR/a.sock"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=
  FRONT_PID=
  HOLDER_SOCK="$WORKDIR/h-pcscd.comm"
  HOLDER_CTL="$WORKDIR/h-ctl.sock"
  HOLDER_LOG="$WORKDIR/h-fibby.log"
  HOLDER_AGENT_SOCK="$WORKDIR/h.sock"
  HOLDER_AGENT_LOG="$WORKDIR/holder.log"
  HOLDER_FIBBY_PID=
  HOLDER_AGENT_PID=
  CGROUP_ROOT="$WORKDIR/cgroup"
  CONFIG="$WORKDIR/config"
  STATE="$WORKDIR/state"
  mkdir -p "$CONFIG/ca-profiles"
  export PIGGY_CONFIG_HOME="$CONFIG"
  export PIGGY_CA_STATE="$STATE"

  OWN_CGROUP="$(sed -n 's/^0:://p' /proc/self/cgroup | head -n1)"
  [[ -n $OWN_CGROUP ]] || skip "no cgroup v2 line in /proc/self/cgroup"
  mkdir -p "$CGROUP_ROOT$OWN_CGROUP"

  NOTICES="$WORKDIR/notices"
  cat >"$WORKDIR/notifier" <<NOTIFIER_EOF
#!/usr/bin/env bash
printf '%s | %s\n' "\$1" "\$2" >>"$NOTICES"
NOTIFIER_EOF
  chmod +x "$WORKDIR/notifier"
  export PIGGY_ASKPASS_NOTIFIER="$WORKDIR/notifier"

  # The operator's card: 9C from `card add-key 9c`, --auto-touch.
  spawn_operator_card --auto-touch
  export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"
  GUID="$("$PIGGY_BIN" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)"
  [[ -n $GUID ]] || { echo "no GUID from piggy tool -j list" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  "$PIGGY_BIN" tool cert f9 >"$WORKDIR/f9.pem"
  _spawn_holder
}

teardown() {
  local pid
  for pid in "${HOLDER_AGENT_PID:-}" "${HOLDER_FIBBY_PID:-}"; do
    [[ -n $pid ]] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  operator_act_teardown
}

# fibby #2 and the holder agent over it, the intermediate scope bound to
# this test's cgroup.
_spawn_holder() {
  FIBBY_LOG=wire "$FIBBY_BIN" --socket "$HOLDER_SOCK" --backend virtual --model yk5.7 \
    --control-socket "$HOLDER_CTL" >"$HOLDER_LOG" 2>&1 3>&- &
  HOLDER_FIBBY_PID=$!
  local _
  for _ in $(seq 1 100); do
    [[ -S $HOLDER_SOCK && -S $HOLDER_CTL ]] && break
    sleep 0.1
  done
  [[ -S $HOLDER_SOCK && -S $HOLDER_CTL ]] || { echo "the holder's fibby never came up" >&2; cat "$HOLDER_LOG" >&2; return 1; }
  "$FIBBY_BIN" ctl --socket "$HOLDER_CTL" destroy "Virtual PCD piggy fibby 00 00" >/dev/null
  PCSCLITE_CSOCK_NAME="$HOLDER_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$HOLDER_CTL" \
    --scope "piggy-ca-intermediate-v1=cgroup:$OWN_CGROUP" \
    --cgroup-root "$CGROUP_ROOT" --scope-poll-interval 1 \
    --service-name piggy-agent-conformance-absent.service \
    -a "$HOLDER_AGENT_SOCK" >"$HOLDER_AGENT_LOG" 2>&1 3>&- &
  HOLDER_AGENT_PID=$!
  for _ in $(seq 1 50); do
    [[ -S $HOLDER_AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "the holder agent socket never appeared" >&2
  cat "$HOLDER_AGENT_LOG" "$HOLDER_LOG" >&2 || true
  return 1
}

_show() {
  printf 'status: %s\noutput: %s\nstderr: %s\n' "${status:-}" "${output:-}" "${stderr:-}" >&2
  operator_act_dump_logs
  echo "--- holder.log (tail) ---" >&2
  tail -40 "$HOLDER_AGENT_LOG" >&2 || true
}

# The root in slot 82 and the card agent, as the issue lane does it.
_root_in_slot_82() {
  "$PIGGY_BIN" tool -K default -P "$OPERATOR_ACT_PIN" -a eccp256 -i always -t always generate 82 >/dev/null || {
    echo "generate 82 failed" >&2; tail -30 "$FIBBY_LOG" >&2; return 1; }
  cat >"$CONFIG/ca-profiles/root.toml" <<EOF
kind = "root"
common_name = "piggy-test fibby root"
names = ["github.com"]
lifetime_hours = 87600
[issuer]
slot = "82"
guid = "$GUID"
attestation_root = "$WORKDIR/f9.pem"
EOF
  spawn_card_agent
  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca root-cert --profile root --out "$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "root-cert: want exit 0, got $status" >&2; _show; return 1; }
  run "$PIGGY_BIN" tool write-cert 82 <"$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "write-cert 82: got $status" >&2; _show; return 1; }
  PROMPTS_BEFORE=$(operator_act_prompt_count "$AGENT_LOG")
}

# The intermediate: minted in the holder, requested through it, signed by
# the card under a ONE-hour profile (shorter than the leaf profile's 720
# hours, so the leaf's notAfter must be the intermediate's).
_intermediate() {
  SSH_AUTH_SOCK="$HOLDER_AGENT_SOCK" run "$PIGGY_BIN" holder mint --scope piggy-ca-intermediate-v1 --type p256
  [[ $status -eq 0 && $output == ecdsa-sha2-nistp256* ]] || { echo "mint failed ($status): $output" >&2; _show; return 1; }
  INT_PUB="$output"
  printf '%s\n' "$INT_PUB" >"$WORKDIR/int.pub"
  SSH_AUTH_SOCK="$HOLDER_AGENT_SOCK" run "$PIGGY_BIN" ca csr --key "$WORKDIR/int.pub" --cn "piggy-test intermediate" --out "$WORKDIR/int.csr"
  [[ $status -eq 0 ]] || { echo "csr failed ($status): $output" >&2; _show; return 1; }
  cat >"$CONFIG/ca-profiles/inter.toml" <<EOF
kind = "intermediate"
common_name = "piggy-test intermediate"
names = ["github.com"]
lifetime_hours = 1
[issuer]
slot = "82"
guid = "$GUID"
attestation_root = "$WORKDIR/f9.pem"
EOF
  SSH_AUTH_SOCK="$AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca sign --profile inter --out "$WORKDIR/int.pem" <"$WORKDIR/int.csr"
  [[ $status -eq 0 ]] || { echo "sign: want exit 0, got $status" >&2; _show; return 1; }
  PROMPTS_BEFORE=$(operator_act_prompt_count "$AGENT_LOG")
}

# A holder leaf profile NAME over the intermediate, with the given names.
_holder_profile() {
  local name="$1" names="$2" key="${3:-$INT_PUB}"
  cat >"$CONFIG/ca-profiles/$name.toml" <<EOF
kind = "leaf"
names = [$names]
lifetime_hours = 720
[issuer]
holder_key = "$key"
issuer_cert = "$WORKDIR/int.pem"
EOF
}

_leaf_request() {
  run "$PIGGY_BIN" ca leaf-csr --key-out "$WORKDIR/leaf.key" --cn github.com --out "$WORKDIR/leaf.csr"
  [[ $status -eq 0 ]] || { echo "leaf-csr: $status: $output" >&2; return 1; }
}

# `piggy ca issue` through SOCK with the holder profile PROFILE on CSR.
_issue_via() {
  local sock="$1" profile="$2" csr="$3"
  shift 3
  PIGGY_AUTH_SOCK="$sock" run --separate-stderr \
    "$PIGGY_BIN" ca issue --profile "$profile" --out "$WORKDIR/$profile.pem" "$@" <"$csr"
}

_assert_refusal() {
  local want="$1" why="$2" profile="$3"
  [[ $status -eq $want ]] || { echo "$why: want exit $want, got $status" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "$why: a refusal wrote to stdout: $output" >&2; return 1; }
  [[ $stderr != *"[piggy-test-askpass]"* ]] || { echo "$why: a refusal reached a PIN prompt" >&2; _show; return 1; }
  [[ ! -e $WORKDIR/$profile.pem ]] || { echo "$why: a refusal wrote the PEM" >&2; return 1; }
  [[ ! -e $STATE/rate/$profile ]] || { echo "$why: a refusal armed the rate limit" >&2; return 1; }
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq $PROMPTS_BEFORE ]] || {
    echo "$why: the card agent raised a prompt" >&2; _show; return 1; }
}

function the_holder_issues_a_leaf_under_its_intermediate_with_no_pin_and_no_act { # @test
  _root_in_slot_82
  _intermediate
  _holder_profile hleaf '"github.com", "api.github.com"'
  _leaf_request
  _issue_via "$HOLDER_AGENT_SOCK" hleaf "$WORKDIR/leaf.csr"
  [[ $status -eq 0 ]] || { echo "issue: want exit 0, got $status" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "--out given, yet stdout carried: $output" >&2; return 1; }
  [[ $stderr == *"the holder at"*"signs a leaf certificate under profile hleaf"*"no PIN, no touch, no act"* ]] || {
    echo "the notice does not describe the holder issuance: $stderr" >&2; return 1; }
  # No PIN anywhere: not the verb's askpass, not the card agent's.
  [[ $stderr != *"[piggy-test-askpass]"* ]] || { echo "a PIN prompt was reached" >&2; _show; return 1; }
  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq $PROMPTS_BEFORE ]] || { echo "the card agent prompted" >&2; _show; return 1; }
  [[ ! -e $WORKDIR/hleaf.pem.act ]] || { echo "a holder leaf has no act, yet one was written" >&2; return 1; }

  # The chain file: the leaf, then the intermediate, never the root.
  [[ $(grep -c 'BEGIN CERTIFICATE' "$WORKDIR/hleaf.pem") -eq 2 ]] || { echo "want two certificates in the chain" >&2; cat "$WORKDIR/hleaf.pem" >&2; return 1; }
  run "$PIGGY_BIN" cert show "$WORKDIR/hleaf.pem"
  [[ $status -eq 0 && $output == *"certificate 1 of 2"*"subject:            CN=github.com"*"certificate 2 of 2"*"subject:            CN=piggy-test intermediate"* ]] || {
    echo "cert show of the chain: $status: $output" >&2; return 1; }
  [[ $output == *"dns-names:          github.com, api.github.com"* ]] || { echo "the leaf lacks the profile's names: $output" >&2; return 1; }

  # Verified in piggy, with the key file, and by openssl.
  run "$PIGGY_BIN" ca verify --root "$WORKDIR/root.pem" --key "$WORKDIR/leaf.key" "$WORKDIR/hleaf.pem"
  [[ $status -eq 0 && $output != *"not ok"* ]] || { echo "piggy ca verify: $status: $output" >&2; return 1; }
  [[ $output == *"the signature of the leaf by the untrusted #1"* ]] || { echo "the leaf is not under the intermediate: $output" >&2; return 1; }
  openssl x509 -in "$WORKDIR/hleaf.pem" -out "$WORKDIR/leaf-only.pem" 2>/dev/null
  run openssl verify -CAfile "$WORKDIR/root.pem" -untrusted "$WORKDIR/int.pem" "$WORKDIR/leaf-only.pem"
  [[ $status -eq 0 ]] || { echo "openssl verify: $output" >&2; return 1; }

  # notAfter: the intermediate's hour, not the profile's 720.
  local leaf_end int_end
  leaf_end=$(openssl x509 -in "$WORKDIR/leaf-only.pem" -noout -enddate)
  int_end=$(openssl x509 -in "$WORKDIR/int.pem" -noout -enddate)
  [[ $leaf_end == "$int_end" ]] || { echo "the leaf outlives its intermediate: $leaf_end vs $int_end" >&2; return 1; }

  # The audit: the intermediate's line carries an act, the leaf's none.
  [[ $(wc -l <"$STATE/audit") -eq 2 ]] || { echo "want two audit lines:" >&2; cat "$STATE/audit" >&2; return 1; }
  grep -q '^piggy-ca issued profile=inter .* act=piggy-record-digest-v1@' "$STATE/audit" || { echo "the intermediate's line lacks its act:" >&2; cat "$STATE/audit" >&2; return 1; }
  local leaf_line
  leaf_line=$(grep '^piggy-ca issued profile=hleaf ' "$STATE/audit")
  [[ -n $leaf_line && $leaf_line != *" act="* ]] || { echo "the leaf's audit line is wrong: $leaf_line" >&2; return 1; }
  [[ $(cat "$STATE/rate/hleaf") =~ ^[0-9]+$ ]] || { echo "no rate stamp for the holder profile" >&2; return 1; }
}

function a_non_holder_agent_an_unserved_key_act_out_and_sign_are_refused { # @test
  _root_in_slot_82
  _intermediate
  _holder_profile hleaf '"github.com"'
  _leaf_request
  # The card agent is not a holder: exit 6, nothing read, nothing written.
  _issue_via "$AGENT_SOCK" hleaf "$WORKDIR/leaf.csr"
  _assert_refusal 6 "the card agent on the socket" hleaf
  [[ $stderr == *"is not a holder"* ]] || { echo "the refusal does not say why: $stderr" >&2; return 1; }
  # No agent at all: exit 6 too.
  _issue_via /nonexistent hleaf "$WORKDIR/leaf.csr"
  _assert_refusal 6 "no agent" hleaf
  # A P-256 key the holder does not serve.
  ssh-keygen -t ecdsa -b 256 -N "" -q -f "$WORKDIR/soft" -C soft
  _holder_profile unserved '"github.com"' "$(cat "$WORKDIR/soft.pub")"
  _issue_via "$HOLDER_AGENT_SOCK" unserved "$WORKDIR/leaf.csr"
  _assert_refusal 6 "a key the holder does not serve" unserved
  [[ $stderr == *"does not serve"* ]] || { echo "the refusal does not say why: $stderr" >&2; return 1; }
  # --act-out: a holder leaf has no act.
  _issue_via "$HOLDER_AGENT_SOCK" hleaf "$WORKDIR/leaf.csr" --act-out "$WORKDIR/no.act"
  _assert_refusal 2 "--act-out" hleaf
  [[ ! -e $WORKDIR/no.act ]] || { echo "an act was written" >&2; return 1; }
  # `sign` with a holder profile: a leaf profile is the wrong kind for it.
  PIGGY_AUTH_SOCK="$HOLDER_AGENT_SOCK" run --separate-stderr \
    "$PIGGY_BIN" ca sign --profile hleaf --out "$WORKDIR/hleaf.pem" <"$WORKDIR/leaf.csr"
  _assert_refusal 3 "sign with the holder profile" hleaf
  [[ $stderr == *"issues an intermediate certificate; this profile is leaf"* ]] || {
    echo "the refusal does not name the kinds: $stderr" >&2; return 1; }
}

function a_holder_profile_naming_outside_the_intermediates_constraints_is_exit_3_before_the_request { # @test
  _root_in_slot_82
  _intermediate
  _holder_profile wide '"github.com", "evil.example"'
  _issue_via "$HOLDER_AGENT_SOCK" wide /dev/null
  _assert_refusal 3 "names outside the intermediate's constraints" wide
  [[ $stderr == *"name constraints do not admit"*"evil.example"* ]] || {
    echo "the refusal does not name the constraint: $stderr" >&2; return 1; }
}
