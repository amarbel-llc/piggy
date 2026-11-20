#! /usr/bin/env bats
#
# The guards of `just explore-fdr0007-chain-card` and
# `just explore-fdr0007-chain-holder` (FDR 0007, the chain test on the
# pilot root), driven with FAKE tools on PATH and no card: the card half
# refuses without CARD=real, a GUID that is not 32 hex digits, a request
# file that is missing, or no agent socket, each before any tool runs; a
# failed S0 read (the root or the attestation) bails out BEFORE the Enter
# prompt that precedes the card signature; a good run writes the two
# profiles from its arguments and drives `ca sign`, the act checks, `ca
# issue`, the act checks and the read-back in that order. The holder
# half's dry-run (the default) prints its steps and calls nothing. The
# card path and the holder itself are not exercised here; the recipes stay
# UNRUN against a real card and a real holder until the card hour.
#
# Needs only bash, just and the justfile; run via
# `just test-bats-conformance-chain-guard` or `just test-bats-file`.

setup() {
  [[ -n ${PIGGY_JUSTFILE:-} && -f ${PIGGY_JUSTFILE:-} ]] || skip "PIGGY_JUSTFILE unset; run via just test-bats-conformance-chain-guard"
  JUSTFILE="$PIGGY_JUSTFILE"
  command -v just >/dev/null || skip "just not on PATH"
  WORK="$(mktemp -d -t chainguard.XXXXXX)"
  FAKE="$WORK/bin"
  mkdir -p "$FAKE"
  printf 'request\n' >"$WORK/int.csr"
  printf 'request\n' >"$WORK/leaf.csr"
  # fibby as a shim that records its calls; openssl answers like the real
  # one for the read-back's few questions and records its calls too.
  printf '#!/usr/bin/env bash\necho "fibby $*" >>"%s/calls"\nexit 0\n' "$WORK" >"$FAKE/fibby"
  chmod +x "$FAKE/fibby"
  cat >"$FAKE/openssl" <<EOF
#!/usr/bin/env bash
echo "openssl \$*" >>"$WORK/calls"
case "\$1" in
  x509)
    in= prev= text=0 pub=0
    for a in "\$@"; do
      [[ \$prev == -in ]] && in=\$a
      [[ \$a == -text ]] && text=1
      [[ \$a == -pubkey ]] && pub=1
      prev=\$a
    done
    if ((text)); then
      case "\$in" in
        *int.pem) echo "CA:TRUE, pathlen:0" ;;
        *) echo "DNS:github.com, DNS:api.github.com"; echo "CA:FALSE" ;;
      esac
    fi
    ((pub)) && echo "key"
    ;;
  req) echo "key" ;;
esac
exit 0
EOF
  chmod +x "$FAKE/openssl"
  export WORK
}

teardown() {
  [[ -n ${WORK:-} ]] && rm -rf "$WORK" 2>/dev/null || true
}

GUID=0123456789ABCDEF0123456789ABCDEF

# A fake piggy whose reads and signatures all succeed: `ca sign` and `ca
# issue` write their --out and its .act and one audit line, `act canon`
# names the right the act's file name implies.
_fake_piggy_ok() {
  cat >"$FAKE/piggy" <<EOF
#!/usr/bin/env bash
echo "piggy \$*" >>"$WORK/calls"
case "\$1 \$2" in
  "tool cert") printf -- '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n' ;;
  "ca sign"|"ca issue")
    while [[ \$# -gt 0 ]]; do [[ \$1 == --out ]] && { printf 'pem\n' >"\$2"; printf 'act\n' >"\$2.act"; }; shift; done
    echo "piggy-ca issued" >>"\$PIGGY_CA_STATE/audit" ;;
  "act canon") case "\$3" in *int.pem.act) echo "- right = piggy:x509-ca" ;; *) echo "- right = piggy:x509-leaf" ;; esac ;;
  "cert show") case "\$3" in *int.pem) echo "basic-constraints:  critical CA:TRUE pathlen:0" ;; *) echo "dns-names:          github.com, api.github.com"; echo "basic-constraints:  critical CA:FALSE" ;; esac ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$FAKE/piggy"
}

# A fake piggy whose `tool cert` (the root read) fails.
_fake_piggy_failing_cert() {
  cat >"$FAKE/piggy" <<EOF
#!/usr/bin/env bash
echo "piggy \$*" >>"$WORK/calls"
case "\$1 \$2" in
  "tool cert") echo "piggy tool: slot 82: no certificate" >&2; exit 1 ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$FAKE/piggy"
}

# The card half with the given positional arguments
# (GUID INT_CSR LEAF_CSR INT_CN NAMES INT_HOURS LEAF_HOURS OUT CARD).
_card() {
  echo "# justfile under test: $JUSTFILE" >&2
  SSH_AUTH_SOCK="$WORK/agent.sock" PATH="$FAKE:$PATH" run just --justfile "$JUSTFILE" --working-directory "$WORK" \
    explore-fdr0007-chain-card "$@"
}

_holder() {
  PATH="$FAKE:$PATH" run just --justfile "$JUSTFILE" --working-directory "$WORK" \
    explore-fdr0007-chain-holder "$@"
}

function the_card_half_refuses_to_run_without_card_real_and_calls_nothing { # @test
  _fake_piggy_ok
  _card "$GUID" "$WORK/int.csr" "$WORK/leaf.csr"
  [[ $status -eq 2 && $output == *"OPERATOR'S CARD"* && $output == *"PIN + touch twice"* ]] || {
    echo "want exit 2 and the card warning, got $status: $output" >&2; return 1; }
  [[ ! -e $WORK/calls ]] || { echo "a tool was called before the CARD check: $(cat "$WORK/calls")" >&2; return 1; }
}

function the_card_half_refuses_a_bad_guid_a_missing_request_or_no_agent_before_any_call { # @test
  _fake_piggy_ok
  _card "not-a-guid" "$WORK/int.csr" "$WORK/leaf.csr" "piggy-test int" github.com 168 720 "$WORK/out" real
  [[ $status -eq 2 && $output == *"GUID must be 32 hex digits"* ]] || {
    echo "want exit 2 naming GUID, got $status: $output" >&2; return 1; }
  _card "$GUID" "$WORK/missing.csr" "$WORK/leaf.csr" "piggy-test int" github.com 168 720 "$WORK/out" real
  [[ $status -eq 2 && $output == *"INT_CSR"*"not a file"* ]] || {
    echo "want exit 2 naming INT_CSR, got $status: $output" >&2; return 1; }
  PATH="$FAKE:$PATH" run env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK just --justfile "$JUSTFILE" --working-directory "$WORK" \
    explore-fdr0007-chain-card "$GUID" "$WORK/int.csr" "$WORK/leaf.csr" "piggy-test int" github.com 168 720 "$WORK/out" real
  [[ $status -eq 2 && $output == *"SSH_AUTH_SOCK is not set"* ]] || {
    echo "want exit 2 naming SSH_AUTH_SOCK, got $status: $output" >&2; return 1; }
  [[ ! -e $WORK/calls ]] || { echo "a tool was called before the preconditions held: $(cat "$WORK/calls")" >&2; return 1; }
}

function a_failed_root_read_bails_out_before_the_card_is_asked_to_sign { # @test
  _fake_piggy_failing_cert
  _card "$GUID" "$WORK/int.csr" "$WORK/leaf.csr" "piggy-test int" github.com 168 720 "$WORK/out" real </dev/null
  [[ $status -eq 1 ]] || { echo "want exit 1, got $status: $output" >&2; return 1; }
  [[ $output == *"not ok 1 - slot 82 certificate (the pilot root) saved"* ]] || {
    echo "the failed read is not a not-ok line: $output" >&2; return 1; }
  [[ $output == *"Bail out!"*"not asked to sign"* ]] || { echo "no bail-out line: $output" >&2; return 1; }
  [[ $output != *"Press Enter"* ]] || { echo "the signing prompt was reached after a failed read: $output" >&2; return 1; }
  if grep -qE '^piggy ca (sign|issue)' "$WORK/calls"; then
    echo "a signing verb ran: $(cat "$WORK/calls")" >&2; return 1
  fi
}

function a_good_run_writes_the_profiles_and_drives_sign_then_issue_in_order { # @test
  _fake_piggy_ok
  _card "$GUID" "$WORK/int.csr" "$WORK/leaf.csr" "piggy-test int" github.com,api.github.com 168 720 "$WORK/out" real <<<$'\n\n'
  [[ $status -eq 0 ]] || { echo "want exit 0, got $status: $output" >&2; return 1; }
  # The profiles carry the arguments: the CN, the names as a TOML list, the GUID, slot 82.
  local int leaf
  int=$(cat "$WORK/out/config/ca-profiles/int.toml")
  leaf=$(cat "$WORK/out/config/ca-profiles/leaf.toml")
  for want in 'kind = "intermediate"' 'common_name = "piggy-test int"' 'names = ["github.com", "api.github.com"]' 'lifetime_hours = 168' 'slot = "82"' "guid = \"$GUID\""; do
    [[ $int == *"$want"* ]] || { echo "int.toml lacks '$want':" >&2; echo "$int" >&2; return 1; }
  done
  for want in 'kind = "leaf"' 'names = ["github.com", "api.github.com"]' 'lifetime_hours = 720' "guid = \"$GUID\""; do
    [[ $leaf == *"$want"* ]] || { echo "leaf.toml lacks '$want':" >&2; echo "$leaf" >&2; return 1; }
  done
  [[ $leaf != *common_name* ]] || { echo "a leaf profile has no common_name" >&2; return 1; }
  # The calls, in order: the two reads, sign, its act checks, issue, its act checks, the read-back.
  local calls
  calls=$(grep -E '^piggy (tool|ca|act) ' "$WORK/calls" | awk '{print $2, $3}' | tr '\n' ';')
  [[ $calls == "tool cert;tool attest-verify;ca sign;act verify;act canon;ca issue;act verify;act canon;tool cert;"* ]] || {
    echo "unexpected call order: $calls" >&2; return 1; }
  [[ $output == *"ok "*"- ca sign:"* && $output == *"ok "*"- ca issue:"* && $output == *"two audit lines"* ]] || {
    echo "the ok lines are missing: $output" >&2; return 1; }
  [[ $output != *"not ok"* ]] || { echo "a check failed in the good run: $output" >&2; return 1; }
  [[ $output == *"2 PIN + 2 touch"* ]] || { echo "the prompts do not state the PIN and touch count: $output" >&2; return 1; }
}

function the_holder_half_dry_run_prints_its_steps_and_calls_nothing { # @test
  _fake_piggy_ok
  _holder "piggy-test int" github.com "$WORK/out"
  [[ $status -eq 0 && $output == *"dry-run"* && $output == *"holder mint --scope piggy-ca-intermediate-v1"* && $output == *"ca leaf-csr"* ]] || {
    echo "want a dry-run listing, got $status: $output" >&2; return 1; }
  # The header's version reads are the only calls a dry-run may make.
  if [[ -e $WORK/calls ]] && grep -vqE '^(piggy|fibby) --version' "$WORK/calls"; then
    echo "a tool was called in a dry-run: $(cat "$WORK/calls")" >&2; return 1
  fi
  [[ ! -e $WORK/out ]] || { echo "a dry-run made the output directory" >&2; return 1; }
}
