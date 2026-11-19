#! /usr/bin/env bats
#
# The guards of `just explore-fdr0007-root-cert` (FDR 0007, the pilot root
# from slot 82), driven with FAKE tools on PATH and no card: the recipe
# refuses without CARD=real, refuses a missing PKCS#11 module or provider,
# and, when a step-1 card read fails (the rollback or the evidence not
# saved), bails out BEFORE the Enter prompt that precedes the card
# signature. The card path itself (openssl through the PKCS#11 provider)
# is not exercised here; the recipe stays UNRUN against a real card until
# the card hour.
#
# Needs only bash, just and the justfile; run via
# `just test-bats-conformance-root-cert-guard` or `just test-bats-file`.

setup() {
  # The justfile under test, named by the recipe (PIGGY_JUSTFILE): the
  # test file's own location may be a store snapshot of the tree whose
  # justfile is older than the worktree's.
  [[ -n ${PIGGY_JUSTFILE:-} && -f ${PIGGY_JUSTFILE:-} ]] || skip "PIGGY_JUSTFILE unset; run via just test-bats-conformance-root-cert-guard"
  JUSTFILE="$PIGGY_JUSTFILE"
  command -v just >/dev/null || skip "just not on PATH"
  WORK="$(mktemp -d -t rootguard.XXXXXX)"
  FAKE="$WORK/bin"
  mkdir -p "$FAKE" "$WORK/provider"
  : >"$WORK/libfake-pkcs11.so"
  : >"$WORK/provider/pkcs11.so"
  # Every tool the recipe checks for, as a shim that records its calls.
  for tool in openssl ssh-keygen pkcs11-tool; do
    printf '#!/usr/bin/env bash\necho "%s $*" >>"%s/calls"\nexit 0\n' "$tool" "$WORK" >"$FAKE/$tool"
    chmod +x "$FAKE/$tool"
  done
  export WORK
}

teardown() {
  [[ -n ${WORK:-} ]] && rm -rf "$WORK" 2>/dev/null || true
}

# A fake piggy whose `tool cert` (the rollback read) fails; everything
# else answers with a line.
_fake_piggy_failing_cert() {
  cat >"$FAKE/piggy" <<EOF
#!/usr/bin/env bash
echo "piggy \$*" >>"$WORK/calls"
case "\$1 \$2" in
  "tool cert") echo "piggy tool: slot 82: no certificate" >&2; exit 1 ;;
  "tool pubkey") echo "ecdsa-sha2-nistp256 AAAA PIV_slot_82" ;;
  "tool attest") echo "-----BEGIN CERTIFICATE-----" ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$FAKE/piggy"
}

_recipe() {
  # Named in the diagnostics, so a wrong justfile is visible in a failure.
  echo "# justfile under test: $JUSTFILE (bail-out lines: $(grep -c 'Bail out!' "$JUSTFILE" 2>/dev/null || echo 0))" >&2
  PATH="$FAKE:$PATH" run just --justfile "$JUSTFILE" --working-directory "$WORK" \
    explore-fdr0007-root-cert "$@"
}

function the_recipe_refuses_to_run_without_card_real { # @test
  _fake_piggy_failing_cert
  _recipe "piggy-test-root" github.com 3650 "$WORK/libfake-pkcs11.so" "$WORK/provider" "pkcs11:x" "$WORK/out"
  [[ $status -eq 2 && $output == *"OPERATOR'S CARD"* ]] || {
    echo "want exit 2 and the card warning, got $status: $output" >&2; return 1; }
  [[ ! -e $WORK/calls ]] || { echo "a tool was called before the CARD check: $(cat "$WORK/calls")" >&2; return 1; }
}

function the_recipe_refuses_a_missing_module_or_provider_before_any_card_read { # @test
  _fake_piggy_failing_cert
  _recipe "piggy-test-root" github.com 3650 "$WORK/nonexistent.so" "$WORK/provider" "pkcs11:x" "$WORK/out" real
  [[ $status -eq 2 && $output == *"MODULE must name"* ]] || {
    echo "want exit 2 naming MODULE, got $status: $output" >&2; return 1; }
  _recipe "piggy-test-root" github.com 3650 "$WORK/libfake-pkcs11.so" "$WORK/nonexistent" "pkcs11:x" "$WORK/out" real
  [[ $status -eq 2 && $output == *"PROVIDER_PATH must hold"* ]] || {
    echo "want exit 2 naming PROVIDER_PATH, got $status: $output" >&2; return 1; }
  [[ ! -e $WORK/calls ]] || { echo "a tool was called before the preconditions held: $(cat "$WORK/calls")" >&2; return 1; }
}

# A fake piggy whose reads all succeed, so the recipe reaches the signing
# call; the fake openssl records its argv and writes the -out file empty.
_fake_piggy_reads_ok() {
  cat >"$FAKE/piggy" <<EOF
#!/usr/bin/env bash
echo "piggy \$*" >>"$WORK/calls"
case "\$1 \$2" in
  "tool pubkey") echo "ecdsa-sha2-nistp256 AAAA PIV_slot_82" ;;
  "tool attest"|"tool cert") echo "-----BEGIN CERTIFICATE-----" ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$FAKE/piggy"
  cat >"$FAKE/openssl" <<EOF
#!/usr/bin/env bash
echo "openssl \$*" >>"$WORK/calls"
if [[ \$1 == req ]]; then
  printf '%s\n' "\$@" >"$WORK/req.argv"
  while [[ \$# -gt 0 ]]; do [[ \$1 == -out ]] && : >"\$2"; shift; done
fi
exit 0
EOF
  chmod +x "$FAKE/openssl"
}

# OpenSSL 3 acts on each provider option as it parses it: the provider
# path must be named before the provider, or pkcs11 is looked up in
# openssl's own module directory (seen on the card host, 2026-11-19).
function the_signing_call_names_the_provider_path_before_the_provider { # @test
  _fake_piggy_reads_ok
  _recipe "piggy-test-root" github.com 180 "$WORK/libfake-pkcs11.so" "$WORK/provider" "pkcs11:x" "$WORK/out" real <<<""
  [[ -s $WORK/req.argv ]] || { echo "openssl req was not reached: $output" >&2; return 1; }
  [[ $output == *"the card signed the root certificate"* ]] || {
    echo "no signed line after a successful openssl req: $output" >&2; return 1; }
  local path_at provider_at
  path_at=$(grep -n -x -- '-provider-path' "$WORK/req.argv" | cut -d: -f1)
  provider_at=$(grep -n -x -- '-provider' "$WORK/req.argv" | head -n1 | cut -d: -f1)
  [[ -n $path_at && -n $provider_at && $path_at -lt $provider_at ]] || {
    echo "want -provider-path before the first -provider; argv:" >&2; cat "$WORK/req.argv" >&2; return 1; }
  # The path named is the one given, and the module reaches the provider
  # through its environment variable.
  grep -q -x -F -- "$WORK/provider" "$WORK/req.argv" || { echo "PROVIDER_PATH not in argv" >&2; return 1; }
  # A read-back failure after the signature says so, instead of implying
  # nothing happened (the fake openssl prints no certificate text).
  [[ $output == *"the signature was made and"*"root.pem exists"* ]] || {
    echo "no after-signature notice: $output" >&2; return 1; }
}

function a_failed_rollback_read_bails_out_before_the_card_is_asked_to_sign { # @test
  _fake_piggy_failing_cert
  _recipe "piggy-test-root" github.com 3650 "$WORK/libfake-pkcs11.so" "$WORK/provider" "pkcs11:x" "$WORK/out" real </dev/null
  [[ $status -eq 1 ]] || { echo "want exit 1, got $status: $output" >&2; return 1; }
  [[ $output == *"not ok 2 - slot 82 stored certificate saved (the rollback)"* ]] || {
    echo "the failed read is not a not-ok line: $output" >&2; return 1; }
  [[ $output == *"Bail out!"*"rollback"* ]] || { echo "no bail-out line: $output" >&2; return 1; }
  [[ $output != *"Press Enter to sign"* ]] || { echo "the signing prompt was reached after a failed read: $output" >&2; return 1; }
  # Nothing past step 1 ran: no openssl, no pkcs11-tool.
  if grep -qE '^(openssl|pkcs11-tool) ' "$WORK/calls"; then
    echo "a signing-side tool ran: $(cat "$WORK/calls")" >&2; return 1
  fi
  # The recipe's out directory holds only what step 1 wrote.
  [[ ! -e $WORK/out/root.pem && ! -e $WORK/out/root.cnf ]] || {
    echo "signing artifacts exist after a bail-out" >&2; return 1; }
}
