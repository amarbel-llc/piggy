#! /usr/bin/env bats
#
# `piggy ca leaf-csr --key-out FILE --cn NAME [--out FILE]` (FDR 0007: the
# card-free leaf key of the host that serves the leaf): no card, no agent,
# no holder. A fresh P-256 key lands in FILE as PKCS#8 PEM with mode 0600,
# and the request (PEM, to --out or stdout) names that key and the one CN
# with no SAN; the public key printed on stderr is the same key. openssl
# is the oracle for the request's self-signature and the key equality, as
# the other ca lanes use it. Refused with nothing written and nothing
# changed: a key file that exists (exit 1), a CN that is not a plain DNS
# name (exit 2); a request that cannot be written takes the key this run
# made with it. No refusal and no success reaches a PIN prompt.
#
# Required env (supplied by `just test-bats-conformance-ca-leaf-csr`):
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

# `run --separate-stderr` needs bats 1.5.0+.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PIGGY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/piggy ]]; then
    PIGGY_BIN="$REPO_ROOT/target/debug/piggy"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable; run via just test-bats-conformance-ca-leaf-csr"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET: nothing here may reach a
  # prompt; the test askpass leaves a banner on stderr if one does.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK PIGGY_TEST_FIB_PIN

  WORKDIR="$(mktemp -d -t leafcsr.XXXXXX)"
  # No PC/SC daemon answers here, and the verb must not look for one.
  export PCSCLITE_CSOCK_NAME="$WORKDIR/no-pcscd.comm"
}

teardown() {
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

_leaf_csr() {
  run --separate-stderr "$PIGGY_BIN" ca leaf-csr "$@"
}

_show() {
  printf 'status: %s\noutput: %s\nstderr: %s\n' "${status:-}" "${output:-}" "${stderr:-}" >&2
}

# The checks every made request passes: the key file private and PKCS#8,
# the request self-signed by it with the CN and no SAN, the stderr line
# the same key.
_assert_made() {
  local key="$1" csr="$2" cn="$3"
  # Later `run`s overwrite $stderr; keep this verb's.
  local stderr="$stderr"
  [[ $stderr != *"[piggy-test-askpass]"* ]] || { echo "a PIN prompt was reached" >&2; _show; return 1; }
  [[ $(stat -c %a "$key") == 600 ]] || { echo "key mode $(stat -c %a "$key"), want 600" >&2; return 1; }
  [[ $(head -n1 "$key") == "-----BEGIN PRIVATE KEY-----" ]] || { echo "the key is not PKCS#8 PEM:" >&2; head -n1 "$key" >&2; return 1; }
  run openssl req -in "$csr" -noout -verify -subject
  [[ $status -eq 0 && $output == *"verify OK"* && $output == *"CN"*"$cn"* ]] || {
    echo "openssl did not verify the request: $output" >&2; cat "$csr" >&2; return 1; }
  [[ $(openssl req -in "$csr" -noout -text) != *"Subject Alternative Name"* ]] || {
    echo "the request asks for a SAN" >&2; return 1; }
  openssl pkey -in "$key" -pubout >"$WORKDIR/from-key.pem" 2>/dev/null
  openssl req -in "$csr" -noout -pubkey >"$WORKDIR/from-csr.pem"
  cmp -s "$WORKDIR/from-key.pem" "$WORKDIR/from-csr.pem" || { echo "the request's key is not the key file's" >&2; return 1; }
  # The stderr notice names the key file and prints the public key as an
  # OpenSSH line that is the same key.
  [[ $stderr == *"key written to $key"* ]] || { echo "no key-written notice: $stderr" >&2; return 1; }
  sed -n 's/.*public key: \(ecdsa-sha2-nistp256 [^ ]* [^ ]*\).*/\1/p' <<<"$stderr" >"$WORKDIR/leaf.pub"
  [[ -s $WORKDIR/leaf.pub ]] || { echo "no OpenSSH public key line on stderr: $stderr" >&2; return 1; }
  ssh-keygen -e -m PKCS8 -f "$WORKDIR/leaf.pub" >"$WORKDIR/from-line.pem"
  cmp -s "$WORKDIR/from-line.pem" "$WORKDIR/from-key.pem" || { echo "the stderr public key is not the key file's" >&2; return 1; }
}

function a_key_and_its_request_are_made_with_no_agent_and_no_card { # @test
  _leaf_csr --key-out "$WORKDIR/leaf.key" --cn github.com
  [[ $status -eq 0 ]] || { echo "want exit 0, got $status" >&2; _show; return 1; }
  [[ $output == "-----BEGIN CERTIFICATE REQUEST-----"* ]] || { echo "stdout is not the request PEM: $output" >&2; return 1; }
  printf '%s\n' "$output" >"$WORKDIR/leaf.csr"
  _assert_made "$WORKDIR/leaf.key" "$WORKDIR/leaf.csr" github.com
}

function out_writes_the_request_file_and_stdout_stays_empty { # @test
  _leaf_csr --key-out "$WORKDIR/leaf.key" --cn api.github.com --out "$WORKDIR/leaf.csr"
  [[ $status -eq 0 ]] || { echo "want exit 0, got $status" >&2; _show; return 1; }
  [[ -z $output ]] || { echo "--out given, yet stdout carried: $output" >&2; return 1; }
  [[ -s $WORKDIR/leaf.csr ]] || { echo "no request at --out" >&2; return 1; }
  _assert_made "$WORKDIR/leaf.key" "$WORKDIR/leaf.csr" api.github.com
  # Two runs never share a key.
  _leaf_csr --key-out "$WORKDIR/other.key" --cn api.github.com --out "$WORKDIR/other.csr"
  [[ $status -eq 0 ]] || { echo "second run: want exit 0, got $status" >&2; _show; return 1; }
  ! cmp -s "$WORKDIR/leaf.key" "$WORKDIR/other.key" || { echo "two runs made the same key" >&2; return 1; }
}

function a_key_file_that_exists_is_refused_and_left_alone { # @test
  echo keep >"$WORKDIR/leaf.key"
  chmod 644 "$WORKDIR/leaf.key"
  _leaf_csr --key-out "$WORKDIR/leaf.key" --cn github.com --out "$WORKDIR/leaf.csr"
  [[ $status -eq 1 ]] || { echo "want exit 1, got $status" >&2; _show; return 1; }
  [[ $stderr == *"exists"* ]] || { echo "the refusal does not say the file exists: $stderr" >&2; return 1; }
  [[ -z $output ]] || { echo "a refusal wrote to stdout: $output" >&2; return 1; }
  [[ $(cat "$WORKDIR/leaf.key") == keep && $(stat -c %a "$WORKDIR/leaf.key") == 644 ]] || {
    echo "the existing key file was touched" >&2; return 1; }
  [[ ! -e $WORKDIR/leaf.csr ]] || { echo "a refusal wrote the request" >&2; return 1; }
}

function a_cn_that_is_not_a_plain_dns_name_is_usage_and_makes_no_key { # @test
  local bad
  for bad in "*.github.com" "a b" "" "github..com"; do
    _leaf_csr --key-out "$WORKDIR/leaf.key" --cn "$bad" --out "$WORKDIR/leaf.csr"
    [[ $status -eq 2 ]] || { echo "CN '$bad': want exit 2, got $status" >&2; _show; return 1; }
    [[ $stderr == *"not a plain DNS name"* ]] || { echo "CN '$bad': the refusal does not say why: $stderr" >&2; return 1; }
    [[ ! -e $WORKDIR/leaf.key && ! -e $WORKDIR/leaf.csr ]] || { echo "CN '$bad': something was written" >&2; return 1; }
  done
}

function a_request_that_cannot_be_written_takes_the_new_key_with_it { # @test
  _leaf_csr --key-out "$WORKDIR/leaf.key" --cn github.com --out "$WORKDIR/nonexistent/leaf.csr"
  [[ $status -eq 1 ]] || { echo "want exit 1, got $status" >&2; _show; return 1; }
  [[ $stderr == *"was removed"* ]] || { echo "the message does not say the key was removed: $stderr" >&2; return 1; }
  [[ ! -e $WORKDIR/leaf.key ]] || { echo "the key this run made stayed behind" >&2; return 1; }
}
