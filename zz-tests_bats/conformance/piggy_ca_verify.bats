#! /usr/bin/env bats
#
# `piggy ca verify` and `piggy cert show` (FDR 0007) over chains openssl
# makes here: a root with CA:TRUE pathlen:1, keyCertSign and name
# constraints (permitted DNS github.com, every IP excluded), an
# intermediate with pathlen 0 and the same constraints, and leaves. A
# good chain passes as TAP (every point ok, exit 0), also with the
# intermediate in a chain file behind the leaf and with --key naming the
# leaf's key in any of its forms; a leaf for a foreign name, a wrong key
# and a tampered signature fail with the check named (exit 1); a file
# that is not a certificate is exit 4; a missing --root is usage. `cert
# show` prints the root's and the leaf's fields and the DER sha256 openssl
# computes. No card, no agent.
#
# Required env (supplied by `just test-bats-conformance-ca-verify`):
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
    skip "PIGGY_BIN unset or not executable; run via just test-bats-conformance-ca-verify"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"

  WORKDIR="$(mktemp -d -t caverify.XXXXXX)"
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
  export PCSCLITE_CSOCK_NAME="$WORKDIR/no-pcscd.comm"
  _chain
}

teardown() {
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# root.pem (self-signed, the FDR root profile), int.pem (under it, pathlen
# 0), leaf.pem (under int, github.com + api.github.com), foreign.pem
# (under int, example.org), direct.pem (under the root).
_chain() {
  cat >"$WORKDIR/ext.cnf" <<EOF
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = piggy-test root
[ v3_root ]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:github.com, excluded;IP:0.0.0.0/0.0.0.0, excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ v3_int ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:github.com, excluded;IP:0.0.0.0/0.0.0.0, excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ v3_leaf ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:github.com, DNS:api.github.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ v3_foreign ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:example.org
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/root.key" 2>/dev/null
  openssl req -x509 -new -key "$WORKDIR/root.key" -config "$WORKDIR/ext.cnf" -extensions v3_root \
    -days 3650 -sha256 -out "$WORKDIR/root.pem" 2>/dev/null
  _issue int "/CN=piggy-test intermediate" root v3_int
  _issue leaf /CN=github.com int v3_leaf
  _issue foreign /CN=example.org int v3_foreign
  _issue direct /CN=api.github.com root v3_leaf
  cat "$WORKDIR/leaf.pem" "$WORKDIR/int.pem" >"$WORKDIR/chain.pem"
}

# _issue NAME SUBJECT ISSUER SECTION: a fresh key, a request, a
# certificate signed by ISSUER's key with SECTION's extensions.
_issue() {
  local name="$1" subject="$2" issuer="$3" section="$4"
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/$name.key" 2>/dev/null
  openssl req -new -key "$WORKDIR/$name.key" -subj "$subject" -out "$WORKDIR/$name.csr" 2>/dev/null
  openssl x509 -req -in "$WORKDIR/$name.csr" -CA "$WORKDIR/$issuer.pem" -CAkey "$WORKDIR/$issuer.key" \
    -CAcreateserial -days 30 -sha256 -extfile "$WORKDIR/ext.cnf" -extensions "$section" \
    -out "$WORKDIR/$name.pem" 2>/dev/null
}

_verify() {
  run --separate-stderr "$PIGGY_BIN" ca verify "$@"
}

_assert_valid() {
  [[ $status -eq 0 ]] || { echo "$1: want exit 0, got $status: $output / $stderr" >&2; return 1; }
  [[ $output == "TAP version 14"* && $output == *$'\n1..'* && $output != *"not ok"* ]] || {
    echo "$1: not an all-ok TAP: $output" >&2; return 1; }
}

function a_good_chain_passes_as_tap_in_every_file_shape { # @test
  _verify --root "$WORKDIR/root.pem" --untrusted "$WORKDIR/int.pem" "$WORKDIR/leaf.pem"
  _assert_valid "root + untrusted + leaf"
  for want in "ok 1 - a path from the leaf to the root" \
    "the signature of the leaf by the untrusted #1" \
    "the untrusted #1's pathlen 0 admits 0 intermediate(s) below it" \
    "the name constraints of the root admit the leaf's names" \
    "the leaf's extendedKeyUsage has serverAuth"; do
    [[ $output == *"$want"* ]] || { echo "missing '$want':" >&2; echo "$output" >&2; return 1; }
  done
  # The chain file: the leaf first, the intermediate behind it.
  _verify --root "$WORKDIR/root.pem" "$WORKDIR/chain.pem"
  _assert_valid "chain file"
  # The pilot shape: the leaf under the root directly.
  _verify --root "$WORKDIR/root.pem" "$WORKDIR/direct.pem"
  _assert_valid "direct"
  # The key, in each form it is kept in.
  openssl pkey -in "$WORKDIR/leaf.key" -pubout >"$WORKDIR/leaf.pub.pem" 2>/dev/null
  for key in "$WORKDIR/leaf.key" "$WORKDIR/leaf.pub.pem" "$WORKDIR/leaf.csr"; do
    _verify --root "$WORKDIR/root.pem" --untrusted "$WORKDIR/int.pem" --key "$key" "$WORKDIR/leaf.pem"
    _assert_valid "--key ${key##*/}"
    [[ $output == *"ok "*"- the leaf's key is the given key"* ]] || { echo "no key point for $key: $output" >&2; return 1; }
  done
  # A time before the chain existed: every certificate is not yet valid.
  _verify --root "$WORKDIR/root.pem" --untrusted "$WORKDIR/int.pem" --at 1000000000 "$WORKDIR/leaf.pem"
  [[ $status -eq 1 && $output == *"not ok "*"- the leaf is valid at 2001-09-09T01:46:40Z"* ]] || {
    echo "--at: want exit 1 naming the time, got $status: $output" >&2; return 1; }
}

function a_foreign_name_a_wrong_key_and_a_tampered_leaf_fail_with_the_check_named { # @test
  _verify --root "$WORKDIR/root.pem" --untrusted "$WORKDIR/int.pem" "$WORKDIR/foreign.pem"
  [[ $status -eq 1 ]] || { echo "foreign: want exit 1, got $status: $output" >&2; return 1; }
  [[ $output == *"not ok "*"- the name constraints of the untrusted #1 admit the leaf's names"* ]] || {
    echo "foreign: the constraint check is not the failing one: $output" >&2; return 1; }
  [[ $output == *"example.org is not under a permitted DNS subtree"* ]] || {
    echo "foreign: the detail does not name the name: $output" >&2; return 1; }
  [[ $stderr == *"the chain does not verify"* ]] || { echo "foreign: stderr: $stderr" >&2; return 1; }

  _verify --root "$WORKDIR/root.pem" --untrusted "$WORKDIR/int.pem" --key "$WORKDIR/int.key" "$WORKDIR/leaf.pem"
  [[ $status -eq 1 && $output == *"not ok "*"- the leaf's key is the given key"* ]] || {
    echo "wrong key: want exit 1 naming the key check, got $status: $output" >&2; return 1; }

  # A byte of the leaf's signature flipped (the last DER byte).
  openssl x509 -in "$WORKDIR/leaf.pem" -outform DER -out "$WORKDIR/leaf.der"
  printf '\x00' | dd of="$WORKDIR/leaf.der" bs=1 seek=$(($(stat -c %s "$WORKDIR/leaf.der") - 1)) conv=notrunc 2>/dev/null
  _verify --root "$WORKDIR/root.pem" --untrusted "$WORKDIR/int.pem" "$WORKDIR/leaf.der"
  [[ $status -eq 1 || $status -eq 4 ]] || { echo "tampered: want exit 1 or 4, got $status: $output" >&2; return 1; }
  if [[ $status -eq 1 ]]; then
    [[ $output == *"not ok "*"- the signature of the leaf by the untrusted #1"* ]] || {
      echo "tampered: the signature check is not the failing one: $output" >&2; return 1; }
  fi
}

function junk_is_exit_4_and_no_root_is_usage { # @test
  printf 'hello\n' >"$WORKDIR/junk"
  _verify --root "$WORKDIR/root.pem" "$WORKDIR/junk"
  [[ $status -eq 4 && $stderr == *"junk"* ]] || { echo "junk leaf: want exit 4, got $status: $stderr" >&2; return 1; }
  _verify --root "$WORKDIR/junk" "$WORKDIR/leaf.pem"
  [[ $status -eq 4 ]] || { echo "junk root: want exit 4, got $status: $stderr" >&2; return 1; }
  _verify --root "$WORKDIR/root.pem" --key "$WORKDIR/junk" "$WORKDIR/leaf.pem"
  [[ $status -eq 4 ]] || { echo "junk key: want exit 4, got $status: $stderr" >&2; return 1; }
  _verify "$WORKDIR/leaf.pem"
  [[ $status -eq 2 ]] || { echo "no root: want exit 2, got $status: $stderr" >&2; return 1; }
  [[ -z $output ]] || { echo "a refusal printed TAP: $output" >&2; return 1; }
}

function cert_show_prints_the_fields_and_the_der_sha256 { # @test
  run --separate-stderr "$PIGGY_BIN" cert show "$WORKDIR/root.pem"
  [[ $status -eq 0 ]] || { echo "show root: $status: $stderr" >&2; return 1; }
  local want
  for want in "subject:            CN=piggy-test root" "(self-issued)" "basic-constraints:  critical CA:TRUE pathlen:1" \
    "key-usage:          keyCertSign, cRLSign" "permitted:          DNS:github.com" \
    "excluded:           IP:0.0.0.0/0.0.0.0, IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0" "key:                EC P-256 ecdsa-sha2-nistp256 "; do
    [[ $output == *"$want"* ]] || { echo "root lacks '$want':" >&2; echo "$output" >&2; return 1; }
  done
  local sha
  sha=$(openssl x509 -in "$WORKDIR/root.pem" -outform DER | sha256sum | cut -d' ' -f1)
  [[ $output == *"der-sha256:         $sha"* ]] || { echo "the DER sha256 is not openssl's ($sha):" >&2; echo "$output" >&2; return 1; }

  run --separate-stderr "$PIGGY_BIN" cert show "$WORKDIR/chain.pem"
  [[ $status -eq 0 && $output == *"certificate 1 of 2"* && $output == *"certificate 2 of 2"* ]] || {
    echo "show chain: $status: $output" >&2; return 1; }
  for want in "subject:            CN=github.com" "issuer:             CN=piggy-test intermediate" \
    "basic-constraints:  critical CA:FALSE" "extended-key-usage: serverAuth" "dns-names:          github.com, api.github.com"; do
    [[ $output == *"$want"* ]] || { echo "leaf lacks '$want':" >&2; echo "$output" >&2; return 1; }
  done
  run --separate-stderr "$PIGGY_BIN" cert show "$WORKDIR/junk"
  [[ $status -eq 4 ]] || { echo "show junk: want exit 4, got $status" >&2; return 1; }
  run --separate-stderr "$PIGGY_BIN" cert
  [[ $status -eq 2 ]] || { echo "bare cert: want exit 2, got $status" >&2; return 1; }
}
