#! /usr/bin/env bats
#
# FDR 0007 phase (i), piggy#393: the X.509 profiles piggy-piv builds (a
# card-held root, a holder-held intermediate, name-constrained leaves),
# checked with `openssl verify`, the verifier nix's curl uses. The
# certificates come from `x509-profile-probe` (software keys through the
# builders' signer closure; the misbehaving ones made with openssl).
#
# What the lane pins (FDR 0007 promotion criteria):
#   - a leaf for the permitted names verifies under the root, with and
#     without the intermediate, and under a P-384 root;
#   - a leaf for any other name is rejected, under the root, under the
#     intermediate, and under an intermediate whose own constraints permit
#     the foreign name or that carries no constraints at all;
#   - a leaf naming an IP address is rejected (every IP is excluded);
#   - each profile carries the FDR's extensions.
#
# Required env (supplied by `just test-bats-conformance-x509-profile`):
#   X509_PROFILE_PROBE_BIN=/path/to/x509-profile-probe

setup_file() {
  if [[ -z ${X509_PROFILE_PROBE_BIN:-} ]] || [[ ! -x ${X509_PROFILE_PROBE_BIN:-/nonexistent} ]]; then
    return 0
  fi
  export X509_DIR="$BATS_FILE_TMPDIR/certs"
  "$X509_PROFILE_PROBE_BIN" "$X509_DIR"
}

setup() {
  if [[ -z ${X509_PROFILE_PROBE_BIN:-} ]] || [[ ! -x ${X509_PROFILE_PROBE_BIN:-/nonexistent} ]]; then
    skip "X509_PROFILE_PROBE_BIN unset; run via just test-bats-conformance-x509-profile"
  fi
  command -v openssl >/dev/null || skip "openssl not on PATH"
  P256="$X509_DIR/p256"
  P384="$X509_DIR/p384"
}

# verifies ROOT [INTERMEDIATE] LEAF: openssl accepts the chain.
verifies() {
  local root=$1 leaf=${*: -1} args=()
  (($# == 3)) && args=(-untrusted "$2")
  run openssl verify -CAfile "$root" "${args[@]}" "$leaf"
  [[ $status -eq 0 && $output == *": OK"* ]] || {
    echo "expected $leaf to verify; openssl said (status $status):" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# rejected WHY ROOT [INTERMEDIATE] LEAF: openssl refuses the chain, and its
# message contains WHY.
rejected() {
  local why=$1 root=$2 leaf=${*: -1} args=()
  (($# == 4)) && args=(-untrusted "$3")
  run openssl verify -CAfile "$root" "${args[@]}" "$leaf"
  [[ $status -ne 0 && $output == *"$why"* ]] || {
    echo "expected $leaf to be rejected for '$why'; openssl said (status $status):" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# has CERT TEXT...: `openssl x509 -text` of CERT contains every TEXT.
has() {
  local cert=$1 want
  local text
  text=$(openssl x509 -in "$cert" -noout -text)
  shift
  for want in "$@"; do
    [[ $text == *"$want"* ]] || {
      echo "$cert lacks '$want':" >&2
      printf '%s\n' "$text" >&2
      return 1
    }
  done
}

function a_leaf_for_the_permitted_names_verifies_through_the_intermediate { # @test
  verifies "$P256/root.pem" "$P256/intermediate.pem" "$P256/leaf.pem"
}

function the_pilots_root_signed_leaf_verifies { # @test
  verifies "$P256/root.pem" "$P256/leaf-direct.pem"
}

function a_p384_root_signs_a_leaf_that_verifies { # @test
  verifies "$P384/root.pem" "$P384/leaf-direct.pem"
}

function a_leaf_for_a_foreign_name_is_rejected_under_the_root { # @test
  rejected "permitted subtree violation" "$P256/root.pem" "$P256/leaf-foreign.pem"
}

function a_leaf_for_a_foreign_name_is_rejected_under_the_intermediate { # @test
  rejected "permitted subtree violation" "$P256/root.pem" "$P256/intermediate.pem" "$P256/leaf-foreign-int.pem"
}

function an_intermediate_permitting_more_cannot_widen_the_roots_names { # @test
  verifies "$P256/root.pem" "$P256/wide-intermediate.pem" "$P256/leaf-wide.pem"
  rejected "permitted subtree violation" "$P256/root.pem" "$P256/wide-intermediate.pem" "$P256/leaf-foreign-wide.pem"
}

function an_unconstrained_intermediate_cannot_widen_the_roots_names { # @test
  verifies "$P256/root.pem" "$P256/rogue-intermediate.pem" "$P256/leaf-rogue.pem"
  rejected "permitted subtree violation" "$P256/root.pem" "$P256/rogue-intermediate.pem" "$P256/leaf-foreign-rogue.pem"
}

function a_leaf_naming_an_ip_address_is_rejected { # @test
  rejected "excluded subtree violation" "$P256/root.pem" "$P256/leaf-ip.pem"
}

function the_root_carries_the_root_profile { # @test
  has "$P256/root.pem" \
    "X509v3 Basic Constraints: critical" "CA:TRUE, pathlen:1" \
    "X509v3 Key Usage: critical" "Certificate Sign, CRL Sign" \
    "X509v3 Name Constraints: critical" "DNS:github.com" \
    "IP:0.0.0.0/0.0.0.0" "IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0" \
    "X509v3 Subject Key Identifier" "X509v3 Authority Key Identifier"
}

function the_intermediate_carries_the_intermediate_profile { # @test
  has "$P256/intermediate.pem" \
    "CA:TRUE, pathlen:0" "Certificate Sign, CRL Sign" \
    "X509v3 Name Constraints: critical" "DNS:github.com"
}

function the_leaf_carries_the_leaf_profile { # @test
  has "$P256/leaf.pem" \
    "Subject: CN=github.com" "CA:FALSE" "Digital Signature" \
    "TLS Web Server Authentication" \
    "DNS:github.com, DNS:api.github.com, DNS:codeload.github.com"
  has "$P384/leaf-direct.pem" "ecdsa-with-SHA384"
}
