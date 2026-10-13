#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §5 — the attestation bundle, read the way a verifier reads it.
# `piggy card export-attestation` prints exactly five parts in order: the
# header line, the `# key <markl-id>` line, the key in authorized_keys form,
# the slot's attestation certificate and the card's F9 certificate. The
# three spellings of the key agree; the attestation is signed by the F9
# certificate; and an operator-act sshsig made with the slot verifies under
# the bundle's key. (The CLI verb's own cases, slot arguments and refusals,
# are in piggy_card_add_key_fibby.bats.)
#
# fibby's F9 certificate is its own, not Yubico's, so the last link of §5,
# F9 to a Yubico root, is the hand pass's on a real card (piggy#303).
#
# Stack and required env: zz-tests_bats/lib/operator_act.bash.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  operator_act_setup
  command -v openssl >/dev/null || skip "openssl not on PATH"
}

teardown() {
  operator_act_teardown
}

# Export the 9C bundle to $WORKDIR/bundle and split its two certificates into
# $WORKDIR/attestation.pem and $WORKDIR/f9.pem.
_export_bundle() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" card export-attestation \
    >"$WORKDIR/bundle" 2>"$WORKDIR/export.err" || {
    cat "$WORKDIR/export.err" >&2
    operator_act_fail "card export-attestation failed"
  }
  awk -v dir="$WORKDIR" '
    /-----BEGIN CERTIFICATE-----/ { n++; out = dir "/" (n == 1 ? "attestation" : "f9") ".pem" }
    out { print > out }
    /-----END CERTIFICATE-----/ { out = "" }
  ' "$WORKDIR/bundle"
}

function bundle_has_exactly_the_five_parts_in_order { # @test
  operator_act_stack_up
  _export_bundle

  [[ $(sed -n 1p "$WORKDIR/bundle") == "# piggy-attestation-bundle v1" ]] ||
    operator_act_fail "part 1 is not the header line"
  [[ $(sed -n 2p "$WORKDIR/bundle") =~ ^#\ key\ piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-[a-z0-9]+$ ]] ||
    operator_act_fail "part 2 is not '# key <markl-id>' with the 9C purpose and format"
  [[ $(sed -n 3p "$WORKDIR/bundle") =~ ^ecdsa-sha2-nistp256\ AAAA[A-Za-z0-9+/=]+\ PIV_slot_9C\ card:[0-9a-f]{8}$ ]] ||
    operator_act_fail "part 3 is not the key in authorized_keys form naming card and slot"
  [[ $(sed -n 4p "$WORKDIR/bundle") == "-----BEGIN CERTIFICATE-----" ]] ||
    operator_act_fail "part 4 does not follow part 3 directly"
  [[ $(tail -1 "$WORKDIR/bundle") == "-----END CERTIFICATE-----" ]] ||
    operator_act_fail "there is text after part 5"
  [[ $(grep -c -- '-----BEGIN CERTIFICATE-----' "$WORKDIR/bundle") -eq 2 ]] ||
    operator_act_fail "the bundle does not hold exactly two certificates"
  [[ $(grep -c '^# ' "$WORKDIR/bundle") -eq 2 ]] ||
    operator_act_fail "the header and key lines do not appear exactly once"
}

function three_spellings_of_the_key_agree { # @test
  operator_act_stack_up
  _export_bundle
  local bundle_key agent_key cert_key
  bundle_key=$(sed -n 3p "$WORKDIR/bundle" | awk '{print $1, $2}')
  agent_key=$(operator_act_public_key 9C | awk '{print $1, $2}')
  [[ -n $bundle_key && $bundle_key == "$agent_key" ]] ||
    operator_act_fail "the bundle's key is not the 9C key the agent serves"

  openssl x509 -in "$WORKDIR/attestation.pem" -noout -pubkey >"$WORKDIR/attested.pub.pem"
  cert_key=$(ssh-keygen -i -m PKCS8 -f "$WORKDIR/attested.pub.pem" | awk '{print $1, $2}')
  [[ $cert_key == "$bundle_key" ]] ||
    operator_act_fail "the attestation certificate is for a different key than the bundle names"

  # The markl id is derived from the key alone: a second export spells it
  # the same way. (That it decodes to this key is piggy-markl's unit tests'.)
  local first second
  first=$(sed -n 2p "$WORKDIR/bundle")
  _export_bundle
  second=$(sed -n 2p "$WORKDIR/bundle")
  [[ $first == "$second" ]] || operator_act_fail "the '# key' line is not stable across exports"
}

function attestation_is_signed_by_the_f9_certificate_and_states_the_policy { # @test
  operator_act_stack_up
  _export_bundle

  openssl verify -partial_chain -CAfile "$WORKDIR/f9.pem" "$WORKDIR/attestation.pem" \
    >"$WORKDIR/verify.out" 2>&1 || {
    cat "$WORKDIR/verify.out" >&2
    operator_act_fail "the attestation certificate is not signed by the bundle's F9 certificate"
  }
  # The Yubico PIV policy extension (1.3.6.1.4.1.41482.3.8): PIN always (03),
  # touch always (02).
  openssl asn1parse -in "$WORKDIR/attestation.pem" >"$WORKDIR/asn1"
  grep -A2 '1.3.6.1.4.1.41482.3.8' "$WORKDIR/asn1" | grep -q 'HEX DUMP\]:0302' ||
    operator_act_fail "the attestation does not state PIN always, touch always"
}

function operator_act_sshsig_verifies_under_the_bundles_key { # @test
  operator_act_stack_up
  _export_bundle
  local text="piggy-test: certify the bundle's key signs acts"
  operator_sign_via "$AGENT_SOCK" "$text" --namespace piggy-certificate-v1
  [[ $status -eq 0 ]] || operator_act_fail "operator-sign failed"
  printf '%s\n' "$output" >"$WORKDIR/act.sig"

  sed -n 3p "$WORKDIR/bundle" | awk '{print "operator", $1, $2}' >"$WORKDIR/allowed_signers"
  ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I operator -n piggy-certificate-v1 \
    -s "$WORKDIR/act.sig" <<<"$text" >"$WORKDIR/verify.out" 2>&1 || {
    cat "$WORKDIR/verify.out" >&2
    operator_act_fail "the sshsig does not verify under the key the bundle attests"
  }
}
