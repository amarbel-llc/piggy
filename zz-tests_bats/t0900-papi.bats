setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  # `papi verify` shells out to curl; mock it with a URL→fixture lookup so the
  # verdict orchestration runs offline.
  piggy_install_helper_as mock-curl.sh curl
  export MOCK_CURL_DIR="$BATS_TEST_TMPDIR/curl-fixtures"
  mkdir -p "$MOCK_CURL_DIR"
}

# Stage a curl fixture for $url with body $2, keyed the same way mock-curl.sh
# sanitizes the URL.
mock_fixture() {
  local url="$1" body="$2" key
  key="$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
  printf '%s' "$body" >"$MOCK_CURL_DIR/$key"
}

# `piggy papi` producing surface (piggy#182). The sandbox lane covers `prove`
# (pure, no agent) and `sign`'s pre-agent error paths (JSON parse + the JCS
# float guard, both of which fire before any key/agent access). The `sign`
# happy path needs a real slot-9A agent signature and lives in the fibby
# conformance lane (conformance/piggy_papi_fibby.bats, hardware tag).

function papi_prove_recipient_emits_token_and_entry { # @test
  run "$PIGGY" papi prove \
    --claim https://github.com/alice \
    --recipient piggy-recipient-v1@pivy_ecdh_p256_pub-qqq \
    --service github
  assert_success
  assert_output --partial "PASTE THIS"
  # The fmt=recipient backlink token is the bare recipient id.
  assert_output --partial "piggy-recipient-v1@pivy_ecdh_p256_pub-qqq"
  # The ready-to-merge proofs[] entry.
  assert_output --partial '"recipient": "piggy-recipient-v1@pivy_ecdh_p256_pub-qqq"'
  assert_output --partial '"claim": "https://github.com/alice"'
  assert_output --partial '"service": "github"'
  assert_output --partial '"fmt": "recipient"'
  # proof_uri is left empty for the subject to fill after pasting.
  assert_output --partial '"proof_uri": ""'
}

function papi_prove_defaults_id_to_service { # @test
  run "$PIGGY" papi prove --claim dns:example.com --recipient r --service dns
  assert_success
  assert_output --partial '"id": "dns"'
}

function papi_prove_signature_needs_a_9a_key { # @test
  # fmt=signature now signs over the agent; with no piggy-ids / slot-9A key in
  # the sandbox store it fails at key selection (no longer "not yet
  # implemented"). The happy path is the fibby lane.
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" papi prove --claim https://x.test/a --recipient r --fmt signature
  assert_failure
  refute_output --partial "not yet implemented"
}

function papi_sign_rejects_non_json_input { # @test
  run bash -c "printf 'not json' | '$PIGGY' papi sign"
  assert_failure
  assert_output --partial "parse --in JSON"
}

function papi_sign_rejects_non_object_document { # @test
  run bash -c "printf '[1,2,3]' | '$PIGGY' papi sign"
  assert_failure
  assert_output --partial "must be a JSON object"
}

function papi_sign_rejects_float_numbers { # @test
  # The §10.2 JCS float guard fires during canonicalization, before any key
  # selection or agent access.
  run bash -c "printf '{\"x\":4.2}' | '$PIGGY' papi sign"
  assert_failure
  assert_output --partial "float canonicalization"
}

function papi_bare_prints_help { # @test
  run "$PIGGY" papi
  # arg_required_else_help => clap prints usage and exits non-zero.
  assert_failure
  assert_output --partial "sign"
  assert_output --partial "prove"
}

# -------- verify (§9.4 / §10.3) via mock curl --------
#
# These exercise the fetch → parse → verdict → exit-code orchestration. The
# signed-AND-valid crypto path is unit-tested (verify_ssh9a round-trip) and
# lives end-to-end in the fibby lane; here we cover the structural verdicts.

function papi_verify_unsigned_doc_skips_signature { # @test
  mock_fixture "https://pp.test/papi" '{"piggy":{"encryption_recipients":[],"ssh_authorized_keys":[]}}'
  mock_fixture "https://pp.test/papi/proofs" '{"data":[]}'
  run "$PIGGY" papi verify pp.test --json
  assert_success
  assert_output --partial '"signature"'
}

function papi_verify_require_signed_on_unsigned_fails { # @test
  mock_fixture "https://pp.test/papi" '{"piggy":{"encryption_recipients":[],"ssh_authorized_keys":[]}}'
  mock_fixture "https://pp.test/papi/proofs" '{"data":[]}'
  run "$PIGGY" papi verify pp.test --json --require-signed
  assert_failure
}

function papi_verify_signed_but_invalid_fails { # @test
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"
  ssh-keygen -t ecdsa -b 256 -N '' -f "$BATS_TEST_TMPDIR/k" -q
  local key
  key="$(cut -d' ' -f1,2 <"$BATS_TEST_TMPDIR/k.pub")"
  # alg understood + key published, but a structurally-bogus sig => not ok.
  mock_fixture "https://pp.test/papi" \
    "{\"piggy\":{\"ssh_authorized_keys\":[\"$key\"]},\"signature\":{\"alg\":\"ssh-9a\",\"key\":\"$key\",\"sig\":\"AAAA\"}}"
  mock_fixture "https://pp.test/papi/proofs" '{"data":[]}'
  run "$PIGGY" papi verify pp.test --json
  assert_failure
  assert_output --partial '"signature"'
}

function papi_verify_unknown_alg_is_unsigned { # @test
  mock_fixture "https://pp.test/papi" \
    '{"piggy":{"ssh_authorized_keys":[]},"signature":{"alg":"pgp","key":"x","sig":"y"}}'
  mock_fixture "https://pp.test/papi/proofs" '{"data":[]}'
  run "$PIGGY" papi verify pp.test --json
  # unknown alg => treated as unsigned (skip), not a failure.
  assert_success
}

function papi_verify_proof_recipient_backlink_verifies { # @test
  local rcpt="piggy-recipient-v1@pivy_ecdh_p256_pub-qqq"
  mock_fixture "https://pp.test/papi" \
    "{\"piggy\":{\"encryption_recipients\":[\"$rcpt\"],\"ssh_authorized_keys\":[]}}"
  mock_fixture "https://pp.test/papi/proofs" \
    "{\"data\":[{\"id\":\"gh\",\"recipient\":\"$rcpt\",\"claim\":\"https://github.com/a\",\"proof_uri\":\"https://gist.test/a\",\"fmt\":\"recipient\"}]}"
  # The backlink body contains the recipient id => verified.
  mock_fixture "https://gist.test/a" "my keys: $rcpt — verified"
  run "$PIGGY" papi verify pp.test --json
  assert_success
  assert_output --partial '"proof: gh"'
}

function papi_verify_proof_backlink_absent_fails { # @test
  local rcpt="piggy-recipient-v1@pivy_ecdh_p256_pub-qqq"
  mock_fixture "https://pp.test/papi" \
    "{\"piggy\":{\"encryption_recipients\":[\"$rcpt\"],\"ssh_authorized_keys\":[]}}"
  mock_fixture "https://pp.test/papi/proofs" \
    "{\"data\":[{\"id\":\"gh\",\"recipient\":\"$rcpt\",\"claim\":\"https://github.com/a\",\"proof_uri\":\"https://gist.test/a\",\"fmt\":\"recipient\"}]}"
  # Backlink body does NOT contain the recipient id => unverified (not ok).
  mock_fixture "https://gist.test/a" "nothing relevant here"
  run "$PIGGY" papi verify pp.test --json
  assert_failure
}
