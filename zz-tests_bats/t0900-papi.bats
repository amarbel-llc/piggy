setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
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

function papi_prove_signature_fmt_is_deferred { # @test
  run "$PIGGY" papi prove --claim c --recipient r --fmt signature
  assert_failure
  assert_output --partial "not yet implemented"
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
