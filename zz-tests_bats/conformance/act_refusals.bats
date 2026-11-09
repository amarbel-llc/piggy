#! /usr/bin/env bats
#
# RFC 0013 §1, §2 and §5.2 step 1: what `piggy act canon` refuses, each
# refusal exiting 1 and naming its rule on stderr as `refused (<rule>)`.
# Pure text: no card, no agent, no PIN.
#
# Not here yet: §3.4's 4096-byte cap is the agent's refusal (`refused-text`)
# and §4.7/§4.8's namespace, kind, issuer and assurance pairing is §5.2 step
# 3, both exercised once acts are signed and verified (RFC 0013 S3 onward).

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

K_SIG=piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-qfcnt7j0myaqnh8f3wlksx6tln6sulqdvd2wv2hmp0lj5dpfv9ux2v2ndra
D_BLAKE=piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400

# A card approval that canon accepts; each test breaks one rule.
_approval() {
  cat <<EOF
---
- kind = approval
- producer = troupe:approval-v1
- issuer = operator
- issuer-key = $K_SIG
- records = $D_BLAKE
- issued-at = 2026-11-08T23:00:00Z
- assurance = piggy:hardware
- key = $K_SIG
- namespace = piggy-approval-v1
- hash = sha256
! piggy-act-v1
---
EOF
}

# Insert $1 as a head line just before the type line.
_with_line() {
  sed "s/^! piggy-act-v1$/$1\n! piggy-act-v1/" <<<"$(_approval)"
}

_assert_refused() {
  local rule=$1 document=$2
  run -1 --separate-stderr "$PIGGY" act canon <<<"$document"
  assert_output ""
  [[ $stderr == *"refused ($rule)"* ]] ||
    fail "want refused ($rule), got: $stderr"
}

function the_fixture_is_accepted { # @test
  run -0 "$PIGGY" act canon <<<"$(_approval)"
}

function a_bare_tag_line_is_refused { # @test
  _assert_refused line-kind "$(_with_line '- urgent')"
}

function a_reference_line_is_refused { # @test
  _assert_refused line-kind "$(_with_line "- one\/uno@${D_BLAKE#*@}")"
}

function an_angle_line_is_refused { # @test
  _assert_refused line-kind "$(_with_line '< nonce = abc')"
}

function a_blob_line_is_refused { # @test
  _assert_refused line-kind "$(_with_line "@ ${D_BLAKE#*@}")"
}

function a_locked_type_line_is_refused { # @test
  _assert_refused type-lock "$(sed "s/^! piggy-act-v1$/! piggy-act-v1@${D_BLAKE#*@}/" <<<"$(_approval)")"
}

function another_type_is_refused { # @test
  _assert_refused type "$(sed 's/^! piggy-act-v1$/! piggy-act-v2/' <<<"$(_approval)")"
}

function a_quoted_field_name_is_refused { # @test
  _assert_refused quoted-field-name "$(_with_line '- "nonce" = abc')"
}

function a_duplicate_kind_is_refused { # @test
  _assert_refused duplicate-field "$(_with_line '- kind = root')"
}

function an_unknown_unprefixed_field_is_refused { # @test
  _assert_refused unknown-field "$(_with_line '- colour = red')"
}

function a_prefixed_field_is_carried { # @test
  run -0 "$PIGGY" act canon <<<"$(_with_line '- spinclass:colour = red')"
  assert_line -- '- spinclass:colour = red'
}

function a_missing_issuer_key_is_refused { # @test
  _assert_refused missing-field "$(sed '/^- issuer-key = /d' <<<"$(_approval)")"
}

function a_card_act_with_an_issuer_record_is_refused { # @test
  _assert_refused forbidden-field "$(_with_line "- issuer-record = $D_BLAKE")"
}

function a_value_outside_its_cell_is_refused { # @test
  _assert_refused value "$(sed 's/^- issued-at = .*/- issued-at = "2026-11-08T23:00:00+00:00"/' <<<"$(_approval)")"
  _assert_refused value "$(sed 's/^- hash = sha256$/- hash = sha1/' <<<"$(_approval)")"
  _assert_refused value "$(sed 's/^- namespace = .*/- namespace = git/' <<<"$(_approval)")"
}

function a_body_with_a_control_character_is_refused { # @test
  local document
  document="$(_approval)"$'\n\n'$'\e[31mhidden\n'
  _assert_refused body "$document"
}

function an_unclosed_metadata_section_is_refused { # @test
  _assert_refused envelope $'---\n- kind = approval'
}

function a_body_only_document_has_no_type { # @test
  _assert_refused type 'kind = approval'
}
