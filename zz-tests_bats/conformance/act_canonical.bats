#! /usr/bin/env bats
#
# RFC 0013 §2 and §3.1: `piggy act canon` writes an act's canonical form.
# The same act arriving in another line order, unspaced, quoted where it
# could be bare, with its description split, or with comments, has ONE
# canonical form; set values sort and dedup; the body rides through byte for
# byte. Pure text: no card, no agent, no PIN.
#
# The vectors (docs/rfcs/0013-vectors.txt) pin the exact bytes; this file
# pins the CLI.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

K_SIG=piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-qfcnt7j0myaqnh8f3wlksx6tln6sulqdvd2wv2hmp0lj5dpfv9ux2v2ndra
K_PRINCIPAL=piggy-principal_pub-v1@ssh_ed25519_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0str2nnx
D_BLAKE=piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400
D_SHA=piggy-record-digest-v1@sha256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s7lcgm6

# A card root in canonical form.
_root_canonical() {
  cat <<EOF
---
# root: operator blesses session 72dca00c
- kind = root
- producer = troupe:root-v1
- subject = clown:72dca00c
- subject-key = $K_PRINCIPAL
- issuer = operator
- issuer-key = $K_SIG
- right = spinclass:check
- right = spinclass:merge
- records = $D_BLAKE
- not-after = 2026-11-09T23:00:00Z
- issued-at = 2026-11-08T23:00:00Z
- assurance = piggy:hardware
- key = $K_SIG
- namespace = piggy-certificate-v1
- hash = sha256
! piggy-act-v1
---
EOF
}

function canonical_form_is_a_fixed_point { # @test
  local want
  want=$(_root_canonical)
  run -0 "$PIGGY" act canon <<<"$want"
  assert_output "$want"
}

function three_line_orders_give_one_canonical_form { # @test
  local want reversed shuffled
  want=$(_root_canonical)
  # Reverse every line between the boundaries: the type line comes first,
  # the description last.
  reversed=$(printf -- '---\n%s\n---\n' "$(sed '1d;$d' <<<"$want" | tac)")
  # Sort the lines: descriptions first, fields alphabetically, type last.
  shuffled=$(printf -- '---\n%s\n---\n' "$(sed '1d;$d' <<<"$want" | sort)")

  run -0 "$PIGGY" act canon <<<"$reversed"
  assert_output "$want"
  run -0 "$PIGGY" act canon <<<"$shuffled"
  assert_output "$want"
}

function unspaced_quoted_and_split_description_give_one_canonical_form { # @test
  local want variant
  want=$(_root_canonical)
  variant=$(sed -e 's/^- \([a-z:-]*\) = /- \1=/' \
    -e 's/^- producer=\(.*\)$/- producer="\1"/' \
    -e 's/^# root: operator blesses session 72dca00c$/#  \troot: operator blesses\n#   session 72dca00c/' \
    <<<"$want")

  run -0 "$PIGGY" act canon <<<"$variant"
  assert_output "$want"
}

function comments_are_not_part_of_the_canonical_form { # @test
  local want commented
  want=$(_root_canonical)
  commented=$(sed -e 's/^- kind = root$/% nobody signs this\n- kind = root % nor this/' <<<"$want")

  run -0 "$PIGGY" act canon <<<"$commented"
  assert_output "$want"
}

function set_values_sort_and_dedup { # @test
  local want doubled
  want=$(_root_canonical)
  doubled=$(sed -e 's/^- right = spinclass:check$/- right = spinclass:merge\n- right = spinclass:check\n- right = spinclass:merge/' \
    -e 's/^- right = spinclass:merge$//' <<<"$want" | sed '/^$/d')

  run -0 "$PIGGY" act canon <<<"$doubled"
  assert_output "$want"
}

function the_signature_line_is_not_in_the_canonical_form { # @test
  local want sealed
  want=$(_root_canonical)
  sealed=$(sed -e "s/^- hash = sha256$/- hash = sha256\n- signature = piggy-record-sig-v1@ecdsa_p256_sig-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqgfzyvjz2f389q5j52ev95hz7vp3xgengdfkxuurjw3m8s7nu0cywvqw8/" <<<"$want")

  run -0 "$PIGGY" act canon <<<"$sealed"
  assert_output "$want"
}

function the_body_rides_through_byte_for_byte { # @test
  local dir="$BATS_TEST_TMPDIR"
  {
    _root_canonical
    printf '\n[moxy !clown-plugin-v1\n\t[-> folio !mcp-server-v1 deny]]\n'
  } >"$dir/act"

  "$PIGGY" act canon "$dir/act" >"$dir/canonical"
  cmp "$dir/act" "$dir/canonical"
}

function a_file_argument_and_stdin_agree { # @test
  _root_canonical >"$BATS_TEST_TMPDIR/act"
  run -0 "$PIGGY" act canon "$BATS_TEST_TMPDIR/act"
  local from_file=$output
  run -0 "$PIGGY" act canon - <"$BATS_TEST_TMPDIR/act"
  assert_output "$from_file"
}

# hyphence RFC 0005's refuse vectors (crates/piggy/testdata/
# hyphence-0005-vectors.txt, copied from hyphence 1c63a98), one row per
# record, documents copied byte for byte. piggy reports a hyphence decode
# error (RFC 0001, `rule: envelope`) and a typed-head error (RFC 0002/0003,
# `rule: content`) alike as `envelope`, both before any act rule runs, so
# every row expects `refused (envelope)`: a pinned hyphence that let one of
# these through would answer with an act rule (`type`, `value`) instead.

function hyphence_0005_refuse_digest_outside_blech32 { # @test
  run -1 "$PIGGY" act canon <<<$'---\n- k = md@blake2b256-9bt3\n! md\n---'
  assert_output --partial 'refused (envelope)'
}

function hyphence_0005_refuse_unquoted_two_words { # @test
  run -1 "$PIGGY" act canon <<<$'---\n- k = two words\n! md\n---'
  assert_output --partial 'refused (envelope)'
}

function hyphence_0005_refuse_quoted_unlocked_type { # @test
  run -1 "$PIGGY" act canon <<<$'---\n! "md"\n---'
  assert_output --partial 'refused (envelope)'
}

function hyphence_0005_refuse_unterminated_metadata { # @test
  run -1 "$PIGGY" act canon <<<$'---\n! md'
  assert_output --partial 'refused (envelope)'
}

function hyphence_0005_refuse_unknown_prefix { # @test
  run -1 "$PIGGY" act canon <<<$'---\nx foo\n! md\n---'
  assert_output --partial 'refused (envelope)'
}

# The 13 canonical records are hyphence documents, not acts (`! md`, a
# locked type, a bare `-` term), so `piggy act canon` refuses each with an
# act rule before RFC 0005 emission is reached, and piggy has no plain
# hyphence emission verb. They are replayed against the linked hyphence in
# crates/piggy/src/act/hyphence_vectors_tests.rs instead; this row only
# pins that the first of them is refused as an act, not as hyphence.
function hyphence_0005_canonical_records_are_not_acts { # @test
  run -1 "$PIGGY" act canon <<<$'---\n- kind = approval\n- urgent\n! piggy-act-v1\n---'
  assert_output --partial 'refused (line-kind)'
}
