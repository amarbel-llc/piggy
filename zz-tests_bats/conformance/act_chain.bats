#! /usr/bin/env bats
#
# RFC 0013 §4 and §5.2 to §5.3: the chain walk behind `piggy act verify`,
# the `act_chain.bats` rows of the Conformance Testing table. Chains are
# built from throwaway ssh-keygen keys: an ECDSA P-256 key stands in for the
# card (its slot-9C key is a P-256 key, and the walk trusts it only because
# the anchors file names it), Ed25519 keys are the principals. Card acts are
# signed by `ssh-keygen -Y sign` under the card namespace: the walk checks
# the seal, not which agent made it. No card, no agent, no PIN, so no
# askpass safety net is needed.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  DIR=$BATS_TEST_TMPDIR
  STORE=$DIR/store
  mkdir -p "$STORE"
  ssh-keygen -q -t ecdsa -b 256 -N '' -C card -f "$DIR/card"
  local k
  for k in a b c stranger; do
    ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$DIR/$k"
  done
  printf 'operator namespaces="piggy-certificate-v1,piggy-escalation-v1,piggy-revocation-v1" %s\n' \
    "$(cat "$DIR/card.pub")" >"$DIR/anchors"
  AT=2026-11-10T12:00:00Z
  LATER=2026-11-11T00:00:00Z
  BODY=
}

UNKNOWN=piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400

_key() { "$PIGGY" act key "$DIR/$1.pub"; }

# _act KIND SIGNER LINE...: seal an act of KIND, signed by SIGNER (`card`
# or a principal key name), with the given `key = value` lines, into the
# store; print its act digest. $BODY, when set, is its body.
_act() {
  local kind=$1 signer=$2
  shift 2
  local key namespace issuer= assurance
  if [[ $signer == card ]]; then
    key=$("$PIGGY" act key --card "$DIR/card.pub")
    case $kind in
      root | link) namespace=piggy-certificate-v1 ;;
      grant | escalation) namespace=piggy-escalation-v1 ;;
      approval) namespace=piggy-approval-v1 ;;
      revocation) namespace=piggy-revocation-v1 ;;
    esac
    issuer='- issuer = operator'
    assurance=piggy:hardware
  else
    key=$(_key "$signer")
    namespace=piggy-record-v1
    assurance=piggy:software
  fi
  namespace=${NAMESPACE:-$namespace}
  assurance=${ASSURANCE:-$assurance}

  local file line digest
  file=$(mktemp "$DIR/act.XXXXXX")
  {
    printf -- '---\n- kind = %s\n- producer = test:chain-v1\n' "$kind"
    if [[ -n $issuer ]]; then printf '%s\n' "$issuer"; fi
    for line in "$@"; do printf -- '- %s\n' "$line"; done
    printf -- '- issuer-key = %s\n- issued-at = 2026-11-10T00:00:00Z\n' "$key"
    printf -- '- assurance = %s\n- key = %s\n' "$assurance" "$key"
    printf -- '- namespace = %s\n- hash = sha256\n! piggy-act-v1\n---\n' "$namespace"
    if [[ -n $BODY ]]; then printf '\n%s' "$BODY"; fi
  } >"$file"
  "$PIGGY" act canon "$file" >"$file.canonical"
  ssh-keygen -q -Y sign -f "$DIR/$signer" -n "$namespace" -O hashalg=sha256 "$file.canonical"
  "$PIGGY" act attach --signature "$file.canonical.sig" "$file" >"$file.sealed"
  digest=$("$PIGGY" act digest "$file.sealed")
  cp "$file.sealed" "$STORE/${digest##*-}.act"
  printf '%s\n' "$digest"
}

# A card root for s:a (key a) and a software link from it to s:b (key b).
_root() {
  _act root card "subject = s:a" "subject-key = $(_key a)" "not-after = ${1:-$LATER}" \
    "right = x:check" "right = x:merge" "right = x:close"
}

_link() { # _link ISSUER-RECORD [RIGHT...]
  local record=$1
  shift
  local rights=() r
  for r in "${@:-x:check}" ; do rights+=("right = $r"); done
  _act link a "subject = s:b" "subject-key = $(_key b)" "issuer = s:a" \
    "issuer-record = $record" "${rights[@]}"
}

# Verify act DIGEST at $AT; the verdict document is $output.
_verify() {
  local act=$1
  shift
  "$PIGGY" act verify --act "$act" --at "$AT" --anchors "$DIR/anchors" \
    --store "$STORE" --store-is-revocation-source --format json "$@"
}

_jq() { jq -r "$1" <<<"$output"; }

function a_valid_chain_answers_the_verdict_document { # @test
  local root link
  root=$(_root)
  link=$(_link "$root" x:check x:merge)

  run -0 _verify "$link"
  [[ $(jq -r 'keys_unsorted[0]' <<<"$output") == schema ]] || fail "$output"
  [[ $(_jq .schema) == piggy-act-verdict-v1 ]]
  [[ $(_jq .verdict) == valid ]]
  [[ $(_jq .act) == "$link" ]]
  [[ $(_jq .at) == "$AT" ]]
  [[ $(_jq .revocation_source) == asserted ]]
  [[ $(_jq .kind) == link ]]
  [[ $(_jq .subject) == s:b ]]
  [[ $(_jq .assurance) == piggy:software ]]
  [[ $(_jq .chain_start_key) == "$("$PIGGY" act key --card "$DIR/card.pub")" ]]
  [[ $(_jq '.chain | join(" ")') == "$root $link" ]]
  [[ $(_jq '.rights | join(" ")') == "x:check x:merge" ]]
  [[ $(_jq .effective_expiry) == "$LATER" ]]
}

function the_text_verdict_is_one_line_and_the_exit_code_is_the_verdict { # @test
  local root link
  root=$(_root)
  link=$(_link "$root")
  run -0 "$PIGGY" act verify --act "$link" --at "$AT" --anchors "$DIR/anchors" \
    --store "$STORE" --store-is-revocation-source
  assert_output "valid $link"
}

# §4.1, §5.2 step 4: the chain edge.

function an_issuer_record_certifying_another_key_or_subject_is_refused { # @test
  local root other_key other_subject
  root=$(_root)
  other_key=$(_act link stranger "subject = s:b" "subject-key = $(_key b)" "issuer = s:a" \
    "issuer-record = $root" "right = x:check")
  run -1 _verify "$other_key"
  [[ $(_jq .failed_step) == 5.2.4 ]] || fail "$output"
  [[ $(_jq .failed_act) == "$other_key" ]]

  other_subject=$(_act link a "subject = s:b" "subject-key = $(_key b)" "issuer = s:z" \
    "issuer-record = $root" "right = x:check")
  run -1 _verify "$other_subject"
  [[ $(_jq .failed_step) == 5.2.4 ]] || fail "$output"
}

function a_card_act_whose_key_is_not_an_anchor_is_refused { # @test
  local root
  root=$(_root)
  ssh-keygen -q -t ecdsa -b 256 -N '' -f "$DIR/other-card"
  printf 'operator %s\n' "$(cat "$DIR/other-card.pub")" >"$DIR/anchors"
  run -1 _verify "$root"
  [[ $(_jq .failed_step) == 5.2.4 ]] || fail "$output"
}

# §4.2: rights never widen without the card.

function a_software_link_or_grant_with_a_right_its_issuer_lacks_is_refused { # @test
  local root wide grant
  root=$(_root)
  wide=$(_link "$root" x:check x:deploy)
  run -1 _verify "$wide"
  [[ $(_jq .failed_step) == 5.2.5 ]] || fail "$output"

  grant=$(_act grant a "subject = s:b" "object = x:repo" "issuer = s:a" \
    "issuer-record = $root" "right = x:deploy")
  run -1 _verify "$grant"
  [[ $(_jq .failed_step) == 5.2.5 ]] || fail "$output"
}

function a_narrow_signed_by_another_key_is_refused { # @test
  local root link narrow
  root=$(_root)
  link=$(_link "$root")
  # s:b narrowing s:a's root: not signed by the root's subject.
  narrow=$(_act narrow b "subject = s:a" "issuer = s:b" "issuer-record = $link" \
    "right = x:check" "names = $root")
  run -1 _verify "$narrow"
  [[ $(_jq .failed_step) == 5.2.3 ]] || fail "$output"
  run -0 _verify "$root"
  [[ $(_jq '.rights | join(" ")') == "x:check x:close x:merge" ]]
}

# §4.3: effective rights.

function an_escalation_replaces_a_links_rights { # @test
  local root link
  root=$(_root)
  link=$(_link "$root" x:check)
  _act escalation card "subject = s:b" "right = x:check" "right = x:deploy" \
    "names = $link" >/dev/null
  run -0 _verify "$link"
  [[ $(_jq '.rights | join(" ")') == "x:check x:deploy" ]] || fail "$output"
}

function a_narrow_intersects_whatever_the_issue_order { # @test
  local root link
  root=$(_root)
  link=$(_link "$root" x:check)
  # The narrow is issued before the escalation and still cuts it.
  _act narrow b "subject = s:b" "issuer = s:b" "issuer-record = $link" \
    "right = x:check" "names = $link" >/dev/null
  _act escalation card "subject = s:b" "right = x:check" "right = x:deploy" \
    "names = $link" >/dev/null
  run -0 _verify "$link"
  [[ $(_jq '.rights | join(" ")') == x:check ]] || fail "$output"
}

function two_unsuperseded_escalations_make_the_act_invalid { # @test
  local root link
  root=$(_root)
  link=$(_link "$root")
  _act escalation card "subject = s:b" "right = x:merge" "names = $link" >/dev/null
  _act escalation card "subject = s:b" "right = x:close" "names = $link" >/dev/null
  run -1 _verify "$link"
  [[ $(_jq .failed_step) == 5.2.6 ]] || fail "$output"
  [[ $(_jq .reason) == *conflicting* ]]
}

function an_escalation_naming_the_narrow_lifts_it { # @test
  local root link narrow
  root=$(_root)
  link=$(_link "$root" x:check x:merge)
  narrow=$(_act narrow b "subject = s:b" "issuer = s:b" "issuer-record = $link" \
    "right = x:check" "names = $link")
  run -0 _verify "$link"
  [[ $(_jq '.rights | join(" ")') == x:check ]] || fail "$output"

  _act escalation card "subject = s:b" "right = x:check" "right = x:merge" \
    "names = $link" "names = $narrow" >/dev/null
  run -0 _verify "$link"
  [[ $(_jq '.rights | join(" ")') == "x:check x:merge" ]] || fail "$output"
}

# §4.1, §5.2 step 6: names and records.

function an_escalation_naming_a_non_act_or_another_subject { # @test
  local root link unresolved other
  root=$(_root)
  link=$(_link "$root")

  unresolved=$(_act escalation card "subject = s:b" "right = x:merge" \
    "names = $link" "names = $UNKNOWN")
  run -2 _verify "$unresolved"
  [[ $(_jq .verdict) == undetermined ]] || fail "$output"
  [[ $(_jq '.unresolved | join(" ")') == "$UNKNOWN" ]]

  other=$(_act escalation card "subject = s:b" "right = x:merge" "names = $root")
  run -1 _verify "$other"
  [[ $(_jq .failed_step) == 5.2.6 ]] || fail "$output"
}

function a_records_entry_is_never_resolved { # @test
  local root
  root=$(_act root card "subject = s:a" "subject-key = $(_key a)" "not-after = $LATER" \
    "right = x:check" "records = $UNKNOWN")
  run -0 _verify "$root"
}

# §4.5: effective expiry.

function a_child_of_an_expired_root_is_invalid { # @test
  local root link
  root=$(_root 2026-11-10T13:00:00Z)
  link=$(_link "$root")
  run -0 _verify "$link"
  # No `not-after` of its own: it inherits the root's.
  [[ $(_jq .effective_expiry) == 2026-11-10T13:00:00Z ]] || fail "$output"

  AT=2026-11-10T13:00:00Z
  run -1 _verify "$link"
  [[ $(_jq .failed_act) == "$root" ]] || fail "$output"
  [[ $(_jq .reason) == *expired* ]]
}

# §4.6: revocation.

function an_act_below_a_revoked_link_is_invalid { # @test
  local root link below
  root=$(_root)
  link=$(_link "$root")
  below=$(_act link b "subject = s:c" "subject-key = $(_key c)" "issuer = s:b" \
    "issuer-record = $link" "right = x:check")
  run -0 _verify "$below"

  # A card revocation under its own namespace (RFC 0012's fourth amendment).
  _act revocation card "names = $link" >/dev/null
  run -1 _verify "$below"
  [[ $(_jq .failed_act) == "$link" ]] || fail "$output"
  [[ $(_jq .reason) == *revoked* ]]
}

function a_software_revocation_by_a_stranger_is_refused_and_by_the_parent_accepted { # @test
  local root link below stranger
  root=$(_root)
  link=$(_link "$root")
  below=$(_act link b "subject = s:c" "subject-key = $(_key c)" "issuer = s:b" \
    "issuer-record = $link" "right = x:check")

  # s:c's key neither signed `link` nor is an ancestor key on its chain.
  stranger=$(_act revocation c "issuer = s:c" "issuer-record = $below" "names = $link")
  run -1 _verify "$stranger"
  [[ $(_jq .failed_step) == 5.2.5 ]] || fail "$output"
  run -0 _verify "$below"

  # s:a's key signed `link` and is an ancestor key of `below`.
  _act revocation a "issuer = s:a" "issuer-record = $root" "names = $below" >/dev/null
  run -1 _verify "$below"
  [[ $(_jq .reason) == *revoked* ]] || fail "$output"
}

function a_revocation_naming_a_revocation_is_refused { # @test
  local root link first second
  root=$(_root)
  link=$(_link "$root")
  first=$(_act revocation card "names = $link")
  second=$(_act revocation card "names = $first")
  run -1 _verify "$second"
  [[ $(_jq .failed_step) == 5.2.6 ]] || fail "$output"
}

# §4.7, §4.8: the namespace, kind, issuer and assurance table, applied at
# §5.2 step 3 (canonicalizing does not apply it, so it is checked here).

function a_pairing_the_namespace_table_does_not_list_is_refused { # @test
  local root link act
  root=$(_root)
  link=$(_link "$root")

  act=$(NAMESPACE=piggy-record-v1 _act escalation a "subject = s:b" "issuer = s:a" \
    "issuer-record = $root" "right = x:check" "names = $link")
  run -1 _verify "$act"
  [[ $(_jq .failed_step) == 5.2.3 ]] || fail "escalation under piggy-record-v1: $output"

  act=$(NAMESPACE=piggy-certificate-v1 _act revocation card "names = $link")
  run -1 _verify "$act"
  [[ $(_jq .failed_step) == 5.2.3 ]] || fail "revocation under piggy-certificate-v1: $output"

  act=$(ASSURANCE=piggy:hardware _act narrow b "subject = s:b" "issuer = s:b" \
    "issuer-record = $link" "right = x:check" "names = $link")
  run -1 _verify "$act"
  [[ $(_jq .failed_step) == 5.2.3 ]] || fail "piggy:hardware on a software act: $output"
}

# §5.3: undetermined.

function an_unresolvable_issuer_record_is_undetermined { # @test
  local link
  link=$(_link "$UNKNOWN")
  run -2 _verify "$link"
  [[ $(_jq .verdict) == undetermined ]] || fail "$output"
  [[ $(_jq '.unresolved | join(" ")') == "$UNKNOWN" ]]
}

function without_a_revocation_source_a_good_chain_is_undetermined { # @test
  local root link
  root=$(_root)
  link=$(_link "$root")
  run -2 "$PIGGY" act verify --act "$link" --at "$AT" --anchors "$DIR/anchors" \
    --store "$STORE" --format json
  [[ $(_jq .verdict) == undetermined ]] || fail "$output"
  [[ $(_jq .revocation_source) == none ]]
}

# §4.9, §5.3: layers, returned as given.

function layers_come_back_in_chain_order_marked_stencil_or_patch { # @test
  local root link profile=reviewer@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400
  root=$(_root)
  BODY=$'[x !y-v1\n  [-> z !w-v1 deny]]\n'
  link=$(_act link a "subject = s:b" "subject-key = $(_key b)" "issuer = s:a" \
    "issuer-record = $root" "profile = $profile" "right = x:check")
  run -0 _verify "$link"
  [[ $(_jq '.layers | length') == 2 ]] || fail "$output"
  [[ $(_jq '.layers[0].role') == stencil ]]
  [[ $(_jq '.layers[0].profile') == "$profile" ]]
  [[ $(_jq '.layers[1].role') == patch ]]
  # Byte for byte, trailing line feed included.
  cmp <(jq -j '.layers[1].body' <<<"$output") <(printf '%s' "$BODY")
}

# §4.9: an escalation replaces, for the act it names, only the layer kinds
# it carries.

PROFILE_OLD=reviewer@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400
PROFILE_NEW=builder@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400
PATCH_OLD=$'[x !y-v1\n  [-> z !w-v1 deny]]\n'
PATCH_NEW=$'[x !y-v1\n  [-> q !w-v1 deny]]\n'

# A link from a root carrying both a profile edge and a patch.
_layered_link() {
  ROOT=$(_root)
  BODY=$PATCH_OLD
  LINK=$(_act link a "subject = s:b" "subject-key = $(_key b)" "issuer = s:a" \
    "issuer-record = $ROOT" "profile = $PROFILE_OLD" "right = x:check")
  BODY=
}

function an_escalation_with_a_profile_and_no_body_keeps_the_acts_body { # @test
  local escalation
  _layered_link
  escalation=$(_act escalation card "subject = s:b" "right = x:check" \
    "profile = $PROFILE_NEW" "names = $LINK")
  run -0 _verify "$LINK"
  [[ $(_jq '.layers | length') == 2 ]] || fail "$output"
  [[ $(_jq '.layers[0].act') == "$escalation" ]]
  [[ $(_jq '.layers[0].role') == stencil ]]
  [[ $(_jq '.layers[0].profile') == "$PROFILE_NEW" ]]
  [[ $(_jq '.layers[1].act') == "$LINK" ]]
  [[ $(_jq '.layers[1].role') == patch ]]
  cmp <(jq -j '.layers[1].body' <<<"$output") <(printf '%s' "$PATCH_OLD")
}

function an_escalation_with_a_body_and_no_profile_replaces_only_the_body { # @test
  local escalation
  _layered_link
  BODY=$PATCH_NEW
  escalation=$(_act escalation card "subject = s:b" "right = x:check" "names = $LINK")
  BODY=
  run -0 _verify "$LINK"
  [[ $(_jq '.layers | length') == 2 ]] || fail "$output"
  [[ $(_jq '.layers[0].act') == "$LINK" ]]
  [[ $(_jq '.layers[0].profile') == "$PROFILE_OLD" ]]
  [[ $(_jq '.layers[1].act') == "$escalation" ]]
  [[ $(_jq '.layers[1].role') == patch ]]
  cmp <(jq -j '.layers[1].body' <<<"$output") <(printf '%s' "$PATCH_NEW")
}

function an_escalation_with_a_leafless_body_clears_the_acts_patch { # @test
  local escalation
  _layered_link
  # Whitespace only: non-empty, so a body to piggy (§3.1 step 7), and zero
  # leaves to the stencil fragment's patch reader.
  BODY=$'\n'
  escalation=$(_act escalation card "subject = s:b" "right = x:check" "names = $LINK")
  BODY=
  run -0 _verify "$LINK"
  [[ $(_jq '.layers | length') == 2 ]] || fail "$output"
  [[ $(_jq '.layers[0].profile') == "$PROFILE_OLD" ]]
  [[ $(_jq '.layers[1].act') == "$escalation" ]]
  [[ $(_jq '.layers[1].role') == patch ]]
  cmp <(jq -j '.layers[1].body' <<<"$output") <(printf '\n') || fail "$output"
}

# RFC 0013 §9's consumer examples (piggy#363).

PROFILE_MANAGER=manager-builder@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400
PROFILE_REVIEWER=engineer-reviewer@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400

# §9 (a), spinclass: a session certified by a card root holds a card grant
# over spinclass:profiles; the grant it hands its child over the same object
# pins a narrower profile.
_spinclass_session() {
  ROOT=$(_act root card "subject = clown:72dca00c" "subject-key = $(_key a)" \
    "not-after = $LATER" "right = spinclass:grant")
  CARD_GRANT=$(_act grant card "subject = clown:72dca00c" "object = spinclass:profiles" \
    "profile = $PROFILE_MANAGER" "right = spinclass:profile:builder" \
    "right = spinclass:profile:reviewer" "not-after = $LATER")
}

_spinclass_child_grant() { # _spinclass_child_grant RIGHT...
  local rights=() r
  for r in "$@"; do rights+=("right = $r"); done
  _act grant a "subject = clown:a1b2c3d4" "object = spinclass:profiles" \
    "issuer = clown:72dca00c" "issuer-record = $ROOT" "profile = $PROFILE_REVIEWER" \
    "${rights[@]}"
}

function spinclass_a_child_grant_carries_the_card_grants_stencil_before_its_own { # @test
  _spinclass_session
  local child
  child=$(_spinclass_child_grant spinclass:profile:reviewer)

  run -0 _verify "$child"
  [[ $(_jq .kind) == grant ]] || fail "$output"
  [[ $(_jq .object) == spinclass:profiles ]]
  [[ $(_jq '.rights | join(" ")') == spinclass:profile:reviewer ]]
  [[ $(_jq '.chain | join(" ")') == "$ROOT $child" ]]
  [[ $(_jq '.layers | length') == 2 ]] || fail "$output"
  [[ $(_jq '.layers[0].act') == "$CARD_GRANT" ]]
  [[ $(_jq '.layers[0].role') == stencil ]]
  [[ $(_jq '.layers[0].profile') == "$PROFILE_MANAGER" ]]
  [[ $(_jq '.layers[1].act') == "$child" ]]
  [[ $(_jq '.layers[1].role') == stencil ]]
  [[ $(_jq '.layers[1].profile') == "$PROFILE_REVIEWER" ]]
}

function spinclass_a_child_grant_with_a_right_the_card_grant_lacks_is_refused { # @test
  _spinclass_session
  local child
  child=$(_spinclass_child_grant spinclass:profile:reviewer spinclass:profile:root)
  run -1 _verify "$child"
  [[ $(_jq .failed_step) == 5.2.5 ]] || fail "$output"
  [[ $(_jq .failed_act) == "$child" ]]
}

# §9 (c), circus: an approval names its merge decision record and confers
# nothing.
function circus_an_approval_names_its_merge_decision_and_confers_nothing { # @test
  local approval
  approval=$(_act approval card "records = $UNKNOWN" "not-after = 2026-11-10T13:00:00Z")
  run -0 _verify "$approval"
  [[ $(_jq .kind) == approval ]] || fail "$output"
  [[ $(_jq 'has("rights") or has("layers")') == false ]] || fail "$output"
  [[ $(_jq .effective_expiry) == 2026-11-10T13:00:00Z ]]

  # The same head with a `right` line: the admission list refuses it at
  # §5.2 step 1, before any signature is looked at.
  sed '/^- kind = approval$/a - right = spinclass:merge' "$STORE/${approval##*-}.act" >"$DIR/with-right"
  run -1 _verify "$DIR/with-right"
  [[ $(_jq .failed_step) == 5.2.1 ]] || fail "$output"
  [[ $(_jq .reason) == *forbidden-field* ]]
}

# The adapters and the CLI contract.

function the_json_store_adapter_answers_as_the_directory_does { # @test
  local root link
  root=$(_root)
  link=$(_link "$root")
  local f json='{"acts": []}'
  for f in "$STORE"/*.act; do
    json=$(jq --rawfile act "$f" '.acts += [$act]' <<<"$json")
  done
  run -0 --separate-stderr "$PIGGY" act verify --act "$link" --at "$AT" \
    --anchors "$DIR/anchors" --store-stdin --store-is-revocation-source <<<"$json"
  assert_output "valid $link"
}

function a_path_to_an_act_verifies_like_its_digest { # @test
  local root link
  root=$(_root)
  link=$(_link "$root")
  run -0 "$PIGGY" act verify --at "$AT" --anchors "$DIR/anchors" --store "$STORE" \
    --store-is-revocation-source "$STORE/${link##*-}.act"
  assert_output "valid $link"
}

function a_usage_error_exits_3 { # @test
  run -3 "$PIGGY" act verify --at "$AT" /dev/null
  run -3 "$PIGGY" act verify --at yesterday --anchors "$DIR/anchors" /dev/null
}
