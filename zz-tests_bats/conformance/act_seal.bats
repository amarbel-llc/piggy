#! /usr/bin/env bats
#
# RFC 0013 §3.2 to §3.5: the seal. A sealed act and a detached sshsig are
# equivalent: `ssh-keygen -Y sign` over the canonical form, attached with
# `piggy act attach`, verifies under `piggy act verify --seal-only`; and a
# sealed act detached with `piggy act detach` verifies under
# `ssh-keygen -Y verify`. A blob whose namespace, key or hash algorithm is
# not the seal's is refused; a changed head breaks the signature; the act
# digest covers the signature.
#
# Keys are throwaway ssh-keygen keys, Ed25519 and ECDSA P-256: no card, no
# agent, no PIN, so no askpass safety net is needed.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  DIR=$BATS_TEST_TMPDIR
  ssh-keygen -q -t ed25519 -N '' -C act-ed25519 -f "$DIR/ed25519"
  ssh-keygen -q -t ecdsa -b 256 -N '' -C act-p256 -f "$DIR/p256"
}

D_BLAKE=piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400

# An unsealed software link signed by the key in $1 (a key file prefix).
_software_link() {
  local key
  key=$("$PIGGY" act key "$1.pub")
  cat <<EOF
---
# link: manager hands the reviewer a read-only tree
- kind = link
- producer = spinclass:link-v1
- subject = clown:a1b2c3d4
- subject-key = $key
- issuer = clown:72dca00c
- issuer-key = $key
- issuer-record = $D_BLAKE
- right = moxy:kind:read
- not-after = 2026-11-10T06:00:00Z
- issued-at = 2026-11-09T22:15:00Z
- assurance = piggy:software
- key = $key
- namespace = piggy-record-v1
- hash = sha256
! piggy-act-v1
---
EOF
}

# An unsealed card root whose `key` is the P-256 key in $1, as a card's
# slot-9C key would be.
_card_root() {
  local card principal
  card=$("$PIGGY" act key --card "$1.pub")
  principal=$("$PIGGY" act key "$DIR/ed25519.pub")
  cat <<EOF
---
- kind = root
- producer = troupe:root-v1
- subject = clown:72dca00c
- subject-key = $principal
- issuer = operator
- issuer-key = $card
- right = spinclass:check
- not-after = 2026-11-09T23:00:00Z
- issued-at = 2026-11-08T23:00:00Z
- assurance = piggy:hardware
- key = $card
- namespace = piggy-certificate-v1
- hash = sha256
! piggy-act-v1
---
EOF
}

# Sign act file $1 with key prefix $2 under namespace $3 (hash $4, default
# sha256) the way any ssh-keygen holder would, and attach: the sealed act
# is $1.sealed.
_sign_and_attach() {
  local act=$1 key=$2 namespace=$3 hash=${4:-sha256}
  "$PIGGY" act canon "$act" >"$act.canonical"
  ssh-keygen -q -Y sign -f "$key" -n "$namespace" -O hashalg="$hash" "$act.canonical"
  "$PIGGY" act attach --signature "$act.canonical.sig" "$act" >"$act.sealed"
}

# Verify sealed act $1 with ssh-keygen through a detached sshsig.
_ssh_keygen_verifies() {
  local act=$1 pub=$2 namespace=$3
  "$PIGGY" act detach --signature "$act.detached.sig" "$act" >"$act.detached"
  printf 'signer %s\n' "$(cat "$pub")" >"$act.allowed"
  ssh-keygen -Y verify -f "$act.allowed" -I signer -n "$namespace" \
    -s "$act.detached.sig" <"$act.detached"
}

function an_ed25519_signature_from_ssh_keygen_seals_an_act { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  _sign_and_attach "$DIR/act" "$DIR/ed25519" piggy-record-v1

  run -0 "$PIGGY" act verify --seal-only "$DIR/act.sealed"
  assert_output --regexp '^valid piggy-record-digest-v1@blake2b256-[a-z0-9]+$'
  grep -q -- '^- signature = piggy-record-sig-v1@ed25519_sig-' "$DIR/act.sealed"
}

function a_p256_signature_from_ssh_keygen_seals_an_act { # @test
  _software_link "$DIR/p256" >"$DIR/act"
  _sign_and_attach "$DIR/act" "$DIR/p256" piggy-record-v1

  run -0 "$PIGGY" act verify --seal-only "$DIR/act.sealed"
  grep -q -- '^- signature = piggy-record-sig-v1@ecdsa_p256_sig-' "$DIR/act.sealed"
}

function a_card_shaped_p256_root_seals_and_verifies { # @test
  _card_root "$DIR/p256" >"$DIR/act"
  _sign_and_attach "$DIR/act" "$DIR/p256" piggy-certificate-v1

  run -0 "$PIGGY" act verify --seal-only "$DIR/act.sealed"
  run -0 _ssh_keygen_verifies "$DIR/act.sealed" "$DIR/p256.pub" piggy-certificate-v1
}

function a_sealed_act_detached_verifies_under_ssh_keygen { # @test
  local key
  for key in ed25519 p256; do
    _software_link "$DIR/$key" >"$DIR/act-$key"
    _sign_and_attach "$DIR/act-$key" "$DIR/$key" piggy-record-v1
    run -0 _ssh_keygen_verifies "$DIR/act-$key.sealed" "$DIR/$key.pub" piggy-record-v1
  done
}

function the_detached_canonical_form_is_the_act_without_its_signature { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  _sign_and_attach "$DIR/act" "$DIR/ed25519" piggy-record-v1

  "$PIGGY" act detach --signature "$DIR/sig" "$DIR/act.sealed" >"$DIR/detached"
  cmp "$DIR/act.canonical" "$DIR/detached"
}

function a_blob_under_another_namespace_is_refused { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  "$PIGGY" act canon "$DIR/act" >"$DIR/canonical"
  ssh-keygen -q -Y sign -f "$DIR/ed25519" -n file -O hashalg=sha256 "$DIR/canonical"

  run -1 --separate-stderr "$PIGGY" act attach --signature "$DIR/canonical.sig" "$DIR/act"
  [[ $stderr == *"refused (signature)"*namespace* ]] || fail "$stderr"
}

function a_blob_under_another_hash_is_refused { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  "$PIGGY" act canon "$DIR/act" >"$DIR/canonical"
  ssh-keygen -q -Y sign -f "$DIR/ed25519" -n piggy-record-v1 -O hashalg=sha512 "$DIR/canonical"

  run -1 --separate-stderr "$PIGGY" act attach --signature "$DIR/canonical.sig" "$DIR/act"
  [[ $stderr == *"refused (signature)"*hash* ]] || fail "$stderr"
}

function a_blob_by_another_key_is_refused { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  "$PIGGY" act canon "$DIR/act" >"$DIR/canonical"
  ssh-keygen -q -Y sign -f "$DIR/p256" -n piggy-record-v1 -O hashalg=sha256 "$DIR/canonical"

  run -1 --separate-stderr "$PIGGY" act attach --signature "$DIR/canonical.sig" "$DIR/act"
  [[ $stderr == *"refused (signature)"*key* ]] || fail "$stderr"
}

function a_changed_head_breaks_the_signature { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  _sign_and_attach "$DIR/act" "$DIR/ed25519" piggy-record-v1
  sed 's/^- right = moxy:kind:read$/- right = moxy:kind:write/' "$DIR/act.sealed" >"$DIR/widened"

  run -1 --separate-stderr "$PIGGY" act verify --seal-only "$DIR/widened"
  [[ $stderr == *"refused (signature)"* ]] || fail "$stderr"
}

function an_unsealed_act_does_not_verify { # @test
  _software_link "$DIR/ed25519" >"$DIR/act"
  run -1 --separate-stderr "$PIGGY" act verify --seal-only "$DIR/act"
  [[ $stderr == *"refused (missing-field)"*signature* ]] || fail "$stderr"
}

function the_digest_covers_the_signature { # @test
  # ECDSA as ssh-keygen makes it is randomized, so two signings of one head
  # are two acts with two digests (§3.5).
  _software_link "$DIR/p256" >"$DIR/act"
  _sign_and_attach "$DIR/act" "$DIR/p256" piggy-record-v1
  local first
  first=$("$PIGGY" act digest "$DIR/act.sealed")
  rm "$DIR/act.canonical.sig"
  _sign_and_attach "$DIR/act" "$DIR/p256" piggy-record-v1
  local second
  second=$("$PIGGY" act digest "$DIR/act.sealed")

  [[ $first == piggy-record-digest-v1@blake2b256-* ]] || fail "$first"
  [[ $first != "$second" ]] || fail "re-signing kept the digest $first"
  run -0 "$PIGGY" act digest --sha256 "$DIR/act.sealed"
  assert_output --regexp '^piggy-record-digest-v1@sha256-'
}

function verify_without_anchors_is_a_usage_error { # @test
  # The chain walk needs trust anchors. `piggy act verify`'s exit code is
  # the verdict (2 is undetermined), so its usage errors are 3.
  run -3 "$PIGGY" act verify /dev/null
}
