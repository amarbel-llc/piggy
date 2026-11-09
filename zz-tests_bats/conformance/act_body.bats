#! /usr/bin/env bats
#
# RFC 0013 §4.9 and §3.1 step 7: a body is signed as its bytes stand and
# piggy never parses it. An act with a body seals and verifies; one body
# byte changed breaks the signature; the body and the `profile` edge ride
# through the canonical form unchanged; a body with a C0 control character
# is refused before any signature is checked.
#
# Throwaway ssh-keygen keys: no card, no agent, no PIN.
#
# The §5.3 verdict that returns every layer of a chain belongs to the chain
# verifier (RFC 0013 S6); here the carrier is the canonical form, which is
# what `piggy act detach` hands `ssh-keygen -Y verify`.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  DIR=$BATS_TEST_TMPDIR
  ssh-keygen -q -t ed25519 -N '' -f "$DIR/key"
}

D_BLAKE=piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400
PROFILE=engineer-reviewer@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400

BODY=$'[moxy !clown-plugin-v1\n  [-> folio !mcp-server-v1\n    [-> read !mcp-tool-v1\n      [-> file:circus/.worktrees/_/infra/secrets !fs-path-v1 deny]]]]\n'

# An unsealed software link with a profile edge and $1 as its body.
_link_with_body() {
  local key
  key=$("$PIGGY" act key "$DIR/key.pub")
  cat <<EOF
---
- kind = link
- producer = spinclass:link-v1
- subject = clown:a1b2c3d4
- subject-key = $key
- issuer = clown:72dca00c
- issuer-key = $key
- issuer-record = $D_BLAKE
- profile = $PROFILE
- right = moxy:kind:read
- issued-at = 2026-11-09T22:15:00Z
- assurance = piggy:software
- key = $key
- namespace = piggy-record-v1
- hash = sha256
! piggy-act-v1
---

EOF
  printf '%s' "$1"
}

_seal() {
  "$PIGGY" act canon "$DIR/act" >"$DIR/canonical"
  ssh-keygen -q -Y sign -f "$DIR/key" -n piggy-record-v1 -O hashalg=sha256 "$DIR/canonical"
  "$PIGGY" act attach --signature "$DIR/canonical.sig" "$DIR/act" >"$DIR/sealed"
}

function an_act_with_a_body_seals_and_verifies { # @test
  _link_with_body "$BODY" >"$DIR/act"
  _seal
  run -0 "$PIGGY" act verify --seal-only "$DIR/sealed"
}

function the_body_and_profile_ride_through_unchanged { # @test
  _link_with_body "$BODY" >"$DIR/act"
  _seal
  "$PIGGY" act detach --signature "$DIR/sig" "$DIR/sealed" >"$DIR/detached"

  # The body is the last bytes of the canonical form, byte for byte.
  local size
  size=$(printf '%s' "$BODY" | wc -c)
  cmp <(printf '%s' "$BODY") <(tail -c "$size" "$DIR/detached")
  grep -qx -- "- profile = $PROFILE" "$DIR/detached"
}

function one_body_byte_changed_breaks_the_signature { # @test
  _link_with_body "$BODY" >"$DIR/act"
  _seal
  sed 's/!fs-path-v1 deny/!fs-path-v1 dent/' "$DIR/sealed" >"$DIR/changed"
  ! cmp -s "$DIR/sealed" "$DIR/changed" || fail "the edit changed nothing"

  run -1 --separate-stderr "$PIGGY" act verify --seal-only "$DIR/changed"
  [[ $stderr == *"refused (signature)"* ]] || fail "$stderr"
}

function a_body_with_a_control_character_is_refused { # @test
  _link_with_body $'[x !y-v1 deny]\e[2K\n' >"$DIR/act"
  run -1 --separate-stderr "$PIGGY" act verify --seal-only "$DIR/act"
  [[ $stderr == *"refused (body)"* ]] || fail "$stderr"
}
