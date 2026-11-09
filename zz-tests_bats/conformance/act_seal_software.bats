#! /usr/bin/env bats
#
# RFC 0013 §3.2, §3.3, §4.8, §7: `piggy act seal` for a software act. The
# producer checks the namespace and kind pairing before anything else, then
# asks the agent for an ordinary signature with the key the act's `key`
# names, normalizes it (low-S), seals the act, and writes only an act that
# `piggy act verify --seal-only` accepts.
#
# The agent is a plain OpenSSH ssh-agent holding throwaway keys: no card, no
# PIN, so no askpass safety net is needed. The card path is
# operator_act_seal.bats.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  DIR=$BATS_TEST_TMPDIR
  ssh-keygen -q -t ed25519 -N '' -f "$DIR/ed25519"
  ssh-keygen -q -t ecdsa -b 256 -N '' -f "$DIR/p256"
  ssh-keygen -q -t ed25519 -N '' -f "$DIR/stranger"

  # Short path: AF_UNIX sun_path is 108 bytes.
  SOCKDIR=$(mktemp -d -t actseal.XXXXXX)
  AGENT_SOCK="$SOCKDIR/agent.sock"
  ssh-agent -D -a "$AGENT_SOCK" >/dev/null 2>&1 3>&- &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && break
    sleep 0.1
  done
  [[ -S $AGENT_SOCK ]] || fail "ssh-agent never made $AGENT_SOCK"
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -q "$DIR/ed25519" "$DIR/p256" 2>/dev/null
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null
  [[ -n ${SOCKDIR:-} ]] && rm -rf "$SOCKDIR"
  true
}

D_BLAKE=piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400

# An unsealed software act of kind $2 signed by the key prefix $1.
_software_act() {
  local key
  key=$("$PIGGY" act key "$1.pub")
  cat <<EOF
---
- kind = ${2:-link}
- producer = spinclass:link-v1
- subject = clown:a1b2c3d4
- subject-key = $key
- issuer = clown:72dca00c
- issuer-key = $key
- issuer-record = $D_BLAKE
- right = moxy:kind:read
- issued-at = 2026-11-09T22:15:00Z
- assurance = piggy:software
- key = $key
- namespace = piggy-record-v1
- hash = sha256
! piggy-act-v1
---
EOF
}

function seal_signs_with_the_agents_ed25519_key_and_verifies { # @test
  _software_act "$DIR/ed25519" >"$DIR/act"
  PIGGY_AUTH_SOCK="$AGENT_SOCK" run -0 --separate-stderr "$PIGGY" act seal "$DIR/act"
  printf '%s\n' "$output" >"$DIR/sealed"

  grep -q -- '^- signature = piggy-record-sig-v1@ed25519_sig-' "$DIR/sealed"
  run -0 "$PIGGY" act verify --seal-only "$DIR/sealed"
  assert_output --regexp '^valid piggy-record-digest-v1@blake2b256-'
}

function seal_signs_with_the_agents_p256_key_and_verifies { # @test
  _software_act "$DIR/p256" >"$DIR/act"
  # Several runs: the agent's ECDSA is randomized, so about half its
  # signatures are high-S and must be normalized before they seal.
  local i
  for i in 1 2 3 4 5 6; do
    PIGGY_AUTH_SOCK="$AGENT_SOCK" "$PIGGY" act seal "$DIR/act" >"$DIR/sealed-$i"
    run -0 "$PIGGY" act verify --seal-only "$DIR/sealed-$i"
  done
}

function the_sealed_act_is_the_input_plus_its_signature { # @test
  _software_act "$DIR/ed25519" >"$DIR/act"
  PIGGY_AUTH_SOCK="$AGENT_SOCK" "$PIGGY" act seal "$DIR/act" >"$DIR/sealed"
  "$PIGGY" act canon "$DIR/act" >"$DIR/canonical"
  "$PIGGY" act canon "$DIR/sealed" >"$DIR/sealed.canonical"
  cmp "$DIR/canonical" "$DIR/sealed.canonical"
}

function a_kind_the_namespace_forbids_is_refused_before_the_agent { # @test
  # A root is a card act: it parses, and only the §4.8 table forbids it
  # under piggy-record-v1.
  _software_act "$DIR/ed25519" root >"$DIR/act"
  run -0 "$PIGGY" act canon "$DIR/act"
  # No socket at all: the pairing is refused before one is looked for.
  run -1 --separate-stderr "$PIGGY" act seal "$DIR/act"
  [[ $stderr == *"refused (namespace-pairing)"* ]] || fail "$stderr"
}

function a_key_the_agent_does_not_hold_is_refused { # @test
  _software_act "$DIR/stranger" >"$DIR/act"
  PIGGY_AUTH_SOCK="$AGENT_SOCK" run -1 --separate-stderr "$PIGGY" act seal "$DIR/act"
  [[ $stderr == *"does not hold the act's \`key\`"* ]] || fail "$stderr"
  assert_output ""
}

function no_agent_socket_exits_3 { # @test
  _software_act "$DIR/ed25519" >"$DIR/act"
  run -3 --separate-stderr "$PIGGY" act seal "$DIR/act"
  [[ $stderr == *"no agent socket"* ]] || fail "$stderr"
}
