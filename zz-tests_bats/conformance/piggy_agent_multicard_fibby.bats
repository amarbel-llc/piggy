#! /usr/bin/env bats
#
# piggy#242 / piggy#177 — multi-card gate: ONE fibby process serving TWO
# virtual cards (two readers on one PCSC socket), fronted by the Rust
# `piggy agent -A`.
#
# The stack per test:
#
#   fibby --card A (9A cert + CHUID, canonical GUID)
#         --card B (9C cert + CHUID, explicit distinct GUID)
#     <- pcsc -> piggy agent -A  <- ssh-add / ssh-keygen
#
# Covered here (the binary-level complement to fibby's two-reader
# loopback test and the agent's PinCache unit tests):
#   - `-A` enumerates BOTH cards: two identities, two distinct GUIDs in
#     the comments
#   - signing with each card's key works, and the PIN is prompted ONCE
#     PER CARD (piggy#177: the per-GUID PIN cache prompts for B even
#     though A's identical PIN is already cached — the old global cache
#     would have reused it silently), with no wrong-PIN VERIFY ever
#     hitting either card
#
# Required env (supplied by the `test-bats-conformance-agent-multicard`
# recipe):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)
#
# When invoked via the conformance glob without those env vars set, the
# suite gracefully skips — same convention as the sibling fibby lanes.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-agent-multicard"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456

  # Short-path workdir under /tmp — $BATS_TEST_TMPDIR can overrun AF_UNIX
  # sun_path's 108-byte limit under deep nix sandbox prefixes.
  WORKDIR="$(mktemp -d -t agmc.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  # Card B's explicit GUID: a distinct PREFIX (not just a distinct last
  # byte like the derived default), so the two cards' short-ids differ in
  # the agent's identity comments.
  GUID_B="B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Two cards: A carries the RFC 6979 9A cert (canonical GUID); B carries
# the fibby 9C cert under an explicit distinct GUID. Distinct slots =>
# distinct keypairs, so the merged listing is two different keys.
_spawn_fibby_two_cards() {
  spawn_fibby \
    --card "Virtual PCD fibby A 00 00" --seed-rfc6979-slot-9a-cert \
    --card "Virtual PCD fibby B 00 00" --seed-slot-9c-cert \
    --seed-chuid-guid "$GUID_B"
}

_spawn_rust_agent() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent -A -a "$AGENT_SOCK" \
    >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  cat "$AGENT_LOG" >&2 || true
  cat "$FIBBY_LOG" >&2 || true
  return 1
}

# `-A` against a two-card fibby serves both cards' identities, tagged
# with their distinct GUIDs.
function all_cards_mode_lists_both_cards { # @test
  _spawn_fibby_two_cards
  _spawn_rust_agent

  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  local keys
  keys=$(printf '%s\n' "$output" | grep -c '^ecdsa-sha2-nistp256 ') || true
  [[ $keys -eq 2 ]] || {
    echo "expected 2 identities across the two cards, got $keys:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  # Card A's 9A key (canonical GUID prefix 191755cf) and card B's 9C key
  # (explicit b2b2… GUID) are both attributed correctly.
  printf '%s\n' "$output" | grep -q 'PIV_slot_9A 191755CF' || {
    echo "card A's 9A identity missing/mis-attributed:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q 'PIV_slot_9C B2B2B2B2' || {
    echo "card B's 9C identity missing/mis-attributed:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# Sign with EACH card's key through one agent socket; both verify. The
# piggy#177 gate rides along: the PIN must be prompted once PER CARD —
# two askpass invocations, even though both cards share the default PIN
# (the old global cache reused A's PIN for B and prompted once) — and no
# wrong-PIN VERIFY may ever hit either card.
function sign_via_each_card_prompts_pin_once_per_card { # @test
  _spawn_fibby_two_cards
  _spawn_rust_agent

  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 ]]
  printf '%s\n' "$output" >"$WORKDIR/listing"
  grep 'PIV_slot_9A 191755CF' "$WORKDIR/listing" >"$WORKDIR/key_a.pub"
  grep 'PIV_slot_9C B2B2B2B2' "$WORKDIR/listing" >"$WORKDIR/key_b.pub"

  local f
  for f in a b; do
    printf 'payload-%s\n' "$f" >"$WORKDIR/data_$f"
    local ktype kdata _rest
    read -r ktype kdata _rest <"$WORKDIR/key_$f.pub"
    printf 'signer-%s %s %s\n' "$f" "$ktype" "$kdata" >"$WORKDIR/data_$f.signers"
    SSH_AUTH_SOCK="$AGENT_SOCK" \
      ssh-keygen -Y sign -f "$WORKDIR/key_$f.pub" -U -n file "$WORKDIR/data_$f" || {
      echo "sign via card $f failed" >&2
      tail -40 "$AGENT_LOG" >&2 || true
      tail -60 "$FIBBY_LOG" >&2 || true
      return 1
    }
    ssh-keygen -Y verify -f "$WORKDIR/data_$f.signers" -I "signer-$f" \
      -n file -s "$WORKDIR/data_$f.sig" <"$WORKDIR/data_$f" >/dev/null || {
      echo "verify of card $f's signature failed" >&2
      return 1
    }
  done

  # piggy#177: one prompt per card. A global PIN cache would have
  # prompted once (both cards share the default PIN) and silently
  # verified A's cached PIN on B.
  local prompts
  prompts=$(grep -c "\[piggy-test-askpass\] supplying" "$AGENT_LOG") || true
  [[ $prompts -eq 2 ]] || {
    echo "expected exactly 2 askpass prompts (one per card), got $prompts" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  # And no wrong-PIN VERIFY ever hit a card.
  ! grep -q "(wrong PIN)" "$FIBBY_LOG" || {
    echo "a wrong-PIN VERIFY reached a card:" >&2
    grep "(wrong PIN)" "$FIBBY_LOG" >&2
    return 1
  }
}
