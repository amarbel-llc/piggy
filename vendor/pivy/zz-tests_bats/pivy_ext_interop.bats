#! /usr/bin/env bats
#
# Hardware integration tests for SSH agent extension response types (#15).
# Requires a YubiKey plugged in.
#
# Run:  just zz-tests_bats/test-tags hardware

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  PIVY_DIR="${PIVY_DIR:-$(dirname "$BATS_TEST_FILE")/../result}"
  PIVY_AGENT="$PIVY_DIR/bin/pivy-agent"
  PIVY_TOOL="$PIVY_DIR/bin/pivy-tool"
  PIVY_BOX="$PIVY_DIR/bin/pivy-box"

  if [[ ! -x $PIVY_AGENT ]]; then
    skip "pivy not found at $PIVY_DIR (run: nix build)"
  fi

  # Check for a PIV card before doing anything
  if ! "$PIVY_TOOL" -p list &>/dev/null; then
    skip "no PIV card found (is your YubiKey plugged in?)"
  fi

  # Use /tmp to keep Unix socket path under 104-byte limit
  PIVY_TMPDIR="$(mktemp -d /tmp/pivy-test.XXXXXX)"
  AGENT_SOCK="$PIVY_TMPDIR/agent.sock"
  TPL_FILE="$PIVY_TMPDIR/test.tpl"
  ENC_FILE="$PIVY_TMPDIR/encrypted.bin"
  DEC_FILE="$PIVY_TMPDIR/decrypted.txt"

  # Get GUID while we have direct PCSC access (before agent starts)
  local list_output
  list_output="$("$PIVY_TOOL" -p list)"
  CARD_GUID="$(echo "$list_output" | head -1 | cut -d: -f2)"
  [[ -n $CARD_GUID ]] || skip "could not parse GUID from pivy-tool output"

  # Create template while we have direct PCSC access
  "$PIVY_BOX" tpl create -f "$TPL_FILE" primary local-guid "$CARD_GUID"

  # Start agent in foreground mode
  "$PIVY_AGENT" -A -D -a "$AGENT_SOCK" &
  AGENT_PID=$!
  # Wait for socket to appear
  local tries=0
  while [[ ! -S $AGENT_SOCK ]] && ((tries < 10)); do
    sleep 0.2
    tries=$((tries + 1))
  done
  [[ -S $AGENT_SOCK ]] || {
    kill "$AGENT_PID" 2>/dev/null || true
    skip "agent socket did not appear"
  }

  export SSH_AUTH_SOCK="$AGENT_SOCK"
}

teardown() {
  if [[ -n ${AGENT_PID:-} ]]; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n ${PIVY_TMPDIR:-} ]]; then
    rm -rf "$PIVY_TMPDIR"
  fi
}

# bats test_tags=hardware
function agent_lists_identities { # @test
  run ssh-add -l
  assert_success
  assert_output --partial "PIV_slot_9A"
  # ssh-add shows the short GUID (first 4 bytes); CARD_GUID is the full 16-byte hex
  assert_output --partial "${CARD_GUID:0:8}"
}

# bats test_tags=hardware
function stream_encrypt_decrypt_round_trip { # @test
  local payload="hello from pivy extension interop test"

  echo "$payload" | "$PIVY_BOX" stream encrypt -Rf "$TPL_FILE" >"$ENC_FILE"
  [[ -s $ENC_FILE ]]

  "$PIVY_BOX" stream decrypt -bR <"$ENC_FILE" >"$DEC_FILE"
  run cat "$DEC_FILE"
  assert_success
  assert_output "$payload"
}

# bats test_tags=hardware
function template_shows_card_guid { # @test
  run "$PIVY_BOX" tpl show -f "$TPL_FILE"
  assert_success
  assert_output --partial "$CARD_GUID"
  assert_output --partial "slot: 9D"
}
