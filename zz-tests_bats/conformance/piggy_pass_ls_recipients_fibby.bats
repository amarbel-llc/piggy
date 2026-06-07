#! /usr/bin/env bats
#
# Fibby-backed proof that `piggy pass show -r` / `--recipients` annotates each
# ebox in the store tree with its REAL recipient, read offline from the ebox
# wire header (no card, no PIN, no decrypt — just `Ebox::from_bytes`).
#
# This is the real-crypto counterpart to the mock-based smoke test in
# t0020-show.bats. The base64 mock writes .ebox files that are NOT real ebox
# wire format, so under the mock every leaf degrades to the `[?]` sentinel and
# only the renderer/dispatch is exercised. Here, with fibby's virtual slot 9D
# and the wrapped piggy (.#default, real pivy-box + piggy-ids), `pass init` +
# `pass insert` write GENUINE eboxes whose recipient is the card's real P-256
# pubkey — so we can assert the rendered annotation matches that recipient.
#
# Required env (supplied by the
# `test-bats-conformance-pass-ls-recipients-fibby` recipe):
#   PIVY_AGENT=/path/to/pivy-agent  (nix build .#pivy)
#   FIBBY_BIN=/path/to/fibby        (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy        (nix build .#default — real pivy-box +
#                                    piggy-ids, bypassing common.bash's mocks)
#
# When invoked via the conformance lane's glob without those env vars set, the
# suite gracefully skips — same convention as the sync/smoke fibby lanes.
#
# NB: recipient extraction is an OFFLINE header read, so unlike the sync lane
# this test needs no agent/askpass for the assertion itself. We still bring up
# fibby (to create real eboxes via init/insert); pivy-agent + askpass are wired
# the same way for parity and in case insert ever needs them.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${PIVY_AGENT:-} ]] || [[ ! -x ${PIVY_AGENT:-/nonexistent} ]]; then
    skip "PIVY_AGENT unset or not executable; run via just test-bats-conformance-pass-ls-recipients-fibby"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable; run via just test-bats-conformance-pass-ls-recipients-fibby"
  fi

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""

  WORKDIR="$(mktemp -d -t lsrec.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  unset SSH_AUTH_SOCK
  # See piggy_recipients_sync_fibby.bats for why GIT_DIR/GIT_WORK_TREE are
  # cleared and discovery is fenced at $WORKDIR.
  unset GIT_DIR GIT_WORK_TREE
  export GIT_CEILING_DIRECTORIES="$WORKDIR"
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Set up a git-backed store seeded from fibby's slot-9D recipient, with the
# named secrets inserted. Mirrors the helper in piggy_recipients_sync_fibby.bats.
# Args: <store-dir> <name>=<secret> ...
_init_store_with_secrets() {
  local store="$1"
  shift

  mkdir -p "$store"
  PIGGY_STORE_DIR="$store" run "$PIGGY_BIN" pass git init
  [[ $status -eq 0 ]] || {
    echo "piggy pass git init exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local pair name secret
  for pair in "$@"; do
    name="${pair%%=*}"
    secret="${pair#*=}"
    printf '%s\n' "$secret" | PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
      PIGGY_STORE_DIR="$store" "$PIGGY_BIN" pass insert -e "$name"
    local ins=$?
    [[ $ins -eq 0 && -f "$store/$name.ebox" ]] || {
      echo "piggy pass insert $name exited $ins (ebox present: $([[ -f $store/$name.ebox ]] && echo yes || echo no))" >&2
      tail -40 "$FIBBY_LOG" >&2 || true
      return 1
    }
  done
}

# `pass show -r` annotates every ebox with the card's real recipient. With a
# single fibby card, every entry shares one recipient, so we assert: exit 0,
# the tree structure, NO `[?]` sentinel (extraction succeeded for real eboxes),
# and that the rendered recipient prefix is an actual prefix of the recipient
# recorded in the store's piggy-ids.
function pass_show_recipients_annotates_real_eboxes_via_fibby { # @test
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert
  spawn_agent

  local store="$WORKDIR/store"
  _init_store_with_secrets "$store" "foo/bar=secret-one" "baz=secret-two"

  # The card's recipient as recorded in piggy-ids (the first non-comment,
  # non-blank line is the markl ID).
  local recipient
  recipient="$(grep -v -e '^#' -e '^[[:space:]]*$' "$store/piggy-ids" | head -1 | awk '{print $1}')"
  [[ -n $recipient ]] || {
    echo "could not read recipient from $store/piggy-ids" >&2
    cat "$store/piggy-ids" >&2 || true
    return 1
  }

  PIGGY_STORE_DIR="$store" run "$PIGGY_BIN" pass show -r
  [[ $status -eq 0 ]] || {
    echo "piggy pass show -r exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # Tree structure: the foo dir, both leaves.
  printf '%s\n' "$output" | grep -q "Password Store" || {
    echo "missing 'Password Store' banner" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q "foo" || {
    echo "missing foo dir in tree" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q "bar" || {
    echo "missing bar leaf in tree" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q "baz" || {
    echo "missing baz leaf in tree" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # Real eboxes parsed → no `[?]` sentinel anywhere.
  if printf '%s\n' "$output" | grep -q '\[?\]'; then
    echo "unexpected [?] sentinel — real ebox extraction should have succeeded" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi

  # The rendered annotation is a truncated prefix of the real recipient.
  # Pull the bracketed annotation off a leaf line and strip the trailing
  # ellipsis, then assert it's a prefix of $recipient.
  local shown
  shown="$(printf '%s\n' "$output" | grep -oE '\[piggy-recipient-v1@[^]]*\]' | head -1)"
  [[ -n $shown ]] || {
    echo "no [piggy-recipient-v1@...] annotation found in output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  # Strip the surrounding [ ] and any trailing … (UTF-8 3-byte ellipsis).
  shown="${shown#\[}"
  shown="${shown%\]}"
  shown="${shown%…}"
  case "$recipient" in
    "$shown"*) : ;; # shown is a prefix of the real recipient — good
    *)
      echo "rendered prefix '$shown' is not a prefix of recipient '$recipient'" >&2
      return 1
      ;;
  esac
}
