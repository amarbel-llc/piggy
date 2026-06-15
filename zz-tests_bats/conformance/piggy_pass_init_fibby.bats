#! /usr/bin/env bats
#
# Fibby-backed conformance for `piggy pass init`'s auto-detect path —
# the pure-Rust counterpart to the fib-backed conformance/piggy_pass_init.bats.
# Same two cases (no-args auto-detect, explicit `-g <guid>`), but driven
# against fibby's virtual slot 9D instead of the Java `fib` card.
#
# This is part of the fib→fibby retirement (docs/plans/2026-06-15-retire-fib-for-fibby.md,
# Phase 1 spike): `piggy pass init` reads the card's slot-9D pubkey via
# piggy-piv (PIN-free) and writes it as the store's recipient. The
# `--seed-rfc5903-slot-9d-cert` seed also installs the canonical CHUID, so
# fibby presents as an initialized card with a stable GUID — exactly what
# `piggy-ids detect-pubkey` / `pivy-tool list` need. No agent or PIN is
# required for init, so unlike the sync/ls-recipients fibby lanes this test
# brings up fibby only.
#
# Required env (supplied by the `test-bats-conformance-init-fibby` recipe):
#   FIBBY_BIN=/path/to/fibby      (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy      (nix build .#default — real pivy-box + piggy-ids)
#   PIVY_TOOL=/path/to/pivy-tool  (nix build .#pivy — for GUID discovery)
#
# When invoked via the conformance glob without those env vars set, the
# suite gracefully skips — same convention as the other fibby lanes.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-init-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable; run via just test-bats-conformance-init-fibby"
  fi

  # Init never prompts (slot-9D pubkey read is PIN-free), but wire the test
  # askpass safety net anyway so a stray pivy decrypt-path prompt can never
  # render a real dialog (CLAUDE.md "Test harness safety net for PIN prompts").
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""

  WORKDIR="$(mktemp -d -t initfibby.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=

  unset SSH_AUTH_SOCK
  # Fence git discovery at $WORKDIR — see piggy_pass_ls_recipients_fibby.bats.
  unset GIT_DIR GIT_WORK_TREE
  export GIT_CEILING_DIRECTORIES="$WORKDIR"

  init_test_git

  # Bring fibby up with a seeded slot 9D (+ canonical CHUID/GUID).
  spawn_fibby --seed-rfc5903-slot-9d-cert
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# `piggy pass init` with no args auto-detects the attached fibby card and
# writes its slot-9D recipient (markl ID) into the store's piggy-ids.
function init_no_args_auto_detects_fibby_card { # @test
  local store="$WORKDIR/store"
  mkdir -p "$store"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -q "Password store initialized" || {
    echo "missing 'Password store initialized' banner" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  [[ -f "$store/piggy-ids" ]] || fail "piggy-ids not written"

  # The recipient is the first non-comment, non-blank line — fibby's real
  # slot-9D markl ID. Assert it is present and non-empty.
  local recipient
  recipient="$(grep -v -e '^#' -e '^[[:space:]]*$' "$store/piggy-ids" | head -1 | awk '{print $1}')"
  [[ -n $recipient ]] || {
    echo "no recipient written to piggy-ids" >&2
    cat "$store/piggy-ids" >&2 || true
    return 1
  }
}

# `piggy pass init -g <guid>` against the explicitly-named fibby GUID writes
# the same recipient. The GUID comes from fibby's seeded CHUID, discovered
# via `pivy-tool list` (mirrors the dance in the fib-backed init lane).
function init_with_explicit_guid_fibby { # @test
  [[ -n ${PIVY_TOOL:-} ]] && [[ -x ${PIVY_TOOL:-/nonexistent} ]] || {
    skip "PIVY_TOOL unset or not executable; cannot discover GUID"
  }

  local guid
  guid="$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIVY_TOOL" list 2>&1 |
    grep -oiE '[0-9a-f]{32}' | head -1)"
  [[ -n $guid ]] || skip "no GUID found from pivy-tool list against fibby"

  local store="$WORKDIR/store-g"
  mkdir -p "$store"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init -g "$guid"
  [[ $status -eq 0 ]] || {
    echo "piggy pass init -g $guid exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -q "Password store initialized" || {
    echo "missing 'Password store initialized' banner" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  local recipient
  recipient="$(grep -v -e '^#' -e '^[[:space:]]*$' "$store/piggy-ids" | head -1 | awk '{print $1}')"
  [[ -n $recipient ]] || {
    echo "no recipient written to piggy-ids" >&2
    cat "$store/piggy-ids" >&2 || true
    return 1
  }
}
