#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#193 — `piggy list` surfaces a factory-blank (uninitialized) PIV card.
#
# A blank card has no CHUID, so piggy-piv's strict `connect`/`enumerate_tokens`
# drop it (read_chuid errors). `piggy list` uses the tolerant
# `enumerate_tokens_including_uninitialized` path, which presents such a card as
# a card-level `uninitialized` record carrying its reader + serial — the handle
# papi needs to discover a blank card for provisioning (papi#17).
#
# Driven direct-PCSC against fibby (no agent). A no-seed fibby card presents as
# blank (SELECT PIV ok, GET DATA CHUID -> 6A82). We use `--model yk5` so the
# vendor serial INS (0xF8) returns fibby's pinned yk5 serial (0x00F2C2E6 =
# 15909606); the default yk4 model returns 6D00 (no serial), matching real
# YubiKey 4 firmware.
#
# Required env (supplied by `test-bats-conformance-list-blank-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-list-blank-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi

  WORKDIR="$(mktemp -d -t lsblank.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_PID=

  # `piggy list` is read-only/PIN-free, but unset agent sockets so nothing
  # reaches an ambient agent — enumeration talks to fibby via PCSCLITE_CSOCK_NAME.
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# A blank yk5 card → one `uninitialized` ndjson record with all-zeros guid and
# the card's serial (the provisioning handle).
function blank_card_appears_uninitialized_in_ndjson { # @test
  spawn_fibby --model yk5

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$PIGGY_BIN" list --format=ndjson
  [[ $status -eq 0 ]] || {
    echo "piggy list --format=ndjson exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local line
  line=$(printf '%s\n' "$output" | grep '"uninitialized":true' | head -1)
  [[ -n $line ]] || {
    echo "no uninitialized record in piggy list output" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$line" | grep -q '"guid":"00000000000000000000000000000000"' || {
    echo "uninitialized record missing all-zeros guid: $line" >&2
    return 1
  }
  # fibby's pinned yk5 serial 0x00F2C2E6 = 15909606.
  printf '%s\n' "$line" | grep -q '"serial":15909606' || {
    echo "uninitialized record missing the expected serial: $line" >&2
    return 1
  }
}

# Human format renders the blank card as a `# uninitialized:` comment line.
function blank_card_human_is_comment { # @test
  spawn_fibby --model yk5

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$PIGGY_BIN" list --format=human
  [[ $status -eq 0 ]] || {
    echo "piggy list --format=human exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q '^# uninitialized:' || {
    echo "no '# uninitialized:' comment line in human output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# No-regression: an INITIALIZED card (seeded 9D + CHUID) is NOT reported as
# uninitialized — it shows its recipient record as before.
function provisioned_card_is_not_uninitialized { # @test
  spawn_fibby --model yk5 --seed-rfc5903-slot-9d-cert

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$PIGGY_BIN" list --format=ndjson
  [[ $status -eq 0 ]] || {
    echo "piggy list --format=ndjson exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  if printf '%s\n' "$output" | grep -q '"uninitialized":true'; then
    echo "a provisioned card was wrongly reported uninitialized" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
  # It should instead surface a recipient record for the 9D slot.
  printf '%s\n' "$output" | grep -q '"slot":"9D"' || {
    echo "provisioned card did not surface its 9D recipient record" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}
