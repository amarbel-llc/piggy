#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#87 — `piggy list` and `piggy pass recipients list-available`
# end to end against fibby: no card present, record shape, the
# recipient-slot subset, and sort order. Blank-card discovery is
# piggy_list_blank_fibby.bats.
#
# Driven direct-PCSC against fibby (no agent); both commands are PIN-free.
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

  WORKDIR="$(mktemp -d -t lsfib.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_LOG="$WORKDIR/fibby.log"
  FIBBY_CTL="$WORKDIR/control.sock"
  FIBBY_PID=

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
}

# Run `piggy <args>` against fibby; fail with its output and the fibby log
# on a nonzero exit.
piggy_against_fibby() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" run "$PIGGY_BIN" "$@"
  [[ $status -eq 0 ]] || {
    echo "piggy $* exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
}

# The "slot" value of every ndjson line in $output, in order.
slots_of_output() {
  printf '%s\n' "$output" | sed -n 's/.*"slot":"\([0-9A-F]*\)".*/\1/p'
}

# The "guid" value of every ndjson line in $output, in order.
guids_of_output() {
  printf '%s\n' "$output" | sed -n 's/.*"guid":"\([0-9A-F]*\)".*/\1/p'
}

# A reader with its card pulled: both commands exit 0 and print nothing.
function no_card_present_exits_zero_with_no_records { # @test
  spawn_fibby --control-socket "$FIBBY_CTL" --seed-rfc5903-slot-9d-cert
  "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" remove "Virtual PCD piggy fibby 00 00"

  piggy_against_fibby list --format=ndjson
  [[ -z $output ]] || {
    echo "piggy list printed records with no card present:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  piggy_against_fibby pass recipients list-available --format=ndjson
  [[ -z $output ]] || {
    echo "list-available printed records with no card present:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# Every ndjson line is one object carrying id, guid, reader and slot.
function ndjson_records_are_objects_with_the_core_fields { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-slot-9c-cert --seed-rfc5903-slot-9d-cert

  piggy_against_fibby list --format=ndjson
  [[ -n $output ]] || {
    echo "piggy list printed nothing for a seeded card" >&2
    return 1
  }
  local line
  while IFS= read -r line; do
    [[ $line == '{'*'}' ]] || {
      echo "not a JSON object: $line" >&2
      return 1
    }
    for field in id guid reader slot; do
      [[ $line == *"\"$field\":"* ]] || {
        echo "record lacks \"$field\": $line" >&2
        return 1
      }
    done
  done <<<"$output"
}

# Human format: the markl id, then a `# guid=…, reader=…, slot=…` comment.
function human_records_are_id_then_metadata_comment { # @test
  spawn_fibby --seed-rfc5903-slot-9d-cert

  piggy_against_fibby list --format=human
  printf '%s\n' "$output" | grep -Eq '^[^ #]+  # guid=[0-9A-F]{32}, .*reader=.*, slot=9D' || {
    echo "no '<id>  # guid=…, reader=…, slot=9D' line in human output:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# list-available is the recipient-slot subset of list: 9D only from a card
# holding 9A, 9C and 9D, and each of its records is a record of list.
function list_available_is_the_recipient_subset_of_list { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-slot-9c-cert --seed-rfc5903-slot-9d-cert

  piggy_against_fibby list --format=ndjson
  local all="$output"
  [[ $(slots_of_output | tr '\n' ' ') == "9A 9C 9D " ]] || {
    echo "piggy list slots: $(slots_of_output | tr '\n' ' ')" >&2
    printf '%s\n' "$all" >&2
    return 1
  }

  piggy_against_fibby pass recipients list-available --format=ndjson
  [[ $(slots_of_output | tr '\n' ' ') == "9D " ]] || {
    echo "list-available slots: $(slots_of_output | tr '\n' ' ')" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  local line
  while IFS= read -r line; do
    grep -qxF -- "$line" <<<"$all" || {
      echo "list-available record not in piggy list: $line" >&2
      printf '%s\n' "$all" >&2
      return 1
    }
  done <<<"$output"
}

# Records sort by card GUID, then slot, whatever order the readers come in:
# the second reader's card is given a GUID that sorts before the first's.
function records_sort_by_guid_then_slot { # @test
  local low=00000000000000000000000000000001
  spawn_fibby \
    --card "Reader One" --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert \
    --card "Reader Two" --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert \
    --seed-chuid-guid "$low"

  piggy_against_fibby list --format=ndjson
  local guids slots first
  guids=$(guids_of_output)
  slots=$(slots_of_output | tr '\n' ' ')
  first=$(head -1 <<<"$guids")
  [[ $first == "$low" ]] || {
    echo "first record's guid is $first, want $low (the lower GUID):" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  [[ $guids == "$(sort <<<"$guids")" ]] || {
    echo "records are not in GUID order:" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  [[ $slots == "9A 9D 9A 9D " ]] || {
    echo "slots within each card are not 9A then 9D: $slots" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}
