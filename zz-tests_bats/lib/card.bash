# Shared helpers for the `piggy card` fibby lanes (piggy_card_init_fibby.bats,
# piggy_card_add_key_fibby.bats): read a card back through `piggy list`,
# assert a slot's attested policy, report a failed run, and stand up the
# two-card store whose backup card a sealed management key is encrypted to.
#
# Consumers `load` this after lib/fibby.bash, with PIGGY_BIN, FIBBY_SOCK and
# FIBBY_LOG set; card_spawn_with_backup_recipient also needs PIGGY_IDS_BIN
# and PIGGY_STORE_DIR (common.bash).

# The two cards of the seal cases: card A is the one provisioned, card B
# carries a seeded 9D key and is the store's only recipient.
CARD_READER_A="Virtual PCD fibby A 00 00"
CARD_READER_B="Virtual PCD fibby B 00 00"
CARD_GUID_B="B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"

card_list_ndjson() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" list --format=ndjson
}

# The `piggy list` record for GUID's SLOT (`9A`); empty when it has none.
card_slot_record() {
  local guid="$1" slot="$2" out
  out=$(card_list_ndjson) || return 1
  printf '%s\n' "$out" | grep -F "\"guid\":\"$guid\"" | grep -F "\"slot\":\"$slot\"" || true
}

# The `id` of GUID's SLOT record: its public key as a markl id.
card_slot_id() {
  card_slot_record "$1" "$2" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'
}

# Assert the policy `piggy list` reports for GUID's SLOT. It comes from the
# slot's attestation, so only a key generated on the card carries one.
card_assert_slot_policy() {
  local guid="$1" slot="$2" pin="$3" touch="$4" record
  record=$(card_slot_record "$guid" "$slot")
  if [[ -z $record ]]; then
    echo "no $slot record for $guid" >&2
    card_list_ndjson >&2 || true
    return 1
  fi
  [[ $record == *"\"pin_policy\":\"$pin\""* && $record == *"\"touch_policy\":\"$touch\""* ]] || {
    echo "slot $slot is not PIN $pin / touch $touch: $record" >&2
    return 1
  }
}

# Fail the test with MESSAGE, the last `run`'s status/stdout/stderr and the
# tail of the fibby log.
card_fail_with_output() {
  echo "$1" >&2
  printf 'status: %s\nstdout: %s\nstderr: %s\n' "$status" "$output" "${stderr:-}" >&2
  tail -60 "$FIBBY_LOG" >&2 || true
  return 1
}

# Spawn cards A (blank) and B (seeded 9D, GUID CARD_GUID_B) and make card B
# the store's only recipient. Extra args go to fibby before the cards.
card_spawn_with_backup_recipient() {
  [[ -x ${PIGGY_IDS_BIN:-/nonexistent} ]] ||
    skip "PIGGY_IDS_BIN unset; run via the lane's just recipe"
  spawn_fibby "$@" \
    --card "$CARD_READER_A" \
    --card "$CARD_READER_B" --seed-rfc5903-slot-9d-cert --seed-chuid-guid "$CARD_GUID_B"
  local b_id
  b_id=$(PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_IDS_BIN" detect-pubkey --guid "$CARD_GUID_B") || {
    echo "detect-pubkey on the backup card failed" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$b_id" >"$PIGGY_STORE_DIR/piggy-ids"
}
