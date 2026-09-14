#! /usr/bin/env bats
# bats file_tags=hardware
#
# Hardware-tagged conformance for `piggy secrets reconcile` (FDR 0003) against
# fibby's seeded slot 9D. Covers the promotion cases that need a real unlock
# backend:
#
#   1. Every missing entry decrypts in one batch with exactly one PIN prompt.
#   2. A steady-state run touches no card (PC/SC pointed at nothing, no prompt).
#   3. A rotated entry rewrites only that entry.
#   4. An unreachable card leaves the previous output byte-identical.
#   5. An unrecorded target is a conflict until the entry adopts it.
#   6. --check reports drift without decrypting or writing.
#   7. An entry dropped from the manifest is released but its file kept.
#
# Parsing, classification and atomic-write behaviour are Rust unit tests in
# crates/piggy/src/secrets.rs; this file proves the card-facing contract.
#
# Uses `run -N` to assert specific exit codes; bats 1.5.0+ required.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-secrets-reconcile-fibby)"
  fi
  if [[ -z ${INTEROP_GUID:-} ]]; then
    skip "INTEROP_GUID not set (run: just test-bats-conformance-secrets-reconcile-fibby)"
  fi
  if [[ -z ${PIGGY_IDS_REAL:-} || ! -x ${PIGGY_IDS_REAL:-} ]]; then
    skip "PIGGY_IDS_REAL not set or not built"
  fi

  CARD_IDS="$BATS_TEST_TMPDIR/card-piggy-ids"
  "$PIGGY_IDS_REAL" detect-pubkey --guid "$INTEROP_GUID" >"$CARD_IDS" ||
    fail "detect-pubkey failed for INTEROP_GUID=$INTEROP_GUID"
  [[ -s $CARD_IDS ]] || skip "detect-pubkey returned an empty markl ID"

  export XDG_STATE_HOME="$BATS_TEST_TMPDIR/state"
  STATE_FILE="$XDG_STATE_HOME/piggy/secrets/state.json"
  CIPHER_DIR="$BATS_TEST_TMPDIR/cipher"
  TARGETS="$BATS_TEST_TMPDIR/home"
  MANIFEST="$BATS_TEST_TMPDIR/secrets.json"
  NO_PCSCD="$BATS_TEST_TMPDIR/no-such-pcscd.comm"
  mkdir -p "$CIPHER_DIR" "$TARGETS"

  # Count PIN prompts by wrapping the in-tree test askpass.
  ASKPASS_COUNTER="$BATS_TEST_TMPDIR/askpass-count"
  local counting_askpass="$BATS_TEST_TMPDIR/counting-askpass.sh"
  cat >"$counting_askpass" <<EOF
#!/usr/bin/env bash
echo \$(( \$(cat "$ASKPASS_COUNTER" 2>/dev/null || echo 0) + 1 )) >"$ASKPASS_COUNTER"
exec "$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh" "\$@"
EOF
  chmod +x "$counting_askpass"
  export SSH_ASKPASS="$counting_askpass"
}

# Seal PLAINTEXT to the card as $CIPHER_DIR/NAME.GENERATION.ebox and print
# the path. A new generation models a rotated (re-committed) ebox.
seal() {
  local name="$1" plaintext="$2" generation="${3:-1}"
  local path="$CIPHER_DIR/$name.$generation.ebox"
  printf '%s' "$plaintext" | "$PIGGY_IDS_REAL" encrypt "$CARD_IDS" >"$path"
  printf '%s' "$path"
}

# Write $MANIFEST from NAME=EBOX[,adopt] specs; each target is $TARGETS/NAME.
write_manifest() {
  local spec name ebox adopt sep=""
  {
    printf '{"version":1,"entries":['
    for spec in "$@"; do
      name="${spec%%=*}"
      ebox="${spec#*=}"
      adopt=false
      if [[ $ebox == *,adopt ]]; then
        ebox="${ebox%,adopt}"
        adopt=true
      fi
      printf '%s{"name":"%s","ebox":"%s","target":"%s","adopt":%s}' \
        "$sep" "$name" "$ebox" "$TARGETS/$name" "$adopt"
      sep=","
    done
    printf ']}\n'
  } >"$MANIFEST"
}

askpass_count() {
  cat "$ASKPASS_COUNTER" 2>/dev/null || echo 0
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

function reconcile_decrypts_every_missing_entry_with_one_pin_prompt { # @test
  local a b c
  a="$(seal alpha first)"
  b="$(seal beta second)"
  c="$(seal gamma third)"
  write_manifest "alpha=$a" "beta=$b" "gamma=$c"

  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success
  assert_line "1..3"
  assert_line "ok 1 - alpha"
  assert_line "ok 2 - beta"
  assert_line "ok 3 - gamma"

  run cat "$TARGETS/alpha"
  assert_output "first"
  run cat "$TARGETS/gamma"
  assert_output "third"
  [[ $(file_mode "$TARGETS/beta") == 600 ]] || fail "expected mode 600, got $(file_mode "$TARGETS/beta")"
  [[ $(askpass_count) == 1 ]] || fail "expected exactly 1 askpass call, got $(askpass_count)"
  assert [ -f "$STATE_FILE" ]
}

function steady_state_touches_no_card { # @test
  local a
  a="$(seal alpha first)"
  write_manifest "alpha=$a"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success
  rm -f "$ASKPASS_COUNTER"

  PCSCLITE_CSOCK_NAME="$NO_PCSCD" run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success
  assert_line "ok 1 - alpha # SKIP up to date"
  [[ $(askpass_count) == 0 ]] || fail "expected no askpass call, got $(askpass_count)"
}

function rotated_entry_rewrites_only_that_entry { # @test
  local a b a2
  a="$(seal alpha first)"
  b="$(seal beta second)"
  write_manifest "alpha=$a" "beta=$b"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success

  a2="$(seal alpha rotated 2)"
  write_manifest "alpha=$a2" "beta=$b"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success
  assert_line "ok 1 - alpha"
  assert_line "ok 2 - beta # SKIP up to date"
  run cat "$TARGETS/alpha"
  assert_output "rotated"
}

function unreachable_card_leaves_previous_output_intact { # @test
  local a a2
  a="$(seal alpha old)"
  write_manifest "alpha=$a"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success

  a2="$(seal alpha new 2)"
  write_manifest "alpha=$a2"
  PCSCLITE_CSOCK_NAME="$NO_PCSCD" run -1 --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_line "not ok 1 - alpha"
  run cat "$TARGETS/alpha"
  assert_output "old"
}

function unrecorded_target_is_a_conflict_until_adopted { # @test
  local a
  a="$(seal alpha secret)"
  printf 'hand-written' >"$TARGETS/alpha"
  write_manifest "alpha=$a"

  run -1 --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_line "not ok 1 - alpha"
  assert_output --partial "not recorded as piggy-managed"
  run cat "$TARGETS/alpha"
  assert_output "hand-written"
  [[ $(askpass_count) == 0 ]] || fail "a conflict must not prompt, got $(askpass_count) askpass calls"

  write_manifest "alpha=$a,adopt"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success
  assert_line "ok 1 - alpha"
  run cat "$TARGETS/alpha"
  assert_output "secret"
}

function check_reports_drift_without_decrypting { # @test
  local a
  a="$(seal alpha first)"
  write_manifest "alpha=$a"

  run -1 --separate-stderr "$PIGGY" secrets reconcile --check --manifest "$MANIFEST"
  assert_line "not ok 1 - alpha"
  assert_output --partial "would write (missing)"
  assert [ ! -e "$TARGETS/alpha" ]
  [[ $(askpass_count) == 0 ]] || fail "--check must not prompt, got $(askpass_count) askpass calls"
}

function dropped_entry_is_released_but_its_file_kept { # @test
  local a b
  a="$(seal alpha first)"
  b="$(seal beta second)"
  write_manifest "alpha=$a" "beta=$b"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success

  write_manifest "alpha=$a"
  run --separate-stderr "$PIGGY" secrets reconcile --manifest "$MANIFEST"
  assert_success
  assert_output --partial "orphaned: released; file kept"
  assert [ -f "$TARGETS/beta" ]
  run grep -F "$TARGETS/beta" "$STATE_FILE"
  assert_failure
}
