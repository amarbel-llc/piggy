#! /usr/bin/env bats
# bats file_tags=hardware
#
# Hardware-tagged conformance for `piggy pass show-batch`. Companion to
# piggy_pass_show_batch.bats — the sandbox file covers usage validation
# and the non-card error surface; this one covers the card-required
# cases that need real PCSC + a real PIV card (fib or fibby):
#
#   1. Single-ebox happy path (decrypt + 0600 atomic write).
#   2. N>1 batch with the single-PIN guarantee (RFC 0005 marquee
#      promise — one askpass invocation across N decrypts).
#   3. Wrong-card bail-out (ebox sealed to a recipient no attached
#      card holds; BatchOracle bails before any decrypt).
#   4. Heterogeneous batch (per-ebox failure stays under decrypt-failed,
#      NOT fatal-for-batch).
#
# The SIGINT-midbatch bail-out case used to live here too but was
# inherently backend-speed-dependent (it raced wall-clock for a mid-batch
# window that a fast backend like fibby never offers); it now has a
# deterministic Rust unit test (#176, show_batch.rs
# sigint_after_first_item_bails_before_the_rest).
#
# show-batch's single-card-path posture means there's no mock-pivy-box
# shortcut — the only way to exercise its real BatchOracle is against
# a live card. See crates/piggy/src/show_batch.rs and #121 for the
# implementation context.
#
# Uses `run -N` to assert specific exit codes; bats 1.5.0+ required.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-show-batch-fibby)"
  fi
  if [[ -z ${INTEROP_GUID:-} ]]; then
    skip "INTEROP_GUID not set (run: just test-bats-conformance-show-batch-fibby)"
  fi
  if [[ -z ${PIGGY_IDS_REAL:-} || ! -x ${PIGGY_IDS_REAL:-} ]]; then
    skip "PIGGY_IDS_REAL not set or not built"
  fi

  OUT_DIR="$BATS_TEST_TMPDIR/show-batch-out"

  # Detect fib's 9D pubkey via real PCSC and write a single-recipient
  # piggy-ids file. Reused by every test in this file to seal eboxes
  # the BatchOracle CAN match against fib.
  FIB_PIGGY_IDS="$BATS_TEST_TMPDIR/fib-piggy-ids"
  local fib_recipient
  fib_recipient="$("$PIGGY_IDS_REAL" detect-pubkey --guid "$INTEROP_GUID")"
  [[ -n $fib_recipient ]] || skip "detect-pubkey returned empty markl ID for INTEROP_GUID=$INTEROP_GUID"
  echo "$fib_recipient" >"$FIB_PIGGY_IDS"

  # Foreign recipient: a VALID off-card P-256 point (the curve generator G,
  # compressed SEC1) that no attached card holds — eboxes sealed to it drive
  # the wrong-card bail-out. #176: the previous value was the markl
  # FORMAT-test vector (payload bytes 0x00..0x20), whose 0x00 leading byte is
  # not a valid SEC1 point prefix, so `pivy-box`/OpenSSL rejected it at
  # encrypt time ("invalid encoding") and seal_to_foreign failed before the
  # batch could run. G is on-curve and encrypts cleanly; the card holds the
  # RFC-5903 point, so G stays correctly "foreign".
  FOREIGN_PIGGY_IDS="$BATS_TEST_TMPDIR/foreign-piggy-ids"
  echo "piggy-recipient-v1@pivy_ecdh_p256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfve2jwdn" >"$FOREIGN_PIGGY_IDS"

  mkdir -p "$PIGGY_STORE_DIR"
}

# Seal `plaintext` to FIB's 9D pubkey and write the ebox to
# $PIGGY_STORE_DIR/<name>.ebox.
seal_to_fib() {
  local name="$1" plaintext="$2"
  printf '%s' "$plaintext" |
    "$PIGGY_IDS_REAL" encrypt "$FIB_PIGGY_IDS" >"$PIGGY_STORE_DIR/${name}.ebox" ||
    fail "encrypt to fib for $name failed (status $?)"
}

# Seal `plaintext` to the foreign (off-card) recipient.
seal_to_foreign() {
  local name="$1" plaintext="$2"
  printf '%s' "$plaintext" |
    "$PIGGY_IDS_REAL" encrypt "$FOREIGN_PIGGY_IDS" >"$PIGGY_STORE_DIR/${name}.ebox" ||
    fail "encrypt to foreign recipient for $name failed (status $?)"
}

function show_batch_single_ebox_happy_path { # @test
  # 1. Seal one ebox to fib's 9D pubkey.
  seal_to_fib "test1" "hello world"

  # 2. show-batch should decrypt it cleanly.
  # --separate-stderr: the on-demand askpass writes a `[piggy-test-askpass]`
  # banner to stderr; without this, bats merges it into $output/$lines and
  # shifts every assert_line --index (#176). Stdout is then pure NDJSON.
  run --separate-stderr "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" test1
  assert_success

  # plan + decrypt-ok + summary, no bail-out.
  assert_line --index 0 --partial '"type":"plan"'
  assert_line --index 0 --partial '"count":1'
  assert_line --index 1 --partial '"type":"decrypt"'
  assert_line --index 1 --partial '"n":1'
  assert_line --index 1 --partial '"name":"test1"'
  assert_line --index 1 --partial '"ok":true'
  assert_line --index 1 --partial '"out_path"'
  # `diagnostic` is Option<Diagnostic>; serde renders Some as the
  # object and None as null (no skip_serializing_if). On success we
  # expect `"diagnostic":null` — the field name appears, but its
  # payload is null, so refute `"kind"` (only in failure diagnostics).
  assert_line --index 1 --partial '"diagnostic":null'
  refute_line --index 1 --partial '"kind"'
  assert_output --partial '"type":"summary"'
  assert_output --partial '"ok":1'
  assert_output --partial '"failed":0'
  refute_output --partial '"type":"bail-out"'

  # 3. Plaintext on disk has the right contents and mode.
  local out_path="$OUT_DIR/test1"
  assert [ -f "$out_path" ]
  run cat "$out_path"
  assert_output "hello world"
  # Mode is 0o600 — atomic_write_0600 in show_batch.rs.
  local mode
  mode="$(stat -c '%a' "$out_path" 2>/dev/null || stat -f '%Lp' "$out_path")"
  [[ $mode == "600" ]] || fail "expected mode 600, got $mode"
}

function show_batch_batch_of_three_invokes_askpass_exactly_once { # @test
  # The single-PIN guarantee is the marquee RFC 0005 promise: across
  # N decrypts in one show-batch run, the askpass is called exactly
  # once. Wrap the in-tree piggy-test-askpass.sh in a counter-stub so
  # we can see how many times BatchOracle reached for a PIN.
  seal_to_fib "test1" "first"
  seal_to_fib "test2" "second"
  seal_to_fib "test3" "third"

  local counter="$BATS_TEST_TMPDIR/askpass-count"
  local wrapper="$BATS_TEST_TMPDIR/counter-askpass.sh"
  cat >"$wrapper" <<EOF
#!/usr/bin/env bash
counter="$counter"
echo \$(( \$(cat "\$counter" 2>/dev/null || echo 0) + 1 )) >"\$counter"
exec "$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh" "\$@"
EOF
  chmod +x "$wrapper"

  SSH_ASKPASS="$wrapper" \
    run --separate-stderr "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" test1 test2 test3
  assert_success

  assert_line --index 0 --partial '"count":3'
  assert_line --index 1 --partial '"n":1'
  assert_line --index 1 --partial '"name":"test1"'
  assert_line --index 1 --partial '"ok":true'
  assert_line --index 2 --partial '"n":2'
  assert_line --index 2 --partial '"name":"test2"'
  assert_line --index 2 --partial '"ok":true'
  assert_line --index 3 --partial '"n":3'
  assert_line --index 3 --partial '"name":"test3"'
  assert_line --index 3 --partial '"ok":true'
  assert_output --partial '"ok":3'
  assert_output --partial '"failed":0'

  # The promise: exactly one PIN prompt for N decrypts.
  local count
  count="$(cat "$counter" 2>/dev/null || echo 0)"
  [[ $count == "1" ]] || fail "expected exactly 1 askpass call, got $count"

  # And the three plaintexts landed correctly.
  run cat "$OUT_DIR/test1"
  assert_output "first"
  run cat "$OUT_DIR/test2"
  assert_output "second"
  run cat "$OUT_DIR/test3"
  assert_output "third"
}

function show_batch_wrong_card_emits_bail_out { # @test
  # First ebox sealed to a recipient no attached card holds. show-
  # batch's card-enumeration step finds no matching 9D, emits
  # bail-out with the documented reason, and exits non-zero WITHOUT
  # any decrypt records (the bail-out happens before per-ebox work
  # begins) and WITHOUT prompting for a PIN (RFC 0005 §Single-card
  # Operation: "MUST NOT prompt for a PIN").
  seal_to_foreign "wrong1" "this should never decrypt"

  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" wrong1
  assert_failure

  assert_line --index 0 --partial '"type":"plan"'
  assert_line --index 0 --partial '"count":1'
  # bail-out is the last record, replacing summary.
  assert_output --partial '"type":"bail-out"'
  assert_output --partial 'no attached PIV card has a 9D slot matching'
  refute_output --partial '"type":"summary"'
  # No plaintext should have been written.
  assert [ ! -f "$OUT_DIR/wrong1" ]
}

function show_batch_heterogeneous_batch_per_ebox_failure { # @test
  # First ebox sealed to fib (matches → drives card selection);
  # second sealed to the off-card recipient. The first decrypts
  # cleanly, the second hits the BatchOracle's NoKey path. Same
  # P-256 curve on both sides, so check_curve_mismatch returns
  # None; show-batch falls through to the generic decrypt-failed
  # diagnostic. Per show_batch.rs's `decrypt_one` and RFC 0005
  # decision 3c ("wrong recipient stays under decrypt-failed"),
  # this is per-ebox failure — NOT fatal-for-batch.
  seal_to_fib "ok1" "first ok"
  seal_to_foreign "bad1" "second sealed off-card"

  # --separate-stderr keeps the askpass banner out of $output (#176).
  run --separate-stderr "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" ok1 bad1
  assert_failure

  assert_line --index 0 --partial '"count":2'
  assert_line --index 1 --partial '"n":1'
  assert_line --index 1 --partial '"name":"ok1"'
  assert_line --index 1 --partial '"ok":true'
  assert_line --index 2 --partial '"n":2'
  assert_line --index 2 --partial '"name":"bad1"'
  assert_line --index 2 --partial '"ok":false'
  assert_line --index 2 --partial '"kind":"decrypt-failed"'
  # Per-ebox failure → summary, not bail-out.
  assert_output --partial '"type":"summary"'
  assert_output --partial '"ok":1'
  assert_output --partial '"failed":1'
  refute_output --partial '"type":"bail-out"'

  # The first plaintext was written; the second was not.
  run cat "$OUT_DIR/ok1"
  assert_output "first ok"
  assert [ ! -f "$OUT_DIR/bad1" ]
}

# NOTE: the SIGINT-midbatch bail-out case used to live here but raced
# wall-clock for a mid-batch window — it relied on a slow cold-fib ECDH
# (~5–10s/decrypt) to deliver SIGINT after the first decrypt but before the
# rest. On a fast backend like fibby the whole batch completes before the
# signal lands, so the test was inherently backend-speed-dependent (#176).
# The loop's bail-at-boundary control flow (item record emitted, remaining
# items skipped, bail_reason set so run() emits bail-out not summary) is now
# covered deterministically by the Rust unit test
# `show_batch::tests::sigint_after_first_item_bails_before_the_rest`.
