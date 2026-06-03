#! /usr/bin/env bats
# bats file_tags=hardware
#
# piggy#57: agentless direct-PCSC decrypt via the re-pointed Rust
# `piggy box stream decrypt`.
#
# Commit `79658e1` flipped `piggy box` to exec the C `pivy-box`, which
# requires an SSH agent for ECDH (no direct-PCSC fallback). #57 re-points
# `piggy box` back at piggy's Rust impl, whose `CardEcdhOracle` (#31, with
# the #56 `PinSession` transactions) decrypts **directly against the card
# with no agent**. This test guards that capability against silent
# regression — it is the focused replacement for the `piggy_box.bats` that
# `79658e1` deleted (that one asserted clap argv error output; this asserts
# the agentless data path).
#
# Flow: Rust `piggy-ids encrypt` -> `$PIGGY box stream decrypt` with
# SSH_AUTH_SOCK / PIGGY_AUTH_SOCK UNSET (so unlock must use the direct-PCSC
# card path), PIN supplied non-interactively by the test askpass
# (PIGGY_TEST_FIB_PIN), against a virtual PIV card.
#
# Card-agnostic (keyed on PCSCLITE_CSOCK_NAME + INTEROP_GUID) — driven by two
# recipes: `test-bats-conformance-interop` (against fib / jcardsim, opt-in)
# and `test-bats-conformance-box-agentless-fibby` (against fibby, the
# pure-Rust VirtualCard — in the default `just test` lane). Tests skip when
# the env vars are absent.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
    skip "PCSCLITE_CSOCK_NAME not set (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${PIGGY:-} || ! -x ${PIGGY:-} ]]; then
    skip "PIGGY not set or not executable (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${INTEROP_GUID:-} ]]; then
    skip "INTEROP_GUID not set (run: just test-bats-conformance-interop)"
  fi
  if [[ -z ${PIGGY_IDS_REAL:-} || ! -x ${PIGGY_IDS_REAL:-} ]]; then
    skip "PIGGY_IDS_REAL not set or not built"
  fi
}

function rust_encrypt_through_piggy_box_stream_decrypt_agentless { # @test
  # 1. Read the card's 9D pubkey through piggy-ids detect-pubkey -> markl ID.
  local recipient
  recipient="$("$PIGGY_IDS_REAL" detect-pubkey --guid "$INTEROP_GUID")"
  [[ -n $recipient ]] || fail "detect-pubkey returned empty markl ID"

  # 2. Build a single-recipient piggy-ids and encrypt to a temp file.
  local piggy_ids="$BATS_TEST_TMPDIR/agentless-piggy-ids"
  local ebox="$BATS_TEST_TMPDIR/agentless.ebox"
  echo "$recipient" >"$piggy_ids"
  local plaintext='piggy#57 agentless: rust encrypt -> piggy box stream decrypt (direct PCSC)'
  printf '%s' "$plaintext" |
    "$PIGGY_IDS_REAL" encrypt "$piggy_ids" >"$ebox" ||
    fail "Rust encrypt failed (status $?)"

  # 3. Decrypt with the re-pointed Rust `piggy box stream decrypt`. Unset
  #    SSH_AUTH_SOCK / PIGGY_AUTH_SOCK so there is NO agent oracle and unlock
  #    must take the direct-PCSC CardEcdhOracle path. PIN comes from the
  #    test askpass the recipe already wired (PIGGY_TEST_FIB_PIN).
  local recovered
  recovered="$(env -u SSH_AUTH_SOCK -u PIGGY_AUTH_SOCK \
    "$PIGGY" box stream decrypt <"$ebox")" ||
    fail "piggy box stream decrypt (agentless) failed (status $?)"

  [[ "$recovered" == "$plaintext" ]] ||
    fail "agentless round-trip lost the plaintext; got: '$recovered'"
}
