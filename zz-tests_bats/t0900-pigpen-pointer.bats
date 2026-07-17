setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"

  # PIN-prompt safety net (CLAUDE.md): a pigpen-pointer piggy-ids
  # resolves entirely offline through the fixture resolver script below
  # (no card, no agent), so no prompt should ever fire. Pin a refusing
  # askpass anyway — if a future change caused an unexpected
  # fallthrough, it must refuse loudly, never pop a GUI. Mirrors the
  # pattern in t0850-sign-bytes.bats.
  export SSH_ASKPASS="$(dirname "$BATS_TEST_FILE")/helpers/piggy-test-askpass.sh"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset PIGGY_TEST_FIB_PIN

  # Fixture resolver: PATH-discovered as `pigpen-resolver-<kind>` per
  # RFC 0010 (kind="bats-fixture" below). $BATS_TEST_TMPDIR is already
  # on PATH (common.bash installs the pivy-box/pivy-tool/piggy-ids
  # mocks there). Always returns an empty recipient-set pigpen doc —
  # a store with zero encryption recipients is enough to prove the
  # pointer -> resolver -> RFC 0003 cache path end-to-end; the
  # crate-level tests in pigpen_pointer.rs already cover recipient
  # content conversion in depth. Each invocation appends one byte to
  # RESOLVER_CALL_COUNT so a test can assert the Task 8 cache-TTL
  # wiring actually skips re-invoking it on a second call.
  RESOLVER_CALL_COUNT="$BATS_TEST_TMPDIR/resolver-call-count"
  : >"$RESOLVER_CALL_COUNT"
  export RESOLVER_CALL_COUNT
  cat >"$BATS_TEST_TMPDIR/pigpen-resolver-bats-fixture" <<EOF
#!/bin/sh
printf x >>"$RESOLVER_CALL_COUNT"
printf -- '---\n! pigpen-v1\n---\n'
EOF
  chmod +x "$BATS_TEST_TMPDIR/pigpen-resolver-bats-fixture"

  cat >"$PIGGY_STORE_DIR/piggy-ids" <<'EOF'
---
- kind="bats-fixture"
- locator="unused"
! pigpen-pointer-v1
---
EOF
}

function pigpen_pointer_resolves_for_recipients_list { # @test
  run "$PIGGY" pass recipients list
  assert_success
  # Zero recipients in the resolved (empty) recipient-set doc.
  assert_output ""
}

function pigpen_pointer_cache_skips_resolver_on_second_call_within_ttl { # @test
  run "$PIGGY" pass recipients list
  assert_success

  run "$PIGGY" pass recipients list
  assert_success

  # The second call must hit the raw-resolver-output cache instead of
  # re-invoking pigpen-resolver-bats-fixture (Task 8's CACHE_TTL).
  run cat "$RESOLVER_CALL_COUNT"
  assert_output "x"
}
