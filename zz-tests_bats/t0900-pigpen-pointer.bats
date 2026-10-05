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
  # mocks there). Returns a recipient-set pigpen doc naming one
  # recipient, the public X25519 key of the RFC 0008 vectors: a pointer
  # that resolves to no encryption recipients is refused (piggy#302).
  # The crate-level tests in pigpen_pointer.rs cover recipient content
  # conversion in depth. Each invocation appends one byte to
  # RESOLVER_CALL_COUNT so a test can assert the Task 8 cache-TTL
  # wiring actually skips re-invoking it on a second call.
  FIXTURE_RECIPIENT="piggy-recipient-v1@age_x25519_pub-q73he0q5yzfu3d64msd3p6rvksnrwjk3d2598mgtmlqt9wrdr37q0vdmee"
  RESOLVER_CALL_COUNT="$BATS_TEST_TMPDIR/resolver-call-count"
  : >"$RESOLVER_CALL_COUNT"
  export RESOLVER_CALL_COUNT
  cat >"$BATS_TEST_TMPDIR/pigpen-resolver-bats-fixture" <<EOF
#!/bin/sh
printf x >>"$RESOLVER_CALL_COUNT"
printf -- '---\n- $FIXTURE_RECIPIENT\n! pigpen-v1\n---\n'
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
  # The one recipient of the resolved recipient-set doc.
  assert_output --partial "age_x25519_pub-q73he0q5"
}

function pigpen_pointer_resolving_to_no_recipients_is_refused { # @test
  cat >"$BATS_TEST_TMPDIR/pigpen-resolver-bats-fixture" <<'EOF'
#!/bin/sh
printf -- '---\n! pigpen-v1\n---\n'
EOF
  run "$PIGGY" pass recipients list
  assert_failure
  assert_output --partial "resolved to no encryption recipients"
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
