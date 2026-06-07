setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

# `piggy health` runs in two very different environments:
#
#   - the sandboxed nix lane (bats-default): no pcscd, no live agent,
#     no tty — points 6-9 fail/skip deterministically;
#   - local `bats --no-sandbox` on a dev machine: a reachable pcscd
#     with a real card and a live ambient SSH agent are likely.
#
# common.bash does NOT scrub PIGGY_AUTH_SOCK/SSH_AUTH_SOCK, so every
# test here unsets (or pins) both to keep the agent-side points (2-5,
# 9) deterministic in both environments and to keep the probes off any
# live agent socket. Points 1 (systemd unit), 6-8 (pcscd/cards) vary
# by host and are only asserted where a guard makes them deterministic
# (see the pcscd-absent test at the bottom). The card probes the
# binary performs against a live pcscd are read-only (enumerate + cert
# read) — no PIN prompt can result from running these tests locally.

function health_unresolved_socket_fails_point_2_and_skips_dependents { # @test
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format tap
  assert_failure
  assert_line --index 0 "TAP version 14"
  assert_line --index 1 "1..9"
  assert_output --partial "not ok 2 - agent: socket resolved"
  assert_output --partial "ok 3 - agent: socket exists # SKIP socket unresolved"
  assert_output --partial "ok 4 - agent: answers request_identities # SKIP socket unresolved"
  assert_output --partial "ok 5 - agent: advertises ecdh extension # SKIP socket unresolved"
  assert_output --partial "ok 9 - agent serves attached card # SKIP agent or card data unavailable"
}

function health_dead_piggy_auth_sock_path_fails_point_3 { # @test
  # PIGGY_AUTH_SOCK wins over SSH_AUTH_SOCK, but unset the ambient one
  # anyway so no probe can reach a live agent on local runs.
  unset SSH_AUTH_SOCK
  export PIGGY_AUTH_SOCK="$BATS_TEST_TMPDIR/nope.sock"
  run "$PIGGY" health --format tap
  assert_failure
  assert_output --partial "ok 2 - agent: socket resolved"
  assert_output --partial "not ok 3 - agent: socket exists"
  assert_output --partial "ok 4 - agent: answers request_identities # SKIP path is not a socket"
  assert_output --partial "ok 5 - agent: advertises ecdh extension # SKIP path is not a socket"
}

function health_ndjson_emits_parseable_records_with_summary { # @test
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format ndjson
  assert_failure
  report="$output"
  # Every line parses as JSON: slurping the stream errors on any
  # malformed line. plan + 9 test records + summary = 11.
  run jq -es 'length' <<<"$report"
  assert_success
  assert_output "11"
  # The trailing record is the tap-ndjson(7) mandatory summary; the
  # unresolved socket guarantees at least one failure on every host.
  # Re-derive the last line from the verified report rather than the
  # first run's $lines, so the dependency on the count check is
  # explicit in the ordering.
  run jq -e '.type == "summary" and .failed >= 1' <<<"$(printf '%s' "$report" | tail -n1)"
  assert_success
}

function health_pcscd_absent_fails_point_6_and_skips_card_points { # @test
  # Environment asymmetry: this case is only real inside the sandboxed
  # nix lane, where no pcscd exists. On a dev machine a live pcscd
  # (and possibly a real card) is reachable, so probe for it cheaply
  # and skip — asserting on live-host card state is forbidden.
  if [[ -S "${PCSCLITE_CSOCK_NAME:-}" || -S /run/pcscd/pcscd.comm ]]; then
    skip "pcscd reachable on this host"
  fi
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format tap
  assert_failure
  assert_output --partial "not ok 6 - pcsc: daemon reachable"
  assert_output --partial "ok 7 - card: PIV card attached # SKIP pcscd unreachable"
  assert_output --partial "ok 8 - card: key-management slot 9D populated # SKIP pcscd unreachable"
}
