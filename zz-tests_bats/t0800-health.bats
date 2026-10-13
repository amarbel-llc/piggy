setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  # Keep the card probes off the host's pcscd, and so off any real card:
  # pcsc-lite's client honours this path on Linux. macOS's PCSC.framework
  # may not, which is why the assertions below still tolerate a card. The
  # lane as a whole is not hermetic against the host's pcscd: piggy#305.
  export PCSCLITE_CSOCK_NAME="$BATS_TEST_TMPDIR/no-pcscd.comm"
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
# (see the pcscd-absent test at the bottom). setup keeps the probes off
# the host's pcscd on Linux; where it cannot, the card probes the binary
# performs are read-only (enumerate + cert read, and since FDR 0006 an
# attestation request per slot) — no PIN prompt can result from running
# these tests locally.
#
# The plan is the base nine plus two FDR 0006 policy points per attached
# card, so its length varies by host too: assert_plan_is_base_nine_plus_cards
# pins the shape without pinning the number of cards.

# The TAP plan line is 1..N with N = 9 + 2 * (cards attached).
assert_plan_is_base_nine_plus_cards() {
  local plan="${lines[1]}"
  [[ $plan =~ ^1\.\.([0-9]+)$ ]] || fail "not a TAP plan line: $plan"
  local count="${BASH_REMATCH[1]}"
  ((count >= 9 && (count - 9) % 2 == 0)) ||
    fail "plan $plan is not the base nine plus two points per card"
}

function health_unresolved_socket_fails_point_2_and_skips_dependents { # @test
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format tap
  assert_failure
  assert_line --index 0 "TAP version 14"
  assert_plan_is_base_nine_plus_cards
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
  # malformed line. The plan record counts the test records, at least
  # the base nine; the stream is plan + tests + summary.
  run jq -es '.[0].type == "plan" and .[0].count >= 9 and length == .[0].count + 2' <<<"$report"
  assert_success
  # The trailing record is the tap-ndjson(7) mandatory summary; the
  # unresolved socket guarantees at least one failure on every host.
  # Re-derive the last line from the verified report rather than the
  # first run's $lines, so the dependency on the count check is
  # explicit in the ordering.
  run jq -e '.type == "summary" and .failed >= 1' <<<"$(printf '%s' "$report" | tail -n1)"
  assert_success
}

function health_sign_test_reports_unreachable_agent_without_disturbing_plan { # @test
  # piggy#179: `--sign-test` adds an opt-in agent self-sign probe on stderr.
  # With both sockets unset it cannot reach an agent (so it never signs and
  # never prompts for a PIN), reports the unresolved socket, and the run
  # still fails. The TAP stream on stdout keeps its plan.
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format tap --sign-test
  assert_failure
  assert_plan_is_base_nine_plus_cards
  assert_output --partial "piggy health --sign-test (piggy#179): agent self-sign probe"
  assert_output --partial "agent socket unresolved"
}

function health_pcscd_absent_fails_point_6_and_skips_card_points { # @test
  # setup points pcsc-lite at a socket that does not exist, which makes
  # this case real on Linux whatever the host runs. Elsewhere the system
  # PC/SC stack may ignore that and reach a live daemon (and possibly a
  # real card) — asserting on live-host card state is forbidden.
  if [[ $(uname -s) != Linux ]]; then
    skip "cannot keep the probe off this host's PC/SC daemon"
  fi
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format tap
  assert_failure
  assert_output --partial "not ok 6 - pcsc: daemon reachable"
  assert_output --partial "ok 7 - card: PIV card attached # SKIP pcscd unreachable"
  assert_output --partial "ok 8 - card: key-management slot 9D populated # SKIP pcscd unreachable"
}
