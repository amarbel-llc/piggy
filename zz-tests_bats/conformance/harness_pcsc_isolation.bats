#! /usr/bin/env bats
#
# piggy#305: in the sandboxed default lane no test reaches the host's
# pcscd. The top-level harness gives every test its own fibby; the
# conformance files opt out of that (PIGGY_TEST_CARD=none) and set
# PCSCLITE_CSOCK_NAME per command, so the harness must point PC/SC at a
# dead socket for any command that does not.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

function sandboxed_lane_points_pcsc_at_a_dead_socket { # @test
  [[ -n ${PIGGY_BATS_NO_HOST_PCSC:-} ]] ||
    skip "PIGGY_BATS_NO_HOST_PCSC unset: not the sandboxed default lane"
  [[ -n ${PCSCLITE_CSOCK_NAME:-} ]] ||
    fail "PCSCLITE_CSOCK_NAME is unset, so PC/SC clients would use the host pcscd"
  [[ ! -e $PCSCLITE_CSOCK_NAME ]] ||
    fail "PCSCLITE_CSOCK_NAME=$PCSCLITE_CSOCK_NAME exists; it should name no socket"
}
