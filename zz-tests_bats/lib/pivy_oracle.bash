# The frozen C pivy oracle (piggy#285, #289 Phase 5).
#
# Differential lanes used to run C pivy-tool live beside the Rust port. A
# lane now calls `pivy_oracle CASE ARGS...` instead, and the call either:
#
#   capture (PIGGY_ORACLE_MODE=capture, REAL_PIVY_TOOL set): runs the real
#     C pivy-tool with ARGS (stdin passed through), stores its stdout and
#     exit status as <lane>/CASE.{out,status} under PIVY_ORACLE_CAPTURE_DIR
#     (the capture recipe copies that into fixtures/pivy-oracle/ afterwards,
#     since the sandboxed lane cannot write the repo), and answers with them;
#   replay (the default): answers with the stored stdout and status, and
#     fails the test when the fixture is missing.
#
# Lanes set PIVY_ORACLE_LANE before calling. `just
# codemod-capture-pivy-oracle-<lane>` re-records a lane; the replay lanes
# need no C binary at all. The fixtures are the C behaviour the port was
# held to, so a re-capture is only for a deliberate change.

PIVY_ORACLE_DIR="$PIGGY_BATS_DIR/fixtures/pivy-oracle"

# pivy_oracle CASE ARGS... — C pivy-tool's stdout for ARGS, with its exit
# status as this function's status.
pivy_oracle() {
  local case="$1"
  shift
  [[ -n ${PIVY_ORACLE_LANE:-} ]] || {
    echo "pivy_oracle: PIVY_ORACLE_LANE is unset" >&2
    return 99
  }
  local base="$PIVY_ORACLE_DIR/$PIVY_ORACLE_LANE/$case"

  if [[ ${PIGGY_ORACLE_MODE:-replay} == capture ]]; then
    [[ -x ${REAL_PIVY_TOOL:-} && -n ${PIVY_ORACLE_CAPTURE_DIR:-} ]] || {
      echo "pivy_oracle: capture needs REAL_PIVY_TOOL and PIVY_ORACLE_CAPTURE_DIR" >&2
      return 99
    }
    base="$PIVY_ORACLE_CAPTURE_DIR/$PIVY_ORACLE_LANE/$case"
    mkdir -p "$(dirname "$base")"
    local status=0
    "$REAL_PIVY_TOOL" "$@" >"$base.out" || status=$?
    printf '%s\n' "$status" >"$base.status"
    # A lane whose C call changes the card defines this to put the card
    # back, so the Rust side starts from the state C did, as in replay.
    if declare -F pivy_oracle_after_capture >/dev/null; then
      pivy_oracle_after_capture
    fi
  fi

  [[ -f $base.out && -f $base.status ]] || {
    echo "pivy_oracle: no fixture for $PIVY_ORACLE_LANE/$case (run: just codemod-capture-pivy-oracle-$PIVY_ORACLE_LANE)" >&2
    return 99
  }
  cat "$base.out"
  return "$(<"$base.status")"
}

# After `run pivy_oracle ...`: C failed, and not because the fixture was
# missing (status 99), which would otherwise pass an "it fails" test.
assert_oracle_failure() {
  [[ $status -ne 99 ]] || fail "pivy_oracle had no fixture: $output"
  assert_failure
}
