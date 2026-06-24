#! /usr/bin/env bats
# bats file_tags=hardware
#
# Exploratory: why does `piggy box tpl create … local-guid …` fail with
# "PCSC: Smart card resource manager not running" when invoked from the
# bats harness, even though it succeeds when invoked by the wrapping
# justfile with the same PCSCLITE_CSOCK_NAME? Each test isolates one
# variable (direct call vs `run`, HOME override, inline PCSC re-export).
#
# Driver:  just explore-bats zz-tests_bats/explore/explore_local_guid_pcsc.bats
#
# Files under zz-tests_bats/explore/ are intentionally outside
# zz-tests_bats/conformance/ so the conformance glob
# (`zz-tests_bats/conformance/*.bats`) does not pick them up and run them
# under the default (non-permissive) sandbox, which this file requires
# escapes from to run `just load-fib`.
#
# FINDING (2026-04-24): the root cause is batman's sandbox. libpcsclite
# cannot connect to pcscd's Unix socket (pcscd.comm) unless bats is run
# with --allow-unix-sockets (and --allow-local-binding for paranoia's
# sake). Without the flag, BOTH the C `pivy-tool` and Rust `piggy` see
# "PC/SC system service/daemon not available" even though
# PCSCLITE_CSOCK_NAME reaches the subprocess correctly. The same flag
# is required for any bats recipe that exercises pcscd-backed code
# (piggy_box_interop.bats, piggy_agent_protocol.bats, etc).
#
# UPDATE (2026-05-29): batman 0.1.3 removed --allow-unix-sockets; fence
# now permits AF_UNIX access by default via its broad filesystem
# allowRead, so recipes pass only --allow-local-binding. See piggy
# CLAUDE.md "Debugging → bats + PCSC" and amarbel-llc/bats#27.
#
# This file keeps its fib setup here so the recipe can stay generic
# (`explore-bats *FILES`). setup_file brings the virtual card up and
# tears it down regardless of pass/fail.

setup_file() {
  # Bring up the fib virtual-PIV stack and capture its PCSC socket path
  # into the process env for all tests in this file. load-fib is
  # idempotent, so back-to-back runs don't stomp each other.
  #
  # NOTE: running `just load-fib` from inside bats only works if bats is
  # invoked with --no-sandbox. batman's default sandbox makes CWD and
  # /run/user read-only, so the recipe fails on `mkdir .fib` or on just's
  # own tempdir creation. The `explore-bats` driver recipe sets that
  # flag; other drivers must too.
  just load-fib >&2
  # shellcheck disable=SC1091
  source .fib/env

  # Generate an ECCP256 key on slot 9D so tpl create has something to read.
  pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null

  export INTEROP_GUID
  INTEROP_GUID=$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)

  # Capture the real pivy-tool path NOW, before common.bash (loaded in
  # per-test setup) prepends a mock directory to PATH and masks it.
  export REAL_PIVY_TOOL
  REAL_PIVY_TOOL=$(command -v pivy-tool)
}

teardown_file() {
  just clean-fib >&2 || true
}

setup() {
  # Load the parent harness directly (PIGGY resolution, mock PATH, etc).
  # Skip conformance/common.bash: nothing in there is needed here.
  load "$(dirname "$BATS_TEST_FILE")/../common.bash"
  export output

  [[ -n ${PCSCLITE_CSOCK_NAME:-} ]] || skip "PCSCLITE_CSOCK_NAME not set (load-fib failed?)"
  [[ -n ${INTEROP_GUID:-} ]] || skip "INTEROP_GUID not set (key generation failed?)"
  [[ -n ${REAL_PIVY_TOOL:-} && -x ${REAL_PIVY_TOOL:-} ]] ||
    skip "REAL_PIVY_TOOL not set or not executable"
}

# --- diagnostic probes -----------------------------------------------------

function probe_env_visible { # @test
  # Confirm PCSCLITE_CSOCK_NAME propagates into a bats `run` subprocess.
  run env
  assert_success
  assert_output --partial "PCSCLITE_CSOCK_NAME=$PCSCLITE_CSOCK_NAME"
}

function probe_pivy_tool_list_via_run { # @test
  # The real pivy-tool (C binary) should enumerate the card if — and only
  # if — the bats sandbox is letting libpcsclite reach pcscd.comm. This
  # was the canary that caught the original --allow-unix-sockets
  # requirement (the flag was since removed in batman 0.1.3; see
  # bats#27 and the FINDING / UPDATE notes above).
  run "$REAL_PIVY_TOOL" list
  echo "status=$status" >&3
  echo "--- output ---" >&3
  echo "$output" >&3 || true
  assert_success
}

# --- piggy baseline (match the justfile recipe invocation) -----------------

function piggy_direct_no_home_override { # @test
  # Closest analogue to the justfile recipe's own successful invocation:
  # no bats `run`, no HOME override. Proves piggy's PCSC codepath works
  # inside the harness once the sandbox flags are correct.
  local tpl_name="explore-direct-$RANDOM"
  "$PIGGY" box tpl create "$tpl_name" primary local-guid "$INTEROP_GUID"
}

function piggy_via_run { # @test
  local tpl_name="explore-run-$RANDOM"
  run "$PIGGY" box tpl create "$tpl_name" primary local-guid "$INTEROP_GUID"
  echo "status=$status" >&3
  echo "$output" >&3 || true
  assert_success
}

function piggy_via_run_home_override { # @test
  # Match the failing piggy_box_interop.bats test exactly.
  local tpl_name="explore-home-$RANDOM"
  HOME="$BATS_TEST_TMPDIR" run "$PIGGY" box tpl create "$tpl_name" primary local-guid "$INTEROP_GUID"
  echo "status=$status" >&3
  echo "$output" >&3 || true
  assert_success
}

function piggy_via_run_explicit_pcsc_env { # @test
  # Belt-and-braces: re-export PCSCLITE_CSOCK_NAME inline on the `run`
  # line. Should be a no-op given probe_env_visible passes, but kept for
  # symmetry with earlier debugging hypotheses.
  local tpl_name="explore-explicit-$RANDOM"
  HOME="$BATS_TEST_TMPDIR" PCSCLITE_CSOCK_NAME="$PCSCLITE_CSOCK_NAME" \
    run "$PIGGY" box tpl create "$tpl_name" primary local-guid "$INTEROP_GUID"
  echo "status=$status" >&3
  echo "$output" >&3 || true
  assert_success
}
