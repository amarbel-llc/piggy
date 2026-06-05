#! /usr/bin/env bats
#
# Regression test for pivy-tool -K default argument parsing.
# See amarbel-llc/piggy#23: the "default" branch failed to set len,
# causing a spurious "admin key must be 24 bytes" error from stack
# garbage in the uninitialized len variable.
#
# These tests exercise the real (nix-built) pivy-tool binary, not the
# mock. The assertions only care about `-K default` argument parsing, but
# the current pivy-tool establishes a PC/SC context before printing the
# version. On Linux that context-establish hits the host's system pcscd,
# which in headless/polkit sessions answers SCardEstablishContext with
# SCARD_W_SECURITY_VIOLATION ("Access denied") and aborts the tool before
# any output. So on Linux setup() routes pivy-tool at a permissive fibby
# virtual card (when FIBBY_BIN is supplied) to keep the parse check
# hermetic; macOS ignores PCSCLITE_CSOCK_NAME and the sandboxed lane has no
# pcscd at all (NO_SERVICE, which pivy-tool tolerates), so both run the
# tool unredirected.

setup() {
  bats_load_library bats-support
  bats_load_library bats-assert

  # Prefer the sandboxed lane's injected REAL_PIVY_TOOL (set by
  # bats.nix's extraEnv, see piggy#116). That path points at the C
  # pivy derivation directly, bypassing the mock pivy-tool that
  # common.bash installs at the front of $PATH for the rest of the
  # suite.
  if [[ -n ${REAL_PIVY_TOOL:-} && -x ${REAL_PIVY_TOOL:-} ]]; then
    PIVY_TOOL="$REAL_PIVY_TOOL"
  fi

  # Local-invocation fallback: prefer the nix-built pivy-tool
  # (from ./result) over the devshell's. The devshell binary may lag
  # behind vendor/pivy source changes until the next `nix develop`
  # rebuild.
  if [[ -z ${PIVY_TOOL:-} ]]; then
    local piggy_wrapper="$BATS_CWD/result/bin/piggy"
    if [[ -f $piggy_wrapper ]]; then
      local nix_pivy_bin
      nix_pivy_bin=$(grep -oE '/nix/store/[a-z0-9]+-pivy-[^/]+/bin' "$piggy_wrapper" | head -1)
      if [[ -n $nix_pivy_bin && -x "$nix_pivy_bin/pivy-tool" ]]; then
        PIVY_TOOL="$nix_pivy_bin/pivy-tool"
      fi
    fi
  fi

  if [[ -z ${PIVY_TOOL:-} ]]; then
    PIVY_TOOL="$(command -v pivy-tool)" || true
  fi
  [[ -x ${PIVY_TOOL:-} ]] || skip "pivy-tool not found via REAL_PIVY_TOOL, ./result, or PATH"

  # Linux only, and only when a fibby binary is supplied (the
  # test-bats-conformance recipe threads FIBBY_BIN): stand up a permissive
  # fibby virtual card and redirect libpcsclite at it, so the
  # context-establish never reaches — and is never denied by — the host's
  # system pcscd. See the header comment for the macOS / sandbox paths.
  FIBBY_PID=
  if [[ -n ${FIBBY_BIN:-} && -x ${FIBBY_BIN:-} && "$(uname -s)" == Linux ]]; then
    load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
    WORKDIR="$(mktemp -d -t pvtak.XXXXXX)"
    FIBBY_SOCK="$WORKDIR/pcscd.comm"
    FIBBY_LOG="$WORKDIR/fibby.log"
    # Best-effort: if fibby comes up we talk to it. If it can't bind (e.g. a
    # restrictive sandbox), the redirect below still points away from the
    # host's denying system pcscd, so libpcsclite reports NO_SERVICE and
    # pivy-tool prints the version anyway (same as the no-daemon bats-default
    # lane). Either path keeps the #23 parse check hermetic and never hits
    # SCARD_W_SECURITY_VIOLATION.
    spawn_fibby || true
    export PCSCLITE_CSOCK_NAME="$FIBBY_SOCK"
  fi
}

teardown() {
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && wait "$FIBBY_PID" 2>/dev/null || true
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
}

function k_default_version_prints_version { # @test
  run "$PIVY_TOOL" -K default version
  # version may exit non-zero when pcscd is unavailable (it tries to
  # establish a PCSC context before printing), but the parse must pass
  # and the version string must appear.
  assert_output --partial "0."
  refute_output --partial "admin key must be"
}

function k_default_list_does_not_fail_with_bad_args { # @test
  run "$PIVY_TOOL" -K default list
  # list will fail (no card), but must NOT be EXIT_BAD_ARGS (2) with
  # the key-length error — that would mean the parse still reads garbage.
  if [[ $status -eq 2 ]]; then
    # Only fail if this is the specific key-length parse error.
    if [[ $output == *"admin key must be"* ]]; then
      fail "-K default still hits uninitialized len: $output"
    fi
  fi
  refute_output --partial "admin key must be"
}
