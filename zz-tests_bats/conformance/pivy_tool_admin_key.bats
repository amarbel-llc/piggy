#! /usr/bin/env bats
#
# Regression test for pivy-tool -K default argument parsing.
# See amarbel-llc/piggy#23: the "default" branch failed to set len,
# causing a spurious "admin key must be 24 bytes" error from stack
# garbage in the uninitialized len variable.
#
# These tests exercise the real (nix-built) pivy-tool binary, not the
# mock. No card or fib stack is needed — the parse check fires before
# any PC/SC connection.

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
