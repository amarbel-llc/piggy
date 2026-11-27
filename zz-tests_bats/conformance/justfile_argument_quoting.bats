#! /usr/bin/env bats
#
# Recipe arguments reach tools as arguments, never as shell text. Each
# case runs a real recipe with FAKE cargo, nix and bats on PATH and an
# argument that would create a marker file if a shell read it. The recipes
# are a sample, one per way of passing arguments; nothing here finds a new
# unquoted parameter elsewhere (a lint for that is conformist#156).
#
# Needs only bash, just and the justfiles; run via
# `just test-bats-conformance-argument-quoting`.

setup() {
  # Named by the recipe: the test file's own location may be a store
  # snapshot of the tree whose justfile is older than the worktree's.
  [[ -n ${PIGGY_JUSTFILE:-} && -f ${PIGGY_JUSTFILE:-} ]] || skip "PIGGY_JUSTFILE unset; run via just test-bats-conformance-argument-quoting"
  command -v just >/dev/null || skip "just not on PATH"
  WORK="$(mktemp -d -t argquote.XXXXXX)"
  FAKE="$WORK/bin"
  MARKER="$WORK/ran"
  mkdir -p "$FAKE"
  for tool in cargo nix bats; do
    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$@" >>"%s/%s.argv"\n' "$WORK" "$tool" >"$FAKE/$tool"
    chmod +x "$FAKE/$tool"
  done
  # Both ways in: a command separator, also after closing either quote,
  # and a substitution.
  PAYLOADS=("x; touch $MARKER" "x'; touch $MARKER; '" "x\"; touch $MARKER; \"" "\$(touch $MARKER)")
}

teardown() {
  [[ -n ${WORK:-} ]] && rm -rf "$WORK" 2>/dev/null || true
}

_recipe() { # JUSTFILE RECIPE ARGS...
  local justfile="$1"
  shift
  # Only this recipe's calls: an earlier one must not answer for it.
  rm -f "$WORK"/*.argv
  PATH="$FAKE:$PATH" run just --justfile "$justfile" --working-directory "$WORK" "$@"
}

_not_run() {
  [[ ! -e $MARKER ]] || { echo "the argument ran as shell text: $1; output: $output" >&2; return 1; }
}

# TOOL got exactly LINE as one of its arguments.
_got() { # TOOL LINE
  grep -q -x -F -- "$2" "$WORK/$1.argv" || {
    echo "$1 did not get '$2' as one argument; got:" >&2
    cat "$WORK/$1.argv" >&2 2>/dev/null
    return 1
  }
}

function variadic_arguments_reach_cargo_unread { # @test
  local recipe payload
  for recipe in validate-rust build-rust test-rust; do
    for payload in "${PAYLOADS[@]}"; do
      _recipe "$PIGGY_JUSTFILE" "$recipe" "$payload"
      _not_run "$recipe $payload"
      _got cargo "$payload"
    done
  done
}

function quoted_arguments_reach_nix_unread { # @test
  local payload
  for payload in "${PAYLOADS[@]}"; do
    _recipe "$PIGGY_JUSTFILE" debug-vm-dry-run "$payload"
    _not_run "debug-vm-dry-run $payload"
    _nix_got_inside_an_argument "$payload"
    _recipe "$PIGGY_JUSTFILE" debug-vm-probe "$payload"
    _not_run "debug-vm-probe $payload"
    _nix_got_inside_an_argument "$payload"
  done
}

_nix_got_inside_an_argument() { # TEXT
  grep -q -F -- "$1" "$WORK/nix.argv" || { echo "nix did not get the argument: $output" >&2; return 1; }
}

# The recipe stopped at its own check: exit 2, and nix was not called.
_refused() { # WHAT
  [[ $status -eq 2 ]] || { echo "want exit 2 for $1, got $status: $output" >&2; return 1; }
  [[ ! -e $WORK/nix.argv ]] || { echo "nix ran for a refused $1" >&2; return 1; }
}

function checked_arguments_are_refused_before_any_tool_runs { # @test
  local payload
  for payload in "${PAYLOADS[@]}"; do
    _recipe "$PIGGY_JUSTFILE" debug-vm-loop "$payload" 1 ""
    _not_run "debug-vm-loop check=$payload"
    _refused CHECK
    _recipe "$PIGGY_JUSTFILE" debug-vm-loop vm-piggy-luks "$payload" ""
    _not_run "debug-vm-loop runs=$payload"
    _refused RUNS
    _recipe "$PIGGY_JUSTFILE" bump-version "$payload"
    _not_run "bump-version $payload"
    _refused "the version"
  done
}

function the_nested_bats_justfile_passes_targets_unread { # @test
  local nested="${PIGGY_JUSTFILE%/*}/zz-tests_bats/justfile" payload
  [[ -f $nested ]] || { echo "no $nested" >&2; return 1; }
  for payload in "${PAYLOADS[@]}"; do
    _recipe "$nested" test "$payload"
    _not_run "zz-tests_bats test $payload"
    _got bats "$payload"
  done
}
