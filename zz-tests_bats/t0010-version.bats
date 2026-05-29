setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
}

# `piggy version` must follow eng-versioning(7): a self-identification line
# "piggy <version>+<rev>", a blank line, then a table of pinned downstream
# components. Assertions pin the SHAPE the spec mandates, not concrete
# values — the commit/rev columns are nondeterministic, and a dev
# `cargo build` (no makeWrapper injection) renders "unknown" for everything
# but the version. Both the wrapped nix lane and the local target/debug lane
# must therefore satisfy the same value-agnostic checks.

function version_first_line_is_self_identification { # @test
  run "$PIGGY" version
  assert_success
  # "piggy <version>+<rev>" — a single whitespace-free token containing '+'.
  assert_line --index 0 --regexp '^piggy [^[:space:]]+[+][^[:space:]]+$'
}

function version_emits_component_table_header { # @test
  run "$PIGGY" version
  assert_success
  assert_line --regexp '^COMPONENT[[:space:]]+VERSION[[:space:]]+REV$'
}

function version_lists_pivy_and_pcsclite_rows { # @test
  run "$PIGGY" version
  assert_success
  # name, non-empty version field, non-empty rev field.
  assert_line --regexp '^pivy[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+$'
  assert_line --regexp '^pcsclite[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+$'
}

function help_header_is_self_line_without_component_table { # @test
  run "$PIGGY" help
  assert_success
  assert_line --index 0 --regexp '^piggy [^[:space:]]+[+][^[:space:]]+$'
  # The help banner is just the self-line — the component table belongs to
  # the `version` subcommand only.
  refute_output --partial 'COMPONENT'
}
