# Conformance harness for the rust `piggy agent` subcommand.
#
# This is the catch-up oracle: as rust subcommands are added, their tests
# live here. Existing C-pivy bats files are kept alongside as `.bats.skip`
# placeholders that document the C contract the rust impl needs to match —
# they are NOT picked up by bats discovery (`*.bats` glob) until renamed.
#
# All tests target the wrapped rust `piggy` binary located via the parent
# common.bash. We do not invoke `pivy-*` directly; the dispatch path is
# `piggy <subcommand>` → rust → (rust impl OR exec to pivy-*).

bats_load_library bats-support
bats_load_library bats-assert

# Load the parent harness for $PIGGY resolution.
load "$(dirname "$BATS_TEST_FILE")/../common.bash"
