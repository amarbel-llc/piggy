
default: build test

# --- build ---

build: build-nix build-rust

build-nix:
    nix build --show-trace

build-nix-conformance:
    nix build .#piggy-agent-conformance -o result-conformance

build-rust:
    cargo build

build-rust-release:
    cargo build --release

run-nix *ARGS:
    nix run . -- {{ARGS}}

# --- test ---
#
# Bats tests are routed through the rust `piggy` binary so the full
# rust → bash dispatch path is exercised on every run. `cargo build`
# is a hard prerequisite — `zz-tests_bats/common.bash` aborts with a
# clear error if `target/debug/piggy` is missing.

test: build-rust test-bats test-rust

test-bats: test-bats-piggy test-bats-conformance

test-bats-piggy: build-rust
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/t*.bats

test-bats-conformance: build-rust
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/conformance/*.bats

test-bats-conformance-protocol: build-rust build-nix-conformance
  CONFORMANCE_BIN="$(readlink -f ./result-conformance)/bin/piggy-agent-conformance" \
    BATS_TEST_TIMEOUT=30 bats --allow-unix-sockets --allow-local-binding \
    --tap zz-tests_bats/conformance/piggy_agent_protocol.bats

test-rust:
    cargo test

# --- format / lint ---

codemod-fmt: codemod-fmt-nix codemod-fmt-shell codemod-fmt-rust

codemod-fmt-nix:
    nix run ./devenvs/nix#fmt -- flake.nix

codemod-fmt-shell:
    nix develop --command shfmt -s -i=2 -w src/

codemod-fmt-rust:
    cargo fmt

lint-rust:
    cargo clippy --workspace --all-targets -- -D warnings

# --- update / clean ---

update: update-nix

update-nix:
    nix flake update

clean: clean-build clean-rust

clean-build:
    rm -rf result

clean-rust:
    cargo clean
