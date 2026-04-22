default: build test

build: build-nix build-nix-rust build-nix-conformance

build-nix:
  nix build

build-nix-rust:
  nix build .#pivy-rust -o result-rust

build-nix-conformance:
  nix build .#pivy-agent-conformance -o result-conformance

build-rust:
  cd rust && cargo build

build-rust-release:
  cd rust && cargo build --release

test: test-bats test-bats-rust test-conformance

test-bats: build-nix
  PATH="$(readlink -f ./result)/bin:$PATH" just zz-tests_bats/test

test-hardware: build-nix
  PATH="$(readlink -f ./result)/bin:$PATH" just zz-tests_bats/test-hardware

test-bats-rust: build-nix-rust
  PIVY_AGENT_RUST="$(readlink -f ./result-rust)/bin/pivy-agent-rust" just zz-tests_bats/test-rust

test-conformance: build-nix build-nix-conformance
  CONFORMANCE_DIR="$(readlink -f ./result-conformance)" \
    PATH="$(readlink -f ./result)/bin:$PATH" \
    just zz-tests_bats/test-conformance

test-conformance-hardware: build-nix build-nix-conformance
  CONFORMANCE_DIR="$(readlink -f ./result-conformance)" \
    PATH="$(readlink -f ./result)/bin:$PATH" \
    just zz-tests_bats/test-conformance-hardware

test-rust:
  cd rust && cargo test

test-rust-verbose:
  cd rust && cargo test -- --nocapture

fmt:
  cd rust && cargo fmt

clippy:
  cd rust && cargo clippy -- -D warnings

check:
  cd rust && cargo check

compile-commands:
  nix develop -c make compile-commands

clean:
  cd rust && cargo clean
