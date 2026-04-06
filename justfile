
default: build test

build: build-nix

build-nix:
    nix build --show-trace

run-nix *ARGS:
    nix run . -- {{ARGS}}

test: test-bats

test-bats:
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/*.bats

codemod-fmt: codemod-fmt-nix codemod-fmt-shell

codemod-fmt-nix:
    nix run ./devenvs/nix#fmt -- flake.nix

codemod-fmt-shell:
    nix develop --command shfmt -s -i=2 -w src/

update: update-nix

update-nix:
    nix flake update

clean: clean-build

clean-build:
    rm -rf result
