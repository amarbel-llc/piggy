set output-format := "tap"

default: build test

build: build-nix

build-nix:
    nix build --show-trace

run-nix *ARGS:
    nix run . -- {{ARGS}}

test: test-sharness

test-sharness:
    nix develop --command make test

codemod-fmt: codemod-fmt-nix codemod-fmt-shell

codemod-fmt-nix:
    nix run ./devenvs/nix#fmt -- flake.nix

codemod-fmt-shell:
    nix develop --command shfmt -s -i=2 -w src/

update: update-nix

update-nix:
    nix flake update

clean: clean-build clean-test

clean-build:
    rm -rf result

clean-test:
    rm -rf tests/test-results/ tests/trash\ directory.*/
