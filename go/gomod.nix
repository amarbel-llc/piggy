# Nix side of go.mod for piggy's go/ module — the producer half of the
# flake-input-go_mod protocol (amarbel-llc/nixpkgs RFC 0001):
#
#   - producer: mkGoPkgs publishes go-pkgs / go-pkgs-test so downstream repos
#     (madder, dodder, cutting-garden) can bridge github.com/amarbel-llc/piggy/go
#     as a flake input instead of pinning a go.mod pseudo-version. The caller
#     scopes src to the go/ subdir (piggy is polyglot: a Rust workspace + this
#     Go module), so downstream bridges with NO subPath. This is the normative
#     single-module producer shape (rich-acacia / RFC 0001 § Producer src
#     scoping).
#
#   - consumer bridge: goFlakeInputs routes go/'s own
#     github.com/amarbel-llc/purse-first/libs/dewey require onto purse-first's
#     go-pkgs output, attached as passthru.goFlakeInputs so a downstream
#     consumer inherits piggy's dewey bridge at depth-1 (RFC 0001 §
#     Multi-producer closures). purse-first's go-pkgs is the whole workspace, so
#     we slice into the dewey module subdir with subPath. dewey is the ONLY
#     amarbel-llc module in go/'s require graph; the rest (filippo.io/age|hpke,
#     golang.org/x/*) is public + hash-stable and rides gomod2nix pins.
#
# The flake input MUST be named "purse-first" so consumers can predict the
# follows target (inputs.piggy.inputs.purse-first.follows = "purse-first").
{
  pkgs,
  src,
  purse-first,
  system,
}:
let
  goFlakeInputs = {
    "github.com/amarbel-llc/purse-first/libs/dewey" = {
      src = purse-first.packages.${system}.go-pkgs;
      subPath = "libs/dewey";
    };
  };
in
{
  # mkGoPkgs filters the go/ source tree into go-pkgs (prod superset, no
  # *_test.go / testdata) and go-pkgs-test (test superset). `name` is set
  # explicitly so the store path is repo-prefixed — the polyglot-subdir
  # inference (src = self + "/go") otherwise yields just "go"
  # (amarbel-llc/nixpkgs#49). goFlakeInputs is threaded so both outputs carry
  # passthru.goFlakeInputs for depth-1 consumer inheritance.
  #
  # extras: marklid.peg (piggy#220) is a non-.go file embedded via
  # //go:embed (go/internal/bravo/markl/marklid_grammar.go) — mkGoPkgs's
  # default filter only keeps *.go/module files, so without this the
  # go:embed directive fails at build time in any nix-built consumer of
  # go-pkgs/go-pkgs-test (piggy-agent-conformance here; any downstream
  # bridge consumer too) with "pattern marklid.peg: no matching files
  # found", even though a plain `go build`/`go test` outside nix's
  # source-filtered tree never notices.
  goPkgs = pkgs.mkGoPkgs {
    inherit src goFlakeInputs;
    name = "piggy-go";
    extras = [ ".*\\.peg" ];
  };
  inherit goFlakeInputs;
}
