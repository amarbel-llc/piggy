# piggy's conformist overlay, merged with conformist.lib.presets.eng in
# flake.nix (conformist.lib.evalModule). The preset enables the eng-convention
# linters (eng-versioning, flake-outputs/lock, the justfile-* roster); here we
# choose the formatters and the repo-specific tweaks.
#
# This is piggy's move off treefmt-nix onto conformist (the migration the
# go/ block's comment used to defer). Formatters: nixfmt (RFC 166),
# rustfmt, and shfmt at 2-space indent. treefmt's shfmt ran plain `-i 2`;
# conformist's shfmt defaults to `-s -ci`. We keep `-ci` (case-indent — the eng
# house style, conformist#52) ON, and switch `-s` (simplify) OFF to stay close
# to the retired treefmt behavior. The one-time `-ci` reflow of the existing
# shell/bats tree lands in the migration commit.
# Go is deliberately NOT formatted here — go/'s hand-written sources are
# gofmt'd by `just codemod-fmt-go`, and its pkgs/ facades are formatted by the
# dagnabit facade lane (flake.nix conformistFacadeModule), not by a conformist
# Go formatter. `nix fmt` runs the generated wrapper; `just lint-fmt` runs the
# sandboxed `checks.formatting` derivation against the same generated config.
# See conformist-nix(7).
{ ... }:
{
  programs.nixfmt.enable = true;

  programs.rustfmt.enable = true;

  # shfmt: 2-space indent, case-indent on (`-ci`, eng house style), simplify
  # off (`-s`). treefmt ran plain `-i 2`; the `-ci` adoption reflows `case`
  # branches once in the migration commit.
  programs.shfmt = {
    enable = true;
    indent_size = 2;
    simplify = false;
    caseIndent = true;
  };

  # eng-versioning(7) derives the version key from the project's manifest;
  # piggy's Cargo workspace doesn't yield the right key, so pin it to match
  # version.env.
  linters.eng-versioning.key = "PIGGY_VERSION";

  # Excludes, ported from treefmt.nix's settings.global.excludes (layered on
  # conformist's default-excludes). `*.lock` covers Cargo.lock + flake.lock.
  settings.excludes = [
    "vendor/**"
    "result"
    "result-*"
    ".direnv/**"
    "target/**"
    ".tmp/**"
    "*.lock"
    "*.md"
  ];
}
