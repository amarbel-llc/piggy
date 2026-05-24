# treefmt-nix module config for piggy.
#
# Wired into the flake at flake.nix via `treefmtEval`, exposed as
# `formatter.${system}` (`nix fmt`) and dropped into the devShell as
# the `treefmt` binary. `just codemod-fmt` calls `nix fmt` and routes
# through here.
{
  projectRootFile = "flake.nix";

  programs.nixfmt.enable = true;

  programs.shfmt = {
    enable = true;
    indent_size = 2;
  };

  programs.rustfmt.enable = true;

  settings.global.excludes = [
    "vendor/**"
    "result"
    "result-*"
    ".direnv/**"
    "target/**"
    ".tmp/**"
    "*.lock"
  ];
}
