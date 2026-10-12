# Stub home-manager-shaped option set, so `services.piggy-agent` can be
# evaluated with plain `lib.evalModules` and no real home-manager.
#
# The module needs `home.sessionVariables`, `home.homeDirectory`,
# `systemd.user.services`, `systemd.user.tmpfiles.rules`,
# `launchd.agents`, `xdg.configFile`, `assertions`, and
# `meta.maintainers` to be declared somewhere; in a real home-manager
# invocation, hm declares them.
#
# Used by ./eval-test.nix (option schema and assertions) and by
# ../vm-tests/agent.nix (which runs the units the module emits).
{ lib, ... }:
{
  options = {
    home.sessionVariables = lib.mkOption {
      type = lib.types.attrs;
      default = { };
    };
    # home-manager normally derives this from `home.username` and the
    # platform; the stub pins it so the module can build absolute
    # default paths (e.g. Darwin's StandardErrorPath — see #64) at
    # eval time. The value is arbitrary but must be an absolute path
    # to satisfy any consumer that type-checks against `path`.
    home.homeDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/Users/eval-test";
    };
    systemd.user.services = lib.mkOption {
      type = lib.types.attrs;
      default = { };
    };
    systemd.user.tmpfiles.rules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
    launchd.agents = lib.mkOption {
      type = lib.types.attrs;
      default = { };
    };
    xdg.configFile = lib.mkOption {
      type = lib.types.attrs;
      default = { };
    };
    assertions = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            assertion = lib.mkOption { type = lib.types.bool; };
            message = lib.mkOption { type = lib.types.str; };
          };
        }
      );
      default = [ ];
    };
    meta.maintainers = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      default = [ ];
    };
  };
}
