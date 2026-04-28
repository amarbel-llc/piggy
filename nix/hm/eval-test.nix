# Smoke-test harness for `services.piggy-agent` home-manager module.
#
# Drives `lib.evalModules` against the module with synthetic configs to
# verify the option schema, the Linux/Darwin code paths, and every
# assertion. Doesn't require a real home-manager.
#
# Use via: `just test-nix-hm-module`. The recipe imports this file and
# evaluates `result` in JSON; non-empty `failures` cause it to exit
# non-zero.
#
# Stays alongside the module in nix/hm/ rather than under tests/ — it's
# the only check the module needs at this scope and adding a tests/
# subdirectory would imply more is coming.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  # Stub home-manager-shaped option set. The piggy-agent module needs
  # `home.sessionVariables`, `systemd.user.services`, `systemd.user.tmpfiles.rules`,
  # `launchd.agents`, `assertions`, and `meta.maintainers` to be declared
  # somewhere; in a real home-manager invocation, hm declares them.
  harness = {
    options = {
      home.sessionVariables = lib.mkOption {
        type = lib.types.attrs;
        default = { };
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
  };

  # `mkPackageOption pkgs "piggy"` defaults to `pkgs.piggy`, which
  # doesn't exist in stock nixpkgs. Every case is evaluated with
  # `package` pinned to `pkgs.hello` so the default's thrown error
  # doesn't fire when the launcher derivation gets forced.
  #
  # Passed as a separate module (not merged via `//`) so evalModules
  # does the proper deep-merge with the case's own config.
  pinPackage = {
    services.piggy-agent.package = pkgs.hello;
  };

  runEval =
    cfg:
    lib.evalModules {
      modules = [
        harness
        module
        pinPackage
        cfg
      ];
      specialArgs = { inherit pkgs; };
    };

  trippedMessages =
    result: map (a: a.message) (builtins.filter (a: !a.assertion) result.config.assertions);

  # Force the launcher derivation through nix's laziness so we catch
  # bugs that would only surface when home-manager actually realizes
  # the unit. Reading either the systemd unit (Linux) or the launchd
  # plist (Darwin) drives `binPath` and the writeShellScript through.
  # `unitName` defaults to `piggy-agent` for the single-instance case;
  # multi-instance cases pass `piggy-agent-<key>` per instance.
  forceLauncherNamed =
    unitName: result:
    if pkgs.stdenv.isLinux then
      result.config.systemd.user.services.${unitName}.Service.ExecStart
    else
      result.config.launchd.agents.${unitName}.config.ProgramArguments;

  forceLauncher = forceLauncherNamed "piggy-agent";

  cases = [
    {
      name = "valid-single-instance-evaluates-cleanly";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          sock = result.config.home.sessionVariables.SSH_AUTH_SOCK or null;
          launcher = forceLauncher result;
        in
        {
          ok = tripped == [ ] && sock != null && launcher != null;
          got = {
            inherit tripped sock launcher;
          };
        };
    }
    {
      name = "all-cards-mode-passes-assertions";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.allCards = true;
      };
      check =
        result:
        let
          launcher = forceLauncher result;
        in
        {
          ok = trippedMessages result == [ ] && launcher != null;
          got = {
            tripped = trippedMessages result;
            inherit launcher;
          };
        };
    }
    {
      name = "no-card-trips-required-assertion";
      cfg = {
        services.piggy-agent.enable = true;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "one of `guid` or `allCards`" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      name = "guid-and-all-cards-trips-mutex-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.allCards = true;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "mutually exclusive" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      name = "invalid-slots-trips-format-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.slots = "not-a-slot";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "comma-separated list" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      name = "multi-instance-evaluates-cleanly";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.instances = {
          default = {
            guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
          };
          work = {
            allCards = true;
            slots = "9a";
          };
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          defaultLauncher = forceLauncherNamed "piggy-agent-default" result;
          workLauncher = forceLauncherNamed "piggy-agent-work" result;
          # In multi-instance mode SSH_AUTH_SOCK must NOT be set —
          # the user picks per-shell via the per-instance snippets.
          sock = result.config.home.sessionVariables.SSH_AUTH_SOCK or null;
        in
        {
          ok = tripped == [ ] && defaultLauncher != null && workLauncher != null && sock == null;
          got = {
            inherit
              tripped
              defaultLauncher
              workLauncher
              sock
              ;
          };
        };
    }
    {
      name = "top-level-with-instances-trips-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.instances.work = {
          allCards = true;
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "top-level options" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      name = "instance-no-card-trips-required-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.instances.work = {
          # Neither guid nor allCards set — should trip the
          # required-card assertion with the (instance ...) suffix.
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (
            m: lib.hasInfix "one of `guid` or `allCards`" m && lib.hasInfix "piggy-agent-work" m
          ) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      name = "multi-instance-emits-shell-snippets";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.instances = {
          default = {
            guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
          };
          work = {
            allCards = true;
          };
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          configFiles = result.config.xdg.configFile or { };
          defaultText = configFiles."piggy/piggy-agent-default.sh".text or null;
          workText = configFiles."piggy/piggy-agent-work.sh".text or null;
          defaultOk =
            defaultText != null
            && lib.hasInfix "SSH_AUTH_SOCK=" defaultText
            && lib.hasInfix "piggy/piggy-agent-default.sock" defaultText;
          workOk =
            workText != null
            && lib.hasInfix "SSH_AUTH_SOCK=" workText
            && lib.hasInfix "piggy/piggy-agent-work.sock" workText;
        in
        {
          ok = tripped == [ ] && defaultOk && workOk;
          got = {
            inherit
              tripped
              defaultText
              workText
              ;
          };
        };
    }
  ];

  results = map (c: {
    name = c.name;
    result = c.check (runEval c.cfg);
  }) cases;

  failures = builtins.filter (r: !r.result.ok) results;
in
{
  inherit results failures;
  pass = failures == [ ];
  summary = "${
    toString (lib.length cases - lib.length failures)
  }/${toString (lib.length cases)} cases passed";
}
