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
      assertions = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            assertion = lib.mkOption { type = lib.types.bool; };
            message = lib.mkOption { type = lib.types.str; };
          };
        });
        default = [ ];
      };
      meta.maintainers = lib.mkOption {
        type = lib.types.listOf lib.types.attrs;
        default = [ ];
      };
    };
  };

  runEval =
    cfg:
    lib.evalModules {
      modules = [
        harness
        module
        cfg
      ];
      specialArgs = { inherit pkgs; };
    };

  trippedMessages =
    result: map (a: a.message) (builtins.filter (a: !a.assertion) result.config.assertions);

  # Each case asserts a property on the module's evaluation. `failures`
  # lists every case whose actual result didn't match `expected`.
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
        in
        {
          ok = tripped == [ ] && sock != null;
          got = {
            inherit tripped sock;
          };
        };
    }
    {
      name = "all-cards-mode-passes-assertions";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.allCards = true;
      };
      check = result: {
        ok = trippedMessages result == [ ];
        got = trippedMessages result;
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
  summary = "${toString (lib.length cases - lib.length failures)}/${toString (lib.length cases)} cases passed";
}
