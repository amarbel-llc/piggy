# Smoke-test harness for the `services.pigtrough` home-manager module
# (FDR 0009, R3). Same shape as ./eval-test.nix: `lib.evalModules` against
# the module with synthetic configs, no real home-manager, no deploy.
#
# Use via: `just test-nix-hm-pigtrough-module`.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  harness = ./stub-home-manager.nix;

  # `mkPackageOption pkgs "pigtrough"` has no default in stock nixpkgs;
  # `pkgs.hello` stands in. Only the path string matters: the launcher is
  # forced through eval, never realised.
  pinPackage = {
    services.pigtrough.package = lib.mkDefault (
      pkgs.hello.overrideAttrs (_: {
        pname = "pigtrough";
      })
    );
    services.pigtrough.piggyPackage = lib.mkDefault (
      pkgs.hello.overrideAttrs (_: {
        pname = "piggy";
      })
    );
  };

  route = name: secret: {
    inherit name secret;
    upstream = "${name}.invalid";
    auth = "token";
    owners = [ "some-org" ];
    allow = [
      {
        method = "GET";
        path = [
          "repos"
          "{owner}"
          "{name}"
        ];
      }
    ];
  };

  # Two routes, as the load unit sees them.
  twoRoutes = [
    (route "forgejo-api" "piggy-test/forgejo")
    (route "github-api" "piggy-test/github")
  ];

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

  unitOf = result: result.config.systemd.user.services.pigtrough or null;

  launcherOf = result: result.config.services.pigtrough._launcherText;

  cases = [
    {
      # Defaults: the unit serves the compiled-in route, so the exec line
      # carries neither --dir nor --routes.
      name = "defaults-serve-the-compiled-in-route";
      cfg.services.pigtrough.enable = true;
      check =
        result:
        let
          tripped = trippedMessages result;
          text = launcherOf result;
        in
        {
          ok =
            tripped == [ ]
            && lib.hasInfix "/bin/pigtrough serve" text
            && !(lib.hasInfix "--routes" text)
            && !(lib.hasInfix "--dir" text);
          got = { inherit tripped text; };
        };
    }
    {
      # The unit fails closed and never reads the card: it restarts, it
      # starts at default.target, and nothing in the launcher loads a
      # secret or runs piggy.
      name = "unit-restarts-fails-closed-and-never-loads";
      cfg.services.pigtrough.enable = true;
      check =
        result:
        let
          unit = unitOf result;
          text = launcherOf result;
        in
        {
          ok =
            unit != null
            && unit.Service.Restart == "always"
            && unit.Service.NoNewPrivileges
            && unit.Install.WantedBy == [ "default.target" ]
            && !(unit.Service ? Environment)
            && !(lib.hasInfix " load" text)
            && !(lib.hasInfix "piggy pass" text)
            && !(lib.hasInfix "piggy " text);
          got = { inherit unit text; };
        };
    }
    {
      name = "routes-render-to-a-routes-flag";
      cfg.services.pigtrough = {
        enable = true;
        routes = [
          {
            name = "forgejo-api";
            upstream = "forgejo.invalid";
            auth = "token";
            secret = "piggy-test/none";
            owners = [ "some-org" ];
            loopback_port = 8731;
            allow = [
              {
                method = "GET";
                path = [
                  "api"
                  "v1"
                  "repos"
                  "{owner}"
                  "{name}"
                ];
              }
            ];
          }
        ];
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = launcherOf result;
        in
        {
          ok = tripped == [ ] && lib.hasInfix "--routes" text && lib.hasInfix "pigtrough-routes.toml" text;
          got = { inherit tripped text; };
        };
    }
    {
      # The load helper steps through the routes in order, each as the
      # pipeline the operator would run by hand, and stops at the first
      # failure.
      name = "load-all-runs-each-route-in-order-and-stops-at-the-first-failure";
      cfg.services.pigtrough = {
        enable = true;
        routes = twoRoutes;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = result.config.services.pigtrough._loadAllText;
          first = lib.hasInfix "piggy pass show piggy-test/forgejo" text;
          second = lib.hasInfix "piggy pass show piggy-test/github" text;
          piped = lib.hasInfix "| /nix/store" text && lib.hasInfix "/bin/pigtrough load forgejo-api" text;
          order =
            let
              parts = lib.splitString "piggy pass show piggy-test/github" text;
            in
            lib.hasInfix "piggy pass show piggy-test/forgejo" (lib.head parts);
        in
        {
          ok =
            tripped == [ ]
            && first
            && second
            && piped
            && order
            && lib.hasInfix "set -eu -o pipefail" text
            && lib.hasInfix "if ! " text
            && lib.hasInfix "exit 1" text
            && !(lib.hasInfix "|| true" text)
            && lib.hasInfix "all 2 routes loaded" text;
          got = { inherit tripped text; };
        };
    }
    {
      # The helper prints route names, never a secret value: no command
      # prints or captures the decrypted text.
      name = "load-all-never-captures-or-echoes-a-secret";
      cfg.services.pigtrough = {
        enable = true;
        routes = twoRoutes;
      };
      check =
        result:
        let
          text = result.config.services.pigtrough._loadAllText;
        in
        {
          ok =
            !(lib.hasInfix "$(" text)
            && !(lib.hasInfix "`" text)
            && !(lib.hasInfix "read " text)
            && !(lib.hasInfix "echo $" text)
            && !(lib.hasInfix "tee " text)
            && !(lib.hasInfix "> /" text);
          got = text;
        };
    }
    {
      # The oneshot unit: started by hand only (no [Install], wanted by
      # nothing), ordered after the serve unit, running the helper.
      name = "load-unit-is-a-manual-oneshot-after-serve";
      cfg.services.pigtrough = {
        enable = true;
        routes = twoRoutes;
        loadEnvironment = {
          SSH_AUTH_SOCK = "/run/user/1000/piggy-agent.sock";
        };
      };
      check =
        result:
        let
          unit = result.config.systemd.user.services.pigtrough-load or null;
          serve = unitOf result;
        in
        {
          ok =
            unit != null
            && unit.Service.Type == "oneshot"
            && !(unit ? Install)
            && unit.Unit.Requires == [ "pigtrough.service" ]
            && unit.Unit.After == [ "pigtrough.service" ]
            && unit.Service.Environment == [ "SSH_AUTH_SOCK=/run/user/1000/piggy-agent.sock" ]
            && lib.hasInfix "pigtrough-load-all" unit.Service.ExecStart
            # Nothing wants it: the serve unit is the only unit with an
            # Install section.
            && serve.Install.WantedBy == [ "default.target" ];
          got = { inherit unit; };
        };
    }
    {
      # Without routes in nix the module cannot know the secrets, so it
      # generates no load unit.
      name = "no-routes-no-load-unit";
      cfg.services.pigtrough.enable = true;
      check =
        result:
        let
          units = lib.attrNames result.config.systemd.user.services;
        in
        {
          ok = units == [ "pigtrough" ] && result.config.services.pigtrough._loadAllText == "";
          got = units;
        };
    }
    {
      # `dir` reaches the load helper too, so it talks to the same server.
      name = "load-all-passes-dir-and-escapes-names";
      cfg.services.pigtrough = {
        enable = true;
        dir = "/tmp/a b";
        routes = [ (route "odd name" "piggy test/odd secret") ];
      };
      check =
        result:
        let
          text = result.config.services.pigtrough._loadAllText;
        in
        {
          ok =
            lib.hasInfix "load 'odd name' --dir '/tmp/a b'" text
            && lib.hasInfix "show 'piggy test/odd secret'" text;
          got = text;
        };
    }
    {
      # A route without a secret or name cannot be loaded: refused at eval
      # time, not discovered when the unit fails.
      name = "a-route-without-a-secret-trips-an-assertion";
      cfg.services.pigtrough = {
        enable = true;
        routes = [
          {
            name = "x";
            upstream = "x.invalid";
          }
        ];
      };
      check =
        result:
        let
          tripped = trippedMessages result;
        in
        {
          ok = lib.any (m: lib.hasInfix "needs a `name` and a `secret`" m) tripped;
          got = tripped;
        };
    }
    {
      name = "dir-is-passed-as-dir";
      cfg.services.pigtrough = {
        enable = true;
        dir = "/run/user/1000/pigtrough";
      };
      check =
        result:
        let
          text = launcherOf result;
        in
        {
          ok = trippedMessages result == [ ] && lib.hasInfix "--dir /run/user/1000/pigtrough" text;
          got = text;
        };
    }
    {
      # A dir with a space or quote must reach the binary as one argument.
      name = "dir-with-a-space-is-escaped";
      cfg.services.pigtrough = {
        enable = true;
        dir = "/tmp/a b";
      };
      check =
        result:
        let
          text = launcherOf result;
        in
        {
          ok = lib.hasInfix "--dir '/tmp/a b'" text;
          got = text;
        };
    }
    {
      name = "disabled-emits-nothing";
      cfg.services.pigtrough.enable = false;
      check =
        result:
        let
          unit = unitOf result;
        in
        {
          ok = unit == null && trippedMessages result == [ ];
          got = unit;
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
