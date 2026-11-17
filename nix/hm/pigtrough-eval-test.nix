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
      name = "routes-file-is-passed-as-routes";
      cfg.services.pigtrough = {
        enable = true;
        # A string, not a path literal: a literal would be copied into the
        # store, and the worktree's `.tmp` may hold sockets.
        routesFile = "/var/lib/pigtrough/my-routes.toml";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = launcherOf result;
        in
        {
          ok = tripped == [ ] && lib.hasInfix "--routes /var/lib/pigtrough/my-routes.toml" text;
          got = { inherit tripped text; };
        };
    }
    {
      name = "routes-and-routes-file-trip-the-mutex";
      cfg.services.pigtrough = {
        enable = true;
        routesFile = "/var/lib/pigtrough/my-routes.toml";
        routes = [ { name = "x"; } ];
      };
      check =
        result:
        let
          tripped = trippedMessages result;
        in
        {
          ok = lib.any (m: lib.hasInfix "mutually exclusive" m) tripped;
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
