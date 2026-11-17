# home-manager module for `services.pigtrough` (FDR 0009; operator rulings
# R3 and the load design, 2026-11-17): a systemd user unit that keeps
# `pigtrough serve` running, and a oneshot unit that loads every route.
#
# The serve unit never holds a credential and never touches the card. A
# (re)start leaves every route unloaded, so it answers `503
# secret-unavailable` until the operator starts the load unit by hand:
#
#   systemctl --user start pigtrough-load
#
# which, for each route in order, runs `piggy pass show <secret> | pigtrough
# load <route>` and stops at the first failure. That is the only step that
# reads the card, and only the operator starts it: fail closed, no unattended
# card use. Linux only (systemd user units).
#
# Routes are defined in nix only (`routes`): the load unit needs each
# route's `secret` name, and a second, hand-written table would be a second
# source of truth. A hand-written table still works outside this module:
# run `pigtrough serve --routes FILE` yourself.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkIf
    mkOption
    types
    ;

  cfg = config.services.pigtrough;

  tomlFormat = pkgs.formats.toml { };

  hasRoutes = cfg.routes != [ ];

  # The route table the unit passes as `--routes`, rendered from `routes`;
  # none means the binary's compiled-in github-api route.
  routesFile =
    if hasRoutes then tomlFormat.generate "pigtrough-routes.toml" { route = cfg.routes; } else null;

  pigtroughBin = "${cfg.package}/bin/pigtrough";
  piggyBin = "${cfg.piggyPackage}/bin/piggy";

  dirArgs = lib.optionals (cfg.dir != null) [
    "--dir"
    cfg.dir
  ];

  # One word per list element, escaped once; the store paths contain no
  # characters that need it, a user-set `dir` might.
  execWords = [
    pigtroughBin
    "serve"
  ]
  ++ dirArgs
  ++ lib.optionals (routesFile != null) [
    "--routes"
    "${routesFile}"
  ];

  launcherText = ''
    set -eu
    exec ${lib.escapeShellArgs execWords}
  '';

  launcher = pkgs.writeShellScript "pigtrough-launch" launcherText;

  # The load-all helper: per route, in order, the pipeline the operator
  # would run by hand, stopping at the first failure. It prints route names
  # and a verdict only, never a value; `pigtrough load` itself prints
  # `loaded <route>`. `pipefail` makes a failed decrypt fail the pipeline.
  loadStep = r: ''
    echo ${lib.escapeShellArg "pigtrough-load: ${r.name}"} >&2
    if ! ${
      lib.escapeShellArgs [
        piggyBin
        "pass"
        "show"
        r.secret
      ]
    } \
      | ${
        lib.escapeShellArgs (
          [
            pigtroughBin
            "load"
            r.name
          ]
          ++ dirArgs
        )
      }; then
      echo ${lib.escapeShellArg "pigtrough-load: ${r.name} failed; stopped, later routes not loaded"} >&2
      exit 1
    fi
  '';

  loadAllText = ''
    set -eu -o pipefail
  ''
  + lib.concatMapStrings loadStep cfg.routes
  + ''
    echo "pigtrough-load: all ${toString (lib.length cfg.routes)} routes loaded" >&2
  '';

  loadAll = pkgs.writeShellScript "pigtrough-load-all" loadAllText;
in
{
  options.services.pigtrough = {
    enable = lib.mkEnableOption "the pigtrough auth decoration proxy (FDR 0009)";

    # As for piggy-agent: no silent fallback. Users without pigtrough in
    # their nixpkgs set `package = piggy.packages.${system}.pigtrough`.
    package = lib.mkPackageOption pkgs "pigtrough" { };

    # The piggy that decrypts the secrets for the load unit.
    piggyPackage = lib.mkPackageOption pkgs "piggy" { };

    dir = mkOption {
      type = types.nullOr types.str;
      default = null;
      defaultText = lib.literalExpression "$XDG_RUNTIME_DIR/pigtrough";
      example = "/run/user/1000/pigtrough";
      description = ''
        The directory holding `proxy.sock` and `control.sock` (`--dir`),
        for both the serve unit and the load unit. `null` uses the
        binary's default, `$XDG_RUNTIME_DIR/pigtrough`. Keep it short: a
        unix socket path is limited to about 108 bytes.
      '';
    };

    routes = mkOption {
      type = types.listOf tomlFormat.type;
      default = [ ];
      example = lib.literalExpression ''
        [
          {
            name = "forgejo-api";
            upstream = "forgejo.example.org";
            auth = "token";
            secret = "forgejo/smith-readonly";
            owners = [ "some-org" ];
            loopback_port = 8731;
            allow = [
              { method = "GET"; path = [ "api" "v1" "repos" "{owner}" "{name}" ]; }
            ];
          }
        ]
      '';
      description = ''
        The route table, as the `[[route]]` entries of pigtrough(1)'s
        ROUTE TABLE, rendered to a TOML file passed as `--routes`. `secret`
        is the name of a piggy entry, never a value. The binary validates
        the table at start and refuses to run on any error, so a mistake
        shows up as a failed unit, not as a silently wrong route.

        Routes are defined here, in nix, only: the load unit reads each
        route's `name` and `secret` from this list. With no routes the unit
        serves the compiled-in `github-api` route and no load unit is
        generated (the module does not know that route's secret name); load
        it by hand as pigtrough(1) shows.
      '';
    };

    loadEnvironment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = lib.literalExpression ''
        {
          SSH_AUTH_SOCK = "/run/user/1000/piggy-agent.sock";
          SSH_ASKPASS = "/run/current-system/sw/libexec/piggy-askpass";
          SSH_ASKPASS_REQUIRE = "force";
        }
      '';
      description = ''
        Environment for the load unit, which runs `piggy pass show`. A user
        unit does not inherit the shell's environment, and the PIN dialog
        and the agent socket come from it; set here what your `piggy` needs
        (for example `PIGGY_AUTH_SOCK` or `SSH_AUTH_SOCK`, `SSH_ASKPASS`,
        `DISPLAY` or `WAYLAND_DISPLAY`). Never put a secret here.
      '';
    };

    _launcherText = mkOption {
      type = types.str;
      internal = true;
      visible = false;
      default = "";
      description = "Internal: the serve launcher script text, for eval-test.";
    };

    _loadAllText = mkOption {
      type = types.str;
      internal = true;
      visible = false;
      default = "";
      description = "Internal: the load-all script text, for eval-test.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.pigtrough: Linux only (it is a systemd user unit and pigtrough reads /proc).";
      }
      {
        assertion = lib.all (r: (r.name or null) != null && (r.secret or null) != null) cfg.routes;
        message = "services.pigtrough: every route needs a `name` and a `secret` (the load unit reads both).";
      }
      {
        assertion = lib.all (
          r: lib.isString (r.name or null) && lib.isString (r.secret or null)
        ) cfg.routes;
        message = "services.pigtrough: a route's `name` and `secret` must be strings.";
      }
    ];

    services.pigtrough._launcherText = launcherText;
    services.pigtrough._loadAllText = lib.optionalString hasRoutes loadAllText;

    # The mkIf sits on the whole attrset, as in piggy-agent: a mkIf on a
    # nested key is not unwrapped by an `attrs`-typed option.
    systemd.user.services = mkIf pkgs.stdenv.hostPlatform.isLinux (
      {
        pigtrough = {
          Unit = {
            Description = "pigtrough auth decoration proxy (no secret loaded until the load unit runs)";
            Documentation = "https://code.linenisgreat.com/piggy";
          };

          Service = {
            ExecStart = "${launcher}";
            # A crash or restart comes back with every route unloaded: it
            # answers 503 until the operator loads again. Never a card touch.
            Restart = "always";
            RestartSec = 3;
            NoNewPrivileges = true;
            # Upstreams are reached over TCP, clients over unix sockets.
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
          };

          Install = {
            WantedBy = [ "default.target" ];
          };
        };
      }
      // lib.optionalAttrs hasRoutes {
        # Started by the operator, never by anything else: it has no
        # [Install] section and nothing wants it, so a boot or a restart of
        # the serve unit never runs it. It reads the card (through
        # `piggy pass show`) only because the operator started it.
        pigtrough-load = {
          Unit = {
            Description = "Load every pigtrough route's secret from the piggy store (start by hand)";
            Documentation = "https://code.linenisgreat.com/piggy";
            Requires = [ "pigtrough.service" ];
            After = [ "pigtrough.service" ];
          };

          Service = {
            Type = "oneshot";
            ExecStart = "${loadAll}";
            Environment = lib.mapAttrsToList (k: v: "${k}=${v}") cfg.loadEnvironment;
          };
        };
      }
    );
  };
}
