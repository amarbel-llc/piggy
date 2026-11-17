# home-manager module for `services.pigtrough` (FDR 0009; operator ruling R3,
# 2026-11-17): a systemd user unit that keeps `pigtrough serve` running.
#
# The unit never holds a credential and never touches the card. A (re)start
# leaves every route unloaded, so it answers `503 secret-unavailable` until
# the operator runs, per route and by hand,
#
#   piggy pass show <entry> | pigtrough load <route>
#
# which is the only step that reads the card. That is the point of R3: fail
# closed, no unattended card use. Linux only (systemd user units).
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

  # The route table the unit passes as `--routes`: the operator's own file,
  # or one generated from `routes`; neither means the binary's compiled-in
  # github-api route.
  routesFile =
    if cfg.routesFile != null then
      cfg.routesFile
    else if cfg.routes != [ ] then
      tomlFormat.generate "pigtrough-routes.toml" { route = cfg.routes; }
    else
      null;

  # One word per list element, escaped once; the store paths contain no
  # characters that need it, a user-set `dir` might.
  execWords = [
    "${cfg.package}/bin/pigtrough"
    "serve"
  ]
  ++ lib.optionals (cfg.dir != null) [
    "--dir"
    cfg.dir
  ]
  ++ lib.optionals (routesFile != null) [
    "--routes"
    "${routesFile}"
  ];

  launcherText = ''
    set -eu
    exec ${lib.escapeShellArgs execWords}
  '';

  launcher = pkgs.writeShellScript "pigtrough-launch" launcherText;
in
{
  options.services.pigtrough = {
    enable = lib.mkEnableOption "the pigtrough auth decoration proxy (FDR 0009)";

    # As for piggy-agent: no silent fallback. Users without pigtrough in
    # their nixpkgs set `package = piggy.packages.${system}.pigtrough`.
    package = lib.mkPackageOption pkgs "pigtrough" { };

    dir = mkOption {
      type = types.nullOr types.str;
      default = null;
      defaultText = lib.literalExpression "$XDG_RUNTIME_DIR/pigtrough";
      example = "/run/user/1000/pigtrough";
      description = ''
        The directory holding `proxy.sock` and `control.sock` (`--dir`).
        `null` uses the binary's default, `$XDG_RUNTIME_DIR/pigtrough`.
        Keep it short: a unix socket path is limited to about 108 bytes.
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
        Mutually exclusive with {option}`routesFile`. With neither set the
        unit serves the compiled-in `github-api` route.
      '';
    };

    routesFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        A route table file of your own, passed as `--routes`. Mutually
        exclusive with {option}`routes`.
      '';
    };

    _launcherText = mkOption {
      type = types.str;
      internal = true;
      visible = false;
      default = "";
      description = "Internal: the launcher script text, for eval-test.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.pigtrough: Linux only (it is a systemd user unit and pigtrough reads /proc).";
      }
      {
        assertion = !(cfg.routes != [ ] && cfg.routesFile != null);
        message = "services.pigtrough: `routes` and `routesFile` are mutually exclusive.";
      }
    ];

    services.pigtrough._launcherText = launcherText;

    # The mkIf sits on the whole attrset, as in piggy-agent: a mkIf on the
    # nested `pigtrough` key is not unwrapped by an `attrs`-typed option.
    systemd.user.services = mkIf pkgs.stdenv.hostPlatform.isLinux {
      pigtrough = {
        Unit = {
          Description = "pigtrough auth decoration proxy (no secret loaded until `pigtrough load`)";
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
    };
  };
}
