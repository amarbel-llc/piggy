# home-manager module for `services.piggy-agent`.
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
    optionalString
    types
    ;

  cfg = config.services.piggy-agent;

  # Auto-detect whether we're running the rust `piggy agent` subcommand
  # or the C `pivy-agent` standalone binary. Determined by `package.pname`
  # so users only configure `package`; the dispatch shape (subcommand vs
  # direct binary) follows from it.
  isRustAgent = (cfg.package.pname or "") == "piggy";
  binPath = "${cfg.package}/bin/${if isRustAgent then "piggy" else "pivy-agent"}";
  preArgs = lib.optional isRustAgent "agent";

  # Build the per-instance unit definitions. Single-instance mode
  # synthesizes one instance named `piggy-agent` from the top-level
  # options; multi-instance mode (planned) maps `cfg.instances` through
  # this helper. `name` becomes the systemd unit / launchd label name
  # AND the default socket basename, so each instance lands at its own
  # `$XDG_STATE_HOME/piggy/<name>.sock`.
  mkInstance =
    name: instanceCfg:
    let
      socketPathExpr =
        if instanceCfg.socketPath != null then
          instanceCfg.socketPath
        else
          "\${XDG_STATE_HOME:-$HOME/.local/state}/piggy/${name}.sock";

      agentArgs = [
        "-i"
        "-a"
        socketPathExpr
      ]
      ++ (lib.optionals (instanceCfg.guid != null) [
        "-g"
        instanceCfg.guid
      ])
      ++ lib.optional instanceCfg.allCards "-A"
      ++ (lib.optionals (instanceCfg.cak != null) [
        "-K"
        instanceCfg.cak
      ])
      ++ [
        "-S"
        instanceCfg.slots
      ]
      ++ instanceCfg.extraArgs;

      # Single shared launcher script for both Linux and Darwin. Handles
      # XDG_STATE_HOME default, socket-dir creation, stale-socket cleanup,
      # askpass env wiring, then exec's the agent. Unifying eliminates
      # the brittle bash -c '...' string in ExecStart (single-quote
      # injection hazards) and the tmpfiles.d rule (the script mkdir's
      # the dir itself).
      launcher = pkgs.writeShellScript "${name}-launch" ''
        set -eu
        : "''${HOME:?HOME must be set}"
        : "''${XDG_STATE_HOME:=$HOME/.local/state}"
        SOCK="${socketPathExpr}"
        mkdir -p -m 0700 "$(dirname "$SOCK")"
        rm -f "$SOCK"
        export SSH_AUTH_SOCK="$SOCK"
        ${optionalString (instanceCfg.askpass != null) ''
          export SSH_ASKPASS="${instanceCfg.askpass}"
          export SSH_ASKPASS_REQUIRE=force
        ''}
        exec ${binPath} ${lib.escapeShellArgs preArgs} ${lib.escapeShellArgs agentArgs}
      '';

      linuxService = {
        Unit = {
          Description = "Piggy PIV-backed SSH agent (${name})";
          Documentation = "https://github.com/amarbel-llc/piggy";
        };

        Service = {
          ExecStart = "${launcher}";
          Restart = "always";
          RestartSec = 3;
        };

        Install = {
          WantedBy = [ "default.target" ];
        };
      };

      darwinAgent = {
        enable = true;
        config = {
          ProgramArguments = [ "${launcher}" ];
          KeepAlive = {
            Crashed = true;
            SuccessfulExit = false;
          };
          RunAtLoad = true;
          ProcessType = "Background";
          StandardErrorPath =
            if instanceCfg.logFile != null then instanceCfg.logFile else "$HOME/Library/Logs/${name}.log";
        };
      };
    in
    {
      inherit
        socketPathExpr
        launcher
        linuxService
        darwinAgent
        ;
    };

  # Single-instance mode: synthesize one instance named `piggy-agent`
  # from the top-level option set. Multi-instance support added in a
  # follow-up commit will replace this with a dispatch on
  # `cfg.instances`.
  singleInstance = mkInstance "piggy-agent" {
    inherit (cfg)
      guid
      allCards
      cak
      slots
      socketPath
      askpass
      logFile
      extraArgs
      ;
  };
in
{
  options.services.piggy-agent = {
    enable = lib.mkEnableOption "piggy PIV-backed SSH agent";

    # mkPackageOption defaults to `pkgs.piggy` and emits the right
    # defaultText. Users without piggy in their nixpkgs (the common
    # case) MUST set `package = piggy.packages.${system}.piggy` from
    # this flake — there's no silent fallback. Set `package = pkgs.pivy`
    # (with pname = "pivy") to run the C agent under the same surface.
    package = lib.mkPackageOption pkgs "piggy" { };

    guid = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "A1B2C3D4E5F60718293A4B5C6D7E8F90";
      description = ''
        GUID of the PIV card to use. Mutually exclusive with
        {option}`allCards`. Exactly one of the two must be set.
      '';
    };

    allCards = mkOption {
      type = types.bool;
      default = false;
      description = ''
        All-cards mode: expose keys from every detected PIV card.
        Mutually exclusive with {option}`guid`. Pass `-A` to the agent.
      '';
    };

    cak = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "ecdsa-sha2-nistp256 AAAA...";
      description = ''
        Card Authentication Key (CAK) public key, as an SSH-formatted
        string. Optional; pinned-card mode without it is allowed.
      '';
    };

    slots = mkOption {
      type = types.str;
      default = "all";
      example = "9a,9e";
      description = ''
        Slot filter passed as `-S`. Default `"all"` exposes every slot.
        Comma-separated hex slot IDs (e.g. `"9a"`, `"9a,9e"`) restrict
        the surface.
      '';
    };

    socketPath = mkOption {
      type = types.nullOr types.str;
      default = null;
      defaultText = lib.literalExpression "$XDG_STATE_HOME/piggy/piggy-agent.sock";
      example = "/run/user/1000/piggy-agent.sock";
      description = ''
        Path to the agent's UNIX socket. When `null` (default), the
        module uses `$XDG_STATE_HOME/piggy/piggy-agent.sock`, with the
        XDG-spec fallback to `$HOME/.local/state/piggy/...` if
        `$XDG_STATE_HOME` is unset. The chosen path is exported as
        `$SSH_AUTH_SOCK` for the user session.
      '';
    };

    askpass = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = lib.literalExpression "\"\${pkgs.piggy}/share/piggy/piggy-askpass.sh\"";
      description = ''
        Path to the askpass helper. When set, exported as
        `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force` so failed
        unlocks render piggy-aware prompts rather than falling back
        to whatever the user's shell inherits.
      '';
    };

    logFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Stderr destination. Linux: ignored (use journalctl).
        Darwin: defaults to `~/Library/Logs/piggy-agent.log` when
        `null`.
      '';
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Extra positional arguments appended to the agent's argv.
        Useful for flags this module doesn't model directly (e.g.
        debug verbosity).
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.guid == null || !cfg.allCards;
        message = "services.piggy-agent: `guid` and `allCards` are mutually exclusive.";
      }
      {
        assertion = cfg.guid != null || cfg.allCards;
        message = "services.piggy-agent: one of `guid` or `allCards` must be set.";
      }
      {
        assertion = builtins.match "^(all|[0-9a-fA-F]{2}(,[0-9a-fA-F]{2})*)$" cfg.slots != null;
        message = "services.piggy-agent: `slots` must be \"all\" or a comma-separated list of two-hex-char slot IDs (e.g. \"9a\", \"9a,9e\").";
      }
    ];

    systemd.user.services = mkIf pkgs.stdenv.isLinux {
      piggy-agent = singleInstance.linuxService;
    };

    launchd.agents = mkIf pkgs.stdenv.isDarwin {
      piggy-agent = singleInstance.darwinAgent;
    };

    home.sessionVariables = {
      SSH_AUTH_SOCK = singleInstance.socketPathExpr;
    };
  };
}
