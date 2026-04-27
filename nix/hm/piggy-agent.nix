# home-manager module for `services.piggy-agent`.
#
# Generates a systemd user service on Linux and a launchd LaunchAgent on
# Darwin from one option set. Wraps the `piggy agent` rust subcommand
# (or the C `pivy-agent` if `package` is swapped to `pkgs.pivy`).
#
# Step 1 (#52): single-instance only — top-level `guid` / `allCards`
# / `cak` / `slots` directly drive one unit. Step 2 adds
# `services.piggy-agent.instances.<name>` for multi-instance.
#
# Scoping doc: docs/plans/2026-04-27-piggy-agent-nix-module.md
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

  # Resolve the binary the unit should exec. Default is `piggy agent ...`
  # against piggy's wrapped binary; users can swap `package` to `pkgs.pivy`
  # and `programName` to `pivy-agent` to run the C agent under the same
  # surface.
  binPath = "${cfg.package}/bin/${cfg.programName}";

  # Socket path: $XDG_STATE_HOME/piggy/piggy-agent.sock with $HOME fallback
  # for platforms (Darwin) that don't set XDG_STATE_HOME by default.
  # The wrapper script and shell-init use the same shell expansion so they
  # always resolve to the same path at runtime.
  socketPathExpr =
    if cfg.socketPath != null then
      cfg.socketPath
    else
      "\${XDG_STATE_HOME:-$HOME/.local/state}/piggy/piggy-agent.sock";

  # The agent's argv beyond `agent` and `-i`. Built from the option surface,
  # then quoted as a shell-string list inside the wrapper script.
  agentArgs =
    [
      "-i"
      "-a"
      socketPathExpr
    ]
    ++ (lib.optionals (cfg.guid != null) [
      "-g"
      cfg.guid
    ])
    ++ lib.optional cfg.allCards "-A"
    ++ (lib.optionals (cfg.cak != null) [
      "-K"
      cfg.cak
    ])
    ++ [
      "-S"
      cfg.slots
    ]
    ++ cfg.extraArgs;

  # Shell-quote each argv element. Used inside the wrapper script and the
  # systemd ExecStart line.
  shellEscape = arg: lib.escapeShellArg arg;
  agentArgsLine = lib.concatStringsSep " " (map shellEscape agentArgs);

  # The agent subcommand on the binary. For `piggy agent ...` we prepend
  # `agent`; for `pivy-agent` (which IS the agent) we don't.
  preArgs = if cfg.programName == "piggy" then [ "agent" ] else [ ];
  preArgsLine = lib.concatStringsSep " " (map shellEscape preArgs);

  # Linux: systemd user service.
  #
  # Uses `ExecStartPre=/bin/rm -f $SOCK` (matching the prior pivy unit) to
  # clear stale sockets from previous runs. Socket activation (#53) would
  # eliminate the need for this preflight; until then this is the
  # well-trodden path.
  linuxService = {
    Unit = {
      Description = "Piggy PIV-backed SSH agent";
      Documentation = "https://github.com/amarbel-llc/piggy";
    };

    Service = {
      Environment = [
        "SSH_AUTH_SOCK=${socketPathExpr}"
      ]
      ++ lib.optional (cfg.askpass != null) "SSH_ASKPASS=${cfg.askpass}"
      ++ lib.optional (cfg.askpass != null) "SSH_ASKPASS_REQUIRE=force";
      # Stale-socket cleanup. systemd expands $SSH_AUTH_SOCK from
      # Environment= above before invoking ExecStartPre.
      ExecStartPre = "${pkgs.coreutils}/bin/rm -f \"$SSH_AUTH_SOCK\"";
      # Use a wrapped shell so $XDG_STATE_HOME / $HOME expansion happens
      # at runtime (systemd does NOT expand env-var refs inside ExecStart
      # argument values, only in `Environment=` and `EnvironmentFile=`).
      ExecStart = "${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/mkdir -p -m 0700 \"$(dirname \"${socketPathExpr}\")\" && exec ${binPath} ${preArgsLine} ${agentArgsLine}'";
      Restart = "always";
      RestartSec = 3;
    };

    Install = {
      WantedBy = [ "default.target" ];
    };
  };

  # Darwin: launchd LaunchAgent. launchd has no ExecStartPre analogue and
  # does not perform shell expansion on ProgramArguments entries, so the
  # cleanest path is a wrapper script that does the mkdir + rm + exec
  # itself.
  darwinWrapper = pkgs.writeShellScript "piggy-agent-launch" ''
    set -eu
    : "''${HOME:?HOME must be set}"
    : "''${XDG_STATE_HOME:=$HOME/.local/state}"
    SOCK="${socketPathExpr}"
    mkdir -p -m 0700 "$(dirname "$SOCK")"
    rm -f "$SOCK"
    export SSH_AUTH_SOCK="$SOCK"
    ${optionalString (cfg.askpass != null) ''
      export SSH_ASKPASS="${cfg.askpass}"
      export SSH_ASKPASS_REQUIRE=force
    ''}
    exec ${binPath} ${preArgsLine} ${agentArgsLine}
  '';

  darwinAgent = {
    enable = true;
    config = {
      ProgramArguments = [ "${darwinWrapper}" ];
      KeepAlive = {
        Crashed = true;
        SuccessfulExit = false;
      };
      RunAtLoad = true;
      ProcessType = "Background";
      StandardErrorPath =
        if cfg.logFile != null then
          cfg.logFile
        else
          "$HOME/Library/Logs/piggy-agent.log";
    };
  };
in
{
  meta.maintainers = [ ];

  options.services.piggy-agent = {
    enable = lib.mkEnableOption "piggy PIV-backed SSH agent";

    package = lib.mkOption {
      type = types.package;
      default = pkgs.piggy or pkgs.pivy;
      defaultText = lib.literalExpression "pkgs.piggy";
      description = ''
        Package providing the agent binary. Default is `pkgs.piggy`
        (the rust agent at `bin/piggy agent ...`). Set to `pkgs.pivy`
        to run the C `pivy-agent` instead under the same option
        surface.
      '';
    };

    programName = lib.mkOption {
      type = types.str;
      default = "piggy";
      description = ''
        Binary name inside `package`'s `bin/`. Defaults to `piggy`,
        which means the unit invokes `piggy agent <flags>`. Set to
        `pivy-agent` when `package = pkgs.pivy` so the unit invokes
        `pivy-agent <flags>` directly (no `agent` subcommand).
      '';
    };

    guid = lib.mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "A1B2C3D4E5F60718293A4B5C6D7E8F90";
      description = ''
        GUID of the PIV card to use. Mutually exclusive with
        {option}`allCards`. Exactly one of the two must be set.
      '';
    };

    allCards = lib.mkOption {
      type = types.bool;
      default = false;
      description = ''
        All-cards mode: expose keys from every detected PIV card.
        Mutually exclusive with {option}`guid`. Pass `-A` to the agent.
      '';
    };

    cak = lib.mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "ecdsa-sha2-nistp256 AAAA...";
      description = ''
        Card Authentication Key (CAK) public key, as an SSH-formatted
        string. Optional; pinned-card mode without it is allowed.
      '';
    };

    slots = lib.mkOption {
      type = types.str;
      default = "all";
      example = "9a,9e";
      description = ''
        Slot filter passed as `-S`. Default `"all"` exposes every slot.
        Comma-separated hex slot IDs (e.g. `"9a"`, `"9a,9e"`) restrict
        the surface.
      '';
    };

    socketPath = lib.mkOption {
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

    askpass = lib.mkOption {
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

    logFile = lib.mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Stderr destination. Linux: ignored (use journalctl).
        Darwin: defaults to `~/Library/Logs/piggy-agent.log` when
        `null`.
      '';
    };

    extraArgs = lib.mkOption {
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

    # Linux: systemd user service.
    systemd.user.services = mkIf pkgs.stdenv.isLinux {
      piggy-agent = linuxService;
    };

    # Linux: ensure $XDG_STATE_HOME/piggy/ exists with mode 0700 before
    # anything tries to bind. tmpfiles.d D = create-dir-if-missing.
    systemd.user.tmpfiles.rules = mkIf pkgs.stdenv.isLinux [
      "D %S/piggy 0700 - - -"
    ];

    # Darwin: launchd agent. The wrapper script handles directory
    # creation + stale-socket cleanup before exec'ing the agent.
    launchd.agents = mkIf pkgs.stdenv.isDarwin {
      piggy-agent = darwinAgent;
    };

    # Export SSH_AUTH_SOCK so the user's shell points at the agent.
    home.sessionVariables = {
      SSH_AUTH_SOCK = socketPathExpr;
    };
  };
}
