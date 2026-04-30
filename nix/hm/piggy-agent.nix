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

      # Args other than the socket path. These get routed through
      # `lib.escapeShellArgs` so user-supplied strings (guid, cak,
      # extraArgs) can't break the exec line. The socket arg is
      # handled separately in `launcherText` because it MUST be bash-
      # expanded — see the comment on the exec line below.
      nonSocketArgs =
        (lib.optionals (instanceCfg.guid != null) [
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
      # then exec's the agent. Unifying eliminates the brittle bash -c
      # '...' string in ExecStart (single-quote injection hazards) and
      # the tmpfiles.d rule (the script mkdir's the dir itself).
      #
      # SSH_AUTH_SOCK stays here because socketPathExpr can include
      # `$XDG_STATE_HOME` / `$HOME` references that need runtime
      # expansion. Static env vars (askpass, confirm, notifySend) are
      # set on the systemd Service.Environment / launchd
      # EnvironmentVariables instead so they're inspectable in
      # eval-test.
      #
      # The exec line writes `-a "$SOCK"` directly instead of routing
      # the socket through `lib.escapeShellArgs` — escapeShellArgs
      # single-quotes every argument, which would prevent bash from
      # expanding `$XDG_STATE_HOME` / `$HOME` and leave the agent to
      # bind(2) the literal string `$HOME/.local/state/...`. See #63.
      launcherText = ''
        set -eu
        : "''${HOME:?HOME must be set}"
        : "''${XDG_STATE_HOME:=$HOME/.local/state}"
        SOCK="${socketPathExpr}"
        mkdir -p -m 0700 "$(dirname "$SOCK")"
        rm -f "$SOCK"
        export SSH_AUTH_SOCK="$SOCK"
        exec ${binPath} ${lib.escapeShellArgs preArgs} -i -a "$SOCK" ${lib.escapeShellArgs nonSocketArgs}
      '';

      launcher = pkgs.writeShellScript "${name}-launch" launcherText;

      # Static env vars routed to the agent process via the unit's
      # native env-vars surface. systemd takes a list of "K=V" strings;
      # launchd takes an attrset.
      agentEnvAttrs =
        lib.optionalAttrs (instanceCfg.askpass != null) {
          SSH_ASKPASS = instanceCfg.askpass;
          SSH_ASKPASS_REQUIRE = "force";
        }
        // lib.optionalAttrs (instanceCfg.confirm != null) {
          SSH_CONFIRM = instanceCfg.confirm;
        }
        // lib.optionalAttrs (instanceCfg.notifySend != null) {
          SSH_NOTIFY_SEND = instanceCfg.notifySend;
        };

      agentEnvList = lib.mapAttrsToList (k: v: "${k}=${v}") agentEnvAttrs;

      linuxService = {
        Unit = {
          Description = "Piggy PIV-backed SSH agent (${name})";
          Documentation = "https://github.com/amarbel-llc/piggy";
        };

        Service = {
          ExecStart = "${launcher}";
          Environment = agentEnvList;
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
          EnvironmentVariables = agentEnvAttrs;
          KeepAlive = {
            Crashed = true;
            SuccessfulExit = false;
          };
          RunAtLoad = true;
          ProcessType = "Background";
          # home-manager's launchd module declares StandardErrorPath as
          # `nullOr (absolute path)`, and launchd does not expand `$HOME`
          # in plist contexts anyway. Resolve the home prefix at eval
          # time via `config.home.homeDirectory` so the default is a
          # real absolute path that passes the type check. Closes #64.
          StandardErrorPath =
            if instanceCfg.logFile != null then
              instanceCfg.logFile
            else
              "${config.home.homeDirectory}/Library/Logs/${name}.log";
        };
      };
    in
    {
      inherit
        socketPathExpr
        launcher
        launcherText
        linuxService
        darwinAgent
        ;
    };

  hasInstances = cfg.instances != { };

  # Snapshot of the top-level instance options, used to synthesize a
  # single `piggy-agent` entry when `cfg.instances` is empty.
  topLevelInstanceCfg = {
    inherit (cfg)
      guid
      allCards
      cak
      slots
      socketPath
      askpass
      confirm
      notifySend
      logFile
      extraArgs
      ;
  };

  # Whether the user set any of the top-level instance options to a
  # non-default value. Used by the "top-level + instances" mutex
  # assertion (OQ1: reject as config error).
  topLevelHasInstanceConfig =
    cfg.guid != null
    || cfg.allCards
    || cfg.cak != null
    || cfg.slots != "all"
    || cfg.socketPath != null
    || cfg.askpass != null
    || cfg.confirm != null
    || cfg.notifySend != null
    || cfg.logFile != null
    || cfg.extraArgs != [ ];

  # Map of effective unit-name → per-instance config. Single-instance
  # mode synthesizes one entry named `piggy-agent` from the top-level
  # options. Multi-instance mode prefixes each user key with
  # `piggy-agent-` so the systemd / launchd labels stay namespaced.
  effectiveInstances =
    if hasInstances then
      lib.mapAttrs' (name: ic: lib.nameValuePair "piggy-agent-${name}" ic) cfg.instances
    else
      { piggy-agent = topLevelInstanceCfg; };

  builtInstances = lib.mapAttrs mkInstance effectiveInstances;

  # Per-instance assertions: mutex (`guid` xor `allCards`),
  # required-card, and `slots` format. The instance-name suffix in
  # the message is what lets users find the offending entry when
  # multi-instance is in play; in single-instance mode it always
  # reads `(instance piggy-agent)`.
  perInstanceAssertions = lib.flatten (
    lib.mapAttrsToList (unitName: ic: [
      {
        assertion = ic.guid == null || !ic.allCards;
        message = "services.piggy-agent: `guid` and `allCards` are mutually exclusive (instance ${unitName}).";
      }
      {
        assertion = ic.guid != null || ic.allCards;
        message = "services.piggy-agent: one of `guid` or `allCards` must be set (instance ${unitName}).";
      }
      {
        assertion = builtins.match "^(all|[0-9a-fA-F]{2}(,[0-9a-fA-F]{2})*)$" ic.slots != null;
        message = "services.piggy-agent: `slots` must be \"all\" or a comma-separated list of two-hex-char slot IDs, e.g. \"9a\", \"9a,9e\" (instance ${unitName}).";
      }
    ]) effectiveInstances
  );
in
{
  options.services.piggy-agent = {
    enable = lib.mkEnableOption "piggy PIV-backed SSH agent";

    # mkPackageOption defaults to `pkgs.piggy` and emits the right
    # defaultText. Users without piggy in their nixpkgs (the common
    # case) MUST set `package = piggy.packages.${system}.piggy` from
    # this flake — there's no silent fallback.
    #
    # Note: post-`79658e1` (v1.0), `piggy agent` itself exec's into C
    # `pivy-agent` — there is no Rust-vs-C implementation choice to
    # make at this layer. The `package = pkgs.pivy` escape hatch
    # (selected by `pname == "pivy"` above) bypasses one layer of
    # wrapping by talking to `pivy-agent` directly instead of via
    # `piggy agent`'s clap dispatch; same underlying agent either way.
    # The Rust agent under `crates/piggy/src/cmd/agent/` is held off
    # the dispatch path until the maturation issues (#56, #58, #59)
    # close.
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
        `$XDG_STATE_HOME` is unset. Whether this path is also
        exported as `$SSH_AUTH_SOCK` for the user shell depends on
        {option}`setSshAuthSock` — default false (mux-in-front
        friendly).
      '';
    };

    setSshAuthSock = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Set `home.sessionVariables.SSH_AUTH_SOCK` to this agent's
        socket. Default false because in mux-in-front setups (e.g.
        ssh-agent-mux multiplexing piggy-agent + a software-keys
        agent + 1Password's agent + ...) the mux owns the user-
        facing `SSH_AUTH_SOCK` and clobbering it from here breaks
        the chain. Set to true if piggy IS the user's primary
        agent (no mux above it).

        Only applies in single-instance mode. Multi-instance mode
        never sets `SSH_AUTH_SOCK` regardless (parallel reasoning:
        the module can't pick a winner among instances). Closes
        piggy#62.
      '';
    };

    askpass = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = lib.literalExpression "\"\${pkgs.piggy}/share/piggy/piggy-askpass.sh\"";
      description = ''
        Path to the askpass helper. When set, exported as
        `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force` in two
        places:

        1. The agent process's environment (always — covers ssh
           operations originating from the agent itself).
        2. The user's interactive shell environment, via
           `home.sessionVariables`, in single-instance mode only —
           covers `ssh-add`, signed `git commit`, and any other
           ssh-client invocation where the askpass fallback chain
           consults the calling shell's env. Multi-instance mode
           skips this propagation, parallel to the SSH_AUTH_SOCK
           decision: the module cannot pick a winner among
           per-instance askpass values; users with multiple
           instances manage `home.sessionVariables.SSH_ASKPASS`
           themselves.

        Together these guarantee that a failed unlock renders the
        configured askpass rather than falling through to whatever
        ssh-client picks up from the OS (typically zenity or
        ssh-askpass). Closes piggy#60.
      '';
    };

    confirm = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = lib.literalExpression "\"\${pkgs.pivy}/libexec/pivy/pivy-askpass\"";
      description = ''
        Path to the SSH_CONFIRM helper, exported into the agent
        process's environment. pivy-agent reads `SSH_CONFIRM` to
        surface slot-touch / sensitive-operation confirmations
        (e.g. "key 9D wants to sign — confirm?"). Without it, the
        relevant pivy-agent code path either fails or falls through
        to a default that may differ from what the operator
        configured. Typically the same path as {option}`askpass` —
        pivy-askpass handles both prompts and confirmations.
      '';
    };

    notifySend = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = lib.literalExpression "\"\${pkgs.pivy}/libexec/pivy/pivy-notify\"";
      description = ''
        Path to the SSH_NOTIFY_SEND helper, exported into the agent
        process's environment. pivy-agent reads `SSH_NOTIFY_SEND` to
        surface desktop notifications (e.g. unlock state changes).
        Distinct from {option}`askpass` and {option}`confirm` because
        pivy ships a separate `pivy-notify` binary for this.
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

    _launcherTexts = mkOption {
      type = types.attrsOf types.str;
      internal = true;
      visible = false;
      default = { };
      description = ''
        Internal: per-instance launcher script texts, keyed by unit
        name. Exposed for `eval-test.nix` to assert wire-level
        properties of the generated launcher (notably, that the
        socket path is bash-expanded rather than single-quoted —
        see #63). Not part of the user-facing surface.
      '';
    };

    instances = mkOption {
      default = { };
      example = lib.literalExpression ''
        {
          default = { guid = "ABCD..."; cak = "ecdsa-sha2-nistp256 AAAA..."; };
          work    = { guid = "1234..."; slots = "9a"; };
          spare   = { allCards = true; };
        }
      '';
      type = types.attrsOf (
        types.submodule {
          options = {
            guid = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "A1B2C3D4E5F60718293A4B5C6D7E8F90";
              description = "GUID of the PIV card for this instance. Mutex with `allCards`.";
            };
            allCards = mkOption {
              type = types.bool;
              default = false;
              description = "All-cards mode for this instance. Mutex with `guid`.";
            };
            cak = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Optional Card Authentication Key for this instance.";
            };
            slots = mkOption {
              type = types.str;
              default = "all";
              description = "Slot filter for this instance.";
            };
            socketPath = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Path to this instance's UNIX socket. When `null` the
                module uses
                `$XDG_STATE_HOME/piggy/piggy-agent-<name>.sock`.
              '';
            };
            askpass = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Per-instance askpass override.";
            };
            confirm = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Per-instance SSH_CONFIRM override.";
            };
            notifySend = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Per-instance SSH_NOTIFY_SEND override.";
            };
            logFile = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Stderr destination. Linux: ignored. Darwin: defaults
                to `~/Library/Logs/piggy-agent-<name>.log` when
                `null`.
              '';
            };
            extraArgs = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "Extra agent argv per instance.";
            };
          };
        }
      );
      description = ''
        Multi-instance map. Each key becomes a systemd user unit
        named `piggy-agent-<name>` (Linux) or a launchd agent labelled
        `piggy-agent-<name>` (Darwin), with its own socket at
        `$XDG_STATE_HOME/piggy/piggy-agent-<name>.sock`.

        Mutually exclusive with the top-level `guid`/`allCards`/
        `cak`/`slots`/`socketPath`/`askpass`/`logFile`/`extraArgs`
        options: setting any of those alongside a non-empty
        `instances` map is a configuration error. Use top-level
        options OR `instances`, never both.

        When `instances` is non-empty, the module does **not** set
        `$SSH_AUTH_SOCK` automatically — users pick which instance
        each shell talks to by sourcing the per-instance shell
        snippets the module emits (added in a later commit).
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = perInstanceAssertions ++ [
      {
        assertion = !(hasInstances && topLevelHasInstanceConfig);
        message =
          "services.piggy-agent: top-level options "
          + "(`guid`/`allCards`/`cak`/`slots`/`socketPath`/`askpass`"
          + "/`logFile`/`extraArgs`) are forbidden when `instances` "
          + "is non-empty. Move them into `instances.<name>` "
          + "entries.";
      }
    ];

    services.piggy-agent._launcherTexts = lib.mapAttrs (_: built: built.launcherText) builtInstances;

    systemd.user.services = mkIf pkgs.stdenv.isLinux (
      lib.mapAttrs (_: built: built.linuxService) builtInstances
    );

    launchd.agents = mkIf pkgs.stdenv.isDarwin (
      lib.mapAttrs (_: built: built.darwinAgent) builtInstances
    );

    home.sessionVariables = lib.mkIf (!hasInstances) (
      lib.optionalAttrs cfg.setSshAuthSock {
        SSH_AUTH_SOCK = builtInstances.piggy-agent.socketPathExpr;
      }
      // lib.optionalAttrs (cfg.askpass != null) {
        SSH_ASKPASS = cfg.askpass;
        SSH_ASKPASS_REQUIRE = "force";
      }
    );

    # Per-instance shell snippets. In multi-instance mode the module
    # cannot pick a winner for `$SSH_AUTH_SOCK`, so it emits one
    # source-able fragment per instance under
    # `~/.config/piggy/<unit>.sh`. Users add e.g.
    #   source ~/.config/piggy/piggy-agent-work.sh
    # to whichever shell-init file (.bashrc / config.fish / .zshrc)
    # should talk to that instance.
    xdg.configFile = lib.mkIf hasInstances (
      lib.mapAttrs' (
        unitName: built:
        lib.nameValuePair "piggy/${unitName}.sh" {
          text = ''
            # Source this file to point ssh-add / ssh at the
            # ${unitName} piggy-agent instance.
            export SSH_AUTH_SOCK="${built.socketPathExpr}"
          '';
        }
      ) builtInstances
    );
  };
}
