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
      # home-manager normally derives this from `home.username` and the
      # platform; the harness pins it so the module can build absolute
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
  };

  # `mkPackageOption pkgs "piggy"` defaults to `pkgs.piggy`, which
  # doesn't exist in stock nixpkgs. Every case is evaluated with
  # `package` pinned to `pkgs.hello` so the default's thrown error
  # doesn't fire when the launcher derivation gets forced.
  #
  # Passed as a separate module (not merged via `//`) so evalModules
  # does the proper deep-merge with the case's own config. `mkDefault` so
  # a case can pin `package` to the rust-agent stub below to exercise the
  # `isRustAgent` flag-construction branch (piggy#58).
  pinPackage = {
    services.piggy-agent.package = lib.mkDefault pkgs.hello;
  };

  # A package whose `pname == "piggy"` so the module's `isRustAgent`
  # branch fires. `pkgs.hello` stands in for the real derivation — the
  # launcher is only forced through eval, never realized, so the store
  # path's contents don't matter; only `pname` and the path string do.
  rustPackageStub = pkgs.hello.overrideAttrs (_: {
    pname = "piggy";
  });

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

  # Read the agent-process env from whichever platform's unit shape
  # is in play. Returns an attrset {KEY = VALUE; ...} regardless of
  # whether the underlying field is a list of "K=V" strings (systemd)
  # or an attrset (launchd). Used by the SSH_ASKPASS-contract tests.
  getUnitEnv =
    unitName: result:
    if pkgs.stdenv.isLinux then
      let
        env = result.config.systemd.user.services.${unitName}.Service.Environment or [ ];
        parsePair =
          s:
          let
            parts = lib.splitString "=" s;
          in
          {
            name = lib.head parts;
            value = lib.concatStringsSep "=" (lib.tail parts);
          };
      in
      builtins.listToAttrs (map parsePair env)
    else
      result.config.launchd.agents.${unitName}.config.EnvironmentVariables or { };

  cases = [
    {
      # Default behavior in single-instance mode (post-#62): the
      # module evaluates cleanly and produces a launcher, but does
      # NOT claim home.sessionVariables.SSH_AUTH_SOCK. The mux-in-
      # front pattern (ssh-agent-mux + 1Password + …) is common
      # enough that auto-claiming SSH_AUTH_SOCK is the wrong
      # default.
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
          ok = tripped == [ ] && sock == null && launcher != null;
          got = {
            inherit tripped sock launcher;
          };
        };
    }
    {
      # Opt-in path for users without a mux: setSshAuthSock = true
      # makes the module claim home.sessionVariables.SSH_AUTH_SOCK,
      # restoring the pre-#62 behavior on demand.
      name = "single-instance-with-set-ssh-auth-sock-true-emits-sock";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.setSshAuthSock = true;
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
    {
      name = "single-instance-with-askpass-emits-session-vars";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.askpass = "/run/current-system/sw/libexec/pivy/pivy-askpass";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          sv = result.config.home.sessionVariables;
          askpass = sv.SSH_ASKPASS or null;
          require = sv.SSH_ASKPASS_REQUIRE or null;
        in
        {
          ok =
            tripped == [ ]
            && askpass == "/run/current-system/sw/libexec/pivy/pivy-askpass"
            && require == "force";
          got = {
            inherit tripped askpass require;
          };
        };
    }
    {
      name = "single-instance-without-askpass-skips-session-vars";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          sv = result.config.home.sessionVariables;
          askpass = sv.SSH_ASKPASS or null;
          require = sv.SSH_ASKPASS_REQUIRE or null;
        in
        {
          ok = tripped == [ ] && askpass == null && require == null;
          got = {
            inherit tripped askpass require;
          };
        };
    }
    {
      # Multi-instance askpass propagation parallels the SSH_AUTH_SOCK
      # decision: the module can't pick a winner among instances, so it
      # declines to emit askpass session vars and lets the user manage
      # them per-shell. See piggy#60 for the design rationale.
      name = "multi-instance-skips-askpass-session-vars";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.instances = {
          default = {
            guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
            askpass = "/run/current-system/sw/libexec/pivy/pivy-askpass";
          };
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          sv = result.config.home.sessionVariables;
          askpass = sv.SSH_ASKPASS or null;
          require = sv.SSH_ASKPASS_REQUIRE or null;
        in
        {
          ok = tripped == [ ] && askpass == null && require == null;
          got = {
            inherit tripped askpass require;
          };
        };
    }
    {
      # SSH_ASKPASS / SSH_ASKPASS_REQUIRE on the agent-process env
      # (systemd Service.Environment / launchd EnvironmentVariables).
      # Site 2 (agent-process) of the SSH_ASKPASS contract.
      name = "single-instance-with-askpass-emits-unit-env";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.askpass = "/run/current-system/sw/libexec/pivy/pivy-askpass";
      };
      check =
        result:
        let
          env = getUnitEnv "piggy-agent" result;
        in
        {
          ok =
            (env.SSH_ASKPASS or null) == "/run/current-system/sw/libexec/pivy/pivy-askpass"
            && (env.SSH_ASKPASS_REQUIRE or null) == "force";
          got = env;
        };
    }
    {
      name = "single-instance-with-confirm-emits-unit-env";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.confirm = "/run/current-system/sw/libexec/pivy/pivy-askpass";
      };
      check =
        result:
        let
          env = getUnitEnv "piggy-agent" result;
        in
        {
          ok = (env.SSH_CONFIRM or null) == "/run/current-system/sw/libexec/pivy/pivy-askpass";
          got = env;
        };
    }
    {
      name = "single-instance-with-notify-send-emits-unit-env";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.notifySend = "/run/current-system/sw/libexec/pivy/pivy-notify";
      };
      check =
        result:
        let
          env = getUnitEnv "piggy-agent" result;
        in
        {
          ok = (env.SSH_NOTIFY_SEND or null) == "/run/current-system/sw/libexec/pivy/pivy-notify";
          got = env;
        };
    }
    {
      name = "single-instance-without-confirm-or-notify-skips-unit-env";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
      };
      check =
        result:
        let
          env = getUnitEnv "piggy-agent" result;
        in
        {
          ok = (env.SSH_CONFIRM or null) == null && (env.SSH_NOTIFY_SEND or null) == null;
          got = env;
        };
    }
    {
      # Regression for piggy#63: launcher must hand `-a "$SOCK"` to
      # the agent so bash expands the socket path before bind(2).
      # The earlier shape routed `socketPathExpr` through
      # `lib.escapeShellArgs`, which single-quotes its arguments and
      # left the agent trying to bind the literal string
      # `$HOME/.local/state/...` — which fails at bind(2) with no
      # such file.
      name = "launcher-bash-expands-default-socket-path";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
      };
      check =
        result:
        let
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          hasExpandedSock = lib.hasInfix "-a \"$SOCK\"" text;
          # `'$` would be the start of a single-quoted shell var, the
          # exact failure mode from #63.
          noSingleQuotedVar = !(lib.hasInfix "'$" text);
        in
        {
          ok = hasExpandedSock && noSingleQuotedVar;
          got = {
            inherit text hasExpandedSock noSingleQuotedVar;
          };
        };
    }
    {
      # Regression for piggy#63 (user-supplied path variant): when
      # `socketPath` is set with a bash-expandable form, the
      # launcher MUST still bash-expand it for the agent's `-a`
      # arg. Same root cause; this case pins the user-set path so a
      # future refactor can't accidentally reintroduce the literal-
      # string regression for the socketPath != null branch.
      name = "launcher-bash-expands-user-socket-path";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.socketPath = "$HOME/.local/state/ssh/pivy-agent.sock";
      };
      check =
        result:
        let
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          # SOCK assignment uses the user-provided path verbatim;
          # bash will expand $HOME at runtime since it's inside
          # double quotes.
          hasSockAssign = lib.hasInfix "SOCK=\"$HOME/.local/state/ssh/pivy-agent.sock\"" text;
          hasExpandedSock = lib.hasInfix "-a \"$SOCK\"" text;
          noSingleQuotedVar = !(lib.hasInfix "'$" text);
        in
        {
          ok = hasSockAssign && hasExpandedSock && noSingleQuotedVar;
          got = {
            inherit
              text
              hasSockAssign
              hasExpandedSock
              noSingleQuotedVar
              ;
          };
        };
    }
    {
      # Per-instance confirm + notifySend route to the right per-
      # instance unit, not to a sibling. Verifies the option is
      # properly threaded through the multi-instance synthesis.
      name = "multi-instance-per-instance-confirm-and-notify-routes-correctly";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.instances = {
          default = {
            guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
            confirm = "/path/default-confirm";
            notifySend = "/path/default-notify";
          };
          work = {
            allCards = true;
            confirm = "/path/work-confirm";
            # No notifySend — verifies per-instance independence.
          };
        };
      };
      check =
        result:
        let
          defaultEnv = getUnitEnv "piggy-agent-default" result;
          workEnv = getUnitEnv "piggy-agent-work" result;
        in
        {
          ok =
            (defaultEnv.SSH_CONFIRM or null) == "/path/default-confirm"
            && (defaultEnv.SSH_NOTIFY_SEND or null) == "/path/default-notify"
            && (workEnv.SSH_CONFIRM or null) == "/path/work-confirm"
            && (workEnv.SSH_NOTIFY_SEND or null) == null;
          got = {
            inherit defaultEnv workEnv;
          };
        };
    }
    {
      # Regression for piggy#64: the Darwin StandardErrorPath default
      # used to be the literal `"$HOME/Library/Logs/<name>.log"`,
      # which fails home-manager's `nullOr (absolute path)` type check
      # (and launchd doesn't expand $HOME in plist contexts anyway).
      # The fix routes the home prefix through `config.home.homeDirectory`
      # so the default is an absolute path. Only meaningful on Darwin —
      # on Linux the launchd.agents attrset is empty by mkIf.
      name = "darwin-default-stderr-path-is-absolute";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
      };
      check =
        result:
        let
          stderrPath = result.config.launchd.agents.piggy-agent.config.StandardErrorPath or null;
          isAbsolute = stderrPath != null && lib.hasPrefix "/" stderrPath;
          noLiteralHome = stderrPath == null || !(lib.hasInfix "$HOME" stderrPath);
        in
        {
          ok =
            if pkgs.stdenv.isDarwin then
              isAbsolute && noLiteralHome
            else
              # On Linux the launchd.agents surface is unpopulated;
              # the regression is unreachable, so pass trivially.
              stderrPath == null;
          got = {
            inherit stderrPath isAbsolute noLiteralHome;
          };
        };
    }
    {
      # piggy#58: with the Rust agent (pname == "piggy") the launcher must
      # invoke the `agent` subcommand and must NOT pass the C-only `-i`
      # (which means print-keys-and-exit on the Rust parser) nor `-S all`
      # (the Rust `-S` takes only a hex slot whitelist; "all" is the
      # default, expressed by omitting `-S`).
      name = "rust-agent-launcher-uses-rust-flags";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = rustPackageStub;
        services.piggy-agent.allCards = true;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          # escapeShellArgs leaves shell-safe args unquoted, so match the
          # bare flags as they appear on the exec line.
          hasAgentSubcmd = lib.hasInfix " agent " text;
          hasAllCards = lib.hasInfix " -A" text;
          noForegroundI = !(lib.hasInfix " -i " text);
          noSlotFilter = !(lib.hasInfix " -S " text);
        in
        {
          ok = tripped == [ ] && hasAgentSubcmd && hasAllCards && noForegroundI && noSlotFilter;
          got = {
            inherit
              tripped
              text
              hasAgentSubcmd
              hasAllCards
              noForegroundI
              noSlotFilter
              ;
          };
        };
    }
    {
      # A hex slot list IS passed to the Rust agent as `-S 9a,9e` (only
      # "all" is omitted).
      name = "rust-agent-passes-hex-slots-as-S";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = rustPackageStub;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.slots = "9a,9e";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          hasSlotFilter = lib.hasInfix "-S 9a,9e" text;
        in
        {
          ok = tripped == [ ] && hasSlotFilter;
          got = {
            inherit tripped text hasSlotFilter;
          };
        };
    }
    {
      # piggy#143: the Rust agent implements CAK (`-K`), so setting `cak`
      # emits `-K <pubkey>` and trips no assertion (the C-only guard is gone).
      name = "rust-agent-with-cak-emits-K";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = rustPackageStub;
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.cak = "ecdsa-sha2-nistp256 AAAATESTKEY";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          # escapeShellArgs single-quotes the cak value (it contains a space).
          hasCak = lib.hasInfix "-K 'ecdsa-sha2-nistp256 AAAATESTKEY'" text;
        in
        {
          ok = tripped == [ ] && hasCak;
          got = {
            inherit tripped text hasCak;
          };
        };
    }
    {
      # The C escape-hatch package (pname == "pivy") keeps the C flag
      # surface: `-i` foreground, `-S all`, and `-K` when a CAK is set.
      name = "c-agent-package-keeps-c-flags";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = pkgs.hello.overrideAttrs (_: {
          pname = "pivy";
        });
        services.piggy-agent.guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
        services.piggy-agent.cak = "ecdsa-sha2-nistp256 AAAATESTKEY";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          hasForegroundI = lib.hasInfix " -i " text;
          hasSlotAll = lib.hasInfix "-S all" text;
          hasCak = lib.hasInfix "-K '" text;
        in
        {
          ok = tripped == [ ] && hasForegroundI && hasSlotAll && hasCak;
          got = {
            inherit
              tripped
              text
              hasForegroundI
              hasSlotAll
              hasCak
              ;
          };
        };
    }
    {
      # piggy#215: upstream proxying options emit the Rust flags. The
      # --upstream fragment keeps its socket path in double quotes (so
      # bash expands $HOME at runtime, same mechanism as -a "$SOCK");
      # --add-new-keys-to and --agent-timeout ride escapeShellArgs.
      name = "rust-agent-upstreams-emit-flags";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = rustPackageStub;
        services.piggy-agent.allCards = true;
        services.piggy-agent.upstreams = [
          {
            name = "soft";
            socketPath = "$HOME/.local/state/ssh/launchd-agent.sock";
          }
        ];
        services.piggy-agent.addNewKeysTo = "soft";
        services.piggy-agent.agentTimeout = 7;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          text = result.config.services.piggy-agent._launcherTexts.piggy-agent or "";
          hasUpstream = lib.hasInfix "--upstream soft=\"$HOME/.local/state/ssh/launchd-agent.sock\"" text;
          hasAddTo = lib.hasInfix "--add-new-keys-to soft" text;
          hasTimeout = lib.hasInfix "--agent-timeout 7" text;
        in
        {
          ok = tripped == [ ] && hasUpstream && hasAddTo && hasTimeout;
          got = {
            inherit
              tripped
              text
              hasUpstream
              hasAddTo
              hasTimeout
              ;
          };
        };
    }
    {
      # piggy#215: the C pivy-agent has no --upstream surface; asking
      # for upstreams with the C escape-hatch package is a config error.
      name = "c-agent-with-upstreams-trips-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = pkgs.hello.overrideAttrs (_: {
          pname = "pivy";
        });
        services.piggy-agent.allCards = true;
        services.piggy-agent.upstreams = [
          {
            name = "soft";
            socketPath = "/tmp/s.sock";
          }
        ];
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "requires the Rust agent" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      # piggy#215: addNewKeysTo must name a configured upstream.
      name = "add-new-keys-to-unknown-upstream-trips-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = rustPackageStub;
        services.piggy-agent.allCards = true;
        services.piggy-agent.upstreams = [
          {
            name = "soft";
            socketPath = "/tmp/s.sock";
          }
        ];
        services.piggy-agent.addNewKeysTo = "nope";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "must name an entry in `upstreams`" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      # piggy#215: duplicate upstream names are a config error.
      name = "duplicate-upstream-names-trip-assertion";
      cfg = {
        services.piggy-agent.enable = true;
        services.piggy-agent.package = rustPackageStub;
        services.piggy-agent.allCards = true;
        services.piggy-agent.upstreams = [
          {
            name = "soft";
            socketPath = "/tmp/a.sock";
          }
          {
            name = "soft";
            socketPath = "/tmp/b.sock";
          }
        ];
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "upstream names must be unique" m) tripped;
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
  summary = "${
    toString (lib.length cases - lib.length failures)
  }/${toString (lib.length cases)} cases passed";
}
