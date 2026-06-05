# Smoke-test harness for the `piggy.secrets` home-manager module.
#
# Drives `lib.evalModules` against the module with synthetic configs to
# verify the option schema and the rendered activation script — the
# decrypt-command shape, the atomic symlink flip, custom-path linking,
# and the PIGGY_AUTH_SOCK / SSH_ASKPASS threading — without needing a real
# home-manager, a PIV card, or a piggy-agent.
#
# Use via: `just test-nix-hm-secrets-module`. The recipe imports this file
# and evaluates `result` as JSON; non-empty `failures` cause it to exit
# non-zero.
#
# Sibling to eval-test.nix (the piggy-agent harness); kept alongside the
# module in nix/hm/ for the same reasons.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  # Stub home-manager-shaped option set. The piggy-secrets module needs
  # `home.activation` declared somewhere; in a real home-manager
  # invocation hm declares it (as a `hm.types.dagOf`). The module builds
  # the dag entry as a plain `{ data; before; after; }` literal precisely
  # so this bare-`attrs` stub accepts it without `lib.hm`.
  harness = {
    options = {
      home.activation = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      home.homeDirectory = lib.mkOption {
        type = lib.types.str;
        default = "/home/eval-test";
      };
    };
  };

  # `mkPackageOption pkgs "piggy"` defaults to `pkgs.piggy`, absent from
  # stock nixpkgs. Pin `package` to `pkgs.hello` so the default's thrown
  # error doesn't fire when the activation derivation is forced. The
  # script's `${package}/bin/piggy` becomes hello's store path — only the
  # path string matters here, never realized.
  pinPackage = {
    piggy.package = lib.mkDefault pkgs.hello;
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

  # Force the activation derivation through nix's laziness so a bug that
  # only surfaces when home-manager realizes it (a bad interpolation, a
  # malformed writeShellScript) is caught here. Reading `.data` drives the
  # writeShellScript through.
  forceActivation = result: result.config.home.activation.piggySecrets.data or null;

  scriptText = result: result.config.piggy._activationScriptText or "";

  cases = [
    {
      # A single default secret evaluates cleanly, produces an activation
      # entry sequenced after writeBoundary, and the script carries the
      # decrypt command + the atomic symlink flip.
      name = "single-secret-evaluates-and-renders-decrypt";
      cfg = {
        piggy.secrets.db-password.eboxFile = ./secrets-eval-test.nix;
      };
      check =
        result:
        let
          act = forceActivation result;
          after = result.config.home.activation.piggySecrets.after or [ ];
          text = scriptText result;
        in
        {
          ok =
            act != null
            && after == [ "writeBoundary" ]
            && lib.hasInfix "box stream decrypt" text
            && lib.hasInfix "piggy_secret_decrypt" text
            && lib.hasInfix "db-password" text
            && lib.hasInfix "ln -sfn \"$GEN\" \"$SYMLINK\"" text;
          got = {
            inherit after text;
            hasAct = act != null;
          };
        };
    }
    {
      # No secrets => no activation entry at all (hasSecrets gate).
      name = "no-secrets-emits-no-activation";
      cfg = { };
      check =
        result:
        let
          act = result.config.home.activation.piggySecrets or null;
        in
        {
          ok = act == null;
          got = {
            inherit act;
          };
        };
    }
    {
      # A secret left at the default path needs no custom-link line.
      name = "default-path-secret-has-no-link-line";
      cfg = {
        piggy.secrets.token.eboxFile = ./secrets-eval-test.nix;
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok = !(lib.hasInfix "piggy_secret_link" text);
          got = {
            inherit text;
          };
        };
    }
    {
      # A secret with a custom path emits a `piggy_secret_link` line that
      # publishes a symlink at the requested path.
      name = "custom-path-secret-emits-link-line";
      cfg = {
        piggy.secrets.token = {
          eboxFile = ./secrets-eval-test.nix;
          path = "/home/eval-test/.config/app/token";
        };
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok =
            lib.hasInfix "piggy_secret_link" text
            && lib.hasInfix "/home/eval-test/.config/app/token" text;
          got = {
            inherit text;
          };
        };
    }
    {
      # The per-secret `mode` is threaded into the decrypt invocation.
      name = "mode-is-threaded-into-decrypt-line";
      cfg = {
        piggy.secrets.token = {
          eboxFile = ./secrets-eval-test.nix;
          mode = "0440";
        };
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok = lib.hasInfix "0440" text;
          got = {
            inherit text;
          };
        };
    }
    {
      # A custom `name` publishes the secret under that basename rather
      # than the attribute key.
      name = "custom-name-changes-published-basename";
      cfg = {
        piggy.secrets.token = {
          eboxFile = ./secrets-eval-test.nix;
          name = "renamed-token";
        };
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok = lib.hasInfix "renamed-token" text;
          got = {
            inherit text;
          };
        };
    }
    {
      # `agentSocket` exports PIGGY_AUTH_SOCK, bash-expandable (NOT
      # single-quoted), so a `$XDG_STATE_HOME` reference resolves at
      # runtime — the #63 lesson.
      name = "agent-socket-exports-bash-expandable-piggy-auth-sock";
      cfg = {
        piggy.agentSocket = "$XDG_STATE_HOME/piggy/piggy-agent.sock";
        piggy.secrets.token.eboxFile = ./secrets-eval-test.nix;
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok =
            lib.hasInfix "export PIGGY_AUTH_SOCK=\"$XDG_STATE_HOME/piggy/piggy-agent.sock\"" text
            && !(lib.hasInfix "'$XDG_STATE_HOME" text);
          got = {
            inherit text;
          };
        };
    }
    {
      # No `agentSocket` => no PIGGY_AUTH_SOCK export (decrypt inherits the
      # ambient SSH_AUTH_SOCK).
      name = "no-agent-socket-skips-piggy-auth-sock";
      cfg = {
        piggy.secrets.token.eboxFile = ./secrets-eval-test.nix;
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok = !(lib.hasInfix "PIGGY_AUTH_SOCK" text);
          got = {
            inherit text;
          };
        };
    }
    {
      # `askpass` exports SSH_ASKPASS with REQUIRE=force for the local-card
      # PIN fallback.
      name = "askpass-exports-ssh-askpass-force";
      cfg = {
        piggy.askpass = "/run/current-system/sw/libexec/piggy/piggy-askpass.sh";
        piggy.secrets.token.eboxFile = ./secrets-eval-test.nix;
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok =
            lib.hasInfix "export SSH_ASKPASS=\"/run/current-system/sw/libexec/piggy/piggy-askpass.sh\"" text
            && lib.hasInfix "export SSH_ASKPASS_REQUIRE=force" text;
          got = {
            inherit text;
          };
        };
    }
    {
      # Multiple secrets each get their own decrypt line.
      name = "multiple-secrets-each-decrypted";
      cfg = {
        piggy.secrets = {
          alpha.eboxFile = ./secrets-eval-test.nix;
          beta.eboxFile = ./secrets-eval-test.nix;
        };
      };
      check =
        result:
        let
          text = scriptText result;
        in
        {
          ok = lib.hasInfix "alpha" text && lib.hasInfix "beta" text;
          got = {
            inherit text;
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
