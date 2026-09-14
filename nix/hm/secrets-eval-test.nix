# Smoke-test harness for the `services.piggy-secrets` home-manager module
# (FDR 0003).
#
# Drives `lib.evalModules` against the module with synthetic configs to verify
# the rendered manifest, that no ciphertext or manifest path is a string
# context (closure reference) of anything the generation embeds, the oneshot
# reconcile unit, the non-blocking activation step, and the assertions —
# without a real home-manager, card, or agent.
#
# Use via: `just test-nix-hm-secrets-module`. The recipe evaluates this file
# as JSON; non-empty `failures` make it exit non-zero. Sibling of
# eval-test.nix (the piggy-agent harness).
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  home = "/home/eval-test";

  # Stub the home-manager options the module writes to (plus a free-form
  # `services.piggy-agent` so cases can simulate that module being enabled).
  harness = {
    options = {
      home.homeDirectory = lib.mkOption {
        type = lib.types.str;
        default = home;
      };
      home.activation = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      systemd.user.services = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      services.piggy-agent = lib.mkOption {
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
    };
  };

  # `mkPackageOption pkgs "piggy"` defaults to `pkgs.piggy`, absent from stock
  # nixpkgs; pin a stand-in whose store path is only ever read as a string.
  pinPackage = {
    services.piggy-secrets.package = lib.mkDefault pkgs.hello;
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

  withFiles = extra: {
    services.piggy-secrets = {
      enable = true;
      files.alpha = {
        source = ./secrets-eval-test.nix;
        target = ".config/app/alpha";
      };
    }
    // extra;
  };

  manifestOf = result: builtins.fromJSON result.config.services.piggy-secrets._manifestText;

  unitOf = result: result.config.systemd.user.services.piggy-secrets;
  unitEnv = result: (unitOf result).Service.Environment;
  activationOf = result: result.config.home.activation.piggySecrets;

  # Store paths a string would record as runtime references.
  contextPaths = s: lib.attrNames (builtins.getContext s);
  mentionsSecretsMaterial = s: lib.any (lib.hasInfix "piggy-secrets-") (contextPaths s);

  trippedMessages =
    result: map (a: a.message) (builtins.filter (a: !a.assertion) result.config.assertions);

  # Unit-shape checks only apply where the module emits a systemd unit.
  onLinux = ok: if pkgs.stdenv.isLinux then ok else true;

  cases = [
    {
      name = "manifest-resolves-relative-target-and-applies-defaults";
      cfg = withFiles { };
      check =
        result:
        let
          m = manifestOf result;
          e = builtins.head m.entries;
        in
        {
          ok =
            m.version == 1
            && lib.length m.entries == 1
            && e.name == "alpha"
            && e.target == "${home}/.config/app/alpha"
            && e.mode == "0600"
            && e.adopt == false
            && lib.hasSuffix "-piggy-secrets-alpha.ebox" e.ebox;
          got = m;
        };
    }
    {
      name = "absolute-target-and-adopt-pass-through";
      cfg = {
        services.piggy-secrets = {
          enable = true;
          files.beta = {
            source = ./secrets-eval-test.nix;
            target = "/srv/beta";
            mode = "0640";
            adopt = true;
          };
        };
      };
      check =
        result:
        let
          e = builtins.head (manifestOf result).entries;
        in
        {
          ok = e.target == "/srv/beta" && e.mode == "0640" && e.adopt;
          got = e;
        };
    }
    {
      name = "manifest-store-name-is-prefixed-and-context-free";
      cfg = withFiles { };
      check =
        result:
        let
          path = result.config.services.piggy-secrets.manifestFile;
        in
        {
          ok = lib.hasSuffix "-piggy-secrets-manifest.json" path && contextPaths path == [ ];
          got = path;
        };
    }
    {
      name = "activation-and-unit-carry-no-secrets-material-references";
      cfg = withFiles { };
      check =
        result:
        let
          act = (activationOf result).data;
          execStart = if pkgs.stdenv.isLinux then (unitOf result).Service.ExecStart else "";
        in
        {
          ok =
            lib.hasInfix "piggy-secrets-alpha.ebox" act
            && !(mentionsSecretsMaterial act)
            && !(mentionsSecretsMaterial execStart);
          got = {
            act = contextPaths act;
            exec = contextPaths execStart;
          };
        };
    }
    {
      name = "activation-roots-manifest-and-ciphertext-and-prunes-stale-roots";
      cfg = withFiles { };
      check =
        result:
        let
          act = (activationOf result).data;
        in
        {
          ok =
            lib.hasInfix ''"$piggy_secrets_nix_store" --add-root'' act
            && lib.hasInfix ''"$piggy_secrets_dir/manifest.json"'' act
            && lib.hasInfix ''"$piggy_secrets_dir/gcroots/"alpha.ebox'' act
            && lib.hasInfix "piggy_secrets_keep=(alpha.ebox)" act
            && lib.hasInfix ''rm -f "$piggy_secrets_link"'' act;
          got = act;
        };
    }
    {
      name = "unit-is-a-oneshot-reconcile-without-login-trigger";
      cfg = withFiles { };
      check = result: {
        ok = onLinux (
          (unitOf result).Service.Type == "oneshot"
          && lib.hasSuffix "/bin/piggy secrets reconcile" (unitOf result).Service.ExecStart
          && !((unitOf result) ? Install)
        );
        got = if pkgs.stdenv.isLinux then unitOf result else null;
      };
    }
    {
      name = "agent-socket-follows-enabled-piggy-agent";
      cfg = lib.recursiveUpdate (withFiles { }) {
        services.piggy-agent = {
          enable = true;
          resolvedSocketPath = "${home}/.local/state/piggy/piggy-agent.sock";
        };
      };
      check = result: {
        ok = onLinux (
          lib.elem "PIGGY_AUTH_SOCK=${home}/.local/state/piggy/piggy-agent.sock" (unitEnv result)
        );
        got = if pkgs.stdenv.isLinux then unitEnv result else null;
      };
    }
    {
      name = "no-piggy-agent-means-no-piggy-auth-sock";
      cfg = withFiles { };
      check = result: {
        ok = onLinux (!(lib.any (lib.hasPrefix "PIGGY_AUTH_SOCK=") (unitEnv result)));
        got = if pkgs.stdenv.isLinux then unitEnv result else null;
      };
    }
    {
      name = "askpass-defaults-to-package-helper-forced";
      cfg = withFiles { };
      check = result: {
        ok = onLinux (
          lib.elem "SSH_ASKPASS_REQUIRE=force" (unitEnv result)
          && lib.any (
            v: lib.hasPrefix "SSH_ASKPASS=" v && lib.hasSuffix "/libexec/piggy/piggy-askpass.sh" v
          ) (unitEnv result)
        );
        got = if pkgs.stdenv.isLinux then unitEnv result else null;
      };
    }
    {
      name = "activation-start-checks-then-starts-without-waiting";
      cfg = withFiles { };
      check =
        result:
        let
          act = activationOf result;
        in
        {
          ok =
            lib.elem "writeBoundary" act.after
            && lib.hasInfix "secrets reconcile --check --manifest" act.data
            && lib.hasInfix "|| piggy_secrets_rc=$?" act.data
            && lib.hasInfix "systemctl --user start --no-block piggy-secrets.service" act.data;
          got = act;
        };
    }
    {
      name = "activation-check-never-starts-the-unit";
      cfg = withFiles { onActivation = "check"; };
      check =
        result:
        let
          act = activationOf result;
        in
        {
          ok = lib.hasInfix "--check" act.data && !(lib.hasInfix "systemctl" act.data);
          got = act;
        };
    }
    {
      name = "activation-none-still-roots-but-skips-the-check";
      cfg = withFiles { onActivation = "none"; };
      check =
        result:
        let
          act = activationOf result;
        in
        {
          ok = lib.hasInfix "--add-root" act.data && !(lib.hasInfix "--check" act.data);
          got = act;
        };
    }
    {
      name = "disabled-module-emits-nothing";
      cfg = {
        services.piggy-secrets.files.alpha = {
          source = ./secrets-eval-test.nix;
          target = ".a";
        };
      };
      check = result: {
        ok = result.config.systemd.user.services == { } && result.config.home.activation == { };
        got = {
          inherit (result.config.home) activation;
        };
      };
    }
    {
      name = "assertion-rejects-relative-agent-socket";
      cfg = withFiles { agentSocket = "$HOME/.local/state/piggy/piggy-agent.sock"; };
      check =
        result:
        let
          msgs = trippedMessages result;
        in
        {
          ok = lib.any (lib.hasInfix "`agentSocket` must be an absolute path") msgs;
          got = msgs;
        };
    }
    {
      name = "assertion-rejects-duplicate-targets";
      cfg = lib.recursiveUpdate (withFiles { }) {
        services.piggy-secrets.files.alpha2 = {
          source = ./secrets-eval-test.nix;
          target = "${home}/.config/app/alpha";
        };
      };
      check =
        result:
        let
          msgs = trippedMessages result;
        in
        {
          ok = lib.any (lib.hasInfix "resolve to the same target") msgs;
          got = msgs;
        };
    }
    {
      name = "assertion-rejects-bad-file-name";
      cfg = {
        services.piggy-secrets = {
          enable = true;
          files."bad name" = {
            source = ./secrets-eval-test.nix;
            target = ".bad";
          };
        };
      };
      check =
        result:
        let
          msgs = trippedMessages result;
        in
        {
          ok = lib.any (lib.hasInfix "attribute names must match") msgs;
          got = msgs;
        };
    }
  ];

  results = map (c: {
    inherit (c) name;
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
