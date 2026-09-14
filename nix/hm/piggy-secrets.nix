# home-manager module for `services.piggy-secrets`: declarative ebox-backed
# secret files, reconciled by `piggy secrets reconcile` (FDR 0003,
# docs/features/0003-declarative-ebox-secret-reconcile.md).
#
#   services.piggy-secrets = {
#     enable = true;
#     files.smith-keys = {
#       source = ./piggy-store/rcm/local/share/smith/keys.json.ebox;
#       target = ".local/share/smith/keys.json";
#     };
#   };
#
# The module copies each ebox into the nix store, renders a JSON manifest
# (ciphertext store paths + targets), and declares a oneshot systemd user unit
# that runs the reconcile. It never decrypts during `home-manager switch`: the
# activation step runs only the offline `--check` and, when something needs
# reconciling, starts the unit without waiting, so a locked or absent card can
# neither block nor fail a switch. Outputs are plain files tracked by the
# reconcile's own state file (never store symlinks), and nothing here ever
# deletes one.
#
# Out-of-closure secrets material: the ciphertext copies and the manifest are
# referenced WITHOUT string context, so they are not store references of the
# home generation and `nix copy` of the generation never carries them (a
# binary-cache uploader can exclude them by their `piggy-secrets-` name). They
# are added to the local store at evaluation time, and the activation step
# keeps them alive with per-user GC roots under
# `$XDG_STATE_HOME/piggy/secrets/`. Consequence: the generation must be
# evaluated on the host it activates on.
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

  cfg = config.services.piggy-secrets;
  piggyBin = "${cfg.package}/bin/piggy";

  # Name prefix of every store path this module creates.
  storeNamePrefix = "piggy-secrets-";

  absoluteTarget =
    target: if lib.hasPrefix "/" target then target else "${config.home.homeDirectory}/${target}";

  # Follow services.piggy-agent's socket when that module is enabled, so the
  # agent-fallback decrypt reaches the agent that advertises ecdh@joyent.com
  # (on a proxy-only host, the stable front to the forwarded card).
  agentCfg = config.services.piggy-agent or { };
  defaultAgentSocket = if agentCfg.enable or false then agentCfg.resolvedSocketPath or null else null;

  # `builtins.path` adds the file to the store at evaluation time; discarding
  # the context keeps the path a plain string, so nothing that embeds it
  # records it as a runtime reference.
  cipherPathOf =
    name: file:
    builtins.unsafeDiscardStringContext "${builtins.path {
      path = file.source;
      name = "${storeNamePrefix}${name}.ebox";
    }}";

  cipherPaths = lib.mapAttrs cipherPathOf cfg.files;

  manifestText = builtins.toJSON {
    version = 1;
    entries = lib.mapAttrsToList (name: file: {
      inherit name;
      ebox = cipherPaths.${name};
      target = absoluteTarget file.target;
      inherit (file) mode adopt;
    }) cfg.files;
  };

  manifestPath = builtins.unsafeDiscardStringContext (
    builtins.toFile "${storeNamePrefix}manifest.json" manifestText
  );

  # systemd `Environment=` does no shell expansion, hence the absolute-path
  # assertion on agentSocket below.
  unitEnvironment =
    lib.optional (cfg.agentSocket != null) "PIGGY_AUTH_SOCK=${cfg.agentSocket}"
    ++ lib.optionals (cfg.askpass != null) [
      "SSH_ASKPASS=${cfg.askpass}"
      "SSH_ASKPASS_REQUIRE=force"
    ];

  rootNames = lib.mapAttrsToList (name: _: "${name}.ebox") cfg.files;

  rootLines = lib.concatStringsSep "\n" (
    [
      ''piggy_secrets_root ${lib.escapeShellArg manifestPath} "$piggy_secrets_dir/manifest.json"''
    ]
    ++ lib.mapAttrsToList (
      name: path:
      ''piggy_secrets_root ${lib.escapeShellArg path} "$piggy_secrets_dir/gcroots/"${lib.escapeShellArg "${name}.ebox"}''
    ) cipherPaths
  );

  needsReconcileAction =
    if cfg.onActivation == "start" then
      ''
        if [[ -n "''${DRY_RUN:-}" ]]; then
          echo "piggy-secrets: secret files need reconciling; would start piggy-secrets.service"
        elif command -v systemctl >/dev/null 2>&1 \
          && systemctl --user start --no-block piggy-secrets.service; then
          echo "piggy-secrets: secret files need reconciling; started piggy-secrets.service"
        else
          echo "piggy-secrets: secret files need reconciling; run: piggy secrets reconcile"
        fi
      ''
    else
      ''
        echo "piggy-secrets: secret files need reconciling; run: piggy secrets reconcile"
      '';

  checkText = ''
    piggy_secrets_rc=0
    ${piggyBin} secrets reconcile --check --manifest ${lib.escapeShellArg manifestPath} >/dev/null 2>&1 \
      || piggy_secrets_rc=$?
    case "$piggy_secrets_rc" in
      0) ;;
      1)
        ${needsReconcileAction}
        ;;
      *)
        echo "piggy-secrets: manifest check failed (exit $piggy_secrets_rc); run: piggy secrets reconcile --check"
        ;;
    esac
  '';

  # Never fails and never blocks: rooting and the offline `--check` catch
  # every exit status, and the unit start is --no-block.
  activationText = ''
    piggy_secrets_dir="''${XDG_STATE_HOME:-$HOME/.local/state}/piggy/secrets"
    if [[ -z "''${DRY_RUN:-}" ]]; then
      # Prefer the host's nix-store (matching its daemon); fall back to nixpkgs'.
      piggy_secrets_nix_store="$(command -v nix-store 2>/dev/null || echo ${lib.getBin pkgs.nix}/bin/nix-store)"
      if mkdir -p -m 0700 "$piggy_secrets_dir/gcroots"; then
        piggy_secrets_root() {
          if ! "$piggy_secrets_nix_store" --add-root "$2" --realise "$1" >/dev/null 2>&1; then
            echo "piggy-secrets: cannot root $1 (not in this host's store? evaluate the generation on this host)"
          fi
        }
        ${rootLines}
        piggy_secrets_keep=(${lib.escapeShellArgs rootNames})
        for piggy_secrets_link in "$piggy_secrets_dir"/gcroots/*; do
          if [[ ! -L "$piggy_secrets_link" ]]; then
            continue
          fi
          piggy_secrets_keep_it=0
          for piggy_secrets_name in "''${piggy_secrets_keep[@]}"; do
            if [[ "''${piggy_secrets_link##*/}" == "$piggy_secrets_name" ]]; then
              piggy_secrets_keep_it=1
            fi
          done
          if [[ "$piggy_secrets_keep_it" == 0 ]]; then
            rm -f "$piggy_secrets_link"
          fi
        done
      else
        echo "piggy-secrets: cannot create $piggy_secrets_dir/gcroots; secrets material is not GC-rooted"
      fi
    fi
    ${lib.optionalString (cfg.onActivation != "none") checkText}
  '';

  fileType = types.submodule {
    options = {
      source = mkOption {
        type = types.path;
        example = lib.literalExpression "./piggy-store/rcm/local/share/smith/keys.json.ebox";
        description = ''
          The encrypted `.ebox`. Copied into the nix store as ciphertext under
          the name `piggy-secrets-<name>.ebox`, outside the home generation's
          closure. Plaintext never enters the store.
        '';
      };
      target = mkOption {
        type = types.str;
        example = ".local/share/smith/keys.json";
        description = ''
          Where the decrypted file is written: an absolute path, or a path
          relative to the home directory. A plain file, not a symlink.
        '';
      };
      mode = mkOption {
        type = types.strMatching "0?[0-7]{3}";
        default = "0600";
        description = "Octal permission bits of the written file.";
      };
      adopt = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Let the reconcile replace a target that exists but is not recorded
          as piggy-managed (e.g. left by rcm or a bootstrap script). Without
          it such a target is reported as a conflict and left alone. Has no
          effect once the target is recorded, so it can stay set.
        '';
      };
    };
  };
in
{
  options.services.piggy-secrets = {
    enable = lib.mkEnableOption "ebox-backed secret files reconciled by `piggy secrets reconcile`";

    package = lib.mkPackageOption pkgs "piggy" { };

    files = mkOption {
      type = types.attrsOf fileType;
      default = { };
      example = lib.literalExpression ''
        {
          smith-keys = {
            source = ./piggy-store/rcm/local/share/smith/keys.json.ebox;
            target = ".local/share/smith/keys.json";
          };
        }
      '';
      description = ''
        Secret files to keep reconciled. Attribute names must match
        `[A-Za-z0-9._-]+`; they name the TAP points, the ciphertext store
        paths, and their GC roots.
      '';
    };

    agentSocket = mkOption {
      type = types.nullOr types.str;
      default = defaultAgentSocket;
      defaultText = lib.literalExpression ''
        if config.services.piggy-agent.enable
        then config.services.piggy-agent.resolvedSocketPath
        else null
      '';
      description = ''
        Absolute path of the agent socket exported to the reconcile unit as
        `PIGGY_AUTH_SOCK`, used when no local card serves the batch. `null`
        leaves the unit to the ambient `SSH_AUTH_SOCK`.
      '';
    };

    askpass = mkOption {
      type = types.nullOr types.str;
      default = "${cfg.package}/libexec/piggy/piggy-askpass.sh";
      defaultText = lib.literalExpression ''"''${config.services.piggy-secrets.package}/libexec/piggy/piggy-askpass.sh"'';
      description = ''
        Askpass helper for the batch PIN prompt, exported to the reconcile
        unit as `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`.
      '';
    };

    onActivation = mkOption {
      type = types.enum [
        "start"
        "check"
        "none"
      ];
      default = "start";
      description = ''
        What `home-manager switch` does after installing the manifest.
        `start`: run the offline check and, if anything needs reconciling,
        start `piggy-secrets.service` without waiting. `check`: only print the
        hint. `none`: nothing. No choice decrypts during the switch or can
        fail it.
      '';
    };

    storeNamePrefix = mkOption {
      type = types.str;
      default = storeNamePrefix;
      readOnly = true;
      description = ''
        Name prefix (the part after `<hash>-`) of every store path this module
        creates: `piggy-secrets-<name>.ebox` and `piggy-secrets-manifest.json`.
        Stable; a binary-cache uploader may exclude on it.
      '';
    };

    manifestFile = mkOption {
      type = types.nullOr types.str;
      default = if cfg.enable then manifestPath else null;
      defaultText = lib.literalMD "the rendered manifest's store path when enabled, else `null`";
      readOnly = true;
      description = ''
        Store path of the rendered manifest, as a context-free string (null
        when the module is disabled). Referencing it does not pull it into a
        closure.
      '';
    };

    _manifestText = mkOption {
      type = types.str;
      internal = true;
      visible = false;
      default = "";
      description = ''
        Internal: the rendered manifest JSON, exposed for
        `secrets-eval-test.nix`. Not part of the user-facing surface.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (n: builtins.match "[A-Za-z0-9._-]+" n != null) (lib.attrNames cfg.files);
        message = "services.piggy-secrets: `files` attribute names must match [A-Za-z0-9._-]+.";
      }
      {
        assertion = cfg.agentSocket == null || lib.hasPrefix "/" cfg.agentSocket;
        message = "services.piggy-secrets: `agentSocket` must be an absolute path (systemd does not expand $HOME-style references).";
      }
      {
        assertion =
          let
            targets = lib.mapAttrsToList (_: f: absoluteTarget f.target) cfg.files;
          in
          lib.length (lib.unique targets) == lib.length targets;
        message = "services.piggy-secrets: two `files` entries resolve to the same target.";
      }
    ];

    services.piggy-secrets._manifestText = manifestText;

    systemd.user.services = mkIf pkgs.stdenv.isLinux {
      piggy-secrets = {
        Unit = {
          Description = "Reconcile piggy ebox-backed secret files";
          Documentation = "https://code.linenisgreat.com/piggy";
        };
        Service = {
          Type = "oneshot";
          # No --manifest: the default is the GC-rooted
          # $XDG_STATE_HOME/piggy/secrets/manifest.json the activation keeps.
          ExecStart = "${piggyBin} secrets reconcile";
          Environment = unitEnvironment;
        };
      };
    };

    # Built as a `{ data; before; after; }` literal (the shape
    # `lib.hm.dag.entryAfter` produces) so the module also evaluates under
    # the bare-lib eval-test harness, which has no `lib.hm`. `reloadSystemd`
    # ordering makes the unit start see this generation's unit definition.
    home.activation.piggySecrets = {
      after = [ "writeBoundary" ] ++ lib.optional pkgs.stdenv.isLinux "reloadSystemd";
      before = [ ];
      data = activationText;
    };
  };
}
