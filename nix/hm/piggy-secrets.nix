# home-manager module for `piggy.secrets` — a sops-nix-shaped secret
# manager whose ciphertext is piggy `.ebox` files (PIV-encrypted via
# pivy-box / ebox templates) instead of sops's age/GPG envelopes.
#
# Design (see docs/plans/2026-06-05-piggy-secrets-nix-module.md):
#
#   piggy.secrets.<name> = {
#     eboxFile = ./secrets/db-password.ebox;   # encrypted source
#     mode     = "0400";                        # decrypted-file perms
#     # path defaults to "$XDG_RUNTIME_DIR/piggy-secrets/<name>"
#   };
#
# At `home-manager switch` the module's activation block decrypts every
# `.ebox` into a fresh per-generation directory under
# `$XDG_RUNTIME_DIR/piggy-secrets.d/`, sets the requested mode, then
# atomically flips the stable `$XDG_RUNTIME_DIR/piggy-secrets` symlink to
# the new generation and prunes the old ones — the same atomic-swap shape
# sops-nix uses, so consumers can hard-code the symlink path and never
# observe a half-written secret.
#
# Why home-manager and not a system/NixOS activation: piggy decryption is
# PIV-interactive (needs the YubiKey + PIN, surfaced through the
# piggy-agent / SSH agent socket). A boot-time root activation has no card
# and no agent, so decryption belongs in the user's interactive session
# where the agent lives. The companion `nixosModules.piggy-secrets` is a
# thin re-export that wires this module into `home-manager.sharedModules`,
# exactly like `services.piggy-agent` (OQ4 in the agent module's plan).
#
# Ciphertext-in-the-store is intentional and safe: `eboxFile` is a
# `types.path`, so it is copied into the world-readable nix store — but an
# `.ebox` is encrypted to the recipients' PIV keys, mirroring how sops-nix
# commits encrypted files. Plaintext only ever lands under
# `$XDG_RUNTIME_DIR` (a tmpfs, mode 0700), never in the store.
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

  cfg = config.piggy;

  # `bin/piggy` provides `piggy box stream decrypt`, which reads the ebox
  # on stdin, honors `PIGGY_AUTH_SOCK` (routing the decrypt at piggy-agent,
  # which advertises `ecdh@joyent.com`), and tries the agent oracle first
  # then the local card. mkPackageOption defaults to `pkgs.piggy` and emits
  # the right defaultText; users without piggy in their nixpkgs must set
  # `package = piggy.packages.${system}.piggy` from this flake.
  piggyBin = "${cfg.package}/bin/piggy";

  hasSecrets = cfg.secrets != { };

  # Per-secret bash. `eboxFile` is a store path (safe — it's ciphertext);
  # `name`/`path`/`mode` are user strings routed through `escapeShellArg`
  # so they can't break the exec line. The decrypt itself writes to
  # `$GEN/<name>` inside the freshly-minted generation dir; the symlink
  # flip below makes it reachable at the stable `path`.
  decryptLine =
    secret:
    "piggy_secret_decrypt ${lib.escapeShellArg secret.eboxFile} "
    + "${lib.escapeShellArg secret.name} ${lib.escapeShellArg secret.mode}";

  # Default path a secret is reachable at: `<symlinkPath>/<name>`. When a
  # user overrides `path` to something outside the symlink tree we drop a
  # symlink there pointing back at the canonical location (parity with
  # sops-nix's custom-`path` handling). Secrets left at the default need no
  # extra link — the generation symlink already exposes them.
  defaultPathOf = secret: "${cfg.symlinkPath}/${secret.name}";
  needsLink = secret: secret.path != defaultPathOf secret;
  linkLine =
    secret:
    "piggy_secret_link ${lib.escapeShellArg secret.name} ${lib.escapeShellArg secret.path}";

  secretList = lib.attrValues cfg.secrets;

  # Agent-socket env prelude. Routed via `PIGGY_AUTH_SOCK` so piggy's own
  # decrypt always hits piggy-agent rather than an ssh-agent-mux that may
  # drop `ecdh@joyent.com` (#123). Kept in double quotes (NOT
  # escapeShellArg) so a `$XDG_RUNTIME_DIR` / `$HOME` reference in the
  # configured socket path is bash-expanded at runtime — same lesson as
  # the agent launcher's `-a "$SOCK"` (#63).
  agentEnvLines = lib.optionalString (cfg.agentSocket != null) ''
    export PIGGY_AUTH_SOCK="${cfg.agentSocket}"
  '';

  # Askpass env prelude. `home-manager switch` may run without a usable
  # tty; pinning SSH_ASKPASS (with REQUIRE=force) guarantees a PIN prompt
  # for the local-card fallback renders the configured helper instead of
  # falling through to whatever the OS picks up (#35).
  askpassEnvLines = lib.optionalString (cfg.askpass != null) ''
    export SSH_ASKPASS="${cfg.askpass}"
    export SSH_ASKPASS_REQUIRE=force
  '';

  # The activation script. `$XDG_RUNTIME_DIR` defaults to `/run/user/<uid>`
  # (its standard value) so the module works under activation runners that
  # don't export it. `set -eu` + the ERR trap make a failed decrypt (no
  # card, wrong PIN, missing recipient) abort loudly and leave the old
  # generation's symlink untouched — a stale-but-consistent secret set is
  # safer than a half-written one.
  activationScriptText = ''
    set -eu

    : "''${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
    MOUNT="${cfg.secretsDir}"
    SYMLINK="${cfg.symlinkPath}"
    ${agentEnvLines}${askpassEnvLines}
    mkdir -p -m 0700 "$MOUNT"
    GEN="$(mktemp -d "$MOUNT/gen.XXXXXX")"
    chmod 0700 "$GEN"

    cleanup_failed() { rm -rf "$GEN"; }
    trap cleanup_failed ERR

    piggy_secret_decrypt() {
      # $1 ebox source, $2 secret name, $3 octal mode.
      local ebox="$1" name="$2" mode="$3"
      local out="$GEN/$name"
      mkdir -p "$(dirname "$out")"
      # Plaintext never crosses argv: the ebox is piped on stdin and the
      # cleartext captured from stdout. umask 0077 so the file is private
      # between create and the explicit chmod below.
      ( umask 0077; ${piggyBin} box stream decrypt < "$ebox" > "$out" )
      chmod "$mode" "$out"
    }

    piggy_secret_link() {
      # $1 secret name, $2 user-facing path (outside the symlink tree).
      local name="$1" path="$2"
      mkdir -p "$(dirname "$path")"
      ln -sfn "$SYMLINK/$name" "$path"
    }

    ${lib.concatMapStringsSep "\n" decryptLine secretList}

    # Atomic flip: point the stable symlink at the new generation. `ln
    # -sfn` replaces the symlink in a single rename, so a reader either
    # sees the whole old generation or the whole new one.
    ln -sfn "$GEN" "$SYMLINK"

    ${lib.concatMapStringsSep "\n" linkLine (lib.filter needsLink secretList)}

    # Prune every generation except the one we just published.
    find "$MOUNT" -mindepth 1 -maxdepth 1 -type d ! -path "$GEN" -exec rm -rf {} + 2>/dev/null || true

    trap - ERR
  '';

  activationScript = pkgs.writeShellScript "piggy-secrets-activate" activationScriptText;
in
{
  options.piggy = {
    package = lib.mkPackageOption pkgs "piggy" { };

    secretsDir = mkOption {
      type = types.str;
      default = "$XDG_RUNTIME_DIR/piggy-secrets.d";
      description = ''
        Generation root: the directory under which each activation
        decrypts a fresh `gen.XXXXXX` subdirectory. Lives on a tmpfs
        (`$XDG_RUNTIME_DIR`) so plaintext never touches disk. May contain
        bash-expandable references like `$XDG_RUNTIME_DIR` / `$HOME`; they
        are expanded at activation time.
      '';
    };

    symlinkPath = mkOption {
      type = types.str;
      default = "$XDG_RUNTIME_DIR/piggy-secrets";
      description = ''
        Stable symlink pointing at the current generation directory. This
        is the path consumers should hard-code: `piggy.secrets.<name>` is
        reachable at `''${symlinkPath}/<name>` and the symlink is flipped
        atomically each activation. May contain bash-expandable
        references.
      '';
    };

    agentSocket = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "$XDG_STATE_HOME/piggy/piggy-agent.sock";
      description = ''
        SSH-agent socket to route decrypts through, exported as
        `PIGGY_AUTH_SOCK` for the decrypt child. When `null` (default),
        piggy falls back to the ambient `SSH_AUTH_SOCK`. Point this at a
        {option}`services.piggy-agent` socket so decrypts hit the agent
        that advertises `ecdh@joyent.com` rather than an ssh-agent-mux
        that may drop it (#123). May contain bash-expandable references.
      '';
    };

    askpass = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = lib.literalExpression "\"\${pkgs.piggy}/libexec/piggy/piggy-askpass.sh\"";
      description = ''
        Path to an askpass helper, exported as `SSH_ASKPASS` (with
        `SSH_ASKPASS_REQUIRE=force`) for the decrypt child. Covers the
        local-card fallback's PIN prompt when activation runs without a
        usable tty; without it a missed prompt falls through to whatever
        ssh-client picks up from the OS (#35). When the decrypt is served
        by a piggy-agent the agent owns the prompt and this is unused.
      '';
    };

    secrets = mkOption {
      default = { };
      example = lib.literalExpression ''
        {
          db-password.eboxFile = ./secrets/db-password.ebox;
          api-token = {
            eboxFile = ./secrets/api-token.ebox;
            mode = "0440";
            path = "''${config.home.homeDirectory}/.config/app/token";
          };
        }
      '';
      description = ''
        Secrets to decrypt at `home-manager switch`. Each entry names a
        piggy `.ebox` file; piggy decrypts it (whole-file, the same model
        as `piggy show`) into `$XDG_RUNTIME_DIR` and exposes the plaintext
        at {option}`piggy.secrets.<name>.path`.
      '';
      type = types.attrsOf (
        types.submodule (
          { name, config, ... }:
          {
            options = {
              eboxFile = mkOption {
                type = types.path;
                example = lib.literalExpression "./secrets/db-password.ebox";
                description = ''
                  The encrypted `.ebox` source. Copied into the nix store
                  as ciphertext (safe — an ebox is encrypted to its PIV
                  recipients). Decrypted via `piggy box stream decrypt`.
                '';
              };

              name = mkOption {
                type = types.str;
                default = name;
                defaultText = lib.literalMD "the attribute name";
                description = ''
                  Basename the decrypted secret is published under inside
                  {option}`piggy.symlinkPath`. Defaults to the attribute
                  name; override to decouple the store-relative path from
                  the published name.
                '';
              };

              mode = mkOption {
                type = types.str;
                default = "0400";
                example = "0440";
                description = ''
                  Octal permission bits applied to the decrypted file via
                  `chmod`. Owner is always the activating user (the file
                  lives in that user's `$XDG_RUNTIME_DIR`).
                '';
              };

              path = mkOption {
                type = types.str;
                default = "${cfg.symlinkPath}/${config.name}";
                defaultText = lib.literalExpression "\"\${piggy.symlinkPath}/\${name}\"";
                description = ''
                  Where the decrypted secret is reachable. Defaults to
                  `''${piggy.symlinkPath}/<name>`. Set to a custom path to
                  also publish a symlink there (pointing back at the
                  canonical location), e.g. a dotfile an app reads from a
                  fixed location.
                '';
              };
            };
          }
        )
      );
    };

    _activationScriptText = mkOption {
      type = types.str;
      internal = true;
      visible = false;
      default = "";
      description = ''
        Internal: the rendered activation script text. Exposed for
        `secrets-eval-test.nix` to assert wire-level properties (decrypt
        command shape, atomic symlink flip, PIGGY_AUTH_SOCK threading)
        without a real home-manager. Not part of the user-facing surface.
      '';
    };
  };

  config = mkIf hasSecrets {
    piggy._activationScriptText = activationScriptText;

    # `lib.hm.dag.entryAfter [ "writeBoundary" ] script` produces exactly
    # this `{ data; before; after; }` shape; we build it as a literal so
    # the module evaluates under the bare-lib eval-test harness (which has
    # no `lib.hm`). `writeBoundary` is home-manager's standard marker that
    # divides "linking files into place" from "running activation logic" —
    # decrypting after it means the store paths are already in place.
    home.activation.piggySecrets = {
      after = [ "writeBoundary" ];
      before = [ ];
      data = "${activationScript}";
    };
  };
}
