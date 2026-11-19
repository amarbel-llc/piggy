# NixOS module: `services.piggy-ca`, the issuance unit of FDR 0007 phase
# (iii-a) (piggy#392): the holder-held intermediate key and its
# certificate request.
#
# The unit `piggy-ca.service` runs under its own account and mints its
# own intermediate key at start, from inside its cgroup, under the
# holder scope definition `piggy-ca-intermediate-v1 =
# cgroup:/system.slice/piggy-ca.service` this module adds to
# `services.piggy-holder`. Because FDR 0006 phase (d) lets only a peer
# inside that cgroup mint for it, no session can mint the unit's key, and
# no other peer can sign with it. The unit then writes the request
# `piggy ca csr` signs through the holder agent, and stays up: the key
# lives exactly as long as the unit does. A restart retires the previous
# key (the unit's cgroup may outlive a restart, so the holder's own
# teardown is not relied on) and mints a new one.
#
# The intermediate CERTIFICATE comes from the card (FDR 0007 phase (ii),
# `piggy ca sign`, or openssl under the card-held root during the pilot):
# the operator takes `<stateDir>/intermediate.csr` to the card and installs
# the PEM at `intermediateCertFile`. After any restart the file names the
# previous key, which `piggy health` is to report as "no intermediate"
# until the operator signs again (FDR 0007: a visible re-mint, nothing
# re-blesses silently). Phase (iii-b) adds `issue` with the key.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.piggy-ca;
  holder = config.services.piggy-holder;
  unitCgroup = "/system.slice/piggy-ca.service";
  stateDir = "/var/lib/piggy-ca";
  keyFile = "${stateDir}/intermediate.pub";
  csrFile = "${stateDir}/intermediate.csr";
  # Mint the unit's key, write its request, then hold the cgroup open.
  serve = pkgs.writeShellScript "piggy-ca-serve" ''
    set -euo pipefail
    export SSH_AUTH_SOCK=${holder.socketPath}
    piggy=${cfg.package}/bin/piggy
    # A previous instance's key: the unit's cgroup may outlive a restart,
    # so the holder cannot be relied on to have torn it down; retire it
    # here (this instance is inside the same binding), then mint afresh.
    # A key already gone (the holder restarted) is not an error.
    if [ -s ${keyFile} ]; then
      "$piggy" holder retire ${keyFile} || echo "piggy-ca: the previous key was already gone"
    fi
    rm -f ${keyFile} ${csrFile}
    "$piggy" holder mint --scope ${cfg.scopeName} --type p256 > ${keyFile}.tmp
    mv ${keyFile}.tmp ${keyFile}
    "$piggy" ca csr --key ${keyFile} --cn ${lib.escapeShellArg cfg.commonName} --out ${csrFile}
    echo "piggy-ca: intermediate key minted; request at ${csrFile}; waiting for ${cfg.intermediateCertFile} from the card"
    exec ${pkgs.coreutils}/bin/sleep infinity
  '';
in
{
  options.services.piggy-ca = {
    enable = lib.mkEnableOption "the piggy issuance unit: a holder-held intermediate key and its request (FDR 0007)";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The piggy package providing `piggy holder mint` and `piggy ca csr`.";
    };

    commonName = lib.mkOption {
      type = lib.types.str;
      default = "piggy-ca-intermediate";
      description = "The intermediate profile's CN, the request's one subject attribute.";
    };

    scopeName = lib.mkOption {
      type = lib.types.str;
      default = "piggy-ca-intermediate-v1";
      description = "The holder scope definition the unit mints under (an opaque name).";
    };

    intermediateCertFile = lib.mkOption {
      type = lib.types.str;
      default = "${stateDir}/intermediate.pem";
      description = ''
        Where the operator installs the card-signed intermediate certificate
        for the current key. Nothing in piggy fetches it; after a restart it
        names the previous key until replaced.
      '';
    };

    requestFile = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = csrFile;
      description = "Where the unit writes the request for its current key.";
    };

    keyFile = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = keyFile;
      description = "The current intermediate key's OpenSSH public key line.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = holder.enable;
        message = "services.piggy-ca needs services.piggy-holder: the intermediate key lives in the holder";
      }
    ];

    # The unit-bound scope: only a peer inside the unit's own cgroup may
    # mint under it, sign with the key, or retire it.
    services.piggy-holder.scopes.${cfg.scopeName} = "cgroup:${unitCgroup}";

    users.groups.piggy-ca = { };
    users.users.piggy-ca = {
      isSystemUser = true;
      group = "piggy-ca";
      # Reaches the holder agent's socket.
      extraGroups = [ holder.clientGroup ];
      description = "piggy issuance unit (FDR 0007)";
    };

    systemd.services.piggy-ca = {
      description = "piggy issuance unit: holder-held intermediate key and request (FDR 0007)";
      wantedBy = [ "multi-user.target" ];
      requires = [ "piggy-holder.service" ];
      after = [ "piggy-holder.service" ];
      serviceConfig = {
        Type = "simple";
        User = "piggy-ca";
        Group = "piggy-ca";
        StateDirectory = "piggy-ca";
        StateDirectoryMode = "0750";
        ExecStart = serve;
        Restart = "on-failure";
        RestartSec = 2;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        LimitCORE = 0;
      };
    };
  };
}
