# NixOS module: `services.piggy-holder`, FDR 0006 tier 2 (phase (d),
# piggy#383 item 5). Two hardened system units under two accounts:
#
#   fibby-holder.service   the fibby holder build, which holds every minted
#                          key in guarded memory; its PC/SC and control
#                          sockets live in /run/fibby-holder, a directory
#                          only the holder agent's account can enter
#   piggy-holder.service   `piggy agent --holder`, the only account on
#                          fibby's sockets; serves mint@piggy and
#                          retire@piggy on /run/piggy-holder/agent.sock to
#                          the members of `clientGroup`
#
# This is a native module, not a home-manager re-export like
# nix/nixos/piggy-agent.nix: the holder is a system service by design (a
# session must not be able to reach its own key store directly, and the
# caller binding is in systemd's cgroup tree). piggy-agent(1) HOLDER MODE
# describes what the units do; FDR 0006 "The holder service" what they
# must not be able to do.
#
# Caller binding reads other users' /proc/<pid>/cgroup, so the agent unit
# keeps the default ProtectProc; a host that mounts /proc with hidepid
# breaks every mint (the holder answers peer-unknown).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.piggy-holder;
  fibbyDir = "/run/fibby-holder";
  fibbySock = "${fibbyDir}/pcscd.comm";
  fibbyCtl = "${fibbyDir}/ctl.sock";
  agentDir = "/run/piggy-holder";
  agentSock = "${agentDir}/agent.sock";

  # What both units share: no privilege, no devices, no network, no core
  # file, a read-only system view, and the memory-locking calls the
  # guarded allocations need (`@memlock` is inside `@system-service`).
  hardening = {
    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateDevices = true;
    PrivateTmp = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectControlGroups = true;
    RestrictAddressFamilies = [ "AF_UNIX" ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    # `@resources` stays allowed: both binaries set their own
    # RLIMIT_CORE to zero at start (piggy-guard's process hardening).
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
    ];
    LimitCORE = 0;
    # Guarded pages per secret: 16 cards times a handful of secrets, the
    # attestation key, the agent's PINs. Generous, so a lock never fails.
    LimitMEMLOCK = toString cfg.memlockBytes;
    Restart = "on-failure";
    RestartSec = 2;
  };
in
{
  options.services.piggy-holder = {
    enable = lib.mkEnableOption "the piggy key holder (FDR 0006 tier 2): fibby plus a holder agent";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The piggy package providing `piggy agent --holder`.";
    };

    fibbyPackage = lib.mkOption {
      type = lib.types.package;
      description = ''
        The fibby HOLDER build (`fibby --build-profile` prints `holder`;
        piggy's `.#fibby-holder` output). The test double is refused at
        start.
      '';
    };

    scopes = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        piggy-mint-v1 = "caller";
        piggy-ca-intermediate-v1 = "cgroup:/system.slice/piggy-ca.service";
      };
      description = ''
        Scope definitions, one `--scope NAME=RULE` each: what a mint naming
        NAME binds to. RULE is `caller` (the calling connection's own
        cgroup) or `cgroup:/absolute/path`. Without any, every mint is
        refused unknown-scope.
      '';
    };

    model = lib.mkOption {
      type = lib.types.str;
      default = "yk5.7";
      description = "The fibby card model; yk5.7 is the one that mints Ed25519.";
    };

    clientGroup = lib.mkOption {
      type = lib.types.str;
      default = "users";
      description = ''
        The group whose members may reach the holder agent's socket. The
        socket directory is 0750 and the socket 0770, owned by the agent
        and this group. Anyone who can connect may mint for their own
        scope; the per-key binding does the rest.
      '';
    };

    cgroupRoot = lib.mkOption {
      type = lib.types.str;
      default = "/sys/fs/cgroup";
      description = "Where cgroup2 is mounted (`--cgroup-root`).";
    };

    scopePollInterval = lib.mkOption {
      type = lib.types.ints.positive;
      default = 2;
      description = "Seconds between checks that every bound cgroup still exists.";
    };

    memlockBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 64 * 1024 * 1024;
      description = "RLIMIT_MEMLOCK for both units, sized for the 16-card cap.";
    };

    extraAgentArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Further `piggy agent` flags for the holder unit.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = agentSock;
      description = "Where the holder agent listens; clients set SSH_AUTH_SOCK to it.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.fibby-holder = { };
    users.users.fibby-holder = {
      isSystemUser = true;
      group = "fibby-holder";
      description = "fibby key holder (FDR 0006)";
    };
    users.groups.piggy-holder = { };
    users.users.piggy-holder = {
      isSystemUser = true;
      group = "piggy-holder";
      # The one account allowed into fibby's socket directory.
      extraGroups = [ "fibby-holder" ];
      description = "piggy holder agent (FDR 0006)";
    };

    systemd.services.fibby-holder = {
      description = "fibby key holder: minted keys in guarded memory (FDR 0006)";
      wantedBy = [ "multi-user.target" ];
      # The holder build is the design: refuse the test double before it
      # serves a single key.
      preStart = ''
        profile="$(${cfg.fibbyPackage}/bin/fibby --build-profile)"
        if [ "$profile" != holder ]; then
          echo "fibby-holder: refusing to start the '$profile' build; services.piggy-holder.fibbyPackage must be the holder build" >&2
          exit 1
        fi
      '';
      serviceConfig = hardening // {
        Type = "simple";
        User = "fibby-holder";
        Group = "fibby-holder";
        RuntimeDirectory = "fibby-holder";
        RuntimeDirectoryMode = "0750";
        UMask = "0077";
        # Keys never go to swap, and nothing is dumped.
        MemorySwapMax = "0";
        ExecStart = lib.concatStringsSep " " [
          "${cfg.fibbyPackage}/bin/fibby"
          "--socket"
          fibbySock
          "--control-socket"
          fibbyCtl
          "--model"
          cfg.model
        ];
        Environment = [ "FIBBY_LOG=info" ];
      };
    };

    systemd.services.piggy-holder = {
      description = "piggy holder agent: mint@piggy and retire@piggy over fibby (FDR 0006)";
      wantedBy = [ "multi-user.target" ];
      requires = [ "fibby-holder.service" ];
      after = [ "fibby-holder.service" ];
      serviceConfig = hardening // {
        Type = "simple";
        User = "piggy-holder";
        # The socket directory is owned by the agent and the client group,
        # 0750; with this umask the socket itself is 0770.
        Group = cfg.clientGroup;
        SupplementaryGroups = [ "fibby-holder" ];
        RuntimeDirectory = "piggy-holder";
        RuntimeDirectoryMode = "0750";
        UMask = "0007";
        ExecStart = lib.concatStringsSep " " (
          [
            "${cfg.package}/bin/piggy"
            "agent"
            "--holder"
            "--holder-fibby-ctl"
            fibbyCtl
            "--cgroup-root"
            cfg.cgroupRoot
            "--scope-poll-interval"
            (toString cfg.scopePollInterval)
            "-a"
            agentSock
            "--service-name"
            "piggy-holder.service"
          ]
          ++ lib.concatMap (name: [
            "--scope"
            "${name}=${cfg.scopes.${name}}"
          ]) (lib.attrNames cfg.scopes)
          ++ cfg.extraAgentArgs
        );
        Environment = [
          "PCSCLITE_CSOCK_NAME=${fibbySock}"
          "HOME=${agentDir}"
          "XDG_CACHE_HOME=${agentDir}/cache"
        ];
      };
    };
  };
}
