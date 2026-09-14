# NixOS VM integration lane (pkgs.testers.runNixOSTest).
#
# Boots a NixOS guest carrying the shipped `piggy` package, runs fibby
# and the Rust `piggy agent` as systemd units (./piggy-stack.nix), builds
# a password store against the virtual card, and then:
#
#   ./luks.nix   unlocks a LUKS2 volume from a store secret
#   ./zfs.nix    keys a ZFS native-encryption dataset from a store secret
#   ./agent.nix  fronts the card agent with a stock ssh-agent upstream and
#                a --proxy-only front (FDR 0001 / piggy#215), logs into a
#                real sshd with both keys, and decrypts over `ssh -A`
#
# It is the harness the Rust `piggy luks` / `piggy zfs` ports and the
# C-pivy retirement are gated on
# (docs/plans/2026-09-14-retire-c-pivy-rust-nix-migration.md), and the
# first end-to-end validation of the closure on a real NixOS system.
#
# KVM is NOT required: host flac has no /dev/kvm (Hetzner cpx42, no
# nested virt) so the guest runs under TCG. `requiredFeatures.kvm =
# false` says so to nix; qemu-common.nix already falls back
# `accel=kvm:tcg`. Measured 2026-09-14: 2-3 minutes per lane.
#
# Linux-only: flake.nix wraps the import in `optionalAttrs isLinux`.
{
  pkgs,
  piggy,
  fibby,
}:
let
  # The bats safety-net askpass, re-homed into the store. writeShellScript
  # supplies its own shebang; the file's `#!/usr/bin/env bash` line
  # becomes a comment.
  askpass = pkgs.writeShellScript "piggy-test-askpass" (
    builtins.readFile ../../zz-tests_bats/helpers/piggy-test-askpass.sh
  );

  # Test-level settings shared by every VM test in this directory; the
  # stack module is parameterised per lane (card seeds, agent flags).
  mkCommon =
    stackArgs:
    let
      stack = import ./piggy-stack.nix (
        {
          inherit
            pkgs
            piggy
            fibby
            askpass
            ;
        }
        // stackArgs
      );
    in
    {
      requiredFeatures.kvm = false;
      # TCG boot of a NixOS guest is minutes; the framework default is
      # already 3600s, restated here so a future bump is a one-line diff.
      globalTimeout = 3600;
      defaults = {
        imports = [ stack ];
        virtualisation.memorySize = 2048;
        virtualisation.cores = 2;
        # /dev/vdb: a real block device for cryptsetup / zpool, without
        # depending on the loop module.
        virtualisation.emptyDiskImages = [ 512 ];
        environment.systemPackages = [
          piggy
          pkgs.cryptsetup
          pkgs.e2fsprogs
          pkgs.openssh
          pkgs.util-linux
        ];
      };
    };

  # Shared testScript prefix: units up, the seeded key(s) visible through
  # the agent, a store initialised against the card, one generated
  # secret that decrypts through agent -> askpass -> fibby.
  bootstrap = import ./store-bootstrap.nix { inherit askpass; };
in
{
  vm-piggy-luks = pkgs.testers.runNixOSTest (
    import ./luks.nix {
      common = mkCommon { };
      inherit bootstrap;
    }
  );
  vm-piggy-zfs = pkgs.testers.runNixOSTest (
    import ./zfs.nix {
      common = mkCommon { };
      inherit bootstrap;
    }
  );
  vm-piggy-agent = pkgs.testers.runNixOSTest (
    import ./agent.nix {
      common = mkCommon {
        # 9A for SSH auth + 9D for the store decrypt, both on one card.
        fibbySeedArgs = [
          "--seed-rfc6979-slot-9a-cert"
          "--seed-rfc5903-slot-9d-cert"
        ];
        # Workstation shape (piggy#215): card-backed agent that also
        # proxies a software ssh-agent and routes ssh-add there.
        agentExtraArgs = [
          "--upstream"
          "soft=/run/upstream/agent.sock"
          "--add-new-keys-to"
          "soft"
        ];
      };
      inherit
        bootstrap
        piggy
        askpass
        ;
    }
  );
}
