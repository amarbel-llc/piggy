# NixOS VM integration lane (pkgs.testers.runNixOSTest).
#
# Boots a NixOS guest carrying the shipped `piggy` package, runs fibby
# and the Rust `piggy agent` as systemd units (./piggy-stack.nix), builds
# a password store against the virtual card, and then uses a store
# secret to unlock real block-level encryption: LUKS2 (./luks.nix) and
# ZFS native encryption (./zfs.nix). It is the harness the Rust
# `piggy luks` / `piggy zfs` ports and the C-pivy retirement are gated
# on (docs/plans/2026-09-14-retire-c-pivy-rust-nix-migration.md), and the
# first end-to-end validation of the closure on a real NixOS system.
#
# KVM is NOT required: host flac has no /dev/kvm (Hetzner cpx42, no
# nested virt) so the guest runs under TCG. `requiredFeatures.kvm =
# false` says so to nix; qemu-common.nix already falls back
# `accel=kvm:tcg`. Expect minutes per run, not seconds.
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

  stack = import ./piggy-stack.nix {
    inherit
      pkgs
      piggy
      fibby
      askpass
      ;
  };

  # Test-level settings shared by every VM test in this directory.
  common = {
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

  # Shared testScript prefix: units up, the seeded 9D key visible through
  # the agent, a store initialised against the card, one generated
  # secret that decrypts through agent -> askpass -> fibby.
  bootstrap = import ./store-bootstrap.nix { inherit askpass; };
in
{
  vm-piggy-luks = pkgs.testers.runNixOSTest (import ./luks.nix { inherit common bootstrap; });
  vm-piggy-zfs = pkgs.testers.runNixOSTest (import ./zfs.nix { inherit common bootstrap; });
}
