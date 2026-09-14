# ZFS native encryption from the piggy store: a store secret is the
# passphrase for an encrypted dataset; unload-key / load-key round-trips
# through `piggy pass show`. Split from luks.nix because this guest
# carries the zfs kernel module (a possible local kernel-module build
# when the igloo pin has no cache hit).
{ bootstrap }:
{ lib, ... }:
{
  name = "piggy-vm-zfs";
  nodes.machine = {
    boot.supportedFilesystems = [ "zfs" ];
    networking.hostId = "8425e349";
    # /dev/disk/by-id is not populated in the test framework (upstream
    # nixos/tests/zfs.nix does the same).
    boot.zfs.devNodes = "/dev/disk/by-uuid";
    boot.zfs.forceImportRoot = false;
    virtualisation.emptyDiskImages = lib.mkForce [ 1024 ];
    # 2 GiB leaves little room once the ARC is live (mkVmChecks' sizing is
    # mkDefault); upstream's zfs test runs the LTS kernel at the module
    # default, which this keeps.
    virtualisation.memorySize = 3072;
  };
  testScript = bootstrap { secretName = "zfs/test"; } + ''
    with subtest("encrypted dataset keyed from the store"):
        machine.succeed("zpool status")
        machine.succeed("zpool create -O mountpoint=none pigpool /dev/vdb")
        n0 = ecdh_count()
        # zfs reads the passphrase as a line from a non-tty stdin.
        machine.succeed(
            ENV + "piggy pass show zfs/test | head -n1 | "
            "zfs create -o encryption=aes-256-gcm -o keyformat=passphrase "
            "-o keylocation=prompt -o mountpoint=/mnt/enc pigpool/enc"
        )
        machine.succeed("zfs get -Ho value keystatus pigpool/enc | grep -Fx available")
        machine.succeed("echo piggy-vm-zfs-marker > /mnt/enc/marker && sync")
        assert ecdh_count() == n0 + 1

    with subtest("unload-key locks the dataset; load-key from the store unlocks it"):
        machine.succeed("zfs unmount pigpool/enc && zfs unload-key pigpool/enc")
        machine.succeed("zfs get -Ho value keystatus pigpool/enc | grep -Fx unavailable")
        machine.fail("zfs mount pigpool/enc")
        machine.fail("echo wrong-passphrase | zfs load-key pigpool/enc")
        machine.succeed(ENV + "piggy pass show zfs/test | head -n1 | zfs load-key pigpool/enc")
        machine.succeed("zfs mount pigpool/enc")
        marker = machine.succeed("cat /mnt/enc/marker").strip()
        assert marker == "piggy-vm-zfs-marker", marker
  '';
}
