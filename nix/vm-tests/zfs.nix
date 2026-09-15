# ZFS native encryption from the piggy store via `piggy zfs` (piggy#279):
# a store secret is the passphrase for an encrypted dataset created and
# re-keyed through the command; the unload-key half and the wrong-
# passphrase check stay on stock zfs to prove it is an ordinary encrypted
# dataset. Split from luks.nix because this guest carries the zfs kernel
# module (a possible local kernel-module build when the igloo pin has no
# cache hit).
{ bootstrap }:
{ lib, ... }:
{
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
    ZFS = ENV + "piggy zfs"

    with subtest("piggy zfs create: encrypted dataset keyed from the store"):
        machine.succeed("zpool status")
        machine.succeed("zpool create -O mountpoint=none pigpool /dev/vdb")
        n0 = ecdh_count()
        machine.succeed(f"{ZFS} create pigpool/enc --secret zfs/test -- -o mountpoint=/mnt/enc")
        machine.succeed("zfs get -Ho value keystatus pigpool/enc | grep -Fx available")
        machine.succeed("zfs get -Ho value encryption pigpool/enc | grep -Fx aes-256-gcm")
        machine.succeed("echo piggy-vm-zfs-marker > /mnt/enc/marker && sync")
        expect_ecdh(n0 + 1)

    with subtest("unload-key locks the dataset; piggy zfs load-key unlocks it"):
        machine.succeed("zfs unmount pigpool/enc && zfs unload-key pigpool/enc")
        machine.succeed("zfs get -Ho value keystatus pigpool/enc | grep -Fx unavailable")
        machine.fail("zfs mount pigpool/enc")
        machine.fail("echo wrong-passphrase | zfs load-key pigpool/enc")
        n0 = ecdh_count()
        machine.succeed(f"{ZFS} load-key pigpool/enc --secret zfs/test")
        expect_ecdh(n0 + 1)
        machine.succeed("zfs mount pigpool/enc")
        marker = machine.succeed("cat /mnt/enc/marker").strip()
        assert marker == "piggy-vm-zfs-marker", marker

    with subtest("a missing store entry fails before zfs runs"):
        machine.succeed("zfs unmount pigpool/enc && zfs unload-key pigpool/enc")
        machine.fail(f"{ZFS} load-key pigpool/enc --secret zfs/does-not-exist")
        machine.succeed("zfs get -Ho value keystatus pigpool/enc | grep -Fx unavailable")
  '';
}
