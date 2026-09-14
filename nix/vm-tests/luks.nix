# LUKS2 from the piggy store: a secret sealed to the fibby card formats,
# opens, and re-opens a LUKS2 volume; a second passphrase keyslot is
# enrolled alongside it (the FDR 0003 shape: token slot + passphrase).
{ common, bootstrap }:
{ ... }:
{
  name = "piggy-vm-luks";
  inherit (common) requiredFeatures globalTimeout defaults;
  nodes.machine = { };
  testScript = bootstrap "luks/test" + ''
    DEV = "/dev/vdb"
    # argon2id benchmarks itself to ~1 GiB / seconds per op, which is
    # hostile under TCG; pbkdf2 with a fixed low count keeps the test
    # about key plumbing, not KDF cost (upstream luks.nix does the same
    # with --iter-time=1).
    KDF = "--pbkdf pbkdf2 --pbkdf-force-iterations 1000"

    with subtest("luksFormat + open from the store secret"):
        n0 = ecdh_count()
        machine.succeed(f"{show('luks/test')} | cryptsetup luksFormat --type luks2 -q {KDF} --key-file - {DEV}")
        machine.succeed(f"{show('luks/test')} | cryptsetup open --key-file - {DEV} pigcrypt")
        machine.wait_for_file("/dev/mapper/pigcrypt")
        machine.succeed("mkfs.ext4 -q /dev/mapper/pigcrypt")
        machine.succeed("mkdir -p /mnt/pig && mount /dev/mapper/pigcrypt /mnt/pig")
        machine.succeed("echo piggy-vm-luks-marker > /mnt/pig/marker && sync")
        machine.succeed("umount /mnt/pig && cryptsetup close pigcrypt")
        machine.wait_until_fails("test -e /dev/mapper/pigcrypt")
        assert ecdh_count() == n0 + 2, "format+open should have cost exactly two card ECDH ops"

    with subtest("reopen from the store and read the marker back"):
        machine.succeed(f"{show('luks/test')} | cryptsetup open --key-file - {DEV} pigcrypt")
        machine.succeed("mount /dev/mapper/pigcrypt /mnt/pig")
        marker = machine.succeed("cat /mnt/pig/marker").strip()
        assert marker == "piggy-vm-luks-marker", marker
        machine.succeed("umount /mnt/pig && cryptsetup close pigcrypt")

    with subtest("second passphrase keyslot; both unlock; wrong key fails"):
        machine.succeed("printf %s second-slot-passphrase > /root/pw2 && chmod 600 /root/pw2")
        machine.succeed(f"{show('luks/test')} | cryptsetup luksAddKey -q {KDF} --key-file - {DEV} /root/pw2")
        dump = machine.succeed(f"cryptsetup luksDump {DEV}")
        assert "  0: luks2" in dump and "  1: luks2" in dump, dump
        machine.succeed(f"cryptsetup open --key-file /root/pw2 {DEV} pigcrypt && cryptsetup close pigcrypt")
        machine.succeed(f"{show('luks/test')} | cryptsetup open --key-file - {DEV} pigcrypt && cryptsetup close pigcrypt")
        machine.fail(f"echo -n wrong-key | cryptsetup open --key-file - {DEV} pigcrypt")
  '';
}
