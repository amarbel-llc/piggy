# LUKS2 from the piggy store via `piggy luks` (piggy#277): a secret
# sealed to the fibby card formats, opens, and re-opens a LUKS2 volume;
# a second passphrase keyslot is enrolled alongside it (the FDR 0004
# shape: token slot + passphrase). The gate for the Rust command: every
# store-keyed step goes through `piggy luks`, and the plain-cryptsetup
# steps prove the resulting volume is an ordinary LUKS2 device.
{ bootstrap }:
{ ... }:
{
  nodes.machine = { };
  testScript = bootstrap { secretName = "luks/test"; } + ''
    DEV = "/dev/vdb"
    # argon2id benchmarks itself to ~1 GiB / seconds per op, which is
    # hostile under TCG; pbkdf2 with a fixed low count keeps the test
    # about key plumbing, not KDF cost (upstream luks.nix does the same
    # with --iter-time=1).
    KDF = "-q --pbkdf pbkdf2 --pbkdf-force-iterations 1000"
    LUKS = ENV + "piggy luks"

    with subtest("piggy luks format + open from the store secret"):
        n0 = ecdh_count()
        machine.succeed(f"{LUKS} format {DEV} --secret luks/test -- {KDF}")
        machine.succeed(f"{LUKS} open {DEV} pigcrypt --secret luks/test")
        machine.wait_for_file("/dev/mapper/pigcrypt")
        machine.succeed("mkfs.ext4 -q /dev/mapper/pigcrypt")
        machine.succeed("mkdir -p /mnt/pig && mount /dev/mapper/pigcrypt /mnt/pig")
        machine.succeed("echo piggy-vm-luks-marker > /mnt/pig/marker && sync")
        machine.succeed(f"umount /mnt/pig && {LUKS} close pigcrypt")
        machine.wait_until_fails("test -e /dev/mapper/pigcrypt")
        expect_ecdh(n0 + 2)  # format + open: exactly two card ECDH ops

    with subtest("reopen from the store and read the marker back"):
        machine.succeed(f"{LUKS} open {DEV} pigcrypt --secret luks/test")
        machine.succeed("mount /dev/mapper/pigcrypt /mnt/pig")
        marker = machine.succeed("cat /mnt/pig/marker").strip()
        assert marker == "piggy-vm-luks-marker", marker
        machine.succeed("umount /mnt/pig && cryptsetup close pigcrypt")

    with subtest("add-key enrols a passphrase keyslot; both unlock; wrong key fails"):
        machine.succeed("printf %s second-slot-passphrase > /root/pw2 && chmod 600 /root/pw2")
        n0 = ecdh_count()
        machine.succeed(f"{LUKS} add-key {DEV} /root/pw2 --secret luks/test -- {KDF}")
        expect_ecdh(n0 + 1)  # the store secret authorised the new slot
        dump = machine.succeed(f"cryptsetup luksDump {DEV}")
        assert "  0: luks2" in dump and "  1: luks2" in dump, dump
        # The passphrase slot opens with stock cryptsetup and no card.
        machine.succeed(f"cryptsetup open --key-file /root/pw2 {DEV} pigcrypt && cryptsetup close pigcrypt")
        machine.succeed(f"{LUKS} open {DEV} pigcrypt --secret luks/test && cryptsetup close pigcrypt")
        machine.fail(f"echo -n wrong-key | cryptsetup open --key-file - {DEV} pigcrypt")

    with subtest("a missing store entry fails before cryptsetup runs"):
        machine.fail(f"{LUKS} open {DEV} pigcrypt --secret luks/does-not-exist")
        machine.fail("test -e /dev/mapper/pigcrypt")
  '';
}
