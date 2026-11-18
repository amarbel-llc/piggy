# The key holder as a NixOS service (FDR 0006 phase (d), piggy#383 item
# 5): the shipped `services.piggy-holder` module, run as it would be on a
# real host, with real systemd units standing in for the sessions:
#
#   fdr6d-bound     a transient service (its own cgroup) that mints two
#                   keys, signs and verifies with one, retires it, and
#                   stays alive until told to exit
#   fdr6d-sibling   a second transient service, same user, different
#                   cgroup, whose sign and retire with the bound key are
#                   refused not-bound-scope
#
# The testScript then lets the bound service exit and watches the holder
# destroy its remaining card. It also reads the units' hardening back
# from the running processes: no capabilities, no core file, not
# dumpable, fibby's sockets unreachable to a session user. The sign
# needs no PIN: the askpass discipline is set with NO PIN to supply, so a
# prompt would fail loudly.
{
  piggy,
  fibbyHolder,
  holderModule,
  prelude,
  # `VAR=value ` words for the session commands: the askpass discipline
  # without PIGGY_TEST_FIB_PIN (a minted key must sign with no PIN).
  sessionEnv,
}:
{ pkgs, lib, ... }:
let
  sock = "/run/piggy-holder/agent.sock";
  work = "/tmp/fdr6d";
  # What the bound session does, as the session user, inside its own unit.
  boundScript = pkgs.writeShellScript "fdr6d-bound" ''
    set -euo pipefail
    cd ${work}
    piggy holder mint --scope piggy-mint-v1 > a.pub
    piggy holder mint --scope piggy-mint-v1 > b.pub
    read -r t k _ < a.pub; printf 'fdr6d %s %s\n' "$t" "$k" > signers
    echo "piggy-test: signed from the bound scope" > data
    ssh-keygen -Y sign -f a.pub -U -n file data
    ssh-keygen -Y verify -f signers -I fdr6d -n file -s data.sig < data
    piggy holder retire a.pub
    touch bound.ok
    while [ ! -e go ]; do sleep 0.2; done
  '';
in
{
  nodes.machine = {
    imports = [ holderModule ];
    services.piggy-holder = {
      enable = true;
      package = piggy;
      fibbyPackage = fibbyHolder;
      scopes.piggy-mint-v1 = "caller";
      clientGroup = "users";
      scopePollInterval = 1;
    };
    users.users.sess = {
      isNormalUser = true;
      extraGroups = [ "users" ];
    };
    systemd.tmpfiles.rules = [ "d ${work} 0777 root root -" ];
  };

  testScript = prelude + ''
    SOCK = "${sock}"
    WORK = "${work}"
    ENV = "${sessionEnv}SSH_AUTH_SOCK=" + SOCK + " "


    def as_sess(unit, cmd, wait=True):
        # A transient SYSTEM service: its own cgroup under system.slice,
        # which is what the holder binds to. --wait makes the call return
        # the command's exit status.
        # A transient service starts with systemd's bare PATH, not the
        # system profile's, so the session gets it set explicitly.
        flags = "--wait --pipe --quiet" if wait else ""
        return (
            f"systemd-run {flags} --unit {unit} --uid sess "
            f"--property=WorkingDirectory={WORK} "
            "--setenv=PATH=/run/current-system/sw/bin:/run/wrappers/bin "
            f"-- /run/current-system/sw/bin/bash -c '{ENV}{cmd}'"
        )


    def main_pid(unit):
        return machine.succeed(f"systemctl show -p MainPID --value {unit}").strip()


    def expect_in_journal(unit, needle):
        machine.wait_until_succeeds(
            f'journalctl -u {unit} --no-pager -o cat | grep -qF "{needle}"', timeout=60
        )


    wait_for_units(["multi-user.target", "fibby-holder.service", "piggy-holder.service"])
    machine.wait_for_file(SOCK)

    with subtest("both units run unprivileged, non-dumpable, with no core file and no capabilities"):
        for unit, user in [("fibby-holder.service", "fibby-holder"), ("piggy-holder.service", "piggy-holder")]:
            pid = main_pid(unit)
            status = machine.succeed(f"cat /proc/{pid}/status")
            assert "CapEff:\t0000000000000000" in status, (unit, status)
            assert "NoNewPrivs:\t1" in status, (unit, status)
            owner = machine.succeed(f"stat -c %U /proc/{pid}/environ").strip()
            assert owner == "root", (unit, owner)  # not dumpable: /proc/<pid>/environ reverts to root
            core = machine.succeed(f"awk '/^Max core file size/ {{print $5}}' /proc/{pid}/limits").strip()
            assert core == "0", (unit, core)
            uid_line = [l for l in status.splitlines() if l.startswith("Uid:")][0]
            uid = machine.succeed(f"id -u {user}").strip()
            assert uid_line.split()[1] == uid, (unit, uid_line, uid)

    with subtest("fibby's sockets are reachable by the holder agent's account and not by a session"):
        machine.succeed("runuser -u piggy-holder -- test -r /run/fibby-holder/ctl.sock")
        machine.fail("runuser -u sess -- test -e /run/fibby-holder/ctl.sock")
        machine.succeed("runuser -u sess -- test -w " + SOCK)

    with subtest("a bound service mints two keys, signs and verifies with one, retires it"):
        machine.succeed(as_sess("fdr6d-bound", "${pkgs.bash}/bin/bash ${boundScript}", wait=False))
        machine.wait_for_file(WORK + "/bound.ok", timeout=180)
        listing = machine.succeed(f"SSH_AUTH_SOCK={SOCK} ssh-add -L")
        assert listing.count("holder:piggy-holder ") == 1, listing
        assert "holder:piggy-holder 2" in listing, listing
        expect_in_journal("piggy-holder", "holder: minted a key")
        expect_in_journal("piggy-holder", "retired by its scope")
        agent_log = machine.succeed("journalctl -u piggy-holder --no-pager -o cat")
        assert "REFUSING to prompt" not in agent_log, agent_log
        assert "pin_prompt" not in agent_log, agent_log

    with subtest("a sibling service is refused not-bound-scope for a sign and for a retire"):
        machine.succeed(f"echo 'piggy-test: from the sibling' > {WORK}/sdata")
        machine.fail(as_sess("fdr6d-sibling-sign", "ssh-keygen -Y sign -f b.pub -U -n file sdata"))
        out = machine.fail(as_sess("fdr6d-sibling-retire", "piggy holder retire b.pub 2>&1"))
        assert "not-bound-scope" in out, out
        expect_in_journal("piggy-holder", "not-bound-scope")
        # The key is still there: a sibling can neither use nor remove it.
        listing = machine.succeed(f"SSH_AUTH_SOCK={SOCK} ssh-add -L")
        assert "holder:piggy-holder 2" in listing, listing

    with subtest("the bound service exits and the holder destroys its card"):
        machine.succeed(f"touch {WORK}/go")
        machine.wait_until_fails("systemctl is-active --quiet fdr6d-bound.service", timeout=60)
        expect_in_journal("piggy-holder", "its scope exited")
        machine.wait_until_succeeds(
            f"! SSH_AUTH_SOCK={SOCK} ssh-add -L 2>/dev/null | grep -q 'holder:'", timeout=60
        )
        expect_in_journal("fibby-holder", "destroyed card 'piggy-holder 2'")

    with subtest("a mint naming no scope, or an undefined one, is refused by name and creates no card"):
        out = machine.fail(as_sess("fdr6d-noscope", "piggy holder mint 2>&1"))
        assert "scope-unbound" in out, out
        out = machine.fail(as_sess("fdr6d-badscope", "piggy holder mint --scope piggy-mint-v9 2>&1"))
        assert "unknown-scope" in out, out
        listing = machine.succeed(f"SSH_AUTH_SOCK={SOCK} ssh-add -L 2>&1 || true")
        assert "holder:" not in listing, listing
  '';
}
