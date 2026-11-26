# TODO(#408): a probe for the pam_piggy design, not a gate. FDR 0010 open
# question 3: sudo's arguments do not say what runs. Is a sudo APPROVAL
# PLUGIN given what will run, in the modes where the arguments mislead?
# Can the approved program be swapped while it waits, and what does
# approving only what root can change (question 23) catch and miss?
# A stand-in plugin (pam-sudo-approval-probe.c) records what sudo gives
# it, then answers as a root-owned switch says.
# Users reach it through a NOPASSWD rule, so the plugin is the only gate
# under test, except `carol`, who shows the order against authentication.
# Run with `just debug-vm-probe pam-sudo-approval`.
{ pkgs, ... }:
let
  password = "piggy-test-not-a-secret";
  state = "/run/pam-probe";

  plugin = pkgs.runCommandCC "pam-probe-approval.so" { } ''
    mkdir source
    tar -xf ${pkgs.sudo.src} -C source --strip-components=1
    $CC -Wall -Wextra -Werror -shared -fPIC -I source/include \
      ${./pam-sudo-approval-probe.c} -o $out
  '';

  inherit (import ./pam-probe-lib.nix { inherit pkgs; }) fake;

  fakeEditor = pkgs.writeShellScript "pam-probe-fake-editor" ''
    echo changed-by-the-caller >"$1"
  '';
in
{
  nodes.machine = {
    security.sudo.enable = true;
    security.sudo.extraConfig = ''
      alice ALL=(ALL:ALL) NOPASSWD: ALL
      # Lets alice pick the directory the command runs in (sudo -D).
      Defaults:alice runcwd="*"
      carol ALL=(ALL:ALL) ALL
      Defaults:carol timestamp_timeout=0
    '';
    # Naming any plugin turns off the built-in default set, so name it too.
    environment.etc."sudo.conf".text = ''
      Plugin sudoers_policy sudoers.so
      Plugin sudoers_io sudoers.so
      Plugin sudoers_audit sudoers.so
      Plugin pam_probe_approval ${plugin}
    '';
    users.users = {
      alice = {
        isNormalUser = true;
        inherit password;
      };
      bob.isNormalUser = true;
      carol = {
        isNormalUser = true;
        inherit password;
      };
    };
    environment.etc."pam-probe-file" = {
      text = "original\n";
      mode = "0644";
    };
    # Root's own script, which finds one of its commands by PATH.
    environment.etc."pam-probe-script" = {
      text = ''
        #!/bin/sh
        pam-probe-step
      '';
      mode = "0755";
    };
    systemd.tmpfiles.rules = [ "d ${state} 0700 root root -" ];
  };

  testScript = ''
    import shlex
    from typing import Any

    machine.wait_for_unit("multi-user.target")
    as_alice = "${pkgs.util-linux}/bin/runuser -u alice --"
    machine.succeed(f"{as_alice} mkdir -p /home/alice/bin /home/alice/work")
    machine.succeed(f"{as_alice} ln -s ${fake "id"} /home/alice/bin/id")
    sudo = "/run/wrappers/bin/sudo"


    def mode(value, hold=False):
        """A plugin that waits for `go` is let through at once unless `hold`."""
        machine.succeed(f"rm -f ${state}/go; echo {value} > ${state}/mode")
        if not hold:
            machine.succeed("touch ${state}/go")


    def calls():
        text = machine.succeed("cat ${state}/approval 2>/dev/null || true")
        found: list[Any] = []
        for line in text.splitlines():
            if line == "call":
                found.append({"user": {}, "info": {}, "argv": [], "env": {}})
            elif line != "end":
                kind, _, value = line.partition(" ")
                if kind == "argv":
                    found[-1][kind].append(value)
                else:
                    key, _, rest = value.partition("=")
                    found[-1][kind][key] = rest
        return found


    def show(label, script, status, output, seen):
        print(f"=== PROBE {label} ===")
        print(f"script: {script}\nexit {status}\noutput: {output.rstrip()}")
        print(f"approval calls: {len(seen)}")
        for call in seen:
            print(f"  info: {call['info']}")
            print(f"  argv: {call['argv']}")
            print(f"  user cwd: {call['user'].get('cwd')} user: {call['user'].get('user')}")
            print("  env: " + str({k: call["env"].get(k) for k in ("PATH", "SHELL", "FOO", "HOME")}))
        print(f"=== END {label} ===")


    def run(label, script, user="alice"):
        machine.succeed("rm -f ${state}/approval")
        status, output = machine.execute(
            f"timeout 90 ${pkgs.util-linux}/bin/runuser -l {user} -c {shlex.quote(script)} 2>&1"
        )
        seen = calls()
        show(label, script, status, output, seen)
        return status, output, seen


    def approved(label, script):
        """A run that must succeed after exactly one call to the plugin."""
        status, output, seen = run(label, script)
        assert status == 0 and len(seen) == 1, (label, status, output, seen)
        return output, seen[0]


    assert "Sudo version 1.9.17p2" in machine.succeed(f"{sudo} -V")

    mode("allow")
    with subtest("what the plugin is given"):
        coreutils = "${pkgs.coreutils}/bin"
        _, call = approved("plain", f"{sudo} {coreutils}/id -u")
        assert call["info"]["command"] == f"{coreutils}/id" and call["argv"][1:] == ["-u"], call

        out, call = approved("caller's PATH", f"PATH=/home/alice/bin:$PATH {sudo} id -u")
        assert call["info"]["command"] == "/home/alice/bin/id" and call["argv"] == ["id", "-u"], call
        assert "FAKE-id ran as uid 0" in out, out

        _, call = approved("-s with the caller's SHELL", f"SHELL=${fake "shell"} {sudo} -s id -u")
        assert call["info"]["command"] == "${fake "shell"}", call
        assert call["argv"] == ["${fake "shell"}", "-c", "id -u"], call

        _, call = approved("-s alone", f"echo id -u | {sudo} -s")
        assert call["info"]["command"].endswith("/bin/bash"), call
        assert call["argv"] == [call["info"]["command"]], call

        _, call = approved("-i with a command", f"{sudo} -i id -u")
        assert call["info"]["command"].endswith("/bin/bash") and call["info"]["cwd"] == "/root", call
        assert call["argv"] == ["-bash", "--login", "-c", "id -u"], call

        _, call = approved("sudoedit", f"SUDO_EDITOR=${fakeEditor} {sudo} -e /etc/pam-probe-file")
        assert call["info"]["sudoedit"] == "true" and call["info"]["command"] == "${fakeEditor}", call
        assert call["argv"][1:] == ["--", "/etc/pam-probe-file"], call
        assert machine.succeed("cat /etc/pam-probe-file") == "changed-by-the-caller\n"

        _, call = approved("-u and -g", f"{sudo} -u bob -g users {coreutils}/id -u")
        got = {k: call["info"].get(k) for k in ("runas_user", "runas_group", "runas_uid", "runas_gid")}
        assert got == {"runas_user": "bob", "runas_group": "users", "runas_uid": "1001", "runas_gid": "100"}, got

        # The command stays relative; the directory is only in user_info.
        _, call = approved("relative command", f"cd bin && {sudo} ./id -u")
        assert call["info"]["command"] == "./id" and "cwd" not in call["info"], call
        assert call["user"]["cwd"] == "/home/alice/bin", call

        _, call = approved("environment on the command line", f"{sudo} FOO=bar {coreutils}/printenv FOO")
        assert call["env"]["FOO"] == "bar", call

    with subtest("which modes reach the plugin"):
        for label, script in (("-v", f"{sudo} -v"), ("-l", f"{sudo} -l")):
            status, _, seen = run(label, script)
            assert status == 0 and not seen, (label, status, seen)
        approved("-n", f"{sudo} -n {coreutils}/true")
        status, _, seen = run("carol, wrong password", f"echo wrong | {sudo} -S {coreutils}/true", "carol")
        assert status != 0 and not seen, (status, seen)
        status, _, seen = run(
            "carol, right password", f"echo ${password} | {sudo} -S {coreutils}/true", "carol"
        )
        assert status == 0 and len(seen) == 1, (status, seen)

    mode("refuse")
    with subtest("a refusal stops the command, NOPASSWD or not"):
        for label, flags in (("refused", ""), ("refused -n", "-n")):
            status, output, seen = run(label, f"{sudo} {flags} {coreutils}/id -u")
            assert status != 0 and len(seen) == 1 and "0" not in output.split(), (label, output, seen)
        machine.succeed("echo original > /etc/pam-probe-file")
        status, _, seen = run("refused sudoedit", f"SUDO_EDITOR=${fakeEditor} {sudo} -e /etc/pam-probe-file")
        assert status != 0 and len(seen) == 1, (status, seen)
        assert machine.succeed("cat /etc/pam-probe-file") == "original\n"


    def held(label, script, swap, setup="true", how="hold"):
        """Starts script, changes the user's files while the plugin waits, then approves."""
        machine.succeed(f"{as_alice} sh -c {shlex.quote(setup)}")
        mode(how, hold=True)
        machine.succeed("rm -f ${state}/approval /tmp/held.log")
        machine.execute(
            f"(status=0; ${pkgs.util-linux}/bin/runuser -l alice -c {shlex.quote(script)}"
            " || status=$?; echo sudo-exit $status) >/tmp/held.log 2>&1 &"
        )
        machine.wait_until_succeeds("grep -qx end ${state}/approval", timeout=60)
        machine.succeed(f"{as_alice} sh -c {shlex.quote(swap)}")
        machine.succeed("touch ${state}/go")
        machine.wait_until_succeeds("grep -q sudo-exit /tmp/held.log", timeout=90)
        output = machine.succeed("cat /tmp/held.log")
        seen = calls()
        show(label, script, "-", output, seen)
        return output, seen


    with subtest("can the approved program change while the plugin waits?"):
        original = "printf '#!/bin/sh\\necho ORIGINAL\\n' > /home/alice/bin/tool && chmod 755 /home/alice/bin/tool"
        # What is asserted is the hole: the approval names a path, and
        # what the caller puts there afterwards is what runs as root. Each
        # payload says which uid it got.
        in_place = (
            "printf '#!/bin/sh\\necho SWAPPED as $(${pkgs.coreutils}/bin/id -u)\\n' > /home/alice/bin/tool"
        )
        swapped = (
            in_place.replace("bin/tool", "bin/next")
            + " && chmod 755 /home/alice/bin/next && mv /home/alice/bin/next /home/alice/bin/tool"
        )
        for label, setup, program, swap, ran in (
            ("file replaced while waiting", original, "tool", swapped, "SWAPPED as 0"),
            ("file rewritten in place while waiting", original, "tool", in_place, "SWAPPED as 0"),
            (
                "link retargeted while waiting",
                "ln -sfn ${fake "approved"} /home/alice/bin/link",
                "link",
                "ln -sfn ${fake "swapped"} /home/alice/bin/link",
                "FAKE-swapped ran as uid 0",
            ),
        ):
            output, seen = held(label, f"{sudo} /home/alice/bin/{program}", swap, setup=setup)
            assert len(seen) == 1 and seen[0]["info"]["command"] == f"/home/alice/bin/{program}", seen
            assert ran in output and "sudo-exit 0" in output, (label, output)

    with subtest("remedy: only a program that only root can change"):
        coreutils = "${pkgs.coreutils}/bin"
        # Files root owns, in places where the caller can or cannot act.
        machine.succeed("install -m 0755 ${fake "root-copy"} /home/alice/bin/root-owned")
        machine.succeed("install -d -m 0755 /srv/safe /srv/open && chmod 0777 /srv/open")
        # Scripts, not copies of coreutils: its binary acts by its name.
        machine.succeed("install -m 0755 ${fake "good"} /srv/safe/good")
        machine.succeed("install -m 0775 -g users ${fake "grouped"} /srv/safe/group-writable")
        machine.succeed("install -m 0755 ${fake "open"} /srv/open/in-open-dir")
        machine.succeed(f"{as_alice} ln -sfn /srv/safe/good /home/alice/bin/link-to-good")
        machine.succeed("ln -sfn /home/alice/bin/tool /srv/safe/link-to-callers")
        machine.succeed(f"{as_alice} sh -c {shlex.quote(original)}")
        machine.succeed("install -o alice -m 0755 ${fake "callers-good"} /home/alice/bin/good")
        # A root-owned sticky directory, so that the exception and the
        # owner rule are each tried on their own.
        machine.succeed("install -d -m 1777 /srv/sticky")
        machine.succeed("install -m 0755 ${fake "sticky"} /srv/sticky/roots")
        # A link the caller owns where only the owner rule can object. Not
        # in a sticky directory: there root could not follow it at all.
        machine.succeed("ln -s /srv/safe/good /srv/safe/callers-link && chown -h alice /srv/safe/callers-link")
        machine.succeed(f"{as_alice} cp ${fake "sticky-own"} /srv/sticky/callers-file")
        machine.succeed(f"{as_alice} chmod 755 /srv/sticky/callers-file")

        for label, script, allowed in (
            ("a store program", f"{sudo} {coreutils}/true", True),
            ("through root's links", f"{sudo} /run/current-system/sw/bin/true", True),
            ("root's file in root's directory", f"{sudo} /srv/safe/good", True),
            ("the caller's own program", f"{sudo} /home/alice/bin/tool", False),
            ("found on the caller's PATH", f"PATH=/home/alice/bin:$PATH {sudo} id -u", False),
            ("root's file in the caller's directory", f"{sudo} /home/alice/bin/root-owned", False),
            ("the caller's link to a good program", f"{sudo} /home/alice/bin/link-to-good", False),
            ("root's link to the caller's program", f"{sudo} /srv/safe/link-to-callers", False),
            ("group-writable file", f"{sudo} /srv/safe/group-writable", False),
            ("in an open directory", f"{sudo} /srv/open/in-open-dir", False),
            ("relative, in the caller's directory", f"cd bin && {sudo} ./tool", False),
            ("relative, in root's directory", f"cd /srv/safe && {sudo} ./good", True),
            ("root's file in a sticky directory", f"{sudo} /srv/sticky/roots", True),
            ("a link the caller owns, all else root's", f"{sudo} /srv/safe/callers-link", False),
            ("the caller's file in a sticky directory", f"{sudo} /srv/sticky/callers-file", False),
            ("relative, run elsewhere with -D", f"cd /srv/safe && {sudo} -D /home/alice/bin ./good", False),
        ):
            if not allowed:
                # Control: without the check the same command runs.
                mode("allow")
                status, output, _ = run(f"control: {label}", script)
                assert status == 0, (label, status, output)
                if "-D" in script:
                    # The directory change is real: the caller's file ran.
                    assert "FAKE-callers-good ran as uid 0" in output, output
            mode("safe")
            status, output, seen = run(f"remedy: {label}", script)
            assert len(seen) == 1 and (status == 0) == allowed, (label, status, output, seen)

    with subtest("what the remedy does not cover"):
        output, _ = held(
            "a good interpreter, the caller's script",
            f"{sudo} /run/current-system/sw/bin/sh /home/alice/bin/tool",
            in_place,
            setup=original,
            how="safe",
        )
        assert "SWAPPED as 0" in output and "sudo-exit 0" in output, output

        step = (
            "printf '#!/bin/sh\\necho CALLERS-STEP as $(${pkgs.coreutils}/bin/id -u)\\n'"
            " > /home/alice/bin/pam-probe-step && chmod 755 /home/alice/bin/pam-probe-step"
        )
        output, _ = held(
            "root's script, a command found on the caller's PATH",
            f"PATH=/home/alice/bin:$PATH {sudo} /etc/pam-probe-script",
            step,
            how="safe",
        )
        assert "CALLERS-STEP as 0" in output and "sudo-exit 0" in output, output

        # A user can put a file of their own into the store: root owns it
        # and nobody can change it, so the check passes.
        added = machine.succeed(
            f"{as_alice} sh -c 'printf \"#!/bin/sh\\necho CALLER-AUTHORED as \\$(${pkgs.coreutils}/bin/id -u)\\n\" >/tmp/authored"
            " && chmod 755 /tmp/authored"
            " && ${pkgs.nix}/bin/nix-store --add /tmp/authored'"
        ).strip()
        mode("safe")
        status, output, seen = run("a program the caller added to the store", f"{sudo} {added}")
        assert status == 0 and "CALLER-AUTHORED as 0" in output, (added, status, output)
  '';
}
