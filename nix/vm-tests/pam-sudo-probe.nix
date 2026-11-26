# TODO(#408): a probe for the pam_piggy design, not a gate. It sets up the
# sudo pilot's shape, a user whose sudo authenticates only through a
# `pam_exec` stack, with a stand-in helper that records what it is given
# and then allows or refuses by a root-owned switch. It answers: does any
# password path remain, what runs compared with the arguments the helper
# can show, which ids the helper needs, and can it reach the user's agent.
# It asserts what FDR 0010 states, including the cases where what ran or
# was written is not what the arguments say.
# The helper IS the authentication here: a probe, never a template.
# Run with `just debug-vm-probe pam-sudo`.
{ piggy }:
{ pkgs, ... }:
let
  password = "piggy-test-not-a-secret";
  agentSock = "/home/alice/.local/state/piggy/piggy-agent.sock";
  softSock = "/run/soft/agent.sock";
  state = "/run/pam-probe";

  helper = pkgs.writeScript "pam-probe-sudo-helper" ''
    #!${pkgs.python3}/bin/python3
    import json, os, subprocess, sys, time


    def argv(pid):
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return [a.decode(errors="replace") for a in f.read().rstrip(b"\0").split(b"\0")]


    parent = os.getppid()
    listing = subprocess.run(
        ["${pkgs.openssh}/bin/ssh-add", "-L"],
        env={"SSH_AUTH_SOCK": "${agentSock}"},
        capture_output=True,
        text=True,
        timeout=20,
    )
    def environ(pid):
        """The environment as it was at exec; Python adds to os.environ itself."""
        with open(f"/proc/{pid}/environ", "rb") as f:
            return dict(
                entry.decode(errors="replace").partition("=")[::2]
                for entry in f.read().split(b"\0")
                if entry
            )


    inherited = environ(parent)
    record = {
        "parent_env_path": inherited.get("PATH"),
        "parent_env_shell": inherited.get("SHELL"),
        "pid": os.getpid(),
        "service": os.environ.get("PAM_SERVICE"),
        "user": os.environ.get("PAM_USER"),
        "ruser": os.environ.get("PAM_RUSER"),
        "ruid": os.getuid(),
        "euid": os.geteuid(),
        "env_keys": sorted(environ("self")),
        "parent_argv": argv(parent),
        "parent_cwd": os.readlink(f"/proc/{parent}/cwd"),
        "agent_lists_key": "pam-probe" in listing.stdout,
    }
    with open("${state}/calls.jsonl", "a") as log:
        log.write(json.dumps(record) + "\n")
    with open("${state}/mode") as f:
        mode = f.read().strip()
    if mode == "sleep":
        time.sleep(30)
    sys.exit(0 if mode in ("allow", "sleep") else 1)
  '';

  askpass = pkgs.writeShellScript "pam-probe-askpass" ''
    echo ${password}
  '';

  inherit (import ./pam-probe-lib.nix { inherit pkgs; }) fake;

  fakeEditor = pkgs.writeShellScript "pam-probe-fake-editor" ''
    echo "FAKE-editor ran as uid $(${pkgs.coreutils}/bin/id -u) with: $*" >/tmp/editor.log
    echo changed-by-the-caller >"$1"
  '';

  noPassword = pkgs.writeShellScript "pam-probe-nopasswd" ''
    ${pkgs.coreutils}/bin/id -u
  '';
in
{
  nodes.machine =
    { config, ... }:
    let
      lib = "${config.security.pam.package}/lib/security";
      stack = flags: ''
        auth required ${lib}/pam_exec.so ${flags} stdout quiet ${helper}
        account required ${lib}/pam_unix.so
        session required ${lib}/pam_permit.so
      '';
      # Without timestamp_timeout=0: sudo's default cache stays on.
      piggyCached = user: service: ''
        Defaults:${user} pam_service=${service}
        Defaults:${user} pam_login_service=${service}
        Defaults:${user} pam_askpass_service=${service}
        ${user} ALL=(ALL:ALL) ALL
      '';
      piggyOnly = user: service: ''
        ${piggyCached user service}
        Defaults:${user} timestamp_timeout=0
      '';
    in
    {
      security.sudo.enable = true;
      security.sudo.extraConfig = ''
        ${piggyOnly "alice" "sudo-piggy"}
        ${piggyOnly "carol" "sudo-piggy-seteuid"}
        ${piggyOnly "dave" "sudo-piggy-seteuid"}
        ${piggyCached "erin" "sudo-piggy"}
        Defaults:dave secure_path="/run/wrappers/bin:/run/current-system/sw/bin"
        alice ALL=(root) NOPASSWD: ${noPassword}
      '';
      security.pam.services.sudo-piggy.text = stack "";
      security.pam.services.sudo-piggy-seteuid.text = stack "seteuid";
      users.users = {
        alice = {
          isNormalUser = true;
          inherit password;
        };
        carol = {
          isNormalUser = true;
          inherit password;
        };
        dave = {
          isNormalUser = true;
          inherit password;
        };
        erin = {
          isNormalUser = true;
          inherit password;
        };
        bob = {
          isNormalUser = true;
          extraGroups = [ "wheel" ];
          inherit password;
        };
      };
      # With a mode, a real file: sudoedit refuses NixOS's usual symlink.
      environment.etc."pam-probe-file" = {
        text = "original\n";
        mode = "0644";
      };
      systemd.tmpfiles.rules = [ "d ${state} 0700 root root -" ];
      systemd.services.soft-ssh-agent = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          User = "alice";
          RuntimeDirectory = "soft";
          ExecStart = "${pkgs.openssh}/bin/ssh-agent -D -a ${softSock}";
        };
      };
      systemd.services.probe-agent = {
        after = [ "soft-ssh-agent.service" ];
        serviceConfig = {
          User = "alice";
          Environment = [ "HOME=/home/alice" ];
          ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p -m 0700 /home/alice/.local/state/piggy";
          ExecStart = "${piggy}/bin/piggy agent --proxy-only -a ${agentSock} --upstream soft=${softSock}";
        };
      };
    };

  testScript = ''
    import json
    import shlex

    machine.wait_for_unit("soft-ssh-agent.service")
    machine.wait_for_file("${softSock}")
    as_alice = "${pkgs.util-linux}/bin/runuser -u alice --"
    machine.succeed(
        f"{as_alice} ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N ''' -C pam-probe -f /tmp/k"
    )
    machine.succeed(f"{as_alice} env SSH_AUTH_SOCK=${softSock} ${pkgs.openssh}/bin/ssh-add /tmp/k")
    machine.systemctl("start probe-agent.service")
    machine.wait_until_succeeds(
        f"{as_alice} env SSH_AUTH_SOCK=${agentSock} ${pkgs.openssh}/bin/ssh-add -L", timeout=60
    )
    machine.succeed(f"{as_alice} mkdir -p /home/alice/bin /home/alice/work")
    machine.succeed(f"{as_alice} ln -s ${fake "id"} /home/alice/bin/id")


    def mode(value):
        machine.succeed(f"echo {value} > ${state}/mode")


    def calls():
        text = machine.succeed("cat ${state}/calls.jsonl 2>/dev/null || true")
        return [json.loads(line) for line in text.splitlines()]


    def run(label, user, script):
        """Runs script in a login shell of user; reports what the helper and sudo saw."""
        machine.succeed("rm -f ${state}/calls.jsonl")
        # journald takes messages in asynchronously.
        machine.succeed("journalctl --sync")
        before = machine.succeed("journalctl -t sudo -o cat --no-pager | grep -c COMMAND= || true")
        status, output = machine.execute(
            f"timeout 90 ${pkgs.util-linux}/bin/runuser -l {user} -c {shlex.quote(script)} 2>&1"
        )
        seen = calls()
        machine.succeed("journalctl --sync")
        logged = machine.succeed("journalctl -t sudo -o cat --no-pager | grep COMMAND= || true")
        logged = logged.splitlines()[int(before):]
        print(f"=== PROBE {label} ===")
        print(f"script: {script}\nexit {status}\noutput: {output.rstrip()}")
        print(f"helper calls: {len(seen)}")
        for call in seen:
            shown = {k: v for k, v in call.items() if k != "env_keys"}
            print(f"  {json.dumps(shown)}")
        for line in logged:
            print(f"  sudo logged: {line.strip()}")
        print(f"=== END {label} ===")
        return status, output, seen, logged


    sudo = "/run/wrappers/bin/sudo"


    def approved(label, user, script):
        """A run that must succeed after exactly one helper call."""
        status, output, seen, logged = run(label, user, script)
        assert status == 0 and len(seen) == 1, (label, status, output, seen)
        (call,) = seen
        # No terminal here, so no PAM_TTY.
        assert call["env_keys"] == ["PAM_RUSER", "PAM_SERVICE", "PAM_TYPE", "PAM_USER"], call["env_keys"]
        assert call["agent_lists_key"] and call["user"] == call["ruser"] == user, call
        return output, call, "\n".join(logged)


    assert "Sudo version 1.9.17p2" in machine.succeed(f"{sudo} -V")
    assert machine.succeed("stat -c %a /home/alice/.local/state/piggy").strip() == "700"

    mode("allow")
    with subtest("what runs, against what the helper sees"):
        _, call, _ = approved("plain", "alice", f"{sudo} ${pkgs.coreutils}/bin/id -u")
        assert call["parent_argv"][1:] == ["${pkgs.coreutils}/bin/id", "-u"], call
        assert (call["ruid"], call["euid"]) == (1000, 0), call

        out, call, logged = approved("caller's PATH", "alice", f"PATH=/home/alice/bin:$PATH {sudo} id -u")
        assert "FAKE-id ran as uid 0" in out and call["parent_argv"][1:] == ["id", "-u"], (out, call)
        assert "COMMAND=/home/alice/bin/id -u" in logged, logged
        assert call["parent_env_path"].startswith("/home/alice/bin:"), call

        out, call, _ = approved("-s with the caller's SHELL", "alice", f"SHELL=${fake "shell"} {sudo} -s id -u")
        assert "FAKE-shell ran as uid 0" in out, out
        assert call["parent_argv"][1:] == ["-s", "id", "-u"], call
        assert call["parent_env_shell"] == "${fake "shell"}", call

        _, call, logged = approved("-s alone", "alice", f"echo id -u | {sudo} -s")
        assert call["parent_argv"][1:] == ["-s"] and "bin/bash" in logged, (call, logged)

        out, _, logged = approved("-i with a command", "alice", f"SHELL=${fake "shell"} {sudo} -i id -u")
        assert "FAKE" not in out and "bash --login -c" in logged, (out, logged)

        _, call, logged = approved(
            "sudoedit", "alice", f"SUDO_EDITOR=${fakeEditor} {sudo} -e /etc/pam-probe-file"
        )
        editor = machine.succeed("cat /tmp/editor.log")
        # As the caller, on a copy; root then writes the caller's text back.
        assert "ran as uid 1000 with: /var/tmp/" in editor, editor
        assert machine.succeed("cat /etc/pam-probe-file") == "changed-by-the-caller\n"
        assert call["parent_argv"][1:] == ["-e", "/etc/pam-probe-file"], call

        out, call, logged = approved("-u another user", "alice", f"{sudo} -u bob ${pkgs.coreutils}/bin/id -u")
        assert "USER=bob" in logged and call["parent_argv"][1:3] == ["-u", "bob"], (call, logged)
        assert call["user"] == "alice", call

        _, call, _ = approved("relative path", "alice", f"cd work && {sudo} ${pkgs.coreutils}/bin/ls .")
        assert call["parent_cwd"] == "/home/alice/work", call

        _, call, logged = approved(
            "environment on the command line", "alice", f"{sudo} FOO=bar ${pkgs.coreutils}/bin/printenv FOO"
        )
        assert "FOO=bar" in call["parent_argv"] and "ENV=FOO=bar" in logged, (call, logged)

        approved(
            "caller's SSH_AUTH_SOCK",
            "alice",
            f"SSH_AUTH_SOCK=/tmp/not-the-agent {sudo} ${pkgs.coreutils}/bin/true",
        )

    machine.succeed("${pkgs.util-linux}/bin/runuser -u dave -- mkdir -p /home/dave/bin")
    machine.succeed("${pkgs.util-linux}/bin/runuser -u dave -- ln -s ${fake "id"} /home/dave/bin/id")

    with subtest("with secure_path set"):
        out, _, _ = approved("secure_path: caller's PATH", "dave", f"PATH=/home/dave/bin:$PATH {sudo} id -u")
        assert "FAKE" not in out and out.strip().endswith("0"), out
        out, _, _ = approved(
            "secure_path: -s with the caller's SHELL", "dave", f"SHELL=${fake "shell"} {sudo} -s id -u"
        )
        assert "FAKE-shell ran as uid 0" in out, out

    with subtest("approval is not reused, and the other modes"):
        # The final `true` keeps bash from exec'ing the second sudo: both
        # must be its children, as with no terminal sudo keys its cache to
        # the parent. erin shows that this setup does reuse an approval.
        twice = f"{sudo} ${pkgs.coreutils}/bin/true; {sudo} ${pkgs.coreutils}/bin/true; true"
        for user, expected in (("alice", 2), ("erin", 1)):
            status, _, seen, _ = run(f"twice in one shell, {user}", user, twice)
            assert status == 0 and len(seen) == expected, (user, status, seen)
        status, out, seen, _ = run("-n", "alice", f"{sudo} -n ${pkgs.coreutils}/bin/true")
        assert status != 0 and not seen and "a password is required" in out, (status, out, seen)
        _, call, _ = approved("-v", "alice", f"{sudo} -v")
        assert call["parent_argv"][1:] == ["-v"], call
        # alice has a NOPASSWD rule, so listing asks for nothing.
        status, _, seen, _ = run("-l", "alice", f"{sudo} -l")
        assert status == 0 and not seen, (status, seen)
        status, _, seen, _ = run("NOPASSWD rule", "alice", f"{sudo} ${noPassword}")
        assert status == 0 and not seen, (status, seen)

    mode("refuse")
    with subtest("refusal leaves no password path"):
        piped = "echo ${password} |"
        for user in ("alice", "carol"):
            for label, script in (
                ("-S", f"{piped} {sudo} -S ${pkgs.coreutils}/bin/id -u"),
                # A bare name: the full path in sudo's log is its own lookup.
                ("-S bare name", f"{piped} {sudo} -S id -u"),
                ("-i -S", f"{piped} {sudo} -S -i id -u"),
                ("-s -S", f"{piped} {sudo} -S -s id -u"),
                ("-A", f"SUDO_ASKPASS=${askpass} {sudo} -A ${pkgs.coreutils}/bin/id -u"),
                ("-A -i", f"SUDO_ASKPASS=${askpass} {sudo} -A -i id -u"),
            ):
                status, output, seen, logged = run(f"refused, {user} {label}", user, script)
                service = "sudo-piggy" if user == "alice" else "sudo-piggy-seteuid"
                assert status != 0 and len(seen) == 1, (user, label, output, seen)
                assert seen[0]["service"] == service and seen[0]["agent_lists_key"], seen
                # sudo had resolved the command although authentication failed.
                assert any("PAM authentication error" in x and "COMMAND=/" in x for x in logged), logged
        # Controls: the same password and askpass work where the stack takes one.
        for label, script in (
            ("-S", f"{piped} {sudo} -S ${pkgs.coreutils}/bin/id -u"),
            ("-A", f"SUDO_ASKPASS=${askpass} {sudo} -k -A ${pkgs.coreutils}/bin/id -u"),
        ):
            status, output, seen, _ = run(f"control: admin with a password {label}", "bob", script)
            assert status == 0 and output.strip().endswith("0") and not seen, (status, output, seen)

    mode("sleep")
    with subtest("can the waiting user signal the helper?"):
        for user in ("alice", "carol"):
            machine.succeed("rm -f ${state}/calls.jsonl /tmp/sudo-sig.log")
            # The driver's shell runs with errexit: catch the status.
            machine.execute(
                f"(status=0; ${pkgs.util-linux}/bin/runuser -l {user} -c '{sudo} ${pkgs.coreutils}/bin/true'"
                " || status=$?; echo sudo-exit $status) >/tmp/sudo-sig.log 2>&1 &"
            )
            machine.wait_until_succeeds("test -s ${state}/calls.jsonl", timeout=60)
            pid = calls()[0]["pid"]
            results = {}
            for signal in ("STOP", "CONT", "KILL"):
                status, output = machine.execute(
                    f"${pkgs.util-linux}/bin/runuser -u {user} -- ${pkgs.bash}/bin/bash -c 'kill -{signal} {pid}' 2>&1"
                )
                results[signal] = status
                # A helper that had already gone would also fail the kill.
                assert status == 0 or "Operation not permitted" in output, (signal, output)
            machine.wait_until_succeeds("grep -q sudo-exit /tmp/sudo-sig.log", timeout=90)
            sudo_log = machine.succeed("cat /tmp/sudo-sig.log")
            print(f"=== PROBE signals from {user}: {results}\n{sudo_log}=== END ===")
            if user == "alice":
                # Without seteuid: every signal lands, and sudo fails closed.
                assert set(results.values()) == {0} and "sudo-exit 1" in sudo_log, (results, sudo_log)
            else:
                assert 0 not in results.values() and "sudo-exit 0" in sudo_log, (results, sudo_log)
  '';
}
