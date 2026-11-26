# TODO(#408): a probe for the pam_piggy design, not a gate. It tests the
# socket plan the operator chose to try: the main agent listens under a
# root-created per-user directory in /run, with a symlink at its old
# path, and falls back to the old path when that directory is missing or
# wrong. The real `piggy agent` runs (proxy-only over a stock ssh-agent:
# the subject is the socket, not a card), and the real
# polkit-agent-helper@.service sandbox, only its ExecStart replaced,
# reaches it. `launcher` is a PROTOTYPE of what services.piggy-agent
# would need. Run with `just debug-vm-probe pam-socket-move`.
{ piggy }:
{ pkgs, ... }:
let
  user = "alice";
  runDir = "/run/piggy-agent/${user}";
  newSock = "${runDir}/agent.sock";
  oldSock = "/home/${user}/.local/state/piggy/piggy-agent.sock";
  softSock = "/run/soft/agent.sock";
  ssh-add = "${pkgs.openssh}/bin/ssh-add";

  launcher = pkgs.writeShellScript "pam-probe-launcher" ''
    set -eu
    old=${oldSock}
    dir=${runDir}
    ${pkgs.coreutils}/bin/mkdir -p -m 0700 "''${old%/*}"
    if [ -d "$dir" ] && [ ! -L "$dir" ] && [ -O "$dir" ] &&
      [ "$(${pkgs.coreutils}/bin/stat -c %a "$dir")" = 700 ]; then
      sock=${newSock}
      # -n -f: replace a leftover socket or link at the old path.
      ${pkgs.coreutils}/bin/ln -sfn "$sock" "$old"
    else
      echo "pam-probe: $dir is unusable, serving the old path" >&2
      sock=$old
    fi
    ${pkgs.coreutils}/bin/rm -f "$sock"
    exec ${piggy}/bin/piggy agent --proxy-only -a "$sock" --upstream soft=${softSock}
  '';

  # What the module would do, from inside the helper unit.
  inSandbox = pkgs.writeShellScript "pam-probe-sandbox-client" ''
    for sock in ${newSock} ${oldSock}; do
      if SSH_AUTH_SOCK=$sock ${ssh-add} -L >/dev/null 2>&1; then
        echo "$sock: lists keys"
      else
        echo "$sock: FAILS"
      fi
    done
  '';

  inherit (import ./pam-probe-lib.nix { inherit pkgs; }) activate;
in
{
  nodes.machine = {
    security.polkit.enable = true;
    users.users.${user}.isNormalUser = true;
    # Only the parent: the test makes and removes the user's directory.
    systemd.tmpfiles.rules = [ "d /run/piggy-agent 0755 root root -" ];
    systemd.services."polkit-agent-helper@".serviceConfig.ExecStart = [
      ""
      "${inSandbox}"
    ];
    systemd.services.soft-ssh-agent = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        User = user;
        RuntimeDirectory = "soft";
        ExecStart = "${pkgs.openssh}/bin/ssh-agent -D -a ${softSock}";
      };
    };
    systemd.services.probe-agent = {
      # The test restarts it once per case, faster than the default limit.
      startLimitIntervalSec = 0;
      after = [ "soft-ssh-agent.service" ];
      wants = [ "soft-ssh-agent.service" ];
      serviceConfig = {
        User = user;
        ExecStart = "${launcher}";
        Environment = [ "HOME=/home/${user}" ];
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("soft-ssh-agent.service")
    machine.wait_for_file("${softSock}")
    as_user = "${pkgs.util-linux}/bin/runuser -u ${user} --"
    machine.succeed(
        f"{as_user} ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N ''' -C pam-probe -f /tmp/k"
    )
    machine.succeed(f"{as_user} env SSH_AUTH_SOCK=${softSock} ${ssh-add} /tmp/k")


    def listing(sock):
        return f"{as_user} env SSH_AUTH_SOCK={sock} ${ssh-add} -L | grep -q pam-probe"


    def make_dir(mode="0700", owner="${user}"):
        machine.succeed(f"install -d -m {mode} -o {owner} ${runDir}")


    def restart():
        machine.succeed("systemctl restart probe-agent.service")
        machine.wait_until_succeeds(listing("${oldSock}"), timeout=60)


    def run_agent(sock, upstream):
        return machine.execute(
            f"{as_user} timeout 5 ${piggy}/bin/piggy agent --proxy-only "
            f"-a {sock} --upstream {upstream} 2>&1"
        )


    def expect_moved(label):
        machine.succeed('test "$(readlink ${oldSock})" = ${newSock}')
        machine.succeed("test -S ${newSock}")
        machine.succeed(listing("${newSock}"))
        print(f"=== PROBE ok: moved, old path works through the link: {label} ===")


    def expect_fallback(label):
        machine.succeed("test -S ${oldSock} && ! test -L ${oldSock}")
        machine.fail(listing("${newSock}"))
        print(f"=== PROBE ok: fallback to a real socket at the old path: {label} ===")


    def sandbox(label):
        output = machine.succeed("${activate}")
        print(f"=== PROBE helper unit, {label} ===\n{output}=== END ===")
        return output


    with subtest("first start, directory missing"):
        restart()
        expect_fallback("first start, no directory")
        out = sandbox("fallback")
        assert out.count("FAILS") == 2, out

    with subtest("directory appears: a restart moves over a leftover socket"):
        # The agent unlinks its socket on a clean stop, so plant the one an
        # unclean stop would leave.
        machine.succeed("systemctl stop probe-agent.service")
        machine.succeed(
            f"{as_user} ${pkgs.python3}/bin/python3 -c "
            "'import socket; socket.socket(socket.AF_UNIX).bind(\"${oldSock}\")'"
        )
        machine.succeed("test -S ${oldSock} && ! test -L ${oldSock}")
        make_dir()
        restart()
        expect_moved("over a leftover socket at the old path")
        out = sandbox("moved")
        assert "${newSock}: lists keys" in out, out
        assert "${oldSock}: FAILS" in out, out

    with subtest("restart while moved"):
        restart()
        expect_moved("restart")

    with subtest("directory removed: a restart replaces the link"):
        machine.succeed("systemctl stop probe-agent.service")
        machine.succeed("rm -rf ${runDir}")
        machine.succeed("test -L ${oldSock} && ! test -e ${oldSock}")
        machine.fail(listing("${oldSock}"))
        restart()
        expect_fallback("over a dangling link")

    with subtest("a symlink in place of the directory falls back"):
        machine.succeed("install -d -m 0700 -o ${user} /run/probe-elsewhere")
        machine.succeed("ln -s /run/probe-elsewhere ${runDir}")
        restart()
        expect_fallback("directory is a symlink")
        machine.succeed("rm ${runDir}")

    with subtest("wrong mode falls back"):
        make_dir(mode="0755")
        restart()
        expect_fallback("directory mode 0755")

    with subtest("wrong owner falls back"):
        make_dir(owner="root")
        restart()
        expect_fallback("directory owned by root")

    with subtest("directory removed under a running agent"):
        make_dir()
        restart()
        expect_moved("again")
        machine.succeed("rm -rf ${runDir}")
        status, _ = machine.execute(listing("${oldSock}"))
        _, active = machine.execute("systemctl is-active probe-agent.service")
        print(f"=== PROBE removed while running: old path exit {status}, unit {active.strip()} ===")
        assert status != 0 and active.strip() == "active", (status, active)
        restart()
        expect_fallback("restart after removal under a running agent")

    with subtest("without a fallback, a missing directory stops the agent"):
        status, output = run_agent("${newSock}", "soft=${softSock}")
        assert status == 1 and "No such file or directory" in output, (status, output)
        print(f"=== PROBE no fallback: exit {status} ===\n{output}=== END ===")

    with subtest("self-upstream through a link is not refused"):
        make_dir()
        # Control: naming the socket itself is refused.
        status, output = run_agent("${runDir}/self.sock", "self=${runDir}/self.sock")
        assert status not in (0, 124) and "own socket" in output, (status, output)
        machine.succeed(f"{as_user} ln -sfn ${runDir}/self.sock /home/${user}/self-link.sock")
        status, output = run_agent("${runDir}/self.sock", "self=/home/${user}/self-link.sock")
        print(f"=== PROBE self-upstream via link: exit {status} ===\n{output}=== END ===")
        # TODO(#416): pins today's bug; expect a refusal once it is fixed.
        assert status == 124, (status, output)
  '';
}
