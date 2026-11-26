# TODO(#408): a probe for the pam_piggy design, not a gate. It runs a
# helper under `pam_exec.so stdout` in the polkit-1 and sudo auth stacks
# and drives real `pkexec` (with its textual agent) and `sudo` on a pty.
# It answers two questions: does a line the helper prints (the matching
# code) reach the requester's terminal BEFORE the helper finishes, and
# what can the helper learn about the command being approved? The helper
# exits 0, so it IS the authentication here: a probe, never a template.
# Run with `just debug-vm-probe pam-command`.
{ pkgs, ... }:
let
  user = "alice";
  id = "${pkgs.coreutils}/bin/id";

  helper = pkgs.writeScript "pam-probe-helper" ''
    #!${pkgs.python3}/bin/python3
    import glob, os, time


    def say(text):
        print(f"probe {text}", flush=True)


    def argv(pid):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return f.read().rstrip(b"\0").split(b"\0")
        except OSError as error:
            return [f"unreadable: {error.strerror}".encode()]


    def show(pid):
        return b" ".join(argv(pid)).decode(errors="replace")


    def pkexec_lines():
        found = set()
        for path in glob.glob("/proc/[0-9]*"):
            words = argv(path.split("/")[2])
            if words and os.path.basename(words[0]) == b"pkexec":
                found.add(b" ".join(words).decode(errors="replace"))
        return found


    print("MATCH-CODE 4711", flush=True)
    # Scan for the whole wait, not once: of two overlapping requests the
    # first to finish may be gone when the other looks.
    seen_pkexec = set()
    for _ in range(40):
        seen_pkexec |= pkexec_lines()
        time.sleep(0.1)
    say(f"ids ruid={os.getuid()} euid={os.geteuid()}")
    for key in sorted(os.environ):
        say(f"env {key}={os.environ[key]}")
    pid = os.getppid()
    while pid > 1:
        say(f"ancestor {pid}: {show(pid)}")
        with open(f"/proc/{pid}/stat") as f:
            pid = int(f.read().rsplit(")", 1)[1].split()[1])
    for line in sorted(seen_pkexec | pkexec_lines()):
        say(f"visible-pkexec {line}")
    say("done")
  '';

  inherit (import ./pam-probe-lib.nix { inherit pkgs; }) viaTtyAgent;

  # Runs argv on a fresh pty and prints each line with its arrival time.
  onPty = pkgs.writeScript "pam-probe-pty" ''
    #!${pkgs.python3}/bin/python3
    import os, pty, select, signal, sys, time

    start = time.monotonic()
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.argv[1], sys.argv[1:])
    pending = b""
    while time.monotonic() - start < 60:
        if not select.select([fd], [], [], 1)[0]:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        pending += chunk
        *lines, pending = pending.split(b"\n")
        for line in lines:
            text = line.decode(errors="replace").rstrip("\r")
            print(f"{time.monotonic() - start:6.2f} {text}", flush=True)
    else:
        os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    print(f"exit {os.waitstatus_to_exitcode(status)}")
  '';
in
{
  nodes.machine =
    { config, ... }:
    let
      probeRule = service: {
        rules.auth.pam-probe = {
          order = config.security.pam.services.${service}.rules.auth.unix.order - 10;
          control = "sufficient";
          modulePath = "${config.security.pam.package}/lib/security/pam_exec.so";
          args = [
            "stdout"
            "quiet"
            "${helper}"
          ];
        };
      };
    in
    {
      security.polkit.enable = true;
      security.polkit.enablePkexecWrapper = true;
      security.sudo.enable = true;
      security.pam.services.polkit-1 = probeRule "polkit-1";
      security.pam.services.sudo = probeRule "sudo";
      users.users.${user} = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
      };
    };

  testScript = ''
    import re

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("polkit-agent-helper.socket")
    run = "${pkgs.util-linux}/bin/runuser -u ${user} -- ${onPty}"


    def report(label, output):
        print(f"=== PROBE {label} ===\n{output}=== END {label} ===")
        return output


    def arrival(output, needle):
        for line in output.splitlines():
            if needle in line:
                return float(line.split()[0])
        raise Exception(f"no {needle!r} in:\n{output}")


    def check_code_arrived_early(output):
        code = arrival(output, "MATCH-CODE 4711")
        done = arrival(output, "probe done")
        print(f"=== PROBE code at {code}s, helper done at {done}s ===")
        assert done - code >= 3, output


    with subtest("pkexec through its own textual agent"):
        # Fails after the PAM stack approved: polkitd, "No session for cookie".
        out = report("pkexec, internal agent", machine.succeed(f"{run} /run/wrappers/bin/pkexec ${id} -u"))
        check_code_arrived_early(out)
        assert "AUTHENTICATION FAILED" in out and "exit 127" in out, out
        machine.wait_until_succeeds("journalctl --no-pager | grep -q 'No session for cookie'", timeout=30)

    with subtest("pkexec through pkttyagent, run as the user"):
        out = report("pkexec, pkttyagent", machine.succeed(f"{run} ${viaTtyAgent}"))
        check_code_arrived_early(out)
        assert "AUTHENTICATION COMPLETE" in out and "exit 0" in out, out
        assert "probe ids ruid=0 euid=0" in out, out
        assert "probe env PAM_TTY=" not in out, out
        parents = re.findall(r"probe ancestor \d+: (.*)", out)
        assert len(parents) == 1 and "polkit-agent-helper-1" in parents[0], parents

    with subtest("sudo"):
        out = report("sudo", machine.succeed(f"{run} /run/wrappers/bin/sudo ${id} -u"))
        check_code_arrived_early(out)
        assert "exit 0" in out, out
        assert "probe ids ruid=1000 euid=0" in out, out
        assert "probe env PAM_TTY=" in out, out
        parent = re.findall(r"probe ancestor \d+: (.*)", out)[0].strip()
        assert re.search(r"/bin/sudo \S*/bin/id -u$", parent), parent

    with subtest("two pkexec requests at once"):
        machine.execute(
            f"{run} /run/wrappers/bin/pkexec ${id} -g >/tmp/other.log 2>&1 &"
        )
        out = report("pkexec A, overlapping", machine.succeed(f"{run} /run/wrappers/bin/pkexec ${id} -u"))
        machine.wait_until_succeeds("grep -q '^exit ' /tmp/other.log", timeout=60)
        other = report("pkexec B, overlapping", machine.succeed("cat /tmp/other.log"))
        for label, output in (("A", out), ("B", other)):
            seen = {line.strip() for line in re.findall(r"probe visible-pkexec (.*)", output)}
            assert len(seen) == 2, (label, seen)
  '';
}
