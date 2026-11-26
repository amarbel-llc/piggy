# TODO(#408): a probe for the pam_piggy design, not a gate. The control
# for pam-command-visibility-probe.nix: with the STOCK polkit-1 PAM stack
# (a typed password, none of our helper), does pkexec's built-in textual
# agent still end "No session for cookie" where pkttyagent succeeds?
# Run with `just debug-vm-probe pkexec-password`.
{ pkgs, ... }:
let
  user = "alice";
  password = "piggy-test-not-a-secret";
  id = "${pkgs.coreutils}/bin/id";

  # Runs argv on a pty and types the guest user's password when asked.
  onPty = pkgs.writeScript "pam-probe-pty-password" ''
    #!${pkgs.python3}/bin/python3
    import os, pty, select, signal, sys, time

    start = time.monotonic()
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.argv[1], sys.argv[1:])
    seen = b""
    typed = False
    while time.monotonic() - start < 60:
        if not select.select([fd], [], [], 1)[0]:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        seen += chunk
        if not typed and b"Password:" in seen:
            time.sleep(0.5)
            os.write(fd, b"${password}\n")
            typed = True
    else:
        os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    print(seen.decode(errors="replace").replace("\r", ""))
    print(f"typed={typed} exit {os.waitstatus_to_exitcode(status)}")
  '';

  inherit (import ./pam-probe-lib.nix { inherit pkgs; }) viaTtyAgent;
in
{
  nodes.machine = {
    security.polkit.enable = true;
    security.polkit.enablePkexecWrapper = true;
    users.users.${user} = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      inherit password;
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


    stack = report("stack", machine.succeed("grep '^auth' /etc/pam.d/polkit-1"))
    assert "pam_unix.so" in stack and "pam_exec.so" not in stack, stack

    with subtest("control: pkttyagent with a password"):
        out = report("pkttyagent", machine.succeed(f"{run} ${viaTtyAgent}"))
        assert "typed=True exit 0" in out, out

    with subtest("pkexec's own textual agent with a password"):
        for attempt in (1, 2, 3):
            out = report(
                f"internal agent, attempt {attempt}",
                machine.succeed(f"{run} /run/wrappers/bin/pkexec ${id} -u"),
            )
            assert "typed=True exit 127" in out and "AUTHENTICATION FAILED" in out, out

    # The instance names end in the uid that connected to the helper.
    # Each unit's own "Failed" line lands after polkitd's answer.
    machine.wait_until_succeeds(
        "test $(journalctl --no-pager | grep -c -- '-0\\.service: Failed') -ge 3", timeout=30
    )
    machine.succeed("test $(journalctl --no-pager | grep -c 'No session for cookie') -ge 3")
    journal = report(
        "journal",
        machine.succeed(
            "journalctl --no-pager | grep -E 'polkit-agent-helper(@|-1)' | cut -c1-260"
        ),
    )
    assert re.search(r"-1000\.service: Deactivated successfully", journal), journal
  '';
}
