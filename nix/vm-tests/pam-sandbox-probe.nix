# TODO(#408): a probe for the pam_piggy design, not a gate: which agent
# socket locations can a PAM module reach from inside the sandbox of
# polkit-agent-helper@.service? The guest's REAL helper unit is socket
# activated with only its ExecStart replaced, so whatever sandbox the
# pinned polkit and NixOS give it applies. Listeners run as an ordinary
# user. It asserts the matrix FDR 0010 states, so a changed sandbox fails
# it. Delete it with the other probes, as FDR 0010 says.
# Run with `just debug-vm-probe pam-sandbox`.
{ pkgs, lib, ... }:
let
  user = "alice";
  uid = 1000;
  homeDir = "/home/${user}/.local/state/piggy";
  sockets = [
    "${homeDir}/agent.sock"
    "/run/user/${toString uid}/piggy-agent.sock"
    "/tmp/piggy-probe/agent.sock"
    "/var/tmp/piggy-probe/agent.sock"
    "/run/piggy-probe/agent.sock"
    "/var/lib/piggy-probe/agent.sock"
  ];

  listener = pkgs.writeScript "pam-probe-listener" ''
    #!${pkgs.python3}/bin/python3
    import os, selectors, socket, sys

    selector = selectors.DefaultSelector()
    for path in sys.argv[1:]:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        server = socket.socket(socket.AF_UNIX)
        server.bind(path)
        server.listen()
        selector.register(server, selectors.EVENT_READ)
    open("/home/${user}/listening", "w").close()
    while True:
        for key, _ in selector.select():
            connection, _ = key.fileobj.accept()
            connection.sendall(b"hello")
            connection.close()
  '';

  # Connects to every socket and prints one line each. Under the helper
  # unit its stdout is the activating connection.
  probe = pkgs.writeScript "pam-probe-connect" ''
    #!${pkgs.python3}/bin/python3
    import errno, os, socket

    print(f"uid={os.getuid()} SSH_AUTH_SOCK={os.environ.get('SSH_AUTH_SOCK')}")
    for path in "${lib.concatStringsSep " " sockets}".split():
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(5)
        try:
            client.connect(path)
            result = "OK " + client.recv(16).decode()
        except OSError as error:
            result = "FAIL " + errno.errorcode.get(error.errno or 0, str(error))
        print(f"{path}: {result}")
        client.close()
  '';

  inherit (import ./pam-probe-lib.nix { inherit pkgs; }) activate;

  # Drop-ins layered on the real unit, one variant at a time.
  variants = {
    bind = [ "BindReadOnlyPaths=${homeDir}" ];
    tmpfs-bind = [
      "ProtectHome=tmpfs"
      "BindReadOnlyPaths=${homeDir}"
    ];
    tmpfs-bind-run-user = [
      "ProtectHome=tmpfs"
      "BindReadOnlyPaths=/run/user/${toString uid}"
    ];
  };
  dropIn =
    name: lines:
    pkgs.writeText "pam-probe-${name}.conf" (
      lib.concatStringsSep "\n" ([ "[Service]" ] ++ lines) + "\n"
    );
in
{
  nodes.machine = {
    security.polkit.enable = true;
    users.users.${user} = {
      isNormalUser = true;
      inherit uid;
      linger = true;
    };
    systemd.tmpfiles.rules = [
      "d /run/piggy-probe 0700 ${user} users -"
      "d /var/lib/piggy-probe 0700 ${user} users -"
    ];
    systemd.services."polkit-agent-helper@".serviceConfig.ExecStart = [
      ""
      "${probe}"
    ];
    systemd.services.pam-probe-listener = {
      wantedBy = [ "multi-user.target" ];
      wants = [ "user@${toString uid}.service" ];
      after = [ "user@${toString uid}.service" ];
      serviceConfig = {
        User = user;
        ExecStart = "${listener} ${lib.concatStringsSep " " sockets}";
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("pam-probe-listener.service")
    machine.wait_for_file("/home/${user}/listening")
    machine.wait_for_unit("polkit-agent-helper.socket")


    def report(label, command):
        output = machine.succeed(command)
        print(f"=== PROBE {label} ===\n{output}=== END {label} ===")
        return output


    report("unit", "systemctl cat 'polkit-agent-helper@.service'")

    control = report("control: unsandboxed root", "${probe}")
    assert control.count(": OK hello") == ${toString (builtins.length sockets)}, control

    sockets = "${lib.concatStringsSep " " sockets}".split()
    home, run_user, _, _, run, var_lib = sockets


    def expect(label, output, reachable):
        assert "uid=0 SSH_AUTH_SOCK=None" in output, (label, output)
        for path in sockets:
            want = "OK hello" if path in reachable else "FAIL ENOENT"
            assert f"{path}: {want}\n" in output, (label, path, want, output)


    expected = {
        "bind": [run, var_lib],
        "tmpfs-bind": [home, run, var_lib],
        "tmpfs-bind-run-user": [run_user, run, var_lib],
    }
    baseline = report("baseline: the real helper unit", "${activate}")
    expect("baseline", baseline, [run, var_lib])

    dropin_dir = "/run/systemd/system/polkit-agent-helper@.service.d"
    machine.succeed(f"mkdir -p {dropin_dir}")
    for name, source in [
    ${
      lib.concatStrings (
        lib.mapAttrsToList (name: lines: ''
          ("${name}", "${dropIn name lines}"),
        '') variants
      )
    }]:
        machine.succeed(f"cp {source} {dropin_dir}/zz-probe.conf")
        machine.succeed("systemctl daemon-reload")
        output = report(f"variant {name}", "${activate}")
        expect(name, output, expected[name])
  '';
}
