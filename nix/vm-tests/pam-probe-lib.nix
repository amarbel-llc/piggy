# TODO(#408): guest scripts the pam_piggy probes share. Goes when they do.
{ pkgs }:
{
  # Connects to the polkit helper socket, which starts one instance of
  # polkit-agent-helper@.service, and prints what the unit sends.
  activate = pkgs.writeScript "pam-probe-activate" ''
    #!${pkgs.python3}/bin/python3
    import socket

    client = socket.socket(socket.AF_UNIX)
    client.settimeout(60)
    client.connect("/run/polkit/agent-helper.socket")
    while chunk := client.recv(4096):
        print(chunk.decode(), end="")
  '';

  # pkttyagent (an ordinary process of the user) as the agent for this
  # shell: pkexec asks for authorization on behalf of its PARENT, so the
  # shell must stay and run pkexec as a child.
  viaTtyAgent = pkgs.writeShellScript "pam-probe-via-pkttyagent" ''
    dir=$(${pkgs.coreutils}/bin/mktemp -d)
    ${pkgs.coreutils}/bin/mkfifo "$dir/ready"
    /run/current-system/sw/bin/pkttyagent --process $$ --notify-fd 3 3>"$dir/ready" &
    agent=$!
    # The agent closes the fd once it is registered, which ends the read.
    ${pkgs.coreutils}/bin/cat "$dir/ready"
    ${pkgs.coreutils}/bin/rm -r "$dir"
    /run/wrappers/bin/pkexec --disable-internal-agent ${pkgs.coreutils}/bin/id -u
    status=$?
    kill $agent
    exit $status
  '';
}
