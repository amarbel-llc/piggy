# The piggy SSH agent, multiplexed, against a real sshd.
#
# Two agent shapes stacked in one guest (FDR 0001, piggy#215):
#
#   soft-ssh-agent   stock OpenSSH ssh-agent holding an ed25519 key
#   piggy-agent      card-backed (fibby 9A + 9D) AND proxies `soft` as an
#                    upstream, routes ssh-add there  — the workstation shape
#   piggy-front      --proxy-only over upstreams piv=piggy-agent and soft
#                    — the remote-host shape, one socket fronting both
#
# The testScript proves the merged listing order, that a sign through the
# front lands on the right backend (card vs software), that a real sshd
# accepts a login with either key via the front, that `ssh -A` forwards
# the front so a remote `pass show` decrypts through it, and that a dead
# upstream degrades the listing instead of breaking it.
{
  common,
  bootstrap,
  piggy,
  askpass,
}:
{ pkgs, lib, ... }:
let
  softSock = "/run/upstream/agent.sock";
  pivSock = "/run/piggy/agent.sock";
  frontSock = "/run/piggy-front/agent.sock";
in
{
  name = "piggy-vm-agent";
  inherit (common) requiredFeatures globalTimeout defaults;
  nodes.machine = {
    services.openssh = {
      enable = true;
      settings.PermitRootLogin = "prohibit-password";
    };

    # Same user as piggy-agent: ssh-agent refuses peers with another uid
    # (root excepted), and the card agent must be able to proxy into it.
    systemd.services.soft-ssh-agent = {
      description = "stock ssh-agent, the software upstream";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        User = "piggy-agent";
        Group = "piggy-agent";
        RuntimeDirectory = "upstream";
        RuntimeDirectoryMode = "0755";
        ExecStart = "${pkgs.openssh}/bin/ssh-agent -D -a ${softSock}";
      };
    };

    systemd.services.piggy-agent = {
      wants = [ "soft-ssh-agent.service" ];
      after = [ "soft-ssh-agent.service" ];
    };

    systemd.services.piggy-front = {
      description = "piggy agent --proxy-only front over the card agent and ssh-agent";
      wantedBy = [ "multi-user.target" ];
      requires = [ "piggy-agent.service" ];
      after = [
        "piggy-agent.service"
        "soft-ssh-agent.service"
      ];
      serviceConfig = {
        Type = "simple";
        User = "piggy-agent";
        Group = "piggy-agent";
        RuntimeDirectory = "piggy-front";
        RuntimeDirectoryMode = "0755";
        ExecStart = lib.concatStringsSep " " [
          "${piggy}/bin/piggy"
          "agent"
          "--proxy-only"
          "-a"
          frontSock
          "--upstream"
          "piv=${pivSock}"
          "--upstream"
          "soft=${softSock}"
          "--add-new-keys-to"
          "soft"
          "--service-name"
          "piggy-front.service"
        ];
        Environment = [
          "HOME=/run/piggy-front"
          "XDG_CACHE_HOME=/run/piggy-front/cache"
        ];
      };
    };
  };

  testScript =
    bootstrap {
      secretName = "agent/test";
      nativeKeys = 2;
    }
    + ''
      SOFT = "${softSock}"
      PIV = "${pivSock}"
      FRONT = "${frontSock}"
      SSH = (
          "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o IdentitiesOnly=yes -o BatchMode=yes"
      )

      machine.wait_for_unit("soft-ssh-agent.service")
      machine.wait_for_unit("piggy-front.service")
      machine.wait_for_unit("sshd.service")
      machine.wait_for_file(SOFT)
      machine.wait_for_file(FRONT)
      machine.wait_for_open_port(22)


      def listing(sock):
          return machine.succeed(f"SSH_AUTH_SOCK={sock} ssh-add -L").strip().splitlines()


      def ecdsa_9a_count():
          out = machine.succeed("journalctl -u fibby --no-pager -o cat || true")
          return out.count("GA ECDSA 9A -> 9000")


      def sign_and_verify(sock, pubfile, ident):
          data = f"/root/payload-{ident}"
          machine.succeed(f"echo payload-{ident} > {data}")
          machine.succeed(
              f"read -r t k _ < {pubfile}; printf '%s %s %s\\n' {ident} \"$t\" \"$k\" > {data}.signers"
          )
          machine.succeed(f"SSH_AUTH_SOCK={sock} ssh-keygen -Y sign -f {pubfile} -U -n file {data}")
          machine.succeed(
              f"ssh-keygen -Y verify -f {data}.signers -I {ident} -n file -s {data}.sig < {data}"
          )


      with subtest("ssh-add through the card agent lands in the designated software upstream"):
          machine.succeed('ssh-keygen -t ed25519 -N "" -q -C soft-upstream-key -f /root/softkey')
          machine.succeed(f"SSH_AUTH_SOCK={PIV} ssh-add -q /root/softkey")
          soft = listing(SOFT)
          assert len(soft) == 1 and soft[0].endswith(" soft-upstream-key"), soft

      with subtest("merged listing: native PIV keys first, software key after; the front mirrors it"):
          piv = listing(PIV)
          assert [l.split()[0] for l in piv] == [
              "ecdsa-sha2-nistp256",
              "ecdsa-sha2-nistp256",
              "ssh-ed25519",
          ], piv
          assert piv[2].endswith(" soft-upstream-key"), piv
          front = listing(FRONT)
          assert front == piv, (front, piv)
          id9a = [l for l in piv if " PIV_slot_9A " in l]
          assert len(id9a) == 1, piv
          machine.succeed(f"printf '%s\\n' '{id9a[0]}' > /root/id9a.pub")

      with subtest("sign via the front: PIV key reaches the card, software key does not"):
          n0 = ecdsa_9a_count()
          sign_and_verify(FRONT, "/root/id9a.pub", "native@fibby")
          assert ecdsa_9a_count() == n0 + 1, "native sign did not hit fibby's slot 9A exactly once"
          sign_and_verify(FRONT, "/root/softkey.pub", "soft@upstream")
          assert ecdsa_9a_count() == n0 + 1, "routed software sign touched the card"

      with subtest("sshd accepts a login with either key offered by the front"):
          machine.succeed("mkdir -p -m 700 /root/.ssh")
          machine.succeed(f"SSH_AUTH_SOCK={FRONT} ssh-add -L > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys")
          n0 = ecdsa_9a_count()
          machine.succeed(f"SSH_AUTH_SOCK={FRONT} {SSH} -i /root/id9a.pub root@localhost true")
          assert ecdsa_9a_count() == n0 + 1, "PIV login did not sign on the card exactly once"
          machine.succeed(f"SSH_AUTH_SOCK={FRONT} {SSH} -i /root/softkey.pub root@localhost true")
          assert ecdsa_9a_count() == n0 + 1, "software-key login touched the card"

      with subtest("ssh -A forwards the front: a remote pass show decrypts through it"):
          n0 = ecdh_count()
          remote = (
              "PIGGY_STORE_DIR=/root/store "
              "SSH_ASKPASS=${askpass} SSH_ASKPASS_REQUIRE=force DISPLAY= "
              # Absolute paths: a non-interactive sshd command shell has no
              # guaranteed PATH.
              "${piggy}/bin/piggy pass show agent/test | ${pkgs.coreutils}/bin/head -n1"
          )
          out = machine.succeed(
              f"SSH_AUTH_SOCK={FRONT} {SSH} -A -i /root/softkey.pub root@localhost '{remote}'"
          ).strip()
          assert out == secret, (out, secret)
          assert ecdh_count() == n0 + 1, "forwarded decrypt did not perform exactly one slot-9D ECDH"

      with subtest("a dead software upstream degrades the front to the PIV keys"):
          machine.succeed("systemctl stop soft-ssh-agent.service")
          front = listing(FRONT)
          assert [l.split()[0] for l in front] == ["ecdsa-sha2-nistp256"] * 2, front
          machine.succeed("systemctl start soft-ssh-agent.service")
          machine.wait_for_file(SOFT)
    '';
}
