# NixOS module for the VM lane's guest: fibby (the pure-Rust virtual PIV
# card) and the Rust `piggy agent` as system units, wired the way the
# fibby conformance bats lanes wire them (zz-tests_bats/lib/fibby.bash),
# but under systemd instead of a bats setup() shell.
#
# Nothing here is a production deployment shape: the operator's real
# agents come from nix/hm/piggy-agent.nix. This module exists so a
# testScript can drive the shipped `piggy` package end to end against a
# card that needs no hardware and no pcscd.
{
  pkgs,
  piggy,
  fibby,
  askpass,
}:
{ lib, ... }:
let
  fibbySock = "/run/fibby/pcscd.comm";
  agentSock = "/run/piggy/agent.sock";

  # The agent tolerates a cold PC/SC (its reconcile loop adopts the card
  # once fibby answers), but a deterministic first `ssh-add -L` is worth
  # the 30s cap.
  waitForFibby = pkgs.writeShellScript "wait-for-fibby" ''
    for _ in $(seq 1 150); do
      [ -S ${fibbySock} ] && exit 0
      sleep 0.2
    done
    echo "fibby socket ${fibbySock} never appeared" >&2
    exit 1
  '';
in
{
  # fibby IS the pcsc-lite server; the system pcscd must not compete for
  # the same client library.
  services.pcscd.enable = lib.mkForce false;

  users.users.piggy-agent = {
    isSystemUser = true;
    group = "piggy-agent";
  };
  users.groups.piggy-agent = { };

  systemd.services.fibby = {
    description = "fibby virtual PIV card (pcsc-lite protocol on AF_UNIX)";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      DynamicUser = true;
      RuntimeDirectory = "fibby";
      RuntimeDirectoryMode = "0755";
      # --seed-rfc5903-slot-9d-cert installs the RFC 5903 §8.1 P-256 key
      # in slot 9D (plus CHUID), the same seed the conformance lanes use.
      ExecStart = "${fibby}/bin/fibby --socket ${fibbySock} --backend virtual --seed-rfc5903-slot-9d-cert";
      # `wire` puts the APDU trace in the journal so the testScript can
      # assert `GA ECDH 9D -> 9000` the way the bats lanes grep FIBBY_LOG.
      Environment = [ "FIBBY_LOG=wire" ];
    };
  };

  systemd.services.piggy-agent = {
    description = "piggy agent (Rust PIV SSH agent) over fibby";
    wantedBy = [ "multi-user.target" ];
    requires = [ "fibby.service" ];
    after = [ "fibby.service" ];
    serviceConfig = {
      Type = "simple";
      User = "piggy-agent";
      Group = "piggy-agent";
      RuntimeDirectory = "piggy";
      RuntimeDirectoryMode = "0755";
      ExecStartPre = waitForFibby;
      ExecStart = "${piggy}/bin/piggy agent -A -a ${agentSock}";
      Environment = [
        "PCSCLITE_CSOCK_NAME=${fibbySock}"
        # The test-harness askpass: supplies PIGGY_TEST_FIB_PIN, or refuses
        # loudly. Never a real prompt (piggy#35).
        "SSH_ASKPASS=${askpass}"
        "SSH_ASKPASS_REQUIRE=force"
        "DISPLAY="
        "PIGGY_TEST_FIB_PIN=123456"
        # Shared code reached from the agent wants a cache dir.
        "HOME=/run/piggy"
        "XDG_CACHE_HOME=/run/piggy/cache"
      ];
    };
  };
}
