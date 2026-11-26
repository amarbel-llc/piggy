# TODO(#408): the pam_piggy design probes. Design experiments, no part of
# the merge gate, so they are kept apart from default.nix and its lanes.
# Run one with `just debug-vm-probe NAME`, NAME being the attribute
# without `vm-probe-`.
{ pkgs, piggy }:
pkgs.mkVmChecks {
  # The agent socket paths the polkit helper sandbox reaches.
  tests.vm-probe-pam-sandbox = import ./pam-sandbox-probe.nix;
  # What a pam_exec helper sees and shows under pkexec and sudo.
  tests.vm-probe-pam-command = import ./pam-command-visibility-probe.nix;
  # pkexec's agents with the stock PAM stack and a password.
  tests.vm-probe-pkexec-password = import ./pam-pkexec-password-probe.nix;
  # The moved agent socket, its link and the fallback.
  tests.vm-probe-pam-socket-move = import ./pam-socket-move-probe.nix { inherit piggy; };
  # The sudo pilot's setup with a stand-in pam_exec helper.
  tests.vm-probe-pam-sudo = import ./pam-sudo-probe.nix { inherit piggy; };
  # A sudo approval plugin, and approving only what root can change.
  tests.vm-probe-pam-sudo-approval = import ./pam-sudo-approval-probe.nix;
}
