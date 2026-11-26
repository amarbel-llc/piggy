# TODO(#408): the pam_piggy design probes. Design experiments, no part of
# the merge gate, so they are kept apart from default.nix and its lanes.
# Run one with `just debug-vm-probe NAME`.
{ pkgs, piggy }:
pkgs.mkVmChecks {
  tests.vm-probe-pam-sandbox = import ./pam-sandbox-probe.nix;
  tests.vm-probe-pam-command = import ./pam-command-visibility-probe.nix;
  tests.vm-probe-pkexec-password = import ./pam-pkexec-password-probe.nix;
  tests.vm-probe-pam-socket-move = import ./pam-socket-move-probe.nix { inherit piggy; };
}
