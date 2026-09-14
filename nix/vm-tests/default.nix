# NixOS VM integration lane, on igloo's `pkgs.mkVmChecks` (FDR 0011,
# vm-tests(7)): piggy's lanes were the reference implementation the
# library was lifted from, and are its first consumer.
#
# Boots a NixOS guest carrying the shipped `piggy` package, runs fibby
# and the Rust `piggy agent` as systemd units (./piggy-stack.nix), builds
# a password store against the virtual card, and then:
#
#   ./luks.nix   unlocks a LUKS2 volume from a store secret
#   ./zfs.nix    keys a ZFS native-encryption dataset from a store secret
#   ./agent.nix  fronts the card agent with a stock ssh-agent upstream and
#                a --proxy-only front (FDR 0001 / piggy#215), logs into a
#                real sshd with both keys, and decrypts over `ssh -A`
#
# It is the harness the Rust `piggy luks` / `piggy zfs` ports and the
# C-pivy retirement are gated on
# (docs/plans/2026-09-14-retire-c-pivy-rust-nix-migration.md), and the
# first end-to-end validation of the closure on a real NixOS system.
#
# mkVmChecks supplies the Linux-only guard (`{ }` elsewhere), the no-KVM
# declaration (host flac has no /dev/kvm; the guest runs under TCG), and
# the TCG sizing. Measured 2026-09-14: 2-3 minutes per lane.
#
# coverage = true runs the SAME lanes on an instrumented piggy (pass the
# `piggy-cov` variant): every guest piggy process writes an LLVM
# .profraw into /coverage, the agent units are stopped cleanly at the
# end so they flush, and the directory is copied into the test's $out
# for ./coverage-report.nix to merge. fibby is left uninstrumented
# (test infrastructure; no SIGTERM handler to flush on).
{
  pkgs,
  piggy,
  fibby,
  coverage ? false,
}:
let
  # The bats safety-net askpass, re-homed into the store. writeShellScript
  # supplies its own shebang; the file's `#!/usr/bin/env bash` line
  # becomes a comment.
  askpass = pkgs.writeShellScript "piggy-test-askpass" (
    builtins.readFile ../../zz-tests_bats/helpers/piggy-test-askpass.sh
  );

  # systemd expands %p/%m in Environment= lines; %% is a literal %. The
  # shell-side spelling (testScript ENV) uses single percents.
  profilePatternUnit = "/coverage/%%p-%%m.profraw";
  profilePatternShell = "/coverage/%p-%m.profraw";
  coverageEnvUnit = pkgs.lib.optionals coverage [ "LLVM_PROFILE_FILE=${profilePatternUnit}" ];
  coverageEnvShell = pkgs.lib.optionalString coverage "LLVM_PROFILE_FILE=${profilePatternShell} ";

  # The per-lane stack module (card seeds, agent flags differ per lane).
  mkStack =
    stackArgs:
    import ./piggy-stack.nix (
      {
        inherit
          pkgs
          piggy
          fibby
          askpass
          ;
        extraEnvironment = coverageEnvUnit;
      }
      // stackArgs
    );

  # Node settings every lane shares (mkVmChecks adds memory/cores).
  sharedNode = {
    # /dev/vdb: a real block device for cryptsetup / zpool, without
    # depending on the loop module.
    virtualisation.emptyDiskImages = [ 512 ];
    environment.systemPackages = [
      piggy
      pkgs.cryptsetup
      pkgs.e2fsprogs
      pkgs.openssh
      pkgs.util-linux
    ];
    # Under TCG on a loaded host the early-boot IO-APIC timer
    # calibration can miss its window and the guest panics with
    # "IO-APIC + timer doesn't work!" (seen 2026-09-14 at host load
    # ~26 with three guests and an instrumented cargo build running).
    # The check guards against broken real hardware; a qemu guest
    # does not need it.
    boot.kernelParams = [ "no_timer_check" ];
    # World-writable: the daemons run as piggy-agent / DynamicUser and
    # the backdoor shell as root all write profiles here.
    systemd.tmpfiles.rules = pkgs.lib.optionals coverage [ "d /coverage 1777 root root -" ];
  };

  # Shared testScript prefix: units up, the seeded key(s) visible through
  # the agent, a store initialised against the card, one generated
  # secret that decrypts through agent -> askpass -> fibby.
  bootstrap = import ./store-bootstrap.nix {
    inherit askpass;
    prelude = pkgs.vmTestPrelude;
    extraEnv = coverageEnvShell;
  };

  # Stop the instrumented daemons cleanly (the LLVM profile runtime
  # writes at exit) and ship /coverage to $out/coverage. Units that a
  # lane did not define are ignored.
  coverageEpilogue = ''

    with subtest("collect coverage profiles"):
        machine.succeed("systemctl stop piggy-front.service 2>/dev/null || true")
        machine.succeed("systemctl stop piggy-agent.service fibby.service")
        machine.succeed("ls /coverage/*.profraw")
        copy_out = getattr(machine, "copy_from_machine", None) or machine.copy_from_vm
        copy_out("/coverage", "")
  '';

  # The module system injects only the arguments a module function
  # declares (lib.functionArgs), so the wrapper must advertise the lane's
  # own argument set or `pkgs`/`lib` stop arriving.
  withCoverage =
    laneModule:
    if !coverage then
      laneModule
    else
      pkgs.lib.setFunctionArgs (
        args:
        let
          m = laneModule args;
        in
        m // { testScript = m.testScript + coverageEpilogue; }
      ) (pkgs.lib.functionArgs laneModule);

  lane =
    { module, stack }:
    {
      imports = [ (withCoverage module) ];
      defaults.imports = [ stack ];
    };
in
pkgs.mkVmChecks {
  defaults = sharedNode;
  tests = {
    vm-piggy-luks = lane {
      module = import ./luks.nix { inherit bootstrap; };
      stack = mkStack { };
    };
    vm-piggy-zfs = lane {
      module = import ./zfs.nix { inherit bootstrap; };
      stack = mkStack { };
    };
    vm-piggy-agent = lane {
      module = import ./agent.nix {
        inherit
          bootstrap
          piggy
          askpass
          ;
        frontExtraEnvironment = coverageEnvUnit;
        remoteExtraEnv = coverageEnvShell;
      };
      stack = mkStack {
        # 9A for SSH auth + 9D for the store decrypt, both on one card.
        fibbySeedArgs = [
          "--seed-rfc6979-slot-9a-cert"
          "--seed-rfc5903-slot-9d-cert"
        ];
        # Workstation shape (piggy#215): card-backed agent that also
        # proxies a software ssh-agent and routes ssh-add there.
        agentExtraArgs = [
          "--upstream"
          "soft=/run/upstream/agent.sock"
          "--add-new-keys-to"
          "soft"
        ];
      };
    };
  };
}
