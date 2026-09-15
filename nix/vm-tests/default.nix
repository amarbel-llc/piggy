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
# declaration (the build host has no /dev/kvm; the guest runs under TCG), and
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

  # The test-harness askpass discipline, identical for every process that
  # could prompt: supplies PIGGY_TEST_FIB_PIN or refuses loudly, never a
  # real prompt (piggy#35). DISPLAY is blanked because the backdoor shell
  # exports DISPLAY=:0.0.
  askpassEnv = [
    "SSH_ASKPASS=${askpass}"
    "SSH_ASKPASS_REQUIRE=force"
    "DISPLAY="
    "PIGGY_TEST_FIB_PIN=123456"
  ];
  # systemd expands %p/%m in Environment= lines; %% is a literal %. The
  # shell-side spelling uses single percents.
  coverageEnvUnit = pkgs.lib.optionals coverage [ "LLVM_PROFILE_FILE=/coverage/%%p-%%m.profraw" ];
  coverageEnvShell = pkgs.lib.optionals coverage [ "LLVM_PROFILE_FILE=/coverage/%p-%m.profraw" ];
  # One list per consumer shape: systemd Environment= entries, and the
  # `VAR=value ` prefix words a shell command line takes.
  unitEnv = askpassEnv ++ coverageEnvUnit;
  shellEnv = pkgs.lib.concatMapStrings (kv: "${kv} ") (askpassEnv ++ coverageEnvShell);

  # The per-lane stack module (card seeds, agent flags differ per lane).
  mkStack =
    stackArgs:
    import ./piggy-stack.nix (
      {
        inherit pkgs piggy fibby;
        extraEnvironment = unitEnv;
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
    # `no_timer_check` (the IO-APIC timer panic under TCG on a loaded
    # host, seen 2026-09-14) is mkVmChecks' no-KVM default since igloo
    # 2a6e42d (piggy#267), so it is no longer set here.
    #
    # fibby at FIBBY_LOG=wire logs every APDU hexdump line; journald's
    # default per-service rate limit (10000 msgs / 30s) could suppress
    # a burst and swallow the `GA … -> 9000` lines the asserts count.
    services.journald.extraConfig = "RateLimitIntervalSec=0";
    # World-writable: the daemons run as piggy-agent / DynamicUser and
    # the backdoor shell as root all write profiles here.
    systemd.tmpfiles.rules = pkgs.lib.optionals coverage [ "d /coverage 1777 root root -" ];
  };

  # Shared testScript prefix: units up, the seeded key(s) visible through
  # the agent, a store initialised against the card, one generated
  # secret that decrypts through agent -> askpass -> fibby.
  bootstrap = import ./store-bootstrap.nix {
    prelude = pkgs.vmTestPrelude;
    extraEnv = shellEnv;
  };

  # Stop the instrumented daemons cleanly (the LLVM profile runtime
  # writes at exit) and ship /coverage to $out/coverage. Each
  # instrumented daemon that was running must have left a profile named
  # by its own PID: the short-lived `piggy pass` processes always leave
  # profraws, so `ls /coverage/*.profraw` alone would hide a daemon that
  # got SIGKILLed past its stop timeout and never flushed. Units a lane
  # did not define are skipped.
  coverageEpilogue = ''

    with subtest("collect coverage profiles"):
        for unit in ["piggy-front.service", "piggy-agent.service"]:
            active, _ = machine.execute(f"systemctl is-active --quiet {unit}")
            if active != 0:
                continue
            pid = machine.succeed(f"systemctl show -p MainPID --value {unit}").strip()
            machine.succeed(f"systemctl stop {unit}")
            machine.succeed(f"ls /coverage/{pid}-*.profraw")
        machine.succeed("systemctl stop fibby.service")
        machine.copy_from_machine("/coverage", "")
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
        inherit bootstrap piggy;
        frontExtraEnvironment = unitEnv;
        remoteExtraEnv = shellEnv;
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
