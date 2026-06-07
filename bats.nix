# bats integration test lanes for piggy.
#
# Wraps the `batsLane` builder exposed by amarbel-llc/bats at
# `bats.lib.${system}.batsLane` (NOT `pkgs.testers.batsLane` — the
# nixpkgs fork's thin overlay no longer ships that helper; the bats
# flake is the canonical source). Provides piggy-specific defaults:
# `bats-libs` from amarbel-llc/bats on `BATS_LIB_PATH`; the wrapped
# `piggy` derivation injected via the `binaries` map so the rust
# dispatcher is exercised end-to-end; and `PIGGY_IDS_REAL` pointed at
# the wrapped `$out/libexec/piggy/piggy-ids` so the same harness works
# inside the nix sandbox and in local `bats --no-sandbox` runs.
#
# Auto-discovers `# bats file_tags=foo,bar` directives at flake-eval
# time and produces one `bats-${tag}` derivation per unique tag plus
# `bats-default` (which filters with `!hardware` to exclude tests
# that need a real pcscd/PIV stack).
#
# Two scan roots: top-level `*.bats` plus `conformance/*.bats`. Both
# are passed as `testFiles` globs to batsLane so the staged tests run
# under the sandboxed lane; tests under `zz-tests_bats/explore/` are
# deliberately omitted (see piggy#115). Hardware-tagged tests in
# either root are filtered out of `bats-default` via the `!hardware`
# tag filter and remain invokable via the
# `just test-bats-conformance-*` recipes that hit real pcscd/cards.
{
  pkgs,
  batsLane,
  bats-libs,
  # The UNWRAPPED rust dispatcher (piggy-rs from flake.nix). Tests
  # need the unwrapped binary so that PATH overrides from
  # zz-tests_bats/helpers/ (mock-pivy-box.sh etc.) win over what
  # the rust handlers try to invoke; the wrapped piggy injects pivyPkg
  # + git via makeWrapper's `--prefix PATH`, which beats every prefix
  # the bats setup can add.
  piggyRs,
  # The WRAPPED piggy (piggy from flake.nix). Used only as a source of
  # `$out/libexec/piggy/piggy-ids` — the real piggy-ids binary the mock
  # delegator needs by absolute path.
  piggyWrapped,
  # The Go-based SSH-agent protocol conformance binary. Plumbed into
  # the lane as `CONFORMANCE_BIN` so
  # `conformance/piggy_agent_protocol.bats` can run under the
  # sandboxed lane instead of via `bats --no-sandbox` only.
  conformanceBin,
  # The C pivy package (pivyPkg in flake.nix). Threaded as
  # `REAL_PIVY_TOOL` so `conformance/pivy_tool_admin_key.bats` can
  # exercise its assertions against the lane-bundled pivy-tool rather
  # than skipping when `./result/bin/piggy` is absent (the sandbox has
  # no `result/` symlink). See piggy#116. Intentionally NOT on
  # `nativeBuildInputs` — the mock `pivy-tool` installed by
  # common.bash at the front of $PATH must still win for the other
  # tests; we hand the real binary in by absolute path instead.
  pivy,
  # batsSrc may be null when this file is imported outside a flake
  # context — `batsLaneOutputs` then returns `{ }` instead of crashing
  # in builtins.readDir. Matches madder's go/default.nix factoring.
  batsSrc ? null,
  batsTestTimeout ? "30",
}:
let
  inherit (pkgs) lib;

  mkBatsLane =
    {
      filter ? "!hardware",
      base ? piggyRs,
    }:
    batsLane {
      inherit base filter batsSrc;
      # Run the top-level `t*.bats` tests AND the non-hardware
      # conformance tests under the sandboxed lane. Hardware-tagged
      # tests in either root are filtered out at bats invocation time
      # via the `!hardware` filter (see piggy#115). The `explore/`
      # directory stays out of scope.
      testFiles = [
        "*.bats"
        "conformance/*.bats"
      ];
      binaries = {
        PIGGY = {
          inherit base;
          name = "piggy";
        };
        # CONFORMANCE_BIN drives the Go-based SSH-agent protocol
        # conformance test (conformance/piggy_agent_protocol.bats).
        # Before piggy#115 this binary was injected by the
        # `just test-bats-conformance-protocol` recipe via
        # `nix build .#piggy.tests.conformance`; now the same path is
        # reachable from the sandboxed lane too.
        CONFORMANCE_BIN = {
          base = conformanceBin;
          name = "piggy-agent-conformance";
        };
      };
      batsLibPath = [ bats-libs.batsLibPath ];
      extraEnv = {
        BATS_TEST_TIMEOUT = batsTestTimeout;
        # Pin against the wrapped piggy's libexec — that's where
        # `flake.nix` installs the piggy-ids binary. PIGGY_IDS_REAL
        # is consumed by mock-piggy-ids.sh for delegation.
        PIGGY_IDS_REAL = "${piggyWrapped}/libexec/piggy/piggy-ids";
        # The real C pivy-tool, used only by pivy_tool_admin_key.bats.
        # Matches the REAL_PIVY_BOX convention used by the interop
        # recipe (see justfile). See piggy#116.
        REAL_PIVY_TOOL = "${pivy}/bin/pivy-tool";
        # Deliberately do NOT export PIGGY_IDS_PATH: when unset, the
        # rust dispatcher falls through to `command -v piggy-ids`,
        # which resolves to the mock symlink in $BATS_TEST_TMPDIR
        # (placed at the front of $PATH by common.bash).
      };
      nativeBuildInputs = [
        # The bats helpers (mock-pivy-box.sh / mock-pivy-tool.sh /
        # mock-piggy-ids.sh) and the rust handlers' callouts shell out
        # to these directly; without them on PATH the sandboxed tests
        # get cryptic "<tool>: command not found" errors. pivy-* are
        # NOT here on purpose — the mock symlinks must win.
        #
        # `openssl` survives as a transitive dep of the mock helpers
        # (mock-pivy-box.sh uses base64 / openssl for its faux
        # encryption). Keeping it in the closure on both platforms is
        # cheap and avoids a platform split here.
        pkgs.bash
        pkgs.coreutils
        pkgs.git
        pkgs.gnugrep
        pkgs.gnused
        # jq: needed by t0800-health.bats to validate the tap-ndjson(7)
        # output of `piggy health --format ndjson`.
        pkgs.jq
        pkgs.openssl
        # python3: needed by conformance/piggy_askpass.bats — the test
        # uses `python3 -c 'import os; os.setsid(); os.execvp(...)'` to
        # detach the controlling TTY before invoking the askpass
        # script under a scrubbed env, mimicking pivy-agent's
        # launchd/systemd fork context. See piggy#115.
        pkgs.python3
        pkgs.qrencode
        pkgs.tree
      ];
    };

  # Defensive guard: when batsSrc is null (non-flake import paths
  # without a flake context wiring it up), produce no lane outputs
  # rather than crashing in builtins.readDir. Matches madder's
  # go/default.nix factoring — see piggy#114 for context.
  batsLaneOutputs =
    if batsSrc == null then
      { }
    else
      let
        # Scan two roots: top-level `t*.bats` plus `conformance/*.bats`.
        # The conformance/ pass is keyed by the relative path so the
        # builtins.readFile in extractFileTags resolves correctly. The
        # tag extraction itself is path-agnostic; we just need the
        # unique tag set across both roots.
        scanDir =
          subdir:
          let
            dir = if subdir == "" then batsSrc else batsSrc + "/${subdir}";
            prefix = if subdir == "" then "" else "${subdir}/";
            entries = builtins.attrNames (builtins.readDir dir);
            batsEntries = lib.filter (f: lib.hasSuffix ".bats" f) entries;
          in
          map (f: "${prefix}${f}") batsEntries;

        batsFiles = (scanDir "") ++ (scanDir "conformance");

        extractFileTags =
          file:
          let
            content = builtins.readFile (batsSrc + "/${file}");
            lines = lib.splitString "\n" content;
            tagLines = lib.filter (l: lib.hasPrefix "# bats file_tags=" l) lines;
          in
          if tagLines == [ ] then
            [ ]
          else
            lib.splitString "," (lib.removePrefix "# bats file_tags=" (builtins.head tagLines));

        allFileTags = lib.unique (lib.concatMap extractFileTags batsFiles);
      in
      lib.listToAttrs (
        map (
          tag:
          lib.nameValuePair "bats-${tag}" (mkBatsLane {
            filter = tag;
          })
        ) allFileTags
      )
      // {
        bats-default = mkBatsLane { };
      };
in
{
  inherit mkBatsLane batsLaneOutputs;
}
