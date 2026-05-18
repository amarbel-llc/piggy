# bats integration test lanes for piggy.
#
# Wraps the `batsLane` builder exposed by amarbel-llc/bats at
# `bats.lib.${system}.batsLane` (NOT `pkgs.testers.batsLane` — the
# nixpkgs fork's thin overlay no longer ships that helper; the bats
# flake is the canonical source). Provides piggy-specific defaults:
# `bats-libs` from amarbel-llc/bats on `BATS_LIB_PATH`; the wrapped
# `piggy` derivation injected via the `binaries` map so the rust
# dispatcher → bash subprocess path is exercised end-to-end; and
# `PIGGY_SH_PATH` / `PIGGY_IDS_REAL` pointed at the wrapped
# `$out/libexec/piggy/` so the same harness works inside the nix
# sandbox and in local `bats --no-sandbox` runs.
#
# Auto-discovers `# bats file_tags=foo,bar` directives at flake-eval
# time and produces one `bats-${tag}` derivation per unique tag plus
# `bats-default` (which filters with `!hardware` to exclude tests
# that need a real pcscd/PIV stack).
#
# Only top-level `*.bats` files under `batsSrc` are scanned (matches
# clown's and tap's bats.nix). Tests under
# `zz-tests_bats/conformance/` and `zz-tests_bats/explore/` stay
# invoked through the existing `just test-bats-conformance-*` recipes.
{
  pkgs,
  batsLane,
  bats-libs,
  # The UNWRAPPED rust dispatcher (piggy-rs from flake.nix). Tests
  # need the unwrapped binary so that PATH overrides from
  # zz-tests_bats/helpers/ (mock-pivy-box.sh etc.) win over what
  # piggy.sh tries to invoke; the wrapped piggy injects pivyPkg + git
  # via makeWrapper's `--prefix PATH`, which beats every prefix the
  # bats setup can add.
  piggyRs,
  # The WRAPPED piggy (piggy from flake.nix). Used only as a source of
  # `$out/libexec/piggy/{piggy.sh,piggy-ids}` — those are the bash
  # script and the real piggy-ids binary the dispatcher / mock
  # delegators need by absolute path.
  piggyWrapped,
  batsSrc,
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
      binaries = {
        PIGGY = {
          inherit base;
          name = "piggy";
        };
      };
      batsLibPath = [ bats-libs.batsLibPath ];
      extraEnv = {
        BATS_TEST_TIMEOUT = batsTestTimeout;
        # Pin against the wrapped piggy's libexec — that's where
        # `flake.nix` installs the bash script and the piggy-ids
        # binary. PIGGY_IDS_REAL is consumed by mock-piggy-ids.sh
        # for delegation; PIGGY_SH_PATH is consumed by the rust
        # dispatcher's find_piggy_sh().
        PIGGY_SH_PATH = "${piggyWrapped}/libexec/piggy/piggy.sh";
        PIGGY_IDS_REAL = "${piggyWrapped}/libexec/piggy/piggy-ids";
        # Deliberately do NOT export PIGGY_IDS_PATH: when unset, the
        # rust dispatcher falls through to `command -v piggy-ids`,
        # which resolves to the mock symlink in $BATS_TEST_TMPDIR
        # (placed at the front of $PATH by common.bash).
      };
      nativeBuildInputs = [
        # piggy.sh + helpers shell out to these directly; without
        # them on PATH the sandboxed tests get cryptic
        # "<tool>: command not found" errors. pivy-* are NOT here
        # on purpose — the mock symlinks must win.
        #
        # `openssl` is darwin-only in practice: src/platform/darwin.sh
        # overrides BASE64 to "openssl base64" because BSD base64 has
        # line-wrapping quirks. Linux uses coreutils' base64 directly
        # (src/piggy.sh BASE64="base64"). Keeping openssl in the
        # closure on both platforms is cheap and avoids a platform
        # split here.
        pkgs.bash
        pkgs.coreutils
        pkgs.getopt
        pkgs.git
        pkgs.gnugrep
        pkgs.gnused
        pkgs.openssl
        pkgs.qrencode
        pkgs.tree
      ];
    };

  batsFiles = lib.filter (f: lib.hasSuffix ".bats" f) (builtins.attrNames (builtins.readDir batsSrc));

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

  batsLaneOutputs =
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
