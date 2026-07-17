{
  inputs = {
    # Fork of upstream nixpkgs with the amarbel-llc package additions.
    # The bats lane builder (`batsLane`) is sourced directly from
    # `amarbel-llc/bats` below — not from `pkgs.testers.batsLane`, which
    # the bats flake no longer ships through this overlay.
    igloo.url = "https://code.linenisgreat.com/igloo/archive/master.tar.gz";
    nixpkgs-master.url = "github:NixOS/nixpkgs/567a49d1913ce81ac6e9582e3553dd90a955875f";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";

    bats = {
      url = "https://code.linenisgreat.com/bats/archive/master.tar.gz";
      inputs.igloo.follows = "igloo";
    };

    # purse-first provides `dagnabit` (cmd/dagnabit), the code-org +
    # export-facade generator used by the go/ module: each `internal/` package
    # marked `//go:generate dagnabit export` gets a `pkgs/` facade so
    # consumers (eventually madder) import a stable public API instead of
    # internal/ (#183). On the devShell PATH; the nix package also installs
    # dagnabit(1). It also publishes `lib.conformistLinters.dewey-facade-export`
    # (purse-first#163) — the conformist linter module behind piggy's facade
    # drift check/repair lanes (see flake.nix conformistFacadeModule below).
    # Follows piggy's shared inputs to collapse the lock, and follows the
    # top-level `conformist` so the lock keeps ONE conformist node.
    purse-first = {
      url = "https://code.linenisgreat.com/purse-first/archive/master.tar.gz";
      inputs.igloo.follows = "igloo";
      inputs.nixpkgs-master.follows = "nixpkgs-master";
      inputs.utils.follows = "utils";
      inputs.conformist.follows = "conformist";
    };

    # conformist: the linter + formatter multiplexer (treefmt successor).
    # piggy's config is Nix-generated from ./conformist.nix (+ presets.eng)
    # via conformist.lib.evalModule — see flake.nix's conformistEval. Drives
    # `nix fmt`, the read-only `checks.formatting` gate, the impure facade
    # CHECK lane (lint-worktree), and the per-commit facade REPAIR hook
    # (conformist-pre-commit). Replaces the retired treefmt-nix.
    conformist = {
      url = "https://code.linenisgreat.com/conformist/archive/master.tar.gz";
      inputs.igloo.follows = "igloo";
      inputs.nixpkgs-master.follows = "nixpkgs-master";
      inputs.utils.follows = "utils";
    };

    # Software PIV smart card for tests — see nix/virtual-piv.nix.
    # Not flakes themselves; fetched as plain sources.
    jcardsim = {
      url = "github:arekinath/jcardsim";
      flake = false;
    };
    pivapplet = {
      url = "github:arekinath/PivApplet";
      flake = false;
    };
    # Oracle JavaCard SDK binaries vendored by martinpaljak. The jc305u3
    # kit provides api_classic.jar, which jcardsim's pom.xml requires at
    # build time (its `initialize` phase runs install-file on
    # $JC_CLASSIC_HOME/lib/api_classic.jar). The resulting jcardsim.jar
    # bundles the javacard.* bytecode.
    #
    # License: Oracle Binary Code License — redistribution allowed
    # "bundled as part of Your Programs" with the constraints listed in
    # jc305u3_kit/legal/Distribution_ReadME.txt. See LICENSING in
    # nix/virtual-piv.nix for how this posture affects piggy.
    oracle-javacard-sdks = {
      url = "github:martinpaljak/oracle_javacard_sdks";
      flake = false;
    };

    igloo.inputs.treefmt-nix.follows = "bats/treefmt-nix";
    utils.inputs.systems.follows = "igloo/systems";
    bats.inputs.nixpkgs-master.follows = "nixpkgs-master";
    igloo.inputs.nixpkgs-master.follows = "nixpkgs-master";
    bats.inputs.utils.follows = "utils";
  };

  outputs =
    {
      self,
      igloo,
      nixpkgs-master,
      utils,
      bats,
      purse-first,
      conformist,
      jcardsim,
      pivapplet,
      oracle-javacard-sdks,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        # Single source of truth for piggy's user-visible version. Read
        # from version.env at flake-eval time and threaded into the
        # piggy/piggy-agent-conformance derivations' `version` attr and
        # the makeWrapper `--set PIGGY_VERSION`. Cargo's build.rs
        # (crates/piggy/build.rs) reads the same file at compile time.
        # See eng-versioning(7) and piggy CLAUDE.md.
        piggyVersion = builtins.head (
          builtins.match ".*PIGGY_VERSION=([^\n]+).*" (builtins.readFile ./version.env)
        );

        # Short commit for the `piggy version` self-line (eng-versioning(7)).
        # Clean tree → shortRev; dirty worktree → dirtyShortRev; neither
        # (e.g. a tarball with no git metadata) → "unknown".
        piggyCommit = self.shortRev or self.dirtyShortRev or "unknown";
        # pcsclite is pinned *within* the nixpkgs-master input rather than as
        # its own tool-flake, so the rev that pins it is the input's rev.
        pcscliteRev = nixpkgs-master.shortRev or "unknown";

        # The `amarbel-llc/nixpkgs` overlay supplies the fork's package
        # additions; the bats lane builder itself comes from the
        # `amarbel-llc/bats` flake input (see `batsLib` below). Keeping
        # the overlay in scope for every consumer of `pkgs` so the rest
        # of the flake picks up the fork additions uniformly.
        #
        # The second overlay strips a malformed " none required" token
        # from libfyaml's pkg-config Libs: line on darwin, which leaks
        # into appstream's link command as literal filename arguments
        # and breaks the build of zenity → libadwaita → appstream's
        # transitive consumers. Tracked at NixOS/nixpkgs#514566; fix
        # ported from NixOS/nixpkgs#513484. Drop once that PR merges
        # and is pulled into amarbel-llc/nixpkgs.
        libfyamlFix =
          final: prev:
          prev.lib.optionalAttrs prev.stdenv.hostPlatform.isDarwin {
            libfyaml = prev.libfyaml.overrideAttrs (old: {
              postInstall = (old.postInstall or "") + ''
                substituteInPlace "$dev/lib/pkgconfig/libfyaml.pc" \
                  --replace-fail " none required" ""
              '';
            });
          };
        pkgs = import igloo {
          inherit system;
          overlays = [
            igloo.overlays.default
            libfyamlFix
          ];
        };
        pkgs-master = import nixpkgs-master { inherit system; };

        # gomod.nix is the producer half of the flake-input-go_mod protocol
        # (amarbel-llc/nixpkgs RFC 0001): mkGoPkgs publishes go-pkgs /
        # go-pkgs-test so madder/dodder/cutting-garden bridge
        # github.com/amarbel-llc/piggy/go as a flake input (flake.lock-only
        # bumps) instead of a go.mod pseudo-version. The producer src is scoped
        # to the go/ subdir, so downstream bridges with NO subPath. goFlakeInputs
        # (the dewey bridge) is threaded into the two buildGoApplication binaries
        # below so dewey resolves during the self-consume build. See go/gomod.nix.
        gomod = import ./go/gomod.nix {
          inherit pkgs purse-first system;
          src = self + "/go";
        };
        inherit (gomod) goFlakeInputs;
        inherit (gomod.goPkgs) go-pkgs go-pkgs-test;

        # Software PIV smart card for tests. Only built on Linux — vsmartcard
        # is marked broken on darwin upstream.
        virtualPiv = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux (
          import ./nix/virtual-piv.nix {
            inherit pkgs pkgs-master;
            jcardsim-src = jcardsim;
            pivapplet-src = pivapplet;
            oracle-javacard-sdks-src = oracle-javacard-sdks;
          }
        );

        # pivy C package, built from vendor/pivy (see nix/pivy.nix and
        # piggy #21). Local derivation instead of a nested flake input.
        pivyPkg = import ./nix/pivy.nix {
          inherit pkgs;
          src = ./vendor/pivy;
        };

        # Runtime deps on PATH for the wrapped piggy binary. `pivy`
        # backs the C-pivy delegations (tool/ca/luks/zfs + the `piggy
        # box` subcommands the rust impl doesn't cover — see
        # crates/piggy/src/exec.rs) and the decrypt backend for
        # `pass show` / `pass edit` / `pass generate -i` (the rust
        # `crypt::decrypt` shells to `pivy-box stream decrypt`).
        # `openssh` provides `ssh-copy-id`, which `piggy ssh-copy-id`
        # (crates/piggy/src/ssh_copy_id.rs) execs to install the 9A keys.
        runtimeDeps = [
          pivyPkg
          pkgs.git
          pkgs.tree
          pkgs.qrencode
          pkgs.gnugrep
          pkgs.coreutils
          pkgs.openssh
        ];

        # Runtime deps for contrib/piggy-askpass.sh when invoked by
        # pivy-agent's launchd job (PATH is unset there). `ps` is in
        # `procps` on Linux; macOS provides /bin/ps in the base system
        # so we don't add a darwin-specific dep. `zenity` is the GUI
        # fallback when /dev/tty isn't connected (the typical agent
        # case).
        askpassRuntimeDeps = [
          pkgs.coreutils
          pkgs.zenity
        ]
        ++ pkgs.lib.optional pkgs.stdenv.isLinux pkgs.procps;

        # Native rust workspace: `piggy` (binary) + `piggy-piv` (library).
        # pcsclite is only needed on linux; macOS has PC/SC in CoreServices.
        # Uses pkgs-master (2.4.1) for backward-compatible IPC protocol
        # negotiation — a 2.4.1 client can talk to daemons as old as 1.8.24,
        # which covers Ubuntu 24.04's 2.0.3 pcscd without workarounds.
        rustBuildInputs = [
          pkgs.openssl
        ]
        ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs-master.pcsclite ];
        rustNativeBuildInputs = [ pkgs.pkg-config ];

        # Shared cargoLock attrs for every buildRustPackage derivation in
        # this flake. They all vendor from the same Cargo.lock, so git-dep
        # outputHashes must stay identical — buildRustPackage fetches every
        # git dep in the lock file regardless of which workspace package is
        # built (fibby doesn't depend on tap-dancer but still needs the
        # hash). Factored here so a tap-dancer bump (or any future git dep)
        # only needs one edit.
        sharedCargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "tap-dancer-0.1.12" = "sha256-tZ30ATmSKh10fY8hRwH+ZY+Hz0Pvpg7/yA9chYSdlvI=";
          };
        };

        piggy-rs = pkgs.rustPlatform.buildRustPackage {
          pname = "piggy-rs";
          version = "0.1.0";

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              name: type:
              let
                rel = pkgs.lib.removePrefix (toString ./. + "/") (toString name);
                base = baseNameOf rel;
              in
              base == "Cargo.toml"
              || base == "Cargo.lock"
              # version.env is read by crates/piggy/build.rs at compile
              # time and must reach the sandboxed source tree.
              || base == "version.env"
              || pkgs.lib.hasPrefix "crates" rel;
          };

          cargoLock = sharedCargoLock;

          buildInputs = rustBuildInputs;
          nativeBuildInputs = rustNativeBuildInputs;

          # Integration tests in crates/piggy-piv/tests/ need a pcsc daemon
          # that nix sandboxes can't provide. Match pivy's flake, which skips
          # checks on darwin for the same reason (no system pcscd under CI).
          doCheck = !pkgs.stdenv.hostPlatform.isDarwin;

          meta = with pkgs.lib; {
            description = "Piggy rust workspace (piggy CLI + piggy-piv library)";
            homepage = "https://github.com/amarbel-llc/piggy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # Standalone `fibby` package — the pcsc-lite-daemon-protocol Rust
        # server (see docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md
        # and crates/fibby/README.md). Shares the workspace source filter
        # with piggy-rs so a single nix-cached build artifact serves both.
        # On Linux, the `hardware-proxy` Cargo feature is enabled so the
        # HardwareProxy backend (real-card passthrough used by the wet-env
        # validation recipes) is available. Darwin builds without the
        # feature because pcsc-sys's libpcsclite link isn't satisfied
        # there — flake.nix:166 only adds pcsclite to rustBuildInputs on
        # `stdenv.isLinux`, matching the upstream vsmartcard-on-darwin
        # status. The `VirtualCard` backend is always available on both
        # platforms.
        #
        # Used by: `just load-fibby` (downstream of this output), the wet-env
        # capture recipes (`debug-fibby-roundtrip-capture` /
        # `debug-fibby-roundtrip-via-fib`), and any consumer of #129's
        # planned packaging story (e.g. a future home-manager service).
        fibby = pkgs.rustPlatform.buildRustPackage {
          pname = "fibby";
          version = "0.1.0";

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              name: type:
              let
                rel = pkgs.lib.removePrefix (toString ./. + "/") (toString name);
                base = baseNameOf rel;
              in
              base == "Cargo.toml"
              || base == "Cargo.lock"
              || base == "version.env"
              || pkgs.lib.hasPrefix "crates" rel;
          };

          cargoLock = sharedCargoLock;

          # Build only the fibby crate (the workspace builds piggy etc. as
          # a side effect via piggy-rs; this keeps the artifact narrow).
          cargoBuildFlags = [
            "-p"
            "fibby"
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            "--features"
            "hardware-proxy"
          ];

          # Match the build feature gate on tests so `cargo test` exercises
          # the hardware-proxy code path on Linux. The 18 fibby tests
          # (17 unit + 1 loopback) are pure-data / VirtualCard-driven, so
          # they pass with or without the feature; the feature gate just
          # ensures the hardware-proxy code TYPE-CHECKS in the sandbox.
          cargoTestFlags = [
            "-p"
            "fibby"
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            "--features"
            "hardware-proxy"
          ];

          buildInputs = rustBuildInputs;
          nativeBuildInputs = rustNativeBuildInputs;

          # Run the 18 fibby tests inside the sandbox. Loopback uses /tmp
          # for its AF_UNIX socket (sun_path-short), so it survives the
          # short nix-sandbox TMPDIR fine. Hardware-proxy unit tests stay
          # hermetic — they don't try to reach a real pcscd.
          doCheck = true;

          meta = with pkgs.lib; {
            description = "Pure-Rust virtual PIV card speaking the pcsc-lite client protocol directly";
            homepage = "https://github.com/amarbel-llc/piggy";
            license = licenses.mpl20;
            mainProgram = "fibby";
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # Wrapped `piggy` binary: rust dispatch + bash passwordstore + pivy
        # fallback, bundled as a single symlink-joined package.
        piggy = pkgs.stdenv.mkDerivation {
          pname = "piggy";
          version = piggyVersion;

          src = ./.;

          nativeBuildInputs = [
            pkgs.makeWrapper
            pkgs.scdoc
          ];

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/bin \
                     $out/libexec/piggy \
                     $out/share/man/man1

            # Stash the rust dispatcher and the piggy-ids helper binary
            # at known paths, then wrap the rust binary as
            # $out/bin/piggy with PIGGY_IDS_PATH set so the rust
            # `piggy-ids` callers (encrypt / list-available / etc.)
            # locate it.
            install -m 0755 ${piggy-rs}/bin/piggy \
                            $out/libexec/piggy/piggy-rs
            install -m 0755 ${piggy-rs}/bin/piggy-ids \
                            $out/libexec/piggy/piggy-ids
            # age discovers the plugin by PATH name (`age-plugin-piggy`); it
            # reads PIGGY_AUTH_SOCK / SSH_AUTH_SOCK at runtime and talks to
            # piggy-agent over the `ecdh@joyent.com` extension. The thin
            # wrapper exists only to bake PIGGY_VERSION/COMMIT in for the
            # eng-versioning(7) `--version` line (build.rs can't get the commit
            # in the .git-less sandbox). makeWrapper exec's the real binary
            # with all args + the rest of the env intact, so the `--age-plugin`
            # protocol and the agent-socket env still flow through. Having
            # `piggy` on PATH then also exposes the plugin to age.
            install -m 0755 ${piggy-rs}/bin/age-plugin-piggy \
                            $out/libexec/piggy/age-plugin-piggy
            makeWrapper $out/libexec/piggy/age-plugin-piggy \
                        $out/bin/age-plugin-piggy \
              --set PIGGY_VERSION ${piggyVersion} \
              --set PIGGY_COMMIT ${piggyCommit}
            # User-facing SSH_ASKPASS helper. Lives under libexec/piggy/
            # so consumers can reference it as
            # `''${piggy}/libexec/piggy/piggy-askpass.sh`, matching the
            # pattern pivy uses for its bundled pivy-askpass. We install
            # the raw script (preserves shebang + comments) then wrap
            # it to pin runtime deps (ps, zenity) on PATH — the script
            # is invoked by pivy-agent's launchd job where PATH is
            # otherwise unset. Replaces pivy's `exec zenity --password`
            # one-liner whose GTK4 AdwMessageDialog deprecation
            # triggers GLib NULL-str warnings on every prompt.
            install -m 0755 contrib/piggy-askpass.sh \
                            $out/libexec/piggy/piggy-askpass.sh.unwrapped
            makeWrapper $out/libexec/piggy/piggy-askpass.sh.unwrapped \
                        $out/libexec/piggy/piggy-askpass.sh \
              --prefix PATH : ${pkgs.lib.makeBinPath askpassRuntimeDeps}
            for f in doc/*.scd; do
              stem="$(basename "$f" .scd)"
              section="''${stem##*.}"
              name="''${stem%.*}"
              mkdir -p "$out/share/man/man''${section}"
              scdoc < "$f" > "$out/share/man/man''${section}/''${name}.''${section}"
            done

            # The PIGGY_VERSION/COMMIT/<component> --set group below is the
            # `piggy version` data source: the native `version` handler
            # reads these from the environment makeWrapper bakes in.
            # Component versions are read live off the derivations
            # (pivyPkg.version, pkgs-master.pcsclite.version) so a pin
            # bump shows up in the output with no manual edit — drift
            # stays visible, per eng-versioning(7).
            #
            # IGLOO-PROMOTION CANDIDATE (amarbel-llc/nixpkgs#68): this
            # version+commit+component injection is the non-Go analog of
            # buildGoApplication's auto-embedding (amarbel-llc/nixpkgs#31).
            # A generalized `mkVersionedWrapper` deriving these flags from
            # {version.env, src.rev, components} is the lift target — this
            # block is the tracer-bullet reference consumer.
            makeWrapper $out/libexec/piggy/piggy-rs $out/bin/piggy \
              --set PIGGY_IDS_PATH $out/libexec/piggy/piggy-ids \
              --set PIGGY_VERSION ${piggyVersion} \
              --set PIGGY_COMMIT ${piggyCommit} \
              --set PIGGY_PIVY_VERSION ${pivyPkg.version} \
              --set PIGGY_PIVY_REV vendored \
              --set PIGGY_PCSCLITE_VERSION ${pkgs-master.pcsclite.version} \
              --set PIGGY_PCSCLITE_REV ${pcscliteRev} \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeDeps}
          '';

          # Expose the Go-based SSH-agent conformance binary as a test
          # attribute of the main piggy package. Reachable via
          # `nix build .#piggy.tests.conformance` and enumerated by
          # `nix flake check`. Keeps the relationship between the agent
          # and its wire-protocol oracle explicit without merging the
          # Rust and Go toolchains into one derivation.
          passthru.tests = {
            conformance = piggy-agent-conformance;
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            fib = virtualPiv.fibBundle;
          };

          meta = with pkgs.lib; {
            description = "PIV-based password store using pivy-box and ebox templates";
            license = licenses.gpl2Plus;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # The two Go test binaries piggy's bats lanes need, now built from the
        # unified go/ module (github.com/amarbel-llc/piggy/go) via
        # buildGoApplication self-consuming the go-pkgs-test producer output
        # (rich-acacia's canonical self-consume, RFC 0001 § Self-consumption): a
        # source-filter regression OR a stale go/gomod2nix.toml fails the build
        # HERE, in piggy's gate, rather than in a downstream consumer's. Building
        # from the unified module is why the #183/#188 "no buildGoModule for the
        # LIBRARY" ruling still holds — the library is gated by the dagnabit
        # facade check; these are BINARIES, always built, now from one module.
        # goFlakeInputs bridges dewey so it resolves hermetically.
        piggy-agent-conformance = pkgs.buildGoApplication {
          pname = "piggy-agent-conformance";
          version = piggyVersion;

          src = go-pkgs-test;
          pwd = go-pkgs-test;
          modules = ./go/gomod2nix.toml;
          inherit goFlakeInputs;

          subPackages = [ "cmd/piggy-agent-conformance" ];
          go = pkgs-master.go_1_26;
          GOTOOLCHAIN = "local";

          # buildGoApplication's stock goCheckHook tests only subPackages (cmd/,
          # no _test.go), so the whole-module registry packages would never be
          # exercised from the filtered tree. Override checkPhase with the blessed
          # self-consume floor: `go vet -tags test ./...` type-checks EVERY
          # package (incl. _test.go under the test tag) against go-pkgs-test, so a
          # dropped source file fails here. vet (not test): no network / no card
          # in the nix sandbox.
          checkPhase = ''
            runHook preCheck
            go vet -tags test ./...
            runHook postCheck
          '';

          meta = with pkgs.lib; {
            description = "Go-based SSH agent conformance tests for piggy";
            homepage = "https://github.com/amarbel-llc/piggy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # Go test-only SSH server for the hardware-free SSH-over-fibby bats lane
        # (piggy#135 Phase A). Same unified-module buildGoApplication shape as
        # piggy-agent-conformance; build-only (its cmd/ import graph is the
        # validation — the whole-module vet self-consume rides on the primary
        # binary above). Named after its cmd/ dir, so no postInstall rename.
        piggy-test-sshd = pkgs.buildGoApplication {
          pname = "piggy-test-sshd";
          version = piggyVersion;

          src = go-pkgs-test;
          pwd = go-pkgs-test;
          modules = ./go/gomod2nix.toml;
          inherit goFlakeInputs;

          subPackages = [ "cmd/piggy-test-sshd" ];
          go = pkgs-master.go_1_26;
          GOTOOLCHAIN = "local";

          meta = with pkgs.lib; {
            description = "Go-based test-only SSH server for piggy's SSH-over-fibby bats lane";
            homepage = "https://github.com/amarbel-llc/piggy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # Sandboxed bats lane. See ./bats.nix for the lane builder and
        # the `# bats file_tags=hardware` convention that filters
        # pcscd/hardware-requiring tests out of the default lane.
        #
        # batsSrc is passed as a plain path (not `cleanSourceWith`)
        # because the auto-discovery in bats.nix does
        # `builtins.readDir batsSrc` at eval time. cleanSourceWith
        # produces a derivation whose store path must be realized
        # before readDir can introspect it; in eval-only mode (e.g.
        # `nix flake check --no-build`) that realization can't happen,
        # surfacing as `error: path '<hash>-source' is not valid`.
        # Store-path stability across unrelated repo edits can be
        # re-added later via `cleanSourceWith` if it becomes worth it.
        batsLib = import ./bats.nix {
          inherit pkgs;
          # Unwrapped rust dispatcher: lets test-PATH overrides
          # (mock-pivy-box.sh etc.) win over what the rust handlers
          # invoke for crypto.
          piggyRs = piggy-rs;
          # Wrapped piggy: source of `$out/libexec/piggy/piggy-ids`
          # referenced by the extraEnv (PIGGY_IDS_REAL).
          piggyWrapped = piggy;
          # Threaded through so the lane can inject CONFORMANCE_BIN
          # for conformance/piggy_agent_protocol.bats. See piggy#115.
          conformanceBin = piggy-agent-conformance;
          # Threaded through so the lane can inject REAL_PIVY_TOOL
          # for conformance/pivy_tool_admin_key.bats. See piggy#116.
          pivy = pivyPkg;
          batsLane = bats.lib.${system}.batsLane;
          bats-libs = bats.packages.${system}.bats-libs;
          batsSrc = ./zz-tests_bats;
        };

        # conformist config, Nix-generated from ./conformist.nix merged with the
        # eng-convention preset (conformist.lib.presets.eng). Drives `nix fmt`
        # (build.wrapper — config + every formatter baked as /nix/store paths)
        # and the read-only `checks.formatting` gate (build.check). Replaces the
        # retired treefmt-nix. See conformist-nix(7).
        conformistEval = conformist.lib.evalModule pkgs {
          imports = [
            conformist.lib.presets.eng
            ./conformist.nix
          ];
          package = conformist.packages.${system}.default;
        };

        # Impure lane: the eng-convention checks that need a live working tree /
        # host tools (git-remotes, git-default-branch, sweatfile, agents-md), so
        # they cannot run in the sandboxed pure config — `just lint-worktree`
        # runs them against the real worktree via this config. See
        # conformist.lib.presets.eng-impure.
        #
        # It also carries the dewey-facade-export drift CHECK as the merge-gate
        # safety net: `just lint-worktree` is in the `lint` aggregate the
        # pre-merge `just` hook runs, so committed go/ facade drift fails
        # the merge even if the pre-commit auto-repair hook was bypassed. This
        # replaces the old standalone `lint-facades` recipe
        # (`dagnabit export --check`). The pre-commit lane (conformistCodegenEval)
        # does the REPAIR; this lane does the merge CHECK — same module, two
        # lanes.
        conformistImpureEval = conformist.lib.evalModule pkgs {
          imports = [
            conformist.lib.presets.eng-impure
            purse-first.lib.conformistLinters.dewey-facade-export
            conformistFacadeModule
          ];
          package = conformist.packages.${system}.default;
          projectRootFile = "flake.nix";
        };

        # The dewey pkgs/ facade-export lane, CONSUMED from purse-first's
        # published module (purse-first#163) rather than hand-wired: the module
        # owns the `dagnabit export` invocation + the DAGNABIT_CONFORMIST_CONFIG
        # threading, fed the PURE formatter config so its facade-format pass
        # matches `nix fmt`. The tier opt-ins are layered on here (the upstream
        # module ships the check/repair commands but not the stage-mutation
        # flags). Shared by BOTH the impure merge-gate CHECK
        # (conformistImpureEval) and the pre-commit REPAIR
        # (conformistCodegenEval).
        #
        # conformistConfig = conformistEval.config.build.configFile is the PURE
        # eval's output, referenced from a SEPARATE eval — so it is not a
        # self-reference: the facade linter does not live in the eval that
        # produces the config it bakes. Same cycle-free shape madder uses.
        conformistFacadeModule =
          { ... }:
          {
            linters.dewey-facade-export.enable = true;
            # piggy's dewey-layout module root (holds internal/ + pkgs/).
            linters.dewey-facade-export.deweyDir = "go";
            # go/ uses `//go:generate dagnabit export` directives, not
            # `--library`.
            linters.dewey-facade-export.library = false;
            # Pinned package ⇒ hermetic, PATH-independent dagnabit.
            linters.dewey-facade-export.dagnabitPackage = purse-first.packages.${system}.dagnabit;
            linters.dewey-facade-export.conformistConfig = conformistEval.config.build.configFile;
            # Layer the stage-mutation tiers (conformist#55/#56/#57) onto the
            # module's generated linter so the pre-commit hook regenerates AND
            # stages drift into the commit.
            settings.linter.dewey-facade-export = {
              # flake.lock joins the module's go-glob trigger (list options
              # merge): the facades embed dagnabit's version stamp, so a
              # purse-first bump restamps them all from a flake.lock-only
              # commit — which stages no *.go and would never fire the lane.
              includes = [ "flake.lock" ];
              "restage-repair-outputs" = true; # tier 2: restage modified facades
              "stage-new-outputs" = true; # tier 3: stage a brand-new pkgs/ facade
              "stage-deleted-outputs" = true; # tier 4: stage a removed/relocated facade
            };
          };

        # Dedicated PRE-COMMIT (facade-repair) eval. EXPLICIT membership: the
        # formatters + excludes from ./conformist.nix, plus the facade-export
        # repair lane — but deliberately NOT presets.eng (its convention linters
        # stay at the merge/worktree gate, not commit time).
        # build.preCommit from THIS eval is the sweatfile [hooks].pre-commit
        # hook, so a commit auto-formats and regenerates-and-stages go/
        # facade drift, and nothing else.
        conformistCodegenEval = conformist.lib.evalModule pkgs {
          imports = [
            ./conformist.nix
            # The facade-export linter MODULE (options.linters.dewey-facade-export.*);
            # conformistFacadeModule above sets its enable + params.
            purse-first.lib.conformistLinters.dewey-facade-export
            conformistFacadeModule
          ];
          package = conformist.packages.${system}.default;
        };
      in
      {
        packages = {
          default = piggy;
          piggy = piggy;
          piggy-rs = piggy-rs;
          piggy-agent-conformance = piggy-agent-conformance;
          # The C pivy stack (pivy-agent / pivy-tool / pivy-box etc.).
          # Exposed so the hardware bats lane can `nix build .#pivy`
          # to get a freshly-built pivy-agent under
          # `result/bin/pivy-agent`. See
          # zz-tests_bats/conformance/pivy_agent_hardware.bats and
          # the test-bats-conformance-pivy-agent-hardware just recipe.
          pivy = pivyPkg;
          # The `age` CLI (plugin-capable), exposed so the
          # age-plugin-piggy hardware bats lane can `nix build .#age`
          # to drive a real encrypt/decrypt round-trip through the
          # plugin. See zz-tests_bats/conformance/age_plugin_piggy_fibby.bats
          # and the test-bats-conformance-age-plugin-piggy recipe.
          age = pkgs.age;
          # Standalone fibby binary. On Linux this carries the
          # `hardware-proxy` feature; on darwin it's VirtualCard-only
          # (vsmartcard upstream is broken on darwin). Consumed by
          # `just load-fibby` and the wet-env capture recipes; future
          # consumer is the planned home-manager service (#129 stretch).
          fibby = fibby;
          # Go test-only SSH server for the SSH-over-fibby bats lane
          # (piggy#135). Consumed by the forthcoming Phase D recipe via
          # `nix build .#piggy-test-sshd`.
          piggy-test-sshd = piggy-test-sshd;
          # The toolchain-hermetic per-commit facade-repair hook, named by the
          # sweatfile [hooks].pre-commit command and put on the devShell PATH as
          # `conformist-pre-commit`. `nix build .#conformist-pre-commit` dogfoods
          # it (forces the codegen eval + facade lane to resolve).
          conformist-pre-commit = conformistCodegenEval.config.build.preCommit;
          # Its merge-repair sibling from the SAME codegen eval, on the
          # devShell PATH below as `conformist-repair` (sweatfile
          # [hooks].repair): heals bump-commit codegen drift (dewey facades)
          # at merge time with the post-bump drivers — the pre-commit hook's
          # store-pinned driver predates the very bump it would need to heal
          # (eng tier-B convergence, proven on madder; eng's fallback wrapper
          # is severed from child repos and would otherwise skip).
          conformist-repair = conformistCodegenEval.config.build.repair;
          # The impure-lane config (eng git-state checks + the facade CHECK),
          # consumed by `just lint-worktree` via `nix build
          # .#conformist-impure-config`.
          conformist-impure-config = conformistImpureEval.config.build.configFile;

          # go-pkgs / go-pkgs-test: the flake-input-go_mod producer outputs
          # (filtered go/ source trees) that let downstream repos
          # (madder/dodder/cutting-garden) bridge piggy's go/ module as a flake
          # input via goFlakeInputs, instead of a go.mod pseudo-version (RFC
          # 0001). Consumers bridge `github.com/amarbel-llc/piggy/go` = go-pkgs
          # with NO subPath (the producer src is already scoped to go/). See
          # go/gomod.nix.
          inherit go-pkgs go-pkgs-test;

          # The gomod2nix CLI (from piggy's pinned igloo), exposed so
          # `just build-gomod2nix` can regenerate go/gomod2nix.toml hermetically
          # (`nix run .#gomod2nix`) without depending on a devShell reload.
          gomod2nix = pkgs.gomod2nix;
        }
        // batsLib.batsLaneOutputs
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          fib = virtualPiv.fib;
          fib-bundle = virtualPiv.fibBundle;
          fib-reader-conf = virtualPiv.readerConf;
          fib-pcscd = virtualPiv.pcscdForFib;
          jcardsim = virtualPiv.jcardsim;
          pivapplet = virtualPiv.pivapplet;
        };

        checks = {
          bats-default = batsLib.batsLaneOutputs.bats-default;
          # Read-only CI gate: builds in /nix/store off a source
          # snapshot, runs the conformist formatters + the eng preset's
          # file-based linters, and fails if any file would change. Driven
          # from `just lint-fmt` and surfaced under `nix flake check`.
          formatting = conformistEval.config.build.check self;
        };

        # `nix fmt` runs the generated conformist wrapper (config + every
        # formatter baked as /nix/store paths). See conformistEval.
        formatter = conformistEval.config.build.wrapper;

        devShells.default = pkgs.mkShell {
          packages =
            runtimeDeps
            ++ rustBuildInputs
            ++ rustNativeBuildInputs
            ++ [
              pkgs-master.just
              pkgs-master.rustc
              pkgs-master.cargo
              pkgs-master.rustfmt
              pkgs-master.clippy
              pkgs-master.rust-analyzer
              # conformist (treefmt successor): the bare CLI for `just
              # lint-worktree` (`conformist check --config-file …`), plus the
              # toolchain-hermetic per-commit facade-repair wrapper on PATH as
              # `conformist-pre-commit` (the sweatfile [hooks].pre-commit
              # command). `nix fmt` uses the wrapper from `formatter` above.
              conformist.packages.${system}.default
              conformistCodegenEval.config.build.preCommit
              # Its merge-repair sibling, on PATH as `conformist-repair` for
              # spinclass's [hooks].repair (see packages.conformist-repair).
              conformistCodegenEval.config.build.repair
              pkgs.scdoc
              # Go toolchain for the go/ module (piggy-agent-conformance
              # + piggy-test-sshd): `go build`/`vet`/`gofmt` for fast
              # dev-loop iteration outside nix, and to back the hamster.*
              # MCP tools. The packaged binaries still build via
              # buildGoModule (which uses its own pkgs.go); this is the
              # same toolchain, exposed on the devShell PATH.
              pkgs.go
              # dagnabit (from purse-first): generates the go/ module's pkgs/
              # export facades from its internal/ packages. The facade
              # check/repair now runs through conformist's
              # dewey-facade-export lane (pre-commit REPAIR + lint-worktree
              # CHECK), which invokes a store-pinned dagnabit; this bare
              # copy stays on PATH for ad-hoc `dagnabit export` and installs
              # dagnabit(1). See #183 and the go/ module.
              purse-first.packages.${system}.dagnabit
              # gomod2nix CLI (from the igloo overlay, same one paired with
              # buildGoApplication): `just build-gomod2nix` (= `cd go &&
              # gomod2nix`) regenerates go/gomod2nix.toml from go.mod/go.sum
              # after a dep change. buildGoApplication is the freshness gate (a
              # stale toml fails the binary builds); conformist subdir lint is
              # deferred to conformist#79.
              pkgs.gomod2nix
              # gum drives terminal UI logging in the maint group recipes
              # (`bump-version`, `tag`, `release`). See eng-versioning(7)
              # "JUSTFILE RELEASE RECIPES".
              pkgs.gum
              # In amarbel-llc/bats's new package layout, `batman`
              # (the test orchestrator) and `bats` (the bats-core
              # binary the bats CLI calls live under) are separate
              # outputs. We need both on PATH so plain `bats` and
              # `batman` invocations from justfile recipes resolve.
              bats.packages.${system}.batman
              bats.packages.${system}.bats
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              # `just load-fib` needs pcscd + fib + opensc-tool on PATH.
              pkgs.pcsclite
              pkgs.opensc
              virtualPiv.fib
            ];

          # Help the openssl + pcsc-sys crates find their libraries
          # without having to vendor, mirroring pivy's flake semantics.
          OPENSSL_NO_VENDOR = "1";
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.lib.getLib pkgs.openssl}/lib";
        };
      }
    ))
    // {
      # See docs/plans/2026-04-27-piggy-agent-nix-module.md for the
      # module's design rationale and option surface. The NixOS
      # module is a thin re-export that wires the hm module into
      # `home-manager.sharedModules`; per-user activation lives
      # under `home-manager.users.<u>.services.piggy-agent`.
      homeManagerModules.piggy-agent = import ./nix/hm/piggy-agent.nix;
      nixosModules.piggy-agent = import ./nix/nixos/piggy-agent.nix;
    };
}
