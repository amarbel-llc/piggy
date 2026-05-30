{
  inputs = {
    # Fork of upstream nixpkgs with the amarbel-llc package additions.
    # The bats lane builder (`batsLane`) is sourced directly from
    # `amarbel-llc/bats` below — not from `pkgs.testers.batsLane`, which
    # the bats flake no longer ships through this overlay.
    igloo.url = "github:amarbel-llc/igloo";
    nixpkgs-master.url = "github:NixOS/nixpkgs/d233902339c02a9c334e7e593de68855ad26c4cb";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";

    bats = {
      url = "github:amarbel-llc/bats";
      inputs.igloo.follows = "igloo";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "igloo";
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

  };

  outputs =
    {
      self,
      igloo,
      nixpkgs-master,
      utils,
      bats,
      treefmt-nix,
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

        # Runtime deps on PATH for the wrapped piggy binary. `pivy` is kept
        # as a fallback for subcommands the rust binary hasn't implemented
        # yet (box/tool/ca/luks/zfs) — see crates/piggy/src/fallback.rs.
        runtimeDeps = [
          pivyPkg
          pkgs.git
          pkgs.tree
          pkgs.qrencode
          pkgs.getopt
          pkgs.gnugrep
          pkgs.coreutils
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

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

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
                     $out/libexec/piggy/platform \
                     $out/share/man/man1

            # Stash the rust dispatcher, the piggy-ids helper binary,
            # and the bash script at known paths, then wrap the rust
            # binary as $out/bin/piggy with PIGGY_SH_PATH +
            # PIGGY_IDS_PATH set so fallback::find_piggy_sh and
            # piggy.sh's recipients/encrypt paths locate them.
            install -m 0755 ${piggy-rs}/bin/piggy \
                            $out/libexec/piggy/piggy-rs
            install -m 0755 ${piggy-rs}/bin/piggy-ids \
                            $out/libexec/piggy/piggy-ids
            install -m 0755 src/piggy.sh \
                            $out/libexec/piggy/piggy.sh
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
            if [ -f src/platform/darwin.sh ]; then
              install -m 0644 src/platform/darwin.sh \
                              $out/libexec/piggy/platform/darwin.sh
            fi
            if [ -f src/platform/linux.sh ]; then
              install -m 0644 src/platform/linux.sh \
                              $out/libexec/piggy/platform/linux.sh
            fi
            for f in doc/*.scd; do
              stem="$(basename "$f" .scd)"
              section="''${stem##*.}"
              name="''${stem%.*}"
              mkdir -p "$out/share/man/man''${section}"
              scdoc < "$f" > "$out/share/man/man''${section}/''${name}.''${section}"
            done

            # The PIGGY_VERSION/COMMIT/<component> --set group below is the
            # `piggy version` data source: cmd_version (src/piggy.sh) reads
            # these from the environment makeWrapper bakes in. Component
            # versions are read live off the derivations (pivyPkg.version,
            # pkgs-master.pcsclite.version) so a pin bump shows up in the
            # output with no manual edit — drift stays visible, per
            # eng-versioning(7).
            #
            # IGLOO-PROMOTION CANDIDATE (amarbel-llc/nixpkgs#68): this
            # version+commit+component injection is the non-Go analog of
            # buildGoApplication's auto-embedding (amarbel-llc/nixpkgs#31).
            # A generalized `mkVersionedWrapper` deriving these flags from
            # {version.env, src.rev, components} is the lift target — this
            # block is the tracer-bullet reference consumer.
            makeWrapper $out/libexec/piggy/piggy-rs $out/bin/piggy \
              --set PIGGY_SH_PATH $out/libexec/piggy/piggy.sh \
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

        piggy-agent-conformance = pkgs.buildGoModule {
          pname = "piggy-agent-conformance";
          version = piggyVersion;

          src = pkgs.lib.fileset.toSource {
            root = ./go;
            fileset = pkgs.lib.fileset.unions [
              ./go/go.mod
              ./go/go.sum
              ./go/main.go
            ];
          };

          vendorHash = "sha256-P8Y1OaDAgNbfGA99vNeXlfOuQqpMhHPebxYceLgZew0=";

          postInstall = ''
            mv $out/bin/conformance $out/bin/piggy-agent-conformance
          '';

          meta = with pkgs.lib; {
            description = "Go-based SSH agent conformance tests for piggy";
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
          # (mock-pivy-box.sh etc.) win over what piggy.sh invokes.
          piggyRs = piggy-rs;
          # Wrapped piggy: source of `$out/libexec/piggy/piggy.sh`
          # and `$out/libexec/piggy/piggy-ids` referenced by the
          # extraEnv (PIGGY_SH_PATH, PIGGY_IDS_REAL).
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

        # Tree-wide formatter: nixfmt + shfmt + rustfmt under one
        # wrapper. Exposed as `formatter.${system}` (so `nix fmt`
        # works) and dropped into the devShell so `treefmt` resolves
        # there too. See ./treefmt.nix for the program config.
        treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
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
          # snapshot, runs treefmt, fails if any file would change.
          # Driven from `just lint-fmt` and surfaced under `nix flake
          # check`.
          formatting = treefmtEval.config.build.check self;
        };

        formatter = treefmtEval.config.build.wrapper;

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
              treefmtEval.config.build.wrapper
              pkgs.scdoc
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
              # `just fib-up` needs pcscd + fib + opensc-tool on PATH.
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
