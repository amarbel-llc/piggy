{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/4590696c8693fea477850fe379a01544293ca4e2";
    nixpkgs-master.url = "github:NixOS/nixpkgs/e2dde111aea2c0699531dc616112a96cd55ab8b5";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";

    bob = {
      url = "github:amarbel-llc/bob";
      inputs.nixpkgs.follows = "nixpkgs";
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

  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-master,
      utils,
      bob,
      jcardsim,
      pivapplet,
      oracle-javacard-sdks,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
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

        # Native rust workspace: `piggy` (binary) + `piggy-piv` (library).
        # pcsclite is only needed on linux; macOS has PC/SC in CoreServices.
        # Uses pkgs-master (2.4.1) for backward-compatible IPC protocol
        # negotiation — a 2.4.1 client can talk to daemons as old as 1.8.24,
        # which covers Ubuntu 24.04's 2.0.3 pcscd without workarounds.
        rustBuildInputs = [ pkgs.openssl ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs-master.pcsclite ];
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
              base == "Cargo.toml" || base == "Cargo.lock" || pkgs.lib.hasPrefix "crates" rel;
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
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [ pkgs.makeWrapper pkgs.scdoc ];

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/bin \
                     $out/libexec/piggy \
                     $out/libexec/piggy/platform \
                     $out/share/man/man1

            # Stash the rust dispatcher and bash script at known paths,
            # then wrap the rust binary as $out/bin/piggy with PIGGY_SH_PATH
            # set so fallback::find_piggy_sh locates the bash script.
            install -m 0755 ${piggy-rs}/bin/piggy \
                            $out/libexec/piggy/piggy-rs
            install -m 0755 src/piggy.sh \
                            $out/libexec/piggy/piggy.sh
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

            makeWrapper $out/libexec/piggy/piggy-rs $out/bin/piggy \
              --set PIGGY_SH_PATH $out/libexec/piggy/piggy.sh \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeDeps}
          '';

          # Expose the Go-based SSH-agent conformance binary as a test
          # attribute of the main piggy package. Reachable via
          # `nix build .#piggy.tests.conformance` and enumerated by
          # `nix flake check`. Keeps the relationship between the agent
          # and its wire-protocol oracle explicit without merging the
          # Rust and Go toolchains into one derivation.
          passthru.tests =
            {
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
          version = "0.1.0";

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
      in
      {
        packages =
          {
            default = piggy;
            piggy = piggy;
            piggy-rs = piggy-rs;
            piggy-agent-conformance = piggy-agent-conformance;
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            fib = virtualPiv.fib;
            fib-bundle = virtualPiv.fibBundle;
            fib-reader-conf = virtualPiv.readerConf;
            fib-pcscd = virtualPiv.pcscdForFib;
            jcardsim = virtualPiv.jcardsim;
            pivapplet = virtualPiv.pivapplet;
          };

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
              pkgs.scdoc
              bob.packages.${system}.batman
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
      # System-independent outputs. The home-manager module is sourced
      # by users from this flake; they're expected to include their own
      # nixpkgs and pass `pkgs.piggy` (or `pkgs.pivy`) via the module's
      # `package` option. See docs/plans/2026-04-27-piggy-agent-nix-module.md
      # for design rationale and the full module surface.
      homeManagerModules.piggy-agent = import ./nix/hm/piggy-agent.nix;
      homeManagerModules.default = import ./nix/hm/piggy-agent.nix;
    };
}
