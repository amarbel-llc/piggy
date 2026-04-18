{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/4590696c8693fea477850fe379a01544293ca4e2";
    nixpkgs-master.url = "github:NixOS/nixpkgs/e2dde111aea2c0699531dc616112a96cd55ab8b5";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";

    pivy = {
      url = "github:amarbel-llc/pivy";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixpkgs-master.follows = "nixpkgs-master";
      inputs.utils.follows = "utils";
    };

    bob = {
      url = "github:amarbel-llc/bob";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixpkgs-master.follows = "nixpkgs-master";
      inputs.utils.follows = "utils";
    };

  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-master,
      utils,
      pivy,
      bob,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        pkgs-master = import nixpkgs-master { inherit system; };

        # Runtime deps on PATH for the wrapped piggy binary. `pivy` is kept
        # as a fallback for subcommands the rust binary hasn't implemented
        # yet (box/tool/ca/luks/zfs) — see crates/piggy/src/fallback.rs.
        runtimeDeps = [
          pivy.packages.${system}.default
          pkgs.git
          pkgs.tree
          pkgs.qrencode
          pkgs.getopt
          pkgs.gnugrep
          pkgs.coreutils
        ];

        # Native rust workspace: `piggy` (binary) + `piggy-piv` (library).
        # pcsclite is only needed on linux; macOS has PC/SC in CoreServices.
        rustBuildInputs = [ pkgs.openssl ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.pcsclite ];
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

          nativeBuildInputs = [ pkgs.makeWrapper ];

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
            install -m 0644 man/piggy.1 $out/share/man/man1/piggy.1

            # --run guards LIBPCSCLITE_DELEGATE with a file-existence check:
            # on hosts where a matching system libpcsclite.so.1 is present
            # (e.g. Ubuntu's apt-installed 2.0.3 when piggy's nix lib is 2.3.0
            # and can't talk to the running Ubuntu pcscd), route through it.
            # On NixOS or hosts without the Ubuntu path, stays unset and the
            # nix libpcsclite_real.so.1 is used as-is. See issue #6.
            makeWrapper $out/libexec/piggy/piggy-rs $out/bin/piggy \
              --set PIGGY_SH_PATH $out/libexec/piggy/piggy.sh \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeDeps} \
              --run '[[ -f /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 ]] && export LIBPCSCLITE_DELEGATE=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1 || true'
          '';

          # Expose the Go-based SSH-agent conformance binary as a test
          # attribute of the main piggy package. Reachable via
          # `nix build .#piggy.tests.conformance` and enumerated by
          # `nix flake check`. Keeps the relationship between the agent
          # and its wire-protocol oracle explicit without merging the
          # Rust and Go toolchains into one derivation.
          passthru.tests = {
            conformance = piggy-agent-conformance;
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
        packages.default = piggy;
        packages.piggy = piggy;
        packages.piggy-rs = piggy-rs;
        packages.piggy-agent-conformance = piggy-agent-conformance;

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
              bob.packages.${system}.batman
            ];

          # Help the openssl + pcsc-sys crates find their libraries
          # without having to vendor, mirroring pivy's flake semantics.
          OPENSSL_NO_VENDOR = "1";
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.lib.getLib pkgs.openssl}/lib";

          # Work around issue #6: piggy's nix libpcsclite 2.3.0 client can't
          # speak the 2.0.x IPC protocol used by Ubuntu's apt-installed pcscd.
          # The nix libpcsclite shim honours LIBPCSCLITE_DELEGATE and dlopens
          # that path in place of libpcsclite_real.so.1. Guarded with [[ -f ]]
          # so NixOS devshells (and anywhere without the Ubuntu lib) are a
          # no-op; the shim errors on a missing delegate, so guarding is
          # mandatory.
          shellHook = ''
            if [[ -f /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 ]]; then
              export LIBPCSCLITE_DELEGATE=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1
            fi
          '';
        };
      }
    ));
}
