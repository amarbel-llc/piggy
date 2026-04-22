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
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-master,
      utils,
      bob,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        pkgs-master = import nixpkgs-master {
          inherit system;
        };

        libressl-src = pkgs.fetchurl {
          url = "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.0.0.tar.gz";
          sha256 = "sha256-TYQZVfCsw9/HHQ49018oOvRhIiNQ4mhD/qlzHAJGoeQ=";
        };

        openssh-src = pkgs.fetchurl {
          url = "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.0p1.tar.gz";
          sha256 = "sha256-AhoucJoO30JQsSVr1anlAEEakN3avqgw7VnO+Q652Fw=";
        };

        libressl = pkgs.stdenv.mkDerivation {
          pname = "libressl-pivy";
          version = "4.0.0";

          src = libressl-src;

          configureFlags = [
            "--enable-static"
            "--disable-asm" # Simplify cross-compilation
          ];

          CFLAGS = "-fPIC -Wno-error";
          LDFLAGS = "";

          buildPhase = ''
            cd crypto
            make -j$NIX_BUILD_CORES
          '';

          installPhase = ''
            mkdir -p $out/lib $out/include
            # Copy static libraries only
            cp .libs/libcrypto.a $out/lib/
            cp .libs/libcompat.a $out/lib/ || true
            cp .libs/libcompatnoopt.a $out/lib/ || true
            # Copy headers
            cp -r ../include/* $out/include/
          '';
        };

        openssh = pkgs.stdenv.mkDerivation {
          pname = "openssh-libssh-pivy";
          version = "10.0p1";

          src = openssh-src;

          patches = [ ./openssh.patch ];

          buildInputs = [
            libressl
            pkgs.zlib
          ];
          nativeBuildInputs = [ pkgs.pkg-config ];

          configureFlags = [
            "--disable-security-key"
            "--disable-pkcs11"
            "--with-ssl-dir=${libressl}"
          ];

          CFLAGS = pkgs.lib.concatStringsSep " " [
            "-I${libressl}/include"
            "-I${pkgs.zlib.dev}/include"
            "-fPIC"
            "-Wno-error"
          ];

          LDFLAGS = pkgs.lib.concatStringsSep " " [
            "-L${libressl}/lib"
            "-L${pkgs.zlib}/lib"
          ];

          buildPhase = ''
            runHook preBuild

            # Build openbsd-compat library first
            make -C openbsd-compat libopenbsd-compat.a

            # Source files for libssh.a (from pivy Makefile _LIBSSH_SOURCES)
            LIBSSH_SRCS="
              sshbuf.c sshbuf-getput-basic.c sshbuf-getput-crypto.c sshbuf-misc.c
              sshkey.c ssh-ed25519.c ssh-ecdsa.c ssh-rsa.c ssh-dss.c
              cipher.c cipher-chachapoly.c cipher-chachapoly-libcrypto.c
              digest-openssl.c atomicio.c hmac.c authfd.c
              misc.c match.c ssh-sk.c log.c fatal.c
              xmalloc.c addrmatch.c addr.c
              ed25519.c hash.c chacha.c poly1305.c
            "

            # Compile each source file
            for src in $LIBSSH_SRCS; do
              echo "Compiling $src"
              $CC $NIX_CFLAGS_COMPILE $CFLAGS -I. -Iopenbsd-compat -DHAVE_CONFIG_H -c "$src" -o "''${src%.c}.o"
            done

            # Create static library combining our objects with openbsd-compat
            ar rcs libssh.a *.o openbsd-compat/*.o

            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            mkdir -p $out/lib $out/src

            # Install static library
            install -m 644 libssh.a $out/lib/

            # Install full source tree (needed by pivy Makefile dependencies)
            cp -r . $out/src/

            # Also copy libssh.a into src where Makefile expects it
            cp libssh.a $out/src/libssh.a

            runHook postInstall
          '';
        };

        buildInputs =
          with pkgs;
          [
            libbsd
            libedit
            zlib
          ]
          ++ pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [
            pcsclite
          ];

        nativeBuildInputs = with pkgs; [
          gcc
          gnumake
          pkg-config
          ragel
          curl
          gnutar
          patch
          makeWrapper
          asciidoctor
        ];

        pivy-rust = pkgs.rustPlatform.buildRustPackage {
          pname = "pivy-agent";
          version = "0.1.0";

          src = ./rust;

          cargoLock = {
            lockFile = ./rust/Cargo.lock;
          };

          buildInputs = [
            pkgs.openssl.dev
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.pcsclite
          ];

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

          doCheck = !pkgs.stdenv.hostPlatform.isDarwin;

          meta = with pkgs.lib; {
            description = "PIV-backed SSH agent (Rust)";
            homepage = "https://github.com/amarbel-llc/pivy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        pivy-agent-conformance = pkgs.buildGoModule {
          pname = "pivy-agent-conformance";
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
            mv $out/bin/conformance $out/bin/pivy-agent-conformance
          '';

          meta = with pkgs.lib; {
            description = "Go-based SSH agent conformance tests for pivy";
            homepage = "https://github.com/amarbel-llc/pivy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # Extract YYYY-MM-DD from the flake's lastModifiedDate (YYYYMMDDHHmmSS)
        revdate =
          let
            d = self.lastModifiedDate;
          in
          "${builtins.substring 0 4 d}-${builtins.substring 4 2 d}-${builtins.substring 6 2 d}";

        pivy = pkgs.stdenv.mkDerivation {
          pname = "pivy";
          version = "0.15.0";

          src = ./.;

          inherit buildInputs nativeBuildInputs;

          preBuild = ''
            # Copy openssh source tree (Makefile needs .c files for dependency checking)
            cp -r ${openssh}/src openssh
            chmod -R +w openssh

            # The pre-built libssh.a is already in openssh/ from the derivation

            # Create minimal libressl structure with pre-built library
            mkdir -p libressl/include libressl/crypto/.libs
            ln -sf ${libressl}/include/* libressl/include/
            ln -sf ${libressl}/lib/libcrypto.a libressl/crypto/.libs/libcrypto.a

            # Create a no-op Makefile in libressl/crypto
            cat > libressl/crypto/Makefile <<'EOF'
            all:
            	@true
            EOF

            # Touch markers to skip extract/patch/configure steps
            touch .libressl.extract .libressl.patch .libressl.configure
            touch .openssh.extract .openssh.patch .openssh.configure

            # Touch libssh.a to ensure it's newer than any source files
            touch openssh/libssh.a
          '';

          buildPhase = ''
            runHook preBuild
            make -j$NIX_BUILD_CORES \
              LIBRESSL_INC=${libressl}/include \
              LIBRESSL_LIB=${libressl}/lib \
              ZLIB_LIB=${pkgs.zlib}/lib \
              SYSTEM_CFLAGS="${pkgs.lib.optionalString pkgs.stdenv.isDarwin "-arch ${pkgs.stdenv.hostPlatform.darwinArch}"}${pkgs.lib.optionalString pkgs.stdenv.isLinux "$(pkg-config --cflags libbsd-overlay) -DHAVE_USER_FROM_UID -DHAVE_STRMODE -DHAVE_GROUP_FROM_GID"} -DPIVY_ASKPASS_DEFAULT='\"$out/libexec/pivy/pivy-askpass\"'" \
              SYSTEM_LDFLAGS="${pkgs.lib.optionalString pkgs.stdenv.isDarwin "-arch ${pkgs.stdenv.hostPlatform.darwinArch}"}${pkgs.lib.optionalString pkgs.stdenv.isLinux "$(pkg-config --libs libbsd-overlay)"}"
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            install -m 755 pivy-tool $out/bin/.pivy-tool-unwrapped
            install -m 755 pivy-agent $out/bin/.pivy-agent-unwrapped
            install -m 755 pivy-box $out/bin/.pivy-box-unwrapped
            install -m 755 pivy-wire-test $out/bin/pivy-wire-test

            # Create wrapper scripts that preload system pcsclite
            # This is needed on non-NixOS where pcscd version must match client library
            for cmd in pivy-tool pivy-agent pivy-box; do
              cat > $out/bin/$cmd <<WRAPPER
            #!/bin/sh
            for lib in \\
              /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \\
              /usr/lib/aarch64-linux-gnu/libpcsclite.so.1 \\
              /usr/lib/libpcsclite.so.1 \\
              /lib/x86_64-linux-gnu/libpcsclite.so.1 \\
              /lib/libpcsclite.so.1; do
              if [ -e "\$lib" ]; then
                export LD_PRELOAD="\$lib\''${LD_PRELOAD:+:\$LD_PRELOAD}"
                break
              fi
            done
            exec $out/bin/.$cmd-unwrapped "\$@"
            WRAPPER
              chmod +x $out/bin/$cmd
            done
            # Build and install manpages
            mkdir -p $out/share/man/man1
            for adoc in man/*.1.adoc; do
              asciidoctor -b manpage \
                -a pivy-version=${pivy.version} \
                -a revdate=${revdate} \
                -D $out/share/man/man1 \
                "$adoc"
            done

            # Install service files
            ${pkgs.lib.optionalString pkgs.stdenv.isLinux ''
              mkdir -p $out/lib/systemd/user
              substitute pivy-agent@.service $out/lib/systemd/user/pivy-agent@.service \
                --replace-fail '@@BINDIR@@' "$out/bin"
            ''}
            ${pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              mkdir -p $out/share/pivy
              substitute macosx/net.cooperi.pivy-agent.plist $out/share/pivy/net.cooperi.pivy-agent.plist \
                --replace-fail '/opt/pivy/bin/pivy-agent' "$out/bin/pivy-agent"
            ''}

            # Install askpass/notify wrapper scripts with baked-in paths
            mkdir -p $out/libexec/pivy

            cat > $out/libexec/pivy/pivy-askpass <<ASKPASS
            #!/bin/sh
            exec ${pkgs.zenity}/bin/zenity --password --title="\$1"
            ASKPASS
            chmod +x $out/libexec/pivy/pivy-askpass

            cat > $out/libexec/pivy/pivy-notify <<NOTIFY
            #!/bin/sh
            case "\$(uname)" in
              Darwin) exec ${
                if pkgs.stdenv.isDarwin then
                  "${pkgs.terminal-notifier}/bin/terminal-notifier"
                else
                  "terminal-notifier"
              } -title "\$1" -message "\$2" ;;
              *)      exec ${
                if pkgs.stdenv.isLinux then "${pkgs.libnotify}/bin/notify-send" else "notify-send"
              } "\$1" "\$2" ;;
            esac
            NOTIFY
            chmod +x $out/libexec/pivy/pivy-notify

            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "PIV tools for YubiKey and similar hardware tokens";
            homepage = "https://github.com/arekinath/pivy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };
      in
      {
        packages.default = pivy;
        packages.pivy = pivy;
        packages.pivy-rust = pivy-rust;
        packages.pivy-agent-conformance = pivy-agent-conformance;
        packages.libressl = libressl;
        packages.openssh = openssh;

        devShells.default = pkgs.mkShell {
          packages =
            buildInputs
            ++ nativeBuildInputs
            ++ (with pkgs; [
              just
              gum
            ])
            ++ [
              bob.packages.${system}.batman
              bob.packages.${system}.sandcastle
              bob.packages.${system}.tap-dancer
            ];
        };

        devShells.rust = pkgs.mkShell {
          packages = [
            pkgs.rustc
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy
            pkgs.pkg-config
            pkgs.openssl.dev
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.pcsclite
          ];
        };
      }
    ));
}
