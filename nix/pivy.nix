# Local derivation for the pivy tree vendored under ./vendor/pivy.
#
# Ported from vendor/pivy/flake.nix so piggy can consume pivy as a plain
# nix derivation instead of a nested flake input. See piggy #21 for the
# vendoring decision and the motivation to avoid nested flakes.
#
# Background: pivy itself originated at arekinath/pivy. amarbel-llc
# previously maintained a fork at github.com/amarbel-llc/pivy, but
# that fork is now archived — all ongoing pivy work happens in this
# tree under vendor/pivy/. The vendored copy IS pivy as far as piggy
# is concerned.
#
# This file reproduces only the outputs piggy actually uses today —
# `packages.default` from the upstream flake, i.e. the C pivy binaries
# (pivy-tool, pivy-agent, pivy-box, pivy-wire-test) plus their
# LD_PRELOAD wrapper scripts, manpages, and systemd/launchd service
# files. The upstream flake's pivy-rust and pivy-agent-conformance
# outputs are intentionally excluded — nothing in piggy references
# them.
#
# Inputs:
#   pkgs: the nixpkgs set piggy's flake already imports.
#   src:  a path to the vendored pivy tree (typically ./vendor/pivy).
#         Used verbatim as the pivy mkDerivation's src and as the
#         origin of patches/source files (openssh.patch, manpages).
#
# Output: a single derivation with the C pivy package layout upstream
# would have produced under `pivy.packages.${system}.default`.

{ pkgs, src }:

let
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
      "--disable-asm"
    ];

    CFLAGS = "-fPIC -Wno-error";
    LDFLAGS = "";

    buildPhase = ''
      cd crypto
      make -j$NIX_BUILD_CORES
    '';

    installPhase = ''
      mkdir -p $out/lib $out/include
      cp .libs/libcrypto.a $out/lib/
      cp .libs/libcompat.a $out/lib/ || true
      cp .libs/libcompatnoopt.a $out/lib/ || true
      cp -r ../include/* $out/include/
    '';
  };

  openssh = pkgs.stdenv.mkDerivation {
    pname = "openssh-libssh-pivy";
    version = "10.0p1";

    src = openssh-src;

    patches = [ "${src}/openssh.patch" ];

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

      make -C openbsd-compat libopenbsd-compat.a

      LIBSSH_SRCS="
        sshbuf.c sshbuf-getput-basic.c sshbuf-getput-crypto.c sshbuf-misc.c
        sshkey.c ssh-ed25519.c ssh-ecdsa.c ssh-rsa.c ssh-dss.c
        cipher.c cipher-chachapoly.c cipher-chachapoly-libcrypto.c
        digest-openssl.c atomicio.c hmac.c authfd.c
        misc.c match.c ssh-sk.c log.c fatal.c
        xmalloc.c addrmatch.c addr.c
        ed25519.c hash.c chacha.c poly1305.c
      "

      for s in $LIBSSH_SRCS; do
        echo "Compiling $s"
        $CC $NIX_CFLAGS_COMPILE $CFLAGS -I. -Iopenbsd-compat -DHAVE_CONFIG_H -c "$s" -o "''${s%.c}.o"
      done

      ar rcs libssh.a *.o openbsd-compat/*.o

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall

      mkdir -p $out/lib $out/src

      install -m 644 libssh.a $out/lib/

      cp -r . $out/src/

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
in
pkgs.stdenv.mkDerivation {
  pname = "pivy";
  version = "0.15.0";

  inherit src buildInputs nativeBuildInputs;

  preBuild = ''
    cp -r ${openssh}/src openssh
    chmod -R +w openssh

    mkdir -p libressl/include libressl/crypto/.libs
    ln -sf ${libressl}/include/* libressl/include/
    ln -sf ${libressl}/lib/libcrypto.a libressl/crypto/.libs/libcrypto.a

    cat > libressl/crypto/Makefile <<'EOF'
    all:
    	@true
    EOF

    touch .libressl.extract .libressl.patch .libressl.configure
    touch .openssh.extract .openssh.patch .openssh.configure

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

    mkdir -p $out/share/man/man1
    for adoc in man/*.1.adoc; do
      asciidoctor -b manpage \
        -a pivy-version=0.15.0 \
        -a revdate=vendored \
        -D $out/share/man/man1 \
        "$adoc"
    done

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
    # The standalone amarbel-llc/pivy fork is archived; piggy now
    # vendors pivy under vendor/pivy/ as the canonical source. The
    # homepage points at piggy where issues are tracked.
    description = "PIV tools for YubiKey and similar hardware tokens (vendored under piggy/vendor/pivy)";
    homepage = "https://github.com/amarbel-llc/piggy";
    license = licenses.mpl20;
    platforms = platforms.linux ++ platforms.darwin;
  };
}
