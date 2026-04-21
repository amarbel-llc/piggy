# Virtual PIV smart card support for piggy tests.
#
# Builds jcardsim (Maven) and PivApplet (ant preprocess → javac) and exposes
# `fib`, a launcher that runs PivApplet inside jCardSim attached to a
# vsmartcard-vpcd virtual reader over TCP.
#
# The pcscd-side wiring is handled by `just fib-up` / `just fib-down`:
# they launch a private pcscd with the reader.conf emitted here, set
# PCSCLITE_CSOCK_NAME, and leave pivy-tool reachable against the virtual
# reader without touching /etc/reader.conf.d/.
#
# See docs/virtual-piv.md for usage.
#
# LICENSING: jcardsim's Maven build requires the Oracle JavaCard SDK
# 3.0.5u3 at compile time (pom.xml `initialize` phase runs install-file
# on $JC_CLASSIC_HOME/lib/api_classic.jar). We source that from
# martinpaljak/oracle_javacard_sdks, which vendors the upstream Oracle
# binaries. Oracle's Binary Code License permits redistribution when
# bundled as part of Your Programs with unmodified legends (see
# jc305u3_kit/legal/Distribution_ReadME.txt inside the SDK repo). The
# resulting jcardsim.jar contains the javacard.* bytecode from Oracle
# and is used at test time only — piggy's runtime CLI does not ship
# jcardsim.jar or any Oracle material. If that changes, revisit the
# license posture.

{
  pkgs,
  pkgs-master,
  jcardsim-src,
  pivapplet-src,
  oracle-javacard-sdks-src,
}:

let
  # jcardsim is Java 8-compatible; PivApplet preprocessing + javac work on
  # any modern JDK. Use headless variant to avoid AWT deps.
  jdk = pkgs.jdk21_headless;

  # jcardsim 3.0.5-SNAPSHOT. Maven produces
  # target/jcardsim-3.0.5-SNAPSHOT.jar which embeds the simulator runtime
  # (`com.licel.jcardsim.*`) plus the javacard.* API classes unpacked
  # from Oracle's api_classic.jar. PivApplet compiles against the
  # javacard.* classes from this jar at runtime.
  #
  # Maven dependencies are vendored in nix/jcardsim-m2/ (captured by
  # `just debug-capture-jcardsim-m2`). This eliminates the
  # buildMavenPackage FOD whose hash drifts when Maven Central changes
  # dependency metadata. Re-run that recipe when bumping the jcardsim
  # flake input.
  jcardsim = pkgs.stdenv.mkDerivation {
    pname = "jcardsim";
    version = "3.0.5-SNAPSHOT";
    src = jcardsim-src;

    nativeBuildInputs = [
      jdk
      pkgs.maven
    ];

    postPatch = ''
      substituteInPlace pom.xml \
        --replace-fail \
          '<scope>compile</scope>' \
          '<scope>system</scope><systemPath>${oracle-javacard-sdks-src}/jc305u3_kit/lib/api_classic.jar</systemPath>'
      sed -i "s|\''${env.JC_CLASSIC_HOME}|${oracle-javacard-sdks-src}/jc305u3_kit|g" pom.xml
    '';

    buildPhase = ''
      runHook preBuild

      cp -dpR ${./jcardsim-m2} mvnDeps
      chmod -R u+w mvnDeps

      mvn package -o -nsu \
        "-Dmaven.repo.local=mvnDeps" \
        -Dmaven.test.skip=true \
        -Dgpg.skip=true \
        -Djava.version=1.8

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/share/java
      install -m 0644 target/jcardsim-3.0.5-SNAPSHOT.jar $out/share/java/
      runHook postInstall
    '';

    meta = with pkgs.lib; {
      description = "Java Card simulator (arekinath's fork, used by PivApplet)";
      homepage = "https://github.com/arekinath/jcardsim";
      license = licenses.asl20;
      platforms = platforms.unix;
    };
  };

  # PivApplet compiled into .class files suitable for jCardSim loading.
  #
  # We deliberately skip the upstream `ant dist` target — that invokes
  # ant-javacard and needs a JavaCard SDK to produce a CAP file for real
  # hardware. For simulation we only need preprocessed sources compiled
  # against jcardsim's embedded JavaCard API classes.
  pivapplet = pkgs.stdenv.mkDerivation {
    pname = "pivapplet-classes";
    version = "0-unstable";
    src = pivapplet-src;

    nativeBuildInputs = [
      jdk
      pkgs.ant
    ];

    # ant preprocess expands //#if directives in PivApplet sources via the
    # vendored ext/jpp-1.0.3.jar (a tiny jar, already in the repo tree).
    # It does NOT recurse into ext/ant or invoke javacard tasks.
    buildPhase = ''
      runHook preBuild

      ant preprocess

      mkdir -p bin
      find src-gen -name '*.java' -print >sources.list
      javac \
        -cp "${jcardsim}/share/java/jcardsim-3.0.5-SNAPSHOT.jar" \
        -d bin \
        @sources.list

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/classes
      cp -r bin/. $out/classes/
      install -m 0644 test/jcardsim.cfg $out/jcardsim.cfg
      runHook postInstall
    '';

    meta = with pkgs.lib; {
      description = "PivApplet compiled for jCardSim simulation (no JavaCard SDK)";
      homepage = "https://github.com/arekinath/PivApplet";
      license = licenses.mpl20;
      platforms = platforms.unix;
    };
  };

  # Custom pcscd. Two constraints:
  #
  # 1. A different ipcdir so the private instance won't collide with a
  #    system pcscd over /run/pcscd/pcscd.pid (pcscdaemon.c reads that
  #    file, does kill(pid, 0), and aborts with EPERM if a root-owned
  #    system daemon is running and our user-level pcscd can't signal
  #    it). Override via meson -Dipcdir=/tmp/piggy-fib-ipc.
  #
  # 2. Use pkgs-master.pcsclite (2.4.1) for IPC protocol compatibility,
  #    mirroring the fix from issue #6: pcsclite 2.4.1 negotiates with
  #    clients as old as 1.8.24, so older system libpcsclite.so (e.g.
  #    Ubuntu 24.04's 2.0.3 that pivy-tool's wrapper LD_PRELOADs) can
  #    still talk to our daemon. Building with pkgs.pcsclite (2.3.0)
  #    broke that compatibility and pivy-tool failed to connect.
  #
  # Clients redirect via PCSCLITE_CSOCK_NAME at runtime so the ipcdir
  # only affects the daemon's own bookkeeping files; clients need
  # libpcsclite.so built with PCSCLITE_CSOCK_NAME env support (true
  # for pcsclite ≥ ~2.0.0).
  pcscdForFib = pkgs-master.pcsclite.overrideAttrs (old: {
    pname = "pcscd-for-fib";
    mesonFlags = (old.mesonFlags or [ ]) ++ [
      "-Dipcdir=/tmp/piggy-fib-ipc"
    ];
  });

  # reader.conf snippet pointing at the nix-store-provided vpcd PCSC driver.
  # Used by `just fib-up` to start a private pcscd; not intended for
  # installation into /etc/reader.conf.d/.
  #
  # CHANNELID is the default TCP port vpcd listens on for the applet side
  # of the connection (35963 = 0x8C7B).
  readerConf = pkgs.writeText "fib-reader.conf" ''
    FRIENDLYNAME      "Virtual PCD piggy fib"
    DEVICENAME        /dev/null:0x8C7B
    LIBPATH           ${pkgs.vsmartcard-vpcd}/var/lib/pcsc/drivers/serial/libifdvpcd.so
    CHANNELID         0x8C7B
  '';

  # Launcher: starts PivApplet inside jCardSim. The applet connects to
  # whatever vpcd is listening on localhost:35963 — that is either a
  # private pcscd launched by `just fib-up`, or a system pcscd with the
  # vpcd driver registered manually.
  fib = pkgs.writeShellApplication {
    name = "fib";
    runtimeInputs = [ jdk ];
    text = ''
      cfg="''${FIB_CFG:-${pivapplet}/jcardsim.cfg}"

      if [ ! -f "$cfg" ]; then
        echo "fib: config not found: $cfg" >&2
        exit 1
      fi

      exec java -noverify \
        -cp "${pivapplet}/classes:${jcardsim}/share/java/jcardsim-3.0.5-SNAPSHOT.jar" \
        com.licel.jcardsim.remote.VSmartCard \
        "$cfg"
    '';
  };

  # Convenience bundle: the launcher plus paths consumers (justfile,
  # docs) might need. Exposed via `passthru.tests.fib` on the piggy
  # package for reachability.
  fibBundle = pkgs.runCommand "fib-bundle" { } ''
    mkdir -p $out/bin $out/share/fib
    ln -s ${fib}/bin/fib $out/bin/fib
    ln -s ${pcscdForFib}/bin/pcscd $out/bin/pcscd-fib
    ln -s ${readerConf} $out/share/fib/reader.conf
    ln -s ${pkgs.vsmartcard-vpcd} $out/share/fib/vsmartcard-vpcd
    ln -s ${jcardsim} $out/share/fib/jcardsim
    ln -s ${pivapplet} $out/share/fib/pivapplet
    ln -s ${pcscdForFib} $out/share/fib/pcscd
    ln -s ${pkgs.opensc}/bin/opensc-tool $out/bin/opensc-tool
  '';
in
{
  inherit
    jcardsim
    pivapplet
    pcscdForFib
    readerConf
    fib
    fibBundle
    ;
}
