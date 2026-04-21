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
  # The pom.xml's `initialize` phase runs install-file on
  # $JC_CLASSIC_HOME/lib/api_classic.jar to register the Oracle SDK jar
  # in Maven's local repo. We set JC_CLASSIC_HOME to the jc305u3_kit
  # path inside the vendored oracle_javacard_sdks input.
  #
  # NOTE: mvnHash is a placeholder. On first build nix will error with
  # "hash mismatch" and print the actual hash; copy it into this file.
  jcardsim = pkgs.maven.buildMavenPackage {
    pname = "jcardsim";
    version = "3.0.5-SNAPSHOT";
    src = jcardsim-src;

    # buildMavenPackage's fetchedMavenDeps sub-derivation (FOD) only
    # inherits `src`, `sourceRoot`, and `patches` from the outer
    # attrset — env vars don't propagate, and dependency resolution
    # runs before the `initialize` phase (so the upstream pom's
    # install-file plugin never gets a chance to register api_classic
    # in the local repo). We instead rewrite the dependency inline to
    # a `<scope>system</scope>` reference to the vendored SDK jar, and
    # also rewrite the `${env.JC_CLASSIC_HOME}` reference in the
    # install-file plugin config so its harmless re-execution at the
    # `initialize` phase still succeeds.
    postPatch = ''
      substituteInPlace pom.xml \
        --replace-fail \
          '<scope>compile</scope>' \
          '<scope>system</scope><systemPath>${oracle-javacard-sdks-src}/jc305u3_kit/lib/api_classic.jar</systemPath>'
      sed -i "s|\''${env.JC_CLASSIC_HOME}|${oracle-javacard-sdks-src}/jc305u3_kit|g" pom.xml
    '';

    mvnHash = "sha256-0lslxntkRr7e+Jhu8GLZgy2aeA6s96oH/gue2T7bsIQ=";
    # Upstream pom targets Java 1.7 (`<java.version>1.7</java.version>`)
    # which JDK 21 dropped support for. Override via the same property.
    mvnParameters = "-Dmaven.test.skip=true -Dgpg.skip=true -Djava.version=1.8 package";

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

  # reader.conf snippet pointing at the nix-store-provided vpcd PCSC driver.
  # Used by `just fib-up` to start a private pcscd; not intended for
  # installation into /etc/reader.conf.d/.
  #
  # CHANNELID is the default TCP port vpcd listens on for the applet side
  # of the connection (35963 = 0x8C7B).
  readerConf = pkgs.writeText "fib-reader.conf" ''
    FRIENDLYNAME      "Virtual PCD piggy fib"
    DEVICENAME        /dev/null:0x8C7B
    LIBPATH           ${pkgs.vsmartcard-vpcd}/lib/pcsc/drivers/serial/libifdvpcd.so
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
    ln -s ${readerConf} $out/share/fib/reader.conf
    ln -s ${pkgs.vsmartcard-vpcd} $out/share/fib/vsmartcard-vpcd
    ln -s ${jcardsim} $out/share/fib/jcardsim
    ln -s ${pivapplet} $out/share/fib/pivapplet
  '';
in
{
  inherit
    jcardsim
    pivapplet
    readerConf
    fib
    fibBundle
    ;
}
