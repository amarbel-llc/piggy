# Virtual PIV smart card (fib)

Piggy's tests target a real PC/SC stack: a YubiKey over libpcsclite, with
`pivy-tool` and `piggy` speaking to it through a live `pcscd`. Running
those tests against a hardware card is expensive (easy to consume PIN
retries, requires human touch confirmations, only works on machines with
a card plugged in). `fib` is the software alternative: an in-repo nix
derivation that builds `PivApplet` inside `jCardSim` and attaches it to a
private `pcscd` through `vsmartcard-vpcd`.

## What's built

The packaging lives in [`nix/virtual-piv.nix`](../nix/virtual-piv.nix) and
is plumbed through the top-level [`flake.nix`](../flake.nix). Linux only
— upstream `vsmartcard` is marked broken on darwin.

| Derivation | Produces | Notes |
|---|---|---|
| `jcardsim` | `$out/share/java/jcardsim-3.0.5-SNAPSHOT.jar` | Maven-built fork (arekinath/jcardsim). Includes a reimplementation of the JavaCard APIs, so compiling the applet does **not** require the Oracle JavaCard SDK. |
| `pivapplet` | `$out/classes/**/*.class`, `$out/jcardsim.cfg` | `ant preprocess` (vendored `ext/jpp-1.0.3.jar`) then `javac` against `jcardsim.jar`. `ant dist` is skipped — we never emit a CAP file. |
| `fib-reader-conf` | `reader.conf` text | Points `LIBPATH` at the nix-store `libifdvpcd.so`. Consumed by the private `pcscd`. |
| `fib` | `bin/fib` | Launches `java com.licel.jcardsim.remote.VSmartCard`. Connects to the vpcd TCP listener at `localhost:35963`. |
| `fib-bundle` | `bin/fib` + convenience symlinks under `share/fib/` | What `piggy.passthru.tests.fib` points at. |

Flake outputs on Linux:

- `.#fib` — the launcher (`nix run .#fib`)
- `.#fib-bundle` — bundle with reader.conf/vsmartcard-vpcd symlinked alongside
- `.#fib-reader-conf` — the `reader.conf` snippet
- `.#jcardsim`, `.#pivapplet` — underlying artifacts

## First build: discovering `mvnHash`

`jcardsim` is built with `pkgs.maven.buildMavenPackage`, which needs a
pre-computed hash of its Maven dependency closure. The first build will
fail with a hash mismatch error and print the actual hash. Copy that
into [`nix/virtual-piv.nix`](../nix/virtual-piv.nix) and rebuild:

```sh
nix build .#jcardsim 2>&1 | tee build.log
# look for "got:    sha256-<hash>" in the error output,
# paste it into nix/virtual-piv.nix as mvnHash.
nix build .#jcardsim        # succeeds
```

The placeholder `sha256-AAAA…` is intentional — first build expects to fail.

## Runtime use: `just fib-up` / `fib-down` / `fib-shell`

The private `pcscd` approach avoids touching `/etc/reader.conf.d/`. The
recipes manage a `.fib/` runtime dir under the repo root (gitignored).

```sh
just fib-up           # start private pcscd + fib
eval "$(cat .fib/env)"  # export PCSCLITE_CSOCK_NAME for this shell
pivy-tool list         # should show "Virtual PCD piggy fib"
just fib-down         # kill pcscd + fib, remove .fib/
```

For interactive sessions:

```sh
just fib-shell        # opens a subshell with env set; teardown on exit
```

### Wire-up

```
┌──────────────┐       PC/SC         ┌──────────┐   dlopen   ┌───────────────┐   TCP 35963   ┌─────────┐
│ pivy-tool    │ ─────────────────▶ │  pcscd   │ ─────────▶ │ libifdvpcd.so │ ─────────────▶ │  fib    │
│  (client)    │  PCSCLITE_CSOCK    │ (private)│ reader.conf│  (vpcd driver)│   applet side  │ jCardSim│
└──────────────┘   = .fib/pcscd.comm└──────────┘            └───────────────┘                └─────────┘
```

`PCSCLITE_CSOCK_NAME` is a libpcsclite env var that redirects both the
server (pcscd) and the client (pivy-tool) to a non-default Unix socket.
This is how we avoid contention with a system pcscd that may also be
running. `fib-up` starts pcscd, waits for the socket to appear, then
launches the jCardSim process — which connects to vpcd's TCP listener
and registers itself as the card.

## Initializing the applet

The first time you talk to the newly-attached fib it has no keys. Follow
the standard PivApplet bring-up:

```sh
# Activate the applet (APDU from the PivApplet README).
opensc-tool -r 'Virtual PCD piggy fib 00 00' -s \
  '80 b8 00 00 12 0b a0 00 00 03 08 00 00 10 00 01 00 05 00 00 02 0F 0F 7f'

# Generate a key in slot 9a using the factory default PIN/admin.
pivy-tool -P 123456 -K default generate 9a
```

Default credentials on a fresh PivApplet:

- **PIN:** `123456`
- **PUK:** `12345678`
- **Admin key:** `010203040506070801020304050607080102030405060708` (3DES)

## When to reach for fib

- **Bats tests that want to exercise the real PC/SC path** without
  consuming real-card PIN retries.
- **Conformance oracle development** — both the C `pivy-tool` side and
  the Rust `piggy tool` side (when it lands, see roadmap
  [issue #3](https://github.com/amarbel-llc/piggy/issues/3)) can be run
  against fib to validate argv-parse and functional behavior without
  hardware.
- **Local debugging of crypto paths** — jCardSim prints full APDUs on
  stderr (`.fib/fib.log`) plus Java stack traces on applet crashes.

## When `fib` is NOT a substitute for hardware

- Card enumeration and removal lifecycles (plug-in / remove events).
- Real-card timing behaviors, touch-policy prompts, LED state.
- YubiKey-specific attestation chains — PivApplet implements
  `ykpiv-attest@joyent.com` but signs with a stubbed chain, not the
  genuine Yubico factory roots.

Keep the hardware-gated bats file (`*_hardware.bats`, pattern from
`piggy_agent_protocol.bats`) around for these. See
[feedback memory on gating hardware tools](../.claude/projects/-home-sasha-eng-repos-piggy/memory/feedback_hardware_tool_gating.md).

## Troubleshooting

- **`fib-up`: pcscd socket never appeared.** Check `.fib/pcscd.log`.
  Common causes: another pcscd holding port 35963, a stale
  `.fib/pcscd.comm` socket (normally deleted on startup but not on kill
  -9), or vpcd driver path mismatch (the nix-store path for
  `libifdvpcd.so` changed and `fib-reader-conf` wasn't rebuilt).
- **jCardSim connects but pcscd reports no card.** The virtual reader
  needs vpcd to be loaded. Verify via `pcsc_scan -n` against
  `PCSCLITE_CSOCK_NAME=$PWD/.fib/pcscd.comm`.
- **APDU failures with `6D 00`.** The applet was never activated with
  the bring-up APDU above.
