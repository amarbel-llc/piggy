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
| `jcardsim` | `$out/share/java/jcardsim-3.0.5-SNAPSHOT.jar` | Maven-built fork (arekinath/jcardsim). Uses vendored deps from `nix/jcardsim-m2/` (offline build). Includes a reimplementation of the JavaCard APIs, so compiling the applet does **not** require the Oracle JavaCard SDK. |
| `pivapplet` | `$out/classes/**/*.class`, `$out/jcardsim.cfg` | `ant preprocess` (vendored `ext/jpp-1.0.3.jar`) then `javac` against `jcardsim.jar`. `ant dist` is skipped — we never emit a CAP file. |
| `fib-reader-conf` | `reader.conf` text | Points `LIBPATH` at the nix-store `libifdvpcd.so`. Consumed by the private `pcscd`. |
| `fib` | `bin/fib` | Launches `java com.licel.jcardsim.remote.VSmartCard`. Connects to the vpcd TCP listener at `localhost:35963`. |
| `fib-bundle` | `bin/fib`, `bin/opensc-tool` + convenience symlinks under `share/fib/` | What `piggy.passthru.tests.fib` points at. Includes `opensc-tool` for applet activation. |

Flake outputs on Linux:

- `.#fib` — the launcher (`nix run .#fib`)
- `.#fib-bundle` — bundle with reader.conf/vsmartcard-vpcd symlinked alongside
- `.#fib-reader-conf` — the `reader.conf` snippet
- `.#jcardsim`, `.#pivapplet` — underlying artifacts

## Vendored Maven dependencies

`jcardsim`'s Maven dependency closure is vendored in
[`nix/jcardsim-m2/`](../nix/jcardsim-m2/) and used offline during the
nix build. This eliminates `buildMavenPackage`'s fixed-output derivation
(FOD) whose hash drifts when Maven Central changes metadata — even with
no code changes on our side.

To regenerate (only needed when bumping the `jcardsim` flake input):

```sh
just debug-capture-jcardsim-m2
git add nix/jcardsim-m2/
```

The recipe runs Maven on the host (pure Java, works on any platform),
applies the same `pom.xml` patches as the nix build, downloads deps, and
strips ephemeral metadata files.

## Runtime use: `just load-fib` / `clean-fib` / `run-fib-shell`

The private `pcscd` approach avoids touching `/etc/reader.conf.d/`. The
recipes manage a `.fib/` runtime dir under the repo root (gitignored).

```sh
just load-fib           # start private pcscd + fib
eval "$(cat .fib/env)"  # export PCSCLITE_CSOCK_NAME for this shell
pivy-tool list         # should show "Virtual PCD piggy fib"
just clean-fib         # kill pcscd + fib, remove .fib/
```

For interactive sessions:

```sh
just run-fib-shell    # opens a subshell with env set; teardown on exit
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
running. `load-fib` starts pcscd, waits for the socket to appear, launches
the jCardSim process, and sends the jCardSim activation APDU to call
`PivApplet.install()`. After `load-fib` returns, the applet is ready for
use — no manual activation step needed.

## Generating keys

After `load-fib`, the applet is active but has no keys. Generate one:

```sh
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
  [issue #3](https://code.linenisgreat.com/piggy/issues/3)) can be run
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

- **`load-fib`: pcscd socket never appeared.** Check `.fib/pcscd.log`.
  Common causes: another pcscd holding port 35963, a stale
  `.fib/pcscd.comm` socket (normally deleted on startup but not on kill
  -9), or vpcd driver path mismatch (the nix-store path for
  `libifdvpcd.so` changed and `fib-reader-conf` wasn't rebuilt).
- **jCardSim connects but pcscd reports no card.** The virtual reader
  needs vpcd to be loaded. Verify via `pcsc_scan -n` against
  `PCSCLITE_CSOCK_NAME=$PWD/.fib/pcscd.comm`.
- **SELECT AID fails with `69 86` (SW_COMMAND_NOT_ALLOWED).** The
  `PivApplet.install()` APDU wasn't sent. `load-fib` does this
  automatically; if you're running jCardSim manually, send:
  `opensc-tool -r 'Virtual PCD piggy fib 00 00' -s '80 b8 00 00 12 0b a0 00 00 03 08 00 00 10 00 01 00 05 00 00 02 0F 0F 7f'`
- **`load-fib`: PivApplet activation timed out.** jCardSim didn't connect
  to vpcd within 5 seconds. Check `.fib/fib.log` for Java errors and
  `.fib/activate.log` for the opensc-tool output.
