---
status: draft
date: 2026-06-06
provenance: |
  Feasibility examination for running `fibby` (the pure-Rust virtual PIV
  card, crates/fibby) on macOS, so the fibby-backed conformance lanes
  (recipients-sync, pass-ls-recipients, agent-pin-on-demand, …) can run
  on a dev mac instead of being [linux]-only. Driven by a live probe on
  macOS 15 / aarch64-darwin plus web research into Apple's PC/SC stack.
  Companion docs: docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md
  (fibby's Linux design), docs/virtual-piv.md (the fib stack it
  replaced). Explore recipes proving each claim:
  `just explore-darwin-fibby-csock`, `explore-darwin-vpcd-build`,
  `explore-darwin-vpcd-build-patched`.
---

# `fibby` on macOS — feasibility examination

## TL;DR

Running fibby on macOS is **feasible but not via fibby's current
mechanism**, and the realistic shape is a **dev-box convenience, not a
CI lane**.

- fibby reaches Linux PC/SC clients by being the pcsc-lite *daemon* at
  the socket named by `PCSCLITE_CSOCK_NAME`. **macOS clients ignore that
  variable** — confirmed by live probe (see below). They link Apple's
  `PCSC.framework`, not `libpcsclite`, and the framework has no
  socket-redirect knob.
- The supported macOS interpose is an **IFD-handler driver bundle** under
  `/usr/local/libexec/SmartCardServices/drivers/`, loaded by
  `com.apple.ifdreader`. This is exactly how vsmartcard's `vpcd`
  (`ifd-vpcd.bundle`) works, and it works on current macOS (vsmartcard
  0.10 on macOS 15.5 arm64). The repo's older "vpcd broken on darwin"
  note is **stale for the upstream mechanism** (though the *nixpkgs
  packaging* is genuinely broken — see below).
- fibby's architecture is ready: the `Backend` trait
  (`crates/fibby/src/backend.rs`) exposes
  `transmit(&[u8]) -> ScardResult<Vec<u8>>`, and `VirtualCard` implements
  it independently of the pcsc-lite server loop. So a macOS front-end is
  **purely additive** — a new "vpicc" module speaking vpcd's APDU socket
  protocol, wrapping the same `Backend::transmit`, with **zero changes**
  to the card logic.
- **The blocker is the activation hack, not the code.** The IFD bundle
  loads only when a USB device matching its `Info.plist`
  `ifdVendorID`/`ifdProductID` is physically attached. A GitHub macOS
  runner has no controllable USB device; a dev mac needs a sacrificial
  non-smartcard USB device permanently plugged in. That, plus the
  codesigning/SIP question, is why this is a dev convenience at best.

## What was proven (with evidence)

### 1. `PCSC.framework` ignores `PCSCLITE_CSOCK_NAME` (live probe)

`just explore-darwin-fibby-csock` starts fibby (virtual, seeded slot 9D)
on a temp Unix socket, exports `PCSCLITE_CSOCK_NAME` pointing at it, and
runs `pivy-tool list`. Result on macOS 15 / aarch64-darwin:

- `pivy-tool` returned the **real** YubiKey (the physical card), not
  fibby's virtual card.
- fibby's wire log showed **zero** client connections — the framework
  never dialed fibby's socket.

So fibby's Linux redirect is structurally dead on macOS. macOS clients
link `PCSC.framework` (the C pivy via `-framework PCSC` in
`vendor/pivy/Makefile`; the Rust path via `pcsc-sys`), and
`PCSCLITE_CSOCK_NAME` is a `libpcsclite`-only variable.

### 2. The IFD-handler-bundle path is the supported interpose

macOS SmartCardServices still loads pcsc-lite-derived IFD-handler v3.0
driver bundles from `/usr/local/libexec/SmartCardServices/drivers/`
(third-party) and `/usr/libexec/...` (system), via `com.apple.ifdreader`.
A bundle is a C `.dylib` exporting the IFD entry points
(`IFDHCreateChannelByName`, `IFDHPowerICC`, `IFDHTransmitToICC`, …).
vsmartcard's `vpcd` is exactly such a bundle (`libifdvpcd.dylib`) that
bridges those IFD calls to a trivial APDU socket protocol: a TCP server
(default port `0x8C7B`/35963), 2-byte big-endian length framing, control
bytes `0x00` PowerOff / `0x01` PowerOn / `0x02` Reset / `0x04` GetATR,
otherwise a command APDU expecting a response APDU.

### 3. The nixpkgs `vsmartcard-vpcd` darwin build is unbreakable with one flag

`nixpkgs#vsmartcard-vpcd` 0.10 carries `broken = isDarwin`. The darwin
build fails at **link**: `libifdvpcd` references `_log_msg` (provided at
runtime by `com.apple.ifdreader`), and darwin `ld` rejects the undefined
symbol. The fix is the standard loadable-bundle flag:

```nix
pkgs.vsmartcard-vpcd.overrideAttrs (old: {
  env = (old.env or {}) // {
    NIX_LDFLAGS = (old.env.NIX_LDFLAGS or "") + " -undefined dynamic_lookup";
  };
  meta = old.meta // { broken = false; };
})
```

`just explore-darwin-vpcd-build-patched` builds this clean and produces
`var/lib/pcsc/drivers/serial/libifdvpcd.dylib`,
`etc/reader.conf.d/Info.plist` (the `--enable-infoplist` activation
plist), and `bin/vicc`. **This is also a candidate nixpkgs unbreak PR.**

## Option space (ranked)

1. **fibby-as-vpicc behind the vpcd bundle** (recommended if pursued).
   Smallest change: a new `crates/fibby` module speaks vpcd's APDU socket
   protocol on a TCP port; install the (patched) `ifd-vpcd.bundle` so
   `com.apple.ifdreader` forwards APDUs to fibby. Reuses
   `Backend::transmit` verbatim. ~300–500 lines, no card-logic changes.
2. **fibby ships its own IFD-handler `.dylib`.** One fibby artifact, no
   vsmartcard dependency, but you own a C dylib + Developer-ID signing +
   `Info.plist`. Larger lift; same activation hack.
3. **Relink pivy/piggy against a self-built macOS pcsc-lite + pcscd.**
   Makes `PCSCLITE_CSOCK_NAME` (and fibby's existing socket protocol)
   work, but pcsc-lite is **explicitly unsupported on macOS** upstream
   and you'd maintain your own pcscd. Not recommended.

Ruled out: **CryptoTokenKit** virtual tokens surface a keychain identity,
not a `SCardConnect`-able reader, so a raw PC/SC client like `pivy-tool`
never sees them — wrong layer. No `reader.conf`/socket/env override
exists for `com.apple.ifdreader`.

## The activation blocker

The IFD bundle's `Info.plist` carries `ifdVendorID`/`ifdProductID`, and
`com.apple.ifdreader` only loads the driver when a USB device with that
VID/PID is attached (the default plist ships `0x18d1/0x4ee1`, a Google
placeholder). You must borrow the VID/PID of an attached **non-smartcard**
USB device — borrowing a real reader's VID/PID collides and can disable
the real reader. Consequences:

- **CI:** a GitHub macOS runner has no controllable USB device → no
  reliable activation → not a viable CI lane.
- **Dev box:** needs a sacrificial USB device (flash drive, dongle,
  keyboard) plugged in for the virtual reader to exist; the reader
  vanishes when it's unplugged.
- **Signing/SIP:** an unsigned bundle may need SIP disabled; a
  Developer-ID-signed bundle is the clean path. Unverified which is
  required here.

## Status & next steps

POC paused at the system-install leg: proving `pivy-tool list` sees the
vpcd reader through `PCSC.framework` requires installing the bundle into
`/usr/local/libexec/SmartCardServices/drivers/` (sudo) with a
VID/PID-matched plist, and the only USB device on the test mac was the
YubiKey (a smartcard, which must not be borrowed). Resume when a
throwaway USB device is available.

If pursued to completion:

1. Install the patched `ifd-vpcd.bundle` (manual sudo first; later a
   nix-darwin module — see the productionization followup) with a plist
   matching a benign attached USB device; restart `com.apple.ifdreader`;
   confirm `pivy-tool list` shows the "Virtual PCD" reader.
2. Add the fibby vpicc front-end (option 1) and point the bundle's socket
   at it; confirm a slot-9D ECDH decrypt round-trips through
   `PCSC.framework → com.apple.ifdreader → ifd-vpcd.bundle → fibby`.
3. Upstream the nixpkgs unbreak (`-undefined dynamic_lookup`) separately.

Given the activation/signing fragility, the honest recommendation is to
keep the fibby conformance lanes **Linux-only for CI** and treat darwin
fibby as an optional dev-box convenience, not a gating lane.
