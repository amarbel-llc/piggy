---
status: draft
date: 2026-05-29
provenance: |
  Feasibility examination for `fibby`: a pure-Rust virtual PIV smart
  card to replace (or sit beside) the current Java-based `fib`
  (jCardSim + PivApplet + vsmartcard-vpcd + private pcscd). Drafted on
  branch claude/virtual-piv-rust-EeB4T. Surveys prior art, fixes the
  "no other dependencies" interpretation, sketches an architecture
  anchored on the existing `piggy-piv` client and the Nitrokey
  `vpicc-rs` transport, and lays out a spec/test-vector validation
  strategy. Companion docs: docs/virtual-piv.md (current fib),
  docs/rfcs/0002-piv-ecdh-box.md (piggy box wire format). Roadmap:
  umbrella #3, triage #26, fib-limitation tracker #83.
---

# `fibby` — pure-Rust virtual PIV smart card (examination)

## TL;DR

A pure-Rust virtual PIV card is feasible and there is strong, directly
reusable prior art. The honest framing of "no other dependencies" is
**no Java / Maven / Oracle JavaCard SDK** — i.e. drop the jCardSim +
PivApplet stack. The one C dependency that is impractical to remove in
v1 is the PC/SC plumbing itself (`pcscd` + the `vsmartcard-vpcd`
reader driver), because every piggy client (`pivy-tool`, `piggy
agent`, `piggy-piv`) reaches a card through `libpcsclite` → `pcscd`.
A second, fully-self-contained tier (reimplement the pcsc-lite IPC
protocol so no `pcscd` runs at all) is possible but is a separate,
larger effort and is **not** recommended for v1.

Recommended shape:

- A new `crates/fibby` binary that implements the PIV applet logic in
  Rust and attaches to `pcscd` via the **`vpicc`** crate
  (Nitrokey/vpicc-rs — the Rust port of the vsmartcard `vpcd`
  protocol). This deletes the entire Java toolchain from the test
  path while keeping the existing `vsmartcard-vpcd` + `pcscd` wiring
  that `just fib-up` already manages.
- Crypto via RustCrypto (`p256`, `p384`, `rsa`, `ed25519-dalek`,
  `x25519-dalek`) — already in piggy's dependency closure.
- Conformance is gated three ways: against piggy's own
  **`piggy-piv`** client, against the C **`pivy-tool`**, and against
  published NIST/Yubico **test vectors** plus RFC 0002 Appendix A.

## Motivation

`fib` (see `docs/virtual-piv.md`) is the software PIV card piggy's
tests target instead of real hardware. It works, but the cost is
steep:

- **Heavy toolchain.** jCardSim is a Maven build that compiles
  against the Oracle JavaCard SDK 3.0.5u3. We vendor the whole Maven
  closure (`nix/jcardsim-m2/`) and carry an Oracle Binary Code License
  note (`nix/virtual-piv.nix:14-24`) just to keep the build offline
  and reproducible.
- **Linux-only.** `vsmartcard` is marked broken on darwin, so fib
  never runs on the macos-15 CI lane — the very lane that keeps
  surprising us (see the `env -i` exit-126 note in CLAUDE.md, #100).
- **Operationally fiddly.** A JVM, a TCP relay on port 35963, a
  private `pcscd`, an INSTALL APDU, and a readiness probe
  (`crates/fib-wait-ready`) all have to line up. The troubleshooting
  section in `docs/virtual-piv.md` is long for a reason.
- **Opaque to us.** When a crypto path misbehaves we are debugging
  someone else's Java applet (`arekinath/PivApplet`) rather than code
  we own and can instrument.

A pure-Rust card we own would: build with `cargo` (no JVM/Maven/Oracle
SDK), be debuggable in-tree, share types with `piggy-piv`, and — for
the unit-test tier that does not need a real `pcscd` — run on darwin
too.

## Non-goals (v1)

- **Not** a hardware replacement for the lifecycle/timing tests.
  Card insert/remove events, touch-policy LED state, and genuine
  Yubico factory attestation roots still need real hardware
  (`*_hardware.bats`), exactly as today (`docs/virtual-piv.md:112`).
- **Not** removing `pcscd`/`vsmartcard-vpcd` in v1. The
  fully-self-contained "no daemon at all" tier is documented below as
  a stretch goal, not a v1 deliverable.
- **Not** a general-purpose JavaCard simulator. fibby virtualizes the
  PIV applet (plus the YubiKey vendor extensions piggy uses), nothing
  else.
- **Not** a CAP file / on-hardware applet. fibby is host software.

## Prior art

### 1. `fib` — the incumbent (Java)

`arekinath/jcardsim` (Java Card simulator) loads `arekinath/PivApplet`
and exposes it over the vsmartcard `vpcd` TCP protocol. This is the
baseline fibby replaces. It is also the **behavioural oracle**:
fibby's command responses should match PivApplet's where piggy depends
on them, because piggy's wire-format tests were calibrated against it.

### 2. Nitrokey `vpicc-rs` + trussed `piv-authenticator` (the key find)

There is already a **pure-Rust virtual PIV card** in the wild:

- **`vpicc`** (crates.io, `Nitrokey/vpicc-rs`, MIT) — a Rust
  implementation of the vsmartcard `vpcd` client side. You implement a
  small trait (power on/off, reset, get-ATR, transmit-APDU) and it
  handles the TCP framing to `pcscd`'s vpcd reader. This is exactly
  the transport fibby needs, already in Rust. It means fibby does
  **not** hand-roll the wire protocol.
- **`trussed-dev/piv-authenticator`** (MIT/Apache) — a Rust
  implementation of the PIV smartcard per NIST SP 800-73-4, built as a
  Trussed app. Its own README states "nearly all functionality
  specified by the standard [is] implemented." It is *tested using
  `vpicc` + `opensc`/`pivy`-style clients*. This is the single most
  reusable body of prior art: either depend on it, vendor it, or use
  it as a reference implementation to crib the APDU dispatch from.

The catch: `piv-authenticator` targets **Trussed** (the embedded HAL
used by Nitrokey 3 / SoloKeys), so it pulls a `trussed` software
backend and its crypto/storage abstractions. That is heavier than
"no dependencies." Two ways to use it:

- **(a) Reference only.** Read its APDU state machine and re-implement
  a slimmer dispatcher directly on RustCrypto. Cleanest dependency
  story, most work.
- **(b) Depend on it behind `vpicc` + `trussed` software backend.**
  Fastest path to a working card, but inherits the Trussed closure and
  its PIV gaps (notably YubiKey vendor extensions — see below).

### 3. vsmartcard / `vpcd` protocol (the transport spec)

`vpcd` is a PC/SC reader driver (`libifdvpcd.so`) that `pcscd` loads;
it relays APDUs over TCP (default port 35963 / `0x8C7B`) to a "vpicc"
(virtual PICC = the card). The framing is trivial and fully public:

- Each message is a **2-byte big-endian length prefix** followed by
  that many payload bytes.
- A **length-1** payload is a control byte: `0x00` power-off, `0x01`
  power-on, `0x02` reset, `0x04` get-ATR. The card answers get-ATR
  with its ATR bytes.
- Any other payload is a **C-APDU**; the card answers with the
  **R-APDU** (data ‖ SW1 SW2).

`vpicc-rs` encapsulates all of this, so fibby implements the trait,
not the framing. Our `nix/virtual-piv.nix` already builds the
`vsmartcard-vpcd` driver and the matching `pcscd`; fibby reuses both
unchanged.

### 4. `yubikey.rs` (host side — not an emulator, but a spec mirror)

`iqlusioninc/yubikey.rs` / `str4d/yubikey-piv.rs` are pure-Rust
**host-side** PIV drivers. They don't emulate a card, but they encode,
in Rust, exactly the YubiKey PIV command set, algorithm IDs, slot
semantics, and the management-key/PIN/PUK flows. They are an excellent
cross-check for "what does a real YubiKey expect on the wire," and
their test fixtures are reusable.

### 5. piggy's own `piggy-piv` (in-tree client + spec encoding)

`crates/piggy-piv` is already a host-side PIV client and it pins the
exact surface fibby must satisfy (see "Command surface" below). It is
the *first* conformance client we should point at fibby because if
fibby satisfies `piggy-piv`, piggy works.

## What "no other dependencies" can mean — and the pcscd boundary

The phrase has two defensible readings:

1. **No Java/Maven/Oracle SDK** (drop jCardSim + PivApplet). Keep the
   thin C plumbing (`pcscd` + `vsmartcard-vpcd`) that *every* PC/SC
   client on the machine already needs. → **Recommended v1.**
2. **No external runtime at all** — fibby is the only process; no
   `pcscd`. This requires reimplementing the **pcsc-lite client IPC
   protocol** (the `pcscd.comm` Unix-socket wire format that
   `libpcsclite` speaks) so that `pivy-tool`/`piggy` connect straight
   to fibby. That is a real, bounded protocol, but it is a second
   project and it is brittle against libpcsclite version drift (we
   already chase that — see the pcsclite 2.4.1 negotiation note in
   `nix/virtual-piv.nix:148-166`). → **Stretch goal, separate issue.**

For the **unit-test tier** there is a third, dependency-free reading
that is genuinely zero-dep: fibby exposes a plain
`transmit(&[u8]) -> Vec<u8>` function and tests drive it with raw
APDUs, no PC/SC at all. This tier runs everywhere (including darwin)
and is where the spec/test-vector validation lives. The `vpicc`
transport is then just a thin adapter over that same core for the
integration tier.

```
        ┌─────────────────────── crates/fibby ───────────────────────┐
        │                                                             │
unit ──▶│  Card core: APDU dispatch + state + RustCrypto  ◀── tests   │ (zero PC/SC, darwin-ok)
        │            │                                                │
        │            ▼                                                │
integ ─▶│  vpicc adapter ──TCP 35963──▶ pcscd + vsmartcard-vpcd ──▶ pivy-tool / piggy
        └─────────────────────────────────────────────────────────────┘
```

## Command surface fibby must implement (derived from piggy)

This is the concrete, *minimum* set, read off `crates/piggy-piv`
(`apdu.rs`, `token.rs`) and the `just fib-*` recipes — i.e. what piggy
actually sends, not the whole of SP 800-73-4:

| Command | INS | Why piggy needs it |
|---|---|---|
| SELECT (PIV AID `A0 00 00 03 08 00 00 10 00 01 00`) | `0xA4` | every session start; `fib-wait-ready` probes it |
| GET DATA | `0xCB` | read CHUID + slot certs (recipients, attestation cert F9) |
| PUT DATA | `0xDB` | import certs after `generate` |
| VERIFY (PIN) | `0x20` | unlock before sign/ECDH |
| CHANGE / RESET PIN, PUK | `0x24`/`0x2C` | PIN-management coverage |
| GENERAL AUTHENTICATE | `0x87` | **the core**: sign (CHALLENGE→RESPONSE) and **ECDH** (EXPONENT→RESPONSE) — piggy box decrypt on slot 9D |
| GENERATE ASYMMETRIC | `0x47` | `pivy-tool generate 9d` creates the test key |
| GENERAL AUTHENTICATE (admin/3DES) | `0x87` | management-key auth before generate/put |
| **YK attestation** | `0xF9` | `yk_attest` / `attest::parse_policy` (OID `1.3.6.1.4.1.41482.3.8`) |
| **YK serial** | `0xF8` | `read_yk_serial` (vendor INS; `None` if unsupported) |
| GET RESPONSE (chaining) | `0xC0` | long responses (RSA-2048 keys, cert reads) |

Algorithms (`piggy-piv/src/apdu.rs::alg`, `slot.rs`): P-256 (`0x11`),
P-384 (`0x14`), RSA-1024/2048 (`0x06`/`0x07`), and the YubicoPIV-5.7+
proprietary Ed25519 (`0xE0`) / X25519 (`0xE1`). piggy's primary path
is **P-256 ECDH in slot 9D** (Key Management) — that must be
bit-exact, validated against RFC 0002 Appendix A.

## Virtualizing "the most common YubiKey models"

A "YubiKey model" from PIV's perspective is a *firmware version* plus
*advertised capabilities*, not physically distinct silicon. fibby
models this as a small config table:

| Profile | Firmware | PIV traits that differ |
|---|---|---|
| YubiKey 4 / NEO | 4.x | RSA + ECC P-256/P-384; no AES mgmt key (3DES only); attestation from 4.3+ |
| YubiKey 5 (pre-5.4.2) | 5.1–5.4 | adds touch/PIN policy; 3DES mgmt key |
| YubiKey 5 (5.4.2+) | 5.4.2 | AES-192 management key default; CCC/CHUID |
| YubiKey 5.7+ | 5.7 | adds Ed25519 (`0xE0`) / X25519 (`0xE1`) slots; RSA-3072/4096 |

Concretely, fibby's YubiKey-ness is four things, all data not code:

1. **AIDs.** Answer SELECT on both the PIV AID and the YubiKey
   management AID `A0 00 00 05 27 47 11 17` (`apdu.rs::YKPIV_AID`).
2. **Vendor INS.** Implement `0xF8` (serial) and `0xF9`
   (attestation). A non-YubiKey profile simply rejects these with a
   non-`9000` SW, which is exactly how piggy detects "no serial."
3. **Attestation chain.** Emit a DER attestation cert carrying the
   `1.3.6.1.4.1.41482.3.{8,9,10}` extensions (firmware/touch/PIN
   policy) so `attest::parse_policy` works. Like PivApplet, fibby
   signs with a **stub root**, not the genuine Yubico factory PKI —
   real-root verification stays hardware-gated (documented limitation,
   `docs/virtual-piv.md:115-118`).
4. **ATR + firmware byte.** Return the right historical-bytes / ATR
   and a `GET VERSION` (`0xFD`) firmware triple matching the chosen
   profile.

A `fibby --model yk5.7` flag (default to a 5.4.2-class profile) keeps
this ergonomic.

## Spec & test-vector validation strategy

The user's ask — "validate as much as possible against public specs /
RFCs and test vectors" — maps to four independent oracles:

1. **NIST SP 800-73-4 (PIV card interface) + SP 800-78-4 (crypto algs).**
   Drive the zero-PC/SC core with canonical APDU sequences from the
   standard (SELECT, GET DATA object tags, GENERAL AUTHENTICATE
   templates). These are structural, not secret-dependent, so they go
   in `#[test]` modules with literal byte vectors.
2. **RustCrypto known-answer tests.** ECDH (P-256/P-384) and the
   Ed25519/X25519 paths are validated against the **Wycheproof** and
   RFC 7748 / RFC 6979 / NIST CAVP vectors that RustCrypto already
   ships — fibby reuses them so the card's crypto is provably correct
   independent of PIV framing.
3. **RFC 0002 Appendix A (piggy's own box vectors).** This is the
   highest-value gate: `crates/piggy-box/src/piv_box.rs::tests::
   rfc0002_vectors` already pins three bit-exact ECDH-box vectors. A
   fibby integration test that seals to a fibby 9D key and round-trips
   through `piggy box stream decrypt` exercises the *exact* path piggy
   ships, and drift is already a CI failure by repo policy
   (CLAUDE.md "Specs").
4. **Differential vs C `pivy-tool` and real hardware.** Replay the
   same APDU script against (a) fibby, (b) the incumbent Java `fib`,
   and (c) a real YubiKey on the hardware lane; diff the R-APDUs. Any
   divergence is either a fibby bug or a documented hardware-only
   behaviour. `piggy-piv` is the in-tree client that makes this cheap.

The layering means most validation runs in fast, hermetic `cargo
test` (tiers 1–3); only tier 4's hardware leg needs the gated lane.

## Proposed architecture

```
crates/fibby/
  src/
    main.rs        # CLI: --model, --port, --pin/--puk/--mgmt, --persist <file>
    transport.rs   # vpicc adapter (impl vpicc::VSmartCard) — integration tier
    core.rs        # transmit(&[u8]) -> Vec<u8>  — the zero-PC/SC entry point
    dispatch.rs    # ISO 7816-4 APDU router (SELECT/GET DATA/GA/GENERATE/…)
    state.rs       # card state: slots, PIN/PUK/retries, mgmt key, data objects
    slots.rs       # 9A/9C/9D/9E + retired 82–95 + F9 attestation
    crypto.rs      # RustCrypto: P-256/P-384 ECDH+ECDSA, RSA, Ed25519, X25519
    yubikey.rs     # profiles, vendor INS 0xF8/0xF9/0xFD, attestation cert
    atr.rs         # ATR + GET VERSION per profile
  tests/
    sp80073_vectors.rs   # tier 1
    crypto_kat.rs        # tier 2
    rfc0002_roundtrip.rs # tier 3 (gated where it needs pcscd)
```

Reuse, don't re-derive: `dispatch.rs`/`slots.rs` should share the TLV
reader/writer, algorithm IDs, slot IDs, and GA template tags with
`crates/piggy-piv` (move shared constants into a small common module
so client and card can't drift). This is the same "shared substrate"
discipline `store.rs`/`git_ops.rs` already follow.

### Crate-vs-reuse decision (open)

Whether to (a) write `dispatch.rs` fresh on RustCrypto or (b) depend
on `trussed-dev/piv-authenticator` behind `vpicc` is the main
architectural fork. Recommendation: **prototype with (b)** to get a
card answering `pivy-tool list`/`generate` in days and learn the gaps,
then decide whether the Trussed closure + its YubiKey-extension gaps
justify the slimmer (a). The vendor extensions (`0xF8`/`0xF9`) are the
likeliest thing `piv-authenticator` lacks, and they are exactly what
piggy's attestation/serial paths need — so some custom code is
probably unavoidable regardless.

## Risks & open questions

- **Trussed dependency weight (if we choose reuse).** `trussed` pulls
  a crypto/storage HAL; "pure Rust" yes, "no other dependencies" not
  really. Needs a call on which reading of the brief wins.
- **YubiKey vendor extensions are under-specified.** `0xF8`/`0xF9` and
  the attestation extension layout come from Yubico docs +
  `yubico-piv-tool`/`pivy` source, not a NIST RFC. fibby must mirror
  pivy's behaviour (`vendor/pivy/src/piv.c`) to stay compatible — this
  is reverse-engineering, not spec-reading.
- **Attestation root.** A stubbed chain (like PivApplet) means
  genuine-root verification stays hardware-only. Acceptable, but must
  be loudly documented so nobody mistakes a fibby attestation for a
  real one (`piggy-test:`-style provenance applies here too).
- **3DES management key.** Real YubiKeys still default to 3DES (or
  AES-192 on 5.4.2+). RustCrypto's `des` is fine, but the GA
  challenge-response mutual-auth flow needs care to match pivy.
- **darwin reach.** The unit/core tier runs on darwin; the
  `vpicc`+`pcscd` integration tier does not (same `vsmartcard`
  brokenness as today). fibby narrows the gap (unit tier gains darwin)
  but does not close it for the PC/SC integration tier.
- **Self-contained tier (no pcscd).** Reimplementing the pcsc-lite
  client IPC is the only way to make fibby *truly* dependency-free at
  runtime; scope it as its own follow-up issue if/when desired.

## Suggested phasing

1. **Spike (reuse).** `crates/fibby` = `vpicc` + `piv-authenticator`
   software backend. Goal: `just fib-up`-equivalent brings up a Rust
   card; `pivy-tool -P 123456 -K default generate 9d` succeeds. Learn
   the gaps. (No production claims yet.)
2. **Core + tiers 1–3.** Zero-PC/SC `core::transmit`, SP 800-73-4
   vectors, RustCrypto KATs, RFC 0002 round-trip. This is the part
   that runs in plain `cargo test` on every platform.
3. **YubiKey profiles.** Vendor INS `0xF8`/`0xF9`/`0xFD`, attestation
   cert, model table, ATR/version. Validate `piggy-piv` attestation +
   serial paths and the `recipients add --all-attached` flow (#83).
4. **Swap the test path.** Add `just fibby-up`/`-down` mirroring the
   fib recipes; flip the sandboxed bats lane and the `just
   test-bats-conformance-*` recipes to fibby; keep `fib` available
   behind a flag for one release as the differential oracle (tier 4).
5. **(Stretch) self-contained.** Optional pcsc-lite IPC server so
   fibby needs no `pcscd`. Separate issue.

## Decision needed before implementation

The "no other dependencies" brief and the Trussed-reuse question pull
against each other. Before writing code we should pick: *slim/custom*
(no Trussed, more work, cleanest deps) vs *reuse `piv-authenticator`*
(fast, but inherits the Trussed closure and likely still needs custom
YubiKey-extension code). The phasing above hedges by spiking on reuse
first, but the production target should be chosen explicitly.

---

## Addendum (2026-05-29): chosen direction — reimplement pcscd + proxy-validate

Direction set after the examination: **fibby implements the pcsc-lite
*daemon* protocol itself** so clients connect straight to it with no
`pcscd` and no `vsmartcard-vpcd`. This is the "fully self-contained"
tier promoted from stretch goal to the goal, because the brief is to
*decouple from pcscd and other nix-unfriendly C giants* — keeping
`pcscd` would defeat that. Validation uses a **proxy pattern**: the
same fibby server, backed by a hardware passthrough, drives a real
YubiKey through the real `pcscd`, so we prove fibby's protocol layer
against hardware before trusting the virtual card.

### The pcsc-lite protocol (now grounded)

Source of truth: LudovicRousseau/PCSC `src/winscard_msg.{h,c}`,
**protocol 4.6**. Captured verbatim in `crates/fibby/src/proto.rs`:

- **Framing.** `struct rxHeader { uint32_t size; uint32_t command; }`
  (8 bytes) then a `size`-byte body. Native host byte order, natural
  alignment, no packing — and every field we touch is 4-byte-aligned,
  so a packed little-endian codec is bit-identical on x86-64/aarch64
  (asserted at the codec boundary, not assumed).
- **Commands** (`enum pcsc_msg_commands`): `SCARD_ESTABLISH_CONTEXT`
  0x01 … `SCARD_TRANSMIT` 0x09 … `CMD_VERSION` 0x11 …
  `CMD_GET_READERS_STATE_ARRAY` 0x17.
- **Handshake.** Client sends `CMD_VERSION` with
  `version_struct{major,minor,rv}`; fibby must answer with a matching
  major or the client aborts with `SCARD_E_SERVICE_STOPPED` (the *only*
  cause of that error per Rousseau's FAQ).
- **Per-command bodies.** `establish_struct`, `connect_struct`
  (carries `szReader[128]`), `transmit_struct` (32-byte fixed header
  then streamed APDU buffers), `disconnect_struct`, `status_struct`,
  the reader-state array, etc. — all mirrored in `proto.rs`.

### Architecture: one server, swappable backend

```
client (pivy-tool / piggy / opensc-tool)
   │  PCSCLITE_CSOCK_NAME → fibby's Unix socket
   ▼
crates/fibby  ── pcsc-lite daemon protocol (proto.rs) ──┐
                                                        │ Backend trait
            ┌───────────────────────────────────────────┤
            ▼                                            ▼
  HardwareProxy (feature "hardware-proxy")        VirtualCard
  forwards via the `pcsc` crate to the real        the in-Rust PIV
  pcscd → real YubiKey  [VALIDATION ORACLE]        applet  [THE GOAL]
```

The proxy and the virtual card share **one** server implementation, so
proving the protocol layer against hardware (HardwareProxy) directly
de-risks the virtual path (VirtualCard). The hardware backend is behind
the `hardware-proxy` Cargo feature so the protocol core + virtual card
build and unit-test on hosts with no PCSC headers (CI containers,
darwin).

### Environment constraint

The web/cloud session container has `libpcsclite.so.1` at runtime but
**no pcscd, no USB, no reader, and no PCSC headers**. Therefore:

- **Buildable + unit-testable here:** `proto.rs` codec, the server
  state machine, the `VirtualCard` backend, byte-vector conformance.
- **Runs only on a machine with a YubiKey:** the `HardwareProxy`
  backend and the end-to-end proxy validation. That leg is operator-
  driven (`cargo run -p fibby --features hardware-proxy`).

### Landed (steps 1–3 complete)

Full protocol server + both backends + hermetic end-to-end coverage:

- `proto.rs` — protocol 4.6 codec: `Command` enum, `rxHeader` framing,
  and codecs for version / establish / connect / transmit / disconnect /
  reader-state structs, plus the 184-byte `READER_STATE` array (ATR
  padding included) and the protocol constants
  (scope/share/protocol/disposition/reader-flags).
- `frame.rs` — message framing with the client↔server asymmetry made
  explicit (header-in / bare-out / streamed TRANSMIT payload), oversize
  guard, clean-EOF detection.
- `error.rs` — `SCARD_*` codes. `trace.rs` — `FIBBY_LOG` leveled logging
  + hex dumps.
- `backend.rs` — the `Backend` trait. `virtual_card.rs` — stub PIV card
  (SELECT→9000, else 6D00). `hardware_proxy.rs` — real-pcscd proxy via
  the `pcsc` crate (feature `hardware-proxy`).
- `server.rs` — listen loop, `CMD_VERSION` handshake, handle table,
  dispatch for the full common command set; unimplemented commands are
  logged loudly and close the connection (no silent mis-replies).
- `main.rs` — CLI (`--socket`/`--backend`/`--reader`).
- Tests: 17 unit + `tests/loopback.rs` (full PC/SC session over a real
  socket against `VirtualCard`), all green via
  `cargo test -p fibby --no-default-features`.
- `crates/fibby/README.md` — module map, `FIBBY_LOG` guide, and the
  hardware-validation runbook for the wet-env pass.

### Next steps

4. **Capture/validate (wet-env, needs a YubiKey):** run fibby with the
   `hardware-proxy` backend, point `pivy-tool list`/`generate 9d` at its
   socket, and record the `FIBBY_LOG=wire` traffic as conformance
   fixtures. The proxy also reveals any command fibby doesn't yet speak
   (logged UNIMPLEMENTED with the body hex).
5. Grow `VirtualCard` into the real PIV applet (GENERATE / GENERAL
   AUTHENTICATE sign+ECDH / GET·PUT DATA / VERIFY / YubiKey
   attestation+serial) and replay the captured fixtures + RFC 0002
   Appendix A + SP 800-73-4 vectors against it.
6. Swap the bats/conformance test path onto fibby; keep `fib` as a
   differential oracle for one release.

### Build-environment note

The cloud session container has `libpcsclite.so.1` but no
`libpcsclite-dev`/pkg-config, so `--features hardware-proxy` cannot be
*compiled* there (pcsc-sys needs the dev package). The protocol core,
`VirtualCard`, and loopback test build and pass; the hardware backend is
exercised on the wet-env machine.
