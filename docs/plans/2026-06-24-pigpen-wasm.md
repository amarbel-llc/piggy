# pigpen — WASM build & host-oracle sketch

Companion to `docs/rfcs/0008-pigpen-encrypted-document.md` §7. Records the
concrete WASM build invocations for the two prototypes and the
host-provided ECDH-oracle interface that card-bound decryption needs.

## Why WASM is a design constraint, not an afterthought

Pigpen's encrypt path and its X25519 decrypt path are pure software, so
the natural deployment surface is broad: a browser extension that seals a
secret to a teammate's recipient set, a CI step that encrypts release
artifacts, an offline web tool that converts a `piggy-ids` file to a
pigpen recipient set. All of those want a WASM module, not a native
binary. The card-bound P-256 *decrypt* is the only operation that cannot
run in the sandbox — and it is abstracted behind an injected oracle so
the WASM module never links PCSC or an agent transport.

## Rust (`crates/piggy-pigpen`) — the primary WASM target

The Rust crate uses the pure-Rust RustCrypto stack and deliberately does
**not** depend on `crates/piggy-box` (OpenSSL, no `wasm32`). It therefore
builds for `wasm32-unknown-unknown` with no host-toolchain crypto:

```sh
# native
cargo build -p piggy-pigpen
cargo test  -p piggy-pigpen

# wasm (library)
rustup target add wasm32-unknown-unknown
cargo build -p piggy-pigpen --target wasm32-unknown-unknown --no-default-features --features wasm

# wasm-bindgen JS bindings (when the wasm feature + wasm-bindgen are wired)
wasm-pack build crates/piggy-pigpen --target web -- --no-default-features --features wasm
```

The crate is `exclude`d from the piggy workspace while it is a prototype
(it carries its own `Cargo.lock` and RustCrypto deps that are not part of
the shared `sharedCargoLock` the nix build pins). Promoting it into the
workspace is a cutover step (RFC 0008 "Compatibility").

### Host oracle (Rust)

```rust
/// Implemented on the host side (native: piggy-agent; wasm: a JS shim).
pub trait EcdhOracle {
    /// X-coordinate of (card_slot9d_private · partner_epk).
    fn ecdh(&self, self_recipient: &MarklId, partner_epk: &[u8]) -> Result<[u8; 32]>;
}
```

Under `--features wasm`, the crate exposes a `wasm-bindgen` adapter that
turns a JS callback `(selfId: string, epk: Uint8Array) => Uint8Array`
into an `EcdhOracle`. The page wires that callback to piggy-agent over a
native-messaging host, a WebUSB/WebAuthn-PIV bridge, or a remote signer.

## Go (`go/markl/pigpen`) — partial WASM today

The pigpen crypto + hyphence framing core compiles cleanly to **both**
`GOOS=js` and `GOOS=wasip1`:

```sh
GOOS=js     GOARCH=wasm go build ./...   # crypto.go + hyphence.go: OK
GOOS=wasip1 GOARCH=wasm go build ./...   # crypto.go + hyphence.go: OK
```

…but the *full* package does not, because the markl Id codec it uses for
recipient IDs (`go/markl/pkgs/markl`) transitively imports
`purse-first/libs/dewey`, which is not WASM-portable:

- `GOOS=js`: `dewey/internal/bravo/errors` references `syscall.SIGHUP`
  (undefined on js).
- `GOOS=wasip1`: `dewey/internal/delta/files` references
  `setUserChanges` (undefined on wasip1).

This is a **dewey** portability gap, surfaced (not caused) by pigpen.
Resolving the Go WASM story therefore means one of:

1. a `//go:build !wasm` / wasm-stub split in dewey's `errors` and `files`
   packages (upstream fix), or
2. a thin wasm-facing markl shim that re-exports only the codec
   (`Id.Set` / `Id.StringWithFormat` / blech32) without the dewey error
   and file machinery, or
3. treating Rust as the sole WASM target and using Go only for native +
   the conformance peer.

Recommendation: pursue (1) at the dewey layer (it benefits every
WASM-targeting consumer of markl), and ship (3) in the interim — the Rust
crate is the production WASM module; the Go package is the native
reference + test peer. The crypto/framing core building cleanly under
both wasm GOOSes confirms pigpen itself adds no new WASM blocker.

## Oracle wire shape (shared)

Whichever language hosts the module, the oracle answers exactly the
`ecdh@joyent.com` question piggy-agent already answers:

```
request:  { self: <recipient markl ID>, epk: <33-byte compressed P-256 point> }
response: { shared: <32-byte X-coordinate> }
```

No private key, no PIN, and no card transport crosses the WASM boundary —
only the ephemeral public key in and the shared X-coordinate out, exactly
as `age-plugin-piggy`'s `AgentEcdhOracle` already does natively.
