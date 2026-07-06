# piggy-pigpen (prototype)

Reference prototype for the **pigpen** encrypted-document format —
[piggy RFC 0008](../../docs/rfcs/0008-pigpen-encrypted-document.md).

A pigpen document is a hyphence document (madder RFC 0001) carrying a
markl-ID recipient set in its metadata section and an optional ciphertext
payload in its body. It combines age's file-key indirection + STREAM
payload + header MAC with the ebox's PIV/P-256 hardware wrap, unified
under markl IDs. A payload-less pigpen is a drop-in for a `piggy-ids`
recipient file (RFC 0003).

## Status

**Prototype.** Excluded from the piggy cargo workspace on purpose: it
uses the pure-Rust RustCrypto stack (so a `wasm32` build is possible)
instead of the OpenSSL-backed `piggy-box`, and carries its own
`Cargo.lock`. Promotion into the workspace is a cutover step (RFC 0008
"Compatibility").

## Build & test

```sh
cargo test -p piggy-pigpen --manifest-path crates/piggy-pigpen/Cargo.toml

# wasm library build (the headline deliverable)
rustup target add wasm32-unknown-unknown
cargo build --manifest-path crates/piggy-pigpen/Cargo.toml --target wasm32-unknown-unknown
```

## Shape

| File | Role |
|------|------|
| `src/hyphence.rs` | minimal hyphence framing (RFC 0001 subset) |
| `src/crypto.rs` | pigpen-v1 crypto suite (wraps, STREAM payload, header MAC) |
| `src/document.rs` | document model, hyphence codec, `seal`/`open`, `EcdhOracle` |

Card-bound P-256 decryption is abstracted behind the `EcdhOracle` trait,
so a wasm host supplies the scalar multiplication (piggy-agent's
`ecdh@joyent.com`) without the module linking any card transport. The
sibling Go prototype lives at `go/internal/delta/pigpen/`.
