//! piggy-pigpen — prototype of the pigpen encrypted-document format
//! (piggy RFC 0008).
//!
//! A pigpen document is a hyphence document (madder RFC 0001) carrying a
//! markl-ID recipient set in its metadata section and an optional
//! ciphertext payload in its body. It combines age's file-key
//! indirection + STREAM payload + header MAC with the ebox's PIV/P-256
//! hardware wrap, unified under markl IDs.
//!
//! **Status: prototype.** This crate is excluded from the piggy
//! workspace (root `Cargo.toml`). It uses the pure-Rust RustCrypto stack
//! — `x25519-dalek`, `p256`, `chacha20poly1305`, `hkdf`, `sha2`, `hmac`
//! — and `piggy-markl` (pure Rust), and deliberately does **not** depend
//! on the OpenSSL-backed `piggy-box`, so it builds for
//! `wasm32-unknown-unknown`. See `docs/plans/2026-06-24-pigpen-wasm.md`.
//!
//! Card-bound P-256 decryption is abstracted behind [`EcdhOracle`] so a
//! wasm host supplies the scalar multiplication (piggy-agent's
//! `ecdh@joyent.com`) without the module linking any card transport.

mod crypto;
mod document;
mod hyphence;

pub use document::{Document, EcdhOracle, Pointer, Recipient, X25519Identity, recipient_id};

/// Errors produced by the pigpen prototype.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("hyphence framing: {0}")]
    Hyphence(String),
    #[error("markl: {0}")]
    Markl(String),
    #[error("blech32: {0}")]
    Blech32(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("unsupported recipient format: {0}")]
    UnsupportedFormat(String),
    #[error("malformed document: {0}")]
    Malformed(String),
    #[error("no usable recipient (no matching identity/oracle)")]
    NoRecipient,
    #[error("header MAC mismatch")]
    MacMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;
