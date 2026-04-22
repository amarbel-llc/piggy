# pivy-agent Rust Rewrite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite pivy-agent as a Rust binary that serves the SSH agent protocol backed by PIV smartcard keys.

**Architecture:** Cargo workspace with three crates: `pivy-piv` (PIV smartcard library on `pcsc` crate), `pivy-agent` (SSH agent using `ssh-agent-lib`), and `pivy-common` (shared error/util types). Pure Rust for SSH key types and crypto; `openssl` crate only for X.509 cert parsing.

**Tech Stack:** Rust 2021 edition, ssh-agent-lib 0.5.x, pcsc 2.9.x, ssh-key, tokio, clap, tracing, openssl, zeroize, thiserror

**Design doc:** `docs/plans/2026-02-17-rust-rewrite-design.md`

**Reference C code:** `src/pivy-agent.c` (3,676 lines), `src/piv.c` (7,669 lines), `src/tlv.c` (791 lines)

---

### Task 1: Scaffold Cargo Workspace and Nix Build

**Files:**
- Create: `rust/Cargo.toml` (workspace root)
- Create: `rust/crates/pivy-common/Cargo.toml`
- Create: `rust/crates/pivy-common/src/lib.rs`
- Create: `rust/crates/pivy-piv/Cargo.toml`
- Create: `rust/crates/pivy-piv/src/lib.rs`
- Create: `rust/crates/pivy-agent/Cargo.toml`
- Create: `rust/crates/pivy-agent/src/main.rs`
- Modify: `flake.nix` (add Rust build alongside C build)
- Create: `.envrc` (direnv for rust devenv)

**Step 1: Create workspace Cargo.toml**

```toml
# rust/Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/pivy-common",
    "crates/pivy-piv",
    "crates/pivy-agent",
]
```

**Step 2: Create pivy-common crate**

```toml
# rust/crates/pivy-common/Cargo.toml
[package]
name = "pivy-common"
version = "0.1.0"
edition = "2021"

[dependencies]
thiserror = "2"
```

```rust
// rust/crates/pivy-common/src/lib.rs
pub mod error;
```

```rust
// rust/crates/pivy-common/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PivyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
```

**Step 3: Create pivy-piv crate with pcsc dependency**

```toml
# rust/crates/pivy-piv/Cargo.toml
[package]
name = "pivy-piv"
version = "0.1.0"
edition = "2021"

[dependencies]
pivy-common = { path = "../pivy-common" }
pcsc = "2.9"
thiserror = "2"
tracing = "0.1"
zeroize = { version = "1", features = ["derive"] }
```

```rust
// rust/crates/pivy-piv/src/lib.rs
pub mod error;
pub mod guid;
pub mod tlv;
pub mod apdu;
pub mod context;
pub mod token;
pub mod slot;

pub use context::PivContext;
pub use token::PivToken;
pub use slot::PivSlot;
pub use guid::Guid;
pub use error::PivError;
```

Create empty stub modules for each (`error.rs`, `guid.rs`, `tlv.rs`, `apdu.rs`, `context.rs`, `token.rs`, `slot.rs`).

**Step 4: Create pivy-agent crate**

```toml
# rust/crates/pivy-agent/Cargo.toml
[package]
name = "pivy-agent"
version = "0.1.0"
edition = "2021"

[dependencies]
pivy-common = { path = "../pivy-common" }
pivy-piv = { path = "../pivy-piv" }
ssh-agent-lib = "0.5"
ssh-key = { version = "0.6", features = ["alloc", "ecdsa", "rsa", "ed25519"] }
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["rt", "macros", "signal", "sync", "net", "time"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
thiserror = "2"
zeroize = { version = "1", features = ["derive"] }
hex = "0.4"
```

```rust
// rust/crates/pivy-agent/src/main.rs
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "pivy-agent", about = "PIV-backed SSH agent")]
struct Cli {
    /// GUID of the PIV card to use
    #[arg(short = 'g')]
    guid: Option<String>,

    /// All-card mode: expose keys from all PIV cards
    #[arg(short = 'A')]
    all_cards: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("pivy-agent starting with {:?}", cli);
}
```

**Step 5: Update flake.nix to add Rust build**

Add a `pivy-rust` package to `flake.nix` that builds the Rust workspace using `rustPlatform.buildRustPackage`, following the `ssh-agent-mux` pattern. Keep the existing C build as `pivy` (default). Add `pivy-rust` as an additional package.

The Rust build needs `buildInputs`: `openssl.dev`, `pcsclite.dev` (Linux only), `pkg-config`.

**Step 6: Create .envrc for direnv**

```bash
# rust/.envrc
use flake "$HOME/eng/devenvs/rust"
```

**Step 7: Verify it compiles**

Run: `cd rust && cargo build`
Expected: Compiles with no errors, produces empty agent binary.

Run: `nix build .#pivy-rust` (from project root)
Expected: Builds successfully.

**Step 8: Commit**

```bash
git add rust/ .envrc
git commit -m "feat: scaffold Rust workspace with pivy-common, pivy-piv, pivy-agent"
```

---

### Task 2: TLV Encoder/Decoder

The TLV (Tag-Length-Value) module is foundational -- used by all PIV APDU parsing. Port from `src/tlv.c` (791 lines).

**Files:**
- Create: `rust/crates/pivy-piv/src/tlv.rs`
- Create: `rust/crates/pivy-piv/tests/tlv_tests.rs`

**Step 1: Write tests for TLV decoding**

Test decoding a simple TLV structure (single tag + value), nested TLV, multi-byte tags, and the PIV CHUID as a real-world example.

```rust
// rust/crates/pivy-piv/tests/tlv_tests.rs
use pivy_piv::tlv::{TlvReader, TlvWriter};

#[test]
fn decode_single_tag() {
    // Tag 0x53 (PIV data object), length 3, value [0x01, 0x02, 0x03]
    let data = [0x53, 0x03, 0x01, 0x02, 0x03];
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x53);
    let value = reader.read_value().unwrap();
    assert_eq!(value, &[0x01, 0x02, 0x03]);
}

#[test]
fn decode_two_byte_length() {
    // Tag 0x53, length 0x81 0x80 (128 bytes), value = 128 zeros
    let mut data = vec![0x53, 0x81, 0x80];
    data.extend(vec![0x00; 128]);
    let mut reader = TlvReader::new(&data);
    let tag = reader.read_tag().unwrap();
    assert_eq!(tag, 0x53);
    let value = reader.read_value().unwrap();
    assert_eq!(value.len(), 128);
}

#[test]
fn encode_single_tag() {
    let mut writer = TlvWriter::new();
    writer.write_tag_value(0x53, &[0x01, 0x02, 0x03]);
    assert_eq!(writer.as_bytes(), &[0x53, 0x03, 0x01, 0x02, 0x03]);
}
```

**Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p pivy-piv`
Expected: Compilation error -- `TlvReader` and `TlvWriter` not defined.

**Step 3: Implement TlvReader and TlvWriter**

Port the core logic from `src/tlv.c`. The C version uses a state machine with `tlv_read_tag`, `tlv_read_upto`. The Rust version should use a cursor-based approach:

```rust
// rust/crates/pivy-piv/src/tlv.rs
use crate::error::PivError;

pub struct TlvReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TlvReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_tag(&mut self) -> Result<u32, PivError> {
        // BER-TLV tag decoding: single or multi-byte
        // ...
    }

    pub fn read_length(&mut self) -> Result<usize, PivError> {
        // BER-TLV length decoding: short form (1 byte) or long form (0x81/0x82)
        // ...
    }

    pub fn read_value(&mut self) -> Result<&'a [u8], PivError> {
        let len = self.read_length()?;
        // ...
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

pub struct TlvWriter {
    buf: Vec<u8>,
}

impl TlvWriter {
    pub fn new() -> Self { Self { buf: Vec::new() } }

    pub fn write_tag_value(&mut self, tag: u32, value: &[u8]) {
        self.write_tag(tag);
        self.write_length(value.len());
        self.buf.extend_from_slice(value);
    }

    fn write_tag(&mut self, tag: u32) { /* ... */ }
    fn write_length(&mut self, len: usize) { /* ... */ }

    pub fn as_bytes(&self) -> &[u8] { &self.buf }
}
```

Implement the full BER-TLV encoding/decoding logic based on `src/tlv.c` lines 50-200 (tag parsing) and lines 200-400 (length parsing).

**Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p pivy-piv`
Expected: All 3 tests pass.

**Step 5: Commit**

```bash
git add rust/crates/pivy-piv/src/tlv.rs rust/crates/pivy-piv/tests/
git commit -m "feat(pivy-piv): add TLV encoder/decoder"
```

---

### Task 3: GUID Type and PIV Error Types

**Files:**
- Implement: `rust/crates/pivy-piv/src/guid.rs`
- Implement: `rust/crates/pivy-piv/src/error.rs`
- Create: `rust/crates/pivy-piv/tests/guid_tests.rs`

**Step 1: Write GUID tests**

```rust
#[test]
fn parse_guid_from_hex() {
    let guid = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    assert_eq!(guid.as_bytes().len(), 16);
    assert_eq!(guid.to_hex(), "995E171383029CDA0D9CDBDBAD580813");
}

#[test]
fn guid_short_display() {
    let guid = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();
    assert_eq!(guid.short_id(), "995E1713");
}

#[test]
fn guid_reject_invalid() {
    assert!(Guid::from_hex("ZZZZ").is_err());
    assert!(Guid::from_hex("00112233445566778899AABBCCDDEEFF00").is_err()); // too long
}
```

**Step 2: Run tests to verify failure, then implement**

```rust
// rust/crates/pivy-piv/src/guid.rs
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn from_hex(s: &str) -> Result<Self, crate::error::PivError> { /* ... */ }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::PivError> { /* ... */ }
    pub fn as_bytes(&self) -> &[u8; 16] { &self.0 }
    pub fn to_hex(&self) -> String { hex::encode_upper(self.0) }
    pub fn short_id(&self) -> String { hex::encode_upper(&self.0[..4]) }
}

impl fmt::Debug for Guid { /* hex display */ }
impl fmt::Display for Guid { /* short_id */ }
```

```rust
// rust/crates/pivy-piv/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PivError {
    #[error("PCSC error: {0}")]
    Pcsc(#[from] pcsc::Error),

    #[error("TLV parse error: {message}")]
    Tlv { message: String },

    #[error("invalid GUID: {0}")]
    InvalidGuid(String),

    #[error("APDU error: SW={sw:#06x}")]
    Apdu { sw: u16 },

    #[error("card not found")]
    CardNotFound,

    #[error("no PIN provided")]
    NoPin,

    #[error("PIN incorrect, {retries} retries remaining")]
    PinIncorrect { retries: u32 },

    #[error("slot {0:#04x} not found or empty")]
    SlotEmpty(u8),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("{0}")]
    Other(String),
}
```

**Step 3: Verify tests pass, commit**

Run: `cd rust && cargo test -p pivy-piv`

```bash
git commit -m "feat(pivy-piv): add Guid type and PivError enum"
```

---

### Task 4: APDU Builder and PIV Constants

Port the APDU command builder from `src/piv.c` (the `apdu` struct and `piv_apdu_sw` constants).

**Files:**
- Implement: `rust/crates/pivy-piv/src/apdu.rs`
- Create: `rust/crates/pivy-piv/tests/apdu_tests.rs`

**Step 1: Write tests**

Test building a SELECT command (the first APDU sent to a PIV card) and parsing a status word response.

```rust
use pivy_piv::apdu::{Apdu, StatusWord, PIV_AID};

#[test]
fn build_select_piv() {
    let apdu = Apdu::select(PIV_AID);
    let bytes = apdu.to_bytes();
    assert_eq!(bytes[0], 0x00); // CLA
    assert_eq!(bytes[1], 0xA4); // INS = SELECT
    assert_eq!(bytes[2], 0x04); // P1 = select by AID
    assert_eq!(bytes[3], 0x00); // P2
}

#[test]
fn parse_status_word_success() {
    let sw = StatusWord::from_bytes(0x90, 0x00);
    assert!(sw.is_success());
}

#[test]
fn parse_status_word_auth_required() {
    let sw = StatusWord::from_bytes(0x69, 0x82);
    assert!(!sw.is_success());
}
```

**Step 2: Implement APDU types**

```rust
// rust/crates/pivy-piv/src/apdu.rs

/// PIV application AID (NIST SP 800-73-4)
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

/// YubiKey PIV management AID
pub const YKPIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// PIV slot IDs
pub mod slot {
    pub const SLOT_9A: u8 = 0x9A; // PIV Authentication
    pub const SLOT_9C: u8 = 0x9C; // Digital Signature
    pub const SLOT_9D: u8 = 0x9D; // Key Management
    pub const SLOT_9E: u8 = 0x9E; // Card Authentication
    // Retired key management slots 82-95
}

pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u16>,
}

impl Apdu {
    pub fn select(aid: &[u8]) -> Self { /* CLA=0x00, INS=0xA4, P1=0x04, P2=0x00 */ }
    pub fn get_data(tag: u32) -> Self { /* INS=0xCB for PIV GET DATA */ }
    pub fn general_authenticate(alg: u8, slot: u8, data: &[u8]) -> Self { /* INS=0x87 */ }
    pub fn verify_pin(pin: &[u8]) -> Self { /* INS=0x20 */ }

    pub fn to_bytes(&self) -> Vec<u8> { /* ISO 7816-4 encoding */ }
}

#[derive(Debug, Clone, Copy)]
pub struct StatusWord(pub u8, pub u8);

impl StatusWord {
    pub fn from_bytes(sw1: u8, sw2: u8) -> Self { Self(sw1, sw2) }
    pub fn is_success(&self) -> bool { self.0 == 0x90 && self.1 == 0x00 }
    pub fn as_u16(&self) -> u16 { (self.0 as u16) << 8 | self.1 as u16 }
}
```

Reference: `src/piv.c` lines 300-500 for APDU construction, lines 100-200 for constants.

**Step 3: Verify tests pass, commit**

```bash
git commit -m "feat(pivy-piv): add APDU builder and PIV constants"
```

---

### Task 5: PivContext -- Reader Enumeration

Connect to the PCSC service and enumerate card readers.

**Files:**
- Implement: `rust/crates/pivy-piv/src/context.rs`
- Create: `rust/crates/pivy-piv/tests/context_tests.rs`

**Step 1: Write test (integration, requires PCSC service)**

```rust
// This is an integration test -- skip if PCSC unavailable
#[test]
fn enumerate_readers() {
    let ctx = match PivContext::new() {
        Ok(ctx) => ctx,
        Err(_) => { eprintln!("PCSC not available, skipping"); return; }
    };
    let readers = ctx.list_readers().unwrap_or_default();
    // Just verify it doesn't crash -- may be empty in CI
    println!("Found {} readers", readers.len());
}
```

**Step 2: Implement PivContext**

```rust
// rust/crates/pivy-piv/src/context.rs
use pcsc::{Context, Scope};
use crate::error::PivError;

pub struct PivContext {
    ctx: Context,
}

impl PivContext {
    pub fn new() -> Result<Self, PivError> {
        let ctx = Context::establish(Scope::System)?;
        Ok(Self { ctx })
    }

    pub fn list_readers(&self) -> Result<Vec<String>, PivError> {
        let mut buf = vec![0u8; 4096];
        let readers = self.ctx.list_readers(&mut buf)?;
        Ok(readers.map(|r| r.to_string_lossy().into_owned()).collect())
    }

    pub fn pcsc_context(&self) -> &Context {
        &self.ctx
    }
}
```

Reference: `src/piv.c` `piv_establish_context()` (line ~300) and `piv_enumerate()` (line ~800).

**Step 3: Verify it compiles and test passes, commit**

```bash
git commit -m "feat(pivy-piv): add PivContext for PCSC reader enumeration"
```

---

### Task 6: PivToken -- Connect and SELECT PIV

Connect to a card in a reader, send SELECT PIV AID, read the CHUID to get the GUID.

**Files:**
- Implement: `rust/crates/pivy-piv/src/token.rs`
- Implement: `rust/crates/pivy-piv/src/slot.rs` (stub)
- Create: `rust/crates/pivy-piv/tests/token_tests.rs`

**Step 1: Write test**

```rust
#[test]
fn connect_and_select() {
    let ctx = match PivContext::new() {
        Ok(ctx) => ctx,
        Err(_) => { eprintln!("PCSC not available, skipping"); return; }
    };
    let tokens = ctx.enumerate_tokens().unwrap_or_default();
    for token in &tokens {
        println!("Found PIV token: GUID={}", token.guid());
    }
}
```

**Step 2: Implement PivToken**

The token connects to a card reader, sends SELECT PIV AID, then reads the CHUID (tag 0x5FC102) to extract the GUID (tag 0x34 within CHUID).

```rust
// rust/crates/pivy-piv/src/token.rs
use pcsc::{Card, ShareMode, Protocols, Disposition};
use crate::{Guid, PivSlot, apdu::{Apdu, StatusWord, PIV_AID}, error::PivError, tlv::TlvReader};

pub struct PivToken {
    card: Card,
    guid: Guid,
    reader_name: String,
    slots: Vec<PivSlot>,
}

impl PivToken {
    pub fn connect(ctx: &PivContext, reader: &str) -> Result<Self, PivError> {
        let card = ctx.pcsc_context().connect(
            &std::ffi::CString::new(reader).unwrap(),
            ShareMode::Shared,
            Protocols::ANY,
        )?;
        let mut token = Self {
            card,
            guid: Guid::from_bytes(&[0; 16])?,
            reader_name: reader.to_string(),
            slots: Vec::new(),
        };
        token.select_piv()?;
        token.read_chuid()?;
        Ok(token)
    }

    fn transmit(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        let cmd = apdu.to_bytes();
        let mut resp = vec![0u8; 4096];
        let resp = self.card.transmit(&cmd, &mut resp)?;
        let len = resp.len();
        if len < 2 { return Err(PivError::Other("short response".into())); }
        let sw = StatusWord::from_bytes(resp[len - 2], resp[len - 1]);
        Ok((resp[..len - 2].to_vec(), sw))
    }

    fn select_piv(&mut self) -> Result<(), PivError> {
        let apdu = Apdu::select(PIV_AID);
        let (_, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }

    fn read_chuid(&mut self) -> Result<(), PivError> {
        // GET DATA for CHUID (tag 0x5FC102)
        // Parse TLV to find GUID (tag 0x34)
        // ...
    }

    pub fn guid(&self) -> &Guid { &self.guid }
    pub fn reader_name(&self) -> &str { &self.reader_name }
}
```

Add `enumerate_tokens()` method to `PivContext` that iterates readers, tries to connect each, and returns successfully connected `PivToken`s.

Reference: `src/piv.c` `piv_enumerate()` (line ~800), `piv_read_chuid()` (line ~600).

**Step 3: Verify, commit**

```bash
git commit -m "feat(pivy-piv): add PivToken with connect, SELECT, and CHUID reading"
```

---

### Task 7: PivSlot -- Read Certificates and Public Keys

Read X.509 certificates from PIV slots and extract SSH public keys.

**Files:**
- Implement: `rust/crates/pivy-piv/src/slot.rs`
- Implement: `rust/crates/pivy-piv/src/cert.rs`
- Create: `rust/crates/pivy-piv/tests/slot_tests.rs`

**Step 1: Write test**

```rust
#[test]
fn read_slots_from_token() {
    // Integration test: enumerate tokens, read all slots
    let ctx = match PivContext::new() { Ok(c) => c, Err(_) => return };
    let tokens = ctx.enumerate_tokens().unwrap_or_default();
    for token in &tokens {
        let slots = token.read_all_slots().unwrap_or_default();
        for slot in &slots {
            println!("Slot {:#04x}: algo={:?}, pubkey={}", slot.id(), slot.algorithm(), slot.ssh_public_key_string());
        }
    }
}
```

**Step 2: Implement PivSlot and cert parsing**

```rust
// rust/crates/pivy-piv/src/slot.rs
use ssh_key::PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivAlgorithm {
    Rsa2048,
    Rsa4096,
    EcP256,
    EcP384,
}

pub struct PivSlot {
    id: u8,
    algorithm: PivAlgorithm,
    cert_der: Vec<u8>,
    public_key: PublicKey,
}

impl PivSlot {
    pub fn id(&self) -> u8 { self.id }
    pub fn algorithm(&self) -> PivAlgorithm { self.algorithm }
    pub fn public_key(&self) -> &PublicKey { &self.public_key }
    pub fn ssh_public_key_string(&self) -> String {
        self.public_key.to_openssh().unwrap_or_default()
    }
    pub fn cert_der(&self) -> &[u8] { &self.cert_der }
}
```

```rust
// rust/crates/pivy-piv/src/cert.rs
// Parse X.509 DER cert to extract the public key and convert to ssh_key::PublicKey
// Uses openssl crate for X509 parsing
use openssl::x509::X509;
use ssh_key::PublicKey;

pub fn extract_public_key(cert_der: &[u8]) -> Result<(PivAlgorithm, PublicKey), PivError> {
    let cert = X509::from_der(cert_der)?;
    let pkey = cert.public_key()?;
    // Convert EVP_PKEY to ssh_key::PublicKey based on key type
    // ...
}
```

Add `read_all_slots()` to `PivToken` that iterates standard PIV slots (9A, 9C, 9D, 9E) + retired slots (82-95), sends GET DATA for each cert object, parses the DER cert, extracts the public key.

Reference: `src/piv.c` `piv_read_cert()` (line ~1200), `src/piv-certs.c`.

**Step 3: Verify, commit**

This requires `openssl` in Cargo.toml for pivy-piv:
```toml
openssl = "0.10"
ssh-key = { version = "0.6", features = ["alloc", "ecdsa", "rsa", "ed25519"] }
```

```bash
git commit -m "feat(pivy-piv): read certificates and extract SSH public keys from slots"
```

---

### Task 8: PivToken -- Sign Operations

Implement `GENERAL AUTHENTICATE` for signing data with a PIV slot key.

**Files:**
- Add to: `rust/crates/pivy-piv/src/token.rs` (sign method)
- Create: `rust/crates/pivy-piv/tests/sign_tests.rs`

**Step 1: Write test**

```rust
#[test]
fn sign_with_9e_no_pin() {
    // 9E (Card Authentication) doesn't require PIN
    let ctx = match PivContext::new() { Ok(c) => c, Err(_) => return };
    let tokens = ctx.enumerate_tokens().unwrap_or_default();
    let token = match tokens.into_iter().next() { Some(t) => t, None => return };
    let data = b"test data to sign";
    let signature = token.sign(0x9E, data).unwrap();
    assert!(!signature.is_empty());
}
```

**Step 2: Implement signing**

The sign operation sends a `GENERAL AUTHENTICATE` (INS=0x87) APDU with the data to sign wrapped in a TLV structure. The algorithm byte and slot ID are in P1/P2.

```rust
impl PivToken {
    pub fn sign(&self, slot_id: u8, data: &[u8]) -> Result<Vec<u8>, PivError> {
        let slot = self.find_slot(slot_id)?;
        let alg_byte = match slot.algorithm() {
            PivAlgorithm::EcP256 => 0x11,
            PivAlgorithm::EcP384 => 0x14,
            PivAlgorithm::Rsa2048 => 0x07,
            PivAlgorithm::Rsa4096 => 0x08,
        };
        // Build GENERAL AUTHENTICATE TLV:
        // Tag 0x7C containing:
        //   Tag 0x82 (response placeholder, empty)
        //   Tag 0x81 (challenge/data to sign)
        let mut inner = TlvWriter::new();
        inner.write_tag_value(0x82, &[]); // response
        inner.write_tag_value(0x81, data); // challenge
        let mut outer = TlvWriter::new();
        outer.write_tag_value(0x7C, inner.as_bytes());

        let apdu = Apdu::general_authenticate(alg_byte, slot_id, outer.as_bytes());
        let (resp, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        // Parse response: tag 0x7C -> tag 0x82 = signature
        let mut reader = TlvReader::new(&resp);
        // ...extract tag 0x82 value...
        Ok(signature_bytes)
    }

    pub fn verify_pin(&self, pin: &str) -> Result<(), PivError> {
        let apdu = Apdu::verify_pin(pin.as_bytes());
        let (_, sw) = self.transmit(&apdu)?;
        match sw.as_u16() {
            0x9000 => Ok(()),
            sw if sw & 0xFFF0 == 0x63C0 => {
                let retries = (sw & 0x000F) as u32;
                Err(PivError::PinIncorrect { retries })
            }
            _ => Err(PivError::Apdu { sw: sw.as_u16() }),
        }
    }
}
```

Reference: `src/piv.c` `piv_sign()` (~line 3000), `piv_verify_pin()` (~line 2500).

**Step 3: Verify, commit**

```bash
git commit -m "feat(pivy-piv): add sign and verify_pin operations"
```

---

### Task 9: Minimal SSH Agent -- Request Identities

Wire up `ssh-agent-lib` to serve public keys from the PIV card.

**Files:**
- Implement: `rust/crates/pivy-agent/src/agent.rs`
- Modify: `rust/crates/pivy-agent/src/main.rs`

**Step 1: Write integration test**

```rust
// Test: start agent, connect with ssh-add -l, verify keys are listed
#[tokio::test]
async fn list_identities_via_socket() {
    // Create agent on a temp socket
    // Connect with ssh-agent-client or manually
    // Verify identity list is non-empty
}
```

**Step 2: Implement Agent Session**

```rust
// rust/crates/pivy-agent/src/agent.rs
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::proto::{Identity, SignRequest, Signature};
use ssh_agent_lib::error::AgentError;
use pivy_piv::{PivContext, PivToken, PivSlot};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct PivyAgent {
    tokens: Arc<Mutex<Vec<PivToken>>>,
    guid: Option<pivy_piv::Guid>,
    all_card_mode: bool,
}

#[ssh_agent_lib::async_trait]
impl Session for PivyAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let tokens = self.tokens.lock().await;
        let mut identities = Vec::new();
        for token in tokens.iter() {
            for slot in token.slots() {
                identities.push(Identity {
                    pubkey: slot.public_key().clone(),
                    comment: format!("PIV_slot_{:02x} {}", slot.id(), token.guid().short_id()),
                });
            }
        }
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        // Find which token/slot matches the requested key
        // Open transaction, verify PIN if needed, sign
        // Convert to ssh_key::Signature
        todo!()
    }
}
```

**Step 3: Wire up main.rs**

```rust
// rust/crates/pivy-agent/src/main.rs
use clap::Parser;
use tokio::net::UnixListener;
use ssh_agent_lib::agent::listen;

mod agent;

#[derive(Parser, Debug)]
#[command(name = "pivy-agent")]
struct Cli {
    #[arg(short = 'g')]
    guid: Option<String>,
    #[arg(short = 'A')]
    all_cards: bool,
    #[arg(short = 'a')]
    socket: Option<String>,
    #[arg(short = 'd', action = clap::ArgAction::Count)]
    debug: u8,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Set up tracing
    tracing_subscriber::fmt()
        .with_env_filter("pivy_agent=info")
        .init();

    // Create socket path
    let socket_path = cli.socket.unwrap_or_else(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("agent.{}", std::process::id()));
        path.to_string_lossy().into_owned()
    });

    // Print SSH_AUTH_SOCK for shell eval
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path);
    println!("SSH_AGENT_PID={}; export SSH_AGENT_PID;", std::process::id());
    println!("echo Agent pid {};", std::process::id());

    // Enumerate tokens
    let ctx = pivy_piv::PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;
    let agent = agent::PivyAgent::new(tokens, cli.guid, cli.all_cards);

    // Listen
    let listener = UnixListener::bind(&socket_path)?;
    listen(listener, agent).await?;
    Ok(())
}
```

**Step 4: Test manually**

Run: `cd rust && cargo run -p pivy-agent -- -A`
Then in another shell: `SSH_AUTH_SOCK=<path> ssh-add -l`
Expected: Lists PIV keys.

**Step 5: Commit**

```bash
git commit -m "feat(pivy-agent): minimal SSH agent serving PIV identities"
```

---

### Task 10: SSH Agent -- Sign Requests

Implement the `sign()` method to actually perform cryptographic signing via the PIV card.

**Files:**
- Modify: `rust/crates/pivy-agent/src/agent.rs`

**Step 1: Write test**

```rust
#[tokio::test]
async fn sign_request_via_agent() {
    // Start agent, send a sign request for a known key
    // Verify the signature is valid
}
```

**Step 2: Implement sign in agent**

```rust
async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
    let tokens = self.tokens.lock().await;

    // Find the token/slot matching the requested public key
    let (token_idx, slot_idx) = self.find_key_for_pubkey(&tokens, &request.pubkey)
        .ok_or_else(|| AgentError::other("key not found"))?;

    let token = &tokens[token_idx];
    let slot = &token.slots()[slot_idx];

    // For slots other than 9E, we need PIN
    if slot.id() != 0x9E {
        if self.pin.is_none() {
            return Err(AgentError::other("no PIN provided (try ssh-add -X)"));
        }
        token.verify_pin(self.pin.as_ref().unwrap())
            .map_err(|e| AgentError::other(e))?;
    }

    // Hash the data if needed (for RSA, hash before signing; for ECDSA, hash matches curve)
    let hash = compute_hash(slot.algorithm(), &request.data);

    // Sign via card
    let sig_bytes = token.sign(slot.id(), &hash)
        .map_err(|e| AgentError::other(e))?;

    // Convert raw signature to ssh_key::Signature
    let signature = to_ssh_signature(slot.algorithm(), &sig_bytes)?;
    Ok(signature)
}
```

**Step 3: Test with actual SSH**

Run: `pivy-agent -A` then `ssh -T git@github.com` (if key is registered).
Or: `ssh-add -l` then `ssh-add -X` (lock), enter PIN, `ssh-add -l` again.

**Step 4: Commit**

```bash
git commit -m "feat(pivy-agent): implement sign requests via PIV card"
```

---

### Task 11: Lock/Unlock (PIN Management)

Implement `lock()` and `unlock()` to manage PIN caching via `ssh-add -x` and `ssh-add -X`.

**Files:**
- Modify: `rust/crates/pivy-agent/src/agent.rs`
- Create: `rust/crates/pivy-agent/src/pin.rs`

**Step 1: Implement secure PIN storage**

```rust
// rust/crates/pivy-agent/src/pin.rs
use zeroize::Zeroize;

/// Secure PIN storage with zeroize-on-drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecurePin {
    pin: String,
}

impl SecurePin {
    pub fn new(pin: String) -> Self { Self { pin } }
    pub fn as_str(&self) -> &str { &self.pin }
}
```

**Step 2: Implement lock/unlock on Session**

```rust
async fn lock(&mut self, password: Vec<u8>) -> Result<(), AgentError> {
    // pivy-agent interprets "lock" as forgetting the PIN
    self.pin = None;
    self.locked = true;
    Ok(())
}

async fn unlock(&mut self, password: Vec<u8>) -> Result<(), AgentError> {
    // pivy-agent interprets "unlock" as setting the PIN
    let pin = String::from_utf8(password)
        .map_err(|_| AgentError::other("invalid PIN encoding"))?;
    self.pin = Some(SecurePin::new(pin));
    self.locked = false;
    Ok(())
}
```

**Step 3: Test**

Run agent, then: `ssh-add -X` (enter PIN), `ssh-add -l` (should show keys), sign something, then `ssh-add -x` (lock), try to sign (should fail for non-9E slots).

**Step 4: Commit**

```bash
git commit -m "feat(pivy-agent): implement lock/unlock for PIN management"
```

---

### Task 12: Card Probing and Transaction Management

Add periodic card probing (check card still present) and transaction timeouts.

**Files:**
- Create: `rust/crates/pivy-agent/src/card.rs`
- Modify: `rust/crates/pivy-agent/src/agent.rs`

**Step 1: Implement card manager**

```rust
// rust/crates/pivy-agent/src/card.rs
use tokio::time::{interval, Duration};

const PROBE_INTERVAL_NO_PIN: Duration = Duration::from_secs(120);
const PROBE_INTERVAL_PIN: Duration = Duration::from_secs(30);
const PROBE_FAIL_LIMIT: u32 = 3;

pub struct CardManager {
    ctx: PivContext,
    probe_fails: u32,
    has_pin: bool,
}

impl CardManager {
    pub async fn probe_loop(&mut self) {
        let mut interval = interval(PROBE_INTERVAL_NO_PIN);
        loop {
            interval.tick().await;
            if let Err(_) = self.probe_card() {
                self.probe_fails += 1;
                if self.probe_fails >= PROBE_FAIL_LIMIT {
                    // Forget PIN for safety
                    tracing::warn!("card unavailable, forgetting PIN");
                }
            } else {
                self.probe_fails = 0;
            }
        }
    }
}
```

**Step 2: Wire into agent lifecycle, commit**

```bash
git commit -m "feat(pivy-agent): add periodic card probing and transaction management"
```

---

### Task 13: Full CLI Flags and Daemon Mode

Add all remaining CLI flags: `-K` (CAK), `-C`/`-CC` (confirm), `-S` (slotspec), `-k` (kill), `-s`/`-c` (shell format), fork-to-background on Linux, foreground-only on macOS.

**Files:**
- Modify: `rust/crates/pivy-agent/src/main.rs`

**Step 1: Extend Cli struct**

```rust
#[derive(Parser)]
struct Cli {
    #[arg(short = 'g')]
    guid: Option<String>,
    #[arg(short = 'A')]
    all_cards: bool,
    #[arg(short = 'K')]
    cak: Option<String>,
    #[arg(short = 'C', action = clap::ArgAction::Count)]
    confirm: u8,
    #[arg(short = 'a')]
    socket: Option<String>,
    #[arg(short = 'S')]
    slot_spec: Option<String>,
    #[arg(short = 'k')]
    kill: bool,
    #[arg(short = 'd', action = clap::ArgAction::Count)]
    debug: u8,
    #[arg(short = 'D')]
    foreground_debug: bool,
    #[arg(short = 'i')]
    info: bool,
    #[arg(short = 's')]
    sh_format: bool,
    #[arg(short = 'c')]
    csh_format: bool,

    /// Command to execute with agent env set
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}
```

**Step 2: Implement daemon fork (Linux only)**

On Linux, fork to background and redirect stdin/stdout to /dev/null. On macOS, stay in foreground (PCSC framework doesn't survive fork).

**Step 3: Implement -k (kill)**

Read `SSH_AGENT_PID` from env, send SIGTERM.

**Step 4: Test all flag combinations, commit**

```bash
git commit -m "feat(pivy-agent): complete CLI flags and daemon mode"
```

---

### Task 14: Nix Build and Service Files

Finalize the Nix build for the Rust binary and install systemd/launchd service files.

**Files:**
- Modify: `flake.nix`
- Create: `rust/pivy-agent@.service` (copy from existing, adjust path)

**Step 1: Update flake.nix**

Add the Rust package as the default, move C build to `packages.pivy-c`:

```nix
pivy-rust = pkgs.rustPlatform.buildRustPackage {
  pname = "pivy-agent";
  version = "0.1.0";
  src = ./rust;
  cargoLock.lockFile = ./rust/Cargo.lock;
  buildInputs = [ pkgs.openssl ] ++ pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [ pkgs.pcsclite ];
  nativeBuildInputs = [ pkgs.pkg-config ];

  postInstall = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
    mkdir -p $out/lib/systemd/user
    substitute ${./pivy-agent@.service} $out/lib/systemd/user/pivy-agent@.service \
      --replace-fail '@@BINDIR@@' "$out/bin"
  '';
};
```

**Step 2: Verify nix build**

Run: `nix build .#pivy-rust`
Expected: Builds, produces `result/bin/pivy-agent`.

**Step 3: Commit**

```bash
git commit -m "feat: nix build for Rust pivy-agent with service files"
```

---

### Task 15: Justfile and Integration Testing

Add justfile targets and basic integration tests using bats.

**Files:**
- Modify: `justfile`
- Create: `rust/tests/integration/agent.bats`

**Step 1: Update justfile**

```makefile
build:
  cd rust && cargo build

build-release:
  cd rust && cargo build --release

build-nix:
  nix build

test:
  cd rust && cargo test

test-integration:
  bats rust/tests/integration/

fmt:
  cd rust && cargo fmt

clippy:
  cd rust && cargo clippy -- -D warnings
```

**Step 2: Create basic bats integration test**

```bash
#!/usr/bin/env bats
# rust/tests/integration/agent.bats

setup() {
    SOCKET_DIR=$(mktemp -d)
    SOCKET="$SOCKET_DIR/agent.sock"
}

teardown() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
    rm -rf "$SOCKET_DIR"
}

@test "pivy-agent starts and listens on socket" {
    cargo run -p pivy-agent -- -A -a "$SOCKET" -D &
    AGENT_PID=$!
    sleep 1
    [ -S "$SOCKET" ]
}

@test "ssh-add -l returns identities" {
    cargo run -p pivy-agent -- -A -a "$SOCKET" -D &
    AGENT_PID=$!
    sleep 1
    SSH_AUTH_SOCK="$SOCKET" ssh-add -l
}
```

**Step 3: Commit**

```bash
git commit -m "feat: add justfile targets and bats integration tests"
```

---

## Summary of Tasks

| # | Task | Crate | Dependencies |
|---|------|-------|------|
| 1 | Scaffold workspace + Nix build | all | - |
| 2 | TLV encoder/decoder | pivy-piv | - |
| 3 | GUID type + error types | pivy-piv | Task 2 |
| 4 | APDU builder + PIV constants | pivy-piv | Tasks 2, 3 |
| 5 | PivContext (reader enumeration) | pivy-piv | Task 4 |
| 6 | PivToken (connect + SELECT) | pivy-piv | Task 5 |
| 7 | PivSlot (read certs, extract SSH keys) | pivy-piv | Task 6 |
| 8 | PivToken sign operations | pivy-piv | Task 7 |
| 9 | Minimal SSH agent (request identities) | pivy-agent | Task 8 |
| 10 | SSH agent sign requests | pivy-agent | Task 9 |
| 11 | Lock/unlock (PIN management) | pivy-agent | Task 10 |
| 12 | Card probing + transaction management | pivy-agent | Task 11 |
| 13 | Full CLI flags + daemon mode | pivy-agent | Task 12 |
| 14 | Nix build + service files | build | Task 13 |
| 15 | Justfile + bats integration tests | test | Task 14 |

Tasks 1-8 build the library bottom-up. Tasks 9-13 build the agent top-down on the library. Tasks 14-15 finalize the build and testing.
