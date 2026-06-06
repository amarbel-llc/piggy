//! Spike: the OpenSSL-free, wasm-capable **decrypt half** of a piggy-box.
//!
//! This mirrors what a future `piggy-box` "rustcrypto" backend (and the
//! `piggy-wasm` module on top of it) would do in the browser, minus the
//! private key — which never leaves the PIV card.
//!
//! ## The split (matches piggy-box's `EcdhOracle` seam)
//!
//! 1. [`parse_box`] reads the wire box and hands back the **ephemeral
//!    public key** (uncompressed SEC1, ready for the card's
//!    `GENERAL AUTHENTICATE`) plus the KDF nonce and AEAD IV. No secret
//!    is required for this step.
//! 2. JS (WebUSB → PIV applet) performs ECDH on slot 9D and returns the
//!    shared secret `Z` (the X-coordinate, field-size big-endian) — the
//!    exact bytes OpenSSL's `Deriver` produces and the card returns.
//! 3. [`open_box`] finishes: `SHA-512(Z ‖ nonce)` → key →
//!    ChaCha20-Poly1305 decrypt → PKCS#7 unpad.
//!
//! Wire format: `docs/rfcs/0002-piv-ecdh-box.md`. Crypto: RFC 7539.
//!
//! Everything in this file is `#![forbid(unsafe_code)]`-clean pure Rust
//! and compiles to `wasm32-unknown-unknown` unchanged.
#![forbid(unsafe_code)]

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha512};

const BOX_MAGIC: [u8; 2] = [0xB0, 0xC5];
const CIPHER_IV_LEN: usize = 12;
const DEFAULT_CIPHER: &str = "chacha20-poly1305@piggy.amarbel.net";
const DEFAULT_KDF: &str = "sha512";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    NistP256,
    NistP384,
}

impl Curve {
    fn from_wire(name: &str) -> Result<Self, String> {
        match name {
            "nistp256" => Ok(Curve::NistP256),
            "nistp384" => Ok(Curve::NistP384),
            other => Err(format!("unsupported curve: {other}")),
        }
    }
    /// Field-element / shared-secret length in bytes.
    pub fn field_len(self) -> usize {
        match self {
            Curve::NistP256 => 32,
            Curve::NistP384 => 48,
        }
    }
}

/// Everything the browser needs to drive the card, plus the bytes needed
/// to finish decryption once the card returns `Z`.
#[derive(Debug, Clone)]
pub struct ParsedBox {
    pub curve: Curve,
    /// Advisory PIV GUID (16 bytes) if the box carried one — lets JS pick
    /// the right card without trial-and-error.
    pub guid: Option<[u8; 16]>,
    /// Advisory PIV slot id (e.g. 0x9D) if present.
    pub slot: Option<u8>,
    /// Ephemeral public key, **uncompressed** SEC1 (`0x04 ‖ X ‖ Y`).
    /// This is the partner point fed to the card's `GENERAL AUTHENTICATE`.
    pub ephemeral_pubkey_uncompressed: Vec<u8>,
    /// Recipient public key, uncompressed SEC1 — lets JS confirm the box
    /// is addressed to the connected card's slot-9D key before prompting
    /// for a PIN.
    pub recipient_pubkey_uncompressed: Vec<u8>,
    pub kdf_nonce: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext_and_tag: Vec<u8>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or("length overflow while parsing box")?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or("unexpected end of box")?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    /// `string8`: one-byte length prefix then that many bytes.
    fn string8(&mut self) -> Result<&'a [u8], String> {
        let len = self.u8()? as usize;
        self.take(len)
    }
    /// `cstring8`: a `string8` carrying a NUL-terminated C string.
    fn cstring8(&mut self) -> Result<String, String> {
        let raw = self.string8()?;
        let trimmed = raw.strip_suffix(&[0]).unwrap_or(raw);
        String::from_utf8(trimmed.to_vec()).map_err(|e| format!("bad utf8 in cstring8: {e}"))
    }
    /// `string`: four-byte big-endian length prefix then that many bytes.
    fn string(&mut self) -> Result<&'a [u8], String> {
        let lb = self.take(4)?;
        let len = u32::from_be_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
        self.take(len)
    }
}

/// Parse a serialized piggy-box. Step 1 of the WASM decrypt flow — needs
/// no key material.
pub fn parse_box(wire: &[u8]) -> Result<ParsedBox, String> {
    let mut r = Reader::new(wire);

    if r.take(2)? != BOX_MAGIC {
        return Err("bad magic (not a piggy-box)".into());
    }
    let version = r.u8()?;
    if !(1..=2).contains(&version) {
        return Err(format!("unsupported version: {version}"));
    }

    let guid_slot_valid = r.u8()?;
    let (guid, slot) = if guid_slot_valid != 0 {
        let g = r.string8()?;
        let guid: [u8; 16] = g
            .try_into()
            .map_err(|_| "guid must be 16 bytes when valid".to_string())?;
        let slot = r.u8()?;
        (Some(guid), Some(slot))
    } else {
        let _empty = r.string8()?; // zero-length guid
        let _zero = r.u8()?; // slot 0x00
        (None, None)
    };

    let cipher = r.cstring8()?;
    if cipher != DEFAULT_CIPHER {
        return Err(format!("unsupported cipher: {cipher}"));
    }
    let kdf = r.cstring8()?;
    if kdf != DEFAULT_KDF {
        return Err(format!("unsupported kdf: {kdf}"));
    }

    let kdf_nonce = if version >= 2 {
        r.string8()?.to_vec()
    } else {
        Vec::new()
    };

    let curve = Curve::from_wire(&r.cstring8()?)?;
    let recipient_compressed = r.string8()?.to_vec();
    let ephemeral_compressed = r.string8()?.to_vec();
    let iv = r.string8()?.to_vec();
    let ciphertext_and_tag = r.string()?.to_vec();

    if iv.len() != CIPHER_IV_LEN {
        return Err(format!(
            "wire IV must be {CIPHER_IV_LEN} bytes for {DEFAULT_CIPHER}, got {}",
            iv.len()
        ));
    }

    Ok(ParsedBox {
        curve,
        guid,
        slot,
        ephemeral_pubkey_uncompressed: decompress_point(curve, &ephemeral_compressed)?,
        recipient_pubkey_uncompressed: decompress_point(curve, &recipient_compressed)?,
        kdf_nonce,
        iv,
        ciphertext_and_tag,
    })
}

/// Step 3 of the WASM decrypt flow: given the card-returned shared secret
/// `z`, derive the symmetric key and decrypt. `z` MUST be the raw
/// X-coordinate, field-size big-endian (what OpenSSL `Deriver` and the
/// PIV card both return).
pub fn open_box(parsed: &ParsedBox, z: &[u8]) -> Result<Vec<u8>, String> {
    if z.len() != parsed.curve.field_len() {
        return Err(format!(
            "shared secret must be {} bytes for this curve, got {}",
            parsed.curve.field_len(),
            z.len()
        ));
    }

    // KDF: key = SHA-512(Z ‖ nonce), truncated to the 32-byte cipher key.
    let mut hasher = Sha512::new();
    hasher.update(z);
    hasher.update(&parsed.kdf_nonce);
    let digest = hasher.finalize();
    let key = Key::from_slice(&digest[..32]);

    // AEAD: RFC 7539 ChaCha20-Poly1305, empty AAD, tag appended to ct.
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&parsed.iv);
    let padded = cipher
        .decrypt(nonce, parsed.ciphertext_and_tag.as_ref())
        .map_err(|_| "AEAD authentication failed (wrong key or tampered box)".to_string())?;

    pkcs7_unpad(&padded, 16)
}

fn pkcs7_unpad(data: &[u8], block: usize) -> Result<Vec<u8>, String> {
    let p = *data.last().ok_or("empty plaintext, cannot unpad")? as usize;
    if p == 0 || p > block || p > data.len() {
        return Err("invalid PKCS#7 padding".into());
    }
    if data[data.len() - p..].iter().any(|&b| b as usize != p) {
        return Err("invalid PKCS#7 padding bytes".into());
    }
    Ok(data[..data.len() - p].to_vec())
}

/// Decompress a SEC1 compressed point (`0x02`/`0x03 ‖ X`) to uncompressed
/// (`0x04 ‖ X ‖ Y`). Pure Rust — no private key involved. Accepts an
/// already-uncompressed point unchanged.
pub fn decompress_point(curve: Curve, point: &[u8]) -> Result<Vec<u8>, String> {
    match curve {
        Curve::NistP256 => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let ep = p256::EncodedPoint::from_bytes(point)
                .map_err(|e| format!("p256 point decode: {e}"))?;
            let pk = Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&ep))
                .ok_or("p256 point not on curve")?;
            Ok(pk.to_encoded_point(false).as_bytes().to_vec())
        }
        Curve::NistP384 => {
            use p384::elliptic_curve::sec1::ToEncodedPoint;
            let ep = p384::EncodedPoint::from_bytes(point)
                .map_err(|e| format!("p384 point decode: {e}"))?;
            let pk = Option::<p384::PublicKey>::from(p384::PublicKey::from_encoded_point(&ep))
                .ok_or("p384 point not on curve")?;
            Ok(pk.to_encoded_point(false).as_bytes().to_vec())
        }
    }
}

use p256::elliptic_curve::sec1::FromEncodedPoint;

// p384 reuses the same trait import path; bring it in under an alias-free
// `use` inside the function above via fully-qualified calls. (Both crates
// re-export `elliptic_curve`.)
#[allow(unused_imports)]
use p384::elliptic_curve::sec1::FromEncodedPoint as _;

/// **Test/spike only — stands in for the PIV card.** Given the recipient
/// private scalar (field-size big-endian) and the ephemeral public point,
/// compute the ECDH shared secret `Z` exactly as the card's
/// `GENERAL AUTHENTICATE` would. In production this never runs in the
/// browser — the private scalar lives only on the card.
pub fn simulate_card_ecdh(
    curve: Curve,
    recipient_scalar: &[u8],
    ephemeral_pub_uncompressed: &[u8],
) -> Result<Vec<u8>, String> {
    match curve {
        Curve::NistP256 => {
            let sk = p256::SecretKey::from_slice(recipient_scalar)
                .map_err(|e| format!("p256 scalar: {e}"))?;
            let ep = p256::EncodedPoint::from_bytes(ephemeral_pub_uncompressed)
                .map_err(|e| format!("p256 ephem decode: {e}"))?;
            let pk = Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&ep))
                .ok_or("p256 ephem not on curve")?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        Curve::NistP384 => {
            let sk = p384::SecretKey::from_slice(recipient_scalar)
                .map_err(|e| format!("p384 scalar: {e}"))?;
            let ep = p384::EncodedPoint::from_bytes(ephemeral_pub_uncompressed)
                .map_err(|e| format!("p384 ephem decode: {e}"))?;
            let pk = Option::<p384::PublicKey>::from(p384::PublicKey::from_encoded_point(&ep))
                .ok_or("p384 ephem not on curve")?;
            let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
    }
}
