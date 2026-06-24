//! pigpen-v1 crypto suite (RFC 0008 §4), pure-Rust / wasm-buildable.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

pub const FILE_KEY_LEN: usize = 16; // RFC 0008 §4.1
pub const PAYLOAD_NONCE_LEN: usize = 16; // RFC 0008 §4.5
pub const STREAM_CHUNK: usize = 64 * 1024;
pub const TAG_LEN: usize = 16;

const INFO_PAYLOAD: &[u8] = b"pigpen-v1 payload";
const INFO_HEADER: &[u8] = b"pigpen-v1 header";
const INFO_P256: &[u8] = b"pigpen-v1 piv-p256";
const INFO_X25519: &[u8] = b"pigpen-v1 x25519";

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 is a valid HKDF length");
    okm
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(key));
    aead.encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| Error::Crypto(format!("aead seal: {e}")))
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(key));
    aead.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| Error::Crypto(format!("aead open: {e}")))
}

const ZERO_NONCE: [u8; 12] = [0u8; 12];

pub fn random_file_key() -> [u8; FILE_KEY_LEN] {
    let mut fk = [0u8; FILE_KEY_LEN];
    OsRng.fill_bytes(&mut fk);
    fk
}

// --- X25519 wrap (RFC 0008 §4.4) ----------------------------------------

pub fn wrap_x25519(file_key: &[u8], recipient_pub: &[u8]) -> Result<Vec<u8>> {
    let rpub: [u8; 32] = recipient_pub
        .try_into()
        .map_err(|_| Error::Crypto("x25519 recipient pubkey must be 32 bytes".into()))?;
    let recipient = x25519_dalek::PublicKey::from(rpub);

    let esk = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let epk = x25519_dalek::PublicKey::from(&esk);
    let shared = esk.diffie_hellman(&recipient);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(epk.as_bytes());
    salt.extend_from_slice(&rpub);
    let kw = hkdf32(shared.as_bytes(), &salt, INFO_X25519);
    let ct = aead_seal(&kw, &ZERO_NONCE, file_key)?;

    let mut blob = Vec::with_capacity(32 + ct.len());
    blob.extend_from_slice(epk.as_bytes());
    blob.extend_from_slice(&ct);
    Ok(blob)
}

pub fn unwrap_x25519(blob: &[u8], recipient_pub: &[u8], recipient_sec: &[u8]) -> Result<Vec<u8>> {
    if blob.len() != 32 + FILE_KEY_LEN + TAG_LEN {
        return Err(Error::Crypto("bad x25519 wrap length".into()));
    }
    let (epk_b, ct) = blob.split_at(32);
    let epk: [u8; 32] = epk_b.try_into().unwrap();
    let sec: [u8; 32] = recipient_sec
        .try_into()
        .map_err(|_| Error::Crypto("x25519 secret must be 32 bytes".into()))?;

    let sk = x25519_dalek::StaticSecret::from(sec);
    let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(epk));

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&epk);
    salt.extend_from_slice(recipient_pub);
    let kw = hkdf32(shared.as_bytes(), &salt, INFO_X25519);
    aead_open(&kw, &ZERO_NONCE, ct)
}

// --- P-256 wrap (RFC 0008 §4.3) -----------------------------------------

pub fn wrap_p256(file_key: &[u8], recipient_compressed: &[u8]) -> Result<Vec<u8>> {
    let recipient = p256::PublicKey::from_sec1_bytes(recipient_compressed)
        .map_err(|e| Error::Crypto(format!("bad P-256 recipient: {e}")))?;

    let esk = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let epk = esk.public_key();
    let epk_compressed = epk.to_encoded_point(true);
    let shared = esk.diffie_hellman(&recipient);

    let mut salt = Vec::with_capacity(66);
    salt.extend_from_slice(epk_compressed.as_bytes());
    salt.extend_from_slice(recipient_compressed);
    let kw = hkdf32(shared.raw_secret_bytes(), &salt, INFO_P256);
    let ct = aead_seal(&kw, &ZERO_NONCE, file_key)?;

    let mut blob = Vec::with_capacity(33 + ct.len());
    blob.extend_from_slice(epk_compressed.as_bytes());
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Unwrap a P-256 stanza given the 32-byte ECDH X-coordinate the oracle
/// (the card) returns for `(slot-9D · epk)`.
pub fn unwrap_p256_with_shared(
    blob: &[u8],
    recipient_compressed: &[u8],
    shared_x: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() != 33 + FILE_KEY_LEN + TAG_LEN {
        return Err(Error::Crypto("bad p256 wrap length".into()));
    }
    let (epk_b, ct) = blob.split_at(33);
    let mut salt = Vec::with_capacity(66);
    salt.extend_from_slice(epk_b);
    salt.extend_from_slice(recipient_compressed);
    let kw = hkdf32(shared_x, &salt, INFO_P256);
    aead_open(&kw, &ZERO_NONCE, ct)
}

/// The compressed ephemeral pubkey carried in a P-256 wrap blob — the
/// `partner_epk` an [`crate::EcdhOracle`] needs.
pub fn p256_wrap_epk(blob: &[u8]) -> Result<&[u8]> {
    if blob.len() < 33 {
        return Err(Error::Crypto("p256 wrap too short".into()));
    }
    Ok(&blob[..33])
}

// --- Payload STREAM (RFC 0008 §4.5) -------------------------------------

pub fn seal_payload(file_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; PAYLOAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let stream_key = hkdf32(file_key, &nonce, INFO_PAYLOAD);
    let aead = ChaCha20Poly1305::new(Key::from_slice(&stream_key));

    let mut out = nonce.to_vec();
    let mut i = 0usize;
    loop {
        let start = i * STREAM_CHUNK;
        let end = (start + STREAM_CHUNK).min(plaintext.len());
        let last = end >= plaintext.len();
        let chunk = &plaintext[start..end];
        let ct = aead
            .encrypt(Nonce::from_slice(&stream_nonce(i as u64, last)), chunk)
            .map_err(|e| Error::Crypto(format!("payload seal: {e}")))?;
        out.extend_from_slice(&ct);
        if last {
            break;
        }
        i += 1;
    }
    Ok(out)
}

pub fn open_payload(file_key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < PAYLOAD_NONCE_LEN {
        return Err(Error::Crypto("payload shorter than nonce".into()));
    }
    let (nonce, body) = payload.split_at(PAYLOAD_NONCE_LEN);
    let stream_key = hkdf32(file_key, nonce, INFO_PAYLOAD);
    let aead = ChaCha20Poly1305::new(Key::from_slice(&stream_key));

    let enc_chunk = STREAM_CHUNK + TAG_LEN;
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let start = i * enc_chunk;
        if start >= body.len() {
            return Err(Error::Crypto("truncated payload (no final chunk)".into()));
        }
        let end = (start + enc_chunk).min(body.len());
        let last = end >= body.len();
        let chunk = &body[start..end];
        let plain = aead
            .decrypt(Nonce::from_slice(&stream_nonce(i as u64, last)), chunk)
            .map_err(|e| Error::Crypto(format!("payload chunk {i}: {e}")))?;
        out.extend_from_slice(&plain);
        if last {
            break;
        }
        i += 1;
    }
    Ok(out)
}

/// 12-byte age STREAM nonce: 11-byte big-endian counter + 1-byte last flag.
fn stream_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    if last {
        n[11] = 0x01;
    }
    n
}

// --- Header MAC (RFC 0008 §4.6) -----------------------------------------

pub fn header_mac(file_key: &[u8], canonical_header: &[u8]) -> [u8; 32] {
    let km = hkdf32(file_key, &[], INFO_HEADER);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&km).expect("hmac key");
    mac.update(canonical_header);
    mac.finalize().into_bytes().into()
}

pub fn verify_mac(file_key: &[u8], canonical_header: &[u8], expected: &[u8]) -> bool {
    let km = hkdf32(file_key, &[], INFO_HEADER);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&km).expect("hmac key");
    mac.update(canonical_header);
    mac.verify_slice(expected).is_ok()
}
