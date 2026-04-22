use std::sync::Arc;
use tokio::sync::Mutex;

use ssh_agent_lib::{
    agent::Session,
    error::AgentError,
    proto::{signature, Identity, SignRequest},
};
use ssh_key::{public::KeyData, Algorithm, Signature};

use pivy_piv::{Guid, PivAlgorithm, PivContext};

/// Cached key info from a PIV token (populated at startup)
#[derive(Clone)]
pub struct CachedKey {
    pub guid: Guid,
    pub reader_name: String,
    pub slot_id: u8,
    pub algorithm: PivAlgorithm,
    pub public_key: KeyData,
    pub comment: String,
}

#[derive(Clone)]
pub struct PivyAgent {
    keys: Arc<Mutex<Vec<CachedKey>>>,
    pin: Arc<Mutex<Option<String>>>,
}

impl PivyAgent {
    pub fn new(keys: Vec<CachedKey>) -> Self {
        Self {
            keys: Arc::new(Mutex::new(keys)),
            pin: Arc::new(Mutex::new(None)),
        }
    }

    pub fn pin_handle(&self) -> Arc<Mutex<Option<String>>> {
        self.pin.clone()
    }

    fn find_key(keys: &[CachedKey], pubkey: &KeyData) -> Option<CachedKey> {
        keys.iter().find(|k| k.public_key == *pubkey).cloned()
    }
}

#[ssh_agent_lib::async_trait]
impl Session for PivyAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.keys.lock().await;
        let identities = keys
            .iter()
            .map(|k| Identity {
                pubkey: k.public_key.clone(),
                comment: k.comment.clone(),
            })
            .collect();
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let keys = self.keys.lock().await;
        let key = Self::find_key(&keys, &request.pubkey)
            .ok_or_else(|| AgentError::Other("key not found".into()))?;
        drop(keys);

        // Reconnect to card for signing
        let ctx = PivContext::new().map_err(|e| AgentError::Other(e.to_string().into()))?;
        let tokens = ctx
            .enumerate_tokens()
            .map_err(|e| AgentError::Other(e.to_string().into()))?;
        let token = tokens
            .iter()
            .find(|t| t.guid() == &key.guid)
            .ok_or_else(|| AgentError::Other("PIV token no longer available".into()))?;

        // Verify PIN if needed (slot 9E doesn't require PIN)
        if key.slot_id != 0x9E {
            let pin_guard = self.pin.lock().await;
            let pin = pin_guard
                .as_ref()
                .ok_or_else(|| AgentError::Other("PIN required (use ssh-add -X)".into()))?;
            token
                .verify_pin(pin)
                .map_err(|e| AgentError::Other(e.to_string().into()))?;
        }

        // Prepare data for signing based on algorithm
        let sign_data = prepare_sign_data(key.algorithm, &request.data, request.flags)?;

        // Sign via card
        let sig_bytes = token
            .sign_prehash(key.slot_id, &sign_data)
            .map_err(|e| AgentError::Other(e.to_string().into()))?;

        // Convert raw signature bytes to ssh_key::Signature
        to_ssh_signature(key.algorithm, &sig_bytes, request.flags)
    }

    async fn lock(&mut self, _key: String) -> Result<(), AgentError> {
        let mut pin = self.pin.lock().await;
        *pin = None;
        Ok(())
    }

    async fn unlock(&mut self, key: String) -> Result<(), AgentError> {
        let mut pin = self.pin.lock().await;
        *pin = Some(key);
        Ok(())
    }
}

/// Hash data and prepare it for the PIV card's GENERAL AUTHENTICATE.
/// For ECDSA: returns the hash digest.
/// For RSA: returns PKCS#1 v1.5 DigestInfo padded to key size.
fn prepare_sign_data(alg: PivAlgorithm, data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    match alg {
        PivAlgorithm::EcP256 => {
            let hash = Sha256::digest(data);
            Ok(hash.to_vec())
        }
        PivAlgorithm::EcP384 => {
            let hash = Sha384::digest(data);
            Ok(hash.to_vec())
        }
        PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => {
            let key_size = match alg {
                PivAlgorithm::Rsa1024 => 128,
                PivAlgorithm::Rsa2048 => 256,
                _ => unreachable!(),
            };

            // Determine hash algorithm from SSH agent flags
            let (hash_bytes, digest_prefix) = if flags & signature::RSA_SHA2_512 != 0 {
                let hash = Sha512::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA512)
            } else if flags & signature::RSA_SHA2_256 != 0 {
                let hash = Sha256::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA256)
            } else {
                // Default to SHA-256 for modern SSH
                let hash = Sha256::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA256)
            };

            // Build PKCS#1 v1.5 DigestInfo + pad
            pkcs1_v15_pad(&hash_bytes, digest_prefix, key_size)
        }
        PivAlgorithm::Ed25519 => {
            // Ed25519 does its own hashing on card; pass raw data
            Ok(data.to_vec())
        }
    }
}

// DER-encoded DigestInfo AlgorithmIdentifier prefixes for PKCS#1 v1.5
// SHA-256: SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING }
const RSA_DIGEST_PREFIX_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

// SHA-512: SEQUENCE { SEQUENCE { OID sha512, NULL }, OCTET STRING }
const RSA_DIGEST_PREFIX_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40,
];

/// Build PKCS#1 v1.5 padded signing block:
/// 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
fn pkcs1_v15_pad(
    hash: &[u8],
    digest_prefix: &[u8],
    key_size: usize,
) -> Result<Vec<u8>, AgentError> {
    let digest_info_len = digest_prefix.len() + hash.len();
    if key_size < digest_info_len + 11 {
        return Err(AgentError::Other("key too small for digest".into()));
    }

    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x01;

    let pad_len = key_size - digest_info_len - 3;
    for byte in &mut padded[2..2 + pad_len] {
        *byte = 0xFF;
    }
    padded[2 + pad_len] = 0x00;

    let di_start = 3 + pad_len;
    padded[di_start..di_start + digest_prefix.len()].copy_from_slice(digest_prefix);
    padded[di_start + digest_prefix.len()..].copy_from_slice(hash);

    Ok(padded)
}

/// Convert raw card signature bytes to ssh_key::Signature.
fn to_ssh_signature(
    alg: PivAlgorithm,
    sig_bytes: &[u8],
    flags: u32,
) -> Result<Signature, AgentError> {
    match alg {
        PivAlgorithm::EcP256 => {
            let algo = Algorithm::new("ecdsa-sha2-nistp256").map_err(AgentError::other)?;
            // PIV card returns DER-encoded ECDSA signature
            // ssh_key expects the raw (r || s) encoding wrapped in the SSH format
            let (r, s) = decode_der_ecdsa_signature(sig_bytes)?;
            let ssh_sig = encode_ecdsa_ssh_signature(&r, &s);
            Signature::new(algo, ssh_sig).map_err(AgentError::other)
        }
        PivAlgorithm::EcP384 => {
            let algo = Algorithm::new("ecdsa-sha2-nistp384").map_err(AgentError::other)?;
            let (r, s) = decode_der_ecdsa_signature(sig_bytes)?;
            let ssh_sig = encode_ecdsa_ssh_signature(&r, &s);
            Signature::new(algo, ssh_sig).map_err(AgentError::other)
        }
        PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => {
            let algo_name = if flags & signature::RSA_SHA2_512 != 0 {
                "rsa-sha2-512"
            } else if flags & signature::RSA_SHA2_256 != 0 {
                "rsa-sha2-256"
            } else {
                "rsa-sha2-256"
            };
            let algo = Algorithm::new(algo_name).map_err(AgentError::other)?;
            Signature::new(algo, sig_bytes.to_vec()).map_err(AgentError::other)
        }
        PivAlgorithm::Ed25519 => {
            let algo = Algorithm::new("ssh-ed25519").map_err(AgentError::other)?;
            Signature::new(algo, sig_bytes.to_vec()).map_err(AgentError::other)
        }
    }
}

/// Decode a DER-encoded ECDSA signature into (r, s) as big-endian byte arrays.
/// DER format: SEQUENCE { INTEGER r, INTEGER s }
fn decode_der_ecdsa_signature(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AgentError> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err(AgentError::Other(
            "invalid DER ECDSA signature".into(),
        ));
    }

    let mut pos = 2; // skip SEQUENCE tag + length

    // Read r
    if der[pos] != 0x02 {
        return Err(AgentError::Other("expected INTEGER tag for r".into()));
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r = &der[pos..pos + r_len];
    pos += r_len;

    // Read s
    if der[pos] != 0x02 {
        return Err(AgentError::Other("expected INTEGER tag for s".into()));
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s = &der[pos..pos + s_len];

    Ok((r.to_vec(), s.to_vec()))
}

/// Encode (r, s) as SSH mpint-pair for ECDSA signature blob.
/// SSH ECDSA signature blob = string(r as mpint) || string(s as mpint)
fn encode_ecdsa_ssh_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // r as SSH mpint
    let r_len = r.len() as u32;
    buf.extend_from_slice(&r_len.to_be_bytes());
    buf.extend_from_slice(r);
    // s as SSH mpint
    let s_len = s.len() as u32;
    buf.extend_from_slice(&s_len.to_be_bytes());
    buf.extend_from_slice(s);
    buf
}
