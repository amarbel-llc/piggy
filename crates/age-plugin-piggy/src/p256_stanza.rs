//! The `piv-p256` age stanza: P-256 ECDH → HKDF-SHA256 → ChaCha20-Poly1305.
//!
//! Wire-shaped after str4d's `age-plugin-yubikey` so output is a valid age
//! file. The one piggy difference is the decrypt path: instead of a local
//! PCSC scalar-mult, [`unwrap_file_key`] delegates the ECDH to an
//! [`EcdhOracle`] (in practice piggy's `AgentEcdhOracle`, i.e. piggy-agent
//! over `ecdh@joyent.com`). The card does `recipient_secret · epk`; this
//! module never sees a private scalar.
//!
//! Encrypt and decrypt derive the AEAD key identically:
//!   salt   = epk_compressed || pk_compressed
//!   ikm    = ECDH shared-secret X-coordinate (32 bytes)
//!   enc_key = HKDF-SHA256(salt, info=b"piv-p256", ikm) → 32 bytes
//! On encrypt the X-coordinate comes from `esk.diffie_hellman(pk)`; on
//! decrypt it comes from `oracle.ecdh(...)`. Both are the same point, so
//! the keys agree — that equality is pinned by the unit tests.

use age_core::{
    format::{FILE_KEY_BYTES, FileKey, Stanza},
    primitives::{aead_decrypt, aead_encrypt, hkdf},
    secrecy::{ExposeSecret, zeroize::Zeroize},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use p256::{
    EncodedPoint, PublicKey,
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use piggy_box::agent_ext::ec_point_to_ssh_pubkey_blob;
use piggy_box::oracle::{EcdhOracle, OracleError};
use piggy_box::piv_box::EcCurve;

/// The age stanza tag for piggy/yubikey P-256 PIV recipients.
pub(crate) const STANZA_TAG: &str = "piv-p256";
/// HKDF `info` label. Must match the encrypt side; shared with yubikey.
const STANZA_KEY_LABEL: &[u8] = b"piv-p256";

/// Recipient-tag length: the first 4 bytes of SHA-256(pubkey).
pub(crate) const TAG_BYTES: usize = 4;
/// Compressed SEC1 P-256 point length (`0x02|0x03 || X`).
pub(crate) const COMPRESSED_BYTES: usize = 33;
/// Ephemeral public key length in a stanza (compressed).
const EPK_BYTES: usize = COMPRESSED_BYTES;
/// `aead_encrypt(16-byte file key)` = 16 + 16-byte Poly1305 tag.
const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// Errors from [`unwrap_file_key`].
#[derive(Debug)]
pub(crate) enum UnwrapError {
    /// A stored/stanza public key failed to parse as a P-256 point.
    BadKey,
    /// The ECDH oracle (agent/card) failed.
    Oracle(OracleError),
    /// AEAD authentication failed (wrong key / corrupt stanza).
    Decrypt,
}

impl std::fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnwrapError::BadKey => write!(f, "invalid P-256 public key"),
            UnwrapError::Oracle(e) => write!(f, "agent ECDH failed: {e}"),
            UnwrapError::Decrypt => write!(f, "stanza failed to decrypt"),
        }
    }
}

/// First [`TAG_BYTES`] of SHA-256 over the compressed recipient pubkey.
pub(crate) fn static_tag(pk_compressed: &[u8]) -> [u8; TAG_BYTES] {
    let digest = Sha256::digest(pk_compressed);
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&digest[..TAG_BYTES]);
    tag
}

/// `Some(())` iff `pk_compressed` is a valid *compressed* P-256 point.
pub(crate) fn validate_compressed(pk_compressed: &[u8; COMPRESSED_BYTES]) -> Option<()> {
    let encoded = EncodedPoint::from_bytes(pk_compressed).ok()?;
    if !encoded.is_compressed() {
        return None;
    }
    if bool::from(PublicKey::from_encoded_point(&encoded).is_some()) {
        Some(())
    } else {
        None
    }
}

/// Compressed SEC1 bytes → uncompressed SEC1 (`0x04 || X || Y`, 65 bytes).
fn uncompressed(pk_compressed: &[u8; COMPRESSED_BYTES]) -> Option<Vec<u8>> {
    let pk = PublicKey::from_sec1_bytes(pk_compressed).ok()?;
    Some(pk.to_encoded_point(false).as_bytes().to_vec())
}

fn salt(epk_compressed: &[u8], pk_compressed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(epk_compressed.len() + pk_compressed.len());
    out.extend_from_slice(epk_compressed);
    out.extend_from_slice(pk_compressed);
    out
}

fn decode_fixed<const N: usize>(arg: &str) -> Option<[u8; N]> {
    let bytes = BASE64_STANDARD_NO_PAD.decode(arg).ok()?;
    bytes.try_into().ok()
}

/// A parsed `piv-p256` stanza.
pub(crate) struct RecipientLine {
    pub(crate) tag: [u8; TAG_BYTES],
    epk_compressed: [u8; EPK_BYTES],
    encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl From<RecipientLine> for Stanza {
    fn from(line: RecipientLine) -> Self {
        Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(line.tag),
                BASE64_STANDARD_NO_PAD.encode(line.epk_compressed),
            ],
            body: line.encrypted_file_key.to_vec(),
        }
    }
}

impl RecipientLine {
    /// `None` → not a `piv-p256` stanza (let another plugin try).
    /// `Some(Err(()))` → ours, but structurally invalid.
    pub(crate) fn from_stanza(stanza: &Stanza) -> Option<Result<Self, ()>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let (tag, epk) = match &stanza.args[..] {
            [tag, epk] => (
                decode_fixed::<TAG_BYTES>(tag),
                decode_fixed::<EPK_BYTES>(epk),
            ),
            _ => (None, None),
        };
        let body: Option<[u8; ENCRYPTED_FILE_KEY_BYTES]> = stanza.body.as_slice().try_into().ok();

        Some(match (tag, epk, body) {
            (Some(tag), Some(epk_compressed), Some(encrypted_file_key)) => {
                if validate_compressed(&epk_compressed).is_none() {
                    return Some(Err(()));
                }
                Ok(RecipientLine {
                    tag,
                    epk_compressed,
                    encrypted_file_key,
                })
            }
            _ => Err(()),
        })
    }
}

/// Encrypt `file_key` to a recipient (compressed P-256 pubkey). Pure
/// software: a fresh ephemeral key, local ECDH, no card.
pub(crate) fn wrap_file_key(
    recipient_compressed: &[u8; COMPRESSED_BYTES],
    file_key: &FileKey,
) -> RecipientLine {
    let recipient_pub = PublicKey::from_sec1_bytes(recipient_compressed)
        .expect("recipient pubkey validated at construction");

    let esk = EphemeralSecret::random(&mut OsRng);
    let epk_point = esk.public_key().to_encoded_point(true);
    let mut epk_compressed = [0u8; EPK_BYTES];
    epk_compressed.copy_from_slice(epk_point.as_bytes());

    let shared = esk.diffie_hellman(&recipient_pub);
    let salt = salt(&epk_compressed, recipient_compressed);
    let enc_key = hkdf(
        &salt,
        STANZA_KEY_LABEL,
        shared.raw_secret_bytes().as_slice(),
    );

    let ciphertext = aead_encrypt(&enc_key, file_key.expose_secret());
    let mut encrypted_file_key = [0u8; ENCRYPTED_FILE_KEY_BYTES];
    encrypted_file_key.copy_from_slice(&ciphertext);

    RecipientLine {
        tag: static_tag(recipient_compressed),
        epk_compressed,
        encrypted_file_key,
    }
}

/// Decrypt a stanza, performing the ECDH via `oracle` (the card/agent).
///
/// `recipient_compressed` is the identity's own public key — it both names
/// the agent key to use (`self` side of the ECDH) and feeds the salt.
pub(crate) fn unwrap_file_key(
    line: &RecipientLine,
    recipient_compressed: &[u8; COMPRESSED_BYTES],
    oracle: &mut dyn EcdhOracle,
) -> Result<FileKey, UnwrapError> {
    let salt = salt(&line.epk_compressed, recipient_compressed);

    let self_point = uncompressed(recipient_compressed).ok_or(UnwrapError::BadKey)?;
    let partner_point = uncompressed(&line.epk_compressed).ok_or(UnwrapError::BadKey)?;
    let self_blob = ec_point_to_ssh_pubkey_blob(EcCurve::NistP256, &self_point);
    let partner_blob = ec_point_to_ssh_pubkey_blob(EcCurve::NistP256, &partner_point);

    let shared = oracle
        .ecdh(&self_blob, &partner_blob)
        .map_err(UnwrapError::Oracle)?;
    let enc_key = hkdf(&salt, STANZA_KEY_LABEL, &shared);

    let mut plaintext = aead_decrypt(&enc_key, FILE_KEY_BYTES, &line.encrypted_file_key)
        .map_err(|_| UnwrapError::Decrypt)?;
    let file_key = FileKey::init_with_mut(|fk| fk.copy_from_slice(&plaintext));
    plaintext.zeroize();
    Ok(file_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use piggy_box::agent_ext::extract_point_from_sshkey_blob;

    /// A software stand-in for piggy-agent: holds the recipient's *private*
    /// key and returns the ECDH X-coordinate — exactly the contract the real
    /// `ecdh@joyent.com` agent must satisfy (32 raw bytes).
    struct SoftOracle {
        secret: SecretKey,
    }

    impl EcdhOracle for SoftOracle {
        fn ecdh(&mut self, _self_blob: &[u8], partner_blob: &[u8]) -> Result<Vec<u8>, OracleError> {
            let point = extract_point_from_sshkey_blob(partner_blob)?;
            let partner = PublicKey::from_sec1_bytes(&point)
                .map_err(|e| OracleError::InvalidPubkey(e.to_string()))?;
            let shared =
                p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), partner.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
    }

    fn keypair() -> (SecretKey, [u8; COMPRESSED_BYTES]) {
        let secret = SecretKey::random(&mut OsRng);
        let point = secret.public_key().to_encoded_point(true);
        let mut compressed = [0u8; COMPRESSED_BYTES];
        compressed.copy_from_slice(point.as_bytes());
        (secret, compressed)
    }

    fn file_key(byte: u8) -> FileKey {
        FileKey::init_with_mut(|fk| fk.copy_from_slice(&[byte; FILE_KEY_BYTES]))
    }

    #[test]
    fn wrap_then_unwrap_recovers_file_key() {
        let (secret, pk) = keypair();
        let original = [0x5Au8; FILE_KEY_BYTES];
        let line = wrap_file_key(&pk, &file_key(0x5A));

        let mut oracle = SoftOracle { secret };
        let recovered = unwrap_file_key(&line, &pk, &mut oracle).expect("unwrap");
        assert_eq!(recovered.expose_secret(), &original);
    }

    /// The load-bearing assumption (plan decision #1): the oracle's bytes
    /// are the ECDH X-coordinate the encrypt side derives. If the real agent
    /// ever returned a full point or a different encoding, this is the shape
    /// the hardware lane would catch — here we pin it at the software level.
    #[test]
    fn oracle_output_equals_encrypt_side_shared_secret() {
        let (secret, pk) = keypair();
        let recipient_pub = PublicKey::from_sec1_bytes(&pk).unwrap();

        let esk = EphemeralSecret::random(&mut OsRng);
        let encrypt_ss = esk.diffie_hellman(&recipient_pub);

        let epk_uncompressed = esk.public_key().to_encoded_point(false);
        let partner_blob =
            ec_point_to_ssh_pubkey_blob(EcCurve::NistP256, epk_uncompressed.as_bytes());

        let mut oracle = SoftOracle { secret };
        let oracle_ss = oracle.ecdh(b"", &partner_blob).unwrap();

        assert_eq!(
            encrypt_ss.raw_secret_bytes().as_slice(),
            oracle_ss.as_slice()
        );
    }

    #[test]
    fn stanza_round_trips_and_tag_matches() {
        let (_secret, pk) = keypair();
        let line = wrap_file_key(&pk, &file_key(0x11));
        let stanza: Stanza = line.into();
        assert_eq!(stanza.tag, STANZA_TAG);

        let parsed = RecipientLine::from_stanza(&stanza)
            .expect("recognized as ours")
            .expect("structurally valid");
        assert_eq!(parsed.tag, static_tag(&pk));
    }

    #[test]
    fn foreign_tag_is_not_ours() {
        let stanza = Stanza {
            tag: "X25519".to_owned(),
            args: vec![],
            body: vec![],
        };
        assert!(RecipientLine::from_stanza(&stanza).is_none());
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let (_secret, pk) = keypair();
        let line = wrap_file_key(&pk, &file_key(0x22));
        // An unrelated keypair's secret must not unwrap.
        let (other_secret, _other_pk) = keypair();
        let mut oracle = SoftOracle {
            secret: other_secret,
        };
        // `FileKey` is secret and not `Debug`, so avoid `expect_err`.
        let result = unwrap_file_key(&line, &pk, &mut oracle);
        assert!(
            matches!(result, Err(UnwrapError::Decrypt)),
            "wrong key must fail AEAD authentication",
        );
    }

    /// End-to-end interop through the layers age actually drives: encode a
    /// recipient string, decode it the way age would, feed the bytes through
    /// the recipient plugin to wrap, serialize to a `Stanza`, then unwrap via
    /// the (mock) agent. Proves the Bech32 strings, stanza wire form, and
    /// crypto all line up — without needing the `age` binary on PATH.
    #[test]
    fn recipient_string_to_decrypt_round_trip() {
        use crate::bech32id::{decode_recipient, encode_recipient};
        use crate::recipient::Recipient;

        let (secret, pk) = keypair();

        let recipient_str = encode_recipient(&pk);
        let decoded = decode_recipient(&recipient_str).expect("recipient decodes");
        assert_eq!(decoded, pk);

        // The bytes age would hand `add_recipient`.
        let recipient = Recipient::from_bytes(crate::PLUGIN_NAME, &decoded).expect("recipient");
        let stanza = recipient.wrap_file_key(&file_key(0x33));

        let line = RecipientLine::from_stanza(&stanza)
            .expect("our stanza")
            .expect("valid");
        let mut oracle = SoftOracle { secret };
        let recovered = unwrap_file_key(&line, &pk, &mut oracle).expect("unwrap");
        assert_eq!(recovered.expose_secret(), &[0x33u8; FILE_KEY_BYTES]);
    }
}
