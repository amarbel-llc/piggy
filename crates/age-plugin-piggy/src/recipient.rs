//! A piggy age recipient: a compressed P-256 public key (`age1piggy1…`).
//!
//! age decodes the Bech32 recipient and hands us the raw key bytes via
//! `add_recipient(_, plugin_name, bytes)`, so this type never parses Bech32
//! itself — it only validates and holds the 33-byte compressed point.

use age_core::format::{FileKey, Stanza};

use crate::PLUGIN_NAME;
use crate::p256_stanza::{self, COMPRESSED_BYTES};

#[derive(Debug, Clone)]
pub(crate) struct Recipient {
    compressed: [u8; COMPRESSED_BYTES],
}

impl Recipient {
    /// Parse the bytes age handed us, rejecting other plugins' recipients.
    pub(crate) fn from_bytes(plugin_name: &str, bytes: &[u8]) -> Option<Self> {
        if plugin_name != PLUGIN_NAME {
            return None;
        }
        let compressed: [u8; COMPRESSED_BYTES] = bytes.try_into().ok()?;
        p256_stanza::validate_compressed(&compressed)?;
        Some(Recipient { compressed })
    }

    /// Build directly from a validated compressed key (used when an identity
    /// is supplied to the recipient phase — its pubkey *is* a recipient).
    pub(crate) fn from_compressed(compressed: [u8; COMPRESSED_BYTES]) -> Self {
        Recipient { compressed }
    }

    /// Encrypt `file_key` to this recipient as a `piv-p256` stanza.
    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> Stanza {
        p256_stanza::wrap_file_key(&self.compressed, file_key).into()
    }
}
