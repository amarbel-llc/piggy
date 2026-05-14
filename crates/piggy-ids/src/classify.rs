//! Classify a PIV slot as supported (P-256 ECDH, the only algorithm
//! piggy 2.x can encrypt to) or unsupported (anything else, including
//! a malformed cert in a slot the card *claims* is EcP256).
//!
//! Pure function; no PCSC, no I/O. Callers feed it the GUID + slot
//! metadata they already read from `PivContext::enumerate_tokens()` and
//! `token.read_slot(slot_id)`. The classifier is slot-agnostic — slot
//! 9D (key management) is the conventional recipient slot, but retired
//! key-management slots 0x82..=0x95 are equally valid recipient targets
//! when populated with P-256 keys.

use piggy_markl::{FormatId, Id as MarklId, PurposeId};
use piggy_piv::{Guid, PinPolicy, PivAlgorithm, TouchPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Supported {
        id: MarklId,
        guid: Guid,
        reader: String,
        /// YubiKey factory serial when the card is a YubiKey v5+ with
        /// the vendor `INS_GET_SERIAL` extension. `None` for every
        /// other PIV card. Populated upstream by `PivToken::yk_serial`.
        serial: Option<u32>,
        /// PIV slot id (e.g. 0x9D for key management, 0x82..=0x95 for
        /// retired key management).
        slot_id: u8,
        /// Subject Common Name from the slot's self-signed cert (the
        /// `-n` value passed to `pivy-tool generate`). `None` when the
        /// cert lacks a CN or fails to parse.
        cn: Option<String>,
        /// YubicoPIV PIN policy (the `-i` value passed to
        /// `pivy-tool generate`). `None` when the card doesn't support
        /// attestation (non-YubiKey, F9 cleared) or attestation parsing
        /// failed.
        pin_policy: Option<PinPolicy>,
        /// YubicoPIV touch policy (the `-t` value passed to
        /// `pivy-tool generate`). Same `None` semantics as
        /// `pin_policy`.
        touch_policy: Option<TouchPolicy>,
    },
    Unsupported {
        guid: Guid,
        reader: String,
        serial: Option<u32>,
        slot_id: u8,
        /// Subject Common Name from the slot's self-signed cert. Useful
        /// for identifying RSA-bearing retired slots even though they
        /// can't act as recipients. `None` when the cert lacks a CN or
        /// fails to parse.
        cn: Option<String>,
        /// YubicoPIV PIN policy. Same `None` semantics as the
        /// `Supported` variant — populated when attestation succeeds.
        pin_policy: Option<PinPolicy>,
        /// YubicoPIV touch policy. Same `None` semantics as the
        /// `Supported` variant.
        touch_policy: Option<TouchPolicy>,
        reason: String,
    },
}

impl Classification {
    pub fn guid(&self) -> &Guid {
        match self {
            Classification::Supported { guid, .. } => guid,
            Classification::Unsupported { guid, .. } => guid,
        }
    }

    pub fn reader(&self) -> &str {
        match self {
            Classification::Supported { reader, .. } => reader,
            Classification::Unsupported { reader, .. } => reader,
        }
    }

    pub fn serial(&self) -> Option<u32> {
        match self {
            Classification::Supported { serial, .. } => *serial,
            Classification::Unsupported { serial, .. } => *serial,
        }
    }

    pub fn slot_id(&self) -> u8 {
        match self {
            Classification::Supported { slot_id, .. } => *slot_id,
            Classification::Unsupported { slot_id, .. } => *slot_id,
        }
    }

    pub fn cn(&self) -> Option<&str> {
        match self {
            Classification::Supported { cn, .. } => cn.as_deref(),
            Classification::Unsupported { cn, .. } => cn.as_deref(),
        }
    }

    pub fn pin_policy(&self) -> Option<PinPolicy> {
        match self {
            Classification::Supported { pin_policy, .. } => *pin_policy,
            Classification::Unsupported { pin_policy, .. } => *pin_policy,
        }
    }

    pub fn touch_policy(&self) -> Option<TouchPolicy> {
        match self {
            Classification::Supported { touch_policy, .. } => *touch_policy,
            Classification::Unsupported { touch_policy, .. } => *touch_policy,
        }
    }
}

/// Classify the given slot. Convenience wrapper for the common
/// `classify_slot(0x9D, ...)` case. The 9D-only caller paths in
/// `detect-pubkey` and `detect-all-pubkeys` don't surface policies, so
/// this wrapper passes `None` for both.
pub fn classify_slot_9d(
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
) -> Classification {
    classify_slot(0x9D, guid, reader, serial, algo, cert_der, None, None)
}

pub fn classify_slot(
    slot_id: u8,
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
) -> Classification {
    let cn = extract_subject_cn(cert_der);
    if algo != PivAlgorithm::EcP256 {
        return Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            reason: format!("slot {} is {algo:?}", format_slot_id(slot_id)),
        };
    }
    let compressed = match compress_p256_pubkey(cert_der) {
        Ok(c) => c,
        Err(e) => {
            return Classification::Unsupported {
                guid,
                reader,
                serial,
                slot_id,
                cn,
                pin_policy,
                touch_policy,
                reason: format!("pubkey decode failed: {e}"),
            };
        }
    };
    // `MarklId::new` cannot fail under the current invariants:
    // `compress_p256_pubkey` enforced the 33-byte length above and the
    // `PivyEcdhP256Pub` format is fixed-size. The `Err` arm is kept as a
    // defensive net so that any future change to `PurposeId`/`FormatId`
    // compatibility rules, or to the compressed-point length contract,
    // surfaces as a user-visible classification rather than a panic in
    // a code path that should never abort.
    match MarklId::new(
        Some(PurposeId::PiggyRecipientV1),
        FormatId::PivyEcdhP256Pub,
        compressed,
    ) {
        Ok(id) => Classification::Supported {
            id,
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
        },
        Err(e) => Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            reason: format!("markl ID build failed: {e}"),
        },
    }
}

/// Classify a non-recipient PIV slot (9A authentication, 9C digital
/// signature, 9E card authentication) as a signing/SSH-style key.
///
/// Each of these slots gets a distinct markl purpose mirroring its
/// NIST 800-73 slot semantics — `piggy-piv_auth-v1`, `piggy-piv_sig-v1`,
/// or `piggy-piv_card_auth-v1` — so a downstream tool seeing the
/// markl ID can immediately tell what the key is meant for without
/// needing to know which slot id it came from. The payload format is
/// `ssh_ecdsa_nistp256_pub` (33-byte SEC1-compressed P-256 point).
///
/// Only ECDSA P-256 is supported in v1; RSA, P-384, and Ed25519 in
/// these slots are reported as `Unsupported` until the markl registry
/// grows compatible format IDs.
pub fn classify_ssh_slot(
    slot_id: u8,
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
) -> Classification {
    let cn = extract_subject_cn(cert_der);

    let purpose = match purpose_for_ssh_slot(slot_id) {
        Some(p) => p,
        None => {
            return Classification::Unsupported {
                guid,
                reader,
                serial,
                slot_id,
                cn,
                pin_policy,
                touch_policy,
                reason: format!(
                    "slot {} is not an SSH-style PIV slot (expected 9A/9C/9E)",
                    format_slot_id(slot_id),
                ),
            };
        }
    };

    if algo != PivAlgorithm::EcP256 {
        return Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            reason: format!(
                "slot {} is {algo:?}; only EcP256 has a markl format in v1",
                format_slot_id(slot_id),
            ),
        };
    }

    let compressed = match compress_p256_pubkey(cert_der) {
        Ok(c) => c,
        Err(e) => {
            return Classification::Unsupported {
                guid,
                reader,
                serial,
                slot_id,
                cn,
                pin_policy,
                touch_policy,
                reason: format!("pubkey decode failed: {e}"),
            };
        }
    };

    match MarklId::new(Some(purpose), FormatId::SshEcdsaNistp256Pub, compressed) {
        Ok(id) => Classification::Supported {
            id,
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
        },
        Err(e) => Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            reason: format!("markl ID build failed: {e}"),
        },
    }
}

fn purpose_for_ssh_slot(slot_id: u8) -> Option<PurposeId> {
    match slot_id {
        0x9A => Some(PurposeId::PiggyPivAuthV1),
        0x9C => Some(PurposeId::PiggyPivSigV1),
        0x9E => Some(PurposeId::PiggyPivCardAuthV1),
        _ => None,
    }
}

/// Format a slot id as the conventional uppercase 2-digit hex (e.g.
/// `9D`, `82`). No `0x` prefix — matches the convention used by
/// `pivy-tool list` and `piggy tool list`.
pub fn format_slot_id(slot_id: u8) -> String {
    format!("{:02X}", slot_id)
}

/// Extract the first Subject Common Name from a DER-encoded X.509 cert.
/// Returns `None` if the cert fails to parse, has no Subject, has no CN
/// entry, or the CN bytes are not valid UTF-8. The `-n` argument to
/// `pivy-tool generate` ends up in this field.
fn extract_subject_cn(cert_der: &[u8]) -> Option<String> {
    let cert = openssl::x509::X509::from_der(cert_der).ok()?;
    let entry = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()?;
    entry.data().as_utf8().ok().map(|s| s.to_string())
}

fn compress_p256_pubkey(cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cert = openssl::x509::X509::from_der(cert_der)?;
    let pubkey = cert.public_key()?;
    let ec = pubkey.ec_key()?;
    let group = ec.group();
    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    let compressed = ec.public_key().to_bytes(
        group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut bn_ctx,
    )?;
    if compressed.len() != 33 {
        return Err(format!(
            "expected 33-byte compressed P-256 point, got {}",
            compressed.len()
        )
        .into());
    }
    Ok(compressed)
}
