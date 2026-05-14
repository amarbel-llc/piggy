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
use piggy_piv::{Guid, PivAlgorithm};

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
}

/// Classify the given slot. Convenience wrapper for the common
/// `classify_slot(0x9D, ...)` case.
pub fn classify_slot_9d(
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
) -> Classification {
    classify_slot(0x9D, guid, reader, serial, algo, cert_der)
}

pub fn classify_slot(
    slot_id: u8,
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
) -> Classification {
    let cn = extract_subject_cn(cert_der);
    if algo != PivAlgorithm::EcP256 {
        return Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
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
        },
        Err(e) => Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            reason: format!("markl ID build failed: {e}"),
        },
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
