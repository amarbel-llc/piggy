//! Classify a PIV card's slot 9D as supported (P-256 ECDH, the only
//! algorithm piggy 2.x can encrypt to) or unsupported (anything else,
//! including a malformed cert in a slot the card *claims* is EcP256).
//!
//! Pure function; no PCSC, no I/O. Callers feed it the GUID + slot
//! metadata they already read from `PivContext::enumerate_tokens()` and
//! `token.read_slot(0x9D)`.

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
    },
    Unsupported {
        guid: Guid,
        reader: String,
        serial: Option<u32>,
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
}

pub fn classify_slot_9d(
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
) -> Classification {
    if algo != PivAlgorithm::EcP256 {
        return Classification::Unsupported {
            guid,
            reader,
            serial,
            reason: format!("slot 9D is {algo:?}"),
        };
    }
    let compressed = match compress_p256_pubkey(cert_der) {
        Ok(c) => c,
        Err(e) => {
            return Classification::Unsupported {
                guid,
                reader,
                serial,
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
        },
        Err(e) => Classification::Unsupported {
            guid,
            reader,
            serial,
            reason: format!("markl ID build failed: {e}"),
        },
    }
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
