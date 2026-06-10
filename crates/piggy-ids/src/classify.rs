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

/// Everything the classifiers need to know about one slot, grouped by
/// domain: identity (`slot_id`, `guid`, `reader`, `serial`), crypto
/// material (`algo`, `cert_der`), and YubicoPIV policies (`pin_policy`,
/// `touch_policy`). Field semantics match the like-named fields on
/// [`Classification`]; `cert_der` is the slot cert as read from the
/// card, borrowed for the duration of the call. Replaces the former
/// 8-positional-argument signatures (#118).
#[derive(Debug)]
pub struct ClassifyInput<'a> {
    pub slot_id: u8,
    pub guid: Guid,
    pub reader: String,
    pub serial: Option<u32>,
    pub algo: PivAlgorithm,
    pub cert_der: &'a [u8],
    pub pin_policy: Option<PinPolicy>,
    pub touch_policy: Option<TouchPolicy>,
}

impl ClassifyInput<'_> {
    /// Consume the input into a `Supported` record. Keeps the
    /// 7-field threading at one site instead of repeating it in every
    /// classifier branch.
    fn supported(self, id: MarklId, cn: Option<String>) -> Classification {
        Classification::Supported {
            id,
            guid: self.guid,
            reader: self.reader,
            serial: self.serial,
            slot_id: self.slot_id,
            cn,
            pin_policy: self.pin_policy,
            touch_policy: self.touch_policy,
        }
    }

    /// Consume the input into an `Unsupported` record. Sibling of
    /// [`ClassifyInput::supported`].
    fn unsupported(self, cn: Option<String>, reason: String) -> Classification {
        Classification::Unsupported {
            guid: self.guid,
            reader: self.reader,
            serial: self.serial,
            slot_id: self.slot_id,
            cn,
            pin_policy: self.pin_policy,
            touch_policy: self.touch_policy,
            reason,
        }
    }
}

/// Classify the given slot. Convenience wrapper for the common
/// slot-9D case. The 9D-only caller paths in `detect-pubkey` and
/// `detect-all-pubkeys` don't surface policies, so this wrapper passes
/// `None` for both.
pub fn classify_slot_9d(
    guid: Guid,
    reader: String,
    serial: Option<u32>,
    algo: PivAlgorithm,
    cert_der: &[u8],
) -> Classification {
    classify_slot(ClassifyInput {
        slot_id: 0x9D,
        guid,
        reader,
        serial,
        algo,
        cert_der,
        pin_policy: None,
        touch_policy: None,
    })
}

pub fn classify_slot(input: ClassifyInput) -> Classification {
    let cn = extract_subject_cn(input.cert_der);
    if input.algo != PivAlgorithm::EcP256 {
        let reason = format!("slot {} is {:?}", format_slot_id(input.slot_id), input.algo);
        return input.unsupported(cn, reason);
    }
    let format = FormatId::PivyEcdhP256Pub;
    let compressed = match compress_ec_pubkey(input.cert_der, format.size()) {
        Ok(c) => c,
        Err(e) => return input.unsupported(cn, format!("pubkey decode failed: {e}")),
    };
    // `MarklId::new` cannot fail under the current invariants:
    // `compress_ec_pubkey` enforced the format's payload length above
    // and the `PivyEcdhP256Pub` format is fixed-size. The `Err` arm is
    // kept as a defensive net so that any future change to
    // `PurposeId`/`FormatId` compatibility rules, or to the
    // compressed-point length contract, surfaces as a user-visible
    // classification rather than a panic in a code path that should
    // never abort.
    match MarklId::new(Some(PurposeId::PiggyRecipientV1), format, compressed) {
        Ok(id) => input.supported(id, cn),
        Err(e) => input.unsupported(cn, format!("markl ID build failed: {e}")),
    }
}

/// Classify a non-recipient PIV slot (9A authentication, 9C digital
/// signature, 9E card authentication) as a signing/SSH-style key.
///
/// Each of these slots gets a distinct markl purpose mirroring its
/// NIST 800-73 slot semantics — `piggy-piv_auth-v1`, `piggy-piv_sig-v1`,
/// or `piggy-piv_card_auth-v1` — so a downstream tool seeing the
/// markl ID can immediately tell what the key is meant for without
/// needing to know which slot id it came from. The payload format
/// depends on the slot's algorithm: `ssh_ecdsa_nistp256_pub` (33-byte
/// SEC1-compressed P-256 point) for ECDSA P-256,
/// `ssh_ecdsa_nistp384_pub` (49 bytes, same shape one curve up) for
/// ECDSA P-384, `ssh_ed25519_pub` (32-byte raw key) for Ed25519 (#86).
///
/// RSA in these slots is reported as `Unsupported` until the markl
/// registry grows a variable-length format ID (#86 step 3).
pub fn classify_ssh_slot(input: ClassifyInput) -> Classification {
    let cn = extract_subject_cn(input.cert_der);

    let purpose = match purpose_for_ssh_slot(input.slot_id) {
        Some(p) => p,
        None => {
            let reason = format!(
                "slot {} is not an SSH-style PIV slot (expected 9A/9C/9E)",
                format_slot_id(input.slot_id),
            );
            return input.unsupported(cn, reason);
        }
    };

    let format = match input.algo {
        PivAlgorithm::EcP256 => FormatId::SshEcdsaNistp256Pub,
        PivAlgorithm::EcP384 => FormatId::SshEcdsaNistp384Pub,
        PivAlgorithm::Ed25519 => FormatId::SshEd25519Pub,
        other => {
            let reason = format!(
                "slot {} is {other:?}; only EcP256, EcP384, and Ed25519 have markl formats (#86)",
                format_slot_id(input.slot_id),
            );
            return input.unsupported(cn, reason);
        }
    };

    let payload = match format {
        FormatId::SshEd25519Pub => raw_ed25519_pubkey(input.cert_der),
        ec => compress_ec_pubkey(input.cert_der, ec.size()),
    };
    let payload = match payload {
        Ok(p) => p,
        Err(e) => return input.unsupported(cn, format!("pubkey decode failed: {e}")),
    };

    match MarklId::new(Some(purpose), format, payload) {
        Ok(id) => input.supported(id, cn),
        Err(e) => input.unsupported(cn, format!("markl ID build failed: {e}")),
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

/// Extract the raw 32-byte Ed25519 public key from a DER-encoded X.509
/// cert. RFC 8410 stores Ed25519 SPKI keys as the raw point with no
/// inner DER structure, which is exactly the `ssh_ed25519_pub` markl
/// payload — no compression step needed. The extraction itself lives
/// in `piggy_piv::cert` (shared with `extract_public_key`).
fn raw_ed25519_pubkey(cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cert = openssl::x509::X509::from_der(cert_der)?;
    let pubkey = cert.public_key()?;
    Ok(piggy_piv::cert::raw_ed25519_from_spki(&pubkey)?.to_vec())
}

/// Compress the EC public point from a DER-encoded X.509 cert and
/// require the SEC1-compressed form to be exactly `expected_len`
/// bytes (33 for P-256, 49 for P-384). The length check doubles as a
/// curve check: a cert whose curve disagrees with the slot's declared
/// algorithm compresses to the wrong length and classifies Unsupported
/// instead of mis-building a markl ID.
fn compress_ec_pubkey(
    cert_der: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    if compressed.len() != expected_len {
        return Err(format!(
            "expected {expected_len}-byte compressed EC point, got {}",
            compressed.len()
        )
        .into());
    }
    Ok(compressed)
}

/// Render a markl ID's SSH pubkey as the `<keytype> <base64-blob>`
/// prefix of an OpenSSH `authorized_keys` line. The caller appends any
/// trailing comment. Dispatches on the ID's format:
/// `ssh_ecdsa_nistp256_pub` / `ssh_ecdsa_nistp384_pub` (SEC1-compressed
/// points, decompressed via openssl) render as `ecdsa-sha2-nistpNNN`;
/// `ssh_ed25519_pub` (raw 32-byte key, already the wire payload)
/// renders as `ssh-ed25519`. Any other format is an `Err` — it has no
/// OpenSSH wire form.
///
/// Blob framing goes through `piggy_box::agent_ext`, so byte-for-byte
/// output matches what `ssh-key`'s `PublicKey::to_bytes` would produce
/// for the same key — verified by the parity tests in
/// `agent_ext::tests`. Returns `Err` (rather than panicking) when an EC
/// payload is not a valid on-curve point, so callers can suppress
/// malformed entries.
///
/// This is the shared renderer behind both `piggy list --format=ssh`
/// (live-card enumeration) and `piggy ssh-copy-id` (offline, from the
/// markl IDs in a `piggy-ids` file).
pub fn openssh_authorized_key(id: &MarklId) -> Result<String, String> {
    use piggy_box::piv_box::EcCurve;

    match id.format() {
        FormatId::SshEcdsaNistp256Pub => {
            openssh_line_from_compressed_ec(id.data(), EcCurve::NistP256)
        }
        FormatId::SshEcdsaNistp384Pub => {
            openssh_line_from_compressed_ec(id.data(), EcCurve::NistP384)
        }
        FormatId::SshEd25519Pub => Ok(openssh_line_from_ed25519(id.data())),
        other => Err(format!("{other} has no OpenSSH wire form")),
    }
}

/// Decompress a SEC1-compressed EC point (33 bytes for P-256, 49 for
/// P-384) and render the `ecdsa-sha2-nistpNNN <base64-blob>` line
/// prefix.
fn openssh_line_from_compressed_ec(
    compressed: &[u8],
    curve: piggy_box::piv_box::EcCurve,
) -> Result<String, String> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint, PointConversionForm};
    use piggy_box::agent_ext::ec_point_to_ssh_pubkey_blob;

    let group = EcGroup::from_curve_name(curve.nid()).map_err(|e| e.to_string())?;
    let mut ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    let point = EcPoint::from_bytes(&group, compressed, &mut ctx).map_err(|e| e.to_string())?;
    let uncompressed = point
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| e.to_string())?;
    let blob = ec_point_to_ssh_pubkey_blob(curve, &uncompressed);
    let b64 = openssl::base64::encode_block(&blob);
    Ok(format!("{} {b64}", curve.ssh_keytype()))
}

/// Render the `ssh-ed25519 <base64-blob>` line prefix from a raw
/// 32-byte Ed25519 key. Infallible because the markl payload is already
/// the exact wire form — no decompression step.
fn openssh_line_from_ed25519(key: &[u8]) -> String {
    use piggy_box::agent_ext::ed25519_to_ssh_pubkey_blob;

    let blob = ed25519_to_ssh_pubkey_blob(key);
    let b64 = openssl::base64::encode_block(&blob);
    format!("ssh-ed25519 {b64}")
}
