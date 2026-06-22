//! Core PIV byte-signing (piggy#190), shared by the `piggy sign-bytes` CLI
//! (the binary crate's `sign_bytes` module, a thin stdin/stdout wrapper) and
//! the `piggy manage` JSON-RPC `sign_bytes` method (piggy#201).
//!
//! [`sign_message`] is the neutral primitive: given a signing slot, an optional
//! card GUID, the exact message bytes, an output framing, and a PIN source
//! (a fixed PIN or a [`Frontend`] to prompt through), it signs the message
//! with the card's private key and returns the framed signature. piggy applies
//! NO canonicalization — SHA-256 (P-256) / SHA-384 (P-384) hashing is intrinsic
//! to `ecdsa-sha2-nistp256/384` and applied here before the card signs the
//! digest (matching `pivy-tool sign`). The private key never leaves the card;
//! `--guid` selection, the digest choice, and the raw-`r‖s` reframing all live
//! here so both callers behave identically.

use piggy_piv::{PivAlgorithm, PivContext, PivError, PivToken};
use sha2::{Digest, Sha256, Sha384};
use zeroize::Zeroizing;

use crate::card::protocol::{CardId, Frontend, FrontendError, SecretKind, SecretRequest};

/// Bounded re-prompt on a wrong interactive PIN (a fixed PIN never retries — it
/// can't change between attempts).
pub const PIN_RETRY_LIMIT: u32 = 2;

/// Output framing for a signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SigFormat {
    /// Fixed-width raw `r‖s` (P-256 → 64 bytes, P-384 → 96), the markl
    /// `…@ecdsa_p256_sig` payload a downstream consumer blech32-wraps directly.
    Raw,
    /// Card-native ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` (matches
    /// `pivy-tool sign`).
    Der,
}

/// Why a [`sign_message`] call failed. The decline case is kept distinct from
/// every other failure so a caller can map it to the protocol's
/// "interaction declined" code (RFC 0007 §6 `-32010`) rather than a generic
/// operation failure; the CLI renders either via `Display`.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The operator declined or cancelled the PIN prompt.
    #[error("interaction declined: {0}")]
    Declined(String),
    /// Any other failure (card selection, PIN-entry transport, verify, sign,
    /// reframing).
    #[error("{0}")]
    Failed(String),
}

/// Map a user-facing slot string to its PIV slot id. Only signing-capable
/// slots are accepted; 9D (Key Management / ECDH) is rejected explicitly.
pub fn parse_slot(s: &str) -> Result<u8, String> {
    match s.to_ascii_lowercase().as_str() {
        "9a" => Ok(0x9A),
        "9c" => Ok(0x9C),
        "9d" => Err(
            "slot 9d is the Key Management (ECDH) slot and cannot sign; use 9a or 9c".to_string(),
        ),
        other => Err(format!(
            "unsupported slot {other:?}; sign-bytes supports 9a (auth) and 9c (signature)"
        )),
    }
}

/// Sign `message` with the PIV signing slot named by `slot` (`"9a"`/`"9c"`) on
/// the selected card, returning the signature framed per `format`.
///
/// PIN source: `fixed_pin` short-circuits the prompt; otherwise `frontend`
/// MUST be `Some` and is used to request the PIN (with a bounded re-prompt on
/// a wrong interactive entry). The message bytes are signed verbatim (no
/// canonicalization); the digest algorithm follows the slot's key curve.
pub fn sign_message<F: Frontend + ?Sized>(
    slot: &str,
    guid: Option<&str>,
    message: &[u8],
    format: SigFormat,
    fixed_pin: Option<&str>,
    frontend: Option<&mut F>,
) -> Result<Vec<u8>, SignError> {
    let slot_id = parse_slot(slot).map_err(SignError::Failed)?;
    let mut token = select_token(guid).map_err(SignError::Failed)?;

    // Read the slot's algorithm (a PIN-free cert read) to choose the digest
    // and the raw field width.
    let slot_meta = token
        .read_slot(slot_id)
        .map_err(|e| SignError::Failed(format!("read slot {slot}: {e}")))?;

    let (digest, field_len) = match slot_meta.algorithm() {
        PivAlgorithm::EcP256 => (Sha256::digest(message).to_vec(), 32usize),
        PivAlgorithm::EcP384 => (Sha384::digest(message).to_vec(), 48usize),
        other => {
            return Err(SignError::Failed(format!(
                "slot {slot} holds a {other:?} key; sign-bytes supports only ECDSA P-256 / P-384"
            )));
        }
    };

    // Name the target card in the PIN prompt (piggy#195): GUID + serial + CN,
    // sourced from the selected card and its slot cert.
    let card_id = CardId {
        guid: token.guid().to_hex(),
        serial: token.yk_serial(),
        cn: slot_cn(slot_meta.cert_der()),
    };

    let der = sign_with_card(
        &mut token, slot_id, &digest, fixed_pin, &card_id, slot, frontend,
    )?;

    match format {
        SigFormat::Raw => crate::ecdsa_sig::der_to_raw_rs(&der, field_len)
            .map_err(|e| SignError::Failed(format!("reframe signature: {e}"))),
        SigFormat::Der => Ok(der),
    }
}

/// Extract the Subject Common Name from a slot's cert DER (e.g.
/// `piv-auth@2835305C`), for naming the card in the PIN prompt. `None` if the
/// cert doesn't parse or has no CN.
fn slot_cn(cert_der: &[u8]) -> Option<String> {
    let x509 = openssl::x509::X509::from_der(cert_der).ok()?;
    x509.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Enumerate attached PIV cards and pick one: by `--guid` if given, else the
/// sole attached card (error if zero or ambiguous).
fn select_token(guid_hint: Option<&str>) -> Result<PivToken, String> {
    let ctx = PivContext::new().map_err(|e| format!("PC/SC context: {e}"))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| format!("enumerate cards: {e}"))?;
    if tokens.is_empty() {
        return Err("no PIV card detected".to_string());
    }
    match guid_hint {
        Some(guid) => tokens
            .into_iter()
            .find(|t| t.guid().to_hex().eq_ignore_ascii_case(guid))
            .ok_or_else(|| format!("no attached card has GUID {guid}")),
        None => {
            if tokens.len() > 1 {
                let guids: Vec<String> = tokens.iter().map(|t| t.guid().to_hex()).collect();
                return Err(format!(
                    "{} cards attached; disambiguate with --guid <GUID> (attached: {})",
                    tokens.len(),
                    guids.join(", ")
                ));
            }
            Ok(tokens.into_iter().next().expect("non-empty checked above"))
        }
    }
}

/// Verify the PIN and sign `digest` in one PC/SC transaction, returning the
/// card's DER ECDSA signature. Re-prompts on a wrong interactive PIN (a fixed
/// PIN fails fast — it can't change between attempts). The PIN is acquired
/// OUTSIDE the card transaction (piggy#105) and verify+sign are bracketed
/// inside one session (piggy#56), mirroring the Rust agent.
fn sign_with_card<F: Frontend + ?Sized>(
    token: &mut PivToken,
    slot_id: u8,
    digest: &[u8],
    fixed_pin: Option<&str>,
    card: &CardId,
    slot_label: &str,
    mut frontend: Option<&mut F>,
) -> Result<Vec<u8>, SignError> {
    let mut attempt = 0u32;
    // Carried into the re-prompt so the operator sees how many tries remain
    // (None on the first prompt — no "tries left" clause).
    let mut attempts_remaining: Option<u32> = None;
    loop {
        let pin: Zeroizing<String> = match fixed_pin {
            Some(p) => Zeroizing::new(p.to_string()),
            None => {
                let fe = frontend
                    .as_mut()
                    .expect("frontend is provided when no fixed PIN is given");
                match fe.request_secret(SecretRequest {
                    kind: SecretKind::CurrentPin,
                    prompt: "Enter PIN".to_string(),
                    card: Some(card.clone()),
                    slot: Some(slot_label.to_string()),
                    attempts_remaining,
                    detail: None,
                }) {
                    Ok(p) => p,
                    // A decline is the one error worth distinguishing (RFC 0007
                    // §6 `-32010`); transport/protocol failures are generic.
                    Err(FrontendError::Declined(m)) => return Err(SignError::Declined(m)),
                    Err(e) => return Err(SignError::Failed(format!("PIN entry: {e}"))),
                }
            }
        };

        let mut session = token
            .begin_pin_session()
            .map_err(|e| SignError::Failed(format!("open card session: {e}")))?;

        match session.verify_pin(pin.as_str()) {
            Ok(()) => {}
            Err(PivError::PinIncorrect { retries }) => {
                if fixed_pin.is_some() || attempt >= PIN_RETRY_LIMIT {
                    return Err(SignError::Failed(format!(
                        "incorrect PIN ({retries} retries remaining)"
                    )));
                }
                attempt += 1;
                attempts_remaining = Some(retries);
                eprintln!("piggy sign-bytes: incorrect PIN, {retries} retries remaining");
                // `session` drops here, ending the transaction before we
                // re-prompt and re-open on the next iteration.
                continue;
            }
            Err(e) => return Err(SignError::Failed(format!("verify PIN: {e}"))),
        }

        return session
            .sign_prehash(slot_id, digest)
            .map_err(|e| SignError::Failed(format!("card sign: {e}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_slot_accepts_signing_slots_case_insensitive() {
        assert_eq!(parse_slot("9a").unwrap(), 0x9A);
        assert_eq!(parse_slot("9A").unwrap(), 0x9A);
        assert_eq!(parse_slot("9c").unwrap(), 0x9C);
        assert_eq!(parse_slot("9C").unwrap(), 0x9C);
    }

    #[test]
    fn parse_slot_rejects_9d_with_ecdh_hint() {
        let err = parse_slot("9d").unwrap_err();
        assert!(err.contains("9d"));
        assert!(err.contains("ECDH") || err.contains("cannot sign"));
    }

    #[test]
    fn parse_slot_rejects_unknown() {
        let err = parse_slot("9e").unwrap_err();
        assert!(err.contains("unsupported slot"));
    }
}
