//! The card-held issuer every phase (ii) verb signs with (FDR 0007
//! "The issuance verbs", step 5): the card a profile's `[issuer]` names,
//! its CA slot, and one PIN-prompted signature per certificate.
//!
//! The key is trusted as the card's only once its attestation verifies:
//! signed by the card's F9 certificate, F9 chained to Yubico's PIV root,
//! the attested key equal to the slot's, PIN always and touch always
//! (the same checks `piggy tool attest-verify` makes, piggy#397). A slot
//! whose attestation fails any of them is "issuer key unavailable" (exit
//! 6), never signed with.
//!
//! The signature is made in-process on the local card through a
//! `PinSession` (design owner's ruling, 2026-11-19): the PIN comes from
//! piggy's askpass with the certificate's description as the prompt's
//! context, so the operator reads what the card is about to certify, and
//! the touch is announced the way the agent announces it. Not through an
//! agent sign request: RFC 0012 §2.7 has the agent refuse a TBSCertificate
//! on a CA slot for that very reason.

use std::fmt::Write as _;

use piggy_piv::{PinPolicy, PivAlgorithm, PivContext, PivError, PivToken, TouchPolicy};
use zeroize::Zeroizing;

use piggy::card_oracle::{notify_operator, run_askpass};
use piggy::cmd::tool::{AttestInputs, PointStatus, verify_attestation};

use super::{Exit, Failure, failure};

/// Wrong-PIN re-prompts before giving up, as `sign-bytes` allows.
const PIN_RETRY_LIMIT: u32 = piggy::sign_core::PIN_RETRY_LIMIT;

/// A card and the CA slot on it a profile names as its issuer.
pub(crate) struct CardSigner {
    token: PivToken,
    slot: u8,
    algorithm: PivAlgorithm,
    point: Vec<u8>,
    /// Set by [`Self::sign_digest`] when the card refused, so the verb can
    /// tell a declined PIN (exit 6) from a build failure (exit 1) after
    /// the builder has folded the error into a `PivError`.
    sign_failure: Option<Failure>,
}

impl CardSigner {
    /// Find the card `issuer` names (by its full GUID) and read the slot's
    /// key, from the slot certificate when there is one, else from the
    /// card's attestation of the slot (a freshly generated CA key holds no
    /// certificate until its root is written back).
    pub(crate) fn open(issuer: &piggy::ca_profile::Issuer) -> Result<Self, Failure> {
        let unavailable = failure(Exit::IssuerUnavailable);
        let (slot, guid) = match (&issuer.slot, &issuer.guid) {
            (Some(slot), Some(guid)) => (slot, guid),
            _ => {
                return Err(failure(Exit::Usage)(
                    "the profile's issuer is not a card slot (holder issuers are not offered yet)"
                        .into(),
                ));
            }
        };
        let slot = u8::from_str_radix(slot, 16)
            .map_err(|_| failure(Exit::Usage)(format!("issuer slot {slot:?} is not hex")))?;

        let ctx = PivContext::new().map_err(|e| unavailable(format!("PC/SC: {e}")))?;
        let tokens = ctx
            .enumerate_tokens()
            .map_err(|e| unavailable(format!("enumerate cards: {e}")))?;
        let mut seen = Vec::new();
        let mut matching = None;
        for token in tokens {
            if token.guid().to_hex().eq_ignore_ascii_case(guid) {
                matching = Some(token);
                break;
            }
            seen.push(token.guid().short_id());
        }
        let token = matching.ok_or_else(|| {
            let mut msg = format!("the issuer card {guid} is not attached");
            if !seen.is_empty() {
                let _ = write!(msg, " (attached: {})", seen.join(", "));
            }
            unavailable(msg)
        })?;

        // `sign` and `issue` will also want the slot's certificate (the
        // issuer certificate they build under); `root-cert` needs the key
        // alone.
        let (algorithm, point) = match token.read_slot(slot) {
            Ok(held) => {
                let point = piggy_piv::cert::ec_sec1_point(held.cert_der()).map_err(|e| {
                    unavailable(format!(
                        "slot {slot:02X} holds a certificate whose key is not EC: {e}"
                    ))
                })?;
                (held.algorithm(), point)
            }
            Err(_) => {
                let attestation = token.yk_attest(slot).map_err(|e| {
                    unavailable(format!(
                        "slot {slot:02X} holds no certificate and the card does not attest a key in it ({e})"
                    ))
                })?;
                let (algorithm, _) =
                    piggy_piv::cert::extract_public_key(&attestation).map_err(|e| {
                        unavailable(format!("slot {slot:02X}: unreadable attestation ({e})"))
                    })?;
                let point = piggy_piv::cert::ec_sec1_point(&attestation).map_err(|e| {
                    unavailable(format!("slot {slot:02X}: the attested key is not EC ({e})"))
                })?;
                (algorithm, point)
            }
        };
        if !matches!(algorithm, PivAlgorithm::EcP256 | PivAlgorithm::EcP384) {
            return Err(unavailable(format!(
                "slot {slot:02X} holds a {algorithm:?} key; a CA key is EC P-256 or P-384"
            )));
        }
        Ok(Self {
            token,
            slot,
            algorithm,
            point,
            sign_failure: None,
        })
    }

    pub(crate) fn slot(&self) -> u8 {
        self.slot
    }

    pub(crate) fn algorithm(&self) -> PivAlgorithm {
        self.algorithm
    }

    /// The key's SEC1 uncompressed point.
    pub(crate) fn pubkey_point(&self) -> &[u8] {
        &self.point
    }

    /// The card, as prompts name it: its short GUID.
    pub(crate) fn card_label(&self) -> String {
        self.token.guid().short_id()
    }

    /// Prove the key is the card's own before anything is signed with it:
    /// a fresh attestation signed by the card's F9 certificate, F9 chained
    /// to `root_pem` (the profile's `attestation_root`; `None` is the
    /// embedded Yubico root), the attested key equal to the slot's, PIN
    /// always and touch always. Any failing check is "issuer key
    /// unavailable", naming the checks that failed. A root other than the
    /// embedded one is announced on stderr with its subject and SHA-256
    /// fingerprint, so the operator sees which root judged the key.
    pub(crate) fn verify_on_card(&self, root_pem: Option<&[u8]>) -> Result<(), Failure> {
        let unavailable = failure(Exit::IssuerUnavailable);
        let slot = self.slot;
        if let Some(pem) = root_pem {
            let root = openssl::x509::X509::from_pem(pem)
                .map_err(|e| failure(Exit::Profile)(format!("attestation_root: {e}")))?;
            let fingerprint = root
                .digest(openssl::hash::MessageDigest::sha256())
                .map(|d| {
                    d.iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":")
                })
                .unwrap_or_else(|e| format!("(digest failed: {e})"));
            let subject = root
                .subject_name()
                .entries()
                .map(|e| {
                    format!(
                        "{}={}",
                        e.object().nid().short_name().unwrap_or("?"),
                        e.data()
                            .as_utf8()
                            .map(|s| s.to_string())
                            .unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "piggy ca: the attestation root is the profile's attestation_root, not the embedded Yubico root: subject {subject}, sha256 {fingerprint}"
            );
        }
        let attestation_der = self.token.yk_attest(slot).map_err(|e| {
            unavailable(format!(
                "the card will not attest slot {slot:02X} ({e}); only a key generated on the card signs certificates"
            ))
        })?;
        let f9_der = self
            .token
            .read_slot(0xF9)
            .map_err(|e| {
                unavailable(format!(
                    "cannot read the card's attestation certificate (slot F9): {e}"
                ))
            })?
            .cert_der()
            .to_vec();
        let points = verify_attestation(&AttestInputs {
            attestation_der: &attestation_der,
            f9_der: &f9_der,
            slot_point: Some(&self.point),
            root_pem,
            saved_pem: None,
            expect_pin: Some(PinPolicy::Always),
            expect_touch: Some(TouchPolicy::Always),
        });
        let failed: Vec<String> = points
            .iter()
            .filter(|p| matches!(p.status, PointStatus::Fail))
            .map(|p| {
                let why = p
                    .diags
                    .iter()
                    .find(|(k, _)| k == "error" || k == "expected")
                    .map(|(k, v)| format!(" ({k}: {v})"))
                    .unwrap_or_default();
                format!("{}{why}", p.name)
            })
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(unavailable(format!(
                "slot {slot:02X}'s key is not proven to be the card's: {}",
                failed.join("; ")
            )))
        }
    }

    /// Sign `digest` (the SHA-256 or SHA-384 the profile builders hand a
    /// signer) with the slot key, returning the card's DER ECDSA
    /// signature. One PIN prompt, re-asked on a wrong PIN up to the limit;
    /// `describing` is shown on the prompt so the operator reads what is
    /// being certified. The touch the slot's policy demands is announced
    /// once the card waits for it.
    pub(crate) fn sign_digest(
        &mut self,
        digest: &[u8],
        describing: &str,
    ) -> Result<Vec<u8>, PivError> {
        let card = self.card_label();
        let slot = self.slot;
        let alg = self.algorithm.to_byte();
        let prompt = format!("PIN for card {card} to sign the certificate");
        let context = format!("piggy ca: card {card} slot {slot:02X} signs {describing}");
        let mut attempt = 0u32;
        loop {
            let pin: Zeroizing<String> = match run_askpass(&prompt, Some(&context)) {
                Ok(pin) => pin,
                Err(e) => {
                    self.sign_failure = Some(failure(Exit::IssuerUnavailable)(format!(
                        "no PIN for card {card}: {e}"
                    )));
                    return Err(PivError::Other(e.to_string()));
                }
            };
            let mut session = self
                .token
                .begin_pin_session()
                .map_err(|e| PivError::Other(format!("open card session: {e}")))?;
            match session.verify_pin(pin.as_str()) {
                Ok(()) => {}
                Err(PivError::PinIncorrect { retries }) => {
                    if attempt >= PIN_RETRY_LIMIT {
                        self.sign_failure = Some(failure(Exit::IssuerUnavailable)(format!(
                            "incorrect PIN ({retries} retries remaining)"
                        )));
                        return Err(PivError::PinIncorrect { retries });
                    }
                    attempt += 1;
                    eprintln!("piggy ca: incorrect PIN, {retries} retries remaining");
                    continue;
                }
                Err(e) => {
                    self.sign_failure = Some(failure(Exit::IssuerUnavailable)(format!(
                        "the card did not take the PIN: {e}"
                    )));
                    return Err(e);
                }
            }
            notify_operator(
                &format!("piggy ca: touch card {card}"),
                &format!("slot {slot:02X} signs {describing}"),
            );
            return session.sign_prehash_with_alg(slot, alg, digest);
        }
    }

    /// The refusal [`Self::sign_digest`] recorded, if the card or the
    /// operator refused.
    pub(crate) fn take_sign_failure(&mut self) -> Option<Failure> {
        self.sign_failure.take()
    }
}
