//! `piggy act seal`: the producer primitive (RFC 0013 §3.2, §3.3, §4.8, §7).
//!
//! Given an unsealed act, check the §4.8 namespace and kind pairing before
//! anything else (so a forbidden act never reaches a prompt), then obtain a
//! signature over the canonical form and seal the act with it:
//!
//! - a card namespace through `operator-act@piggy` (RFC 0012) on slot 9C,
//!   the canonical form being the text the operator reads, so the operator
//!   sees exactly the signed bytes;
//! - `piggy-record-v1` through an ordinary agent sign request with the key
//!   the act's `key` names.
//!
//! The signature then goes through [`seal::attach`], which checks it against
//! the seal fields and normalizes a P-256 signature to low-S (§3.3), and
//! through [`seal::verify_seal`], so what is written is an act a verifier
//! accepts or nothing at all (an Ed25519 signature with a non-canonical S
//! is refused there).

use std::path::Path;

use super::{Act, Refusal, seal};
use crate::agent_client::{AgentSignError, OperatorActError, agent_sign_with_key, operator_act};
use crate::operator_act::{HashAlgorithm, Status, displayable_text, signed_data, sshsig_blob};

/// The slot whose key signs card acts: PIV Digital Signature, the slot
/// `piggy card init` gives PIN-always, touch-always (FDR 0006).
const CARD_SLOT: u8 = 0x9C;

/// Why no sealed act was written, grouped as `piggy operator-sign` groups
/// its exits so a caller scripts against the same codes.
#[derive(Debug)]
pub enum SealError {
    /// The answer is no and would be no again (exit 1): the act, the
    /// pairing, the text, the key, or the agent's refusal.
    Refused(String),
    /// Nothing here serves the signature (exit 3): no agent socket, an
    /// unreachable agent, or one without `operator-act@piggy`.
    NotServed(String),
    /// Not signed this time (exit 4): the operator cancelled, or the card
    /// was absent.
    Retryable(String),
}

impl SealError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SealError::Refused(_) => 1,
            SealError::NotServed(_) => 3,
            SealError::Retryable(_) => 4,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            SealError::Refused(m) | SealError::NotServed(m) | SealError::Retryable(m) => m,
        }
    }
}

impl From<Refusal> for SealError {
    fn from(refusal: Refusal) -> Self {
        SealError::Refused(format!(
            "refused ({}): {}",
            refusal.rule.as_str(),
            refusal.detail
        ))
    }
}

/// Seal `act` through the agent at `socket`. `guid` narrows the card when
/// the agent serves slot 9C for more than one.
pub fn seal_act(act: &Act, socket: &Path, guid: Option<&str>) -> Result<Act, SealError> {
    act.check_namespace_pairing()?;

    let canonical = act.canonical();
    let namespace = act.text("namespace").unwrap_or_default();
    let hash = HashAlgorithm::parse(act.text("hash").unwrap_or_default())
        .expect("parse admitted only sha256 and sha512");
    let key = seal::public_key_blob(&seal::seal_key(act)?)?;

    let sshsig = if act.is_card_act() {
        card_sshsig(socket, guid, namespace, hash, &canonical)?
    } else {
        let data = signed_data(namespace, hash, &canonical);
        let signature = agent_sign_with_key(socket, &key, &data).map_err(|e| match e {
            AgentSignError::Unreachable(m) => SealError::NotServed(m),
            AgentSignError::NoKey(m) | AgentSignError::Refused(m) => SealError::Refused(m),
        })?;
        sshsig_blob(&key, namespace, hash, &signature)
    };

    let sealed = seal::attach(act, &sshsig)?;
    seal::verify_seal(&sealed)?;
    Ok(sealed)
}

fn card_sshsig(
    socket: &Path,
    guid: Option<&str>,
    namespace: &str,
    hash: HashAlgorithm,
    canonical: &[u8],
) -> Result<Vec<u8>, SealError> {
    // What the agent would answer `refused-text`, said before the operator
    // is bothered: a card act's canonical form is the prompt (§3.4, §6).
    if displayable_text(canonical).is_none() {
        return Err(SealError::Refused(format!(
            "refused (text): the canonical form is {} bytes; a card act carries at most {} \
             displayable bytes (RFC 0012 §2.5)",
            canonical.len(),
            crate::operator_act::MAX_TEXT_BYTES
        )));
    }

    let (response, _key) = operator_act(socket, CARD_SLOT, guid, namespace, hash, canonical)
        .map_err(|e| match e {
            OperatorActError::Unreachable(_) | OperatorActError::NotServed(_) => {
                SealError::NotServed(e.to_string())
            }
            OperatorActError::NoKey(_) | OperatorActError::Protocol(_) => {
                SealError::Refused(e.to_string())
            }
        })?;

    match response.status {
        Status::Signed => Ok(response.sshsig),
        status @ (Status::Cancelled | Status::CardAbsent) => Err(SealError::Retryable(format!(
            "the act was not signed ({}){}",
            status.name(),
            detail(&response.detail)
        ))),
        status => Err(SealError::Refused(format!(
            "the agent refused the act ({}){}",
            status.name(),
            detail(&response.detail)
        ))),
    }
}

fn detail(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}
