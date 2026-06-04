//! CAK (Card Authentication Key) challenge/response for `piggy agent -K`.
//!
//! The operator pins the expected slot-9E public key with `-K`. At startup
//! (and on every card probe) the agent signs a fresh random challenge with
//! the card's PIN-never slot-9E key (GENERAL AUTHENTICATE) and verifies the
//! signature against the configured CAK. A match proves the card holds the
//! CAK private key — i.e. it is the expected card, not a swapped imposter
//! (piggy#143). Mirrors the C `pivy-agent`'s `piv_auth_key` (`-K`).

use ssh_key::public::KeyData;

use piggy_piv::Guid;

use super::session::reconnect_to_token;

/// Authenticate the card identified by `guid` against `cak`. Best-effort:
/// any PCSC / card / crypto error (missing 9E key, malformed signature, a
/// non-EC CAK, …) counts as a failed authentication, never a panic.
pub(super) fn authenticate(guid: &Guid, cak: &KeyData) -> bool {
    let start = std::time::Instant::now();
    let ok = match authenticate_inner(guid, cak) {
        Ok(ok) => ok,
        Err(e) => {
            tracing::debug!("CAK authentication error: {e}");
            false
        }
    };
    // stats-me: `piggy.agent.cak.<result>` + duration (best-effort/opt-in).
    let outcome = if ok {
        crate::stats::Outcome::Success
    } else {
        crate::stats::Outcome::Failure
    };
    crate::stats::agent_op("cak", outcome, start.elapsed());
    ok
}

fn authenticate_inner(guid: &Guid, cak: &KeyData) -> Result<bool, String> {
    // A fresh random challenge per attempt — a captured (challenge, response)
    // pair can't be replayed against the next probe.
    let mut challenge = [0u8; 32];
    openssl::rand::rand_bytes(&mut challenge).map_err(|e| e.to_string())?;

    let mut token = reconnect_to_token(guid).map_err(|e| e.to_string())?;
    // Slot 9E (Card Authentication) is PIN-never; no verify_pin needed. We
    // open a session anyway so the sign runs inside a PC/SC transaction.
    let mut session = token.begin_pin_session().map_err(|e| e.to_string())?;
    let der_sig = session
        .sign_prehash(0x9E, &challenge)
        .map_err(|e| e.to_string())?;

    piggy_piv::cert::verify_ec_signature(cak, &challenge, &der_sig).map_err(|e| e.to_string())
}
