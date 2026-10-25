//! Card ECDH for a pigpen (RFC 0008 §4.3) recipient over any
//! [`ApduTransport`](crate::transport::ApduTransport): the PIV side of a
//! `piggy_pigpen::EcdhOracle` that does not go through an agent (piggy#341,
//! design in docs/plans/2026-10-25-card-ecdh-oracle.md). Pure Rust, so it
//! builds without the `pcsc-transport` feature (pigsty's Android path).
//!
//! The PIN comes from a [`PinSource`] the caller supplies, as a structured
//! [`PinRequest`] so an app can render its own dialog. It is asked once and
//! cached for the [`CardEcdh`]'s lifetime.

use std::sync::Mutex;

use elliptic_curve::sec1::ToEncodedPoint;
use zeroize::{Zeroize, Zeroizing};

use crate::error::PivError;
use crate::guid::Guid;
use crate::token::PivToken;

/// The key-management slot pigpen's card recipients live in.
const SLOT_9D: u8 = 0x9D;

/// What the PIN dialog is told.
pub struct PinRequest<'a> {
    pub token_guid: &'a Guid,
    pub slot: u8,
    /// `None` on the first ask; `Some(n)` after a wrong PIN, from the
    /// card's counter.
    pub retries_remaining: Option<u8>,
}

/// The user declined to enter a PIN.
#[derive(Debug)]
pub struct PinDeclined;

/// Where the PIN comes from. Synchronous: an app with an async dialog runs
/// the oracle off its UI thread.
pub trait PinSource: Send {
    fn pin(&self, req: &PinRequest<'_>) -> Result<Zeroizing<String>, PinDeclined>;
}

#[derive(Debug, thiserror::Error)]
pub enum CardEcdhError {
    /// This card's slot 9D does not hold the recipient; try another
    /// recipient or card. No PIN was asked.
    #[error("this card's slot 9D does not hold that recipient")]
    NotThisCard,
    #[error("PIN entry was declined")]
    PinDeclined,
    #[error("PIN is blocked")]
    PinBlocked,
    #[error(transparent)]
    Piv(#[from] PivError),
}

/// Slot-9D ECDH on one card, with the PIN asked once.
pub struct CardEcdh {
    token: Mutex<PivToken>,
    pin_source: Box<dyn PinSource>,
    cached_pin: Mutex<Option<Zeroizing<String>>>,
}

impl CardEcdh {
    pub fn new(token: PivToken, pin_source: Box<dyn PinSource>) -> Self {
        Self {
            token: Mutex::new(token),
            pin_source,
            cached_pin: Mutex::new(None),
        }
    }

    /// Whether slot 9D holds `recipient` (a SEC1 P-256 point, either form).
    /// Offline: reads the slot certificate, needs no PIN.
    pub fn holds(&self, recipient: &[u8]) -> Result<bool, CardEcdhError> {
        let want = uncompressed_p256(recipient, "recipient")?;
        let token = self.token.lock().expect("CardEcdh token lock");
        Ok(token.read_slot(SLOT_9D)?.ec_sec1_point()? == want)
    }

    /// The X coordinate of (slot-9D private key · `partner`), where
    /// `partner` is a SEC1 P-256 point and `recipient` must be the slot's
    /// public key.
    pub fn ecdh(
        &self,
        recipient: &[u8],
        partner: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CardEcdhError> {
        let want = uncompressed_p256(recipient, "recipient")?;
        let partner = uncompressed_p256(partner, "partner key")?;
        let mut token = self.token.lock().expect("CardEcdh token lock");
        let guid = token.guid().clone();
        let mut session = token.begin_pin_session()?;

        // Read the slot before the VERIFY so nothing sits between the
        // VERIFY and the GENERAL AUTHENTICATE (piggy#325).
        let slot = session.read_slot(SLOT_9D)?;
        if slot.ec_sec1_point()? != want {
            return Err(CardEcdhError::NotThisCard);
        }

        let mut cached = self.cached_pin.lock().expect("CardEcdh PIN lock");
        let mut retries_remaining = None;
        loop {
            let pin = match cached.take() {
                Some(pin) => pin,
                None => self
                    .pin_source
                    .pin(&PinRequest {
                        token_guid: &guid,
                        slot: SLOT_9D,
                        retries_remaining,
                    })
                    .map_err(|PinDeclined| CardEcdhError::PinDeclined)?,
            };
            match session.verify_pin(&pin) {
                Ok(()) => {
                    *cached = Some(pin);
                    break;
                }
                Err(PivError::PinIncorrect { retries }) => {
                    retries_remaining = Some(u8::try_from(retries).unwrap_or(u8::MAX));
                }
                Err(PivError::PinBlocked) => return Err(CardEcdhError::PinBlocked),
                Err(e) => return Err(e.into()),
            }
        }

        let mut response = session.ecdh_derive(&slot, &partner)?;
        let secret = response
            .get(..32)
            .and_then(|x| <[u8; 32]>::try_from(x).ok());
        response.zeroize();
        session.end()?;
        secret
            .map(Zeroizing::new)
            .ok_or_else(|| PivError::Crypto("ECDH response shorter than 32 bytes".into()).into())
    }
}

fn uncompressed_p256(sec1: &[u8], what: &str) -> Result<Vec<u8>, CardEcdhError> {
    let key = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|e| PivError::Crypto(format!("{what} is not a P-256 point: {e}")))?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}
