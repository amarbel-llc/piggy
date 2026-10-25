//! The APDU transport seam: PIV logic above, bytes below (pigsty design,
//! docs/plans/2026-10-25-pigsty-design.md §1).
//!
//! [`PivToken`](crate::token::PivToken) and
//! [`PinSession`](crate::token::PinSession) talk to a card only through
//! these traits. [`PcscTransport`] is the PC/SC implementation every
//! existing caller gets through `PivToken::connect`; a test, or a host
//! without PC/SC (Android NFC/USB), supplies its own and hands it to
//! `PivToken::from_transport`.

use pcsc::{Disposition, Protocols, ShareMode};

use crate::context::PivContext;
use crate::error::PivError;

/// Bound on retries when `SCardBeginTransaction` returns
/// `SCARD_W_RESET_CARD`. C pivy (vendor/pivy/src/piv.c::piv_txn_begin)
/// retries unboundedly; piggy caps it so a card stuck in a reset loop
/// fails fast instead of hanging the agent (piggy#56 decision 5).
pub const PIN_SESSION_RESET_RETRY_CAP: u32 = 3;

/// What happens to the card when a transaction ends. `ResetCard` after a
/// session that verified a PIN, so no PIN state outlives the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndDisposition {
    LeaveCard,
    ResetCard,
}

/// One command APDU in, `data ‖ SW1 SW2` out. No GET RESPONSE chaining,
/// no status-word interpretation: that is the token's job, so every
/// transport gets it identically.
pub trait RawApdu {
    fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError>;
}

/// A connection to one card. `Send` because the agent holds a token and
/// its session across `.await` points in futures that must be `Send`.
pub trait ApduTransport: RawApdu + Send {
    /// Begin an exclusive transaction. The session borrows the transport
    /// for its lifetime; ending it (or dropping it) releases the card.
    fn begin_transaction<'a>(&'a mut self) -> Result<Box<dyn ApduSession + 'a>, PivError>;
}

/// An open transaction. A transport whose medium has no transactions (a
/// single-client NFC link) returns a session that forwards to the
/// connection and treats `end` as a no-op.
pub trait ApduSession: RawApdu + Send {
    fn end(self: Box<Self>, disposition: EndDisposition) -> Result<(), PivError>;
}

/// The PC/SC transport: a shared-mode `pcsc::Card`.
pub struct PcscTransport {
    card: pcsc::Card,
}

impl PcscTransport {
    pub fn connect(ctx: &PivContext, reader: &str) -> Result<Self, PivError> {
        let cstr = std::ffi::CString::new(reader).map_err(|e| PivError::Other(e.to_string()))?;
        let card = ctx
            .pcsc_context()
            .connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        Ok(Self { card })
    }
}

impl RawApdu for PcscTransport {
    fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError> {
        transmit_pcsc(&self.card, command)
    }
}

impl ApduTransport for PcscTransport {
    /// Retries on `SCardBeginTransaction → SCARD_W_RESET_CARD` by
    /// `SCardReconnect`-ing, bounded by [`PIN_SESSION_RESET_RETRY_CAP`].
    /// Mirrors `vendor/pivy/src/piv.c::piv_txn_begin`. The two-phase
    /// shape (probe, then acquire) leaves a small window in which another
    /// client can reset the card between the probe and the acquire; that
    /// surfaces as `PivError::Pcsc`, the same window C pivy has.
    fn begin_transaction<'a>(&'a mut self) -> Result<Box<dyn ApduSession + 'a>, PivError> {
        // The probe phase never retains the success borrow across
        // iterations: the local enum carries only owned values out of each
        // iteration's match, so the borrow checker sees them as independent.
        enum Peek {
            Ready,
            NeedsReconnect,
            Fatal(pcsc::Error),
        }
        for attempt in 1..=PIN_SESSION_RESET_RETRY_CAP {
            let peek = match self.card.transaction() {
                Ok(_txn_dropped) => Peek::Ready,
                Err(pcsc::Error::ResetCard) if attempt < PIN_SESSION_RESET_RETRY_CAP => {
                    Peek::NeedsReconnect
                }
                Err(e) => Peek::Fatal(e),
            };
            match peek {
                Peek::Ready => break,
                Peek::NeedsReconnect => {
                    tracing::warn!(
                        attempt = attempt,
                        cap = PIN_SESSION_RESET_RETRY_CAP,
                        "SCardBeginTransaction returned SCARD_W_RESET_CARD; reconnecting",
                    );
                    self.card.reconnect(
                        ShareMode::Shared,
                        Protocols::ANY,
                        Disposition::ResetCard,
                    )?;
                }
                Peek::Fatal(e) => return Err(PivError::Pcsc(e)),
            }
        }
        let txn = self.card.transaction().map_err(PivError::Pcsc)?;
        Ok(Box::new(PcscSession { txn: Some(txn) }))
    }
}

struct PcscSession<'a> {
    /// `Option` so `end` can consume the transaction; `None` only after
    /// `end`. A session dropped without `end` lets `pcsc::Transaction`'s
    /// own `Drop` end it with LeaveCard.
    txn: Option<pcsc::Transaction<'a>>,
}

impl RawApdu for PcscSession<'_> {
    fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError> {
        let txn = self.txn.as_ref().expect("PcscSession transmit after end");
        // pcsc::Transaction: Deref<Target = pcsc::Card>.
        transmit_pcsc(txn, command)
    }
}

impl ApduSession for PcscSession<'_> {
    fn end(mut self: Box<Self>, disposition: EndDisposition) -> Result<(), PivError> {
        let txn = self.txn.take().expect("PcscSession::end called twice");
        let disposition = match disposition {
            EndDisposition::LeaveCard => Disposition::LeaveCard,
            EndDisposition::ResetCard => Disposition::ResetCard,
        };
        // On error the Transaction is dropped by the closure, which runs
        // SCardEndTransaction(SCARD_LEAVE_CARD) again as a backstop; pcscd
        // handles the redundancy.
        txn.end(disposition).map_err(|(_, e)| PivError::Pcsc(e))
    }
}

fn transmit_pcsc(card: &pcsc::Card, command: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut buf = vec![0u8; 4096];
    Ok(card.transmit(command, &mut buf)?.to_vec())
}
