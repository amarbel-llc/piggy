//! The PC/SC implementation of the transport seam
//! ([`crate::transport`]), behind the default-on `pcsc-transport` feature so a
//! `default-features = false` build links no pcsclite (piggy#337).

use pcsc::{Disposition, Protocols, ShareMode};

use crate::context::PivContext;
use crate::error::PivError;
use crate::transport::{
    ApduSession, ApduTransport, EndDisposition, PIN_SESSION_RESET_RETRY_CAP, RawApdu,
};

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
