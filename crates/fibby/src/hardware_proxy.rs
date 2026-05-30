//! `HardwareProxy` — forward fibby's backend calls to a *real* `pcscd`
//! → real reader/YubiKey via the `pcsc` crate.
//!
//! This is the validation oracle. Run fibby with this backend on a
//! machine that has a YubiKey plugged into the system `pcscd`, point a
//! client at fibby's socket, and you are exercising fibby's pcsc-lite
//! *protocol server* in front of genuine silicon. If `pivy-tool list`
//! and `pivy-tool generate 9d` work through fibby, the protocol layer
//! is correct — and the captured wire traffic (`FIBBY_LOG=wire`)
//! becomes the conformance fixtures the `VirtualCard` must replay.
//!
//! Gated behind the `hardware-proxy` Cargo feature so the protocol core
//! and `VirtualCard` build/test on hosts with no PCSC headers (CI
//! containers, darwin).
//!
//! Notes for the wet-env agents:
//! - The reader is selected by substring (`--reader <substr>`), default
//!   "Yubico". First match wins; all readers are logged at INFO.
//! - `pcsc::Error` is mapped to the closest `SCARD_*` code *and* logged
//!   verbatim, so a mismatch between the real code and fibby's mapping
//!   is visible rather than silently coerced.
//! - This holds one `pcsc::Card` at a time (single-client validation).

use std::ffi::CString;

use pcsc::{Context, Disposition, Protocols, Scope, ShareMode};

use crate::backend::{Backend, ScardResult};
use crate::error::*;
use crate::proto::{disposition, protocol};
use crate::trace;

pub struct HardwareProxy {
    ctx: Context,
    reader: CString,
    reader_name: String,
    card: Option<pcsc::Card>,
    cached_atr: Vec<u8>,
}

impl HardwareProxy {
    /// Establish a system context and pick the first reader whose name
    /// contains `reader_substr`. Probes the ATR once up front.
    pub fn new(reader_substr: &str) -> Result<Self, String> {
        let ctx = Context::establish(Scope::System)
            .map_err(|e| format!("SCardEstablishContext failed: {e}"))?;

        let mut names_buf = [0u8; 2048];
        let readers = ctx
            .list_readers(&mut names_buf)
            .map_err(|e| format!("SCardListReaders failed: {e}"))?;

        let mut chosen: Option<CString> = None;
        for r in readers {
            let name = r.to_string_lossy();
            trace::emit(trace::INFO, "proxy", &format!("reader: {name}"));
            if chosen.is_none() && name.contains(reader_substr) {
                chosen = Some(r.to_owned());
            }
        }
        let reader = chosen.ok_or_else(|| {
            format!("no reader matching {reader_substr:?}; is the card plugged in and pcscd up?")
        })?;
        let reader_name = reader.to_string_lossy().into_owned();
        trace::emit(
            trace::INFO,
            "proxy",
            &format!("selected reader: {reader_name}"),
        );

        let mut me = HardwareProxy {
            ctx,
            reader,
            reader_name,
            card: None,
            cached_atr: Vec::new(),
        };
        // Best-effort ATR probe (LEAVE the card as found).
        if me
            .connect(crate::proto::share::SHARED, protocol::ANY)
            .is_ok()
        {
            me.cached_atr = me.atr();
            let _ = me.disconnect(disposition::LEAVE);
        }
        Ok(me)
    }

    fn map_share(share_mode: u32) -> ShareMode {
        match share_mode {
            x if x == crate::proto::share::EXCLUSIVE => ShareMode::Exclusive,
            x if x == crate::proto::share::DIRECT => ShareMode::Direct,
            _ => ShareMode::Shared,
        }
    }

    fn map_protocols(preferred: u32) -> Protocols {
        let t0 = preferred & protocol::T0 != 0;
        let t1 = preferred & protocol::T1 != 0;
        match (t0, t1) {
            (true, true) => Protocols::ANY,
            (true, false) => Protocols::T0,
            (false, true) => Protocols::T1,
            (false, false) => Protocols::ANY,
        }
    }

    fn map_disposition(d: u32) -> Disposition {
        match d {
            x if x == disposition::RESET => Disposition::ResetCard,
            x if x == disposition::UNPOWER => Disposition::UnpowerCard,
            x if x == disposition::EJECT => Disposition::EjectCard,
            _ => Disposition::LeaveCard,
        }
    }

    fn map_err(e: pcsc::Error) -> u32 {
        trace::emit(trace::DEBUG, "proxy", &format!("pcsc error: {e:?}"));
        match e {
            pcsc::Error::NoSmartcard => SCARD_E_NO_SMARTCARD,
            pcsc::Error::RemovedCard => SCARD_W_REMOVED_CARD,
            pcsc::Error::UnresponsiveCard => SCARD_W_UNRESPONSIVE_CARD,
            pcsc::Error::UnknownReader => SCARD_E_UNKNOWN_READER,
            pcsc::Error::ReaderUnavailable => SCARD_E_READER_UNAVAILABLE,
            pcsc::Error::SharingViolation => SCARD_E_SHARING_VIOLATION,
            pcsc::Error::ProtoMismatch => SCARD_E_PROTO_MISMATCH,
            pcsc::Error::InvalidValue => SCARD_E_INVALID_VALUE,
            pcsc::Error::InvalidHandle => SCARD_E_INVALID_HANDLE,
            _ => SCARD_F_INTERNAL_ERROR,
        }
    }
}

impl Backend for HardwareProxy {
    fn reader_name(&self) -> String {
        self.reader_name.clone()
    }

    fn card_present(&self) -> bool {
        // We probed at startup; treat a known ATR as "present". The
        // server's reader-state reply uses this. Wet-env: if hot-plug
        // matters, re-probe via SCardGetStatusChange here.
        !self.cached_atr.is_empty() || self.card.is_some()
    }

    fn atr(&self) -> Vec<u8> {
        if let Some(card) = &self.card {
            let mut names_buf = [0u8; 256];
            let mut atr_buf = [0u8; pcsc::MAX_ATR_SIZE];
            if let Ok(status) = card.status2(&mut names_buf, &mut atr_buf) {
                return status.atr().to_vec();
            }
        }
        self.cached_atr.clone()
    }

    fn connect(&mut self, share_mode: u32, preferred_protocols: u32) -> ScardResult<u32> {
        let card = self
            .ctx
            .connect(
                &self.reader,
                Self::map_share(share_mode),
                Self::map_protocols(preferred_protocols),
            )
            .map_err(Self::map_err)?;
        let mut names_buf = [0u8; 256];
        let mut atr_buf = [0u8; pcsc::MAX_ATR_SIZE];
        let active = match card.status2(&mut names_buf, &mut atr_buf) {
            Ok(s) => {
                self.cached_atr = s.atr().to_vec();
                match s.protocol2() {
                    Some(pcsc::Protocol::T0) => protocol::T0,
                    _ => protocol::T1,
                }
            }
            Err(_) => protocol::T1,
        };
        self.card = Some(card);
        trace::emit(
            trace::DEBUG,
            "proxy",
            &format!("connected, active protocol = {active}"),
        );
        Ok(active)
    }

    fn disconnect(&mut self, disp: u32) -> ScardResult<()> {
        if let Some(card) = self.card.take() {
            card.disconnect(Self::map_disposition(disp))
                .map_err(|(_, e)| Self::map_err(e))?;
        }
        Ok(())
    }

    fn transmit(&mut self, command_apdu: &[u8]) -> ScardResult<Vec<u8>> {
        let card = self.card.as_ref().ok_or(SCARD_E_INVALID_HANDLE)?;
        // PIV responses fit in the short buffer except chained reads;
        // use the extended buffer to be safe.
        let mut rx = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let resp = card
            .transmit(command_apdu, &mut rx)
            .map_err(Self::map_err)?;
        Ok(resp.to_vec())
    }
}
