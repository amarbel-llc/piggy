//! `VirtualCard` — the in-Rust card behind fibby's reader.
//!
//! **Status: stub.** This exists to bring the pcsc-lite protocol path
//! up end-to-end (a client can ESTABLISH → CONNECT → TRANSMIT SELECT →
//! DISCONNECT against fibby with no pcscd). The real PIV applet —
//! GENERATE ASYMMETRIC, GENERAL AUTHENTICATE (sign + ECDH), GET/PUT
//! DATA, VERIFY PIN, YubiKey attestation/serial — is phase-5 work in
//! docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md, validated
//! against RFC 0002 Appendix A and SP 800-73-4 vectors.
//!
//! Until then, SELECT of the PIV AID succeeds (so `pivy-tool list` /
//! readiness probes see a live PIV card) and every other instruction
//! returns `6D00` (INS not supported). Keep the stub honest: it must
//! never *look* like it did crypto it didn't.

use crate::apdu;
use crate::backend::{Backend, ScardResult};
use crate::proto::protocol;
use crate::trace;

/// YubiKey 4 firmware 4.3.5 ATR, captured against real silicon on
/// 2026-05-31 (the wet-env validation pass — see
/// docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md "Validated").
/// The ASCII tail is "Yubikey4" (lowercase k) followed by a TCK byte.
const YK4_ATR: &[u8] = &[
    0x3B, 0xF8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x59, 0x75, 0x62, 0x69, 0x6B, 0x65, 0x79,
    0x34, 0xD4,
];

/// YubiKey 5 ATR (ASCII tail is "YubiKey" — capital K). Carried over
/// from VirtualCard's original placeholder; **not** a wet-env-verified
/// capture — should be replaced with bytes from a real YK5 reader the
/// next time someone has one on hand. Tracked under #128.
const YK5_ATR: &[u8] = &[
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
];

/// PIV card hardware profile. Selects the ATR VirtualCard advertises
/// and (eventually, once design-doc step 5 lands the real PIV applet)
/// the firmware-version-derived behaviors VirtualCard will fork on.
/// For #128 only the ATR is profile-dependent; capability tables
/// (algorithm set, vendor INS support, default mgmt-key kind, etc.)
/// arrive with step 5.
///
/// Validation status:
///
/// - `Yk4` — captured at YubiKey 4 firmware 4.3.5 on 2026-05-31.
///   Fixtures at `crates/fibby/tests/fixtures/captures/yubikey/`.
/// - `Yk5` — placeholder ATR ported from VirtualCard's original
///   constant. Real-card capture pending; see #128.
///
/// `Yk57` (YubiKey 5.7+) is intentionally **not** an enum variant
/// yet — we'd have nothing real to back it with. Add the variant
/// once a 5.7 ATR has been captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Model {
    /// YubiKey 4 / NEO firmware family. Default — the only wet-env-
    /// verified profile today, and the model the replay fixtures pin
    /// against.
    #[default]
    Yk4,
    /// YubiKey 5 (pre-5.4) family. ATR is a real-shape YK5 ATR but
    /// not a captured one; behavior bytes diverge from real silicon
    /// until a capture lands.
    Yk5,
}

impl Model {
    /// Bytes VirtualCard returns from its `Backend::atr()` method.
    pub fn atr(self) -> &'static [u8] {
        match self {
            Model::Yk4 => YK4_ATR,
            Model::Yk5 => YK5_ATR,
        }
    }

    /// Parse a CLI `--model VALUE`. Accepts `yk4` and `yk5`; rejects
    /// anything else with a message naming the supported set. Add
    /// new variants here as wet-env captures land.
    pub fn parse_arg(s: &str) -> Result<Self, String> {
        match s {
            "yk4" => Ok(Model::Yk4),
            "yk5" => Ok(Model::Yk5),
            other => Err(format!(
                "unknown model {other:?} (want 'yk4' or 'yk5'; #128 tracks adding 'yk5.7')"
            )),
        }
    }
}

pub struct VirtualCard {
    reader_name: String,
    model: Model,
    powered: bool,
    selected_piv: bool,
}

impl Default for VirtualCard {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualCard {
    /// Constructor with the default model (YK4 — the wet-env-verified
    /// profile). For an explicit model, use [`Self::with_model`].
    pub fn new() -> Self {
        Self::with_model(Model::default())
    }

    /// Constructor with an explicit hardware profile. Used by the CLI's
    /// `--model` flag and by tests that need to assert per-model ATR
    /// bytes.
    pub fn with_model(model: Model) -> Self {
        VirtualCard {
            reader_name: "Virtual PCD piggy fibby 00 00".to_string(),
            model,
            powered: false,
            selected_piv: false,
        }
    }
}

impl Backend for VirtualCard {
    fn reader_name(&self) -> String {
        self.reader_name.clone()
    }

    fn card_present(&self) -> bool {
        true // the virtual card is always inserted
    }

    fn atr(&self) -> Vec<u8> {
        self.model.atr().to_vec()
    }

    fn connect(&mut self, _share_mode: u32, _preferred_protocols: u32) -> ScardResult<u32> {
        self.powered = true;
        self.selected_piv = false;
        Ok(protocol::T1)
    }

    fn disconnect(&mut self, _disposition: u32) -> ScardResult<()> {
        self.powered = false;
        self.selected_piv = false;
        Ok(())
    }

    fn transmit(&mut self, command_apdu: &[u8]) -> ScardResult<Vec<u8>> {
        if command_apdu.len() < 4 {
            return Ok(sw(0x6F, 0x00)); // no precise diagnosis
        }
        let (cla, ins, p1, p2) = (
            command_apdu[0],
            command_apdu[1],
            command_apdu[2],
            command_apdu[3],
        );

        // SELECT (00 A4 04 00 <Lc> <AID>) of the PIV application.
        if cla == 0x00 && ins == apdu::ins::SELECT && p1 == 0x04 && p2 == 0x00 {
            let aid = command_apdu.get(5..).unwrap_or(&[]);
            let lc = command_apdu.get(4).copied().unwrap_or(0) as usize;
            let aid = aid.get(..lc.min(aid.len())).unwrap_or(aid);
            if aid.starts_with(apdu::PIV_AID_PREFIX) {
                self.selected_piv = true;
                trace::emit(trace::DEBUG, "vcard", "SELECT PIV AID -> 9000 (stub FCI)");
                let mut resp = piv_select_fci();
                resp.extend_from_slice(&sw(0x90, 0x00));
                return Ok(resp);
            }
            trace::emit(trace::DEBUG, "vcard", "SELECT non-PIV AID -> 6A82");
            return Ok(sw(0x6A, 0x82)); // file/application not found
        }

        trace::emit(
            trace::DEBUG,
            "vcard",
            &format!("unimplemented INS {ins:#04x} -> 6D00 (stub)"),
        );
        Ok(sw(0x6D, 0x00)) // instruction not supported (yet)
    }
}

/// Minimal PIV application property template (tag 0x61) naming the PIV
/// AID, enough for a client's SELECT to parse. Not a full SP 800-73-4
/// FCI — the real applet emits the algorithm list etc.
fn piv_select_fci() -> Vec<u8> {
    // 61 <len> 4F <len> <AID full> 79 <len> 4F <len> <AID prefix>
    let mut inner = Vec::new();
    inner.push(0x4F);
    inner.push(apdu::PIV_AID.len() as u8);
    inner.extend_from_slice(apdu::PIV_AID);
    let mut out = vec![0x61, inner.len() as u8];
    out.extend_from_slice(&inner);
    out
}

#[inline]
fn sw(sw1: u8, sw2: u8) -> Vec<u8> {
    vec![sw1, sw2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_piv() -> Vec<u8> {
        let mut a = vec![0x00, 0xA4, 0x04, 0x00, apdu::PIV_AID.len() as u8];
        a.extend_from_slice(apdu::PIV_AID);
        a
    }

    #[test]
    fn connect_then_select_piv_succeeds() {
        let mut c = VirtualCard::new();
        assert_eq!(c.connect(2, 3), Ok(protocol::T1));
        let resp = c.transmit(&select_piv()).unwrap();
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00]);
        assert_eq!(resp[0], 0x61); // application property template
    }

    #[test]
    fn unknown_instruction_is_6d00() {
        let mut c = VirtualCard::new();
        let resp = c.transmit(&[0x00, 0x47, 0x00, 0x9D]).unwrap();
        assert_eq!(resp, vec![0x6D, 0x00]);
    }

    #[test]
    fn default_card_uses_yk4_model_and_wet_env_atr() {
        let c = VirtualCard::new();
        assert!(c.card_present());
        let atr = c.atr();
        // Byte-for-byte equal to the YK4 firmware 4.3.5 ATR captured
        // on 2026-05-31. Any drift here flags a regression in the
        // hardware profile (#128).
        assert_eq!(atr, YK4_ATR.to_vec());
        // ASCII tail is "Yubikey4" (lowercase k, captured) followed
        // by the TCK byte.
        assert!(atr.windows(8).any(|w| w == b"Yubikey4"));
    }

    #[test]
    fn model_yk5_returns_yk5_atr_with_capital_yubikey() {
        let c = VirtualCard::with_model(Model::Yk5);
        let atr = c.atr();
        assert_eq!(atr, YK5_ATR.to_vec());
        // Yk5 placeholder is "YubiKey" (capital K) per the original
        // VirtualCard constant — distinguishes it from Yk4 at a glance.
        assert!(atr.windows(7).any(|w| w == b"YubiKey"));
    }

    #[test]
    fn every_model_atr_starts_with_direct_convention() {
        for model in [Model::Yk4, Model::Yk5] {
            assert_eq!(
                model.atr()[0],
                0x3B,
                "{model:?}: ISO 7816-3 direct-convention TS byte"
            );
        }
    }

    #[test]
    fn model_parse_arg_round_trips_known_values() {
        assert_eq!(Model::parse_arg("yk4"), Ok(Model::Yk4));
        assert_eq!(Model::parse_arg("yk5"), Ok(Model::Yk5));
    }

    #[test]
    fn model_parse_arg_rejects_unknown_values_with_helpful_message() {
        let err = Model::parse_arg("yk9").unwrap_err();
        assert!(
            err.contains("yk9"),
            "error names the offending value: {err}"
        );
        assert!(
            err.contains("yk4") && err.contains("yk5"),
            "error lists supported values: {err}"
        );
    }

    #[test]
    fn model_default_is_yk4_wet_env_profile() {
        assert_eq!(Model::default(), Model::Yk4);
    }
}
