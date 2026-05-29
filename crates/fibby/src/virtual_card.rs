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

/// A real YubiKey 5 PIV ATR (contains the ASCII "YubiKey"). Placeholder:
/// the wet-env capture should replace this with the exact ATR the target
/// model reports, taken from the hardware-proxy backend's `atr()`.
const YUBIKEY5_ATR: &[u8] = &[
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
];

pub struct VirtualCard {
    reader_name: String,
    powered: bool,
    selected_piv: bool,
}

impl Default for VirtualCard {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualCard {
    pub fn new() -> Self {
        VirtualCard {
            reader_name: "Virtual PCD piggy fibby 00 00".to_string(),
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
        YUBIKEY5_ATR.to_vec()
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
    fn atr_is_present_and_yubikey_flavored() {
        let c = VirtualCard::new();
        assert!(c.card_present());
        let atr = c.atr();
        assert_eq!(atr[0], 0x3B); // direct convention TS byte
        assert!(atr.windows(7).any(|w| w == b"YubiKey"));
    }
}
