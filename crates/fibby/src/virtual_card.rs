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

use std::collections::HashMap;

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

/// Canonical real-card PIV SELECT FCI. Wet-env-captured byte-equal
/// from both YubiKey 4 firmware 4.3.5 AND YubiKey 5 firmware 5.2.7
/// on 2026-05-31 — both real cards emit this exact 19-byte response
/// on every successful SELECT of the PIV AID, despite their different
/// firmware lineages.
///
/// Structure: outer 0x61 (application-property template, len 0x11=17),
/// then:
///
/// - `4F 06 00 00 10 00 01 00` — application identifier (the
///   post-RID portion of the PIV AID `A0 00 00 03 08 *00 00 10 00 01
///   00*`).
/// - `79 07 4F 05 A0 00 00 03 08` — coexistent tag allocation
///   authority (RID-only portion of the PIV AID).
///
/// Trailing SW 9000 is added by the caller. fib's PivApplet does NOT
/// emit this — it prepends its 30-byte applet identity string into a
/// 121-byte FCI. A separate `Model::FibPivApplet` variant or an
/// embedded fib-specific constant would close that gap; out of scope
/// for the current YK4/YK5 alignment.
const CANONICAL_REAL_CARD_PIV_FCI: &[u8] = &[
    0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00,
    0x00, 0x03, 0x08,
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

    /// Bytes returned in the PIV SELECT response (inside the 0x61
    /// application-property template), without the trailing SW 9000.
    /// Per SP 800-73-4 §3.1.1 + the YK4 + YK5 wet-env captures:
    ///
    /// - `Yk4` and `Yk5` both → the wet-env-canonical 19-byte FCI
    ///   `61 11 4F 06 <PIV AID app portion> 79 07 4F 05 <PIV AID RID>`.
    ///   Wet-env captures confirm real YubiKey 4 firmware 4.3.5 and
    ///   real YubiKey 5 firmware 5.2.7 emit byte-identical responses
    ///   on every PIV SELECT — that's the canonical real-card PIV
    ///   FCI, shared by both profiles. fib's PivApplet, by contrast,
    ///   prepends its applet identity string and emits a 121-byte
    ///   FCI; aligning fib requires either a `Model::FibPivApplet`
    ///   variant or the wet-env-captured PivApplet bytes embedded
    ///   here — deferred.
    pub fn select_fci_bytes(self) -> &'static [u8] {
        match self {
            // Both YubiKey models emit the canonical 19-byte real-card
            // PIV FCI; verified wet-env on YK4 4.3.5 + YK5 5.2.7.
            Model::Yk4 | Model::Yk5 => CANONICAL_REAL_CARD_PIV_FCI,
        }
    }

    /// 3-byte firmware version returned by the YubiKey vendor GET
    /// VERSION instruction (INS 0xFD): `[major, minor, patch]`. The
    /// wire response is these three bytes followed by SW 9000.
    ///
    /// - `Yk4` → `(4, 3, 5)`, the version reported by the real YubiKey
    ///   4 we captured against on 2026-05-31.
    /// - `Yk5` → `(5, 2, 7)`, captured wet-env on 2026-05-31 against a
    ///   real YubiKey 5 firmware 5.2.7. This used to be `(5, 4, 0)` as
    ///   a placeholder that happened to match fib's PivApplet
    ///   emulation; now that we have real YK5 wire, Yk5 reflects real
    ///   silicon. fib's `5.4.0` advertisement no longer byte-matches
    ///   Yk5 — that's a separate concern best handled by a
    ///   `Model::FibPivApplet` variant or by accepting the gap.
    pub fn firmware_version(self) -> [u8; 3] {
        match self {
            Model::Yk4 => [0x04, 0x03, 0x05],
            Model::Yk5 => [0x05, 0x02, 0x07],
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
    /// PIV data-object storage keyed by tag bytes (the inner `<tag>` in
    /// `5C <len> <tag>`). Values are stored already-wrapped in a 53
    /// BER-TLV so GET DATA can return them verbatim — that's how real
    /// silicon's wire looks. Empty by default; clients populate via
    /// PUT DATA. See SP 800-73-4 §3.1.{2,3} for the request/response
    /// shape.
    ///
    /// NB no mgmt-key auth enforcement yet — any client can PUT
    /// anything. Auth enforcement is its own slice; the design-doc
    /// step-5 work tracks it. Until then, VirtualCard is a stub a
    /// trusted local test can drive end-to-end, not a security
    /// boundary.
    data_objects: HashMap<Vec<u8>, Vec<u8>>,
    /// PIV application PIN state (SP 800-73-4 §3.2.1). The PIN is
    /// stored as 8 bytes; YubiKey factory default is `"123456"` padded
    /// with 0xFF to the full 8-byte length (`31 32 33 34 35 36 FF FF`).
    /// pivy-tool's captures use this default, so VirtualCard byte-
    /// matches successful VERIFYs out of the box.
    pin: Vec<u8>,
    /// Number of remaining VERIFY attempts. Reset to 3 on a successful
    /// verification; decremented on a wrong-PIN attempt; PIN becomes
    /// permanently blocked at 0 (real silicon needs PUK to unblock,
    /// not implemented yet). Persists across `disconnect()` like real
    /// silicon — only successful VERIFY restores it.
    pin_retries: u8,
    /// Whether the PIN has been verified in this session. Cleared on
    /// `disconnect()` to mirror real-card semantics (the verified
    /// state doesn't survive a power cycle). Subsequent PIN-gated
    /// operations (GA ECDH, etc.) must check this before honoring the
    /// request — TODO once GA lands.
    pin_verified: bool,
}

/// YubiKey factory-default PIN: ASCII "123456" padded with 0xFF bytes
/// to 8 bytes total. pivy-tool's captured wires include this exact
/// byte sequence when verifying a freshly-init'd card.
const DEFAULT_PIN: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];

/// PIV factory-default PIN retry count.
const DEFAULT_PIN_RETRIES: u8 = 3;

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
            data_objects: HashMap::new(),
            pin: DEFAULT_PIN.to_vec(),
            pin_retries: DEFAULT_PIN_RETRIES,
            pin_verified: false,
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
        // Real silicon clears PIN-verified status when the card loses
        // power. retry counter is persistent — only a successful
        // VERIFY resets it.
        self.pin_verified = false;
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

        // SELECT (00 A4 04 00 <Lc> <AID>) of the PIV application. Use
        // apdu_body() so both short-form and extended-length Lc work
        // — YK4's pivy-tool sends extended-length SELECT (we saw the
        // same issue cause `is_select_piv` to underreport SELECTs in
        // replay; the same bug class here would silently fail the
        // PIV AID check on every YK4 SELECT and fall through to 6A82).
        if cla == 0x00 && ins == apdu::ins::SELECT && p1 == 0x04 && p2 == 0x00 {
            let aid = apdu_body(command_apdu).unwrap_or(&[]);
            if aid.starts_with(apdu::PIV_AID_PREFIX) {
                self.selected_piv = true;
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("SELECT PIV AID -> 9000 ({} FCI)", model_name(self.model)),
                );
                let mut resp = self.model.select_fci_bytes().to_vec();
                resp.extend_from_slice(&sw(0x90, 0x00));
                return Ok(resp);
            }
            trace::emit(trace::DEBUG, "vcard", "SELECT non-PIV AID -> 6A82");
            return Ok(sw(0x6A, 0x82)); // file/application not found
        }

        // GET DATA (00 CB 3F FF <Lc> 5C <tag_len> <tag> [Le])
        if cla == 0x00 && ins == apdu::ins::GET_DATA && p1 == 0x3F && p2 == 0xFF {
            return Ok(self.handle_get_data(command_apdu));
        }

        // PUT DATA (00 DB 3F FF <Lc> 5C <tag_len> <tag> 53 <data_len> <data>)
        if cla == 0x00 && ins == apdu::ins::PUT_DATA && p1 == 0x3F && p2 == 0xFF {
            return Ok(self.handle_put_data(command_apdu));
        }

        // GET VERSION (00 FD 00 00 ...). YubiKey vendor extension; no
        // body. Returns the 3-byte firmware tuple + SW 9000. Both
        // short-form and extended-length case-2 encodings show up in
        // the captures; we don't look at the body so both hit this
        // branch.
        if cla == 0x00 && ins == apdu::ins::GET_VERSION && p1 == 0x00 && p2 == 0x00 {
            let fw = self.model.firmware_version();
            trace::emit(
                trace::DEBUG,
                "vcard",
                &format!("GET VERSION -> {}.{}.{} 9000", fw[0], fw[1], fw[2]),
            );
            let mut out = fw.to_vec();
            out.extend_from_slice(&sw(0x90, 0x00));
            return Ok(out);
        }

        // VERIFY (00 20 P1 P2 ...). PIV application PIN at P1=00 P2=80.
        // Other P1/P2 combinations: the YK4 wet-env capture shows real
        // silicon returning 6A80 for `00 20 FF 80 00 00 00` (which
        // SP 800-73-4 nominally documents as "clear verify status"),
        // so we match that behavior — return 6A80 for any non-(00, 80)
        // P1/P2 combination instead of inventing an interpretation.
        if cla == 0x00 && ins == apdu::ins::VERIFY {
            if p1 != 0x00 || p2 != 0x80 {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("VERIFY P1={p1:#04x} P2={p2:#04x} -> 6A80 (unsupported)"),
                );
                return Ok(sw(0x6A, 0x80));
            }
            return Ok(self.handle_verify(apdu_body(command_apdu)));
        }

        trace::emit(
            trace::DEBUG,
            "vcard",
            &format!("unimplemented INS {ins:#04x} -> 6D00 (stub)"),
        );
        Ok(sw(0x6D, 0x00)) // instruction not supported (yet)
    }
}

impl VirtualCard {
    /// Handle a VERIFY (INS 0x20, P1=00, P2=80) APDU.
    ///
    /// Two body shapes, both per SP 800-73-4 §3.2.1:
    ///
    /// - **No body** (status query): return 9000 if the PIN has been
    ///   verified in this session, `63 Cx` if not — `x` is
    ///   `self.pin_retries` packed into the low nibble.
    /// - **8-byte body** (verify attempt): compare against
    ///   `self.pin`. On success, reset retries to 3, set
    ///   `pin_verified`, return 9000. On mismatch, decrement retries
    ///   and return `63 Cx`. When retries hit 0, the PIN is blocked
    ///   and subsequent attempts (including with the correct PIN)
    ///   return `69 83`.
    ///
    /// Any other body length returns `6A80` (incorrect data field).
    fn handle_verify(&mut self, body: Option<&[u8]>) -> Vec<u8> {
        match body {
            None => {
                if self.pin_verified {
                    trace::emit(trace::DEBUG, "vcard", "VERIFY (status) -> 9000 (verified)");
                    sw(0x90, 0x00)
                } else {
                    let resp = sw(0x63, 0xC0 | self.pin_retries);
                    trace::emit(
                        trace::DEBUG,
                        "vcard",
                        &format!(
                            "VERIFY (status) -> 63 C{} ({} retries left)",
                            self.pin_retries, self.pin_retries
                        ),
                    );
                    resp
                }
            }
            Some(pin) => {
                if pin.len() != 8 {
                    trace::emit(
                        trace::DEBUG,
                        "vcard",
                        &format!("VERIFY (body len {}) -> 6A80 (must be 8)", pin.len()),
                    );
                    return sw(0x6A, 0x80);
                }
                if self.pin_retries == 0 {
                    trace::emit(trace::DEBUG, "vcard", "VERIFY -> 6983 (blocked)");
                    return sw(0x69, 0x83);
                }
                if pin == self.pin.as_slice() {
                    self.pin_retries = DEFAULT_PIN_RETRIES;
                    self.pin_verified = true;
                    trace::emit(trace::DEBUG, "vcard", "VERIFY -> 9000 (success)");
                    sw(0x90, 0x00)
                } else {
                    self.pin_retries -= 1;
                    if self.pin_retries == 0 {
                        trace::emit(trace::DEBUG, "vcard", "VERIFY -> 6983 (just blocked)");
                        sw(0x69, 0x83)
                    } else {
                        trace::emit(
                            trace::DEBUG,
                            "vcard",
                            &format!("VERIFY -> 63 C{} (wrong PIN)", self.pin_retries),
                        );
                        sw(0x63, 0xC0 | self.pin_retries)
                    }
                }
            }
        }
    }

    /// Handle a `GET DATA` APDU. Parses the `5C <tag_len> <tag>` body
    /// to extract the tag and looks it up in `self.data_objects`.
    /// Returns the stored `53 <len> <value>` plus SW=9000 if present,
    /// `6A82` (file not found) if not, `6A80` (incorrect data field
    /// parameters) on a malformed request.
    fn handle_get_data(&mut self, apdu: &[u8]) -> Vec<u8> {
        let body = match apdu_body(apdu) {
            Some(b) => b,
            None => return sw(0x6A, 0x80),
        };
        let tag = match parse_5c_tag(body) {
            Some(t) => t.to_vec(),
            None => {
                trace::emit(trace::DEBUG, "vcard", "GET DATA: malformed 5C TLV");
                return sw(0x6A, 0x80);
            }
        };
        match self.data_objects.get(&tag) {
            Some(value) => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GET DATA tag={} -> {} bytes", hex_tag(&tag), value.len()),
                );
                let mut out = value.clone();
                out.extend_from_slice(&sw(0x90, 0x00));
                out
            }
            None => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GET DATA tag={} -> 6A82 (not present)", hex_tag(&tag)),
                );
                sw(0x6A, 0x82)
            }
        }
    }

    /// Handle a `PUT DATA` APDU. Parses `5C <tag_len> <tag>` followed
    /// by the `53 <len> <data>` block, stores the 53-wrapped form in
    /// `self.data_objects`. Returns SW=9000 on success, `6A80` on a
    /// malformed body. No mgmt-key auth enforced (see struct doc).
    fn handle_put_data(&mut self, apdu: &[u8]) -> Vec<u8> {
        let body = match apdu_body(apdu) {
            Some(b) => b,
            None => return sw(0x6A, 0x80),
        };
        let (tag, rest) = match parse_5c_tag_with_rest(body) {
            Some(t) => t,
            None => {
                trace::emit(trace::DEBUG, "vcard", "PUT DATA: malformed 5C TLV");
                return sw(0x6A, 0x80);
            }
        };
        // The remainder must be a single 53 BER-TLV. We store the
        // whole 53-wrapped form verbatim so GET DATA can return it
        // unchanged.
        let (value_with_53, _trailing) = match split_53_tlv(rest) {
            Some(t) => t,
            None => {
                trace::emit(trace::DEBUG, "vcard", "PUT DATA: malformed 53 TLV");
                return sw(0x6A, 0x80);
            }
        };
        trace::emit(
            trace::DEBUG,
            "vcard",
            &format!(
                "PUT DATA tag={} -> {} bytes stored",
                hex_tag(tag),
                value_with_53.len()
            ),
        );
        self.data_objects
            .insert(tag.to_vec(), value_with_53.to_vec());
        sw(0x90, 0x00)
    }
}

/// Extract the data field from a case-3 or case-4 APDU. Handles both
/// ISO 7816-4 encodings:
///
/// - **Short-form**: `CLA INS P1 P2 Lc <data> [Le]` where `Lc` is one
///   byte in 1..=255.
/// - **Extended-length**: `CLA INS P1 P2 00 <Lc_hi> <Lc_lo> <data>
///   [<Le_hi> <Le_lo>]` — distinguished by `apdu[4] == 0x00` with at
///   least 7 bytes total.
///
/// Real wet-env captures show pivy-tool's PIV path picking encoding
/// per card: YubiKey 4 negotiates extended-length and uses it for
/// GET/PUT DATA, while fib's PivApplet falls back to short-form after
/// rejecting extended (the `6986` error we see in the fib init
/// fixture). Without both encodings, GET DATA against a YK4 capture
/// would never match.
fn apdu_body(apdu: &[u8]) -> Option<&[u8]> {
    if apdu.len() < 5 {
        return None;
    }
    if apdu[4] == 0x00 && apdu.len() >= 7 {
        // Extended-length: Lc is 2 bytes BE at [5..7], data at [7..].
        let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
        if lc == 0 || apdu.len() < 7 + lc {
            return None;
        }
        Some(&apdu[7..7 + lc])
    } else {
        let lc = apdu[4] as usize;
        if lc == 0 || apdu.len() < 5 + lc {
            return None;
        }
        Some(&apdu[5..5 + lc])
    }
}

/// Parse a single `5C <tag_len> <tag>` BER-TLV at the front of the
/// data field, returning the tag bytes. Tag length 0 is rejected.
/// Anything after the 5C TLV is ignored — use [`parse_5c_tag_with_rest`]
/// when there's more to read (PUT DATA's 53 TLV).
fn parse_5c_tag(body: &[u8]) -> Option<&[u8]> {
    parse_5c_tag_with_rest(body).map(|(tag, _rest)| tag)
}

/// Variant of [`parse_5c_tag`] that also returns the bytes after the
/// 5C TLV. PUT DATA needs this — the `53 <len> <data>` block follows.
fn parse_5c_tag_with_rest(body: &[u8]) -> Option<(&[u8], &[u8])> {
    if body.first()? != &0x5C {
        return None;
    }
    let tag_len = *body.get(1)? as usize;
    if tag_len == 0 || body.len() < 2 + tag_len {
        return None;
    }
    let tag = &body[2..2 + tag_len];
    let rest = &body[2 + tag_len..];
    Some((tag, rest))
}

/// Parse a single 53 BER-TLV at the front of `body`. Supports the
/// short form (length 0-127 in one byte) and the 0x81 form (length
/// 128-255 in one length byte). Returns `(full_tlv_with_53_header,
/// trailing_bytes)`. Anything beyond the 0x81 form is rejected for now
/// — real PIV objects fit (CHUID/CCC: ~50-60 bytes; slot certs: handled
/// by GENERATE flow, not raw PUT DATA in our current captures).
fn split_53_tlv(body: &[u8]) -> Option<(&[u8], &[u8])> {
    if body.first()? != &0x53 {
        return None;
    }
    let first_len = *body.get(1)?;
    let (header_len, payload_len) = if first_len < 0x80 {
        (2, first_len as usize)
    } else if first_len == 0x81 {
        (3, *body.get(2)? as usize)
    } else {
        return None;
    };
    let total = header_len + payload_len;
    if body.len() < total {
        return None;
    }
    Some((&body[..total], &body[total..]))
}

/// Render a tag as a hex string for trace messages. Tags are 1-3 bytes;
/// this is decoration, not on a hot path.
fn hex_tag(tag: &[u8]) -> String {
    let mut s = String::with_capacity(tag.len() * 2);
    for byte in tag {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{byte:02X}");
    }
    s
}

/// Short label for trace messages. Display impl would be neater but
/// requires a derive; this is one decoration site.
fn model_name(model: Model) -> &'static str {
    match model {
        Model::Yk4 => "Yk4 wet-env",
        Model::Yk5 => "Yk5 stub",
    }
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

    // -- GET DATA / PUT DATA tests ---------------------------------------

    /// Build a PIV GET DATA APDU for a 3-byte tag (e.g. CHUID `5FC102`).
    fn get_data_apdu(tag: &[u8]) -> Vec<u8> {
        // 00 CB 3F FF Lc 5C <tag_len> <tag> 00
        let mut a = vec![0x00, 0xCB, 0x3F, 0xFF];
        let body_len = 2 + tag.len(); // 5C + tag_len + tag
        a.push(body_len as u8);
        a.push(0x5C);
        a.push(tag.len() as u8);
        a.extend_from_slice(tag);
        a.push(0x00); // Le = 0 (max)
        a
    }

    /// Build a PIV PUT DATA APDU for a tag + value. Wraps the value
    /// in a 53 BER-TLV (short form, value len ≤ 127) automatically.
    fn put_data_apdu(tag: &[u8], value: &[u8]) -> Vec<u8> {
        assert!(value.len() <= 127, "test helper: short-form only");
        let mut a = vec![0x00, 0xDB, 0x3F, 0xFF];
        let body_len = 2 + tag.len() + 2 + value.len(); // 5C + tag_len + tag + 53 + val_len + val
        a.push(body_len as u8);
        a.push(0x5C);
        a.push(tag.len() as u8);
        a.extend_from_slice(tag);
        a.push(0x53);
        a.push(value.len() as u8);
        a.extend_from_slice(value);
        a
    }

    const TAG_CHUID: &[u8] = &[0x5F, 0xC1, 0x02];
    const TAG_CCC: &[u8] = &[0x5F, 0xC1, 0x07];

    #[test]
    fn get_data_returns_6a82_on_unset_tag() {
        let mut c = VirtualCard::new();
        let resp = c.transmit(&get_data_apdu(TAG_CHUID)).unwrap();
        assert_eq!(resp, vec![0x6A, 0x82]);
    }

    #[test]
    fn put_data_then_get_data_round_trips_bytes() {
        let mut c = VirtualCard::new();
        // Arbitrary CHUID-shaped payload; we only assert byte equality.
        let value: &[u8] = &[0x30, 0x19, 0xD0, 0x42, 0x10, 0xAA, 0xBB];

        let put = c.transmit(&put_data_apdu(TAG_CHUID, value)).unwrap();
        assert_eq!(put, vec![0x90, 0x00], "PUT DATA -> 9000");

        let get = c.transmit(&get_data_apdu(TAG_CHUID)).unwrap();
        // GET DATA response is the stored 53-wrapped form + SW.
        let mut expected = vec![0x53, value.len() as u8];
        expected.extend_from_slice(value);
        expected.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(get, expected);
    }

    #[test]
    fn put_data_namespaces_by_tag() {
        let mut c = VirtualCard::new();
        c.transmit(&put_data_apdu(TAG_CHUID, &[0xAA, 0xAA]))
            .unwrap();
        c.transmit(&put_data_apdu(TAG_CCC, &[0xBB, 0xBB])).unwrap();

        let chuid_get = c.transmit(&get_data_apdu(TAG_CHUID)).unwrap();
        let ccc_get = c.transmit(&get_data_apdu(TAG_CCC)).unwrap();

        // Each tag returns its own stored value (not the other one).
        assert_eq!(
            chuid_get,
            vec![0x53, 0x02, 0xAA, 0xAA, 0x90, 0x00],
            "CHUID tag returns its own value"
        );
        assert_eq!(
            ccc_get,
            vec![0x53, 0x02, 0xBB, 0xBB, 0x90, 0x00],
            "CCC tag returns its own value"
        );
    }

    #[test]
    fn put_data_overwrites_existing_value() {
        let mut c = VirtualCard::new();
        c.transmit(&put_data_apdu(TAG_CHUID, &[0x01])).unwrap();
        c.transmit(&put_data_apdu(TAG_CHUID, &[0x02, 0x03]))
            .unwrap();

        let resp = c.transmit(&get_data_apdu(TAG_CHUID)).unwrap();
        assert_eq!(
            resp,
            vec![0x53, 0x02, 0x02, 0x03, 0x90, 0x00],
            "second PUT overwrites the first"
        );
    }

    #[test]
    fn put_data_supports_0x81_length_form_for_values_128_to_255() {
        let mut c = VirtualCard::new();
        let value: Vec<u8> = (0..200u8).collect();
        // Build PUT DATA manually with the 0x81 length form (the helper
        // above asserts ≤ 127). Body shape:
        //   5C 03 <tag>  53 81 <len> <value>
        let body_len = 2 + 3 + 3 + value.len(); // 5C+5C_len+tag(3) + 53+81+len + value
        let mut apdu = vec![0x00, 0xDB, 0x3F, 0xFF, body_len as u8];
        apdu.extend_from_slice(&[0x5C, 0x03]);
        apdu.extend_from_slice(TAG_CHUID);
        apdu.extend_from_slice(&[0x53, 0x81, value.len() as u8]);
        apdu.extend_from_slice(&value);

        let put = c.transmit(&apdu).unwrap();
        assert_eq!(put, vec![0x90, 0x00]);

        let get = c.transmit(&get_data_apdu(TAG_CHUID)).unwrap();
        // GET returns the stored 53-wrapped form verbatim + SW.
        let mut expected = vec![0x53, 0x81, value.len() as u8];
        expected.extend_from_slice(&value);
        expected.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(get, expected);
    }

    #[test]
    fn get_data_with_truncated_5c_tlv_returns_6a80() {
        let mut c = VirtualCard::new();
        // Lc says 2 bytes of body, body is `5C 03` claiming 3 tag bytes
        // that aren't there. Malformed → 6A80.
        let apdu = vec![0x00, 0xCB, 0x3F, 0xFF, 0x02, 0x5C, 0x03];
        let resp = c.transmit(&apdu).unwrap();
        assert_eq!(resp, vec![0x6A, 0x80]);
    }

    #[test]
    fn put_data_without_53_block_returns_6a80() {
        let mut c = VirtualCard::new();
        // PUT DATA with a valid 5C TLV but no 53 block after it.
        let apdu = vec![0x00, 0xDB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let resp = c.transmit(&apdu).unwrap();
        assert_eq!(resp, vec![0x6A, 0x80]);
    }

    #[test]
    fn get_version_returns_yk4_firmware_for_default_model() {
        let mut c = VirtualCard::new();
        // Short-form Le=0 (case 2).
        let resp = c.transmit(&[0x00, 0xFD, 0x00, 0x00, 0x00]).unwrap();
        // 4.3.5 + 9000; byte-equal to what the YK4 capture returned.
        assert_eq!(resp, vec![0x04, 0x03, 0x05, 0x90, 0x00]);
    }

    #[test]
    fn get_version_returns_yk5_firmware_for_yk5_model() {
        let mut c = VirtualCard::with_model(Model::Yk5);
        let resp = c.transmit(&[0x00, 0xFD, 0x00, 0x00, 0x00]).unwrap();
        // 5.2.7 + 9000; byte-equal to the YubiKey 5 firmware 5.2.7
        // wire response captured 2026-05-31. (Previously this asserted
        // 5.4.0 from a placeholder that happened to match fib's
        // PivApplet emulation.)
        assert_eq!(resp, vec![0x05, 0x02, 0x07, 0x90, 0x00]);
    }

    #[test]
    fn get_version_accepts_extended_length_le_encoding() {
        // YK4's pivy-tool sends GET VERSION as
        // `00 FD 00 00 00 00 00` (case-2 extended-length, Le=0).
        let mut c = VirtualCard::new();
        let resp = c
            .transmit(&[0x00, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(resp, vec![0x04, 0x03, 0x05, 0x90, 0x00]);
    }

    #[test]
    fn select_piv_returns_yk4_wet_env_fci_for_default_model() {
        let mut c = VirtualCard::new();
        c.connect(2, 3).unwrap();
        let resp = c.transmit(&select_piv()).unwrap();
        // Byte-equal to YK4 firmware 4.3.5's wire response on every
        // SELECT PIV pair in the captures.
        assert_eq!(
            resp,
            vec![
                0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05,
                0xA0, 0x00, 0x00, 0x03, 0x08, 0x90, 0x00,
            ]
        );
    }

    #[test]
    fn select_piv_returns_canonical_real_card_fci_for_yk5_model() {
        let mut c = VirtualCard::with_model(Model::Yk5);
        c.connect(2, 3).unwrap();
        let resp = c.transmit(&select_piv()).unwrap();
        // Wet-env captures on 2026-05-31 confirmed real YK4 and real
        // YK5 emit byte-identical PIV SELECT FCIs. So Yk5's response
        // is the same canonical bytes Yk4 returns.
        assert_eq!(
            resp,
            vec![
                0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05,
                0xA0, 0x00, 0x00, 0x03, 0x08, 0x90, 0x00,
            ]
        );
    }

    #[test]
    fn model_firmware_version_for_yk4_is_4_3_5_wet_env_captured() {
        // Byte-equality with the YK4 capture's GET VERSION response.
        assert_eq!(Model::Yk4.firmware_version(), [0x04, 0x03, 0x05]);
    }

    #[test]
    fn model_firmware_version_for_yk5_is_5_2_7_wet_env_captured() {
        // 5.2.7 — captured wet-env from real YubiKey 5 on 2026-05-31.
        // Byte-equal to the YK5 GET VERSION wire response.
        assert_eq!(Model::Yk5.firmware_version(), [0x05, 0x02, 0x07]);
    }

    // -- VERIFY PIN tests ---------------------------------------------

    /// Status-query VERIFY: `00 20 00 80 00 00 00` (case 2 extended-
    /// length, Lc=0). Real YK4 returned `63 C3` here on a freshly-init'd
    /// card. VirtualCard's defaults reproduce that byte-equal.
    fn verify_status_apdu_ext() -> Vec<u8> {
        vec![0x00, 0x20, 0x00, 0x80, 0x00, 0x00, 0x00]
    }

    /// VERIFY-with-PIN: `00 20 00 80 00 00 08 <8-byte PIN> 00 00`
    /// (case 4 extended-length with the YubiKey factory default PIN
    /// "123456" + FF FF padding). Real YK4 returned 9000.
    fn verify_default_pin_apdu_ext() -> Vec<u8> {
        vec![
            0x00, 0x20, 0x00, 0x80, 0x00, 0x00, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF,
            0xFF, 0x00, 0x00,
        ]
    }

    /// Short-form variant of the above (for testing without leaning on
    /// extended-length): `00 20 00 80 08 <PIN>`. Real YK4 wouldn't see
    /// this shape from pivy-tool (it uses extended-length), but the
    /// handler should support both.
    fn verify_default_pin_apdu_short() -> Vec<u8> {
        vec![
            0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF,
        ]
    }

    #[test]
    fn verify_status_query_on_fresh_card_returns_63_c3() {
        let mut c = VirtualCard::new();
        let resp = c.transmit(&verify_status_apdu_ext()).unwrap();
        assert_eq!(
            resp,
            vec![0x63, 0xC3],
            "fresh card: 3 retries left, not verified"
        );
    }

    #[test]
    fn verify_with_default_pin_returns_9000_and_marks_verified() {
        let mut c = VirtualCard::new();
        let resp = c.transmit(&verify_default_pin_apdu_ext()).unwrap();
        assert_eq!(resp, vec![0x90, 0x00], "default PIN should verify");
        // Status query now returns 9000.
        assert_eq!(
            c.transmit(&verify_status_apdu_ext()).unwrap(),
            vec![0x90, 0x00]
        );
    }

    #[test]
    fn verify_short_form_works_same_as_extended() {
        let mut c = VirtualCard::new();
        let resp = c.transmit(&verify_default_pin_apdu_short()).unwrap();
        assert_eq!(resp, vec![0x90, 0x00]);
    }

    #[test]
    fn verify_with_wrong_pin_decrements_retries_and_returns_63_cx() {
        let mut c = VirtualCard::new();
        let mut wrong = verify_default_pin_apdu_short();
        wrong[5] = 0x39; // change first PIN byte from '1' to '9'

        let resp1 = c.transmit(&wrong).unwrap();
        assert_eq!(resp1, vec![0x63, 0xC2], "first wrong: 2 left");

        let resp2 = c.transmit(&wrong).unwrap();
        assert_eq!(resp2, vec![0x63, 0xC1], "second wrong: 1 left");

        let resp3 = c.transmit(&wrong).unwrap();
        assert_eq!(resp3, vec![0x69, 0x83], "third wrong: PIN blocked");
    }

    #[test]
    fn verify_correct_pin_after_one_wrong_resets_retry_counter() {
        let mut c = VirtualCard::new();
        let mut wrong = verify_default_pin_apdu_short();
        wrong[5] = 0x39;

        c.transmit(&wrong).unwrap(); // retries = 2
        let resp = c.transmit(&verify_default_pin_apdu_short()).unwrap();
        assert_eq!(resp, vec![0x90, 0x00]);

        // Subsequent wrong attempts should start from 3 again, not 2.
        let resp = c.transmit(&wrong).unwrap();
        assert_eq!(resp, vec![0x63, 0xC2], "retries reset after success");
    }

    #[test]
    fn verify_with_correct_pin_after_blocked_still_returns_6983() {
        let mut c = VirtualCard::new();
        let mut wrong = verify_default_pin_apdu_short();
        wrong[5] = 0x39;
        // Burn all 3 retries.
        for _ in 0..3 {
            c.transmit(&wrong).unwrap();
        }
        // Now even the correct PIN is rejected.
        let resp = c.transmit(&verify_default_pin_apdu_short()).unwrap();
        assert_eq!(resp, vec![0x69, 0x83]);
    }

    #[test]
    fn verify_with_wrong_body_length_returns_6a80() {
        let mut c = VirtualCard::new();
        let apdu = vec![
            0x00, 0x20, 0x00, 0x80, 0x04, 0x31, 0x32, 0x33, 0x34, // 4-byte body, not 8
        ];
        assert_eq!(c.transmit(&apdu).unwrap(), vec![0x6A, 0x80]);
    }

    #[test]
    fn verify_with_p1_ff_returns_6a80_matching_yk4_capture() {
        let mut c = VirtualCard::new();
        // 00 20 FF 80 00 00 00 — what we saw real YK4 return 6A80 to
        // in the wet-env yk4-roundtrip capture.
        let apdu = vec![0x00, 0x20, 0xFF, 0x80, 0x00, 0x00, 0x00];
        assert_eq!(c.transmit(&apdu).unwrap(), vec![0x6A, 0x80]);
    }

    #[test]
    fn disconnect_clears_verified_flag_but_keeps_retries() {
        let mut c = VirtualCard::new();
        c.transmit(&verify_default_pin_apdu_short()).unwrap();
        assert_eq!(
            c.transmit(&verify_status_apdu_ext()).unwrap(),
            vec![0x90, 0x00]
        );

        c.disconnect(0).unwrap();
        c.connect(2, 3).unwrap();

        // Verified flag cleared, but retry counter persists at 3
        // (real silicon: a successful verify reset it; disconnect
        // doesn't touch it).
        assert_eq!(
            c.transmit(&verify_status_apdu_ext()).unwrap(),
            vec![0x63, 0xC3]
        );
    }

    #[test]
    fn get_data_handles_extended_length_lc_encoding() {
        // YubiKey 4's pivy-tool sends GET DATA in extended-length
        // form: `00 CB 3F FF 00 <Lc_hi> <Lc_lo> <body> <Le_hi> <Le_lo>`.
        // This is the shape that appears in `yk4-list.fixture`.
        let mut c = VirtualCard::new();
        // CHUID payload to plant via short-form PUT (the encoding of
        // the WRITE doesn't matter here; what we're testing is the
        // READ accepting extended-length).
        c.transmit(&put_data_apdu(TAG_CHUID, &[0xAB, 0xCD]))
            .unwrap();

        let extended_get = vec![
            0x00, 0xCB, 0x3F, 0xFF, 0x00, 0x00, 0x05, // CLA INS P1 P2 + extended Lc=5
            0x5C, 0x03, 0x5F, 0xC1, 0x02, // 5C TLV identifying CHUID
            0x00, 0x00, // extended Le = 0 (max)
        ];
        let resp = c.transmit(&extended_get).unwrap();
        assert_eq!(resp, vec![0x53, 0x02, 0xAB, 0xCD, 0x90, 0x00]);
    }
}
