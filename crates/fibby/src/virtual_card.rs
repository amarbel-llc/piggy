//! `VirtualCard` — the in-Rust card behind fibby's reader.
//!
//! A software PIV applet that answers the PIV command set over fibby's
//! pcsc-lite protocol path with no pcscd and no hardware. Implemented
//! today (validated against RFC 0002 Appendix A, SP 800-73-4 vectors,
//! and wet-env captures — see
//! docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md):
//!
//! - SELECT (PIV AID), GET DATA / PUT DATA, GET VERSION, YubiKey SERIAL.
//! - VERIFY PIN (with retry counter + blocked state).
//! - GENERAL AUTHENTICATE: ECDH on slot 9D (alg 0x11; the piggy decrypt
//!   path), ECDSA sign on slot 9A (alg 0x11; the SSH-auth path, RFC 6979
//!   deterministic), and the 3DES mgmt-key challenge-response (alg 0x03).
//! - YubiKey ATTEST (INS 0xF9 — `6A80` for imported/empty slots).
//!
//! Not yet implemented (returns `6D00`, INS not supported): GENERATE
//! ASYMMETRIC (on-card keygen), slot 9C signing, and the rest of the
//! phase-5 surface in the design doc. Keep the card honest: an
//! unimplemented instruction must return `6D00`, never *look* like it
//! did crypto it didn't.

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

    /// 4-byte serial number returned by the YubiKey vendor instruction
    /// `0xF8`, or `None` if the model doesn't implement that vendor
    /// extension (real silicon then returns `6D00`).
    ///
    /// - `Yk4` → `None`. Captured wire on YubiKey 4 firmware 4.3.5
    ///   (2026-05-31) shows `6D00` for every `00 F8 00 00 ...`
    ///   request; YubiKey 4 firmware predates this vendor extension.
    /// - `Yk5` → the 4-byte serial `00 F2 C2 E6` captured from the
    ///   primary YubiKey 5 firmware 5.2.7 on 2026-05-31. Hardcoding a
    ///   specific physical card's serial in source is unusual, but
    ///   the test bed pins to that specific card the same way the
    ///   throwaway's GUID pins yk4-init. A future `with_serial(...)`
    ///   constructor — symmetric with `with_pin(...)` (see #134) — is
    ///   the right escape hatch when more YK5s need to be modeled.
    pub fn serial(self) -> Option<[u8; 4]> {
        match self {
            Model::Yk4 => None,
            Model::Yk5 => Some([0x00, 0xF2, 0xC2, 0xE6]),
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
    /// state doesn't survive a power cycle). PIN-gated operations
    /// (e.g. GA ECDH on slot 9D) consult this before honoring the
    /// request and return `69 82` when unset.
    pin_verified: bool,
    /// Raw P-256 scalar (big-endian) installed in slot 9A (PIV
    /// Authentication), or `None` if no key is present. This is the
    /// SSH-auth signing slot: GA ECDSA requests (INS 0x87, P1=0x11,
    /// P2=0x9A) sign the client-supplied prehash under RFC 6979
    /// deterministic ECDSA. Set via [`Self::seed_slot_9a_priv`], or
    /// implicitly by [`Self::seed_rfc6979_slot_9a_cert`] which seeds the
    /// scalar matching the canonical slot-9A cert. Empty (`6A 88` to GA)
    /// until a future generate-asymmetric branch lands for production runs.
    slot_9a_priv: Option<[u8; 32]>,
    /// Raw P-256 scalar (big-endian) installed in slot 9D, or `None`
    /// if no key is present. Mirrors real silicon's PIV state: a slot
    /// can be either populated (key + optional cert) or empty
    /// (returns `6A 88` to GA). Set via [`Self::seed_slot_9d_priv`]
    /// by tests that import a test-vector scalar (see piggy#134) so
    /// GA ECDH responses are byte-deterministic across captures.
    /// Production VirtualCard runs always have this `None` until a
    /// future generate-asymmetric branch lands.
    slot_9d_priv: Option<[u8; 32]>,
    /// Raw P-256 scalar (big-endian) installed in slot 9C (Digital
    /// Signature), or `None` if no key is present. The signature slot
    /// with PIV PIN policy **"always"**: GA ECDSA requests (INS 0x87,
    /// P1=0x11, P2=0x9C) sign the client-supplied prehash under RFC 6979
    /// deterministic ECDSA, but unlike slot 9A ("once") the PIN
    /// verification is *consumed* by each sign — see
    /// [`Self::sign_ecdsa_slot`]. Set via [`Self::seed_slot_9c_priv`], or
    /// implicitly by [`Self::seed_fibby_slot_9c_cert`]. Empty (`6A 88` to
    /// GA) until seeded.
    slot_9c_priv: Option<[u8; 32]>,
    /// 24-byte TripleDES management key. Defaults to YubiKey's factory
    /// constant `01 02 03 04 05 06 07 08 01 02 03 04 05 06 07 08 01
    /// 02 03 04 05 06 07 08` — the same value our throwaway captures
    /// pin against. Gated by INS 0x87 P1=0x03 P2=0x9B challenge-
    /// response (SP 800-73-4 §3.2.4). Override via
    /// [`Self::seed_mgmt_key`] for tests that capture against a
    /// rotated mgmt-key.
    mgmt_key: [u8; 24],
    /// Witness bytes the mgmt-key auth's phase-1 (`7C 02 81 00`)
    /// returns to the client. Real silicon picks 8 random bytes per
    /// session; for byte-deterministic replay (piggy#134's pattern)
    /// tests seed the value captured on the wire via
    /// [`Self::seed_mgmt_key_witness`]. Cleared on phase-2 completion
    /// (success or failure) and on `disconnect()`. `None` means
    /// "no challenge outstanding" — phase 2 then returns 6982.
    pending_mgmt_witness: Option<[u8; 8]>,
}

/// YubiKey factory-default PIN: ASCII "123456" padded with 0xFF bytes
/// to 8 bytes total. pivy-tool's captured wires include this exact
/// byte sequence when verifying a freshly-init'd card.
const DEFAULT_PIN: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];

/// PIV factory-default PIN retry count.
const DEFAULT_PIN_RETRIES: u8 = 3;

/// YubiKey factory-default TripleDES mgmt-key: three identical 8-byte
/// halves `01 02 03 04 05 06 07 08`. Every freshly-reset throwaway in
/// our fixtures uses this exact constant.
const DEFAULT_MGMT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// RFC 6979 §A.2.5 P-256 private scalar, big-endian. This is the
/// keypair the canonical slot-9A cert ([`RFC6979_SLOT_9A_CERT_OBJECT`])
/// is self-signed over — its embedded public point
/// `04 60 FE D4 BA … 46 22 99` is exactly this scalar's public key — and
/// the same scalar imported into the throwaway YubiKey slot 9D for the
/// wet-env ECDH captures. [`VirtualCard::seed_rfc6979_slot_9a_cert`]
/// installs both the cert and this scalar so the seeded SSH identity can
/// actually sign. The unit tests reference it as `RFC6979_SCALAR`.
const RFC6979_A2_5_PRIV: [u8; 32] = [
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
    0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
];

/// RFC 5903 §8.1 P-256 private scalar, big-endian — the initiator key of
/// the "256-Bit Random ECP Group" (= NIST P-256). This is the keypair
/// the canonical slot-9D cert ([`RFC5903_SLOT_9D_CERT_OBJECT`]) is
/// self-signed over, and the key [`VirtualCard::seed_rfc5903_slot_9d_cert`]
/// installs into slot 9D for ECDH. Deliberately distinct from the §A.2.5
/// scalar used by slot 9A: a shared pubkey across 9A (sign) and 9D
/// (ECDH) could let pivy-agent route a decrypt's ECDH to the sign-only
/// 9A slot. Its public point is `04 ‖ DA D0 B6 53 … ‖ 52 71 A0 46 …`
/// (see tests/fixtures/test-vectors/rfc5903-8-1-priv.pem).
const RFC5903_SLOT_9D_PRIV: [u8; 32] = [
    0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2, 0x92, 0xDA, 0xA2, 0x31, 0x6D, 0xE5,
    0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49, 0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D, 0x14, 0x33,
];

/// fibby's slot 9C (Digital Signature) test P-256 scalar, big-endian.
/// Unlike the 9A/9D keys, this is **not** a published RFC vector: the
/// slot-9C sign path uses RFC 6979 deterministic ECDSA, so (unlike 9D's
/// ECDH byte-replay, piggy#134) there is no captured wire to match — only
/// a key distinct from 9A (§A.2.5) and 9D (§8.1) is needed so sign routing
/// is unambiguous. Generated once by `just debug-fibby-gen-slot-9c-cert`
/// and pinned alongside [`FIBBY_SLOT_9C_CERT_OBJECT`] (the self-signed
/// cert over this exact key); the anchor PEM is
/// tests/fixtures/test-vectors/fibby-slot-9c-test-priv.pem. Its public
/// point is `04 ‖ BA 37 10 C3 … ‖ … 67 20 E6 2E 89`.
const FIBBY_SLOT_9C_TEST_PRIV: [u8; 32] = [
    0x7A, 0x02, 0x52, 0x57, 0xFB, 0xC7, 0x8C, 0x36, 0x9C, 0x6C, 0xFA, 0x4B, 0xEE, 0x3B, 0x1C, 0x04,
    0x49, 0xD1, 0x93, 0xA5, 0xD4, 0x46, 0x11, 0x88, 0x85, 0x14, 0x1F, 0x0F, 0xBE, 0xBB, 0x47, 0xFC,
];

/// PIV tag for the slot 9A (PIV Authentication) X.509 cert object,
/// per SP 800-73-4 §3.3 Table 6 / pivy `PIV_TAG_CERT_9A`: `5F C1 05`.
///
/// NB: `5F C1 01` is the slot **9E** (Card Authentication) cert object,
/// not slot 9A — a tempting off-by-one. Seeding the 9A cert under
/// `5F C1 01` makes pivy-agent expose the identity as slot 9E and sign
/// via GA `P2=0x9E` (which fibby's sign handler, keyed on slot 9A,
/// rejects with `6D00`). The fibby↔pivy-agent Phase 0 smoke caught
/// exactly this. See `pivy-piv/src/slot.rs` for the full slot→tag map.
const TAG_SLOT_9A_CERT: &[u8] = &[0x5F, 0xC1, 0x05];

/// Canonical fibby test-vector slot 9A certificate, wrapped in the PIV
/// cert-object TLV (`53 <len> 70 <der-len> <der> 71 01 00 FE 00`).
///
/// The DER cert is a self-signed X.509 v3 over the RFC 6979 §A.2.5
/// P-256 keypair (see `tests/fixtures/test-vectors/`). Generated once
/// (openssl req -x509 with fixed serial=1, notBefore=2026-01-01Z,
/// notAfter=2126-01-01Z, subject `CN=fibby-test-slot-9a`) and pinned
/// here byte-for-byte. The ECDSA signature uses a random `k`, so the
/// bytes are not reproducible from the PEM by external tools — but
/// once pinned here, they're the canonical "fibby slot 9A cert" until
/// someone deliberately regenerates and re-pins.
///
/// The embedded SubjectPublicKeyInfo carries the RFC 6979 §A.2.5
/// public point (`04 60 FE D4 BA … 46 22 99`) so any consumer reading
/// the cert sees the test-vector pubkey. pivy-agent parses this into
/// an SSH-presentable identity (`ecdsa-sha2-nistp256 …`).
///
/// Activated by [`VirtualCard::seed_rfc6979_slot_9a_cert`] — typically
/// from the fibby CLI's `--seed-rfc6979-slot-9a-cert` flag, which the
/// bats smoke tests use to exercise the seeded-identity path.
///
/// 399 bytes total (1-byte `53` tag + 3-byte BER `82 01 8B` long-form
/// length + 395-byte inner: `70 82 01 82 <386 B DER> 71 01 00 FE 00`).
const RFC6979_SLOT_9A_CERT_OBJECT: &[u8] = &[
    0x53, 0x82, 0x01, 0x8B, 0x70, 0x82, 0x01, 0x82, 0x30, 0x82, 0x01, 0x7E, 0x30, 0x82, 0x01, 0x24,
    0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x04, 0x03, 0x02, 0x30, 0x1D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x12, 0x66, 0x69, 0x62, 0x62, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x73, 0x6C, 0x6F, 0x74,
    0x2D, 0x39, 0x61, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x31, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x1D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x12, 0x66, 0x69, 0x62, 0x62, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x73, 0x6C, 0x6F,
    0x74, 0x2D, 0x39, 0x61, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x60,
    0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68, 0xC0,
    0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6, 0x79,
    0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64, 0xF2,
    0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99, 0xA3,
    0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x1A, 0x95,
    0x69, 0x57, 0x9B, 0xCE, 0x32, 0x9A, 0x94, 0x2D, 0x07, 0x69, 0xC9, 0xC0, 0xB5, 0x64, 0x31, 0x56,
    0x37, 0x10, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x1A,
    0x95, 0x69, 0x57, 0x9B, 0xCE, 0x32, 0x9A, 0x94, 0x2D, 0x07, 0x69, 0xC9, 0xC0, 0xB5, 0x64, 0x31,
    0x56, 0x37, 0x10, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xAB, 0x19, 0x95, 0x5E, 0xC3, 0xE1, 0x46, 0x40,
    0x46, 0xB5, 0xC0, 0x92, 0x22, 0xEA, 0x63, 0x07, 0x97, 0x98, 0xE8, 0x6E, 0xE3, 0xEC, 0x58, 0xE4,
    0x17, 0x74, 0x6F, 0xC4, 0x3B, 0x1B, 0x77, 0x41, 0x02, 0x20, 0x57, 0x57, 0x9B, 0x69, 0x63, 0xC4,
    0xEE, 0xBF, 0xB4, 0x34, 0x37, 0x53, 0xD4, 0x88, 0x09, 0x43, 0x39, 0x0C, 0x54, 0x8A, 0x40, 0x6E,
    0x5D, 0xD8, 0x88, 0x1C, 0x42, 0x9E, 0x88, 0xCF, 0xF4, 0x6A, 0x71, 0x01, 0x00, 0xFE, 0x00,
];

/// PIV tag for the slot 9D (Key Management) X.509 cert object, per
/// SP 800-73-4 §3.3 Table 6 / pivy `PIV_TAG_CERT_9D`: `5F C1 0B`.
/// This is the cert pivy-agent enumerates to expose fibby's ECDH /
/// decrypt identity.
const TAG_SLOT_9D_CERT: &[u8] = &[0x5F, 0xC1, 0x0B];

/// Canonical fibby slot-9D certificate, wrapped in the PIV cert-object
/// TLV (`53 <len> 70 <der-len> <der> 71 01 00 FE 00`).
///
/// Self-signed X.509 v3 over the RFC 5903 §8.1 P-256 keypair
/// ([`RFC5903_SLOT_9D_PRIV`]; CN `fibby-test-slot-9d`, serial 1,
/// notBefore 2026-01-01Z, notAfter 2126-01-01Z), generated once and
/// pinned here byte-for-byte. The embedded SubjectPublicKeyInfo carries
/// the §8.1 public point (`04 ‖ DA D0 B6 53 … ‖ 52 71 A0 46 …`), so
/// pivy-agent exposes a slot-9D ECDH identity whose pubkey is the §8.1
/// vector — distinct from the slot-9A cert's §A.2.5 pubkey, so a
/// decrypt's ECDH routes unambiguously to slot 9D. The ECDSA signature
/// uses a random `k`, so the bytes aren't reproducible from the PEM by
/// external tools; once pinned they're canonical. See
/// tests/fixtures/test-vectors/README.md for the regeneration recipe.
///
/// Activated by [`VirtualCard::seed_rfc5903_slot_9d_cert`] — typically
/// via the fibby CLI's `--seed-rfc5903-slot-9d-cert` flag.
const RFC5903_SLOT_9D_CERT_OBJECT: &[u8] = &[
    0x53, 0x82, 0x01, 0x69, 0x70, 0x82, 0x01, 0x60, 0x30, 0x82, 0x01, 0x5C, 0x30, 0x82, 0x01, 0x03,
    0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x04, 0x03, 0x02, 0x30, 0x1D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x12, 0x66, 0x69, 0x62, 0x62, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x73, 0x6C, 0x6F, 0x74,
    0x2D, 0x39, 0x64, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x31, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x1D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x12, 0x66, 0x69, 0x62, 0x62, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x73, 0x6C, 0x6F,
    0x74, 0x2D, 0x39, 0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xDA,
    0xD0, 0xB6, 0x53, 0x94, 0x22, 0x1C, 0xF9, 0xB0, 0x51, 0xE1, 0xFE, 0xCA, 0x57, 0x87, 0xD0, 0x98,
    0xDF, 0xE6, 0x37, 0xFC, 0x90, 0xB9, 0xEF, 0x94, 0x5D, 0x0C, 0x37, 0x72, 0x58, 0x11, 0x80, 0x52,
    0x71, 0xA0, 0x46, 0x1C, 0xDB, 0x82, 0x52, 0xD6, 0x1F, 0x1C, 0x45, 0x6F, 0xA3, 0xE5, 0x9A, 0xB1,
    0xF4, 0x5B, 0x33, 0xAC, 0xCF, 0x5F, 0x58, 0x38, 0x9E, 0x05, 0x77, 0xB8, 0x99, 0x0B, 0xB3, 0xA3,
    0x32, 0x30, 0x30, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xFF, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x49,
    0x49, 0xD4, 0x61, 0xBC, 0xB2, 0x5B, 0x69, 0x7E, 0x11, 0x77, 0xBD, 0x82, 0x16, 0xFF, 0x2C, 0x97,
    0x96, 0x40, 0xAF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03,
    0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x28, 0xD9, 0x89, 0x38, 0xB3, 0x0B, 0x54, 0xD3, 0xE4, 0x9C,
    0x87, 0x71, 0x3D, 0xD4, 0x5F, 0x1C, 0x12, 0x96, 0xB3, 0xA4, 0x39, 0x1A, 0xEF, 0x01, 0xA4, 0xB7,
    0x74, 0x07, 0x80, 0x4E, 0x71, 0x21, 0x02, 0x20, 0x43, 0xEE, 0x0A, 0x54, 0x88, 0x62, 0x6B, 0x0F,
    0x32, 0x5E, 0x0A, 0xCD, 0x29, 0x77, 0xE3, 0x9E, 0x0A, 0x65, 0x58, 0x8B, 0xB8, 0x37, 0x95, 0x77,
    0x9E, 0xD9, 0x8D, 0xA5, 0xB8, 0xB7, 0xF2, 0x86, 0x71, 0x01, 0x00, 0xFE, 0x00,
];

/// PIV tag for the slot 9C (Digital Signature) X.509 cert object, per
/// SP 800-73-4 §3.3 Table 6 / pivy `PIV_TAG_CERT_9C`: `5F C1 0A`. (The
/// fibby↔pivy-agent smoke documents the same slot↔tag map.)
const TAG_SLOT_9C_CERT: &[u8] = &[0x5F, 0xC1, 0x0A];

/// Canonical fibby slot-9C certificate, wrapped in the PIV cert-object
/// TLV (`53 <len> 70 <der-len> <der> 71 01 00 FE 00`).
///
/// Self-signed X.509 v3 over the [`FIBBY_SLOT_9C_TEST_PRIV`] P-256 key
/// (CN `fibby-test-slot-9c`, serial 1, 100-year validity), generated once
/// by `just debug-fibby-gen-slot-9c-cert` and pinned here byte-for-byte.
/// The embedded SubjectPublicKeyInfo carries that key's public point
/// (`04 ‖ BA 37 10 C3 … ‖ … 67 20 E6 2E 89`), so pivy-agent exposes a
/// slot-9C signature identity distinct from the 9A/9D ones. The ECDSA
/// signature uses a random `k`, so the bytes aren't reproducible from the
/// PEM by external tools — once pinned they're canonical. 398 bytes.
const FIBBY_SLOT_9C_CERT_OBJECT: &[u8] = &[
    0x53, 0x82, 0x01, 0x8A, 0x70, 0x82, 0x01, 0x81, 0x30, 0x82, 0x01, 0x7D, 0x30, 0x82, 0x01, 0x24,
    0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x04, 0x03, 0x02, 0x30, 0x1D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x12, 0x66, 0x69, 0x62, 0x62, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x73, 0x6C, 0x6F, 0x74,
    0x2D, 0x39, 0x63, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x36, 0x30, 0x31, 0x31, 0x39, 0x31,
    0x34, 0x35, 0x31, 0x5A, 0x18, 0x0F, 0x32, 0x31, 0x32, 0x36, 0x30, 0x35, 0x30, 0x38, 0x31, 0x39,
    0x31, 0x34, 0x35, 0x31, 0x5A, 0x30, 0x1D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x12, 0x66, 0x69, 0x62, 0x62, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x73, 0x6C, 0x6F,
    0x74, 0x2D, 0x39, 0x63, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xBA,
    0x37, 0x10, 0xC3, 0xF9, 0xFF, 0x6E, 0x02, 0x84, 0xF5, 0x0B, 0x8A, 0x6A, 0x7F, 0x69, 0x38, 0xF2,
    0xB9, 0x92, 0x5D, 0x95, 0x02, 0xAF, 0x92, 0xB2, 0xB9, 0x5D, 0xC7, 0x22, 0x3B, 0x46, 0x60, 0x91,
    0xFD, 0x83, 0xEB, 0xF9, 0xE2, 0x45, 0x6C, 0x67, 0x45, 0x19, 0xFA, 0xFB, 0x20, 0x3C, 0xE5, 0xBE,
    0x68, 0x53, 0xFE, 0x33, 0x17, 0x33, 0x60, 0xF0, 0x34, 0x8D, 0x67, 0x20, 0xE6, 0x2E, 0x89, 0xA3,
    0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x7B, 0x6C,
    0x46, 0xA8, 0x2B, 0x6A, 0xC6, 0x2A, 0x82, 0xCB, 0xA6, 0xB4, 0x89, 0xD3, 0xF5, 0x54, 0x2D, 0x41,
    0x17, 0x60, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x7B,
    0x6C, 0x46, 0xA8, 0x2B, 0x6A, 0xC6, 0x2A, 0x82, 0xCB, 0xA6, 0xB4, 0x89, 0xD3, 0xF5, 0x54, 0x2D,
    0x41, 0x17, 0x60, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x38, 0xB3, 0xD0, 0xF9, 0x38, 0xC0, 0xB2, 0x04, 0xF0,
    0x21, 0x17, 0x2D, 0x7D, 0xE5, 0x99, 0x98, 0x72, 0xB8, 0x1F, 0x94, 0xEA, 0xC5, 0xDE, 0x7D, 0xCB,
    0xC9, 0xBA, 0x97, 0xD5, 0xC0, 0x94, 0x82, 0x02, 0x20, 0x12, 0x7F, 0x90, 0xB3, 0xAD, 0x84, 0x2C,
    0xA5, 0xC1, 0xE8, 0x05, 0x0E, 0x27, 0x98, 0x39, 0x1D, 0xB1, 0xEF, 0x44, 0xF4, 0x39, 0x84, 0xB4,
    0x44, 0x0C, 0x91, 0xE8, 0xB5, 0x78, 0xC5, 0x8E, 0x65, 0x71, 0x01, 0x00, 0xFE, 0x00,
];

/// PIV tag for the Card Holder Unique Identifier (CHUID) data object,
/// per SP 800-73-4 §3.1.2: `5F C1 02`.
const TAG_CHUID: &[u8] = &[0x5F, 0xC1, 0x02];

/// Canonical CHUID object, captured from the YubiKey 4 throwaway during
/// the 2026-05-31 wet-env init (`tests/fixtures/apdu/yk4-init.fixture`,
/// the GET DATA 5F C1 02 response). A real CHUID is needed because
/// clients treat a card with no CHUID as *uninitialized*: `pivy-tool
/// list` reports `guid: 0000…` / "needs initialization", and piggy's
/// `PivToken::connect` → `read_chuid` (pivy-piv) errors outright, so
/// `piggy-ids detect-pubkey` / `piggy pass init` see "no PIV cards".
/// Seeding this makes VirtualCard a detectable, initialized card with a
/// stable GUID (`19 17 55 CF … BE B1`, tag 0x34) — required for the
/// SSH-over-fibby decrypt store setup (piggy#135 Phase D).
///
/// Wraps `53 39 30 19 <FASC-N> 34 10 <GUID> 35 08 <expiry> 3E 00`. The
/// FASC-N / GUID / expiry are the throwaway card's real (public, not
/// sensitive) values — a CHUID carries no key material.
const CANONICAL_REAL_CARD_CHUID: &[u8] = &[
    0x53, 0x39, 0x30, 0x19, 0xD0, 0x42, 0x10, 0xD8, 0x21, 0x08, 0x6C, 0x10, 0x84, 0x21, 0x0D, 0x83,
    0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB, 0x34, 0x10, 0x19,
    0x17, 0x55, 0xCF, 0xF3, 0x9E, 0xFE, 0x52, 0x2C, 0x07, 0xA3, 0x83, 0x27, 0x5B, 0xBE, 0xB1, 0x35,
    0x08, 0x32, 0x30, 0x33, 0x36, 0x30, 0x35, 0x32, 0x38, 0x3E, 0x00,
];

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

    /// Pre-populate a single PIV data object — used by the replay
    /// test bed to seed VirtualCard with state that real silicon
    /// had established before the captured session started. `tag` is
    /// the bare tag bytes (no `5C` wrapper); `payload` is the bytes
    /// the wire returned between the response opening and the trailing
    /// SW 9000. For object data this is `53 <len> <value>` (CHUID,
    /// CCC, slot certs); for the Discovery Object (SP 800-73-4
    /// §3.3.2) it's `7E <len> <value>`. `handle_get_data` echoes
    /// these bytes verbatim, so any leading tag the captured wire
    /// shows is preserved.
    ///
    /// In production, callers should use PUT DATA. This method
    /// bypasses the auth check that PUT DATA would eventually
    /// enforce, so reserve it for test scaffolding.
    pub fn seed_data_object(&mut self, tag: Vec<u8>, payload: Vec<u8>) {
        self.data_objects.insert(tag, payload);
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
            slot_9a_priv: None,
            slot_9d_priv: None,
            slot_9c_priv: None,
            mgmt_key: DEFAULT_MGMT_KEY,
            pending_mgmt_witness: None,
        }
    }

    /// Seed the next mgmt-key auth phase-1's witness bytes. The
    /// dispatcher will return these exact 8 bytes inside `7C 0A 81
    /// 08 <witness>` instead of the default zero-filled witness.
    /// Reserved for replay tests that pin against a captured wire
    /// (see the piggy#134 pattern). Cleared after one read; subsequent
    /// phase-1 requests fall back to the zero default.
    pub fn seed_mgmt_key_witness(&mut self, witness: [u8; 8]) {
        self.pending_mgmt_witness = Some(witness);
    }

    /// Override the 24-byte TripleDES mgmt-key. Reserved for replay
    /// tests that capture against a rotated mgmt-key; the default is
    /// the YubiKey factory constant.
    pub fn seed_mgmt_key(&mut self, key: [u8; 24]) {
        self.mgmt_key = key;
    }

    /// Install the canonical fibby slot 9A test cert under PIV tag
    /// `5F C1 05` **and** the matching RFC 6979 §A.2.5 private scalar
    /// into slot 9A. After this, GET DATA for the slot 9A cert tag
    /// returns the pinned cert object (`53 …`) instead of the
    /// empty-slot 6A82, and GA ECDSA (INS 0x87, P1=0x11, P2=0x9A) signs
    /// with the key the cert is over. Subscriber: pivy-agent's
    /// identity-listing flow exposes one SSH identity backed by the
    /// RFC 6979 §A.2.5 public point, and that identity can sign — the
    /// cert and key are a matched pair, so seeding one without the
    /// other would yield a non-functional identity.
    ///
    /// See [`RFC6979_SLOT_9A_CERT_OBJECT`] for the cert byte layout and
    /// regeneration recipe, and [`RFC6979_A2_5_PRIV`] for the scalar.
    pub fn seed_rfc6979_slot_9a_cert(&mut self) {
        self.seed_data_object(
            TAG_SLOT_9A_CERT.to_vec(),
            RFC6979_SLOT_9A_CERT_OBJECT.to_vec(),
        );
        self.seed_slot_9a_priv(RFC6979_A2_5_PRIV);
    }

    /// Install the canonical fibby slot 9D test cert under PIV tag
    /// `5F C1 0B` **and** the matching RFC 5903 §8.1 private scalar into
    /// slot 9D. After this, GET DATA for the slot 9D cert tag returns the
    /// pinned cert object, and GA ECDH (INS 0x87, P1=0x11, P2=0x9D)
    /// computes `scalar * client_eph_pub`. Subscriber: pivy-agent's
    /// enumeration exposes a slot-9D key-management identity backed by
    /// the §8.1 public point, so `pivy-box stream decrypt` can ECDH
    /// against it over a (possibly SSH-forwarded) agent. Cert and key are
    /// a matched pair — seeding one without the other yields a
    /// non-functional identity.
    ///
    /// See [`RFC5903_SLOT_9D_CERT_OBJECT`] for the cert byte layout /
    /// regeneration recipe and [`RFC5903_SLOT_9D_PRIV`] for the scalar.
    pub fn seed_rfc5903_slot_9d_cert(&mut self) {
        self.seed_data_object(
            TAG_SLOT_9D_CERT.to_vec(),
            RFC5903_SLOT_9D_CERT_OBJECT.to_vec(),
        );
        self.seed_slot_9d_priv(RFC5903_SLOT_9D_PRIV);
        // A 9D recipient is only reachable if clients see an *initialized*
        // card; without a CHUID, pivy-piv's read_chuid errors and
        // `piggy-ids detect-pubkey` / `piggy pass init` report no card.
        self.seed_chuid();
    }

    /// Install fibby's slot 9C (Digital Signature) test cert under PIV tag
    /// `5F C1 0A` **and** the matching [`FIBBY_SLOT_9C_TEST_PRIV`] scalar
    /// into slot 9C. After this, GET DATA for the slot 9C cert tag returns
    /// the pinned cert object, and GA ECDSA (INS 0x87, P1=0x11, P2=0x9C)
    /// signs with the key the cert is over (under the PIN-always policy —
    /// each sign consumes the PIN verification). Subscriber: pivy-agent's
    /// identity-listing flow exposes one SSH identity backed by the
    /// slot-9C public point, and that identity can sign — cert and key are
    /// a matched pair. No CHUID is seeded (the agent enumeration/sign path
    /// doesn't need it, mirroring [`Self::seed_rfc6979_slot_9a_cert`];
    /// only the piggy `detect-pubkey` ECDH path requires a CHUID).
    pub fn seed_fibby_slot_9c_cert(&mut self) {
        self.seed_data_object(
            TAG_SLOT_9C_CERT.to_vec(),
            FIBBY_SLOT_9C_CERT_OBJECT.to_vec(),
        );
        self.seed_slot_9c_priv(FIBBY_SLOT_9C_TEST_PRIV);
    }

    /// Install the canonical CHUID ([`CANONICAL_REAL_CARD_CHUID`]) under
    /// PIV tag `5F C1 02`, making VirtualCard present as an *initialized*
    /// card with a stable GUID. Without it, clients that key off the
    /// CHUID (pivy-tool, pivy-piv's `read_chuid`) treat the card as
    /// uninitialized and won't enumerate its slots. Idempotent; reserved
    /// for test scaffolding (bypasses the mgmt-key auth a real
    /// `pivy-tool init` PUT DATA would require).
    pub fn seed_chuid(&mut self) {
        self.seed_data_object(TAG_CHUID.to_vec(), CANONICAL_REAL_CARD_CHUID.to_vec());
    }

    /// Install a P-256 scalar into slot 9A (PIV Authentication, the
    /// SSH-auth signing slot). The scalar is the 32-byte big-endian raw
    /// secret (no PKCS-#8 / SEC1 wrapping). Subsequent GA ECDSA requests
    /// (INS 0x87, P1=0x11, P2=0x9A) sign the client-supplied prehash
    /// under RFC 6979 deterministic ECDSA.
    ///
    /// Mirrors [`Self::seed_slot_9d_priv`]: bypasses the mgmt-key auth a
    /// real GENERATE / import flow would require, so reserve it for test
    /// scaffolding (or the CLI seed flag, piggy#135).
    pub fn seed_slot_9a_priv(&mut self, scalar: [u8; 32]) {
        self.slot_9a_priv = Some(scalar);
    }

    /// Install a P-256 scalar into slot 9D. The scalar is the 32-byte
    /// big-endian raw secret (no PKCS-#8 / SEC1 wrapping). Subsequent
    /// GA ECDH requests (INS 0x87, P1=0x11, P2=0x9D) compute
    /// `scalar * client_eph_pub` and return the X-coordinate.
    ///
    /// Mirrors `seed_data_object` semantics: bypasses the mgmt-key auth
    /// that a real GENERATE / import flow would require. Reserved for
    /// test scaffolding — specifically the piggy#134 byte-deterministic
    /// replay pattern where the same RFC 6979 §A.2.5 scalar is imported
    /// into a throwaway YubiKey and into VirtualCard, so the wire
    /// capture matches VirtualCard's response byte-for-byte.
    pub fn seed_slot_9d_priv(&mut self, scalar: [u8; 32]) {
        self.slot_9d_priv = Some(scalar);
    }

    /// Install a P-256 scalar into slot 9C (Digital Signature). The scalar
    /// is the 32-byte big-endian raw secret. Subsequent GA ECDSA requests
    /// (INS 0x87, P1=0x11, P2=0x9C) sign the client-supplied prehash under
    /// RFC 6979 deterministic ECDSA, consuming the PIN verification each
    /// time (PIN-always policy). Mirrors [`Self::seed_slot_9a_priv`].
    pub fn seed_slot_9c_priv(&mut self, scalar: [u8; 32]) {
        self.slot_9c_priv = Some(scalar);
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
        // Same power-cycle semantics for mgmt-key witnesses: any
        // outstanding phase-1 challenge is invalidated.
        self.pending_mgmt_witness = None;
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

        // YubiKey vendor GET SERIAL (00 F8 00 00 ...). YK4 firmware
        // doesn't implement this and returns 6D00; YK5 returns a
        // 4-byte serial + SW 9000. We delegate to `Model::serial()`
        // to decide. P1 P2 must be 00 00; otherwise fall through to
        // the catch-all 6D00 (no wet-env evidence for what real
        // silicon does on non-standard P1/P2 here, so default-to-
        // 6D00 keeps the diagnostic honest).
        if cla == 0x00 && ins == apdu::ins::YK_SERIAL && p1 == 0x00 && p2 == 0x00 {
            match self.model.serial() {
                Some(serial) => {
                    trace::emit(
                        trace::DEBUG,
                        "vcard",
                        &format!(
                            "YK SERIAL -> {:02X}{:02X}{:02X}{:02X} 9000",
                            serial[0], serial[1], serial[2], serial[3]
                        ),
                    );
                    let mut out = serial.to_vec();
                    out.extend_from_slice(&sw(0x90, 0x00));
                    return Ok(out);
                }
                None => {
                    trace::emit(
                        trace::DEBUG,
                        "vcard",
                        "YK SERIAL -> 6D00 (not supported by model)",
                    );
                    return Ok(sw(0x6D, 0x00));
                }
            }
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

        // GENERAL AUTHENTICATE (00 87 <alg> <slot> <Lc> 7C ...). Slot 9D
        // ECDH (alg=0x11, slot=0x9D) is the piggy decrypt path; slots 9A
        // and 9C ECDSA (alg=0x11, slot=0x9A / 0x9C) are the SSH-auth and
        // digital-signature signing paths. The mgmt-key challenge-response
        // (alg=0x03, slot=0x9B) is handled below.
        if cla == 0x00 && ins == apdu::ins::GENERAL_AUTHENTICATE && p1 == 0x11 && p2 == 0x9D {
            return Ok(self.handle_general_authenticate_ecdh_slot_9d(apdu_body(command_apdu)));
        }

        // GENERAL AUTHENTICATE ECDSA sign (alg=0x11 P-256). The request
        // carries the host-computed prehash in the 81 (CHALLENGE) tag; we
        // return the DER ECDSA signature in the 82 (RESPONSE) tag. This is
        // pivy/piggy-agent's KEYREQ_SIGN path; see piv.c::piv_sign_prehash.
        // Slot 9A (SSH auth) is PIN policy "once"; slot 9C (Digital
        // Signature) is PIN policy "always" — each sign consumes the PIN
        // verification (consume_pin = true).
        if cla == 0x00 && ins == apdu::ins::GENERAL_AUTHENTICATE && p1 == 0x11 && p2 == 0x9A {
            let scalar = self.slot_9a_priv;
            return Ok(self.sign_ecdsa_slot(apdu_body(command_apdu), scalar, "9A", false));
        }
        if cla == 0x00 && ins == apdu::ins::GENERAL_AUTHENTICATE && p1 == 0x11 && p2 == 0x9C {
            let scalar = self.slot_9c_priv;
            return Ok(self.sign_ecdsa_slot(apdu_body(command_apdu), scalar, "9C", true));
        }

        // GENERAL AUTHENTICATE mgmt-key challenge-response (00 87 03
        // 9B). P1=0x03 selects TripleDES-EDE3, P2=0x9B addresses the
        // mgmt-key. Two-phase: phase-1 request body is `7C 02 81 00`
        // (the client asking the card for an 8-byte witness); phase-2
        // request body is `7C 0A 82 08 <client-response>` (the client
        // returning the TDES-encrypted witness). See SP 800-73-4
        // §3.2.4 and the yk4-init.fixture wire.
        if cla == 0x00 && ins == apdu::ins::GENERAL_AUTHENTICATE && p1 == 0x03 && p2 == 0x9B {
            return Ok(self.handle_general_authenticate_mgmt_key(apdu_body(command_apdu)));
        }

        // YK ATTEST (00 F9 <slot> 00 ...). Real silicon returns a
        // YubicoPIV-signed cert when the slot key was generated on-
        // card and 6A80 when the key was imported. VirtualCard models
        // only imported / empty slots (no factory attestation key,
        // no on-card generate flow yet), so 6A80 is the byte-correct
        // response in every case VirtualCard actually exercises today
        // — matches both test-vector fixtures' F9 pair. P1 carries
        // the slot reference; P2 must be 00.
        if cla == 0x00 && ins == apdu::ins::YK_ATTEST && p2 == 0x00 {
            trace::emit(
                trace::DEBUG,
                "vcard",
                &format!("YK ATTEST slot={p1:#04x} -> 6A80 (imported-key default)"),
            );
            return Ok(sw(0x6A, 0x80));
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

    /// Handle a `GENERAL AUTHENTICATE` mgmt-key challenge-response
    /// exchange (INS 0x87, P1=0x03 TripleDES, P2=0x9B mgmt-key).
    ///
    /// Two phases, decoded from the body's inner TLV tag:
    ///
    /// - **Phase 1 (witness request)** — body `7C 02 81 00`. Returns
    ///   `7C 0A 81 08 <witness>` + 9000, where `<witness>` is either
    ///   the value seeded via [`Self::seed_mgmt_key_witness`] (for
    ///   replay tests pinning against a captured wire) or 8 zero
    ///   bytes when nothing was seeded.
    /// - **Phase 2 (witness response)** — body `7C 0A 82 08 <enc>`.
    ///   TripleDES-decrypts `<enc>` with `self.mgmt_key`; if the
    ///   plaintext matches `self.pending_mgmt_witness`, returns
    ///   9000. Wrong response → 6982; no outstanding witness → 6982.
    ///
    /// Any other body shape → 6A80. The pending witness is cleared
    /// on phase-2 completion (success or failure), mirroring real
    /// silicon's one-shot semantics.
    fn handle_general_authenticate_mgmt_key(&mut self, body: Option<&[u8]>) -> Vec<u8> {
        use cipher::{BlockDecrypt, KeyInit};
        let body = match body {
            Some(b) => b,
            None => return sw(0x6A, 0x80),
        };
        // Phase 1: request witness. Body `7C 02 81 00`.
        if body == [0x7C, 0x02, 0x81, 0x00] {
            let witness = self.pending_mgmt_witness.unwrap_or([0u8; 8]);
            self.pending_mgmt_witness = Some(witness);
            trace::emit(
                trace::DEBUG,
                "vcard",
                &format!("GA mgmt-key phase-1 witness={:02X?} -> 9000", witness),
            );
            let mut out = Vec::with_capacity(4 + 8 + 2);
            out.extend_from_slice(&[0x7C, 0x0A, 0x81, 0x08]);
            out.extend_from_slice(&witness);
            out.extend_from_slice(&sw(0x90, 0x00));
            return out;
        }
        // Phase 2: verify response. Body `7C 0A 82 08 <enc>`.
        if body.len() == 12 && body.starts_with(&[0x7C, 0x0A, 0x82, 0x08]) {
            let enc: [u8; 8] = body[4..12].try_into().expect("checked len");
            let witness = match self.pending_mgmt_witness.take() {
                Some(w) => w,
                None => {
                    trace::emit(
                        trace::DEBUG,
                        "vcard",
                        "GA mgmt-key phase-2 -> 6982 (no outstanding witness)",
                    );
                    return sw(0x69, 0x82);
                }
            };
            // Real PIV mgmt-key auth: client encrypts the card-supplied
            // witness with the mgmt-key; card decrypts and compares.
            let cipher = des::TdesEde3::new(&self.mgmt_key.into());
            let mut block = enc;
            cipher.decrypt_block((&mut block).into());
            if block == witness {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    "GA mgmt-key phase-2 -> 9000 (verified)",
                );
                sw(0x90, 0x00)
            } else {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    "GA mgmt-key phase-2 -> 6982 (witness mismatch)",
                );
                sw(0x69, 0x82)
            }
        } else {
            trace::emit(
                trace::DEBUG,
                "vcard",
                "GA mgmt-key -> 6A80 (unrecognized body)",
            );
            sw(0x6A, 0x80)
        }
    }

    /// Handle a `GENERAL AUTHENTICATE` (INS 0x87) for the ECDH key
    /// agreement use case on slot 9D, P-256.
    ///
    /// Wire shape per SP 800-73-4 §3.2.4 + the wet-env captures
    /// (`crates/fibby/tests/fixtures/apdu/yk4-test-vector-roundtrip*
    /// .fixture`):
    ///
    /// - Request body: `7C <len> 82 00 85 <len2> 04 <Xeph 32B>
    ///   <Yeph 32B>`. The `82 00` is an empty response template (the
    ///   client asking the card to fill it in); `85` is the
    ///   exponentiation parameter holding the client's ephemeral
    ///   uncompressed P-256 point. `<len2>` is `0x41` (65 = 1 prefix
    ///   + 32 X + 32 Y).
    /// - Response: `7C 22 82 20 <Xshared 32B>` + SW 9000, where
    ///   `Xshared = (scalar * eph_pub).x`, zero-padded big-endian to
    ///   32 bytes.
    ///
    /// Status words:
    ///
    /// - `69 82` (security status not satisfied): PIN not verified.
    /// - `6A 88` (referenced data not found): slot 9D is empty (no
    ///   key installed; see [`Self::seed_slot_9d_priv`]).
    /// - `6A 80` (incorrect parameters in data field): malformed
    ///   request body or invalid ephemeral point.
    /// - `90 00` + `7C 22 82 20 <X>` on success.
    ///
    /// Reads the scalar from `self.slot_9d_priv` and uses
    /// `p256::ecdh::diffie_hellman` for the math, whose output is the
    /// raw X-coordinate in the exact byte form real silicon emits.
    fn handle_general_authenticate_ecdh_slot_9d(&mut self, body: Option<&[u8]>) -> Vec<u8> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::{EncodedPoint, NonZeroScalar, PublicKey};

        if !self.pin_verified {
            trace::emit(
                trace::DEBUG,
                "vcard",
                "GA ECDH 9D -> 6982 (PIN not verified)",
            );
            return sw(0x69, 0x82);
        }
        let scalar_bytes = match self.slot_9d_priv {
            Some(s) => s,
            None => {
                trace::emit(trace::DEBUG, "vcard", "GA ECDH 9D -> 6A88 (slot empty)");
                return sw(0x6A, 0x88);
            }
        };
        let body = match body {
            Some(b) => b,
            None => {
                trace::emit(trace::DEBUG, "vcard", "GA ECDH 9D -> 6A80 (no body)");
                return sw(0x6A, 0x80);
            }
        };
        let eph_pub_bytes = match parse_ga_ecdh_request(body) {
            Some(b) => b,
            None => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    "GA ECDH 9D -> 6A80 (malformed 7C/85 TLV)",
                );
                return sw(0x6A, 0x80);
            }
        };
        let eph_point = match EncodedPoint::from_bytes(eph_pub_bytes) {
            Ok(p) => p,
            Err(_) => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    "GA ECDH 9D -> 6A80 (bad SEC1 encoding)",
                );
                return sw(0x6A, 0x80);
            }
        };
        let eph_pub: PublicKey = match Option::from(PublicKey::from_encoded_point(&eph_point)) {
            Some(pk) => pk,
            None => {
                trace::emit(trace::DEBUG, "vcard", "GA ECDH 9D -> 6A80 (not on curve)");
                return sw(0x6A, 0x80);
            }
        };
        let scalar = match NonZeroScalar::try_from(&scalar_bytes[..]) {
            Ok(s) => s,
            Err(_) => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    "GA ECDH 9D -> 6A88 (slot scalar invalid)",
                );
                return sw(0x6A, 0x88);
            }
        };
        let shared = p256::ecdh::diffie_hellman(scalar, eph_pub.as_affine());
        let x = shared.raw_secret_bytes();
        debug_assert_eq!(x.len(), 32);
        let mut out = Vec::with_capacity(2 + 2 + 32 + 2);
        out.push(0x7C);
        out.push(0x22);
        out.push(0x82);
        out.push(0x20);
        out.extend_from_slice(x);
        out.extend_from_slice(&sw(0x90, 0x00));
        trace::emit(
            trace::DEBUG,
            "vcard",
            &format!("GA ECDH 9D -> 9000 (X[0]={:02X} X[31]={:02X})", x[0], x[31]),
        );
        out
    }

    /// Shared `GENERAL AUTHENTICATE` ECDSA sign handler for the signing
    /// slots (9A SSH-auth, 9C Digital Signature). INS 0x87, P1=0x11 P-256.
    /// The client supplies a host-computed prehash in the `81` (CHALLENGE)
    /// tag; we return the DER-encoded ECDSA signature in the `82`
    /// (RESPONSE) tag. Wire shape mirrors `piv.c::piv_sign_prehash`.
    ///
    /// `scalar` is the slot's key (read by the dispatcher); `slot_label` is
    /// the trace label ("9A" / "9C"); `consume_pin` selects the PIN policy:
    /// - `false` (slot 9A, policy "once"): leave `pin_verified` set.
    /// - `true` (slot 9C, policy "always"): clear `pin_verified` after a
    ///   successful sign, so the next PIN-gated op needs a fresh VERIFY.
    ///   This is the conservative model of YubiKey's "always" policy —
    ///   exact global-vs-per-slot semantics on real silicon are unverified;
    ///   here the verification is treated as consumed by the sign.
    ///
    /// Returns:
    /// - `69 82` if the PIN is not verified.
    /// - `6A 88` if the slot is empty (no scalar seeded) or the scalar is
    ///   invalid.
    /// - `6A 80` on a missing/malformed request body.
    /// - `7C <len> 82 <len> <DER sig>` + `90 00` on success.
    ///
    /// Signing is **RFC 6979 deterministic** (`p256`'s `sign_prehash`), so
    /// VirtualCard's output is reproducible. Real silicon randomizes `k`,
    /// so a sign capture is *not* byte-replayable — tests verify the
    /// signature against the public key instead (piggy#135).
    fn sign_ecdsa_slot(
        &mut self,
        body: Option<&[u8]>,
        scalar: Option<[u8; 32]>,
        slot_label: &str,
        consume_pin: bool,
    ) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey};

        if !self.pin_verified {
            trace::emit(
                trace::DEBUG,
                "vcard",
                &format!("GA ECDSA {slot_label} -> 6982 (PIN not verified)"),
            );
            return sw(0x69, 0x82);
        }
        let scalar_bytes = match scalar {
            Some(s) => s,
            None => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GA ECDSA {slot_label} -> 6A88 (slot empty)"),
                );
                return sw(0x6A, 0x88);
            }
        };
        let body = match body {
            Some(b) => b,
            None => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GA ECDSA {slot_label} -> 6A80 (no body)"),
                );
                return sw(0x6A, 0x80);
            }
        };
        let challenge = match parse_ga_sign_request(body) {
            Some(c) => c,
            None => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GA ECDSA {slot_label} -> 6A80 (malformed 7C/81 TLV)"),
                );
                return sw(0x6A, 0x80);
            }
        };
        let signing_key = match SigningKey::from_slice(&scalar_bytes) {
            Ok(k) => k,
            Err(_) => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GA ECDSA {slot_label} -> 6A88 (slot scalar invalid)"),
                );
                return sw(0x6A, 0x88);
            }
        };
        let sig: Signature = match signing_key.sign_prehash(challenge) {
            Ok(s) => s,
            Err(_) => {
                trace::emit(
                    trace::DEBUG,
                    "vcard",
                    &format!("GA ECDSA {slot_label} -> 6A80 (sign failed)"),
                );
                return sw(0x6A, 0x80);
            }
        };
        // The card returns the ASN.1 `ECDSA-Sig-Value` (SEQUENCE { r, s })
        // under the GA `82` (RESPONSE) tag — the same DER pivy parses out
        // in piv_sign_prehash.
        let der = sig.to_der();
        let der = der.as_bytes();

        let mut inner = Vec::with_capacity(2 + der.len());
        inner.push(0x82); // GA RESPONSE tag (SP 800-73-4 dynamic auth)
        push_ber_len(&mut inner, der.len());
        inner.extend_from_slice(der);

        let mut out = Vec::with_capacity(3 + inner.len() + 2);
        out.push(0x7C);
        push_ber_len(&mut out, inner.len());
        out.extend_from_slice(&inner);
        out.extend_from_slice(&sw(0x90, 0x00));

        // PIN-always (slot 9C): the sign consumes the PIN verification.
        if consume_pin {
            self.pin_verified = false;
        }

        trace::emit(
            trace::DEBUG,
            "vcard",
            &format!("GA ECDSA {slot_label} -> 9000 ({}-byte DER sig)", der.len()),
        );
        out
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

/// Parse a `GENERAL AUTHENTICATE` ECDH request body and return the
/// raw ephemeral SEC1-uncompressed P-256 point (65 bytes: `04 ‖ X ‖ Y`).
///
/// Expected shape: `7C <len> 82 00 85 <len2> 04 <Xeph 32B> <Yeph 32B>`
/// where `<len>` is BER short or 0x81 long. The `82 00` is a
/// zero-length response-template placeholder. The `85` is the
/// dynamic-authentication "exponentiation parameter" carrying the
/// client's ephemeral public point.
///
/// Returns `None` on any structural error. Does not validate that
/// the point is on the curve — leave that to `EncodedPoint`.
fn parse_ga_ecdh_request(body: &[u8]) -> Option<&[u8]> {
    if body.first()? != &0x7C {
        return None;
    }
    let (inner_offset, inner_len) = ber_len(&body[1..])?;
    let inner_start = 1 + inner_offset;
    if body.len() < inner_start + inner_len {
        return None;
    }
    let inner = &body[inner_start..inner_start + inner_len];
    let mut cur = inner;
    while !cur.is_empty() {
        let tag = *cur.first()?;
        let (len_offset, len) = ber_len(&cur[1..])?;
        let value_start = 1 + len_offset;
        if cur.len() < value_start + len {
            return None;
        }
        let value = &cur[value_start..value_start + len];
        if tag == 0x85 {
            // SEC1 uncompressed: 65 bytes, leading 0x04.
            if value.len() == 65 && value[0] == 0x04 {
                return Some(value);
            }
            return None;
        }
        cur = &cur[value_start + len..];
    }
    None
}

/// Parse a `GENERAL AUTHENTICATE` ECDSA sign request body and return the
/// challenge bytes (the host-computed prehash to sign).
///
/// Expected shape: `7C <len> 82 00 81 <len2> <prehash>` — the `82 00` is
/// the empty response-template placeholder asking the card for a
/// signature, and the `81` (CHALLENGE) tag carries the digest. Mirrors
/// `parse_ga_ecdh_request` but matches tag `0x81` and accepts a value of
/// any length (the digest width is the caller's choice, typically 32 B
/// SHA-256; we do not constrain it). Returns `None` on structural error.
fn parse_ga_sign_request(body: &[u8]) -> Option<&[u8]> {
    if body.first()? != &0x7C {
        return None;
    }
    let (inner_offset, inner_len) = ber_len(&body[1..])?;
    let inner_start = 1 + inner_offset;
    if body.len() < inner_start + inner_len {
        return None;
    }
    let inner = &body[inner_start..inner_start + inner_len];
    let mut cur = inner;
    while !cur.is_empty() {
        let tag = *cur.first()?;
        let (len_offset, len) = ber_len(&cur[1..])?;
        let value_start = 1 + len_offset;
        if cur.len() < value_start + len {
            return None;
        }
        let value = &cur[value_start..value_start + len];
        if tag == 0x81 {
            if value.is_empty() {
                return None;
            }
            return Some(value);
        }
        cur = &cur[value_start + len..];
    }
    None
}

/// Append a BER-TLV definite length to `out`: short form for `len < 128`,
/// one-byte long form (`81 xx`) for `128..256`, two-byte (`82 xx xx`)
/// otherwise. Used to wrap the variable-width DER ECDSA signature in the
/// `7C`/`82` response template (the ECDH handler hard-codes its lengths
/// because the X-coordinate output is fixed-width; sign output is not).
fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// Parse a BER-TLV length octet sequence at the front of `bytes`,
/// returning `(bytes_consumed_for_length, length_value)`. Supports
/// short form (length 0-127 in one byte) and 0x81 long form
/// (128-255 in one length byte). Returns `None` for 0x82+ — real
/// PIV objects in our wire fit in one length byte. Mirrors
/// `split_53_tlv`'s discipline.
fn ber_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        Some((1, first as usize))
    } else if first == 0x81 {
        Some((2, *bytes.get(1)? as usize))
    } else {
        None
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

    // TAG_CHUID is now a module-level const (see CANONICAL_REAL_CARD_CHUID);
    // imported via `use super::*`.
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

    // -- YubiKey vendor INS 0xF8 (serial) tests ----------------------

    #[test]
    fn yk_serial_returns_6d00_on_yk4_matching_real_silicon() {
        let mut c = VirtualCard::with_model(Model::Yk4);
        // Both short-form `00 F8 00 00 00` (fib-style) and extended-
        // length `00 F8 00 00 00 00 00` (YK4-style) should return 6D00
        // on a YK4 model. Captures showed the YK4 firmware doesn't
        // implement this vendor extension.
        for apdu in [
            vec![0x00, 0xF8, 0x00, 0x00, 0x00],
            vec![0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            let resp = c.transmit(&apdu).unwrap();
            assert_eq!(resp, vec![0x6D, 0x00], "Yk4 INS 0xF8 must return 6D00");
        }
    }

    #[test]
    fn yk_serial_returns_captured_value_on_yk5() {
        let mut c = VirtualCard::with_model(Model::Yk5);
        let resp = c
            .transmit(&[0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
        // 00 F2 C2 E6 + 9000 — byte-equal to the primary YubiKey 5's
        // captured wire response.
        assert_eq!(resp, vec![0x00, 0xF2, 0xC2, 0xE6, 0x90, 0x00]);
    }

    #[test]
    fn model_serial_for_yk4_is_none() {
        assert_eq!(Model::Yk4.serial(), None);
    }

    #[test]
    fn model_serial_for_yk5_is_primary_capture() {
        assert_eq!(Model::Yk5.serial(), Some([0x00, 0xF2, 0xC2, 0xE6]));
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

    // -- GA ECDH (slot 9D, P-256) tests ----------------------------------

    /// RFC 6979 §A.2.5 P-256 private scalar, big-endian. Same scalar
    /// imported into the throwaway YubiKey 4 slot 9D for the wet-env
    /// captures under `tests/fixtures/captures/yubikey/test-vector/`,
    /// and the keypair the canonical slot-9A cert is over. Aliases the
    /// module const so there is one source of truth for these bytes.
    const RFC6979_SCALAR: [u8; 32] = RFC6979_A2_5_PRIV;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn ga_ecdh_slot_9d_without_pin_verify_returns_6982() {
        let mut c = VirtualCard::new();
        c.seed_slot_9d_priv(RFC6979_SCALAR);
        // Capture #1 GA ECDH request bytes (extended-length Lc).
        let req = hex_to_bytes(
            "0087119d0000477c458200854104b3ef72daa94a55f409e495f654f234fb8f9730fa66923e7e45a910bb9773535e5d9a77be8d9f0968e7fb008cf9c156d7d468fbecb573e17801e2d441486b9f860000",
        );
        let resp = c.transmit(&req).unwrap();
        assert_eq!(resp, vec![0x69, 0x82], "PIN not verified -> 6982");
    }

    #[test]
    fn ga_ecdh_slot_9d_without_key_returns_6a88() {
        let mut c = VirtualCard::new();
        c.pin_verified = true;
        let req = hex_to_bytes(
            "0087119d0000477c458200854104b3ef72daa94a55f409e495f654f234fb8f9730fa66923e7e45a910bb9773535e5d9a77be8d9f0968e7fb008cf9c156d7d468fbecb573e17801e2d441486b9f860000",
        );
        let resp = c.transmit(&req).unwrap();
        assert_eq!(resp, vec![0x6A, 0x88], "slot 9D empty -> 6A88");
    }

    /// Byte-deterministic replay of the wet-env GA ECDH pair from
    /// `yk4-test-vector-roundtrip.fixture` (capture #1, yubico-piv-tool
    /// import bootstrap). The card's response is purely a function of
    /// the slot scalar (RFC 6979 §A.2.5) and the client's ephemeral
    /// public key (carried in the request body), so VirtualCard must
    /// reproduce it byte-for-byte.
    #[test]
    fn ga_ecdh_slot_9d_matches_wet_env_capture_yubico_piv_tool_bootstrap() {
        let mut c = VirtualCard::new();
        c.seed_slot_9d_priv(RFC6979_SCALAR);
        c.pin_verified = true;
        let req = hex_to_bytes(
            "0087119d0000477c458200854104b3ef72daa94a55f409e495f654f234fb8f9730fa66923e7e45a910bb9773535e5d9a77be8d9f0968e7fb008cf9c156d7d468fbecb573e17801e2d441486b9f860000",
        );
        let expected = hex_to_bytes(
            "7c22822047e03668154b982a23f935f0ac074cb306cb94860073ebc10b92ddcc289e96f29000",
        );
        assert_eq!(c.transmit(&req).unwrap(), expected);
    }

    /// Companion to the yubico-piv-tool capture replay: the
    /// pivy-tool-bootstrapped capture (#58) uses a different ephemeral
    /// pub but the same slot scalar, so the deterministic X-coord
    /// response differs. Both fixtures together verify that
    /// VirtualCard's ECDH math is correct under independent client
    /// inputs, not just one frozen pair.
    #[test]
    fn ga_ecdh_slot_9d_matches_wet_env_capture_pivy_tool_bootstrap() {
        let mut c = VirtualCard::new();
        c.seed_slot_9d_priv(RFC6979_SCALAR);
        c.pin_verified = true;
        let req = hex_to_bytes(
            "0087119d0000477c458200854104b47f3c10ff4444e640a4837b83d1b600f1dd60e98df6c778116f219670166705f3dd289073c4090ce100001d2a5eae3faa9104f59e1d372f6b068702f0ec42cb0000",
        );
        let expected = hex_to_bytes(
            "7c22822097b863dabf25c290ec35650685e2ae7bed49ae9c097a6feda338ad45c36049fb9000",
        );
        assert_eq!(c.transmit(&req).unwrap(), expected);
    }

    /// `seed_rfc5903_slot_9d_cert` must install the slot-9D cert (so
    /// pivy-agent can enumerate the ECDH/key-management identity) AND the
    /// matching RFC 5903 §8.1 key (so GA ECDH actually computes). After
    /// it, GET DATA on `5F C1 0B` returns the cert object, and a slot-9D
    /// GA ECDH request (PIN-verified) returns a well-formed shared
    /// X-coord rather than the empty-slot `6A88` — the matched cert+key
    /// pair the SSH-forwarded decrypt path (piggy#135 Phase D) needs.
    #[test]
    fn seed_rfc5903_slot_9d_cert_installs_cert_and_enables_ecdh() {
        let mut c = VirtualCard::new();
        c.seed_rfc5903_slot_9d_cert();
        c.pin_verified = true;

        let cert = c.transmit(&get_data_apdu(TAG_SLOT_9D_CERT)).unwrap();
        assert_eq!(cert[0], 0x53, "GET DATA returns the 53-wrapped cert object");
        assert_eq!(&cert[cert.len() - 2..], &[0x90, 0x00], "cert read -> 9000");

        // It also installs a CHUID so clients see an initialized card with
        // a GUID (else pivy-piv's read_chuid errors and detect-pubkey /
        // init report no card).
        let chuid = c.transmit(&get_data_apdu(TAG_CHUID)).unwrap();
        assert_eq!(chuid[0], 0x53, "GET DATA returns the 53-wrapped CHUID");
        assert!(
            chuid.windows(2).any(|w| w == [0x34, 0x10]),
            "CHUID carries a 16-byte GUID (tag 0x34) for pivy-piv to read"
        );

        // Reuse an ephemeral point from the 9D ECDH captures; the X-coord
        // differs (different key) but the response must be a well-formed
        // `7C 22 82 20 <32B> 90 00`, not the empty-slot `6A88`.
        let req = hex_to_bytes(
            "0087119d0000477c458200854104b3ef72daa94a55f409e495f654f234fb8f9730fa66923e7e45a910bb9773535e5d9a77be8d9f0968e7fb008cf9c156d7d468fbecb573e17801e2d441486b9f860000",
        );
        let resp = c.transmit(&req).unwrap();
        assert_eq!(resp.len(), 38, "7C 22 82 20 <32B X> 90 00");
        assert_eq!(
            &resp[..4],
            &[0x7C, 0x22, 0x82, 0x20],
            "ECDH response template"
        );
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "ECDH -> 9000");
    }

    // -- GA ECDSA (slot 9A sign, P-256) tests ----------------------------

    /// Build a GA ECDSA sign APDU for the given signing slot: `00 87 11
    /// <slot> <Lc> 7C <l> 82 00 81 <hl> <digest>` (empty RESPONSE
    /// placeholder + CHALLENGE carrying the prehash). Short-form lengths —
    /// the digests we test are <128 bytes so the wrappers fit one length
    /// byte.
    fn ga_sign_apdu_slot(slot: u8, digest: &[u8]) -> Vec<u8> {
        let mut inner = vec![0x82, 0x00, 0x81, digest.len() as u8];
        inner.extend_from_slice(digest);
        let mut body = vec![0x7C, inner.len() as u8];
        body.extend_from_slice(&inner);
        let mut apdu = vec![0x00, 0x87, 0x11, slot, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu
    }

    /// GA ECDSA sign APDU for slot 9A (the common case in these tests).
    fn ga_sign_apdu(digest: &[u8]) -> Vec<u8> {
        ga_sign_apdu_slot(0x9A, digest)
    }

    /// Strip the trailing SW and unwrap `7C <l> 82 <l2> <der>`, returning
    /// the DER signature bytes. Asserts the wrapper shape and a 9000 SW.
    fn extract_ga_sign_der(resp: &[u8]) -> Vec<u8> {
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "trailing SW 9000");
        let payload = &resp[..resp.len() - 2];
        assert_eq!(payload[0], 0x7C, "outer GA template tag");
        let l7c = payload[1] as usize; // short form for our sizes
        let inner = &payload[2..2 + l7c];
        assert_eq!(inner[0], 0x82, "GA RESPONSE tag");
        let l82 = inner[1] as usize;
        inner[2..2 + l82].to_vec()
    }

    #[test]
    fn ga_ecdsa_slot_9a_without_pin_verify_returns_6982() {
        let mut c = VirtualCard::new();
        c.seed_slot_9a_priv(RFC6979_SCALAR);
        let resp = c.transmit(&ga_sign_apdu(&[0x5A; 32])).unwrap();
        assert_eq!(resp, vec![0x69, 0x82], "PIN not verified -> 6982");
    }

    #[test]
    fn ga_ecdsa_slot_9a_without_key_returns_6a88() {
        let mut c = VirtualCard::new();
        c.pin_verified = true;
        let resp = c.transmit(&ga_sign_apdu(&[0x5A; 32])).unwrap();
        assert_eq!(resp, vec![0x6A, 0x88], "slot 9A empty -> 6A88");
    }

    /// The signature the card returns must verify against the RFC 6979
    /// §A.2.5 public key over the supplied prehash. Real silicon
    /// randomizes `k`, so we verify cryptographically rather than pin a
    /// captured wire (piggy#135).
    #[test]
    fn ga_ecdsa_slot_9a_signs_and_verifies_against_a2_5_pubkey() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

        let mut c = VirtualCard::new();
        c.seed_slot_9a_priv(RFC6979_SCALAR);
        c.pin_verified = true;

        let digest: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
            0xC3, 0xD2, 0xE1, 0xF0,
        ];
        let resp = c.transmit(&ga_sign_apdu(&digest)).unwrap();
        let der = extract_ga_sign_der(&resp);

        let sig = Signature::from_der(&der).expect("card returned valid DER sig");
        let vk = VerifyingKey::from(&SigningKey::from_slice(&RFC6979_SCALAR).unwrap());
        vk.verify_prehash(&digest, &sig)
            .expect("signature verifies against the §A.2.5 public key");
    }

    /// RFC 6979 signing is deterministic: signing the same prehash twice
    /// yields byte-identical output. Guards against an accidental switch
    /// to randomized `k` (which would silently break replayability).
    #[test]
    fn ga_ecdsa_slot_9a_is_deterministic() {
        let mut c = VirtualCard::new();
        c.seed_slot_9a_priv(RFC6979_SCALAR);
        c.pin_verified = true;
        let apdu = ga_sign_apdu(&[0x42; 32]);
        let first = c.transmit(&apdu).unwrap();
        let second = c.transmit(&apdu).unwrap();
        assert_eq!(first, second, "RFC 6979 sign is deterministic");
        assert_eq!(&first[first.len() - 2..], &[0x90, 0x00]);
    }

    /// End-to-end identity wiring: `seed_rfc6979_slot_9a_cert` must make
    /// the slot-9A cert readable via GET DATA *and* the slot signable —
    /// the cert and key are a matched pair, so the seeded SSH identity is
    /// fully usable (enumerate + sign).
    #[test]
    fn seed_rfc6979_slot_9a_cert_enables_signing() {
        let mut c = VirtualCard::new();
        c.seed_rfc6979_slot_9a_cert();
        c.pin_verified = true;

        let cert = c.transmit(&get_data_apdu(TAG_SLOT_9A_CERT)).unwrap();
        assert_eq!(cert[0], 0x53, "GET DATA returns the 53-wrapped cert object");
        assert_eq!(&cert[cert.len() - 2..], &[0x90, 0x00], "cert read -> 9000");

        let sig = c.transmit(&ga_sign_apdu(&[0x7E; 32])).unwrap();
        assert_eq!(
            &sig[sig.len() - 2..],
            &[0x90, 0x00],
            "seeded slot 9A can sign -> 9000"
        );
        assert_eq!(sig[0], 0x7C, "sign response is a GA template");
    }

    // -- GA ECDSA (slot 9C, Digital Signature, PIN-always) tests ---------

    #[test]
    fn ga_ecdsa_slot_9c_without_pin_verify_returns_6982() {
        let mut c = VirtualCard::new();
        c.seed_slot_9c_priv(FIBBY_SLOT_9C_TEST_PRIV);
        let resp = c.transmit(&ga_sign_apdu_slot(0x9C, &[0x5A; 32])).unwrap();
        assert_eq!(resp, vec![0x69, 0x82], "PIN not verified -> 6982");
    }

    #[test]
    fn ga_ecdsa_slot_9c_without_key_returns_6a88() {
        let mut c = VirtualCard::new();
        c.pin_verified = true;
        let resp = c.transmit(&ga_sign_apdu_slot(0x9C, &[0x5A; 32])).unwrap();
        assert_eq!(resp, vec![0x6A, 0x88], "slot 9C empty -> 6A88");
    }

    /// The slot-9C signature must verify against the slot's public key over
    /// the supplied prehash. Real silicon randomizes `k`, so we verify
    /// cryptographically rather than pin a captured wire.
    #[test]
    fn ga_ecdsa_slot_9c_signs_and_verifies_against_slot_pubkey() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

        let mut c = VirtualCard::new();
        c.seed_slot_9c_priv(FIBBY_SLOT_9C_TEST_PRIV);
        c.pin_verified = true;

        let digest: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
            0xC3, 0xD2, 0xE1, 0xF0,
        ];
        let resp = c.transmit(&ga_sign_apdu_slot(0x9C, &digest)).unwrap();
        let der = extract_ga_sign_der(&resp);

        let sig = Signature::from_der(&der).expect("card returned valid DER sig");
        let vk = VerifyingKey::from(&SigningKey::from_slice(&FIBBY_SLOT_9C_TEST_PRIV).unwrap());
        vk.verify_prehash(&digest, &sig)
            .expect("signature verifies against the slot-9C public key");
    }

    /// RFC 6979 signing is deterministic. Slot 9C consumes the PIN
    /// verification on each sign (policy "always"), so re-verify between the
    /// two signs; the outputs must still be byte-identical.
    #[test]
    fn ga_ecdsa_slot_9c_is_deterministic() {
        let mut c = VirtualCard::new();
        c.seed_slot_9c_priv(FIBBY_SLOT_9C_TEST_PRIV);
        c.pin_verified = true;
        let apdu = ga_sign_apdu_slot(0x9C, &[0x42; 32]);
        let first = c.transmit(&apdu).unwrap();
        c.pin_verified = true; // re-VERIFY: slot 9C is PIN-always
        let second = c.transmit(&apdu).unwrap();
        assert_eq!(first, second, "RFC 6979 sign is deterministic");
        assert_eq!(&first[first.len() - 2..], &[0x90, 0x00]);
    }

    /// The distinguishing slot-9C behavior: PIN policy "always". A
    /// successful sign consumes the PIN verification, so a second sign
    /// without a fresh VERIFY returns 6982; re-verifying re-enables it.
    #[test]
    fn ga_ecdsa_slot_9c_consumes_pin_verification() {
        let mut c = VirtualCard::new();
        c.seed_slot_9c_priv(FIBBY_SLOT_9C_TEST_PRIV);
        c.pin_verified = true;
        let apdu = ga_sign_apdu_slot(0x9C, &[0x33; 32]);

        let first = c.transmit(&apdu).unwrap();
        assert_eq!(
            &first[first.len() - 2..],
            &[0x90, 0x00],
            "first sign -> 9000"
        );
        assert!(!c.pin_verified, "the 9C sign consumed the PIN verification");

        let second = c.transmit(&apdu).unwrap();
        assert_eq!(
            second,
            vec![0x69, 0x82],
            "second sign without re-VERIFY -> 6982"
        );

        c.pin_verified = true; // fresh VERIFY
        let third = c.transmit(&apdu).unwrap();
        assert_eq!(
            &third[third.len() - 2..],
            &[0x90, 0x00],
            "re-verify then sign -> 9000"
        );
    }

    /// Contrast guard for the shared signer: slot 9A is PIN policy "once",
    /// so a sign leaves `pin_verified` set and back-to-back signs both work
    /// without re-VERIFY (the inverse of the 9C consume behavior above).
    #[test]
    fn ga_ecdsa_slot_9a_sign_does_not_consume_pin_verification() {
        let mut c = VirtualCard::new();
        c.seed_slot_9a_priv(RFC6979_SCALAR);
        c.pin_verified = true;
        let apdu = ga_sign_apdu(&[0x44; 32]);

        let first = c.transmit(&apdu).unwrap();
        assert_eq!(
            &first[first.len() - 2..],
            &[0x90, 0x00],
            "first 9A sign -> 9000"
        );
        assert!(c.pin_verified, "9A sign leaves the PIN verification set");

        let second = c.transmit(&apdu).unwrap();
        assert_eq!(
            &second[second.len() - 2..],
            &[0x90, 0x00],
            "second 9A sign without re-VERIFY still -> 9000"
        );
    }

    /// End-to-end identity wiring: `seed_fibby_slot_9c_cert` makes the
    /// slot-9C cert readable via GET DATA *and* the slot signable, and the
    /// cert's embedded SubjectPublicKeyInfo point matches the slot key —
    /// the last assertion guards the pinned cert↔key pair (a transcription
    /// slip in either const would break it).
    #[test]
    fn seed_fibby_slot_9c_cert_enables_signing_and_cert_matches_key() {
        use p256::ecdsa::{SigningKey, VerifyingKey};

        let mut c = VirtualCard::new();
        c.seed_fibby_slot_9c_cert();
        c.pin_verified = true;

        let cert = c.transmit(&get_data_apdu(TAG_SLOT_9C_CERT)).unwrap();
        assert_eq!(cert[0], 0x53, "GET DATA returns the 53-wrapped cert object");
        assert_eq!(&cert[cert.len() - 2..], &[0x90, 0x00], "cert read -> 9000");

        let sig = c.transmit(&ga_sign_apdu_slot(0x9C, &[0x7E; 32])).unwrap();
        assert_eq!(
            &sig[sig.len() - 2..],
            &[0x90, 0x00],
            "seeded slot 9C can sign -> 9000"
        );

        // The cert's SubjectPublicKeyInfo point (`03 42 00 04 ‖ x ‖ y`) must
        // equal the slot key's uncompressed public point.
        let marker = [0x03u8, 0x42, 0x00, 0x04];
        let pos = FIBBY_SLOT_9C_CERT_OBJECT
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("cert embeds an uncompressed P-256 point");
        let point = &FIBBY_SLOT_9C_CERT_OBJECT[pos + 3..pos + 3 + 65]; // 04 ‖ x ‖ y
        let vk = VerifyingKey::from(&SigningKey::from_slice(&FIBBY_SLOT_9C_TEST_PRIV).unwrap());
        let expected = vk.to_encoded_point(false);
        assert_eq!(
            point,
            expected.as_bytes(),
            "cert SPKI point matches the slot-9C key"
        );
    }

    // -- YK ATTEST (INS 0xF9) tests --------------------------------------

    /// Real YK4 silicon's response to `00 F9 9D 00 00 00 00` when slot
    /// 9D holds an *imported* key is `6A 80` — attestation refuses
    /// imported keys (no on-card-generation provenance to sign).
    /// VirtualCard mirrors this for every F9 9D probe, since it has
    /// no factory attestation key to sign anything with anyway.
    /// Captured wire from both `yk4-test-vector-roundtrip*.fixture`
    /// files.
    #[test]
    fn yk_attest_slot_9d_returns_6a80_matching_imported_key_silicon() {
        let mut c = VirtualCard::new();
        let req = hex_to_bytes("00f99d00000000");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x6A, 0x80]);
    }

    /// Sanity: the same 6A80 response is returned regardless of
    /// whether VirtualCard's slot 9D has been seeded with a test-
    /// vector scalar or not. The attestation refusal path is purely
    /// a function of "we don't have a YubicoPIV factory key".
    #[test]
    fn yk_attest_slot_9d_returns_6a80_even_when_slot_seeded() {
        let mut c = VirtualCard::new();
        c.seed_slot_9d_priv(RFC6979_SCALAR);
        let req = hex_to_bytes("00f99d00000000");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x6A, 0x80]);
    }

    // -- GA mgmt-key challenge-response (slot 9B, 3DES) tests -------------

    #[test]
    fn ga_mgmt_key_phase1_returns_seeded_witness_matching_yk4_init_capture() {
        let mut c = VirtualCard::new();
        // Captured witness from yk4-init.fixture pair [7].
        c.seed_mgmt_key_witness([0xCA, 0xB1, 0x8C, 0x96, 0xB5, 0x49, 0x7D, 0xAE]);
        let req = hex_to_bytes("0087039b0000047c0281000000");
        let expected = hex_to_bytes("7c0a8108cab18c96b5497dae9000");
        assert_eq!(c.transmit(&req).unwrap(), expected);
    }

    #[test]
    fn ga_mgmt_key_phase2_verifies_factory_key_response_matching_yk4_init_capture() {
        let mut c = VirtualCard::new();
        c.seed_mgmt_key_witness([0xCA, 0xB1, 0x8C, 0x96, 0xB5, 0x49, 0x7D, 0xAE]);
        // Drive phase-1 to set the outstanding witness state.
        let _ = c
            .transmit(&hex_to_bytes("0087039b0000047c0281000000"))
            .unwrap();
        // Phase-2 with the client-computed TDES-EDE3(factory_key,
        // witness) = 731EFC2B4BD58610 (verified externally via
        // `openssl enc -des-ede3 -K 0102...070708`).
        let req = hex_to_bytes("0087039b00000c7c0a8208731efc2b4bd5861000");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x90, 0x00]);
    }

    #[test]
    fn ga_mgmt_key_phase2_rejects_wrong_response_with_6982() {
        let mut c = VirtualCard::new();
        c.seed_mgmt_key_witness([0xCA, 0xB1, 0x8C, 0x96, 0xB5, 0x49, 0x7D, 0xAE]);
        let _ = c
            .transmit(&hex_to_bytes("0087039b0000047c0281000000"))
            .unwrap();
        // Twiddle one byte of the correct response.
        let req = hex_to_bytes("0087039b00000c7c0a8208731efc2b4bd5861100");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x69, 0x82]);
    }

    #[test]
    fn ga_mgmt_key_phase2_without_prior_phase1_returns_6982() {
        let mut c = VirtualCard::new();
        let req = hex_to_bytes("0087039b00000c7c0a8208731efc2b4bd5861000");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x69, 0x82]);
    }

    #[test]
    fn ga_mgmt_key_witness_is_cleared_after_phase2() {
        let mut c = VirtualCard::new();
        c.seed_mgmt_key_witness([0xCA, 0xB1, 0x8C, 0x96, 0xB5, 0x49, 0x7D, 0xAE]);
        let _ = c
            .transmit(&hex_to_bytes("0087039b0000047c0281000000"))
            .unwrap();
        // Successful phase-2.
        let _ = c
            .transmit(&hex_to_bytes("0087039b00000c7c0a8208731efc2b4bd5861000"))
            .unwrap();
        // Replay phase-2: no outstanding witness now -> 6982.
        let req = hex_to_bytes("0087039b00000c7c0a8208731efc2b4bd5861000");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x69, 0x82]);
    }

    #[test]
    fn disconnect_clears_pending_mgmt_witness() {
        let mut c = VirtualCard::new();
        c.connect(2, 3).unwrap();
        c.seed_mgmt_key_witness([0xCA, 0xB1, 0x8C, 0x96, 0xB5, 0x49, 0x7D, 0xAE]);
        let _ = c
            .transmit(&hex_to_bytes("0087039b0000047c0281000000"))
            .unwrap();
        c.disconnect(0).unwrap();
        c.connect(2, 3).unwrap();
        // Witness was cleared; phase-2 without re-seeding -> 6982.
        let req = hex_to_bytes("0087039b00000c7c0a8208731efc2b4bd5861000");
        assert_eq!(c.transmit(&req).unwrap(), vec![0x69, 0x82]);
    }
}
