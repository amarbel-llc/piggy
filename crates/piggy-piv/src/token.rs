use crate::transport::{ApduSession, ApduTransport, EndDisposition, RawApdu};
#[cfg(feature = "pcsc")]
use crate::{PivContext, transport::PcscTransport};

use crate::apdu::{Apdu, PIV_AID, StatusWord, ga_tag};
use crate::cert;
use crate::error::PivError;
use crate::guid::Guid;
use crate::slot::{self, PivAlgorithm, PivSlot};
use crate::tlv::{TlvReader, TlvWriter};

/// RAII guard wrapping a single transaction lifetime on the token's
/// transport against a [`PivToken`].
///
/// All PIN-using card operations (`verify_pin`, `sign_prehash`,
/// `ecdh_derive`) live on this type. They are reachable **only**
/// from inside a `PinSession`; calling them on the underlying
/// `PivToken` is not possible at compile time. This is the
/// type-state guard satisfying piggy#56 acceptance criterion 2 for
/// the PIN-using path.
///
/// Drop semantics: when the session ends — either via the explicit
/// [`PinSession::end`] terminator or via an implicit drop after an
/// early-return `?` — the underlying transaction is ended with
/// `EndDisposition::ResetCard` if any successful `verify_pin` ran
/// during the session, and `EndDisposition::LeaveCard` otherwise. The
/// `ResetCard` disposition clears PIN-verified state on the card so
/// it does not leak across sessions. Drop swallows
/// end-of-transaction errors and logs them via `tracing::warn`;
/// the explicit `end` propagates them.
///
/// The session does NOT mirror C pivy's `piv_clear_pin` attempt
/// before disposition (vendor/pivy/src/piv.c::piv_txn_end). That
/// optimization lets cooperative cards retain other state across the
/// reset; piggy chooses the simpler "always reset" rule. Cost: a
/// subsequent client must re-select the PIV applet, which
/// [`PivToken::begin_pin_session`] does on every session it opens.
pub struct PinSession<'tok> {
    /// `Option` so [`PinSession::end`] can consume the transaction
    /// without `Drop` re-running over `self.session`. `None` only
    /// transiently inside `end`; outside that path it is always
    /// `Some`.
    session: Option<Box<dyn ApduSession + 'tok>>,
    /// True after at least one successful `verify_pin` call within
    /// this session. Drives the end-disposition decision.
    pin_verified: bool,
}

/// CHUID data object tag (NIST SP 800-73-4)
const PIV_TAG_CHUID: u32 = 0x5FC102;

/// Tag for GUID within CHUID
const CHUID_TAG_GUID: u32 = 0x34;

pub struct PivToken {
    transport: Box<dyn ApduTransport>,
    guid: Guid,
    reader_name: String,
    /// YubiKey factory serial, cached at connect() time. `None` only for
    /// non-YubiKey PIV cards; a YubiKey whose firmware doesn't expose the
    /// serial over the PIV applet (e.g. a YubiKey 4) is read via the OTP-applet
    /// fallback. See `read_yk_serial` for the two-path read + failure-as-None
    /// policy.
    yk_serial: Option<u32>,
    /// Human diagnostic for the serial read: which path produced it, or why
    /// none did. Surfaced by `piggy list --verbose` (piggy#256); never affects
    /// `yk_serial` itself. `None` only if the read was never attempted.
    yk_serial_diag: Option<String>,
    /// Whether the card carries a CHUID (and thus a real GUID). `false` for
    /// a factory-blank / uninitialized PIV card. Only `connect_inner` with
    /// `require_chuid = false` can yield `false` here; the strict `connect`
    /// errors instead, so existing callers never see an uninitialized token.
    initialized: bool,
    /// The raw `53`-wrapped CHUID GET DATA response, retained at connect for
    /// the `piggy tool list` port (which reports the CHUID's signed flag,
    /// cardholder UUID, FASC-N, and expiry). `None` on an uninitialized card.
    chuid_raw: Option<Vec<u8>>,
}

/// Parse a 4-byte big-endian serial from a vendor serial-read response, or
/// `None` when the status word isn't success or the response is too short.
/// Shared by the PIV (`0xF8`) and OTP-applet serial-read paths (piggy#256).
fn parse_serial_response(data: &[u8], sw: StatusWord) -> Option<u32> {
    if sw.is_success() && data.len() >= 4 {
        Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    } else {
        None
    }
}

/// The PC/SC entry points (the default-on `pcsc` feature, piggy#337).
#[cfg(feature = "pcsc")]
impl PivToken {
    pub fn connect(ctx: &PivContext, reader: &str) -> Result<Self, PivError> {
        Self::connect_inner(ctx, reader, true)
    }

    /// Like [`PivToken::connect`], but a PIV card with no CHUID (an
    /// uninitialized / factory-blank card) is returned as a token with an
    /// all-zeros GUID and [`PivToken::is_initialized`] == `false`, instead of
    /// erroring. A non-PIV card (SELECT PIV fails) still errors.
    ///
    /// Used by [`PivContext::enumerate_tokens_including_uninitialized`] so
    /// `piggy list` can surface blank cards for provisioning discovery
    /// (piggy#193). The strict [`PivToken::connect`] keeps every other caller —
    /// which auto-selects the sole card and errors on more than one — from
    /// seeing blanks, so plugging a blank card in next to a real one does not
    /// turn an auto-select into an ambiguity error.
    pub fn connect_allowing_uninitialized(
        ctx: &PivContext,
        reader: &str,
    ) -> Result<Self, PivError> {
        Self::connect_inner(ctx, reader, false)
    }

    fn connect_inner(
        ctx: &PivContext,
        reader: &str,
        require_chuid: bool,
    ) -> Result<Self, PivError> {
        let transport = PcscTransport::connect(ctx, reader)?;
        Self::from_transport(Box::new(transport), reader, require_chuid)
    }
}

impl PivToken {
    /// Build a token over any [`ApduTransport`]: the seam a host without
    /// PC/SC (Android NFC/USB) and the in-process test cards use. Same
    /// SELECT / CHUID / serial sequence as [`PivToken::connect`];
    /// `require_chuid` as in [`PivToken::connect_allowing_uninitialized`].
    pub fn from_transport(
        transport: Box<dyn ApduTransport>,
        reader_name: &str,
        require_chuid: bool,
    ) -> Result<Self, PivError> {
        let mut token = Self {
            transport,
            guid: Guid::from_bytes(&[0; 16])?,
            reader_name: reader_name.to_string(),
            yk_serial: None,
            yk_serial_diag: None,
            initialized: false,
            chuid_raw: None,
        };
        token.select_piv()?;
        match token.read_chuid() {
            Ok(()) => token.initialized = true,
            Err(e) => {
                // A non-blank card that fails CHUID read is a real error for
                // strict callers. For the tolerant path, treat any CHUID-read
                // failure on an otherwise-selectable PIV applet as
                // "uninitialized": leave the GUID all-zeros (set above) and
                // initialized = false, matching how `pivy-tool list` reports a
                // factory-blank card (guid 0000…, "needs initialization").
                if require_chuid {
                    return Err(e);
                }
            }
        }
        let (serial, diag) = token.read_yk_serial();
        token.yk_serial = serial;
        token.yk_serial_diag = diag;
        Ok(token)
    }

    fn transmit(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        transmit_on(&*self.transport, apdu)
    }

    fn select_piv(&mut self) -> Result<(), PivError> {
        let apdu = Apdu::select(PIV_AID);
        let (_, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }

    fn read_chuid(&mut self) -> Result<(), PivError> {
        let apdu = Apdu::get_data(PIV_TAG_CHUID);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        // Retain the raw object for the list port's fuller CHUID read; the GUID
        // walk below stays the connect-critical path.
        self.chuid_raw = Some(data.clone());

        // Response is wrapped in tag 0x53
        let mut reader = TlvReader::new(&data);
        let outer_tag = reader.read_tag()?;
        if outer_tag != 0x53 {
            return Err(PivError::Tlv {
                message: format!("expected CHUID outer tag 0x53, got {:#X}", outer_tag),
            });
        }
        let chuid_data = reader.read_value()?;

        // Parse CHUID TLV to find GUID (tag 0x34)
        let mut chuid_reader = TlvReader::new(chuid_data);
        while chuid_reader.has_remaining() {
            let tag = chuid_reader.read_tag()?;
            let value = chuid_reader.read_value()?;
            if tag == CHUID_TAG_GUID {
                self.guid = Guid::from_bytes(value)?;
                return Ok(());
            }
        }

        Err(PivError::Tlv {
            message: "GUID tag (0x34) not found in CHUID".into(),
        })
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    /// Cached YubiKey factory serial. `None` only for non-YubiKey PIV cards:
    /// a YubiKey that doesn't expose the serial over the PIV applet is read via
    /// the OTP-applet fallback (piggy#256). Populated at `connect()` time via
    /// `read_yk_serial`; never re-queries the card.
    pub fn yk_serial(&self) -> Option<u32> {
        self.yk_serial
    }

    /// Human diagnostic for the serial read — which path produced the serial,
    /// or why none did (e.g. `"PIV GET_SERIAL SW=0x6D00; read via OTP applet"`).
    /// Surfaced by `piggy list --verbose`. `None` only if the read was never
    /// attempted; independent of whether [`Self::yk_serial`] is `Some`.
    pub fn yk_serial_diag(&self) -> Option<&str> {
        self.yk_serial_diag.as_deref()
    }

    /// Whether the card is initialized (carries a CHUID, and thus a real
    /// GUID). `false` only for a factory-blank card returned via
    /// [`PivToken::connect_allowing_uninitialized`]; the strict
    /// [`PivToken::connect`] never returns an uninitialized token.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Read the YubiKey factory serial, returning `(serial, diagnostic)`.
    ///
    /// Path 1 is the PIV-applet vendor INS `0xF8` (`YK_GET_SERIAL`) against the
    /// already-selected PIV applet — the path all YubiKey-5-era firmware
    /// answers. If it yields no serial (a non-9000 SW, e.g. the `0x6D00` an
    /// older YubiKey 4 returns because it doesn't expose the serial over PIV),
    /// path 2 falls back to the **OTP applet**: SELECT it, issue its serial
    /// API-request, then re-SELECT the PIV applet so the token is left
    /// PIV-selected for every later card op. This mirrors ykman /
    /// yubico-piv-tool (`lib/ykpiv.c` `_ykpiv_get_serial`), which reads the
    /// serial from the OTP applet on pre-5.x firmware (piggy#256).
    ///
    /// The diagnostic records which path produced the serial, or why none did
    /// — surfaced by `piggy list --verbose`. A missing serial is never a
    /// connect-time failure, so every error is swallowed into the diagnostic.
    fn read_yk_serial(&self) -> (Option<u32>, Option<String>) {
        // Path 1: PIV-applet vendor GET_SERIAL (YubiKey 5+). On success, return
        // immediately without touching the OTP applet.
        let piv = Apdu::new(0x00, crate::apdu::ins::YK_GET_SERIAL, 0x00, 0x00);
        let piv_note = match self.transmit(&piv) {
            Ok((data, sw)) => match parse_serial_response(&data, sw) {
                Some(serial) => {
                    return (Some(serial), Some("read via PIV GET_SERIAL".to_string()));
                }
                None => format!("PIV GET_SERIAL SW={sw}"),
            },
            Err(e) => format!("PIV GET_SERIAL error: {e}"),
        };

        // Path 2: OTP-applet serial (YubiKey 4 / pre-5.x firmware). ALWAYS
        // re-SELECT PIV afterward — a failed OTP SELECT may leave the card with
        // no (or a different) applet selected, and every later op assumes PIV.
        let otp_result = self.read_otp_serial();
        let reselect = self
            .transmit(&Apdu::select(crate::apdu::PIV_AID))
            .err()
            .map(|e| format!("; re-SELECT PIV error: {e}"))
            .unwrap_or_default();

        match otp_result {
            Ok(serial) => (
                Some(serial),
                Some(format!("{piv_note}; read via OTP applet{reselect}")),
            ),
            Err(otp_note) => (None, Some(format!("{piv_note}; {otp_note}{reselect}"))),
        }
    }

    /// SELECT the OTP applet and read the 4-byte big-endian factory serial.
    /// Does NOT restore PIV selection — [`Self::read_yk_serial`] does that
    /// unconditionally. Returns the serial or a diagnostic reason (a non-YubiKey
    /// card has no OTP applet, so its SELECT fails with e.g. `0x6A82`).
    fn read_otp_serial(&self) -> Result<u32, String> {
        let (_, sw) = self
            .transmit(&Apdu::select(crate::apdu::YK_OTP_AID))
            .map_err(|e| format!("OTP SELECT error: {e}"))?;
        if !sw.is_success() {
            return Err(format!("OTP SELECT SW={sw} (not a YubiKey?)"));
        }
        let req = Apdu::new(
            0x00,
            crate::apdu::otp::API_REQ,
            crate::apdu::otp::SLOT_DEVICE_SERIAL,
            0x00,
        );
        let (data, sw) = self
            .transmit(&req)
            .map_err(|e| format!("OTP serial read error: {e}"))?;
        parse_serial_response(&data, sw)
            .ok_or_else(|| format!("OTP serial read SW={sw}, len={}", data.len()))
    }

    pub fn transmit_apdu(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        self.transmit(apdu)
    }

    /// Read a certificate from the given PIV slot and extract the SSH public key.
    pub fn read_slot(&self, slot_id: u8) -> Result<PivSlot, PivError> {
        let cert_tag = slot::slot_to_cert_tag(slot_id).ok_or(PivError::SlotEmpty(slot_id))?;
        let apdu = Apdu::get_data(cert_tag);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::SlotEmpty(slot_id));
        }

        // Response wrapped in tag 0x53
        let mut reader = TlvReader::new(&data);
        let outer_tag = reader.read_tag()?;
        if outer_tag != 0x53 {
            return Err(PivError::Tlv {
                message: format!("expected cert outer tag 0x53, got {:#X}", outer_tag),
            });
        }
        let inner = reader.read_value()?;

        // Parse inner TLV: tag 0x70 = certificate, tag 0x71 = cert info
        let mut inner_reader = TlvReader::new(inner);
        let mut cert_der: Option<Vec<u8>> = None;
        while inner_reader.has_remaining() {
            let tag = inner_reader.read_tag()?;
            let value = inner_reader.read_value()?;
            if tag == 0x70 {
                cert_der = Some(value.to_vec());
            }
            // tag 0x71 = certinfo, tag 0xFE = error detection code -- skip
        }

        let cert_der = cert_der.ok_or(PivError::SlotEmpty(slot_id))?;
        let (algorithm, public_key) = cert::extract_public_key(&cert_der)?;
        Ok(PivSlot::new(slot_id, algorithm, cert_der, public_key))
    }

    /// Read certificates from all standard PIV slots plus retired slots.
    /// Silently skips empty slots.
    pub fn read_all_slots(&self) -> Result<Vec<PivSlot>, PivError> {
        let mut slots = Vec::new();

        // Standard slots
        for &slot_id in slot::STANDARD_SLOTS {
            match self.read_slot(slot_id) {
                Ok(s) => slots.push(s),
                Err(_) => continue,
            }
        }

        // Retired key management slots 82-95
        for slot_id in 0x82..=0x95_u8 {
            match self.read_slot(slot_id) {
                Ok(s) => slots.push(s),
                Err(_) => continue,
            }
        }

        Ok(slots)
    }

    /// Read the existing PIV Key History object (`5FC10C`). An absent object
    /// (`6A82`) is the fresh-card case and returns the default (all-zero, no
    /// URL), mirroring how `pivy-tool update-keyhist` treats a card with no
    /// prior key history.
    pub fn read_keyhistory(&self) -> Result<crate::keyhist::KeyHistory, PivError> {
        let apdu = Apdu::get_data(crate::keyhist::KEYHIST_TAG);
        let (data, sw) = self.transmit(&apdu)?;
        if sw.as_u16() == 0x6A82 {
            return Ok(crate::keyhist::KeyHistory::default());
        }
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(crate::keyhist::parse_keyhistory(&data))
    }

    /// Read and parse the PIV Printed Information object (`5FC109`). On a card
    /// whose PINFO read is PIN-gated this surfaces the raw `6982`/`6A82` status
    /// in `PivError::Apdu`; the PIN-gated read retry is a follow-up (piggy#292,
    /// fibby models the object PIN-free).
    pub fn read_pinfo(&self) -> Result<crate::pinfo::Pinfo, PivError> {
        let apdu = Apdu::get_data(crate::pinfo::PINFO_TAG);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(crate::pinfo::parse_pinfo(&data))
    }

    /// The card's CHUID fields for the `list` port (signed flag, cardholder
    /// UUID, FASC-N, expiry), parsed from the response retained at connect.
    /// Returns the default (all-`None`, unsigned) for an uninitialized card.
    pub fn chuid(&self) -> crate::chuid::Chuid {
        match &self.chuid_raw {
            Some(raw) => crate::chuid::parse_chuid(raw),
            None => crate::chuid::Chuid::default(),
        }
    }

    /// Read the YubiKey firmware version (`[major, minor, patch]`) via the
    /// YubicoPIV GET VERSION vendor INS (`0xFD`). `None` for a card that rejects
    /// it (a non-YubiKey PIV card) — matching how `pivy-tool list` omits
    /// `ykpiv_version` for a non-ykpiv token.
    pub fn read_ykpiv_version(&self) -> Option<[u8; 3]> {
        let apdu = Apdu::new(0x00, crate::apdu::ins::YK_GET_VERSION, 0x00, 0x00);
        match self.transmit(&apdu) {
            Ok((data, sw)) if sw.is_success() && data.len() >= 3 => {
                Some([data[0], data[1], data[2]])
            }
            _ => None,
        }
    }

    /// Read the YubiKey serial via the PIV-applet vendor INS (`0xF8`) ONLY — no
    /// OTP-applet fallback. `pivy-tool list` reports `serial` only when the PIV
    /// applet answers (`ykpiv_token_has_serial`); a YubiKey 4, whose PIV applet
    /// returns `0x6D00`, has no `serial` in the listing even though its serial
    /// is reachable over the OTP applet. This deliberately differs from
    /// [`Self::yk_serial`] (which does fall back to OTP) so the list JSON is
    /// byte-identical to C.
    pub fn read_ykpiv_piv_serial(&self) -> Option<u32> {
        let apdu = Apdu::new(0x00, crate::apdu::ins::YK_GET_SERIAL, 0x00, 0x00);
        match self.transmit(&apdu) {
            Ok((data, sw)) => parse_serial_response(&data, sw),
            Err(_) => None,
        }
    }

    /// Factory-reset the PIV applet via the YubicoPIV RESET vendor INS
    /// (`0xFB`): wipe every slot key/cert and restore the factory PIN, PUK, and
    /// management key with their retry counters. The applet only permits this
    /// once BOTH the PIN and the PUK are blocked; otherwise it answers `0x6985`,
    /// surfaced here as `PivError::Apdu { sw: 0x6985 }` so the caller can
    /// explain the precondition. Takes no PIN or management-key auth — the
    /// blocked-credentials state IS the authorization. Destructive and
    /// irreversible; mirrors pivy's `ykpiv_reset`.
    pub fn factory_reset(&self) -> Result<(), PivError> {
        let apdu = Apdu::new(0x00, crate::apdu::ins::YK_RESET, 0x00, 0x00);
        let (_, sw) = self.transmit(&apdu)?;
        if sw.is_success() {
            Ok(())
        } else {
            Err(PivError::Apdu { sw: sw.as_u16() })
        }
    }

    /// Count the on-card retired-slot certificates: the highest retired-slot
    /// index (`1..20`, slots `82`..`95`) that holds a cert — what
    /// `pivy-tool update-keyhist` records as `oncard`. A card with no retired
    /// certs (every empty slot answering `6A82`) yields `0`. An unreadable
    /// slot is treated as empty, matching `read_all_slots`' lenient skip;
    /// counting reads the cert, so a retired slot holding a key algorithm
    /// piggy cannot parse (e.g. RSA) would be undercounted — the full-fidelity
    /// path is tracked in piggy#290.
    pub fn count_oncard_retired(&self) -> u8 {
        let mut oncard = 0u8;
        for slot_id in 0x82..=0x95_u8 {
            if self.read_slot(slot_id).is_ok() {
                oncard = slot_id - 0x82 + 1;
            }
        }
        oncard
    }

    /// Read the configured PIN policy and touch policy for the given
    /// slot. Backed by an INS_ATTEST round-trip plus a walk of the
    /// returned attestation cert's `1.3.6.1.4.1.41482.3.8` extension.
    ///
    /// Fails when the card doesn't support attestation (no F9 key, or
    /// non-YubiKey card returning 6A88/6A82). Callers that just want to
    /// surface "policy not known" should treat any `Err` here as `None`.
    pub fn read_slot_policy(
        &self,
        slot_id: u8,
    ) -> Result<(crate::policy::PinPolicy, crate::policy::TouchPolicy), PivError> {
        let cert_der = self.yk_attest(slot_id)?;
        crate::attest::parse_policy(&cert_der)
    }

    /// Generate a YubiKey attestation certificate for the given slot.
    /// Returns the DER-encoded X.509 attestation statement signed by the F9 key.
    pub fn yk_attest(&self, slot_id: u8) -> Result<Vec<u8>, PivError> {
        let apdu = Apdu::yk_attest(slot_id);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(attestation_cert_der(data))
    }

    /// Begin a PIN-bracketed session over this token. Card operations
    /// performed via the returned [`PinSession`] are atomic with
    /// respect to other PC/SC clients sharing the card — they cannot
    /// reset the card's PIN-verified state between this token's
    /// `verify_pin` and subsequent sign/ECDH calls.
    ///
    /// Over PC/SC, the transport retries `SCardBeginTransaction →
    /// SCARD_W_RESET_CARD` with a bounded reconnect; see
    /// [`crate::transport::PcscTransport`]'s `begin_transaction`.
    ///
    /// Mirrors the lifecycle structure of
    /// `vendor/pivy/src/piv.c::piv_txn_begin` but does not (yet)
    /// attempt `piv_clear_pin` before disposition. See the
    /// [`PinSession`] type docs.
    pub fn begin_pin_session(&mut self) -> Result<PinSession<'_>, PivError> {
        let session = self.transport.begin_transaction()?;
        // SELECT PIV again, inside the transaction, every time. The token
        // selected it at connect, but another client's session may have
        // ended with ResetCard since (every PIN-verified session does, see
        // above), and a reset card has no applet selected: its first PIV
        // APDU would come back 0x6D00 (piggy#323, #325). Inside the
        // transaction nothing can deselect it again before the session's
        // own APDUs run.
        let (_, sw) = transmit_on(&*session, &Apdu::select(PIV_AID))?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(PinSession {
            session: Some(session),
            pin_verified: false,
        })
    }
}

impl<'tok> PinSession<'tok> {
    /// Verify the PIV PIN inside the active transaction. PIN-verified
    /// state set by this call is owned by the session and is cleared
    /// when the session ends (via `EndDisposition::ResetCard`).
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), PivError> {
        if pin.len() > 8 {
            return Err(PivError::Other(format!(
                "PIV PIN must be at most 8 bytes, got {}",
                pin.len()
            )));
        }
        let apdu = Apdu::verify_pin(pin.as_bytes());
        let (_, sw) = self.transmit(&apdu)?;
        if sw.is_success() {
            self.pin_verified = true;
            Ok(())
        } else if sw.is_pin_incorrect() {
            Err(PivError::PinIncorrect {
                retries: sw.pin_retries_remaining().unwrap_or(0) as u32,
            })
        } else if sw.as_u16() == 0x6983 {
            Err(PivError::PinBlocked)
        } else {
            Err(PivError::Apdu { sw: sw.as_u16() })
        }
    }

    /// Query the card's remaining PIN retry counter WITHOUT consuming a try
    /// (piggy#245): sends a VERIFY with an empty data field (SP 800-73-4
    /// §3.2.1). Returns `u8::MAX` when the PIN is already verified in this
    /// session (9000 — no retry concern), the packed count on 63Cx, and 0
    /// when the PIN is blocked (6983). Any other status word is an APDU
    /// error. Non-consuming, so it is safe to call before deciding whether
    /// to risk an offered PIN against this card.
    pub fn pin_retries_remaining(&mut self) -> Result<u8, PivError> {
        let (_, sw) = self.transmit(&Apdu::verify_pin_status())?;
        if sw.is_success() {
            Ok(u8::MAX)
        } else if sw.is_pin_incorrect() {
            Ok(sw.pin_retries_remaining().unwrap_or(0))
        } else if sw.as_u16() == 0x6983 {
            Ok(0)
        } else {
            Err(PivError::Apdu { sw: sw.as_u16() })
        }
    }

    /// Sign pre-hashed data with the key in the given slot, inside this
    /// session's transaction so a concurrent PC/SC client cannot clear the
    /// PIN-verified state between `verify_pin` and this call.
    ///
    /// `slot` is the slot as [`Self::read_slot`] read it, which the caller
    /// does BEFORE `verify_pin`: on a PIN-always slot a YubiKey needs the
    /// VERIFY immediately before the private-key operation, and answers
    /// 6982 when any other command (the certificate read included) came
    /// between them (piggy#325). Taking the slot rather than its id is
    /// what keeps that read out of the gap.
    ///
    /// Requires a prior `verify_pin` for slots whose PIN policy
    /// demands it; this method does NOT pre-check (the card enforces
    /// the policy and returns SW=6982 if the PIN is required and
    /// missing), matching C pivy's behavior.
    pub fn sign_prehash(&mut self, slot: &PivSlot, data: &[u8]) -> Result<Vec<u8>, PivError> {
        self.general_authenticate(
            slot.algorithm().to_byte(),
            slot.id(),
            ga_tag::CHALLENGE,
            data,
        )
    }

    /// Sign pre-hashed data with the slot key using an explicitly-supplied PIV
    /// algorithm byte (e.g. `0x11` ECCP256), skipping the cert read that
    /// [`PinSession::sign_prehash`] does to discover the algorithm.
    ///
    /// Needed during provisioning (piggy#194): a freshly-generated key must
    /// sign its own self-signed certificate *before* that cert is written to
    /// the slot, so `read_slot` would 6A82 ("slot empty"). The caller knows the
    /// algorithm from the GENERATE that just created the key. Same
    /// PIN-policy/transaction semantics as `sign_prehash`.
    pub fn sign_prehash_with_alg(
        &mut self,
        slot_id: u8,
        alg: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        self.general_authenticate(alg, slot_id, ga_tag::CHALLENGE, data)
    }

    /// Perform ECDH key agreement with the slot's private key, inside this
    /// session's transaction. `slot` is read before `verify_pin`, and the
    /// PIN-policy semantics are those of [`Self::sign_prehash`].
    pub fn ecdh_derive(
        &mut self,
        slot: &PivSlot,
        peer_ec_point: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        validate_ec_point(slot.algorithm(), peer_ec_point)?;
        self.general_authenticate(
            slot.algorithm().to_byte(),
            slot.id(),
            ga_tag::EXPONENT,
            peer_ec_point,
        )
    }

    /// Explicit termination: end the transaction with the
    /// appropriate disposition (`ResetCard` if any `verify_pin`
    /// succeeded in this session, `LeaveCard` otherwise) and return
    /// any error from ending the transport's transaction
    /// (`SCardEndTransaction` over PC/SC).
    ///
    /// After `end` returns, `Drop` is a no-op (`self.session` is `None`).
    pub fn end(mut self) -> Result<(), PivError> {
        let disposition = self.disposition();
        let session = self.session.take().expect("PinSession::end called twice");
        session.end(disposition)
    }

    fn disposition(&self) -> EndDisposition {
        if self.pin_verified {
            EndDisposition::ResetCard
        } else {
            EndDisposition::LeaveCard
        }
    }

    /// Read a slot's cert and public key, for [`Self::sign_prehash`] and
    /// [`Self::ecdh_derive`]. Does not need PIN; call it BEFORE
    /// `verify_pin`, so no command sits between the VERIFY and the
    /// operation (piggy#325). Lives on `PinSession` so callers don't have
    /// to break out of the session borrow to call it on the token.
    pub fn read_slot(&self, slot_id: u8) -> Result<PivSlot, PivError> {
        let cert_tag = slot::slot_to_cert_tag(slot_id).ok_or(PivError::SlotEmpty(slot_id))?;
        let apdu = Apdu::get_data(cert_tag);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::SlotEmpty(slot_id));
        }
        let mut reader = TlvReader::new(&data);
        let outer_tag = reader.read_tag()?;
        if outer_tag != 0x53 {
            return Err(PivError::Tlv {
                message: format!("expected cert outer tag 0x53, got {:#X}", outer_tag),
            });
        }
        let inner = reader.read_value()?;
        let mut inner_reader = TlvReader::new(inner);
        let mut cert_der: Option<Vec<u8>> = None;
        while inner_reader.has_remaining() {
            let tag = inner_reader.read_tag()?;
            let value = inner_reader.read_value()?;
            if tag == 0x70 {
                cert_der = Some(value.to_vec());
            }
        }
        let cert_der = cert_der.ok_or(PivError::SlotEmpty(slot_id))?;
        let (algorithm, public_key) = cert::extract_public_key(&cert_der)?;
        Ok(PivSlot::new(slot_id, algorithm, cert_der, public_key))
    }

    fn general_authenticate(
        &self,
        alg: u8,
        slot_id: u8,
        data_tag: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        let mut inner = TlvWriter::new();
        inner.write_tag_value(ga_tag::RESPONSE as u32, &[]);
        inner.write_tag_value(data_tag as u32, data);
        let mut outer = TlvWriter::new();
        outer.write_tag_value(0x7C, inner.as_bytes());

        let apdu = Apdu::general_authenticate(alg, slot_id, outer.as_bytes());
        let (resp, sw) = self.transmit(&apdu)?;

        if sw.as_u16() == 0x6982 {
            return Err(PivError::PinRequired);
        }
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        parse_ga_response(&resp)
    }

    /// Transmit an APDU within this session's transaction. `pub(crate)` so the
    /// write-op modules (`admin`, `keygen`, `put_data`) can build on the same
    /// transaction the PIN/sign/ECDH ops use.
    pub(crate) fn transmit(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        // transmit_on routes APDU + GET RESPONSE chain through the
        // session identically to PivToken::transmit.
        transmit_on(
            &**self
                .session
                .as_ref()
                .expect("PinSession transmit after end/drop"),
            apdu,
        )
    }
}

impl<'tok> Drop for PinSession<'tok> {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let disp = self.disposition();
            if let Err(e) = session.end(disp) {
                tracing::warn!(
                    error = %e,
                    pin_verified = self.pin_verified,
                    "SCardEndTransaction failed during PinSession drop"
                );
            }
        }
    }
}

/// Send an APDU on `link`, handle GET RESPONSE chaining (SW 61xx),
/// and return the assembled payload plus the final status word.
/// Shared body for `PivToken::transmit` (over the transport) and
/// `PinSession::transmit` (over the open session), so every transport
/// gets the same chaining and status-word handling.
fn transmit_on(link: &dyn RawApdu, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
    let cmd = apdu.to_bytes();
    let resp = link.transmit_raw(&cmd)?;
    let len = resp.len();
    if len < 2 {
        return Err(PivError::Other("response too short for status word".into()));
    }
    let sw = StatusWord::from_bytes(resp[len - 2], resp[len - 1]);
    let data = resp[..len - 2].to_vec();

    // Handle GET RESPONSE chaining (SW 61xx)
    if sw.has_more_data() {
        let mut full = data;
        let mut chain_sw = sw;
        while chain_sw.has_more_data() {
            let mut get_resp = Apdu::new(0x00, 0xC0, 0x00, 0x00);
            get_resp.le = Some(chain_sw.remaining_bytes());
            let cmd2 = get_resp.to_bytes();
            let resp2 = link.transmit_raw(&cmd2)?;
            let len2 = resp2.len();
            if len2 < 2 {
                return Err(PivError::Other("chained response too short".into()));
            }
            chain_sw = StatusWord::from_bytes(resp2[len2 - 2], resp2[len2 - 1]);
            full.extend_from_slice(&resp2[..len2 - 2]);
        }
        return Ok((full, chain_sw));
    }

    Ok((data, sw))
}

/// The certificate DER out of an ATTEST response. Most YubiKey firmware
/// returns raw DER (starts with SEQUENCE 0x30); some versions wrap the cert
/// in a PIV data object (0x53 { 0x70 = cert }). Both are handled.
fn attestation_cert_der(data: Vec<u8>) -> Vec<u8> {
    if data.first().copied() == Some(0x53) {
        if let Ok(cert_der) = unwrap_piv_cert_object(&data) {
            return cert_der;
        }
    }
    data
}

impl PinSession<'_> {
    /// A slot's PIN and touch policy as its attestation states them, read
    /// inside the session (so right after a GENERATE in the same session).
    /// Needs no PIN. Fails on a card that cannot attest the slot's key: see
    /// [`PivToken::read_slot_policy`].
    pub fn attested_policy(&self, slot_id: u8) -> Result<crate::policy::KeyPolicy, PivError> {
        let (data, sw) = self.transmit(&Apdu::yk_attest(slot_id))?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        let (pin, touch) = crate::attest::parse_policy(&attestation_cert_der(data))?;
        Ok(crate::policy::KeyPolicy { pin, touch })
    }
}

/// Try to unwrap a PIV data object (0x53 { 0x70 = cert_der }).
fn unwrap_piv_cert_object(data: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut reader = TlvReader::new(data);
    let tag = reader.read_tag()?;
    if tag != 0x53 {
        return Err(PivError::Tlv {
            message: "not a PIV data object".into(),
        });
    }
    let inner = reader.read_value()?;
    let mut inner_reader = TlvReader::new(inner);
    while inner_reader.has_remaining() {
        let tag = inner_reader.read_tag()?;
        let value = inner_reader.read_value()?;
        if tag == 0x70 {
            return Ok(value.to_vec());
        }
    }
    Err(PivError::Tlv {
        message: "cert tag (0x70) not found in data object".into(),
    })
}

/// Validate that `peer_ec_point` is an uncompressed SEC1 point whose size
/// matches the slot's curve.
fn validate_ec_point(alg: PivAlgorithm, point: &[u8]) -> Result<(), PivError> {
    let expected_len = match alg {
        PivAlgorithm::EcP256 => 65, // 1 + 32 + 32
        PivAlgorithm::EcP384 => 97, // 1 + 48 + 48
        _ => {
            return Err(PivError::UnsupportedAlgorithm(
                "ECDH requires an EC key (P-256 or P-384)".into(),
            ));
        }
    };
    if point.is_empty() || point[0] != 0x04 {
        return Err(PivError::Crypto(
            "peer EC point must be uncompressed (0x04 prefix)".into(),
        ));
    }
    if point.len() != expected_len {
        return Err(PivError::Crypto(format!(
            "peer EC point length {} does not match curve (expected {})",
            point.len(),
            expected_len,
        )));
    }
    Ok(())
}

/// Parse a GENERAL AUTHENTICATE response: 0x7C { 0x82 = payload }.
fn parse_ga_response(resp: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut reader = TlvReader::new(resp);
    let outer_tag = reader.read_tag()?;
    if outer_tag != 0x7C {
        return Err(PivError::Tlv {
            message: format!("expected GA response tag 0x7C, got {:#X}", outer_tag),
        });
    }
    let inner_data = reader.read_value()?;

    let mut inner_reader = TlvReader::new(inner_data);
    let resp_tag = inner_reader.read_tag()?;
    if resp_tag != ga_tag::RESPONSE as u32 {
        return Err(PivError::Tlv {
            message: format!("expected GA response tag 0x82, got {:#X}", resp_tag),
        });
    }
    let payload = inner_reader.read_value()?;

    Ok(payload.to_vec())
}

#[cfg(feature = "pcsc")]
impl PivContext {
    /// Enumerate all PIV tokens across all readers.
    /// Silently skips readers that don't have PIV cards.
    pub fn enumerate_tokens(&self) -> Result<Vec<PivToken>, PivError> {
        let readers = self.list_readers()?;
        let mut tokens = Vec::new();
        for reader in &readers {
            match PivToken::connect(self, reader) {
                Ok(token) => tokens.push(token),
                Err(_) => continue, // Not a PIV card or not inserted
            }
        }
        Ok(tokens)
    }

    /// Like [`PivContext::enumerate_tokens`], but ALSO includes uninitialized
    /// (factory-blank, no-CHUID) PIV cards — returned with an all-zeros GUID
    /// and [`PivToken::is_initialized`] == `false`. Non-PIV cards are still
    /// skipped. Used by `piggy list` to surface blank cards for provisioning
    /// discovery (piggy#193); other callers keep [`enumerate_tokens`] so a
    /// blank card never perturbs their sole-card auto-selection.
    pub fn enumerate_tokens_including_uninitialized(&self) -> Result<Vec<PivToken>, PivError> {
        let readers = self.list_readers()?;
        let mut tokens = Vec::new();
        for reader in &readers {
            match PivToken::connect_allowing_uninitialized(self, reader) {
                Ok(token) => tokens.push(token),
                Err(_) => continue, // Not a PIV card or not inserted
            }
        }
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sw(sw1: u8, sw2: u8) -> StatusWord {
        StatusWord::from_bytes(sw1, sw2)
    }

    #[test]
    fn parse_serial_ok() {
        // 0x00BC614E = 12345678, big-endian.
        let data = [0x00, 0xBC, 0x61, 0x4E];
        assert_eq!(
            parse_serial_response(&data, sw(0x90, 0x00)),
            Some(12_345_678)
        );
    }

    #[test]
    fn parse_serial_ignores_trailing_bytes() {
        // A response longer than 4 bytes uses only the first 4.
        let data = [0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF];
        assert_eq!(parse_serial_response(&data, sw(0x90, 0x00)), Some(1));
    }

    #[test]
    fn parse_serial_none_on_non_success_sw() {
        // 0x6D00 = instruction not supported (an old YubiKey 4 on PIV 0xF8).
        let data = [0x00, 0x00, 0x00, 0x01];
        assert_eq!(parse_serial_response(&data, sw(0x6D, 0x00)), None);
    }

    #[test]
    fn parse_serial_none_on_short_response() {
        let data = [0x00, 0x00, 0x01]; // only 3 bytes
        assert_eq!(parse_serial_response(&data, sw(0x90, 0x00)), None);
    }

    use crate::transport::{ApduSession, ApduTransport, EndDisposition, RawApdu};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Shared state of a scripted card: canned responses (`data ‖ SW`),
    /// every command sent, and every transaction end disposition.
    #[derive(Default)]
    struct Script {
        responses: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        ended: Vec<EndDisposition>,
    }

    // Arc<Mutex<..>>, not Rc<RefCell<..>>: the transport traits are Send.
    struct ScriptedTransport(Arc<Mutex<Script>>);
    struct ScriptedSession(Arc<Mutex<Script>>);

    fn scripted(responses: &[&[u8]]) -> (Box<dyn ApduTransport>, Arc<Mutex<Script>>) {
        let script = Arc::new(Mutex::new(Script {
            responses: responses.iter().map(|r| r.to_vec()).collect(),
            ..Default::default()
        }));
        (Box::new(ScriptedTransport(script.clone())), script)
    }

    fn pop_response(script: &Mutex<Script>, command: &[u8]) -> Result<Vec<u8>, PivError> {
        let mut s = script.lock().unwrap();
        s.sent.push(command.to_vec());
        s.responses
            .pop_front()
            .ok_or_else(|| PivError::Transport("script exhausted".into()))
    }

    impl RawApdu for ScriptedTransport {
        fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError> {
            pop_response(&self.0, command)
        }
    }
    impl ApduTransport for ScriptedTransport {
        fn begin_transaction<'a>(&'a mut self) -> Result<Box<dyn ApduSession + 'a>, PivError> {
            Ok(Box::new(ScriptedSession(self.0.clone())))
        }
    }
    impl RawApdu for ScriptedSession {
        fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError> {
            pop_response(&self.0, command)
        }
    }
    impl ApduSession for ScriptedSession {
        fn end(self: Box<Self>, disposition: EndDisposition) -> Result<(), PivError> {
            self.0.lock().unwrap().ended.push(disposition);
            Ok(())
        }
    }

    const OK: &[u8] = &[0x90, 0x00];
    const NOT_FOUND: &[u8] = &[0x6A, 0x82];
    const INS_NOT_SUPPORTED: &[u8] = &[0x6D, 0x00];

    /// A factory-blank, non-YubiKey card's answers to the connect
    /// sequence: SELECT PIV, GET DATA CHUID (absent), PIV GET_SERIAL
    /// (unsupported), SELECT OTP applet (absent), re-SELECT PIV.
    const BLANK_CONNECT: [&[u8]; 5] = [OK, NOT_FOUND, INS_NOT_SUPPORTED, NOT_FOUND, OK];

    /// `BLANK_CONNECT` followed by `then`.
    fn blank_card_then(then: &[&[u8]]) -> (Box<dyn ApduTransport>, Arc<Mutex<Script>>) {
        let responses: Vec<&[u8]> = BLANK_CONNECT.iter().chain(then).copied().collect();
        scripted(&responses)
    }

    /// A factory-blank card over any transport.
    fn blank_card_script() -> (Box<dyn ApduTransport>, Arc<Mutex<Script>>) {
        blank_card_then(&[])
    }

    #[test]
    fn from_transport_selects_piv_and_reports_a_blank_card() {
        let (transport, script) = blank_card_script();
        let token = PivToken::from_transport(transport, "scripted 00 00", false)
            .expect("blank card connects on the tolerant path");
        assert!(!token.is_initialized());
        assert_eq!(token.reader_name(), "scripted 00 00");
        let sent = &script.lock().unwrap().sent;
        // The first command is SELECT of the PIV AID, byte for byte.
        assert_eq!(sent[0], Apdu::select(PIV_AID).to_bytes());
    }

    #[test]
    fn from_transport_strict_refuses_a_card_without_chuid() {
        let (transport, _script) = blank_card_script();
        // PivToken has no Debug, so no unwrap_err.
        let Err(err) = PivToken::from_transport(transport, "scripted 00 00", true) else {
            panic!("strict connect accepted a card without a CHUID");
        };
        assert!(matches!(err, PivError::Apdu { sw: 0x6A82 }), "got {err:?}");
    }

    #[test]
    fn pin_session_runs_select_and_verify_through_the_session_and_resets_on_end() {
        // connect: 5 responses; begin_pin_session: SELECT; verify_pin: OK.
        let (transport, script) = blank_card_then(&[OK, OK]);
        let mut token = PivToken::from_transport(transport, "scripted 00 00", false).unwrap();
        {
            let mut session = token.begin_pin_session().expect("session");
            session.verify_pin("123456").expect("verify");
        } // dropped: pin was verified, so the card is reset
        let s = script.lock().unwrap();
        assert_eq!(
            s.sent[5],
            Apdu::select(PIV_AID).to_bytes(),
            "SELECT again inside the transaction"
        );
        assert_eq!(
            s.sent[6],
            vec![
                0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF
            ],
            "VERIFY with the PIN padded to 8 bytes"
        );
        assert_eq!(s.ended, vec![EndDisposition::ResetCard]);
    }

    #[test]
    fn pin_session_without_a_verify_leaves_the_card() {
        let (transport, script) = blank_card_then(&[OK]);
        let mut token = PivToken::from_transport(transport, "scripted 00 00", false).unwrap();
        token
            .begin_pin_session()
            .expect("session")
            .end()
            .expect("end");
        assert_eq!(
            script.lock().unwrap().ended,
            vec![EndDisposition::LeaveCard]
        );
    }

    #[test]
    fn get_response_chaining_is_done_by_the_token_not_the_transport() {
        // SELECT ok; CHUID answered in two chunks: first `AA` + SW 61 01,
        // then `BB` + 90 00, so read_chuid sees `AA BB` and parses (fails
        // as a bad CHUID, which is fine: the point is the second command).
        let (transport, script) = scripted(&[
            OK,
            &[0xAA, 0x61, 0x01],
            &[0xBB, 0x90, 0x00],
            INS_NOT_SUPPORTED,
            INS_NOT_SUPPORTED,
        ]);
        let _ = PivToken::from_transport(transport, "scripted 00 00", false);
        let s = script.lock().unwrap();
        assert_eq!(
            s.sent[2],
            vec![0x00, 0xC0, 0x00, 0x00, 0x01],
            "GET RESPONSE for the 1 remaining byte"
        );
    }
}
