use pcsc::{Disposition, Protocols, ShareMode, Transaction};

use crate::PivContext;
use crate::apdu::{Apdu, PIV_AID, StatusWord, ga_tag};
use crate::cert;
use crate::error::PivError;
use crate::guid::Guid;
use crate::slot::{self, PivAlgorithm, PivSlot};
use crate::tlv::{TlvReader, TlvWriter};

/// Bound on retries when `SCardBeginTransaction` returns
/// `SCARD_W_RESET_CARD`. C pivy (vendor/pivy/src/piv.c::piv_txn_begin)
/// loops unboundedly; the bounded form fails fast against a stuck card
/// while still tolerating routine reset windows between connect() and
/// transaction acquisition. See piggy#56 decision 5.
const PIN_SESSION_RESET_RETRY_CAP: u32 = 3;

/// RAII guard wrapping a single `SCardBeginTransaction` /
/// `SCardEndTransaction` lifetime against a [`PivToken`].
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
/// `Disposition::ResetCard` if any successful `verify_pin` ran
/// during the session, and `Disposition::LeaveCard` otherwise. The
/// `ResetCard` disposition clears PIN-verified state on the card so
/// it does not leak across sessions. Drop swallows
/// `SCardEndTransaction` errors and logs them via `tracing::warn`;
/// the explicit `end` propagates them.
///
/// The session does NOT mirror C pivy's `piv_clear_pin` attempt
/// before disposition (vendor/pivy/src/piv.c::piv_txn_end). That
/// optimization lets cooperative cards retain other state across the
/// reset; piggy chooses the simpler "always reset" rule. Cost: a
/// subsequent client must re-select the PIV applet. Acceptable for
/// the show-batch use case.
pub struct PinSession<'tok> {
    /// `Option` so [`PinSession::end`] can consume the transaction
    /// without `Drop` re-running over `self.txn`. `None` only
    /// transiently inside `end`; outside that path it is always
    /// `Some`.
    txn: Option<Transaction<'tok>>,
    /// True after at least one successful `verify_pin` call within
    /// this session. Drives the end-disposition decision.
    pin_verified: bool,
}

/// CHUID data object tag (NIST SP 800-73-4)
const PIV_TAG_CHUID: u32 = 0x5FC102;

/// Tag for GUID within CHUID
const CHUID_TAG_GUID: u32 = 0x34;

pub struct PivToken {
    card: pcsc::Card,
    guid: Guid,
    reader_name: String,
    /// YubiKey factory serial, cached at connect() time. `None` for
    /// non-YubiKey PIV cards (the vendor-specific INS rejects with a
    /// non-9000 SW) or YubiKey firmware too old to support the INS.
    /// See `read_yk_serial` for the failure-as-None policy.
    yk_serial: Option<u32>,
    /// Whether the card carries a CHUID (and thus a real GUID). `false` for
    /// a factory-blank / uninitialized PIV card. Only `connect_inner` with
    /// `require_chuid = false` can yield `false` here; the strict `connect`
    /// errors instead, so existing callers never see an uninitialized token.
    initialized: bool,
}

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
        let cstr = std::ffi::CString::new(reader).map_err(|e| PivError::Other(e.to_string()))?;
        let card = ctx
            .pcsc_context()
            .connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let mut token = Self {
            card,
            guid: Guid::from_bytes(&[0; 16])?,
            reader_name: reader.to_string(),
            yk_serial: None,
            initialized: false,
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
        token.yk_serial = token.read_yk_serial();
        Ok(token)
    }

    fn transmit(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        transmit_on(&self.card, apdu)
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

    /// Cached YubiKey factory serial. `None` for non-YubiKey PIV cards
    /// or YubiKey firmware that pre-dates the `INS_GET_SERIAL` (0xF8)
    /// vendor extension. Populated at `connect()` time via
    /// `read_yk_serial`; never re-queries the card.
    pub fn yk_serial(&self) -> Option<u32> {
        self.yk_serial
    }

    /// Whether the card is initialized (carries a CHUID, and thus a real
    /// GUID). `false` only for a factory-blank card returned via
    /// [`PivToken::connect_allowing_uninitialized`]; the strict
    /// [`PivToken::connect`] never returns an uninitialized token.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Probe the YubiKey factory-serial vendor INS (0xF8) against the
    /// already-selected PIV applet. Returns the serial on `SW=9000`
    /// with a >=4-byte response, `None` on every other outcome. We
    /// deliberately swallow errors: non-YubiKey cards routinely reject
    /// this INS, and a missing serial is not a connect-time failure.
    /// Mirrors pivy's `ykpiv_read_serial` (vendor/pivy/src/piv.c:644).
    fn read_yk_serial(&self) -> Option<u32> {
        let apdu = Apdu::new(0x00, crate::apdu::ins::YK_GET_SERIAL, 0x00, 0x00);
        let (data, sw) = self.transmit(&apdu).ok()?;
        if !sw.is_success() || data.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
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
        // Most YubiKey firmware returns raw DER (starts with SEQUENCE 0x30).
        // Some versions wrap the cert in a PIV data object (0x53 { 0x70 = cert }).
        // Handle both transparently.
        if data.first().copied() == Some(0x53) {
            if let Ok(cert_der) = unwrap_piv_cert_object(&data) {
                return Ok(cert_der);
            }
        }
        Ok(data)
    }

    /// Begin a PIN-bracketed session over this token. Card operations
    /// performed via the returned [`PinSession`] are atomic with
    /// respect to other PC/SC clients sharing the card — they cannot
    /// reset the card's PIN-verified state between this token's
    /// `verify_pin` and subsequent sign/ECDH calls.
    ///
    /// Retries on `SCardBeginTransaction → SCARD_W_RESET_CARD` by
    /// `SCardReconnect`-ing and retrying. Bounded by
    /// [`PIN_SESSION_RESET_RETRY_CAP`] (= 3); a card stuck in a
    /// reset loop fails fast rather than hanging the agent.
    ///
    /// Mirrors the lifecycle structure of
    /// `vendor/pivy/src/piv.c::piv_txn_begin` but does not (yet)
    /// attempt `piv_clear_pin` before disposition. See the
    /// [`PinSession`] type docs.
    pub fn begin_pin_session(&mut self) -> Result<PinSession<'_>, PivError> {
        // Two-phase retry: prepare the card for transaction
        // acquisition (running `reconnect` if a prior call would have
        // returned ResetCard), then acquire once and return. The
        // prepare phase NEVER retains the success borrow across
        // iterations — the local enum below carries only owned
        // values out of each iteration's match, so the borrow
        // checker can see iterations as independent.
        //
        // The two-phase approach has a tiny race window: another
        // PC/SC client could reset the card between the prepare loop
        // exiting and the final `transaction()` below. That
        // ResetCard surfaces as `PivError::Pcsc` to the caller (not
        // retried). The window is the same shape as C pivy's
        // `piv_txn_begin`'s race between its `SCardReconnect`
        // success and the `goto retry`'s next `SCardBeginTransaction`,
        // and hasn't been reported as a real problem there.
        enum Peek {
            Ready,
            NeedsReconnect,
            Fatal(pcsc::Error),
        }
        for attempt in 1..=PIN_SESSION_RESET_RETRY_CAP {
            let peek: Peek = match self.card.transaction() {
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
        Ok(PinSession {
            txn: Some(txn),
            pin_verified: false,
        })
    }
}

impl<'tok> PinSession<'tok> {
    /// Verify the PIV PIN inside the active transaction. PIN-verified
    /// state set by this call is owned by the session and is cleared
    /// when the session ends (via `Disposition::ResetCard`).
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
    /// Requires a prior `verify_pin` for slots whose PIN policy
    /// demands it; this method does NOT pre-check (the card enforces
    /// the policy and returns SW=6982 if the PIN is required and
    /// missing), matching C pivy's behavior.
    pub fn sign_prehash(&mut self, slot_id: u8, data: &[u8]) -> Result<Vec<u8>, PivError> {
        let slot = self.read_slot(slot_id)?;
        self.general_authenticate(slot.algorithm().to_byte(), slot_id, ga_tag::CHALLENGE, data)
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
    /// session's transaction. Same PIN-policy semantics as `sign_prehash`.
    pub fn ecdh_derive(&mut self, slot_id: u8, peer_ec_point: &[u8]) -> Result<Vec<u8>, PivError> {
        let slot = self.read_slot(slot_id)?;
        validate_ec_point(slot.algorithm(), peer_ec_point)?;
        self.general_authenticate(
            slot.algorithm().to_byte(),
            slot_id,
            ga_tag::EXPONENT,
            peer_ec_point,
        )
    }

    /// Explicit termination: end the transaction with the
    /// appropriate disposition (`ResetCard` if any `verify_pin`
    /// succeeded in this session, `LeaveCard` otherwise) and return
    /// any error from `SCardEndTransaction`.
    ///
    /// On error the `Transaction` is dropped, which itself runs
    /// `SCardEndTransaction(SCARD_LEAVE_CARD)` again as a backstop;
    /// pcscd handles the redundancy.
    ///
    /// After `end` returns, `Drop` is a no-op (`self.txn` is `None`).
    pub fn end(mut self) -> Result<(), PivError> {
        let disposition = self.disposition();
        let txn = self.txn.take().expect("PinSession::end called twice");
        txn.end(disposition).map_err(|(_, e)| PivError::Pcsc(e))
    }

    fn disposition(&self) -> Disposition {
        if self.pin_verified {
            Disposition::ResetCard
        } else {
            Disposition::LeaveCard
        }
    }

    /// Read a slot's cert and public key. Does not need PIN, but
    /// lives on `PinSession` so callers don't have to break out of
    /// the session borrow to call it on the underlying token.
    fn read_slot(&self, slot_id: u8) -> Result<PivSlot, PivError> {
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
        let txn = self
            .txn
            .as_ref()
            .expect("PinSession transmit after end/drop");
        // pcsc::Transaction: Deref<Target = pcsc::Card>, so &**txn is
        // a &pcsc::Card. transmit_on routes APDU + GET RESPONSE chain
        // through it identically to PivToken::transmit.
        transmit_on(txn, apdu)
    }
}

impl<'tok> Drop for PinSession<'tok> {
    fn drop(&mut self) {
        if let Some(txn) = self.txn.take() {
            let disp = if self.pin_verified {
                Disposition::ResetCard
            } else {
                Disposition::LeaveCard
            };
            if let Err((_, e)) = txn.end(disp) {
                tracing::warn!(
                    error = %e,
                    pin_verified = self.pin_verified,
                    "SCardEndTransaction failed during PinSession drop"
                );
            }
        }
    }
}

/// Send an APDU on `card`, handle GET RESPONSE chaining (SW 61xx),
/// and return the assembled payload plus the final status word.
/// Shared body for `PivToken::transmit` and `PinSession::transmit`
/// (the latter goes through `pcsc::Transaction`'s `Deref<Target=Card>`).
fn transmit_on(card: &pcsc::Card, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
    let cmd = apdu.to_bytes();
    let mut resp_buf = vec![0u8; 4096];
    let resp = card.transmit(&cmd, &mut resp_buf)?;
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
            let mut resp_buf2 = vec![0u8; 4096];
            let resp2 = card.transmit(&cmd2, &mut resp_buf2)?;
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
