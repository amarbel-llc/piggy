# pigsty piggy-side work Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Land the three pieces of piggy that the pigsty vault app (`docs/plans/2026-10-25-pigsty-design.md` §6) and madder's Rust store crate need from this repo: a card transport seam in piggy-piv, the agent ECDH extension rename with an indefinite alias (piggy#335), and the docs that go with both.

**Architecture:** piggy-piv's PIV session logic (`token.rs`) is lifted off `pcsc::Card` onto a small `ApduTransport` / `ApduSession` trait pair, with PC/SC as the first implementation and fibby's `VirtualCard` as an in-process test implementation; every public API stays the same. The agent answers the ECDH extension under both `ecdh@code.linenisgreat.com` (canonical) and `ecdh@joyent.com` (legacy alias), echoes whichever name it was asked with, and keeps the pinned telemetry label; the Rust and Go clients send the canonical name and fall back to the legacy one on refusal, so every pairing of old and new agent and client keeps working.

**Tech Stack:** Rust (`crates/piggy-piv`, `crates/piggy`, `crates/fibby` as a dev-dependency), Go (`go/internal/delta/agent`, `go/cmd/piggy-agent-conformance`), scdoc manpages, just recipes.

**Rollback:** Task 1 and 2 are one behavior-preserving refactor with no wire or CLI change: revert the commit. Tasks 3 to 5 are additive (an alias): reverting them returns to the legacy name only; nothing written to disk changes.

**Paved paths:** `just validate-rust -p <crate>`, `just test-rust -p <crate> -- <filter>`, `just lint-rust`, `just codemod-fmt`, `just test-go`, `just codemod-fmt-go`, `just test-bats-conformance-sign-bytes-fibby`, `just debug-conformance-run`. Never bare cargo/go/bats. Do not run bare `just` before `merge-this-session`; the merge hook is the gate.

**Already done (drop from the queue):** the October 5 plan listed "align `piggy_pigpen::Pointer::parse` with Go `ParsePointer`". Read side by side on 2026-10-25, `crates/piggy-pigpen/src/document.rs:398` and `go/internal/delta/pigpen/pointer.go:21` reject the same shapes (a second `!` line, a body, a repeated or foreign `-` line, a missing tag, a bad kind). Task 6 records that in the old plan.

**Out of scope here:** piggy-piv still links OpenSSL (`cert.rs`, `keygen.rs`); making the crate build for `aarch64-linux-android` and wasm is pigsty phase-0 work and gets its own issue. Any `piggy-pigpen` API `madder/live-cedar` asks for is added as a task when the request arrives.

---

### Task 1: `ApduTransport` seam in piggy-piv, PC/SC behind it

**Promotion criteria:** N/A (refactor; no old approach remains).

**Files:**
- Create: `crates/piggy-piv/src/transport.rs`
- Modify: `crates/piggy-piv/src/lib.rs` (add `pub mod transport;` and re-exports)
- Modify: `crates/piggy-piv/src/error.rs:4-49` (add a `Transport` variant)
- Modify: `crates/piggy-piv/src/token.rs:1`, `:44-53`, `:61-84`, `:97-161`, `:521-584`, `:703-715`, `:776-846`
- Test: `crates/piggy-piv/src/token.rs` (`mod tests`, new cases)

**Step 1: Write the failing tests.** Append to `mod tests` at the bottom of `crates/piggy-piv/src/token.rs` (after `parse_serial_none_on_short_response`). They use a scripted transport that records every command APDU and replays canned responses, so no card and no pcscd is involved.

```rust
    use crate::transport::{ApduSession, ApduTransport, EndDisposition, RawApdu};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// Shared state of a scripted card: canned responses (`data ‖ SW`),
    /// every command sent, and every transaction end disposition.
    #[derive(Default)]
    struct Script {
        responses: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        ended: Vec<EndDisposition>,
    }

    struct ScriptedTransport(Rc<RefCell<Script>>);
    struct ScriptedSession(Rc<RefCell<Script>>);

    fn scripted(responses: &[&[u8]]) -> (Box<dyn ApduTransport>, Rc<RefCell<Script>>) {
        let script = Rc::new(RefCell::new(Script {
            responses: responses.iter().map(|r| r.to_vec()).collect(),
            ..Default::default()
        }));
        (Box::new(ScriptedTransport(script.clone())), script)
    }

    fn pop_response(script: &RefCell<Script>, command: &[u8]) -> Result<Vec<u8>, PivError> {
        let mut s = script.borrow_mut();
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
            self.0.borrow_mut().ended.push(disposition);
            Ok(())
        }
    }

    const OK: &[u8] = &[0x90, 0x00];
    const NOT_FOUND: &[u8] = &[0x6A, 0x82];
    const INS_NOT_SUPPORTED: &[u8] = &[0x6D, 0x00];

    /// SELECT PIV, GET DATA CHUID (absent), the two serial reads (both
    /// unsupported): a factory-blank card over any transport.
    fn blank_card_script() -> (Box<dyn ApduTransport>, Rc<RefCell<Script>>) {
        scripted(&[OK, NOT_FOUND, INS_NOT_SUPPORTED, INS_NOT_SUPPORTED])
    }

    #[test]
    fn from_transport_selects_piv_and_reports_a_blank_card() {
        let (transport, script) = blank_card_script();
        let token = PivToken::from_transport(transport, "scripted 00 00", false)
            .expect("blank card connects on the tolerant path");
        assert!(!token.is_initialized());
        assert_eq!(token.reader_name(), "scripted 00 00");
        let sent = &script.borrow().sent;
        // The first command is SELECT of the PIV AID, byte for byte.
        assert_eq!(sent[0], Apdu::select(PIV_AID).to_bytes());
    }

    #[test]
    fn from_transport_strict_refuses_a_card_without_chuid() {
        let (transport, _script) = blank_card_script();
        let err = PivToken::from_transport(transport, "scripted 00 00", true).unwrap_err();
        assert!(matches!(err, PivError::Apdu { sw: 0x6A82 }), "got {err:?}");
    }

    #[test]
    fn pin_session_runs_select_and_verify_through_the_session_and_resets_on_end() {
        // connect: 4 responses; begin_pin_session: SELECT; verify_pin: OK.
        let (transport, script) = scripted(&[OK, NOT_FOUND, INS_NOT_SUPPORTED, INS_NOT_SUPPORTED, OK, OK]);
        let mut token = PivToken::from_transport(transport, "scripted 00 00", false).unwrap();
        {
            let mut session = token.begin_pin_session().expect("session");
            session.verify_pin("123456").expect("verify");
        } // dropped: pin was verified, so the card is reset
        let s = script.borrow();
        assert_eq!(s.sent[4], Apdu::select(PIV_AID).to_bytes(), "SELECT again inside the transaction");
        assert_eq!(
            s.sent[5],
            vec![0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF],
            "VERIFY with the PIN padded to 8 bytes"
        );
        assert_eq!(s.ended, vec![EndDisposition::ResetCard]);
    }

    #[test]
    fn pin_session_without_a_verify_leaves_the_card() {
        let (transport, script) = scripted(&[OK, NOT_FOUND, INS_NOT_SUPPORTED, INS_NOT_SUPPORTED, OK]);
        let mut token = PivToken::from_transport(transport, "scripted 00 00", false).unwrap();
        token.begin_pin_session().expect("session").end().expect("end");
        assert_eq!(script.borrow().ended, vec![EndDisposition::LeaveCard]);
    }

    #[test]
    fn get_response_chaining_is_done_by_the_token_not_the_transport() {
        // SELECT ok; CHUID answered in two chunks: first `AA` + SW 61 01,
        // then `BB` + 90 00, so read_chuid sees `AA BB` and parses (fails
        // as a bad CHUID, which is fine: the point is the second command).
        let (transport, script) = scripted(&[OK, &[0xAA, 0x61, 0x01], &[0xBB, 0x90, 0x00], INS_NOT_SUPPORTED, INS_NOT_SUPPORTED]);
        let _ = PivToken::from_transport(transport, "scripted 00 00", false);
        let s = script.borrow();
        assert_eq!(s.sent[2], vec![0x00, 0xC0, 0x00, 0x00, 0x01], "GET RESPONSE for the 1 remaining byte");
    }
```

If `token.reader_name()` or `token.is_initialized()` do not exist under those names, read `token.rs:180-320` for the accessors and use the ones that do; do not add new ones.

**Step 2: Run them to see them fail.**

Run: `just test-rust -p piggy-piv -- token::tests`
Expected: compile error, `transport` module and `from_transport` not found.

**Step 3: Create `crates/piggy-piv/src/transport.rs`.**

```rust
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
/// fails fast instead of hanging the agent.
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

/// A connection to one card.
pub trait ApduTransport: RawApdu {
    /// Begin an exclusive transaction. The session borrows the transport
    /// for its lifetime; ending it (or dropping it) releases the card.
    fn begin_transaction<'a>(&'a mut self) -> Result<Box<dyn ApduSession + 'a>, PivError>;
}

/// An open transaction. A transport whose medium has no transactions (a
/// single-client NFC link) returns a session that forwards to the
/// connection and treats `end` as a no-op.
pub trait ApduSession: RawApdu {
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
```

**Step 4: Add the error variant.** In `crates/piggy-piv/src/error.rs`, after the `Pcsc` variant:

```rust
    /// A non-PC/SC transport (a scripted test card, an NFC link) failed.
    #[error("transport error: {0}")]
    Transport(String),
```

**Step 5: Refactor `token.rs` onto the seam.** Make exactly these changes:

1. Line 1: replace `use pcsc::{Disposition, Protocols, ShareMode, Transaction};` with `use crate::transport::{ApduSession, ApduTransport, EndDisposition, PcscTransport, RawApdu};`. Remove the local `PIN_SESSION_RESET_RETRY_CAP` constant and its doc (lines 11-16) if the transport module now owns it; keep the `PinSession` type docs (lines 17-43), rewording "SCardBeginTransaction / SCardEndTransaction lifetime" to "transaction lifetime on the token's transport".
2. `PinSession` (lines 44-53): replace the `txn: Option<Transaction<'tok>>` field with `session: Option<Box<dyn ApduSession + 'tok>>`; keep `pin_verified`.
3. `PivToken` (line 62): replace `card: pcsc::Card` with `transport: Box<dyn ApduTransport>`.
4. `connect_inner` (lines 120-157): becomes

```rust
    fn connect_inner(
        ctx: &PivContext,
        reader: &str,
        require_chuid: bool,
    ) -> Result<Self, PivError> {
        let transport = PcscTransport::connect(ctx, reader)?;
        Self::from_transport(Box::new(transport), reader, require_chuid)
    }

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
```

   Keep the existing comment block about the tolerant path on the `Err(e)` arm.
5. `PivToken::transmit` (line 159): `transmit_on(&*self.transport, apdu)`.
6. `begin_pin_session` (lines 521-584): the retry loop moved to `PcscTransport::begin_transaction`, so the body becomes

```rust
    pub fn begin_pin_session(&mut self) -> Result<PinSession<'_>, PivError> {
        let session = self.transport.begin_transaction()?;
        // SELECT PIV again, inside the transaction, every time: another
        // client's session may have ended with ResetCard since connect, and
        // a reset card has no applet selected (piggy#323, #325).
        let (_, sw) = transmit_on(&*session, &Apdu::select(PIV_AID))?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(PinSession {
            session: Some(session),
            pin_verified: false,
        })
    }
```

   Keep the doc comment, replacing its retry paragraph with a pointer to `transport::PcscTransport::begin_transaction`.
7. `PinSession::end` and `disposition` (lines 703-715): `end` takes `self.session.take()` and calls `.end(self.disposition())`; `disposition` returns `EndDisposition::{ResetCard,LeaveCard}`.
8. `PinSession::transmit` (lines 779-788): `transmit_on(&**self.session.as_ref().expect("PinSession transmit after end/drop"), apdu)`.
9. `Drop for PinSession` (lines 791-808): take `self.session`, call `end(disp)`, log on `Err(e)` as today.
10. `transmit_on` (lines 814-846): signature `fn transmit_on(link: &dyn RawApdu, apdu: &Apdu)`, replacing each `card.transmit(&cmd, &mut buf)?` with `link.transmit_raw(&cmd)?`; the 61xx chaining logic is unchanged. Its doc says both token and session go through it; keep that.

Search `token.rs` for any remaining `self.card`, `pcsc::`, `Disposition`, `ShareMode`, `Protocols`; there must be none.

**Step 6: Wire `lib.rs`.** Add `pub mod transport;` in alphabetical position and `pub use transport::{ApduSession, ApduTransport, EndDisposition, PcscTransport, RawApdu};` after the existing re-exports.

**Step 7: Run the piggy-piv tests.**

Run: `just test-rust -p piggy-piv`
Expected: PASS, the five new tests included. The `tests/*.rs` files in piggy-piv skip without a card.

**Step 8: Build everything that links piggy-piv.**

Run: `just validate-rust` then `just lint-rust`
Expected: both clean. The `piggy` crate, `age-plugin-piggy` and `piggy-ids` only use `PivContext`, `PivToken::connect*`, `enumerate_tokens*` and `begin_pin_session`, none of which changed shape.

**Step 9: Live smoke over fibby through PC/SC.**

Run: `just test-bats-conformance-sign-bytes-fibby`
Expected: PASS (the PIN session, SELECT-in-transaction and ResetCard disposition all run against the virtual card through real pcsc-lite framing).

**Step 10: Format and commit.**

Run: `just codemod-fmt`
```
git add crates/piggy-piv/src/transport.rs crates/piggy-piv/src/token.rs crates/piggy-piv/src/error.rs crates/piggy-piv/src/lib.rs
git commit -m "piggy-piv: PIV session logic over an ApduTransport seam, PC/SC behind it

PivToken and PinSession no longer hold a pcsc::Card; they talk to the card
through ApduTransport / ApduSession, with PcscTransport as the one
production implementation and PivToken::from_transport as the seam a host
without PC/SC (pigsty on Android) uses. The SCARD_W_RESET_CARD retry and
the end-of-session disposition move into the PC/SC transport unchanged.
No public API changes; pigsty design §1 and §6."
```

---

### Task 2: fibby's `VirtualCard` as an in-process transport

**Promotion criteria:** N/A (additive test).

**Files:**
- Modify: `crates/piggy-piv/Cargo.toml` (add `[dev-dependencies] fibby = { path = "../fibby" }`)
- Create: `crates/piggy-piv/tests/fibby_transport_tests.rs`

fibby does not depend on piggy-piv (`crates/fibby/Cargo.toml`), so the dev-dependency makes no cycle. Keep the adapter inside the test file: pigsty will write its own Android transport, and a reusable fibby adapter is promoted only when a second consumer needs it.

**Step 1: Write the failing test.**

```rust
//! piggy-piv's PIV session logic over fibby's VirtualCard, in process: no
//! pcscd, no socket, no PC/SC. Proves the transport seam carries a whole
//! PIN session (SELECT, VERIFY, retry counter, reset-on-end) and gives
//! pigsty's Android transport the shape to copy.

use std::cell::RefCell;
use std::rc::Rc;

use fibby::backend::Backend;
use fibby::proto;
use fibby::virtual_card::VirtualCard;
use piggy_piv::{ApduSession, ApduTransport, EndDisposition, PivError, PivToken, RawApdu};

struct FibbyTransport(Rc<RefCell<VirtualCard>>);
struct FibbySession(Rc<RefCell<VirtualCard>>);

fn transmit(card: &RefCell<VirtualCard>, command: &[u8]) -> Result<Vec<u8>, PivError> {
    card.borrow_mut()
        .transmit(command)
        .map_err(|scard| PivError::Transport(format!("fibby SCARD {scard:#010x}")))
}

impl RawApdu for FibbyTransport {
    fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError> {
        transmit(&self.0, command)
    }
}
impl ApduTransport for FibbyTransport {
    fn begin_transaction<'a>(&'a mut self) -> Result<Box<dyn ApduSession + 'a>, PivError> {
        Ok(Box::new(FibbySession(self.0.clone())))
    }
}
impl RawApdu for FibbySession {
    fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError> {
        transmit(&self.0, command)
    }
}
impl ApduSession for FibbySession {
    fn end(self: Box<Self>, disposition: EndDisposition) -> Result<(), PivError> {
        let disposition = match disposition {
            EndDisposition::LeaveCard => proto::disposition::LEAVE_CARD,
            EndDisposition::ResetCard => proto::disposition::RESET_CARD,
        };
        self.0.borrow_mut().end_transaction(disposition);
        Ok(())
    }
}

fn connected_blank_card() -> (PivToken, Rc<RefCell<VirtualCard>>) {
    let mut card = VirtualCard::new();
    card.connect(proto::share_mode::SHARED, proto::protocol::T1)
        .expect("virtual card powers up");
    let card = Rc::new(RefCell::new(card));
    let token = PivToken::from_transport(Box::new(FibbyTransport(card.clone())), "fibby in-process", false)
        .expect("a blank VirtualCard connects on the tolerant path");
    (token, card)
}

#[test]
fn wrong_then_right_pin_over_the_in_process_card() {
    let (mut token, _card) = connected_blank_card();
    let mut session = token.begin_pin_session().expect("session");
    match session.verify_pin("000000") {
        Err(PivError::PinIncorrect { retries }) => assert_eq!(retries, 2),
        other => panic!("expected PinIncorrect with 2 retries, got {other:?}"),
    }
    session.verify_pin("123456").expect("factory PIN verifies");
    session.end().expect("end resets the card");
}

#[test]
fn a_reset_end_clears_the_verified_pin_for_the_next_session() {
    let (mut token, _card) = connected_blank_card();
    token.begin_pin_session().unwrap().verify_pin("123456").unwrap();
    // The session dropped with the PIN verified, so the card was reset:
    // a protected operation in a fresh session must demand the PIN again.
    let session = token.begin_pin_session().unwrap();
    let err = session.read_slot(0x9D).or_else(|_| Err::<_, PivError>(PivError::SlotEmpty(0x9D)));
    assert!(matches!(err, Err(PivError::SlotEmpty(0x9D))), "blank 9D: {err:?}");
}
```

The names `proto::disposition::*`, `proto::share_mode::*` and `proto::protocol::T1` are the ones `fibby::backend::Backend`'s docs cite (`crates/fibby/src/backend.rs:76-82`); confirm the exact constant names in `crates/fibby/src/proto.rs` before running and fix the paths, not the test's intent. If `VirtualCard::connect` needs the card inserted first or returns a different protocol, read `crates/fibby/src/virtual_card.rs:1258-1330` (`impl Backend for VirtualCard`) and adjust the setup only.

**Step 2: Run it to see it fail.**

Run: `just test-rust -p piggy-piv -- --test fibby_transport_tests` (if the filter form differs, `just test-rust -p piggy-piv -- fibby_transport`)
Expected: FAIL to compile, `fibby` not a dependency.

**Step 3: Add the dev-dependency.** In `crates/piggy-piv/Cargo.toml`:

```toml
[dev-dependencies]
# fibby's VirtualCard as an in-process ApduTransport (pigsty design §5):
# the PIV session logic runs against the virtual card without pcscd.
fibby = { path = "../fibby" }
```

**Step 4: Run to see it pass.**

Run: `just test-rust -p piggy-piv -- fibby_transport`
Expected: PASS, 2 tests. If `nix build` lanes complain about the new dev-dependency, `just build-nix` must still succeed; the shared `Cargo.lock` gains no new external crates since fibby is already a workspace member.

**Step 5: Commit.**

```
git add crates/piggy-piv/Cargo.toml crates/piggy-piv/tests/fibby_transport_tests.rs
git commit -m "piggy-piv: PIN session over fibby's VirtualCard in process

The ApduTransport seam carries a whole PIN session (SELECT, wrong and right
VERIFY, reset on end) against the virtual card with no pcscd or socket; the
adapter in the test is the shape pigsty's Android transport copies."
```

Then record the attestation (`nothing-but-the-truth`) and `merge-this-session-async`; continue with Task 3 while it runs.

---

### Task 3: agent answers `ecdh@code.linenisgreat.com` and keeps `ecdh@joyent.com` (piggy#335)

**Promotion criteria:** the legacy name is kept indefinitely (piggy#335); a later issue decides otherwise.

**Files:**
- Create: `crates/piggy/src/ecdh_ext.rs`
- Modify: `crates/piggy/src/lib.rs` (add `pub mod ecdh_ext;`)
- Modify: `crates/piggy/src/cmd/agent/session.rs:310-318`, `:514-529`, `:596-614`, `:1078-1081`
- Test: `crates/piggy/src/cmd/agent/session.rs` (`mod tests`, near `:2489` and `:2722`)

**Step 1: Write the failing tests.** Next to the existing `query` test at `session.rs:2489` and the `ecdh_request_for_foreign_key` helper at `:2722`, add:

```rust
    #[tokio::test]
    async fn query_advertises_both_ecdh_names() {
        let names = query_names_of_a_bare_agent().await; // reuse the helper the test at :2489 uses to list names; if none exists, build the session as that test does and decode the flat list with `flat_names`
        assert!(names.iter().any(|n| n == crate::ecdh_ext::CANONICAL), "{names:?}");
        assert!(names.iter().any(|n| n == crate::ecdh_ext::LEGACY), "{names:?}");
    }

    #[tokio::test]
    async fn ecdh_under_the_canonical_name_is_served_and_echoes_that_name() {
        // Same setup as the native ecdh test near :2722 (virtual card key,
        // PIN cached), but the request is named CANONICAL.
        let mut req = ecdh_request_for_native_key();
        req.name = crate::ecdh_ext::CANONICAL.into();
        let resp = session.extension(req).await.expect("served").expect("extension response");
        assert_eq!(resp.name.as_str(), crate::ecdh_ext::CANONICAL);
    }

    #[tokio::test]
    async fn ecdh_under_the_legacy_name_still_echoes_the_legacy_name() {
        let req = ecdh_request_for_native_key(); // named LEGACY
        let resp = session.extension(req).await.expect("served").expect("extension response");
        assert_eq!(resp.name.as_str(), crate::ecdh_ext::LEGACY);
    }

    #[test]
    fn both_ecdh_names_share_the_pinned_metric_label() {
        assert_eq!(crate::ecdh_ext::metric_label(crate::ecdh_ext::CANONICAL), crate::ecdh_ext::LEGACY);
        assert_eq!(crate::ecdh_ext::metric_label(crate::ecdh_ext::LEGACY), crate::ecdh_ext::LEGACY);
        assert_eq!(crate::ecdh_ext::metric_label("query"), "query");
    }
```

Read the existing tests around `:2700-2850` for the real session-construction helper names and the native-key request builder (the one whose key IS cached, as opposed to `ecdh_request_for_foreign_key`); use those names. If no native-key ECDH test exists in this module, the serve-and-echo tests go into the fibby-backed integration test `crates/piggy/tests/agent_ecdh_integration.rs` instead (Task 4 touches it anyway), and this task keeps only the query and metric tests here.

**Step 2: Run to see them fail.**

Run: `just test-rust -p piggy -- ecdh_ext`
Expected: compile error, `crate::ecdh_ext` missing.

**Step 3: Create `crates/piggy/src/ecdh_ext.rs`.**

```rust
//! Names of the agent's card ECDH extension (piggy#335).
//!
//! The extension was inherited from C pivy-agent as `ecdh@joyent.com`.
//! piggy now owns the protocol, so the canonical name is
//! `ecdh@code.linenisgreat.com`; the legacy name stays an alias for as
//! long as anything might speak it (indefinitely, per piggy#335). The wire
//! encoding is identical under both names. Literals are assembled by
//! concatenation so editing tools cannot mangle the email-like strings.

/// The name piggy clients send first and the agent prefers.
pub const CANONICAL: &str = concat!("ecdh@", "code.linenisgreat.com");

/// The name C pivy-agent and every piggy before #335 speak.
pub const LEGACY: &str = concat!("ecdh@", "joyent.com");

/// Both names, canonical first: the order a client tries them in.
pub const NAMES: [&str; 2] = [CANONICAL, LEGACY];

pub fn is_ecdh(name: &str) -> bool {
    NAMES.contains(&name)
}

/// The telemetry label for an extension request. The `piggy.agent.*`
/// category is pinned byte-identical to the C agent's mirror
/// (`stats.rs::payload_agent_category_is_byte_identical_to_the_c_mirror`),
/// so both ECDH names record under the legacy label; every other
/// extension records under its own name.
pub fn metric_label(name: &str) -> &str {
    if is_ecdh(name) { LEGACY } else { name }
}
```

Add `pub mod ecdh_ext;` to `crates/piggy/src/lib.rs`.

**Step 4: Change `session.rs`.**

1. `extension` (line 314): `let op = crate::ecdh_ext::metric_label(extension.name.as_str()).to_owned();` and update the comment to say both ECDH names share the legacy label.
2. `query` (lines 516-526): replace the `"ecdh@joyent.com",` entry with `crate::ecdh_ext::CANONICAL, crate::ecdh_ext::LEGACY,`.
3. Dispatch (line 596): the arm becomes `name if crate::ecdh_ext::is_ecdh(name) || name == "ecdh-rebox@joyent.com" || name == "ykpiv-attest@joyent.com" => {`, and inside, line 599 becomes `n if crate::ecdh_ext::is_ecdh(n) => self.handle_ecdh(n, &details).await,`.
4. `handle_ecdh` (line 995): takes `name: &str` as its first argument and echoes it at line 1079: `name: name.to_string().into(),`. Update its two callers (the dispatch and any test calling it directly).
5. Forwarding (lines 606-612): when the native miss forwards to upstreams and `extension.name == CANONICAL`, try the canonical request first and, on `Err`, the same request renamed to `LEGACY` (a C pivy-agent or a pre-#335 piggy upstream knows only that name):

```rust
                    Err(NativeExtError::KeyNotNative(_)) if !self.upstreams.is_empty() => {
                        tracing::debug!(extension = %extension.name, "card key not served natively; forwarding to upstreams");
                        let first = self.upstreams.forward_extension(extension.clone()).await;
                        if first.is_ok() || extension.name.as_str() != crate::ecdh_ext::CANONICAL {
                            first
                        } else {
                            let mut legacy = extension;
                            legacy.name = crate::ecdh_ext::LEGACY.into();
                            self.upstreams.forward_extension(legacy).await
                        }
                    }
```

   The reply echoes whatever name the upstream answered with; the proxy passes it through unchanged (the client that asked under the canonical name handles a legacy echo, Task 4).

**Step 5: Run the tests.**

Run: `just test-rust -p piggy -- ecdh`
Expected: PASS including the new ones; the existing `query` test at `:2489` that counts `ecdh@joyent.com` once still passes.

Run: `just test-rust -p piggy -- stats`
Expected: PASS (the pinned mirror test is untouched).

**Step 6: Commit.**

```
git add crates/piggy/src/ecdh_ext.rs crates/piggy/src/lib.rs crates/piggy/src/cmd/agent/session.rs
git commit -m "agent: answer ecdh@code.linenisgreat.com, keep ecdh@joyent.com as an alias

Both names dispatch to the same handler and the reply echoes the name
asked; query advertises both; the telemetry label stays the legacy one
so the pinned piggy.agent.* mirror is unchanged. A proxy-only agent that
forwards a canonical request to an upstream knowing only the legacy name
retries under it. Refs piggy#335."
```

---

### Task 4: Rust clients send the canonical name and fall back

**Promotion criteria:** N/A.

**Files:**
- Modify: `crates/piggy/src/agent_client.rs:65-98` (`AgentEcdhOracle::ecdh`), `:754-758` (test constant)
- Modify: `crates/piggy/src/health.rs:19-21`, `:952-958`, `:1337`
- Test: `crates/piggy/src/agent_client.rs` (`mod tests`), `crates/piggy/src/health.rs` (`mod tests`), `crates/piggy/tests/agent_ecdh_integration.rs`

**Step 1: Write the failing tests.**

In `health.rs` tests, next to the fixture at `:1337` that lists `ECDH_EXT`, add a case where the agent advertises only the canonical name and assert `results[4]` ("agent: advertises ecdh extension") is `Status::Pass`; and one where it advertises only the legacy name, also Pass; and one with neither, Fail. Copy the surrounding fixture-building code.

In `agent_client.rs` tests, add a stub-agent test if the module has a stub (the `upstream_stub` used in `session.rs` tests is in `cmd/agent`; if `agent_client` tests cannot reach it, put this test in `crates/piggy/tests/agent_ecdh_integration.rs` under the same `PCSCLITE_CSOCK_NAME`/`PIGGY_BIN` gate):

```rust
/// Against the real agent (which now serves both names), the oracle's
/// first request goes out under the canonical name and succeeds; against
/// a stub that refuses the canonical name, the second request goes out
/// under the legacy name and succeeds.
```

For the integration file, extend `ecdh_roundtrip_against_real_agent` with a second oracle call after `probe_extensions` and assert the advertised list contains both `piggy::ecdh_ext::CANONICAL` and `piggy::ecdh_ext::LEGACY`.

**Step 2: Run to see them fail.**

Run: `just test-rust -p piggy -- health::tests`
Expected: the canonical-only case FAILS (the probe checks `== ECDH_EXT`, the legacy name).

**Step 3: Implement.**

`agent_client.rs:65-98`: send `crate::ecdh_ext::CANONICAL`; if the call returns an error (the agent's `SSH_AGENT_FAILURE` surfaces as `Err` from `client.extension`), retry once with `crate::ecdh_ext::LEGACY` on a fresh connection; accept a reply whose echoed name is either (the proxy case). Keep the connect-per-call shape:

```rust
        self.runtime.block_on(async move {
            let mut last_err = None;
            for name in crate::ecdh_ext::NAMES {
                match ecdh_once(&socket_path, name, &request_bytes).await {
                    Ok(secret) => return Ok(secret),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.expect("NAMES is non-empty"))
        })
```

with `ecdh_once` holding the body that is there today (connect, `client.extension`, `ok_or_else`, `decode_ecdh_response`). A `Protocol` error (bad bytes from an agent that did answer) must NOT trigger the fallback: return it at once. Only `Transport`-class failures from the extension call fall through.

`health.rs`: replace `ECDH_EXT` with `pub use crate::ecdh_ext::{CANONICAL as ECDH_EXT, LEGACY as ECDH_EXT_LEGACY};` or simply make the check at `:955` `names.iter().any(|n| piggy::ecdh_ext::is_ecdh(n))` (health.rs is in the binary crate; use the path that compiles). Rename the check's detail text to say which name was found. Update the test constant at `agent_client.rs:758` to use `crate::ecdh_ext::LEGACY`.

**Step 4: Run.**

Run: `just test-rust -p piggy -- health` and `just test-rust -p piggy -- agent_client`
Expected: PASS.

Run: `just test-rust-integration-fibby`
Expected: PASS; the integration test's round-trip now goes out under the canonical name against the Task 3 agent.

**Step 5: Commit.**

```
git add crates/piggy/src/agent_client.rs crates/piggy/src/health.rs crates/piggy/tests/agent_ecdh_integration.rs
git commit -m "agent clients: ask for ecdh@code.linenisgreat.com first, fall back to the legacy name

AgentEcdhOracle tries the canonical name and retries under ecdh@joyent.com
when the agent refuses it, so a new client works against a C pivy-agent or
a pre-#335 piggy-agent; piggy health passes when either name is
advertised. Refs piggy#335."
```

---

### Task 5: Go client fallback and the conformance suite

**Promotion criteria:** N/A.

**Files:**
- Modify: `go/internal/delta/agent/pigpen_oracle.go:35-36`, `:114-135`, `:169-197`
- Modify: `go/cmd/piggy-agent-conformance/main.go:335-394`
- Test: `go/internal/delta/agent/pigpen_oracle_test.go:58-80`

**Step 1: Write the failing test.** In `pigpen_oracle_test.go`, the software stub agent at `:58-80` accepts only `ecdh@joyent.com`. Add a second stub mode that accepts only `ecdh@code.linenisgreat.com` and a test that `AgentECDHOracle.ECDH` succeeds against both; and a third stub that refuses the canonical name with `SSH_AGENT_FAILURE` and serves the legacy one, asserting the oracle still returns the secret. Reuse the stub's request-decoding code; only the accepted name list changes.

**Step 2: Run.**

Run: `just test-go`
Expected: FAIL for the canonical-only stub (the client sends the legacy name and checks the echo against it).

**Step 3: Implement.**

```go
const (
	ecdhExtension       = "ecdh@code.linenisgreat.com" // canonical (piggy#335)
	ecdhExtensionLegacy = "ecdh@joyent.com"            // C pivy-agent and pre-#335 piggy
)

var ecdhExtensionNames = []string{ecdhExtension, ecdhExtensionLegacy}
```

In `agentECDH`, loop over `ecdhExtensionNames`: call `client.Extension(name, ...)`; on `agent.ErrExtensionUnsupported` try the next name; on any other error return it; on success parse with `parseECDHResponse(response, name)`. `parseECDHResponse` takes the name sent and accepts an echo of either name in `ecdhExtensionNames` (a proxy may echo the upstream's name). The final `ErrExtensionUnsupported` message names both.

**Step 4: Conformance.** In `main.go:335-394`, `testECDH` runs twice, once per name, each a separate TAP line (`ecdh@code.linenisgreat.com`, `ecdh@joyent.com`), and checks the echo equals the name it sent. Keep the `--hardware` SKIP.

**Step 5: Run.**

Run: `just codemod-fmt-go` then `just test-go`
Expected: PASS.

Run: `just debug-conformance-run`
Expected: the two ECDH lines show `SKIP` (no `--hardware`), and nothing else regresses. If a fibby lane exists for the conformance ECDH case by then, run that instead.

**Step 6: Commit.**

```
git add go/internal/delta/agent/pigpen_oracle.go go/internal/delta/agent/pigpen_oracle_test.go go/cmd/piggy-agent-conformance/main.go
git commit -m "go/agent: canonical ecdh name first, legacy fallback; conformance covers both

Refs piggy#335."
```

---

### Task 6: Docs, the plan ledger, and piggy#26

**Promotion criteria:** N/A.

**Files:**
- Modify: `doc/piggy-agent.1.scd:144-147`, `doc/piggy.1.scd:703`, `:1055`, `doc/age-plugin-piggy.1.scd:26`, `:84`, `doc/piggy-markl.7.scd:70`
- Modify: `docs/rfcs/0002-piv-ecdh-box.md` (the one `ecdh@joyent.com` mention), `docs/rfcs/0008-pigpen-encrypted-document.md` §4.3 and §7, `docs/features/0001-proxy-only-agent-universal-front.md` (two mentions)
- Modify: `docs/plans/2026-10-05-pigpen-go-for-madder.md:37` (mark the pointer-parser alignment done, with the two file:line refs above)
- Modify: `AGENTS.md` (the `agent` bullet names the extensions; add the canonical name and that the legacy one is an alias)

**Step 1: Edit.** Everywhere the docs name the extension as the thing a client uses, write `ecdh@code.linenisgreat.com` and add one clause: "(the legacy `ecdh@joyent.com` is answered as an alias)". In piggy-agent(1)'s extension list give both names. In RFC 0008 §4.3 and §7, which describe the oracle, name the canonical extension and footnote the alias. Do not touch `vendor/pivy/`: that is the C agent's own documentation.

**Step 2: Check the manpages render and the AGENTS.md cap.**

Run: `just lint-worktree`
Expected: PASS (AGENTS.md under 40000 characters; scdoc renders in `just build-nix`, which the merge gate runs).

**Step 3: Commit, closing the issue.**

```
git add doc docs AGENTS.md
git commit -m "docs: the agent ECDH extension is ecdh@code.linenisgreat.com, with the legacy alias

Closes #335."
```

**Step 4: Update piggy#26** with a comment: pigsty design landed (`docs/plans/2026-10-25-pigsty-design.md`), the piggy-side work of this plan, piggy#335 closed by the merge, and the open items (pigsty repo bootstrap by eager-holly, madder/live-cedar's crate, piggy-piv OpenSSL-free build for Android as a new issue to file). Then record the attestation and `merge-this-session-async`.

---

## Verification after both merges

- `just test-bats-conformance-pigpen-open-fibby` and `just test-bats-conformance-age-plugin-piggy`: both decrypt paths go through `AgentEcdhOracle`, now under the canonical name against the new agent.
- `piggy health` against the running local agent (`just explore-piggy-health`): "agent: advertises ecdh extension" passes and names the canonical extension.
