//! piggy-piv's PIV session logic over fibby's VirtualCard, in process: no
//! pcscd, no socket, no PC/SC. Proves the transport seam carries a whole
//! PIN session (SELECT, VERIFY, retry counter, reset-on-end) and gives
//! pigsty's Android transport the shape to copy.

use std::sync::{Arc, Mutex};

use fibby::backend::Backend;
use fibby::proto;
use fibby::virtual_card::VirtualCard;
use piggy_piv::{ApduSession, ApduTransport, EndDisposition, PivError, PivToken, RawApdu};

// Arc<Mutex<..>>, not Rc<RefCell<..>>: the transport traits are Send.
struct FibbyTransport(Arc<Mutex<VirtualCard>>);
struct FibbySession(Arc<Mutex<VirtualCard>>);

fn transmit(card: &Mutex<VirtualCard>, command: &[u8]) -> Result<Vec<u8>, PivError> {
    card.lock()
        .unwrap()
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
            EndDisposition::LeaveCard => proto::disposition::LEAVE,
            EndDisposition::ResetCard => proto::disposition::RESET,
        };
        self.0.lock().unwrap().end_transaction(disposition);
        Ok(())
    }
}

fn connected_blank_card() -> (PivToken, Arc<Mutex<VirtualCard>>) {
    let mut card = VirtualCard::new();
    card.connect(proto::share::SHARED, proto::protocol::T1)
        .expect("virtual card powers up");
    let card = Arc::new(Mutex::new(card));
    let token = PivToken::from_transport(
        Box::new(FibbyTransport(card.clone())),
        "fibby in-process",
        false,
    )
    .unwrap_or_else(|e| panic!("a blank VirtualCard connects on the tolerant path: {e}"));
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
    token
        .begin_pin_session()
        .unwrap()
        .verify_pin("123456")
        .unwrap();
    // The session dropped with the PIN verified, so the card was reset:
    // a protected operation in a fresh session must demand the PIN again.
    let mut session = token.begin_pin_session().unwrap();
    // The non-consuming retry query answers u8::MAX only while the PIN is
    // verified; after the reset it reports the full counter again.
    assert_eq!(
        session.pin_retries_remaining().expect("retry query"),
        3,
        "the reset end cleared the verified PIN"
    );
    let err = session
        .read_slot(0x9D)
        .map_err(|_| PivError::SlotEmpty(0x9D));
    assert!(
        matches!(err, Err(PivError::SlotEmpty(0x9D))),
        // PivSlot has no Debug, so show only the error side.
        "blank 9D: {:?}",
        err.as_ref().err()
    );
}
