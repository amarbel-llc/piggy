//! piggy#341: `piggy_piv::card_ecdh` over fibby's VirtualCard, in process
//! (no pcscd). The card is seeded with the RFC 5903 slot-9D key; every
//! derived secret is checked against a software ECDH with the card's
//! public key.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fibby::backend::Backend;
use fibby::proto;
use fibby::virtual_card::VirtualCard;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use piggy_piv::card_ecdh::{CardEcdh, CardEcdhError, PinDeclined, PinRequest, PinSource};
use piggy_piv::{ApduSession, ApduTransport, EndDisposition, PivError, PivToken, RawApdu};
use zeroize::Zeroizing;

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

fn seeded_token() -> PivToken {
    let mut card = VirtualCard::new();
    card.seed_rfc5903_slot_9d_cert();
    card.seed_chuid();
    card.connect(proto::share::SHARED, proto::protocol::T1)
        .expect("virtual card powers up");
    PivToken::from_transport(
        Box::new(FibbyTransport(Arc::new(Mutex::new(card)))),
        "fibby in-process",
        true,
    )
    .expect("a seeded VirtualCard connects")
}

/// The card's 9D public key, read the way any client would.
fn card_recipient(token: &PivToken) -> Vec<u8> {
    token.read_slot(0x9D).unwrap().ec_sec1_point().unwrap()
}

/// How many times the PIN was asked for.
type Asks = Arc<AtomicUsize>;
/// The `retries_remaining` each ask carried.
type RetriesSeen = Arc<Mutex<Vec<Option<u8>>>>;

/// Answers from a script, counting the asks and recording each request's
/// retry counter.
struct ScriptedPins {
    answers: Mutex<Vec<Option<&'static str>>>,
    asks: Asks,
    retries_seen: RetriesSeen,
}

impl ScriptedPins {
    fn new(answers: &[Option<&'static str>]) -> (Self, Asks, RetriesSeen) {
        let asks = Arc::new(AtomicUsize::new(0));
        let retries = Arc::new(Mutex::new(Vec::new()));
        let mut script = answers.to_vec();
        script.reverse();
        (
            Self {
                answers: Mutex::new(script),
                asks: asks.clone(),
                retries_seen: retries.clone(),
            },
            asks,
            retries,
        )
    }
}

impl PinSource for ScriptedPins {
    fn pin(&self, req: &PinRequest<'_>) -> Result<Zeroizing<String>, PinDeclined> {
        assert_eq!(req.slot, 0x9D);
        self.asks.fetch_add(1, Ordering::SeqCst);
        self.retries_seen
            .lock()
            .unwrap()
            .push(req.retries_remaining);
        match self.answers.lock().unwrap().pop().flatten() {
            Some(pin) => Ok(Zeroizing::new(pin.to_string())),
            None => Err(PinDeclined),
        }
    }
}

/// A fixed, valid P-256 scalar (test-only), so every run is deterministic.
fn fixed_key(byte: u8) -> p256::SecretKey {
    p256::SecretKey::from_slice(&[byte; 32]).expect("a valid scalar")
}

/// An ephemeral key and the secret the card must derive against it.
fn ephemeral_and_expected(recipient: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let eph = fixed_key(0x07);
    let card = p256::PublicKey::from_sec1_bytes(recipient).unwrap();
    let shared = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), card.as_affine());
    let mut expected = [0u8; 32];
    expected.copy_from_slice(shared.raw_secret_bytes());
    let epk = eph.public_key().to_encoded_point(false).as_bytes().to_vec();
    (epk, expected)
}

#[test]
fn ecdh_matches_a_software_ecdh_and_asks_for_the_pin_once() {
    let token = seeded_token();
    let recipient = card_recipient(&token);
    let (pins, asks, _) = ScriptedPins::new(&[Some("123456")]);
    let oracle = CardEcdh::new(token, Box::new(pins));

    for _ in 0..2 {
        let (epk, expected) = ephemeral_and_expected(&recipient);
        let got = oracle.ecdh(&recipient, &epk).expect("ecdh");
        assert_eq!(*got, expected);
    }
    assert_eq!(
        asks.load(Ordering::SeqCst),
        1,
        "the PIN is cached for the oracle's lifetime"
    );
}

#[test]
fn a_compressed_recipient_and_partner_are_accepted() {
    let token = seeded_token();
    let recipient = card_recipient(&token);
    let compressed = p256::PublicKey::from_sec1_bytes(&recipient)
        .unwrap()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let (pins, _, _) = ScriptedPins::new(&[Some("123456")]);
    let oracle = CardEcdh::new(token, Box::new(pins));
    let (epk, expected) = ephemeral_and_expected(&recipient);
    let epk_compressed = p256::PublicKey::from_sec1_bytes(&epk)
        .unwrap()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert!(oracle.holds(&compressed).unwrap());
    assert_eq!(
        *oracle.ecdh(&compressed, &epk_compressed).unwrap(),
        expected
    );
}

#[test]
fn a_wrong_pin_asks_again_with_the_card_counter() {
    let token = seeded_token();
    let recipient = card_recipient(&token);
    let (pins, asks, retries) = ScriptedPins::new(&[Some("000000"), Some("123456")]);
    let oracle = CardEcdh::new(token, Box::new(pins));
    let (epk, expected) = ephemeral_and_expected(&recipient);
    assert_eq!(*oracle.ecdh(&recipient, &epk).unwrap(), expected);
    assert_eq!(asks.load(Ordering::SeqCst), 2);
    assert_eq!(*retries.lock().unwrap(), vec![None, Some(2)]);
}

#[test]
fn a_declined_pin_ends_the_call_without_another_verify() {
    let token = seeded_token();
    let recipient = card_recipient(&token);
    let (pins, asks, _) = ScriptedPins::new(&[Some("000000"), None]);
    let oracle = CardEcdh::new(token, Box::new(pins));
    let (epk, _) = ephemeral_and_expected(&recipient);
    assert!(matches!(
        oracle.ecdh(&recipient, &epk),
        Err(CardEcdhError::PinDeclined)
    ));
    // Asked twice (the wrong PIN, then the decline) and stopped there: the
    // decline left nothing to VERIFY.
    assert_eq!(asks.load(Ordering::SeqCst), 2);
}

#[test]
fn a_recipient_the_card_does_not_hold_is_refused_before_any_pin() {
    let token = seeded_token();
    let other = fixed_key(0x0b)
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let (pins, asks, _) = ScriptedPins::new(&[Some("123456")]);
    let oracle = CardEcdh::new(token, Box::new(pins));
    assert!(!oracle.holds(&other).unwrap());
    let (epk, _) = ephemeral_and_expected(&other);
    assert!(matches!(
        oracle.ecdh(&other, &epk),
        Err(CardEcdhError::NotThisCard)
    ));
    assert_eq!(
        asks.load(Ordering::SeqCst),
        0,
        "no PIN for a card that is not the recipient"
    );
}
