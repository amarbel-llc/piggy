//! A certificate authority's key (slot 82, X.509; slot 83, OpenSSH
//! certificates) never performs key agreement, on any path (the Fable review
//! of c7dd0561, finding 4): the refusal sits in `PinSession::ecdh_derive`, the
//! one place every caller reaches, so the agent's ECDH extensions, `piggy tool
//! ecdh`, `pass show-batch`, the agentless oracle and the age and pigpen
//! plugins are all covered with no gate of their own. Over fibby's
//! VirtualCard, in process.

use std::sync::{Arc, Mutex};

use fibby::backend::Backend;
use fibby::proto;
use fibby::virtual_card::VirtualCard;
use piggy_piv::{ApduSession, ApduTransport, EndDisposition, PivError, PivToken, RawApdu};

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

/// A card with a P-256 key in slot 9D and, generated on it the way `piggy
/// tool generate` does (management key, GENERATE, PIN, a self-signed
/// certificate, PUT DATA), in each of the CA slots 82 and 83.
fn token() -> PivToken {
    use piggy_piv::apdu::alg::{ECCP256, TDEA_3KEY};
    use piggy_piv::{DEFAULT_ADMIN_KEY, PivAlgorithm, cert_builder};

    let mut card = VirtualCard::new();
    card.seed_rfc5903_slot_9d_cert();
    card.seed_chuid();
    card.connect(proto::share::SHARED, proto::protocol::T1)
        .expect("virtual card powers up");
    let mut token = PivToken::from_transport(
        Box::new(FibbyTransport(Arc::new(Mutex::new(card)))),
        "fibby in-process",
        true,
    )
    .expect("a seeded VirtualCard connects");
    for slot_id in [0x82u8, 0x83] {
        let mut session = token.begin_pin_session().unwrap();
        session
            .authenticate_admin(&DEFAULT_ADMIN_KEY, TDEA_3KEY)
            .unwrap();
        let point = session.generate_key(slot_id, ECCP256, None, None).unwrap();
        session.verify_pin("123456").unwrap();
        let cert = cert_builder::build_self_signed_cert(
            &point,
            PivAlgorithm::EcP256,
            &format!("PIV slot {slot_id:02X}"),
            |digest| session.sign_prehash_with_alg(slot_id, ECCP256, digest),
        )
        .unwrap();
        session.put_cert(slot_id, &cert).unwrap();
    }
    token
}

#[test]
fn a_ca_slot_never_performs_key_agreement() {
    let mut token = token();
    let peer = token.read_slot(0x9D).unwrap().ec_sec1_point().unwrap();
    for slot_id in [0x82u8, 0x83] {
        let slot = token.read_slot(slot_id).unwrap();
        let mut session = token.begin_pin_session().unwrap();
        // With the PIN verified, so only the gate can stop it.
        session.verify_pin("123456").unwrap();
        let err = session
            .ecdh_derive(&slot, &peer)
            .expect_err("a CA key agreed on a secret")
            .to_string();
        assert!(
            err.contains("certificate authority") && err.contains("key agreement"),
            "slot {slot_id:02x}: {err}"
        );
    }
}

#[test]
fn the_key_management_slot_still_does() {
    let mut token = token();
    let peer = fibby_peer_point();
    let slot = token.read_slot(0x9D).unwrap();
    let mut session = token.begin_pin_session().unwrap();
    // The card may want the PIN first; what must not appear is the CA refusal.
    match session.ecdh_derive(&slot, &peer) {
        Ok(secret) => assert!(!secret.is_empty()),
        Err(e) => assert!(!e.to_string().contains("certificate authority"), "{e}"),
    }
}

/// Any valid uncompressed P-256 point: the 9D key itself is one.
fn fibby_peer_point() -> Vec<u8> {
    token().read_slot(0x9D).unwrap().ec_sec1_point().unwrap()
}
