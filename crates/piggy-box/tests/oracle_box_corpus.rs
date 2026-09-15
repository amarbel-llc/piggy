//! Differential-corpus replay (piggy#164 Phase 1 item 2).
//!
//! `just codemod-capture-pivy-oracle-box` encrypts a matrix of plaintexts
//! to fibby's RFC 5903 slot-9D key with the Rust `piggy-ids encrypt`,
//! decrypts each ebox with BOTH the C `pivy-box stream decrypt` and the
//! Rust in-process decrypt against the same card, asserts the two agree
//! byte-for-byte, and freezes the ebox + plaintext under
//! `tests/fixtures/oracle-box/`. That recipe needs fibby and C pivy-box;
//! THIS test needs neither. It replays every frozen ebox offline with the
//! RFC 5903 §8.1 private scalar (the key fibby seeds at slot 9D, so it
//! opens the card-recipient part of each box) and asserts the plaintext
//! comes back — the guarantee that the wire format C accepted at capture
//! time stays decryptable by Rust after C is gone.
//!
//! A fixture is a pair `<name>.ebox` (the stream: header ‖ chunk frames)
//! and `<name>.plaintext` (the exact bytes). The offline decrypt mirrors
//! `piggy::cmd::pivy_box::Decryptor::decrypt`: parse the header, unlock
//! the ebox through a software ECDH oracle, then walk the chunk frames.

use std::path::{Path, PathBuf};

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use piggy_box::oracle::{EcdhOracle, OracleError};
use piggy_box::piv_box::EcCurve;
use piggy_box::stream::EboxStream;
use piggy_box::unlock::unlock_ebox;

/// RFC 5903 §8.1 P-256 private scalar (big-endian). This is the exact key
/// `fibby --seed-rfc5903-slot-9d-cert` installs at slot 9D and the one the
/// capture recipe encrypts a card-recipient part to, so it opens every
/// fixture. Kept in step with `crates/fibby/src/virtual_card.rs`'s
/// `RFC5903_SLOT_9D_PRIV`.
const RFC5903_SLOT_9D_PRIV: [u8; 32] = [
    0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2, 0x92, 0xDA, 0xA2, 0x31, 0x6D, 0xE5,
    0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49, 0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D, 0x14, 0x33,
];

/// A P-256 scalar as a software ECDH oracle — the offline stand-in for a
/// card. Mirrors the `LocalEcdhOracle` in `e2e_recipients.rs`.
struct SoftwareEcdhOracle {
    priv_key: EcKey<Private>,
}

impl EcdhOracle for SoftwareEcdhOracle {
    fn ecdh(&mut self, _self_blob: &[u8], partner_blob: &[u8]) -> Result<Vec<u8>, OracleError> {
        let point = piggy_box::agent_ext::extract_point_from_sshkey_blob(partner_blob)?;
        let group = EcGroup::from_curve_name(EcCurve::NistP256.nid())
            .map_err(|e| OracleError::Other(e.to_string()))?;
        let mut ctx = BigNumContext::new().map_err(|e| OracleError::Other(e.to_string()))?;
        let ec_point = EcPoint::from_bytes(&group, &point, &mut ctx)
            .map_err(|e| OracleError::InvalidPubkey(e.to_string()))?;
        let peer_pub = EcKey::from_public_key(&group, &ec_point)
            .map_err(|e| OracleError::Other(e.to_string()))?;

        let priv_pkey = PKey::from_ec_key(self.priv_key.clone())
            .map_err(|e| OracleError::Other(e.to_string()))?;
        let peer_pkey =
            PKey::from_ec_key(peer_pub).map_err(|e| OracleError::Other(e.to_string()))?;
        let mut d = openssl::derive::Deriver::new(&priv_pkey)
            .map_err(|e| OracleError::Other(e.to_string()))?;
        d.set_peer(&peer_pkey)
            .map_err(|e| OracleError::Other(e.to_string()))?;
        d.derive_to_vec()
            .map_err(|e| OracleError::Other(e.to_string()))
    }
}

fn rfc5903_priv_key() -> EcKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let scalar = openssl::bn::BigNum::from_slice(&RFC5903_SLOT_9D_PRIV).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator(&group, &scalar, &ctx).unwrap();
    // Round-trip the public point through bytes so the key carries an
    // explicit public component (some openssl builds want it set).
    let pub_bytes = point
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    let pub_point = EcPoint::from_bytes(&group, &pub_bytes, &mut ctx).unwrap();
    EcKey::from_private_components(&group, &scalar, &pub_point).unwrap()
}

/// Decrypt one frozen stream ebox (header ‖ chunk frames) offline with the
/// RFC 5903 card scalar. Byte-for-byte the shape of
/// `Decryptor::decrypt`, minus the agent/card oracles.
fn decrypt_offline(ebox_bytes: &[u8]) -> Vec<u8> {
    let mut stream = EboxStream::from_bytes(ebox_bytes).expect("parse ebox header");
    let mut oracle = SoftwareEcdhOracle {
        priv_key: rfc5903_priv_key(),
    };
    unlock_ebox(&mut stream.ebox, None, Some(&mut oracle)).expect("unlock ebox with RFC 5903 key");

    let header_len = stream.to_bytes().expect("re-serialize header").len();
    let mut chunk_data = &ebox_bytes[header_len..];
    let mut out = Vec::new();
    let mut expected_seqnr: u32 = 0;
    while !chunk_data.is_empty() {
        assert!(chunk_data.len() >= 8, "truncated chunk frame");
        let string_len =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]])
                as usize;
        let frame_len = 4 + 4 + string_len;
        assert!(chunk_data.len() >= frame_len, "truncated chunk data");
        let (_, plain) = stream
            .decrypt_chunk(Some(expected_seqnr), &chunk_data[..frame_len])
            .expect("decrypt chunk");
        out.extend_from_slice(&plain);
        chunk_data = &chunk_data[frame_len..];
        expected_seqnr += 1;
    }
    out
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oracle-box")
}

fn ebox_fixtures() -> Vec<PathBuf> {
    let dir = fixtures_dir();
    let mut v: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "ebox"))
        .collect();
    v.sort();
    v
}

#[test]
fn every_frozen_ebox_decrypts_offline_to_its_plaintext() {
    let fixtures = ebox_fixtures();
    assert!(
        fixtures.len() >= 5,
        "expected the captured corpus under {} — regenerate it with \
         `just codemod-capture-pivy-oracle-box` (found {})",
        fixtures_dir().display(),
        fixtures.len()
    );

    for ebox_path in fixtures {
        let plaintext_path = ebox_path.with_extension("plaintext");
        let ebox = std::fs::read(&ebox_path).unwrap();
        let want = std::fs::read(&plaintext_path).unwrap_or_else(|e| {
            panic!(
                "missing {} for {}: {e}",
                plaintext_path.display(),
                ebox_path.display()
            )
        });
        let got = decrypt_offline(&ebox);
        assert_eq!(
            got,
            want,
            "offline decrypt of {} did not recover its plaintext",
            ebox_path.file_name().unwrap().to_string_lossy()
        );
    }
}
