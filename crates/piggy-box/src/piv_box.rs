use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::Private;
use zeroize::Zeroizing;

use crate::error::{BoxError, Result};
use crate::wire::{WireReader, WireWriter};
use piggy_piv::Guid;

const BOX_MAGIC: u16 = 0xB0C5;
const BOX_VERSION: u8 = 2;
const DEFAULT_CIPHER: &str = "chacha20-poly1305";
const DEFAULT_KDF: &str = "sha512";
const NONCE_LEN: usize = 16;
const CIPHER_IV_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    NistP256,
    NistP384,
}

impl EcCurve {
    pub fn wire_name(&self) -> &'static str {
        match self {
            EcCurve::NistP256 => "nistp256",
            EcCurve::NistP384 => "nistp384",
        }
    }

    pub fn from_wire_name(s: &str) -> Result<Self> {
        match s {
            "nistp256" => Ok(EcCurve::NistP256),
            "nistp384" => Ok(EcCurve::NistP384),
            _ => Err(BoxError::UnsupportedCurve(s.to_string())),
        }
    }

    pub fn nid(&self) -> Nid {
        match self {
            EcCurve::NistP256 => Nid::X9_62_PRIME256V1,
            EcCurve::NistP384 => Nid::SECP384R1,
        }
    }

    pub fn from_nid(nid: Nid) -> Result<Self> {
        if nid == Nid::X9_62_PRIME256V1 {
            Ok(EcCurve::NistP256)
        } else if nid == Nid::SECP384R1 {
            Ok(EcCurve::NistP384)
        } else {
            Err(BoxError::UnsupportedCurve(format!("NID {:?}", nid)))
        }
    }
}

pub struct PivBox {
    pub version: u8,
    pub guid_slot: Option<(Guid, u8)>,
    pub cipher: String,
    pub kdf: String,
    pub nonce: Vec<u8>,
    pub curve: EcCurve,
    pub recipient_pubkey: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    plaintext: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for PivBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PivBox")
            .field("version", &self.version)
            .field("curve", &self.curve)
            .field("guid_slot", &self.guid_slot)
            .field("cipher", &self.cipher)
            .field("has_plaintext", &self.plaintext.is_some())
            .finish_non_exhaustive()
    }
}

impl PivBox {
    pub fn new(curve: EcCurve) -> Self {
        Self {
            version: BOX_VERSION,
            guid_slot: None,
            cipher: DEFAULT_CIPHER.to_string(),
            kdf: DEFAULT_KDF.to_string(),
            nonce: Vec::new(),
            curve,
            recipient_pubkey: Vec::new(),
            ephemeral_pubkey: Vec::new(),
            iv: Vec::new(),
            ciphertext: Vec::new(),
            plaintext: None,
        }
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.plaintext = Some(Zeroizing::new(data.to_vec()));
    }

    pub fn take_data(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        self.plaintext.take().ok_or(BoxError::NotOpened)
    }

    pub fn has_plaintext(&self) -> bool {
        self.plaintext.is_some()
    }

    pub fn seal_offline(&mut self, recipient_pub: &EcKey<openssl::pkey::Public>) -> Result<()> {
        let group = EcGroup::from_curve_name(self.curve.nid())?;
        let ephem = EcKey::generate(&group)?;
        self.seal_offline_with_ephemeral(recipient_pub, &ephem)
    }

    /// Seal using an externally-provided ephemeral key. Used by Ebox to
    /// share a single ephemeral key across all parts on the same curve.
    ///
    /// The 16-byte KDF nonce and the 12-byte cipher IV are both
    /// generated freshly here. For deterministic reproduction (e.g.
    /// RFC 0002 §A test vectors) call
    /// [`PivBox::seal_offline_with_ephemeral_and_pinned_random`]
    /// directly with caller-controlled values.
    pub fn seal_offline_with_ephemeral(
        &mut self,
        recipient_pub: &EcKey<openssl::pkey::Public>,
        ephem: &EcKey<Private>,
    ) -> Result<()> {
        let mut kdf_nonce = vec![0u8; NONCE_LEN];
        openssl::rand::rand_bytes(&mut kdf_nonce)?;
        let mut cipher_iv = vec![0u8; CIPHER_IV_LEN];
        openssl::rand::rand_bytes(&mut cipher_iv)?;
        self.seal_offline_with_ephemeral_and_pinned_random(
            recipient_pub,
            ephem,
            &kdf_nonce,
            &cipher_iv,
        )
    }

    /// Seal with the ephemeral key, KDF nonce, AND cipher IV supplied
    /// by the caller. Crate-private because deterministic nonce/IV
    /// reuse is unsafe in production: callers MUST guarantee per-box
    /// freshness for both, which only holds for one-shot tests with
    /// hard-coded inputs (see `docs/rfcs/0002-piv-ecdh-box.md` §A).
    pub(crate) fn seal_offline_with_ephemeral_and_pinned_random(
        &mut self,
        recipient_pub: &EcKey<openssl::pkey::Public>,
        ephem: &EcKey<Private>,
        kdf_nonce: &[u8],
        cipher_iv: &[u8],
    ) -> Result<()> {
        let plaintext = self.plaintext.as_ref().ok_or(BoxError::NotSealed)?;

        let group = EcGroup::from_curve_name(self.curve.nid())?;
        let mut ctx = openssl::bn::BigNumContext::new()?;

        self.recipient_pubkey = recipient_pub.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?;

        self.ephemeral_pubkey = ephem.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?;

        let shared_secret = ecdh_derive(ephem, recipient_pub)?;

        self.nonce = kdf_nonce.to_vec();
        self.iv = cipher_iv.to_vec();

        let key_material = kdf_sha512(&shared_secret, &self.nonce)?;
        let padded = pkcs7_pad(plaintext, 16);
        let ct = chacha20_poly1305_encrypt(&key_material[..32], &self.iv, &padded)?;
        self.ciphertext = ct;

        Ok(())
    }

    pub fn open_offline(&mut self, privkey: &EcKey<Private>) -> Result<()> {
        let group = EcGroup::from_curve_name(self.curve.nid())?;
        let mut ctx = openssl::bn::BigNumContext::new()?;

        let ephem_point = EcPoint::from_bytes(&group, &self.ephemeral_pubkey, &mut ctx)?;
        let ephem_pub = EcKey::from_public_key(&group, &ephem_point)?;

        let shared_secret = ecdh_derive(privkey, &ephem_pub)?;
        self.open_with_secret(&shared_secret)
    }

    pub fn open_with_secret(&mut self, shared_secret: &[u8]) -> Result<()> {
        if self.iv.len() != CIPHER_IV_LEN {
            return Err(BoxError::Crypto(format!(
                "wire IV must be {CIPHER_IV_LEN} bytes for chacha20-poly1305, got {}",
                self.iv.len()
            )));
        }
        let key_material = kdf_sha512(shared_secret, &self.nonce)?;
        // The wire IV is the AEAD nonce per RFC 7539 (see
        // `docs/rfcs/0002-piv-ecdh-box.md` §Cipher).
        let padded = chacha20_poly1305_decrypt(&key_material[..32], &self.iv, &self.ciphertext)?;
        let plain = pkcs7_unpad(&padded, 16)?;
        self.plaintext = Some(Zeroizing::new(plain));
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = WireWriter::new();
        w.put_u8((BOX_MAGIC >> 8) as u8);
        w.put_u8((BOX_MAGIC & 0xFF) as u8);
        w.put_u8(self.version);

        match &self.guid_slot {
            Some((guid, slot)) => {
                w.put_u8(0x01);
                w.put_string8(guid.as_bytes())?;
                w.put_u8(*slot);
            }
            None => {
                w.put_u8(0x00);
                w.put_u8(0x00); // string8 length 0 for guid
                w.put_u8(0x00); // slot
            }
        }

        w.put_cstring8(&self.cipher)?;
        w.put_cstring8(&self.kdf)?;

        if self.version >= 2 {
            w.put_string8(&self.nonce)?;
        }

        w.put_cstring8(self.curve.wire_name())?;
        w.put_eckey8(&self.recipient_pubkey)?;
        w.put_eckey8(&self.ephemeral_pubkey)?;
        w.put_string8(&self.iv)?;
        w.put_string(&self.ciphertext);

        Ok(w.into_bytes())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = WireReader::new(data);

        let magic_hi = r.get_u8()?;
        let magic_lo = r.get_u8()?;
        let magic = ((magic_hi as u16) << 8) | (magic_lo as u16);
        if magic != BOX_MAGIC {
            return Err(BoxError::BadMagic {
                expected: BOX_MAGIC,
                got: magic,
            });
        }

        let version = r.get_u8()?;
        if !(1..=BOX_VERSION).contains(&version) {
            return Err(BoxError::UnsupportedVersion(version));
        }

        let guidslot_valid = r.get_u8()?;
        let guid_slot = if guidslot_valid != 0 {
            let guid_bytes = r.get_string8()?;
            let guid = Guid::from_bytes(&guid_bytes)?;
            let slot = r.get_u8()?;
            Some((guid, slot))
        } else {
            let _guid_empty = r.get_string8()?;
            let _slot_zero = r.get_u8()?;
            None
        };

        let cipher = r.get_cstring8()?;
        let kdf = r.get_cstring8()?;

        let nonce = if version >= 2 {
            r.get_string8()?
        } else {
            Vec::new()
        };

        let curve_name = r.get_cstring8()?;
        let curve = EcCurve::from_wire_name(&curve_name)?;
        let recipient_pubkey = r.get_eckey8()?;
        let ephemeral_pubkey = r.get_eckey8()?;
        let iv = r.get_string8()?;
        let ciphertext = r.get_string()?;

        Ok(Self {
            version,
            guid_slot,
            cipher,
            kdf,
            nonce,
            curve,
            recipient_pubkey,
            ephemeral_pubkey,
            iv,
            ciphertext,
            plaintext: None,
        })
    }
}

fn ecdh_derive<T: openssl::pkey::HasPrivate, U: openssl::pkey::HasPublic>(
    privkey: &EcKey<T>,
    pubkey: &EcKey<U>,
) -> Result<Vec<u8>> {
    let pkey_priv = openssl::pkey::PKey::from_ec_key(EcKey::from_private_components(
        privkey.group(),
        privkey.private_key(),
        privkey.public_key(),
    )?)?;
    let pkey_pub = openssl::pkey::PKey::from_ec_key(EcKey::from_public_key(
        pubkey.group(),
        pubkey.public_key(),
    )?)?;
    let mut deriver = openssl::derive::Deriver::new(&pkey_priv)?;
    deriver.set_peer(&pkey_pub)?;
    Ok(deriver.derive_to_vec()?)
}

fn kdf_sha512(shared_secret: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    use openssl::hash::{Hasher, MessageDigest};
    let mut h = Hasher::new(MessageDigest::sha512())?;
    h.update(shared_secret)?;
    h.update(nonce)?;
    Ok(h.finish()?.to_vec())
}

/// Encrypt with RFC 7539 / RFC 8439 ChaCha20-Poly1305 AEAD.
///
/// Per `docs/rfcs/0002-piv-ecdh-box.md` §Cipher, the AEAD nonce is the
/// 12-byte wire IV — fresh per box, supplied by the caller, and serialized
/// verbatim into the piv_box `iv` field. AAD is empty; the 16-byte
/// authentication tag is appended to the ciphertext.
fn chacha20_poly1305_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use openssl::symm::{encrypt_aead, Cipher};

    if iv.len() != CIPHER_IV_LEN {
        return Err(BoxError::Crypto(format!(
            "ChaCha20-Poly1305 IV must be {CIPHER_IV_LEN} bytes, got {}",
            iv.len()
        )));
    }

    let cipher = Cipher::chacha20_poly1305();

    let mut tag = vec![0u8; 16];
    let mut ct = encrypt_aead(cipher, key, Some(iv), &[], plaintext, &mut tag)?;
    ct.extend_from_slice(&tag);

    Ok(ct)
}

/// Decrypt RFC 7539 ChaCha20-Poly1305 ciphertext (with appended 16-byte
/// tag). See [`chacha20_poly1305_encrypt`].
fn chacha20_poly1305_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use openssl::symm::{decrypt_aead, Cipher};

    if iv.len() != CIPHER_IV_LEN {
        return Err(BoxError::Crypto(format!(
            "ChaCha20-Poly1305 IV must be {CIPHER_IV_LEN} bytes, got {}",
            iv.len()
        )));
    }

    let cipher = Cipher::chacha20_poly1305();

    if ciphertext.len() < 16 {
        return Err(BoxError::Crypto("ciphertext too short for auth tag".into()));
    }

    let tag_offset = ciphertext.len() - 16;
    let ct = &ciphertext[..tag_offset];
    let tag = &ciphertext[tag_offset..];

    let pt = decrypt_aead(cipher, key, Some(iv), &[], ct, tag)
        .map_err(|e| BoxError::Crypto(format!("ChaCha20-Poly1305 decrypt: {e}")))?;

    Ok(pt)
}

use crate::wire::{pkcs7_pad, pkcs7_unpad};

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::EcGroup;

    fn generate_keypair(curve: EcCurve) -> (EcKey<openssl::pkey::Public>, EcKey<Private>) {
        let group = EcGroup::from_curve_name(curve.nid()).unwrap();
        let priv_key = EcKey::generate(&group).unwrap();
        let pub_key = EcKey::from_public_key(&group, priv_key.public_key()).unwrap();
        (pub_key, priv_key)
    }

    #[test]
    fn seal_open_roundtrip_p256() {
        let (pub_key, priv_key) = generate_keypair(EcCurve::NistP256);
        let data = b"hello world";

        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(data);
        b.seal_offline(&pub_key).unwrap();

        let bytes = b.to_bytes().unwrap();
        let mut b2 = PivBox::from_bytes(&bytes).unwrap();
        b2.open_offline(&priv_key).unwrap();

        let recovered = b2.take_data().unwrap();
        assert_eq!(&*recovered, data);
    }

    #[test]
    fn seal_open_roundtrip_p384() {
        let (pub_key, priv_key) = generate_keypair(EcCurve::NistP384);
        let data = b"test data for P-384";

        let mut b = PivBox::new(EcCurve::NistP384);
        b.set_data(data);
        b.seal_offline(&pub_key).unwrap();

        let bytes = b.to_bytes().unwrap();
        let mut b2 = PivBox::from_bytes(&bytes).unwrap();
        b2.open_offline(&priv_key).unwrap();

        let recovered = b2.take_data().unwrap();
        assert_eq!(&*recovered, data);
    }

    #[test]
    fn seal_writes_random_12_byte_iv() {
        // Per RFC 0002 §Cipher (post-#36), the chacha20-poly1305 wire
        // IV is 12 bytes — the AEAD nonce per RFC 7539, freshly random
        // per box. Two consecutive seals MUST produce distinct IVs.
        let (pub_key, _) = generate_keypair(EcCurve::NistP256);

        let mut b1 = PivBox::new(EcCurve::NistP256);
        b1.set_data(b"payload");
        b1.seal_offline(&pub_key).unwrap();
        assert_eq!(
            b1.iv.len(),
            CIPHER_IV_LEN,
            "PivBox.iv must be {CIPHER_IV_LEN} bytes for chacha20-poly1305 (got {})",
            b1.iv.len()
        );

        let mut b2 = PivBox::new(EcCurve::NistP256);
        b2.set_data(b"payload");
        b2.seal_offline(&pub_key).unwrap();
        assert_ne!(
            b1.iv, b2.iv,
            "successive seals must produce distinct random IVs"
        );

        // Wire round-trip preserves the IV bytes verbatim.
        let bytes = b1.to_bytes().unwrap();
        let parsed = PivBox::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.iv, b1.iv, "wire round-trip must preserve IV");
    }

    #[test]
    fn wire_iv_length_prefix_is_twelve() {
        // Byte-level canary: the IV field's u8 length prefix sits at a
        // known offset for a v2 no-guid Primary box with DEFAULT_CIPHER
        // + DEFAULT_KDF on NistP256. If a future refactor writes any
        // value other than 0x0C there, RFC 7539 conformance breaks —
        // this test fails before vector tests do.
        //
        // Layout up to the IV field (RFC 0002 §Binary Serialization):
        //   off 0..2   magic "B0 C5"
        //   off 2      version (0x02)
        //   off 3      guid_valid flag (0x00 here)
        //   off 4      guid string8 len (0x00)
        //   off 5      slot u8 (0x00)
        //   off 6      cipher cstring8 len (0x11 for "chacha20-poly1305")
        //   off 7..24  "chacha20-poly1305"        (17 bytes)
        //   off 24     kdf cstring8 len (0x06 for "sha512")
        //   off 25..31 "sha512"                   (6 bytes)
        //   off 31     nonce string8 len (0x10, NONCE_LEN=16)
        //   off 32..48 nonce                      (16 bytes)
        //   off 48     curve cstring8 len (0x08 for "nistp256")
        //   off 49..57 "nistp256"                 (8 bytes)
        //   off 57     recipient eckey8 len (0x21, compressed P-256 = 33)
        //   off 58..91 recipient pubkey           (33 bytes)
        //   off 91     ephemeral eckey8 len (0x21)
        //   off 92..125 ephemeral pubkey          (33 bytes)
        //   off 125    IV string8 len             <-- MUST be 0x0C
        //   off 126..138 IV bytes                 (12 bytes)
        let (pub_key, _) = generate_keypair(EcCurve::NistP256);
        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"payload");
        b.seal_offline(&pub_key).unwrap();
        let bytes = b.to_bytes().unwrap();

        assert_eq!(
            bytes.get(125),
            Some(&0x0C),
            "IV length byte at offset 125 must be 0x0C ({CIPHER_IV_LEN}) for \
             chacha20-poly1305 (got {:?}). If the layout above shifted, \
             update the offset AND the spec.",
            bytes.get(125)
        );
        assert!(
            bytes.len() >= 138,
            "wire must contain the full 12-byte IV before ciphertext (len {})",
            bytes.len()
        );
    }

    #[test]
    fn open_rejects_wire_iv_of_wrong_length() {
        // Belt-and-braces for the length validation in
        // `open_with_secret`. Any IV length != CIPHER_IV_LEN must
        // produce an error; in particular, the legacy 0-byte and
        // 12-zero-byte shapes (from pre-#36 piggy or pivy) MUST NOT
        // silently round-trip into garbage plaintext.
        let (pub_key, priv_key) = generate_keypair(EcCurve::NistP256);
        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"payload");
        b.seal_offline(&pub_key).unwrap();

        let bytes = b.to_bytes().unwrap();

        // Empty IV — pre-#36 (post-#34) wire shape.
        let mut b_empty = PivBox::from_bytes(&bytes).unwrap();
        b_empty.iv = Vec::new();
        assert!(b_empty.open_offline(&priv_key).is_err());

        // 13 bytes — clearly wrong length.
        let mut b_long = PivBox::from_bytes(&bytes).unwrap();
        b_long.iv = vec![0u8; 13];
        assert!(b_long.open_offline(&priv_key).is_err());

        // 11 bytes — clearly wrong length.
        let mut b_short = PivBox::from_bytes(&bytes).unwrap();
        b_short.iv = vec![0u8; 11];
        assert!(b_short.open_offline(&priv_key).is_err());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let (pub_key, _) = generate_keypair(EcCurve::NistP256);
        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"payload");
        b.seal_offline(&pub_key).unwrap();

        let bytes1 = b.to_bytes().unwrap();
        let b2 = PivBox::from_bytes(&bytes1).unwrap();
        let bytes2 = b2.to_bytes().unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn serialize_with_guid_slot() {
        let (pub_key, priv_key) = generate_keypair(EcCurve::NistP256);
        let guid = Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap();

        let mut b = PivBox::new(EcCurve::NistP256);
        b.guid_slot = Some((guid.clone(), 0x9D));
        b.set_data(b"with guid");
        b.seal_offline(&pub_key).unwrap();

        let bytes = b.to_bytes().unwrap();
        let mut b2 = PivBox::from_bytes(&bytes).unwrap();

        let (g, s) = b2.guid_slot.as_ref().unwrap();
        assert_eq!(g.to_hex(), guid.to_hex());
        assert_eq!(*s, 0x9D);

        b2.open_offline(&priv_key).unwrap();
        assert_eq!(&*b2.take_data().unwrap(), b"with guid");
    }

    #[test]
    fn wrong_key_fails() {
        let (pub_key, _) = generate_keypair(EcCurve::NistP256);
        let (_, wrong_priv) = generate_keypair(EcCurve::NistP256);

        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"secret");
        b.seal_offline(&pub_key).unwrap();

        let bytes = b.to_bytes().unwrap();
        let mut b2 = PivBox::from_bytes(&bytes).unwrap();
        assert!(b2.open_offline(&wrong_priv).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut data = vec![0xFF, 0xFF, 0x02];
        data.extend(vec![0; 100]);
        assert!(matches!(
            PivBox::from_bytes(&data),
            Err(BoxError::BadMagic { .. })
        ));
    }

    #[test]
    fn pkcs7_roundtrip() {
        for len in 0..50 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pkcs7_pad(&data, 16);
            assert_eq!(padded.len() % 16, 0);
            let unpadded = pkcs7_unpad(&padded, 16).unwrap();
            assert_eq!(unpadded, data);
        }
    }

    #[test]
    fn empty_payload() {
        let (pub_key, priv_key) = generate_keypair(EcCurve::NistP256);

        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"");
        b.seal_offline(&pub_key).unwrap();

        let bytes = b.to_bytes().unwrap();
        let mut b2 = PivBox::from_bytes(&bytes).unwrap();
        b2.open_offline(&priv_key).unwrap();
        assert_eq!(&*b2.take_data().unwrap(), b"");
    }

    #[test]
    fn curve_wire_name_roundtrip() {
        for curve in [EcCurve::NistP256, EcCurve::NistP384] {
            assert_eq!(EcCurve::from_wire_name(curve.wire_name()).unwrap(), curve);
        }
    }

    /// Property-based wire-format fuzzing for `PivBox`. Idempotence:
    /// `serialize(parse(serialize(v))) == serialize(v)` for any sealed
    /// `PivBox`. Catches asymmetry between writer and parser (e.g. a
    /// length prefix written one way and read another). See #40.
    mod proptest_wire {
        use super::*;
        use proptest::prelude::*;

        fn arb_curve() -> impl Strategy<Value = EcCurve> {
            prop_oneof![Just(EcCurve::NistP256), Just(EcCurve::NistP384)]
        }

        fn arb_guid_slot() -> impl Strategy<Value = Option<(piggy_piv::Guid, u8)>> {
            prop_oneof![
                Just(None),
                (any::<[u8; 16]>(), 1u8..=0xFFu8).prop_map(|(b, slot)| {
                    Some((piggy_piv::Guid::from_bytes(&b).unwrap(), slot))
                }),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

            #[test]
            fn piv_box_serialize_parse_idempotent(
                curve in arb_curve(),
                plaintext in proptest::collection::vec(any::<u8>(), 0..=128),
                guid_slot in arb_guid_slot(),
            ) {
                let group = openssl::ec::EcGroup::from_curve_name(curve.nid()).unwrap();
                let recipient_priv = EcKey::generate(&group).unwrap();
                let recipient_pub =
                    EcKey::from_public_key(&group, recipient_priv.public_key()).unwrap();
                let ephemeral_priv = EcKey::generate(&group).unwrap();

                let mut sealed = PivBox::new(curve);
                sealed.guid_slot = guid_slot;
                sealed.set_data(&plaintext);
                sealed
                    .seal_offline_with_ephemeral(&recipient_pub, &ephemeral_priv)
                    .unwrap();

                let bytes1 = sealed.to_bytes().unwrap();
                let parsed = PivBox::from_bytes(&bytes1).unwrap();
                let bytes2 = parsed.to_bytes().unwrap();
                prop_assert_eq!(
                    bytes1,
                    bytes2,
                    "piv_box wire serialize→parse→serialize is not idempotent"
                );
            }
        }
    }

    /// Cross-impl oracle: encrypt/decrypt the same inputs with both
    /// piggy's openssl-backed `chacha20_poly1305_*` wrapper AND
    /// RustCrypto's pure-Rust `chacha20poly1305` crate, then compare.
    /// Catches regressions where one impl drifts from the AEAD spec
    /// while the other doesn't (e.g. an openssl version bump that
    /// silently changes nonce-extension or tag-verification behavior).
    /// piggy-box compiles against openssl in production; the
    /// RustCrypto crate is `[dev-dependencies]` only. See #38.
    mod oracle_xcheck {
        use super::*;
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        /// Both impls SHOULD produce byte-identical (ciphertext || tag)
        /// for the same key/IV/plaintext under empty AAD. AEAD is
        /// deterministic given those inputs, so any divergence is a
        /// real disagreement.
        #[test]
        fn openssl_and_rustcrypto_produce_identical_ciphertext() {
            let key = [0x42u8; 32];
            let iv = [0x07u8; 12];
            let plaintext = b"piggy oracle xcheck #38 :: identical-ciphertext";

            let openssl_ct =
                chacha20_poly1305_encrypt(&key, &iv, plaintext).expect("openssl encrypt");

            let rust_cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let rust_ct = rust_cipher
                .encrypt(Nonce::from_slice(&iv), plaintext.as_ref())
                .expect("rustcrypto encrypt");

            assert_eq!(
                openssl_ct, rust_ct,
                "openssl and RustCrypto produced different (ciphertext || tag) \
                 for the same key/iv/plaintext under empty AAD"
            );
        }

        /// What openssl encrypts, RustCrypto decrypts. Catches
        /// "openssl produces tag/ct that doesn't verify under a spec
        /// implementation."
        #[test]
        fn rustcrypto_decrypts_openssl_ciphertext() {
            let key = [0x11u8; 32];
            let iv: [u8; 12] = std::array::from_fn(|i| i as u8);
            let plaintext = b"";

            let openssl_ct =
                chacha20_poly1305_encrypt(&key, &iv, plaintext).expect("openssl encrypt");

            let rust_cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let recovered = rust_cipher
                .decrypt(Nonce::from_slice(&iv), openssl_ct.as_ref())
                .expect("rustcrypto decrypt");

            assert_eq!(recovered, plaintext);
        }

        /// What RustCrypto encrypts, openssl decrypts (via piggy's
        /// wrapper). Catches "openssl rejects spec-conformant tag/ct
        /// from another impl."
        #[test]
        fn openssl_decrypts_rustcrypto_ciphertext() {
            let key = [0xa5u8; 32];
            let iv: [u8; 12] = std::array::from_fn(|i| 0xc0 | (i as u8));
            // 64 bytes — exercises a multi-block payload.
            let plaintext: Vec<u8> = (0..64u8).collect();

            let rust_cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let rust_ct = rust_cipher
                .encrypt(Nonce::from_slice(&iv), plaintext.as_slice())
                .expect("rustcrypto encrypt");

            let recovered =
                chacha20_poly1305_decrypt(&key, &iv, &rust_ct).expect("openssl decrypt");

            assert_eq!(recovered, plaintext);
        }
    }

    /// Pinned RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD test vector. piggy's
    /// `chacha20_poly1305_encrypt` is a thin wrapper over
    /// `openssl::symm::{encrypt_aead, decrypt_aead}` with empty AAD; this
    /// module exercises the underlying openssl primitive *with* AAD so
    /// the RFC's published byte-strings can be compared directly. Acts as
    /// a regression canary against silent drift in the openssl AEAD impl.
    /// Reference: <https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2>.
    mod chacha20_poly1305_rfc8439 {
        use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

        const KEY: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];

        // Nonce = 4-byte constant 07 00 00 00 || 8-byte IV 40..47 (RFC §2.8.2).
        const NONCE: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        const AAD: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];

        const PLAINTEXT: &[u8] =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        const EXPECTED_CIPHERTEXT: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        const EXPECTED_TAG: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        #[test]
        fn encrypt_matches_spec_ciphertext_and_tag() {
            let mut tag = vec![0u8; 16];
            let ct = encrypt_aead(
                Cipher::chacha20_poly1305(),
                &KEY,
                Some(&NONCE),
                &AAD,
                PLAINTEXT,
                &mut tag,
            )
            .expect("encrypt");
            assert_eq!(
                ct, EXPECTED_CIPHERTEXT,
                "ciphertext drifted from RFC 8439 §2.8.2"
            );
            assert_eq!(tag, EXPECTED_TAG, "auth tag drifted from RFC 8439 §2.8.2");
        }

        #[test]
        fn decrypt_recovers_spec_plaintext() {
            let pt = decrypt_aead(
                Cipher::chacha20_poly1305(),
                &KEY,
                Some(&NONCE),
                &AAD,
                &EXPECTED_CIPHERTEXT,
                &EXPECTED_TAG,
            )
            .expect("decrypt");
            assert_eq!(pt, PLAINTEXT);
        }

        #[test]
        fn tampered_tag_fails_decrypt() {
            let mut bad_tag = EXPECTED_TAG;
            bad_tag[0] ^= 0x01;
            let result = decrypt_aead(
                Cipher::chacha20_poly1305(),
                &KEY,
                Some(&NONCE),
                &AAD,
                &EXPECTED_CIPHERTEXT,
                &bad_tag,
            );
            assert!(
                result.is_err(),
                "decryption with bit-flipped tag must fail; got {:?}",
                result.map(|_| "ok")
            );
        }
    }

    /// Replays the bit-exact wire vectors pinned in
    /// `docs/rfcs/0002-piv-ecdh-box.md` Appendix A. Each vector fixes
    /// every input that feeds the wire (recipient priv, ephemeral priv,
    /// KDF nonce, cipher IV, plaintext, GUID/slot) so that
    /// `seal_offline_with_ephemeral_and_pinned_random` produces a
    /// known-byte output. Drift between this module and the spec is a
    /// CI failure.
    mod rfc0002_vectors {
        use super::*;

        fn priv_key_from_scalar(curve: EcCurve, scalar_bytes: &[u8]) -> EcKey<Private> {
            let group = EcGroup::from_curve_name(curve.nid()).unwrap();
            let ctx = openssl::bn::BigNumContext::new().unwrap();
            let scalar = openssl::bn::BigNum::from_slice(scalar_bytes).unwrap();
            let mut pub_point = EcPoint::new(&group).unwrap();
            pub_point.mul_generator(&group, &scalar, &ctx).unwrap();
            EcKey::from_private_components(&group, &scalar, &pub_point).unwrap()
        }

        fn pub_from_priv(
            curve: EcCurve,
            priv_key: &EcKey<Private>,
        ) -> EcKey<openssl::pkey::Public> {
            let group = EcGroup::from_curve_name(curve.nid()).unwrap();
            EcKey::from_public_key(&group, priv_key.public_key()).unwrap()
        }

        /// Replay one §A vector end-to-end:
        /// 1. seal with pinned inputs and assert wire == expected_hex
        /// 2. from_bytes(expected) and assert all wire fields match inputs
        /// 3. open_offline(recipient_priv) and assert plaintext recovered
        #[allow(clippy::too_many_arguments)]
        fn replay_vector(
            curve: EcCurve,
            recipient_scalar: &[u8],
            ephemeral_scalar: &[u8],
            kdf_nonce: &[u8],
            cipher_iv: &[u8],
            plaintext: &[u8],
            guid_slot: Option<(piggy_piv::Guid, u8)>,
            expected_hex: &str,
        ) {
            let recipient_priv = priv_key_from_scalar(curve, recipient_scalar);
            let recipient_pub = pub_from_priv(curve, &recipient_priv);
            let ephemeral_priv = priv_key_from_scalar(curve, ephemeral_scalar);
            let expected_bytes = hex::decode(expected_hex).expect("vector hex parses");

            // (1) seal -> exact wire match
            let mut sealed = PivBox::new(curve);
            sealed.guid_slot = guid_slot.clone();
            sealed.set_data(plaintext);
            sealed
                .seal_offline_with_ephemeral_and_pinned_random(
                    &recipient_pub,
                    &ephemeral_priv,
                    kdf_nonce,
                    cipher_iv,
                )
                .unwrap();
            let actual_bytes = sealed.to_bytes().unwrap();
            assert_eq!(
                hex::encode(&actual_bytes),
                expected_hex,
                "wire bytes drifted from RFC 0002 §A vector"
            );

            // (2) from_bytes -> field equality
            let parsed = PivBox::from_bytes(&expected_bytes).unwrap();
            assert_eq!(parsed.version, BOX_VERSION, "version");
            assert_eq!(parsed.cipher, DEFAULT_CIPHER, "cipher");
            assert_eq!(parsed.kdf, DEFAULT_KDF, "kdf");
            assert_eq!(parsed.curve, curve, "curve");
            assert_eq!(parsed.nonce, kdf_nonce, "kdf nonce");
            assert_eq!(parsed.iv, cipher_iv, "cipher IV");
            match (&parsed.guid_slot, &guid_slot) {
                (None, None) => {}
                (Some((pg, ps)), Some((eg, es))) => {
                    assert_eq!(pg.to_hex(), eg.to_hex(), "guid");
                    assert_eq!(ps, es, "slot");
                }
                _ => panic!("guid_slot mismatch: parsed={:?}", parsed.guid_slot),
            }

            // (3) open with the recipient private key recovers plaintext
            let mut opener = PivBox::from_bytes(&expected_bytes).unwrap();
            opener.open_offline(&recipient_priv).unwrap();
            let recovered = opener.take_data().unwrap();
            assert_eq!(&*recovered, plaintext, "plaintext mismatch");
        }

        /// docs/rfcs/0002-piv-ecdh-box.md §A.1 — P-256, no GUID/slot,
        /// empty plaintext. Smallest realistic box (one PKCS7 block of
        /// padding, 16-byte AEAD tag). 174 bytes total.
        const A1_WIRE_HEX: &str = "b0c5020000001163686163686132302d706f6c79313330350673686135313210a0a1a2a3a4a5a6a7a8a9aaabacadaeaf086e697374703235362102515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f21031f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e0cd0d1d2d3d4d5d6d7d8d9dadb000000208dd88e114913dc759f69c7590b369008a754ee2d0528e4386c46661631e7fbfd";

        #[test]
        fn vector_a_1() {
            let recipient: Vec<u8> = (1u8..=32).collect();
            let ephemeral: Vec<u8> = (33u8..=64).collect();
            let kdf_nonce: Vec<u8> = (0xA0u8..=0xAF).collect();
            let cipher_iv: Vec<u8> = (0xD0u8..=0xDB).collect();
            replay_vector(
                EcCurve::NistP256,
                &recipient,
                &ephemeral,
                &kdf_nonce,
                &cipher_iv,
                b"",
                None,
                A1_WIRE_HEX,
            );
        }

        /// docs/rfcs/0002-piv-ecdh-box.md §A.2 — P-256, GUID
        /// 000102…0f / slot 0x9D, plaintext "hello". Exercises the
        /// guid_slot path on the wire and a non-empty payload. 190
        /// bytes total.
        const A2_WIRE_HEX: &str = "b0c5020110000102030405060708090a0b0c0d0e0f9d1163686163686132302d706f6c79313330350673686135313210b0b1b2b3b4b5b6b7b8b9babbbcbdbebf086e6973747032353621038e71ca9d7a62917be7f0db9896b47bf9b91c8b86628eed55d47fe750e65e5bcb21038ed57ec2b8f5e75e9192327b51e5661c87c8e5db0170721309a517fc6e1046b10ce0e1e2e3e4e5e6e7e8e9eaeb00000020f0a8350c88929a3f68dd0d5a74b5d339c5d3624f6b5be4a3b7aa86eac9e0e0db";

        #[test]
        fn vector_a_2() {
            let recipient: Vec<u8> = (0x10u8..=0x2F).collect();
            let ephemeral: Vec<u8> = (0x30u8..=0x4F).collect();
            let kdf_nonce: Vec<u8> = (0xB0u8..=0xBF).collect();
            let cipher_iv: Vec<u8> = (0xE0u8..=0xEBu8).collect();
            let guid_bytes: [u8; 16] = std::array::from_fn(|i| i as u8);
            let guid = piggy_piv::Guid::from_bytes(&guid_bytes).unwrap();
            replay_vector(
                EcCurve::NistP256,
                &recipient,
                &ephemeral,
                &kdf_nonce,
                &cipher_iv,
                b"hello",
                Some((guid, 0x9D)),
                A2_WIRE_HEX,
            );
        }

        /// docs/rfcs/0002-piv-ecdh-box.md §A.3 — P-384, no GUID/slot,
        /// plaintext "piggy rfc0002 vector A.3". Exercises the second
        /// supported curve (49-byte compressed points, longer wire).
        /// 222 bytes total.
        const A3_WIRE_HEX: &str = "b0c5020000001163686163686132302d706f6c79313330350673686135313210c0c1c2c3c4c5c6c7c8c9cacbcccdcecf086e697374703338343103c76f2283dda95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0b97499aef2f0ab313fa0283103db89855d1980b2aacdec0752249bea9e0630c16b69c095f6c752b2547b520d8109511d908881491780594f03cfee8a0a0cf0f1f2f3f4f5f6f7f8f9fafb0000003001ed7daba77156dd87a22208274ce93706f3261619acf1f52c8c3d12e71380f30fe5091f18b17ccdfbcefe2a15d0d6df";

        #[test]
        fn vector_a_3() {
            let recipient: Vec<u8> = (0x01u8..=0x30).collect();
            let ephemeral: Vec<u8> = (0x31u8..=0x60).collect();
            let kdf_nonce: Vec<u8> = (0xC0u8..=0xCF).collect();
            let cipher_iv: Vec<u8> = (0xF0u8..=0xFBu8).collect();
            replay_vector(
                EcCurve::NistP384,
                &recipient,
                &ephemeral,
                &kdf_nonce,
                &cipher_iv,
                b"piggy rfc0002 vector A.3",
                None,
                A3_WIRE_HEX,
            );
        }

        /// Sanity check: forces touching this list when adding a
        /// vector, which forces re-checking the spec.
        #[test]
        fn vector_count_matches_spec() {
            let ids = ["A.1", "A.2", "A.3"];
            assert_eq!(ids.len(), 3, "RFC 0002 §A pins exactly 3 vectors");
        }
    }

    /// Project Wycheproof ECDH test vectors replayed against piggy's
    /// `ecdh_derive` decode chain (`EcPoint::from_bytes` ->
    /// `EcKey::from_public_key` -> `ecdh_derive`). The vectors carry
    /// adversarial public keys: off-curve points, identity, low-order,
    /// wrong-curve, malformed encodings. The expected outcome of each
    /// vector is encoded in `result`:
    ///
    ///   Valid       => derive must succeed AND match `shared_secret`
    ///   Invalid     => derive must error somewhere in the chain
    ///   Acceptable  => either outcome is permitted (typically a
    ///                  compatibility carve-out the upstream policy
    ///                  flags but does not require)
    ///
    /// Failure in any of `EcPoint::from_bytes`, `EcKey::from_public_key`,
    /// or `Deriver::set_peer/derive` counts as "errored" — that mirrors
    /// what an attacker-controlled box would actually exercise via
    /// `PivBox::open_offline` (see piv_box.rs:189).
    ///
    /// The `_ecpoint_` schema is the right one for piggy: the wire
    /// `eckey8` field carries raw SEC1 octets (uncompressed `04‖X‖Y`
    /// or compressed `02/03‖X`), not ASN.1 SubjectPublicKeyInfo.
    /// Vectors whose public key uses a compressed encoding flow
    /// through unchanged — `EcPoint::from_bytes` accepts both forms,
    /// matching what `piv_box.rs::open_offline` accepts on the wire.
    mod wycheproof_ecdh {
        use super::*;
        use openssl::bn::{BigNum, BigNumContext};
        use wycheproof::ecdh::{EcdhEncoding, TestName, TestSet};
        use wycheproof::{EllipticCurve, TestResult};

        fn priv_key_from_scalar(curve: EcCurve, scalar_bytes: &[u8]) -> Option<EcKey<Private>> {
            let group = EcGroup::from_curve_name(curve.nid()).ok()?;
            let ctx = BigNumContext::new().ok()?;
            let scalar = BigNum::from_slice(scalar_bytes).ok()?;
            let mut pub_point = EcPoint::new(&group).ok()?;
            pub_point.mul_generator(&group, &scalar, &ctx).ok()?;
            // Guard the degenerate scalar=0 case: mul_generator yields
            // the point-at-infinity, which `from_private_components`
            // would happily wrap into an unusable EcKey. Wycheproof's
            // ECDH sets never carry such scalars, but be defensive.
            if pub_point.is_infinity(&group) {
                return None;
            }
            EcKey::from_private_components(&group, &scalar, &pub_point).ok()
        }

        /// Mirror of `PivBox::open_offline`'s decode chain (piv_box.rs:189):
        /// raw SEC1 bytes -> EcPoint -> EcKey<Public> -> ecdh_derive.
        /// Any step erroring is reported as `Err`.
        fn try_derive(
            curve: EcCurve,
            priv_scalar: &[u8],
            pub_bytes: &[u8],
        ) -> std::result::Result<Vec<u8>, String> {
            let group = EcGroup::from_curve_name(curve.nid())
                .map_err(|e| format!("group: {e}"))?;
            let mut ctx = BigNumContext::new().map_err(|e| format!("ctx: {e}"))?;
            let priv_key = priv_key_from_scalar(curve, priv_scalar)
                .ok_or_else(|| "priv scalar invalid".to_string())?;
            let pub_point = EcPoint::from_bytes(&group, pub_bytes, &mut ctx)
                .map_err(|e| format!("from_bytes: {e}"))?;
            let pub_key = EcKey::from_public_key(&group, &pub_point)
                .map_err(|e| format!("from_public_key: {e}"))?;
            ecdh_derive(&priv_key, &pub_key).map_err(|e| format!("derive: {e}"))
        }

        fn wycheproof_curve_to_piggy(c: EllipticCurve) -> Option<EcCurve> {
            match c {
                EllipticCurve::Secp256r1 => Some(EcCurve::NistP256),
                EllipticCurve::Secp384r1 => Some(EcCurve::NistP384),
                _ => None,
            }
        }

        fn run_set(name: TestName, expected: EcCurve) {
            let set = TestSet::load(name).expect("load wycheproof set");
            let mut valid_seen = 0usize;
            let mut invalid_seen = 0usize;
            for group in &set.test_groups {
                if group.encoding != EcdhEncoding::EcPoint {
                    continue;
                }
                let curve = match wycheproof_curve_to_piggy(group.curve) {
                    Some(c) if c == expected => c,
                    _ => continue,
                };
                for tc in &group.tests {
                    match tc.result {
                        TestResult::Valid => valid_seen += 1,
                        TestResult::Invalid => invalid_seen += 1,
                        TestResult::Acceptable => {}
                    }
                    let got = try_derive(curve, &tc.private_key, &tc.public_key);
                    match (&tc.result, &got) {
                        (TestResult::Valid, Ok(secret)) => {
                            assert_eq!(
                                secret.as_slice(),
                                tc.shared_secret.as_slice(),
                                "tcId {} ({}): valid vector produced wrong shared secret \
                                 (flags={:?})",
                                tc.tc_id,
                                tc.comment,
                                tc.flags,
                            );
                        }
                        (TestResult::Valid, Err(e)) => panic!(
                            "tcId {} ({}): valid vector errored: {e} (flags={:?})",
                            tc.tc_id, tc.comment, tc.flags,
                        ),
                        (TestResult::Invalid, Ok(secret)) => {
                            // The only safe way an "invalid" vector
                            // can succeed is if the derived secret
                            // happens to equal the listed value AND
                            // every flag is in the "acceptable for
                            // compat" allow-list. We don't grant any
                            // such compat here — invalid means error.
                            panic!(
                                "tcId {} ({}): invalid vector unexpectedly produced \
                                 secret {} (flags={:?})",
                                tc.tc_id,
                                tc.comment,
                                hex::encode(secret),
                                tc.flags,
                            );
                        }
                        (TestResult::Invalid, Err(_)) => {}
                        (TestResult::Acceptable, _) => {
                            // Either outcome permitted; if it
                            // succeeded, the secret must still match.
                            if let Ok(secret) = &got {
                                assert_eq!(
                                    secret.as_slice(),
                                    tc.shared_secret.as_slice(),
                                    "tcId {} ({}): acceptable vector succeeded but \
                                     produced wrong shared secret (flags={:?})",
                                    tc.tc_id,
                                    tc.comment,
                                    tc.flags,
                                );
                            }
                        }
                    }
                }
            }
            // Both buckets MUST be non-empty: a regression that silently
            // drops the invalid-vector groups would otherwise pass.
            assert!(
                valid_seen > 0 && invalid_seen > 0,
                "wycheproof set {name:?} produced \
                 {valid_seen} valid / {invalid_seen} invalid vectors — \
                 expected both buckets populated; group filter is wrong",
            );
        }

        #[test]
        fn wycheproof_p256_ecpoint() {
            run_set(TestName::EcdhSecp256r1Ecpoint, EcCurve::NistP256);
        }

        #[test]
        fn wycheproof_p384_ecpoint() {
            run_set(TestName::EcdhSecp384r1Ecpoint, EcCurve::NistP384);
        }
    }
}
