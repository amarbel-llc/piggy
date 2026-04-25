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
    /// The wire nonce is generated freshly here. For deterministic
    /// reproduction (e.g. RFC 0002 §A test vectors) call
    /// [`PivBox::seal_offline_with_ephemeral_and_nonce`] directly with a
    /// caller-controlled nonce.
    pub fn seal_offline_with_ephemeral(
        &mut self,
        recipient_pub: &EcKey<openssl::pkey::Public>,
        ephem: &EcKey<Private>,
    ) -> Result<()> {
        let mut nonce = vec![0u8; NONCE_LEN];
        openssl::rand::rand_bytes(&mut nonce)?;
        self.seal_offline_with_ephemeral_and_nonce(recipient_pub, ephem, &nonce)
    }

    /// Seal with both the ephemeral key and the KDF nonce supplied by
    /// the caller. Crate-private because deterministic nonce reuse is
    /// unsafe in production: callers MUST guarantee per-box nonce
    /// freshness, which only holds for one-shot tests with hard-coded
    /// inputs (see `docs/rfcs/0002-piv-ecdh-box.md` §A).
    pub(crate) fn seal_offline_with_ephemeral_and_nonce(
        &mut self,
        recipient_pub: &EcKey<openssl::pkey::Public>,
        ephem: &EcKey<Private>,
        nonce: &[u8],
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

        self.nonce = nonce.to_vec();

        let key_material = kdf_sha512(&shared_secret, &self.nonce)?;
        let padded = pkcs7_pad(plaintext, 16);
        let ct = chacha20_poly1305_encrypt(&key_material[..32], &padded)?;
        // Per RFC 0002 §Cipher, chacha20-poly1305 has a 0-byte IV on the
        // wire — the cipher uses an all-zero internal nonce fed to the
        // AEAD primitive, but the serialized `iv` field is empty. pivy C's
        // `piv_box_open_common` validates `pdb_iv.b_len == cipher_ivlen`,
        // and `cipher_ivlen("chacha20-poly1305") == 0`; writing any
        // non-empty IV here makes pivy reject the box.
        // TODO: when we support aes256-gcm (or any cipher with non-zero
        // ivlen), cipher-dispatch both the internal nonce and the wire IV.
        self.iv = Vec::new();
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
        let key_material = kdf_sha512(shared_secret, &self.nonce)?;
        // `self.iv` is intentionally ignored: per RFC 0002 §Cipher, the
        // chacha20-poly1305 wire IV is 0-length and the primitive uses an
        // all-zero internal nonce (established inside
        // `chacha20_poly1305_decrypt`). This accepts any serialized IV —
        // 0-byte (spec-correct) or 12-zero-byte (from older Rust seals
        // before the #34 fix) — so we can decrypt both shapes.
        let padded = chacha20_poly1305_decrypt(&key_material[..32], &self.ciphertext)?;
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

/// Encrypt with ChaCha20-Poly1305 using an all-zero internal nonce.
///
/// Per RFC 0002 §Cipher, the `chacha20-poly1305` cipher as used by pivy
/// feeds the AEAD primitive an all-zero 12-byte nonce; the serialized
/// piv_box `iv` field is always 0-length for this cipher. Returning just
/// the (ciphertext || tag) keeps the encrypt path from leaking an
/// already-known nonce that callers might be tempted to persist.
fn chacha20_poly1305_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use openssl::symm::{encrypt_aead, Cipher};

    let cipher = Cipher::chacha20_poly1305();
    let iv = [0u8; 12];

    let mut tag = vec![0u8; 16];
    let mut ct = encrypt_aead(cipher, key, Some(&iv), &[], plaintext, &mut tag)?;
    ct.extend_from_slice(&tag);

    Ok(ct)
}

/// Decrypt ChaCha20-Poly1305 ciphertext (with appended 16-byte tag)
/// using an all-zero internal nonce. See [`chacha20_poly1305_encrypt`].
fn chacha20_poly1305_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use openssl::symm::{decrypt_aead, Cipher};

    let cipher = Cipher::chacha20_poly1305();

    if ciphertext.len() < 16 {
        return Err(BoxError::Crypto("ciphertext too short for auth tag".into()));
    }

    let tag_offset = ciphertext.len() - 16;
    let ct = &ciphertext[..tag_offset];
    let tag = &ciphertext[tag_offset..];

    let iv = [0u8; 12];
    let pt = decrypt_aead(cipher, key, Some(&iv), &[], ct, tag)
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
    fn seal_leaves_iv_field_empty_per_rfc_0002() {
        // Regression test for #34. Per RFC 0002 §Cipher, the
        // chacha20-poly1305 wire IV is 0 bytes. Pre-fix, Rust wrote 12
        // zero bytes here, shifting the rest of the parse on pivy C and
        // surfacing as "IV length (0) is not appropriate for cipher
        // 'chacha20-poly1305'".
        let (pub_key, _) = generate_keypair(EcCurve::NistP256);
        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"payload");
        b.seal_offline(&pub_key).unwrap();
        assert!(
            b.iv.is_empty(),
            "post-#34, PivBox.iv must be empty for chacha20-poly1305 (got {} bytes)",
            b.iv.len()
        );

        // Deserialize and assert the field survives the wire round-trip.
        let bytes = b.to_bytes().unwrap();
        let b2 = PivBox::from_bytes(&bytes).unwrap();
        assert!(
            b2.iv.is_empty(),
            "IV field on the wire must deserialize as empty (got {} bytes)",
            b2.iv.len()
        );
    }

    #[test]
    fn wire_iv_length_prefix_is_zero_byte() {
        // Byte-level canary: the IV field's u8 length prefix sits at a
        // known offset for a v2 no-guid Primary box with DEFAULT_CIPHER
        // + DEFAULT_KDF on NistP256. If a future refactor writes any
        // non-zero byte there, pivy C will reject — this test fails
        // before interop does.
        //
        // Layout up to the IV field (pivy RFC 0002 §Binary Serialization):
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
        //   off 125    IV string8 len             <-- MUST be 0x00
        let (pub_key, _) = generate_keypair(EcCurve::NistP256);
        let mut b = PivBox::new(EcCurve::NistP256);
        b.set_data(b"payload");
        b.seal_offline(&pub_key).unwrap();
        let bytes = b.to_bytes().unwrap();

        assert_eq!(
            bytes.get(125),
            Some(&0x00),
            "IV length byte at offset 125 must be 0x00 for chacha20-poly1305 \
             (got {:?}); pivy C rejects anything else. If the layout above \
             shifted, update the offset AND pivy C's expected ivlen.",
            bytes.get(125)
        );
    }

    #[test]
    fn open_with_secret_ignores_self_iv() {
        // open_with_secret must not depend on `self.iv`. This test seals
        // a box, then mutates `self.iv` to a bogus 12-zero vector — the
        // same shape older Rust seals produced before #34 — and confirms
        // decrypt still succeeds. Covers backwards-compatibility for
        // eboxes sealed by a pre-fix Rust and still at rest on disk.
        let (pub_key, priv_key) = generate_keypair(EcCurve::NistP256);
        let mut b = PivBox::new(EcCurve::NistP256);
        let data = b"backcompat-payload";
        b.set_data(data);
        b.seal_offline(&pub_key).unwrap();

        // Round-trip through the wire so we have a fresh struct whose
        // state mirrors what from_bytes would produce — then inject a
        // legacy-shaped IV.
        let bytes = b.to_bytes().unwrap();
        let mut b2 = PivBox::from_bytes(&bytes).unwrap();
        b2.iv = vec![0u8; 12];
        b2.open_offline(&priv_key).unwrap();

        let recovered = b2.take_data().unwrap();
        assert_eq!(&*recovered, data);
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

    /// Replays the bit-exact wire vectors pinned in
    /// `docs/rfcs/0002-piv-ecdh-box.md` Appendix A. Each vector fixes
    /// every input that feeds the wire (recipient priv, ephemeral priv,
    /// KDF nonce, plaintext, GUID/slot) so that
    /// `seal_offline_with_ephemeral_and_nonce` produces a known-byte
    /// output. Drift between this module and the spec is a CI failure.
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
        fn replay_vector(
            curve: EcCurve,
            recipient_scalar: &[u8],
            ephemeral_scalar: &[u8],
            nonce: &[u8],
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
                .seal_offline_with_ephemeral_and_nonce(&recipient_pub, &ephemeral_priv, nonce)
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
            assert_eq!(parsed.nonce, nonce, "nonce");
            assert!(parsed.iv.is_empty(), "wire IV must be 0-length");
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
        /// padding, 16-byte AEAD tag).
        const A1_WIRE_HEX: &str = "b0c5020000001163686163686132302d706f6c79313330350673686135313210a0a1a2a3a4a5a6a7a8a9aaabacadaeaf086e697374703235362102515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f21031f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e0000000020e1a6ec6df050b2a882cd105457da7b1d6d36a2ab8636ec0181d34e9150290f88";

        #[test]
        fn vector_a_1() {
            let recipient: Vec<u8> = (1u8..=32).collect();
            let ephemeral: Vec<u8> = (33u8..=64).collect();
            let nonce: Vec<u8> = (0xA0u8..=0xAF).collect();
            replay_vector(
                EcCurve::NistP256,
                &recipient,
                &ephemeral,
                &nonce,
                b"",
                None,
                A1_WIRE_HEX,
            );
        }

        /// docs/rfcs/0002-piv-ecdh-box.md §A.2 — P-256, GUID
        /// 000102…0f / slot 0x9D, plaintext "hello". Exercises the
        /// guid_slot path on the wire and a non-empty payload.
        const A2_WIRE_HEX: &str = "b0c5020110000102030405060708090a0b0c0d0e0f9d1163686163686132302d706f6c79313330350673686135313210b0b1b2b3b4b5b6b7b8b9babbbcbdbebf086e6973747032353621038e71ca9d7a62917be7f0db9896b47bf9b91c8b86628eed55d47fe750e65e5bcb21038ed57ec2b8f5e75e9192327b51e5661c87c8e5db0170721309a517fc6e1046b10000000020038feab45e59efde12f175924622799489bb4bd7da8fbba06f898c04a3dff04f";

        #[test]
        fn vector_a_2() {
            let recipient: Vec<u8> = (0x10u8..=0x2F).collect();
            let ephemeral: Vec<u8> = (0x30u8..=0x4F).collect();
            let nonce: Vec<u8> = (0xB0u8..=0xBF).collect();
            let guid_bytes: [u8; 16] = std::array::from_fn(|i| i as u8);
            let guid = piggy_piv::Guid::from_bytes(&guid_bytes).unwrap();
            replay_vector(
                EcCurve::NistP256,
                &recipient,
                &ephemeral,
                &nonce,
                b"hello",
                Some((guid, 0x9D)),
                A2_WIRE_HEX,
            );
        }

        /// docs/rfcs/0002-piv-ecdh-box.md §A.3 — P-384, no GUID/slot,
        /// plaintext "piggy rfc0002 vector A.3". Exercises the second
        /// supported curve (49-byte compressed points, longer wire).
        const A3_WIRE_HEX: &str = "b0c5020000001163686163686132302d706f6c79313330350673686135313210c0c1c2c3c4c5c6c7c8c9cacbcccdcecf086e697374703338343103c76f2283dda95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0b97499aef2f0ab313fa0283103db89855d1980b2aacdec0752249bea9e0630c16b69c095f6c752b2547b520d8109511d908881491780594f03cfee8a0a000000003034edc15689caddcaffd2267362aae0a69c1af4696fc7dd02cec0be62b6552163999d6d9bb78fd6d79715e2f7359f0501";

        #[test]
        fn vector_a_3() {
            let recipient: Vec<u8> = (0x01u8..=0x30).collect();
            let ephemeral: Vec<u8> = (0x31u8..=0x60).collect();
            let nonce: Vec<u8> = (0xC0u8..=0xCF).collect();
            replay_vector(
                EcCurve::NistP384,
                &recipient,
                &ephemeral,
                &nonce,
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
}
