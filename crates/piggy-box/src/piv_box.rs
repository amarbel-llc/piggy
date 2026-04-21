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

    pub fn seal_offline(
        &mut self,
        recipient_pub: &EcKey<openssl::pkey::Public>,
    ) -> Result<()> {
        let group = EcGroup::from_curve_name(self.curve.nid())?;
        let ephem = EcKey::generate(&group)?;
        self.seal_offline_with_ephemeral(recipient_pub, &ephem)
    }

    /// Seal using an externally-provided ephemeral key. Used by Ebox to
    /// share a single ephemeral key across all parts on the same curve.
    pub fn seal_offline_with_ephemeral(
        &mut self,
        recipient_pub: &EcKey<openssl::pkey::Public>,
        ephem: &EcKey<Private>,
    ) -> Result<()> {
        let plaintext = self.plaintext.as_ref().ok_or(BoxError::NotSealed)?;

        let group = EcGroup::from_curve_name(self.curve.nid())?;
        let mut ctx = openssl::bn::BigNumContext::new()?;

        self.recipient_pubkey = recipient_pub
            .public_key()
            .to_bytes(&group, openssl::ec::PointConversionForm::COMPRESSED, &mut ctx)?;

        self.ephemeral_pubkey = ephem
            .public_key()
            .to_bytes(&group, openssl::ec::PointConversionForm::COMPRESSED, &mut ctx)?;

        let shared_secret = ecdh_derive(ephem, recipient_pub)?;

        let mut nonce = vec![0u8; NONCE_LEN];
        openssl::rand::rand_bytes(&mut nonce)?;
        self.nonce = nonce;

        let key_material = kdf_sha512(&shared_secret, &self.nonce)?;
        let padded = pkcs7_pad(plaintext, 16);
        let (ct, iv) = chacha20_poly1305_encrypt(&key_material[..32], &padded)?;
        self.iv = iv;
        self.ciphertext = ct;

        Ok(())
    }

    pub fn open_offline(
        &mut self,
        privkey: &EcKey<Private>,
    ) -> Result<()> {
        let group = EcGroup::from_curve_name(self.curve.nid())?;
        let mut ctx = openssl::bn::BigNumContext::new()?;

        // Reconstruct ephemeral public key from compressed point
        let ephem_point = EcPoint::from_bytes(&group, &self.ephemeral_pubkey, &mut ctx)?;
        let ephem_pub = EcKey::from_public_key(&group, &ephem_point)?;

        // ECDH shared secret
        let shared_secret = ecdh_derive(privkey, &ephem_pub)?;

        // KDF
        let key_material = kdf_sha512(&shared_secret, &self.nonce)?;

        // Decrypt
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
    let pkey_priv = openssl::pkey::PKey::from_ec_key(
        EcKey::from_private_components(
            privkey.group(),
            privkey.private_key(),
            privkey.public_key(),
        )?,
    )?;
    let pkey_pub = openssl::pkey::PKey::from_ec_key(
        EcKey::from_public_key(pubkey.group(), pubkey.public_key())?,
    )?;
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

fn chacha20_poly1305_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use openssl::symm::{encrypt_aead, Cipher};

    let cipher = Cipher::chacha20_poly1305();
    let iv = vec![0u8; 12]; // pivy always uses zero IV for ChaCha20-Poly1305

    let mut tag = vec![0u8; 16];
    let mut ct = encrypt_aead(cipher, key, Some(&iv), &[], plaintext, &mut tag)?;
    ct.extend_from_slice(&tag);

    Ok((ct, iv))
}

fn chacha20_poly1305_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use openssl::symm::{decrypt_aead, Cipher};

    let cipher = Cipher::chacha20_poly1305();

    if ciphertext.len() < 16 {
        return Err(BoxError::Crypto("ciphertext too short for auth tag".into()));
    }

    let tag_offset = ciphertext.len() - 16;
    let ct = &ciphertext[..tag_offset];
    let tag = &ciphertext[tag_offset..];

    let effective_iv = if iv.is_empty() {
        vec![0u8; 12]
    } else {
        iv.to_vec()
    };

    let pt = decrypt_aead(cipher, key, Some(&effective_iv), &[], ct, tag)
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
}
