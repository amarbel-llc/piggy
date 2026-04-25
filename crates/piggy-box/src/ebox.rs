use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey::Private;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher as SymCipher};
use zeroize::Zeroizing;

use piggy_piv::Guid;

use crate::error::{BoxError, Result};
use crate::piv_box::{EcCurve, PivBox};
use crate::template::{
    EboxConfigType, EboxTemplate, DEFAULT_SLOT, PART_BOX, PART_CAK, PART_END, PART_GUID, PART_NAME,
    PART_OPTIONAL_FLAG, PART_PUBKEY, PART_SLOT,
};
use crate::wire::{WireReader, WireWriter};

const EBOX_MAGIC: u16 = 0xEB0C;
const EBOX_VERSION: u8 = 3;
const RECOVERY_CIPHER: &str = "aes256-gcm";

const RECOV_KEY: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EboxType {
    Template = 1,
    Key = 2,
    Stream = 3,
}

impl EboxType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(EboxType::Template),
            2 => Ok(EboxType::Key),
            3 => Ok(EboxType::Stream),
            _ => Err(BoxError::BadEboxType(v)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EphemeralKey {
    pub curve: EcCurve,
    pub pubkey: Vec<u8>,
}

#[derive(Debug)]
pub struct EboxPart {
    pub guid: Option<Guid>,
    pub slot: u8,
    pub name: Option<String>,
    pub pubkey: Option<Vec<u8>>,
    pub pubkey_curve: Option<EcCurve>,
    pub cak: Option<Vec<u8>>,
    pub piv_box: PivBox,
}

#[derive(Debug)]
pub struct EboxConfig {
    pub config_type: EboxConfigType,
    pub n: u8,
    pub nonce: Vec<u8>,
    pub parts: Vec<EboxPart>,
}

impl EboxConfig {
    pub fn m(&self) -> u8 {
        self.parts.len() as u8
    }
}

#[derive(Debug)]
pub struct Ebox {
    pub version: u8,
    pub ebox_type: EboxType,
    pub recovery_cipher: String,
    pub recovery_iv: Vec<u8>,
    pub recovery_enc: Vec<u8>,
    pub ephemeral_keys: Vec<EphemeralKey>,
    pub configs: Vec<EboxConfig>,
    key: Option<Zeroizing<Vec<u8>>>,
}

impl Ebox {
    pub fn create(tpl: &EboxTemplate, key: &[u8], ebox_type: EboxType) -> Result<Self> {
        let recovery_key = generate_random(32)?;

        // Build recovery plaintext: u8(RECOV_KEY) + string8(key)
        let mut recov_plain = WireWriter::new();
        recov_plain.put_u8(RECOV_KEY);
        recov_plain.put_string8(key)?;
        let recov_plaintext = recov_plain.into_bytes();

        // Encrypt with AES-256-GCM
        let (recovery_enc, recovery_iv) = aes256_gcm_encrypt(&recovery_key, &recov_plaintext)?;

        let mut ephemeral_keys: Vec<EphemeralKey> = Vec::new();
        let mut ephem_privkeys: Vec<(EcCurve, EcKey<Private>)> = Vec::new();

        let mut configs = Vec::with_capacity(tpl.configs.len());
        for tpl_config in &tpl.configs {
            let mut nonce = Vec::new();
            let mut shares: Option<Vec<Vec<u8>>> = None;

            if tpl_config.config_type == EboxConfigType::Recovery {
                nonce = generate_random(32)?;
                let mut config_key = vec![0u8; 32];
                for i in 0..32 {
                    config_key[i] = nonce[i] ^ recovery_key[i];
                }

                let m = tpl_config.parts.len() as u8;
                let n = tpl_config.n;
                let dealer = sharks::Sharks(n).dealer(&config_key);
                let share_vec: Vec<sharks::Share> = dealer.take(m as usize).collect();
                shares = Some(share_vec.iter().map(Vec::from).collect());
            }

            let mut parts = Vec::with_capacity(tpl_config.parts.len());
            for (i, tpl_part) in tpl_config.parts.iter().enumerate() {
                let curve = tpl_part.pubkey_curve;

                let ephem =
                    get_or_create_ephemeral(curve, &mut ephemeral_keys, &mut ephem_privkeys)?;

                let group = EcGroup::from_curve_name(curve.nid())?;
                let mut ctx = openssl::bn::BigNumContext::new()?;

                let recipient_point = EcPoint::from_bytes(&group, &tpl_part.pubkey, &mut ctx)?;
                let recipient_pub = EcKey::from_public_key(&group, &recipient_point)?;

                let mut pbox = PivBox::new(curve);
                pbox.guid_slot = Some((tpl_part.guid.clone(), tpl_part.slot));

                let plaintext = match &shares {
                    Some(ss) => ss[i].clone(),
                    None => key.to_vec(),
                };
                pbox.set_data(&plaintext);
                pbox.seal_offline_with_ephemeral(&recipient_pub, ephem)?;

                parts.push(EboxPart {
                    guid: Some(tpl_part.guid.clone()),
                    slot: tpl_part.slot,
                    name: tpl_part.name.clone(),
                    pubkey: Some(tpl_part.pubkey.clone()),
                    pubkey_curve: Some(curve),
                    cak: tpl_part.cak.clone(),
                    piv_box: pbox,
                });
            }

            configs.push(EboxConfig {
                config_type: tpl_config.config_type,
                n: tpl_config.n,
                nonce,
                parts,
            });
        }

        Ok(Ebox {
            version: EBOX_VERSION,
            ebox_type,
            recovery_cipher: RECOVERY_CIPHER.to_string(),
            recovery_iv,
            recovery_enc,
            ephemeral_keys,
            configs,
            key: None,
        })
    }

    /// Unlock with a PRIMARY config — first part with decrypted box data
    /// provides the ebox key.
    pub fn unlock(&mut self, config_idx: usize) -> Result<()> {
        if self.key.is_some() {
            return Err(BoxError::AlreadyUnlocked);
        }
        let config = &mut self.configs[config_idx];
        for part in &mut config.parts {
            if part.piv_box.has_plaintext() {
                let data = part.piv_box.take_data()?;
                self.key = Some(data);
                return Ok(());
            }
        }
        Err(BoxError::UnlockFailed)
    }

    /// Recover with a RECOVERY config — combine Shamir shares, XOR with
    /// nonce, then decrypt the recovery box.
    pub fn recover(&mut self, config_idx: usize) -> Result<()> {
        if self.key.is_some() {
            return Err(BoxError::AlreadyUnlocked);
        }
        let n = self.configs[config_idx].n;

        let mut shares: Vec<sharks::Share> = Vec::new();
        for part in &mut self.configs[config_idx].parts {
            if part.piv_box.has_plaintext() {
                let data = part.piv_box.take_data()?;
                if let Ok(share) = sharks::Share::try_from(data.as_slice()) {
                    shares.push(share);
                }
            }
        }

        if shares.len() < n as usize {
            return Err(BoxError::ThresholdNotMet {
                have: shares.len(),
                need: n as usize,
            });
        }

        let config_key = sharks::Sharks(n)
            .recover(&shares)
            .map_err(|e| BoxError::Crypto(format!("Shamir recover: {e}")))?;

        // XOR config_key with nonce to get recovery key
        let nonce = &self.configs[config_idx].nonce;
        if nonce.len() != config_key.len() {
            return Err(BoxError::Crypto("recovery nonce length mismatch".into()));
        }
        let mut recovery_key = vec![0u8; config_key.len()];
        for i in 0..config_key.len() {
            recovery_key[i] = config_key[i] ^ nonce[i];
        }

        // Decrypt recovery box
        let recov_plain = aes256_gcm_decrypt(&recovery_key, &self.recovery_iv, &self.recovery_enc)?;

        // Parse recovery plaintext to extract key
        let mut r = WireReader::new(&recov_plain);
        loop {
            let tag = r.get_u8()?;
            let data = r.get_string8()?;
            if tag == RECOV_KEY {
                self.key = Some(Zeroizing::new(data));
                return Ok(());
            }
            // Skip unknown tags
            if r.remaining() == 0 {
                break;
            }
        }

        Err(BoxError::Crypto("recovery box did not contain key".into()))
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_ref().map(|k| k.as_slice())
    }

    /// True once [`Self::unlock`] (or [`Self::recover`], or
    /// [`Self::set_key`]) has populated the inner key. Added in
    /// checkpoint 3A of issue #32 so integration tests can assert on
    /// unlock state without poking into private fields.
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = Some(Zeroizing::new(key));
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = WireWriter::new();
        w.put_u8((EBOX_MAGIC >> 8) as u8);
        w.put_u8((EBOX_MAGIC & 0xFF) as u8);
        w.put_u8(self.version);
        w.put_u8(self.ebox_type as u8);

        w.put_cstring8(&self.recovery_cipher)?;
        w.put_string8(&self.recovery_iv)?;
        w.put_string8(&self.recovery_enc)?;

        if self.version >= 2 {
            w.put_u8(self.ephemeral_keys.len() as u8);
            for ek in &self.ephemeral_keys {
                w.put_cstring8(ek.curve.wire_name())?;
                w.put_eckey8(&ek.pubkey)?;
            }
        }

        w.put_u8(self.configs.len() as u8);
        for config in &self.configs {
            write_ebox_config(&mut w, config, self.version)?;
        }

        Ok(w.into_bytes())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = WireReader::new(data);
        Self::read_from(&mut r)
    }

    pub fn read_from(r: &mut WireReader) -> Result<Self> {
        let magic_hi = r.get_u8()?;
        let magic_lo = r.get_u8()?;
        let magic = ((magic_hi as u16) << 8) | (magic_lo as u16);
        if magic != EBOX_MAGIC {
            return Err(BoxError::BadMagic {
                expected: EBOX_MAGIC,
                got: magic,
            });
        }

        let version = r.get_u8()?;
        let etype_raw = r.get_u8()?;
        let ebox_type = EboxType::from_u8(etype_raw)?;
        if ebox_type == EboxType::Template {
            return Err(BoxError::BadEboxType(etype_raw));
        }

        let recovery_cipher = r.get_cstring8()?;
        let recovery_iv = r.get_string8()?;
        let recovery_enc = r.get_string8()?;

        let mut ephemeral_keys = Vec::new();
        if version >= 2 {
            let neeks = r.get_u8()?;
            for _ in 0..neeks {
                let curve_name = r.get_cstring8()?;
                let curve = EcCurve::from_wire_name(&curve_name)?;
                let pubkey = r.get_eckey8()?;
                ephemeral_keys.push(EphemeralKey { curve, pubkey });
            }
        }

        let nconfigs = r.get_u8()?;
        let mut configs = Vec::with_capacity(nconfigs as usize);
        for _ in 0..nconfigs {
            configs.push(read_ebox_config(r, version)?);
        }

        Ok(Ebox {
            version,
            ebox_type,
            recovery_cipher,
            recovery_iv,
            recovery_enc,
            ephemeral_keys,
            configs,
            key: None,
        })
    }
}

fn write_ebox_config(w: &mut WireWriter, config: &EboxConfig, version: u8) -> Result<()> {
    w.put_u8(config.config_type as u8);
    w.put_u8(config.n);
    w.put_u8(config.m());

    // Nonce: non-empty for RECOVERY in v3+, zero-length string8 for PRIMARY
    if !config.nonce.is_empty() {
        w.put_string8(&config.nonce)?;
    } else {
        w.put_u8(0); // string8 with length 0
    }

    for part in &config.parts {
        write_ebox_part(w, part, version)?;
    }

    Ok(())
}

fn read_ebox_config(r: &mut WireReader, version: u8) -> Result<EboxConfig> {
    let config_type = EboxConfigType::from_u8(r.get_u8()?)?;
    let n = r.get_u8()?;
    let m = r.get_u8()?;

    // Nonce field
    let nonce = r.get_string8()?;

    let mut parts = Vec::with_capacity(m as usize);
    for _ in 0..m {
        parts.push(read_ebox_part(r, version)?);
    }

    Ok(EboxConfig {
        config_type,
        n,
        nonce,
        parts,
    })
}

fn write_ebox_part(w: &mut WireWriter, part: &EboxPart, version: u8) -> Result<()> {
    // GUID tag
    if let Some(guid) = &part.guid {
        w.put_u8(PART_GUID);
        w.put_string8(guid.as_bytes())?;
    }

    // NAME tag
    if let Some(name) = &part.name {
        w.put_u8(PART_NAME);
        w.put_cstring8(name)?;
    }

    // CAK tag
    if let Some(cak) = &part.cak {
        w.put_u8(PART_CAK);
        w.put_string(cak);
    }

    // SLOT tag (only if non-default)
    if part.slot != DEFAULT_SLOT {
        w.put_u8(PART_SLOT);
        w.put_u8(part.slot);
    }

    // BOX tag — inline fields for v2+
    w.put_u8(PART_BOX);
    if version >= 2 {
        let b = &part.piv_box;
        w.put_cstring8(&b.cipher)?;
        w.put_cstring8(&b.kdf)?;
        w.put_string8(&b.nonce)?;
        w.put_cstring8(b.curve.wire_name())?;
        w.put_eckey8(&b.recipient_pubkey)?;
        w.put_string8(&b.iv)?;
        w.put_string(&b.ciphertext);
    } else {
        let box_bytes = part.piv_box.to_bytes()?;
        w.put_raw(&box_bytes);
    }

    w.put_u8(PART_END);
    Ok(())
}

fn read_ebox_part(r: &mut WireReader, version: u8) -> Result<EboxPart> {
    let mut guid: Option<Guid> = None;
    let mut slot: u8 = DEFAULT_SLOT;
    let mut name: Option<String> = None;
    let mut pubkey: Option<Vec<u8>> = None;
    let mut pubkey_curve: Option<EcCurve> = None;
    let mut cak: Option<Vec<u8>> = None;
    let mut piv_box: Option<PivBox> = None;

    let mut tag = r.get_u8()?;
    while tag != PART_END {
        match tag & !PART_OPTIONAL_FLAG {
            PART_PUBKEY => {
                let curve_name = r.get_cstring8()?;
                pubkey_curve = Some(EcCurve::from_wire_name(&curve_name)?);
                pubkey = Some(r.get_eckey8()?);
            }
            PART_GUID => {
                let guid_bytes = r.get_string8()?;
                guid = Some(Guid::from_bytes(&guid_bytes)?);
            }
            PART_NAME => {
                name = Some(r.get_cstring8()?);
            }
            PART_CAK => {
                cak = Some(r.get_string()?);
            }
            PART_SLOT => {
                slot = r.get_u8()?;
            }
            PART_BOX => {
                if version >= 2 {
                    let cipher = r.get_cstring8()?;
                    let kdf = r.get_cstring8()?;
                    let nonce = r.get_string8()?;
                    let curve_name = r.get_cstring8()?;
                    let curve = EcCurve::from_wire_name(&curve_name)?;
                    let recipient_pubkey = r.get_eckey8()?;
                    let iv = r.get_string8()?;
                    let ciphertext = r.get_string()?;

                    let mut b = PivBox::new(curve);
                    b.cipher = cipher;
                    b.kdf = kdf;
                    b.nonce = nonce;
                    b.recipient_pubkey = recipient_pubkey;
                    b.ephemeral_pubkey = Vec::new(); // derived from ebox ephemeral keys
                    b.iv = iv;
                    b.ciphertext = ciphertext;
                    if let Some(g) = &guid {
                        b.guid_slot = Some((g.clone(), slot));
                    }
                    piv_box = Some(b);
                } else {
                    piv_box = Some(PivBox::from_bytes(r.rest())?);
                    // TODO: advance reader past the consumed bytes
                }
            }
            _ => {
                if tag & PART_OPTIONAL_FLAG != 0 {
                    let _ = r.get_string8()?;
                } else {
                    return Err(BoxError::Wire(format!("unknown ebox part tag {tag:#04x}")));
                }
            }
        }
        tag = r.get_u8()?;
    }

    let piv_box = piv_box.ok_or_else(|| BoxError::Wire("ebox part missing BOX tag".into()))?;

    Ok(EboxPart {
        guid,
        slot,
        name,
        pubkey,
        pubkey_curve,
        cak,
        piv_box,
    })
}

fn get_or_create_ephemeral<'a>(
    curve: EcCurve,
    ephemeral_keys: &mut Vec<EphemeralKey>,
    ephem_privkeys: &'a mut Vec<(EcCurve, EcKey<Private>)>,
) -> Result<&'a EcKey<Private>> {
    if let Some(idx) = ephem_privkeys.iter().position(|(c, _)| *c == curve) {
        return Ok(&ephem_privkeys[idx].1);
    }

    let group = EcGroup::from_curve_name(curve.nid())?;
    let priv_key = EcKey::generate(&group)?;

    let mut ctx = openssl::bn::BigNumContext::new()?;
    let pubkey_bytes = priv_key.public_key().to_bytes(
        &group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut ctx,
    )?;

    ephemeral_keys.push(EphemeralKey {
        curve,
        pubkey: pubkey_bytes,
    });
    ephem_privkeys.push((curve, priv_key));

    Ok(&ephem_privkeys.last().unwrap().1)
}

fn generate_random(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    openssl::rand::rand_bytes(&mut buf)?;
    Ok(buf)
}

fn aes256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = SymCipher::aes_256_gcm();
    let mut iv = vec![0u8; 12];
    openssl::rand::rand_bytes(&mut iv)?;

    let mut tag = vec![0u8; 16];
    let mut ct = encrypt_aead(cipher, key, Some(&iv), &[], plaintext, &mut tag)?;
    ct.extend_from_slice(&tag);

    Ok((ct, iv))
}

fn aes256_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 16 {
        return Err(BoxError::Crypto(
            "AES-256-GCM ciphertext too short for tag".into(),
        ));
    }
    let tag_offset = ciphertext.len() - 16;
    let ct = &ciphertext[..tag_offset];
    let tag = &ciphertext[tag_offset..];

    let cipher = SymCipher::aes_256_gcm();
    let pt = decrypt_aead(cipher, key, Some(iv), &[], ct, tag)
        .map_err(|e| BoxError::Crypto(format!("AES-256-GCM decrypt: {e}")))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{EboxConfigType, EboxTemplate, EboxTplConfig, EboxTplPart};

    fn make_tpl_and_privkey() -> (EboxTemplate, EcKey<Private>) {
        let curve = EcCurve::NistP256;
        let group = EcGroup::from_curve_name(curve.nid()).unwrap();
        let priv_key = EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let pubkey = priv_key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::COMPRESSED,
                &mut ctx,
            )
            .unwrap();

        let tpl = EboxTemplate {
            version: 1,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![EboxTplPart {
                    guid: Guid::from_hex("AABBCCDD11223344AABBCCDD11223344").unwrap(),
                    slot: DEFAULT_SLOT,
                    name: Some("piggy-test:ebox-fixture".to_string()),
                    pubkey,
                    pubkey_curve: curve,
                    cak: None,
                }],
            }],
        };

        (tpl, priv_key)
    }

    #[test]
    fn ebox_create_and_serialize_roundtrip() {
        let (tpl, _) = make_tpl_and_privkey();
        let user_key = b"my-secret-key-32-bytes-exactly!!";

        let ebox = Ebox::create(&tpl, user_key, EboxType::Key).unwrap();
        let bytes = ebox.to_bytes().unwrap();
        let ebox2 = Ebox::from_bytes(&bytes).unwrap();

        assert_eq!(ebox2.version, EBOX_VERSION);
        assert_eq!(ebox2.ebox_type, EboxType::Key);
        assert_eq!(ebox2.configs.len(), 1);
        assert_eq!(ebox2.configs[0].parts.len(), 1);

        let bytes2 = ebox2.to_bytes().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ebox_create_unlock_roundtrip() {
        let (tpl, priv_key) = make_tpl_and_privkey();
        let user_key = b"my-secret-key-32-bytes-exactly!!";

        let ebox = Ebox::create(&tpl, user_key, EboxType::Key).unwrap();
        let bytes = ebox.to_bytes().unwrap();
        let mut ebox2 = Ebox::from_bytes(&bytes).unwrap();

        // Need to set the ephemeral pubkey on the box for decryption
        assert!(!ebox2.ephemeral_keys.is_empty());
        let ephem_pub_bytes = &ebox2.ephemeral_keys[0].pubkey.clone();
        ebox2.configs[0].parts[0].piv_box.ephemeral_pubkey = ephem_pub_bytes.clone();

        ebox2.configs[0].parts[0]
            .piv_box
            .open_offline(&priv_key)
            .unwrap();
        ebox2.unlock(0).unwrap();

        assert_eq!(ebox2.key().unwrap(), user_key);
    }

    #[test]
    fn ebox_already_unlocked_error() {
        let (tpl, priv_key) = make_tpl_and_privkey();
        let user_key = b"my-secret-key-32-bytes-exactly!!";

        let ebox = Ebox::create(&tpl, user_key, EboxType::Key).unwrap();
        let bytes = ebox.to_bytes().unwrap();
        let mut ebox2 = Ebox::from_bytes(&bytes).unwrap();

        let ephem_pub = ebox2.ephemeral_keys[0].pubkey.clone();
        ebox2.configs[0].parts[0].piv_box.ephemeral_pubkey = ephem_pub;

        ebox2.configs[0].parts[0]
            .piv_box
            .open_offline(&priv_key)
            .unwrap();
        ebox2.unlock(0).unwrap();
        assert!(matches!(ebox2.unlock(0), Err(BoxError::AlreadyUnlocked)));
    }

    /// Property-based wire-format fuzzing for `Ebox`. See #40. Each
    /// iteration runs real ECDH + AEAD, so cases are capped low.
    mod proptest_wire {
        use super::*;
        use crate::template::{EboxTplConfig, EboxTplPart, DEFAULT_SLOT};
        use proptest::prelude::*;

        // Generate compressed-point bytes by spawning a real EcKey on
        // the chosen curve — Ebox::create needs the bytes to round-trip
        // through ECDH (the stub PivBox parts hash these against an
        // ephemeral). Random bytes won't validate as EC points.
        fn arb_curve_and_real_pubkey() -> impl Strategy<Value = (EcCurve, Vec<u8>)> {
            prop_oneof![
                Just(EcCurve::NistP256),
                Just(EcCurve::NistP384),
            ]
            .prop_map(|curve| {
                let group = EcGroup::from_curve_name(curve.nid()).unwrap();
                let key = EcKey::generate(&group).unwrap();
                let mut ctx = openssl::bn::BigNumContext::new().unwrap();
                let pubkey = key
                    .public_key()
                    .to_bytes(
                        &group,
                        openssl::ec::PointConversionForm::COMPRESSED,
                        &mut ctx,
                    )
                    .unwrap();
                (curve, pubkey)
            })
        }

        fn arb_part() -> impl Strategy<Value = EboxTplPart> {
            (
                any::<[u8; 16]>(),
                arb_curve_and_real_pubkey(),
                prop::option::of("piggy-test:proptest-[a-z0-9]{1,8}"),
            )
                .prop_map(|(guid_bytes, (pubkey_curve, pubkey), name)| EboxTplPart {
                    guid: piggy_piv::Guid::from_bytes(&guid_bytes).unwrap(),
                    slot: DEFAULT_SLOT,
                    name,
                    pubkey,
                    pubkey_curve,
                    cak: None,
                })
        }

        fn arb_template() -> impl Strategy<Value = crate::template::EboxTemplate> {
            proptest::collection::vec(arb_part(), 1..=2).prop_map(|parts| {
                crate::template::EboxTemplate {
                    version: 1,
                    configs: vec![EboxTplConfig {
                        config_type: EboxConfigType::Primary,
                        n: 1,
                        parts,
                    }],
                }
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 16, .. ProptestConfig::default() })]

            #[test]
            fn ebox_serialize_parse_idempotent(
                tpl in arb_template(),
                key_len in 16usize..=64,
            ) {
                let key = vec![0xa5u8; key_len];
                let ebox = Ebox::create(&tpl, &key, EboxType::Key).unwrap();

                let bytes1 = ebox.to_bytes().unwrap();
                let parsed = Ebox::from_bytes(&bytes1).unwrap();
                let bytes2 = parsed.to_bytes().unwrap();
                prop_assert_eq!(
                    bytes1,
                    bytes2,
                    "ebox wire serialize→parse→serialize is not idempotent"
                );
            }
        }
    }
}
