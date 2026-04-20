use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher as SymCipher, Crypter, Mode};

use crate::ebox::{Ebox, EboxType};
use crate::error::{BoxError, Result};
use crate::template::EboxTemplate;
use crate::wire::{WireReader, WireWriter};

const DEFAULT_CHUNK_SIZE: u64 = 128 * 1024;
const DEFAULT_CIPHER: &str = "aes256-ctr";
const DEFAULT_MAC: &str = "sha256";
const AES_BLOCK_SIZE: usize = 16;
const AES_KEY_LEN: usize = 32;
const AES_IV_LEN: usize = 16;
const HMAC_LEN: usize = 32;

#[derive(Debug)]
pub struct EboxStream {
    pub ebox: Ebox,
    pub cipher: String,
    pub mac: String,
    pub chunk_size: u64,
}

impl EboxStream {
    pub fn new(tpl: &EboxTemplate) -> Result<Self> {
        let mut key_bytes = vec![0u8; AES_KEY_LEN];
        openssl::rand::rand_bytes(&mut key_bytes)?;

        let mut ebox = Ebox::create(tpl, &key_bytes, EboxType::Stream)?;
        ebox.set_key(key_bytes);

        Ok(EboxStream {
            ebox,
            cipher: DEFAULT_CIPHER.to_string(),
            mac: DEFAULT_MAC.to_string(),
            chunk_size: DEFAULT_CHUNK_SIZE,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = WireWriter::new();
        let ebox_bytes = self.ebox.to_bytes()?;
        w.put_raw(&ebox_bytes);
        w.put_u64(self.chunk_size);
        w.put_cstring8(&self.cipher)?;
        w.put_cstring8(&self.mac)?;
        Ok(w.into_bytes())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = WireReader::new(data);
        let ebox = Ebox::read_from(&mut r)?;
        let chunk_size = r.get_u64()?;
        let cipher = r.get_cstring8()?;
        let mac = r.get_cstring8()?;

        Ok(EboxStream {
            ebox,
            cipher,
            mac,
            chunk_size,
        })
    }

    pub fn encrypt_chunk(&self, seqnr: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .ebox
            .key()
            .ok_or(BoxError::NotUnlocked)?;

        let padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE);

        let iv = seqnr_to_iv(seqnr);
        let ciphertext = aes256_ctr_encrypt(key, &iv, &padded)?;

        let hmac = hmac_sha256(key, &ciphertext)?;

        // Framed chunk: u32(seqnr) + string(ciphertext + hmac)
        let mut w = WireWriter::new();
        w.put_u32(seqnr);
        let mut enc_data = ciphertext;
        enc_data.extend_from_slice(&hmac);
        w.put_string(&enc_data);

        Ok(w.into_bytes())
    }

    pub fn decrypt_chunk(
        &self,
        expected_seqnr: Option<u32>,
        chunk_data: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        let key = self
            .ebox
            .key()
            .ok_or(BoxError::NotUnlocked)?;

        let mut r = WireReader::new(chunk_data);
        let seqnr = r.get_u32()?;
        let enc_with_mac = r.get_string()?;

        if let Some(expected) = expected_seqnr {
            if seqnr != expected {
                return Err(BoxError::SequenceMismatch {
                    expected,
                    got: seqnr,
                });
            }
        }

        if enc_with_mac.len() < HMAC_LEN + AES_BLOCK_SIZE {
            return Err(BoxError::Wire(
                "encrypted chunk too short".into(),
            ));
        }

        let mac_offset = enc_with_mac.len() - HMAC_LEN;
        let ciphertext = &enc_with_mac[..mac_offset];
        let received_mac = &enc_with_mac[mac_offset..];

        // Verify HMAC
        let computed_mac = hmac_sha256(key, ciphertext)?;
        if !openssl::memcmp::eq(&computed_mac, received_mac) {
            return Err(BoxError::HmacMismatch { seqnr });
        }

        let iv = seqnr_to_iv(seqnr);
        let padded = aes256_ctr_decrypt(key, &iv, ciphertext)?;
        let plain = pkcs7_unpad(&padded)?;

        Ok((seqnr, plain))
    }
}

fn seqnr_to_iv(seqnr: u32) -> Vec<u8> {
    let mut iv = vec![0u8; AES_IV_LEN];
    iv[..4].copy_from_slice(&seqnr.to_be_bytes());
    Ok::<Vec<u8>, BoxError>(iv).unwrap()
}

fn aes256_ctr_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = SymCipher::aes_256_ctr();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    crypter.pad(false);
    let mut out = vec![0u8; plaintext.len() + AES_BLOCK_SIZE];
    let count = crypter.update(plaintext, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

fn aes256_ctr_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    // CTR mode: encrypt and decrypt are identical
    aes256_ctr_encrypt(key, iv, ciphertext)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(BoxError::BadPadding);
    }
    let pad_byte = data[data.len() - 1];
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > data.len() || pad_len > AES_BLOCK_SIZE {
        return Err(BoxError::BadPadding);
    }
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(BoxError::BadPadding);
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piv_box::EcCurve;
    use crate::template::{EboxConfigType, EboxTplConfig, EboxTplPart};
    use openssl::ec::{EcGroup, EcKey};
    use piggy_piv::Guid;

    fn make_tpl_and_privkey() -> (EboxTemplate, openssl::ec::EcKey<openssl::pkey::Private>) {
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
                    slot: crate::template::DEFAULT_SLOT,
                    name: Some("test".to_string()),
                    pubkey,
                    pubkey_curve: curve,
                    cak: None,
                }],
            }],
        };
        (tpl, priv_key)
    }

    #[test]
    fn stream_header_serialize_roundtrip() {
        let (tpl, _) = make_tpl_and_privkey();
        let stream = EboxStream::new(&tpl).unwrap();
        let bytes = stream.to_bytes().unwrap();
        let stream2 = EboxStream::from_bytes(&bytes).unwrap();

        assert_eq!(stream2.cipher, "aes256-ctr");
        assert_eq!(stream2.mac, "sha256");
        assert_eq!(stream2.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(stream2.ebox.ebox_type, EboxType::Stream);
    }

    #[test]
    fn stream_encrypt_decrypt_chunk_roundtrip() {
        let (tpl, priv_key) = make_tpl_and_privkey();
        let stream = EboxStream::new(&tpl).unwrap();

        let plaintext = b"hello world, this is a stream chunk!";
        let chunk_bytes = stream.encrypt_chunk(0, plaintext).unwrap();
        let (seqnr, recovered) = stream.decrypt_chunk(Some(0), &chunk_bytes).unwrap();

        assert_eq!(seqnr, 0);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn stream_multiple_chunks() {
        let (tpl, _) = make_tpl_and_privkey();
        let stream = EboxStream::new(&tpl).unwrap();

        for i in 0..5u32 {
            let data = format!("chunk number {i}");
            let enc = stream.encrypt_chunk(i, data.as_bytes()).unwrap();
            let (seq, dec) = stream.decrypt_chunk(Some(i), &enc).unwrap();
            assert_eq!(seq, i);
            assert_eq!(dec, data.as_bytes());
        }
    }

    #[test]
    fn stream_hmac_tamper_detected() {
        let (tpl, _) = make_tpl_and_privkey();
        let stream = EboxStream::new(&tpl).unwrap();

        let mut chunk_bytes = stream.encrypt_chunk(0, b"secret").unwrap();
        // Tamper with a byte in the encrypted payload
        if chunk_bytes.len() > 10 {
            chunk_bytes[10] ^= 0xFF;
        }
        assert!(stream.decrypt_chunk(Some(0), &chunk_bytes).is_err());
    }

    #[test]
    fn stream_seqnr_mismatch() {
        let (tpl, _) = make_tpl_and_privkey();
        let stream = EboxStream::new(&tpl).unwrap();

        let chunk_bytes = stream.encrypt_chunk(5, b"data").unwrap();
        assert!(matches!(
            stream.decrypt_chunk(Some(0), &chunk_bytes),
            Err(BoxError::SequenceMismatch {
                expected: 0,
                got: 5
            })
        ));
    }

    #[test]
    fn stream_empty_chunk() {
        let (tpl, _) = make_tpl_and_privkey();
        let stream = EboxStream::new(&tpl).unwrap();

        let enc = stream.encrypt_chunk(0, b"").unwrap();
        let (_, dec) = stream.decrypt_chunk(Some(0), &enc).unwrap();
        assert_eq!(dec, b"");
    }

    #[test]
    fn pkcs7_roundtrip_various_lengths() {
        for len in 0..65 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pkcs7_pad(&data, AES_BLOCK_SIZE);
            assert_eq!(padded.len() % AES_BLOCK_SIZE, 0);
            assert!(padded.len() > data.len());
            let unpadded = pkcs7_unpad(&padded).unwrap();
            assert_eq!(unpadded, data);
        }
    }
}
