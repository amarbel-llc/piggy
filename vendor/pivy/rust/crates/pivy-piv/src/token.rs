use pcsc::{Protocols, ShareMode};

use crate::apdu::{ga_tag, Apdu, StatusWord, PIV_AID};
use crate::cert;
use crate::error::PivError;
use crate::guid::Guid;
use crate::slot::{self, PivSlot};
use crate::tlv::{TlvReader, TlvWriter};
use crate::PivContext;

/// CHUID data object tag (NIST SP 800-73-4)
const PIV_TAG_CHUID: u32 = 0x5FC102;

/// Tag for GUID within CHUID
const CHUID_TAG_GUID: u32 = 0x34;

pub struct PivToken {
    card: pcsc::Card,
    guid: Guid,
    reader_name: String,
}

impl PivToken {
    pub fn connect(ctx: &PivContext, reader: &str) -> Result<Self, PivError> {
        let cstr =
            std::ffi::CString::new(reader).map_err(|e| PivError::Other(e.to_string()))?;
        let card = ctx
            .pcsc_context()
            .connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let mut token = Self {
            card,
            guid: Guid::from_bytes(&[0; 16])?,
            reader_name: reader.to_string(),
        };
        token.select_piv()?;
        token.read_chuid()?;
        Ok(token)
    }

    fn transmit(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        let cmd = apdu.to_bytes();
        let mut resp_buf = vec![0u8; 4096];
        let resp = self.card.transmit(&cmd, &mut resp_buf)?;
        let len = resp.len();
        if len < 2 {
            return Err(PivError::Other("response too short for status word".into()));
        }
        let sw = StatusWord::from_bytes(resp[len - 2], resp[len - 1]);
        let data = resp[..len - 2].to_vec();

        // Handle GET RESPONSE chaining (SW 61xx)
        if sw.has_more_data() {
            let mut full = data;
            let mut chain_sw = sw;
            while chain_sw.has_more_data() {
                let mut get_resp = Apdu::new(0x00, 0xC0, 0x00, 0x00);
                get_resp.le = Some(chain_sw.remaining_bytes() as u16);
                let cmd2 = get_resp.to_bytes();
                let mut resp_buf2 = vec![0u8; 4096];
                let resp2 = self.card.transmit(&cmd2, &mut resp_buf2)?;
                let len2 = resp2.len();
                if len2 < 2 {
                    return Err(PivError::Other("chained response too short".into()));
                }
                chain_sw = StatusWord::from_bytes(resp2[len2 - 2], resp2[len2 - 1]);
                full.extend_from_slice(&resp2[..len2 - 2]);
            }
            return Ok((full, chain_sw));
        }

        Ok((data, sw))
    }

    fn select_piv(&mut self) -> Result<(), PivError> {
        let apdu = Apdu::select(PIV_AID);
        let (_, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }

    fn read_chuid(&mut self) -> Result<(), PivError> {
        let apdu = Apdu::get_data(PIV_TAG_CHUID);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }

        // Response is wrapped in tag 0x53
        let mut reader = TlvReader::new(&data);
        let outer_tag = reader.read_tag()?;
        if outer_tag != 0x53 {
            return Err(PivError::Tlv {
                message: format!("expected CHUID outer tag 0x53, got {:#X}", outer_tag),
            });
        }
        let chuid_data = reader.read_value()?;

        // Parse CHUID TLV to find GUID (tag 0x34)
        let mut chuid_reader = TlvReader::new(chuid_data);
        while chuid_reader.has_remaining() {
            let tag = chuid_reader.read_tag()?;
            let value = chuid_reader.read_value()?;
            if tag == CHUID_TAG_GUID {
                self.guid = Guid::from_bytes(value)?;
                return Ok(());
            }
        }

        Err(PivError::Tlv {
            message: "GUID tag (0x34) not found in CHUID".into(),
        })
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    pub fn transmit_apdu(&self, apdu: &Apdu) -> Result<(Vec<u8>, StatusWord), PivError> {
        self.transmit(apdu)
    }

    /// Read a certificate from the given PIV slot and extract the SSH public key.
    pub fn read_slot(&self, slot_id: u8) -> Result<PivSlot, PivError> {
        let cert_tag = slot::slot_to_cert_tag(slot_id)
            .ok_or(PivError::SlotEmpty(slot_id))?;
        let apdu = Apdu::get_data(cert_tag);
        let (data, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::SlotEmpty(slot_id));
        }

        // Response wrapped in tag 0x53
        let mut reader = TlvReader::new(&data);
        let outer_tag = reader.read_tag()?;
        if outer_tag != 0x53 {
            return Err(PivError::Tlv {
                message: format!("expected cert outer tag 0x53, got {:#X}", outer_tag),
            });
        }
        let inner = reader.read_value()?;

        // Parse inner TLV: tag 0x70 = certificate, tag 0x71 = cert info
        let mut inner_reader = TlvReader::new(inner);
        let mut cert_der: Option<Vec<u8>> = None;
        while inner_reader.has_remaining() {
            let tag = inner_reader.read_tag()?;
            let value = inner_reader.read_value()?;
            if tag == 0x70 {
                cert_der = Some(value.to_vec());
            }
            // tag 0x71 = certinfo, tag 0xFE = error detection code -- skip
        }

        let cert_der = cert_der.ok_or(PivError::SlotEmpty(slot_id))?;
        let (algorithm, public_key) = cert::extract_public_key(&cert_der)?;
        Ok(PivSlot::new(slot_id, algorithm, cert_der, public_key))
    }

    /// Read certificates from all standard PIV slots plus retired slots.
    /// Silently skips empty slots.
    pub fn read_all_slots(&self) -> Result<Vec<PivSlot>, PivError> {
        let mut slots = Vec::new();

        // Standard slots
        for &slot_id in slot::STANDARD_SLOTS {
            match self.read_slot(slot_id) {
                Ok(s) => slots.push(s),
                Err(_) => continue,
            }
        }

        // Retired key management slots 82-95
        for slot_id in 0x82..=0x95_u8 {
            match self.read_slot(slot_id) {
                Ok(s) => slots.push(s),
                Err(_) => continue,
            }
        }

        Ok(slots)
    }

    /// Sign pre-hashed data with the key in the given slot.
    /// For ECDSA, `data` is the hash digest (32 bytes for P256, 48 for P384).
    /// For RSA, `data` is the PKCS#1 v1.5 padded DigestInfo (128 or 256 bytes).
    pub fn sign_prehash(&self, slot_id: u8, data: &[u8]) -> Result<Vec<u8>, PivError> {
        let slot = self.read_slot(slot_id)?;
        let alg_byte = slot.algorithm().to_byte();

        // Build GENERAL AUTHENTICATE TLV:
        //   Tag 0x7C containing:
        //     Tag 0x82 (response placeholder, empty)
        //     Tag 0x81 (challenge/data to sign)
        let mut inner = TlvWriter::new();
        inner.write_tag_value(ga_tag::RESPONSE as u32, &[]);
        inner.write_tag_value(ga_tag::CHALLENGE as u32, data);
        let mut outer = TlvWriter::new();
        outer.write_tag_value(0x7C, inner.as_bytes());

        let apdu = Apdu::general_authenticate(alg_byte, slot_id, outer.as_bytes());
        let (resp, sw) = self.transmit(&apdu)?;

        if sw.as_u16() == 0x6982 {
            return Err(PivError::PinRequired);
        }
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }

        // Parse response: 0x7C { 0x82 = signature }
        let mut reader = TlvReader::new(&resp);
        let outer_tag = reader.read_tag()?;
        if outer_tag != 0x7C {
            return Err(PivError::Tlv {
                message: format!("expected GA response tag 0x7C, got {:#X}", outer_tag),
            });
        }
        let inner_data = reader.read_value()?;

        let mut inner_reader = TlvReader::new(inner_data);
        let resp_tag = inner_reader.read_tag()?;
        if resp_tag != ga_tag::RESPONSE as u32 {
            return Err(PivError::Tlv {
                message: format!("expected GA response tag 0x82, got {:#X}", resp_tag),
            });
        }
        let signature = inner_reader.read_value()?;

        Ok(signature.to_vec())
    }

    /// Verify the PIV PIN. The PIN is padded to 8 bytes with 0xFF per the spec.
    pub fn verify_pin(&self, pin: &str) -> Result<(), PivError> {
        let apdu = Apdu::verify_pin(pin.as_bytes());
        let (_, sw) = self.transmit(&apdu)?;
        if sw.is_success() {
            Ok(())
        } else if sw.is_pin_incorrect() {
            Err(PivError::PinIncorrect {
                retries: sw.pin_retries_remaining().unwrap_or(0) as u32,
            })
        } else if sw.as_u16() == 0x6983 {
            Err(PivError::PinBlocked)
        } else {
            Err(PivError::Apdu { sw: sw.as_u16() })
        }
    }
}

impl PivContext {
    /// Enumerate all PIV tokens across all readers.
    /// Silently skips readers that don't have PIV cards.
    pub fn enumerate_tokens(&self) -> Result<Vec<PivToken>, PivError> {
        let readers = self.list_readers()?;
        let mut tokens = Vec::new();
        for reader in &readers {
            match PivToken::connect(self, reader) {
                Ok(token) => tokens.push(token),
                Err(_) => continue, // Not a PIV card or not inserted
            }
        }
        Ok(tokens)
    }
}
