use piggy_piv::Guid;

use crate::error::{BoxError, Result};
use crate::piv_box::EcCurve;
use crate::wire::{WireReader, WireWriter};

const EBOX_MAGIC: u16 = 0xEB0C;
#[cfg(test)]
const EBOX_TPL_VERSION: u8 = 1;
const EBOX_TYPE_TEMPLATE: u8 = 0x01;
pub const DEFAULT_SLOT: u8 = 0x9D; // PIV_SLOT_KEY_MGMT

pub(crate) const PART_END: u8 = 0;
pub(crate) const PART_PUBKEY: u8 = 1;
pub(crate) const PART_NAME: u8 = 2;
pub(crate) const PART_CAK: u8 = 3;
pub(crate) const PART_GUID: u8 = 4;
pub(crate) const PART_BOX: u8 = 5;
pub(crate) const PART_SLOT: u8 = 6;
pub(crate) const PART_OPTIONAL_FLAG: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EboxConfigType {
    Primary = 1,
    Recovery = 2,
}

impl EboxConfigType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(EboxConfigType::Primary),
            2 => Ok(EboxConfigType::Recovery),
            _ => Err(BoxError::BadConfigType(v)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EboxTplPart {
    pub guid: Guid,
    pub slot: u8,
    pub name: Option<String>,
    pub pubkey: Vec<u8>,
    pub pubkey_curve: EcCurve,
    pub cak: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct EboxTplConfig {
    pub config_type: EboxConfigType,
    pub n: u8,
    pub parts: Vec<EboxTplPart>,
}

impl EboxTplConfig {
    pub fn m(&self) -> u8 {
        self.parts.len() as u8
    }
}

#[derive(Debug, Clone)]
pub struct EboxTemplate {
    pub version: u8,
    pub configs: Vec<EboxTplConfig>,
}

impl EboxTemplate {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = WireWriter::new();
        w.put_u8((EBOX_MAGIC >> 8) as u8);
        w.put_u8((EBOX_MAGIC & 0xFF) as u8);
        w.put_u8(self.version);
        w.put_u8(EBOX_TYPE_TEMPLATE);
        w.put_u8(self.configs.len() as u8);

        for config in &self.configs {
            write_tpl_config(&mut w, config)?;
        }

        Ok(w.into_bytes())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = WireReader::new(data);

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
        let etype = r.get_u8()?;
        if etype != EBOX_TYPE_TEMPLATE {
            return Err(BoxError::BadEboxType(etype));
        }

        let nconfigs = r.get_u8()?;
        let mut configs = Vec::with_capacity(nconfigs as usize);
        for _ in 0..nconfigs {
            configs.push(read_tpl_config(&mut r)?);
        }

        Ok(EboxTemplate { version, configs })
    }
}

fn write_tpl_part(w: &mut WireWriter, part: &EboxTplPart) -> Result<()> {
    // PUBKEY tag: curve name + compressed ecpoint
    w.put_u8(PART_PUBKEY);
    w.put_cstring8(part.pubkey_curve.wire_name())?;
    w.put_eckey8(&part.pubkey)?;

    // GUID tag
    w.put_u8(PART_GUID);
    w.put_string8(part.guid.as_bytes())?;

    // NAME tag (optional)
    if let Some(name) = &part.name {
        w.put_u8(PART_NAME);
        w.put_cstring8(name)?;
    }

    // CAK tag (optional) — stored as SSH `string` (u32 prefix) inside the tag
    if let Some(cak) = &part.cak {
        w.put_u8(PART_CAK);
        w.put_string(cak);
    }

    // SLOT tag — only written if not the default (0x9D)
    if part.slot != DEFAULT_SLOT {
        w.put_u8(PART_SLOT);
        w.put_u8(part.slot);
    }

    // END
    w.put_u8(PART_END);
    Ok(())
}

pub(crate) fn read_tpl_part(r: &mut WireReader) -> Result<EboxTplPart> {
    let mut guid: Option<Guid> = None;
    let mut slot: u8 = DEFAULT_SLOT;
    let mut name: Option<String> = None;
    let mut pubkey: Option<Vec<u8>> = None;
    let mut pubkey_curve: Option<EcCurve> = None;
    let mut cak: Option<Vec<u8>> = None;

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
            _ => {
                if tag & PART_OPTIONAL_FLAG != 0 {
                    let _ = r.get_string8()?;
                } else {
                    return Err(BoxError::Wire(format!("unknown part tag {tag:#04x}")));
                }
            }
        }
        tag = r.get_u8()?;
    }

    let guid = guid.ok_or_else(|| BoxError::Wire("template part missing GUID".into()))?;
    let pubkey = pubkey.ok_or_else(|| BoxError::Wire("template part missing PUBKEY".into()))?;
    let pubkey_curve =
        pubkey_curve.ok_or_else(|| BoxError::Wire("template part missing curve".into()))?;

    Ok(EboxTplPart {
        guid,
        slot,
        name,
        pubkey,
        pubkey_curve,
        cak,
    })
}

fn write_tpl_config(w: &mut WireWriter, config: &EboxTplConfig) -> Result<()> {
    w.put_u8(config.config_type as u8);
    w.put_u8(config.n);
    w.put_u8(config.m());

    for part in &config.parts {
        write_tpl_part(w, part)?;
    }

    Ok(())
}

fn read_tpl_config(r: &mut WireReader) -> Result<EboxTplConfig> {
    let config_type = EboxConfigType::from_u8(r.get_u8()?)?;
    let n = r.get_u8()?;
    let m = r.get_u8()?;

    if config_type == EboxConfigType::Primary && n > 1 {
        return Err(BoxError::Wire(format!(
            "PRIMARY config must have n=1, got n={n}"
        )));
    }

    let mut parts = Vec::with_capacity(m as usize);
    for _ in 0..m {
        parts.push(read_tpl_part(r)?);
    }

    Ok(EboxTplConfig {
        config_type,
        n,
        parts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_part(curve: EcCurve) -> EboxTplPart {
        let group = openssl::ec::EcGroup::from_curve_name(curve.nid()).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let pubkey = key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::COMPRESSED,
                &mut ctx,
            )
            .unwrap();

        EboxTplPart {
            guid: Guid::from_hex("AABBCCDD11223344AABBCCDD11223344").unwrap(),
            slot: DEFAULT_SLOT,
            name: Some("test-key".to_string()),
            pubkey,
            pubkey_curve: curve,
            cak: None,
        }
    }

    #[test]
    fn template_serialize_deserialize_roundtrip() {
        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![sample_part(EcCurve::NistP256)],
            }],
        };

        let bytes = tpl.to_bytes().unwrap();
        let tpl2 = EboxTemplate::from_bytes(&bytes).unwrap();

        assert_eq!(tpl2.version, tpl.version);
        assert_eq!(tpl2.configs.len(), 1);
        assert_eq!(tpl2.configs[0].config_type, EboxConfigType::Primary);
        assert_eq!(tpl2.configs[0].n, 1);
        assert_eq!(tpl2.configs[0].parts.len(), 1);
        assert_eq!(tpl2.configs[0].parts[0].name.as_deref(), Some("test-key"));
        assert_eq!(
            tpl2.configs[0].parts[0].guid.to_hex(),
            "AABBCCDD11223344AABBCCDD11223344"
        );
        assert_eq!(tpl2.configs[0].parts[0].slot, DEFAULT_SLOT);

        let bytes2 = tpl2.to_bytes().unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn template_with_recovery_config() {
        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![
                EboxTplConfig {
                    config_type: EboxConfigType::Primary,
                    n: 1,
                    parts: vec![sample_part(EcCurve::NistP256)],
                },
                EboxTplConfig {
                    config_type: EboxConfigType::Recovery,
                    n: 2,
                    parts: vec![
                        sample_part(EcCurve::NistP256),
                        sample_part(EcCurve::NistP256),
                        sample_part(EcCurve::NistP256),
                    ],
                },
            ],
        };

        let bytes = tpl.to_bytes().unwrap();
        let tpl2 = EboxTemplate::from_bytes(&bytes).unwrap();
        assert_eq!(tpl2.configs.len(), 2);
        assert_eq!(tpl2.configs[1].config_type, EboxConfigType::Recovery);
        assert_eq!(tpl2.configs[1].n, 2);
        assert_eq!(tpl2.configs[1].m(), 3);
    }

    #[test]
    fn template_with_non_default_slot() {
        let mut part = sample_part(EcCurve::NistP256);
        part.slot = 0x82;

        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![part],
            }],
        };

        let bytes = tpl.to_bytes().unwrap();
        let tpl2 = EboxTemplate::from_bytes(&bytes).unwrap();
        assert_eq!(tpl2.configs[0].parts[0].slot, 0x82);
    }

    #[test]
    fn bad_magic_rejected() {
        let data = vec![0xFF, 0xFF, 0x01, 0x01, 0x00];
        assert!(matches!(
            EboxTemplate::from_bytes(&data),
            Err(BoxError::BadMagic { .. })
        ));
    }

    #[test]
    fn wrong_type_rejected() {
        let mut w = WireWriter::new();
        w.put_u8(0xEB);
        w.put_u8(0x0C);
        w.put_u8(1);
        w.put_u8(0x02); // KEY, not TEMPLATE
        w.put_u8(0);
        assert!(matches!(
            EboxTemplate::from_bytes(w.as_bytes()),
            Err(BoxError::BadEboxType(0x02))
        ));
    }
}
