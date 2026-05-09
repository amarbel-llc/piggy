use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use piggy_piv::Guid;

use crate::error::{BoxError, Result};
use crate::piv_box::EcCurve;
use crate::wire::{WireReader, WireWriter};

const EBOX_MAGIC: u16 = 0xEB0C;

/// Line width pivy-box wraps base64 at (`BASE64_LINE_LEN` in
/// `vendor/pivy/src/ebox-cmd.h`). Matches the on-disk byte-for-byte so
/// templates written by Rust are indistinguishable from pivy's.
const BASE64_LINE_LEN: usize = 65;
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
    /// Optional PIV card hardware GUID. Piggy 2.x produces guid-less
    /// templates (#69 / #70); the runtime in `vendor/pivy/src/piv.c`
    /// `piv_box_find_token` matches by pubkey alone via its
    /// `allslots:` fallback when `pdb_guidslot_valid` is false. Set
    /// to `Some(_)` for back-compat with guid-bearing templates.
    pub guid: Option<Guid>,
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

    /// Serialize as a pivy-box-compatible template file: binary wire format
    /// wrapped as base64 at 65 chars per line, each line terminated with
    /// `\n` (including the last). Exactly matches what
    /// `vendor/pivy/src/pivy-box.c` writes via
    /// `printwrap(sshbuf_dtob64_string(buf, 0), BASE64_LINE_LEN)`.
    pub fn to_b64_wrapped(&self) -> Result<String> {
        let bin = self.to_bytes()?;
        let raw = BASE64_STANDARD.encode(&bin);
        let mut out = String::with_capacity(raw.len() + raw.len() / BASE64_LINE_LEN + 1);
        let bytes = raw.as_bytes();
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + BASE64_LINE_LEN).min(bytes.len());
            out.push_str(std::str::from_utf8(&bytes[offset..end]).unwrap());
            out.push('\n');
            offset = end;
        }
        Ok(out)
    }

    /// Parse a pivy-box-compatible template file: strips any whitespace
    /// (newlines, spaces, tabs, CR) from `data` and base64-decodes the
    /// remainder before delegating to [`Self::from_bytes`]. Tolerant of
    /// either LF or CRLF line endings and of files with or without a
    /// trailing newline.
    pub fn from_b64_bytes(data: &[u8]) -> Result<Self> {
        let stripped: Vec<u8> = data
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        let bin = BASE64_STANDARD
            .decode(&stripped)
            .map_err(|e| BoxError::Wire(format!("base64 decode failed: {e}")))?;
        Self::from_bytes(&bin)
    }
}

fn write_tpl_part(w: &mut WireWriter, part: &EboxTplPart) -> Result<()> {
    // PUBKEY tag: curve name + compressed ecpoint
    w.put_u8(PART_PUBKEY);
    w.put_cstring8(part.pubkey_curve.wire_name())?;
    w.put_eckey8(&part.pubkey)?;

    // GUID tag — optional in piggy 2.x; emitted only when present
    if let Some(guid) = &part.guid {
        w.put_u8(PART_GUID);
        w.put_string8(guid.as_bytes())?;
    }

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

    // GUID is optional in piggy 2.x — the patched pivy parser
    // accepts templates without it, and the runtime falls back to
    // pubkey-only matching. PUBKEY and curve remain compulsory.
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
            guid: Some(Guid::from_hex("AABBCCDD11223344AABBCCDD11223344").unwrap()),
            slot: DEFAULT_SLOT,
            name: Some("piggy-test:template-fixture".to_string()),
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
        assert_eq!(
            tpl2.configs[0].parts[0].name.as_deref(),
            Some("piggy-test:template-fixture")
        );
        assert_eq!(
            tpl2.configs[0].parts[0]
                .guid
                .as_ref()
                .expect("test fixture sets guid; round-trip must preserve it")
                .to_hex(),
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

    #[test]
    fn b64_wrap_width_matches_pivy() {
        // Craft a template large enough to need multiple wrapped lines.
        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![sample_part(EcCurve::NistP384)],
            }],
        };
        let text = tpl.to_b64_wrapped().unwrap();
        assert!(text.ends_with('\n'), "must end with newline");
        // Every line except the last may be exactly BASE64_LINE_LEN long; the
        // last may be shorter. No line may exceed BASE64_LINE_LEN.
        for (i, line) in text.trim_end_matches('\n').split('\n').enumerate() {
            assert!(
                line.len() <= BASE64_LINE_LEN,
                "line {i} is {} chars, max {BASE64_LINE_LEN}",
                line.len()
            );
        }
    }

    #[test]
    fn b64_roundtrip_through_wire() {
        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![sample_part(EcCurve::NistP256)],
            }],
        };
        let text = tpl.to_b64_wrapped().unwrap();
        let parsed = EboxTemplate::from_b64_bytes(text.as_bytes()).unwrap();
        assert_eq!(parsed.to_bytes().unwrap(), tpl.to_bytes().unwrap());
    }

    #[test]
    fn b64_from_bytes_tolerates_crlf_and_no_trailing_newline() {
        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![sample_part(EcCurve::NistP256)],
            }],
        };
        let text = tpl.to_b64_wrapped().unwrap();
        let crlf: String = text.replace('\n', "\r\n");
        let no_trail = crlf.trim_end_matches(['\r', '\n']);
        assert!(EboxTemplate::from_b64_bytes(no_trail.as_bytes()).is_ok());
    }

    #[test]
    fn b64_rejects_binary_input() {
        // Passing raw binary (old on-disk format) must fail cleanly, not
        // silently misinterpret it as base64.
        let tpl = EboxTemplate {
            version: EBOX_TPL_VERSION,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![sample_part(EcCurve::NistP256)],
            }],
        };
        let bin = tpl.to_bytes().unwrap();
        assert!(matches!(
            EboxTemplate::from_b64_bytes(&bin),
            Err(BoxError::Wire(_))
        ));
    }

    /// Property-based wire-format fuzzing for `EboxTemplate`. See #40.
    /// The pubkey field is generated as random bytes of the correct
    /// compressed-point length (33 for P-256, 49 for P-384) — the wire
    /// idempotence property does not depend on the bytes being valid
    /// EC points; that's tested separately by `unlock_ebox_*`.
    mod proptest_wire {
        use super::*;
        use proptest::prelude::*;

        fn arb_curve_and_pubkey() -> impl Strategy<Value = (EcCurve, Vec<u8>)> {
            prop_oneof![
                proptest::collection::vec(any::<u8>(), 33..=33)
                    .prop_map(|v| (EcCurve::NistP256, v)),
                proptest::collection::vec(any::<u8>(), 49..=49)
                    .prop_map(|v| (EcCurve::NistP384, v)),
            ]
        }

        fn arb_part() -> impl Strategy<Value = EboxTplPart> {
            (
                any::<[u8; 16]>(),
                prop_oneof![Just(DEFAULT_SLOT), 0x82u8..=0x95u8],
                prop::option::of("[a-zA-Z0-9_:-]{1,30}"),
                arb_curve_and_pubkey(),
                prop::option::of(proptest::collection::vec(any::<u8>(), 0..=64)),
            )
                .prop_map(|(guid_bytes, slot, name, (pubkey_curve, pubkey), cak)| {
                    EboxTplPart {
                        guid: Some(Guid::from_bytes(&guid_bytes).unwrap()),
                        slot,
                        name,
                        pubkey,
                        pubkey_curve,
                        cak,
                    }
                })
        }

        fn arb_config() -> impl Strategy<Value = EboxTplConfig> {
            (
                prop_oneof![
                    Just(EboxConfigType::Primary),
                    Just(EboxConfigType::Recovery),
                ],
                proptest::collection::vec(arb_part(), 1..=3),
            )
                .prop_map(|(config_type, parts)| {
                    let m = parts.len() as u8;
                    let n = match config_type {
                        // Per `read_tpl_config`: PRIMARY MUST have n=1.
                        EboxConfigType::Primary => 1,
                        // RECOVERY: 1 <= n <= m.
                        EboxConfigType::Recovery => 1.max(m / 2).min(m),
                    };
                    EboxTplConfig {
                        config_type,
                        n,
                        parts,
                    }
                })
        }

        fn arb_template() -> impl Strategy<Value = EboxTemplate> {
            proptest::collection::vec(arb_config(), 1..=2).prop_map(|configs| EboxTemplate {
                version: EBOX_TPL_VERSION,
                configs,
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

            #[test]
            fn ebox_template_serialize_parse_idempotent(tpl in arb_template()) {
                let bytes1 = tpl.to_bytes().unwrap();
                let parsed = EboxTemplate::from_bytes(&bytes1).unwrap();
                let bytes2 = parsed.to_bytes().unwrap();
                prop_assert_eq!(
                    bytes1,
                    bytes2,
                    "ebox_template wire serialize→parse→serialize is not idempotent"
                );
            }
        }
    }
}
