//! Markl ID → ebox template plumbing.
//!
//! Bridges `piggy_markl::Id` (the piggy 2.x recipient identifier) and
//! piggy-box's [`EboxTplPart`] / [`EboxTemplate`] shapes. The
//! conversion produces guid-less template parts, which the patched
//! pivy parser (#70) accepts and the runtime resolves by pubkey
//! alone.
//!
//! This module is the load-bearing piece of phase 3's tracer-bullet
//! (#73): once `recipients_to_template` works end-to-end (Rust
//! encrypt → `pivy-box stream decrypt` succeeds), the Rust-native
//! encrypt path is proven viable.

use piggy_markl::{FormatId, Id as MarklId, PurposeId};

use crate::error::{BoxError, Result};
use crate::piv_box::EcCurve;
use crate::template::{EboxConfigType, EboxTemplate, EboxTplConfig, EboxTplPart, DEFAULT_SLOT};

/// Build a piggy 2.x recipient template part from a markl ID. The
/// produced part is guid-less; piggy-box's writer (after the
/// guid-optional change in this commit) skips emitting the GUID tag.
pub fn tpl_part_from_markl(id: &MarklId) -> Result<EboxTplPart> {
    if id.format() != FormatId::PivyEcdhP256Pub {
        return Err(BoxError::Wire(format!(
            "expected pivy_ecdh_p256_pub format, got {:?}",
            id.format()
        )));
    }
    if !matches!(id.purpose(), None | Some(PurposeId::PiggyRecipientV1)) {
        return Err(BoxError::Wire(format!(
            "expected piggy-recipient-v1 purpose (or none), got {:?}",
            id.purpose()
        )));
    }

    Ok(EboxTplPart {
        guid: None,
        slot: DEFAULT_SLOT,
        name: None,
        pubkey: id.data().to_vec(),
        pubkey_curve: EcCurve::NistP256,
        cak: None,
    })
}

/// Build an `EboxTemplate` whose single Primary config requires
/// recovering N=1 share — i.e. any one of the recipients can decrypt.
/// Mirrors what `pivy-box tpl create` produces for "encrypt to any
/// of these card holders" templates.
pub fn template_from_recipients(ids: &[MarklId]) -> Result<EboxTemplate> {
    if ids.is_empty() {
        return Err(BoxError::Wire(
            "at least one recipient is required".into(),
        ));
    }

    let parts: Result<Vec<EboxTplPart>> = ids.iter().map(tpl_part_from_markl).collect();
    let parts = parts?;

    Ok(EboxTemplate {
        version: 1,
        configs: vec![EboxTplConfig {
            config_type: EboxConfigType::Primary,
            n: 1,
            parts,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::nid::Nid;
    use piggy_markl::Id;

    /// Generate a real (curve-valid) P-256 pubkey and return its
    /// 33-byte SEC 1 compressed encoding.
    fn fresh_p256_pubkey_bytes() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let priv_key = EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        priv_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap()
    }

    #[test]
    fn part_from_markl_with_purpose_succeeds() {
        let pubkey = fresh_p256_pubkey_bytes();
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            pubkey.clone(),
        )
        .unwrap();
        let part = tpl_part_from_markl(&id).unwrap();
        assert!(part.guid.is_none());
        assert_eq!(part.slot, DEFAULT_SLOT);
        assert!(part.name.is_none());
        assert_eq!(part.pubkey, pubkey);
        assert_eq!(part.pubkey_curve, EcCurve::NistP256);
        assert!(part.cak.is_none());
    }

    #[test]
    fn part_from_markl_bare_format_succeeds() {
        let pubkey = fresh_p256_pubkey_bytes();
        let id = Id::new(None, FormatId::PivyEcdhP256Pub, pubkey).unwrap();
        let part = tpl_part_from_markl(&id).unwrap();
        assert!(part.guid.is_none());
    }

    #[test]
    fn template_from_recipients_builds_primary_config_n_1() {
        let pk_a = fresh_p256_pubkey_bytes();
        let pk_b = fresh_p256_pubkey_bytes();
        let id_a = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            pk_a,
        )
        .unwrap();
        let id_b = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            pk_b,
        )
        .unwrap();
        let tpl = template_from_recipients(&[id_a, id_b]).unwrap();
        assert_eq!(tpl.configs.len(), 1);
        assert_eq!(tpl.configs[0].config_type, EboxConfigType::Primary);
        assert_eq!(tpl.configs[0].n, 1);
        assert_eq!(tpl.configs[0].parts.len(), 2);
        for part in &tpl.configs[0].parts {
            assert!(part.guid.is_none());
        }
    }

    #[test]
    fn template_from_recipients_rejects_empty_input() {
        let err = template_from_recipients(&[]).unwrap_err();
        assert!(matches!(err, BoxError::Wire(_)));
    }

    #[test]
    fn template_round_trips_through_wire_format_with_no_guid_tag() {
        // Build template, serialize, deserialize, assert no guid
        // present — this exercises the guid-optional plumbing in
        // template.rs end-to-end.
        let pk = fresh_p256_pubkey_bytes();
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            pk.clone(),
        )
        .unwrap();
        let tpl = template_from_recipients(&[id]).unwrap();
        let bytes = tpl.to_bytes().unwrap();
        let parsed = EboxTemplate::from_bytes(&bytes).unwrap();
        assert!(parsed.configs[0].parts[0].guid.is_none());
        assert_eq!(parsed.configs[0].parts[0].pubkey, pk);
    }
}
