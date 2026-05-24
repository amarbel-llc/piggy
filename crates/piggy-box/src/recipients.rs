//! Markl ID → ebox template plumbing.
//!
//! Bridges `piggy_markl::Id` (the piggy 2.x recipient identifier) and
//! piggy-box's [`EboxTplPart`] / [`EboxTemplate`] shapes.
//!
//! The piggy 2.x recipient purpose (`piggy-recipient-v1`) accepts two
//! markl formats:
//!
//! * `pivy_ecdh_p256_pub` — PIV ECDH P-256 recipient. Maps directly
//!   onto today's [`EboxTplPart`]; the produced template is a v1
//!   ebox that decrypts via the existing PIV path.
//! * `age_x25519_pub` — age v1 X25519 recipient. Accepted at the
//!   markl/`piggy-ids` layer so files declaring age recipients
//!   parse cleanly, but the encrypt pipeline does **not** yet
//!   produce ebox files for age parts — that lands with the RFC
//!   0004 wire-format extension (`AgeBox` part variant, ebox v2).
//!   Attempting `template_from_recipients` on an age markl ID today
//!   returns [`BoxError::UnsupportedRecipientFormat`].

use piggy_markl::{FormatId, Id as MarklId, PurposeId};

use crate::error::{BoxError, Result};
use crate::piv_box::EcCurve;
use crate::template::{DEFAULT_SLOT, EboxConfigType, EboxTemplate, EboxTplConfig, EboxTplPart};

/// Build a piggy 2.x recipient template part from a markl ID. Routes
/// on the markl format:
///
/// * [`FormatId::PivyEcdhP256Pub`] → [`piv_part_from_markl`]
/// * [`FormatId::AgeX25519Pub`]    → [`age_part_from_markl`] (currently
///   returns [`BoxError::UnsupportedRecipientFormat`])
///
/// Any other format is rejected as a wire-level error. The produced
/// part (when a part is produced) is guid-less; piggy-box's writer
/// skips emitting the GUID tag.
pub fn tpl_part_from_markl(id: &MarklId) -> Result<EboxTplPart> {
    match id.format() {
        FormatId::PivyEcdhP256Pub => piv_part_from_markl(id),
        FormatId::AgeX25519Pub => age_part_from_markl(id),
        other => Err(BoxError::Wire(format!(
            "unsupported recipient format: {other:?} \
             (piggy-recipient-v1 accepts pivy_ecdh_p256_pub or age_x25519_pub)"
        ))),
    }
}

/// Build an [`EboxTplPart`] from a `pivy_ecdh_p256_pub` markl ID.
/// Validates the purpose constraint (must be
/// [`PurposeId::PiggyRecipientV1`] or bare) and produces a guid-less
/// part on the NIST P-256 curve.
pub fn piv_part_from_markl(id: &MarklId) -> Result<EboxTplPart> {
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

/// Build an [`EboxTplPart`] from an `age_x25519_pub` markl ID.
///
/// Currently returns [`BoxError::UnsupportedRecipientFormat`] — the
/// markl/`piggy-ids` layers accept age recipients, but the encrypt
/// pipeline has no `AgeBox` part variant yet. See docs/rfcs/0004.
pub fn age_part_from_markl(id: &MarklId) -> Result<EboxTplPart> {
    if id.format() != FormatId::AgeX25519Pub {
        return Err(BoxError::Wire(format!(
            "expected age_x25519_pub format, got {:?}",
            id.format()
        )));
    }
    if !matches!(id.purpose(), None | Some(PurposeId::PiggyRecipientV1)) {
        return Err(BoxError::Wire(format!(
            "expected piggy-recipient-v1 purpose (or none), got {:?}",
            id.purpose()
        )));
    }
    Err(BoxError::UnsupportedRecipientFormat(FormatId::AgeX25519Pub))
}

/// Build an `EboxTemplate` whose single Primary config requires
/// recovering N=1 share — i.e. any one of the recipients can decrypt.
/// Mirrors what `pivy-box tpl create` produces for "encrypt to any
/// of these card holders" templates.
pub fn template_from_recipients(ids: &[MarklId]) -> Result<EboxTemplate> {
    if ids.is_empty() {
        return Err(BoxError::Wire("at least one recipient is required".into()));
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

    fn placeholder_age_pubkey_bytes() -> Vec<u8> {
        (0u8..32).collect()
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

    #[test]
    fn age_recipient_markl_id_parses_but_encrypt_pipeline_refuses() {
        let pk = placeholder_age_pubkey_bytes();
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::AgeX25519Pub,
            pk,
        )
        .expect("piggy-recipient-v1 must accept age_x25519_pub");
        let err = tpl_part_from_markl(&id).unwrap_err();
        assert!(
            matches!(err, BoxError::UnsupportedRecipientFormat(_)),
            "expected UnsupportedRecipientFormat, got {err:?}",
        );
    }

    #[test]
    fn template_with_mixed_recipients_fails_on_age_part() {
        let piv_id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            fresh_p256_pubkey_bytes(),
        )
        .unwrap();
        let age_id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::AgeX25519Pub,
            placeholder_age_pubkey_bytes(),
        )
        .unwrap();
        let err = template_from_recipients(&[piv_id, age_id]).unwrap_err();
        assert!(matches!(err, BoxError::UnsupportedRecipientFormat(_)));
    }

    #[test]
    fn piv_part_from_markl_rejects_wrong_format() {
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::AgeX25519Pub,
            placeholder_age_pubkey_bytes(),
        )
        .unwrap();
        let err = piv_part_from_markl(&id).unwrap_err();
        assert!(matches!(err, BoxError::Wire(_)));
    }

    #[test]
    fn age_part_from_markl_rejects_wrong_format() {
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            fresh_p256_pubkey_bytes(),
        )
        .unwrap();
        let err = age_part_from_markl(&id).unwrap_err();
        assert!(matches!(err, BoxError::Wire(_)));
    }
}
