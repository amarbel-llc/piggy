//! Management-key escrow (piggy#258): instead of displaying the freshly-minted
//! PIV management key once, `card init` can seal it into the password store,
//! encrypted to the recipients the store already declares for that path.
//!
//! The lib owns the policy (when to seal, when to offer) and the recipient
//! guard. The store/encrypt/git mechanics live in the `piggy` binary and are
//! injected through [`ManagementKeySealer`], so the lib stays free of the
//! pass-store substrate.
//!
//! This is the off-card escrow path; the on-card PIN-protected management key
//! (piggy#198) is a separate, composable mechanism.

use piggy_markl::Id;

/// Whether `card init` escrows a freshly-generated management key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealMode {
    /// Never seal and never offer: the key is displayed once.
    Never,
    /// Offer the seal through the frontend when the store can take it.
    Offer,
    /// Seal without asking, at the given store path (`None` means
    /// [`default_pass_name`]).
    Always(Option<String>),
}

impl SealMode {
    /// Map the CLI's `--seal-management-key[=PASS-NAME]` (an empty value is the
    /// bare flag) and `--no-seal-management-key`.
    pub fn from_cli(seal: Option<String>, no_seal: bool) -> Self {
        match (seal, no_seal) {
            (Some(p), _) if p.is_empty() => Self::Always(None),
            (Some(p), _) => Self::Always(Some(p)),
            (None, true) => Self::Never,
            (None, false) => Self::Offer,
        }
    }
}

/// What `card init` does with a generated management key, and the store that
/// would receive it.
pub struct SealRequest<'a> {
    pub mode: SealMode,
    pub sealer: &'a dyn ManagementKeySealer,
}

/// The conventional store path for a card's escrowed management key.
pub fn default_pass_name(guid_hex: &str) -> String {
    format!("piv/{guid_hex}/management-key")
}

/// A resolved escrow target, prepared before the card is touched.
pub trait KeyEscrow {
    /// The store path the key is sealed to.
    fn pass_name(&self) -> &str;
    /// The encryption recipients that can read the sealed key.
    fn recipients(&self) -> &[Id];
    /// Write the sealed key. Runs before the key is set on the card.
    fn seal(&mut self, key_hex: &str) -> Result<(), String>;
    /// Remove the sealed key after the card rejected it.
    fn rollback(&mut self);
    /// Record the sealed key durably (e.g. a store commit) once the card holds it.
    fn commit(&mut self);
}

/// Resolves escrow targets against a password store (implemented by the binary).
pub trait ManagementKeySealer {
    /// Resolve the recipients the store declares for `pass_name`.
    fn prepare(&self, pass_name: &str) -> Result<Box<dyn KeyEscrow>, String>;
}

/// A sealer with no store behind it; every seal request fails.
#[cfg(test)]
pub struct NoStore;

#[cfg(test)]
impl ManagementKeySealer for NoStore {
    fn prepare(&self, _: &str) -> Result<Box<dyn KeyEscrow>, String> {
        Err("no password store is available to seal into".into())
    }
}

/// Whether two ids name the same key. The purpose is ignored: a piggy-ids file
/// may spell a recipient bare (`pivy_ecdh_p256_pub-…`) or purpose-tagged.
fn same_key(a: &Id, b: &Id) -> bool {
    a.format() == b.format() && a.data() == b.data()
}

/// Check an escrow's encryption recipients. Refuses an empty set, and a set
/// whose only key is the one reprovisioning is about to destroy — either would
/// leave the sealed key unreadable. Returns a warning when the doomed key is
/// one recipient among others.
pub fn check_escrow_recipients(
    recipients: &[Id],
    destroyed_9d: Option<&Id>,
) -> Result<Option<String>, String> {
    if recipients.is_empty() {
        return Err("the piggy-ids for this path declares no encryption recipients".into());
    }
    let Some(doomed) = destroyed_9d else {
        return Ok(None);
    };
    if !recipients.iter().any(|r| same_key(r, doomed)) {
        return Ok(None);
    }
    if recipients.iter().all(|r| same_key(r, doomed)) {
        return Err(
            "the only recipient is this card's current 9D key, which reprovisioning destroys; \
             add a backup card to the piggy-ids first"
                .into(),
        );
    }
    Ok(Some(
        "this card's current 9D key is a recipient, but reprovisioning destroys it; \
         the sealed key stays readable by the other recipients only"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::nid::Nid;
    use piggy_markl::{FormatId, PurposeId};

    fn compressed_point() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        key.public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap()
    }

    fn id(purpose: Option<PurposeId>, point: Vec<u8>) -> Id {
        Id::new(purpose, FormatId::PivyEcdhP256Pub, point).unwrap()
    }

    fn recipient() -> Id {
        id(Some(PurposeId::PiggyRecipientV1), compressed_point())
    }

    #[test]
    fn from_cli_maps_flags_to_modes() {
        assert_eq!(SealMode::from_cli(None, false), SealMode::Offer);
        assert_eq!(SealMode::from_cli(None, true), SealMode::Never);
        assert_eq!(
            SealMode::from_cli(Some(String::new()), false),
            SealMode::Always(None)
        );
        assert_eq!(
            SealMode::from_cli(Some("escrow/yk".into()), false),
            SealMode::Always(Some("escrow/yk".into()))
        );
    }

    #[test]
    fn default_pass_name_nests_under_piv_guid() {
        assert_eq!(
            default_pass_name("0123456789ABCDEF0123456789ABCDEF"),
            "piv/0123456789ABCDEF0123456789ABCDEF/management-key"
        );
    }

    #[test]
    fn empty_recipient_set_is_refused() {
        let err = check_escrow_recipients(&[], None).unwrap_err();
        assert!(err.contains("no encryption recipients"), "{err}");
    }

    #[test]
    fn unrelated_recipients_pass_without_warning() {
        let backup = recipient();
        let doomed = recipient();
        assert_eq!(check_escrow_recipients(&[backup], Some(&doomed)), Ok(None));
    }

    #[test]
    fn doomed_key_as_sole_recipient_is_refused() {
        let doomed = recipient();
        let err =
            check_escrow_recipients(std::slice::from_ref(&doomed), Some(&doomed)).unwrap_err();
        assert!(err.contains("reprovisioning destroys"), "{err}");
    }

    #[test]
    fn doomed_key_spelled_bare_in_piggy_ids_is_still_refused() {
        let point = compressed_point();
        let doomed = id(Some(PurposeId::PiggyRecipientV1), point.clone());
        let bare = id(None, point);
        let err = check_escrow_recipients(&[bare], Some(&doomed)).unwrap_err();
        assert!(err.contains("reprovisioning destroys"), "{err}");
    }

    #[test]
    fn doomed_key_among_others_warns() {
        let doomed = recipient();
        let warning = check_escrow_recipients(&[doomed.clone(), recipient()], Some(&doomed))
            .unwrap()
            .expect("a warning");
        assert!(warning.contains("other recipients"), "{warning}");
    }
}
