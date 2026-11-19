//! The profile file `piggy ca root-cert|sign|issue --profile NAME` reads
//! (FDR 0007, "The issuance verbs"): `<config>/ca-profiles/NAME.toml`.
//!
//! A profile has two authors. The consumer writes the policy fields (kind,
//! names, key types, lifetime); the operator fills `[issuer]` at install
//! time. The profile is the only source of the issuer: the verbs take no
//! slot flag. Unknown keys are refused, so a typo in a policy field is an
//! error and never a silently weaker profile.
//!
//! Pure: text in, a [`Profile`] or a [`ProfileError`] out. Reading the
//! file, the clock, the card and the audit line are the verbs' business.

use std::path::{Path, PathBuf};

use piggy_piv::PivAlgorithm;
use serde::Deserialize;

/// What a profile issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Root,
    Intermediate,
    Leaf,
}

/// A key type a request may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum KeyType {
    #[serde(rename = "p256")]
    P256,
    #[serde(rename = "p384")]
    P384,
}

impl KeyType {
    pub fn algorithm(self) -> PivAlgorithm {
        match self {
            Self::P256 => PivAlgorithm::EcP256,
            Self::P384 => PivAlgorithm::EcP384,
        }
    }
}

/// The key that signs: a card slot, or a holder key by public key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// A card's CA slot, as two hex digits (`82`).
    #[serde(default)]
    pub slot: Option<String>,
    /// The card's GUID, 32 hex digits.
    #[serde(default)]
    pub guid: Option<String>,
    /// A holder key, by its public key (not offered until phase (iii)).
    #[serde(default)]
    pub holder_key: Option<String>,
    /// The PEM certificate the card's attestation chain must reach for the
    /// slot's key to count as the card's own, as an absolute path; absent,
    /// the embedded Yubico PIV root. A virtual card's lane points it at
    /// that card's own F9 certificate; a production profile leaves it out.
    #[serde(default)]
    pub attestation_root: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    kind: Kind,
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    key_types: Option<Vec<KeyType>>,
    /// Certificate lifetime, in hours.
    lifetime_hours: u64,
    /// How far before signing time `notBefore` is set, in minutes, for
    /// verifiers whose clocks run behind (default 5).
    #[serde(default)]
    not_before_skew_minutes: Option<u64>,
    issuer: Issuer,
}

/// The `notBefore` skew a profile gets when it names none.
pub const DEFAULT_NOT_BEFORE_SKEW_MINUTES: u64 = 5;

/// A checked profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub kind: Kind,
    /// Root and intermediate: the subject `CN`. Leaf: `None` (the first
    /// permitted name is the `CN`).
    pub common_name: Option<String>,
    /// The permitted DNS names, as an exact set, in the file's order.
    pub names: Vec<String>,
    pub key_types: Vec<KeyType>,
    pub lifetime_hours: u64,
    /// Minutes before signing time that `notBefore` is set.
    pub not_before_skew_minutes: u64,
    pub issuer: Issuer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "profile: {}", self.0)
    }
}

impl std::error::Error for ProfileError {}

fn bad<T>(why: impl Into<String>) -> Result<T, ProfileError> {
    Err(ProfileError(why.into()))
}

/// The path of profile `name` under `config_dir`. `name` is a plain
/// word (`[a-z0-9_-]`, 1 to 64 bytes), so no name can leave the directory.
pub fn profile_path(config_dir: &Path, name: &str) -> Result<PathBuf, ProfileError> {
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !plain {
        return bad(format!(
            "name {name:?} must be 1 to 64 characters of a-z, 0-9, '-' and '_'"
        ));
    }
    Ok(config_dir.join("ca-profiles").join(format!("{name}.toml")))
}

/// Parse and check one profile file's text.
pub fn parse(text: &str) -> Result<Profile, ProfileError> {
    let spec: Spec = toml::from_str(text).map_err(|e| ProfileError(e.to_string()))?;

    let mut seen: Vec<String> = Vec::new();
    for name in &spec.names {
        check_dns_name(name)?;
        let lower = name.to_ascii_lowercase();
        if seen.contains(&lower) {
            return bad(format!("name {name:?} is listed twice"));
        }
        seen.push(lower);
    }

    match spec.kind {
        Kind::Root | Kind::Intermediate => {
            match spec.common_name.as_deref() {
                None | Some("") => {
                    return bad("a root or intermediate profile needs a common_name");
                }
                Some(cn)
                    if cn.contains(['=', ',', '+', '\\']) || cn.chars().any(char::is_control) =>
                {
                    return bad(
                        "common_name may not contain '=', ',', '+', '\\' or control characters",
                    );
                }
                Some(_) => {}
            }
            if spec.names.is_empty() {
                return bad(
                    "a root or intermediate profile needs the names its constraints permit",
                );
            }
        }
        Kind::Leaf => {
            if spec.common_name.is_some() {
                return bad("a leaf profile has no common_name; its CN is the first of names");
            }
            if spec.names.is_empty() {
                return bad("a leaf profile needs at least one name");
            }
        }
    }

    if spec.lifetime_hours == 0 {
        return bad("lifetime_hours must be positive");
    }

    let issuer = spec.issuer;
    match (&issuer.slot, &issuer.guid, &issuer.holder_key) {
        (Some(slot), Some(guid), None) => {
            check_slot(slot)?;
            check_guid(guid)?;
        }
        (None, None, Some(_)) => {
            return bad("holder_key issuers are not offered yet; use slot and guid");
        }
        _ => return bad("[issuer] needs slot and guid together, or holder_key alone"),
    }
    if spec.kind == Kind::Root
        && issuer.slot.as_deref().map(str::to_ascii_lowercase) != Some("82".into())
    {
        return bad("a root is signed by the CA slot 82");
    }
    if let Some(root) = &issuer.attestation_root {
        if !Path::new(root).is_absolute() {
            return bad(format!(
                "attestation_root {root:?} must be an absolute path (absent means the embedded Yubico root)"
            ));
        }
    }

    let key_types = match spec.key_types {
        None => vec![KeyType::P256, KeyType::P384],
        Some(list) if list.is_empty() => return bad("key_types may not be empty"),
        Some(list) => list,
    };

    Ok(Profile {
        kind: spec.kind,
        common_name: spec.common_name,
        names: spec.names,
        key_types,
        lifetime_hours: spec.lifetime_hours,
        not_before_skew_minutes: spec
            .not_before_skew_minutes
            .unwrap_or(DEFAULT_NOT_BEFORE_SKEW_MINUTES),
        issuer,
    })
}

impl Profile {
    /// Whether a request key of `algorithm` is accepted.
    pub fn accepts(&self, algorithm: PivAlgorithm) -> bool {
        self.key_types.iter().any(|k| k.algorithm() == algorithm)
    }
}

fn check_dns_name(name: &str) -> Result<(), ProfileError> {
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
        return bad(format!(
            "{name:?} is not a plain DNS name (no wildcard, no empty or malformed label)"
        ));
    }
    Ok(())
}

fn check_slot(slot: &str) -> Result<(), ProfileError> {
    match u8::from_str_radix(slot, 16) {
        Ok(id) if slot.len() == 2 && piggy_piv::slot::is_ca_slot(id) => Ok(()),
        _ => bad(format!("slot {slot:?} is not a CA slot (82)")),
    }
}

fn check_guid(guid: &str) -> Result<(), ProfileError> {
    if guid.len() == 32 && guid.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        bad("guid must be 32 hex digits")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "0123456789abcdef0123456789abcdef";

    fn leaf(extra: &str) -> String {
        format!(
            "kind = \"leaf\"\nnames = [\"github.com\", \"api.github.com\"]\nlifetime_hours = 720\n{extra}\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        )
    }

    #[test]
    fn a_leaf_profile_parses_with_both_key_types_by_default() {
        let p = parse(&leaf("")).unwrap();
        assert_eq!(p.kind, Kind::Leaf);
        assert_eq!(p.names, ["github.com", "api.github.com"]);
        assert_eq!(p.lifetime_hours, 720);
        assert!(p.accepts(PivAlgorithm::EcP256) && p.accepts(PivAlgorithm::EcP384));
        assert_eq!(p.common_name, None);
    }

    #[test]
    fn key_types_narrow_what_a_request_may_carry() {
        let p = parse(&leaf("key_types = [\"p256\"]")).unwrap();
        assert!(p.accepts(PivAlgorithm::EcP256));
        assert!(!p.accepts(PivAlgorithm::EcP384));
        assert!(parse(&leaf("key_types = []")).is_err());
        assert!(parse(&leaf("key_types = [\"rsa\"]")).is_err());
    }

    #[test]
    fn a_root_and_an_intermediate_profile_parse() {
        let root = format!(
            "kind = \"root\"\ncommon_name = \"shithub root\"\nnames = [\"github.com\"]\nlifetime_hours = 87600\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        );
        assert_eq!(parse(&root).unwrap().kind, Kind::Root);
        let inter = root.replace("root", "intermediate");
        assert_eq!(parse(&inter).unwrap().kind, Kind::Intermediate);
    }

    #[test]
    fn an_unknown_key_anywhere_is_refused() {
        assert!(parse(&leaf("allow_wildcards = true")).is_err());
        let in_issuer = leaf("").replace("slot = \"82\"", "slot = \"82\"\npin = \"123456\"");
        assert!(parse(&in_issuer).is_err());
    }

    #[test]
    fn names_must_be_plain_unique_dns_names() {
        for bad_name in [
            "*.github.com",
            "github..com",
            "-x.com",
            "a b.com",
            "",
            "git hub.com",
        ] {
            let text = leaf("").replace("\"api.github.com\"", &format!("\"{bad_name}\""));
            assert!(parse(&text).is_err(), "{bad_name:?} must be refused");
        }
        let twice = leaf("").replace("api.github.com", "GitHub.com");
        assert!(parse(&twice).unwrap_err().0.contains("twice"));
        let none = leaf("").replace("names = [\"github.com\", \"api.github.com\"]", "names = []");
        assert!(parse(&none).is_err());
    }

    #[test]
    fn the_kind_decides_whether_a_common_name_belongs() {
        assert!(parse(&leaf("common_name = \"x\"")).is_err());
        let no_cn = format!(
            "kind = \"intermediate\"\nnames = [\"github.com\"]\nlifetime_hours = 24\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        );
        assert!(parse(&no_cn).is_err());
        let injected = no_cn.replace(
            "kind = \"intermediate\"",
            "kind = \"intermediate\"\ncommon_name = \"a,CN=b\"",
        );
        assert!(parse(&injected).is_err());
    }

    #[test]
    fn the_issuer_must_be_a_ca_slot_with_a_guid_and_a_root_must_use_82() {
        assert!(parse(&leaf("").replace("\"82\"", "\"9c\"")).is_err());
        assert!(parse(&leaf("").replace("\"82\"", "\"8\"")).is_err());
        assert!(parse(&leaf("").replace(GUID, "abc")).is_err());
        let no_guid = leaf("").replace(&format!("guid = \"{GUID}\"\n"), "");
        assert!(parse(&no_guid).is_err());
        let holder = leaf("").replace(
            &format!("slot = \"82\"\nguid = \"{GUID}\"\n"),
            "holder_key = \"ecdsa-sha2-nistp256 AAAA\"\n",
        );
        assert!(parse(&holder).unwrap_err().0.contains("not offered"));
    }

    #[test]
    fn a_zero_lifetime_is_refused() {
        assert!(parse(&leaf("").replace("720", "0")).is_err());
    }

    #[test]
    fn the_attestation_root_is_optional_and_absolute() {
        assert_eq!(parse(&leaf("")).unwrap().issuer.attestation_root, None);
        let with = leaf("").replace(
            "slot = \"82\"",
            "slot = \"82\"\nattestation_root = \"/etc/piggy/f9.pem\"",
        );
        assert_eq!(
            parse(&with).unwrap().issuer.attestation_root.as_deref(),
            Some("/etc/piggy/f9.pem")
        );
        let relative = with.replace("/etc/piggy/f9.pem", "f9.pem");
        assert!(parse(&relative).unwrap_err().0.contains("absolute"));
    }

    #[test]
    fn the_not_before_skew_defaults_to_five_minutes() {
        assert_eq!(parse(&leaf("")).unwrap().not_before_skew_minutes, 5);
        assert_eq!(
            parse(&leaf("not_before_skew_minutes = 0"))
                .unwrap()
                .not_before_skew_minutes,
            0
        );
        assert!(parse(&leaf("not_before_skew_minutes = -1")).is_err());
    }

    #[test]
    fn a_profile_name_cannot_leave_the_directory() {
        let dir = Path::new("/c");
        assert_eq!(
            profile_path(dir, "shithub-github").unwrap(),
            Path::new("/c/ca-profiles/shithub-github.toml")
        );
        for name in ["", "../x", "a/b", "A", "x.toml", "a b", &"x".repeat(65)] {
            assert!(profile_path(dir, name).is_err(), "{name:?}");
        }
    }
}
