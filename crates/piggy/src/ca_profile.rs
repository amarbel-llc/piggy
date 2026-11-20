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
    /// A holder key, by its OpenSSH public key line (`ecdsa-sha2-nistp256`,
    /// as `piggy holder mint --type p256` printed it): the holder-held
    /// intermediate that issues leaves through the holder agent (FDR 0007
    /// phase (iii-b)). Only a leaf profile may name one.
    #[serde(default)]
    pub holder_key: Option<String>,
    /// With `holder_key`: the intermediate's certificate (PEM) the holder key
    /// signs under, as an absolute path (the holder serves the key, not its
    /// certificate; the issuance unit keeps it at `intermediateCertFile`).
    #[serde(default)]
    pub issuer_cert: Option<String>,
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
    /// The principal the certificate act is about (RFC 0013 `subject`, a
    /// bare word); default `piggy:ca:<profile name>`.
    #[serde(default)]
    principal: Option<String>,
    issuer: Issuer,
}

/// The `notBefore` skew a profile gets when it names none.
pub const DEFAULT_NOT_BEFORE_SKEW_MINUTES: u64 = 5;

/// The `subject` of a profile's certificate acts when the profile names no
/// `principal`: `piggy:ca:<profile name>`, a bare word for every name
/// [`profile_path`] admits.
pub fn default_principal(profile_name: &str) -> String {
    format!("piggy:ca:{profile_name}")
}

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
    /// The `subject` of the profile's certificate acts, when set.
    pub principal: Option<String>,
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
            if issuer.issuer_cert.is_some() {
                return bad(
                    "issuer_cert belongs to a holder issuer; a card issuer's certificate is the slot's own",
                );
            }
        }
        (None, None, Some(key)) => {
            check_holder_key(key)?;
            match &issuer.issuer_cert {
                Some(path) => check_absolute("issuer_cert", path)?,
                None => {
                    return bad(
                        "a holder issuer needs issuer_cert: the intermediate's certificate the holder key signs under",
                    );
                }
            }
            if issuer.attestation_root.is_some() {
                return bad(
                    "attestation_root is a card issuer's; a holder key is proven by its holder",
                );
            }
            if spec.kind != Kind::Leaf {
                return bad(
                    "a holder key issues leaves only (kind = \"leaf\"); a root or an intermediate is signed on the card",
                );
            }
        }
        _ => return bad("[issuer] needs slot and guid together, or holder_key alone"),
    }
    if spec.kind == Kind::Root
        && !issuer
            .slot
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("82"))
    {
        return bad("a root is signed by the CA slot 82");
    }
    if let Some(root) = &issuer.attestation_root {
        check_absolute("attestation_root", root)?;
    }

    let key_types = match spec.key_types {
        None => vec![KeyType::P256, KeyType::P384],
        Some(list) if list.is_empty() => return bad("key_types may not be empty"),
        Some(list) => list,
    };

    if let Some(principal) = &spec.principal {
        if !crate::act::spells_bare(principal) {
            return bad(format!(
                "principal {principal:?} must be a bare word (no spaces, quotes or commas): it is the certificate act's subject (RFC 0013 §2)"
            ));
        }
    }

    Ok(Profile {
        kind: spec.kind,
        common_name: spec.common_name,
        names: spec.names,
        key_types,
        lifetime_hours: spec.lifetime_hours,
        not_before_skew_minutes: spec
            .not_before_skew_minutes
            .unwrap_or(DEFAULT_NOT_BEFORE_SKEW_MINUTES),
        principal: spec.principal,
        issuer,
    })
}

impl Profile {
    /// Whether a request key of `algorithm` is accepted.
    pub fn accepts(&self, algorithm: PivAlgorithm) -> bool {
        self.key_types.iter().any(|k| k.algorithm() == algorithm)
    }

    /// The `subject` of this profile's certificate acts: its `principal`,
    /// else [`default_principal`] of `profile_name`.
    pub fn principal_for(&self, profile_name: &str) -> String {
        self.principal
            .clone()
            .unwrap_or_else(|| default_principal(profile_name))
    }
}

/// Whether `name` is a plain DNS name: no wildcard, no empty or malformed
/// label, at most 253 bytes. The rule a profile's `names` are held to, and
/// the one `piggy ca leaf-csr` holds its CN to, so a request it makes is
/// one a profile can name.
pub fn check_dns_name(name: &str) -> Result<(), ProfileError> {
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

/// A profile's file paths are absolute, so a profile reads the same from
/// any working directory (a relative `attestation_root` would also mean
/// "the embedded root" by accident when missing).
fn check_absolute(field: &str, path: &str) -> Result<(), ProfileError> {
    if Path::new(path).is_absolute() {
        Ok(())
    } else {
        bad(format!("{field} {path:?} must be an absolute path"))
    }
}

/// A holder key is an OpenSSH `ecdsa-sha2-nistp256` public key line, the
/// intermediate's (FDR 0007 issues P-256 intermediates only).
fn check_holder_key(key: &str) -> Result<(), ProfileError> {
    use ssh_key::public::{EcdsaPublicKey, KeyData};
    let parsed = ssh_key::PublicKey::from_openssh(key.trim())
        .map_err(|e| ProfileError(format!("holder_key is not an OpenSSH public key line: {e}")))?;
    match parsed.key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(_)) => Ok(()),
        other => bad(format!(
            "holder_key is {}; the holder's intermediate is an ecdsa-sha2-nistp256 key",
            other.algorithm()
        )),
    }
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
    }

    /// An OpenSSH `ecdsa-sha2-nistp256` line over a point of the given tag
    /// and 64 bytes: the line parses; the curve is not checked by the parser.
    fn holder_line(tag: u8) -> String {
        use base64::Engine;
        fn put(buf: &mut Vec<u8>, s: &[u8]) {
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s);
        }
        let mut point = vec![0x04];
        point.extend_from_slice(&[tag; 64]);
        let mut blob = Vec::new();
        put(&mut blob, b"ecdsa-sha2-nistp256");
        put(&mut blob, b"nistp256");
        put(&mut blob, &point);
        format!(
            "ecdsa-sha2-nistp256 {} holder:piggy-ca-intermediate-v1",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    fn holder_leaf(extra: &str) -> String {
        format!(
            "kind = \"leaf\"\nnames = [\"github.com\"]\nlifetime_hours = 720\n[issuer]\nholder_key = \"{}\"\n{extra}",
            holder_line(7)
        )
    }

    #[test]
    fn a_holder_issuer_is_a_p256_line_with_the_intermediates_certificate_on_a_leaf_profile() {
        let p = parse(&holder_leaf(
            "issuer_cert = \"/var/lib/piggy-ca/intermediate.pem\"\n",
        ))
        .unwrap();
        assert_eq!(
            p.issuer.holder_key.as_deref(),
            Some(holder_line(7).as_str())
        );
        assert_eq!(
            p.issuer.issuer_cert.as_deref(),
            Some("/var/lib/piggy-ca/intermediate.pem")
        );
        assert!(p.issuer.slot.is_none() && p.issuer.guid.is_none());

        let no_cert = parse(&holder_leaf("")).unwrap_err();
        assert!(no_cert.0.contains("issuer_cert"), "{no_cert}");
        let relative = parse(&holder_leaf("issuer_cert = \"intermediate.pem\"\n")).unwrap_err();
        assert!(relative.0.contains("absolute"), "{relative}");
        let with_root = parse(&holder_leaf(
            "issuer_cert = \"/i.pem\"\nattestation_root = \"/f9.pem\"\n",
        ))
        .unwrap_err();
        assert!(with_root.0.contains("attestation_root"), "{with_root}");
        let not_a_line = parse(
            &holder_leaf("issuer_cert = \"/i.pem\"\n")
                .replace(&holder_line(7), "ecdsa-sha2-nistp256 AAAA"),
        )
        .unwrap_err();
        assert!(
            not_a_line.0.contains("OpenSSH public key line"),
            "{not_a_line}"
        );
        let ed = parse(&holder_leaf("issuer_cert = \"/i.pem\"\n").replace(
            &holder_line(7),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA h",
        ))
        .unwrap_err();
        assert!(ed.0.contains("ssh-ed25519"), "{ed}");
        // Only a leaf profile: an intermediate or a root is the card's.
        let inter = format!(
            "kind = \"intermediate\"\ncommon_name = \"x\"\nnames = [\"github.com\"]\nlifetime_hours = 24\n[issuer]\nholder_key = \"{}\"\nissuer_cert = \"/i.pem\"\n",
            holder_line(7)
        );
        assert!(parse(&inter).unwrap_err().0.contains("leaves only"));
        // issuer_cert is the holder's field.
        let card_with_cert =
            leaf("").replace("slot = \"82\"", "slot = \"82\"\nissuer_cert = \"/i.pem\"");
        assert!(
            parse(&card_with_cert)
                .unwrap_err()
                .0
                .contains("holder issuer")
        );
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

    /// RFC 0013 §2: `subject` is a bare word. The default must be one for
    /// every profile name the directory admits, and a set `principal` is
    /// held to the same rule, by the encoder's own verdict.
    #[test]
    fn the_principal_defaults_to_a_bare_word_named_after_the_profile() {
        let p = parse(&leaf("")).unwrap();
        assert_eq!(p.principal, None);
        assert_eq!(p.principal_for("shithub-github"), "piggy:ca:shithub-github");
        for name in ["shithub", "a-b_c", "x0", &"z".repeat(64)] {
            assert!(crate::act::spells_bare(&default_principal(name)), "{name}");
        }

        let set = parse(&leaf("principal = \"shithub:proxy\"")).unwrap();
        assert_eq!(set.principal_for("ignored"), "shithub:proxy");
        for bad in ["a b", "a,b", "\"q\"", ""] {
            let err = parse(&leaf(&format!("principal = {bad:?}"))).unwrap_err();
            assert!(err.0.contains("bare word"), "{bad:?}: {err}");
        }
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
