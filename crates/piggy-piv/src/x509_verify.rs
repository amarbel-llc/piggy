//! The chain check behind `piggy ca verify` (FDR 0007): a leaf under zero
//! or more intermediates under one given root. Checked, each as a named
//! point: the path (issuer names and key identifiers), every signature
//! with its issuer's key, the validity at a given time, every CA's
//! basicConstraints (critical, CA, pathlen honoured) and keyCertSign, the
//! leaf's own profile (not a CA, digitalSignature, serverAuth, a DNS
//! subjectAltName), the name constraints of every CA on the path applied
//! to the leaf's DNS names and CN (RFC 5280 §4.2.1.10: a DNS subtree
//! admits the name itself and every name under it; an IP subtree is an
//! address and a mask), every unknown critical extension refused, and,
//! when asked, the leaf's key equal to a given one.
//!
//! Pure: DER in, a [`Report`] out; no clock (the caller passes `at`), no
//! file, no system trust store (the given root is the only anchor), no
//! OpenSSL (the test module uses it as the oracle). EC P-256 and P-384
//! keys only, as everything FDR 0007 issues; any other key fails the
//! signature point. A checker, not a gate: issuance never calls it, and
//! [`describe`] is the read-only face `piggy cert show` prints.

use std::time::Duration;

use const_oid::ObjectIdentifier;
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::certificate::Certificate;
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};

use crate::csr_check;
use crate::slot::PivAlgorithm;

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// One named check of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    /// What was seen, for the TAP diagnostics; the reason when `!ok`.
    pub detail: Option<String>,
}

/// What [`verify_chain`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The subjects along the path, the leaf first and the root last; empty
    /// when no path could be built.
    pub path: Vec<String>,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn valid(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

/// A certificate that could not be read: not DER, or not a certificate.
/// The verb answers exit 4 to it (FDR 0007's exit table: a malformed
/// input), as distinct from a chain that does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub which: String,
    pub why: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.which, self.why)
    }
}

impl std::error::Error for ParseError {}

/// What the chain is checked against.
pub struct Expect<'a> {
    /// The instant the validity windows are read at, since the Unix epoch.
    pub at: Duration,
    /// When set, the leaf's key must be this SEC1 uncompressed point.
    pub leaf_key_point: Option<&'a [u8]>,
}

/// A certificate read once, with the fields the checks use.
struct Parsed {
    label: String,
    subject: String,
    issuer: String,
    serial_hex: String,
    subject_der: Vec<u8>,
    issuer_der: Vec<u8>,
    common_name: Option<String>,
    key: Option<(PivAlgorithm, Vec<u8>)>,
    tbs_der: Vec<u8>,
    sig_alg: ObjectIdentifier,
    tbs_sig_alg: ObjectIdentifier,
    signature: Option<Vec<u8>>,
    not_before: Duration,
    not_after: Duration,
    /// (critical, the constraints).
    basic: Option<(bool, BasicConstraints)>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<Vec<ObjectIdentifier>>,
    san: Option<Vec<GeneralName>>,
    name_constraints: Option<NameConstraints>,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
    unknown_critical: Vec<String>,
}

fn parse(label: &str, der: &[u8]) -> Result<Parsed, ParseError> {
    let fail = |why: String| ParseError {
        which: label.to_string(),
        why,
    };
    let cert =
        Certificate::from_der(der).map_err(|e| fail(format!("not a DER certificate: {e}")))?;
    let tbs = &cert.tbs_certificate;
    let mut parsed = Parsed {
        label: label.to_string(),
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        serial_hex: hex::encode(tbs.serial_number.as_bytes()),
        subject_der: tbs.subject.to_der().map_err(|e| fail(e.to_string()))?,
        issuer_der: tbs.issuer.to_der().map_err(|e| fail(e.to_string()))?,
        common_name: common_name_of(&tbs.subject),
        key: ec_key_of(&tbs.subject_public_key_info),
        tbs_der: tbs.to_der().map_err(|e| fail(e.to_string()))?,
        sig_alg: cert.signature_algorithm.oid,
        tbs_sig_alg: tbs.signature.oid,
        signature: cert.signature.as_bytes().map(<[u8]>::to_vec),
        not_before: tbs.validity.not_before.to_unix_duration(),
        not_after: tbs.validity.not_after.to_unix_duration(),
        basic: None,
        key_usage: None,
        extended_key_usage: None,
        san: None,
        name_constraints: None,
        ski: None,
        aki: None,
        unknown_critical: Vec::new(),
    };
    for ext in tbs.extensions.iter().flatten() {
        let bytes = ext.extn_value.as_bytes();
        let bad =
            |what: &str, e: der::Error| fail(format!("{what} extension does not decode: {e}"));
        match ext.extn_id {
            BasicConstraints::OID => {
                let bc =
                    BasicConstraints::from_der(bytes).map_err(|e| bad("basicConstraints", e))?;
                parsed.basic = Some((ext.critical, bc));
            }
            KeyUsage::OID => {
                parsed.key_usage = Some(KeyUsage::from_der(bytes).map_err(|e| bad("keyUsage", e))?);
            }
            ExtendedKeyUsage::OID => {
                parsed.extended_key_usage = Some(
                    ExtendedKeyUsage::from_der(bytes)
                        .map_err(|e| bad("extendedKeyUsage", e))?
                        .0,
                );
            }
            SubjectAltName::OID => {
                parsed.san = Some(
                    SubjectAltName::from_der(bytes)
                        .map_err(|e| bad("subjectAltName", e))?
                        .0,
                );
            }
            NameConstraints::OID => {
                parsed.name_constraints =
                    Some(NameConstraints::from_der(bytes).map_err(|e| bad("nameConstraints", e))?);
            }
            SubjectKeyIdentifier::OID => {
                parsed.ski = Some(
                    SubjectKeyIdentifier::from_der(bytes)
                        .map_err(|e| bad("subjectKeyIdentifier", e))?
                        .0
                        .as_bytes()
                        .to_vec(),
                );
            }
            AuthorityKeyIdentifier::OID => {
                parsed.aki = AuthorityKeyIdentifier::from_der(bytes)
                    .map_err(|e| bad("authorityKeyIdentifier", e))?
                    .key_identifier
                    .map(|k| k.as_bytes().to_vec());
            }
            other if ext.critical => parsed.unknown_critical.push(other.to_string()),
            _ => {}
        }
    }
    Ok(parsed)
}

fn ec_key_of(spki: &SubjectPublicKeyInfoOwned) -> Option<(PivAlgorithm, Vec<u8>)> {
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    let algorithm = match (spki.algorithm.oid, curve) {
        (OID_EC_PUBLIC_KEY, Some(OID_PRIME256V1)) => PivAlgorithm::EcP256,
        (OID_EC_PUBLIC_KEY, Some(OID_SECP384R1)) => PivAlgorithm::EcP384,
        _ => return None,
    };
    Some((algorithm, spki.subject_public_key.as_bytes()?.to_vec()))
}

/// The subject's `CN` when it carries exactly one.
fn common_name_of(name: &x509_cert::name::Name) -> Option<String> {
    use der::asn1::{PrintableStringRef, Utf8StringRef};
    let mut found = Vec::new();
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid != OID_COMMON_NAME {
                continue;
            }
            if let Ok(s) = atv.value.decode_as::<Utf8StringRef<'_>>() {
                found.push(s.as_str().to_owned());
            } else if let Ok(s) = atv.value.decode_as::<PrintableStringRef<'_>>() {
                found.push(s.as_str().to_owned());
            }
        }
    }
    (found.len() == 1).then(|| found.remove(0))
}

/// Whether `name` is under the DNS subtree `base` (RFC 5280 §4.2.1.10): the
/// name itself or any name with more labels on the left; a base that
/// starts with a dot admits any name ending in it. ASCII case-insensitive.
fn dns_in_subtree(name: &str, base: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let base = base.to_ascii_lowercase();
    if base.is_empty() {
        return true;
    }
    if base.starts_with('.') {
        return name.ends_with(base.as_str());
    }
    name == base || name.ends_with(&format!(".{base}"))
}

/// Whether `cert` carries `issuer`'s signature: the algorithm the issuer's
/// curve calls for, named the same in both places, and the ECDSA check.
fn signed_by(cert: &Parsed, issuer: &Parsed) -> bool {
    match (&issuer.key, &cert.signature) {
        (Some((algorithm, point)), Some(sig)) => {
            signature_oid_for(*algorithm) == Some(cert.sig_alg)
                && cert.sig_alg == cert.tbs_sig_alg
                && csr_check::verifies(*algorithm, point, &cert.tbs_der, sig)
        }
        _ => false,
    }
}

/// Whether `cert_der`'s signature verifies under `issuer_der`'s key, with
/// the signature algorithm the issuer's curve calls for: what an issuing
/// verb asks of a certificate it just had signed, before it writes it,
/// when the signer was not proven the issuer's key on a card.
pub fn signature_verifies(cert_der: &[u8], issuer_der: &[u8]) -> Result<bool, ParseError> {
    Ok(signed_by(
        &parse("certificate", cert_der)?,
        &parse("issuer", issuer_der)?,
    ))
}

/// The subject key of `cert_der` when it is EC P-256 or P-384: the
/// algorithm and the SEC1 uncompressed point.
pub fn subject_key(cert_der: &[u8]) -> Result<Option<(PivAlgorithm, Vec<u8>)>, ParseError> {
    Ok(parse("certificate", cert_der)?.key)
}

/// The DNS bases of the subtrees in `trees`.
fn dns_bases(trees: &Option<Vec<GeneralSubtree>>) -> Vec<String> {
    trees
        .iter()
        .flatten()
        .filter_map(|t| match &t.base {
            GeneralName::DnsName(d) => Some(d.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

/// The IP subtrees (address then mask) in `trees`.
fn ip_bases(trees: &Option<Vec<GeneralSubtree>>) -> Vec<Vec<u8>> {
    trees
        .iter()
        .flatten()
        .filter_map(|t| match &t.base {
            GeneralName::IpAddress(ip) => Some(ip.as_bytes().to_vec()),
            _ => None,
        })
        .collect()
}

/// Why `name` is refused by DNS subtrees: not under any permitted one
/// (when there are any), or inside an excluded one. Empty when admitted.
fn dns_violations(name: &str, permitted: &[String], excluded: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if !permitted.is_empty() && !permitted.iter().any(|b| dns_in_subtree(name, b)) {
        out.push(format!(
            "{name} is not under a permitted DNS subtree (permitted: {})",
            permitted.join(", ")
        ));
    }
    if let Some(b) = excluded.iter().find(|b| dns_in_subtree(name, b)) {
        out.push(format!("{name} is in the excluded DNS subtree {b}"));
    }
    out
}

/// The DNS `names` that `issuer_der`'s name constraints refuse, each with
/// its reason; empty when every name is admitted or the issuer carries no
/// constraints. What `piggy ca sign` and `issue` ask of a profile before
/// anything is signed, so a profile cannot name what its issuer may not
/// certify.
pub fn dns_names_refused_by(
    issuer_der: &[u8],
    names: &[String],
) -> Result<Vec<String>, ParseError> {
    let issuer = parse("issuer", issuer_der)?;
    let Some(nc) = &issuer.name_constraints else {
        return Ok(Vec::new());
    };
    let permitted = dns_bases(&nc.permitted_subtrees);
    let excluded = dns_bases(&nc.excluded_subtrees);
    Ok(names
        .iter()
        .flat_map(|name| dns_violations(name, &permitted, &excluded))
        .collect())
}

/// Whether the address `ip` (4 or 16 bytes) is in the IP subtree
/// `subtree` (address then mask, 8 or 32 bytes). Mismatched families are
/// not in.
fn ip_in_subtree(ip: &[u8], subtree: &[u8]) -> bool {
    if subtree.len() != ip.len() * 2 || !(ip.len() == 4 || ip.len() == 16) {
        return false;
    }
    let (base, mask) = subtree.split_at(ip.len());
    ip.iter()
        .zip(base)
        .zip(mask)
        .all(|((a, b), m)| a & m == b & m)
}

fn signature_oid_for(algorithm: PivAlgorithm) -> Option<ObjectIdentifier> {
    match algorithm {
        PivAlgorithm::EcP256 => Some(OID_ECDSA_SHA256),
        PivAlgorithm::EcP384 => Some(OID_ECDSA_SHA384),
        _ => None,
    }
}

/// The path from the leaf to the root, or why none exists: each step's
/// issuer is the untrusted certificate (or the root) whose subject is the
/// step's issuer name and, when the step names an authority key id, whose
/// subject key id is that one. Each certificate is used once.
fn build_path(
    leaf: Parsed,
    mut untrusted: Vec<Parsed>,
    root: Parsed,
) -> Result<Vec<Parsed>, (Vec<Parsed>, String)> {
    let is_issuer = |cert: &Parsed, candidate: &Parsed| {
        candidate.subject_der == cert.issuer_der
            && match (&cert.aki, &candidate.ski) {
                (Some(aki), Some(ski)) => aki == ski,
                _ => true,
            }
    };
    let mut path = vec![leaf];
    loop {
        let current = path.last().expect("the path starts with the leaf");
        if is_issuer(current, &root) {
            path.push(root);
            return Ok(path);
        }
        if current.subject_der == current.issuer_der {
            let why = format!(
                "{} ({}) is self-issued and is not the given root",
                current.label, current.subject
            );
            return Err((path, why));
        }
        match untrusted.iter().position(|c| is_issuer(current, c)) {
            Some(i) => {
                let next = untrusted.remove(i);
                path.push(next);
            }
            None => {
                let why = format!(
                    "no issuer for {} ({}) among the untrusted certificates and the root",
                    current.label, current.subject
                );
                return Err((path, why));
            }
        }
    }
}

fn iso(at: Duration) -> String {
    match der::DateTime::from_unix_duration(at) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minutes(),
            t.seconds()
        ),
        Err(_) => format!("{}s", at.as_secs()),
    }
}

/// Check `leaf_der` under `untrusted` (intermediates, any order) under
/// `root_der`. A certificate that does not parse is a [`ParseError`]; a
/// chain that does not hold is a [`Report`] with failing checks.
pub fn verify_chain(
    root_der: &[u8],
    untrusted: &[&[u8]],
    leaf_der: &[u8],
    expect: &Expect<'_>,
) -> Result<Report, ParseError> {
    let leaf = parse("leaf", leaf_der)?;
    let root = parse("root", root_der)?;
    let untrusted = untrusted
        .iter()
        .enumerate()
        .map(|(i, der)| parse(&format!("untrusted #{}", i + 1), der))
        .collect::<Result<Vec<_>, _>>()?;

    let mut checks = Vec::new();
    let mut push = |name: String, ok: bool, detail: Option<String>| {
        checks.push(Check { name, ok, detail });
    };

    let path = match build_path(leaf, untrusted, root) {
        Ok(path) => {
            let shown = path
                .iter()
                .map(|c| format!("{} ({})", c.label, c.subject))
                .collect::<Vec<_>>()
                .join(" <- ");
            push("a path from the leaf to the root".into(), true, Some(shown));
            path
        }
        Err((partial, why)) => {
            push("a path from the leaf to the root".into(), false, Some(why));
            return Ok(Report {
                path: partial.into_iter().map(|c| c.subject).collect(),
                checks,
            });
        }
    };

    let last = path.len() - 1;
    for (i, cert) in path.iter().enumerate() {
        // The root signs itself.
        let issuer = &path[(i + 1).min(last)];
        let ok = signed_by(cert, issuer);
        let detail = match &issuer.key {
            Some((algorithm, _)) => {
                format!("{algorithm:?} key of {}, {}", issuer.label, cert.sig_alg)
            }
            None => format!("{}'s key is not EC P-256 or P-384", issuer.label),
        };
        push(
            format!(
                "the signature of the {} by the {}",
                cert.label, issuer.label
            ),
            ok,
            Some(detail),
        );
    }

    for cert in &path {
        let ok = cert.not_before <= expect.at && expect.at <= cert.not_after;
        push(
            format!("the {} is valid at {}", cert.label, iso(expect.at)),
            ok,
            Some(format!(
                "notBefore {} notAfter {}",
                iso(cert.not_before),
                iso(cert.not_after)
            )),
        );
    }

    for cert in &path {
        push(
            format!("no unknown critical extension in the {}", cert.label),
            cert.unknown_critical.is_empty(),
            (!cert.unknown_critical.is_empty()).then(|| cert.unknown_critical.join(", ")),
        );
    }

    // The CAs: every certificate above the leaf. `below` counts the
    // intermediates between a CA and the leaf, what its pathlen bounds.
    for (i, cert) in path.iter().enumerate().skip(1) {
        let below = i - 1;
        let (critical_ca, pathlen) = match &cert.basic {
            Some((critical, bc)) => (*critical && bc.ca, bc.path_len_constraint),
            None => (false, None),
        };
        push(
            format!(
                "the {} is a CA (basicConstraints critical, CA:TRUE)",
                cert.label
            ),
            critical_ca,
            Some(match &cert.basic {
                Some((critical, bc)) => format!(
                    "basicConstraints {}CA:{}",
                    if *critical {
                        "critical "
                    } else {
                        "not critical, "
                    },
                    if bc.ca { "TRUE" } else { "FALSE" }
                ),
                None => "no basicConstraints".into(),
            }),
        );
        let signs = cert
            .key_usage
            .as_ref()
            .is_some_and(|ku| ku.0.contains(KeyUsages::KeyCertSign));
        push(
            format!(
                "the {} may sign certificates (keyUsage keyCertSign)",
                cert.label
            ),
            signs,
            None,
        );
        if let Some(limit) = pathlen {
            push(
                format!(
                    "the {}'s pathlen {limit} admits {below} intermediate(s) below it",
                    cert.label
                ),
                below <= usize::from(limit),
                None,
            );
        }
    }

    // The leaf's own profile.
    let leaf = &path[0];
    push(
        "the leaf is not a CA".into(),
        !leaf.basic.as_ref().is_some_and(|(_, bc)| bc.ca),
        None,
    );
    push(
        "the leaf's keyUsage has digitalSignature".into(),
        leaf.key_usage
            .as_ref()
            .is_some_and(|ku| ku.0.contains(KeyUsages::DigitalSignature)),
        None,
    );
    push(
        "the leaf's extendedKeyUsage has serverAuth".into(),
        leaf.extended_key_usage
            .as_ref()
            .is_some_and(|eku| eku.contains(&OID_KP_SERVER_AUTH)),
        None,
    );
    let dns_names: Vec<String> = leaf
        .san
        .iter()
        .flatten()
        .filter_map(|n| match n {
            GeneralName::DnsName(d) => Some(d.as_str().to_owned()),
            _ => None,
        })
        .collect();
    let ip_names: Vec<Vec<u8>> = leaf
        .san
        .iter()
        .flatten()
        .filter_map(|n| match n {
            GeneralName::IpAddress(ip) => Some(ip.as_bytes().to_vec()),
            _ => None,
        })
        .collect();
    push(
        "the leaf has a DNS subjectAltName".into(),
        !dns_names.is_empty(),
        Some(dns_names.join(", ")),
    );

    // The names the constraints are applied to: every DNS SAN, and the CN
    // when it is shaped like a host name (what a verifier that falls back
    // to the CN would match).
    let mut constrained: Vec<String> = dns_names.clone();
    if let Some(cn) = &leaf.common_name {
        let hostlike = !cn.is_empty()
            && cn
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
        if hostlike && !constrained.iter().any(|n| n.eq_ignore_ascii_case(cn)) {
            constrained.push(cn.clone());
        }
    }
    for ca in path.iter().skip(1) {
        let Some(nc) = &ca.name_constraints else {
            continue;
        };
        let permitted_dns = dns_bases(&nc.permitted_subtrees);
        let excluded_dns = dns_bases(&nc.excluded_subtrees);
        let permitted_ip = ip_bases(&nc.permitted_subtrees);
        let excluded_ip = ip_bases(&nc.excluded_subtrees);
        let mut failures: Vec<String> = constrained
            .iter()
            .flat_map(|name| dns_violations(name, &permitted_dns, &excluded_dns))
            .collect();
        for ip in &ip_names {
            let shown = ip
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(".");
            if excluded_ip.iter().any(|t| ip_in_subtree(ip, t)) {
                failures.push(format!(
                    "the IP address {shown} is in an excluded IP subtree"
                ));
            }
            if !permitted_ip.is_empty() && !permitted_ip.iter().any(|t| ip_in_subtree(ip, t)) {
                failures.push(format!(
                    "the IP address {shown} is not under a permitted IP subtree"
                ));
            }
        }
        let checked = if constrained.is_empty() && ip_names.is_empty() {
            "no names to check".to_string()
        } else {
            format!("checked: {}", constrained.join(", "))
        };
        push(
            format!(
                "the name constraints of the {} admit the leaf's names",
                ca.label
            ),
            failures.is_empty(),
            Some(if failures.is_empty() {
                checked
            } else {
                failures.join("; ")
            }),
        );
    }

    if let Some(want) = expect.leaf_key_point {
        let ok = leaf.key.as_ref().is_some_and(|(_, point)| point == want);
        push("the leaf's key is the given key".into(), ok, None);
    }

    Ok(Report {
        path: path.into_iter().map(|c| c.subject).collect(),
        checks,
    })
}

/// What `piggy cert show` prints: a certificate's fields read back, each
/// as text, with the SHA-256 of the DER (the digest a certificate act's
/// description carries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    pub subject: String,
    pub issuer: String,
    pub self_issued: bool,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    /// The subject key when it is EC P-256 or P-384: the algorithm and the
    /// SEC1 uncompressed point.
    pub key: Option<(PivAlgorithm, Vec<u8>)>,
    /// `(critical, CA, pathlen)` when basicConstraints is present.
    pub basic_constraints: Option<(bool, bool, Option<u8>)>,
    pub key_usage: Vec<&'static str>,
    pub extended_key_usage: Vec<String>,
    pub dns_names: Vec<String>,
    pub ip_names: Vec<String>,
    pub permitted: Vec<String>,
    pub excluded: Vec<String>,
    pub ski_hex: Option<String>,
    pub aki_hex: Option<String>,
    pub unknown_critical: Vec<String>,
    pub sha256_hex: String,
}

fn ip_text(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        16 => bytes
            .chunks(2)
            .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex::encode(bytes),
    }
}

fn subtree_text(tree: &GeneralSubtree) -> String {
    match &tree.base {
        GeneralName::DnsName(d) => format!("DNS:{}", d.as_str()),
        GeneralName::IpAddress(ip) => {
            let bytes = ip.as_bytes();
            if bytes.len() == 8 || bytes.len() == 32 {
                let (addr, mask) = bytes.split_at(bytes.len() / 2);
                format!("IP:{}/{}", ip_text(addr), ip_text(mask))
            } else {
                format!("IP:{}", hex::encode(bytes))
            }
        }
        GeneralName::Rfc822Name(m) => format!("email:{}", m.as_str()),
        GeneralName::UniformResourceIdentifier(u) => format!("URI:{}", u.as_str()),
        GeneralName::DirectoryName(n) => format!("dirName:{n}"),
        other => format!("{other:?}"),
    }
}

/// Read a certificate back as text.
pub fn describe(der: &[u8]) -> Result<Description, ParseError> {
    use sha2::Digest as _;
    let p = parse("certificate", der)?;
    let key_usage = p
        .key_usage
        .as_ref()
        .map(|ku| {
            [
                (KeyUsages::DigitalSignature, "digitalSignature"),
                (KeyUsages::NonRepudiation, "nonRepudiation"),
                (KeyUsages::KeyEncipherment, "keyEncipherment"),
                (KeyUsages::DataEncipherment, "dataEncipherment"),
                (KeyUsages::KeyAgreement, "keyAgreement"),
                (KeyUsages::KeyCertSign, "keyCertSign"),
                (KeyUsages::CRLSign, "cRLSign"),
                (KeyUsages::EncipherOnly, "encipherOnly"),
                (KeyUsages::DecipherOnly, "decipherOnly"),
            ]
            .into_iter()
            .filter(|(flag, _)| ku.0.contains(*flag))
            .map(|(_, name)| name)
            .collect()
        })
        .unwrap_or_default();
    let extended_key_usage = p
        .extended_key_usage
        .iter()
        .flatten()
        .map(|oid| {
            if *oid == OID_KP_SERVER_AUTH {
                "serverAuth".to_string()
            } else {
                oid.to_string()
            }
        })
        .collect();
    let dns_names = p
        .san
        .iter()
        .flatten()
        .filter_map(|n| match n {
            GeneralName::DnsName(d) => Some(d.as_str().to_owned()),
            _ => None,
        })
        .collect();
    let ip_names = p
        .san
        .iter()
        .flatten()
        .filter_map(|n| match n {
            GeneralName::IpAddress(ip) => Some(ip_text(ip.as_bytes())),
            _ => None,
        })
        .collect();
    let (permitted, excluded) = match &p.name_constraints {
        Some(nc) => (
            nc.permitted_subtrees
                .iter()
                .flatten()
                .map(subtree_text)
                .collect(),
            nc.excluded_subtrees
                .iter()
                .flatten()
                .map(subtree_text)
                .collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    Ok(Description {
        subject: p.subject,
        issuer: p.issuer,
        self_issued: p.subject_der == p.issuer_der,
        serial_hex: p.serial_hex,
        not_before: iso(p.not_before),
        not_after: iso(p.not_after),
        key: p.key,
        basic_constraints: p
            .basic
            .map(|(critical, bc)| (critical, bc.ca, bc.path_len_constraint)),
        key_usage,
        extended_key_usage,
        dns_names,
        ip_names,
        permitted,
        excluded,
        ski_hex: p.ski.map(hex::encode),
        aki_hex: p.aki.map(hex::encode),
        unknown_critical: p.unknown_critical,
        sha256_hex: hex::encode(sha2::Sha256::digest(der)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509_profile::{self, CertValidity};
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, BigNumContext, MsbOption};
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::stack::Stack;
    use openssl::x509::extension::{
        AuthorityKeyIdentifier as OsslAki, SubjectKeyIdentifier as OsslSki,
    };
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509, X509Builder, X509Extension, X509NameBuilder, X509StoreContext};

    const DAY: u64 = 86_400;

    fn now() -> Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn p256() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn point(key: &PKey<Private>) -> Vec<u8> {
        let ec = key.ec_key().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        ec.public_key()
            .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap()
    }

    fn signer(key: &PKey<Private>) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, crate::PivError> + '_ {
        move |digest| {
            Ok(EcdsaSig::sign(digest, &key.ec_key().unwrap())
                .unwrap()
                .to_der()
                .unwrap())
        }
    }

    fn validity(days: u64) -> CertValidity {
        CertValidity {
            not_before: now() - Duration::from_secs(300),
            not_after: now() + Duration::from_secs(days * DAY),
        }
    }

    /// The profiles' own builders: what piggy issues.
    fn root(key: &PKey<Private>, permitted: &[&str]) -> Vec<u8> {
        x509_profile::build_root_cert(
            &point(key),
            PivAlgorithm::EcP256,
            "piggy-test root",
            &names(permitted),
            validity(3650),
            &[0x5A; 16],
            signer(key),
        )
        .unwrap()
    }

    fn intermediate(
        key: &PKey<Private>,
        cn: &str,
        permitted: &[&str],
        issuer_der: &[u8],
        issuer_key: &PKey<Private>,
        days: u64,
    ) -> Vec<u8> {
        x509_profile::build_intermediate_cert(
            &point(key),
            PivAlgorithm::EcP256,
            cn,
            &names(permitted),
            issuer_der,
            validity(days),
            &[0x11; 16],
            signer(issuer_key),
        )
        .unwrap()
    }

    fn leaf(
        key: &PKey<Private>,
        dns: &[&str],
        issuer_der: &[u8],
        issuer_key: &PKey<Private>,
    ) -> Vec<u8> {
        x509_profile::build_leaf_cert(
            &point(key),
            PivAlgorithm::EcP256,
            &names(dns),
            issuer_der,
            validity(30),
            &[0x22; 16],
            signer(issuer_key),
        )
        .unwrap()
    }

    /// A certificate with whatever extensions a vector needs, built and
    /// signed by OpenSSL (the oracle's own builder), so a negative case
    /// is never one piggy's builders could not have produced.
    struct Custom<'a> {
        cn: &'a str,
        key: &'a PKey<Private>,
        issuer: Option<(&'a X509, &'a PKey<Private>)>,
        not_before: i64,
        not_after: i64,
        /// Extension conf strings for `X509Extension::new_nid`, by nid.
        exts: Vec<(Nid, &'a str)>,
        ski_aki: bool,
        /// An unknown critical extension.
        odd_critical: bool,
    }

    impl Default for Custom<'_> {
        fn default() -> Self {
            Custom {
                cn: "piggy-test custom",
                key: Box::leak(Box::new(p256())),
                issuer: None,
                not_before: now().as_secs() as i64 - 300,
                not_after: now().as_secs() as i64 + 30 * DAY as i64,
                exts: Vec::new(),
                ski_aki: true,
                odd_critical: false,
            }
        }
    }

    #[allow(deprecated)]
    fn custom(spec: &Custom<'_>) -> X509 {
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", spec.cn).unwrap();
        let name = name.build();
        b.set_subject_name(&name).unwrap();
        match spec.issuer {
            Some((cert, _)) => b.set_issuer_name(cert.subject_name()).unwrap(),
            None => b.set_issuer_name(&name).unwrap(),
        }
        b.set_pubkey(spec.key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(spec.not_before).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::from_unix(spec.not_after).unwrap())
            .unwrap();
        let built = {
            let ctx = b.x509v3_context(spec.issuer.map(|(c, _)| &**c), None);
            let mut exts = Vec::new();
            if spec.ski_aki {
                exts.push(OsslSki::new().build(&ctx).unwrap());
                exts.push(OsslAki::new().keyid(true).build(&ctx).unwrap());
            }
            for (nid, value) in &spec.exts {
                exts.push(X509Extension::new_nid(None, Some(&ctx), *nid, value).unwrap());
            }
            exts
        };
        for ext in built {
            b.append_extension(ext).unwrap();
        }
        if spec.odd_critical {
            let oid = openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.99999.7").unwrap();
            let value = openssl::asn1::Asn1OctetString::new_from_bytes(&[0x05, 0x00]).unwrap();
            b.append_extension(X509Extension::new_from_der(&oid, true, &value).unwrap())
                .unwrap();
        }
        let signing = spec.issuer.map(|(_, k)| k).unwrap_or(spec.key);
        b.sign(signing, MessageDigest::sha256()).unwrap();
        b.build()
    }

    /// What OpenSSL says of the same chain (the oracle).
    fn openssl_says(root: &[u8], intermediates: &[&[u8]], leaf: &[u8]) -> Result<(), String> {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(X509::from_der(root).unwrap()).unwrap();
        let store = store.build();
        let mut chain = Stack::new().unwrap();
        for der in intermediates {
            chain.push(X509::from_der(der).unwrap()).unwrap();
        }
        let leaf = X509::from_der(leaf).unwrap();
        let mut ctx = X509StoreContext::new().unwrap();
        ctx.init(&store, &leaf, &chain, |c| {
            Ok(if c.verify_cert()? {
                Ok(())
            } else {
                Err(c.error().to_string())
            })
        })
        .unwrap()
    }

    fn piggy_says(root: &[u8], intermediates: &[&[u8]], leaf: &[u8]) -> Report {
        verify_chain(
            root,
            intermediates,
            leaf,
            &Expect {
                at: now(),
                leaf_key_point: None,
            },
        )
        .unwrap()
    }

    fn failing(report: &Report) -> Vec<String> {
        report
            .checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| format!("{}: {}", c.name, c.detail.clone().unwrap_or_default()))
            .collect()
    }

    /// Both verifiers agree, and when piggy refuses, one failing check's
    /// name contains `names_a_failure`.
    fn agree(
        root: &[u8],
        intermediates: &[&[u8]],
        leaf: &[u8],
        want_valid: bool,
        names_a_failure: &str,
    ) -> Report {
        let report = piggy_says(root, intermediates, leaf);
        let oracle = openssl_says(root, intermediates, leaf);
        assert_eq!(
            report.valid(),
            want_valid,
            "piggy: {:?}\nopenssl: {oracle:?}",
            failing(&report)
        );
        assert_eq!(oracle.is_ok(), want_valid, "openssl disagrees: {oracle:?}");
        if !want_valid {
            assert!(
                failing(&report).iter().any(|f| f.contains(names_a_failure)),
                "no failing check names {names_a_failure:?}: {:?}",
                failing(&report)
            );
        }
        report
    }

    #[test]
    fn the_profiles_chain_root_intermediate_leaf_verifies_and_lists_the_path() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let int_key = p256();
        let int_der = intermediate(
            &int_key,
            "piggy-test intermediate",
            &["github.com"],
            &root_der,
            &root_key,
            7,
        );
        let leaf_key = p256();
        let leaf_der = leaf(
            &leaf_key,
            &["github.com", "api.github.com", "codeload.github.com"],
            &int_der,
            &int_key,
        );
        let report = agree(&root_der, &[&int_der], &leaf_der, true, "");
        assert_eq!(
            report.path,
            [
                "CN=github.com",
                "CN=piggy-test intermediate",
                "CN=piggy-test root"
            ]
        );
        // Every check the FDR asks for is present and named.
        let checks: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();
        for want in [
            "a path from the leaf to the root",
            "the signature of the leaf by the untrusted #1",
            "the signature of the untrusted #1 by the root",
            "the signature of the root by the root",
            "the untrusted #1 is a CA (basicConstraints critical, CA:TRUE)",
            "the root's pathlen 1 admits 1 intermediate(s) below it",
            "the untrusted #1's pathlen 0 admits 0 intermediate(s) below it",
            "the leaf is not a CA",
            "the leaf's keyUsage has digitalSignature",
            "the leaf's extendedKeyUsage has serverAuth",
            "the leaf has a DNS subjectAltName",
            "the name constraints of the untrusted #1 admit the leaf's names",
            "the name constraints of the root admit the leaf's names",
        ] {
            assert!(checks.contains(&want), "missing {want:?} in {checks:?}");
        }
        // The pilot: the root signs the leaf directly, and the intermediate
        // may come in any order and position.
        let direct = leaf(&leaf_key, &["api.github.com"], &root_der, &root_key);
        agree(&root_der, &[], &direct, true, "");
        agree(&root_der, &[&int_der], &direct, true, "");
    }

    #[test]
    fn the_leafs_key_is_compared_when_asked() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let leaf_key = p256();
        let leaf_der = leaf(&leaf_key, &["github.com"], &root_der, &root_key);
        let same = verify_chain(
            &root_der,
            &[],
            &leaf_der,
            &Expect {
                at: now(),
                leaf_key_point: Some(&point(&leaf_key)),
            },
        )
        .unwrap();
        assert!(same.valid(), "{:?}", failing(&same));
        let other = verify_chain(
            &root_der,
            &[],
            &leaf_der,
            &Expect {
                at: now(),
                leaf_key_point: Some(&point(&p256())),
            },
        )
        .unwrap();
        assert!(!other.valid());
        assert!(failing(&other)[0].starts_with("the leaf's key is the given key"));
    }

    #[test]
    fn a_pathlen_that_is_exceeded_fails() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let int1_key = p256();
        let int1 = intermediate(
            &int1_key,
            "int one",
            &["github.com"],
            &root_der,
            &root_key,
            7,
        );
        let int2_key = p256();
        // pathlen 0 on int1 forbids int2; pathlen 1 on the root forbids two.
        let int2 = intermediate(&int2_key, "int two", &["github.com"], &int1, &int1_key, 7);
        let leaf_der = leaf(&p256(), &["github.com"], &int2, &int2_key);
        agree(&root_der, &[&int1, &int2], &leaf_der, false, "pathlen");
    }

    #[test]
    fn a_name_outside_the_constraint_fails_under_the_root_and_under_an_intermediate() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let foreign = leaf(&p256(), &["example.org"], &root_der, &root_key);
        agree(
            &root_der,
            &[],
            &foreign,
            false,
            "name constraints of the root",
        );
        // The same answer before signing: what the issuer refuses of a
        // profile's names.
        let refused =
            dns_names_refused_by(&root_der, &names(&["api.github.com", "example.org"])).unwrap();
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with(
                "example.org is not under a permitted DNS subtree (permitted: github.com)"
            ),
            "{refused:?}"
        );
        assert!(
            dns_names_refused_by(&root_der, &names(&["codeload.github.com"]))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            dns_names_refused_by(b"junk", &names(&["github.com"]))
                .unwrap_err()
                .which,
            "issuer"
        );
        let int_key = p256();
        let int_der = intermediate(&int_key, "int", &["github.com"], &root_der, &root_key, 7);
        let under = leaf(&p256(), &["github.com", "evil.example"], &int_der, &int_key);
        let report = agree(&root_der, &[&int_der], &under, false, "name constraints");
        assert!(
            failing(&report)
                .iter()
                .any(|f| f.contains("evil.example is not under a permitted DNS subtree")),
            "{:?}",
            failing(&report)
        );
    }

    #[test]
    fn a_name_in_an_excluded_subtree_fails() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let root_x = X509::from_der(&root_der).unwrap();
        let int_key = p256();
        let int_x = custom(&Custom {
            cn: "excluding intermediate",
            key: &int_key,
            issuer: Some((&root_x, &root_key)),
            exts: vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:TRUE,pathlen:0"),
                (Nid::KEY_USAGE, "critical,keyCertSign,cRLSign"),
                (
                    Nid::NAME_CONSTRAINTS,
                    "critical,permitted;DNS:github.com,excluded;DNS:evil.github.com",
                ),
            ],
            ..Default::default()
        });
        let int_der = int_x.to_der().unwrap();
        let bad = leaf(&p256(), &["evil.github.com"], &int_der, &int_key);
        agree(
            &root_der,
            &[&int_der],
            &bad,
            false,
            "name constraints of the untrusted #1",
        );
        let good = leaf(&p256(), &["api.github.com"], &int_der, &int_key);
        agree(&root_der, &[&int_der], &good, true, "");
    }

    #[test]
    fn an_expired_intermediate_fails_and_at_moves_the_clock() {
        let root_key = p256();
        // A root old enough to be valid at the earlier `at` below.
        let root_der = x509_profile::build_root_cert(
            &point(&root_key),
            PivAlgorithm::EcP256,
            "piggy-test root",
            &names(&["github.com"]),
            CertValidity {
                not_before: now() - Duration::from_secs(30 * DAY),
                not_after: now() + Duration::from_secs(3650 * DAY),
            },
            &[0x5A; 16],
            signer(&root_key),
        )
        .unwrap();
        let root_x = X509::from_der(&root_der).unwrap();
        let int_key = p256();
        let int_x = custom(&Custom {
            cn: "expired intermediate",
            key: &int_key,
            issuer: Some((&root_x, &root_key)),
            not_before: now().as_secs() as i64 - 10 * DAY as i64,
            not_after: now().as_secs() as i64 - 3 * DAY as i64,
            exts: vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:TRUE,pathlen:0"),
                (Nid::KEY_USAGE, "critical,keyCertSign,cRLSign"),
                (Nid::NAME_CONSTRAINTS, "critical,permitted;DNS:github.com"),
            ],
            ..Default::default()
        });
        let int_der = int_x.to_der().unwrap();
        // The leaf's own notAfter is clamped to the intermediate's by the
        // builder, so it is expired too: the point is that the check names
        // the intermediate as well.
        // The builder clamps a leaf's notAfter to the issuer's and refuses an
        // empty window, so this leaf lived while the intermediate did.
        let leaf_key = p256();
        let leaf_der = x509_profile::build_leaf_cert(
            &point(&leaf_key),
            PivAlgorithm::EcP256,
            &names(&["github.com"]),
            &int_der,
            CertValidity {
                not_before: now() - Duration::from_secs(10 * DAY),
                not_after: now() - Duration::from_secs(4 * DAY),
            },
            &[0x22; 16],
            signer(&int_key),
        )
        .unwrap();
        let report = agree(
            &root_der,
            &[&int_der],
            &leaf_der,
            false,
            "the untrusted #1 is valid at",
        );
        assert!(
            failing(&report)
                .iter()
                .any(|f| f.contains("the leaf is valid at"))
        );
        // Read a week ago, the same chain holds.
        let then = verify_chain(
            &root_der,
            &[&int_der],
            &leaf_der,
            &Expect {
                at: now() - Duration::from_secs(7 * DAY),
                leaf_key_point: None,
            },
        )
        .unwrap();
        assert!(then.valid(), "{:?}", failing(&then));
    }

    #[test]
    fn a_root_that_is_not_a_ca_fails() {
        let key = p256();
        let not_ca = custom(&Custom {
            cn: "not a CA",
            key: &key,
            // Self-signed through OpenSSL's builder: an AKI needs an issuer
            // certificate it does not have yet, so only the SKI (which the
            // leaf builder reads) is set, by hand.
            exts: vec![
                (Nid::KEY_USAGE, "critical,keyCertSign,cRLSign"),
                (Nid::SUBJECT_KEY_IDENTIFIER, "hash"),
            ],
            ski_aki: false,
            ..Default::default()
        });
        let root_der = not_ca.to_der().unwrap();
        // piggy's own builder refuses a non-CA issuer, so the oracle's
        // builder signs this leaf.
        let leaf_key = p256();
        let leaf_x = custom(&Custom {
            cn: "github.com",
            key: &leaf_key,
            issuer: Some((&not_ca, &key)),
            exts: vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "serverAuth"),
                (Nid::SUBJECT_ALT_NAME, "DNS:github.com"),
            ],
            ..Default::default()
        });
        let leaf_der = leaf_x.to_der().unwrap();
        // OpenSSL accepts a self-signed trust anchor with no
        // basicConstraints (observed: its verify answers OK here); piggy's
        // CA profile requires the critical CA:TRUE on every CA, the root
        // included, so the oracle is not consulted for this one.
        let report = piggy_says(&root_der, &[], &leaf_der);
        assert!(!report.valid());
        assert!(
            failing(&report)
                .iter()
                .any(|f| f.starts_with("the root is a CA")),
            "{:?}",
            failing(&report)
        );
    }

    #[test]
    fn a_leaf_that_is_a_ca_lacks_server_auth_or_has_no_san_fails_in_piggy() {
        // OpenSSL without a purpose accepts each of these; piggy's leaf
        // profile does not, so the oracle is not consulted here.
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let root_x = X509::from_der(&root_der).unwrap();
        let base = |cn: &'static str, exts: Vec<(Nid, &'static str)>| {
            let key = p256();
            let x = custom(&Custom {
                cn,
                key: &key,
                issuer: Some((&root_x, &root_key)),
                exts,
                ..Default::default()
            });
            x.to_der().unwrap()
        };
        let ca_leaf = base(
            "github.com",
            vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:TRUE,pathlen:0"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "serverAuth"),
                (Nid::SUBJECT_ALT_NAME, "DNS:github.com"),
            ],
        );
        let r = piggy_says(&root_der, &[], &ca_leaf);
        assert!(
            failing(&r)
                .iter()
                .any(|f| f.starts_with("the leaf is not a CA")),
            "{:?}",
            failing(&r)
        );

        let client_only = base(
            "github.com",
            vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "clientAuth"),
                (Nid::SUBJECT_ALT_NAME, "DNS:github.com"),
            ],
        );
        let r = piggy_says(&root_der, &[], &client_only);
        assert!(
            failing(&r)
                .iter()
                .any(|f| f.starts_with("the leaf's extendedKeyUsage has serverAuth")),
            "{:?}",
            failing(&r)
        );

        let no_san = base(
            "github.com",
            vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "serverAuth"),
            ],
        );
        let r = piggy_says(&root_der, &[], &no_san);
        assert!(
            failing(&r)
                .iter()
                .any(|f| f.starts_with("the leaf has a DNS subjectAltName")),
            "{:?}",
            failing(&r)
        );
        // The CN alone is still held to the constraint.
        let cn_outside = base(
            "evil.example",
            vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "serverAuth"),
                (Nid::SUBJECT_ALT_NAME, "DNS:github.com"),
            ],
        );
        let r = piggy_says(&root_der, &[], &cn_outside);
        assert!(
            failing(&r)
                .iter()
                .any(|f| f.contains("evil.example is not under a permitted DNS subtree")),
            "{:?}",
            failing(&r)
        );
    }

    #[test]
    fn a_non_critical_basic_constraints_on_a_ca_fails_in_piggy() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let root_x = X509::from_der(&root_der).unwrap();
        let int_key = p256();
        let lax = custom(&Custom {
            cn: "lax intermediate",
            key: &int_key,
            issuer: Some((&root_x, &root_key)),
            exts: vec![
                (Nid::BASIC_CONSTRAINTS, "CA:TRUE,pathlen:0"),
                (Nid::KEY_USAGE, "critical,keyCertSign,cRLSign"),
                (Nid::NAME_CONSTRAINTS, "critical,permitted;DNS:github.com"),
            ],
            ..Default::default()
        });
        let int_der = lax.to_der().unwrap();
        let leaf_der = leaf(&p256(), &["github.com"], &int_der, &int_key);
        let r = piggy_says(&root_der, &[&int_der], &leaf_der);
        assert!(
            failing(&r).iter().any(|f| f.contains(
                "is a CA (basicConstraints critical, CA:TRUE): basicConstraints not critical"
            )),
            "{:?}",
            failing(&r)
        );
    }

    #[test]
    fn an_ip_san_under_the_all_ip_exclusion_fails() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let root_x = X509::from_der(&root_der).unwrap();
        let key = p256();
        let with_ip = custom(&Custom {
            cn: "github.com",
            key: &key,
            issuer: Some((&root_x, &root_key)),
            exts: vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "serverAuth"),
                (Nid::SUBJECT_ALT_NAME, "DNS:github.com,IP:127.0.0.1"),
            ],
            ..Default::default()
        });
        let der = with_ip.to_der().unwrap();
        let report = agree(&root_der, &[], &der, false, "name constraints of the root");
        assert!(
            failing(&report)
                .iter()
                .any(|f| f.contains("127.0.0.1 is in an excluded IP subtree")),
            "{:?}",
            failing(&report)
        );
    }

    #[test]
    fn an_unknown_critical_extension_fails() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let root_x = X509::from_der(&root_der).unwrap();
        let key = p256();
        let odd = custom(&Custom {
            cn: "github.com",
            key: &key,
            issuer: Some((&root_x, &root_key)),
            exts: vec![
                (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                (Nid::KEY_USAGE, "critical,digitalSignature"),
                (Nid::EXT_KEY_USAGE, "serverAuth"),
                (Nid::SUBJECT_ALT_NAME, "DNS:github.com"),
            ],
            odd_critical: true,
            ..Default::default()
        });
        let der = odd.to_der().unwrap();
        agree(
            &root_der,
            &[],
            &der,
            false,
            "no unknown critical extension in the leaf",
        );
    }

    #[test]
    fn a_missing_issuer_or_a_tampered_signature_fails_and_junk_is_a_parse_error() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com"]);
        let other_root = root(&p256(), &["github.com"]);
        let leaf_der = leaf(&p256(), &["github.com"], &root_der, &root_key);
        // Another root with the same name: the key id does not match, so
        // there is no path (and OpenSSL fails the signature instead).
        let r = piggy_says(&other_root, &[], &leaf_der);
        assert!(!r.valid());
        assert!(
            failing(&r)[0].starts_with("a path from the leaf to the root"),
            "{:?}",
            failing(&r)
        );
        assert!(openssl_says(&other_root, &[], &leaf_der).is_err());

        // A flipped byte in the leaf's signature.
        let mut tampered = leaf_der.clone();
        let at = tampered.len() - 5;
        tampered[at] ^= 0x01;
        let r = piggy_says(&root_der, &[], &tampered);
        assert!(
            failing(&r)
                .iter()
                .any(|f| f.starts_with("the signature of the leaf by the root")),
            "{:?}",
            failing(&r)
        );

        let expect = Expect {
            at: now(),
            leaf_key_point: None,
        };
        let err = verify_chain(&root_der, &[], b"not a certificate", &expect).unwrap_err();
        assert_eq!(err.which, "leaf");
        let err = verify_chain(b"", &[], &leaf_der, &expect).unwrap_err();
        assert_eq!(err.which, "root");
        let err = verify_chain(&root_der, &[b"x"], &leaf_der, &expect).unwrap_err();
        assert_eq!(err.which, "untrusted #1");
    }

    #[test]
    fn dns_and_ip_subtrees_match_as_rfc_5280_says() {
        assert!(dns_in_subtree("github.com", "github.com"));
        assert!(dns_in_subtree("api.GitHub.com", "github.com"));
        assert!(dns_in_subtree("a.b.github.com", "github.com"));
        assert!(!dns_in_subtree("notgithub.com", "github.com"));
        assert!(!dns_in_subtree("github.com.evil", "github.com"));
        assert!(!dns_in_subtree("com", "github.com"));
        assert!(dns_in_subtree("api.github.com", ".github.com"));
        assert!(!dns_in_subtree("github.com", ".github.com"));
        assert!(ip_in_subtree(&[127, 0, 0, 1], &[0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(ip_in_subtree(
            &[10, 1, 2, 3],
            &[10, 1, 0, 0, 255, 255, 0, 0]
        ));
        assert!(!ip_in_subtree(
            &[10, 2, 2, 3],
            &[10, 1, 0, 0, 255, 255, 0, 0]
        ));
        assert!(
            !ip_in_subtree(&[127, 0, 0, 1], &[0u8; 32]),
            "a v4 address is not in a v6 subtree"
        );
        assert!(ip_in_subtree(&[0u8; 16], &[0u8; 32]));
    }

    #[test]
    fn describe_reads_the_roots_fields_back_as_openssl_prints_them() {
        let root_key = p256();
        let root_der = root(&root_key, &["github.com", "api.github.com"]);
        let d = describe(&root_der).unwrap();
        assert_eq!(d.subject, "CN=piggy-test root");
        assert_eq!(d.issuer, d.subject);
        assert!(d.self_issued);
        assert_eq!(d.serial_hex, "5a".repeat(16));
        assert_eq!(d.basic_constraints, Some((true, true, Some(1))));
        assert_eq!(d.key_usage, ["keyCertSign", "cRLSign"]);
        assert!(d.extended_key_usage.is_empty() && d.dns_names.is_empty());
        assert_eq!(d.permitted, ["DNS:github.com", "DNS:api.github.com"]);
        assert_eq!(
            d.excluded,
            ["IP:0.0.0.0/0.0.0.0", "IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0"]
        );
        assert_eq!(d.key.as_ref().map(|(a, _)| *a), Some(PivAlgorithm::EcP256));
        assert_eq!(d.key.as_ref().unwrap().1, point(&root_key));
        assert_eq!(d.ski_hex, d.aki_hex);
        assert!(d.ski_hex.as_ref().is_some_and(|s| s.len() == 40));
        assert!(d.unknown_critical.is_empty());
        let x = X509::from_der(&root_der).unwrap();
        assert_eq!(
            d.sha256_hex,
            hex::encode(x.digest(MessageDigest::sha256()).unwrap())
        );
        assert!(
            d.not_before.ends_with('Z') && d.not_after.ends_with('Z'),
            "{} {}",
            d.not_before,
            d.not_after
        );

        let leaf_der = leaf(
            &p256(),
            &["github.com", "api.github.com"],
            &root_der,
            &root_key,
        );
        let l = describe(&leaf_der).unwrap();
        assert_eq!(l.subject, "CN=github.com");
        assert_eq!(l.issuer, "CN=piggy-test root");
        assert!(!l.self_issued);
        assert_eq!(l.basic_constraints, Some((true, false, None)));
        assert_eq!(l.key_usage, ["digitalSignature"]);
        assert_eq!(l.extended_key_usage, ["serverAuth"]);
        assert_eq!(l.dns_names, ["github.com", "api.github.com"]);
        assert_eq!(l.aki_hex, d.ski_hex);
        assert!(describe(b"nope").is_err());
    }
}
