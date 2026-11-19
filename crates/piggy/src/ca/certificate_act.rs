//! The `piggy-certificate-v1` act every card-signed certificate leaves in
//! the ledger (piggy RFC 0012 §3.2, RFC 0013; FDR 0007 phase (ii), the
//! operator's ruling of 2026-11-17): the certificate is signed by the CA
//! slot, the act by the same card's slot 9C through the agent's
//! `operator-act@piggy` under the `certificate` banner, so the ledger
//! records that the operator touched for it. Shared by `root-cert` (a
//! `root` act) and `sign`/`issue` (a card `link`).
//!
//! Order, and why: ECDSA signatures are not deterministic and the act names
//! the digest of the signed certificate's DER, so the act cannot exist
//! before the certificate does. A verb therefore checks everything the act
//! will need before the first PIN prompt ([`preflight`]: the certified key
//! type, the output path, the agent, the card's 9C key), signs the
//! certificate, builds the act from the certificate itself ([`plan`]),
//! seals it through the agent ([`seal_and_write`]: the second PIN and
//! touch), and only then writes the certificate. An act that is not sealed
//! means the certificate is dropped: a certificate without its act exists
//! only when something other than piggy signed it (§3.2).
//!
//! Every field is read from the certificate, never restated from the
//! profile: `subject-key` from the SPKI, `right` from basicConstraints
//! (`piggy:x509-ca` for a CA, `piggy:x509-leaf` otherwise), `not-after`
//! from `notAfter`, `records` from the DER's SHA-256. The description line
//! repeats the words the first prompt showed and adds the DER's SHA-256 in
//! hex, so the operator reads the same certificate twice and can check the
//! hex against `openssl x509 -outform DER | sha256sum`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use piggy_markl::{FormatId, Id, PurposeId};
use piggy_piv::x509_profile::{self, CertificateFacts};
use piggy_piv::{KeyPolicy, PivAlgorithm};
use sha2::{Digest, Sha256};

use piggy::act::produce::{SealError, check_before_signing, seal_act};
use piggy::act::seal::{DigestFormat, act_digest, public_key_blob};
use piggy::act::verify::timestamp;
use piggy::act::{Act, parse};
use piggy::agent_client::{probe_ecdsa_points, probe_extensions};
use piggy::card::slot_policy::{OperatorActBlocker, operator_act_verdict};
use piggy::operator_act::EXTENSION;

use super::card_signer::CardSigner;
use super::{Exit, Failure, failure};

/// RFC 0012 §3's namespace for a card-signed certificate.
pub(crate) const NAMESPACE: &str = "piggy-certificate-v1";
/// RFC 0013 `producer`: the program that built the act.
pub(crate) const PRODUCER: &str = "piggy:ca";
/// The `right` of a certificate with the CA basic constraint (§3.2).
pub(crate) const RIGHT_CA: &str = "piggy:x509-ca";
/// The `right` of any other certificate (§3.2).
pub(crate) const RIGHT_LEAF: &str = "piggy:x509-leaf";

/// How long the agent gets to answer the two probes that need no human.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The act's `kind`: a self-signed root, or a card `link` for every other
/// certificate the card signs (an intermediate, or a leaf under the root).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertifiedAs {
    Root,
    Link,
}

impl CertifiedAs {
    fn kind(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Link => "link",
        }
    }
}

/// The card's operator-act key (slot 9C) in the three spellings the act
/// and the agent need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorKey {
    /// `piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…`, the act's `key`.
    pub id: String,
    /// The sshsig `publickey` blob, what the agent matches by equality.
    pub blob: Vec<u8>,
    /// SEC1 uncompressed, what the agent lists.
    pub point: Vec<u8>,
}

impl OperatorKey {
    /// From the slot's key as a SEC1 point (compressed or not).
    pub(crate) fn from_p256_point(point: &[u8]) -> Result<Self, String> {
        let compressed = compressed_p256(point)?;
        let id = Id::new(
            Some(PurposeId::PiggyPivSigV1),
            FormatId::SshEcdsaNistp256Pub,
            compressed,
        )
        .map_err(|e| e.to_string())?;
        let blob = public_key_blob(&id).map_err(|r| r.detail)?;
        Ok(OperatorKey {
            id: id.to_wire(),
            blob,
            point: uncompressed_p256(point)?,
        })
    }
}

fn compressed_p256(point: &[u8]) -> Result<Vec<u8>, String> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    p256::PublicKey::from_sec1_bytes(point)
        .map(|k| k.to_encoded_point(true).as_bytes().to_vec())
        .map_err(|_| "the key is not a point on P-256".to_string())
}

fn uncompressed_p256(point: &[u8]) -> Result<Vec<u8>, String> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    p256::PublicKey::from_sec1_bytes(point)
        .map(|k| k.to_encoded_point(false).as_bytes().to_vec())
        .map_err(|_| "the key is not a point on P-256".to_string())
}

/// What [`preflight`] established: the key that will seal, the agent that
/// serves it, and where the act goes.
#[derive(Debug, Clone)]
pub(crate) struct Operator {
    pub key: OperatorKey,
    pub socket: PathBuf,
    pub act_out: PathBuf,
}

/// Where the act lands: `--act-out`, else the PEM's path with `.act`
/// appended, else a usage error, since stdout carries the PEM alone and
/// the act has to land somewhere.
pub(crate) fn act_out_path(
    out: Option<&Path>,
    act_out: Option<PathBuf>,
) -> Result<PathBuf, Failure> {
    match (act_out, out) {
        (Some(path), _) => Ok(path),
        (None, Some(out)) => {
            let mut name = out.as_os_str().to_owned();
            name.push(".act");
            Ok(PathBuf::from(name))
        }
        (None, None) => Err(failure(Exit::Usage)(
            "the certificate act has to land somewhere: pass --act-out FILE when the PEM goes to stdout (RFC 0012 §3.2)"
                .into(),
        )),
    }
}

/// RFC 0013 §2 admits only P-256 (and Ed25519) as a `subject-key`, so a
/// P-384 certificate can have no act; it is refused before any prompt.
pub(crate) fn check_certified_key(algorithm: PivAlgorithm) -> Result<(), Failure> {
    if algorithm == PivAlgorithm::EcP256 {
        Ok(())
    } else {
        Err(failure(Exit::Refused)(format!(
            "the certificate act cannot name a {algorithm:?} key: RFC 0013 §2 admits ssh_ecdsa_nistp256_pub only, so FDR 0007 issues P-256"
        )))
    }
}

/// Whether the card's 9C key, attested with `attested` (`None`: the card
/// did not attest it), can seal an act: the verdict `piggy health` and
/// `card init` give, so the three cannot disagree. The agent applies RFC
/// 0012 §2.4 at the second prompt; this says no before the first, while
/// the certificate signature is still unspent.
pub(crate) fn operator_key_verdict(attested: Option<KeyPolicy>, card: &str) -> Result<(), Failure> {
    let unavailable = failure(Exit::IssuerUnavailable);
    match operator_act_verdict(attested) {
        Ok(()) => Ok(()),
        Err(OperatorActBlocker::Policy(policy)) => Err(unavailable(format!(
            "card {card}'s slot-9C key is attested {policy}, not PIN always, touch always: the agent would refuse the certificate act (RFC 0012 §2.4), so nothing is signed"
        ))),
        Err(OperatorActBlocker::Unattested) => Err(unavailable(format!(
            "card {card} cannot attest its 9C key: the agent would refuse the certificate act (RFC 0012 §2.4), so nothing is signed"
        ))),
    }
}

/// The checks that need no card, run before the card is opened so a taken
/// path is refused with nothing else looked for: `act_out` does not exist
/// and its directory does (the act is created exclusively, never over an
/// earlier one), and `pem_out`'s directory exists when the PEM goes to a
/// file. Exit 1.
pub(crate) fn precheck(act_out: &Path, pem_out: Option<&Path>) -> Result<(), Failure> {
    check_act_out(act_out)?;
    if let Some(pem) = pem_out {
        check_output_dir(pem)?;
    }
    Ok(())
}

/// The slot's attested policy as [`operator_key_verdict`] judges it: a
/// card that cannot attest the slot (no F9 key, not a YubiKey, an APDU
/// error) attests nothing, which the verdict refuses.
pub(crate) fn attested_policy(
    read: Result<(piggy_piv::PinPolicy, piggy_piv::TouchPolicy), piggy_piv::PivError>,
) -> Option<KeyPolicy> {
    read.ok().map(|(pin, touch)| KeyPolicy { pin, touch })
}

/// Everything the act will need from the card and the agent, checked
/// after the card's attestation and before the first PIN prompt, so a
/// missing agent never costs a card signature: the certified key is P-256;
/// an agent socket is set, the agent answers and serves
/// `operator-act@piggy`; the card holds a 9C key attested PIN always and
/// touch always; the agent lists it. Each failure names what is missing;
/// the agent and card ones are exit 6 ("no agent serving the key", "the
/// slot's key is not proven"). The path checks are [`precheck`], run
/// before the card is opened.
pub(crate) fn preflight(
    signer: &CardSigner,
    certified: PivAlgorithm,
    act_out: PathBuf,
) -> Result<Operator, Failure> {
    check_certified_key(certified)?;
    let unavailable = failure(Exit::IssuerUnavailable);
    let socket = super::agent_socket().map_err(|e| {
        unavailable(format!(
            "{e}; the certificate act (RFC 0012 §3.2) is signed through the agent that serves the card's slot 9C"
        ))
    })?;
    let extensions = probe_extensions(&socket, PROBE_TIMEOUT)
        .map_err(|e| unavailable(format!("the agent at {}: {e}", socket.display())))?;
    if !extensions.iter().any(|name| name == EXTENSION) {
        return Err(unavailable(format!(
            "the agent at {} does not serve {EXTENSION}; the certificate act (RFC 0012 §3.2) needs piggy agent with the card",
            socket.display()
        )));
    }
    let key = signer.operator_act_key()?;
    let points = probe_ecdsa_points(&socket, PROBE_TIMEOUT)
        .map_err(|e| unavailable(format!("the agent at {}: {e}", socket.display())))?;
    if !points.iter().any(|p| *p == key.point) {
        return Err(unavailable(format!(
            "the agent at {} does not list card {}'s slot-9C key; is that card the one the agent serves?",
            socket.display(),
            signer.card_label()
        )));
    }
    Ok(Operator {
        key,
        socket,
        act_out,
    })
}

fn check_act_out(path: &Path) -> Result<(), Failure> {
    if path.exists() {
        return Err(failure(Exit::Refused)(format!(
            "{} exists; an act is never written over another (pass another --act-out)",
            path.display()
        )));
    }
    check_output_dir(path)
}

/// The directory an output file would be created in exists. Checked before
/// any prompt: a write that fails after the signatures would leave an act
/// with no certificate, or cost the operator two prompts for nothing.
fn check_output_dir(path: &Path) -> Result<(), Failure> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if !dir.is_dir() {
        return Err(failure(Exit::Refused)(format!(
            "{}: the directory for {} does not exist",
            dir.display(),
            path.display()
        )));
    }
    Ok(())
}

/// The sha256 `piggy-record-digest-v1` markl-id of `der`, the act's
/// `records` entry (§3.2), and the same digest in hex for the description.
pub(crate) fn certificate_record(der: &[u8]) -> (String, String) {
    let digest = Sha256::digest(der);
    let id = Id::new(
        Some(PurposeId::PiggyRecordDigestV1),
        FormatId::Sha256,
        digest.to_vec(),
    )
    .expect("a 32-byte sha256 under its own purpose");
    (id.to_wire(), hex::encode(digest))
}

/// Build the unsealed act for the signed certificate `cert_der`, every
/// field from the certificate; `subject` is the profile's principal,
/// `describing` the words the first prompt showed, `now` the Unix time of
/// signing. A certificate that is not what `kind` says (a `root` over a
/// certificate that is not a self-signed CA, a `link` over one that is
/// self-signed) is refused, as is an act RFC 0013 would refuse.
pub(crate) fn plan(
    cert_der: &[u8],
    subject: &str,
    kind: CertifiedAs,
    operator: &OperatorKey,
    now: u64,
    describing: &str,
) -> Result<Act, Failure> {
    let refuse = failure(Exit::Refused);
    let facts = x509_profile::inspect(cert_der)
        .map_err(|e| refuse(format!("the signed certificate does not read back: {e}")))?;
    check_certified_key(facts.algorithm)?;
    check_kind(kind, &facts)?;
    let subject_key = Id::new(
        Some(PurposeId::PiggyPrincipalPubV1),
        FormatId::SshEcdsaNistp256Pub,
        compressed_p256(&facts.pubkey_point).map_err(|e| refuse(e))?,
    )
    .map_err(|e| refuse(e.to_string()))?
    .to_wire();
    let right = if facts.is_ca { RIGHT_CA } else { RIGHT_LEAF };
    let (record, hex) = certificate_record(cert_der);
    let key = &operator.id;
    let doc = format!(
        "---\n# {describing}; DER sha256 {hex}\n- kind = {kind}\n- producer = {PRODUCER}\n\
         - subject = {subject}\n- subject-key = {subject_key}\n- issuer = operator\n\
         - issuer-key = {key}\n- right = {right}\n- records = {record}\n\
         - not-after = {not_after}\n- issued-at = {issued_at}\n- assurance = piggy:hardware\n\
         - key = {key}\n- namespace = {NAMESPACE}\n- hash = sha256\n! piggy-act-v1\n---\n",
        kind = kind.kind(),
        not_after = timestamp(facts.not_after.as_secs()),
        issued_at = timestamp(now),
    );
    let act = parse(doc.as_bytes()).map_err(|r| {
        refuse(format!(
            "the certificate act does not pass RFC 0013 ({r}); nothing is written"
        ))
    })?;
    check_before_signing(&act).map_err(|e| refuse(e.message().to_owned()))?;
    Ok(act)
}

fn check_kind(kind: CertifiedAs, facts: &CertificateFacts) -> Result<(), Failure> {
    let refuse = failure(Exit::Refused);
    match kind {
        CertifiedAs::Root if !(facts.is_ca && facts.self_issued) => Err(refuse(
            "a root act names a self-signed CA certificate; the signed certificate is not one".into(),
        )),
        CertifiedAs::Link if facts.self_issued => Err(refuse(
            "a link act names a certificate signed by its issuer; the signed certificate is self-signed"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// Seal `act` through the agent (the second PIN and touch, under the
/// `certificate` banner) and write it to the operator's `act_out`, created
/// exclusively. The act digest, for the verb's notice. An act that is not
/// sealed or not written is the certificate dropped: exit 1 when the agent
/// refused, 6 when it is gone, the operator cancelled or the card left.
pub(crate) fn seal_and_write(act: &Act, operator: &Operator) -> Result<String, Failure> {
    let sealed = seal_act(act, &operator.socket).map_err(|e| {
        let exit = match &e {
            SealError::Refused(_) => Exit::Refused,
            SealError::NotServed(_) | SealError::Retryable(_) => Exit::IssuerUnavailable,
        };
        failure(exit)(format!(
            "the certificate act was not sealed ({}); the card's signature over the certificate was made and is dropped, nothing is written",
            e.message()
        ))
    })?;
    write_act(&sealed, &operator.act_out)
}

/// Write a sealed act to `path`, created exclusively; its blake2b256 act
/// digest (RFC 0013 §3.5).
pub(crate) fn write_act(sealed: &Act, path: &Path) -> Result<String, Failure> {
    let refuse = failure(Exit::Refused);
    let bytes = sealed
        .sealed_canonical()
        .ok_or_else(|| refuse("the act carries no signature".into()))?;
    let digest = act_digest(sealed, DigestFormat::Blake2b256)
        .ok_or_else(|| refuse("the act carries no signature".into()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(&bytes).and_then(|()| f.flush()))
        .map_err(|e| {
            refuse(format!(
                "write the act {}: {e}; the certificate is dropped with it",
                path.display()
            ))
        })?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use p256::ecdsa::signature::Signer as _;
    use piggy::act::parsed_bytes;
    use piggy::act::seal::verify_seal;
    use piggy::act::store::MemoryStore;
    use piggy::act::verify::{Options, Verifier};
    use piggy::operator_act::{HashAlgorithm, signed_data};
    use piggy_piv::x509_profile::{CertValidity, build_leaf_cert, build_root_cert};

    use super::super::root_cert::{SERIAL_BYTES, issue_root, plan_root};
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const GUID: &str = "0123456789abcdef0123456789abcdef";

    /// A software P-256 key standing in for a card slot.
    struct SoftKey {
        sk: p256::ecdsa::SigningKey,
        point: Vec<u8>,
    }

    fn soft_key(seed: u8) -> SoftKey {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        SoftKey { sk, point }
    }

    /// The card's DER ECDSA signature over a prehash, as the slot gives it.
    fn sign_der(key: &SoftKey) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, piggy_piv::PivError> + '_ {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        move |digest| {
            let sig: p256::ecdsa::Signature = key
                .sk
                .sign_prehash(digest)
                .map_err(|e| piggy_piv::PivError::Other(e.to_string()))?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }

    fn root_profile() -> piggy::ca_profile::Profile {
        piggy::ca_profile::parse(&format!(
            "kind = \"root\"\ncommon_name = \"shithub root\"\nnames = [\"github.com\", \"api.github.com\"]\nlifetime_hours = 87600\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        ))
        .unwrap()
    }

    fn software_root(ca: &SoftKey) -> (Vec<u8>, String) {
        let plan = plan_root(
            &root_profile(),
            Duration::from_secs(NOW),
            [0x42; SERIAL_BYTES],
        )
        .unwrap();
        let der = issue_root(&plan, &ca.point, PivAlgorithm::EcP256, sign_der(ca)).unwrap();
        (der, plan.describe())
    }

    /// Seal a card act with a software key spelled as the card's 9C key:
    /// the walk judges keys by the anchor set, not by the hardware.
    fn seal_in_software(act: &Act, operator: &SoftKey) -> Act {
        let data = signed_data(NAMESPACE, HashAlgorithm::Sha256, &act.canonical());
        let sig: p256::ecdsa::Signature = operator.sk.sign(&data);
        let sig = sig.normalize_s().unwrap_or(sig);
        let id = Id::new(
            Some(PurposeId::PiggyRecordSigV1),
            FormatId::EcdsaP256Sig,
            sig.to_bytes().to_vec(),
        )
        .unwrap();
        act.with_signature(&id)
    }

    #[test]
    fn the_operator_key_has_the_three_spellings_of_one_point() {
        let k = soft_key(1);
        let key = OperatorKey::from_p256_point(&k.point).unwrap();
        assert!(
            key.id
                .starts_with("piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-")
        );
        assert_eq!(key.point, k.point, "uncompressed, as the agent lists it");
        assert_eq!(key.blob.len(), 4 + 19 + 4 + 8 + 4 + 65);
        // A compressed point gives the same key.
        let compressed = compressed_p256(&k.point).unwrap();
        assert_eq!(OperatorKey::from_p256_point(&compressed).unwrap(), key);
        assert!(OperatorKey::from_p256_point(&[4u8; 65]).is_err());
    }

    #[test]
    fn a_root_act_reads_everything_from_the_certificate() {
        let ca = soft_key(2);
        let operator = OperatorKey::from_p256_point(&soft_key(3).point).unwrap();
        let (der, describing) = software_root(&ca);
        let act = plan(
            &der,
            "piggy:ca:shithub",
            CertifiedAs::Root,
            &operator,
            NOW,
            &describing,
        )
        .unwrap();

        assert_eq!(act.text("kind"), Some("root"));
        assert_eq!(act.text("producer"), Some(PRODUCER));
        assert_eq!(act.text("subject"), Some("piggy:ca:shithub"));
        assert_eq!(act.text("issuer"), Some("operator"));
        assert_eq!(act.text("assurance"), Some("piggy:hardware"));
        assert_eq!(act.text("namespace"), Some(NAMESPACE));
        assert_eq!(act.text("hash"), Some("sha256"));
        assert_eq!(
            act.field("key").map(parsed_bytes).as_deref(),
            Some(operator.id.as_str())
        );
        assert_eq!(
            act.field("issuer-key").map(parsed_bytes),
            act.field("key").map(parsed_bytes)
        );

        let rights: Vec<String> = act.values("right").map(parsed_bytes).collect();
        assert_eq!(rights, [RIGHT_CA], "a CA certificate");

        // subject-key is the certificate's key, compressed, as a principal key.
        let expected = Id::new(
            Some(PurposeId::PiggyPrincipalPubV1),
            FormatId::SshEcdsaNistp256Pub,
            compressed_p256(&ca.point).unwrap(),
        )
        .unwrap()
        .to_wire();
        assert_eq!(
            act.field("subject-key").map(parsed_bytes).as_deref(),
            Some(expected.as_str())
        );

        // records is the DER's sha256, recomputed here, and the hex is on
        // the description line beside the first prompt's words.
        let (record, hex) = certificate_record(&der);
        let records: Vec<String> = act.values("records").map(parsed_bytes).collect();
        assert_eq!(records, [record.clone()]);
        assert!(record.starts_with("piggy-record-digest-v1@sha256-"));
        assert_eq!(hex, hex::encode(Sha256::digest(&der)));
        let description = act.description().unwrap();
        assert!(description.contains(&describing), "{description}");
        assert!(
            description.ends_with(&format!("DER sha256 {hex}")),
            "{description}"
        );

        // not-after is the certificate's notAfter, exactly.
        let facts = x509_profile::inspect(&der).unwrap();
        assert_eq!(
            act.text("not-after"),
            Some(timestamp(facts.not_after.as_secs()).as_str())
        );
        assert_eq!(act.text("issued-at"), Some(timestamp(NOW).as_str()));
        assert!(act.field("not-before").is_none() && act.field("nonce").is_none());
        assert!(act.field("profile").is_none() && act.field("signature").is_none());
    }

    #[test]
    fn the_sealed_act_verifies_under_the_card_as_anchor_and_names_the_der() {
        let ca = soft_key(4);
        let card = soft_key(5);
        let operator = OperatorKey::from_p256_point(&card.point).unwrap();
        let (der, describing) = software_root(&ca);
        let act = plan(
            &der,
            "piggy:ca:shithub",
            CertifiedAs::Root,
            &operator,
            NOW,
            &describing,
        )
        .unwrap();
        let sealed = seal_in_software(&act, &card);

        verify_seal(&sealed).unwrap();
        let verifier = Verifier::new(
            MemoryStore::new(),
            Options {
                at: timestamp(NOW + 60),
                anchors: BTreeSet::from([operator.id.clone()]),
                revocation_source: false,
            },
        );
        let outcome = verifier.verify(&sealed);
        assert!(outcome.is_valid(), "{outcome:?}");

        // A verifier holding the certificate recomputes the digest (§3.2)
        // and checks not-after against notAfter.
        let (record, _) = certificate_record(&der);
        assert!(sealed.values("records").any(|v| parsed_bytes(v) == record));
        let facts = x509_profile::inspect(&der).unwrap();
        assert!(sealed.text("not-after").unwrap() <= timestamp(facts.not_after.as_secs()).as_str());

        // Written exclusively: the second write of the same path is refused.
        let dir = std::env::temp_dir().join(format!("piggy-cert-act-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("root.act");
        let digest = write_act(&sealed, &path).unwrap();
        assert!(digest.starts_with("piggy-record-digest-v1@blake2b256-"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            sealed.sealed_canonical().unwrap()
        );
        let again = write_act(&sealed, &path).unwrap_err();
        assert_eq!(again.exit, Exit::Refused);
        assert!(again.message.contains("dropped"), "{}", again.message);
        let taken = check_act_out(&path).unwrap_err();
        assert!(taken.message.contains("exists"), "{}", taken.message);
        assert!(check_act_out(&dir.join("missing-dir").join("x.act")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_link_act_over_a_leaf_carries_the_leaf_right() {
        let ca = soft_key(6);
        let leaf = soft_key(7);
        let operator = OperatorKey::from_p256_point(&soft_key(8).point).unwrap();
        let (root_der, _) = software_root(&ca);
        let names = vec!["github.com".to_string()];
        let leaf_der = build_leaf_cert(
            &leaf.point,
            PivAlgorithm::EcP256,
            &names,
            &root_der,
            CertValidity {
                not_before: Duration::from_secs(NOW - 300),
                not_after: Duration::from_secs(NOW + 720 * 3600),
            },
            &[7; 16],
            sign_der(&ca),
        )
        .unwrap();
        let act = plan(
            &leaf_der,
            "shithub:proxy",
            CertifiedAs::Link,
            &operator,
            NOW,
            "the leaf",
        )
        .unwrap();
        assert_eq!(act.text("kind"), Some("link"));
        let rights: Vec<String> = act.values("right").map(parsed_bytes).collect();
        assert_eq!(rights, [RIGHT_LEAF]);

        // The kind must match the certificate.
        let wrong = plan(
            &leaf_der,
            "shithub:proxy",
            CertifiedAs::Root,
            &operator,
            NOW,
            "x",
        )
        .unwrap_err();
        assert_eq!(wrong.exit, Exit::Refused);
        let wrong = plan(
            &root_der,
            "piggy:ca:x",
            CertifiedAs::Link,
            &operator,
            NOW,
            "x",
        )
        .unwrap_err();
        assert_eq!(wrong.exit, Exit::Refused);
    }

    /// The 9C policy is judged before the first prompt with health's
    /// verdict, so a card whose 9C the agent would refuse at the second
    /// prompt never spends a certificate signature.
    #[test]
    fn a_9c_key_the_agent_would_refuse_is_refused_before_the_first_prompt() {
        use piggy_piv::{PinPolicy, TouchPolicy};
        assert!(operator_key_verdict(Some(KeyPolicy::OPERATOR_ACT), "c1").is_ok());
        let weak = operator_key_verdict(
            Some(KeyPolicy {
                pin: PinPolicy::Always,
                touch: TouchPolicy::Cached,
            }),
            "c1",
        )
        .unwrap_err();
        assert_eq!(weak.exit, Exit::IssuerUnavailable);
        assert!(
            weak.message.contains("touch cached") && weak.message.contains("RFC 0012"),
            "{}",
            weak.message
        );
        let unattested = operator_key_verdict(None, "c1").unwrap_err();
        assert_eq!(unattested.exit, Exit::IssuerUnavailable);
        assert!(
            unattested.message.contains("cannot attest"),
            "{}",
            unattested.message
        );

        // A slot-policy read that errors (the card cannot attest) is the
        // unattested verdict, never a pass.
        assert_eq!(
            attested_policy(Err(piggy_piv::PivError::Other("SW 6D00".into()))),
            None
        );
        assert_eq!(
            attested_policy(Ok((PinPolicy::Always, TouchPolicy::Always))),
            Some(KeyPolicy::OPERATOR_ACT)
        );
        let errored = operator_key_verdict(
            attested_policy(Err(piggy_piv::PivError::Other("SW 6D00".into()))),
            "c1",
        )
        .unwrap_err();
        assert_eq!(errored.exit, Exit::IssuerUnavailable);
    }

    #[test]
    fn the_path_checks_run_without_a_card() {
        let dir = std::env::temp_dir().join(format!("piggy-cert-pre-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(precheck(&dir.join("root.act"), Some(&dir.join("root.pem"))).is_ok());
        assert!(precheck(&dir.join("root.act"), None).is_ok());
        std::fs::write(dir.join("taken.act"), b"x").unwrap();
        assert_eq!(
            precheck(&dir.join("taken.act"), None).unwrap_err().exit,
            Exit::Refused
        );
        assert_eq!(
            precheck(
                &dir.join("root.act"),
                Some(&dir.join("nodir").join("root.pem"))
            )
            .unwrap_err()
            .exit,
            Exit::Refused
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_pems_directory_is_checked_before_any_prompt_too() {
        let dir = std::env::temp_dir().join(format!("piggy-cert-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(check_output_dir(&dir.join("root.pem")).is_ok());
        assert!(
            check_output_dir(Path::new("root.pem")).is_ok(),
            "the working directory"
        );
        let missing = check_output_dir(&dir.join("nodir").join("root.pem")).unwrap_err();
        assert_eq!(missing.exit, Exit::Refused);
        assert!(
            missing.message.contains("nodir") && missing.message.contains("root.pem"),
            "{}",
            missing.message
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_p384_key_has_no_act_and_is_refused_before_anything() {
        assert!(check_certified_key(PivAlgorithm::EcP256).is_ok());
        let err = check_certified_key(PivAlgorithm::EcP384).unwrap_err();
        assert_eq!(err.exit, Exit::Refused);
        assert!(
            err.message.contains("P-384") || err.message.contains("EcP384"),
            "{}",
            err.message
        );

        // And a P-384 certificate that somehow got signed gets no act either.
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        let group = EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let der = build_root_cert(
            &point,
            PivAlgorithm::EcP384,
            "p384 root",
            &["github.com".to_string()],
            CertValidity {
                not_before: Duration::from_secs(NOW - 300),
                not_after: Duration::from_secs(NOW + 3600),
            },
            &[9; 16],
            |digest| {
                Ok(openssl::ecdsa::EcdsaSig::sign(digest, &key)
                    .unwrap()
                    .to_der()
                    .unwrap())
            },
        )
        .unwrap();
        let operator = OperatorKey::from_p256_point(&soft_key(9).point).unwrap();
        let err = plan(&der, "piggy:ca:x", CertifiedAs::Root, &operator, NOW, "x").unwrap_err();
        assert_eq!(err.exit, Exit::Refused);
    }

    #[test]
    fn a_subject_that_is_not_a_bare_word_is_refused_by_the_act_rules() {
        let ca = soft_key(10);
        let operator = OperatorKey::from_p256_point(&soft_key(11).point).unwrap();
        let (der, describing) = software_root(&ca);
        let err = plan(
            &der,
            "not bare",
            CertifiedAs::Root,
            &operator,
            NOW,
            &describing,
        )
        .unwrap_err();
        assert_eq!(err.exit, Exit::Refused);
        assert!(err.message.contains("RFC 0013"), "{}", err.message);
    }

    #[test]
    fn the_act_lands_beside_the_pem_or_where_told_and_never_on_stdout() {
        assert_eq!(
            act_out_path(Some(Path::new("/tmp/root.pem")), None).unwrap(),
            PathBuf::from("/tmp/root.pem.act")
        );
        assert_eq!(
            act_out_path(
                Some(Path::new("/tmp/root.pem")),
                Some(PathBuf::from("/x/a.act"))
            )
            .unwrap(),
            PathBuf::from("/x/a.act")
        );
        assert_eq!(
            act_out_path(None, Some(PathBuf::from("a.act"))).unwrap(),
            PathBuf::from("a.act")
        );
        let err = act_out_path(None, None).unwrap_err();
        assert_eq!(err.exit, Exit::Usage);
        assert!(err.message.contains("--act-out"), "{}", err.message);
    }
}
