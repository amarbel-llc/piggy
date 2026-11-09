//! The seal (RFC 0013 §3.2 to §3.5): the four fields that rebuild an act's
//! sshsig, the signature check under `key`, the act digest, and the
//! conversions between a sealed act and a detached sshsig.
//!
//! The signed data is PROTOCOL.sshsig §3 over the canonical form, built by
//! [`operator_act::signed_data`] exactly as the agent builds it for an
//! operator act (RFC 0012 §2.7). Ed25519 verifies over that data directly;
//! ECDSA P-256 (`ecdsa-sha2-nistp256`) over its SHA-256.

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use hyphence::{MarklId, Value};
use piggy_markl::{FormatId, Id, PurposeId};
use sha2::Sha256;

use super::{Act, Refusal, Rule, refuse};
use crate::ecdsa_sig::{der_to_raw_rs, raw_rs_to_ssh_ecdsa_blob, ssh_ecdsa_blob_to_der};
use crate::operator_act::{HashAlgorithm, signed_data, ssh_signature, sshsig_blob};
use crate::ssh_wire::{Reader, put_string};

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const ED25519: &str = "ssh-ed25519";
const ECDSA_P256: &str = "ecdsa-sha2-nistp256";

/// The digest algorithms an act digest may be under (§3.5): producers emit
/// blake2b256, verifiers accept both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestFormat {
    Blake2b256,
    Sha256,
}

/// The act digest (§3.5): a `piggy-record-digest-v1` markl id over the
/// sealed canonical form. `None` for an unsealed act.
pub fn act_digest(act: &Act, format: DigestFormat) -> Option<String> {
    let sealed = act.sealed_canonical()?;
    let (format, bytes) = match format {
        DigestFormat::Blake2b256 => (
            FormatId::Blake2b256,
            Blake2b::<U32>::digest(&sealed).to_vec(),
        ),
        DigestFormat::Sha256 => (FormatId::Sha256, Sha256::digest(&sealed).to_vec()),
    };

    let id = Id::new(Some(PurposeId::PiggyRecordDigestV1), format, bytes)
        .expect("a 32-byte digest under its own purpose");
    Some(id.to_wire())
}

/// Whether `id` names this act: the act digest under `id`'s format.
pub fn names_act(act: &Act, id: &str) -> bool {
    [DigestFormat::Blake2b256, DigestFormat::Sha256]
        .into_iter()
        .any(|format| act_digest(act, format).as_deref() == Some(id))
}

/// The key of an act's `key` field, decoded.
pub fn seal_key(act: &Act) -> Result<Id, Refusal> {
    match act.field("key") {
        Some(Value::Markl(id)) => markl(id),
        _ => refuse(Rule::MissingField, "`key` is required to verify"),
    }
}

fn markl(id: &MarklId) -> Result<Id, Refusal> {
    let text = match &id.purpose {
        Some(p) => format!("{}@{}", piggy_markl::spell_purpose(p), id.digest),
        None => id.digest.to_string(),
    };
    Id::parse(&text).or_else(|e| refuse(Rule::Value, e.to_string()))
}

/// The sshsig `publickey` blob for a `key` value (§2 "Key payloads", RFC
/// 4253 §6.6): Ed25519 as is, P-256 decompressed (RFC 5656 §3.1). A P-256
/// payload that does not decompress is refused.
pub fn public_key_blob(key: &Id) -> Result<Vec<u8>, Refusal> {
    let mut out = Vec::new();
    match key.format() {
        FormatId::SshEd25519Pub => {
            put_string(&mut out, ED25519.as_bytes());
            put_string(&mut out, key.data());
        }
        FormatId::SshEcdsaNistp256Pub => {
            put_string(&mut out, ECDSA_P256.as_bytes());
            put_string(&mut out, b"nistp256");
            put_string(&mut out, &decompress_p256(key.data())?);
        }
        other => return refuse(Rule::Value, format!("a {other} key cannot seal an act")),
    }
    Ok(out)
}

/// The 65-byte uncompressed SEC1 point for a 33-byte compressed one, or a
/// refusal when the bytes are not a point on P-256.
pub fn decompress_p256(compressed: &[u8]) -> Result<Vec<u8>, Refusal> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    match p256::PublicKey::from_sec1_bytes(compressed) {
        Ok(key) => Ok(key.to_encoded_point(false).as_bytes().to_vec()),
        Err(_) => refuse(
            Rule::Value,
            "the ssh_ecdsa_nistp256_pub payload does not decompress to a P-256 point",
        ),
    }
}

/// The seal's raw signature, decoded from its `signature` field.
fn seal_signature(act: &Act) -> Result<Id, Refusal> {
    match act.field("signature") {
        Some(Value::Markl(id)) => markl(id),
        _ => refuse(Rule::MissingField, "`signature` is required to verify"),
    }
}

fn seal_hash(act: &Act) -> HashAlgorithm {
    // parse() admitted only sha256 and sha512.
    HashAlgorithm::parse(act.text("hash").unwrap_or_default()).unwrap_or(HashAlgorithm::Sha512)
}

/// §5.2 step 2: verify `signature` under `key` over the signed data of the
/// canonical form. Says nothing about the chain.
pub fn verify_seal(act: &Act) -> Result<(), Refusal> {
    let key = seal_key(act)?;
    let signature = seal_signature(act)?;
    let namespace = act.text("namespace").unwrap_or_default();
    let data = signed_data(namespace, seal_hash(act), &act.canonical());

    let verified = match (key.format(), signature.format()) {
        (FormatId::SshEd25519Pub, FormatId::Ed25519Sig) => verify_ed25519(&key, &signature, &data),
        (FormatId::SshEcdsaNistp256Pub, FormatId::EcdsaP256Sig) => {
            verify_p256(&key, &signature, &data)?
        }
        (k, s) => {
            return refuse(
                Rule::Signature,
                format!("a {s} signature cannot be under a {k} key"),
            );
        }
    };

    if verified {
        Ok(())
    } else {
        refuse(Rule::Signature, "the signature does not verify under `key`")
    }
}

fn verify_ed25519(key: &Id, signature: &Id, data: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        <[u8; 32]>::try_from(key.data()),
        <[u8; 64]>::try_from(signature.data()),
    ) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

fn verify_p256(key: &Id, signature: &Id, data: &[u8]) -> Result<bool, Refusal> {
    use p256::ecdsa::signature::Verifier;

    // The decompression refusal outranks the signature result (§5.2 step 1).
    decompress_p256(key.data())?;
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.data()) else {
        return Ok(false);
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature.data()) else {
        return Ok(false);
    };
    // (r, n - s) verifies wherever (r, s) does; with the signature inside
    // the act digest, admitting both would let anyone mint a second act
    // from a sealed one. Only the low-S form seals.
    if signature.normalize_s().is_some() {
        return refuse(
            Rule::Signature,
            "a P-256 signature must be in low-S form (s <= n/2)",
        );
    }
    Ok(key.verify(data, &signature).is_ok())
}

/// §3.3: the detached sshsig blob rebuilt from the four seal fields. The
/// text it signs is the act's canonical form.
pub fn detached_sshsig(act: &Act) -> Result<Vec<u8>, Refusal> {
    let key = seal_key(act)?;
    let signature = seal_signature(act)?;
    let namespace = act.text("namespace").unwrap_or_default();

    let ssh_signature = match signature.format() {
        FormatId::Ed25519Sig => ssh_signature(ED25519, signature.data()),
        FormatId::EcdsaP256Sig => ssh_signature(
            ECDSA_P256,
            &raw_rs_to_ssh_ecdsa_blob(signature.data()).or_else(|e| refuse(Rule::Value, e))?,
        ),
        other => return refuse(Rule::Value, format!("{other} is not a seal signature")),
    };

    Ok(sshsig_blob(
        &public_key_blob(&key)?,
        namespace,
        seal_hash(act),
        &ssh_signature,
    ))
}

/// §3.3 in the other direction: join a detached sshsig to its unsealed
/// act. The blob's namespace, public key and hash algorithm MUST equal the
/// act's `namespace`, `key` and `hash`; the result is the act with its
/// `signature` field, which [`verify_seal`] then checks.
pub fn attach(act: &Act, sshsig: &[u8]) -> Result<Act, Refusal> {
    let blob = SshSig::decode(sshsig).ok_or_else(|| Refusal {
        rule: Rule::Signature,
        detail: "not an sshsig blob (PROTOCOL.sshsig §2)".into(),
    })?;

    let key = seal_key(act)?;
    if blob.public_key != public_key_blob(&key)? {
        return refuse(Rule::Signature, "the sshsig's public key is not `key`");
    }
    let namespace = act.text("namespace").unwrap_or_default();
    if blob.namespace != namespace.as_bytes() {
        return refuse(
            Rule::Signature,
            format!(
                "the sshsig's namespace {:?} is not `namespace` {namespace}",
                String::from_utf8_lossy(blob.namespace)
            ),
        );
    }
    if blob.hash_algorithm != seal_hash(act).as_str().as_bytes() {
        return refuse(Rule::Signature, "the sshsig's hash algorithm is not `hash`");
    }

    let mut reader = Reader::new(blob.signature);
    let (Some(algorithm), Some(data)) = (reader.string(), reader.string()) else {
        return refuse(Rule::Signature, "a malformed SSH signature");
    };
    let (format, raw) = match algorithm {
        a if a == ED25519.as_bytes() => (FormatId::Ed25519Sig, data.to_vec()),
        a if a == ECDSA_P256.as_bytes() => (
            FormatId::EcdsaP256Sig,
            low_s(
                &ssh_ecdsa_blob_to_der(data)
                    .and_then(|der| der_to_raw_rs(&der, 32))
                    .or_else(|e| refuse(Rule::Signature, e))?,
            )?,
        ),
        other => {
            return refuse(
                Rule::Signature,
                format!(
                    "a {} signature cannot seal an act",
                    String::from_utf8_lossy(other)
                ),
            );
        }
    };

    let signature = Id::new(Some(PurposeId::PiggyRecordSigV1), format, raw)
        .or_else(|e| refuse(Rule::Signature, e.to_string()))?;
    Ok(act.with_signature(&signature))
}

/// A raw P-256 `r‖s` in low-S form: ssh-keygen (OpenSSL) and a PIV card
/// emit high-S about half the time, and only the low-S twin seals. The
/// normalized signature still verifies under `ssh-keygen -Y verify`.
pub fn low_s(raw: &[u8]) -> Result<Vec<u8>, Refusal> {
    let signature = p256::ecdsa::Signature::from_slice(raw)
        .or_else(|_| refuse(Rule::Signature, "not a P-256 r||s signature"))?;
    Ok(signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .to_vec())
}

/// The fields of an unarmored sshsig blob (PROTOCOL.sshsig §2).
struct SshSig<'a> {
    public_key: &'a [u8],
    namespace: &'a [u8],
    hash_algorithm: &'a [u8],
    signature: &'a [u8],
}

impl<'a> SshSig<'a> {
    fn decode(blob: &'a [u8]) -> Option<Self> {
        let mut reader = Reader::new(blob.strip_prefix(SSHSIG_MAGIC)?);
        if reader.u32()? != 1 {
            return None;
        }
        let public_key = reader.string()?;
        let namespace = reader.string()?;
        let _reserved = reader.string()?;
        let hash_algorithm = reader.string()?;
        let signature = reader.string()?;
        reader.is_empty().then_some(SshSig {
            public_key,
            namespace,
            hash_algorithm,
            signature,
        })
    }
}

/// The sshsig blob inside an armored signature (PROTOCOL.sshsig §1), or the
/// bytes unchanged when they are not armored.
pub fn unarmor(input: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;

    let Ok(text) = std::str::from_utf8(input) else {
        return Some(input.to_vec());
    };
    let Some(inner) = text
        .trim()
        .strip_prefix("-----BEGIN SSH SIGNATURE-----")
        .and_then(|t| t.strip_suffix("-----END SSH SIGNATURE-----"))
    else {
        return Some(input.to_vec());
    };
    let joined: String = inner.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(joined)
        .ok()
}

/// The `key` value for an OpenSSH public key line (`ssh-ed25519 AAAA…` or
/// `ecdsa-sha2-nistp256 AAAA…`): `piggy-principal_pub-v1@…`, or
/// `piggy-piv_sig-v1@…` for a card's slot-9C key.
pub fn key_id(openssh: &str, card: bool) -> Result<String, String> {
    let key = ssh_key::PublicKey::from_openssh(openssh.trim())
        .map_err(|e| format!("not an OpenSSH public key: {e}"))?;
    let (format, data) = match key.key_data() {
        ssh_key::public::KeyData::Ed25519(k) => (FormatId::SshEd25519Pub, k.0.to_vec()),
        ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP256(point)) => {
            let key = p256::PublicKey::from_sec1_bytes(point.as_bytes())
                .map_err(|_| "the ECDSA point is not on P-256".to_string())?;
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            (
                FormatId::SshEcdsaNistp256Pub,
                key.to_encoded_point(true).as_bytes().to_vec(),
            )
        }
        _ => return Err("an act key is Ed25519 or ECDSA P-256".into()),
    };
    let purpose = if card {
        PurposeId::PiggyPivSigV1
    } else {
        PurposeId::PiggyPrincipalPubV1
    };
    Id::new(Some(purpose), format, data)
        .map(|id| id.to_wire())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::act::parse;

    fn ed25519() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    fn p256_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
    }

    fn key_wire(purpose: PurposeId, format: FormatId, data: Vec<u8>) -> String {
        Id::new(Some(purpose), format, data).unwrap().to_wire()
    }

    fn ed25519_key_wire() -> String {
        key_wire(
            PurposeId::PiggyPrincipalPubV1,
            FormatId::SshEd25519Pub,
            ed25519().verifying_key().to_bytes().to_vec(),
        )
    }

    fn p256_card_key_wire() -> String {
        let point = p256_key().verifying_key().to_encoded_point(true);
        key_wire(
            PurposeId::PiggyPivSigV1,
            FormatId::SshEcdsaNistp256Pub,
            point.as_bytes().to_vec(),
        )
    }

    const D: &str = "piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400";

    fn software_narrow() -> Act {
        let key = ed25519_key_wire();
        parse(
            format!(
                "---\n- kind = narrow\n- producer = spinclass:narrow-v1\n\
                 - subject = clown:x\n- issuer = clown:x\n- issuer-key = {key}\n\
                 - issuer-record = {D}\n- right = spinclass:check\n- names = {D}\n\
                 - issued-at = 2026-11-08T23:30:00Z\n- assurance = piggy:software\n\
                 - key = {key}\n- namespace = piggy-record-v1\n- hash = sha256\n\
                 ! piggy-act-v1\n---\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn card_approval() -> Act {
        let key = p256_card_key_wire();
        parse(
            format!(
                "---\n- kind = approval\n- producer = troupe:approval-v1\n\
                 - issuer = operator\n- issuer-key = {key}\n- records = {D}\n\
                 - issued-at = 2026-11-08T23:00:00Z\n- assurance = piggy:hardware\n\
                 - key = {key}\n- namespace = piggy-approval-v1\n- hash = sha512\n\
                 ! piggy-act-v1\n---\n\n[x !y-v1 deny]\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn sign_ed25519(act: &Act) -> Act {
        use ed25519_dalek::Signer;
        let data = signed_data("piggy-record-v1", HashAlgorithm::Sha256, &act.canonical());
        let raw = ed25519().sign(&data).to_bytes().to_vec();
        let sig = Id::new(Some(PurposeId::PiggyRecordSigV1), FormatId::Ed25519Sig, raw).unwrap();
        act.with_signature(&sig)
    }

    fn sign_p256(act: &Act) -> Act {
        use p256::ecdsa::signature::Signer;
        let data = signed_data("piggy-approval-v1", HashAlgorithm::Sha512, &act.canonical());
        let signature: p256::ecdsa::Signature = p256_key().sign(&data);
        let sig = Id::new(
            Some(PurposeId::PiggyRecordSigV1),
            FormatId::EcdsaP256Sig,
            signature.to_bytes().to_vec(),
        )
        .unwrap();
        act.with_signature(&sig)
    }

    #[test]
    fn ed25519_and_p256_seals_verify() {
        assert_eq!(verify_seal(&sign_ed25519(&software_narrow())), Ok(()));
        assert_eq!(verify_seal(&sign_p256(&card_approval())), Ok(()));
    }

    #[test]
    fn a_changed_head_or_body_does_not_verify() {
        let sealed = sign_ed25519(&software_narrow());
        let text = String::from_utf8(sealed.sealed_canonical().unwrap()).unwrap();
        let widened = parse(
            text.replace("spinclass:check", "spinclass:merge")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_seal(&widened).map_err(|r| r.rule),
            Err(Rule::Signature)
        );

        let sealed = sign_p256(&card_approval());
        let text = String::from_utf8(sealed.sealed_canonical().unwrap()).unwrap();
        let changed = parse(text.replace("deny]", "dent]").as_bytes()).unwrap();
        assert_eq!(
            verify_seal(&changed).map_err(|r| r.rule),
            Err(Rule::Signature)
        );
    }

    #[test]
    fn detach_then_attach_is_the_identity() {
        for sealed in [
            sign_ed25519(&software_narrow()),
            sign_p256(&card_approval()),
        ] {
            let blob = detached_sshsig(&sealed).unwrap();
            let unsealed = parse(&sealed.canonical()).unwrap();
            let rebuilt = attach(&unsealed, &blob).unwrap();
            assert_eq!(rebuilt.sealed_canonical(), sealed.sealed_canonical());
            assert_eq!(
                unarmor(crate::operator_act::armor(&blob).as_bytes()),
                Some(blob)
            );
        }
    }

    #[test]
    fn attach_refuses_a_blob_for_another_namespace() {
        let sealed = sign_ed25519(&software_narrow());
        let blob = detached_sshsig(&sealed).unwrap();

        // The same blob with its namespace bytes changed in place.
        let mut wrong = blob.clone();
        let at = wrong
            .windows(b"piggy-record-v1".len())
            .position(|w| w == b"piggy-record-v1")
            .unwrap();
        wrong[at..at + 5].copy_from_slice(b"PIGGY");
        let unsealed = parse(&sealed.canonical()).unwrap();
        assert_eq!(
            attach(&unsealed, &wrong).map_err(|r| r.rule),
            Err(Rule::Signature)
        );
    }

    #[test]
    fn the_digest_covers_the_signature() {
        let sealed = sign_p256(&card_approval());
        let resealed = sign_p256(&card_approval());
        let digest = act_digest(&sealed, DigestFormat::Blake2b256).unwrap();
        assert!(digest.starts_with("piggy-record-digest-v1@blake2b256-"));
        assert!(names_act(&sealed, &digest));
        assert!(names_act(
            &sealed,
            &act_digest(&sealed, DigestFormat::Sha256).unwrap()
        ));
        // RFC 6979 makes p256's signature deterministic: the same head
        // signed twice is byte-identical and so is its digest. A randomized
        // signer (ssh-keygen's ECDSA) gives two acts; act_seal.bats pins
        // that. A different signature always gives a different digest:
        let other = Id::new(
            Some(PurposeId::PiggyRecordSigV1),
            FormatId::EcdsaP256Sig,
            vec![1; 64],
        )
        .unwrap();
        assert_ne!(
            act_digest(&resealed.with_signature(&other), DigestFormat::Blake2b256),
            Some(digest)
        );
        assert_eq!(act_digest(&card_approval(), DigestFormat::Blake2b256), None);
    }

    /// The re-encoding (r, n - s) of a valid P-256 signature also verifies
    /// under plain ECDSA. Since the act digest covers the signature, a
    /// verifier that admitted both would let anyone mint a second act, with
    /// a second digest, from a sealed one.
    #[test]
    fn the_high_s_twin_of_a_p256_seal_is_refused() {
        let sealed = sign_p256(&card_approval());
        let Some(Value::Markl(id)) = sealed.field("signature") else {
            panic!("sealed");
        };
        let signature = p256::ecdsa::Signature::from_slice(markl(id).unwrap().data()).unwrap();
        let (r, s) = signature.split_scalars();
        let twin = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
        let twin = Id::new(
            Some(PurposeId::PiggyRecordSigV1),
            FormatId::EcdsaP256Sig,
            twin.to_bytes().to_vec(),
        )
        .unwrap();
        let twin = sealed.with_signature(&twin);

        assert_ne!(
            act_digest(&twin, DigestFormat::Blake2b256),
            act_digest(&sealed, DigestFormat::Blake2b256)
        );
        assert_eq!(verify_seal(&sealed), Ok(()));
        assert_eq!(
            verify_seal(&twin).map_err(|r| r.rule),
            Err(Rule::Signature),
            "the n - s twin verified"
        );

        // A high-S signature from outside (ssh-keygen, a card) is attached
        // in its low-S form: the twin's blob seals into the original act.
        let blob = detached_sshsig(&twin).unwrap();
        let unsealed = parse(&sealed.canonical()).unwrap();
        let attached = attach(&unsealed, &blob).unwrap();
        assert_eq!(attached.sealed_canonical(), sealed.sealed_canonical());
    }

    #[test]
    fn an_off_curve_p256_key_is_refused_at_parse() {
        let off_curve = key_wire(
            PurposeId::PiggyPivSigV1,
            FormatId::SshEcdsaNistp256Pub,
            (0u8..33).collect(),
        );
        let text = String::from_utf8(card_approval().canonical())
            .unwrap()
            .replace(&p256_card_key_wire(), &off_curve);
        let refusal = parse(text.as_bytes()).unwrap_err();
        assert_eq!(refusal.rule, Rule::Value);
        assert!(refusal.detail.contains("does not decompress"), "{refusal}");
    }

    #[test]
    fn raw_ecdsa_round_trips_through_the_ssh_blob() {
        for rs in [[0x80; 64], [0x00; 64], [0x7f; 64]] {
            let mut rs = rs;
            rs[31] = 1;
            rs[63] = 1;
            let blob = raw_rs_to_ssh_ecdsa_blob(&rs).unwrap();
            let back = der_to_raw_rs(&ssh_ecdsa_blob_to_der(&blob).unwrap(), 32).unwrap();
            assert_eq!(back, rs.to_vec());
        }
    }
}
