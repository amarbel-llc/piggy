//! Replays the normative pigpen-v1 vector file (piggy RFC 0008 §10,
//! RFC 0009 §8). The Go implementation replays the SAME file
//! (`go/internal/delta/pigpen/vectors_test.go`), so there is one source
//! and no second copy to drift. The file's header documents its fields;
//! regenerate it with `just codemod-pigpen-vectors`.

use std::collections::BTreeMap;

use piggy_markl::Id;
use piggy_pigpen::{Document, EcdhOracle, Error, Result, SealInputs, X25519Identity};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../docs/rfcs/0008-pigpen-vectors.txt");

struct Record(BTreeMap<String, String>);

fn load_vectors() -> Vec<Record> {
    let mut records = Vec::new();
    let mut current = BTreeMap::new();
    for (n, line) in VECTORS.lines().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(Record(std::mem::take(&mut current)));
            }
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("vector line {}: not a `key: value` line", n + 1));
        let previous = current.insert(key.to_string(), value.trim().to_string());
        assert!(
            previous.is_none(),
            "vector line {}: duplicate key {key:?}",
            n + 1
        );
    }
    if !current.is_empty() {
        records.push(Record(current));
    }
    records
}

impl Record {
    fn name(&self) -> &str {
        self.text("name")
    }

    fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    fn text(&self, key: &str) -> &str {
        self.0
            .get(key)
            .unwrap_or_else(|| panic!("{}: missing field {key:?}", self.0["name"]))
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        hex::decode(self.text(key))
            .unwrap_or_else(|e| panic!("{}: field {key:?} is not hex: {e}", self.name()))
    }

    fn hex_list(&self, key: &str) -> Vec<Vec<u8>> {
        match self.0.get(key) {
            None => Vec::new(),
            Some(v) => v
                .split_whitespace()
                .map(|f| {
                    hex::decode(f).unwrap_or_else(|e| {
                        panic!("{}: field {key:?} is not a hex list: {e}", self.name())
                    })
                })
                .collect(),
        }
    }

    fn recipients(&self) -> Vec<Id> {
        self.text("recipients")
            .split_whitespace()
            .map(|f| {
                Id::parse(f).unwrap_or_else(|e| panic!("{}: bad recipient {f:?}: {e}", self.name()))
            })
            .collect()
    }

    fn plaintext(&self) -> Vec<u8> {
        if self.has("plaintext-zeros") {
            let n: usize = self.text("plaintext-zeros").parse().unwrap();
            return vec![0u8; n];
        }
        self.hex("plaintext")
    }

    fn x25519_identities(&self) -> Vec<X25519Identity> {
        self.hex_list("x25519-secrets")
            .into_iter()
            .map(|secret| {
                let sec: [u8; 32] = secret.clone().try_into().unwrap();
                let sk = x25519_dalek::StaticSecret::from(sec);
                X25519Identity {
                    public: x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec(),
                    secret,
                }
            })
            .collect()
    }

    fn p256_oracle(&self) -> Option<SoftP256Oracle> {
        self.has("p256-secret").then(|| SoftP256Oracle {
            sk: p256::SecretKey::from_slice(&self.hex("p256-secret")).unwrap(),
        })
    }

    fn open(&self, doc: &Document) -> Result<Vec<u8>> {
        let oracle = self.p256_oracle();
        doc.open(
            oracle.as_ref().map(|o| o as &dyn EcdhOracle),
            &self.x25519_identities(),
        )
    }

    /// Reproduce a sealed document from the record's explicit inputs.
    fn reseal(&self) -> Vec<u8> {
        let inputs = SealInputs {
            file_key: self.hex("file-key").try_into().unwrap(),
            payload_nonce: self.hex("payload-nonce").try_into().unwrap(),
            ephemeral: self
                .hex_list("ephemeral-secrets")
                .into_iter()
                .map(|s| s.try_into().unwrap())
                .collect(),
        };
        Document::seal_with(&self.plaintext(), &self.recipients(), &inputs)
            .unwrap_or_else(|e| panic!("{}: seal with the record's inputs: {e:?}", self.name()))
            .to_bytes()
            .unwrap()
    }
}

/// The card stand-in: a software P-256 key behind the ECDH oracle.
struct SoftP256Oracle {
    sk: p256::SecretKey,
}

impl EcdhOracle for SoftP256Oracle {
    fn ecdh(&self, _self: &Id, partner_epk: &[u8]) -> Result<[u8; 32]> {
        let epk = p256::PublicKey::from_sec1_bytes(partner_epk)
            .map_err(|e| Error::Crypto(format!("{e}")))?;
        let shared = p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), epk.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }
}

/// An `open` record is a sealed document plus identities that open it. When
/// it carries seal inputs, sealing with them must reproduce the document
/// byte for byte. A record with `document-sha256` instead of `document`
/// names its bytes by digest; the document is then the reseal output.
fn replay_open(r: &Record) {
    let mut wire = r.has("document").then(|| r.hex("document"));

    if r.has("file-key") {
        let resealed = r.reseal();
        match &wire {
            Some(want) => assert_eq!(
                hex::encode(&resealed),
                hex::encode(want),
                "{}: sealing with the record's inputs gives different bytes",
                r.name()
            ),
            None => {
                assert_eq!(
                    hex::encode(Sha256::digest(&resealed)),
                    r.text("document-sha256"),
                    "{}: sealed document digest",
                    r.name()
                );
                wire = Some(resealed);
            }
        }
    }
    let wire = wire.unwrap_or_else(|| panic!("{}: neither a document nor seal inputs", r.name()));

    let doc = Document::parse(&wire).unwrap_or_else(|e| panic!("{}: parse: {e:?}", r.name()));
    assert_eq!(
        hex::encode(doc.to_bytes().unwrap()),
        hex::encode(&wire),
        "{}: document changed on re-serialization",
        r.name()
    );
    let got = r
        .open(&doc)
        .unwrap_or_else(|e| panic!("{}: open: {e:?}", r.name()));
    assert_eq!(got, r.plaintext(), "{}: plaintext", r.name());
}

/// A `normalize` record is a document in a non-canonical spelling that a
/// reader accepts and re-serializes as `normalized`.
fn replay_normalize(r: &Record) {
    let doc = Document::parse(&r.hex("document"))
        .unwrap_or_else(|e| panic!("{}: parse: {e:?}", r.name()));
    assert_eq!(
        hex::encode(doc.to_bytes().unwrap()),
        r.text("normalized"),
        "{}: normalized form",
        r.name()
    );
    let got = r
        .open(&doc)
        .unwrap_or_else(|e| panic!("{}: open: {e:?}", r.name()));
    assert_eq!(got, r.plaintext(), "{}: plaintext", r.name());
}

fn replay_recipient_set(r: &Record) {
    let wire = r.hex("document");
    let doc = Document::parse(&wire).unwrap_or_else(|e| panic!("{}: parse: {e:?}", r.name()));
    assert!(
        !doc.sealed(),
        "{}: a recipient set parsed as sealed",
        r.name()
    );
    assert_eq!(
        hex::encode(doc.to_bytes().unwrap()),
        hex::encode(&wire),
        "{}: recipient set changed on re-serialization",
        r.name()
    );
}

/// A `reject` record must fail at its `stage`: `parse`, or `open` for a
/// document that is well-formed but must not release plaintext.
fn replay_reject(r: &Record) {
    let parsed = Document::parse(&r.hex("document"));
    match r.text("stage") {
        "parse" => assert!(
            parsed.is_err(),
            "{}: parse accepted the document, want rejection",
            r.name()
        ),
        "open" => {
            let doc = parsed.unwrap_or_else(|e| {
                panic!(
                    "{}: parse rejected a document that must fail only at open: {e:?}",
                    r.name()
                )
            });
            assert!(
                r.open(&doc).is_err(),
                "{}: open released plaintext, want rejection",
                r.name()
            );
        }
        other => panic!("{}: unknown stage {other:?}", r.name()),
    }
}

#[test]
fn normative_pigpen_vectors() {
    let records = load_vectors();
    assert!(!records.is_empty(), "no vectors loaded");
    for r in &records {
        match r.text("outcome") {
            "open" => replay_open(r),
            "normalize" => replay_normalize(r),
            "recipient-set" => replay_recipient_set(r),
            "reject" => replay_reject(r),
            other => panic!("{}: unknown outcome {other:?}", r.name()),
        }
    }
}
