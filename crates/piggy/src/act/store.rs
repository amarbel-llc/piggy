//! Where a verifier finds acts (RFC 0013 §5.4): the pluggable store the
//! chain walk resolves `issuer-record` and `names` in, and searches for the
//! escalations, narrows and revocations naming an act (§4.3, §4.6).
//!
//! The store is the consumer's (§5.4, "piggy does not distribute"); piggy
//! ships two adapters over one in-memory index: a directory of sealed acts,
//! and a JSON document on stdin (`{"acts": ["<sealed act>", ...]}`) for a
//! consumer that keeps acts elsewhere. A file or entry that is not a sealed
//! act is skipped: it could never be valid, and the walk answers undetermined
//! for any act it needed and did not find.

use std::collections::HashMap;
use std::path::Path;

use super::seal::{DigestFormat, act_digest};
use super::{Act, parse, parsed_bytes};

/// One sealed act and its two names (§3.5: verifiers accept blake2b256 and
/// sha256).
#[derive(Debug, Clone)]
pub struct StoredAct {
    pub act: Act,
    /// The blake2b256 act digest, the name a verdict reports.
    pub digest: String,
    pub sha256: String,
}

impl StoredAct {
    /// `None` for an unsealed act, which has no act digest.
    pub fn new(act: Act) -> Option<StoredAct> {
        Some(StoredAct {
            digest: act_digest(&act, DigestFormat::Blake2b256)?,
            sha256: act_digest(&act, DigestFormat::Sha256)?,
            act,
        })
    }

    /// Whether `name` (a `names` or `issuer-record` value) names this act.
    pub fn is_named_by(&self, name: &str) -> bool {
        name == self.digest || name == self.sha256
    }

    /// Whether this act's `names` holds a name of `target`.
    pub fn names(&self, target: &StoredAct) -> bool {
        self.act
            .values("names")
            .any(|v| target.is_named_by(&parsed_bytes(v)))
    }
}

/// The lookups the chain walk needs. An implementation answers from what it
/// holds; whether that is every revocation there is, is the caller's
/// assertion ([`super::verify::Options::revocation_source`]), not the
/// store's.
pub trait ActStore {
    /// The act a digest names, under either digest format.
    fn get(&self, digest: &str) -> Option<StoredAct>;
    /// Every act whose `names` holds a name of `target`.
    fn naming(&self, target: &StoredAct) -> Vec<StoredAct>;
    /// Every `grant` to `subject` over `object` (spelled as parsed values),
    /// which a software grant by `subject` over `object` hands down from
    /// (§5.2 step 5).
    fn grants(&self, subject: &str, object: &str) -> Vec<StoredAct>;
}

/// An in-memory index of sealed acts, the backing of both adapters.
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    acts: Vec<StoredAct>,
    by_digest: HashMap<String, usize>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    /// Add a sealed act; its blake2b256 digest, or `None` when it is not
    /// sealed. Adding an act twice keeps one copy.
    pub fn insert(&mut self, act: Act) -> Option<String> {
        let stored = StoredAct::new(act)?;
        let digest = stored.digest.clone();
        if !self.by_digest.contains_key(&digest) {
            let at = self.acts.len();
            self.by_digest.insert(stored.digest.clone(), at);
            self.by_digest.insert(stored.sha256.clone(), at);
            self.acts.push(stored);
        }
        Some(digest)
    }

    /// Parse and add one document; `None` when it is not a sealed act.
    pub fn insert_bytes(&mut self, bytes: &[u8]) -> Option<String> {
        self.insert(parse(bytes).ok()?)
    }

    /// The directory adapter: every regular file directly in `dir`.
    pub fn from_dir(dir: &Path) -> std::io::Result<MemoryStore> {
        let mut store = MemoryStore::new();
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        paths.sort();
        for path in paths {
            store.insert_bytes(&std::fs::read(&path)?);
        }
        Ok(store)
    }

    /// The JSON adapter: `{"acts": ["<sealed act text>", ...]}`.
    pub fn from_json(json: &[u8]) -> Result<MemoryStore, String> {
        #[derive(serde::Deserialize)]
        struct Doc {
            acts: Vec<String>,
        }
        let doc: Doc = serde_json::from_slice(json)
            .map_err(|e| format!("not a store document ({{\"acts\": [...]}}): {e}"))?;
        let mut store = MemoryStore::new();
        for act in doc.acts {
            store.insert_bytes(act.as_bytes());
        }
        Ok(store)
    }

    pub fn len(&self) -> usize {
        self.acts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.acts.is_empty()
    }
}

impl ActStore for MemoryStore {
    fn get(&self, digest: &str) -> Option<StoredAct> {
        self.by_digest.get(digest).map(|&at| self.acts[at].clone())
    }

    fn naming(&self, target: &StoredAct) -> Vec<StoredAct> {
        self.acts
            .iter()
            .filter(|a| a.names(target))
            .cloned()
            .collect()
    }

    fn grants(&self, subject: &str, object: &str) -> Vec<StoredAct> {
        self.acts
            .iter()
            .filter(|a| {
                a.act.text("kind") == Some("grant")
                    && a.act.text("subject") == Some(subject)
                    && a.act.field("object").map(parsed_bytes).as_deref() == Some(object)
            })
            .cloned()
            .collect()
    }
}
