//! The holder's two agent extensions, `mint@piggy` and `retire@piggy`
//! (FDR 0006 phase (d), piggy#383; wire RFC part 2): their codec, the
//! shared status table, and the grammar of the scope field.
//!
//! Pure, like [`crate::operator_act`]: the holder agent (which serves the
//! extensions), the CLI client (`piggy holder`) and the tests share one
//! definition of the bytes and one list of the reasons a request is
//! refused.

use crate::ssh_wire::{Reader, put_string, put_u32};

/// `mint@piggy`: ask the holder for a new key bound to a scope.
pub const MINT: &str = "mint@piggy";
/// `retire@piggy`: destroy a key the caller's scope owns.
pub const RETIRE: &str = "retire@piggy";

/// The only request and response version.
pub const VERSION: u32 = 1;

/// The key types a holder mints, by their SSH algorithm names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
}

impl KeyType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(Self::Ed25519),
            "ecdsa-sha2-nistp256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }

    /// The `alg=` word fibby's `create` verb takes (phase (c)).
    pub fn fibby_alg(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "p256",
        }
    }
}

/// The outcome of a mint or a retire. One table serves both extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Minted (the response carries the key), or retired.
    Ok,
    /// No key the holder serves matches `key` (retire).
    NoSuchKey,
    /// The caller is not inside the scope the key is bound to.
    NotBoundScope,
    /// The scope names no definition the holder is configured with, or
    /// carries a payload this version does not define.
    UnknownScope,
    /// No scope was named, and the holder infers none.
    ScopeUnbound,
    /// The holder serves its cap of live cards; retire one first.
    CapReached,
    /// A key type the holder does not mint.
    RefusedKeyType,
    /// Malformed request.
    BadRequest,
    /// Any other failure; `detail` says what.
    Error,
    /// The holder could not read who is calling.
    PeerUnknown,
    /// A code this build does not know; a failure.
    Unknown(u32),
}

impl Status {
    pub fn code(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::NoSuchKey => 1,
            Self::NotBoundScope => 2,
            Self::UnknownScope => 3,
            Self::ScopeUnbound => 4,
            Self::CapReached => 5,
            Self::RefusedKeyType => 6,
            Self::BadRequest => 7,
            Self::Error => 8,
            Self::PeerUnknown => 9,
            Self::Unknown(code) => code,
        }
    }

    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::NoSuchKey,
            2 => Self::NotBoundScope,
            3 => Self::UnknownScope,
            4 => Self::ScopeUnbound,
            5 => Self::CapReached,
            6 => Self::RefusedKeyType,
            7 => Self::BadRequest,
            8 => Self::Error,
            9 => Self::PeerUnknown,
            other => Self::Unknown(other),
        }
    }

    /// The RFC's name for the status.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoSuchKey => "no-such-key",
            Self::NotBoundScope => "not-bound-scope",
            Self::UnknownScope => "unknown-scope",
            Self::ScopeUnbound => "scope-unbound",
            Self::CapReached => "cap-reached",
            Self::RefusedKeyType => "refused-key-type",
            Self::BadRequest => "bad-request",
            Self::Error => "error",
            Self::PeerUnknown => "peer-unknown",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// The scope field is an opaque UTF-8 string (the operator's ruling: a
/// plain versioned name like `piggy-mint-v1` today, possibly
/// `piggy-mint-v1@<format>-<data>` later). The codec does not parse it:
/// the holder looks it up, whole, among the scope definitions it is
/// configured with, so a plain name stays valid whatever a payload form
/// later means. Only the empty string is special: it is "absent".
pub fn scope_is_absent(scope: &str) -> bool {
    scope.is_empty()
}

/// Unwrap the one outer `string contents` an extension's payload is.
fn contents(details: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(details);
    let inner = reader.string()?;
    reader.is_empty().then_some(inner)
}

fn frame(inner: &[u8]) -> Vec<u8> {
    let mut details = Vec::new();
    put_string(&mut details, inner);
    details
}

/// A `mint@piggy` request as it arrives, not yet judged: `scope` and
/// `key_type` stay raw so a refusal reports `unknown-scope` or
/// `refused-key-type`, not `bad-request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest {
    /// The scope value, empty when absent.
    pub scope: String,
    pub key_type: String,
}

impl MintRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_string(&mut inner, self.scope.as_bytes());
        put_string(&mut inner, self.key_type.as_bytes());
        put_u32(&mut inner, 0);
        frame(&inner)
    }

    /// `None` is `bad-request`: a short field, another version, flags
    /// other than 0, a scope or key type that is not UTF-8, or trailing
    /// bytes (version 1 has no extension point).
    pub fn decode(details: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(contents(details)?);
        if reader.u32()? != VERSION {
            return None;
        }
        let scope = String::from_utf8(reader.string()?.to_vec()).ok()?;
        let key_type = String::from_utf8(reader.string()?.to_vec()).ok()?;
        if reader.u32()? != 0 || !reader.is_empty() {
            return None;
        }
        Some(Self { scope, key_type })
    }
}

/// A `mint@piggy` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintResponse {
    pub status: Status,
    /// The ssh public key blob of the minted key when `status` is `Ok`.
    pub key: Vec<u8>,
    /// The reader the card is served as; the handle a retire names in
    /// its detail and `piggy health` lists.
    pub card: String,
    pub detail: String,
}

impl MintResponse {
    pub fn refusal(status: Status, detail: impl Into<String>) -> Self {
        Self {
            status,
            key: Vec::new(),
            card: String::new(),
            detail: detail.into(),
        }
    }

    pub fn minted(key: Vec<u8>, card: impl Into<String>) -> Self {
        Self {
            status: Status::Ok,
            key,
            card: card.into(),
            detail: String::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_u32(&mut inner, self.status.code());
        put_string(&mut inner, &self.key);
        put_string(&mut inner, self.card.as_bytes());
        put_string(&mut inner, self.detail.as_bytes());
        frame(&inner)
    }

    pub fn decode(details: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(contents(details)?);
        if reader.u32()? != VERSION {
            return None;
        }
        let status = Status::from_code(reader.u32()?);
        let key = reader.string()?.to_vec();
        let card = String::from_utf8_lossy(reader.string()?).into_owned();
        let detail = String::from_utf8_lossy(reader.string()?).into_owned();
        Some(Self {
            status,
            key,
            card,
            detail,
        })
    }
}

/// A `retire@piggy` request: the key to destroy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireRequest {
    /// The ssh public key blob of the key.
    pub key: Vec<u8>,
}

impl RetireRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_string(&mut inner, &self.key);
        put_u32(&mut inner, 0);
        frame(&inner)
    }

    pub fn decode(details: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(contents(details)?);
        if reader.u32()? != VERSION {
            return None;
        }
        let key = reader.string()?.to_vec();
        if reader.u32()? != 0 || !reader.is_empty() {
            return None;
        }
        Some(Self { key })
    }
}

/// A `retire@piggy` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireResponse {
    pub status: Status,
    pub detail: String,
}

impl RetireResponse {
    pub fn refusal(status: Status, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }

    pub fn retired() -> Self {
        Self {
            status: Status::Ok,
            detail: String::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_u32(&mut inner, self.status.code());
        put_string(&mut inner, self.detail.as_bytes());
        frame(&inner)
    }

    pub fn decode(details: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(contents(details)?);
        if reader.u32()? != VERSION {
            return None;
        }
        let status = Status::from_code(reader.u32()?);
        let detail = String::from_utf8_lossy(reader.string()?).into_owned();
        Some(Self { status, detail })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_round_trip_and_name() {
        for code in 0..=9 {
            let status = Status::from_code(code);
            assert_eq!(status.code(), code);
            assert_ne!(status.name(), "unknown", "code {code}");
        }
        assert_eq!(Status::from_code(42), Status::Unknown(42));
        assert_eq!(Status::Unknown(42).code(), 42);
        assert_eq!(Status::NotBoundScope.name(), "not-bound-scope");
        assert_eq!(Status::CapReached.name(), "cap-reached");
    }

    #[test]
    fn key_types_by_ssh_name() {
        assert_eq!(KeyType::parse("ssh-ed25519"), Some(KeyType::Ed25519));
        assert_eq!(
            KeyType::parse("ecdsa-sha2-nistp256"),
            Some(KeyType::EcdsaP256)
        );
        assert_eq!(
            KeyType::parse("ssh-rsa"),
            None,
            "piggy is EC and 25519 only"
        );
        assert_eq!(KeyType::Ed25519.fibby_alg(), "ed25519");
        assert_eq!(KeyType::EcdsaP256.fibby_alg(), "p256");
    }

    /// The wire carries the scope whole: a payload form is just more of
    /// the same string, so defining one later cannot break a plain name.
    #[test]
    fn the_scope_is_opaque_and_only_empty_is_absent() {
        assert!(scope_is_absent(""));
        assert!(!scope_is_absent("piggy-mint-v1"));
        let with_payload = MintRequest {
            scope: "piggy-mint-v1@blake2b256-abcdefg".into(),
            key_type: "ssh-ed25519".into(),
        };
        assert_eq!(
            MintRequest::decode(&with_payload.encode()),
            Some(with_payload)
        );
    }

    #[test]
    fn mint_request_round_trips_and_every_cut_is_bad_request() {
        let request = MintRequest {
            scope: "piggy-mint-v1".into(),
            key_type: "ssh-ed25519".into(),
        };
        let bytes = request.encode();
        assert_eq!(MintRequest::decode(&bytes), Some(request.clone()));
        for cut in 0..bytes.len() {
            assert!(MintRequest::decode(&bytes[..cut]).is_none(), "cut {cut}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(MintRequest::decode(&trailing).is_none());
        // An absent scope is an empty string, which decodes.
        let absent = MintRequest {
            scope: String::new(),
            key_type: "ssh-ed25519".into(),
        };
        assert_eq!(MintRequest::decode(&absent.encode()), Some(absent));
    }

    #[test]
    fn mint_request_rejects_other_versions_and_flags() {
        let mut inner = Vec::new();
        put_u32(&mut inner, 2);
        put_string(&mut inner, b"piggy-mint-v1");
        put_string(&mut inner, b"ssh-ed25519");
        put_u32(&mut inner, 0);
        assert!(MintRequest::decode(&frame(&inner)).is_none());

        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_string(&mut inner, b"piggy-mint-v1");
        put_string(&mut inner, b"ssh-ed25519");
        put_u32(&mut inner, 1);
        assert!(MintRequest::decode(&frame(&inner)).is_none());
    }

    #[test]
    fn mint_response_round_trips() {
        let minted = MintResponse::minted(vec![1, 2, 3], "piggy-holder 1");
        assert_eq!(MintResponse::decode(&minted.encode()), Some(minted));
        let refused = MintResponse::refusal(Status::CapReached, "16 live cards");
        let decoded = MintResponse::decode(&refused.encode()).unwrap();
        assert_eq!(decoded, refused);
        assert!(decoded.key.is_empty());
        assert!(MintResponse::decode(&[]).is_none());
    }

    #[test]
    fn retire_round_trips_and_cuts_are_bad_request() {
        let request = RetireRequest { key: vec![9; 40] };
        let bytes = request.encode();
        assert_eq!(RetireRequest::decode(&bytes), Some(request));
        for cut in 0..bytes.len() {
            assert!(RetireRequest::decode(&bytes[..cut]).is_none(), "cut {cut}");
        }
        let response = RetireResponse::refusal(Status::NotBoundScope, "sibling");
        assert_eq!(RetireResponse::decode(&response.encode()), Some(response));
        assert_eq!(
            RetireResponse::decode(&RetireResponse::retired().encode()),
            Some(RetireResponse::retired())
        );
    }
}
