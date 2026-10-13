//! The `operator-act@piggy` agent extension (RFC 0012): its wire codec, the
//! sshsig namespace registry, the displayable-text rule, and sshsig assembly.
//!
//! Everything here is pure, so the agent (which serves the extension), a
//! proxy (which routes it by key) and the CLI client (which sends it) share
//! one definition of the bytes, and the rules a request is refused under are
//! unit-testable without a card.

use sha2::{Digest, Sha256, Sha512};

/// The extension name, in the request and echoed in the response.
pub const EXTENSION: &str = "operator-act@piggy";

/// The only request and response version (RFC 0012 §2.1, §2.2).
pub const VERSION: u32 = 1;

/// The longest text an operator act may carry, in bytes (RFC 0012 §2.5).
pub const MAX_TEXT_BYTES: usize = 4096;

const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;

/// How an act is shown to the operator (RFC 0012 §3): the prompt for each
/// class looks different, an escalation most of all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayClass {
    Quote,
    Escalation,
    Certificate,
}

impl DisplayClass {
    /// The value of `PIGGY_ASKPASS_KIND` for this class.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quote => "quote",
            Self::Escalation => "escalation",
            Self::Certificate => "certificate",
        }
    }
}

/// The display class of a namespace registered for the operator-act path,
/// or `None` for every other namespace: OpenSSH's and git's (`file`, `git`,
/// `email`), `piggy-record-v1` (signatures made without a display), and
/// anything unregistered. There is no override (RFC 0012 §3).
pub fn display_class(namespace: &str) -> Option<DisplayClass> {
    match namespace {
        "piggy-quote-v1" => Some(DisplayClass::Quote),
        "piggy-escalation-v1" => Some(DisplayClass::Escalation),
        "piggy-certificate-v1" => Some(DisplayClass::Certificate),
        _ => None,
    }
}

/// The namespaces [`display_class`] accepts, for help text.
pub const NAMESPACES: [&str; 3] = [
    "piggy-quote-v1",
    "piggy-escalation-v1",
    "piggy-certificate-v1",
];

/// The digest an sshsig is made over (RFC 0012 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

/// The outcome of a request (RFC 0012 §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Signed,
    NoSuchKey,
    RefusedPolicy,
    RefusedNamespace,
    RefusedText,
    Cancelled,
    CardAbsent,
    BadRequest,
    Error,
    /// A code this build does not know; a failure (RFC 0012 §2.3).
    Unknown(u32),
}

impl Status {
    pub fn code(self) -> u32 {
        match self {
            Self::Signed => 0,
            Self::NoSuchKey => 1,
            Self::RefusedPolicy => 2,
            Self::RefusedNamespace => 3,
            Self::RefusedText => 4,
            Self::Cancelled => 5,
            Self::CardAbsent => 6,
            Self::BadRequest => 7,
            Self::Error => 8,
            Self::Unknown(code) => code,
        }
    }

    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Signed,
            1 => Self::NoSuchKey,
            2 => Self::RefusedPolicy,
            3 => Self::RefusedNamespace,
            4 => Self::RefusedText,
            5 => Self::Cancelled,
            6 => Self::CardAbsent,
            7 => Self::BadRequest,
            8 => Self::Error,
            other => Self::Unknown(other),
        }
    }

    /// The RFC's name for the status.
    pub fn name(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::NoSuchKey => "no-such-key",
            Self::RefusedPolicy => "refused-policy",
            Self::RefusedNamespace => "refused-namespace",
            Self::RefusedText => "refused-text",
            Self::Cancelled => "cancelled",
            Self::CardAbsent => "card-absent",
            Self::BadRequest => "bad-request",
            Self::Error => "error",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// A request as it arrives: the fields of RFC 0012 §2.1, not yet judged.
/// `namespace` and `hash_algorithm` stay raw so a refusal can be reported
/// with the right status instead of collapsing into `bad-request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The ssh public key blob of the signing slot.
    pub key: Vec<u8>,
    pub namespace: String,
    pub hash_algorithm: String,
    /// The bytes to show and sign.
    pub text: Vec<u8>,
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// A cursor over SSH wire fields. Every read is bounds-checked.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, tail) = self.rest.split_first_chunk::<4>()?;
        self.rest = tail;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if self.rest.len() < len {
            return None;
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Some(head)
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

/// Unwrap the one outer `string contents` an extension's payload is.
fn contents(details: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader { rest: details };
    let inner = reader.string()?;
    reader.is_empty().then_some(inner)
}

/// The `key` field of a request payload, read without judging anything
/// else in it. A proxy routes on this alone (RFC 0012 §2.8): it must not
/// refuse a request, for a key it does not hold, just because this build
/// would not understand the rest.
pub fn request_key(details: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader {
        rest: contents(details).or_else(|| {
            // Trailing bytes after the outer string are the key holder's
            // to refuse; the key is still where it is.
            Reader { rest: details }.string()
        })?,
    };
    reader.u32()?;
    reader.string()
}

impl Request {
    /// The extension payload: `string contents` (RFC 0012 §2.1).
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_string(&mut inner, &self.key);
        put_string(&mut inner, self.namespace.as_bytes());
        put_string(&mut inner, self.hash_algorithm.as_bytes());
        put_string(&mut inner, &self.text);
        put_u32(&mut inner, 0);
        let mut details = Vec::new();
        put_string(&mut details, &inner);
        details
    }

    /// Parse a payload. `None` is `bad-request`: a truncated field, a
    /// version other than 1, flags other than 0, a namespace or hash name
    /// that is not UTF-8, or any trailing byte (version 1 has no extension
    /// point).
    pub fn decode(details: &[u8]) -> Option<Self> {
        let mut reader = Reader {
            rest: contents(details)?,
        };
        if reader.u32()? != VERSION {
            return None;
        }
        let key = reader.string()?.to_vec();
        // Lossy on purpose: a namespace that is not UTF-8 is not a
        // registered one, and the answer to that is `refused-namespace`
        // (§3), not `bad-request`. The replacement character cannot turn
        // bad bytes into a registered name.
        let namespace = String::from_utf8_lossy(reader.string()?).into_owned();
        let hash_algorithm = String::from_utf8(reader.string()?.to_vec()).ok()?;
        let text = reader.string()?.to_vec();
        if reader.u32()? != 0 || !reader.is_empty() {
            return None;
        }
        Some(Self {
            key,
            namespace,
            hash_algorithm,
            text,
        })
    }
}

/// A response (RFC 0012 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: Status,
    /// The unarmored sshsig blob when `status` is [`Status::Signed`].
    pub sshsig: Vec<u8>,
    pub detail: String,
}

impl Response {
    /// A response that is not a signature.
    pub fn refusal(status: Status, detail: impl Into<String>) -> Self {
        Self {
            status,
            sshsig: Vec::new(),
            detail: detail.into(),
        }
    }

    pub fn signed(sshsig: Vec<u8>) -> Self {
        Self {
            status: Status::Signed,
            sshsig,
            detail: String::new(),
        }
    }

    /// The extension payload: `string contents`.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_u32(&mut inner, VERSION);
        put_u32(&mut inner, self.status.code());
        put_string(&mut inner, &self.sshsig);
        put_string(&mut inner, self.detail.as_bytes());
        let mut details = Vec::new();
        put_string(&mut details, &inner);
        details
    }

    pub fn decode(details: &[u8]) -> Option<Self> {
        let mut reader = Reader {
            rest: contents(details)?,
        };
        if reader.u32()? != VERSION {
            return None;
        }
        let status = Status::from_code(reader.u32()?);
        let sshsig = reader.string()?.to_vec();
        let detail = String::from_utf8_lossy(reader.string()?).into_owned();
        Some(Self {
            status,
            sshsig,
            detail,
        })
    }
}

/// The text as the operator can be shown it, or `None` when it is not
/// displayable (RFC 0012 §2.5): empty, over [`MAX_TEXT_BYTES`], not UTF-8, or
/// holding a C0 or C1 control other than LF and TAB. Terminal escapes could
/// otherwise reflow or hide what the operator reads before the PIN.
pub fn displayable_text(text: &[u8]) -> Option<&str> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return None;
    }
    let text = std::str::from_utf8(text).ok()?;
    let allowed = |c: char| c == '\n' || c == '\t' || !c.is_control();
    text.chars().all(allowed).then_some(text)
}

/// The bytes the slot key signs (PROTOCOL.sshsig §3), with `reserved`
/// empty. The hash is computed here from the text: no caller-supplied
/// digest is ever signed (RFC 0012 §2.7).
pub fn signed_data(namespace: &str, hash: HashAlgorithm, text: &[u8]) -> Vec<u8> {
    let mut out = SSHSIG_MAGIC.to_vec();
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, hash.as_str().as_bytes());
    put_string(&mut out, &hash.digest(text));
    out
}

/// The operator-act namespace `data` would be signed under, when `data` is
/// sshsig signed data naming one.
///
/// An ordinary sign request carries bytes the agent never shows anyone. If
/// the agent signed these, `ssh-keygen -Y sign -n piggy-escalation-v1`
/// would yield an escalation no operator read, which is the one thing the
/// namespace is supposed to rule out (RFC 0012 §3), so the sign path
/// refuses them and [`EXTENSION`] stays the only way to such a signature.
/// Only the prefix is read: whatever follows a registered namespace, the
/// signature would verify under it.
pub fn namespace_of_signed_data(data: &[u8]) -> Option<&'static str> {
    let mut reader = Reader {
        rest: data.strip_prefix(SSHSIG_MAGIC)?,
    };
    let namespace = reader.string()?;
    NAMESPACES
        .into_iter()
        .find(|registered| registered.as_bytes() == namespace)
}

/// The gate every ordinary signing surface passes its message through
/// (RFC 0012 §2.7): the agent's sign request, `piggy sign-bytes`, `piggy
/// tool sign`. `Err` is the refusal to report.
pub fn refuse_operator_act_signed_data(data: &[u8]) -> Result<(), String> {
    match namespace_of_signed_data(data) {
        None => Ok(()),
        Some(namespace) => Err(format!(
            "refusing to sign sshsig data for namespace {namespace} here: \
             it is signed only through {EXTENSION}, which shows the text first"
        )),
    }
}

/// The unarmored sshsig blob (PROTOCOL.sshsig §2). `signature` is the SSH
/// signature encoding: `string algorithm || string signature-data`.
pub fn sshsig_blob(
    public_key: &[u8],
    namespace: &str,
    hash: HashAlgorithm,
    signature: &[u8],
) -> Vec<u8> {
    let mut out = SSHSIG_MAGIC.to_vec();
    put_u32(&mut out, SSHSIG_VERSION);
    put_string(&mut out, public_key);
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, hash.as_str().as_bytes());
    put_string(&mut out, signature);
    out
}

/// An SSH signature encoding from its algorithm name and signature data.
pub fn ssh_signature(algorithm: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, algorithm.as_bytes());
    put_string(&mut out, data);
    out
}

/// Armor an sshsig blob the way `ssh-keygen -Y sign` writes one
/// (PROTOCOL.sshsig §1): base64 in 70-column lines between the markers.
pub fn armor(sshsig: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(sshsig);
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for line in encoded.as_bytes().chunks(70) {
        // Base64 output is ASCII.
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    out
}

/// What the operator is shown above the PIN line (RFC 0012 §2.6): the class,
/// the card and slot, the namespace, and the text verbatim. This is also the
/// `PIGGY_ASKPASS_CONTEXT` string, so the askpass program and the tty route
/// show the same words.
pub fn prompt_context(
    class: DisplayClass,
    card: &str,
    slot: u8,
    namespace: &str,
    text: &str,
) -> String {
    format!(
        "operator act: {}\ncard {card}, slot {slot:02X}\nnamespace {namespace}\n\n{text}",
        class.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            key: vec![1, 2, 3],
            namespace: "piggy-escalation-v1".into(),
            hash_algorithm: "sha256".into(),
            text: b"grant session \"swift-elder\" the right spinclass:force for 24h\n".to_vec(),
        }
    }

    #[test]
    fn request_round_trips_and_is_one_outer_string() {
        let encoded = request().encode();
        let outer = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(outer, encoded.len() - 4, "payload is `string contents`");
        assert_eq!(&encoded[4..8], &1u32.to_be_bytes(), "version 1 first");
        assert_eq!(Request::decode(&encoded), Some(request()));
    }

    /// Rebuild a request payload with one field changed, to hit each
    /// `bad-request` rule of RFC 0012 §2.1.
    fn payload(version: u32, flags: u32, trailing: &[u8]) -> Vec<u8> {
        let r = request();
        let mut inner = Vec::new();
        put_u32(&mut inner, version);
        put_string(&mut inner, &r.key);
        put_string(&mut inner, r.namespace.as_bytes());
        put_string(&mut inner, r.hash_algorithm.as_bytes());
        put_string(&mut inner, &r.text);
        put_u32(&mut inner, flags);
        inner.extend_from_slice(trailing);
        let mut details = Vec::new();
        put_string(&mut details, &inner);
        details
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(
            Request::decode(&payload(1, 0, b"")).is_some(),
            "the control"
        );
        assert!(Request::decode(&payload(2, 0, b"")).is_none(), "version");
        assert!(Request::decode(&payload(1, 1, b"")).is_none(), "flags");
        assert!(Request::decode(&payload(1, 0, b"\0")).is_none(), "trailing");
        let good = payload(1, 0, b"");
        for cut in 0..good.len() {
            assert!(
                Request::decode(&good[..cut]).is_none(),
                "truncated at {cut}"
            );
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(
            Request::decode(&extra).is_none(),
            "bytes after the outer string"
        );
    }

    #[test]
    fn response_round_trips_and_unknown_status_is_kept() {
        let signed = Response::signed(vec![9, 9]);
        assert_eq!(Response::decode(&signed.encode()), Some(signed));
        let refused = Response::refusal(Status::RefusedPolicy, "slot 9A: PIN once, touch cached");
        assert_eq!(Response::decode(&refused.encode()), Some(refused));
        let future = Response::refusal(Status::Unknown(42), "");
        let decoded = Response::decode(&future.encode()).unwrap();
        assert_eq!(decoded.status, Status::Unknown(42));
        assert_ne!(
            decoded.status,
            Status::Signed,
            "an unknown status is a failure"
        );
    }

    #[test]
    fn status_codes_are_the_rfc_table() {
        let table = [
            (0, "signed"),
            (1, "no-such-key"),
            (2, "refused-policy"),
            (3, "refused-namespace"),
            (4, "refused-text"),
            (5, "cancelled"),
            (6, "card-absent"),
            (7, "bad-request"),
            (8, "error"),
        ];
        for (code, name) in table {
            let status = Status::from_code(code);
            assert_eq!(status.code(), code);
            assert_eq!(status.name(), name);
        }
    }

    #[test]
    fn only_the_three_act_namespaces_have_a_display_class() {
        assert_eq!(display_class("piggy-quote-v1"), Some(DisplayClass::Quote));
        assert_eq!(
            display_class("piggy-escalation-v1"),
            Some(DisplayClass::Escalation)
        );
        assert_eq!(
            display_class("piggy-certificate-v1"),
            Some(DisplayClass::Certificate)
        );
        for refused in [
            "git",
            "file",
            "email",
            "piggy-record-v1",
            "piggy-operator_act-v1",
            "",
        ] {
            assert_eq!(display_class(refused), None, "{refused:?}");
        }
        for ns in NAMESPACES {
            assert!(display_class(ns).is_some());
        }
    }

    #[test]
    fn text_must_be_displayable() {
        assert_eq!(
            displayable_text(b"two\nlines\tand a tab"),
            Some("two\nlines\tand a tab")
        );
        assert_eq!(displayable_text("naïve ✓".as_bytes()), Some("naïve ✓"));
        assert!(displayable_text(b"").is_none(), "empty");
        assert!(displayable_text(b"esc \x1b[2J").is_none(), "C0 control");
        assert!(displayable_text(b"cr\r\n").is_none(), "carriage return");
        assert!(
            displayable_text("c1 \u{0085}".as_bytes()).is_none(),
            "C1 control"
        );
        assert!(displayable_text(&[0xff, 0xfe]).is_none(), "not UTF-8");
        assert!(displayable_text(&vec![b'a'; MAX_TEXT_BYTES]).is_some());
        assert!(
            displayable_text(&vec![b'a'; MAX_TEXT_BYTES + 1]).is_none(),
            "oversize"
        );
    }

    #[test]
    fn signed_data_is_the_sshsig_layout() {
        let data = signed_data("piggy-quote-v1", HashAlgorithm::Sha256, b"hello");
        let mut reader = Reader { rest: &data[6..] };
        assert_eq!(&data[..6], b"SSHSIG");
        assert_eq!(reader.string().unwrap(), b"piggy-quote-v1");
        assert_eq!(reader.string().unwrap(), b"", "reserved is empty");
        assert_eq!(reader.string().unwrap(), b"sha256");
        assert_eq!(
            reader.string().unwrap(),
            Sha256::digest(b"hello").as_slice()
        );
        assert!(reader.is_empty());
        let wide = signed_data("piggy-quote-v1", HashAlgorithm::Sha512, b"hello");
        assert_eq!(
            wide.len() - data.len(),
            32,
            "sha512 digest is 32 bytes longer"
        );
    }

    /// A proxy routes on the key alone: it is readable from a request this
    /// build would otherwise refuse (a later version, trailing bytes).
    #[test]
    fn request_key_is_read_without_judging_the_rest() {
        let request = request();
        assert_eq!(request_key(&request.encode()), Some(&request.key[..]));

        let mut contents = Vec::new();
        put_u32(&mut contents, 2);
        put_string(&mut contents, &request.key);
        contents.extend_from_slice(b"fields a later version defines");
        let mut later = Vec::new();
        put_string(&mut later, &contents);
        assert!(Request::decode(&later).is_none(), "this build refuses it");
        assert_eq!(request_key(&later), Some(&request.key[..]));
        later.push(0);
        assert_eq!(request_key(&later), Some(&request.key[..]));

        assert_eq!(request_key(&[0, 0]), None);
        assert_eq!(request_key(&[0, 0, 0, 4, 0, 0, 0, 1]), None);
    }

    #[test]
    fn namespace_that_is_not_utf8_decodes_to_an_unregistered_one() {
        let mut bad = request();
        bad.namespace = "piggy-escalation-v1".into();
        let mut encoded = bad.encode();
        // Corrupt the first byte of the namespace in place.
        let at = encoded
            .windows(5)
            .position(|w| w == b"piggy")
            .expect("the namespace is in the payload");
        encoded[at] = 0xFF;
        let decoded = Request::decode(&encoded).expect("still a well-formed request");
        assert_eq!(display_class(&decoded.namespace), None);
    }

    #[test]
    fn signed_data_names_its_namespace_only_when_it_is_an_operator_act() {
        for namespace in NAMESPACES {
            let data = signed_data(namespace, HashAlgorithm::Sha512, b"hello");
            assert_eq!(namespace_of_signed_data(&data), Some(namespace));
            // A prefix is enough: the signature would verify under it.
            let prefix = &data[..SSHSIG_MAGIC.len() + 4 + namespace.len()];
            assert_eq!(namespace_of_signed_data(prefix), Some(namespace));
        }
        // What ssh-keygen -Y sign and git send through an agent stays signable.
        for namespace in ["file", "git", "piggy-record-v1"] {
            let data = signed_data(namespace, HashAlgorithm::Sha512, b"hello");
            assert_eq!(namespace_of_signed_data(&data), None, "{namespace}");
        }
        assert_eq!(namespace_of_signed_data(b"an ssh userauth request"), None);
        assert_eq!(namespace_of_signed_data(b"SSHSIG\x00\x00"), None);
    }

    #[test]
    fn sshsig_blob_is_the_sshsig_layout() {
        let signature = ssh_signature("ecdsa-sha2-nistp256", b"sigdata");
        let blob = sshsig_blob(
            b"keyblob",
            "piggy-quote-v1",
            HashAlgorithm::Sha256,
            &signature,
        );
        assert_eq!(&blob[..6], b"SSHSIG");
        let mut reader = Reader { rest: &blob[6..] };
        assert_eq!(reader.u32(), Some(1));
        assert_eq!(reader.string().unwrap(), b"keyblob");
        assert_eq!(reader.string().unwrap(), b"piggy-quote-v1");
        assert_eq!(reader.string().unwrap(), b"");
        assert_eq!(reader.string().unwrap(), b"sha256");
        let mut sig = Reader {
            rest: reader.string().unwrap(),
        };
        assert_eq!(sig.string().unwrap(), b"ecdsa-sha2-nistp256");
        assert_eq!(sig.string().unwrap(), b"sigdata");
        assert!(reader.is_empty() && sig.is_empty());
    }

    #[test]
    fn armor_wraps_at_70_columns_between_the_markers() {
        let armored = armor(&[7u8; 100]);
        let lines: Vec<&str> = armored.lines().collect();
        assert_eq!(lines[0], "-----BEGIN SSH SIGNATURE-----");
        assert_eq!(*lines.last().unwrap(), "-----END SSH SIGNATURE-----");
        assert!(lines[1..lines.len() - 1].iter().all(|l| l.len() <= 70));
        assert_eq!(lines[1].len(), 70);
        assert!(armored.ends_with('\n'));
    }

    #[test]
    fn prompt_context_carries_class_card_slot_namespace_and_text_verbatim() {
        let context = prompt_context(
            DisplayClass::Escalation,
            "5da19c98",
            0x9C,
            "piggy-escalation-v1",
            "grant X\nfor 24h",
        );
        assert_eq!(
            context,
            "operator act: escalation\ncard 5da19c98, slot 9C\nnamespace piggy-escalation-v1\n\ngrant X\nfor 24h"
        );
    }
}
