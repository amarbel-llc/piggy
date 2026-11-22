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
    /// A decision that grants no right (an acknowledgement, a deploy
    /// approval); deliberately not an escalation.
    Approval,
    /// A card act that cancels earlier acts; shown so it cannot read as the
    /// certificate it may be cancelling.
    Revocation,
}

impl DisplayClass {
    /// The value of `PIGGY_ASKPASS_KIND` for this class.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quote => "quote",
            Self::Escalation => "escalation",
            Self::Certificate => "certificate",
            Self::Approval => "approval",
            Self::Revocation => "revocation",
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
        "piggy-approval-v1" => Some(DisplayClass::Approval),
        "piggy-revocation-v1" => Some(DisplayClass::Revocation),
        _ => None,
    }
}

/// The namespaces [`display_class`] accepts, for help text.
pub const NAMESPACES: [&str; 5] = [
    "piggy-quote-v1",
    "piggy-escalation-v1",
    "piggy-certificate-v1",
    "piggy-approval-v1",
    "piggy-revocation-v1",
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

use crate::ssh_wire::{Reader, put_string, put_u32};

/// Unwrap the one outer `string contents` an extension's payload is.
fn contents(details: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(details);
    let inner = reader.string()?;
    reader.is_empty().then_some(inner)
}

/// The `key` field of a request payload, read without judging anything
/// else in it. A proxy routes on this alone (RFC 0012 §2.8): it must not
/// refuse a request, for a key it does not hold, just because this build
/// would not understand the rest.
pub fn request_key(details: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(contents(details).or_else(|| {
        // Trailing bytes after the outer string are the key holder's
        // to refuse; the key is still where it is.
        Reader::new(details).string()
    })?);
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
        let mut reader = Reader::new(contents(details)?);
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
        let mut reader = Reader::new(contents(details)?);
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

/// Why a text cannot be an operator act's text (RFC 0012 §2.5): the one
/// reason the agent answers `refused-text` with and a client says before
/// asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextProblem {
    Empty,
    TooLong(usize),
    /// Not UTF-8, or holding a C0 or C1 control other than LF and TAB.
    NotDisplayable,
}

impl std::fmt::Display for TextProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextProblem::Empty => {
                f.write_str("no text: an operator act signs the text the operator reads")
            }
            TextProblem::TooLong(len) => write!(
                f,
                "the text is {len} bytes; an operator act carries at most {MAX_TEXT_BYTES}"
            ),
            TextProblem::NotDisplayable => f.write_str(
                "the text must be UTF-8 with no control characters other than newline and tab, \
                 so the prompt shows exactly what is signed",
            ),
        }
    }
}

/// The text as the operator can be shown it, or why it cannot be (RFC 0012
/// §2.5). Terminal escapes could otherwise reflow or hide what the operator
/// reads before the PIN.
pub fn check_text(text: &[u8]) -> Result<&str, TextProblem> {
    if text.is_empty() {
        return Err(TextProblem::Empty);
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(TextProblem::TooLong(text.len()));
    }
    let text = std::str::from_utf8(text).map_err(|_| TextProblem::NotDisplayable)?;
    let allowed = |c: char| c == '\n' || c == '\t' || !c.is_control();
    if text.chars().all(allowed) {
        Ok(text)
    } else {
        Err(TextProblem::NotDisplayable)
    }
}

/// [`check_text`] when only whether matters.
pub fn displayable_text(text: &[u8]) -> Option<&str> {
    check_text(text).ok()
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
    let mut reader = Reader::new(data.strip_prefix(SSHSIG_MAGIC)?);
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

/// What a sign request may be, once it has passed the slot gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotData {
    /// Ordinary data for an ordinary slot.
    Ordinary,
    /// An unsigned OpenSSH user certificate, for the SSH CA slot.
    SshCertificate(Box<piggy_piv::ssh_cert::SshCertTbs>),
}

/// The slot gate for every ordinary signing surface (RFC 0012 §2.7 as
/// amended for FDR 0007 phase (ii) and the SSH CA slot, 2026-11-22): what
/// each slot may be asked to sign depends on its kind
/// ([`piggy_piv::slot::ca_kind`]).
///
/// - The X.509 CA slot (82) refuses a DER TBSCertificate (a certificate is
///   signed only through `piggy ca`, which says what it is certifying) and
///   an OpenSSH certificate.
/// - The SSH CA slot (83) signs ONLY a parsed, unsigned OpenSSH user
///   certificate: no TBSCertificate, no sshsig, no login challenge, no
///   other bytes.
/// - Every other slot refuses an OpenSSH certificate: a key that is not the
///   SSH CA never certifies.
///
/// `piggy ca` reaches the card by its own route and never passes through
/// here. `Err` is the refusal to report.
pub fn gate_data_for_slot(data: &[u8], slot_id: u8) -> Result<SlotData, String> {
    use piggy_piv::slot::{CaKind, ca_kind};
    use piggy_piv::ssh_cert::parse_unsigned_certificate;
    match ca_kind(slot_id) {
        Some(CaKind::SshCertificate) => match parse_unsigned_certificate(data) {
            Ok(tbs) => Ok(SlotData::SshCertificate(Box::new(tbs))),
            Err(why) => Err(format!(
                "refusing to sign with the SSH certificate authority in slot {slot_id:02x}: \
                 it signs only an unsigned OpenSSH user certificate, and this is not one ({why})"
            )),
        },
        Some(CaKind::X509) => {
            if piggy_piv::x509_profile::looks_like_tbs_certificate(data) {
                return Err(format!(
                    "refusing to sign a TBSCertificate with the CA key in slot {slot_id:02x} here: \
                     a certificate is signed only through `piggy ca`, which says what it is certifying"
                ));
            }
            refuse_ssh_certificate_shape(data, slot_id)?;
            Ok(SlotData::Ordinary)
        }
        None => {
            refuse_ssh_certificate_shape(data, slot_id)?;
            Ok(SlotData::Ordinary)
        }
    }
}

/// The certificate is signed by the key it names as its CA: the CA key the
/// certificate carries must be, byte for byte, the key about to sign it.
/// Otherwise the dialog's "Signed by CA" line would be a value the requester
/// chose, and the signature could never verify as the certificate says.
pub fn refuse_certificate_naming_another_ca(
    tbs: &piggy_piv::ssh_cert::SshCertTbs,
    signing_key_blob: &[u8],
) -> Result<(), String> {
    if tbs.ca_key_blob == signing_key_blob {
        Ok(())
    } else {
        Err(format!(
            "refusing to certify {}: the certificate names a different CA key ({}) than the one asked to sign it",
            tbs.key_id, tbs.ca_fingerprint
        ))
    }
}

fn refuse_ssh_certificate_shape(data: &[u8], slot_id: u8) -> Result<(), String> {
    if piggy_piv::ssh_cert::looks_like_ssh_certificate(data) {
        return Err(format!(
            "refusing to sign an OpenSSH certificate with the key in slot {slot_id:02x}: \
             only the SSH certificate authority in slot 83 signs those"
        ));
    }
    Ok(())
}

/// [`gate_data_for_slot`] for a surface that never signs a certificate
/// (`piggy tool sign`): the SSH CA slot refuses everything here, because a
/// certificate is signed through the agent, whose PIN dialog says what it
/// certifies.
pub fn refuse_data_for_slot(data: &[u8], slot_id: u8) -> Result<(), String> {
    if piggy_piv::slot::ca_kind(slot_id) == Some(piggy_piv::slot::CaKind::SshCertificate) {
        return Err(format!(
            "refusing to sign here with the SSH certificate authority in slot {slot_id:02x}: \
             an OpenSSH certificate is signed through the agent (ssh-keygen -U -s), whose PIN \
             dialog says what it certifies"
        ));
    }
    gate_data_for_slot(data, slot_id).map(|_| ())
}

/// The slot gate of RFC 0012 §2.4 item 5 (the sixth amendment): an operator
/// act is signed only by a key whose attestation names slot 9C. The CA key
/// in slot 82 attests the same PIN-always, touch-always policy, and a
/// signature by it must never pass for an approval, so policy alone does
/// not qualify a slot. The slot is read from the attestation certificate
/// the card produced; `slot_id`, the slot the caller asked about, is for
/// the wording only. `Err` is the `refused-policy` detail.
pub fn refuse_attestation_not_for_slot_9c(
    attestation_der: &[u8],
    slot_id: u8,
) -> Result<(), String> {
    use crate::card::slot_policy::SLOT_SIGNATURE;
    match piggy_piv::attest::attested_slot(attestation_der) {
        Ok(Some(SLOT_SIGNATURE)) => Ok(()),
        Ok(Some(named)) => Err(format!(
            "slot {slot_id:02X}: the attestation names slot {named:02X}, not 9C; only the \
             9C key signs operator acts"
        )),
        Ok(None) => Err(format!("slot {slot_id:02X}: the attestation names no slot")),
        Err(e) => Err(format!("slot {slot_id:02X}: unreadable attestation ({e})")),
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

/// The agent's PIN prompt for an operator act, the last line of the askpass
/// dialog's body.
pub fn pin_prompt(card: &str) -> String {
    format!("PIN for card {card} to sign this operator act")
}

/// The width the askpass dialog wraps an act's text at, in characters:
/// piggy-askpass-gtk's `TEXT_WIDTH_CHARS`, wide enough for a fully
/// qualified markl-id on one line. The dialog has no height limit (the
/// operator's ruling of 2026-11-21, piggy#400: the one it had, 24 rendered
/// lines, refused every `piggy-act-v1` card act, whose required fields alone
/// render to more); [`askpass_rendered_lines`] measures a text at this width
/// so the heights are on record for the re-examination.
pub const ASKPASS_WRAP_COLUMNS: usize = 100;

impl DisplayClass {
    /// The banner `contrib/piggy-askpass.sh` puts over this class's text,
    /// the dialog body's first line.
    pub fn askpass_banner(self) -> &'static str {
        match self {
            Self::Quote => "=== OPERATOR ACT: QUOTE — you are signing words already on record ===",
            Self::Escalation => "!!! OPERATOR ACT: ESCALATION — you are GRANTING AUTHORITY !!!",
            Self::Certificate => "=== OPERATOR ACT: CERTIFICATE — you are certifying a key ===",
            Self::Approval => {
                "=== OPERATOR ACT: APPROVAL — you are approving a decision; this grants no right ==="
            }
            Self::Revocation => {
                "=== OPERATOR ACT: REVOCATION — you are cancelling earlier acts ==="
            }
        }
    }
}

/// The dialog body `contrib/piggy-askpass.sh` renders for an operator act
/// (its `render_context`): the class banner, the `Parent:` line (stood in
/// for here; it never wraps), the `Context:` line opening
/// [`prompt_context`] and that context's remaining lines, then a blank line
/// and the agent's [`pin_prompt`].
pub fn askpass_body(
    class: DisplayClass,
    card: &str,
    slot: u8,
    namespace: &str,
    text: &str,
) -> String {
    format!(
        "{}\nParent: piggy (PID 1)\nContext: {}\n\n{}",
        class.askpass_banner(),
        prompt_context(class, card, slot, namespace, text),
        pin_prompt(card)
    )
}

/// How many lines [`askpass_body`] takes on the dialog: each line, plus one
/// more for every [`ASKPASS_WRAP_COLUMNS`] characters it runs past the
/// first (the count the script's height limit used, kept as the measure).
pub fn askpass_rendered_lines(
    class: DisplayClass,
    card: &str,
    slot: u8,
    namespace: &str,
    text: &str,
) -> usize {
    askpass_body(class, card, slot, namespace, text)
        .lines()
        .map(|line| 1 + line.chars().count().saturating_sub(1) / ASKPASS_WRAP_COLUMNS)
        .sum()
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

    /// The askpass body mirrors `contrib/piggy-askpass.sh`'s `render_context`
    /// and the dialog's wrap width mirrors piggy-askpass-gtk's: held equal
    /// to the sources here, since the Rust side only measures.
    #[test]
    fn the_askpass_mirror_matches_the_script_and_the_dialog() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        // The nix build's source holds this crate alone; the check runs
        // wherever the whole tree is (`just test-rust`, the worktree).
        let (Ok(script), Ok(dialog)) = (
            std::fs::read_to_string(root.join("contrib/piggy-askpass.sh")),
            std::fs::read_to_string(root.join("crates/piggy-askpass-gtk/src/dialog.rs")),
        ) else {
            eprintln!("skipped: the script and the dialog are not in this source tree");
            return;
        };
        for class in [
            DisplayClass::Quote,
            DisplayClass::Escalation,
            DisplayClass::Certificate,
            DisplayClass::Approval,
            DisplayClass::Revocation,
        ] {
            let line = format!("class_banner=\"{}\"", class.askpass_banner());
            assert!(script.contains(&line), "the script lacks {line}");
        }
        assert!(
            !script.contains("operator_act_max_lines="),
            "the script has a height limit again; the mirror and piggy#400's record need it"
        );
        assert!(dialog.contains(&format!(
            "const TEXT_WIDTH_CHARS: i32 = {ASKPASS_WRAP_COLUMNS};"
        )));
    }

    /// Counted as the script's `rendered_body_lines` counted: every line
    /// once, a line over the wrap width once more per width, blank lines
    /// included, and the two blank lines the script leaves between a text
    /// that ends in a newline and the PIN prompt.
    #[test]
    fn the_askpass_height_counts_wrapped_and_blank_lines() {
        let card = "55C3439D";
        let one = "x".repeat(ASKPASS_WRAP_COLUMNS);
        let two = "x".repeat(ASKPASS_WRAP_COLUMNS + 1);
        // banner, Parent, "Context: operator act: quote", card, namespace,
        // blank, the text's lines, blank, prompt.
        let framing = 8;
        let text = format!("{one}\n{two}\n\nlast");
        assert_eq!(
            askpass_rendered_lines(DisplayClass::Quote, card, 0x9C, "piggy-quote-v1", &text),
            framing + 1 + 2 + 1 + 1
        );
        // A trailing newline on the text costs one more line, as it does
        // on the dialog.
        assert_eq!(
            askpass_rendered_lines(DisplayClass::Quote, card, 0x9C, "piggy-quote-v1", "a\n"),
            framing + 2
        );
        let body = askpass_body(
            DisplayClass::Certificate,
            card,
            0x9C,
            "piggy-certificate-v1",
            "t\n",
        );
        assert_eq!(
            body,
            "=== OPERATOR ACT: CERTIFICATE — you are certifying a key ===\nParent: piggy (PID 1)\nContext: operator act: certificate\ncard 55C3439D, slot 9C\nnamespace piggy-certificate-v1\n\nt\n\n\nPIN for card 55C3439D to sign this operator act"
        );
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

    /// The outer shape of a v3 TBSCertificate with empty names: enough for
    /// the guard, which reads shape only.
    fn tbs_shaped() -> Vec<u8> {
        let mut body = vec![0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        for _ in 0..5 {
            body.extend_from_slice(&[0x30, 0x00]);
        }
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// An unsigned OpenSSH user certificate for an ed25519 key, valid
    /// `lifetime` seconds, for principal `deploy`.
    fn ssh_cert_unsigned(lifetime: u64) -> Vec<u8> {
        let mut d = Vec::new();
        ssh_string(&mut d, b"ssh-ed25519-cert-v01@openssh.com");
        ssh_string(&mut d, &[1u8; 32]);
        ssh_string(&mut d, &[7u8; 32]);
        d.extend_from_slice(&0u64.to_be_bytes());
        d.extend_from_slice(&1u32.to_be_bytes());
        ssh_string(&mut d, b"grant-1");
        let mut principals = Vec::new();
        ssh_string(&mut principals, b"deploy");
        ssh_string(&mut d, &principals);
        d.extend_from_slice(&1_795_000_000u64.to_be_bytes());
        d.extend_from_slice(&(1_795_000_000u64 + lifetime).to_be_bytes());
        ssh_string(&mut d, b"");
        ssh_string(&mut d, b"");
        ssh_string(&mut d, b"");
        let mut ca = Vec::new();
        ssh_string(&mut ca, b"ssh-ed25519");
        ssh_string(&mut ca, &[9u8; 32]);
        ssh_string(&mut d, &ca);
        d
    }

    #[test]
    fn a_tbs_certificate_is_refused_on_both_ca_slots_and_passes_elsewhere() {
        let tbs = tbs_shaped();
        let refusal = gate_data_for_slot(&tbs, 0x82).unwrap_err();
        assert!(refusal.contains("TBSCertificate"), "{refusal}");
        assert!(refusal.contains("slot 82"), "{refusal}");
        // The SSH CA signs only an OpenSSH certificate: a TBS is refused too.
        let refusal = gate_data_for_slot(&tbs, 0x83).unwrap_err();
        assert!(refusal.contains("slot 83"), "{refusal}");
        assert!(refusal.contains("not one"), "{refusal}");
        // 9A signs SSH challenges, 9C operator acts, 9D does not sign: not
        // CA slots, so the same bytes pass there.
        for slot in [0x9A, 0x9C, 0x9D, 0x9E, 0x84] {
            assert_eq!(
                gate_data_for_slot(&tbs, slot),
                Ok(SlotData::Ordinary),
                "slot {slot:02X}"
            );
        }
    }

    #[test]
    fn other_bytes_pass_on_the_x509_ca_slot_and_are_refused_on_the_ssh_one() {
        for data in [&b""[..], b"hello", b"SSHSIG", &tbs_shaped()[1..]] {
            assert_eq!(
                gate_data_for_slot(data, 0x82),
                Ok(SlotData::Ordinary),
                "{data:?}"
            );
            // Slot 83 signs nothing but an OpenSSH certificate: no sshsig, no
            // login challenge, no other bytes.
            assert!(gate_data_for_slot(data, 0x83).is_err(), "{data:?}");
        }
    }

    #[test]
    fn the_ssh_ca_slot_signs_a_parsed_certificate_and_every_other_slot_refuses_it() {
        let cert = ssh_cert_unsigned(3_600);
        match gate_data_for_slot(&cert, 0x83) {
            Ok(SlotData::SshCertificate(tbs)) => {
                assert_eq!(tbs.key_id, "grant-1");
                assert_eq!(tbs.principals, ["deploy"]);
            }
            other => panic!("slot 83 should sign it: {other:?}"),
        }
        for slot in [0x82, 0x9A, 0x9C, 0x9D, 0x9E, 0x84, 0x95] {
            let refusal = gate_data_for_slot(&cert, slot).unwrap_err();
            assert!(
                refusal.contains("only the SSH certificate authority in slot 83"),
                "slot {slot:02X}: {refusal}"
            );
        }
        // A host certificate, or one with no principal, is not signed even
        // by slot 83.
        let mut host = ssh_cert_unsigned(3_600);
        let type_at = 4 + 32 + 4 + 32 + 4 + 32 + 8; // key type, nonce, key, serial
        host[type_at..type_at + 4].copy_from_slice(&2u32.to_be_bytes());
        assert!(gate_data_for_slot(&host, 0x83).is_err());
    }

    #[test]
    fn a_certificate_must_name_the_key_that_signs_it() {
        let cert = ssh_cert_unsigned(3_600);
        let tbs = match gate_data_for_slot(&cert, 0x83) {
            Ok(SlotData::SshCertificate(tbs)) => tbs,
            other => panic!("{other:?}"),
        };
        // The certificate names the ed25519 key of nine-bytes; that key signs.
        let mut ca = Vec::new();
        ssh_string(&mut ca, b"ssh-ed25519");
        ssh_string(&mut ca, &[9u8; 32]);
        assert_eq!(refuse_certificate_naming_another_ca(&tbs, &ca), Ok(()));
        // Any other key asked to sign it is refused, the named one reported.
        let mut other = Vec::new();
        ssh_string(&mut other, b"ssh-ed25519");
        ssh_string(&mut other, &[8u8; 32]);
        let refusal = refuse_certificate_naming_another_ca(&tbs, &other).unwrap_err();
        assert!(refusal.contains("a different CA key"), "{refusal}");
        assert!(refusal.contains(&tbs.ca_fingerprint), "{refusal}");
    }

    #[test]
    fn tool_sign_refuses_everything_on_the_ssh_ca_slot() {
        assert!(refuse_data_for_slot(&ssh_cert_unsigned(3_600), 0x83).is_err());
        assert!(refuse_data_for_slot(b"hello", 0x83).is_err());
        assert!(refuse_data_for_slot(b"hello", 0x9A).is_ok());
        assert!(refuse_data_for_slot(&ssh_cert_unsigned(3_600), 0x9A).is_err());
        assert!(refuse_data_for_slot(&tbs_shaped(), 0x82).is_err());
    }

    /// A self-signed certificate with subject `CN=<cn>`: the shape of a
    /// slot attestation as far as the slot gate reads it.
    fn attestation_naming(cn: &str) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        b.build().to_der().unwrap()
    }

    /// RFC 0012 §2.4 item 5: the CA key in slot 82 attests PIN always and
    /// touch always like 9C does, and is refused on the slot its
    /// attestation names, whatever slot the caller asked about.
    #[test]
    fn an_attestation_naming_a_slot_other_than_9c_is_refused() {
        assert_eq!(
            refuse_attestation_not_for_slot_9c(
                &attestation_naming("YubiKey PIV Attestation 9c"),
                0x9C
            ),
            Ok(())
        );
        assert_eq!(
            refuse_attestation_not_for_slot_9c(
                &attestation_naming("fibby PIV attestation 9c"),
                0x9C
            ),
            Ok(())
        );

        let refusal = refuse_attestation_not_for_slot_9c(
            &attestation_naming("YubiKey PIV Attestation 82"),
            0x82,
        )
        .unwrap_err();
        assert!(refusal.starts_with("slot 82: "), "{refusal}");
        assert!(refusal.contains("names slot 82, not 9C"), "{refusal}");

        // The verdict is the certificate's: a caller asking about 9C with
        // an attestation naming 82 is refused just the same.
        let refusal = refuse_attestation_not_for_slot_9c(
            &attestation_naming("YubiKey PIV Attestation 82"),
            0x9C,
        )
        .unwrap_err();
        assert!(refusal.contains("names slot 82, not 9C"), "{refusal}");

        for other in ["YubiKey PIV Attestation 9a", "YubiKey PIV Attestation 9d"] {
            assert!(
                refuse_attestation_not_for_slot_9c(&attestation_naming(other), 0x9C).is_err(),
                "{other}"
            );
        }
        let no_slot =
            refuse_attestation_not_for_slot_9c(&attestation_naming("Yubico PIV Attestation"), 0x9C)
                .unwrap_err();
        assert!(no_slot.contains("names no slot"), "{no_slot}");
        let unreadable = refuse_attestation_not_for_slot_9c(b"\x30\x00", 0x9C).unwrap_err();
        assert!(
            unreadable.contains("unreadable attestation"),
            "{unreadable}"
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
    fn only_the_five_act_namespaces_have_a_display_class() {
        assert_eq!(display_class("piggy-quote-v1"), Some(DisplayClass::Quote));
        assert_eq!(
            display_class("piggy-escalation-v1"),
            Some(DisplayClass::Escalation)
        );
        assert_eq!(
            display_class("piggy-certificate-v1"),
            Some(DisplayClass::Certificate)
        );
        assert_eq!(
            display_class("piggy-approval-v1"),
            Some(DisplayClass::Approval)
        );
        assert_eq!(DisplayClass::Approval.as_str(), "approval");
        assert_eq!(
            display_class("piggy-revocation-v1"),
            Some(DisplayClass::Revocation)
        );
        assert_eq!(DisplayClass::Revocation.as_str(), "revocation");
        assert_eq!(NAMESPACES.len(), 5);
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
        let mut reader = Reader::new(&data[6..]);
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
        let mut reader = Reader::new(&blob[6..]);
        assert_eq!(reader.u32(), Some(1));
        assert_eq!(reader.string().unwrap(), b"keyblob");
        assert_eq!(reader.string().unwrap(), b"piggy-quote-v1");
        assert_eq!(reader.string().unwrap(), b"");
        assert_eq!(reader.string().unwrap(), b"sha256");
        let mut sig = Reader::new(reader.string().unwrap());
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
        let context = prompt_context(
            DisplayClass::Approval,
            "5da19c98",
            0x9C,
            "piggy-approval-v1",
            "approve deploy of piggy 0.1.24",
        );
        assert_eq!(
            context,
            "operator act: approval\ncard 5da19c98, slot 9C\nnamespace piggy-approval-v1\n\napprove deploy of piggy 0.1.24"
        );
        let context = prompt_context(
            DisplayClass::Revocation,
            "5da19c98",
            0x9C,
            "piggy-revocation-v1",
            "cancel act X",
        );
        assert_eq!(
            context,
            "operator act: revocation\ncard 5da19c98, slot 9C\nnamespace piggy-revocation-v1\n\ncancel act X"
        );
    }
}
