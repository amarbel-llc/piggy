//! The OpenSSH certificate a CA slot signs (FDR 0007's slot kinds, lane 1):
//! the data `ssh-keygen -U -s` sends an agent is the certificate with
//! everything up to and including the CA key, and no signature (PROTOCOL.certkeys).
//! This module reads exactly that shape and nothing else: a refusal for
//! anything that is not an unsigned user certificate, a summary of what the
//! signature would certify for the PIN dialog, and the lifetime rule.
//!
//! Pure: no card, no agent, std and sha2 only.

use sha2::{Digest, Sha256};

/// The suffix every OpenSSH certificate key type ends with.
const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

/// What the dialog shows about a certificate's validity when there is no end.
const FOREVER: u64 = u64::MAX;

/// A user certificate's lifetime may exceed the limit by this much: ssh-keygen
/// back-dates the start by a minute, so `-V +24h` is 24h01m long.
pub const BACKDATE_ALLOWANCE_SECS: u64 = 5 * 60;

/// The built-in lifetime limit (the operator, 2026-11-22: 24 hours, built in
/// for now, configurable later).
pub const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Why data is not a certificate this crate will have a CA key sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshCertRefusal {
    #[error("not an OpenSSH certificate: {0}")]
    NotACertificate(String),
    #[error("a host certificate: this CA signs user certificates only")]
    NotAUserCertificate,
    #[error("the certificate names no principal, so it would be valid for every user")]
    NoPrincipals,
    #[error("the certificate has no end (valid until the end of time)")]
    NoExpiry,
    #[error("the certificate is valid for {secs} seconds, over the limit of {limit} seconds")]
    TooLong { secs: u64, limit: u64 },
    #[error("the certificate ends before it starts")]
    Backwards,
    #[error("the certificate starts {secs} seconds from now, over the {allowance} allowed")]
    StartsLater { secs: u64, allowance: u64 },
    #[error(
        "{what} holds a control or formatting character, which the dialog could not show truthfully"
    )]
    Undisplayable { what: &'static str },
    #[error("more than {max} {what}")]
    TooMany { what: &'static str, max: usize },
    #[error("{name:?} is not an option this CA signs")]
    UnknownOption { name: String },
    #[error("{name:?} appears twice")]
    DuplicateOption { name: String },
    #[error("the certificate ended {secs} seconds ago")]
    Expired { secs: u64 },
}

/// One critical option or extension: its name and its data, shown as text
/// when the data is one string (as `force-command`'s is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedData {
    pub name: String,
    pub value: Option<String>,
}

/// What an unsigned certificate would certify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertTbs {
    /// The certificate key type, `ssh-ed25519-cert-v01@openssh.com` and so on.
    pub cert_key_type: String,
    /// `SHA256:...` of the certified key.
    pub subject_fingerprint: String,
    /// `SHA256:...` of the CA key named inside the certificate.
    pub ca_fingerprint: String,
    /// The CA key's SSH wire blob as the certificate carries it, for the
    /// caller to compare with the key that is about to sign.
    pub ca_key_blob: Vec<u8>,
    pub serial: u64,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Seconds since the epoch; `0` is "from the beginning".
    pub valid_after: u64,
    /// Seconds since the epoch; `u64::MAX` is "forever".
    pub valid_before: u64,
    pub critical_options: Vec<NamedData>,
    pub extensions: Vec<NamedData>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| format!("{what} runs past the end of the data"))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self, what: &str) -> Result<u32, String> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &str) -> Result<u64, String> {
        let b = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn string(&mut self, what: &str) -> Result<&'a [u8], String> {
        let n = self.u32(what)? as usize;
        self.take(n, what)
    }

    fn text(&mut self, what: &str) -> Result<&'a str, String> {
        std::str::from_utf8(self.string(what)?).map_err(|_| format!("{what} is not UTF-8"))
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// The key types a certificate may certify and the fields each carries after
/// the nonce, as the count of strings (an RSA key's `e` and `n` are strings
/// on the wire as mpints).
fn key_field_strings(base: &str) -> Option<usize> {
    match base {
        "ssh-ed25519" => Some(1),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => Some(2),
        "ssh-rsa" => Some(2),
        "sk-ssh-ed25519@openssh.com" => Some(2),
        "sk-ecdsa-sha2-nistp256@openssh.com" => Some(3),
        _ => None,
    }
}

/// The base key type of a certificate key type, when it is one.
fn base_key_type(cert_key_type: &str) -> Option<&str> {
    let stem = cert_key_type.strip_suffix(CERT_SUFFIX)?;
    // `sk-ssh-ed25519-cert-v01@openssh.com` is spelled this way in OpenSSH.
    match stem {
        "sk-ssh-ed25519" => Some("sk-ssh-ed25519@openssh.com"),
        "sk-ecdsa-sha2-nistp256" => Some("sk-ecdsa-sha2-nistp256@openssh.com"),
        other => Some(other),
    }
}

/// Whether `data` starts like an OpenSSH certificate: a string that is a
/// certificate key type. Cheap and total; a `true` is no promise that it
/// parses.
pub fn looks_like_ssh_certificate(data: &[u8]) -> bool {
    let mut r = Reader::new(data);
    match r.text("key type") {
        Ok(t) => t.ends_with(CERT_SUFFIX) && t.len() > CERT_SUFFIX.len(),
        Err(_) => false,
    }
}

fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", base64_no_pad(&Sha256::digest(blob)))
}

fn base64_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn string_of(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

/// The longest key id or principal, in bytes (the Fable review, 2026-11-22).
const MAX_NAME: usize = 64;
/// The most principals a certificate this CA signs may name.
const MAX_PRINCIPALS: usize = 8;
/// The longest option value, in bytes.
const MAX_OPTION_VALUE: usize = 256;

/// A key id or principal: 1 to [`MAX_NAME`] bytes of `[A-Za-z0-9._@:+-]` and
/// nothing else. Plain ASCII by refusal, so no invisible, reordering,
/// look-alike or separator character can make the dialog say something
/// the certificate does not.
fn plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b':' | b'+' | b'-')
        })
}

/// An option value: printable ASCII (space to tilde), at most
/// [`MAX_OPTION_VALUE`] bytes.
fn plain_text(s: &str) -> bool {
    s.len() <= MAX_OPTION_VALUE && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// What an option or extension carries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Carries {
    Flag,
    Value,
}

/// The critical options this CA signs: these three and no other.
const CRITICAL_OPTIONS: [(&str, Carries); 3] = [
    ("force-command", Carries::Value),
    ("source-address", Carries::Value),
    ("verify-required", Carries::Flag),
];

/// The extensions this CA signs. `no-touch-required`, which waives a
/// security key's touch, is deliberately not among them.
const EXTENSIONS: [(&str, Carries); 5] = [
    ("permit-X11-forwarding", Carries::Flag),
    ("permit-agent-forwarding", Carries::Flag),
    ("permit-port-forwarding", Carries::Flag),
    ("permit-pty", Carries::Flag),
    ("permit-user-rc", Carries::Flag),
];

/// The packed `name, data` pairs of the critical options or the extensions:
/// only the `known` ones, each once, a flag with no data and a value option
/// with one printable-ASCII string.
fn named_data(
    packed: &[u8],
    what: &str,
    known: &[(&str, Carries)],
    undisplayable: &'static str,
) -> Result<Vec<NamedData>, SshCertRefusal> {
    let bad = SshCertRefusal::NotACertificate;
    let undisplayable = SshCertRefusal::Undisplayable {
        what: undisplayable,
    };
    let mut r = Reader::new(packed);
    let mut out: Vec<NamedData> = Vec::new();
    while !r.done() {
        let name = r.text(&format!("{what} name")).map_err(bad)?.to_owned();
        let data = r.string(&format!("{what} data")).map_err(bad)?;
        if !plain_text(&name) {
            return Err(undisplayable);
        }
        let Some((_, carries)) = known.iter().find(|(known_name, _)| *known_name == name) else {
            return Err(SshCertRefusal::UnknownOption { name });
        };
        if out.iter().any(|d| d.name == name) {
            return Err(SshCertRefusal::DuplicateOption { name });
        }
        // The data is itself one string for an option with a value and empty
        // for a flag.
        let value = match carries {
            Carries::Flag if data.is_empty() => None,
            Carries::Flag => return Err(undisplayable),
            Carries::Value => {
                let mut inner = Reader::new(data);
                match inner.text("option value") {
                    Ok(s) if inner.done() && !s.is_empty() && plain_text(s) => Some(s.to_owned()),
                    _ => return Err(undisplayable),
                }
            }
        };
        out.push(NamedData { name, value });
    }
    Ok(out)
}

/// The certified key's fields checked for what they claim to be (finding 8 of
/// the Fable review): a key of the stated type and a sane size. Anything
/// else is not a key a certificate should name.
fn check_key_fields(base: &str, fields: &[&[u8]]) -> Result<(), String> {
    let printable = |b: &[u8]| {
        !b.is_empty() && b.len() <= MAX_NAME && b.iter().all(|c| (0x20..=0x7e).contains(c))
    };
    let curve = |name: &str, point_len: usize| -> Result<(), String> {
        if fields[0] != name.as_bytes() {
            return Err(format!("the curve name is not {name}"));
        }
        if fields[1].len() != point_len || fields[1].first() != Some(&4) {
            return Err(format!(
                "the {name} point is not {point_len} uncompressed bytes"
            ));
        }
        Ok(())
    };
    match base {
        "ssh-ed25519" if fields[0].len() == 32 => Ok(()),
        "ssh-ed25519" => Err("an ed25519 key is 32 bytes".into()),
        "ecdsa-sha2-nistp256" => curve("nistp256", 65),
        "ecdsa-sha2-nistp384" => curve("nistp384", 97),
        "ecdsa-sha2-nistp521" => curve("nistp521", 133),
        "ssh-rsa" => {
            let strip = |b: &[u8]| b.iter().skip_while(|c| **c == 0).count();
            let (e, n) = (strip(fields[0]), strip(fields[1]));
            if !(1..=8).contains(&e) {
                return Err("the RSA exponent is not 1 to 8 bytes".into());
            }
            if !(256..=1024).contains(&n) {
                return Err("the RSA modulus is not 2048 to 8192 bits".into());
            }
            Ok(())
        }
        "sk-ssh-ed25519@openssh.com" if fields[0].len() == 32 && printable(fields[1]) => Ok(()),
        "sk-ecdsa-sha2-nistp256@openssh.com" if printable(fields[2]) => curve("nistp256", 65),
        _ => Err(format!("a {base} key with fields that are not one")),
    }
}

/// Read the data an agent is asked to sign for `ssh-keygen -U -s`: a user
/// certificate with its CA key and no signature. Anything else is refused.
pub fn parse_unsigned_certificate(data: &[u8]) -> Result<SshCertTbs, SshCertRefusal> {
    let bad = |why: String| SshCertRefusal::NotACertificate(why);
    let mut r = Reader::new(data);
    let cert_key_type = r.text("key type").map_err(bad)?.to_owned();
    let base = base_key_type(&cert_key_type)
        .ok_or_else(|| bad(format!("{cert_key_type:?} is not a certificate key type")))?
        .to_owned();
    let n_fields = key_field_strings(&base)
        .ok_or_else(|| bad(format!("a {base} key is not one this CA certifies")))?;
    let nonce = r.string("nonce").map_err(bad)?;
    if nonce.len() != 32 {
        return Err(bad(format!("the nonce is {} bytes, not 32", nonce.len())));
    }

    // The certified key's fields, kept verbatim for its fingerprint and
    // checked for what they claim to be.
    let key_start = r.pos;
    let mut fields: Vec<&[u8]> = Vec::with_capacity(n_fields);
    for i in 0..n_fields {
        fields.push(r.string(&format!("key field {}", i + 1)).map_err(bad)?);
    }
    check_key_fields(&base, &fields).map_err(bad)?;
    let key_fields = &data[key_start..r.pos];
    let mut subject_blob = string_of(base.as_bytes());
    subject_blob.extend_from_slice(key_fields);

    let serial = r.u64("serial").map_err(bad)?;
    let cert_type = r.u32("certificate type").map_err(bad)?;
    let key_id = r.text("key id").map_err(bad)?.to_owned();
    if !plain_name(&key_id) {
        return Err(SshCertRefusal::Undisplayable { what: "the key id" });
    }
    let principals_packed = r.string("principals").map_err(bad)?;
    let valid_after = r.u64("valid after").map_err(bad)?;
    let valid_before = r.u64("valid before").map_err(bad)?;
    let critical_packed = r.string("critical options").map_err(bad)?;
    let extensions_packed = r.string("extensions").map_err(bad)?;
    let reserved = r.string("reserved").map_err(bad)?;
    let ca_blob = r.string("signature key").map_err(bad)?;
    if !r.done() {
        return Err(bad(
            "bytes follow the CA key: this is a signed certificate, not data to sign".into(),
        ));
    }
    if !reserved.is_empty() {
        return Err(bad("the reserved field is not empty".into()));
    }
    if cert_type != 1 {
        return Err(if cert_type == 2 {
            SshCertRefusal::NotAUserCertificate
        } else {
            bad(format!(
                "certificate type {cert_type} is neither user nor host"
            ))
        });
    }
    let mut principals = Vec::new();
    let mut pr = Reader::new(principals_packed);
    while !pr.done() {
        let p = pr.text("principal").map_err(bad)?;
        if p.is_empty() {
            return Err(bad("an empty principal".into()));
        }
        if !plain_name(p) {
            return Err(SshCertRefusal::Undisplayable {
                what: "a principal",
            });
        }
        if principals.len() == MAX_PRINCIPALS {
            return Err(SshCertRefusal::TooMany {
                what: "principals",
                max: MAX_PRINCIPALS,
            });
        }
        principals.push(p.to_owned());
    }
    if principals.is_empty() {
        return Err(SshCertRefusal::NoPrincipals);
    }
    if valid_before <= valid_after {
        return Err(SshCertRefusal::Backwards);
    }
    // The CA key must itself be a key blob: a string type first.
    let mut ca = Reader::new(ca_blob);
    ca.text("CA key type").map_err(bad)?;

    Ok(SshCertTbs {
        cert_key_type,
        subject_fingerprint: fingerprint(&subject_blob),
        ca_fingerprint: fingerprint(ca_blob),
        ca_key_blob: ca_blob.to_vec(),
        serial,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options: named_data(
            critical_packed,
            "critical option",
            &CRITICAL_OPTIONS,
            "a critical option",
        )?,
        extensions: named_data(extensions_packed, "extension", &EXTENSIONS, "an extension")?,
    })
}

impl SshCertTbs {
    /// `valid_before - valid_after`, when the certificate has an end.
    pub fn lifetime_secs(&self) -> Option<u64> {
        if self.valid_before == FOREVER {
            None
        } else {
            Some(self.valid_before.saturating_sub(self.valid_after))
        }
    }

    /// The validity rule, checked before any prompt, against `now` (seconds
    /// since the epoch): an end is required, the span may not exceed
    /// `max_secs` plus the back-dating allowance, and the certificate may not
    /// start later than the allowance from now (a `-V 20300101:20300102`
    /// certificate, valid only years ahead, is not a short-lived one).
    pub fn check_validity(&self, max_secs: u64, now: u64) -> Result<(), SshCertRefusal> {
        let secs = match self.lifetime_secs() {
            None => return Err(SshCertRefusal::NoExpiry),
            Some(secs) => secs,
        };
        if secs > max_secs.saturating_add(BACKDATE_ALLOWANCE_SECS) {
            return Err(SshCertRefusal::TooLong {
                secs,
                limit: max_secs,
            });
        }
        let ahead = self.valid_after.saturating_sub(now);
        if ahead > BACKDATE_ALLOWANCE_SECS {
            return Err(SshCertRefusal::StartsLater {
                secs: ahead,
                allowance: BACKDATE_ALLOWANCE_SECS,
            });
        }
        // Not already over: `now` must be inside [valid_after - allowance,
        // valid_before).
        if now >= self.valid_before {
            return Err(SshCertRefusal::Expired {
                secs: now - self.valid_before,
            });
        }
        Ok(())
    }

    /// The text the PIN dialog shows: what this signature would certify.
    /// Plain ASCII lines (the parser admits nothing else), each principal and
    /// each critical option on a line of its own and each value in quotes, so
    /// no field can read as another line or another option. Its height is
    /// bounded by the parser's limits: at most 24 rendered lines at the
    /// dialog's width, however hostile the certificate.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        s.push_str("OpenSSH user certificate\n");
        s.push_str(&format!("Key id: {}\n", self.key_id));
        for principal in &self.principals {
            s.push_str(&format!("Principal: {principal}\n"));
        }
        s.push_str(&format!("Certified key: {}\n", self.subject_fingerprint));
        s.push_str(&format!("Signed by CA: {}\n", self.ca_fingerprint));
        s.push_str(&format!("Serial: {}\n", self.serial));
        s.push_str(&format!(
            "Valid: {} to {}\n",
            show_time(self.valid_after, "the beginning"),
            show_time(self.valid_before, "forever")
        ));
        if let Some(secs) = self.lifetime_secs() {
            s.push_str(&format!("Lifetime: {}\n", show_span(secs)));
        }
        if self.critical_options.is_empty() {
            s.push_str("Critical options: none\n");
        }
        for option in &self.critical_options {
            match &option.value {
                Some(v) => s.push_str(&format!(
                    "Critical option: {}: \"{}\"\n",
                    option.name,
                    v.replace('\\', "\\\\").replace('"', "\\\"")
                )),
                None => s.push_str(&format!("Critical option: {}\n", option.name)),
            }
        }
        s.push_str("Extensions: ");
        if self.extensions.is_empty() {
            s.push_str("none");
        } else {
            let names: Vec<&str> = self.extensions.iter().map(|e| e.name.as_str()).collect();
            s.push_str(&names.join(", "));
        }
        s
    }
}

/// A UTC time as `2026-11-22T19:02:00Z`; `0` and `u64::MAX` as the words.
fn show_time(secs: u64, edge: &str) -> String {
    if secs == 0 || secs == FOREVER {
        return edge.to_owned();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 as a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn show_span(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86_400,
        secs % 86_400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&string_of(bytes));
    }

    fn packed(items: &[(&str, Option<&str>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, value) in items {
            put_string(&mut out, name.as_bytes());
            match value {
                Some(v) => {
                    let mut inner = Vec::new();
                    put_string(&mut inner, v.as_bytes());
                    put_string(&mut out, &inner);
                }
                None => put_string(&mut out, b""),
            }
        }
        out
    }

    /// A CA key blob for an ed25519 key of all `fill` bytes.
    fn ca_blob(fill: u8) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, &[fill; 32]);
        b
    }

    struct Cert {
        key_type: &'static str,
        nonce: Vec<u8>,
        fields: Vec<Vec<u8>>,
        serial: u64,
        cert_type: u32,
        key_id: &'static str,
        principals: Vec<&'static str>,
        after: u64,
        before: u64,
        critical: Vec<u8>,
        extensions: Vec<u8>,
        reserved: Vec<u8>,
        ca: Vec<u8>,
    }

    impl Cert {
        fn user() -> Cert {
            Cert {
                key_type: "ssh-ed25519-cert-v01@openssh.com",
                nonce: vec![1u8; 32],
                fields: vec![vec![7u8; 32]],
                serial: 5,
                cert_type: 1,
                key_id: "grant-1",
                principals: vec!["deploy-site", "restart-service"],
                after: 1_795_000_000,
                before: 1_795_007_200,
                critical: packed(&[("force-command", Some("/usr/bin/true"))]),
                extensions: packed(&[("permit-pty", None)]),
                reserved: Vec::new(),
                ca: ca_blob(9),
            }
        }

        fn unsigned(&self) -> Vec<u8> {
            let mut d = Vec::new();
            put_string(&mut d, self.key_type.as_bytes());
            put_string(&mut d, &self.nonce);
            for f in &self.fields {
                put_string(&mut d, f);
            }
            d.extend_from_slice(&self.serial.to_be_bytes());
            d.extend_from_slice(&self.cert_type.to_be_bytes());
            put_string(&mut d, self.key_id.as_bytes());
            let mut pr = Vec::new();
            for p in &self.principals {
                put_string(&mut pr, p.as_bytes());
            }
            put_string(&mut d, &pr);
            d.extend_from_slice(&self.after.to_be_bytes());
            d.extend_from_slice(&self.before.to_be_bytes());
            put_string(&mut d, &self.critical);
            put_string(&mut d, &self.extensions);
            put_string(&mut d, &self.reserved);
            put_string(&mut d, &self.ca);
            d
        }
    }

    #[test]
    fn a_user_certificate_reads_back_field_for_field() {
        let tbs = parse_unsigned_certificate(&Cert::user().unsigned()).unwrap();
        assert_eq!(tbs.cert_key_type, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(tbs.key_id, "grant-1");
        assert_eq!(tbs.principals, ["deploy-site", "restart-service"]);
        assert_eq!(tbs.serial, 5);
        assert_eq!(
            (tbs.valid_after, tbs.valid_before),
            (1_795_000_000, 1_795_007_200)
        );
        assert_eq!(tbs.lifetime_secs(), Some(7_200));
        assert_eq!(
            tbs.critical_options,
            [NamedData {
                name: "force-command".into(),
                value: Some("/usr/bin/true".into())
            }]
        );
        assert_eq!(
            tbs.extensions,
            [NamedData {
                name: "permit-pty".into(),
                value: None
            }]
        );
        assert!(tbs.subject_fingerprint.starts_with("SHA256:"));
        assert_eq!(tbs.ca_fingerprint, fingerprint(&ca_blob(9)));
        assert_ne!(tbs.subject_fingerprint, tbs.ca_fingerprint);
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0;
        for c in s.bytes().filter(|c| *c != b'=') {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                other => panic!("not base64: {other}"),
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    /// A certificate `ssh-keygen -U -s` really made (through a card agent over
    /// fibby's slot-83 key, 2026-11-22): public material only. The unsigned
    /// data is the blob without its trailing signature string.
    const REAL_CERT: &str = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIAmYYQNoQ24Q3INBlC00FhU1N1+SneR2X75Bj5siKmJhAAAAILIY/BI1PL2XNutnTHgTtcAGGwjfPoLsPRWSIDEBRd27AAAAAAAAAAAAAAABAAAAE2Nvb3JkaW5hdG9yLXByb29mLUEAAAAPAAAAC2Nvb3JkaW5hdG9yAAAAAGsDPCgAAAAAawNYigAAAAAAAAAWAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFgpI7YdK4MJXV2wMpFRTIIrPYIGD4QuQpRBzSm8F70qwt38xeVAuO9COO6vZIeu1Qq8TVZ/mH4arM6JKzVvnlMAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIQCyG8w1+4VAsvHoPThTaCH34AgY6IC8b2bfvLZ2y/28LgAAACBCmrJF1JmOOEOzuOeXvd3R/M9Hyk6ry1028cSIMLlivQ==";

    #[test]
    fn a_certificate_ssh_keygen_made_reads_as_ssh_keygen_shows_it() {
        let blob = base64_decode(REAL_CERT);
        // The signed certificate itself is refused: it carries a signature.
        assert!(parse_unsigned_certificate(&blob).is_err());
        // Its unsigned prefix is the longest one that parses.
        let tbs = (0..=blob.len())
            .rev()
            .find_map(|n| parse_unsigned_certificate(&blob[..n]).ok())
            .expect("an unsigned prefix parses");
        // Every value below is what `ssh-keygen -L` printed for it.
        assert_eq!(tbs.cert_key_type, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(
            tbs.subject_fingerprint,
            "SHA256:7N8wnTdjd536aUPrSbOBGaj0hG7C97qc7/tQyR8n26E"
        );
        assert_eq!(
            tbs.ca_fingerprint,
            "SHA256:GuxEpThI+sAZHJvPbntIMZir0om/uiwmjt+yvpX25q0"
        );
        assert_eq!(tbs.key_id, "coordinator-proof-A");
        assert_eq!(tbs.serial, 0);
        assert_eq!(tbs.principals, ["coordinator"]);
        assert_eq!(show_time(tbs.valid_after, "x"), "2026-11-22T19:02:00Z");
        assert_eq!(show_time(tbs.valid_before, "x"), "2026-11-22T21:03:06Z");
        assert!(tbs.critical_options.is_empty());
        assert_eq!(
            tbs.extensions,
            [NamedData {
                name: "permit-user-rc".into(),
                value: None
            }]
        );
        // And two hours of lifetime passes the 24-hour rule.
        assert!(
            tbs.check_validity(MAX_LIFETIME_SECS, tbs.valid_after + 60)
                .is_ok()
        );
    }

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64_no_pad(b""), "");
        assert_eq!(base64_no_pad(b"f"), "Zg");
        assert_eq!(base64_no_pad(b"fo"), "Zm8");
        assert_eq!(base64_no_pad(b"foo"), "Zm9v");
        assert_eq!(base64_no_pad(b"foob"), "Zm9vYg");
    }

    #[test]
    fn every_supported_key_type_parses() {
        for (key_type, fields) in [
            ("ssh-ed25519-cert-v01@openssh.com", vec![vec![1u8; 32]]),
            (
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                vec![b"nistp256".to_vec(), vec![4u8; 65]],
            ),
            (
                "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                vec![b"nistp384".to_vec(), vec![4u8; 97]],
            ),
            (
                "ssh-rsa-cert-v01@openssh.com",
                vec![vec![1, 0, 1], {
                    let mut n = vec![0u8, 0xc0];
                    n.extend(vec![0x55u8; 255]);
                    n
                }],
            ),
            (
                "sk-ssh-ed25519-cert-v01@openssh.com",
                vec![vec![1u8; 32], b"ssh:".to_vec()],
            ),
            (
                "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
                vec![b"nistp256".to_vec(), vec![4u8; 65], b"ssh:".to_vec()],
            ),
        ] {
            let mut cert = Cert::user();
            cert.key_type = key_type;
            cert.fields = fields;
            let tbs = parse_unsigned_certificate(&cert.unsigned())
                .unwrap_or_else(|e| panic!("{key_type}: {e}"));
            assert_eq!(tbs.cert_key_type, key_type);
        }
    }

    #[test]
    fn what_is_not_an_unsigned_user_certificate_is_refused() {
        let user = Cert::user();
        let refused = |c: &Cert| parse_unsigned_certificate(&c.unsigned()).unwrap_err();

        let mut host = Cert::user();
        host.cert_type = 2;
        assert_eq!(refused(&host), SshCertRefusal::NotAUserCertificate);

        let mut weird = Cert::user();
        weird.cert_type = 7;
        assert!(matches!(
            refused(&weird),
            SshCertRefusal::NotACertificate(_)
        ));

        let mut none = Cert::user();
        none.principals = vec![];
        assert_eq!(refused(&none), SshCertRefusal::NoPrincipals);

        let mut empty_principal = Cert::user();
        empty_principal.principals = vec![""];
        assert!(matches!(
            refused(&empty_principal),
            SshCertRefusal::NotACertificate(_)
        ));

        let mut backwards = Cert::user();
        backwards.before = backwards.after;
        assert_eq!(refused(&backwards), SshCertRefusal::Backwards);

        let mut reserved = Cert::user();
        reserved.reserved = vec![1];
        assert!(matches!(
            refused(&reserved),
            SshCertRefusal::NotACertificate(_)
        ));

        let mut dss = Cert::user();
        dss.key_type = "ssh-dss-cert-v01@openssh.com";
        assert!(matches!(refused(&dss), SshCertRefusal::NotACertificate(_)));

        // A signed certificate (a signature string after the CA key).
        let mut signed = user.unsigned();
        put_string(&mut signed, b"signature");
        assert!(matches!(
            parse_unsigned_certificate(&signed).unwrap_err(),
            SshCertRefusal::NotACertificate(m) if m.contains("signed certificate")
        ));

        // Truncated at every length: never a panic, always a refusal.
        let whole = user.unsigned();
        for n in 0..whole.len() {
            assert!(parse_unsigned_certificate(&whole[..n]).is_err(), "{n}");
        }
        // Not a certificate at all.
        assert!(parse_unsigned_certificate(b"").is_err());
        assert!(parse_unsigned_certificate(b"ssh-ed25519").is_err());
        assert!(parse_unsigned_certificate(&[0xff; 64]).is_err());
    }

    #[test]
    fn the_shape_test_is_cheap_and_total() {
        assert!(looks_like_ssh_certificate(&Cert::user().unsigned()));
        // A truncated or garbled start is false, not a panic.
        assert!(!looks_like_ssh_certificate(b""));
        assert!(!looks_like_ssh_certificate(&[0, 0, 0, 200, 1, 2]));
        // sshsig signed data, an SSH login challenge's session-id string and
        // a DER TBSCertificate do not look like one.
        assert!(!looks_like_ssh_certificate(b"SSHSIG\0\0\0\x04file"));
        assert!(!looks_like_ssh_certificate(&[0x30, 0x82, 0x01, 0x00]));
        let mut plain = Vec::new();
        put_string(&mut plain, b"ssh-ed25519");
        assert!(!looks_like_ssh_certificate(&plain));
    }

    #[test]
    fn the_lifetime_rule_needs_an_end_and_a_span_under_the_limit() {
        let mut cert = Cert::user();
        let day = MAX_LIFETIME_SECS;
        // Exactly the limit, and ssh-keygen's one-minute back-dating on top.
        cert.before = cert.after + day + 60;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        // Signed a minute after it starts, as ssh-keygen's back-dating makes it.
        let now = cert.after + 60;
        assert!(tbs.check_validity(day, now).is_ok());
        // Past the limit plus the allowance.
        cert.before = cert.after + day + BACKDATE_ALLOWANCE_SECS + 1;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        assert_eq!(
            tbs.check_validity(day, now),
            Err(SshCertRefusal::TooLong {
                secs: day + BACKDATE_ALLOWANCE_SECS + 1,
                limit: day
            })
        );
        // No end.
        cert.before = u64::MAX;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        assert_eq!(tbs.check_validity(day, now), Err(SshCertRefusal::NoExpiry));
    }

    #[test]
    fn a_certificate_that_starts_in_the_future_is_refused_however_short() {
        let mut cert = Cert::user();
        let now = cert.after;
        // Starts years ahead: short, but not short-lived from now.
        cert.after = now + 4 * 365 * 86_400;
        cert.before = cert.after + 3_600;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        assert!(matches!(
            tbs.check_validity(MAX_LIFETIME_SECS, now),
            Err(SshCertRefusal::StartsLater { .. })
        ));
        // Starting within the allowance (clock skew, back-dating) passes.
        cert.after = now + BACKDATE_ALLOWANCE_SECS;
        cert.before = cert.after + 3_600;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        assert!(tbs.check_validity(MAX_LIFETIME_SECS, now).is_ok());
        cert.after = now + BACKDATE_ALLOWANCE_SECS + 1;
        cert.before = cert.after + 3_600;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        assert!(tbs.check_validity(MAX_LIFETIME_SECS, now).is_err());
    }

    #[test]
    fn a_field_that_could_fake_the_dialog_is_refused() {
        // Control characters (a carriage return and a CSI sequence that erase
        // and rewrite a terminal line, a newline that adds a fake line),
        // bidirectional and zero-width formatting characters.
        let hostile = [
            "root\r\u{1b}[2KPrincipals: deploy-site",
            "a\nPrincipals: deploy-site",
            "a\tb",
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{2066}b",
            "a\u{FEFF}b",
            "a\u{0085}b",
        ];
        for text in hostile {
            let mut cert = Cert::user();
            cert.principals = vec![text];
            assert_eq!(
                parse_unsigned_certificate(&cert.unsigned()).unwrap_err(),
                SshCertRefusal::Undisplayable {
                    what: "a principal"
                },
                "{text:?}"
            );
            let mut cert = Cert::user();
            cert.key_id = text;
            assert_eq!(
                parse_unsigned_certificate(&cert.unsigned()).unwrap_err(),
                SshCertRefusal::Undisplayable { what: "the key id" },
                "{text:?}"
            );
            let mut cert = Cert::user();
            cert.critical = packed(&[("force-command", Some(text))]);
            assert_eq!(
                parse_unsigned_certificate(&cert.unsigned()).unwrap_err(),
                SshCertRefusal::Undisplayable {
                    what: "a critical option"
                },
                "{text:?}"
            );
            let mut cert = Cert::user();
            cert.extensions = packed(&[(text, None)]);
            assert_eq!(
                parse_unsigned_certificate(&cert.unsigned()).unwrap_err(),
                SshCertRefusal::Undisplayable {
                    what: "an extension"
                },
                "{text:?}"
            );
        }
        // Nor is non-ASCII text shown: ASCII by refusal (finding 3), so no
        // look-alike, invisible or reordering character gets through.
        for text in ["déploiement", "运维", "a\u{a0}b", "a\u{2800}b", "a\u{61c}b"] {
            let mut cert = Cert::user();
            cert.principals = vec![text];
            assert_eq!(
                parse_unsigned_certificate(&cert.unsigned()).unwrap_err(),
                SshCertRefusal::Undisplayable {
                    what: "a principal"
                },
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_ca_key_the_certificate_names_is_kept_whole() {
        let tbs = parse_unsigned_certificate(&Cert::user().unsigned()).unwrap();
        assert_eq!(tbs.ca_key_blob, ca_blob(9));
    }

    // The Fable review of c7dd0561 (findings 2, 3, 6, 7, 8): the text the dialog
    // shows is bounded and plain by construction, only known options pass,
    // an expired certificate is not signed, and the certified key is a key.

    fn refused(cert: &Cert) -> SshCertRefusal {
        parse_unsigned_certificate(&cert.unsigned()).unwrap_err()
    }

    #[test]
    fn the_key_id_and_principals_are_short_plain_ascii() {
        let long = Box::leak("a".repeat(65).into_boxed_str());
        let ok64 = Box::leak("a".repeat(64).into_boxed_str());
        for bad in [
            long,
            "two words",
            "a,b",
            "caf\u{e9}",
            "a\"b",
            "a=b",
            "x/y",
            "*",
            "",
        ] {
            let mut cert = Cert::user();
            cert.key_id = bad;
            assert!(
                matches!(
                    refused(&cert),
                    SshCertRefusal::Undisplayable { .. } | SshCertRefusal::NotACertificate(_)
                ),
                "key id {bad:?}"
            );
            let mut cert = Cert::user();
            cert.principals = vec![bad];
            assert!(
                matches!(
                    refused(&cert),
                    SshCertRefusal::Undisplayable { .. } | SshCertRefusal::NotACertificate(_)
                ),
                "principal {bad:?}"
            );
        }
        let mut cert = Cert::user();
        cert.key_id = ok64;
        cert.principals = vec![ok64, "user.name_1+x@host:2-b"];
        assert!(parse_unsigned_certificate(&cert.unsigned()).is_ok());
    }

    #[test]
    fn at_most_eight_principals() {
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let mut cert = Cert::user();
        cert.principals = names[..8].to_vec();
        assert!(parse_unsigned_certificate(&cert.unsigned()).is_ok());
        cert.principals = names.to_vec();
        assert!(matches!(
            refused(&cert),
            SshCertRefusal::TooMany {
                what: "principals",
                ..
            }
        ));
    }

    #[test]
    fn only_known_options_and_extensions_once_each() {
        let ok_options = [
            ("force-command", Some("/usr/bin/true")),
            ("source-address", Some("10.0.0.0/8,192.168.1.1")),
            ("verify-required", None),
        ];
        let mut cert = Cert::user();
        cert.critical = packed(&ok_options);
        cert.extensions = packed(&[
            ("permit-X11-forwarding", None),
            ("permit-agent-forwarding", None),
            ("permit-port-forwarding", None),
            ("permit-pty", None),
            ("permit-user-rc", None),
        ]);
        assert!(parse_unsigned_certificate(&cert.unsigned()).is_ok());

        // An option this CA does not know, a duplicate, and the one extension
        // that waives the security key's touch.
        for critical in [
            packed(&[("tunnel", Some("x"))]),
            packed(&[("force-command", Some("a")), ("force-command", Some("b"))]),
        ] {
            let mut cert = Cert::user();
            cert.critical = critical;
            assert!(
                matches!(
                    refused(&cert),
                    SshCertRefusal::UnknownOption { .. } | SshCertRefusal::DuplicateOption { .. }
                ),
                "{:?}",
                refused(&cert)
            );
        }
        for extensions in [
            packed(&[("no-touch-required", None)]),
            packed(&[("login@example.com", Some("x"))]),
            packed(&[("permit-pty", None), ("permit-pty", None)]),
        ] {
            let mut cert = Cert::user();
            cert.extensions = extensions;
            assert!(
                matches!(
                    refused(&cert),
                    SshCertRefusal::UnknownOption { .. } | SshCertRefusal::DuplicateOption { .. }
                ),
                "{:?}",
                refused(&cert)
            );
        }
    }

    #[test]
    fn option_values_are_short_printable_ascii_and_never_opaque() {
        for value in ["caf\u{e9}", "tab\there", "a\u{7f}b"] {
            let mut cert = Cert::user();
            cert.critical = packed(&[("force-command", Some(value))]);
            assert!(
                matches!(refused(&cert), SshCertRefusal::Undisplayable { .. }),
                "{value:?}"
            );
        }
        // Longer than a line the dialog could show whole.
        let long = "x".repeat(257);
        let mut cert = Cert::user();
        cert.critical = packed(&[("force-command", Some(&long))]);
        assert!(matches!(
            refused(&cert),
            SshCertRefusal::Undisplayable { .. }
        ));
        // Data that is not one UTF-8 string is refused, not summarised as a
        // byte count.
        let mut data = Vec::new();
        put_string(&mut data, b"force-command");
        put_string(&mut data, &[0xff, 0xfe, 0xfd]);
        let mut cert = Cert::user();
        cert.critical = data;
        assert!(
            matches!(refused(&cert), SshCertRefusal::Undisplayable { .. }),
            "{:?}",
            refused(&cert)
        );
        // A flag carrying data, and an option that needs a value without one.
        let mut cert = Cert::user();
        cert.critical = packed(&[("verify-required", Some("x"))]);
        assert!(matches!(
            refused(&cert),
            SshCertRefusal::Undisplayable { .. }
        ));
        let mut cert = Cert::user();
        cert.critical = packed(&[("force-command", None)]);
        assert!(matches!(
            refused(&cert),
            SshCertRefusal::Undisplayable { .. }
        ));
    }

    #[test]
    fn the_dialog_cannot_be_made_to_read_as_other_lines_or_grow_without_bound() {
        // A value that spells another option, and a long worst case.
        let mut cert = Cert::user();
        cert.critical = packed(&[("force-command", Some("/bin/true, source-address=10.0.0.1"))]);
        let text = parse_unsigned_certificate(&cert.unsigned())
            .unwrap()
            .describe();
        let option_lines: Vec<&str> = text
            .lines()
            .filter(|l| l.trim_start().starts_with("source-address"))
            .collect();
        assert!(option_lines.is_empty(), "{text}");
        assert!(
            text.contains("force-command: \"/bin/true, source-address=10.0.0.1\""),
            "{text}"
        );

        // The worst case that parses: its dialog fits 24 rendered lines
        // (the operator-act dialog's old limit), whatever the certificate says.
        let mut cert = Cert::user();
        cert.principals = ["a"; 8].to_vec();
        let value = "y".repeat(256);
        cert.critical = packed(&[
            ("force-command", Some(&value)),
            ("source-address", Some(&value)),
            ("verify-required", None),
        ]);
        cert.extensions = packed(&[
            ("permit-X11-forwarding", None),
            ("permit-agent-forwarding", None),
            ("permit-port-forwarding", None),
            ("permit-pty", None),
            ("permit-user-rc", None),
        ]);
        let text = parse_unsigned_certificate(&cert.unsigned())
            .unwrap()
            .describe();
        let rendered: usize = text
            .lines()
            .map(|l| 1 + l.chars().count().saturating_sub(1) / 100)
            .sum();
        assert!(rendered <= 24, "{rendered} rendered lines:\n{text}");
        // One line per principal.
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("Principal: "))
                .count(),
            8,
            "{text}"
        );
    }

    #[test]
    fn an_expired_certificate_is_refused_and_so_is_one_not_yet_valid() {
        let mut cert = Cert::user();
        let after = cert.after;
        cert.before = after + 3_600;
        let tbs = parse_unsigned_certificate(&cert.unsigned()).unwrap();
        // Inside the window.
        assert!(tbs.check_validity(MAX_LIFETIME_SECS, after + 60).is_ok());
        // At and after the end.
        assert!(matches!(
            tbs.check_validity(MAX_LIFETIME_SECS, after + 3_600),
            Err(SshCertRefusal::Expired { .. })
        ));
        assert!(matches!(
            tbs.check_validity(MAX_LIFETIME_SECS, after + 86_400),
            Err(SshCertRefusal::Expired { .. })
        ));
    }

    #[test]
    fn the_certified_key_must_be_a_key_of_its_type_and_the_nonce_32_bytes() {
        let mut cert = Cert::user();
        cert.nonce = vec![1u8; 31];
        assert!(matches!(refused(&cert), SshCertRefusal::NotACertificate(_)));
        cert.nonce = Vec::new();
        assert!(matches!(refused(&cert), SshCertRefusal::NotACertificate(_)));

        let mut cert = Cert::user();
        cert.fields = vec![vec![7u8; 31]];
        assert!(
            matches!(refused(&cert), SshCertRefusal::NotACertificate(_)),
            "short ed25519"
        );

        let mut cert = Cert::user();
        cert.key_type = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
        let mut point = vec![4u8; 65];
        cert.fields = vec![b"nistp256".to_vec(), point.clone()];
        assert!(parse_unsigned_certificate(&cert.unsigned()).is_ok());
        cert.fields = vec![b"nistp384".to_vec(), point.clone()];
        assert!(
            matches!(refused(&cert), SshCertRefusal::NotACertificate(_)),
            "curve mismatch"
        );
        cert.fields = vec![b"nistp256".to_vec(), vec![4u8; 64]];
        assert!(
            matches!(refused(&cert), SshCertRefusal::NotACertificate(_)),
            "short point"
        );
        point[0] = 2;
        cert.fields = vec![b"nistp256".to_vec(), point];
        assert!(
            matches!(refused(&cert), SshCertRefusal::NotACertificate(_)),
            "compressed point"
        );

        let mut cert = Cert::user();
        cert.key_type = "ssh-rsa-cert-v01@openssh.com";
        let n = {
            let mut n = vec![0u8, 0xc0];
            n.extend(vec![0x55u8; 255]);
            n
        };
        cert.fields = vec![vec![1, 0, 1], n];
        assert!(parse_unsigned_certificate(&cert.unsigned()).is_ok());
        cert.fields = vec![vec![1, 0, 1], vec![0, 0xc0, 1, 2, 3]];
        assert!(
            matches!(refused(&cert), SshCertRefusal::NotACertificate(_)),
            "tiny RSA modulus"
        );
        cert.fields = vec![vec![0u8; 9], vec![0xc0u8; 256]];
        assert!(
            matches!(refused(&cert), SshCertRefusal::NotACertificate(_)),
            "huge exponent"
        );
    }

    #[test]
    fn the_dialog_text_names_what_is_certified() {
        let text = parse_unsigned_certificate(&Cert::user().unsigned())
            .unwrap()
            .describe();
        for want in [
            "OpenSSH user certificate",
            "Key id: grant-1",
            "Principal: deploy-site\n",
            "Principal: restart-service",
            "Certified key: SHA256:",
            "Signed by CA: SHA256:",
            "Serial: 5",
            "Valid: 2026-11-18T11:06:40Z to 2026-11-18T13:06:40Z",
            "Lifetime: 2h",
            "Critical option: force-command: \"/usr/bin/true\"",
            "Extensions: permit-pty",
        ] {
            assert!(text.contains(want), "{want:?} not in:\n{text}");
        }
        assert!(
            text.chars().all(|c| c == '\n' || !c.is_control()),
            "control character in the dialog text"
        );
    }

    #[test]
    fn dates_and_spans_render() {
        assert_eq!(show_time(0, "the beginning"), "the beginning");
        assert_eq!(show_time(u64::MAX, "forever"), "forever");
        assert_eq!(show_time(951_782_400, "x"), "2000-02-29T00:00:00Z");
        assert_eq!(show_time(1_795_000_000, "x"), "2026-11-18T11:06:40Z");
        assert_eq!(show_span(60), "1m");
        assert_eq!(show_span(86_400 + 3_600 + 61), "1d 1h 1m 1s");
        assert_eq!(show_span(0), "0s");
    }
}
