//! Reading (never trusting) the two OpenSSH structures a response carries:
//! the sshsig blob (PROTOCOL.sshsig) and the user certificate embedded in
//! it (PROTOCOL.certkeys). The signature itself is checked by ssh-keygen
//! (`verify.rs`); this module exists so hogtie can refuse more than
//! ssh-keygen does (critical options, wildcard principals, too long a
//! validity) and can write which grant was used into the audit line.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    TrailingBytes,
    NotSshsig,
    UnsupportedVersion(u32),
    /// The embedded public key is not a certificate type hogtie knows.
    NotACertificate(String),
    NotUtf8,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("ends inside a field"),
            WireError::TrailingBytes => f.write_str("bytes after the last field"),
            WireError::NotSshsig => f.write_str("not an sshsig (no SSHSIG magic)"),
            WireError::UnsupportedVersion(v) => write!(f, "sshsig version {v}, only 1 is known"),
            WireError::NotACertificate(t) => write!(
                f,
                "signing key is {t:?}, not a known OpenSSH certificate type"
            ),
            WireError::NotUtf8 => f.write_str("a text field is not UTF-8"),
        }
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub(crate) fn string(&mut self) -> Result<&'a [u8], WireError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub(crate) fn text(&mut self) -> Result<String, WireError> {
        String::from_utf8(self.string()?.to_vec()).map_err(|_| WireError::NotUtf8)
    }

    pub(crate) fn end(&self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

pub(crate) fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// An sshsig blob, its fields as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sshsig {
    pub public_key: Vec<u8>,
    pub namespace: String,
    pub reserved: Vec<u8>,
    pub hash_algorithm: String,
    pub signature: Vec<u8>,
}

const MAGIC: &[u8] = b"SSHSIG";

impl Sshsig {
    pub fn parse(blob: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(blob);
        if r.take(MAGIC.len()).map_err(|_| WireError::NotSshsig)? != MAGIC {
            return Err(WireError::NotSshsig);
        }
        let version = r.u32()?;
        if version != 1 {
            return Err(WireError::UnsupportedVersion(version));
        }
        let public_key = r.string()?.to_vec();
        let namespace = r.text()?;
        let reserved = r.string()?.to_vec();
        let hash_algorithm = r.text()?;
        let signature = r.string()?.to_vec();
        r.end()?;
        Ok(Self {
            public_key,
            namespace,
            reserved,
            hash_algorithm,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut out, &self.public_key);
        put_string(&mut out, self.namespace.as_bytes());
        put_string(&mut out, &self.reserved);
        put_string(&mut out, self.hash_algorithm.as_bytes());
        put_string(&mut out, &self.signature);
        out
    }

    /// The ASCII armor ssh-keygen reads (`-s FILE`).
    pub fn armor(&self) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.encode());
        let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for chunk in b64.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        out
    }
}

/// Parse ssh-keygen's armored signature (what `-Y sign` writes).
pub fn dearmor(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let body = text
        .trim()
        .strip_prefix("-----BEGIN SSH SIGNATURE-----")?
        .strip_suffix("-----END SSH SIGNATURE-----")?;
    let joined: String = body.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(joined)
        .ok()
}

/// The certificate's type field: 1 user, 2 host.
pub const SSH2_CERT_TYPE_USER: u32 = 1;

/// The parts of an OpenSSH certificate hogtie reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub key_type: String,
    pub serial: u64,
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    /// (name, data) pairs, as packed in the certificate.
    pub critical_options: Vec<(String, Vec<u8>)>,
    pub extensions: Vec<(String, Vec<u8>)>,
    /// The CA's public key blob.
    pub signature_key: Vec<u8>,
}

/// How many key-specific fields follow the certificate's nonce, by type.
fn key_fields(key_type: &str) -> Option<usize> {
    Some(match key_type {
        "ssh-ed25519-cert-v01@openssh.com" => 1,
        "sk-ssh-ed25519-cert-v01@openssh.com" => 2,
        "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        | "ecdsa-sha2-nistp521-cert-v01@openssh.com" => 2,
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => 3,
        "ssh-rsa-cert-v01@openssh.com" => 2,
        _ => return None,
    })
}

fn pairs(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>, WireError> {
    let mut r = Reader(blob);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let name = r.text()?;
        let data = r.string()?.to_vec();
        out.push((name, data));
    }
    Ok(out)
}

impl Certificate {
    pub fn parse(blob: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(blob);
        let key_type = r.text()?;
        let fields =
            key_fields(&key_type).ok_or_else(|| WireError::NotACertificate(key_type.clone()))?;
        r.string()?; // nonce
        for _ in 0..fields {
            r.string()?; // the certified key (an mpint is a string on the wire)
        }
        let serial = r.u64()?;
        let cert_type = r.u32()?;
        let key_id = r.text()?;
        let mut principals = Vec::new();
        let mut p = Reader(r.string()?);
        while !p.0.is_empty() {
            principals.push(p.text()?);
        }
        let valid_after = r.u64()?;
        let valid_before = r.u64()?;
        let critical_options = pairs(r.string()?)?;
        let extensions = pairs(r.string()?)?;
        r.string()?; // reserved
        let signature_key = r.string()?.to_vec();
        r.string()?; // the CA's signature, checked by ssh-keygen
        r.end()?;
        Ok(Self {
            key_type,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Sshsig {
        Sshsig {
            public_key: b"pk".to_vec(),
            namespace: "hogtie-v1".into(),
            reserved: vec![],
            hash_algorithm: "sha512".into(),
            signature: b"sig".to_vec(),
        }
    }

    #[test]
    fn an_sshsig_round_trips_through_its_armor() {
        let s = sample();
        assert_eq!(Sshsig::parse(&dearmor(&s.armor()).unwrap()).unwrap(), s);
    }

    #[test]
    fn a_blob_without_the_magic_is_not_an_sshsig() {
        let mut b = sample().encode();
        b[0] = b'X';
        assert_eq!(Sshsig::parse(&b), Err(WireError::NotSshsig));
        assert_eq!(Sshsig::parse(b"SSH"), Err(WireError::NotSshsig));
    }

    #[test]
    fn version_two_is_refused() {
        let mut b = sample().encode();
        b[9] = 2;
        assert_eq!(Sshsig::parse(&b), Err(WireError::UnsupportedVersion(2)));
    }

    #[test]
    fn trailing_and_truncated_sshsigs_are_refused() {
        let mut b = sample().encode();
        b.push(0);
        assert_eq!(Sshsig::parse(&b), Err(WireError::TrailingBytes));
        let b = sample().encode();
        assert_eq!(Sshsig::parse(&b[..b.len() - 1]), Err(WireError::Truncated));
    }

    #[test]
    fn a_plain_key_is_not_a_certificate() {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, &[0u8; 32]);
        assert_eq!(
            Certificate::parse(&b),
            Err(WireError::NotACertificate("ssh-ed25519".into()))
        );
    }

    #[test]
    fn dearmor_refuses_a_missing_header() {
        assert_eq!(dearmor("AAAA"), None);
    }
}
