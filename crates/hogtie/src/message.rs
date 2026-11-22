//! The one canonical encoding of what a caller signs: the nonce it was
//! handed, the account it is, the action and its arguments, in SSH wire
//! format (every string a big-endian `uint32` length then its bytes), so
//! there is nothing to escape and no two requests share an encoding.
//!
//! ```text
//! string "hogtie-v1-exec"
//! string nonce        (32 bytes)
//! uint32 uid
//! string action       ([a-z0-9][a-z0-9-]{0,62})
//! uint32 nargs        (<= MAX_ARGS)
//! string arg[i]       (UTF-8, no NUL, <= MAX_ARG_LEN bytes)
//! ```
//!
//! The bytes are signed as an sshsig in namespace [`NAMESPACE`]. hogtie
//! never reads the message from the caller: `hogtie exec` rebuilds it from
//! the nonce it holds, the account sudo names and the argv it was given, and
//! verifies the signature over that.

use std::fmt;

/// The domain tag, the first field of every message.
pub const DOMAIN: &str = "hogtie-v1-exec";
/// The sshsig namespace of every hogtie signature.
pub const NAMESPACE: &str = "hogtie-v1";
pub const NONCE_LEN: usize = 32;
pub const MAX_ARGS: usize = 32;
pub const MAX_ARG_LEN: usize = 4096;
pub const MAX_ACTION_LEN: usize = 63;

pub type Nonce = [u8; NONCE_LEN];

/// One request to run one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub nonce: Nonce,
    pub uid: u32,
    pub action: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// The action name is outside `[a-z0-9][a-z0-9-]{0,62}`.
    BadAction(String),
    TooManyArgs(usize),
    /// Argument `index` is too long or holds a NUL.
    BadArg(usize),
    /// The bytes end inside a field.
    Truncated,
    /// Bytes are left after the last argument.
    TrailingBytes,
    /// The first field is not the domain tag.
    BadDomain,
    /// The nonce field is not 32 bytes.
    BadNonce,
    /// An argument or the action is not UTF-8.
    NotUtf8,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::BadAction(a) => {
                write!(f, "action name {a:?} is not [a-z0-9][a-z0-9-]{{0,62}}")
            }
            MessageError::TooManyArgs(n) => write!(f, "{n} arguments, at most {MAX_ARGS}"),
            MessageError::BadArg(i) => write!(
                f,
                "argument {i} is longer than {MAX_ARG_LEN} bytes or holds a NUL"
            ),
            MessageError::Truncated => f.write_str("message ends inside a field"),
            MessageError::TrailingBytes => f.write_str("bytes after the last argument"),
            MessageError::BadDomain => write!(f, "message does not start with {DOMAIN:?}"),
            MessageError::BadNonce => write!(f, "nonce field is not {NONCE_LEN} bytes"),
            MessageError::NotUtf8 => f.write_str("action or argument is not UTF-8"),
        }
    }
}

/// Whether `name` is a valid action name: lowercase letters, digits and
/// hyphens, not starting with a hyphen, at most 63 bytes. Nothing in it is
/// special to ssh-keygen's principal matching or to a shell.
pub fn is_action_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ACTION_LEN
        && b[0] != b'-'
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl Request {
    /// Check every field against the limits the encoding promises.
    pub fn check(&self) -> Result<(), MessageError> {
        if !is_action_name(&self.action) {
            return Err(MessageError::BadAction(self.action.clone()));
        }
        if self.args.len() > MAX_ARGS {
            return Err(MessageError::TooManyArgs(self.args.len()));
        }
        for (i, a) in self.args.iter().enumerate() {
            if a.len() > MAX_ARG_LEN || a.as_bytes().contains(&0) {
                return Err(MessageError::BadArg(i));
            }
        }
        Ok(())
    }

    /// The canonical bytes to sign. Refuses a request [`Request::check`]
    /// refuses, so no unencodable request is ever signed or verified.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.check()?;
        let mut out = Vec::new();
        put_string(&mut out, DOMAIN.as_bytes());
        put_string(&mut out, &self.nonce);
        out.extend_from_slice(&self.uid.to_be_bytes());
        put_string(&mut out, self.action.as_bytes());
        out.extend_from_slice(&(self.args.len() as u32).to_be_bytes());
        for a in &self.args {
            put_string(&mut out, a.as_bytes());
        }
        Ok(out)
    }

    /// Parse canonical bytes back, refusing anything [`Request::encode`]
    /// would not have produced.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut r = Reader(bytes);
        if r.string()? != DOMAIN.as_bytes() {
            return Err(MessageError::BadDomain);
        }
        let nonce: Nonce = r.string()?.try_into().map_err(|_| MessageError::BadNonce)?;
        let uid = r.u32()?;
        let action = utf8(r.string()?)?;
        let nargs = r.u32()? as usize;
        if nargs > MAX_ARGS {
            return Err(MessageError::TooManyArgs(nargs));
        }
        let mut args = Vec::with_capacity(nargs);
        for _ in 0..nargs {
            args.push(utf8(r.string()?)?);
        }
        if !r.0.is_empty() {
            return Err(MessageError::TrailingBytes);
        }
        let req = Request {
            nonce,
            uid,
            action,
            args,
        };
        req.check()?;
        Ok(req)
    }
}

fn utf8(b: &[u8]) -> Result<String, MessageError> {
    String::from_utf8(b.to_vec()).map_err(|_| MessageError::NotUtf8)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MessageError> {
        if self.0.len() < n {
            return Err(MessageError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, MessageError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn string(&mut self) -> Result<&'a [u8], MessageError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vector_a() -> Request {
        let mut nonce = [0u8; 32];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        Request {
            nonce,
            uid: 1000,
            action: "restic-snapshots".into(),
            args: vec!["/srv/backup/a".into()],
        }
    }

    const VECTOR_A: &str = "0000000e686f677469652d76312d65786563
        00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        000003e8
        000000107265737469632d736e617073686f7473
        00000001
        0000000d2f7372762f6261636b75702f61";

    fn vector_b() -> Request {
        Request {
            nonce: [0xff; 32],
            uid: 1001,
            action: "circus-status".into(),
            args: vec![],
        }
    }

    const VECTOR_B: &str = "0000000e686f677469652d76312d65786563
        00000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        000003e9
        0000000d636972637573 2d737461747573
        00000000";

    #[test]
    fn vector_a_encodes_to_its_bytes() {
        assert_eq!(vector_a().encode().unwrap(), hex(VECTOR_A));
    }

    #[test]
    fn vector_b_encodes_to_its_bytes() {
        assert_eq!(vector_b().encode().unwrap(), hex(VECTOR_B));
    }

    #[test]
    fn vectors_decode_back() {
        assert_eq!(Request::decode(&hex(VECTOR_A)).unwrap(), vector_a());
        assert_eq!(Request::decode(&hex(VECTOR_B)).unwrap(), vector_b());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut b = hex(VECTOR_A);
        b.push(0);
        assert_eq!(Request::decode(&b), Err(MessageError::TrailingBytes));
    }

    #[test]
    fn a_count_larger_than_the_arguments_is_truncated() {
        let mut b = hex(VECTOR_B);
        let n = b.len();
        b[n - 1] = 1;
        assert_eq!(Request::decode(&b), Err(MessageError::Truncated));
    }

    #[test]
    fn a_short_nonce_is_refused() {
        let mut b = Vec::new();
        put_string(&mut b, DOMAIN.as_bytes());
        put_string(&mut b, &[0u8; 31]);
        assert_eq!(Request::decode(&b), Err(MessageError::BadNonce));
    }

    #[test]
    fn another_domain_is_refused() {
        let mut b = hex(VECTOR_B);
        b[4] = b'H';
        assert_eq!(Request::decode(&b), Err(MessageError::BadDomain));
    }

    #[test]
    fn bad_action_names_are_refused() {
        for a in [
            "",
            "-x",
            "Restic",
            "a b",
            "a*",
            "a?",
            "a,b",
            "a!",
            &"a".repeat(64),
        ] {
            let mut r = vector_b();
            r.action = a.to_string();
            assert_eq!(
                r.encode(),
                Err(MessageError::BadAction(a.to_string())),
                "{a:?}"
            );
        }
        let mut r = vector_b();
        r.action = "a".repeat(63);
        assert!(r.encode().is_ok());
    }

    #[test]
    fn a_nul_in_an_argument_is_refused() {
        let mut r = vector_a();
        r.args = vec!["ok".into(), "a\0b".into()];
        assert_eq!(r.encode(), Err(MessageError::BadArg(1)));
    }

    #[test]
    fn too_many_or_too_long_arguments_are_refused() {
        let mut r = vector_b();
        r.args = vec!["x".into(); MAX_ARGS + 1];
        assert_eq!(r.encode(), Err(MessageError::TooManyArgs(MAX_ARGS + 1)));
        r.args = vec!["x".repeat(MAX_ARG_LEN + 1)];
        assert_eq!(r.encode(), Err(MessageError::BadArg(0)));
    }

    #[test]
    fn decode_refuses_what_encode_refuses() {
        let mut b = Vec::new();
        put_string(&mut b, DOMAIN.as_bytes());
        put_string(&mut b, &[0u8; 32]);
        b.extend_from_slice(&0u32.to_be_bytes());
        put_string(&mut b, b"Bad");
        b.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            Request::decode(&b),
            Err(MessageError::BadAction("Bad".into()))
        );
    }

    #[test]
    fn moving_bytes_between_action_and_argument_changes_the_encoding() {
        let one = Request {
            args: vec!["b".into()],
            action: "a".into(),
            ..vector_b()
        };
        let two = Request {
            args: vec![],
            action: "ab".into(),
            ..vector_b()
        };
        assert_ne!(one.encode().unwrap(), two.encode().unwrap());
    }
}
