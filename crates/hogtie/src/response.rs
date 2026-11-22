//! The response word a caller puts on `hogtie exec`'s command line:
//! `v1.<nonce as 64 lowercase hex digits>.<the binary sshsig, standard base64>`.
//! One argv word, no spaces. Other processes of the same account can read
//! it while hogtie runs; the nonce is single use, so a copy is worthless
//! once hogtie has claimed it.

use crate::message::{NONCE_LEN, Nonce};
use std::fmt;

/// Responses longer than this are refused before any decoding (an sshsig
/// with an RSA-4096 certificate is about 2 KiB of base64).
pub const MAX_RESPONSE_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub nonce: Nonce,
    pub sshsig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError {
    TooLong,
    NotV1,
    BadNonce,
    BadBase64,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResponseError::TooLong => "response is too long",
            ResponseError::NotV1 => "response is not v1.<nonce>.<signature>",
            ResponseError::BadNonce => "response nonce is not 64 lowercase hex digits",
            ResponseError::BadBase64 => "response signature is not standard base64",
        })
    }
}

pub fn nonce_hex(nonce: &Nonce) -> String {
    crate::util::hex(nonce)
}

pub fn parse_nonce_hex(s: &str) -> Option<Nonce> {
    let b = s.as_bytes();
    if b.len() != NONCE_LEN * 2 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; NONCE_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl Response {
    pub fn parse(word: &str) -> Result<Self, ResponseError> {
        use base64::Engine as _;
        if word.len() > MAX_RESPONSE_LEN {
            return Err(ResponseError::TooLong);
        }
        let rest = word.strip_prefix("v1.").ok_or(ResponseError::NotV1)?;
        let (nonce, sig) = rest.split_once('.').ok_or(ResponseError::NotV1)?;
        let nonce = parse_nonce_hex(nonce).ok_or(ResponseError::BadNonce)?;
        let sshsig = base64::engine::general_purpose::STANDARD
            .decode(sig)
            .map_err(|_| ResponseError::BadBase64)?;
        Ok(Self { nonce, sshsig })
    }

    pub fn format(&self) -> String {
        use base64::Engine as _;
        format!(
            "v1.{}.{}",
            nonce_hex(&self.nonce),
            base64::engine::general_purpose::STANDARD.encode(&self.sshsig)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_of_any_other_length_is_refused() {
        for n in [0, 63, 65, 128] {
            assert_eq!(parse_nonce_hex(&"a".repeat(n)), None, "{n} digits");
            assert_eq!(
                Response::parse(&format!("v1.{}.AAAA", "a".repeat(n))),
                Err(ResponseError::BadNonce),
                "{n} digits"
            );
        }
        assert!(parse_nonce_hex(&"a".repeat(64)).is_some());
    }

    #[test]
    fn a_response_round_trips() {
        let r = Response {
            nonce: [7; 32],
            sshsig: b"SSHSIG...".to_vec(),
        };
        assert_eq!(Response::parse(&r.format()).unwrap(), r);
    }

    #[test]
    fn malformed_responses_are_refused() {
        let good = Response {
            nonce: [0xab; 32],
            sshsig: b"x".to_vec(),
        }
        .format();
        assert_eq!(
            Response::parse(&good.replacen("v1.", "v2.", 1)),
            Err(ResponseError::NotV1)
        );
        assert_eq!(Response::parse("v1.abc"), Err(ResponseError::NotV1));
        assert_eq!(
            Response::parse(&good.to_uppercase().replacen("V1.", "v1.", 1)),
            Err(ResponseError::BadNonce)
        );
        assert_eq!(
            Response::parse(&format!("v1.{}.@@@", "0".repeat(64))),
            Err(ResponseError::BadBase64)
        );
        assert_eq!(
            Response::parse(&format!("v1.{}.AAAA", "0".repeat(63))),
            Err(ResponseError::BadNonce)
        );
        assert_eq!(
            Response::parse(&"v".repeat(MAX_RESPONSE_LEN + 1)),
            Err(ResponseError::TooLong)
        );
    }
}
