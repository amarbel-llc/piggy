//! [`EcdhOracle`] — abstract interface for computing ECDH shared secrets.
//!
//! Checkpoint 2 of issue #32 introduces this trait so the unlock path does
//! not hard-code "the SSH agent" as the only ECDH provider. An oracle holds
//! the **private** ECDH scalar (on a PIV card, in memory, or wherever) and
//! exposes a single method:
//!
//! > "Given my public-key blob and a partner public-key blob, produce the
//! > raw shared-secret bytes."
//!
//! The concrete [`AgentEcdhOracle`](../../piggy/src/agent_client.rs) in the
//! `piggy` crate wraps a Unix-socket `piggy-agent` and calls the
//! `ecdh@joyent.com` extension. A future checkpoint will add a direct
//! PIV-card oracle used when no agent is available.
//!
//! The trait is deliberately object-safe: downstream code can store
//! `Box<dyn EcdhOracle>` without carrying generic parameters around.

use std::error::Error as StdError;
use std::fmt;

/// Errors an [`EcdhOracle`] can produce.
///
/// `Transport` wraps any I/O failure reaching the backing implementation
/// (socket connect, read, write, etc.). `Protocol` wraps wire-format
/// mismatches — the backend returned bytes, but they did not parse the way
/// the oracle expects. `NoKey` means the oracle doesn't have a key matching
/// `self_pubkey_ssh_blob`; `InvalidPubkey` means the bytes passed in did
/// not parse as an SSH public-key blob at all. `Other` is a catch-all for
/// any failure mode not covered by the above.
#[derive(Debug)]
pub enum OracleError {
    /// The oracle doesn't hold this `self_pubkey`.
    NoKey,
    /// Pubkey bytes don't parse.
    InvalidPubkey(String),
    /// I/O to the oracle failed.
    Transport(String),
    /// Oracle replied with malformed data.
    Protocol(String),
    /// Anything else.
    Other(String),
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleError::NoKey => write!(f, "oracle does not hold a matching key"),
            OracleError::InvalidPubkey(msg) => write!(f, "invalid pubkey: {msg}"),
            OracleError::Transport(msg) => write!(f, "transport: {msg}"),
            OracleError::Protocol(msg) => write!(f, "protocol: {msg}"),
            OracleError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl StdError for OracleError {}

/// Abstract ECDH oracle.
///
/// `self_pubkey_ssh_blob` identifies which of the oracle's keys to use
/// (OpenSSH-wire-format public-key bytes, per the
/// [`ssh_key`](https://docs.rs/ssh-key) crate — i.e. what
/// [`ssh_key::PublicKey::to_bytes`] returns).
///
/// `partner_pubkey_ssh_blob` is the peer's ephemeral public key in the same
/// encoding.
///
/// On success, returns the raw shared-secret bytes (exactly 32 bytes for
/// P-256, 48 for P-384). The caller is responsible for any subsequent KDF
/// or zeroization.
pub trait EcdhOracle {
    /// Compute `self_secret · partner_pub`.
    fn ecdh(
        &mut self,
        self_pubkey_ssh_blob: &[u8],
        partner_pubkey_ssh_blob: &[u8],
    ) -> std::result::Result<Vec<u8>, OracleError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock oracle that returns whatever bytes it was constructed with,
    /// ignoring the inputs. Used only to prove the trait compiles and is
    /// object-safe.
    struct FixedSecretOracle {
        secret: Vec<u8>,
        last_self: Option<Vec<u8>>,
        last_partner: Option<Vec<u8>>,
    }

    impl EcdhOracle for FixedSecretOracle {
        fn ecdh(
            &mut self,
            self_pubkey_ssh_blob: &[u8],
            partner_pubkey_ssh_blob: &[u8],
        ) -> Result<Vec<u8>, OracleError> {
            self.last_self = Some(self_pubkey_ssh_blob.to_vec());
            self.last_partner = Some(partner_pubkey_ssh_blob.to_vec());
            Ok(self.secret.clone())
        }
    }

    #[test]
    fn mock_oracle_returns_configured_secret() {
        let mut oracle = FixedSecretOracle {
            secret: vec![1, 2, 3, 4],
            last_self: None,
            last_partner: None,
        };
        let got = oracle.ecdh(b"self-blob", b"partner-blob").unwrap();
        assert_eq!(got, vec![1, 2, 3, 4]);
        assert_eq!(oracle.last_self.as_deref(), Some(b"self-blob".as_slice()));
        assert_eq!(
            oracle.last_partner.as_deref(),
            Some(b"partner-blob".as_slice())
        );
    }

    /// Pin the trait's object-safety. If someone adds a generic method to
    /// `EcdhOracle`, this line stops compiling — which is the signal to
    /// refactor back to an object-safe shape rather than silently losing
    /// the ability to store oracles behind a trait object.
    #[test]
    fn trait_is_object_safe() {
        let mut oracle: Box<dyn EcdhOracle> = Box::new(FixedSecretOracle {
            secret: vec![0xAA, 0xBB],
            last_self: None,
            last_partner: None,
        });
        let got = oracle.ecdh(b"", b"").unwrap();
        assert_eq!(got, vec![0xAA, 0xBB]);
    }

    #[test]
    fn error_display_has_variant_specific_text() {
        assert!(format!("{}", OracleError::NoKey).contains("does not hold"));
        assert!(
            format!("{}", OracleError::InvalidPubkey("bad".into())).contains("invalid pubkey")
        );
        assert!(format!("{}", OracleError::Transport("eof".into())).contains("transport"));
        assert!(format!("{}", OracleError::Protocol("short".into())).contains("protocol"));
        assert!(format!("{}", OracleError::Other("boom".into())).contains("boom"));
    }

    #[test]
    fn error_is_std_error() {
        fn _requires_error<E: StdError>(_: &E) {}
        let e = OracleError::NoKey;
        _requires_error(&e);
    }
}
