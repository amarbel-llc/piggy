//! A piggy age identity (`AGE-PLUGIN-PIGGY-1…`) and the agent oracle.
//!
//! Our identity carries **no private key** — only the compressed P-256
//! public key. That is enough to (a) name the key piggy-agent should use
//! for the ECDH (`self` side) and (b) recompute the stanza salt/tag. The
//! actual scalar-mult happens on the card via [`agent_oracle`].

use piggy::agent_client::{AgentEcdhOracle, piggy_auth_sock_override};

use crate::PLUGIN_NAME;
use crate::p256_stanza::{self, COMPRESSED_BYTES, TAG_BYTES};

#[derive(Debug, Clone)]
pub(crate) struct Identity {
    compressed: [u8; COMPRESSED_BYTES],
}

impl Identity {
    /// Parse the bytes age handed us, rejecting other plugins' identities.
    pub(crate) fn from_bytes(plugin_name: &str, bytes: &[u8]) -> Option<Self> {
        if plugin_name != PLUGIN_NAME {
            return None;
        }
        let compressed: [u8; COMPRESSED_BYTES] = bytes.try_into().ok()?;
        p256_stanza::validate_compressed(&compressed)?;
        Some(Identity { compressed })
    }

    pub(crate) fn compressed(&self) -> &[u8; COMPRESSED_BYTES] {
        &self.compressed
    }

    /// The recipient tag this identity unwraps (`SHA-256(pubkey)[..4]`).
    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        p256_stanza::static_tag(&self.compressed)
    }
}

/// Build the agent ECDH oracle from `PIGGY_AUTH_SOCK` (preferred) or the
/// ambient `SSH_AUTH_SOCK`. The agent owns any PIN/touch prompt.
pub(crate) fn agent_oracle() -> Result<AgentEcdhOracle, String> {
    let socket = piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK"))
        .ok_or_else(|| {
            "no SSH agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK to a piggy-agent".to_owned()
        })?;
    AgentEcdhOracle::new(socket).map_err(|e| e.to_string())
}
