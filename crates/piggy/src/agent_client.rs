//! Client-side SSH agent support for the `ecdh@joyent.com` extension.
//!
//! The piggy-agent (and the C pivy-agent) implements the `ecdh@joyent.com`
//! SSH-agent extension: send the agent a "self" public-key blob (identifying
//! a card-resident key) and a "partner" ephemeral public-key blob, and the
//! agent returns the raw ECDH shared secret computed on the card. This
//! module is the client side of that call, packaged behind the abstract
//! [`piggy_box::oracle::EcdhOracle`] trait introduced in checkpoint 2 of
//! issue #32.
//!
//! The oracle owns a private tokio current-thread runtime and reconnects on
//! every call: opening a fresh Unix-domain socket per ECDH request. That's
//! the same shape ssh-agent clients typically use (no long-lived connection
//! state) and avoids interacting with any enclosing runtime the caller may
//! already have.
//!
//! The oracle does NOT unlock the agent — PIN provisioning is a separate
//! flow handled by [`unlock_agent_pin`] (or the user running `ssh-add -X`
//! interactively). Calling `ecdh` on a locked agent fails at the server
//! with "PIN required".

use std::path::{Path, PathBuf};

use piggy_box::agent_ext::{decode_ecdh_response, encode_ecdh_request};
use piggy_box::oracle::{EcdhOracle, OracleError};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Extension;
use tokio::net::UnixStream;
use tokio::runtime::Runtime;

/// ECDH oracle backed by a `piggy-agent` (or any SSH agent speaking the
/// `ecdh@joyent.com` extension) reachable over a Unix-domain socket.
///
/// Construction pins the socket path; each `ecdh` call opens a fresh
/// connection and tears it down when the call returns.
pub struct AgentEcdhOracle {
    /// Dedicated current-thread runtime. Owning the runtime means `ecdh`
    /// can be called from synchronous code without requiring the caller
    /// to supply a tokio context.
    runtime: Runtime,
    socket_path: PathBuf,
}

impl AgentEcdhOracle {
    /// Build an oracle for the agent at `socket_path`.
    ///
    /// The socket is NOT connected here — we only construct the runtime.
    /// `ecdh` does the connect lazily so a long-lived oracle can ride
    /// through brief agent restarts.
    pub fn new(socket_path: impl Into<PathBuf>) -> Result<Self, OracleError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| OracleError::Transport(format!("tokio runtime: {e}")))?;
        Ok(Self {
            runtime,
            socket_path: socket_path.into(),
        })
    }
}

impl EcdhOracle for AgentEcdhOracle {
    fn ecdh(
        &mut self,
        self_pubkey_ssh_blob: &[u8],
        partner_pubkey_ssh_blob: &[u8],
    ) -> Result<Vec<u8>, OracleError> {
        let request_bytes =
            encode_ecdh_request(self_pubkey_ssh_blob, partner_pubkey_ssh_blob, 0);
        let socket_path = self.socket_path.clone();

        self.runtime.block_on(async move {
            let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
                OracleError::Transport(format!(
                    "connect {}: {e}",
                    socket_path.display()
                ))
            })?;
            let mut client = Client::new(stream);

            let response = client
                .extension(Extension {
                    name: "ecdh@joyent.com".into(),
                    details: request_bytes.into(),
                })
                .await
                .map_err(|e| OracleError::Transport(format!("extension call: {e}")))?;

            let ext = response.ok_or_else(|| {
                OracleError::Protocol(
                    "agent returned SUCCESS instead of ExtensionResponse".to_string(),
                )
            })?;

            decode_ecdh_response(ext.details.as_ref())
                .map_err(|e| OracleError::Protocol(e.to_string()))
        })
    }
}

/// Send an `SSH_AGENTC_UNLOCK` with `pin` to the agent at `socket_path`.
///
/// piggy-agent treats the unlock "passphrase" as the PIV PIN — see
/// `crates/piggy/src/cmd/agent/session.rs::unlock`. On success the agent
/// will use this PIN for subsequent `verify_pin` calls during ECDH and
/// sign operations. Returns `Ok(())` on success.
///
/// Creates and tears down its own current-thread tokio runtime for the
/// one-shot call, so it's safe to invoke from a plain `#[test] fn`.
pub fn unlock_agent_pin(socket_path: &Path, pin: &str) -> Result<(), OracleError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OracleError::Transport(format!("tokio runtime: {e}")))?;

    let socket_path = socket_path.to_path_buf();
    let pin = pin.to_string();

    runtime.block_on(async move {
        let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
            OracleError::Transport(format!(
                "connect {}: {e}",
                socket_path.display()
            ))
        })?;
        let mut client = Client::new(stream);
        client
            .unlock(pin)
            .await
            .map_err(|e| OracleError::Transport(format!("unlock: {e}")))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construction succeeds for any path (even if it doesn't exist yet)
    /// because the oracle connects lazily. Proves the struct compiles and
    /// the runtime builds cleanly.
    #[test]
    fn oracle_constructs_with_arbitrary_path() {
        let oracle = AgentEcdhOracle::new("/nonexistent/piggy-agent.sock");
        assert!(oracle.is_ok(), "construction should not touch the filesystem");
    }

    /// When the socket doesn't exist, `ecdh` surfaces `Transport`, not
    /// `Protocol`. Pins the error taxonomy so callers can distinguish
    /// network/permission failures from server-side protocol bugs.
    #[test]
    fn ecdh_on_missing_socket_is_transport_error() {
        let mut oracle =
            AgentEcdhOracle::new("/nonexistent/piggy-agent.sock").expect("construct");
        let err = oracle
            .ecdh(b"self-blob", b"partner-blob")
            .expect_err("missing socket must fail");
        assert!(
            matches!(err, OracleError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }
}
