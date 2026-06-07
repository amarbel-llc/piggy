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
use std::time::Duration;

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
        let request_bytes = encode_ecdh_request(self_pubkey_ssh_blob, partner_pubkey_ssh_blob, 0);
        let socket_path = self.socket_path.clone();

        self.runtime.block_on(async move {
            let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
                OracleError::Transport(format!("connect {}: {e}", socket_path.display()))
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
            OracleError::Transport(format!("connect {}: {e}", socket_path.display()))
        })?;
        let mut client = Client::new(stream);
        client
            .unlock(pin)
            .await
            .map_err(|e| OracleError::Transport(format!("unlock: {e}")))?;
        Ok(())
    })
}

/// List the agent's identities; returns the key comments (count = len).
///
/// Health-check probe for `piggy health` — same fresh-connection shape
/// as [`unlock_agent_pin`] (own current-thread runtime, one UnixStream
/// per call), but additionally bounded by `timeout` and surfacing every
/// failure as `Err(String)` so the caller can render it as a TAP
/// diagnostic. Never prompts, never panics on IO.
pub fn probe_identities(socket_path: &Path, timeout: Duration) -> Result<Vec<String>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    let socket_path = socket_path.to_path_buf();

    runtime.block_on(async move {
        tokio::time::timeout(timeout, async {
            let stream = UnixStream::connect(&socket_path)
                .await
                .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
            let mut client = Client::new(stream);
            let ids = client
                .request_identities()
                .await
                .map_err(|e| format!("request_identities: {e}"))?;
            Ok(ids.into_iter().map(|i| i.comment).collect())
        })
        .await
        .map_err(|_| format!("timeout after {timeout:?}"))?
    })
}

/// Send the `query` extension and decode the supported-extension list.
///
/// Same fresh-connection/timeout shell as [`probe_identities`]. A plain
/// SUCCESS (no extension payload) is an error too: a conforming agent
/// answers `query` with an extension response carrying the name list
/// (draft-miller-ssh-agent-14 §3.8.1).
pub fn probe_extensions(socket_path: &Path, timeout: Duration) -> Result<Vec<String>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    let socket_path = socket_path.to_path_buf();

    runtime.block_on(async move {
        tokio::time::timeout(timeout, async {
            let stream = UnixStream::connect(&socket_path)
                .await
                .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
            let mut client = Client::new(stream);
            let response = client
                .extension(Extension {
                    name: "query".into(),
                    details: Vec::<u8>::new().into(),
                })
                .await
                .map_err(|e| format!("query extension: {e}"))?;
            let ext = response.ok_or_else(|| {
                "agent answered query with plain SUCCESS (no extension list)".to_string()
            })?;
            decode_query_response(ext.details.as_ref())
        })
        .await
        .map_err(|_| format!("timeout after {timeout:?}"))?
    })
}

/// Decode the body of a `query` extension response into the advertised
/// extension names.
///
/// Two encodings exist in the wild (documented in the query-response
/// comment in vendor/pivy/src/piv.c, which this mirrors):
///
///   1. Flat cstrings — one u32-length-prefixed name after another.
///      Emitted by pivy-agent's process_ext_query and the Rust agent's
///      "query" arm (cmd/agent/session.rs).
///   2. A single SSH-string blob wrapping the flat cstrings. Emitted by
///      ssh-agent-lib's QueryResponse (`Vec<String>` serialization),
///      which ssh-agent-mux uses to aggregate upstream responses
///      (piggy#119).
///
/// As in piv.c, encoding 2 is detected by peeking the first u32: if it
/// equals the remaining buffer length, the rest is the wrapped blob.
/// A single-entry flat body aliases the wrapped shape and fails to
/// parse — the same accepted limitation as the C parser (real agents
/// advertise several extensions, "query" itself included).
///
/// The IETF-draft echoed extension name ("query") is NOT part of
/// `details` and is never expected here: ssh-agent-lib 0.5's response
/// plumbing consumes it as `Extension::name` when decoding
/// SSH_AGENT_EXTENSION_RESPONSE (proto::message::Extension::decode
/// reads the name cstring first and hands back only the remainder), so
/// this decoder sees only the name list regardless of which agent
/// answered. The C parser consumes the same echo itself before its
/// dual-encoding switch.
fn decode_query_response(details: &[u8]) -> Result<Vec<String>, String> {
    if details.len() >= 4 {
        let blob_len =
            u32::from_be_bytes([details[0], details[1], details[2], details[3]]) as usize;
        if blob_len + 4 == details.len() {
            return parse_flat_cstrings(&details[4..]);
        }
    }
    parse_flat_cstrings(details)
}

/// Parse consecutive u32-length-prefixed UTF-8 strings until the buffer
/// is exhausted. Any truncation or invalid UTF-8 is an `Err`.
fn parse_flat_cstrings(mut buf: &[u8]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(format!(
                "query response: truncated length prefix ({} trailing bytes)",
                buf.len()
            ));
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        if buf.len() < len {
            return Err(format!(
                "query response: truncated name (want {len} bytes, have {})",
                buf.len()
            ));
        }
        let name = std::str::from_utf8(&buf[..len])
            .map_err(|e| format!("query response: non-UTF-8 extension name: {e}"))?;
        names.push(name.to_string());
        buf = &buf[len..];
    }
    Ok(names)
}

/// The SSH-agent socket override piggy should prefer for PIV decrypt.
///
/// Returns `PIGGY_AUTH_SOCK` when it is set and non-empty, else `None`.
/// Callers fall back to the ambient `SSH_AUTH_SOCK` themselves. The point
/// is to route piggy's own decrypts at piggy-agent — which advertises the
/// `ecdh@joyent.com` extension — rather than through an ssh-agent-mux that
/// may not. See piggy#123.
pub fn piggy_auth_sock_override() -> Option<std::ffi::OsString> {
    std::env::var_os("PIGGY_AUTH_SOCK").filter(|s| !s.is_empty())
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
        assert!(
            oracle.is_ok(),
            "construction should not touch the filesystem"
        );
    }

    /// When the socket doesn't exist, `ecdh` surfaces `Transport`, not
    /// `Protocol`. Pins the error taxonomy so callers can distinguish
    /// network/permission failures from server-side protocol bugs.
    #[test]
    fn ecdh_on_missing_socket_is_transport_error() {
        let mut oracle = AgentEcdhOracle::new("/nonexistent/piggy-agent.sock").expect("construct");
        let err = oracle
            .ecdh(b"self-blob", b"partner-blob")
            .expect_err("missing socket must fail");
        assert!(
            matches!(err, OracleError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }

    /// `piggy_auth_sock_override` returns the var only when set and
    /// non-empty. No other test reads `PIGGY_AUTH_SOCK`, so mutating it
    /// process-wide here is race-free; we restore it on exit regardless.
    #[test]
    fn auth_sock_override_prefers_set_nonempty() {
        let saved = std::env::var_os("PIGGY_AUTH_SOCK");

        std::env::set_var("PIGGY_AUTH_SOCK", "/run/piggy.sock");
        assert_eq!(
            piggy_auth_sock_override().as_deref(),
            Some(std::ffi::OsStr::new("/run/piggy.sock"))
        );

        std::env::set_var("PIGGY_AUTH_SOCK", "");
        assert_eq!(
            piggy_auth_sock_override(),
            None,
            "empty must be treated as unset"
        );

        std::env::remove_var("PIGGY_AUTH_SOCK");
        assert_eq!(piggy_auth_sock_override(), None);

        match saved {
            Some(v) => std::env::set_var("PIGGY_AUTH_SOCK", v),
            None => std::env::remove_var("PIGGY_AUTH_SOCK"),
        }
    }

    // -------- health probes: probe_identities / probe_extensions --------

    use std::time::Duration;

    /// Test-local copy of the ecdh extension name, assembled by
    /// concatenation so editing tools cannot mangle the email-like
    /// literal (see CLAUDE.md). The canonical `health::ECDH_EXT` lives
    /// in the binary crate, out of reach of this library module.
    const ECDH_EXT: &str = concat!("ecdh@", "joyent.com");

    /// Missing socket surfaces a connect error string, not a panic/hang.
    #[test]
    fn identity_probe_on_missing_socket_errors_fast() {
        let err = probe_identities(
            Path::new("/nonexistent/health.sock"),
            Duration::from_secs(2),
        )
        .expect_err("missing socket must fail");
        assert!(err.contains("connect"), "got: {err}");
    }

    #[test]
    fn query_probe_on_missing_socket_errors_fast() {
        let err = probe_extensions(
            Path::new("/nonexistent/health.sock"),
            Duration::from_secs(2),
        )
        .expect_err("missing socket must fail");
        assert!(err.contains("connect"), "got: {err}");
    }

    /// Build the flat encoding: repeated u32-length-prefixed names.
    fn flat_cstrings(names: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for name in names {
            buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
            buf.extend_from_slice(name.as_bytes());
        }
        buf
    }

    /// Wild encoding 1 — flat cstrings, as emitted by pivy-agent's
    /// process_ext_query and the Rust agent's "query" arm (server-side
    /// bytes pinned by cmd/agent/session.rs's
    /// `extension_query_lists_supported_names`).
    #[test]
    fn decode_query_response_flat_cstrings() {
        let buf = flat_cstrings(&["query", ECDH_EXT]);
        let names = decode_query_response(&buf).expect("flat encoding");
        assert_eq!(names, vec!["query".to_string(), ECDH_EXT.to_string()]);
    }

    /// Wild encoding 2 — a single SSH-string blob wrapping the flat
    /// cstrings, as emitted by ssh-agent-lib's QueryResponse
    /// (`Vec<String>` serialization) and forwarded by ssh-agent-mux.
    /// See the query-response comment in vendor/pivy/src/piv.c and
    /// piggy#119.
    #[test]
    fn decode_query_response_wrapped_blob() {
        let inner = flat_cstrings(&["query", ECDH_EXT]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        buf.extend_from_slice(&inner);
        let names = decode_query_response(&buf).expect("wrapped encoding");
        assert_eq!(names, vec!["query".to_string(), ECDH_EXT.to_string()]);
    }

    /// Truncation (length prefix running past the buffer) is an Err,
    /// never a panic.
    #[test]
    fn decode_query_response_truncated_is_error() {
        let full = flat_cstrings(&["query", ECDH_EXT]);
        let err = decode_query_response(&full[..full.len() - 3]).expect_err("truncated must fail");
        assert!(err.contains("truncated"), "got: {err}");
    }

    /// A single-entry flat body aliases the wrapped shape; mirroring
    /// pivy's C parser we prefer the wrapped interpretation, which then
    /// fails to parse. Accepted limitation (same as piv.c): real agents
    /// advertise several extensions, "query" itself included.
    #[test]
    fn decode_query_response_single_flat_entry_errors_like_pivy() {
        let buf = flat_cstrings(&[ECDH_EXT]);
        decode_query_response(&buf).expect_err("single flat entry aliases the wrapped shape");
    }
}
