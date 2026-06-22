//! The JSON-RPC frontend binding (RFC 0006 §4).
//!
//! Here **piggy is the JSON-RPC client**: it issues requests/notifications and
//! the external frontend (e.g. a charmbracelet TUI) is the server that returns
//! responses. Messages are JSON-RPC 2.0 objects, one per line, `\n`-terminated
//! (§4.1). The binding is generic over a [`BufRead`] + [`Write`] pair, so tests
//! drive it over in-memory buffers and the `piggy card init` command (Phase 4)
//! wires it to an `AF_UNIX` stream selected by `--socket` (§4.2).
//!
//! Interactions are strictly single-flight: piggy writes one request and blocks
//! reading exactly one response line before issuing the next. That keeps the
//! client free of an id-correlation map — it ignores the response `id` (§4.3
//! examples notwithstanding, a single in-flight request needs no matching).

use std::io::{BufRead, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::card::protocol::{
    CardSelectRequest, CardSelectResponse, CompletedEvent, ConfirmRequest, ConfirmResponse,
    Frontend, FrontendError, MgmtKeyChoice, MgmtKeyRequest, PROTOCOL_VERSION, ProgressEvent,
    SecretRequest,
};

/// JSON-RPC error code for "interaction declined" (RFC 0006 §4.4). The engine
/// treats this as an operator abort.
pub const INTERACTION_DECLINED: i64 = -32010;

/// A JSON-RPC frontend over a byte-stream pair.
pub struct JsonRpcFrontend<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    next_id: u64,
    initialized: bool,
    operation: String,
}

/// Outgoing JSON-RPC request (`id` present).
#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

/// Outgoing JSON-RPC notification (no `id`, no response).
#[derive(Serialize)]
struct RpcNotification<'a, P: Serialize> {
    jsonrpc: &'static str,
    method: &'a str,
    params: P,
}

/// Incoming JSON-RPC response. `id` is accepted but not correlated (single
/// in-flight request).
#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    #[serde(default)]
    message: String,
}

/// The `initialize` handshake result (RFC 0006 §4.3).
#[derive(Serialize)]
struct InitializeParams<'a> {
    protocol: &'static str,
    operation: &'a str,
}

#[derive(Deserialize)]
struct InitializeResult {
    #[serde(default)]
    protocol: String,
}

impl<R: BufRead, W: Write> JsonRpcFrontend<R, W> {
    /// Construct a frontend bound to a reader/writer pair. `operation` is sent
    /// in the `initialize` handshake (e.g. `"card-init"`). The handshake is
    /// performed lazily before the first interaction.
    pub fn new(reader: R, writer: W, operation: impl Into<String>) -> Self {
        Self {
            reader,
            writer,
            next_id: 0,
            initialized: false,
            operation: operation.into(),
        }
    }

    /// Construct a frontend for the **server-side interaction role** (RFC 0007):
    /// the connection's `initialize` handshake has already been performed by the
    /// command layer (`piggy manage`), so this binding skips its own lazy
    /// handshake and issues interaction requests directly. Used to drive a
    /// running command's PIN/confirm/progress prompts back over the same
    /// connection the client invoked the command on.
    pub fn already_initialized(reader: R, writer: W, operation: impl Into<String>) -> Self {
        Self {
            reader,
            writer,
            next_id: 0,
            initialized: true,
            operation: operation.into(),
        }
    }

    /// Issue a request and block for its single response, deserializing the
    /// `result` into `T`. Maps a `-32010` error to [`FrontendError::Declined`],
    /// any other error to [`FrontendError::Protocol`], and I/O / EOF to
    /// [`FrontendError::Transport`].
    fn call<P: Serialize, T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<T, FrontendError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        self.write_line(&req)?;
        let resp: RpcResponse = self.read_response()?;
        if let Some(err) = resp.error {
            return Err(if err.code == INTERACTION_DECLINED {
                FrontendError::Declined(err.message)
            } else {
                FrontendError::Protocol(format!("JSON-RPC error {}: {}", err.code, err.message))
            });
        }
        let result = resp.result.ok_or_else(|| {
            FrontendError::Protocol("response missing both result and error".into())
        })?;
        serde_json::from_value(result)
            .map_err(|e| FrontendError::Protocol(format!("malformed result: {e}")))
    }

    /// Send a fire-and-forget notification (no response read). A write failure
    /// is swallowed: notifications are advisory and the next *request* will
    /// surface a dead channel as a transport error.
    fn notify<P: Serialize>(&mut self, method: &str, params: P) {
        let note = RpcNotification {
            jsonrpc: "2.0",
            method,
            params,
        };
        let _ = self.write_line(&note);
    }

    fn write_line<M: Serialize>(&mut self, msg: &M) -> Result<(), FrontendError> {
        let mut line = serde_json::to_string(msg)
            .map_err(|e| FrontendError::Protocol(format!("encode: {e}")))?;
        // §4.1: one object per line; a serialized JSON-RPC object never
        // contains a raw newline, so a single trailing LF frames it.
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.flush())
            .map_err(|e| FrontendError::Transport(e.to_string()))
    }

    fn read_response(&mut self) -> Result<RpcResponse, FrontendError> {
        // §4.1: ignore blank lines; read until the first non-blank object.
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| FrontendError::Transport(e.to_string()))?;
            if n == 0 {
                return Err(FrontendError::Transport("channel closed".into()));
            }
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(&line)
                .map_err(|e| FrontendError::Protocol(format!("malformed response: {e}")));
        }
    }

    /// Perform the `initialize` handshake once, before the first interaction.
    fn ensure_initialized(&mut self) -> Result<(), FrontendError> {
        if self.initialized {
            return Ok(());
        }
        let operation = self.operation.clone();
        let result: InitializeResult = self.call(
            "initialize",
            InitializeParams {
                protocol: PROTOCOL_VERSION,
                operation: &operation,
            },
        )?;
        if result.protocol != PROTOCOL_VERSION {
            return Err(FrontendError::Protocol(format!(
                "frontend speaks {:?}, expected {PROTOCOL_VERSION}",
                result.protocol
            )));
        }
        self.initialized = true;
        Ok(())
    }
}

#[derive(Deserialize)]
struct SecretResponse {
    secret: String,
}

impl<R: BufRead, W: Write> Frontend for JsonRpcFrontend<R, W> {
    fn request_secret(&mut self, req: SecretRequest) -> Result<Zeroizing<String>, FrontendError> {
        self.ensure_initialized()?;
        let resp: SecretResponse = self.call("secret.request", req)?;
        Ok(Zeroizing::new(resp.secret))
    }

    fn request_mgmt_key(&mut self, req: MgmtKeyRequest) -> Result<MgmtKeyChoice, FrontendError> {
        self.ensure_initialized()?;
        self.call("mgmt_key.request", req)
    }

    fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError> {
        self.ensure_initialized()?;
        let resp: ConfirmResponse = self.call("confirm.request", req)?;
        Ok(resp.confirmed)
    }

    fn select_card(&mut self, req: CardSelectRequest) -> Result<String, FrontendError> {
        self.ensure_initialized()?;
        let resp: CardSelectResponse = self.call("card_select.request", req)?;
        Ok(resp.guid)
    }

    fn progress(&mut self, ev: ProgressEvent) {
        self.notify("progress", ev);
    }

    fn completed(&mut self, ev: CompletedEvent) {
        self.notify("completed", ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::protocol::{CardId, SecretKind};
    use std::io::BufReader;

    /// Build a frontend whose "server" responses are pre-seeded (one JSON-RPC
    /// object per line, in the order piggy will read them). Single-flight means
    /// a pre-seeded reader is a faithful server for a scripted exchange.
    fn frontend(responses: &str) -> JsonRpcFrontend<BufReader<std::io::Cursor<Vec<u8>>>, Vec<u8>> {
        let reader = BufReader::new(std::io::Cursor::new(responses.as_bytes().to_vec()));
        JsonRpcFrontend::new(reader, Vec::new(), "test-op")
    }

    fn sample_card() -> CardId {
        CardId {
            guid: "2835305C6024B3255557BF6901443404".into(),
            serial: Some(15909078),
            cn: Some("piv-auth@2835305C".into()),
        }
    }

    #[test]
    fn secret_request_handshakes_then_returns_secret() {
        // First line answers `initialize`; second answers `secret.request`.
        let responses = concat!(
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocol":"piggy-mgmt/1"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"result":{"secret":"123456"}}"#,
            "\n",
        );
        let mut fe = frontend(responses);
        let secret = fe
            .request_secret(SecretRequest {
                kind: SecretKind::CurrentPin,
                prompt: "Enter PIN".into(),
                card: Some(sample_card()),
                slot: Some("9a".into()),
                attempts_remaining: Some(3),
                detail: None,
            })
            .unwrap();
        assert_eq!(&*secret, "123456");

        // The writer carries the initialize request then the secret.request,
        // each on its own LF-framed line (§4.1), and the request names the card.
        let written = String::from_utf8(fe.writer.clone()).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2, "one initialize + one secret.request");
        assert!(lines[0].contains(r#""method":"initialize""#));
        assert!(lines[0].contains("piggy-mgmt/1"));
        assert!(lines[1].contains(r#""method":"secret.request""#));
        assert!(lines[1].contains(r#""kind":"current_pin""#));
        assert!(lines[1].contains("15909078"), "request carries the serial");
    }

    #[test]
    fn already_initialized_skips_the_handshake() {
        // The server-side role (RFC 0007): the connection was already
        // `initialize`d by the command layer, so the first interaction goes out
        // as the real request — no initialize line, and the reader is not
        // expected to carry an initialize response.
        let responses = concat!(
            r#"{"jsonrpc":"2.0","id":0,"result":{"secret":"123456"}}"#,
            "\n",
        );
        let reader = BufReader::new(std::io::Cursor::new(responses.as_bytes().to_vec()));
        let mut fe = JsonRpcFrontend::already_initialized(reader, Vec::new(), "manage");
        let secret = fe
            .request_secret(SecretRequest {
                kind: SecretKind::CurrentPin,
                prompt: "Enter PIN".into(),
                card: Some(sample_card()),
                slot: Some("9a".into()),
                attempts_remaining: None,
                detail: None,
            })
            .unwrap();
        assert_eq!(&*secret, "123456");

        let written = String::from_utf8(fe.writer.clone()).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 1, "no initialize, just the secret.request");
        assert!(lines[0].contains(r#""method":"secret.request""#));
        assert!(
            !written.contains(r#""method":"initialize""#),
            "handshake must be skipped: {written}"
        );
    }

    #[test]
    fn declined_error_maps_to_declined_abort() {
        let responses = concat!(
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocol":"piggy-mgmt/1"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"operator cancelled"}}"#,
            "\n",
        );
        let mut fe = frontend(responses);
        let err = fe
            .request_secret(SecretRequest {
                kind: SecretKind::NewPin,
                prompt: "New PIN".into(),
                card: Some(sample_card()),
                slot: None,
                attempts_remaining: None,
                detail: None,
            })
            .unwrap_err();
        assert!(
            matches!(err, FrontendError::Declined(ref m) if m.contains("cancelled")),
            "got {err:?}"
        );
    }

    #[test]
    fn other_error_code_maps_to_protocol_error() {
        let responses = concat!(
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocol":"piggy-mgmt/1"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#,
            "\n",
        );
        let mut fe = frontend(responses);
        let err = fe
            .confirm(ConfirmRequest {
                message: "ok?".into(),
                default: Some(true),
            })
            .unwrap_err();
        assert!(matches!(err, FrontendError::Protocol(_)), "got {err:?}");
    }

    #[test]
    fn blank_lines_between_objects_are_ignored() {
        let responses = concat!(
            "\n",
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocol":"piggy-mgmt/1"}}"#,
            "\n\n",
            r#"{"jsonrpc":"2.0","id":1,"result":{"confirmed":true}}"#,
            "\n",
        );
        let mut fe = frontend(responses);
        let ok = fe
            .confirm(ConfirmRequest {
                message: "proceed?".into(),
                default: None,
            })
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn closed_channel_is_a_transport_error() {
        // Empty reader: initialize read hits EOF immediately.
        let mut fe = frontend("");
        let err = fe
            .confirm(ConfirmRequest {
                message: "x".into(),
                default: None,
            })
            .unwrap_err();
        assert!(matches!(err, FrontendError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn version_mismatch_in_handshake_is_protocol_error() {
        let responses = concat!(
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocol":"piggy-mgmt/2"}}"#,
            "\n",
        );
        let mut fe = frontend(responses);
        let err = fe
            .confirm(ConfirmRequest {
                message: "x".into(),
                default: None,
            })
            .unwrap_err();
        assert!(matches!(err, FrontendError::Protocol(_)), "got {err:?}");
    }

    #[test]
    fn progress_and_completed_emit_notifications_without_id() {
        let mut fe = frontend(concat!(
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocol":"piggy-mgmt/1"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"result":{"confirmed":true}}"#,
            "\n",
        ));
        // Drive the handshake first via a real request.
        let _ = fe.confirm(ConfirmRequest {
            message: "go?".into(),
            default: None,
        });
        fe.progress(ProgressEvent {
            step: "generate-9d".into(),
            message: "Generating".into(),
            current: Some(1),
            total: Some(2),
        });
        fe.completed(CompletedEvent {
            status: crate::card::protocol::CompletedStatus::Ok,
            summary: None,
            error: None,
        });
        let written = String::from_utf8(fe.writer.clone()).unwrap();
        let progress_line = written
            .lines()
            .find(|l| l.contains(r#""method":"progress""#))
            .expect("a progress notification was written");
        assert!(
            !progress_line.contains(r#""id""#),
            "notifications carry no id: {progress_line}"
        );
        assert!(
            written
                .lines()
                .any(|l| l.contains(r#""method":"completed""#))
        );
    }
}
