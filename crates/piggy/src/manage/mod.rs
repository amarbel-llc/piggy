//! `piggy manage` — the headless JSON-RPC command server (RFC 0007, piggy#201).
//!
//! An external program (papi, piggy#203; a GUI, piggy#202) drives piggy's
//! neutral management primitives over a byte stream instead of spawning CLI
//! subprocesses. This module is the **command** half (client → server: the
//! client invokes `card.list` / `card.init` / `sign_bytes`); the RFC 0006
//! **interaction** half (server → client: piggy issues the PIN/confirm/progress
//! requests a running command needs) is the existing
//! [`crate::card::frontend::jsonrpc::JsonRpcFrontend`], reused over the *same*
//! connection via its [`JsonRpcFrontend::already_initialized`] constructor.
//!
//! [`JsonRpcFrontend::already_initialized`]: crate::card::frontend::jsonrpc::JsonRpcFrontend::already_initialized
//!
//! The server is **blocking** and **single-flight** (RFC 0007 §4): unlike the
//! agent (which needs tokio for ssh-agent-lib + the probe loop), the commands
//! are synchronous, so this is a plain `read line → dispatch → write result`
//! loop. A connection carries at most one in-flight command; because of that,
//! the client's command-request ids and piggy's interaction-request ids occupy
//! independent spaces and cannot be confused (§4): at the dispatch level every
//! inbound line is a command *request*, and a command's interaction *responses*
//! are read inline by the frontend before the command returns.
//!
//! [`serve`] is transport-agnostic over a [`BufRead`] + [`Write`] pair, so the
//! stdio and `AF_UNIX`-socket transports (§3) share one core and the protocol
//! is unit-tested over in-memory buffers. Phase 3 (piggy#201) fills the method
//! handlers in [`dispatch`]; this skeleton answers `initialize`, rejects
//! unknown methods, and returns a "not implemented yet" error for the v1
//! methods so the wire machinery can be exercised end-to-end first.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::card::frontend::jsonrpc::JsonRpcFrontend;
use crate::card::protocol::PROTOCOL_VERSION;

mod methods;

/// JSON-RPC parse error (malformed JSON on the wire).
pub const PARSE_ERROR: i64 = -32700;
/// Bad/unsupported request — including a non-`initialize` first message or an
/// unsupported `initialize` protocol (RFC 0007 §6).
pub const INVALID_REQUEST: i64 = -32600;
/// Method not found (RFC 0007 §5).
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Invalid method params (RFC 0007 §6).
pub const INVALID_PARAMS: i64 = -32602;
/// An operator decline propagated from an interaction (RFC 0006 §4.4 / 0007 §6).
pub const INTERACTION_DECLINED: i64 = -32010;
/// piggy-specific card/operation failure (RFC 0007 §6).
pub const CARD_OP_FAILED: i64 = -32050;

/// An inbound JSON-RPC message at the command level. Every line the dispatch
/// loop reads is a *request* (a command's interaction *responses* are consumed
/// by the frontend, not here), so a line without `method` is a protocol error.
#[derive(Deserialize)]
struct Incoming {
    #[serde(default)]
    id: Value,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct OutgoingResult<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    result: Value,
}

#[derive(Serialize)]
struct OutgoingError<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// `initialize` params (RFC 0007 §4) — only the protocol version matters.
#[derive(Deserialize)]
struct InitializeParams {
    #[serde(default)]
    protocol: String,
}

/// Serialize `msg` as one `\n`-framed line and flush (RFC 0007 §2). Our own
/// result/error types always serialize, so a serde failure is mapped to an I/O
/// error rather than surfaced as a separate case.
fn write_line<W: Write, M: Serialize>(writer: &mut W, msg: &M) -> std::io::Result<()> {
    let mut line = serde_json::to_string(msg).map_err(std::io::Error::other)?;
    line.push('\n');
    writer.write_all(line.as_bytes())?;
    writer.flush()
}

fn write_result<W: Write>(writer: &mut W, id: &Value, result: Value) -> std::io::Result<()> {
    write_line(
        writer,
        &OutgoingResult {
            jsonrpc: "2.0",
            id,
            result,
        },
    )
}

fn write_error<W: Write>(
    writer: &mut W,
    id: &Value,
    code: i64,
    message: impl Into<String>,
    data: Option<Value>,
) -> std::io::Result<()> {
    write_line(
        writer,
        &OutgoingError {
            jsonrpc: "2.0",
            id,
            error: ErrorBody {
                code,
                message: message.into(),
                data,
            },
        },
    )
}

/// Validate the `initialize` handshake (RFC 0007 §4), returning the result
/// object on success or a `(code, message)` error.
fn handle_initialize(params: &Value) -> Result<Value, (i64, String)> {
    let p: InitializeParams = serde_json::from_value(params.clone())
        .map_err(|e| (INVALID_PARAMS, format!("initialize params: {e}")))?;
    if p.protocol != PROTOCOL_VERSION {
        return Err((
            INVALID_REQUEST,
            format!(
                "unsupported protocol {:?}; this server speaks {PROTOCOL_VERSION}",
                p.protocol
            ),
        ));
    }
    Ok(serde_json::json!({ "protocol": PROTOCOL_VERSION }))
}

/// Dispatch one command method (RFC 0007 §5). For the interactive methods
/// (`card.init` / `sign_bytes`) a [`JsonRpcFrontend::already_initialized`] is
/// built over the live connection (`reader`/`writer`) so the method's
/// PIN/confirm/progress requests travel back to the client inline; the frontend
/// is dropped before the method *result* is written, freeing the writer.
///
/// [`JsonRpcFrontend::already_initialized`]: crate::card::frontend::jsonrpc::JsonRpcFrontend::already_initialized
fn dispatch<R: BufRead, W: Write>(
    method: &str,
    params: &Value,
    id: &Value,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    match method {
        // Read-only, PIN-free: no interaction frontend needed.
        "card.list" => respond(writer, id, methods::card_list(params)),
        "card.init" => {
            let outcome = {
                let mut fe =
                    JsonRpcFrontend::already_initialized(&mut *reader, &mut *writer, "card init");
                methods::card_init(params, &mut fe)
            };
            respond(writer, id, outcome)
        }
        "sign_bytes" => {
            let outcome = {
                let mut fe =
                    JsonRpcFrontend::already_initialized(&mut *reader, &mut *writer, "sign-bytes");
                methods::sign_bytes(params, &mut fe)
            };
            respond(writer, id, outcome)
        }
        other => write_error(
            writer,
            id,
            METHOD_NOT_FOUND,
            format!("unknown method {other:?}"),
            None,
        ),
    }
}

/// Write a method handler's `Result` as the matching JSON-RPC response.
fn respond<W: Write>(
    writer: &mut W,
    id: &Value,
    outcome: Result<Value, (i64, String)>,
) -> std::io::Result<()> {
    match outcome {
        Ok(result) => write_result(writer, id, result),
        Err((code, message)) => write_error(writer, id, code, message, None),
    }
}

/// Serve one connection: run the `initialize` handshake, then dispatch command
/// requests until EOF (RFC 0007 §1–§5). Returns `Ok(())` on a clean
/// client-side close. A per-message error (parse failure, unsupported method,
/// declined interaction) is reported as a JSON-RPC error response and the loop
/// continues; only a transport I/O failure aborts with `Err`.
pub fn serve<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> std::io::Result<()> {
    let mut initialized = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // EOF: the client closed the connection. Clean shutdown.
            return Ok(());
        }
        if line.trim().is_empty() {
            // §2: implementations MUST ignore blank lines.
            continue;
        }

        let req: Incoming = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_error(
                    writer,
                    &Value::Null,
                    PARSE_ERROR,
                    format!("parse error: {e}"),
                    None,
                )?;
                continue;
            }
        };

        let Some(method) = req.method.as_deref() else {
            write_error(
                writer,
                &req.id,
                INVALID_REQUEST,
                "request missing 'method'",
                None,
            )?;
            continue;
        };

        if method == "initialize" {
            match handle_initialize(&req.params) {
                Ok(result) => {
                    initialized = true;
                    write_result(writer, &req.id, result)?;
                }
                Err((code, msg)) => write_error(writer, &req.id, code, msg, None)?,
            }
            continue;
        }

        if !initialized {
            // §4: initialize MUST be the first request.
            write_error(
                writer,
                &req.id,
                INVALID_REQUEST,
                "initialize must be called before any other method",
                None,
            )?;
            continue;
        }

        dispatch(method, &req.params, &req.id, reader, writer)?;
    }
}

/// `piggy manage` entry point. `jsonrpc` MUST be set (the only protocol in v1).
/// With `socket == None` the server speaks over stdio (the headless default —
/// the spawner owns the channel); with `Some(path)` it listens on an `AF_UNIX`
/// socket. Returns a process exit code.
pub fn run(jsonrpc: bool, socket: Option<&Path>) -> i32 {
    if !jsonrpc {
        eprintln!("piggy manage: only the JSON-RPC command protocol is supported; pass --jsonrpc");
        return 2;
    }
    match socket {
        None => serve_stdio(),
        Some(path) => serve_socket(path),
    }
}

/// Serve a single session over stdio (RFC 0007 §3). Protocol output is stdout;
/// diagnostics go to stderr so they never corrupt the stream.
fn serve_stdio() -> i32 {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    match serve(&mut reader, &mut writer) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy manage: {e}");
            1
        }
    }
}

/// Listen on an `AF_UNIX` socket and serve connections one at a time (RFC 0007
/// §3). The socket is created `0600` (§Security); a stale socket at `path` is
/// removed first. The server is long-lived — it serves each client to EOF and
/// then accepts the next — so it runs until killed.
fn serve_socket(path: &Path) -> i32 {
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("piggy manage: bind {}: {e}", path.display());
            return 1;
        }
    };
    // Owner-only: secrets cross this channel in both directions (RFC 0007
    // §Security). Best-effort — a chmod failure is reported but not fatal.
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("piggy manage: chmod {}: {e}", path.display());
    }
    eprintln!("piggy manage: listening on {}", path.display());

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("piggy manage: accept: {e}");
                return 1;
            }
        };
        let cloned = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("piggy manage: clone connection: {e}");
                continue;
            }
        };
        let mut reader = BufReader::new(cloned);
        let mut writer = stream;
        if let Err(e) = serve(&mut reader, &mut writer) {
            eprintln!("piggy manage: connection error: {e}");
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Drive [`serve`] over a canned request stream and return the response
    /// objects it wrote, in order (blank lines dropped). EOF at the end of the
    /// input is the clean-shutdown signal.
    fn run_serve(input: &str) -> Vec<Value> {
        let mut reader = Cursor::new(input.as_bytes().to_vec());
        let mut writer: Vec<u8> = Vec::new();
        serve(&mut reader, &mut writer).expect("in-memory transport never errors");
        String::from_utf8(writer)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn init_line() -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"protocol":"{PROTOCOL_VERSION}"}}}}"#
        )
    }

    #[test]
    fn initialize_returns_the_protocol_version() {
        let out = run_serve(&format!("{}\n", init_line()));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], 0);
        assert_eq!(out[0]["result"]["protocol"], PROTOCOL_VERSION);
    }

    #[test]
    fn unsupported_initialize_protocol_is_invalid_request() {
        let out = run_serve(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol":"piggy-mgmt/2"}}
"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn method_before_initialize_is_rejected() {
        let out = run_serve(
            r#"{"jsonrpc":"2.0","id":7,"method":"card.list","params":{}}
"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], 7);
        assert_eq!(out[0]["error"]["code"], INVALID_REQUEST);
        assert!(
            out[0]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("initialize")
        );
    }

    #[test]
    fn unknown_method_after_initialize_is_method_not_found() {
        let input = format!(
            "{}\n{}\n",
            init_line(),
            r#"{"jsonrpc":"2.0","id":2,"method":"does.not.exist","params":{}}"#
        );
        let out = run_serve(&input);
        assert_eq!(out.len(), 2, "initialize result + the method error");
        assert_eq!(out[1]["id"], 2);
        assert_eq!(out[1]["error"]["code"], METHOD_NOT_FOUND);
    }

    // The card.list/card.init/sign_bytes methods touch real PC/SC hardware, so
    // they are NOT driven through `serve` in these unit tests (this dev machine
    // has live YubiKeys); their param-validation is covered card-free in
    // `methods::tests`, and the end-to-end card paths by the fibby conformance
    // lane (piggy#201 Phase 4). The serve-loop mechanics below use only the
    // hardware-free `initialize` and unknown-method paths.

    #[test]
    fn single_flight_sequential_calls_each_get_a_response_in_order() {
        let input = format!(
            "{}\n{}\n{}\n",
            init_line(),
            r#"{"jsonrpc":"2.0","id":1,"method":"nope.one","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"nope.two","params":{}}"#,
        );
        let out = run_serve(&input);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["id"], 0); // initialize
        assert_eq!(out[1]["id"], 1); // first unknown method
        assert_eq!(out[1]["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(out[2]["id"], 2); // second unknown method
        assert_eq!(out[2]["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn blank_lines_between_messages_are_ignored() {
        let input = format!("\n{}\n\n", init_line());
        let out = run_serve(&input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["result"]["protocol"], PROTOCOL_VERSION);
    }

    #[test]
    fn malformed_json_is_a_parse_error_with_null_id() {
        let out = run_serve("{not json}\n");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["error"]["code"], PARSE_ERROR);
        assert!(out[0]["id"].is_null());
    }

    #[test]
    fn eof_with_no_input_is_a_clean_shutdown() {
        assert!(run_serve("").is_empty());
    }

    #[test]
    fn missing_method_is_invalid_request() {
        let out = run_serve(
            r#"{"jsonrpc":"2.0","id":9}
"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], 9);
        assert_eq!(out[0]["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn run_without_jsonrpc_flag_errors() {
        assert_eq!(run(false, None), 2);
    }
}
