//! Scripted JSON-RPC frontend server — a test helper for the `piggy card init`
//! JSON-RPC conformance lane (piggy#194, RFC 0006 §4).
//!
//! Listens on an `AF_UNIX` socket, accepts one connection (piggy, the JSON-RPC
//! *client*), and answers the RFC 0006 interactions with canned values:
//!
//! - `initialize` → `{ "protocol": "piggy-mgmt/1" }`
//! - `secret.request` → `{ "secret": <pin|puk> }` (chosen by the request's
//!   `kind`: `*puk*` → the PUK, else the PIN)
//! - `confirm.request` → `{ "confirmed": true }`
//! - `mgmt_key.request` → `{ "source": <default|random|hex+key> }`
//! - `progress` (notification) → ignored
//! - `completed` (notification) → terminal; the server exits
//!
//! This is an **independent** implementation of the frontend side (it parses
//! generic JSON rather than reusing piggy's serde types), so a green lane is a
//! real cross-process conformance check of the wire contract, not a tautology.
//! It is deliberately a separate workspace crate built on demand by the
//! conformance recipe (mirroring `fib-wait-ready`), never shipped.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "Scripted JSON-RPC frontend server for piggy card init conformance")]
struct Args {
    /// AF_UNIX socket path to listen on. The server creates it; piggy connects.
    #[arg(long)]
    socket: String,
    /// PIN to return for new_pin / confirm_new_pin secret requests.
    #[arg(long, default_value = "654321")]
    pin: String,
    /// PUK to return for new_puk / confirm_new_puk secret requests.
    #[arg(long, default_value = "87654321")]
    puk: String,
    /// Management-key source to return: "default", "random", or a hex key
    /// (treated as `{"source":"hex","key":<hex>}`).
    #[arg(long = "mgmt-source", default_value = "random")]
    mgmt_source: String,
}

fn main() {
    let args = Args::parse();

    let _ = std::fs::remove_file(&args.socket);
    let listener =
        UnixListener::bind(&args.socket).unwrap_or_else(|e| panic!("bind {}: {e}", args.socket));
    // Readiness signal so the test can wait for the socket before launching
    // piggy (it also waits on the socket file existing).
    println!("listening on {}", args.socket);
    let _ = std::io::stdout().flush();

    let (stream, _) = listener.accept().expect("accept piggy connection");
    let mut writer = stream.try_clone().expect("clone socket handle");
    let reader = BufReader::new(stream);

    for line in reader.lines() {
        let line = line.expect("read request line");
        if line.trim().is_empty() {
            continue;
        }
        let msg: serde_json::Value =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("parse {line:?}: {e}"));
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = msg.get("id").cloned();

        let result = match method {
            "initialize" => Some(serde_json::json!({ "protocol": "piggy-mgmt/1" })),
            "secret.request" => {
                let kind = msg
                    .pointer("/params/kind")
                    .and_then(|k| k.as_str())
                    .unwrap_or("");
                let secret = if kind.contains("puk") {
                    &args.puk
                } else {
                    &args.pin
                };
                Some(serde_json::json!({ "secret": secret }))
            }
            "confirm.request" => Some(serde_json::json!({ "confirmed": true })),
            "mgmt_key.request" => Some(match args.mgmt_source.as_str() {
                "default" => serde_json::json!({ "source": "default" }),
                "random" => serde_json::json!({ "source": "random" }),
                hex => serde_json::json!({ "source": "hex", "key": hex }),
            }),
            // Notifications: no response. `completed` is terminal.
            "progress" => None,
            "completed" => break,
            other => panic!("unexpected JSON-RPC method {other:?}"),
        };

        // Only requests (those carrying an `id`) get a response.
        if let (Some(id), Some(result)) = (id, result) {
            let resp = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
            writeln!(writer, "{resp}").expect("write response");
            writer.flush().expect("flush response");
        }
    }
}
