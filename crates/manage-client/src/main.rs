//! Scripted JSON-RPC **command client** — a test helper for the `piggy manage`
//! conformance lane (piggy#201, RFC 0007).
//!
//! The inverse of `card-frontend-server`: where that answers interactions for
//! the `piggy card init --frontend jsonrpc` lane, this *drives* a management
//! method on piggy (the server) and answers the RFC 0006 interaction requests
//! piggy issues back over the same connection. It exercises both transports:
//!
//! - `--socket PATH` — connect to a `piggy manage --jsonrpc --socket PATH`
//!   already listening.
//! - `--spawn PIGGY` — spawn `PIGGY manage --jsonrpc` and talk over its
//!   stdin/stdout.
//!
//! Flow: send `initialize` (`piggy-mgmt/1`), send the command method, then
//! answer every interaction request (secret/confirm/mgmt_key/card_select) with
//! canned values until the command's result/error arrives, which is printed
//! (compact JSON) to stdout. Like `card-frontend-server`, this parses generic
//! JSON rather than reusing piggy's serde types, so a green lane is a real
//! cross-process check of the wire contract.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

use clap::Parser;
use serde_json::{Value, json};

const PROTOCOL: &str = "piggy-mgmt/1";

#[derive(Parser, Debug)]
#[command(about = "Scripted JSON-RPC command client for piggy manage conformance")]
struct Args {
    /// Method to invoke: `card.list`, `card.init`, or `sign_bytes`.
    #[arg(long)]
    method: String,

    /// Connect to a listening `piggy manage --jsonrpc --socket <PATH>`.
    /// Mutually exclusive with `--spawn`.
    #[arg(long)]
    socket: Option<String>,
    /// Spawn `<PIGGY> manage --jsonrpc` and talk over stdio. Mutually exclusive
    /// with `--socket`.
    #[arg(long)]
    spawn: Option<String>,

    // --- interaction answers ---
    /// PIN returned for non-PUK secret requests (current_pin / new_pin / …).
    #[arg(long, default_value = "654321")]
    pin: String,
    /// PUK returned for *puk* secret requests.
    #[arg(long, default_value = "87654321")]
    puk: String,
    /// Management-key source for `card.init`: "default", "random", or a hex key.
    #[arg(long = "mgmt-source", default_value = "random")]
    mgmt_source: String,
    /// Answer `confirm.request` with this (true = proceed). Set false to test
    /// a declined provision.
    #[arg(long, default_value_t = true)]
    confirm: bool,

    // --- card.init params ---
    /// Optional YubiKey serial to provision (card.init).
    #[arg(long)]
    serial: Option<u32>,

    // --- card.list params ---
    /// Whether card.list includes factory-blank cards (default true).
    #[arg(long, default_value_t = true)]
    include_uninitialized: bool,

    // --- sign_bytes params ---
    /// Signing slot for sign_bytes (`9a`/`9c`).
    #[arg(long)]
    slot: Option<String>,
    /// GUID to select for sign_bytes (optional).
    #[arg(long)]
    guid: Option<String>,
    /// Base64 message to sign (sign_bytes).
    #[arg(long = "message-b64")]
    message_b64: Option<String>,
    /// Signature framing for sign_bytes: "raw" or "der".
    #[arg(long, default_value = "raw")]
    format: String,
}

fn main() {
    let args = Args::parse();

    let mut child: Option<Child> = None;
    let (mut reader, mut writer): (Box<dyn BufRead>, Box<dyn Write>) =
        match (&args.socket, &args.spawn) {
            (Some(path), None) => {
                let stream =
                    UnixStream::connect(path).unwrap_or_else(|e| panic!("connect {path}: {e}"));
                let w = stream.try_clone().expect("clone socket handle");
                (Box::new(BufReader::new(stream)), Box::new(w))
            }
            (None, Some(piggy)) => {
                let mut c = Command::new(piggy)
                    .args(["manage", "--jsonrpc"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap_or_else(|e| panic!("spawn {piggy} manage: {e}"));
                let w = c.stdin.take().expect("child stdin");
                let r = BufReader::new(c.stdout.take().expect("child stdout"));
                child = Some(c);
                (Box::new(r), Box::new(w))
            }
            _ => {
                eprintln!("manage-client: pass exactly one of --socket or --spawn");
                std::process::exit(2);
            }
        };

    // 1. Handshake.
    send(
        &mut writer,
        &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocol":PROTOCOL}}),
    );
    let init = read_msg(&mut reader);
    let proto = init.pointer("/result/protocol").and_then(Value::as_str);
    if proto != Some(PROTOCOL) {
        panic!("initialize failed: {init}");
    }

    // 2. Invoke the command.
    let params = build_params(&args);
    send(
        &mut writer,
        &json!({"jsonrpc":"2.0","id":1,"method":args.method,"params":params}),
    );

    // 3. Answer interactions until the command's result/error arrives.
    let exit_code = loop {
        let msg = read_msg(&mut reader);
        if msg.get("method").and_then(Value::as_str).is_some() {
            answer_interaction(&mut writer, &args, &msg);
            continue;
        }
        // A line with no `method` is the command response (single-flight).
        if let Some(err) = msg.get("error") {
            // Print the whole response so the test can assert on the code, and
            // signal failure via the exit status.
            println!("{msg}");
            eprintln!("manage-client: command error: {err}");
            break 1;
        }
        let result = msg.get("result").cloned().unwrap_or(msg.clone());
        println!("{result}");
        break 0;
    };

    // Closing the writer signals EOF to a spawned stdio server so it exits.
    drop(writer);
    drop(reader);
    if let Some(mut c) = child {
        let _ = c.wait();
    }
    std::process::exit(exit_code);
}

fn build_params(args: &Args) -> Value {
    match args.method.as_str() {
        "card.list" => json!({ "include_uninitialized": args.include_uninitialized }),
        "card.init" => {
            let mut p = json!({});
            if let Some(s) = args.serial {
                p["serial"] = json!(s);
            }
            p
        }
        "sign_bytes" => {
            let slot = args
                .slot
                .as_deref()
                .expect("--slot required for sign_bytes");
            let message = args
                .message_b64
                .as_deref()
                .expect("--message-b64 required for sign_bytes");
            let mut p = json!({ "slot": slot, "format": args.format, "message": message });
            if let Some(g) = &args.guid {
                p["guid"] = json!(g);
            }
            p
        }
        other => panic!("unknown method {other:?}"),
    }
}

fn answer_interaction(writer: &mut dyn Write, args: &Args, msg: &Value) {
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let id = msg.get("id").cloned();
    let result = match method {
        "secret.request" => {
            let kind = msg
                .pointer("/params/kind")
                .and_then(Value::as_str)
                .unwrap_or("");
            let secret = if kind.contains("puk") {
                &args.puk
            } else {
                &args.pin
            };
            Some(json!({ "secret": secret }))
        }
        "confirm.request" => Some(json!({ "confirmed": args.confirm })),
        "mgmt_key.request" => Some(match args.mgmt_source.as_str() {
            "default" => json!({ "source": "default" }),
            "random" => json!({ "source": "random" }),
            hex => json!({ "source": "hex", "key": hex }),
        }),
        "card_select.request" => {
            let guid = msg
                .pointer("/params/candidates/0/guid")
                .and_then(Value::as_str)
                .expect("card_select.request carries at least one candidate");
            Some(json!({ "guid": guid }))
        }
        // Notifications carry no id and get no response.
        "progress" | "completed" => None,
        other => panic!("unexpected interaction method {other:?}"),
    };
    if let (Some(id), Some(result)) = (id, result) {
        send(writer, &json!({"jsonrpc":"2.0","id":id,"result":result}));
    }
}

fn send(writer: &mut dyn Write, v: &Value) {
    writeln!(writer, "{v}").expect("write message");
    writer.flush().expect("flush message");
}

fn read_msg(reader: &mut dyn BufRead) -> Value {
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read line");
        if n == 0 {
            panic!("server closed the connection before responding");
        }
        if line.trim().is_empty() {
            continue;
        }
        return serde_json::from_str(&line).unwrap_or_else(|e| panic!("parse {line:?}: {e}"));
    }
}
