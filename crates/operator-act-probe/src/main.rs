//! A raw `operator-act@piggy` client for the RFC 0012 conformance lanes.
//!
//! It asks the agent on `--socket` for its identities, picks the key whose
//! comment starts `PIV_slot_<SLOT>`, and sends one extension request built
//! from the flags, with every field overridable so a lane can send what a
//! well-behaved client never would. The answer is printed one fact per line:
//!
//! ```text
//! reply 29 extension-response
//! raw <hex of the reply body, type byte included>
//! version 1
//! status 3
//! detail namespace "git" is not registered for operator acts
//! sshsig-hex
//! ```
//!
//! `raw` is what a proxy must relay untouched (RFC 0012 §2.8); the rest is
//! the same bytes parsed. A reply that is not an operator-act response
//! prints `reply` and `raw` only. Exit status is 0 whenever the agent
//! answered, whatever it said: the lanes assert on the lines.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

const EXTENSION: &str = "operator-act@piggy";

const USAGE: &str =
    "usage: operator-act-probe --socket PATH (--slot XX [--guid PREFIX] | --key-hex HEX)
    [--version N] [--namespace NS] [--hash NAME] [--flags N]
    [--text STR | --text-hex HEX | --text-file PATH]
    [--trailing-hex HEX] [--details-hex HEX]";

struct Args {
    socket: String,
    slot: Option<String>,
    guid: Option<String>,
    key: Option<Vec<u8>>,
    version: u32,
    namespace: String,
    hash: String,
    flags: u32,
    text: Vec<u8>,
    trailing: Vec<u8>,
    details: Option<Vec<u8>>,
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(format!("not an even number of hex digits: {text:?}"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| format!("not hex: {text:?}")))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        socket: String::new(),
        slot: None,
        guid: None,
        key: None,
        version: 1,
        namespace: "piggy-escalation-v1".into(),
        hash: "sha512".into(),
        flags: 0,
        text: b"piggy-test: operator act probe".to_vec(),
        trailing: Vec::new(),
        details: None,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u32>().map_err(|_| format!("not a number: {v:?}"));
        match flag.as_str() {
            "--socket" => args.socket = value()?,
            "--slot" => args.slot = Some(value()?.to_ascii_uppercase()),
            "--guid" => args.guid = Some(value()?.to_ascii_uppercase()),
            "--key-hex" => args.key = Some(unhex(&value()?)?),
            "--version" => args.version = number(value()?)?,
            "--namespace" => args.namespace = value()?,
            "--hash" => args.hash = value()?,
            "--flags" => args.flags = number(value()?)?,
            "--text" => args.text = value()?.into_bytes(),
            "--text-hex" => args.text = unhex(&value()?)?,
            "--text-file" => {
                let path = value()?;
                args.text = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
            }
            "--trailing-hex" => args.trailing = unhex(&value()?)?,
            "--details-hex" => args.details = Some(unhex(&value()?)?),
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    if args.socket.is_empty() {
        return Err(format!("--socket is required\n{USAGE}"));
    }
    if args.slot.is_none() && args.key.is_none() && args.details.is_none() {
        return Err(format!(
            "one of --slot, --key-hex, --details-hex is required\n{USAGE}"
        ));
    }
    Ok(args)
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// A cursor over SSH wire fields; `None` on any short read.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, tail) = self.0.split_first_chunk::<4>()?;
        self.0 = tail;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if self.0.len() < len {
            return None;
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Some(head)
    }
}

/// One request/reply exchange on a fresh connection. Returns the reply body
/// (type byte first). No read timeout: the agent may be waiting on a touch.
fn exchange(socket: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect {socket}: {e}"))?;
    let mut framed = Vec::new();
    put_string(&mut framed, body);
    stream
        .write_all(&framed)
        .map_err(|e| format!("write: {e}"))?;
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("read reply length: {e}"))?;
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    stream
        .read_exact(&mut reply)
        .map_err(|e| format!("read reply: {e}"))?;
    Ok(reply)
}

/// The key blob of the identity whose comment is `PIV_slot_<slot> <guid…>`.
fn find_key(socket: &str, slot: &str, guid: Option<&str>) -> Result<Vec<u8>, String> {
    let reply = exchange(socket, &[SSH_AGENTC_REQUEST_IDENTITIES])?;
    let malformed = || "malformed identities answer".to_string();
    let (&kind, rest) = reply.split_first().ok_or_else(malformed)?;
    if kind != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(format!("identities request answered with type {kind}"));
    }
    let mut reader = Reader(rest);
    let count = reader.u32().ok_or_else(malformed)?;
    let tag = format!("PIV_slot_{slot}");
    let mut comments = Vec::new();
    for _ in 0..count {
        let blob = reader.string().ok_or_else(malformed)?;
        let comment = String::from_utf8_lossy(reader.string().ok_or_else(malformed)?).into_owned();
        let mut words = comment.split_whitespace();
        let slot_matches = words.next() == Some(tag.as_str());
        let guid_matches = guid.is_none_or(|g| words.next().is_some_and(|w| w.starts_with(g)));
        if slot_matches && guid_matches {
            return Ok(blob.to_vec());
        }
        comments.push(comment);
    }
    Err(format!(
        "no identity for {tag}; the agent serves: {comments:?}"
    ))
}

fn request_details(args: &Args, key: &[u8]) -> Vec<u8> {
    let mut contents = Vec::new();
    put_u32(&mut contents, args.version);
    put_string(&mut contents, key);
    put_string(&mut contents, args.namespace.as_bytes());
    put_string(&mut contents, args.hash.as_bytes());
    put_string(&mut contents, &args.text);
    put_u32(&mut contents, args.flags);
    contents.extend_from_slice(&args.trailing);
    let mut details = Vec::new();
    put_string(&mut details, &contents);
    details
}

fn reply_name(kind: u8) -> &'static str {
    match kind {
        SSH_AGENT_FAILURE => "failure",
        SSH_AGENT_SUCCESS => "success",
        SSH_AGENT_EXTENSION_FAILURE => "extension-failure",
        SSH_AGENT_EXTENSION_RESPONSE => "extension-response",
        _ => "other",
    }
}

/// Print the parsed operator-act response inside an extension response, if
/// that is what `rest` holds.
fn print_response(rest: &[u8]) -> Option<()> {
    let mut reader = Reader(rest);
    if reader.string()? != EXTENSION.as_bytes() {
        return None;
    }
    let mut contents = Reader(reader.string()?);
    let version = contents.u32()?;
    let status = contents.u32()?;
    let sshsig = contents.string()?;
    let detail = contents.string()?;
    println!("version {version}");
    println!("status {status}");
    println!("detail {}", String::from_utf8_lossy(detail));
    println!("sshsig-hex {}", hex(sshsig));
    Some(())
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let details = match &args.details {
        Some(details) => details.clone(),
        None => {
            let key = match &args.key {
                Some(key) => key.clone(),
                None => find_key(
                    &args.socket,
                    args.slot.as_deref().unwrap_or_default(),
                    args.guid.as_deref(),
                )?,
            };
            request_details(&args, &key)
        }
    };

    let mut body = vec![SSH_AGENTC_EXTENSION];
    put_string(&mut body, EXTENSION.as_bytes());
    body.extend_from_slice(&details);
    let reply = exchange(&args.socket, &body)?;

    let (&kind, rest) = reply.split_first().ok_or("empty reply")?;
    println!("reply {kind} {}", reply_name(kind));
    println!("raw {}", hex(&reply));
    if kind == SSH_AGENT_EXTENSION_RESPONSE {
        print_response(rest);
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("operator-act-probe: {e}");
            ExitCode::from(2)
        }
    }
}
