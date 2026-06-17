//! `piggy papi` — produce PAPI identity proofs and document signatures.
//!
//! PAPI RFC-0001 Amendment 3 (amarbel-llc/papi §9–§10) adds two OPTIONAL,
//! key-anchored primitives so a PAPI document proves the identities it
//! asserts and is verifiable against a key rather than the host that served
//! it: bidirectional ownership **proofs** (§9) and a detached document
//! **signature** (§10). piggy owns the *producing* side because it holds the
//! keys (slot-9D ECDH recipients, slot-9A SSH-auth); the *verification* side
//! is the papi validator's job (a convenience `verify` is a planned
//! follow-up). Design: `docs/plans/2026-06-17-piggy-papi-design.md`.
//!
//! Subcommands (this increment):
//! - `papi sign`  — emit a §10 `signature` object (`alg: ssh-9a`) over the
//!   RFC 8785 (JCS) canonicalization of the signature-stripped source doc,
//!   signed with a slot-9A SSH signature via the agent.
//! - `papi prove` — emit a §9 proof backlink token + the ready-to-merge
//!   `proofs[]` entry (`fmt: recipient` first; `fmt: signature` is a
//!   follow-up).
//!
//! No new crypto: signing reuses `agent_client::sign_bytes` (the slot-9A
//! agent path), key selection reuses the `piggy_ids` 9A grammar +
//! `openssh_authorized_key` (the same surface behind `piggy ssh-copy-id`).

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};

use crate::store::{find_piggy_ids, store_root};
use piggy_ids::{RecipientFile, openssh_authorized_key};

/// Generous per-sign timeout: the agent MAY prompt for a PIN, so allow for
/// human entry (mirrors `health::SIGN_PROBE_TIMEOUT`).
const SIGN_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(
    name = "piggy papi",
    about = "Produce & verify PAPI identity proofs and document signatures",
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: PapiCommand,
}

#[derive(Subcommand, Debug)]
enum PapiCommand {
    /// Emit a §10 detached document signature (alg: ssh-9a).
    Sign(SignArgs),
    /// Emit a §9 proof backlink token + the proofs[] entry to merge.
    Prove(ProveArgs),
}

#[derive(Args, Debug)]
struct SignArgs {
    /// PAPI source document JSON (default: stdin).
    #[arg(long = "in")]
    input: Option<String>,
    /// Select the signing key by published recipient id (slot-9A).
    #[arg(long, conflicts_with = "ssh_key")]
    recipient: Option<String>,
    /// Select the signing key by an authorized_keys line directly.
    #[arg(long = "ssh-key", conflicts_with = "recipient")]
    ssh_key: Option<String>,
    /// With --inline, write the merged document here (default: stdout).
    #[arg(long)]
    out: Option<String>,
    /// Merge the `signature` member into the full document instead of
    /// emitting the bare signature object.
    #[arg(long)]
    inline: bool,
}

#[derive(Args, Debug)]
struct ProveArgs {
    /// The external identity being proven, as a URI (https://…, dns:…, …).
    #[arg(long)]
    claim: String,
    /// The published recipient id this proof binds the claim to (slot-9D).
    #[arg(long)]
    recipient: String,
    /// Service-provider matcher hint (github, gitlab, mastodon, dns, …).
    #[arg(long)]
    service: Option<String>,
    /// Backlink format (§9.3).
    #[arg(long, value_enum, default_value_t = Fmt::Recipient)]
    fmt: Fmt,
    /// Stable id for the proofs[] entry (unique within proofs[]).
    #[arg(long)]
    id: Option<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Fmt {
    Recipient,
    Signature,
}

impl Fmt {
    fn as_str(self) -> &'static str {
        match self {
            Fmt::Recipient => "recipient",
            Fmt::Signature => "signature",
        }
    }
}

/// `piggy papi` entry point. `argv` is the trailing argv after the
/// subcommand name. Each sub is timed under `piggy.papi.<sub>`.
pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy papi".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let cli = match Cli::try_parse_from(&full) {
        Ok(c) => c,
        // clap prints help/errors itself and exits with its own codes.
        Err(e) => e.exit(),
    };
    match cli.cmd {
        PapiCommand::Sign(a) => piggy::stats::timed_papi("sign", || sign(a)),
        PapiCommand::Prove(a) => piggy::stats::timed_papi("prove", || prove(a)),
    }
}

// -------- sign (§10) --------

fn sign(args: SignArgs) -> i32 {
    match sign_inner(args) {
        Ok(out) => {
            print!("{out}");
            0
        }
        Err(e) => {
            eprintln!("piggy papi sign: {e}");
            1
        }
    }
}

fn sign_inner(args: SignArgs) -> Result<String, String> {
    let src = read_input(args.input.as_deref())?;
    let doc: Value = serde_json::from_str(&src).map_err(|e| format!("parse --in JSON: {e}"))?;
    if !doc.is_object() {
        return Err("source document must be a JSON object".into());
    }

    // §10.2: the signature covers the document with `signature` removed,
    // RFC 8785 (JCS) canonicalized, as UTF-8 bytes.
    let signing_input = jcs_signing_input(&doc)?;

    let (key_line, key_data) =
        select_signing_key(args.recipient.as_deref(), args.ssh_key.as_deref())?;

    let socket = resolve_agent_socket()?;
    let sig = piggy::agent_client::sign_bytes(&socket, &key_data, &signing_input, SIGN_TIMEOUT)
        .map_err(|e| format!("agent sign: {e}"))?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(ssh_signature_wire(&sig));

    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let signature = signature_object(&key_line, &sig_b64, created);

    if args.inline {
        let mut obj = doc.as_object().expect("checked is_object").clone();
        obj.insert("signature".into(), signature);
        let merged =
            serde_json::to_string_pretty(&Value::Object(obj)).map_err(|e| e.to_string())? + "\n";
        match args.out {
            Some(path) => {
                std::fs::write(&path, &merged).map_err(|e| format!("writing {path}: {e}"))?;
                Ok(String::new())
            }
            None => Ok(merged),
        }
    } else {
        Ok(serde_json::to_string_pretty(&signature).map_err(|e| e.to_string())? + "\n")
    }
}

/// Serialize an agent `Signature` to the SSH signature wire blob
/// `string(algorithm) || string(signature)` — the bytes the ssh-agent SIGN
/// response carries verbatim, which PAPI §10.4 base64s into `sig` (the
/// `"ecdsa-sha2-nistp256"` name string followed by the RFC 5656 §3.1.2 (r,s)
/// blob). `Signature::as_bytes()` is only the inner algorithm blob, so the
/// algorithm-name string MUST be prepended for a verifier to recover the key
/// type and decode the signature. `string` is the SSH `uint32`-length-prefixed
/// byte string (RFC 4251 §5).
fn ssh_signature_wire(sig: &ssh_key::Signature) -> Vec<u8> {
    let algorithm = sig.algorithm();
    let algo = algorithm.as_str().as_bytes();
    let blob = sig.as_bytes();
    let mut out = Vec::with_capacity(8 + algo.len() + blob.len());
    out.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    out.extend_from_slice(algo);
    out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    out.extend_from_slice(blob);
    out
}

/// Build the §10.1 signature object `{alg, key, sig, created}`.
fn signature_object(key_line: &str, sig_b64: &str, created: u64) -> Value {
    let mut m = Map::new();
    m.insert("alg".into(), Value::String("ssh-9a".into()));
    m.insert("key".into(), Value::String(key_line.to_string()));
    m.insert("sig".into(), Value::String(sig_b64.to_string()));
    m.insert("created".into(), Value::Number(created.into()));
    Value::Object(m)
}

// -------- prove (§9) --------

fn prove(args: ProveArgs) -> i32 {
    match prove_inner(args) {
        Ok(out) => {
            print!("{out}");
            0
        }
        Err(e) => {
            eprintln!("piggy papi prove: {e}");
            1
        }
    }
}

fn prove_inner(args: ProveArgs) -> Result<String, String> {
    if args.fmt == Fmt::Signature {
        return Err(
            "fmt=signature is not yet implemented; use --fmt recipient (piggy#182 follow-up)"
                .into(),
        );
    }
    // §9.3 fmt=recipient: the backlink token is the bare recipient id.
    let token = args.recipient.clone();
    let id = args
        .id
        .clone()
        .or_else(|| args.service.clone())
        .unwrap_or_else(|| "proof".into());
    let entry = proof_entry(
        &id,
        &args.recipient,
        &args.claim,
        args.service.as_deref(),
        Fmt::Recipient,
    );
    let entry_json = serde_json::to_string_pretty(&entry).map_err(|e| e.to_string())?;

    Ok(format!(
        "PASTE THIS at your proof_uri (GitHub bio, gist, pinned post, DNS TXT, …):\n\
         \n  {token}\n\n\
         ADD TO papi.json proofs[] (fill in \"proof_uri\" with where you pasted it):\n\
         \n{entry_json}\n"
    ))
}

/// Build a §9.1 proof entry. `proof_uri` is left empty for the subject to
/// fill after pasting the backlink token.
fn proof_entry(id: &str, recipient: &str, claim: &str, service: Option<&str>, fmt: Fmt) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), Value::String(id.to_string()));
    m.insert("recipient".into(), Value::String(recipient.to_string()));
    m.insert("claim".into(), Value::String(claim.to_string()));
    m.insert("proof_uri".into(), Value::String(String::new()));
    if let Some(s) = service {
        m.insert("service".into(), Value::String(s.to_string()));
    }
    m.insert("fmt".into(), Value::String(fmt.as_str().to_string()));
    Value::Object(m)
}

// -------- key selection --------

/// Resolve the slot-9A signing key, returning `(authorized_keys_line,
/// KeyData)`. The line becomes the §10.1 `key` field; the `KeyData` selects
/// the agent identity to sign with. `--ssh-key` takes a line directly;
/// `--recipient` selects a published 9A id from the store's piggy-ids; the
/// default uses the store's single 9A entry (error if ambiguous/absent).
fn select_signing_key(
    recipient: Option<&str>,
    ssh_key: Option<&str>,
) -> Result<(String, ssh_key::public::KeyData), String> {
    if let Some(line) = ssh_key {
        let key = key_data_from_line(line)?;
        return Ok((line.to_string(), key));
    }

    let ids_path = find_piggy_ids(&store_root(), "")?;
    let text = std::fs::read_to_string(&ids_path)
        .map_err(|e| format!("reading {}: {e}", ids_path.display()))?;
    let file =
        RecipientFile::parse(&text).map_err(|e| format!("parsing {}: {e}", ids_path.display()))?;
    let candidates: Vec<_> = file.ssh_auth_recipients().collect();

    let chosen = match recipient {
        Some(want) => candidates
            .iter()
            .find(|r| r.id().to_wire() == want)
            .ok_or_else(|| {
                format!(
                    "--recipient {want} is not a published slot-9A SSH-auth key in {}",
                    ids_path.display()
                )
            })?,
        None => match candidates.as_slice() {
            [only] => only,
            [] => {
                return Err(format!(
                    "no slot-9A SSH-auth key in {}; add one with \
                     `piggy pass recipients add <piggy-piv_auth-v1@…>`, or pass --ssh-key/--recipient",
                    ids_path.display()
                ));
            }
            many => {
                let list = many
                    .iter()
                    .map(|r| format!("  {}", r.id().to_wire()))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(format!(
                    "multiple slot-9A keys in {}; pick one with --recipient <id>:\n{list}",
                    ids_path.display()
                ));
            }
        },
    };

    let line = openssh_authorized_key(chosen.id())
        .map_err(|e| format!("rendering SSH key for {}: {e}", chosen.id().to_wire()))?;
    let key = key_data_from_line(&line)?;
    Ok((line, key))
}

/// Parse an OpenSSH `authorized_keys` line (`<keytype> <base64> [comment]`)
/// into the `KeyData` the agent matches identities by.
fn key_data_from_line(line: &str) -> Result<ssh_key::public::KeyData, String> {
    let pk = ssh_key::PublicKey::from_openssh(line)
        .map_err(|e| format!("not a valid OpenSSH public key: {e}"))?;
    Ok(pk.key_data().clone())
}

fn resolve_agent_socket() -> Result<std::path::PathBuf, String> {
    piggy::agent_client::piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "no agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK".into())
}

fn read_input(path: Option<&str>) -> Result<String, String> {
    match path {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("reading {p}: {e}")),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("reading stdin: {e}"))?;
            Ok(buf)
        }
    }
}

// -------- RFC 8785 (JCS) canonicalization --------

/// The §10.2 signing input: the source document with the top-level
/// `signature` member removed, RFC 8785 (JCS) canonicalized, as UTF-8 bytes.
fn jcs_signing_input(doc: &Value) -> Result<Vec<u8>, String> {
    let mut obj = doc
        .as_object()
        .ok_or("document must be a JSON object")?
        .clone();
    obj.remove("signature");
    Ok(canonical_json(&Value::Object(obj))?.into_bytes())
}

/// Serialize `v` per RFC 8785 JCS: lexicographically sorted object keys, no
/// insignificant whitespace, canonical number forms.
///
/// Number canonicalization is the load-bearing part of JCS. This impl ships
/// the integer-only path: any non-integer (float) number is rejected rather
/// than risk a non-canonical serialization, since a float-free PAPI document
/// is JCS-equivalent to compact sorted-`Value` output (the design decision in
/// `docs/plans/2026-06-17-piggy-papi-design.md`). Key ordering uses byte
/// comparison, which equals JCS's UTF-16-code-unit order for the ASCII member
/// names PAPI uses; a non-ASCII member name is the only gap and does not occur
/// in `papi/v0`.
fn canonical_json(v: &Value) -> Result<String, String> {
    let sorted = sort_value(v)?;
    serde_json::to_string(&sorted).map_err(|e| format!("serialize: {e}"))
}

/// Recursively rebuild `v` with object keys in sorted order and reject any
/// non-integer number. Inserting pairs in sorted order makes the result
/// serialize sorted whether `serde_json::Map` is `BTreeMap`- or
/// `IndexMap`-backed (the `preserve_order` feature), so JCS key order holds
/// either way.
fn sort_value(v: &Value) -> Result<Value, String> {
    match v {
        Value::Object(m) => {
            let mut pairs: Vec<(String, Value)> = Vec::with_capacity(m.len());
            for (k, val) in m {
                pairs.push((k.clone(), sort_value(val)?));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Map::new();
            for (k, val) in pairs {
                out.insert(k, val);
            }
            Ok(Value::Object(out))
        }
        Value::Array(a) => Ok(Value::Array(
            a.iter().map(sort_value).collect::<Result<_, _>>()?,
        )),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(format!(
                    "non-integer number {n}: JCS float canonicalization is unsupported in papi/v0"
                ));
            }
            Ok(v.clone())
        }
        _ => Ok(v.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_and_is_compact() {
        let v: Value = serde_json::from_str(r#"{ "b": 1, "a": 2 }"#).unwrap();
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let v: Value = serde_json::from_str(r#"{"z":{"y":1,"x":2},"a":[{"d":1,"c":2}]}"#).unwrap();
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":[{"c":2,"d":1}],"z":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn canonical_json_rejects_floats() {
        let v: Value = serde_json::from_str(r#"{"x": 4.2}"#).unwrap();
        let err = canonical_json(&v).unwrap_err();
        assert!(err.contains("float canonicalization"), "got: {err}");
    }

    #[test]
    fn jcs_signing_input_strips_signature() {
        let v: Value =
            serde_json::from_str(r#"{"piggy":{"x":1},"signature":{"alg":"ssh-9a"}}"#).unwrap();
        let bytes = jcs_signing_input(&v).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"piggy":{"x":1}}"#);
    }

    #[test]
    fn jcs_signing_input_no_signature_is_whole_doc() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let bytes = jcs_signing_input(&v).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn ssh_signature_wire_prepends_algorithm_name_string() {
        // PAPI §10.4: `sig` is the raw agent blob = string(alg) || string(blob),
        // NOT the bare inner blob from Signature::as_bytes(). Pin that framing.
        use ssh_key::{Algorithm, Signature};
        let blob = vec![7u8; 64]; // Ed25519 sig length; no inner structure to validate.
        let sig = Signature::new(Algorithm::new("ssh-ed25519").unwrap(), blob.clone()).unwrap();

        let name = b"ssh-ed25519";
        let mut expected = Vec::new();
        expected.extend_from_slice(&(name.len() as u32).to_be_bytes());
        expected.extend_from_slice(name);
        expected.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        expected.extend_from_slice(&blob);

        assert_eq!(ssh_signature_wire(&sig), expected);
    }

    #[test]
    fn signature_object_shape() {
        let v = signature_object("ecdsa-sha2-nistp256 AAAA", "c2ln", 1_700_000_000);
        assert_eq!(v["alg"], "ssh-9a");
        assert_eq!(v["key"], "ecdsa-sha2-nistp256 AAAA");
        assert_eq!(v["sig"], "c2ln");
        assert_eq!(v["created"], 1_700_000_000u64);
    }

    #[test]
    fn proof_entry_defaults_proof_uri_empty_and_carries_fmt() {
        let v = proof_entry(
            "github",
            "piggy-recipient-v1@pivy_ecdh_p256_pub-qqq",
            "https://github.com/alice",
            Some("github"),
            Fmt::Recipient,
        );
        assert_eq!(v["id"], "github");
        assert_eq!(v["recipient"], "piggy-recipient-v1@pivy_ecdh_p256_pub-qqq");
        assert_eq!(v["claim"], "https://github.com/alice");
        assert_eq!(v["proof_uri"], "");
        assert_eq!(v["service"], "github");
        assert_eq!(v["fmt"], "recipient");
    }

    #[test]
    fn proof_entry_omits_absent_service() {
        let v = proof_entry("p", "r", "c", None, Fmt::Recipient);
        assert!(v.get("service").is_none());
    }
}
