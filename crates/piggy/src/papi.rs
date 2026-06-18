//! `piggy papi` — produce PAPI identity proofs and document signatures.
//!
//! PAPI RFC-0001 Amendment 3 (amarbel-llc/papi §9–§10) adds two OPTIONAL,
//! key-anchored primitives so a PAPI document proves the identities it
//! asserts and is verifiable against a key rather than the host that served
//! it: bidirectional ownership **proofs** (§9) and a detached document
//! **signature** (§10). piggy owns the *producing* side because it holds the
//! keys (slot-9D ECDH recipients, slot-9A SSH-auth); the authoritative
//! *verification* side is the papi validator's job, and piggy ships a
//! convenience `verify`. Design: `docs/plans/2026-06-17-piggy-papi-design.md`.
//!
//! Subcommands:
//! - `papi sign`  — emit a §10 `signature` object (`alg: ssh-9a`) over the
//!   RFC 8785 (JCS) canonicalization of the signature-stripped source doc,
//!   signed with a slot-9A SSH signature via the agent.
//! - `papi prove` — emit a §9 proof backlink token + the ready-to-merge
//!   `proofs[]` entry. `fmt: recipient` is the bare recipient id; `fmt:
//!   signature` is a slot-9A SSH signature over the `claim` (§9.3).
//! - `papi verify` — convenience client: fetch a live domain (bounded
//!   `curl`), run the §9.4 proof verdicts and the §10.3 signature verdict
//!   (ECDSA/Ed25519 over the §10.2 JCS bytes), emit a TAP/ndjson stream. The
//!   authoritative verifier is the amarbel-llc/papi validator; this is the
//!   ergonomic paved path (mirrors `piggy health` vs `ssh-agent-mux health`).
//!
//! Per §10.2 (Amendment 6) the signature commits to the ANONYMOUS /papi
//! projection: feed `papi sign --in` the document you will serve at anonymous
//! `/papi`, and `verify` checks the signature against anonymous `/papi`.
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
    /// Verify a live domain's proofs (§9.4) and document signature (§10.3).
    Verify(VerifyArgs),
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
    /// For --fmt signature: the slot-9A signing key as an authorized_keys
    /// line (default: the store's single slot-9A key).
    #[arg(long = "ssh-key")]
    ssh_key: Option<String>,
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

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Domain to verify, optionally `#<proof-id>` to select one proof.
    domain: String,
    /// Emit tap-ndjson(7) records instead of TAP-14.
    #[arg(long)]
    json: bool,
    /// Fail the run if the document is unsigned or signed-but-invalid.
    #[arg(long = "require-signed")]
    require_signed: bool,
    /// Restrict verification to these proof ids (repeatable).
    #[arg(long = "proof")]
    proof: Vec<String>,
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
        PapiCommand::Verify(a) => piggy::stats::timed_papi("verify", || verify(a)),
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
    let id = args
        .id
        .clone()
        .or_else(|| args.service.clone())
        .unwrap_or_else(|| "proof".into());

    let token = match args.fmt {
        // §9.3 fmt=recipient: the backlink token is the bare recipient id.
        Fmt::Recipient => args.recipient.clone(),
        // §9.3 fmt=signature: a slot-9A SSH signature over the exact `claim`
        // string, verifiable against the doc's ssh_authorized_keys[]. The
        // signing key is a slot-9A key (NOT the --recipient, which is the
        // slot-9D binding); default to the store's single 9A, --ssh-key to
        // override. The signed string is the bare `claim` per §9.3 as written
        // (namespacing for replay-resistance is an open spec question raised
        // with the papi side; bare keeps us interoperable with the validator
        // today).
        Fmt::Signature => {
            let (_key_line, key_data) = select_signing_key(None, args.ssh_key.as_deref())?;
            let socket = resolve_agent_socket()?;
            let sig = piggy::agent_client::sign_bytes(
                &socket,
                &key_data,
                args.claim.as_bytes(),
                SIGN_TIMEOUT,
            )
            .map_err(|e| format!("agent sign: {e}"))?;
            base64::engine::general_purpose::STANDARD.encode(ssh_signature_wire(&sig))
        }
    };

    let entry = proof_entry(
        &id,
        &args.recipient,
        &args.claim,
        args.service.as_deref(),
        args.fmt,
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

// -------- verify (§9.4 / §10.3) --------

/// curl bounds for the convenience verifier (this is not the authoritative
/// validator). HTTPS only, no redirect following (so a cross-host redirect at
/// a `proof_uri` yields an empty body → unverified, never a silent cross-host
/// fetch), bounded time + size.
const FETCH_MAX_TIME: &str = "10";
const FETCH_MAX_FILESIZE: &str = "1048576"; // 1 MiB

/// A single verify verdict line (proof or signature). Owned `name` because
/// proof ids are dynamic, so this can't reuse `health::CheckResult`.
struct Point {
    name: String,
    status: Verdict,
    diags: Vec<(String, String)>,
}

enum Verdict {
    Pass,
    Fail,
    Skip(String),
}

fn verify(args: VerifyArgs) -> i32 {
    match verify_inner(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piggy papi verify: {e}");
            2
        }
    }
}

fn verify_inner(args: &VerifyArgs) -> Result<i32, String> {
    let (domain, anchor) = match args.domain.split_once('#') {
        Some((d, p)) => (d.to_string(), Some(p.to_string())),
        None => (args.domain.clone(), None),
    };

    // The signature commits to the ANONYMOUS /papi projection (§10.2,
    // Amendment 6), so verify against /papi requested anonymously.
    let doc = fetch_json(&format!("https://{domain}/papi"))?;
    let proofs = match fetch_text(&format!("https://{domain}/papi/proofs")) {
        Ok(body) => serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("data").cloned())
            .unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };

    let mut points: Vec<Point> = Vec::new();

    // §9.4 — proofs.
    if let Some(arr) = proofs.as_array() {
        for entry in arr {
            let id = entry.get("id").and_then(Value::as_str).unwrap_or("?");
            if anchor.as_deref().is_some_and(|a| a != id) {
                continue;
            }
            if !args.proof.is_empty() && !args.proof.iter().any(|p| p == id) {
                continue;
            }
            points.push(verify_proof(entry, &doc));
        }
    }

    // §10.3 — document signature.
    points.push(verify_document_signature(&doc));

    let format = if args.json {
        crate::health::Format::Ndjson
    } else {
        crate::health::Format::Auto
    };
    render_points(&points, format)?;

    let proof_fail = points
        .iter()
        .any(|p| p.name.starts_with("proof:") && matches!(p.status, Verdict::Fail));
    let sig_bad = points.iter().any(|p| {
        p.name == "signature"
            && (matches!(p.status, Verdict::Fail)
                || (args.require_signed && matches!(p.status, Verdict::Skip(_))))
    });
    Ok(i32::from(proof_fail || sig_bad))
}

/// §9.4 verdict for one proof entry. `fmt:recipient`: the `recipient` id must
/// be published in `piggy.encryption_recipients[]` (else unverifiable) and the
/// body at `proof_uri` must contain it (verified) or not (unverified). An
/// unknown `fmt` is skipped (§9.3).
fn verify_proof(entry: &Value, doc: &Value) -> Point {
    let id = entry.get("id").and_then(Value::as_str).unwrap_or("?");
    let name = format!("proof: {id}");
    let recipient = entry.get("recipient").and_then(Value::as_str).unwrap_or("");
    let claim = entry.get("claim").and_then(Value::as_str).unwrap_or("");
    let proof_uri = entry.get("proof_uri").and_then(Value::as_str).unwrap_or("");
    let fmt = entry
        .get("fmt")
        .and_then(Value::as_str)
        .unwrap_or("recipient");

    let diags = vec![
        ("claim".into(), claim.to_string()),
        ("recipient".into(), recipient.to_string()),
        ("fmt".into(), fmt.to_string()),
    ];

    if fmt != "recipient" {
        return Point {
            name,
            status: Verdict::Skip(format!("unsupported fmt {fmt}")),
            diags: vec![],
        };
    }
    if !published_recipients(doc).iter().any(|r| r == recipient) {
        return Point {
            name,
            status: Verdict::Skip(format!("recipient not published: {recipient}")),
            diags,
        };
    }
    match fetch_text(proof_uri) {
        Ok(body) if body.contains(recipient) => Point {
            name,
            status: Verdict::Pass,
            diags,
        },
        Ok(_) => Point {
            name,
            status: Verdict::Fail,
            diags: with(diags, "reason", "backlink absent at proof_uri"),
        },
        Err(e) => Point {
            name,
            status: Verdict::Fail,
            diags: with(diags, "reason", &format!("fetch proof_uri: {e}")),
        },
    }
}

/// §10.3 verdict for the document `signature` member.
fn verify_document_signature(doc: &Value) -> Point {
    let name = "signature".to_string();
    let Some(sig) = doc.get("signature") else {
        return Point {
            name,
            status: Verdict::Skip("no signature member".into()),
            diags: vec![],
        };
    };
    let alg = sig.get("alg").and_then(Value::as_str).unwrap_or("");
    let key = sig.get("key").and_then(Value::as_str).unwrap_or("");
    let sig_b64 = sig.get("sig").and_then(Value::as_str).unwrap_or("");
    let diags = vec![
        ("alg".into(), alg.to_string()),
        ("key".into(), key.to_string()),
    ];

    if alg != "ssh-9a" {
        // §10.1: unknown alg → treat as unsigned (skip), not invalid.
        return Point {
            name,
            status: Verdict::Skip(format!("unknown alg {alg}")),
            diags: vec![],
        };
    }
    if !published_ssh_keys(doc).iter().any(|k| k == key) {
        // key not in ssh_authorized_keys[] → unverifiable → unsigned.
        return Point {
            name,
            status: Verdict::Skip("key not published in ssh_authorized_keys".into()),
            diags,
        };
    }
    let signing_input = match jcs_signing_input(doc) {
        Ok(b) => b,
        Err(e) => {
            return Point {
                name,
                status: Verdict::Fail,
                diags: with(diags, "reason", &format!("canonicalize: {e}")),
            };
        }
    };
    match verify_ssh9a(key, sig_b64, &signing_input) {
        Ok(true) => Point {
            name,
            status: Verdict::Pass,
            diags,
        },
        Ok(false) => Point {
            name,
            status: Verdict::Fail,
            diags: with(diags, "reason", "signature does not verify"),
        },
        Err(e) => Point {
            name,
            status: Verdict::Fail,
            diags: with(diags, "reason", &e),
        },
    }
}

fn with(mut diags: Vec<(String, String)>, k: &str, v: &str) -> Vec<(String, String)> {
    diags.push((k.to_string(), v.to_string()));
    diags
}

fn published_recipients(doc: &Value) -> Vec<String> {
    string_array(doc.pointer("/piggy/encryption_recipients"))
}

fn published_ssh_keys(doc: &Value) -> Vec<String> {
    string_array(doc.pointer("/piggy/ssh_authorized_keys"))
}

fn string_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// -------- §10.4 ssh-9a signature verification (openssl) --------

/// Verify a §10.4 `ssh-9a` signature. `sig_b64` is base64 of the SSH wire blob
/// `string(algo) || string(blob)`; verify it against `key_line` (an
/// authorized_keys line) over `message` (the §10.2 JCS bytes). ECDSA uses
/// SHA-256 (P-256) / SHA-384 (P-384); Ed25519 hashes internally. `Ok(false)`
/// = a well-formed signature that doesn't verify; `Err` = a structural problem
/// (the caller renders both as a failing verdict).
fn verify_ssh9a(key_line: &str, sig_b64: &str, message: &[u8]) -> Result<bool, String> {
    use base64::engine::general_purpose::STANDARD;
    let wire = STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| format!("sig is not valid base64: {e}"))?;
    let (algo, blob) = parse_ssh_string_pair(&wire).map_err(|e| format!("sig blob: {e}"))?;
    let algo = String::from_utf8(algo).map_err(|e| format!("sig algorithm not UTF-8: {e}"))?;
    let key = key_data_from_line(key_line)?;

    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use ssh_key::public::KeyData;
    match (algo.as_str(), &key) {
        ("ecdsa-sha2-nistp256", KeyData::Ecdsa(ec)) => verify_ecdsa(
            Nid::X9_62_PRIME256V1,
            MessageDigest::sha256(),
            ec.as_sec1_bytes(),
            &blob,
            message,
        ),
        ("ecdsa-sha2-nistp384", KeyData::Ecdsa(ec)) => verify_ecdsa(
            Nid::SECP384R1,
            MessageDigest::sha384(),
            ec.as_sec1_bytes(),
            &blob,
            message,
        ),
        ("ssh-ed25519", KeyData::Ed25519(ed)) => verify_ed25519(ed.as_ref(), &blob, message),
        _ => Err(format!("signature alg {algo} does not match key type")),
    }
}

fn verify_ecdsa(
    nid: openssl::nid::Nid,
    md: openssl::hash::MessageDigest,
    sec1_point: &[u8],
    blob: &[u8],
    message: &[u8],
) -> Result<bool, String> {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::ecdsa::EcdsaSig;

    // The ECDSA signature blob is string(mpint r) || string(mpint s) (RFC 5656).
    let (r, s) = parse_ssh_string_pair(blob).map_err(|e| format!("ecdsa sig: {e}"))?;
    let group = EcGroup::from_curve_name(nid).map_err(|e| e.to_string())?;
    let mut ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    let point = EcPoint::from_bytes(&group, sec1_point, &mut ctx)
        .map_err(|e| format!("bad ec point: {e}"))?;
    let eckey = EcKey::from_public_key(&group, &point).map_err(|e| e.to_string())?;
    let r = BigNum::from_slice(&r).map_err(|e| e.to_string())?;
    let s = BigNum::from_slice(&s).map_err(|e| e.to_string())?;
    let sig = EcdsaSig::from_private_components(r, s).map_err(|e| e.to_string())?;
    let digest = openssl::hash::hash(md, message).map_err(|e| e.to_string())?;
    sig.verify(&digest, &eckey).map_err(|e| e.to_string())
}

fn verify_ed25519(pubkey: &[u8], sig: &[u8], message: &[u8]) -> Result<bool, String> {
    use openssl::pkey::{Id, PKey};
    use openssl::sign::Verifier;
    let pkey = PKey::public_key_from_raw_bytes(pubkey, Id::ED25519)
        .map_err(|e| format!("ed25519 key: {e}"))?;
    let mut verifier = Verifier::new_without_digest(&pkey).map_err(|e| e.to_string())?;
    verifier
        .verify_oneshot(sig, message)
        .map_err(|e| e.to_string())
}

/// Read two consecutive SSH `string`s (uint32-length-prefixed, RFC 4251 §5)
/// from the front of `buf`, returning their byte contents.
fn parse_ssh_string_pair(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (a, rest) = read_ssh_string(buf)?;
    let (b, _) = read_ssh_string(rest)?;
    Ok((a.to_vec(), b.to_vec()))
}

fn read_ssh_string(buf: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if buf.len() < 4 {
        return Err("truncated length prefix".into());
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let rest = &buf[4..];
    if rest.len() < len {
        return Err(format!(
            "truncated string (want {len}, have {})",
            rest.len()
        ));
    }
    Ok((&rest[..len], &rest[len..]))
}

// -------- fetch (curl shell-out) --------

fn fetch_text(url: &str) -> Result<String, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsS",
            "--proto",
            "=https",
            "--max-time",
            FETCH_MAX_TIME,
            "--max-filesize",
            FETCH_MAX_FILESIZE,
            url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e} (is curl installed?)"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("response not UTF-8: {e}"))
}

fn fetch_json(url: &str) -> Result<Value, String> {
    serde_json::from_str(&fetch_text(url)?).map_err(|e| format!("parse {url} JSON: {e}"))
}

// -------- verdict rendering (tap-dancer) --------

fn render_points(points: &[Point], format: crate::health::Format) -> Result<(), String> {
    use std::io::IsTerminal;
    let stdout = std::io::stdout();
    let mut buf = stdout.lock();
    let mut rep = match format {
        crate::health::Format::Ndjson => {
            tap_dancer::Reporter::Ndjson(tap_dancer::NdjsonWriter::new(&mut buf))
        }
        crate::health::Format::Auto if !std::io::stdout().is_terminal() => {
            tap_dancer::Reporter::Ndjson(tap_dancer::NdjsonWriter::new(&mut buf))
        }
        _ => tap_dancer::Reporter::Tap(
            tap_dancer::TapWriterBuilder::new(&mut buf)
                .build()
                .map_err(|e| e.to_string())?,
        ),
    };
    rep.plan_ahead(points.len()).map_err(|e| e.to_string())?;
    for p in points {
        let diags: Vec<(&str, serde_json::Value)> = p
            .diags
            .iter()
            .map(|(k, v)| (k.as_str(), Value::String(v.clone())))
            .collect();
        let r = match &p.status {
            Verdict::Pass if diags.is_empty() => rep.ok(&p.name),
            Verdict::Pass => rep.ok_diag(&p.name, &diags),
            Verdict::Fail => rep.not_ok_diag(&p.name, &diags),
            Verdict::Skip(reason) => rep.skip(&p.name, reason),
        };
        r.map_err(|e| e.to_string())?;
    }
    rep.finish().map_err(|e| e.to_string())
}

// -------- RFC 8785 (JCS) canonicalization --------

/// The §10.2 signing input: the source document with the signature members
/// removed, RFC 8785 (JCS) canonicalized, as UTF-8 bytes. Both `signature`
/// (the Amendment-5/6 single signature) and `signatures` (the Amendment-7
/// multi-signature array, forthcoming — pinned with the papi side) are
/// stripped, so the signed bytes never include any signature member.
/// Stripping `signatures` today is a forward-compatible no-op until the array
/// exists; it keeps the signing input stable across the Amendment-7 cutover.
fn jcs_signing_input(doc: &Value) -> Result<Vec<u8>, String> {
    let mut obj = doc
        .as_object()
        .ok_or("document must be a JSON object")?
        .clone();
    obj.remove("signature");
    obj.remove("signatures");
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
    fn jcs_signing_input_strips_signatures_array_too() {
        // Amendment 7 forward-compat: the signing input excludes `signatures[]`.
        let v: Value = serde_json::from_str(
            r#"{"piggy":{"x":1},"signature":{"alg":"ssh-9a"},"signatures":[{"alg":"ssh-9a"}]}"#,
        )
        .unwrap();
        let bytes = jcs_signing_input(&v).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"piggy":{"x":1}}"#);
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

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut v = (bytes.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(bytes);
        v
    }

    /// SSH mpint: minimal big-endian, sign-extended with a leading 0x00 when
    /// the high bit is set (matches what the agent emits).
    fn mpint(bytes: &[u8]) -> Vec<u8> {
        let mut b = bytes;
        while b.len() > 1 && b[0] == 0 {
            b = &b[1..];
        }
        if !b.is_empty() && b[0] & 0x80 != 0 {
            let mut out = vec![0u8];
            out.extend_from_slice(b);
            out
        } else {
            b.to_vec()
        }
    }

    #[test]
    fn verify_ssh9a_ecdsa_p256_roundtrip_and_tamper() {
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        use openssl::ecdsa::EcdsaSig;
        use openssl::hash::{MessageDigest, hash};
        use openssl::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let sec1 = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let message = br#"{"a":1,"b":2}"#;
        let digest = hash(MessageDigest::sha256(), message).unwrap();
        let sig = EcdsaSig::sign(&digest, &key).unwrap();

        // blob = string(mpint r) || string(mpint s); wire = string(alg) || string(blob)
        let mut blob = ssh_string(&mpint(&sig.r().to_vec()));
        blob.extend(ssh_string(&mpint(&sig.s().to_vec())));
        let mut wire = ssh_string(b"ecdsa-sha2-nistp256");
        wire.extend(ssh_string(&blob));
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&wire);

        let pk = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(&sec1).unwrap();
        let line = ssh_key::PublicKey::new(ssh_key::public::KeyData::Ecdsa(pk), "")
            .to_openssh()
            .unwrap();

        assert!(
            verify_ssh9a(&line, &sig_b64, message).unwrap(),
            "valid sig must verify"
        );
        assert!(
            !verify_ssh9a(&line, &sig_b64, b"tampered").unwrap(),
            "tampered message must not verify"
        );
    }

    #[test]
    fn read_ssh_string_parses_length_prefixed() {
        let mut buf = ssh_string(b"first");
        buf.extend(ssh_string(b"second"));
        let (a, b) = parse_ssh_string_pair(&buf).unwrap();
        assert_eq!(a, b"first");
        assert_eq!(b, b"second");
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

    #[test]
    fn proof_entry_signature_fmt() {
        let v = proof_entry("p", "r", "c", None, Fmt::Signature);
        assert_eq!(v["fmt"], "signature");
    }
}
