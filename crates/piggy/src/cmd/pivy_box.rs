//! `piggy box` subcommand — PIV-based encryption/decryption.
//!
//! The first-party Rust re-implementation of the C `pivy-box` surface
//! piggy uses. As of piggy#165 it is NO LONGER a superset that falls
//! back to C: the only subcommands are the four below, and anything else
//! is a usage error, not a silent hop to the C binary. The full C
//! surface (`tpl edit`, `key *`, `challenge *`, interactive modes) stays
//! reachable only through the explicit `piggy pivy box` escape hatch
//! while C is still shipped (piggy#289 Phase 5 removes it).
//!
//! - `piggy box stream encrypt <tpl-path>`
//! - `piggy box stream decrypt [file]`
//! - `piggy box tpl create <name> primary local-guid <guid>`
//! - `piggy box tpl show [tpl-path]`

use std::io::{self, Read, Write};
use std::path::PathBuf;

use piggy_box::stream::EboxStream;
use piggy_box::unlock::unlock_ebox;

/// Entry point for `piggy box ...`. `args` is the argv *after* `box`
/// (i.e. `Command::Box { rest }`), dispatched as `<type> <operation>` to
/// match pivy-box's two-level subcommand structure. Returns the process
/// exit code: a handler's own code, or `2` for an unrecognized
/// subcommand (piggy#165 — the C fallback is gone).
pub fn run(args: &[String]) -> i32 {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((type_name, op_rest)) = argv.split_first() else {
        return usage_error("");
    };
    let handled = match *type_name {
        "stream" => dispatch_stream(op_rest),
        "tpl" => dispatch_tpl(op_rest),
        _ => None,
    };
    handled.unwrap_or_else(|| usage_error(&argv.join(" ")))
}

/// Print the `piggy box` usage banner for an unrecognized subcommand and
/// return exit code 2. The C `pivy-box` surface piggy does not
/// re-implement is reachable through `piggy pivy box`.
fn usage_error(attempted: &str) -> i32 {
    if attempted.is_empty() {
        eprintln!("piggy box: missing subcommand");
    } else {
        eprintln!("piggy box: unknown subcommand: {attempted}");
    }
    eprintln!("supported: stream encrypt|decrypt, tpl create|show");
    eprintln!(
        "for the rest of the pivy-box surface (tpl edit, key, challenge, …): \
         piggy pivy box <args>"
    );
    2
}

fn dispatch_stream(args: &[&str]) -> Option<i32> {
    let (op, rest) = args.split_first()?;
    // Handled ops emit `piggy.box.<op>` telemetry (stats-me); the fall-back
    // (`None`) paths reach C `pivy-box`, which isn't instrumented here.
    match *op {
        "encrypt" => Some(crate::stats::timed_box("stream_encrypt", || {
            cmd_stream_encrypt(rest)
        })),
        "decrypt" => Some(crate::stats::timed_box("stream_decrypt", || {
            cmd_stream_decrypt(rest)
        })),
        // Unknown stream op (or empty) — a usage error (piggy#165).
        _ => None,
    }
}

fn dispatch_tpl(args: &[&str]) -> Option<i32> {
    let (op, rest) = args.split_first()?;
    match *op {
        "create" => Some(crate::stats::timed_box("tpl_create", || {
            cmd_tpl_create(rest)
        })),
        "show" => Some(crate::stats::timed_box("tpl_show", || cmd_tpl_show(rest))),
        // `edit` (and any unknown tpl op, or empty) — the Rust impl never
        // implemented `tpl edit`; it is a usage error now (piggy#165), and
        // the C builder is reachable via `piggy pivy box tpl edit`.
        _ => None,
    }
}

/// `piggy box stream encrypt <tpl-path>`
///
/// Reads plaintext from stdin, encrypts as an ebox stream, writes to stdout.
fn cmd_stream_encrypt(args: &[&str]) -> i32 {
    let tpl_path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("piggy box stream encrypt: template path required");
            return 1;
        }
    };

    let tpl_bytes = match std::fs::read(&tpl_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "piggy box stream encrypt: cannot read template {}: {e}",
                tpl_path.display()
            );
            return 1;
        }
    };

    let tpl = match piggy_box::EboxTemplate::from_b64_bytes(&tpl_bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("piggy box stream encrypt: invalid template: {e}");
            return 1;
        }
    };

    let stream = match EboxStream::new(&tpl) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy box stream encrypt: failed to create stream: {e}");
            return 1;
        }
    };

    let mut plaintext = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut plaintext) {
        eprintln!("piggy box stream encrypt: stdin: {e}");
        return 1;
    }

    let mut stdout = io::stdout().lock();

    let header = match stream.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("piggy box stream encrypt: header: {e}");
            return 1;
        }
    };
    if let Err(e) = stdout.write_all(&header) {
        eprintln!("piggy box stream encrypt: write: {e}");
        return 1;
    }

    let chunk_size = stream.chunk_size as usize;
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![b""]
    } else {
        plaintext.chunks(chunk_size).collect()
    };

    for (seqnr, chunk) in chunks.iter().enumerate() {
        match stream.encrypt_chunk(seqnr as u32, chunk) {
            Ok(enc) => {
                if let Err(e) = stdout.write_all(&enc) {
                    eprintln!("piggy box stream encrypt: write: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("piggy box stream encrypt: chunk {seqnr}: {e}");
                return 1;
            }
        }
    }

    0
}

/// The in-process ebox-stream decryptor every store decrypt goes through
/// (piggy#164/#154: `pass show`/`edit`/`generate -i`/`grep`/`verify`, the
/// re-encryption walk, and `piggy box stream decrypt` itself). Holds the
/// two ECDH oracles for the life of one command so a walk over many
/// eboxes pays for the agent connection and the card PIN once: the
/// card oracle caches the PIN per token GUID.
///
/// Oracle resolution:
/// - agent: `PIGGY_AUTH_SOCK` when set and non-empty, else `SSH_AUTH_SOCK`
///   (piggy#123); constructed lazily-connecting, so an unreachable socket
///   costs nothing until a part is tried.
/// - card: direct PC/SC through [`crate::card_oracle::CardEcdhOracle`]
///   with the askpass PIN supplier (piggy#31); skipped when no resource
///   manager is reachable. There is no agent-only mode (the C era's
///   `pivy-box stream decrypt -b`): a caller that must never prompt runs
///   with `SSH_ASKPASS_REQUIRE=never` and no tty, and the askpass
///   refuses.
///
/// Test hook (#123): when `PIGGY_TEST_SOCK_RECORD` names a file, the
/// agent socket this decryptor resolved (or an empty line) is appended
/// to it, so a bats test can assert routing without a real agent. It
/// replaces the hook the C-era mock `pivy-box` carried.
pub struct Decryptor {
    agent: Option<crate::agent_client::AgentEcdhOracle>,
    card: Option<crate::card_oracle::CardEcdhOracle>,
}

impl Decryptor {
    /// Build both oracles from the environment. The agent socket is not
    /// contacted until the first [`Decryptor::decrypt`]; the card oracle
    /// establishes its PC/SC context here (and is dropped if it cannot).
    pub fn from_env() -> Self {
        let agent_socket = crate::agent_client::piggy_auth_sock_override()
            .or_else(|| std::env::var_os("SSH_AUTH_SOCK"))
            .map(PathBuf::from);
        record_agent_socket_for_tests(agent_socket.as_deref());
        let agent =
            agent_socket.and_then(
                |sock| match crate::agent_client::AgentEcdhOracle::new(&sock) {
                    Ok(o) => Some(o),
                    Err(e) => {
                        tracing::warn!(
                            "decrypt: failed to construct AgentEcdhOracle for {}: {e} — \
                         proceeding without agent",
                            sock.display()
                        );
                        None
                    }
                },
            );
        let card = match crate::card_oracle::CardEcdhOracle::new(
            crate::card_oracle::askpass_pin_supplier(),
        ) {
            Ok(o) => Some(o),
            Err(e) => {
                tracing::debug!("decrypt: card oracle unavailable: {e} — agent path only");
                None
            }
        };
        Self { agent, card }
    }

    /// Decrypt one on-disk ebox stream (header + chunk frames) to its
    /// plaintext. Errors are one-line, user-facing strings.
    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream =
            EboxStream::from_bytes(input).map_err(|e| format!("invalid stream: {e}"))?;

        let agent_dyn: Option<&mut dyn piggy_box::oracle::EcdhOracle> = self
            .agent
            .as_mut()
            .map(|o| o as &mut dyn piggy_box::oracle::EcdhOracle);
        let card_dyn: Option<&mut dyn piggy_box::oracle::EcdhOracle> = self
            .card
            .as_mut()
            .map(|o| o as &mut dyn piggy_box::oracle::EcdhOracle);
        unlock_ebox(&mut stream.ebox, agent_dyn, card_dyn)
            .map_err(|e| format!("unlock failed: {e}"))?;

        // The remaining bytes after the stream header are the chunks.
        // Re-serialize the header to find where chunks begin.
        let header_bytes = stream.to_bytes().map_err(|e| e.to_string())?;
        let mut chunk_data = &input[header_bytes.len()..];
        let mut out = Vec::new();
        let mut expected_seqnr: u32 = 0;
        while !chunk_data.is_empty() {
            // Each chunk frame is: u32(seqnr) + u32(len) + len bytes.
            if chunk_data.len() < 8 {
                return Err("truncated chunk frame".into());
            }
            let string_len =
                u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]])
                    as usize;
            let frame_len = 4 + 4 + string_len;
            if chunk_data.len() < frame_len {
                return Err("truncated chunk data".into());
            }
            let (_, plain) = stream
                .decrypt_chunk(Some(expected_seqnr), &chunk_data[..frame_len])
                .map_err(|e| format!("chunk {expected_seqnr}: {e}"))?;
            out.extend_from_slice(&plain);
            chunk_data = &chunk_data[frame_len..];
            expected_seqnr += 1;
        }
        Ok(out)
    }
}

fn record_agent_socket_for_tests(sock: Option<&std::path::Path>) {
    if let Some(record) = std::env::var_os("PIGGY_TEST_SOCK_RECORD") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(record)
        {
            let line = sock.map(|p| p.display().to_string()).unwrap_or_default();
            let _ = writeln!(f, "{line}");
        }
    }
}

/// `piggy box stream decrypt [file]`
///
/// Reads an ebox stream (from file or stdin), unlocks it via agent/card,
/// decrypts all chunks, writes plaintext to stdout.
fn cmd_stream_decrypt(args: &[&str]) -> i32 {
    let input = match args.first() {
        Some(path) => match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("piggy box stream decrypt: cannot read {path}: {e}");
                return 1;
            }
        },
        None => {
            let mut buf = Vec::new();
            if let Err(e) = io::stdin().read_to_end(&mut buf) {
                eprintln!("piggy box stream decrypt: stdin: {e}");
                return 1;
            }
            buf
        }
    };

    let plain = match Decryptor::from_env().decrypt(&input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy box stream decrypt: {e}");
            return 1;
        }
    };
    if let Err(e) = io::stdout().lock().write_all(&plain) {
        eprintln!("piggy box stream decrypt: write: {e}");
        return 1;
    }
    0
}

/// `piggy box tpl create <name> primary local-guid <guid>`
///
/// Creates a template file with a PRIMARY config containing the public
/// key from a locally-connected PIV device.
fn cmd_tpl_create(args: &[&str]) -> i32 {
    // Parse: <name> primary local-guid <guid>
    // For -i (interactive), we'd need TUI — out of scope for v1.
    if args.first() == Some(&"-i") {
        eprintln!("piggy box tpl create: interactive mode not yet implemented");
        return 1;
    }

    if args.len() < 4 {
        eprintln!(
            "piggy box tpl create: usage: piggy box tpl create <name> primary local-guid <guid>"
        );
        return 1;
    }

    let tpl_name = args[0];
    let config_type = args[1];
    let guid_source = args[2];
    let guid_hex = args[3];

    if config_type != "primary" {
        eprintln!("piggy box tpl create: only 'primary' config type supported");
        return 1;
    }
    if guid_source != "local-guid" {
        eprintln!("piggy box tpl create: only 'local-guid' source supported");
        return 1;
    }

    let guid = match piggy_piv::Guid::from_hex(guid_hex) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("piggy box tpl create: invalid GUID: {e}");
            return 1;
        }
    };

    // Connect to the card and read the key management slot (9D)
    let ctx = match piggy_piv::PivContext::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("piggy box tpl create: PCSC: {e}");
            return 1;
        }
    };

    let tokens = match ctx.enumerate_tokens() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("piggy box tpl create: enumerate: {e}");
            return 1;
        }
    };

    let token = match tokens.iter().find(|t| t.guid().to_hex() == guid.to_hex()) {
        Some(t) => t,
        None => {
            eprintln!(
                "piggy box tpl create: PIV device {} not found",
                guid.to_hex()
            );
            return 1;
        }
    };

    let slots = match token.read_all_slots() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy box tpl create: read slots: {e}");
            return 1;
        }
    };

    // Slot 0x9D = Key Management (ECDH)
    let slot = match slots.iter().find(|s| s.id() == 0x9D) {
        Some(s) => s,
        None => {
            eprintln!("piggy box tpl create: slot 9D not found on device");
            return 1;
        }
    };

    let curve = match slot.algorithm() {
        piggy_piv::PivAlgorithm::EcP256 => piggy_box::piv_box::EcCurve::NistP256,
        piggy_piv::PivAlgorithm::EcP384 => piggy_box::piv_box::EcCurve::NistP384,
        other => {
            eprintln!(
                "piggy box tpl create: unsupported key algorithm: {:?}",
                other
            );
            return 1;
        }
    };

    let ec_pubkey_bytes = match extract_ec_compressed_point(slot.public_key(), curve) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("piggy box tpl create: {e}");
            return 1;
        }
    };

    let tpl = piggy_box::EboxTemplate {
        version: 1,
        configs: vec![piggy_box::EboxTplConfig {
            config_type: piggy_box::EboxConfigType::Primary,
            n: 1,
            parts: vec![piggy_box::EboxTplPart {
                guid: Some(guid.clone()),
                slot: piggy_box::template::DEFAULT_SLOT,
                name: None,
                pubkey: ec_pubkey_bytes,
                pubkey_curve: curve,
                cak: None,
            }],
        }],
    };

    // Serialize in pivy-box's on-disk format: base64-wrapped at 65 chars/line.
    // See vendor/pivy/src/pivy-box.c `printwrap(sshbuf_dtob64_string(...))`.
    let tpl_text = match tpl.to_b64_wrapped() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy box tpl create: serialize: {e}");
            return 1;
        }
    };

    // Write to the standard pivy template location
    let tpl_dir = tpl_dir();
    if let Err(e) = std::fs::create_dir_all(&tpl_dir) {
        eprintln!("piggy box tpl create: mkdir {}: {e}", tpl_dir.display());
        return 1;
    }

    let tpl_file = tpl_dir.join(tpl_name);
    if let Err(e) = std::fs::write(&tpl_file, tpl_text.as_bytes()) {
        eprintln!("piggy box tpl create: write {}: {e}", tpl_file.display());
        return 1;
    }

    0
}

/// `piggy box tpl show [tpl-path]`
///
/// Reads a template file (from path or stdin) and prints a human-readable
/// summary to stdout.
fn cmd_tpl_show(args: &[&str]) -> i32 {
    let tpl_bytes = match args.first() {
        Some(path) => match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("piggy box tpl show: cannot read {path}: {e}");
                return 1;
            }
        },
        None => {
            let mut buf = Vec::new();
            if let Err(e) = io::stdin().read_to_end(&mut buf) {
                eprintln!("piggy box tpl show: stdin: {e}");
                return 1;
            }
            buf
        }
    };

    let tpl = match piggy_box::EboxTemplate::from_b64_bytes(&tpl_bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("piggy box tpl show: invalid template: {e}");
            return 1;
        }
    };

    println!("-- template --");
    println!("version: {}", tpl.version);
    for (i, config) in tpl.configs.iter().enumerate() {
        println!(
            "configuration {i}: {:?}, n={}, parts={}",
            config.config_type,
            config.n,
            config.parts.len()
        );
        for (j, part) in config.parts.iter().enumerate() {
            let guid_str = part
                .guid
                .as_ref()
                .map(|g| g.to_hex())
                .unwrap_or_else(|| "(none — piggy 2.x guid-less)".to_string());
            print!("  part {j}: guid={guid_str}");
            println!(", slot={:02x}", part.slot);
            if let Some(ref name) = part.name {
                println!("    name: {name}");
            }
            println!(
                "    pubkey: {} ({} bytes)",
                part.pubkey_curve.wire_name(),
                part.pubkey.len()
            );
        }
    }

    0
}

/// Standard pivy template directory (matches C pivy-box behavior).
fn tpl_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        dirs_path("Library/Preferences/pivy/tpl")
    } else {
        dirs_path(".pivy/tpl")
    }
}

fn dirs_path(suffix: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(suffix)
}

fn extract_ec_compressed_point(
    pubkey: &ssh_key::PublicKey,
    curve: piggy_box::piv_box::EcCurve,
) -> std::result::Result<Vec<u8>, String> {
    use openssl::ec::{EcGroup, EcPoint, PointConversionForm};

    let group = EcGroup::from_curve_name(curve.nid()).map_err(|e| format!("EC group: {e}"))?;

    let ec_bytes = match pubkey.key_data() {
        ssh_key::public::KeyData::Ecdsa(ecdsa) => ecdsa.as_ref().to_vec(),
        _ => return Err("not an EC key".to_string()),
    };

    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| format!("BN context: {e}"))?;
    let point =
        EcPoint::from_bytes(&group, &ec_bytes, &mut ctx).map_err(|e| format!("EC point: {e}"))?;
    let compressed = point
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .map_err(|e| format!("compress: {e}"))?;

    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use super::run;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// piggy#165: an unrecognized `piggy box` subcommand is a usage error
    /// (exit 2), no longer a silent fall-through to the C `pivy-box`.
    #[test]
    fn unknown_subcommands_are_usage_errors() {
        // No subcommand at all.
        assert_eq!(run(&argv(&[])), 2);
        // Unknown top-level type.
        assert_eq!(run(&argv(&["key"])), 2);
        assert_eq!(run(&argv(&["challenge", "respond"])), 2);
        // Known type, unknown op — including the dropped `tpl edit`.
        assert_eq!(run(&argv(&["tpl", "edit"])), 2);
        assert_eq!(run(&argv(&["stream", "sign"])), 2);
        // A bare known type with no op.
        assert_eq!(run(&argv(&["tpl"])), 2);
        assert_eq!(run(&argv(&["stream"])), 2);
    }

    /// A recognized subcommand reaches its handler, so it returns the
    /// handler's own code — here `1` for a missing template argument, NOT
    /// the `2` a usage error would give. This pins that `run` still
    /// dispatches rather than rejecting everything.
    #[test]
    fn recognized_subcommand_reaches_its_handler() {
        // `stream encrypt` with no template path: the handler prints
        // "template path required" and returns 1 before touching stdin.
        assert_eq!(run(&argv(&["stream", "encrypt"])), 1);
    }
}
