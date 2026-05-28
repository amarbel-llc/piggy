//! `piggy box` subcommand — PIV-based encryption/decryption.
//!
//! Replaces the C `pivy-box` binary. Implements the same subcommand
//! surface used by `piggy.sh`:
//!
//! - `piggy box stream encrypt <tpl-path>`
//! - `piggy box stream decrypt [file]`
//! - `piggy box tpl create <name> primary local-guid <guid>`
//! - `piggy box tpl show [tpl-path]`

use std::io::{self, Read, Write};
use std::path::PathBuf;

use piggy_box::stream::EboxStream;
use piggy_box::unlock::unlock_ebox;

/// Entry point for `piggy box ...`.
///
/// `full_argv` is the full argv including `args[0]` (program name) and
/// `args[1]` (`"box"`). We dispatch on `args[2]` (type) and `args[3]`
/// (operation) to match pivy-box's two-level subcommand structure.
pub fn run(full_argv: Vec<String>) -> i32 {
    let rest: Vec<&str> = full_argv.iter().skip(2).map(String::as_str).collect();

    let (type_name, op_rest) = match rest.split_first() {
        Some((t, r)) => (*t, r),
        None => {
            eprintln!("piggy box: type and operation required");
            eprintln!("Usage: piggy box <type> <operation> [args...]");
            eprintln!("Types: stream, tpl");
            return 1;
        }
    };

    match type_name {
        "stream" => dispatch_stream(op_rest),
        "tpl" => dispatch_tpl(op_rest),
        _ => {
            eprintln!("piggy box: unknown type: {type_name}");
            eprintln!("Types: stream, tpl");
            1
        }
    }
}

fn dispatch_stream(args: &[&str]) -> i32 {
    let (op, rest) = match args.split_first() {
        Some((o, r)) => (*o, r),
        None => {
            eprintln!("piggy box stream: operation required");
            eprintln!("Operations: encrypt, decrypt");
            return 1;
        }
    };

    match op {
        "encrypt" => cmd_stream_encrypt(rest),
        "decrypt" => cmd_stream_decrypt(rest),
        _ => {
            eprintln!("piggy box stream: unknown operation: {op}");
            1
        }
    }
}

fn dispatch_tpl(args: &[&str]) -> i32 {
    let (op, rest) = match args.split_first() {
        Some((o, r)) => (*o, r),
        None => {
            eprintln!("piggy box tpl: operation required");
            eprintln!("Operations: create, show");
            return 1;
        }
    };

    match op {
        "create" => cmd_tpl_create(rest),
        "show" => cmd_tpl_show(rest),
        "edit" => {
            eprintln!("piggy box tpl edit: not yet implemented");
            1
        }
        _ => {
            eprintln!("piggy box tpl: unknown operation: {op}");
            1
        }
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

    let mut stream = match EboxStream::from_bytes(&input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy box stream decrypt: invalid stream: {e}");
            return 1;
        }
    };

    // Checkpoint 3A (#32): build an AgentEcdhOracle from the agent socket
    // if set, so unlock can hit a running piggy-agent / pivy-agent.
    // Prefer PIGGY_AUTH_SOCK (piggy's own agent, which advertises
    // ecdh@joyent.com) over the ambient SSH_AUTH_SOCK (commonly an
    // ssh-agent-mux that may not) — see #123. A missing socket is not
    // fatal: we also try the direct-PCSC card path (#31) below. PIN unlock
    // for the agent path is NOT done here; the user is expected to have run
    // `ssh-add -X` externally.
    let agent_socket = crate::agent_client::piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK"))
        .map(PathBuf::from);
    let mut agent_oracle: Option<crate::agent_client::AgentEcdhOracle> = match &agent_socket {
        Some(sock) => match crate::agent_client::AgentEcdhOracle::new(sock) {
            Ok(o) => Some(o),
            Err(e) => {
                tracing::warn!(
                    "piggy box stream decrypt: failed to construct AgentEcdhOracle: {e} — \
                     proceeding without agent"
                );
                None
            }
        },
        None => None,
    };

    // Issue #31: build a CardEcdhOracle backed by PCSC + SSH_ASKPASS.
    // Construction can fail if the PCSC resource manager is unreachable
    // (no pcscd, no PCSCLITE_CSOCK_NAME); that's fine — we simply skip
    // the card path and let the agent path carry the unlock, or surface
    // UnlockFailed if neither is available.
    let mut card_oracle: Option<crate::card_oracle::CardEcdhOracle> =
        match crate::card_oracle::CardEcdhOracle::new(crate::card_oracle::askpass_pin_supplier()) {
            Ok(o) => Some(o),
            Err(e) => {
                tracing::debug!(
                    "piggy box stream decrypt: card oracle unavailable: {e} — \
                     agent path only"
                );
                None
            }
        };

    let agent_dyn: Option<&mut dyn piggy_box::oracle::EcdhOracle> = agent_oracle
        .as_mut()
        .map(|o| o as &mut dyn piggy_box::oracle::EcdhOracle);
    let card_dyn: Option<&mut dyn piggy_box::oracle::EcdhOracle> = card_oracle
        .as_mut()
        .map(|o| o as &mut dyn piggy_box::oracle::EcdhOracle);

    if let Err(e) = unlock_ebox(&mut stream.ebox, agent_dyn, card_dyn) {
        eprintln!("piggy box stream decrypt: unlock failed: {e}");
        return 1;
    }

    // The remaining bytes after the stream header are the chunks.
    // Re-serialize the header to find where chunks begin.
    let header_bytes = match stream.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("piggy box stream decrypt: {e}");
            return 1;
        }
    };
    let mut chunk_data = &input[header_bytes.len()..];

    let mut stdout = io::stdout().lock();
    let mut expected_seqnr: u32 = 0;

    while !chunk_data.is_empty() {
        // Each chunk frame is: u32(seqnr) + u32(len) + len bytes.
        // Peek at the string length to compute the frame size.
        if chunk_data.len() < 8 {
            eprintln!("piggy box stream decrypt: truncated chunk frame");
            return 1;
        }
        let string_len =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]])
                as usize;
        let frame_len = 4 + 4 + string_len;
        if chunk_data.len() < frame_len {
            eprintln!("piggy box stream decrypt: truncated chunk data");
            return 1;
        }

        let frame = &chunk_data[..frame_len];
        match stream.decrypt_chunk(Some(expected_seqnr), frame) {
            Ok((_, plain)) => {
                if let Err(e) = stdout.write_all(&plain) {
                    eprintln!("piggy box stream decrypt: write: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("piggy box stream decrypt: chunk {expected_seqnr}: {e}");
                return 1;
            }
        }

        chunk_data = &chunk_data[frame_len..];
        expected_seqnr += 1;
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
