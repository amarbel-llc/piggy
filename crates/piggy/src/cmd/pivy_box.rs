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

    let tpl = match piggy_box::EboxTemplate::from_bytes(&tpl_bytes) {
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
    let mut seqnr: u32 = 0;
    let mut offset = 0;

    while offset < plaintext.len() {
        let end = (offset + chunk_size).min(plaintext.len());
        let chunk = &plaintext[offset..end];
        let last = end >= plaintext.len();

        match stream.encrypt_chunk(seqnr, chunk) {
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

        seqnr += 1;
        offset = end;

        if last {
            break;
        }
    }

    // Empty input: write a single empty chunk
    if plaintext.is_empty() {
        match stream.encrypt_chunk(0, b"") {
            Ok(enc) => {
                if let Err(e) = stdout.write_all(&enc) {
                    eprintln!("piggy box stream encrypt: write: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("piggy box stream encrypt: {e}");
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

    let agent_socket = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);

    if let Err(e) = unlock_ebox(&mut stream.ebox, agent_socket.as_deref()) {
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
        let string_len = u32::from_be_bytes([
            chunk_data[4],
            chunk_data[5],
            chunk_data[6],
            chunk_data[7],
        ]) as usize;
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
        eprintln!("piggy box tpl create: usage: piggy box tpl create <name> primary local-guid <guid>");
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

    let token = match tokens
        .iter()
        .find(|t| t.guid().to_hex() == guid.to_hex())
    {
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
                guid: guid.clone(),
                slot: piggy_box::template::DEFAULT_SLOT,
                name: None,
                pubkey: ec_pubkey_bytes,
                pubkey_curve: curve,
                cak: None,
            }],
        }],
    };

    let tpl_bytes = match tpl.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("piggy box tpl create: serialize: {e}");
            return 1;
        }
    };

    // Write to the standard pivy template location
    let tpl_dir = tpl_dir();
    if let Err(e) = std::fs::create_dir_all(&tpl_dir) {
        eprintln!(
            "piggy box tpl create: mkdir {}: {e}",
            tpl_dir.display()
        );
        return 1;
    }

    let tpl_file = tpl_dir.join(tpl_name);
    if let Err(e) = std::fs::write(&tpl_file, &tpl_bytes) {
        eprintln!(
            "piggy box tpl create: write {}: {e}",
            tpl_file.display()
        );
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

    let tpl = match piggy_box::EboxTemplate::from_bytes(&tpl_bytes) {
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
            print!("  part {j}: guid={}", part.guid.to_hex());
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

    let group = EcGroup::from_curve_name(curve.nid())
        .map_err(|e| format!("EC group: {e}"))?;

    let ec_bytes = match pubkey.key_data() {
        ssh_key::public::KeyData::Ecdsa(ecdsa) => {
            ecdsa.as_ref().to_vec()
        }
        _ => return Err("not an EC key".to_string()),
    };

    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| format!("BN context: {e}"))?;
    let point = EcPoint::from_bytes(&group, &ec_bytes, &mut ctx)
        .map_err(|e| format!("EC point: {e}"))?;
    let compressed = point
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .map_err(|e| format!("compress: {e}"))?;

    Ok(compressed)
}
