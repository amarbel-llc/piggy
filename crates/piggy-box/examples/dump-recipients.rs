//! Diagnostic: dump the recipient pubkey(s) baked into one or more
//! `.ebox` files, rendered as `piggy-recipient-v1@pivy_ecdh_p256_pub-…`
//! markl IDs so they compare byte-for-byte against `piggy-ids` and
//! `piggy pass recipients list-available`.
//!
//! Non-destructive: parses the ebox wire format off-disk via
//! `Ebox::from_bytes`, touches no card, prompts for no PIN. Used to
//! diagnose "card present but cannot decrypt" — if none of an ebox's
//! recipients match an attached card's pubkey, the box was simply
//! encrypted to a different recipient set.
//!
//! Run via `just debug-ebox-recipients <file.ebox>…`.

use piggy_box::ebox::Ebox;
use piggy_markl::{FormatId, Id as MarklId, PurposeId};

fn render_recipient(pubkey: &[u8]) -> String {
    MarklId::new(
        Some(PurposeId::PiggyRecipientV1),
        FormatId::PivyEcdhP256Pub,
        pubkey.to_vec(),
    )
    .map(|id| id.to_string())
    .unwrap_or_else(|e| format!("<unrenderable: {e}; {} raw bytes>", pubkey.len()))
}

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: dump-recipients <file.ebox> [more.ebox …]");
        std::process::exit(2);
    }

    for path in &paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: read failed: {e}");
                continue;
            }
        };
        let ebox = match Ebox::from_bytes(&bytes) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{path}: parse failed: {e}");
                continue;
            }
        };

        println!("{path}  (ebox v{})", ebox.version);
        for (ci, config) in ebox.configs.iter().enumerate() {
            println!("  config {ci} ({:?}, n={})", config.config_type, config.n);
            for (pi, part) in config.parts.iter().enumerate() {
                let guid = part
                    .guid
                    .as_ref()
                    .map(|g| format!("{g:?}"))
                    .unwrap_or_else(|| "none (guid-less)".into());
                println!("    part {pi}: guid={guid}");
                println!(
                    "    part {pi}: recipient={}",
                    render_recipient(&part.piv_box.recipient_pubkey)
                );
            }
        }
    }
}
