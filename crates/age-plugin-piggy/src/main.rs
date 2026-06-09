#![forbid(unsafe_code)]
//! `age-plugin-piggy` — an [age](https://age-encryption.org) plugin whose
//! identities are piggy PIV keys (NIST P-256, slot 9D).
//!
//! Secrets are plain age files. Encryption is pure software (ECDH against
//! the recipient's public key, no card). Decryption performs the P-256
//! scalar-multiplication on the card **through piggy-agent** (the
//! `ecdh@joyent.com` extension, forwardable over SSH) — the private key
//! never leaves the card and never materializes on disk.
//!
//! The stanza wire format is age-plugin-yubikey's proven `piv-p256` scheme
//! (P-256 ECDH → HKDF-SHA256 → ChaCha20-Poly1305); the only piggy-specific
//! piece is *where the ECDH happens* (a forwarded agent rather than a local
//! PCSC handle). See `crates/age-plugin-piggy/src/p256_stanza.rs`.

use std::io;

use age_plugin::run_state_machine;

mod bech32id;
mod convert;
mod generate;
mod identity;
mod p256_stanza;
mod plugin;
mod recipient;

/// Plugin name. Drives the recipient HRP `age1piggy` and the identity HRP
/// `AGE-PLUGIN-PIGGY-`, and is the `plugin_name` age hands to
/// `add_recipient` / `add_identity`.
pub(crate) const PLUGIN_NAME: &str = "piggy";

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // age invokes us as `age-plugin-piggy --age-plugin=recipient-v1` (or
    // `identity-v1`). That always wins.
    if let Some(state_machine) = args.iter().find_map(|a| a.strip_prefix("--age-plugin=")) {
        return run_state_machine(state_machine, plugin::Handler);
    }

    // Otherwise this is the (human) admin surface.
    match args.first().map(String::as_str) {
        Some("generate") => generate::run(parse_guid(&args[1..])),
        Some("convert") => convert::run(args.get(1).map(String::as_str)),
        Some("--version" | "-V") => {
            println!("age-plugin-piggy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            print_usage();
            Ok(())
        }
    }
}

/// Pull `--guid <GUID>` or `--guid=<GUID>` out of the trailing args.
fn parse_guid(args: &[String]) -> Option<&str> {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if let Some(value) = arg.strip_prefix("--guid=") {
            return Some(value);
        }
        if arg == "--guid" {
            return it.next().map(String::as_str);
        }
    }
    None
}

fn print_usage() {
    eprintln!("age-plugin-piggy: an age plugin backed by piggy PIV/agent ECDH.");
    eprintln!();
    eprintln!("Normally invoked by age via --age-plugin=recipient-v1|identity-v1.");
    eprintln!();
    eprintln!("Admin commands:");
    eprintln!("  generate [--guid <GUID>]          read a card's slot-9D key and print its");
    eprintln!(
        "                                    age1piggy recipient + AGE-PLUGIN-PIGGY identity"
    );
    eprintln!(
        "  convert <markl-id | hex-pubkey>   same, but offline from an existing piggy recipient"
    );
    eprintln!("  --version                         print the version");
}
