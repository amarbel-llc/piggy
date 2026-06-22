//! `piggy sign-bytes` — a low-level, caller-agnostic PIV card byte-signer.
//!
//! Reads a message from stdin, signs it with the private key in a PIV signing
//! slot (9A authentication or 9C signature), and writes the signature to
//! stdout. piggy applies NO canonicalization to the message — the caller
//! controls the exact bytes. SHA-256 (P-256) / SHA-384 (P-384) hashing is
//! intrinsic to `ecdsa-sha2-nistp256/384` and is applied here before the card
//! signs the digest (matching `pivy-tool sign`).
//!
//! This is the neutral primitive a downstream protocol (e.g. amarbel-llc/papi
//! enrollment, papi#15) builds on: piggy stays agnostic of the caller's
//! semantics — it signs bytes and returns a signature. See piggy#190.
//!
//! Output framing (`--format`, default `raw`):
//! - `raw` — fixed-width `r‖s` (P-256 → 64 bytes, P-384 → 96), the markl
//!   `…@ecdsa_p256_sig` payload a downstream consumer blech32-wraps directly.
//! - `der` — the card-native ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`
//!   (matches `pivy-tool sign`; for callers that already parse DER).
//!
//! Card / PIN: `--guid` selects among attached cards (direct-PCSC, no agent);
//! the PIN comes from `-P/--pin` or, absent that, an `SSH_ASKPASS`/tty prompt
//! via [`piggy::card_oracle::run_askpass`]. Signing on 9A/9C exercises the
//! private key and requires the card PIN per the slot's policy.

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use piggy_piv::{PivAlgorithm, PivContext, PivError, PivToken};
use sha2::{Digest, Sha256, Sha384};
use zeroize::Zeroizing;

use piggy::card::frontend::select::{FrontendKind, build_frontend};
use piggy::card::protocol::{CardId, Frontend, SecretKind, SecretRequest};

/// Bounded re-prompt on a wrong interactive PIN (a fixed `-P` PIN never
/// retries — it can't change between attempts).
const PIN_RETRY_LIMIT: u32 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "piggy sign-bytes",
    about = "Sign stdin with a PIV slot key; output the signature on stdout",
    disable_help_subcommand = true
)]
struct SignBytesCli {
    /// PIV signing slot: `9a` (authentication) or `9c` (signature).
    #[arg(long)]
    slot: String,
    /// GUID of the card to use (hex). Required when more than one card is
    /// attached; otherwise the single attached card is used.
    #[arg(long)]
    guid: Option<String>,
    /// Output framing for the signature.
    #[arg(long, value_enum, default_value_t = OutFormat::Raw)]
    format: OutFormat,
    /// PIN to authenticate with. When omitted, piggy prompts via the selected
    /// frontend (`--frontend`).
    #[arg(short = 'P', long = "pin")]
    pin: Option<String>,
    /// Interaction frontend for the PIN prompt (RFC 0006 §6): `tty` (default,
    /// askpass) or `jsonrpc` (an external program supplies the PIN over
    /// `--socket`). Ignored when `-P/--pin` is given.
    #[arg(long, value_enum, default_value_t = FrontendKind::Tty)]
    frontend: FrontendKind,
    /// `AF_UNIX` socket the JSON-RPC frontend listens on. Required (and only
    /// used) when `--frontend jsonrpc`.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutFormat {
    /// Fixed-width raw `r‖s` (P-256 → 64 bytes, P-384 → 96).
    Raw,
    /// Card-native ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
    Der,
}

/// Entry point: parse argv (clap prints help/errors and exits itself), then
/// run the signer. Returns the process exit code.
pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy sign-bytes".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match SignBytesCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    match execute(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy sign-bytes: {e}");
            1
        }
    }
}

fn execute(args: SignBytesCli) -> Result<(), String> {
    let slot_id = parse_slot(&args.slot)?;

    // Build the frontend before any card operation (RFC 0006 §6): a
    // `--frontend jsonrpc` without a usable `--socket` must fail fast, before
    // we enumerate cards. Skipped when a fixed `-P` PIN short-circuits the
    // prompt (no frontend needed, no unused socket connected).
    let mut frontend: Option<Box<dyn Frontend>> = match args.pin {
        Some(_) => None,
        None => Some(build_frontend(
            args.frontend,
            args.socket.as_deref(),
            "sign-bytes",
        )?),
    };

    let mut token = select_token(args.guid.as_deref())?;

    // Read the slot's algorithm (a PIN-free cert read) to choose the digest
    // and the raw field width.
    let slot_meta = token
        .read_slot(slot_id)
        .map_err(|e| format!("read slot {}: {e}", args.slot))?;

    let mut message = Vec::new();
    std::io::stdin()
        .read_to_end(&mut message)
        .map_err(|e| format!("read stdin: {e}"))?;

    let (digest, field_len) = match slot_meta.algorithm() {
        PivAlgorithm::EcP256 => (Sha256::digest(&message).to_vec(), 32usize),
        PivAlgorithm::EcP384 => (Sha384::digest(&message).to_vec(), 48usize),
        other => {
            return Err(format!(
                "slot {} holds a {other:?} key; sign-bytes supports only ECDSA P-256 / P-384",
                args.slot
            ));
        }
    };

    // Name the target card in the PIN prompt (piggy#195): with more than one
    // card attached, an unlabeled "Enter PIN" let an operator enter the wrong
    // PIN (e.g. a freshly-provisioned card's default vs a trusted card's real
    // PIN) and block a card. Carry GUID + serial + CN — all three the operator
    // asked for — sourced from the already-selected card and its slot cert. The
    // RFC 0006 frontend renders this structured identity (the tty binding into
    // the same prompt as before; a JSON-RPC binding ships it to its client).
    let card_id = CardId {
        guid: token.guid().to_hex(),
        serial: token.yk_serial(),
        cn: slot_cn(slot_meta.cert_der()),
    };

    let der = sign_with_card(
        &mut token,
        slot_id,
        &digest,
        args.pin.as_deref(),
        &card_id,
        &args.slot,
        frontend.take(),
    )?;

    let out = match args.format {
        OutFormat::Raw => piggy::ecdsa_sig::der_to_raw_rs(&der, field_len)
            .map_err(|e| format!("reframe signature: {e}"))?,
        OutFormat::Der => der,
    };

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&out)
        .map_err(|e| format!("write stdout: {e}"))?;
    stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    Ok(())
}

/// Extract the Subject Common Name from a slot's cert DER (e.g.
/// `piv-auth@2835305C`), for naming the card in the PIN prompt. `None` if the
/// cert doesn't parse or has no CN.
fn slot_cn(cert_der: &[u8]) -> Option<String> {
    let x509 = openssl::x509::X509::from_der(cert_der).ok()?;
    x509.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Map a user-facing slot string to its PIV slot id. Only signing-capable
/// slots are accepted; 9D (Key Management / ECDH) is rejected explicitly.
fn parse_slot(s: &str) -> Result<u8, String> {
    match s.to_ascii_lowercase().as_str() {
        "9a" => Ok(0x9A),
        "9c" => Ok(0x9C),
        "9d" => Err(
            "slot 9d is the Key Management (ECDH) slot and cannot sign; use 9a or 9c".to_string(),
        ),
        other => Err(format!(
            "unsupported slot {other:?}; sign-bytes supports 9a (auth) and 9c (signature)"
        )),
    }
}

/// Enumerate attached PIV cards and pick one: by `--guid` if given, else the
/// sole attached card (error if zero or ambiguous). Mirrors the selection in
/// `age-plugin-piggy generate` / `piggy health`.
fn select_token(guid_hint: Option<&str>) -> Result<PivToken, String> {
    let ctx = PivContext::new().map_err(|e| format!("PC/SC context: {e}"))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| format!("enumerate cards: {e}"))?;
    if tokens.is_empty() {
        return Err("no PIV card detected".to_string());
    }
    match guid_hint {
        Some(guid) => tokens
            .into_iter()
            .find(|t| t.guid().to_hex().eq_ignore_ascii_case(guid))
            .ok_or_else(|| format!("no attached card has GUID {guid}")),
        None => {
            if tokens.len() > 1 {
                let guids: Vec<String> = tokens.iter().map(|t| t.guid().to_hex()).collect();
                return Err(format!(
                    "{} cards attached; disambiguate with --guid <GUID> (attached: {})",
                    tokens.len(),
                    guids.join(", ")
                ));
            }
            Ok(tokens.into_iter().next().expect("non-empty checked above"))
        }
    }
}

/// Verify the PIN and sign `digest` in one PC/SC transaction, returning the
/// card's DER ECDSA signature. Re-prompts on a wrong interactive PIN (a fixed
/// `-P` PIN fails fast — it can't change between attempts). The PIN is
/// acquired OUTSIDE the card transaction (piggy#105) and verify+sign are
/// bracketed inside one session (piggy#56), mirroring the Rust agent.
fn sign_with_card(
    token: &mut PivToken,
    slot_id: u8,
    digest: &[u8],
    fixed_pin: Option<&str>,
    card: &CardId,
    slot_label: &str,
    mut frontend: Option<Box<dyn Frontend>>,
) -> Result<Vec<u8>, String> {
    let mut attempt = 0u32;
    // Carried into the re-prompt so the operator sees how many tries remain
    // (None on the first prompt — no "tries left" clause, preserving the
    // original first-prompt text).
    let mut attempts_remaining: Option<u32> = None;
    loop {
        let pin: Zeroizing<String> = match fixed_pin {
            Some(p) => Zeroizing::new(p.to_string()),
            None => {
                let fe = frontend
                    .as_deref_mut()
                    .expect("frontend is built when no -P/--pin is given");
                fe.request_secret(SecretRequest {
                    kind: SecretKind::CurrentPin,
                    prompt: "Enter PIN".to_string(),
                    card: Some(card.clone()),
                    slot: Some(slot_label.to_string()),
                    attempts_remaining,
                })
                .map_err(|e| format!("PIN entry: {e}"))?
            }
        };

        let mut session = token
            .begin_pin_session()
            .map_err(|e| format!("open card session: {e}"))?;

        match session.verify_pin(pin.as_str()) {
            Ok(()) => {}
            Err(PivError::PinIncorrect { retries }) => {
                if fixed_pin.is_some() || attempt >= PIN_RETRY_LIMIT {
                    return Err(format!("incorrect PIN ({retries} retries remaining)"));
                }
                attempt += 1;
                attempts_remaining = Some(retries);
                eprintln!("piggy sign-bytes: incorrect PIN, {retries} retries remaining");
                // `session` drops here, ending the transaction before we
                // re-prompt and re-open on the next iteration.
                continue;
            }
            Err(e) => return Err(format!("verify PIN: {e}")),
        }

        return session
            .sign_prehash(slot_id, digest)
            .map_err(|e| format!("card sign: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The PIN-prompt card-naming (#195) now lives in the shared TtyFrontend
    // (crates/piggy/src/card/frontend/tty.rs) and is unit-tested there; sign-bytes
    // builds a CardId and routes the PIN through the Frontend trait (#200).

    #[test]
    fn parse_slot_accepts_signing_slots_case_insensitive() {
        assert_eq!(parse_slot("9a").unwrap(), 0x9A);
        assert_eq!(parse_slot("9A").unwrap(), 0x9A);
        assert_eq!(parse_slot("9c").unwrap(), 0x9C);
        assert_eq!(parse_slot("9C").unwrap(), 0x9C);
    }

    #[test]
    fn parse_slot_rejects_9d_with_ecdh_hint() {
        let err = parse_slot("9d").unwrap_err();
        assert!(err.contains("9d"));
        assert!(err.contains("ECDH") || err.contains("cannot sign"));
    }

    #[test]
    fn parse_slot_rejects_unknown() {
        let err = parse_slot("9e").unwrap_err();
        assert!(err.contains("unsupported slot"));
    }

    #[test]
    fn cli_requires_slot() {
        // No --slot → clap parse error (would exit(2) at runtime).
        let r = SignBytesCli::try_parse_from(["piggy sign-bytes"]);
        assert!(r.is_err());
    }

    #[test]
    fn cli_parses_full_arg_set() {
        let a = SignBytesCli::try_parse_from([
            "piggy sign-bytes",
            "--slot",
            "9a",
            "--guid",
            "DEADBEEF",
            "--format",
            "der",
            "-P",
            "123456",
        ])
        .unwrap();
        assert_eq!(a.slot, "9a");
        assert_eq!(a.guid.as_deref(), Some("DEADBEEF"));
        assert!(matches!(a.format, OutFormat::Der));
        assert_eq!(a.pin.as_deref(), Some("123456"));
        // --frontend defaults to tty.
        assert!(matches!(a.frontend, FrontendKind::Tty));
    }

    #[test]
    fn cli_parses_jsonrpc_frontend_and_socket() {
        let a = SignBytesCli::try_parse_from([
            "piggy sign-bytes",
            "--slot",
            "9a",
            "--frontend",
            "jsonrpc",
            "--socket",
            "/tmp/piggy-ui.sock",
        ])
        .unwrap();
        assert!(matches!(a.frontend, FrontendKind::Jsonrpc));
        assert_eq!(
            a.socket.as_deref(),
            Some(std::path::Path::new("/tmp/piggy-ui.sock"))
        );
    }

    #[test]
    fn cli_format_defaults_to_raw() {
        let a = SignBytesCli::try_parse_from(["piggy sign-bytes", "--slot", "9a"]).unwrap();
        assert!(matches!(a.format, OutFormat::Raw));
    }
}
