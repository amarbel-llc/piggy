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

use clap::{Parser, ValueEnum};
use piggy_piv::{PivAlgorithm, PivContext, PivError, PivToken};
use sha2::{Digest, Sha256, Sha384};
use zeroize::Zeroizing;

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
    /// PIN to authenticate with. When omitted, piggy prompts via
    /// `SSH_ASKPASS`/tty (see card_oracle).
    #[arg(short = 'P', long = "pin")]
    pin: Option<String>,
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
    // asked for — sourced from the already-selected card and its slot cert.
    let guid_short = token.guid().short_id();
    let serial = token.yk_serial();
    let cn = slot_cn(slot_meta.cert_der());
    let prompt = pin_prompt(&args.slot, &guid_short, serial, cn.as_deref());
    let context = pin_context(&args.slot, &guid_short, serial, cn.as_deref());
    let der = sign_with_card(
        &mut token,
        slot_id,
        &digest,
        args.pin.as_deref(),
        &prompt,
        &context,
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

/// Build the PIN prompt for a sign on `slot`, NAMING the target card so an
/// operator holding more than one card can't enter the wrong PIN and block one
/// (piggy#195). Carries all three identifiers the operator asked for — short
/// GUID, serial (the handle that matches `piggy list` + the physical card),
/// and the slot cert's CN — omitting serial/CN gracefully when unavailable,
/// e.g. `Enter PIN — card 2835305C… · serial 15909078 · piv-auth@2835305C
/// (slot 9a) [piggy sign-bytes]: `. This card-identity context is exactly what
/// a structured / JSON-RPC front-end (piggy#194's `ProvisionFrontend` seam +
/// the #197 management-API epic) carries in its PIN request, so an alternate
/// TUI can render it itself rather than show a bare "Enter PIN".
fn pin_prompt(slot: &str, guid_short: &str, serial: Option<u32>, cn: Option<&str>) -> String {
    let mut id = format!("card {guid_short}…");
    if let Some(s) = serial {
        id.push_str(&format!(" · serial {s}"));
    }
    if let Some(c) = cn {
        id.push_str(&format!(" · {c}"));
    }
    format!("Enter PIN — {id} (slot {slot}) [piggy sign-bytes]: ")
}

/// The `PIGGY_ASKPASS_CONTEXT` string the user-facing askpass renders as a
/// `Context:` line — same card identity as the prompt, machine-ish form.
fn pin_context(slot: &str, guid_short: &str, serial: Option<u32>, cn: Option<&str>) -> String {
    let mut id = format!("guid {guid_short}");
    if let Some(s) = serial {
        id.push_str(&format!(" serial {s}"));
    }
    if let Some(c) = cn {
        id.push_str(&format!(" cn {c}"));
    }
    format!("piggy sign-bytes: card {id} slot {slot}")
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
    prompt: &str,
    context: &str,
) -> Result<Vec<u8>, String> {
    let mut attempt = 0u32;
    loop {
        let pin: Zeroizing<String> = match fixed_pin {
            Some(p) => Zeroizing::new(p.to_string()),
            None => piggy::card_oracle::run_askpass(prompt, Some(context))
                .map_err(|e| format!("PIN entry: {e}"))?,
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

    #[test]
    fn pin_prompt_names_guid_serial_cn_and_slot() {
        // All three identifiers the operator asked for (piggy#195).
        let p = pin_prompt("9a", "2835305C", Some(15909078), Some("piv-auth@2835305C"));
        assert!(p.contains("2835305C"), "prompt names the guid: {p}");
        assert!(
            p.contains("serial 15909078"),
            "prompt names the serial: {p}"
        );
        assert!(p.contains("piv-auth@2835305C"), "prompt names the CN: {p}");
        assert!(p.contains("9a"), "prompt names the slot: {p}");
    }

    #[test]
    fn pin_prompt_omits_absent_serial_and_cn() {
        let p = pin_prompt("9c", "AABBCCDD", None, None);
        assert!(p.contains("AABBCCDD"), "prompt names the guid: {p}");
        assert!(p.contains("9c"));
        assert!(
            !p.contains("serial"),
            "no serial clause when serial absent: {p}"
        );
        assert!(
            !p.contains(" · "),
            "no dangling separators when serial/CN absent: {p}"
        );
    }

    #[test]
    fn pin_context_carries_guid_serial_and_cn() {
        let c = pin_context("9a", "DEADBEEF", Some(42), Some("piv-auth@DEADBEEF"));
        assert!(c.contains("serial 42"));
        assert!(c.contains("DEADBEEF"));
        assert!(c.contains("cn piv-auth@DEADBEEF"));
        assert!(c.contains("9a"));
    }

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
    }

    #[test]
    fn cli_format_defaults_to_raw() {
        let a = SignBytesCli::try_parse_from(["piggy sign-bytes", "--slot", "9a"]).unwrap();
        assert!(matches!(a.format, OutFormat::Raw));
    }
}
