//! `piggy tool` — the Rust re-implementation of `pivy-tool` (piggy#289
//! Phase 3). Milestone 3.1a covers the read-only, no-PIN slot readers:
//!
//! - `piggy tool pubkey <slot>` — the slot's public key in OpenSSH format
//!   (matches C `pivy-tool`'s `sshkey_write`).
//! - `piggy tool cert <slot>` — the slot's X.509 certificate as PEM
//!   (matches C `PEM_write_X509`).
//! - `piggy tool attest <slot>` — the slot's YubiKey attestation cert
//!   followed by the device attestation cert, both PEM (matches C's two
//!   `PEM_write_X509` calls). On a card whose slot key was imported (so
//!   attestation is unavailable — every fibby key, and a real YubiKey's
//!   imported keys) this fails exactly as C does; the two-PEM happy path
//!   is exercised only by the hardware lane.
//! - `piggy tool sign <slot>` — hash stdin (SHA-256 for P-256, SHA-384
//!   for P-384) and ECDSA-sign the digest, writing the card's raw
//!   signature bytes (DER) to stdout (matches C `piv_sign` + `fwrite`).
//! - `piggy tool ecdh <slot>` — read an OpenSSH public key from stdin and
//!   write the raw ECDH shared secret to stdout (matches C `piv_ecdh` +
//!   `fwrite`). Both are PIN-gated; the PIN comes from `-P` or the same
//!   `SSH_ASKPASS` prompt C uses.
//! - `piggy tool change-pin` / `change-puk` — rotate the PIV PIN / PUK
//!   (CHANGE REFERENCE DATA, matches C `piv_change_pin`). The current and
//!   new values come from two repeated `-P` options, as C consumes them;
//!   piggy prompts via `SSH_ASKPASS` when either is absent.
//! - `piggy tool reset-pin` — unblock a PIN whose retry counter hit zero,
//!   installing a new PIN under PUK authority (RESET RETRY COUNTER, INS
//!   0x2C, matches C `piv_reset_pin`). The two repeated `-P` options are
//!   the PUK then the new PIN, as C consumes them; piggy prompts via
//!   `SSH_ASKPASS` when either is absent.
//!
//! Like `cmd::pivy_box`, this is a SUPERSET-by-fallback while the port is
//! incomplete: [`run`] returns `Some(exit_code)` for the ops it handles
//! and `None` for everything else, so `main.rs` execs the C `pivy-tool`
//! for the rest (`list`, `pinfo`, `version`, the admin/key surface). It
//! also returns `None` the moment it sees an option it does
//! not model, so a flag piggy would silently ignore is handled by C
//! instead — the superset stays honest. `piggy pivy tool` always reaches
//! C regardless.

use std::io::{Read, Write};

use piggy_piv::{PivAlgorithm, PivContext, PivToken};

/// One parsed `piggy tool` invocation: the general options piggy models,
/// the operation, and its positional arguments.
struct Invocation {
    /// `-g <hex>`: GUID (or prefix) selecting a token among several.
    guid: Option<String>,
    /// Repeated `-P <code>` values, in order. pivy-tool consumes the first
    /// as the current PIN/PUK and the second as the new one (change-pin,
    /// change-puk); the single-secret ops (sign, ecdh) use only the first.
    pins: Vec<String>,
    op: String,
    positionals: Vec<String>,
}

/// Parse `piggy tool <args>` into an [`Invocation`], or `None` if the op
/// is unrecognized OR an unmodeled option is present — in both cases the
/// caller falls back to C `pivy-tool`.
fn parse(args: &[String]) -> Option<Invocation> {
    let mut guid = None;
    let mut pins = Vec::new();
    let mut i = 0;
    // Leading options (pivy-tool style: options precede the operation).
    while i < args.len() {
        let a = &args[i];
        if !a.starts_with('-') {
            break;
        }
        match a.as_str() {
            "-g" => {
                guid = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            "-P" => {
                pins.push(args.get(i + 1)?.clone());
                i += 2;
            }
            // Any other flag is not modeled here — let C handle the whole
            // invocation so behavior is never silently dropped.
            _ => return None,
        }
    }
    let op = args.get(i)?.clone();
    // Only claim the ops this milestone implements; everything else falls
    // through to C.
    if !matches!(
        op.as_str(),
        "pubkey" | "cert" | "attest" | "sign" | "ecdh" | "change-pin" | "change-puk" | "reset-pin"
    ) {
        return None;
    }
    Some(Invocation {
        guid,
        pins,
        op,
        positionals: args[i + 1..].to_vec(),
    })
}

/// Dispatch `piggy tool <args>`. `Some(code)` for a handled op; `None` to
/// fall back to C `pivy-tool`.
pub fn run(args: &[String]) -> Option<i32> {
    let inv = parse(args)?;
    Some(match inv.op.as_str() {
        "pubkey" => cmd_pubkey(&inv),
        "cert" => cmd_cert(&inv),
        "attest" => cmd_attest(&inv),
        "sign" => cmd_sign(&inv),
        "ecdh" => cmd_ecdh(&inv),
        "change-pin" => cmd_change_secret(&inv, Secret::Pin),
        "change-puk" => cmd_change_secret(&inv, Secret::Puk),
        "reset-pin" => cmd_reset_pin(&inv),
        // parse() only returns these ops.
        _ => unreachable!(),
    })
}

/// `piggy tool pubkey <slot>`: print the slot's public key in OpenSSH
/// wire form (`<type> <base64>`), matching C `pivy-tool`'s `sshkey_write`.
fn cmd_pubkey(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "pubkey") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool pubkey: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool pubkey: slot {slot_id:02x}: {e}");
            return 1;
        }
    };
    // Match C `pivy-tool` exactly: after the OpenSSH `<type> <base64>` it
    // appends ` PIV_slot_<SLOT>@<GUID> "<cert-subject>"` as the key
    // comment (pivy-tool.c:1762). Setting that as the ssh comment yields
    // the same single-space-joined line.
    let subject = subject_oneline(slot.cert_der());
    let comment = format!(
        "PIV_slot_{slot_id:02X}@{} \"{subject}\"",
        token.guid().to_hex()
    );
    let mut pubkey = slot.public_key().clone();
    pubkey.set_comment(comment);
    match pubkey.to_openssh() {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(e) => {
            eprintln!("piggy tool pubkey: render OpenSSH: {e}");
            1
        }
    }
}

/// The certificate's subject DN as OpenSSL's `X509_NAME_oneline` renders
/// it (`/CN=foo`), which is what pivy's `piv_slot_subject` returns and
/// bakes into the pubkey comment. Best-effort: an unreadable cert yields
/// an empty string (the C side would have failed to read the slot at all).
fn subject_oneline(cert_der: &[u8]) -> String {
    let Ok(x509) = openssl::x509::X509::from_der(cert_der) else {
        return String::new();
    };
    let mut out = String::new();
    for entry in x509.subject_name().entries() {
        let key = entry
            .object()
            .nid()
            .short_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| entry.object().to_string());
        let val = entry
            .data()
            .as_utf8()
            .map(|s| s.to_string())
            .unwrap_or_default();
        out.push('/');
        out.push_str(&key);
        out.push('=');
        out.push_str(&val);
    }
    out
}

/// `piggy tool cert <slot>`: print the slot's X.509 certificate as PEM,
/// matching C `pivy-tool`'s `PEM_write_X509`.
fn cmd_cert(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "cert") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool cert: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool cert: slot {slot_id:02x}: {e}");
            return 1;
        }
    };
    match print_cert_pem(slot.cert_der()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy tool cert: {e}");
            1
        }
    }
}

/// `piggy tool attest <slot>`: print the slot's YubiKey attestation cert
/// and then the device attestation cert, both PEM — matching C's two
/// `PEM_write_X509` calls (pivy-tool.c:1699,1719). Attestation is
/// unavailable for an imported key (INS_ATTEST returns 6A80), so on fibby
/// and on a real YubiKey's imported keys this fails just as C does; the
/// happy path is validated by the hardware lane.
fn cmd_attest(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "attest") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool attest: {msg}");
            return 1;
        }
    };
    // 1. The per-slot attestation cert (INS_ATTEST / 0xF9 signing key).
    let att = match token.yk_attest(slot_id) {
        Ok(der) => der,
        Err(e) => {
            eprintln!("piggy tool attest: attestation failed: {e}");
            return 1;
        }
    };
    if let Err(e) = print_cert_pem(&att) {
        eprintln!("piggy tool attest: slot attestation cert: {e}");
        return 1;
    }
    // 2. The device attestation cert (the F9 slot's own cert object).
    let dev = match token.read_slot(0xF9) {
        Ok(slot) => slot.cert_der().to_vec(),
        Err(e) => {
            eprintln!("piggy tool attest: read device attestation cert: {e}");
            return 1;
        }
    };
    if let Err(e) = print_cert_pem(&dev) {
        eprintln!("piggy tool attest: device attestation cert: {e}");
        return 1;
    }
    0
}

/// Re-encode a DER X.509 certificate as PEM and write it to stdout,
/// matching OpenSSL's `PEM_write_X509` (the PEM already ends in a
/// newline). Shared by `cert` and `attest`.
fn print_cert_pem(cert_der: &[u8]) -> Result<(), String> {
    let pem = openssl::x509::X509::from_der(cert_der)
        .and_then(|x509| x509.to_pem())
        .map_err(|e| format!("encode PEM: {e}"))?;
    print!("{}", String::from_utf8_lossy(&pem));
    Ok(())
}

/// `piggy tool sign <slot>`: hash stdin with the key's matching digest
/// (SHA-256 for P-256, SHA-384 for P-384) and ECDSA-sign it, writing the
/// card's raw signature bytes to stdout — matching C `pivy-tool`'s
/// `piv_sign` (which auto-selects the hash) + `fwrite`. PIN-gated.
fn cmd_sign(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "sign") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool sign: {msg}");
            return 1;
        }
    };
    let algorithm = match token.read_slot(slot_id) {
        Ok(s) => s.algorithm(),
        Err(e) => {
            eprintln!(
                "piggy tool sign: failed to read cert for signing key in slot {slot_id:02X}: {e}"
            );
            return 1;
        }
    };
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("piggy tool sign: stdin: {e}");
        return 1;
    }
    let digest: Vec<u8> = match algorithm {
        PivAlgorithm::EcP256 => openssl::sha::sha256(&input).to_vec(),
        PivAlgorithm::EcP384 => openssl::sha::sha384(&input).to_vec(),
        other => {
            eprintln!(
                "piggy tool sign: slot {slot_id:02X} key algorithm {other:?} is not supported for signing"
            );
            return 1;
        }
    };
    let pin = match get_pin(inv, "sign") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool sign: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool sign: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool sign: PIN verification failed: {e}");
        return 1;
    }
    let sig = match session.sign_prehash(slot_id, &digest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool sign: failed to sign data: {e}");
            return 1;
        }
    };
    if let Err(e) = std::io::stdout().write_all(&sig) {
        eprintln!("piggy tool sign: write: {e}");
        return 1;
    }
    0
}

/// `piggy tool ecdh <slot>`: read an OpenSSH public key from stdin and
/// write the raw ECDH shared secret (the card's GENERAL AUTHENTICATE
/// output) to stdout — matching C `pivy-tool`'s `piv_ecdh` + `fwrite`.
/// PIN-gated; only the EC key slots 9A/9C/9D/9E can do ECDH.
fn cmd_ecdh(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "ecdh") {
        Ok(s) => s,
        Err(code) => return code,
    };
    if !matches!(slot_id, 0x9A | 0x9C | 0x9D | 0x9E) {
        eprintln!("piggy tool ecdh: PIV slot {slot_id:02X} cannot be used for ECDH");
        return 1;
    }
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool ecdh: {msg}");
            return 1;
        }
    };
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("piggy tool ecdh: stdin: {e}");
        return 1;
    }
    let peer_point = match parse_openssh_ec_point(&input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool ecdh: {e}");
            return 1;
        }
    };
    let pin = match get_pin(inv, "ecdh") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool ecdh: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool ecdh: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool ecdh: PIN verification failed: {e}");
        return 1;
    }
    let secret = match session.ecdh_derive(slot_id, &peer_point) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool ecdh: failed to compute ECDH: {e}");
            return 1;
        }
    };
    if let Err(e) = std::io::stdout().write_all(&secret) {
        eprintln!("piggy tool ecdh: write: {e}");
        return 1;
    }
    0
}

/// Parse an OpenSSH public-key line into its uncompressed SEC1 EC point,
/// the peer input `ecdh` feeds to the card (matches C's `sshkey_read` +
/// `piv_ecdh`).
fn parse_openssh_ec_point(input: &str) -> Result<Vec<u8>, String> {
    let pk = ssh_key::PublicKey::from_openssh(input.trim())
        .map_err(|e| format!("failed to parse public key input: {e}"))?;
    match pk.key_data() {
        ssh_key::public::KeyData::Ecdsa(ec) => Ok(ec.as_sec1_bytes().to_vec()),
        _ => Err("public key input is not an EC key".into()),
    }
}

/// The PIV PIN for a PIN-gated op: from `-P` if given, otherwise the same
/// `SSH_ASKPASS` prompt C `pivy-tool` uses (via `card_oracle::run_askpass`),
/// tagged with a `piggy-tool:<op>` context.
fn get_pin(inv: &Invocation, op: &str) -> Result<zeroize::Zeroizing<String>, String> {
    if let Some(p) = inv.pins.first() {
        return Ok(zeroize::Zeroizing::new(p.clone()));
    }
    crate::card_oracle::run_askpass(
        &format!("Enter PIV PIN for {op}: "),
        Some(&format!("piggy-tool:{op}")),
    )
    .map_err(|e| format!("PIN prompt failed: {e}"))
}

/// Which credential `change-pin`/`change-puk` rotates.
#[derive(Clone, Copy)]
enum Secret {
    Pin,
    Puk,
}

impl Secret {
    fn label(self) -> &'static str {
        match self {
            Secret::Pin => "PIN",
            Secret::Puk => "PUK",
        }
    }
    fn op(self) -> &'static str {
        match self {
            Secret::Pin => "change-pin",
            Secret::Puk => "change-puk",
        }
    }
}

/// Prompt for one credential value with `SSH_ASKPASS`, tagged so an
/// escaped prompt is identifiable.
fn prompt_secret(op: &str, which: &str, label: &str) -> Result<zeroize::Zeroizing<String>, String> {
    crate::card_oracle::run_askpass(
        &format!("Enter {which} {label}: "),
        Some(&format!("piggy-tool:{op}:{which}")),
    )
    .map_err(|e| format!("{which} {label} prompt failed: {e}"))
}

/// `piggy tool change-pin` / `change-puk`: rotate the PIV PIN or PUK
/// (CHANGE REFERENCE DATA, INS 0x24) — matching C `pivy-tool`'s
/// `piv_change_pin`. The current and new values come from two repeated
/// `-P` options (exactly as C consumes them); when either is absent piggy
/// prompts via `SSH_ASKPASS` (C requires a tty for that path). No stdout
/// on success, matching C.
fn cmd_change_secret(inv: &Invocation, secret: Secret) -> i32 {
    let label = secret.label();
    let op = secret.op();
    let old = match inv.pins.first() {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "current", label) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let new = match inv.pins.get(1) {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "new", label) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    let result = match secret {
        Secret::Pin => session.change_pin(&old, &new),
        Secret::Puk => session.change_puk(&old, &new),
    };
    match result {
        Ok(()) => 0,
        Err(piggy_piv::PivError::PinIncorrect { retries }) => {
            eprintln!(
                "piggy tool {op}: current {label} was incorrect ({retries} attempt(s) remaining); {label} change failed"
            );
            1
        }
        Err(e) => {
            eprintln!("piggy tool {op}: failed to set new {label}: {e}");
            1
        }
    }
}

/// `piggy tool reset-pin`: unblock the PIV PIN using the PUK and install a
/// new PIN (RESET RETRY COUNTER, INS 0x2C) — matching C `pivy-tool`'s
/// `piv_reset_pin`. The two repeated `-P` options are the PUK then the new
/// PIN (exactly as C consumes them); when either is absent piggy prompts
/// via `SSH_ASKPASS` (C requires a tty for that path). No stdout on
/// success, matching C.
fn cmd_reset_pin(inv: &Invocation) -> i32 {
    let op = "reset-pin";
    let puk = match inv.pins.first() {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "current", "PUK") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let new_pin = match inv.pins.get(1) {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "new", "PIN") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    match session.reset_pin(&puk, &new_pin) {
        Ok(()) => 0,
        Err(piggy_piv::PivError::PinIncorrect { retries }) => {
            eprintln!(
                "piggy tool {op}: PUK was incorrect ({retries} attempt(s) remaining); PIN reset failed"
            );
            1
        }
        Err(e) => {
            eprintln!("piggy tool {op}: failed to reset PIN: {e}");
            1
        }
    }
}

/// The slot positional (`9a`, `9d`, `9e`, `9c`, `82`..`95`, `f9`),
/// parsed as a hex byte and validated as a PIV slot that can hold a cert.
fn slot_arg(inv: &Invocation, op: &str) -> Result<u8, i32> {
    let Some(raw) = inv.positionals.first() else {
        eprintln!("piggy tool {op}: missing slot (e.g. 9d)");
        return Err(2);
    };
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    let slot_id = u8::from_str_radix(hex, 16).map_err(|_| {
        eprintln!("piggy tool {op}: invalid slot {raw:?} (want a hex slot id like 9d)");
        2
    })?;
    if !piggy_piv::slot::is_valid_piv_slot(slot_id) {
        eprintln!("piggy tool {op}: {raw:?} is not a PIV slot that holds a certificate");
        return Err(2);
    }
    Ok(slot_id)
}

/// Select the PIV token to operate on. With `-g`, the token whose GUID
/// starts with that hex prefix (case-insensitive); without it, the sole
/// present token, mirroring `pivy-tool`'s "required if more than one
/// token is present" rule.
fn select_token(guid_prefix: Option<&str>) -> Result<PivToken, String> {
    let ctx = PivContext::new().map_err(|e| format!("PC/SC: {e}"))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| format!("enumerate tokens: {e}"))?;
    if tokens.is_empty() {
        return Err("no PIV tokens present".into());
    }
    match guid_prefix {
        Some(prefix) => {
            // Validate the prefix is hex so a typo is a clear error, not a
            // silent no-match (Guid::to_hex is uppercase).
            let prefix = prefix.to_ascii_uppercase();
            if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("-g {prefix:?}: not a hex GUID prefix"));
            }
            let mut matches: Vec<PivToken> = tokens
                .into_iter()
                .filter(|t| t.guid().to_hex().starts_with(&prefix))
                .collect();
            match matches.len() {
                0 => Err(format!("no PIV token matches GUID prefix {prefix}")),
                1 => Ok(matches.remove(0)),
                n => Err(format!("{n} PIV tokens match GUID prefix {prefix}")),
            }
        }
        None => {
            let mut tokens = tokens;
            if tokens.len() > 1 {
                return Err("more than one PIV token present; select one with -g <guid>".into());
            }
            Ok(tokens.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_claims_only_the_ported_ops() {
        assert!(parse(&argv(&["pubkey", "9d"])).is_some());
        assert!(parse(&argv(&["cert", "9a"])).is_some());
        assert!(parse(&argv(&["attest", "9d"])).is_some());
        assert!(parse(&argv(&["sign", "9c"])).is_some());
        assert!(parse(&argv(&["ecdh", "9d"])).is_some());
        assert!(parse(&argv(&["change-pin"])).is_some());
        assert!(parse(&argv(&["change-puk"])).is_some());
        assert!(parse(&argv(&["reset-pin"])).is_some());
        assert!(parse(&argv(&["-P", "12345678", "-P", "654321", "reset-pin"])).is_some());
        assert!(parse(&argv(&["-g", "ABCD", "pubkey", "9d"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "sign", "9a"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "-P", "654321", "change-pin"])).is_some());
        // Unported ops fall through to C.
        assert!(parse(&argv(&["list"])).is_none());
        assert!(parse(&argv(&["pinfo"])).is_none());
        assert!(parse(&argv(&["init"])).is_none());
        // An option we don't model → C handles the whole invocation.
        assert!(parse(&argv(&["-d", "pubkey", "9d"])).is_none());
        // No op at all.
        assert!(parse(&argv(&[])).is_none());
        // `-g` with no value.
        assert!(parse(&argv(&["-g"])).is_none());
    }

    #[test]
    fn parse_extracts_guid_pin_and_positionals() {
        let inv = parse(&argv(&["-g", "deadbeef", "-P", "123456", "sign", "9c"])).unwrap();
        assert_eq!(inv.guid.as_deref(), Some("deadbeef"));
        assert_eq!(inv.pins, vec!["123456".to_string()]);
        assert_eq!(inv.op, "sign");
        assert_eq!(inv.positionals, vec!["9c".to_string()]);
    }

    #[test]
    fn parse_collects_repeated_pins_for_change() {
        // pivy-tool consumes the first -P as the current secret, the
        // second as the new one.
        let inv = parse(&argv(&["-P", "123456", "-P", "654321", "change-pin"])).unwrap();
        assert_eq!(inv.pins, vec!["123456".to_string(), "654321".to_string()]);
        assert_eq!(inv.op, "change-pin");
    }
}
