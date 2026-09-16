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
//! - `piggy tool set-admin <newkey>` — rotate the PIV management (admin)
//!   key (mgmt-key mutual auth with the current key, then SET MANAGEMENT
//!   KEY; matches C `cmd_set_admin`). The current key comes from `-K`
//!   (`default` or hex; default: the factory 3DES key), the new key from
//!   the positional (`default` or hex). 3DES-only: AES admin keys,
//!   `random`, `@file`, and `-R` PINFO-save fall through to C.
//! - `piggy tool delete-cert <slot>` — clear a slot's certificate object
//!   (mgmt-key mutual auth, then PUT DATA at the slot's cert tag with an
//!   empty body; matches C `cmd_delete_cert`). The current key comes from
//!   `-K` (`default` or hex). Ported for the cert-holding slots
//!   9A/9C/9D/9E; retired and other slots fall through to C.
//! - `piggy tool update-keyhist` — rescan the retired key slots and rewrite
//!   the PIV Key History object (mgmt-key mutual auth, then PUT DATA at
//!   `5FC10C`; matches C `cmd_update_keyhist`). `oncard` is recomputed from
//!   the retired slots, `offcard`/URL preserved from the existing object.
//!   The current key comes from `-K` (`default` or hex).
//! - `piggy tool write-cert <slot>` — read an X.509 cert (DER or PEM) from
//!   stdin and write it to the slot's cert object (mgmt-key mutual auth,
//!   then PUT DATA; matches C `cmd_write_cert`). The current key comes from
//!   `-K` (`default` or hex). Ported for the cert-holding slots 9A/9C/9D/9E;
//!   retired and other slots fall through to C.
//! - `piggy tool generate <slot> -a <alg>` — generate a new key pair
//!   (GENERATE ASYMMETRIC under mgmt auth), self-sign a minimal cert for it
//!   (PIN-gated), and print the new public key (matches C `cmd_generate`).
//!   Modeled for the EC algorithms `eccp256`/`eccp384` on slots 9A/9C/9D/9E;
//!   RSA/Ed25519 and other slots fall through to C. Needs `-K` (mgmt) and a
//!   PIN (`-P` or askpass, for the self-sign).
//!
//! Like `cmd::pivy_box`, this is a SUPERSET-by-fallback while the port is
//! incomplete: [`run`] returns `Some(exit_code)` for the ops it handles
//! and `None` for everything else, so `main.rs` execs the C `pivy-tool`
//! for the rest (`list`, `pinfo`, `version`, `init`, the rest of the
//! key surface). It also returns `None` the moment it sees an option it
//! does not model, so a flag piggy would silently ignore is handled by C
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
    /// `-K <key>`: the CURRENT management (admin) key used to authenticate a
    /// write op, as `default` or a hex string. pivy-tool's general admin-key
    /// option; `set-admin` reads it as the old key to auth with.
    admin_key: Option<String>,
    /// `-a <alg>`: pivy-tool's algorithm option (e.g. `eccp256`). Required by
    /// `generate`; this port models the EC algorithms only.
    alg: Option<String>,
    op: String,
    positionals: Vec<String>,
}

/// Parse `piggy tool <args>` into an [`Invocation`], or `None` if the op
/// is unrecognized OR an unmodeled option is present — in both cases the
/// caller falls back to C `pivy-tool`.
fn parse(args: &[String]) -> Option<Invocation> {
    let mut guid = None;
    let mut pins = Vec::new();
    let mut admin_key = None;
    let mut alg = None;
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
            "-K" => {
                admin_key = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            "-a" => {
                alg = Some(args.get(i + 1)?.clone());
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
        "pubkey"
            | "cert"
            | "attest"
            | "sign"
            | "ecdh"
            | "change-pin"
            | "change-puk"
            | "reset-pin"
            | "set-admin"
            | "delete-cert"
            | "update-keyhist"
            | "write-cert"
            | "generate"
    ) {
        return None;
    }
    let positionals = args[i + 1..].to_vec();
    // The admin-key–gated write ops authenticate with `-K`; validate the
    // modeled key form so `random`/`@file` fall through to C, keeping the
    // superset honest.
    if matches!(
        op.as_str(),
        "set-admin" | "delete-cert" | "update-keyhist" | "write-cert" | "generate"
    ) {
        if let Some(k) = &admin_key {
            if !is_admin_key_arg(k) {
                return None;
            }
        }
    }
    // `generate` requires `-a <alg>` and this port models only the EC
    // algorithms (eccp256/eccp384); a missing or RSA/Ed25519 `-a` falls
    // through to C, as does an unsupported slot.
    if op == "generate" {
        let slot = positionals.first()?;
        if positionals.len() != 1
            || !is_supported_cert_slot(slot)
            || alg.as_deref().and_then(parse_ec_alg).is_none()
        {
            return None;
        }
    }
    // `update-keyhist` takes no positionals (C errors "too many arguments").
    if op == "update-keyhist" && !positionals.is_empty() {
        return None;
    }
    // `set-admin` is 3DES-only in this port: the new key positional must be
    // `default` or a hex string (not `random`, `@file`, an AES `-N`, or `-R`).
    if op == "set-admin" {
        let new_key = positionals.first()?;
        if positionals.len() != 1 || !is_admin_key_arg(new_key) {
            return None;
        }
    }
    // `delete-cert` and `write-cert` claim only the slots this port maps a
    // cert tag for (9A/9C/9D/9E); retired and other slots fall through to C.
    if matches!(op.as_str(), "delete-cert" | "write-cert") {
        let slot = positionals.first()?;
        if positionals.len() != 1 || !is_supported_cert_slot(slot) {
            return None;
        }
    }
    Some(Invocation {
        guid,
        pins,
        admin_key,
        alg,
        op,
        positionals,
    })
}

/// Map a pivy-tool `-a` algorithm name to the EC algorithms this port
/// models: `eccp256` → P-256, `eccp384` → P-384. Everything else (RSA,
/// Ed25519, X25519) returns `None` and falls through to C.
fn parse_ec_alg(s: &str) -> Option<(PivAlgorithm, u8)> {
    match s {
        "eccp256" => Some((PivAlgorithm::EcP256, piggy_piv::apdu::alg::ECCP256)),
        "eccp384" => Some((PivAlgorithm::EcP384, piggy_piv::apdu::alg::ECCP384)),
        _ => None,
    }
}

/// Whether an admin-key argument is one this port models: the literal
/// `default` (the factory 3DES key) or a plain hex string. `random`, an
/// `@file` reference, and anything else fall through to C `pivy-tool`.
fn is_admin_key_arg(s: &str) -> bool {
    s == "default"
        || (!s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Whether a slot argument names one of the key slots this port maps a cert
/// data-object tag for (9A/9C/9D/9E). Retired slots (82..95) and others fall
/// through to C `pivy-tool`, which handles the full range.
fn is_supported_cert_slot(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    matches!(u8::from_str_radix(hex, 16), Ok(0x9A | 0x9C | 0x9D | 0x9E))
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
        "set-admin" => cmd_set_admin(&inv),
        "delete-cert" => cmd_delete_cert(&inv),
        "update-keyhist" => cmd_update_keyhist(&inv),
        "write-cert" => cmd_write_cert(&inv),
        "generate" => cmd_generate(&inv),
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

/// `piggy tool set-admin <newkey>`: rotate the PIV management (admin) key —
/// matching C `pivy-tool`'s `cmd_set_admin` (mgmt-key mutual authentication
/// with the current key, then YubicoPIV SET MANAGEMENT KEY). The current key
/// comes from `-K` (`default` or hex; default: the factory 3DES key); the new
/// key is the positional (`default` or hex). 3DES-only in this port — AES
/// admin keys, `random`, `@file`, and `-R` PINFO-save fall through to C
/// (rejected in `parse`). No stdout on success, matching C.
fn cmd_set_admin(inv: &Invocation) -> i32 {
    let op = "set-admin";
    let old_key = match resolve_admin_key(inv.admin_key.as_deref().unwrap_or("default")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: current admin key: {e}");
            return 2;
        }
    };
    // parse() guaranteed exactly one positional in a modeled key form.
    let new_key = match resolve_admin_key(&inv.positionals[0]) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: new admin key: {e}");
            return 2;
        }
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
    if let Err(e) = session.authenticate_admin(&old_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.set_management_key_3des(&new_key) {
        eprintln!("piggy tool {op}: failed to set new admin key: {e}");
        return 1;
    }
    0
}

/// Resolve an admin-key argument to its 24-byte 3DES value: `default` → the
/// factory key, else a hex string decoded to bytes. Errors (like C's
/// EXIT_BAD_ARGS) when the hex is malformed or not 24 bytes.
fn resolve_admin_key(arg: &str) -> Result<Vec<u8>, String> {
    if arg == "default" {
        return Ok(piggy_piv::DEFAULT_ADMIN_KEY.to_vec());
    }
    if arg.is_empty() || !arg.len().is_multiple_of(2) || !arg.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(format!("{arg:?} is not a hex admin key"));
    }
    let bytes: Vec<u8> = (0..arg.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&arg[i..i + 2], 16).expect("validated hex"))
        .collect();
    if bytes.len() != 24 {
        return Err(format!(
            "admin key must be 24 bytes for 3DES ({} given)",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// `piggy tool delete-cert <slot>`: clear a slot's certificate object —
/// matching C `pivy-tool`'s `cmd_delete_cert` (mgmt-key mutual auth with the
/// current key, then PUT DATA at the slot's cert tag with an empty body). The
/// current key comes from `-K` (`default` or hex; default: the factory 3DES
/// key). Ported for the cert-holding slots 9A/9C/9D/9E; retired and other
/// slots fall through to C. On a YubiKey <5.7 (fibby's model) this clears only
/// the cert, not the private key, exactly as C does. No stdout on success.
fn cmd_delete_cert(inv: &Invocation) -> i32 {
    let op = "delete-cert";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let admin_key = match resolve_admin_key(inv.admin_key.as_deref().unwrap_or("default")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: current admin key: {e}");
            return 2;
        }
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
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.clear_cert(slot_id) {
        eprintln!("piggy tool {op}: failed to clear the certificate for slot {slot_id:02X}: {e}");
        return 1;
    }
    0
}

/// `piggy tool update-keyhist`: rescan the retired key slots and rewrite the
/// PIV Key History object — matching C `pivy-tool`'s `cmd_update_keyhist`.
/// The `oncard` count is recomputed from the retired slots (82..95); the
/// `offcard` count and off-card URL are preserved from the existing object;
/// then mgmt-key mutual auth (current key from `-K`, default factory 3DES)
/// gates the PUT DATA at `5FC10C`. No stdout on success, matching C.
fn cmd_update_keyhist(inv: &Invocation) -> i32 {
    let op = "update-keyhist";
    let admin_key = match resolve_admin_key(inv.admin_key.as_deref().unwrap_or("default")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: current admin key: {e}");
            return 2;
        }
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    // Recompute oncard from the retired slots; preserve offcard/url from the
    // existing Key History object (exactly what pivy's update-keyhist does).
    let oncard = token.count_oncard_retired();
    let existing = match token.read_keyhistory() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: failed to read the existing key history: {e}");
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
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.write_keyhistory(oncard, existing.offcard, existing.url.as_deref()) {
        eprintln!("piggy tool {op}: failed to write the key history object: {e}");
        return 1;
    }
    0
}

/// `piggy tool write-cert <slot>`: read an X.509 certificate (DER or PEM)
/// from stdin and write it to the slot's cert object — matching C
/// `pivy-tool`'s `cmd_write_cert` (mgmt-key mutual auth, then PUT DATA at the
/// slot's cert tag wrapping the DER as `70 <cert> 71 00`). The current key
/// comes from `-K` (`default` or hex). Ported for the cert-holding slots
/// 9A/9C/9D/9E; retired and other slots fall through to C. No stdout on
/// success, matching C.
fn cmd_write_cert(inv: &Invocation) -> i32 {
    let op = "write-cert";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let admin_key = match resolve_admin_key(inv.admin_key.as_deref().unwrap_or("default")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: current admin key: {e}");
            return 2;
        }
    };
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("piggy tool {op}: stdin: {e}");
        return 1;
    }
    let cert_der = match parse_cert_input(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
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
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.put_cert(slot_id, &cert_der) {
        eprintln!("piggy tool {op}: failed to write the certificate to slot {slot_id:02X}: {e}");
        return 1;
    }
    0
}

/// Parse an X.509 certificate from stdin bytes, accepting DER or PEM (C
/// `pivy-tool`'s `cmd_write_cert` tries DER first, then PEM). Returns the
/// canonical DER the card stores.
fn parse_cert_input(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(x509) = openssl::x509::X509::from_der(bytes) {
        return x509
            .to_der()
            .map_err(|e| format!("re-encode cert DER: {e}"));
    }
    let x509 = openssl::x509::X509::from_pem(bytes)
        .map_err(|_| "invalid certificate input (expected DER or PEM on stdin)".to_string())?;
    x509.to_der()
        .map_err(|e| format!("re-encode cert DER: {e}"))
}

/// `piggy tool generate <slot> -a <alg>`: generate a new key pair on the
/// card, self-sign a minimal cert for it, and print the new public key —
/// matching C `pivy-tool`'s `cmd_generate` (GENERATE ASYMMETRIC under mgmt
/// auth, then a PIN-gated self-signed cert). Modeled for the EC algorithms
/// (`eccp256`, `eccp384`) on the cert-holding slots 9A/9C/9D/9E; other
/// algorithms/slots fall through to C. The generated key is random on real
/// hardware (so the printed pubkey differs per run); the self-signed cert C
/// writes carries a random serial (a side effect that legitimately differs).
/// Prints `<openssh-pubkey> PIV_slot_XX@<GUID>`, matching C's format (a bare
/// slot/GUID comment — no cert subject, unlike `pubkey`).
fn cmd_generate(inv: &Invocation) -> i32 {
    let op = "generate";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // parse() validated the algorithm and slot.
    let (algorithm, alg_byte) = inv
        .alg
        .as_deref()
        .and_then(parse_ec_alg)
        .expect("parse() validated -a");
    let admin_key = match resolve_admin_key(inv.admin_key.as_deref().unwrap_or("default")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: current admin key: {e}");
            return 2;
        }
    };
    let pin = match get_pin(inv, op) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let guid = token.guid().to_hex();
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    let point = match session.generate_key(slot_id, alg_byte, None, None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: key generation failed: {e}");
            return 1;
        }
    };
    // The self-signed cert is signed by the freshly-generated slot key, which
    // is PIN-gated — C's selfsign_slot does the same via assert_pin.
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool {op}: PIN verification failed: {e}");
        return 1;
    }
    let cert_der = match piggy_piv::cert_builder::build_self_signed_cert(
        &point,
        algorithm,
        &format!("PIV slot {slot_id:02X}"),
        |digest| session.sign_prehash(slot_id, digest),
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("piggy tool {op}: self-signing the new cert failed: {e}");
            return 1;
        }
    };
    if let Err(e) = session.put_cert(slot_id, &cert_der) {
        eprintln!("piggy tool {op}: failed to write the new cert to slot {slot_id:02X}: {e}");
        return 1;
    }
    let ecdsa = match ssh_key::public::EcdsaPublicKey::from_sec1_bytes(&point) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("piggy tool {op}: parse generated public key: {e}");
            return 1;
        }
    };
    let mut pubkey = ssh_key::PublicKey::from(ssh_key::public::KeyData::Ecdsa(ecdsa));
    pubkey.set_comment(format!("PIV_slot_{slot_id:02X}@{guid}"));
    match pubkey.to_openssh() {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(e) => {
            eprintln!("piggy tool {op}: render OpenSSH: {e}");
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
    use super::{is_admin_key_arg, is_supported_cert_slot, parse};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    const HEX24: &str = "0102030405060708010203040506070801020304050607ff";

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
        assert!(parse(&argv(&["set-admin", "default"])).is_some());
        assert!(parse(&argv(&["set-admin", HEX24])).is_some());
        assert!(parse(&argv(&["-K", "default", "set-admin", HEX24])).is_some());
        assert!(parse(&argv(&["delete-cert", "9d"])).is_some());
        assert!(parse(&argv(&["-K", "default", "delete-cert", "9a"])).is_some());
        assert!(parse(&argv(&["update-keyhist"])).is_some());
        assert!(parse(&argv(&["-K", "default", "update-keyhist"])).is_some());
        assert!(parse(&argv(&["write-cert", "9d"])).is_some());
        assert!(parse(&argv(&["-K", "default", "write-cert", "9a"])).is_some());
        assert!(parse(&argv(&["-a", "eccp256", "generate", "9a"])).is_some());
        assert!(parse(&argv(&["-a", "eccp384", "generate", "9d"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "-a", "eccp256", "generate", "9c"])).is_some());
        assert!(parse(&argv(&["-P", "12345678", "-P", "654321", "reset-pin"])).is_some());
        assert!(parse(&argv(&["-g", "ABCD", "pubkey", "9d"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "sign", "9a"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "-P", "654321", "change-pin"])).is_some());
        // Unported ops fall through to C.
        assert!(parse(&argv(&["list"])).is_none());
        assert!(parse(&argv(&["pinfo"])).is_none());
        assert!(parse(&argv(&["init"])).is_none());
        // set-admin key forms this port does not model → C.
        assert!(parse(&argv(&["set-admin", "random"])).is_none());
        assert!(parse(&argv(&["set-admin", "@keyfile"])).is_none());
        assert!(parse(&argv(&["-K", "@keyfile", "set-admin", "default"])).is_none());
        assert!(parse(&argv(&["set-admin"])).is_none()); // missing new key
        assert!(parse(&argv(&["set-admin", "default", "extra"])).is_none());
        // delete-cert only claims the cert-holding slots; others fall to C.
        assert!(parse(&argv(&["delete-cert", "82"])).is_none()); // retired slot
        assert!(parse(&argv(&["delete-cert", "f9"])).is_none()); // attestation slot
        assert!(parse(&argv(&["delete-cert"])).is_none()); // missing slot
        assert!(parse(&argv(&["-K", "@keyfile", "delete-cert", "9d"])).is_none());
        // update-keyhist takes no positionals.
        assert!(parse(&argv(&["update-keyhist", "9d"])).is_none());
        assert!(parse(&argv(&["-K", "@keyfile", "update-keyhist"])).is_none());
        // write-cert only claims the cert-holding slots.
        assert!(parse(&argv(&["write-cert", "82"])).is_none()); // retired slot
        assert!(parse(&argv(&["write-cert"])).is_none()); // missing slot
        assert!(parse(&argv(&["-K", "@keyfile", "write-cert", "9d"])).is_none());
        // generate requires -a and an EC algorithm on a cert slot.
        assert!(parse(&argv(&["generate", "9a"])).is_none()); // no -a
        assert!(parse(&argv(&["-a", "rsa2048", "generate", "9a"])).is_none()); // RSA -> C
        assert!(parse(&argv(&["-a", "ed25519", "generate", "9a"])).is_none()); // Ed25519 -> C
        assert!(parse(&argv(&["-a", "eccp256", "generate", "82"])).is_none()); // retired slot
        assert!(parse(&argv(&["-a", "eccp256", "generate"])).is_none()); // no slot
        // An option we don't model → C handles the whole invocation.
        assert!(parse(&argv(&["-d", "pubkey", "9d"])).is_none());
        // No op at all.
        assert!(parse(&argv(&[])).is_none());
        // `-g` with no value.
        assert!(parse(&argv(&["-g"])).is_none());
    }

    #[test]
    fn parse_extracts_admin_key_for_set_admin() {
        let inv = parse(&argv(&["-K", "default", "set-admin", HEX24])).unwrap();
        assert_eq!(inv.admin_key.as_deref(), Some("default"));
        assert_eq!(inv.op, "set-admin");
        assert_eq!(inv.positionals, vec![HEX24.to_string()]);
    }

    #[test]
    fn is_admin_key_arg_accepts_default_and_hex_only() {
        assert!(is_admin_key_arg("default"));
        assert!(is_admin_key_arg(HEX24));
        assert!(!is_admin_key_arg("random"));
        assert!(!is_admin_key_arg("@file"));
        assert!(!is_admin_key_arg("0102030")); // odd length
        assert!(!is_admin_key_arg("")); // empty
    }

    #[test]
    fn is_supported_cert_slot_covers_9a_9c_9d_9e() {
        for s in ["9a", "9A", "9c", "9d", "9e", "0x9d"] {
            assert!(is_supported_cert_slot(s), "{s}");
        }
        for s in ["82", "95", "f9", "9b", "zz", ""] {
            assert!(!is_supported_cert_slot(s), "{s}");
        }
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
