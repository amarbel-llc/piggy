//! `piggy tool` — the Rust re-implementation of `pivy-tool` (piggy#289
//! Phase 3). Milestone 3.1a covers the read-only, no-PIN slot readers:
//!
//! - `piggy tool pubkey <slot>` — the slot's public key in OpenSSH format
//!   (matches C `pivy-tool`'s `sshkey_write`).
//! - `piggy tool cert <slot>` — the slot's X.509 certificate as PEM
//!   (matches C `PEM_write_X509`).
//!
//! Like `cmd::pivy_box`, this is a SUPERSET-by-fallback while the port is
//! incomplete: [`run`] returns `Some(exit_code)` for the ops it handles
//! and `None` for everything else, so `main.rs` execs the C `pivy-tool`
//! for the rest (`list`, `pinfo`, `attest`, `sign`, the whole admin/key
//! surface). It also returns `None` the moment it sees an option it does
//! not model, so a flag piggy would silently ignore is handled by C
//! instead — the superset stays honest. `piggy pivy tool` always reaches
//! C regardless.

use piggy_piv::{PivContext, PivToken};

/// One parsed `piggy tool` invocation: the general options piggy models,
/// the operation, and its positional arguments.
struct Invocation {
    /// `-g <hex>`: GUID (or prefix) selecting a token among several.
    guid: Option<String>,
    op: String,
    positionals: Vec<String>,
}

/// Parse `piggy tool <args>` into an [`Invocation`], or `None` if the op
/// is unrecognized OR an unmodeled option is present — in both cases the
/// caller falls back to C `pivy-tool`.
fn parse(args: &[String]) -> Option<Invocation> {
    let mut guid = None;
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
            // Any other flag is not modeled here — let C handle the whole
            // invocation so behavior is never silently dropped.
            _ => return None,
        }
    }
    let op = args.get(i)?.clone();
    // Only claim the ops this milestone implements; everything else falls
    // through to C.
    if !matches!(op.as_str(), "pubkey" | "cert") {
        return None;
    }
    Some(Invocation {
        guid,
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
        // parse() only returns these two ops.
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
    let pem = match openssl::x509::X509::from_der(slot.cert_der()).and_then(|x509| x509.to_pem()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool cert: encode PEM: {e}");
            return 1;
        }
    };
    // PEM already ends in a newline, matching PEM_write_X509.
    print!("{}", String::from_utf8_lossy(&pem));
    0
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
        assert!(parse(&argv(&["-g", "ABCD", "pubkey", "9d"])).is_some());
        // Unported ops fall through to C.
        assert!(parse(&argv(&["list"])).is_none());
        assert!(parse(&argv(&["pinfo"])).is_none());
        assert!(parse(&argv(&["sign", "9c"])).is_none());
        // An option we don't model → C handles the whole invocation.
        assert!(parse(&argv(&["-d", "pubkey", "9d"])).is_none());
        // No op at all.
        assert!(parse(&argv(&[])).is_none());
        // `-g` with no value.
        assert!(parse(&argv(&["-g"])).is_none());
    }

    #[test]
    fn parse_extracts_guid_and_positionals() {
        let inv = parse(&argv(&["-g", "deadbeef", "cert", "9d"])).unwrap();
        assert_eq!(inv.guid.as_deref(), Some("deadbeef"));
        assert_eq!(inv.op, "cert");
        assert_eq!(inv.positionals, vec!["9d".to_string()]);
    }
}
