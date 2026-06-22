//! The in-process terminal frontend (RFC 0006 §5) — the default binding.
//!
//! Preserves piggy's current interaction behavior: secrets are read via
//! `$SSH_ASKPASS` / the tty through [`crate::card_oracle::run_askpass`] (which
//! honors `SSH_ASKPASS_REQUIRE`, #166), and progress / confirmation render to
//! stderr / the tty. Every card-scoped prompt names the card by serial (when
//! present) and short GUID, and includes the CN when available — the piggy#195
//! mis-identification guard, here made the contract for *every* interactive
//! operation rather than just `sign-bytes`.
//!
//! Management-key policy (per the #194 design discussion): the tty default
//! returns [`MgmtKeyChoice::Random`] — the engine generates a fresh random 3DES
//! key, rotates to it, and returns it to the command, which displays it once for
//! the operator to record (a tty operator can; the secret never crosses a
//! `progress`/`completed` notification, per RFC 0006 security). The richer
//! "keep default / supply hex / random" choice is a frontend concern a GUI/TUI
//! (JSON-RPC) binding renders natively; PIN-protected storage — the eventual
//! secure default — is tracked in piggy#198.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::card::protocol::{
    CardId, CardSelectRequest, CompletedEvent, CompletedStatus, ConfirmRequest, Frontend,
    FrontendError, MgmtKeyChoice, MgmtKeyRequest, ProgressEvent, SecretKind, SecretRequest,
};
use crate::card_oracle::run_askpass;

/// The default terminal/askpass frontend.
#[derive(Debug, Default)]
pub struct TtyFrontend;

impl TtyFrontend {
    pub fn new() -> Self {
        Self
    }
}

/// The imperative verb a [`SecretKind`] prompt opens with.
fn secret_verb(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::CurrentPin => "Enter PIN",
        SecretKind::NewPin => "Enter NEW PIN",
        SecretKind::ConfirmNewPin => "Confirm NEW PIN",
        SecretKind::CurrentPuk => "Enter PUK",
        SecretKind::NewPuk => "Enter NEW PUK",
        SecretKind::ConfirmNewPuk => "Confirm NEW PUK",
        SecretKind::ManagementKey => "Enter management key",
        SecretKind::Generic => "Enter value",
    }
}

/// Render the card-identity suffix shared by the prompt and context strings:
/// `card <short>… · serial <n> · <cn> (slot <slot>)`, each piece omitted
/// gracefully when absent. Mirrors `sign_bytes::pin_prompt` so the operator
/// sees the same card handle (#195) across every interactive operation.
fn card_suffix(card: Option<&CardId>, slot: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(c) = card {
        let short: String = c.guid.chars().take(8).collect();
        s.push_str(&format!(" — card {short}…"));
        if let Some(serial) = c.serial {
            s.push_str(&format!(" · serial {serial}"));
        }
        if let Some(cn) = &c.cn {
            s.push_str(&format!(" · {cn}"));
        }
    }
    if let Some(slot) = slot {
        s.push_str(&format!(" (slot {slot})"));
    }
    s
}

/// Build the askpass prompt for a secret request. For [`SecretKind::Generic`]
/// the caller-supplied `prompt` is used verbatim (it is already human text);
/// every other kind gets a card-named prompt. Pure, so the #195 card-naming is
/// unit-testable without spawning askpass.
fn secret_prompt(req: &SecretRequest) -> String {
    if req.kind == SecretKind::Generic {
        return req.prompt.clone();
    }
    let verb = secret_verb(req.kind);
    let mut p = format!(
        "{verb}{}",
        card_suffix(req.card.as_ref(), req.slot.as_deref())
    );
    if let Some(n) = req.attempts_remaining {
        p.push_str(&format!(" · {n} tries left"));
    }
    p.push_str(" [piggy card init]: ");
    p
}

/// The `PIGGY_ASKPASS_CONTEXT` string for a secret request — the same card
/// identity in a `Context:`-line form for the user-facing askpass.
fn secret_context(req: &SecretRequest) -> Option<String> {
    let card = req.card.as_ref()?;
    let mut id = format!("guid {}", card.guid);
    if let Some(s) = card.serial {
        id.push_str(&format!(" serial {s}"));
    }
    if let Some(cn) = &card.cn {
        id.push_str(&format!(" cn {cn}"));
    }
    if let Some(slot) = &req.slot {
        id.push_str(&format!(" slot {slot}"));
    }
    Some(format!("piggy card init: card {id}"))
}

/// Interpret a tty yes/no answer. Empty falls back to `default` (if a default
/// was offered); `y`/`yes` → true, `n`/`no` → false; anything else → `None`
/// (the caller re-prompts or aborts). Pure, for unit testing.
fn parse_confirm_answer(answer: &str, default: Option<bool>) -> Option<bool> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" => default,
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

impl Frontend for TtyFrontend {
    fn request_secret(&mut self, req: SecretRequest) -> Result<Zeroizing<String>, FrontendError> {
        let prompt = secret_prompt(&req);
        let context = secret_context(&req);
        // At the tty there is no channel distinct from the operation; a failure
        // to obtain the secret (refused askpass, no tty, I/O error) aborts the
        // operation without retry — exactly the engine's `Declined` semantics.
        run_askpass(&prompt, context.as_deref()).map_err(|e| FrontendError::Declined(e.to_string()))
    }

    fn request_mgmt_key(&mut self, _req: MgmtKeyRequest) -> Result<MgmtKeyChoice, FrontendError> {
        // Tty default: rotate to a fresh random key (see the module doc). The
        // engine generates it and returns it for the command to display once.
        Ok(MgmtKeyChoice::Random)
    }

    fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError> {
        let hint = match req.default {
            Some(true) => " [Y/n] ",
            Some(false) => " [y/N] ",
            None => " [y/n] ",
        };
        // Prefer the controlling tty so a piped stdin carrying data is not
        // consumed; fall back to a stderr-prompt + stdin read when there is no
        // tty (non-interactive automation, a piped invocation, some sudo
        // setups). This y/n channel is entirely separate from secret entry:
        // PINs/PUKs always come via `$SSH_ASKPASS` (`run_askpass`), never the
        // tty or stdin, so this fallback cannot interfere with the askpass
        // flow. Echo stays on — a y/n is not a secret.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            Ok(mut tty) => {
                write!(tty, "{}{hint}", req.message)
                    .and_then(|()| tty.flush())
                    .map_err(|e| FrontendError::Transport(e.to_string()))?;
                let mut buf = [0u8; 256];
                let n = tty
                    .read(&mut buf)
                    .map_err(|e| FrontendError::Transport(e.to_string()))?;
                let answer = String::from_utf8_lossy(&buf[..n]);
                parse_confirm_answer(&answer, req.default).ok_or_else(|| {
                    FrontendError::Declined(format!("unrecognized answer {:?}", answer.trim()))
                })
            }
            Err(_) => {
                eprint!("{}{hint}", req.message);
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                let n = std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|e| FrontendError::Transport(e.to_string()))?;
                if n == 0 {
                    // EOF with no answer: take the offered default, else decline.
                    return req.default.ok_or_else(|| {
                        FrontendError::Declined("no answer (eof, no controlling tty)".into())
                    });
                }
                parse_confirm_answer(&line, req.default).ok_or_else(|| {
                    FrontendError::Declined(format!("unrecognized answer {:?}", line.trim()))
                })
            }
        }
    }

    fn select_card(&mut self, req: CardSelectRequest) -> Result<String, FrontendError> {
        // The tty binding does not present an interactive picker: card
        // selection at the tty is resolved by the command (e.g. `--serial`)
        // before the engine runs. If an operation ever reaches a tty
        // `select_card` with more than one candidate it is a usage error.
        match req.candidates.as_slice() {
            [only] => Ok(only.card.guid.clone()),
            _ => Err(FrontendError::Declined(format!(
                "tty frontend cannot disambiguate {} candidate cards; select one with --serial",
                req.candidates.len()
            ))),
        }
    }

    fn progress(&mut self, ev: ProgressEvent) {
        let counter = match (ev.current, ev.total) {
            (Some(c), Some(t)) => format!("[{c}/{t}] "),
            _ => String::new(),
        };
        eprintln!("{counter}{}", ev.message);
    }

    fn completed(&mut self, ev: CompletedEvent) {
        match ev.status {
            CompletedStatus::Ok => eprintln!("✓ done"),
            CompletedStatus::Error => {
                eprintln!(
                    "✗ failed: {}",
                    ev.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> CardId {
        CardId {
            guid: "2835305C6024B3255557BF6901443404".into(),
            serial: Some(15909078),
            cn: Some("piv-auth@2835305C".into()),
        }
    }

    #[test]
    fn secret_prompt_names_card_by_serial_short_guid_and_cn() {
        let req = SecretRequest {
            kind: SecretKind::CurrentPin,
            prompt: String::new(),
            card: Some(card()),
            slot: Some("9a".into()),
            attempts_remaining: Some(3),
        };
        let p = secret_prompt(&req);
        assert!(p.starts_with("Enter PIN"), "{p}");
        assert!(p.contains("2835305C…"), "short guid: {p}");
        assert!(p.contains("serial 15909078"), "serial: {p}");
        assert!(p.contains("piv-auth@2835305C"), "cn: {p}");
        assert!(p.contains("(slot 9a)"), "slot: {p}");
        assert!(p.contains("3 tries left"), "attempts: {p}");
    }

    #[test]
    fn secret_prompt_uses_kind_verb() {
        let mk = |kind| SecretRequest {
            kind,
            prompt: String::new(),
            card: Some(card()),
            slot: None,
            attempts_remaining: None,
        };
        assert!(secret_prompt(&mk(SecretKind::NewPin)).starts_with("Enter NEW PIN"));
        assert!(secret_prompt(&mk(SecretKind::ConfirmNewPuk)).starts_with("Confirm NEW PUK"));
        assert!(secret_prompt(&mk(SecretKind::ManagementKey)).starts_with("Enter management key"));
    }

    #[test]
    fn secret_prompt_generic_uses_caller_text_verbatim() {
        let req = SecretRequest {
            kind: SecretKind::Generic,
            prompt: "Type the magic word: ".into(),
            card: None,
            slot: None,
            attempts_remaining: None,
        };
        assert_eq!(secret_prompt(&req), "Type the magic word: ");
    }

    #[test]
    fn secret_prompt_omits_absent_card_fields() {
        let req = SecretRequest {
            kind: SecretKind::CurrentPin,
            prompt: String::new(),
            card: Some(CardId {
                guid: "AABBCCDD00000000000000000000FFFF".into(),
                serial: None,
                cn: None,
            }),
            slot: None,
            attempts_remaining: None,
        };
        let p = secret_prompt(&req);
        assert!(p.contains("AABBCCDD…"));
        assert!(!p.contains("serial"), "no serial line: {p}");
        assert!(!p.contains("·  ·"), "no empty separators: {p}");
    }

    #[test]
    fn secret_context_carries_guid_serial_cn_slot() {
        let req = SecretRequest {
            kind: SecretKind::CurrentPin,
            prompt: String::new(),
            card: Some(card()),
            slot: Some("9a".into()),
            attempts_remaining: None,
        };
        let c = secret_context(&req).unwrap();
        assert!(c.contains("guid 2835305C6024B3255557BF6901443404"));
        assert!(c.contains("serial 15909078"));
        assert!(c.contains("cn piv-auth@2835305C"));
        assert!(c.contains("slot 9a"));
    }

    #[test]
    fn secret_context_is_none_without_card() {
        let req = SecretRequest {
            kind: SecretKind::Generic,
            prompt: "x".into(),
            card: None,
            slot: None,
            attempts_remaining: None,
        };
        assert!(secret_context(&req).is_none());
    }

    #[test]
    fn parse_confirm_answer_matrix() {
        assert_eq!(parse_confirm_answer("y", None), Some(true));
        assert_eq!(parse_confirm_answer("YES", None), Some(true));
        assert_eq!(parse_confirm_answer("n", None), Some(false));
        assert_eq!(parse_confirm_answer("No", None), Some(false));
        // Empty falls back to the offered default.
        assert_eq!(parse_confirm_answer("", Some(true)), Some(true));
        assert_eq!(parse_confirm_answer("  ", Some(false)), Some(false));
        assert_eq!(parse_confirm_answer("", None), None);
        // Garbage is unrecognized.
        assert_eq!(parse_confirm_answer("maybe", Some(true)), None);
    }

    #[test]
    fn tty_default_mgmt_key_choice_is_random() {
        let mut fe = TtyFrontend::new();
        let choice = fe
            .request_mgmt_key(MgmtKeyRequest {
                prompt: "mgmt key".into(),
                card: card(),
            })
            .unwrap();
        assert_eq!(choice, MgmtKeyChoice::Random);
    }
}
