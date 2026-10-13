//! `piggy operator-sign` — the thin client of `operator-act@piggy` (RFC 0012).
//!
//! Reads the text of an operator act from stdin, asks the agent to sign it
//! under a registered namespace, and writes the armored sshsig to stdout.
//! Everything that makes it an operator act happens in the agent that holds
//! the card: the agent shows the exact text on the PIN prompt, checks the
//! slot's attestation, and waits for the PIN and the touch. This client
//! cannot sign locally and has no flag to skip any of that, which is the
//! point: it works the same against a forwarded agent socket.
//!
//! Exit codes, grouped so a script can tell what to do next ([`Exit`]):
//! 0 signed; 1 refused, and asking again will not help; 2 usage; 3 no agent
//! here serves operator acts; 4 not signed this time, worth asking again
//! (the operator cancelled, or the card was absent). The RFC status name is
//! on stderr either way.

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;

use piggy::agent_client::{OperatorActError, operator_act, piggy_auth_sock_override};
use piggy::operator_act::{
    HashAlgorithm, MAX_TEXT_BYTES, NAMESPACES, Status, armor, display_class, displayable_text,
};

/// Why nothing was signed, as the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// The answer is no and would be no again: the policy, the namespace,
    /// the text or the request is what is wrong.
    Refused = 1,
    /// The command line is wrong (clap exits with the same code).
    Usage = 2,
    /// Nothing here serves operator acts: no agent socket, an unreachable
    /// agent, or one that predates the extension.
    NotServed = 3,
    /// Nothing is wrong with the request: the operator cancelled, the touch
    /// timed out, or the card was not there.
    Retryable = 4,
}

impl Exit {
    /// The group an RFC 0012 §2.3 status other than `signed` falls in.
    fn of_status(status: Status) -> Self {
        match status {
            Status::Cancelled | Status::CardAbsent => Self::Retryable,
            _ => Self::Refused,
        }
    }
}

struct Failure {
    exit: Exit,
    message: String,
}

fn failure(exit: Exit) -> impl Fn(String) -> Failure {
    move |message| Failure { exit, message }
}

#[derive(Parser, Debug)]
#[command(
    name = "piggy operator-sign",
    about = "Sign stdin as an operator act through the agent; armored sshsig on stdout",
    disable_help_subcommand = true
)]
struct OperatorSignCli {
    /// The sshsig namespace: piggy-quote-v1, piggy-escalation-v1 or
    /// piggy-certificate-v1. It selects how the agent presents the prompt.
    #[arg(long)]
    namespace: String,
    /// PIV slot to sign with. The agent refuses a slot whose key is not
    /// attested PIN-always and touch-always; `piggy card init` gives 9c
    /// that policy.
    #[arg(long, default_value = "9c")]
    slot: String,
    /// GUID (hex, or a prefix) of the card to use, when the agent serves
    /// the slot for more than one card.
    #[arg(long)]
    guid: Option<String>,
    /// Hash the sshsig is made over: sha512 or sha256.
    #[arg(long, default_value = "sha512")]
    hash: String,
}

/// Entry point: parse argv (clap prints help/errors and exits itself), then
/// run the client. Returns the process exit code.
pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy operator-sign".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match OperatorSignCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    match execute(args) {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("piggy operator-sign: {}", failure.message);
            failure.exit as i32
        }
    }
}

/// The slot and hash the flags name. A value neither flag can take is a
/// usage error; the agent makes these checks again and is the authority.
fn parse_slot_and_hash(slot: &str, hash: &str) -> Result<(u8, HashAlgorithm), String> {
    let slot_id = piggy::sign_core::parse_slot(slot)?;
    let hash = HashAlgorithm::parse(hash)
        .ok_or_else(|| format!("unsupported hash {hash:?}; use sha512 or sha256"))?;
    Ok((slot_id, hash))
}

/// What the agent would answer `refused-namespace`, said before the
/// operator is bothered.
fn check_namespace(namespace: &str) -> Result<(), String> {
    if display_class(namespace).is_some() {
        return Ok(());
    }
    Err(format!(
        "namespace {namespace:?} is not an operator-act namespace; use one of {}",
        NAMESPACES.join(", ")
    ))
}

/// What the agent would answer `refused-text`.
fn check_text(text: &[u8]) -> Result<(), String> {
    if displayable_text(text).is_some() {
        return Ok(());
    }
    Err(if text.is_empty() {
        "no text on stdin; an operator act signs the text the operator reads".to_string()
    } else if text.len() > MAX_TEXT_BYTES {
        format!(
            "the text is {} bytes; an operator act carries at most {MAX_TEXT_BYTES}",
            text.len()
        )
    } else {
        "the text must be UTF-8 with no control characters other than newline and tab, \
         so the prompt shows exactly what is signed"
            .to_string()
    })
}

fn agent_socket() -> Result<PathBuf, String> {
    piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()))
        .map(PathBuf::from)
        .ok_or_else(|| {
            "no agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK (operator acts are signed \
             by the agent that holds the card)"
                .to_string()
        })
}

fn refusal_message(status: Status, detail: &str) -> String {
    let what = match Exit::of_status(status) {
        Exit::Retryable => "the operator act was not signed",
        _ => "the agent refused the operator act",
    };
    if detail.is_empty() {
        format!("{what} ({})", status.name())
    } else {
        format!("{what} ({}): {detail}", status.name())
    }
}

fn exit_of_client_error(error: &OperatorActError) -> Exit {
    match error {
        OperatorActError::Unreachable(_) | OperatorActError::NotServed(_) => Exit::NotServed,
        // The same answer the agent gives as `no-such-key`.
        OperatorActError::NoKey(_) | OperatorActError::Protocol(_) => Exit::Refused,
    }
}

fn execute(args: OperatorSignCli) -> Result<(), Failure> {
    let (slot_id, hash) =
        parse_slot_and_hash(&args.slot, &args.hash).map_err(failure(Exit::Usage))?;
    check_namespace(&args.namespace).map_err(failure(Exit::Refused))?;

    let mut text = Vec::new();
    std::io::stdin()
        .read_to_end(&mut text)
        .map_err(|e| failure(Exit::Refused)(format!("read stdin: {e}")))?;
    check_text(&text).map_err(failure(Exit::Refused))?;

    let socket = agent_socket().map_err(failure(Exit::NotServed))?;
    let (response, key) = operator_act(
        &socket,
        slot_id,
        args.guid.as_deref(),
        &args.namespace,
        hash,
        &text,
    )
    .map_err(|e| failure(exit_of_client_error(&e))(e.to_string()))?;

    if response.status != Status::Signed {
        return Err(failure(Exit::of_status(response.status))(refusal_message(
            response.status,
            &response.detail,
        )));
    }

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(armor(&response.sshsig).as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| failure(Exit::Refused)(format!("write stdout: {e}")))?;
    eprintln!(
        "piggy operator-sign: signed under {} by {}",
        args.namespace,
        key.comment()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_requires_a_namespace_and_defaults_to_slot_9c_sha512() {
        assert!(OperatorSignCli::try_parse_from(["piggy operator-sign"]).is_err());
        let a = OperatorSignCli::try_parse_from([
            "piggy operator-sign",
            "--namespace",
            "piggy-escalation-v1",
        ])
        .unwrap();
        assert_eq!(a.slot, "9c");
        assert_eq!(a.hash, "sha512");
        assert!(a.guid.is_none());
    }

    #[test]
    fn only_registered_namespaces_pass_the_client_check() {
        for namespace in NAMESPACES {
            assert!(check_namespace(namespace).is_ok());
        }
        let err = check_namespace("git").unwrap_err();
        assert!(err.contains("piggy-escalation-v1"), "{err}");
    }

    #[test]
    fn slot_and_hash_flags_take_only_what_can_sign() {
        assert_eq!(
            parse_slot_and_hash("9C", "sha256").unwrap(),
            (0x9C, HashAlgorithm::Sha256)
        );
        assert!(parse_slot_and_hash("9d", "sha512").is_err());
        let err = parse_slot_and_hash("9e", "sha512").unwrap_err();
        assert!(!err.contains("sign-bytes"), "{err}");
        let err = parse_slot_and_hash("9c", "md5").unwrap_err();
        assert!(err.contains("sha512"), "{err}");
    }

    #[test]
    fn check_text_names_what_is_wrong() {
        assert!(check_text(b"grant: merge to master\n").is_ok());
        assert!(check_text(b"").unwrap_err().contains("no text"));
        assert!(
            check_text(&vec![b'a'; MAX_TEXT_BYTES + 1])
                .unwrap_err()
                .contains("at most")
        );
        assert!(check_text(b"a\x1b[2Jb").unwrap_err().contains("control"));
    }

    /// The grouping a caller scripts against: only a cancel and an absent
    /// card are worth asking again.
    #[test]
    fn exit_codes_group_the_rfc_statuses() {
        for status in [Status::Cancelled, Status::CardAbsent] {
            assert_eq!(Exit::of_status(status) as i32, 4, "{}", status.name());
        }
        for status in [
            Status::NoSuchKey,
            Status::RefusedPolicy,
            Status::RefusedNamespace,
            Status::RefusedText,
            Status::BadRequest,
            Status::Error,
            Status::Unknown(99),
        ] {
            assert_eq!(Exit::of_status(status) as i32, 1, "{}", status.name());
        }
        assert_eq!(Exit::Usage as i32, 2);
        assert_eq!(
            exit_of_client_error(&OperatorActError::NotServed(String::new())) as i32,
            3
        );
        assert_eq!(
            exit_of_client_error(&OperatorActError::Unreachable(String::new())) as i32,
            3
        );
        assert_eq!(
            exit_of_client_error(&OperatorActError::NoKey(String::new())) as i32,
            1
        );
    }

    #[test]
    fn refusal_message_carries_the_rfc_status_name_and_detail() {
        let cancelled = refusal_message(Status::Cancelled, "");
        assert!(cancelled.contains("not signed"), "{cancelled}");
        assert!(cancelled.contains("(cancelled)"), "{cancelled}");
        let refused = refusal_message(Status::RefusedPolicy, "slot 9A: PIN once, touch cached");
        assert!(refused.contains("refused the operator act"), "{refused}");
        assert!(
            refused.contains("(refused-policy): slot 9A: PIN once, touch cached"),
            "{refused}"
        );
    }
}
