//! `piggy holder mint` and `piggy holder retire`: the thin clients of the
//! holder agent's `mint@piggy` and `retire@piggy` extensions (FDR 0006
//! phase (d), piggy#383), the way `piggy operator-sign` is the client of
//! `operator-act@piggy`. Everything that matters happens in the holder: it
//! reads who is calling, resolves the scope, creates the card and keeps
//! its PIN. This client only names the scope and the key type and prints
//! what came back.
//!
//! Exit codes: 0 done; 1 refused (the status name is on stderr); 2 usage;
//! 3 no holder here (no agent socket, an unreachable agent, or an agent
//! that is not a holder).

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use piggy::agent_client::{
    HolderClientError, holder_mint, holder_retire, piggy_auth_sock_override,
};
use piggy::holder_ext::{KeyType, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Refused = 1,
    Usage = 2,
    NotServed = 3,
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
    name = "piggy holder",
    about = "Mint and retire scope-bound keys in a holder agent (FDR 0006)",
    disable_help_subcommand = true
)]
struct HolderCli {
    #[command(subcommand)]
    cmd: HolderCommand,
}

#[derive(Subcommand, Debug)]
enum HolderCommand {
    /// Ask the holder for a new key bound to a scope; the OpenSSH public
    /// key line is printed on stdout.
    Mint {
        /// The scope the key binds to, by the name the holder defines
        /// (`--scope NAME=…` on `piggy agent --holder`), like piggy-mint-v1.
        /// Without it the holder refuses the mint as scope-unbound.
        #[arg(long, value_name = "NAME", default_value = "")]
        scope: String,
        /// The key type: ed25519 or p256.
        #[arg(long = "type", value_name = "TYPE", default_value = "ed25519")]
        key_type: String,
    },
    /// Destroy a minted key's card. The key is read as an OpenSSH public
    /// key line from FILE, or stdin.
    Retire { file: Option<PathBuf> },
}

pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy holder".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match HolderCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    match execute(args.cmd) {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("piggy holder: {}", failure.message);
            failure.exit as i32
        }
    }
}

fn agent_socket() -> Result<PathBuf, String> {
    piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()))
        .map(PathBuf::from)
        .ok_or_else(|| {
            "no agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK to the holder agent's socket"
                .to_string()
        })
}

/// The key type a `--type` names.
fn parse_key_type(name: &str) -> Result<KeyType, String> {
    match name {
        "ed25519" | "ssh-ed25519" => Ok(KeyType::Ed25519),
        "p256" | "ecdsa-sha2-nistp256" => Ok(KeyType::EcdsaP256),
        other => Err(format!("unknown key type {other:?}; use ed25519 or p256")),
    }
}

fn exit_of_client_error(error: &HolderClientError) -> Exit {
    match error {
        HolderClientError::Unreachable(_) | HolderClientError::NotServed(_) => Exit::NotServed,
        HolderClientError::Protocol(_) => Exit::Refused,
    }
}

fn refusal_message(what: &str, status: Status, detail: &str) -> String {
    if detail.is_empty() {
        format!("the holder refused the {what} ({})", status.name())
    } else {
        format!(
            "the holder refused the {what} ({}): {detail}",
            status.name()
        )
    }
}

fn execute(cmd: HolderCommand) -> Result<(), Failure> {
    match cmd {
        HolderCommand::Mint { scope, key_type } => {
            let key_type = parse_key_type(&key_type).map_err(failure(Exit::Usage))?;
            let socket = agent_socket().map_err(failure(Exit::NotServed))?;
            let response = holder_mint(&socket, &scope, key_type)
                .map_err(|e| failure(exit_of_client_error(&e))(e.to_string()))?;
            if response.status != Status::Ok {
                return Err(failure(Exit::Refused)(refusal_message(
                    "mint",
                    response.status,
                    &response.detail,
                )));
            }
            let key = ssh_key::PublicKey::from_bytes(&response.key).map_err(|e| {
                failure(Exit::Refused)(format!("the minted key is unreadable: {e}"))
            })?;
            let line = ssh_key::PublicKey::new(
                key.key_data().clone(),
                format!("holder:{}", response.card),
            )
            .to_openssh()
            .map_err(|e| failure(Exit::Refused)(format!("encode the minted key: {e}")))?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{line}")
                .and_then(|()| stdout.flush())
                .map_err(|e| failure(Exit::Refused)(format!("write stdout: {e}")))?;
            eprintln!(
                "piggy holder: minted {} on card {:?}{}",
                key_type.as_str(),
                response.card,
                if scope.is_empty() {
                    String::new()
                } else {
                    format!(" bound to scope {scope}")
                }
            );
            Ok(())
        }
        HolderCommand::Retire { file } => {
            let text = match &file {
                Some(path) => std::fs::read_to_string(path)
                    .map_err(|e| failure(Exit::Usage)(format!("read {}: {e}", path.display())))?,
                None => {
                    let mut text = String::new();
                    std::io::stdin()
                        .read_to_string(&mut text)
                        .map_err(|e| failure(Exit::Usage)(format!("read stdin: {e}")))?;
                    text
                }
            };
            let key = ssh_key::PublicKey::from_openssh(text.trim()).map_err(|e| {
                failure(Exit::Usage)(format!("not an OpenSSH public key line: {e}"))
            })?;
            let blob = key
                .to_bytes()
                .map_err(|e| failure(Exit::Usage)(format!("encode the key: {e}")))?;
            let socket = agent_socket().map_err(failure(Exit::NotServed))?;
            let response = holder_retire(&socket, &blob)
                .map_err(|e| failure(exit_of_client_error(&e))(e.to_string()))?;
            if response.status != Status::Ok {
                return Err(failure(Exit::Refused)(refusal_message(
                    "retire",
                    response.status,
                    &response.detail,
                )));
            }
            eprintln!("piggy holder: retired {}", key.comment());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_defaults_to_ed25519_and_no_scope() {
        let cli = HolderCli::try_parse_from(["piggy holder", "mint"]).unwrap();
        match cli.cmd {
            HolderCommand::Mint { scope, key_type } => {
                assert_eq!(scope, "");
                assert_eq!(key_type, "ed25519");
            }
            other => panic!("{other:?}"),
        }
        let cli = HolderCli::try_parse_from([
            "piggy holder",
            "mint",
            "--scope",
            "piggy-mint-v1",
            "--type",
            "p256",
        ])
        .unwrap();
        assert!(
            matches!(cli.cmd, HolderCommand::Mint { ref scope, ref key_type }
            if scope == "piggy-mint-v1" && key_type == "p256")
        );
        assert!(HolderCli::try_parse_from(["piggy holder"]).is_err());
    }

    #[test]
    fn key_types_by_short_and_ssh_names() {
        assert_eq!(parse_key_type("ed25519").unwrap(), KeyType::Ed25519);
        assert_eq!(parse_key_type("ssh-ed25519").unwrap(), KeyType::Ed25519);
        assert_eq!(parse_key_type("p256").unwrap(), KeyType::EcdsaP256);
        assert!(parse_key_type("rsa").is_err());
    }

    #[test]
    fn a_refusal_names_the_status() {
        assert_eq!(
            refusal_message("mint", Status::CapReached, "16 live cards"),
            "the holder refused the mint (cap-reached): 16 live cards"
        );
        assert_eq!(
            refusal_message("retire", Status::NotBoundScope, ""),
            "the holder refused the retire (not-bound-scope)"
        );
    }
}
