//! `piggy ca`: X.509 issuance (FDR 0007). Phase (iii-a) brings the first
//! verb, `csr`, the certificate request for a holder-held intermediate
//! key; phase (ii) adds `root-cert`, `sign` and `issue` for a card-held
//! issuer beside it (each verb its own module, so the two land without
//! conflict).
//!
//! Exit codes, shared by every verb: 0 done; 1 refused (the reason on
//! stderr); 2 usage; 3 no agent here serves the key.

use clap::{Parser, Subcommand};

mod csr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    Refused = 1,
    Usage = 2,
    NotServed = 3,
}

pub(crate) struct Failure {
    pub exit: Exit,
    pub message: String,
}

pub(crate) fn failure(exit: Exit) -> impl Fn(String) -> Failure {
    move |message| Failure { exit, message }
}

#[derive(Parser, Debug)]
#[command(
    name = "piggy ca",
    about = "X.509 issuance: a card-held root, a holder-held intermediate (FDR 0007)",
    disable_help_subcommand = true
)]
struct CaCli {
    #[command(subcommand)]
    cmd: CaCommand,
}

#[derive(Subcommand, Debug)]
enum CaCommand {
    /// A PKCS#10 certificate request for a key the agent serves (a holder
    /// intermediate key minted with `piggy holder mint --type p256`),
    /// signed through the agent; PEM on stdout.
    Csr(csr::CsrArgs),
}

pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy ca".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match CaCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    let result = match args.cmd {
        CaCommand::Csr(args) => csr::execute(args),
    };
    match result {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("piggy ca: {}", failure.message);
            failure.exit as i32
        }
    }
}

/// The agent socket every verb that signs through the agent uses.
pub(crate) fn agent_socket() -> Result<std::path::PathBuf, String> {
    piggy::agent_client::piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            "no agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK to the agent serving the key"
                .to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_is_the_only_verb_and_needs_a_key() {
        assert!(CaCli::try_parse_from(["piggy ca"]).is_err());
        assert!(
            CaCli::try_parse_from(["piggy ca", "csr"]).is_err(),
            "--key is required"
        );
        let cli = CaCli::try_parse_from(["piggy ca", "csr", "--key", "id.pub"]).unwrap();
        match cli.cmd {
            CaCommand::Csr(args) => {
                assert_eq!(args.key.to_string_lossy(), "id.pub");
                assert_eq!(args.cn, csr::DEFAULT_CN);
                assert!(args.out.is_none());
            }
        }
    }
}
