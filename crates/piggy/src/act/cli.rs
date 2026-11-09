//! `piggy act` — the `piggy-act-v1` document verbs (piggy RFC 0013).
//!
//! - `canon [FILE]`: the canonical form (§3.1) on stdout, the bytes a
//!   producer signs and the agent shows.
//! - `verify --seal-only [FILE]`: the signature alone (§5.2 steps 1 and 2),
//!   no chain walk; prints `valid <act digest>`.
//! - `digest [--sha256] [FILE]`: the act digest (§3.5) of a sealed act.
//! - `detach --signature OUT [FILE]`: the canonical form on stdout and the
//!   detached sshsig rebuilt from the seal (§3.3), armored, in OUT; together
//!   they are what `ssh-keygen -Y verify` checks.
//! - `attach --signature SIG [FILE]`: join a detached sshsig (armored or not)
//!   to its unsealed act after checking its namespace, key and hash against
//!   the seal fields (§3.3); the sealed act on stdout.
//! - `key [--card] [PUBFILE]`: the `key` value for an OpenSSH public key.
//!
//! FILE is stdin when absent or `-`. A refusal is on stderr as
//! `refused (<rule>): <detail>`, the rule the stable name of what was broken.
//!
//! Exit codes: 0 done; 1 refused (for `verify`, invalid); 2 usage; 3 an
//! input could not be read or an output written.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use super::seal::{self, DigestFormat};
use super::{Act, Refusal, parse};
use crate::operator_act::armor;

#[derive(Parser, Debug)]
#[command(
    name = "piggy act",
    about = "Read, canonicalize and check piggy-act-v1 documents (RFC 0013)",
    disable_help_subcommand = true
)]
struct ActCli {
    #[command(subcommand)]
    cmd: ActCommand,
}

#[derive(Subcommand, Debug)]
enum ActCommand {
    /// Write an act's canonical form (RFC 0013 §3.1) to stdout.
    Canon {
        /// The act to read; stdin when absent or `-`.
        file: Option<PathBuf>,
    },
    /// Check a sealed act's signature under its `key` (RFC 0013 §5.2 steps
    /// 1 and 2); prints `valid <act digest>`.
    Verify {
        /// Check the seal only, with no chain walk. Required: the chain walk
        /// is not built yet.
        #[arg(long)]
        seal_only: bool,
        /// The act to read; stdin when absent or `-`.
        file: Option<PathBuf>,
    },
    /// Print a sealed act's digest (RFC 0013 §3.5), blake2b256 unless
    /// --sha256.
    Digest {
        #[arg(long)]
        sha256: bool,
        /// The act to read; stdin when absent or `-`.
        file: Option<PathBuf>,
    },
    /// Write the canonical form to stdout and the detached, armored sshsig
    /// rebuilt from the seal (RFC 0013 §3.3) to --signature.
    Detach {
        #[arg(long)]
        signature: PathBuf,
        /// The sealed act to read; stdin when absent or `-`.
        file: Option<PathBuf>,
    },
    /// Join a detached sshsig to its unsealed act (RFC 0013 §3.3) and write
    /// the sealed act to stdout.
    Attach {
        #[arg(long)]
        signature: PathBuf,
        /// The act to read; stdin when absent or `-`.
        file: Option<PathBuf>,
    },
    /// Print the `key` value for an OpenSSH public key:
    /// piggy-principal_pub-v1, or piggy-piv_sig-v1 with --card.
    Key {
        #[arg(long)]
        card: bool,
        /// The public key file; stdin when absent or `-`.
        file: Option<PathBuf>,
    },
}

const EXIT_REFUSED: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_INPUT: i32 = 3;

struct Failure {
    exit: i32,
    message: String,
}

impl From<Refusal> for Failure {
    fn from(refusal: Refusal) -> Self {
        Failure {
            exit: EXIT_REFUSED,
            message: format!("refused ({}): {}", refusal.rule.as_str(), refusal.detail),
        }
    }
}

fn input_failure(message: String) -> Failure {
    Failure {
        exit: EXIT_INPUT,
        message,
    }
}

/// Run `piggy act` with the arguments after `act`; the process exit code.
pub fn run(args: &[String]) -> i32 {
    let cli = match ActCli::try_parse_from(
        std::iter::once("piggy act".to_owned()).chain(args.iter().cloned()),
    ) {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { EXIT_USAGE } else { 0 };
            let _ = e.print();
            return code;
        }
    };

    let (verb, result) = match cli.cmd {
        ActCommand::Canon { file } => ("canon", read_act(file.as_deref()).map(|a| a.canonical())),
        ActCommand::Verify { seal_only, file } => ("verify", verify(seal_only, file.as_deref())),
        ActCommand::Digest { sha256, file } => ("digest", digest(sha256, file.as_deref())),
        ActCommand::Detach { signature, file } => ("detach", detach(&signature, file.as_deref())),
        ActCommand::Attach { signature, file } => ("attach", attach(&signature, file.as_deref())),
        ActCommand::Key { card, file } => ("key", key(card, file.as_deref())),
    };

    match result {
        Ok(output) => {
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(&output).and_then(|()| stdout.flush()) {
                Ok(()) => 0,
                Err(_) => EXIT_INPUT,
            }
        }
        Err(failure) => {
            eprintln!("piggy act {verb}: {}", failure.message);
            failure.exit
        }
    }
}

fn read_act(file: Option<&Path>) -> Result<Act, Failure> {
    let input = read_input(file).map_err(input_failure)?;
    Ok(parse(&input)?)
}

fn verify(seal_only: bool, file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    if !seal_only {
        return Err(Failure {
            exit: EXIT_USAGE,
            message: "only --seal-only is built: the chain walk (RFC 0013 §5.2 steps 3 to 6) \
                      comes later"
                .into(),
        });
    }
    let act = read_act(file)?;
    seal::verify_seal(&act)?;
    let digest = sealed_digest(&act, DigestFormat::Blake2b256)?;
    Ok(format!("valid {digest}\n").into_bytes())
}

fn digest(sha256: bool, file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    let format = if sha256 {
        DigestFormat::Sha256
    } else {
        DigestFormat::Blake2b256
    };
    let digest = sealed_digest(&read_act(file)?, format)?;
    Ok(format!("{digest}\n").into_bytes())
}

fn sealed_digest(act: &Act, format: DigestFormat) -> Result<String, Failure> {
    seal::act_digest(act, format).ok_or_else(|| Failure {
        exit: EXIT_REFUSED,
        message: "refused (missing-field): an act digest is over a sealed act; `signature` \
                  is absent"
            .into(),
    })
}

fn detach(signature: &Path, file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    let act = read_act(file)?;
    let blob = seal::detached_sshsig(&act)?;
    std::fs::write(signature, armor(&blob))
        .map_err(|e| input_failure(format!("writing {}: {e}", signature.display())))?;
    Ok(act.canonical())
}

fn attach(signature: &Path, file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    let act = read_act(file)?;
    let raw = std::fs::read(signature)
        .map_err(|e| input_failure(format!("reading {}: {e}", signature.display())))?;
    let blob = seal::unarmor(&raw).ok_or_else(|| Failure {
        exit: EXIT_REFUSED,
        message: "refused (signature): the armored sshsig is not valid base64".into(),
    })?;
    let sealed = seal::attach(&act, &blob)?;
    seal::verify_seal(&sealed)?;
    sealed
        .sealed_canonical()
        .ok_or_else(|| input_failure("attach produced no seal".into()))
}

fn key(card: bool, file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    let input = read_input(file).map_err(input_failure)?;
    let text = String::from_utf8(input)
        .map_err(|_| input_failure("the public key is not UTF-8".into()))?;
    let id = seal::key_id(&text, card).map_err(|message| Failure {
        exit: EXIT_REFUSED,
        message: format!("refused (value): {message}"),
    })?;
    Ok(format!("{id}\n").into_bytes())
}

fn read_input(file: Option<&Path>) -> Result<Vec<u8>, String> {
    match file {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
        }
        _ => {
            let mut input = Vec::new();
            std::io::stdin()
                .read_to_end(&mut input)
                .map_err(|e| format!("reading stdin: {e}"))?;
            Ok(input)
        }
    }
}
