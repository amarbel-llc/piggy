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
//! - `seal [FILE]`: sign an unsealed act through the agent with the key its
//!   `key` names (card namespaces through operator-act@piggy,
//!   piggy-record-v1 through an ordinary sign request) and write the sealed
//!   act. Its exit codes are `piggy operator-sign`'s: 1 refused (and, as
//!   there, an unreadable input or a failed write), 3 no agent serves it, 4
//!   not signed this time.
//!
//! FILE is stdin when absent or `-`. A refusal is on stderr as
//! `refused (<rule>): <detail>`, the rule the stable name of what was broken.
//!
//! Exit codes: 0 done; 1 refused (for `verify`, invalid); 2 usage; 3 an
//! input could not be read or an output written.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use super::produce::{SealError, check_before_signing, seal_act};
use super::seal::{self, DigestFormat};
use super::store::{ActStore, MemoryStore};
use super::verify::{self, Failure as VerifyFailure, Options, Outcome, Step, Unresolved, Verifier};
use super::{Act, Refusal, fields, parse, verdict};
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
    /// Verify an act against its chain (RFC 0013 §5.2) and print the
    /// verdict; with --seal-only, its signature alone (§5.2 steps 1 and 2).
    /// The exit code is the verdict: 0 valid, 1 invalid, 2 undetermined, 3
    /// a usage or input error with no verdict.
    Verify {
        /// Check the seal only, with no chain walk; prints `valid <act
        /// digest>`.
        #[arg(long)]
        seal_only: bool,
        /// The act to verify, as a path or as an act digest found in the
        /// store; instead of FILE.
        #[arg(long, conflicts_with = "file")]
        act: Option<String>,
        /// The time T, YYYY-MM-DDThh:mm:ssZ; now when absent.
        #[arg(long)]
        at: Option<String>,
        /// The trust anchors: an allowed-signers file naming the card keys.
        #[arg(long, required_unless_present = "seal_only")]
        anchors: Option<PathBuf>,
        /// A directory of sealed acts.
        #[arg(long, conflicts_with = "store_stdin")]
        store: Option<PathBuf>,
        /// A test adapter: the store as {"acts": ["<sealed act>", ...]} on
        /// stdin (provisional).
        #[arg(long)]
        store_stdin: bool,
        /// Assert that the store holds every revocation there is.
        #[arg(long)]
        store_is_revocation_source: bool,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
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
    /// Sign an unsealed act through the agent and write the sealed act
    /// (RFC 0013 §3.2, §3.3): a card namespace through operator-act@piggy
    /// (the canonical form is the prompt), piggy-record-v1 through an
    /// ordinary sign request with the act's `key`.
    Seal {
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

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Text,
    /// One `piggy-act-verdict-v1` JSON object.
    Json,
}

const EXIT_REFUSED: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_INPUT: i32 = 3;

/// `piggy act verify`'s exit code is the verdict, so its usage and input
/// errors are 3, not piggy's usual 2.
const EXIT_UNDETERMINED: i32 = 2;
const EXIT_VERIFY_USAGE: i32 = 3;

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
            let usage = if args.first().map(String::as_str) == Some("verify") {
                EXIT_VERIFY_USAGE
            } else {
                EXIT_USAGE
            };
            let code = if e.use_stderr() { usage } else { 0 };
            let _ = e.print();
            return code;
        }
    };

    let (verb, result) = match cli.cmd {
        ActCommand::Canon { file } => ("canon", read_act(file.as_deref()).map(|a| a.canonical())),
        ActCommand::Verify {
            seal_only: true,
            file,
            act,
            ..
        } => {
            let file = act.map(PathBuf::from).or(file);
            (
                "verify",
                verify_seal_only(file.as_deref()).map_err(|f| Failure {
                    exit: if f.exit == EXIT_REFUSED {
                        EXIT_REFUSED
                    } else {
                        EXIT_VERIFY_USAGE
                    },
                    ..f
                }),
            )
        }
        ActCommand::Verify {
            seal_only: false,
            act,
            at,
            anchors,
            store,
            store_stdin,
            store_is_revocation_source,
            format,
            file,
        } => {
            return verify_chain(VerifyArgs {
                act,
                file,
                at,
                anchors: anchors.expect("clap requires --anchors"),
                store,
                store_stdin,
                revocation_source: store_is_revocation_source,
                format,
            });
        }
        ActCommand::Digest { sha256, file } => ("digest", digest(sha256, file.as_deref())),
        ActCommand::Detach { signature, file } => ("detach", detach(&signature, file.as_deref())),
        ActCommand::Attach { signature, file } => ("attach", attach(&signature, file.as_deref())),
        ActCommand::Seal { file } => ("seal", seal(file.as_deref())),
        ActCommand::Key { card, file } => ("key", key(card, file.as_deref())),
    };

    match result {
        Ok(output) => {
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(&output).and_then(|()| stdout.flush()) {
                Ok(()) => 0,
                // As operator-sign: a failed write after the act was signed is
                // a refusal, never "nothing serves it".
                Err(_) if verb == "seal" => EXIT_REFUSED,
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

fn verify_seal_only(file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    let act = read_act(file)?;
    seal::verify_seal(&act)?;
    let digest = sealed_digest(&act, DigestFormat::Blake2b256)?;
    Ok(format!("valid {digest}\n").into_bytes())
}

struct VerifyArgs {
    act: Option<String>,
    file: Option<PathBuf>,
    at: Option<String>,
    anchors: PathBuf,
    store: Option<PathBuf>,
    store_stdin: bool,
    revocation_source: bool,
    format: Format,
}

/// The full `piggy act verify` (RFC 0013 §5.2, §5.3); returns the exit code.
fn verify_chain(args: VerifyArgs) -> i32 {
    let usage = |message: String| {
        eprintln!("piggy act verify: {message}");
        EXIT_VERIFY_USAGE
    };

    let at = match args.at {
        Some(at) if fields::is_timestamp(&at) => at,
        Some(at) => return usage(format!("--at {at:?} is not spelled YYYY-MM-DDThh:mm:ssZ")),
        None => verify::now(),
    };
    let anchors = match load_anchors(&args.anchors) {
        Ok(anchors) => anchors,
        Err(message) => return usage(message),
    };

    let store = if args.store_stdin {
        let reads_stdin = match (&args.act, &args.file) {
            (Some(_), _) => false,
            (None, Some(f)) => f.as_os_str() == "-",
            (None, None) => true,
        };
        if reads_stdin {
            return usage("--store-stdin needs the act from --act or FILE, not stdin".into());
        }
        match read_input(None).and_then(|bytes| MemoryStore::from_json(&bytes)) {
            Ok(store) => store,
            Err(message) => return usage(message),
        }
    } else if let Some(dir) = &args.store {
        match MemoryStore::from_dir(dir) {
            Ok(store) => store,
            Err(e) => return usage(format!("reading the store {}: {e}", dir.display())),
        }
    } else {
        MemoryStore::new()
    };

    // The act: a digest in the store, or a document.
    let (digest, outcome) = match &args.act {
        Some(digest) if digest.starts_with("piggy-record-digest-v1@") => match store.get(digest) {
            Some(stored) => {
                let outcome = Verifier::new(
                    store,
                    Options {
                        at: at.clone(),
                        anchors,
                        revocation_source: args.revocation_source,
                    },
                )
                .verify(&stored.act);
                (Some(stored.digest), outcome)
            }
            None => (
                Some(digest.clone()),
                Outcome::Undetermined(Unresolved {
                    digests: vec![digest.clone()],
                    reason: "the act is not in the store".into(),
                }),
            ),
        },
        _ => {
            let path = args.act.as_ref().map(PathBuf::from).or(args.file);
            let input = match read_input(path.as_deref()) {
                Ok(input) => input,
                Err(message) => return usage(message),
            };
            match parse(&input) {
                Err(refusal) => (
                    None,
                    Outcome::Invalid(VerifyFailure {
                        step: Step::Parse,
                        act: String::new(),
                        reason: refusal.to_string(),
                    }),
                ),
                Ok(act) => {
                    let digest = seal::act_digest(&act, DigestFormat::Blake2b256);
                    let outcome = Verifier::new(
                        store,
                        Options {
                            at: at.clone(),
                            anchors,
                            revocation_source: args.revocation_source,
                        },
                    )
                    .verify(&act);
                    (digest, outcome)
                }
            }
        }
    };

    let output = match args.format {
        Format::Json => verdict::to_json(&outcome, digest.as_deref(), &at, args.revocation_source),
        Format::Text => verdict_text(&outcome, digest.as_deref()),
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(output.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return EXIT_VERIFY_USAGE;
    }

    match outcome {
        Outcome::Valid(_) => 0,
        Outcome::Invalid(_) => EXIT_REFUSED,
        Outcome::Undetermined(_) => EXIT_UNDETERMINED,
    }
}

fn verdict_text(outcome: &Outcome, digest: Option<&str>) -> String {
    let act = digest.unwrap_or("-");
    match outcome {
        Outcome::Valid(_) => format!("valid {act}\n"),
        Outcome::Invalid(f) => {
            let failed = if f.act.is_empty() || f.act == act {
                String::new()
            } else {
                format!(" ({})", f.act)
            };
            format!(
                "invalid {act}: step {}{failed}: {}\n",
                f.step.as_str(),
                f.reason
            )
        }
        Outcome::Undetermined(u) => {
            let mut out = format!("undetermined {act}: {}\n", u.reason);
            for d in &u.digests {
                out.push_str(&format!("unresolved {d}\n"));
            }
            out
        }
    }
}

/// The trust anchors (§5.1) from an allowed-signers file (ssh-keygen(1)
/// ALLOWED SIGNERS): every key on a line, whatever its principals and
/// options, spelled as a card act's `key`. A bare OpenSSH public key line or
/// a `piggy-piv_sig-v1@…` line counts too.
fn load_anchors(path: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading the anchors {}: {e}", path.display()))?;
    let mut anchors = std::collections::BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("piggy-piv_sig-v1@") {
            anchors.insert(line.to_owned());
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = tokens
            .iter()
            .position(|t| matches!(*t, "ssh-ed25519" | "ecdsa-sha2-nistp256"))
        else {
            return Err(format!(
                "{}:{}: no ssh-ed25519 or ecdsa-sha2-nistp256 key",
                path.display(),
                n + 1
            ));
        };
        let key = tokens[at..]
            .iter()
            .take(2)
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        anchors.insert(
            seal::key_id(&key, true).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?,
        );
    }
    if anchors.is_empty() {
        return Err(format!("{} names no trust anchor", path.display()));
    }
    Ok(anchors)
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

fn seal(file: Option<&Path>) -> Result<Vec<u8>, Failure> {
    // `piggy operator-sign` answers an unreadable input with 1, and 3 means
    // only "nothing serves the signature"; seal keeps that contract.
    let act = read_act(file).map_err(|f| Failure {
        exit: if f.exit == EXIT_INPUT {
            EXIT_REFUSED
        } else {
            f.exit
        },
        ..f
    })?;
    let as_failure = |e: SealError| Failure {
        exit: e.exit_code(),
        message: e.message().to_owned(),
    };

    // The act's own checks run before the socket is looked for, so an act
    // a verifier would refuse is refused the same way with or without an
    // agent, and never reaches a prompt.
    check_before_signing(&act).map_err(as_failure)?;
    let socket = crate::agent_client::piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()))
        .ok_or_else(|| {
            as_failure(SealError::NotServed(
                "no agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK".into(),
            ))
        })?;

    let sealed = seal_act(&act, Path::new(&socket)).map_err(as_failure)?;
    sealed.sealed_canonical().ok_or_else(|| Failure {
        exit: EXIT_REFUSED,
        message: "seal produced no signature".into(),
    })
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
