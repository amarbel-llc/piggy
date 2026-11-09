//! `piggy act` — the `piggy-act-v1` document verbs (piggy RFC 0013).
//!
//! `piggy act canon [FILE]` reads an act (stdin when FILE is absent or `-`)
//! and writes its canonical form (§3.1) to stdout: the bytes a producer
//! signs and the agent shows. A document that is not an act is refused on
//! stderr as `refused (<rule>): <detail>`, where the rule is the stable name
//! of the RFC rule it broke.
//!
//! Exit codes: 0 done; 1 refused; 2 usage; 3 the input could not be read.

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
}

const EXIT_REFUSED: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_INPUT: i32 = 3;

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

    match cli.cmd {
        ActCommand::Canon { file } => canon(file),
    }
}

fn canon(file: Option<PathBuf>) -> i32 {
    let input = match read_input(file.as_deref()) {
        Ok(input) => input,
        Err(message) => {
            eprintln!("piggy act canon: {message}");
            return EXIT_INPUT;
        }
    };

    match super::parse(&input) {
        Ok(act) => {
            let mut stdout = std::io::stdout().lock();
            if stdout
                .write_all(&act.canonical())
                .and_then(|()| stdout.flush())
                .is_err()
            {
                return EXIT_INPUT;
            }
            0
        }
        Err(refusal) => {
            eprintln!(
                "piggy act canon: refused ({}): {}",
                refusal.rule.as_str(),
                refusal.detail
            );
            EXIT_REFUSED
        }
    }
}

fn read_input(file: Option<&std::path::Path>) -> Result<Vec<u8>, String> {
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
