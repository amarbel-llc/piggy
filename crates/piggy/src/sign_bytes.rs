//! `piggy sign-bytes` CLI — a thin wrapper over the shared signing core
//! ([`piggy::sign_core`]).
//!
//! Parses argv, reads the message from stdin, builds the interaction frontend
//! for the PIN prompt (RFC 0006 §6), signs via [`sign_message`], and writes the
//! signature to stdout. The signing pipeline itself — card selection by GUID,
//! the digest choice, the bounded PIN-prompt loop, and the DER→raw reframing —
//! lives in [`piggy::sign_core`] so the `piggy manage` `sign_bytes` JSON-RPC
//! method (piggy#201) shares exactly the same behavior. piggy applies NO
//! canonicalization: the caller controls the exact bytes. See piggy#190.
//!
//! Output framing (`--format`, default `raw`):
//! - `raw` — fixed-width `r‖s` (P-256 → 64 bytes, P-384 → 96).
//! - `der` — the card-native ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`.
//!
//! Card / PIN: `--guid` selects among attached cards (direct-PCSC, no agent);
//! the PIN comes from `-P/--pin` or, absent that, the selected `--frontend`
//! (tty askpass by default, or a JSON-RPC program over `--socket`).

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use piggy::card::frontend::select::{FrontendKind, build_frontend};
use piggy::card::protocol::Frontend;
use piggy::sign_core::{SigFormat, sign_message};

#[derive(Parser, Debug)]
#[command(
    name = "piggy sign-bytes",
    about = "Sign stdin with a PIV slot key; output the signature on stdout",
    disable_help_subcommand = true
)]
struct SignBytesCli {
    /// PIV signing slot: `9a` (authentication) or `9c` (signature).
    #[arg(long)]
    slot: String,
    /// GUID of the card to use (hex). Required when more than one card is
    /// attached; otherwise the single attached card is used.
    #[arg(long)]
    guid: Option<String>,
    /// Output framing for the signature.
    #[arg(long, value_enum, default_value_t = OutFormat::Raw)]
    format: OutFormat,
    /// PIN to authenticate with. When omitted, piggy prompts via the selected
    /// frontend (`--frontend`).
    #[arg(short = 'P', long = "pin")]
    pin: Option<String>,
    /// Interaction frontend for the PIN prompt (RFC 0006 §6): `tty` (default,
    /// askpass) or `jsonrpc` (an external program supplies the PIN over
    /// `--socket`). Ignored when `-P/--pin` is given.
    #[arg(long, value_enum, default_value_t = FrontendKind::Tty)]
    frontend: FrontendKind,
    /// `AF_UNIX` socket the JSON-RPC frontend listens on. Required (and only
    /// used) when `--frontend jsonrpc`.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutFormat {
    /// Fixed-width raw `r‖s` (P-256 → 64 bytes, P-384 → 96).
    Raw,
    /// Card-native ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
    Der,
}

impl From<OutFormat> for SigFormat {
    fn from(o: OutFormat) -> Self {
        match o {
            OutFormat::Raw => SigFormat::Raw,
            OutFormat::Der => SigFormat::Der,
        }
    }
}

/// Entry point: parse argv (clap prints help/errors and exits itself), then
/// run the signer. Returns the process exit code.
pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy sign-bytes".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match SignBytesCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    match execute(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy sign-bytes: {e}");
            1
        }
    }
}

fn execute(args: SignBytesCli) -> Result<(), String> {
    // Build the frontend before any card operation (RFC 0006 §6): a
    // `--frontend jsonrpc` without a usable `--socket` must fail fast. Skipped
    // when a fixed `-P` PIN short-circuits the prompt (no frontend needed).
    let mut frontend: Option<Box<dyn Frontend>> = match args.pin {
        Some(_) => None,
        None => Some(build_frontend(
            args.frontend,
            args.socket.as_deref(),
            "sign-bytes",
        )?),
    };

    let mut message = Vec::new();
    std::io::stdin()
        .read_to_end(&mut message)
        .map_err(|e| format!("read stdin: {e}"))?;

    let out = sign_message(
        &args.slot,
        args.guid.as_deref(),
        &message,
        args.format.into(),
        args.pin.as_deref(),
        frontend.as_deref_mut(),
    )
    .map_err(|e| e.to_string())?;

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&out)
        .map_err(|e| format!("write stdout: {e}"))?;
    stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The signing pipeline (slot parsing, card selection, PIN loop, reframing)
    // is unit-tested in `piggy::sign_core`; the PIN-prompt card-naming (#195)
    // lives in the shared `TtyFrontend`. These tests cover only the CLI surface.

    #[test]
    fn cli_requires_slot() {
        // No --slot → clap parse error (would exit(2) at runtime).
        let r = SignBytesCli::try_parse_from(["piggy sign-bytes"]);
        assert!(r.is_err());
    }

    #[test]
    fn cli_parses_full_arg_set() {
        let a = SignBytesCli::try_parse_from([
            "piggy sign-bytes",
            "--slot",
            "9a",
            "--guid",
            "DEADBEEF",
            "--format",
            "der",
            "-P",
            "123456",
        ])
        .unwrap();
        assert_eq!(a.slot, "9a");
        assert_eq!(a.guid.as_deref(), Some("DEADBEEF"));
        assert!(matches!(a.format, OutFormat::Der));
        assert_eq!(a.pin.as_deref(), Some("123456"));
        // --frontend defaults to tty.
        assert!(matches!(a.frontend, FrontendKind::Tty));
    }

    #[test]
    fn cli_parses_jsonrpc_frontend_and_socket() {
        let a = SignBytesCli::try_parse_from([
            "piggy sign-bytes",
            "--slot",
            "9a",
            "--frontend",
            "jsonrpc",
            "--socket",
            "/tmp/piggy-ui.sock",
        ])
        .unwrap();
        assert!(matches!(a.frontend, FrontendKind::Jsonrpc));
        assert_eq!(
            a.socket.as_deref(),
            Some(std::path::Path::new("/tmp/piggy-ui.sock"))
        );
    }

    #[test]
    fn cli_format_defaults_to_raw() {
        let a = SignBytesCli::try_parse_from(["piggy sign-bytes", "--slot", "9a"]).unwrap();
        assert!(matches!(a.format, OutFormat::Raw));
    }
}
