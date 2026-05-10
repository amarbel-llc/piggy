//! `piggy-ids` — internal helper binary used by `piggy.sh` to read,
//! write, validate, and encrypt against `.piggy-ids` recipient files.
//!
//! Subcommands:
//!   * `encrypt <piggy-ids-file>` — stdin → ebox stream → stdout, using
//!     the recipients listed in the file as the encrypt template.
//!   * `validate <piggy-ids-file>` — exit 0 if the file parses; exit
//!     nonzero with a line-precise stderr error otherwise.
//!   * `canonicalize <piggy-ids-file>` — parse + render in place;
//!     promotes bare-format recipients to the purpose-tagged form.
//!   * `diff <current> <desired>` — exit 0 if equal, exit 1 with `+/-`
//!     output on stdout otherwise. Used by `piggy pass recipients sync`
//!     for its idempotency check.
//!
//! Reachable from `piggy.sh` via the `PIGGY_IDS_PATH` env var that
//! `flake.nix`'s `makeWrapper` bakes into the user-facing `piggy`
//! binary. Not on the user-facing CLI surface (no `piggy ids …` —
//! the user-facing surface is `piggy pass recipients`).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use piggy_box::recipients::template_from_recipients;
use piggy_box::stream::EboxStream;
use piggy_ids::RecipientFile;
use piggy_markl::Id as MarklId;

#[derive(Parser, Debug)]
#[command(name = "piggy-ids", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encrypt stdin to a piggy 2.x ebox stream on stdout. Recipients
    /// are read from the given .piggy-ids file.
    Encrypt {
        /// Path to a .piggy-ids file.
        ids: PathBuf,
    },
    /// Parse and validate a .piggy-ids file. Exit 0 on success, 1 with
    /// a line-precise error on failure.
    Validate {
        /// Path to a .piggy-ids file.
        ids: PathBuf,
    },
    /// Parse + render the file in place, promoting bare-format
    /// recipients to the canonical `piggy-recipient-v1@…` form.
    Canonicalize {
        /// Path to a .piggy-ids file.
        ids: PathBuf,
    },
    /// Diff two .piggy-ids files by markl ID. Exit 0 if equal, exit 1
    /// with `+ added` / `- removed` lines otherwise.
    Diff {
        /// Current state.
        current: PathBuf,
        /// Desired state.
        desired: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piggy-ids: {e}");
            ExitCode::from(1)
        }
    }
}

type DynErr = Box<dyn std::error::Error>;

fn dispatch(cli: Cli) -> Result<ExitCode, DynErr> {
    match cli.cmd {
        Cmd::Encrypt { ids } => cmd_encrypt(&ids),
        Cmd::Validate { ids } => cmd_validate(&ids),
        Cmd::Canonicalize { ids } => cmd_canonicalize(&ids),
        Cmd::Diff { current, desired } => cmd_diff(&current, &desired),
    }
}

fn read_recipient_file(path: &Path) -> Result<RecipientFile, DynErr> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    let file = RecipientFile::parse(&text)
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;
    Ok(file)
}

fn cmd_validate(path: &Path) -> Result<ExitCode, DynErr> {
    read_recipient_file(path)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_canonicalize(path: &Path) -> Result<ExitCode, DynErr> {
    let file = read_recipient_file(path)?;
    let rendered = file.render();
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, rendered.as_bytes())
        .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path)
        .map_err(|e| format!("renaming {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_diff(current: &Path, desired: &Path) -> Result<ExitCode, DynErr> {
    let cur = read_recipient_file(current)?;
    let des = read_recipient_file(desired)?;
    let d = cur.diff(&des);
    if d.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for r in &d.added {
        writeln!(out, "+ {}", r.id())?;
    }
    for r in &d.removed {
        writeln!(out, "- {}", r.id())?;
    }
    Ok(ExitCode::from(1))
}

fn cmd_encrypt(path: &Path) -> Result<ExitCode, DynErr> {
    let file = read_recipient_file(path)?;
    let ids: Vec<MarklId> = file
        .recipients()
        .iter()
        .map(|r| r.id().clone())
        .collect();

    let tpl = template_from_recipients(&ids)?;
    let stream = EboxStream::new(&tpl)?;

    let header = stream.to_bytes()?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(&header)?;

    let chunk_size = stream.chunk_size as usize;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut buf = vec![0u8; chunk_size];
    let mut seqnr: u32 = 0;
    loop {
        let mut filled = 0;
        while filled < chunk_size {
            match input.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        if filled == 0 {
            break;
        }
        let chunk = stream.encrypt_chunk(seqnr, &buf[..filled])?;
        out.write_all(&chunk)?;
        seqnr = seqnr.wrapping_add(1);
        if filled < chunk_size {
            break;
        }
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}
