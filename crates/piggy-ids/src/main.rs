//! `piggy-ids` — internal helper binary used by `piggy.sh` to read,
//! write, validate, and encrypt against `piggy-ids` recipient files.
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
//!   * `detect-pubkey [--guid <hex>]` — read the attached PIV card's
//!     slot 9D pubkey, SEC1-compress, and emit a `piggy-recipient-v1@
//!     pivy_ecdh_p256_pub-…` markl ID on stdout. Drives the no-flags
//!     `piggy pass init` path (#79).
//!   * `detect-all-pubkeys` — enumerate every attached PIV card and
//!     emit one line per card, tab-separated:
//!     `supported<TAB><markl-id><TAB><guid-hex>` or
//!     `unsupported<TAB><guid-hex><TAB><reason>`. Tab is the field
//!     separator (not two spaces) so `reason` strings containing
//!     arbitrary whitespace (e.g. OpenSSL error stacks, free-form
//!     `PivError` messages) remain unambiguously parseable by downstream
//!     bash. Lines are sorted by GUID for stable output. Drives
//!     `piggy pass recipients add --all-attached`.
//!   * `list-available [--format human|ndjson]` — enumerate every
//!     populated recipient-eligible slot on every attached PIV card
//!     and emit one record per (card, slot) on stdout. The eligible
//!     slot set is 9D (key management) plus the retired key-management
//!     slots 0x82..=0x95. Empty/unreadable slots are skipped silently.
//!     Default format auto-selects based on TTY: human-readable when
//!     stdout is a TTY, NDJSON otherwise. Records carry the CHUID
//!     `guid`, the PCSC `reader`, the slot id (e.g. `9D`, `82`), and
//!     the YubiKey factory `serial` when the card is a YubiKey v5+
//!     (the vendor `INS_GET_SERIAL` extension). Non-YubiKey PIV cards
//!     simply omit `serial`. Unsupported slots (RSA, malformed cert,
//!     etc) are prefixed with `# unsupported:` in human mode and
//!     marked `"unsupported":true` in NDJSON mode. Drives
//!     `piggy pass recipients list-available`.
//!
//! Reachable from `piggy.sh` via the `PIGGY_IDS_PATH` env var that
//! `flake.nix`'s `makeWrapper` bakes into the user-facing `piggy`
//! binary. Not on the user-facing CLI surface (no `piggy ids …` —
//! the user-facing surface is `piggy pass recipients`).

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use piggy_box::recipients::template_from_recipients;
use piggy_box::stream::EboxStream;
use piggy_ids::RecipientFile;
use piggy_markl::Id as MarklId;
use piggy_piv::{Guid, PivContext, PivToken};

#[derive(Parser, Debug)]
#[command(name = "piggy-ids", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encrypt stdin to a piggy 2.x ebox stream on stdout. Recipients
    /// are read from the given piggy-ids file.
    Encrypt {
        /// Path to a piggy-ids file.
        ids: PathBuf,
    },
    /// Parse and validate a piggy-ids file. Exit 0 on success, 1 with
    /// a line-precise error on failure.
    Validate {
        /// Path to a piggy-ids file.
        ids: PathBuf,
    },
    /// Parse + render the file in place, promoting bare-format
    /// recipients to the canonical `piggy-recipient-v1@…` form.
    Canonicalize {
        /// Path to a piggy-ids file.
        ids: PathBuf,
    },
    /// Diff two piggy-ids files by markl ID. Exit 0 if equal, exit 1
    /// with `+ added` / `- removed` lines otherwise.
    Diff {
        /// Current state.
        current: PathBuf,
        /// Desired state.
        desired: PathBuf,
    },
    /// Read the attached PIV card's slot 9D pubkey and emit a
    /// piggy-recipient-v1 markl ID on stdout.
    DetectPubkey {
        /// Optional PIV card GUID (hex, 32 chars). Required when more
        /// than one PIV card is attached.
        #[arg(long)]
        guid: Option<String>,
    },
    /// Enumerate every attached PIV card and emit one line per card,
    /// tab-separated:
    ///
    ///   supported<TAB><markl-id><TAB><guid-hex>
    ///   unsupported<TAB><guid-hex><TAB><reason>
    ///
    /// Tab is the field separator (not two spaces) so reason strings
    /// containing arbitrary whitespace (e.g. OpenSSL error stacks,
    /// free-form PivError messages) remain unambiguously parseable.
    /// Lines are sorted by GUID for stable output. Exit 0 even when all
    /// cards are unsupported or no cards are attached; nonzero only on
    /// PCSC failure.
    DetectAllPubkeys,
    /// Enumerate every attached PIV card and emit one record per card
    /// suitable for `piggy pass recipients list-available`.
    ///
    /// Format auto-selects based on TTY: human-readable when stdout is
    /// a TTY, NDJSON otherwise. Pass --format to override.
    ///
    /// Lines are sorted by GUID for stable output. Exit 0 even when no
    /// cards are attached; nonzero only on PCSC failure.
    ListAvailable {
        /// Output format. Default: `human` when stdout is a TTY,
        /// `ndjson` otherwise.
        #[arg(long)]
        format: Option<ListFormat>,
    },
    /// Enumerate every populated PIV slot — both recipient-eligible
    /// slots (9D + retired 0x82..=0x95, same as `list-available`) and
    /// SSH-style slots (9A authentication, 9C signature, 9E card
    /// authentication) — and emit one record per (card, slot) on
    /// stdout. Recipient slots carry the `piggy-recipient-v1` markl
    /// purpose; SSH slots carry `piggy-piv_auth-v1`, `piggy-piv_sig-v1`,
    /// or `piggy-piv_card_auth-v1` per slot semantics.
    ///
    /// Same format/sort/skip-empty rules as `list-available`, plus a
    /// third `--format=ssh` mode that renders OpenSSH
    /// `authorized_keys`-style lines for SSH slots (9A/9C/9E) and
    /// suppresses every other slot entirely. Drives `piggy list`.
    ListAll {
        #[arg(long)]
        format: Option<ListFormat>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum ListFormat {
    Human,
    Ndjson,
    /// OpenSSH `authorized_keys`-style output: one
    /// `<keytype> <base64> piggy slot=<id> guid=<hex> [cn=<name>]`
    /// line per supported SSH-style slot (9A/9C/9E), where `<keytype>`
    /// is `ecdsa-sha2-nistp256` or `ssh-ed25519` (#86). Every other
    /// slot — recipient slots (9D + retired 0x82..=0x95), unsupported
    /// keys (RSA, P-384), attestation failures — is suppressed
    /// entirely, so the output is a strict `authorized_keys`-compatible
    /// feed of SSH-capable keys. Re-run with `--format=human` to
    /// enumerate every slot. Rejected by `list-available`. Drives
    /// `piggy list --format=ssh`.
    Ssh,
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
        Cmd::DetectPubkey { guid } => cmd_detect_pubkey(guid.as_deref()),
        Cmd::DetectAllPubkeys => cmd_detect_all_pubkeys(),
        Cmd::ListAvailable { format } => cmd_list_available(format),
        Cmd::ListAll { format } => cmd_list_all(format),
    }
}

fn read_recipient_file(path: &Path) -> Result<RecipientFile, DynErr> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let file =
        RecipientFile::parse(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
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
    fs::write(&tmp, rendered.as_bytes()).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
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
    let ids: Vec<MarklId> = file.recipients().iter().map(|r| r.id().clone()).collect();

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

/// Read slot 9D from the attached PIV card and emit the canonical
/// `piggy-recipient-v1@pivy_ecdh_p256_pub-…` markl ID. When more than
/// one PIV card is attached, callers must pass the desired GUID via
/// `--guid <hex>`.
fn cmd_detect_pubkey(guid_hex: Option<&str>) -> Result<ExitCode, DynErr> {
    use piggy_ids::{Classification, ClassifyInput, classify_slot};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;
    if tokens.is_empty() {
        return Err("no PIV cards detected".into());
    }

    let token = pick_token(&tokens, guid_hex)?;
    let slot = token.read_slot(0x9D)?;
    match classify_slot(ClassifyInput {
        slot_id: 0x9D,
        guid: token.guid().clone(),
        reader: token.reader_name().to_string(),
        serial: token.yk_serial(),
        algo: slot.algorithm(),
        cert_der: slot.cert_der(),
        // detect-pubkey doesn't surface PIN/touch policy.
        pin_policy: None,
        touch_policy: None,
    }) {
        Classification::Supported { id, .. } => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            writeln!(out, "{}", id)?;
            Ok(ExitCode::SUCCESS)
        }
        Classification::Unsupported { reason, .. } => Err(reason.into()),
    }
}

fn pick_token<'a>(tokens: &'a [PivToken], guid_hex: Option<&str>) -> Result<&'a PivToken, DynErr> {
    match guid_hex {
        Some(hex) => {
            let want = Guid::from_hex(hex)?;
            tokens
                .iter()
                .find(|t| t.guid() == &want)
                .ok_or_else(|| format!("no PIV card with GUID {hex} attached").into())
        }
        None => {
            if tokens.len() > 1 {
                let attached = tokens
                    .iter()
                    .map(|t| t.guid().to_hex())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "{} PIV cards attached; pass --guid <hex> to disambiguate (attached: {})",
                    tokens.len(),
                    attached
                )
                .into());
            }
            Ok(&tokens[0])
        }
    }
}

/// Enumerate every attached PIV card and return one `Classification`
/// per card for slot 9D, sorted by GUID hex for stable output. Used by
/// `detect-all-pubkeys` (bash-friendly TSV); always emits exactly one
/// row per card so unreadable 9D appears as `Unsupported` rather than
/// being silently dropped.
fn enumerate_and_classify() -> Result<Vec<piggy_ids::Classification>, DynErr> {
    use piggy_ids::{Classification, ClassifyInput, classify_slot};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;

    let mut classifications: Vec<Classification> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let reader = token.reader_name().to_string();
        let serial = token.yk_serial();
        match token.read_slot(0x9D) {
            // detect-all-pubkeys is the bash-friendly TSV path; it
            // doesn't surface PIN/touch policy, so skip the
            // attestation round-trip entirely.
            Ok(slot) => classifications.push(classify_slot(ClassifyInput {
                slot_id: 0x9D,
                guid: token.guid().clone(),
                reader,
                serial,
                algo: slot.algorithm(),
                cert_der: slot.cert_der(),
                pin_policy: None,
                touch_policy: None,
            })),
            Err(e) => classifications.push(Classification::Unsupported {
                guid: token.guid().clone(),
                reader,
                serial,
                slot_id: 0x9D,
                cn: None,
                pin_policy: None,
                touch_policy: None,
                reason: format!("slot 9D unreadable: {e}"),
            }),
        }
    }

    classifications.sort_by_key(|c| c.guid().to_hex());
    Ok(classifications)
}

/// Slots that may legitimately hold a P-256 ECDH key usable as a piggy
/// recipient: slot 9D (key management) plus retired key-management
/// slots 0x82..=0x95. Slots 9A (auth), 9C (signature), and 9E (card
/// auth) are excluded — they are not key-management slots per the
/// NIST 800-73 PIV model.
fn recipient_eligible_slots() -> Vec<u8> {
    let mut slots = Vec::with_capacity(1 + (0x95 - 0x82 + 1));
    slots.push(0x9D);
    for slot_id in 0x82..=0x95_u8 {
        slots.push(slot_id);
    }
    slots
}

/// Sort key that puts non-retired slots (9A, 9C, 9D, 9E) before retired
/// key-management slots (0x82..=0x95), preserving slot-id order within
/// each group. The leading 0/1 tier is what flips retired to the bottom
/// even though `0x82` < `0x9A` numerically.
fn slot_sort_key(slot_id: u8) -> (u8, u8) {
    let retired = (0x82..=0x95).contains(&slot_id);
    (retired as u8, slot_id)
}

/// Enumerate every attached PIV card and emit one `Classification` per
/// populated recipient-eligible slot. Skip empty/unreadable slots
/// silently — a card with only a populated 9D produces one row, a card
/// with both 9D and 82 populated produces two. Sort by (guid_hex,
/// slot_id) for stable output.
///
/// For each populated slot we also issue an INS_ATTEST round-trip to
/// recover the slot's configured PIN and touch policies. Attestation
/// is best-effort: non-YubiKey cards, YubiKeys with the F9 attestation
/// key cleared, and pre-4.3 firmware all return errors that the caller
/// treats as "policy unknown" (`None`) rather than failing the whole
/// enumeration.
fn enumerate_all_recipient_slots() -> Result<Vec<piggy_ids::Classification>, DynErr> {
    use piggy_ids::{Classification, ClassifyInput, classify_slot};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;

    let slots = recipient_eligible_slots();
    let mut classifications: Vec<Classification> = Vec::new();
    for token in &tokens {
        let reader = token.reader_name().to_string();
        let serial = token.yk_serial();
        for &slot_id in &slots {
            let slot = match token.read_slot(slot_id) {
                Ok(s) => s,
                // Empty/unreadable slots are not an error in
                // list-available's contract — skip silently.
                Err(_) => continue,
            };
            let (pin_policy, touch_policy) = match token.read_slot_policy(slot_id) {
                Ok((p, t)) => (Some(p), Some(t)),
                Err(_) => (None, None),
            };
            classifications.push(classify_slot(ClassifyInput {
                slot_id,
                guid: token.guid().clone(),
                reader: reader.clone(),
                serial,
                algo: slot.algorithm(),
                cert_der: slot.cert_der(),
                pin_policy,
                touch_policy,
            }));
        }
    }

    classifications.sort_by(|a, b| {
        a.guid()
            .to_hex()
            .cmp(&b.guid().to_hex())
            .then_with(|| slot_sort_key(a.slot_id()).cmp(&slot_sort_key(b.slot_id())))
    });
    Ok(classifications)
}

/// Enumerate every attached PIV card, classify each card's slot 9D, and
/// emit one line per card on stdout, sorted by GUID hex for stable
/// output. Exit 0 even when all cards are unsupported or no cards are
/// attached; nonzero only on PCSC failure.
fn cmd_detect_all_pubkeys() -> Result<ExitCode, DynErr> {
    use piggy_ids::Classification;

    let classifications = enumerate_and_classify()?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for c in &classifications {
        match c {
            Classification::Supported { id, guid, .. } => {
                writeln!(out, "supported\t{}\t{}", id, guid.to_hex())?;
            }
            Classification::Unsupported { guid, reason, .. } => {
                writeln!(out, "unsupported\t{}\t{}", guid.to_hex(), reason)?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// SSH-style slots (9A authentication, 9C signature, 9E card
/// authentication). Distinct from recipient-eligible slots (9D + retired
/// 0x82..=0x95) — each set gets its own enumerator + classifier so the
/// markl purpose attached to each record matches the slot's intended
/// semantic role.
fn ssh_eligible_slots() -> &'static [u8] {
    &[0x9A, 0x9C, 0x9E]
}

/// Enumerate every populated slot across all attached cards:
///   * 9D + retired 0x82..=0x95 → `classify_slot` (recipient purpose)
///   * 9A, 9C, 9E              → `classify_ssh_slot` (per-slot SSH purpose)
///
/// Empty/unreadable slots are skipped silently. Sort by (guid_hex,
/// slot_id) for stable output. Each populated slot incurs one
/// INS_ATTEST round-trip to recover PIN/touch policies; non-YubiKey
/// cards and YubiKeys with the F9 attestation key cleared get `None`
/// policies (graceful degradation, same as `enumerate_all_recipient_slots`).
fn enumerate_all_slots() -> Result<Vec<piggy_ids::Classification>, DynErr> {
    use piggy_ids::{Classification, ClassifyInput, classify_slot, classify_ssh_slot};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;

    let recipient_slots = recipient_eligible_slots();
    let ssh_slots = ssh_eligible_slots();

    let mut classifications: Vec<Classification> = Vec::new();
    for token in &tokens {
        let reader = token.reader_name().to_string();
        let serial = token.yk_serial();

        for &slot_id in recipient_slots.iter().chain(ssh_slots.iter()) {
            let slot = match token.read_slot(slot_id) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (pin_policy, touch_policy) = match token.read_slot_policy(slot_id) {
                Ok((p, t)) => (Some(p), Some(t)),
                Err(_) => (None, None),
            };
            let input = ClassifyInput {
                slot_id,
                guid: token.guid().clone(),
                reader: reader.clone(),
                serial,
                algo: slot.algorithm(),
                cert_der: slot.cert_der(),
                pin_policy,
                touch_policy,
            };
            let classification = if ssh_slots.contains(&slot_id) {
                classify_ssh_slot(input)
            } else {
                classify_slot(input)
            };
            classifications.push(classification);
        }
    }

    classifications.sort_by(|a, b| {
        a.guid()
            .to_hex()
            .cmp(&b.guid().to_hex())
            .then_with(|| slot_sort_key(a.slot_id()).cmp(&slot_sort_key(b.slot_id())))
    });
    Ok(classifications)
}

/// User-facing full-slot list. Same output shape as `cmd_list_available`
/// but covers 9A/9C/9E in addition to recipient slots. Drives
/// `piggy list`.
fn cmd_list_all(format: Option<ListFormat>) -> Result<ExitCode, DynErr> {
    let classifications = enumerate_all_slots()?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let effective_format = format.unwrap_or_else(|| {
        if io::stdout().is_terminal() {
            ListFormat::Human
        } else {
            ListFormat::Ndjson
        }
    });

    for c in &classifications {
        let line = match effective_format {
            ListFormat::Human => Some(format_human(c)),
            ListFormat::Ndjson => Some(format_ndjson(c)),
            ListFormat::Ssh => format_ssh(c),
        };
        if let Some(line) = line {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// User-facing recipient list. Default format follows stdout's TTY
/// status — human-readable when interactive, NDJSON when piped — so
/// `piggy pass recipients list-available | xargs piggy pass
/// recipients add ...` Just Works.
fn cmd_list_available(format: Option<ListFormat>) -> Result<ExitCode, DynErr> {
    // `list-available` only enumerates ECDH recipient slots, which by
    // design have no `authorized_keys`-style representation. Rather
    // than emit a file of all-`#`-comment lines, refuse loudly so the
    // caller knows to switch to `piggy list --format=ssh`.
    if format == Some(ListFormat::Ssh) {
        return Err("--format=ssh is only supported by `piggy list` \
            (list-all); recipient slots have no authorized_keys-style \
            representation"
            .into());
    }

    let classifications = enumerate_all_recipient_slots()?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let effective_format = format.unwrap_or_else(|| {
        if io::stdout().is_terminal() {
            ListFormat::Human
        } else {
            ListFormat::Ndjson
        }
    });

    for c in &classifications {
        let line = match effective_format {
            ListFormat::Human => format_human(c),
            ListFormat::Ndjson => format_ndjson(c),
            ListFormat::Ssh => unreachable!("rejected at function entry"),
        };
        writeln!(out, "{line}")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Render a `Classification` as a single human-readable line. Supported
/// cards print the markl ID followed by a `# guid=..., serial=...,
/// reader=..., slot=<id>[, cn=<name>][, pin=<policy>, touch=<policy>]`
/// comment (with `serial=`, `cn=`, `pin=`, and `touch=` omitted when
/// the source doesn't carry them — non-YubiKey cards have no policies
/// and a few older firmware revisions block attestation). Unsupported
/// slots are commented out entirely so the output round-trips through
/// `xargs piggy pass recipients add` without picking up rejected
/// entries.
fn format_human(c: &piggy_ids::Classification) -> String {
    use piggy_ids::Classification;
    match c {
        Classification::Supported {
            id,
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
        } => format!(
            "{}  # {}",
            id,
            human_metadata(
                guid,
                *serial,
                reader,
                *slot_id,
                cn.as_deref(),
                *pin_policy,
                *touch_policy,
            ),
        ),
        Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            reason,
        } => format!(
            "# unsupported: {}, reason={}",
            human_metadata(
                guid,
                *serial,
                reader,
                *slot_id,
                cn.as_deref(),
                *pin_policy,
                *touch_policy,
            ),
            reason,
        ),
    }
}

fn human_metadata(
    guid: &piggy_piv::Guid,
    serial: Option<u32>,
    reader: &str,
    slot_id: u8,
    cn: Option<&str>,
    pin_policy: Option<piggy_piv::PinPolicy>,
    touch_policy: Option<piggy_piv::TouchPolicy>,
) -> String {
    let slot = piggy_ids::format_slot_id(slot_id);
    let serial_field = match serial {
        Some(s) => format!(", serial={}", s),
        None => String::new(),
    };
    let cn_field = match cn {
        Some(name) => format!(", cn={}", name),
        None => String::new(),
    };
    let pin_field = match pin_policy {
        Some(p) => format!(", pin={}", p),
        None => String::new(),
    };
    let touch_field = match touch_policy {
        Some(t) => format!(", touch={}", t),
        None => String::new(),
    };
    format!(
        "guid={}{}, reader={}, slot={}{}{}{}",
        guid.to_hex(),
        serial_field,
        reader,
        slot,
        cn_field,
        pin_field,
        touch_field,
    )
}

/// Render a `Classification` as a single NDJSON record. The `serial`
/// key is emitted as a JSON number (not a string) when present, and
/// omitted entirely when absent so consumers can write `record.serial
/// ?? null` cleanly. `slot` is the uppercase 2-digit hex slot id
/// (e.g. `"9D"`, `"82"`). The `cn`, `pin_policy`, and `touch_policy`
/// keys are omitted when the source doesn't carry them. Policy values
/// are the lowercase names accepted by `pivy-tool generate -i/-t`:
/// `default`, `never`, `once`, `always` (pin); `default`, `never`,
/// `always`, `cached` (touch).
fn format_ndjson(c: &piggy_ids::Classification) -> String {
    use piggy_ids::Classification;
    match c {
        Classification::Supported {
            id,
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
        } => {
            let serial_field = serial
                .map(|s| format!(",\"serial\":{}", s))
                .unwrap_or_default();
            let cn_field = cn
                .as_deref()
                .map(|n| format!(",\"cn\":{}", json_string(n)))
                .unwrap_or_default();
            let policy_fields = policy_ndjson_fields(*pin_policy, *touch_policy);
            format!(
                "{{\"id\":{},\"guid\":{}{},\"reader\":{},\"slot\":{}{}{}}}",
                json_string(&id.to_wire()),
                json_string(&guid.to_hex()),
                serial_field,
                json_string(reader),
                json_string(&piggy_ids::format_slot_id(*slot_id)),
                cn_field,
                policy_fields,
            )
        }
        Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            reason,
        } => {
            let serial_field = serial
                .map(|s| format!(",\"serial\":{}", s))
                .unwrap_or_default();
            let cn_field = cn
                .as_deref()
                .map(|n| format!(",\"cn\":{}", json_string(n)))
                .unwrap_or_default();
            let policy_fields = policy_ndjson_fields(*pin_policy, *touch_policy);
            format!(
                "{{\"unsupported\":true,\"guid\":{}{},\"reader\":{},\"slot\":{}{}{},\"reason\":{}}}",
                json_string(&guid.to_hex()),
                serial_field,
                json_string(reader),
                json_string(&piggy_ids::format_slot_id(*slot_id)),
                cn_field,
                policy_fields,
                json_string(reason),
            )
        }
    }
}

/// Render a `Classification` as a single OpenSSH `authorized_keys`-style
/// line, or `None` to suppress the line entirely.
///
/// Supported 9A/9C/9E slots become `<keytype> <b64> piggy slot=<id>
/// guid=<hex> [cn=<name>]` — `ecdsa-sha2-nistp256` for P-256 keys,
/// `ssh-ed25519` for Ed25519 keys (#86) — safe to pipe straight into a
/// remote `authorized_keys`. Every other slot returns `None`:
/// recipient slots (9D + retired 0x82..=0x95) have no
/// `authorized_keys`-style representation, unsupported classifications
/// (RSA, P-384, attestation failures) have no SSH wire form, and any
/// classification whose payload fails to render as its key type cannot
/// be safely emitted. Callers wanting to enumerate recipient and
/// unsupported slots should re-run with `--format=human` or
/// `--format=ndjson`.
fn format_ssh(c: &piggy_ids::Classification) -> Option<String> {
    use piggy_ids::Classification;
    use piggy_markl::FormatId;
    let Classification::Supported {
        id,
        guid,
        slot_id,
        cn,
        ..
    } = c
    else {
        return None;
    };
    if !is_ssh_slot(*slot_id) {
        return None;
    }
    let prefix = match id.format() {
        FormatId::SshEcdsaNistp256Pub => openssh_line_from_compressed_p256(id.data()).ok()?,
        FormatId::SshEd25519Pub => openssh_line_from_ed25519(id.data()),
        // A Supported SSH-slot record always carries one of the two
        // formats above; anything else has no SSH wire form.
        _ => return None,
    };
    let cn_field = cn
        .as_deref()
        .map(|n| format!(" cn={n}"))
        .unwrap_or_default();
    Some(format!(
        "{prefix} piggy slot={} guid={}{cn_field}",
        piggy_ids::format_slot_id(*slot_id),
        guid.to_hex(),
    ))
}

fn is_ssh_slot(slot_id: u8) -> bool {
    matches!(slot_id, 0x9A | 0x9C | 0x9E)
}

/// Decompress a 33-byte SEC1-compressed P-256 point and render the
/// `ecdsa-sha2-nistp256 <base64-blob>` half of an OpenSSH
/// `authorized_keys` line. The caller appends the trailing comment.
///
/// Uses openssl (already a direct dep) to decompress and
/// `piggy_box::agent_ext::ec_point_to_ssh_pubkey_blob` to frame the
/// SSH wire blob, so byte-for-byte output matches what `ssh-key`'s
/// `PublicKey::to_bytes` would produce for the same point —
/// verified by the parity test in `agent_ext::tests`.
fn openssh_line_from_compressed_p256(compressed: &[u8]) -> Result<String, DynErr> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint, PointConversionForm};
    use openssl::nid::Nid;
    use piggy_box::agent_ext::ec_point_to_ssh_pubkey_blob;
    use piggy_box::piv_box::EcCurve;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, compressed, &mut ctx)?;
    let uncompressed = point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let blob = ec_point_to_ssh_pubkey_blob(EcCurve::NistP256, &uncompressed);
    let b64 = openssl::base64::encode_block(&blob);
    Ok(format!("ecdsa-sha2-nistp256 {b64}"))
}

/// Render the `ssh-ed25519 <base64-blob>` half of an OpenSSH
/// `authorized_keys` line from a raw 32-byte Ed25519 key. The caller
/// appends the trailing comment. Infallible because the markl payload
/// is already the exact wire form (`ssh_ed25519_pub` is fixed at 32
/// raw bytes — no decompression step); framing parity with `ssh-key`
/// is pinned by `agent_ext`'s `blob_matches_ssh_key_crate_for_ed25519`.
fn openssh_line_from_ed25519(key: &[u8]) -> String {
    use piggy_box::agent_ext::ed25519_to_ssh_pubkey_blob;

    let blob = ed25519_to_ssh_pubkey_blob(key);
    let b64 = openssl::base64::encode_block(&blob);
    format!("ssh-ed25519 {b64}")
}

fn policy_ndjson_fields(
    pin: Option<piggy_piv::PinPolicy>,
    touch: Option<piggy_piv::TouchPolicy>,
) -> String {
    let mut out = String::new();
    if let Some(p) = pin {
        out.push_str(&format!(",\"pin_policy\":{}", json_string(p.as_str())));
    }
    if let Some(t) = touch {
        out.push_str(&format!(",\"touch_policy\":{}", json_string(t.as_str())));
    }
    out
}

/// JSON-encode a string with surrounding quotes. We do this by hand
/// rather than pulling in serde_json — output is small, escape rules
/// are RFC 8259-minimal, and avoiding the dep keeps `piggy-ids` slim.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        format_human, format_ndjson, format_ssh, json_string, openssh_line_from_compressed_p256,
        slot_sort_key,
    };
    use piggy_ids::Classification;
    use piggy_markl::{FormatId, Id as MarklId, PurposeId};
    use piggy_piv::{Guid, PinPolicy, TouchPolicy};

    #[test]
    fn json_string_quotes_basic_ascii() {
        assert_eq!(json_string("hello"), "\"hello\"");
    }

    #[test]
    fn json_string_escapes_quote_and_backslash() {
        assert_eq!(json_string("he said \"hi\""), "\"he said \\\"hi\\\"\"");
        assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn json_string_escapes_control_chars() {
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
        assert_eq!(json_string("a\tb"), "\"a\\tb\"");
        assert_eq!(json_string("a\x01b"), "\"a\\u0001b\"");
    }

    fn sample_supported(serial: Option<u32>) -> Classification {
        sample_supported_full(serial, 0x9D, None, None, None)
    }

    fn sample_supported_slot(serial: Option<u32>, slot_id: u8) -> Classification {
        sample_supported_full(serial, slot_id, None, None, None)
    }

    fn sample_supported_with_cn(cn: &str) -> Classification {
        sample_supported_full(None, 0x9D, Some(cn.into()), None, None)
    }

    fn sample_supported_with_policies(pin: PinPolicy, touch: TouchPolicy) -> Classification {
        sample_supported_full(None, 0x9D, None, Some(pin), Some(touch))
    }

    fn sample_supported_full(
        serial: Option<u32>,
        slot_id: u8,
        cn: Option<String>,
        pin_policy: Option<PinPolicy>,
        touch_policy: Option<TouchPolicy>,
    ) -> Classification {
        let id = MarklId::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            {
                let mut v = vec![0x03];
                v.extend(0u8..32);
                v
            },
        )
        .expect("valid recipient id");
        Classification::Supported {
            id,
            guid: Guid::from_hex("00112233445566778899aabbccddeeff").expect("valid hex"),
            reader: "Yubico YubiKey OTP+FIDO+CCID 00 00".into(),
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
        }
    }

    fn sample_unsupported(serial: Option<u32>) -> Classification {
        Classification::Unsupported {
            guid: Guid::from_hex("ffeeddccbbaa99887766554433221100").expect("valid hex"),
            reader: "Some Other Reader 00 00".into(),
            serial,
            slot_id: 0x9D,
            cn: None,
            pin_policy: None,
            touch_policy: None,
            reason: "slot 9D is Rsa2048".into(),
        }
    }

    #[test]
    fn format_human_includes_serial_when_present() {
        let line = format_human(&sample_supported(Some(12_345_678)));
        assert!(line.contains("serial=12345678"), "missing serial=: {line}");
        // Guid::to_hex emits uppercase; match the literal it produces.
        assert!(
            line.contains("guid=00112233445566778899AABBCCDDEEFF"),
            "guid not present: {line}"
        );
        assert!(line.contains("slot=9D"), "slot missing: {line}");
    }

    #[test]
    fn format_human_omits_serial_when_absent() {
        let line = format_human(&sample_supported(None));
        assert!(
            !line.contains("serial="),
            "expected no serial= when None: {line}"
        );
    }

    #[test]
    fn format_human_renders_retired_slot_id() {
        let line = format_human(&sample_supported_slot(None, 0x82));
        assert!(
            line.contains("slot=82"),
            "expected slot=82 in human output: {line}"
        );
    }

    #[test]
    fn format_human_includes_cn_when_present() {
        let line = format_human(&sample_supported_with_cn("piv-key-mgmt@TESTCARD"));
        assert!(
            line.contains("cn=piv-key-mgmt@TESTCARD"),
            "missing cn= field: {line}"
        );
    }

    #[test]
    fn format_human_omits_cn_when_absent() {
        let line = format_human(&sample_supported(None));
        assert!(
            !line.contains("cn="),
            "expected no cn= when CN is None: {line}"
        );
    }

    #[test]
    fn format_human_includes_policies_when_present() {
        let line = format_human(&sample_supported_with_policies(
            PinPolicy::Never,
            TouchPolicy::Never,
        ));
        assert!(line.contains(", pin=never"), "missing pin=never: {line}");
        assert!(
            line.contains(", touch=never"),
            "missing touch=never: {line}"
        );
    }

    #[test]
    fn format_human_omits_policies_when_absent() {
        let line = format_human(&sample_supported(None));
        assert!(!line.contains("pin="), "expected no pin= field: {line}");
        assert!(!line.contains("touch="), "expected no touch= field: {line}");
    }

    #[test]
    fn format_human_unsupported_is_comment_with_reason() {
        let line = format_human(&sample_unsupported(None));
        assert!(
            line.starts_with("# unsupported: "),
            "expected leading '# unsupported: ': {line}"
        );
        assert!(
            line.contains("reason=slot 9D is Rsa2048"),
            "missing reason: {line}"
        );
    }

    #[test]
    fn format_ndjson_emits_numeric_serial() {
        let line = format_ndjson(&sample_supported(Some(7_654_321)));
        // Numeric, not string: there should be `"serial":7654321` literally.
        assert!(
            line.contains("\"serial\":7654321"),
            "expected numeric serial field: {line}"
        );
    }

    #[test]
    fn format_ndjson_omits_serial_key_when_absent() {
        let line = format_ndjson(&sample_supported(None));
        assert!(
            !line.contains("\"serial\""),
            "expected no serial key when None: {line}"
        );
    }

    #[test]
    fn format_ndjson_emits_slot_id_for_retired_slot() {
        let line = format_ndjson(&sample_supported_slot(None, 0x83));
        assert!(
            line.contains("\"slot\":\"83\""),
            "expected slot=\"83\" in NDJSON: {line}"
        );
    }

    #[test]
    fn format_ndjson_emits_slot_id_for_9d() {
        let line = format_ndjson(&sample_supported_slot(None, 0x9D));
        assert!(
            line.contains("\"slot\":\"9D\""),
            "expected slot=\"9D\" in NDJSON: {line}"
        );
    }

    #[test]
    fn format_ndjson_includes_cn_when_present() {
        let line = format_ndjson(&sample_supported_with_cn("piv-key-mgmt@TESTCARD"));
        assert!(
            line.contains("\"cn\":\"piv-key-mgmt@TESTCARD\""),
            "missing cn key in NDJSON: {line}"
        );
    }

    #[test]
    fn format_ndjson_omits_cn_key_when_absent() {
        let line = format_ndjson(&sample_supported(None));
        assert!(
            !line.contains("\"cn\""),
            "expected no cn key when None: {line}"
        );
    }

    #[test]
    fn format_ndjson_escapes_cn_with_special_chars() {
        // CN with double-quote + backslash exercises json_string escaping.
        let line = format_ndjson(&sample_supported_with_cn("weird \"cn\"\\name"));
        assert!(
            line.contains("\"cn\":\"weird \\\"cn\\\"\\\\name\""),
            "expected escaped cn in NDJSON: {line}"
        );
    }

    #[test]
    fn format_ndjson_includes_policies_when_present() {
        let line = format_ndjson(&sample_supported_with_policies(
            PinPolicy::Once,
            TouchPolicy::Cached,
        ));
        assert!(
            line.contains("\"pin_policy\":\"once\""),
            "missing pin_policy in NDJSON: {line}"
        );
        assert!(
            line.contains("\"touch_policy\":\"cached\""),
            "missing touch_policy in NDJSON: {line}"
        );
    }

    #[test]
    fn format_ndjson_omits_policy_keys_when_absent() {
        let line = format_ndjson(&sample_supported(None));
        assert!(
            !line.contains("\"pin_policy\""),
            "expected no pin_policy key: {line}"
        );
        assert!(
            !line.contains("\"touch_policy\""),
            "expected no touch_policy key: {line}"
        );
    }

    #[test]
    fn format_ndjson_unsupported_marks_unsupported_true() {
        let line = format_ndjson(&sample_unsupported(Some(99)));
        assert!(
            line.contains("\"unsupported\":true"),
            "expected unsupported flag: {line}"
        );
        assert!(line.contains("\"serial\":99"), "serial dropped: {line}");
        assert!(
            line.contains("\"reason\":\"slot 9D is Rsa2048\""),
            "reason missing: {line}"
        );
    }

    #[test]
    fn slot_sort_key_groups_non_retired_before_retired() {
        // Direct comparison: 9A < 9D < 82 < 95 under the new key.
        // (Numerically 0x82 < 0x9A, so the only way 9A precedes 82 is
        // via the (non_retired, retired) tier.)
        let mut slots = [0x82_u8, 0x9A, 0x95, 0x9D, 0x83, 0x9C, 0x9E];
        slots.sort_by_key(|&s| slot_sort_key(s));
        assert_eq!(slots, [0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x83, 0x95]);
    }

    #[test]
    fn slot_sort_key_treats_full_retired_range_uniformly() {
        // Every slot in 0x82..=0x95 must land in the retired tier
        // (sort_key.0 == 1); every other slot must land in the
        // non-retired tier.
        for slot_id in 0x82_u8..=0x95 {
            assert_eq!(
                slot_sort_key(slot_id).0,
                1,
                "slot 0x{slot_id:02X} should be retired"
            );
        }
        for slot_id in [0x9A_u8, 0x9C, 0x9D, 0x9E] {
            assert_eq!(
                slot_sort_key(slot_id).0,
                0,
                "slot 0x{slot_id:02X} should be non-retired"
            );
        }
    }

    /// Generate a fresh on-curve P-256 keypair via openssl and return
    /// the SEC1 (compressed, uncompressed) byte forms of its public
    /// point. Used to seed `format_ssh` fixtures with payloads that
    /// `openssh_line_from_compressed_p256` can actually decompress.
    fn fresh_p256_point() -> (Vec<u8>, Vec<u8>) {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let compressed = key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::COMPRESSED,
                &mut ctx,
            )
            .unwrap();
        let uncompressed = key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);
        (compressed, uncompressed)
    }

    fn purpose_for_ssh_slot(slot_id: u8) -> PurposeId {
        match slot_id {
            0x9A => PurposeId::PiggyPivAuthV1,
            0x9C => PurposeId::PiggyPivSigV1,
            0x9E => PurposeId::PiggyPivCardAuthV1,
            other => panic!("not an SSH slot: 0x{other:02X}"),
        }
    }

    /// Build a `Classification::Supported` for an SSH-style slot
    /// (9A/9C/9E) backed by a real on-curve P-256 compressed point.
    /// Returns `(classification, compressed, uncompressed)` so the
    /// parity test can independently re-derive the expected SSH wire
    /// blob without re-extracting the point from the markl ID.
    fn sample_supported_ssh_with_point(
        slot_id: u8,
        cn: Option<&str>,
    ) -> (Classification, Vec<u8>, Vec<u8>) {
        let (compressed, uncompressed) = fresh_p256_point();
        let id = MarklId::new(
            Some(purpose_for_ssh_slot(slot_id)),
            FormatId::SshEcdsaNistp256Pub,
            compressed.clone(),
        )
        .expect("valid SSH-slot markl id");
        let classification = Classification::Supported {
            id,
            guid: Guid::from_hex("00112233445566778899aabbccddeeff").expect("valid hex"),
            reader: "Yubico YubiKey OTP+FIDO+CCID 00 00".into(),
            serial: Some(12_345_678),
            slot_id,
            cn: cn.map(str::to_string),
            pin_policy: None,
            touch_policy: None,
        };
        (classification, compressed, uncompressed)
    }

    #[test]
    fn format_ssh_emits_clean_authorized_keys_line_for_9a() {
        let (c, _, _) = sample_supported_ssh_with_point(0x9A, None);
        let line = format_ssh(&c).expect("9A is a supported SSH slot");
        assert!(
            line.starts_with("ecdsa-sha2-nistp256 "),
            "expected ecdsa keytype prefix: {line}"
        );
        assert!(
            line.contains(" piggy slot=9A guid=00112233445566778899AABBCCDDEEFF"),
            "expected piggy metadata after b64 blob: {line}"
        );
        assert!(
            !line.contains("cn="),
            "no cn provided, expected no cn= field: {line}"
        );
        // Must not start with `#` — recipient-comment shape would break
        // authorized_keys consumers.
        assert!(!line.starts_with('#'), "SSH-slot line is not a comment");
    }

    #[test]
    fn format_ssh_emits_clean_line_for_9c_and_9e() {
        for slot in [0x9C_u8, 0x9E] {
            let (c, _, _) = sample_supported_ssh_with_point(slot, None);
            let line = format_ssh(&c).unwrap_or_else(|| panic!("slot {slot:02X} produced None"));
            assert!(
                line.starts_with("ecdsa-sha2-nistp256 "),
                "slot {slot:02X}: missing keytype prefix: {line}"
            );
            assert!(
                line.contains(&format!(" piggy slot={slot:02X} ")),
                "slot {slot:02X}: missing piggy slot=… metadata: {line}"
            );
        }
    }

    #[test]
    fn format_ssh_includes_cn_when_present() {
        let (c, _, _) = sample_supported_ssh_with_point(0x9A, Some("user@host"));
        let line = format_ssh(&c).expect("supported");
        assert!(
            line.ends_with(" cn=user@host"),
            "expected trailing cn=user@host: {line}"
        );
    }

    #[test]
    fn format_ssh_blob_matches_independent_encode() {
        // Parity check: the b64 segment of `format_ssh`'s output must
        // equal base64(ec_point_to_ssh_pubkey_blob(P256, uncompressed))
        // computed independently from the same point. Catches drift in
        // either the wire framing or the base64 step.
        let (c, _, uncompressed) = sample_supported_ssh_with_point(0x9A, None);
        let line = format_ssh(&c).expect("supported");

        let expected_blob = piggy_box::agent_ext::ec_point_to_ssh_pubkey_blob(
            piggy_box::piv_box::EcCurve::NistP256,
            &uncompressed,
        );
        let expected_b64 = openssl::base64::encode_block(&expected_blob);
        let expected_prefix = format!("ecdsa-sha2-nistp256 {expected_b64}");
        assert!(
            line.starts_with(&expected_prefix),
            "format_ssh blob diverged from independent encode\n  got:      {line}\n  expected: {expected_prefix} …"
        );
    }

    #[test]
    fn format_ssh_recipient_slot_9d_returns_none() {
        // 9D carries `PivyEcdhP256Pub` (recipient format) — it has no
        // `authorized_keys`-style representation, so --format=ssh
        // suppresses it entirely. Use --format=human to enumerate.
        let c = sample_supported_slot(None, 0x9D);
        assert!(
            format_ssh(&c).is_none(),
            "recipient slot must suppress the line entirely under --format=ssh"
        );
    }

    #[test]
    fn format_ssh_retired_recipient_slot_returns_none() {
        // Retired key-management slots (0x82..=0x95) are recipient
        // slots too — same suppression as 9D.
        let c = sample_supported_slot(None, 0x82);
        assert!(
            format_ssh(&c).is_none(),
            "retired recipient slot must suppress the line entirely under --format=ssh"
        );
    }

    #[test]
    fn format_ssh_unsupported_returns_none() {
        // Unsupported classifications drop out of --format=ssh
        // entirely (no `# unsupported:` comment, unlike --format=human).
        let c = sample_unsupported(None);
        assert!(
            format_ssh(&c).is_none(),
            "unsupported slot must suppress the line entirely"
        );
    }

    #[test]
    fn format_ssh_off_curve_payload_returns_none() {
        // If the markl payload happens not to decompress as a valid
        // P-256 point (e.g. corrupt cert data sneaks through), we
        // suppress the line rather than panic.
        //
        // 0x05 is not a valid SEC1 leading byte — valid compressed
        // points start with 0x02 or 0x03 (and uncompressed with 0x04,
        // hybrid with 0x06/0x07). Openssl rejects this at the prefix
        // check, so we don't have to worry about the trailing 32 bytes
        // accidentally landing on the curve.
        let mut bogus = vec![0x05_u8];
        bogus.extend(0u8..32);
        assert!(
            openssh_line_from_compressed_p256(&bogus).is_err(),
            "invalid SEC1 prefix must not decode as a P-256 point"
        );

        // And the wrapping format_ssh must absorb that error and
        // suppress the line entirely rather than emit a malformed
        // `ecdsa-sha2-nistp256 …` entry. MarklId::new accepts any
        // 33-byte payload — curve validation lives in
        // openssh_line_from_compressed_p256, not in markl.
        let bogus_id = MarklId::new(
            Some(PurposeId::PiggyPivAuthV1),
            FormatId::SshEcdsaNistp256Pub,
            bogus,
        )
        .expect("markl-level payload size is the only constraint");
        let c = Classification::Supported {
            id: bogus_id,
            guid: Guid::from_hex("00112233445566778899aabbccddeeff").unwrap(),
            reader: "Test Reader".into(),
            serial: None,
            slot_id: 0x9A,
            cn: None,
            pin_policy: None,
            touch_policy: None,
        };
        assert!(
            format_ssh(&c).is_none(),
            "format_ssh must suppress lines whose payload fails decompression"
        );
    }

    /// Build a `Classification::Supported` for an SSH-style slot
    /// (9A/9C/9E) carrying a raw 32-byte Ed25519 key (#86). Returns
    /// `(classification, raw_key)` so tests can independently re-derive
    /// the expected SSH wire blob.
    fn sample_supported_ssh_ed25519(slot_id: u8, cn: Option<&str>) -> (Classification, Vec<u8>) {
        let key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(11).wrapping_add(5)).collect();
        let id = MarklId::new(
            Some(purpose_for_ssh_slot(slot_id)),
            FormatId::SshEd25519Pub,
            key.clone(),
        )
        .expect("valid Ed25519 SSH-slot markl id");
        let classification = Classification::Supported {
            id,
            guid: Guid::from_hex("00112233445566778899aabbccddeeff").expect("valid hex"),
            reader: "Yubico YubiKey OTP+FIDO+CCID 00 00".into(),
            serial: Some(12_345_678),
            slot_id,
            cn: cn.map(str::to_string),
            pin_policy: None,
            touch_policy: None,
        };
        (classification, key)
    }

    #[test]
    fn format_ssh_emits_ssh_ed25519_line() {
        let (c, key) = sample_supported_ssh_ed25519(0x9A, Some("user@host"));
        let line = format_ssh(&c).expect("Ed25519 9A is a supported SSH slot");
        assert!(
            line.starts_with("ssh-ed25519 "),
            "expected ssh-ed25519 keytype prefix: {line}"
        );
        assert!(
            line.contains(" piggy slot=9A guid=00112233445566778899AABBCCDDEEFF"),
            "expected piggy metadata after b64 blob: {line}"
        );
        assert!(
            line.ends_with(" cn=user@host"),
            "expected trailing cn=user@host: {line}"
        );

        // Parity: the b64 segment must equal an independently framed
        // ssh-ed25519 blob over the same raw key, and the blob's tail
        // must decode back to that key.
        let expected_blob = piggy_box::agent_ext::ed25519_to_ssh_pubkey_blob(&key);
        let expected_b64 = openssl::base64::encode_block(&expected_blob);
        assert!(
            line.starts_with(&format!("ssh-ed25519 {expected_b64}")),
            "format_ssh blob diverged from independent encode: {line}"
        );
        // string("ssh-ed25519"): 4 + 11; string(key): 4 + 32.
        assert_eq!(expected_blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(&expected_blob[expected_blob.len() - 32..], &key[..]);
    }

    #[test]
    fn openssh_line_from_compressed_p256_round_trips_through_ssh_wire_format() {
        // Sanity: feed a real compressed point in, get a parseable SSH
        // line out whose b64 body decodes back to a structurally-valid
        // sshkey blob (`string(keytype) | string(curve) | string(point)`)
        // with the original 65-byte uncompressed point as the third
        // string.
        let (compressed, uncompressed) = fresh_p256_point();
        let line = openssh_line_from_compressed_p256(&compressed).expect("on-curve");
        let mut parts = line.splitn(2, ' ');
        let keytype = parts.next().expect("keytype");
        let b64 = parts.next().expect("b64 body");
        assert_eq!(keytype, "ecdsa-sha2-nistp256");
        let blob = openssl::base64::decode_block(b64).expect("valid base64");
        // string(keytype): 4 + 19; string(curve): 4 + 8; string(point): 4 + 65.
        assert_eq!(blob.len(), 4 + 19 + 4 + 8 + 4 + 65);
        // Third string is the uncompressed point; tail of the blob.
        let point_tail = &blob[blob.len() - 65..];
        assert_eq!(point_tail, &uncompressed[..]);
    }
}
