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
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ListFormat {
    Human,
    Ndjson,
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
    use piggy_ids::{classify_slot, Classification};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;
    if tokens.is_empty() {
        return Err("no PIV cards detected".into());
    }

    let token = pick_token(&tokens, guid_hex)?;
    let slot = token.read_slot(0x9D)?;
    match classify_slot(
        0x9D,
        token.guid().clone(),
        token.reader_name().to_string(),
        token.yk_serial(),
        slot.algorithm(),
        slot.cert_der(),
    ) {
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
    use piggy_ids::{classify_slot, Classification};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;

    let mut classifications: Vec<Classification> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let reader = token.reader_name().to_string();
        let serial = token.yk_serial();
        match token.read_slot(0x9D) {
            Ok(slot) => classifications.push(classify_slot(
                0x9D,
                token.guid().clone(),
                reader,
                serial,
                slot.algorithm(),
                slot.cert_der(),
            )),
            Err(e) => classifications.push(Classification::Unsupported {
                guid: token.guid().clone(),
                reader,
                serial,
                slot_id: 0x9D,
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

/// Enumerate every attached PIV card and emit one `Classification` per
/// populated recipient-eligible slot. Skip empty/unreadable slots
/// silently — a card with only a populated 9D produces one row, a card
/// with both 9D and 82 populated produces two. Sort by (guid_hex,
/// slot_id) for stable output.
fn enumerate_all_recipient_slots() -> Result<Vec<piggy_ids::Classification>, DynErr> {
    use piggy_ids::{classify_slot, Classification};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;

    let slots = recipient_eligible_slots();
    let mut classifications: Vec<Classification> = Vec::new();
    for token in &tokens {
        let reader = token.reader_name().to_string();
        let serial = token.yk_serial();
        for &slot_id in &slots {
            match token.read_slot(slot_id) {
                Ok(slot) => classifications.push(classify_slot(
                    slot_id,
                    token.guid().clone(),
                    reader.clone(),
                    serial,
                    slot.algorithm(),
                    slot.cert_der(),
                )),
                // Empty/unreadable slots are not an error in
                // list-available's contract — skip silently.
                Err(_) => continue,
            }
        }
    }

    classifications.sort_by(|a, b| {
        a.guid()
            .to_hex()
            .cmp(&b.guid().to_hex())
            .then_with(|| a.slot_id().cmp(&b.slot_id()))
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

/// User-facing recipient list. Default format follows stdout's TTY
/// status — human-readable when interactive, NDJSON when piped — so
/// `piggy pass recipients list-available | xargs piggy pass
/// recipients add ...` Just Works.
fn cmd_list_available(format: Option<ListFormat>) -> Result<ExitCode, DynErr> {
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
        };
        writeln!(out, "{line}")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Render a `Classification` as a single human-readable line. Supported
/// cards print the markl ID followed by a `# guid=..., serial=...,
/// reader=..., slot=<id>` comment (with `serial=` omitted when the card
/// has no YubiKey serial). Unsupported slots are commented out entirely
/// so the output round-trips through `xargs piggy pass recipients
/// add` without picking up rejected entries.
fn format_human(c: &piggy_ids::Classification) -> String {
    use piggy_ids::Classification;
    match c {
        Classification::Supported {
            id,
            guid,
            reader,
            serial,
            slot_id,
        } => format!(
            "{}  # {}",
            id,
            human_metadata(guid, *serial, reader, *slot_id),
        ),
        Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            reason,
        } => format!(
            "# unsupported: {}, reason={}",
            human_metadata(guid, *serial, reader, *slot_id),
            reason,
        ),
    }
}

fn human_metadata(
    guid: &piggy_piv::Guid,
    serial: Option<u32>,
    reader: &str,
    slot_id: u8,
) -> String {
    let slot = piggy_ids::format_slot_id(slot_id);
    match serial {
        Some(s) => format!(
            "guid={}, serial={}, reader={}, slot={}",
            guid.to_hex(),
            s,
            reader,
            slot,
        ),
        None => format!(
            "guid={}, reader={}, slot={}",
            guid.to_hex(),
            reader,
            slot,
        ),
    }
}

/// Render a `Classification` as a single NDJSON record. The `serial`
/// key is emitted as a JSON number (not a string) when present, and
/// omitted entirely when absent so consumers can write `record.serial
/// ?? null` cleanly. `slot` is the uppercase 2-digit hex slot id
/// (e.g. `"9D"`, `"82"`).
fn format_ndjson(c: &piggy_ids::Classification) -> String {
    use piggy_ids::Classification;
    match c {
        Classification::Supported {
            id,
            guid,
            reader,
            serial,
            slot_id,
        } => {
            let serial_field = serial
                .map(|s| format!(",\"serial\":{}", s))
                .unwrap_or_default();
            format!(
                "{{\"id\":{},\"guid\":{}{},\"reader\":{},\"slot\":{}}}",
                json_string(&id.to_wire()),
                json_string(&guid.to_hex()),
                serial_field,
                json_string(reader),
                json_string(&piggy_ids::format_slot_id(*slot_id)),
            )
        }
        Classification::Unsupported {
            guid,
            reader,
            serial,
            slot_id,
            reason,
        } => {
            let serial_field = serial
                .map(|s| format!(",\"serial\":{}", s))
                .unwrap_or_default();
            format!(
                "{{\"unsupported\":true,\"guid\":{}{},\"reader\":{},\"slot\":{},\"reason\":{}}}",
                json_string(&guid.to_hex()),
                serial_field,
                json_string(reader),
                json_string(&piggy_ids::format_slot_id(*slot_id)),
                json_string(reason),
            )
        }
    }
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
    use super::{format_human, format_ndjson, json_string};
    use piggy_ids::Classification;
    use piggy_markl::{FormatId, Id as MarklId, PurposeId};
    use piggy_piv::Guid;

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
        sample_supported_slot(serial, 0x9D)
    }

    fn sample_supported_slot(serial: Option<u32>, slot_id: u8) -> Classification {
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
        }
    }

    fn sample_unsupported(serial: Option<u32>) -> Classification {
        Classification::Unsupported {
            guid: Guid::from_hex("ffeeddccbbaa99887766554433221100").expect("valid hex"),
            reader: "Some Other Reader 00 00".into(),
            serial,
            slot_id: 0x9D,
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
}
