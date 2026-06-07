//! `piggy health` — agent/card/service checks emitting TAP-14 (tty) or
//! tap-ndjson(7) (non-tty). Design: docs/plans/2026-06-07-piggy-health-design.md.
//!
//! Split: probe phase (IO, `gather`) → pure `evaluate` → render via
//! `HealthSink`. All card operations are read-only (enumerate + cert
//! read); nothing here prompts for a PIN or decrypts.

use std::time::Duration;

/// Per-probe timeout. Tuning lever (design doc): change signal is false
/// `not ok` timeouts on slow readers/agents.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The extension piggy decrypts require. Built by concatenation so
/// editing tools cannot mangle the literal (see CLAUDE.md memory).
pub const ECDH_EXT: &str = concat!("ecdh@", "joyent.com");

/// Output format for `piggy health`, parsed straight from `--format`
/// (this is the clap `ValueEnum`; main.rs uses it directly rather than
/// mapping through a duplicate enum). `Auto` switches on whether stdout
/// is a tty: TAP-14 for humans, tap-ndjson(7) for pipes.
#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum Format {
    Auto,
    Tap,
    Ndjson,
}

pub enum Status {
    Pass,
    Fail,
    Skip(String),
}

pub struct CheckResult {
    pub name: &'static str,
    pub status: Status,
    /// Rendered as the YAML diagnostic block (TAP) / diagnostics map
    /// (ndjson). Failures always carry diags; passes only under -v.
    pub diags: Vec<(String, String)>,
}

/// systemd unit probe outcome (point 1).
pub enum ServiceProbe {
    /// Non-Linux, no systemctl on PATH, or systemctl itself errored —
    /// the reason string becomes the SKIP directive.
    NotAvailable(String),
    /// `LoadState=not-found`: no unit installed (manual agent setups).
    UnitNotFound,
    Unit {
        load_state: String,
        active_state: String,
        sub_state: String,
        exec_main_status: String,
    },
}

/// Socket resolution + stat outcome (points 2–3).
pub enum SocketProbe {
    /// Neither PIGGY_AUTH_SOCK nor SSH_AUTH_SOCK set non-empty.
    Unresolved,
    Resolved {
        source: &'static str, // "PIGGY_AUTH_SOCK" | "SSH_AUTH_SOCK"
        path: std::path::PathBuf,
        /// `true` = exists and is a unix socket; `false` = exists/missing
        /// but not a socket; carried diag explains.
        is_socket: bool,
        stat_detail: String,
    },
}

pub enum PcscProbe {
    Ok,
    Error(String),
}

/// One attached card's identity-relevant facts (points 7–8).
pub struct CardInfo {
    pub reader: String,
    pub guid: String,
    pub slot_9d_populated: bool,
}

/// Everything `evaluate` needs. `None` = probe not attempted because a
/// prerequisite failed (drives SKIP).
pub struct Probes {
    pub service: ServiceProbe,
    pub socket: SocketProbe,
    /// Ok(identity comments) — count = len; Err = connect/protocol error.
    pub agent: Option<Result<Vec<String>, String>>,
    /// Ok(extension names from the `query` extension); Err = query failed.
    pub extensions: Option<Result<Vec<String>, String>>,
    pub pcsc: PcscProbe,
    pub cards: Option<Vec<CardInfo>>,
}

/// Parse `systemctl show` key=value output into a [`ServiceProbe`].
/// Pure: no IO.
///
/// systemctl emits one `Key=Value` per line in no guaranteed order
/// (observed live: ExecMainStatus first). Missing Active/Sub/ExecMain
/// keys default to empty strings, but output carrying no `LoadState`
/// at all is not `systemctl show` output we understand — that maps to
/// `NotAvailable` rather than a bogus `Unit`, keeping SKIP as the
/// graceful-degradation path.
fn parse_systemctl_show(stdout: &str) -> ServiceProbe {
    let mut load_state: Option<&str> = None;
    let mut active_state = String::new();
    let mut sub_state = String::new();
    let mut exec_main_status = String::new();
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "LoadState" => load_state = Some(value),
            "ActiveState" => active_state = value.to_string(),
            "SubState" => sub_state = value.to_string(),
            "ExecMainStatus" => exec_main_status = value.to_string(),
            _ => {}
        }
    }
    match load_state {
        None => ServiceProbe::NotAvailable("unparseable systemctl output".into()),
        Some("not-found") => ServiceProbe::UnitNotFound,
        Some(load_state) => ServiceProbe::Unit {
            load_state: load_state.to_string(),
            active_state,
            sub_state,
            exec_main_status,
        },
    }
}

/// Run `systemctl --user show piggy-agent.service
/// --property=LoadState,ActiveState,SubState,ExecMainStatus`.
///
/// Thin IO shim over [`parse_systemctl_show`]: a spawn error IS the
/// which-style "no systemctl" failure (no PATH pre-check), and the
/// exit status is deliberately not gated on — `systemctl show` exits 0
/// even for inactive units and reports not-found via `LoadState`, so
/// any usable stdout is handed to the parser regardless. The exit
/// status only flavors the `NotAvailable` reason when stdout was
/// unusable (e.g. "Failed to connect to bus" on a session without a
/// user manager, which lands on stderr with a non-zero exit).
#[cfg(target_os = "linux")]
fn probe_service() -> ServiceProbe {
    let output = match std::process::Command::new("systemctl")
        .args([
            "--user",
            "show",
            "piggy-agent.service",
            "--property=LoadState,ActiveState,SubState,ExecMainStatus",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ServiceProbe::NotAvailable("systemctl not found".into());
        }
        Err(e) => return ServiceProbe::NotAvailable(format!("systemctl spawn failed: {e}")),
    };
    // Lossy UTF-8 is safe: invalid bytes in unit state names are
    // implausible, and the conservative parser maps any resulting
    // garbage to NotAvailable anyway.
    enrich_unparseable_with_exit(
        parse_systemctl_show(&String::from_utf8_lossy(&output.stdout)),
        output.status.success(),
        &output.status.to_string(),
        &output.stderr,
    )
}

/// When the parse degraded to NotAvailable and systemctl itself exited
/// non-zero, fold the exit status + stderr into the reason (covers the
/// "Failed to connect to bus" no-user-manager case). Pure: any other
/// probe — or a zero exit — passes through untouched.
fn enrich_unparseable_with_exit(
    probe: ServiceProbe,
    success: bool,
    exit_desc: &str,
    stderr: &[u8],
) -> ServiceProbe {
    match probe {
        ServiceProbe::NotAvailable(_) if !success => ServiceProbe::NotAvailable(format!(
            "systemctl failed ({exit_desc}): {}",
            String::from_utf8_lossy(stderr).trim()
        )),
        probe => probe,
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_service() -> ServiceProbe {
    ServiceProbe::NotAvailable("service check is Linux-only".into())
}

/// Resolve the agent socket for the health probe: `PIGGY_AUTH_SOCK`
/// (set non-empty, via the canonical
/// [`piggy::agent_client::piggy_auth_sock_override`] resolver) wins
/// over the ambient `SSH_AUTH_SOCK` (also only when set non-empty);
/// neither → [`SocketProbe::Unresolved`]. The resolved path is stat'd
/// immediately so points 2 and 3 come from one probe.
fn resolve_socket() -> SocketProbe {
    let (source, raw): (&'static str, std::ffi::OsString) =
        match piggy::agent_client::piggy_auth_sock_override() {
            Some(p) => ("PIGGY_AUTH_SOCK", p),
            None => match std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) {
                Some(p) => ("SSH_AUTH_SOCK", p),
                None => return SocketProbe::Unresolved,
            },
        };
    let path = std::path::PathBuf::from(raw);
    let (is_socket, stat_detail) = stat_socket_path(&path);
    SocketProbe::Resolved {
        source,
        path,
        is_socket,
        stat_detail,
    }
}

/// Stat `path` and decide whether it is a unix socket, with an
/// explanatory detail string for every outcome (missing path, wrong
/// file type, metadata error). Follows symlinks (`fs::metadata`): an
/// agent socket reached through a symlink still counts as a socket.
fn stat_socket_path(path: &std::path::Path) -> (bool, String) {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => (true, "unix socket".into()),
        Ok(meta) => (
            false,
            format!(
                "exists but is not a socket ({})",
                file_type_name(meta.file_type())
            ),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, "path does not exist".into()),
        Err(e) => (false, format!("stat failed: {e}")),
    }
}

/// Human name for a non-socket file type, for `stat_detail`.
fn file_type_name(ft: std::fs::FileType) -> &'static str {
    if ft.is_file() {
        "regular file"
    } else if ft.is_dir() {
        "directory"
    } else {
        "non-socket special file"
    }
}

/// Enumerate PIV cards read-only: pcsc context + token enumeration +
/// a 9D cert read per token. NO PIN, NO decrypt — `read_slot` is a
/// bare GET DATA on the slot's cert object
/// (`crates/piggy-piv/src/token.rs::PivToken::read_slot`, no
/// `verify_pin` on its path; cert objects are free-read per NIST SP
/// 800-73). An empty or unreadable 9D returns
/// `Err(PivError::SlotEmpty(0x9d))`, which maps to
/// `slot_9d_populated: false`.
///
/// Context establishment and enumeration failures both collapse to
/// `PcscProbe::Error` with `cards: None` — evaluate renders point 6
/// as the failure and SKIPs the card points.
fn probe_cards() -> (PcscProbe, Option<Vec<CardInfo>>) {
    let ctx = match piggy_piv::PivContext::new() {
        Ok(ctx) => ctx,
        Err(e) => return (PcscProbe::Error(e.to_string()), None),
    };
    let tokens = match ctx.enumerate_tokens() {
        Ok(tokens) => tokens,
        Err(e) => return (PcscProbe::Error(e.to_string()), None),
    };
    let cards = tokens
        .into_iter()
        .map(|t| CardInfo {
            reader: t.reader_name().to_string(),
            // Full uppercase hex, matching how the rest of the
            // codebase renders guids user-facing (Guid::to_hex).
            guid: t.guid().to_hex(),
            slot_9d_populated: t.read_slot(0x9d).is_ok(),
        })
        .collect();
    (PcscProbe::Ok, Some(cards))
}

/// Probe phase: run every probe defensively and short-circuit
/// dependents — the agent is contacted only when the socket resolved
/// AND stat'd as a real unix socket, and the `query` extension is sent
/// only when `request_identities` got an answer. Card probing is
/// independent of the agent-side chain.
pub fn gather() -> Probes {
    let service = probe_service();
    let socket = resolve_socket();
    let (agent, extensions) = match &socket {
        SocketProbe::Resolved {
            path,
            is_socket: true,
            ..
        } => {
            let ids = piggy::agent_client::probe_identities(path, PROBE_TIMEOUT);
            let exts = if ids.is_ok() {
                Some(piggy::agent_client::probe_extensions(path, PROBE_TIMEOUT))
            } else {
                None
            };
            (Some(ids), exts)
        }
        _ => (None, None),
    };
    let (pcsc, cards) = probe_cards();
    Probes {
        service,
        socket,
        agent,
        extensions,
        pcsc,
        cards,
    }
}

pub fn exit_code(results: &[CheckResult]) -> i32 {
    if results.iter().any(|r| matches!(r.status, Status::Fail)) {
        1
    } else {
        0
    }
}

/// `piggy health` entry point: [`gather`] → [`evaluate`] → render to
/// stdout via the format-selected [`HealthSink`] → [`exit_code`].
///
/// Exit code conventions (the render-error 2 mirrors `pass verify`):
/// - 0: no point failed (SKIPs count as ok)
/// - 1: at least one point is `not ok`
/// - 2: the report itself could not be rendered (stdout IO error)
pub fn run(format: Format, verbose: bool) -> i32 {
    use std::io::IsTerminal;

    let results = evaluate(&gather());
    let stdout = std::io::stdout();
    let rendered = match format {
        Format::Tap => TapSink::new(stdout.lock(), verbose).render(&results),
        Format::Ndjson => NdjsonSink::new(stdout.lock(), verbose).render(&results),
        Format::Auto if stdout.is_terminal() => {
            TapSink::auto(stdout.lock(), verbose).render(&results)
        }
        Format::Auto => NdjsonSink::new(stdout.lock(), verbose).render(&results),
    };
    if let Err(e) = rendered {
        eprintln!("piggy health: failed to render report: {e}");
        return 2;
    }
    exit_code(&results)
}

/// Render a full health run (the 9 [`CheckResult`]s from [`evaluate`])
/// to an output stream. Two implementations: [`TapSink`] (TAP-14 text,
/// tty) and [`NdjsonSink`] (tap-ndjson(7) records, non-tty / `--format
/// ndjson`).
pub trait HealthSink {
    fn render(&mut self, results: &[CheckResult]) -> std::io::Result<()>;
}

/// TAP-14 text sink. [`TapSink::new`] builds a plain (colorless,
/// locale-free) `tap_dancer::TapWriter` so the output is deterministic
/// — explicit `--format tap` stays byte-stable for scripts and tests.
/// [`TapSink::auto`] opts into `TapWriterBuilder::auto` (NO_COLOR-gated
/// color + env-derived locale pragma) for the interactive
/// `--format auto`-on-a-tty path, where presentation beats
/// determinism.
pub struct TapSink<W: std::io::Write> {
    w: W,
    verbose: bool,
    auto_style: bool,
}

impl<W: std::io::Write> TapSink<W> {
    pub fn new(w: W, verbose: bool) -> Self {
        Self {
            w,
            verbose,
            auto_style: false,
        }
    }

    /// Like [`TapSink::new`] but with `TapWriterBuilder::auto` styling
    /// (color unless NO_COLOR, locale pragma from LC_ALL/LC_NUMERIC/
    /// LANG). The builder never sniffs file descriptors itself — only
    /// call this when the caller has established the writer is a tty.
    pub fn auto(w: W, verbose: bool) -> Self {
        Self {
            w,
            verbose,
            auto_style: true,
        }
    }
}

impl<W: std::io::Write> HealthSink for TapSink<W> {
    fn render(&mut self, results: &[CheckResult]) -> std::io::Result<()> {
        let builder = if self.auto_style {
            tap_dancer::TapWriterBuilder::auto(&mut self.w)
        } else {
            tap_dancer::TapWriterBuilder::new(&mut self.w)
        };
        let mut rep = tap_dancer::Reporter::Tap(builder.build()?);
        render_into(&mut rep, results, self.verbose)
    }
}

/// tap-ndjson(7) sink: plan record, one test record per point (skip
/// reason as the directive, diags as the diagnostics map), and the
/// spec-mandatory trailing summary record.
pub struct NdjsonSink<W: std::io::Write> {
    w: W,
    verbose: bool,
}

impl<W: std::io::Write> NdjsonSink<W> {
    pub fn new(w: W, verbose: bool) -> Self {
        Self { w, verbose }
    }
}

impl<W: std::io::Write> HealthSink for NdjsonSink<W> {
    fn render(&mut self, results: &[CheckResult]) -> std::io::Result<()> {
        let mut rep = tap_dancer::Reporter::Ndjson(tap_dancer::NdjsonWriter::new(&mut self.w));
        render_into(&mut rep, results, self.verbose)
    }
}

/// Shared point-emission loop over tap-dancer's format-dispatching
/// `Reporter`. Failures always carry their diag block; passes only
/// under verbose (the [`CheckResult::diags`] contract). Diag values
/// pass through as JSON strings deliberately — `CheckResult` diags are
/// `(String, String)` by contract and sniffing `"0"` into the integer
/// `0` would silently change the ndjson type surface; out of scope.
///
/// Skips: tap-dancer's `skip(desc, reason)` carries no diagnostics, so
/// a Skip's diags are not expressible even under verbose. `evaluate`
/// never attaches diags to a Skip, so nothing is lost in practice.
///
/// `finish()` is required on the ndjson side (summary record); on the
/// TAP side it is the idempotent trailing plan, a no-op after
/// `plan_ahead`.
fn render_into(
    rep: &mut tap_dancer::Reporter,
    results: &[CheckResult],
    verbose: bool,
) -> std::io::Result<()> {
    rep.plan_ahead(results.len())?;
    for r in results {
        let diags: Vec<(&str, serde_json::Value)> = r
            .diags
            .iter()
            .map(|(k, v)| (k.as_str(), serde_json::Value::String(v.clone())))
            .collect();
        match &r.status {
            Status::Pass if verbose && !diags.is_empty() => {
                rep.ok_diag(r.name, &diags)?;
            }
            Status::Pass => {
                rep.ok(r.name)?;
            }
            Status::Fail => {
                rep.not_ok_diag(r.name, &diags)?;
            }
            Status::Skip(reason) => {
                rep.skip(r.name, reason)?;
            }
        }
    }
    rep.finish()
}

/// Skip reason for agent-side points when the agent was never probed,
/// derived from how far the socket probe got. The `is_socket: true`
/// arm shouldn't occur under gather's contract (a good socket means
/// the agent IS probed), but evaluate is pure and must not panic on
/// any input — "socket missing" is the sensible fallback.
fn socket_skip_reason(socket: &SocketProbe) -> String {
    match socket {
        SocketProbe::Unresolved => "socket unresolved".into(),
        SocketProbe::Resolved {
            is_socket: false, ..
        } => "path is not a socket".into(),
        SocketProbe::Resolved { .. } => "socket missing".into(),
    }
}

/// Derive the fixed 9-point plan from probe outcomes. Pure: no IO — the
/// plan is always 9 points in the documented order, with SKIP cascades
/// when a prerequisite probe failed or was not attempted.
pub fn evaluate(probes: &Probes) -> Vec<CheckResult> {
    let mut out = Vec::with_capacity(9);

    // 1 — service
    out.push(match &probes.service {
        ServiceProbe::NotAvailable(why) => CheckResult {
            name: "service: piggy-agent.service active",
            status: Status::Skip(why.clone()),
            diags: vec![],
        },
        ServiceProbe::UnitNotFound => CheckResult {
            name: "service: piggy-agent.service active",
            status: Status::Skip("no piggy-agent.service unit installed".into()),
            diags: vec![],
        },
        ServiceProbe::Unit {
            load_state,
            active_state,
            sub_state,
            exec_main_status,
        } => CheckResult {
            name: "service: piggy-agent.service active",
            status: if active_state == "active" {
                Status::Pass
            } else {
                Status::Fail
            },
            diags: vec![
                ("load_state".into(), load_state.clone()),
                ("active_state".into(), active_state.clone()),
                ("sub_state".into(), sub_state.clone()),
                ("exec_main_status".into(), exec_main_status.clone()),
            ],
        },
    });

    // 2 + 3 — socket resolved / exists
    match &probes.socket {
        SocketProbe::Unresolved => {
            out.push(CheckResult {
                name: "agent: socket resolved",
                status: Status::Fail,
                diags: vec![(
                    "error".into(),
                    "neither PIGGY_AUTH_SOCK nor SSH_AUTH_SOCK is set non-empty".into(),
                )],
            });
            out.push(CheckResult {
                name: "agent: socket exists",
                status: Status::Skip("socket unresolved".into()),
                diags: vec![],
            });
        }
        SocketProbe::Resolved {
            source,
            path,
            is_socket,
            stat_detail,
        } => {
            out.push(CheckResult {
                name: "agent: socket resolved",
                status: Status::Pass,
                diags: vec![
                    ("source".into(), (*source).into()),
                    ("path".into(), path.display().to_string()),
                ],
            });
            out.push(CheckResult {
                name: "agent: socket exists",
                status: if *is_socket {
                    Status::Pass
                } else {
                    Status::Fail
                },
                diags: vec![("stat".into(), stat_detail.clone())],
            });
        }
    }

    // 4 — agent answers request_identities
    out.push(match &probes.agent {
        None => CheckResult {
            name: "agent: answers request_identities",
            status: Status::Skip(socket_skip_reason(&probes.socket)),
            diags: vec![],
        },
        Some(Err(e)) => CheckResult {
            name: "agent: answers request_identities",
            status: Status::Fail,
            diags: vec![("error".into(), e.clone())],
        },
        // NOTE: identities: 0 still passes here — point 9 owns the
        // cross-referenced verdict (zero-identities semantics, design doc).
        Some(Ok(ids)) => CheckResult {
            name: "agent: answers request_identities",
            status: Status::Pass,
            diags: vec![("identities".into(), ids.len().to_string())],
        },
    });

    // 5 — ecdh extension
    out.push(match &probes.extensions {
        // gather's contract: extensions is only probed when
        // request_identities succeeded — so `extensions: None` means
        // either the socket was never reachable (agent: None) or the
        // agent failed to answer (agent: Some(Err)). Distinguish the
        // SKIP reason via probes.agent; the Some(Ok) arm shouldn't
        // occur under that contract, but evaluate is pure and must not
        // panic on any input, so it falls back to "agent did not
        // answer".
        None => CheckResult {
            name: "agent: advertises ecdh extension",
            status: Status::Skip(match &probes.agent {
                None => socket_skip_reason(&probes.socket),
                Some(_) => "agent did not answer".into(),
            }),
            diags: vec![],
        },
        // The query extension being unsupported or failing is itself a
        // failure: piggy decrypts will fail either way (piggy#123
        // catch). The error text carries the unsupported-vs-failed
        // detail under the file-consistent "error" key.
        Some(Err(e)) => CheckResult {
            name: "agent: advertises ecdh extension",
            status: Status::Fail,
            diags: vec![("error".into(), e.clone())],
        },
        Some(Ok(names)) => CheckResult {
            name: "agent: advertises ecdh extension",
            status: if names.iter().any(|n| n == ECDH_EXT) {
                Status::Pass
            } else {
                Status::Fail
            },
            diags: vec![("advertised".into(), names.join(", "))],
        },
    });

    // 6 — pcsc daemon reachable
    out.push(match &probes.pcsc {
        PcscProbe::Ok => CheckResult {
            name: "pcsc: daemon reachable",
            status: Status::Pass,
            diags: vec![],
        },
        PcscProbe::Error(e) => CheckResult {
            name: "pcsc: daemon reachable",
            status: Status::Fail,
            diags: vec![("error".into(), e.clone())],
        },
    });

    // 7 — card attached
    out.push(match &probes.cards {
        None => CheckResult {
            name: "card: PIV card attached",
            status: Status::Skip("pcscd unreachable".into()),
            diags: vec![],
        },
        Some(cards) if cards.is_empty() => CheckResult {
            name: "card: PIV card attached",
            status: Status::Fail,
            diags: vec![("cards".into(), "0".into())],
        },
        Some(cards) => CheckResult {
            name: "card: PIV card attached",
            status: Status::Pass,
            diags: cards
                .iter()
                .flat_map(|c| {
                    [
                        ("reader".to_string(), c.reader.clone()),
                        ("guid".to_string(), c.guid.clone()),
                    ]
                })
                .collect(),
        },
    });

    // 8 — slot 9D populated on any attached card
    out.push(match &probes.cards {
        None => CheckResult {
            name: "card: key-management slot 9D populated",
            status: Status::Skip("pcscd unreachable".into()),
            diags: vec![],
        },
        Some(cards) if cards.is_empty() => CheckResult {
            name: "card: key-management slot 9D populated",
            status: Status::Skip("no card attached".into()),
            diags: vec![],
        },
        Some(cards) => CheckResult {
            name: "card: key-management slot 9D populated",
            status: if cards.iter().any(|c| c.slot_9d_populated) {
                Status::Pass
            } else {
                Status::Fail
            },
            diags: cards
                .iter()
                .map(|c| {
                    (
                        c.guid.clone(),
                        if c.slot_9d_populated {
                            "9D populated".to_string()
                        } else {
                            "9D empty".to_string()
                        },
                    )
                })
                .collect(),
        },
    });

    // 9 — cross-check: agent identity count vs attached provisioned card
    let provisioned_card = probes
        .cards
        .as_ref()
        .is_some_and(|cards| cards.iter().any(|c| c.slot_9d_populated));
    out.push(match (&probes.agent, provisioned_card) {
        (Some(Ok(ids)), true) => {
            if ids.is_empty() {
                CheckResult {
                    name: "agent serves attached card",
                    status: Status::Fail,
                    diags: vec![(
                        "hint".into(),
                        "pcscd race or locked agent — restart piggy-agent".into(),
                    )],
                }
            } else {
                CheckResult {
                    name: "agent serves attached card",
                    status: Status::Pass,
                    diags: vec![("identities".into(), ids.len().to_string())],
                }
            }
        }
        _ => CheckResult {
            name: "agent serves attached card",
            status: Status::Skip("agent or card data unavailable".into()),
            diags: vec![],
        },
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_probes() -> Probes {
        Probes {
            service: ServiceProbe::NotAvailable("non-linux".into()),
            socket: SocketProbe::Unresolved,
            agent: None,
            extensions: None,
            pcsc: PcscProbe::Error("PC/SC unavailable".into()),
            cards: None,
        }
    }

    /// Fully-healthy probe set: every point evaluates Pass. Matrix
    /// tests mutate one field at a time from here.
    fn healthy_probes() -> Probes {
        Probes {
            service: ServiceProbe::Unit {
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                exec_main_status: "0".into(),
            },
            socket: SocketProbe::Resolved {
                source: "PIGGY_AUTH_SOCK",
                path: "/run/user/1000/piggy-agent.sock".into(),
                is_socket: true,
                stat_detail: "unix socket".into(),
            },
            agent: Some(Ok(vec!["card-a".into(), "card-b".into(), "card-c".into()])),
            extensions: Some(Ok(vec![ECDH_EXT.into(), "other-ext".into()])),
            pcsc: PcscProbe::Ok,
            cards: Some(vec![CardInfo {
                reader: "Yubico YubiKey CCID 00 00".into(),
                guid: "DEADBEEFDEADBEEF".into(),
                slot_9d_populated: true,
            }]),
        }
    }

    fn diag<'a>(r: &'a CheckResult, key: &str) -> Option<&'a str> {
        r.diags
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The plan is always 9 points, in the fixed documented order,
    /// regardless of probe outcomes.
    #[test]
    fn evaluate_always_yields_nine_points_in_order() {
        let results = evaluate(&empty_probes());
        assert_eq!(results.len(), 9);
        let names: Vec<&str> = results.iter().map(|r| r.name).collect();
        assert_eq!(
            names,
            vec![
                "service: piggy-agent.service active",
                "agent: socket resolved",
                "agent: socket exists",
                "agent: answers request_identities",
                "agent: advertises ecdh extension",
                "pcsc: daemon reachable",
                "card: PIV card attached",
                "card: key-management slot 9D populated",
                "agent serves attached card",
            ]
        );
    }

    /// Unresolved socket fails point 2 and SKIPs every dependent
    /// agent-side point (3, 4, 5, 9) — with the skip reason naming the
    /// unresolved socket, not a missing one.
    #[test]
    fn unresolved_socket_skips_dependents() {
        let results = evaluate(&empty_probes());
        assert!(matches!(results[1].status, Status::Fail));
        assert!(matches!(results[2].status, Status::Skip(_)));
        match &results[3].status {
            Status::Skip(reason) => assert_eq!(reason, "socket unresolved"),
            _ => panic!("expected Skip for point 4"),
        }
        match &results[4].status {
            Status::Skip(reason) => assert_eq!(reason, "socket unresolved"),
            _ => panic!("expected Skip for point 5"),
        }
        assert!(matches!(results[8].status, Status::Skip(_)));
    }

    /// Matrix row 1: fully-populated healthy probes → all 9 Pass.
    #[test]
    fn healthy_probes_all_pass() {
        let results = evaluate(&healthy_probes());
        assert_eq!(results.len(), 9);
        for r in &results {
            assert!(
                matches!(r.status, Status::Pass),
                "expected Pass for {:?}",
                r.name
            );
        }
        assert_eq!(exit_code(&results), 0);
    }

    /// Matrix row 2: agent answers with zero identities while a
    /// provisioned card is attached — point 4 still passes (it owns
    /// only "did the agent answer"), point 9 owns the cross-checked
    /// verdict and fails with the restart hint.
    #[test]
    fn zero_identities_with_provisioned_card_fails_point_9() {
        let mut probes = healthy_probes();
        probes.agent = Some(Ok(vec![]));
        let results = evaluate(&probes);
        assert!(matches!(results[3].status, Status::Pass));
        assert_eq!(diag(&results[3], "identities"), Some("0"));
        assert!(matches!(results[8].status, Status::Fail));
        assert_eq!(
            diag(&results[8], "hint"),
            Some("pcscd race or locked agent — restart piggy-agent")
        );
    }

    /// Matrix row 3: zero identities but no card attached — point 7
    /// fails (no card), points 8 and 9 SKIP (nothing to cross-check).
    #[test]
    fn zero_identities_without_card_skips_point_9() {
        let mut probes = healthy_probes();
        probes.agent = Some(Ok(vec![]));
        probes.cards = Some(vec![]);
        let results = evaluate(&probes);
        assert!(matches!(results[6].status, Status::Fail));
        assert!(matches!(results[7].status, Status::Skip(_)));
        assert!(matches!(results[8].status, Status::Skip(_)));
    }

    /// Matrix row 4: the query extension answered but the ecdh
    /// extension is absent — point 5 fails carrying the advertised set.
    #[test]
    fn ecdh_missing_from_query_fails_point_5() {
        let mut probes = healthy_probes();
        probes.extensions = Some(Ok(vec!["other-ext".into()]));
        let results = evaluate(&probes);
        assert!(matches!(results[4].status, Status::Fail));
        assert_eq!(diag(&results[4], "advertised"), Some("other-ext"));
    }

    /// Matrix row 5: the query extension itself is unsupported or
    /// errored — point 5 fails (piggy decrypts will fail either way).
    #[test]
    fn query_unsupported_fails_point_5() {
        let mut probes = healthy_probes();
        probes.extensions = Some(Err("agent: unsupported extension".into()));
        let results = evaluate(&probes);
        assert!(matches!(results[4].status, Status::Fail));
    }

    /// Matrix row 6: agent connect/protocol error — point 4 fails,
    /// point 5 SKIPs with "agent did not answer" (gather's contract:
    /// extensions only probed when identities succeeded, so it is
    /// None here), point 9 SKIPs.
    #[test]
    fn agent_connect_error_fails_4_skips_5_and_9() {
        let mut probes = healthy_probes();
        probes.agent = Some(Err("connection refused".into()));
        probes.extensions = None;
        let results = evaluate(&probes);
        assert!(matches!(results[3].status, Status::Fail));
        match &results[4].status {
            Status::Skip(reason) => assert_eq!(reason, "agent did not answer"),
            _ => panic!("expected Skip for point 5"),
        }
        assert!(matches!(results[8].status, Status::Skip(_)));
    }

    /// Matrix row 7: pcscd unreachable — point 6 fails; 7, 8, and 9
    /// SKIP (card data unavailable).
    #[test]
    fn pcsc_error_fails_6_skips_7_8_9() {
        let mut probes = healthy_probes();
        probes.pcsc = PcscProbe::Error("PC/SC daemon not available".into());
        probes.cards = None;
        let results = evaluate(&probes);
        assert!(matches!(results[5].status, Status::Fail));
        assert!(matches!(results[6].status, Status::Skip(_)));
        assert!(matches!(results[7].status, Status::Skip(_)));
        assert!(matches!(results[8].status, Status::Skip(_)));
    }

    /// Matrix row 8: unit installed but not active — point 1 fails.
    #[test]
    fn unit_inactive_fails_point_1() {
        let mut probes = healthy_probes();
        probes.service = ServiceProbe::Unit {
            load_state: "loaded".into(),
            active_state: "failed".into(),
            sub_state: "failed".into(),
            exec_main_status: "1".into(),
        };
        let results = evaluate(&probes);
        assert!(matches!(results[0].status, Status::Fail));
        // the service failure must not cascade to any other point
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r.status, Status::Fail))
                .count(),
            1
        );
        assert_eq!(exit_code(&results), 1);
    }

    /// Matrix row 9: no unit installed (manual agent setups) — point 1
    /// SKIPs rather than fails.
    #[test]
    fn unit_not_found_skips_point_1() {
        let mut probes = healthy_probes();
        probes.service = ServiceProbe::UnitNotFound;
        let results = evaluate(&probes);
        assert!(matches!(results[0].status, Status::Skip(_)));
    }

    /// Matrix row 10: socket env var resolved to a path that exists
    /// but is not a unix socket — point 2 passes, point 3 fails.
    #[test]
    fn socket_path_not_a_socket_fails_point_3() {
        let mut probes = healthy_probes();
        probes.socket = SocketProbe::Resolved {
            source: "SSH_AUTH_SOCK",
            path: "/tmp/not-a-socket".into(),
            is_socket: false,
            stat_detail: "regular file".into(),
        };
        // gather's contract: the agent is only probed when the socket
        // resolved AND is_socket, so these are always None here.
        probes.agent = None;
        probes.extensions = None;
        let results = evaluate(&probes);
        assert!(matches!(results[1].status, Status::Pass));
        assert!(matches!(results[2].status, Status::Fail));
        match &results[3].status {
            Status::Skip(reason) => assert_eq!(reason, "path is not a socket"),
            _ => panic!("expected Skip for point 4"),
        }
        match &results[4].status {
            Status::Skip(reason) => assert_eq!(reason, "path is not a socket"),
            _ => panic!("expected Skip for point 5"),
        }
        assert!(matches!(results[8].status, Status::Skip(_)));
    }

    /// systemctl show parser: a loaded, active unit maps to Unit with
    /// the four properties carried through verbatim.
    #[test]
    fn parse_systemctl_show_active_unit() {
        let out = "LoadState=loaded\nActiveState=active\nSubState=running\nExecMainStatus=0\n";
        match parse_systemctl_show(out) {
            ServiceProbe::Unit {
                load_state,
                active_state,
                sub_state,
                exec_main_status,
            } => {
                assert_eq!(load_state, "loaded");
                assert_eq!(active_state, "active");
                assert_eq!(sub_state, "running");
                assert_eq!(exec_main_status, "0");
            }
            _ => panic!("expected Unit"),
        }
    }

    /// systemctl show parser: LoadState=not-found (no unit installed)
    /// maps to UnitNotFound regardless of the other keys.
    #[test]
    fn parse_systemctl_show_not_found_unit() {
        let out = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nExecMainStatus=0\n";
        assert!(matches!(
            parse_systemctl_show(out),
            ServiceProbe::UnitNotFound
        ));
    }

    /// systemctl show parser: empty output carries no LoadState, so the
    /// conservative path is NotAvailable (SKIP), never a bogus Unit.
    #[test]
    fn parse_systemctl_show_empty_input_is_not_available() {
        assert!(matches!(
            parse_systemctl_show(""),
            ServiceProbe::NotAvailable(_)
        ));
    }

    /// Exit-status enrichment: an unparseable probe + non-zero exit
    /// folds the exit description and stderr text into the reason.
    #[test]
    fn enrich_unparseable_with_exit_folds_status_and_stderr() {
        let probe = ServiceProbe::NotAvailable("unparseable systemctl output".into());
        match enrich_unparseable_with_exit(
            probe,
            false,
            "exit status: 1",
            b"Failed to connect to bus: No medium found\n",
        ) {
            ServiceProbe::NotAvailable(reason) => {
                assert!(reason.contains("exit status: 1"), "reason: {reason}");
                assert!(
                    reason.contains("Failed to connect to bus: No medium found"),
                    "reason: {reason}"
                );
            }
            _ => panic!("expected NotAvailable"),
        }
    }

    /// Exit-status enrichment: a parseable Unit result passes through
    /// untouched regardless of exit status.
    #[test]
    fn enrich_unparseable_with_exit_passes_unit_through() {
        let probe = ServiceProbe::Unit {
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            exec_main_status: "0".into(),
        };
        match enrich_unparseable_with_exit(probe, false, "exit status: 1", b"noise") {
            ServiceProbe::Unit { active_state, .. } => assert_eq!(active_state, "active"),
            _ => panic!("expected Unit to pass through"),
        }
    }

    /// resolve_socket honors PIGGY_AUTH_SOCK over SSH_AUTH_SOCK and
    /// treats empty as unset on both vars. Mutating env: this is the
    /// only test in this test binary touching these vars (the
    /// agent_client override test lives in the library crate's separate
    /// test binary), so the process-wide mutation is race-free.
    /// Snapshot + restore mirrors stats.rs's
    /// `endpoint_gated_on_env_presence`.
    #[test]
    fn resolve_socket_precedence() {
        let saved_piggy = std::env::var_os("PIGGY_AUTH_SOCK");
        let saved_ssh = std::env::var_os("SSH_AUTH_SOCK");

        std::env::set_var("PIGGY_AUTH_SOCK", "/run/piggy-health-test.sock");
        std::env::set_var("SSH_AUTH_SOCK", "/run/ambient-health-test.sock");
        match resolve_socket() {
            SocketProbe::Resolved { source, path, .. } => {
                assert_eq!(source, "PIGGY_AUTH_SOCK");
                assert_eq!(
                    path,
                    std::path::PathBuf::from("/run/piggy-health-test.sock")
                );
            }
            _ => panic!("expected Resolved via PIGGY_AUTH_SOCK"),
        }

        std::env::set_var("PIGGY_AUTH_SOCK", "");
        match resolve_socket() {
            SocketProbe::Resolved { source, path, .. } => {
                assert_eq!(
                    source, "SSH_AUTH_SOCK",
                    "empty PIGGY_AUTH_SOCK must be treated as unset"
                );
                assert_eq!(
                    path,
                    std::path::PathBuf::from("/run/ambient-health-test.sock")
                );
            }
            _ => panic!("expected Resolved via SSH_AUTH_SOCK"),
        }

        std::env::remove_var("PIGGY_AUTH_SOCK");
        std::env::set_var("SSH_AUTH_SOCK", "");
        assert!(
            matches!(resolve_socket(), SocketProbe::Unresolved),
            "both empty must be Unresolved"
        );

        std::env::remove_var("SSH_AUTH_SOCK");
        assert!(
            matches!(resolve_socket(), SocketProbe::Unresolved),
            "both unset must be Unresolved"
        );

        // Restore.
        match saved_piggy {
            Some(v) => std::env::set_var("PIGGY_AUTH_SOCK", v),
            None => std::env::remove_var("PIGGY_AUTH_SOCK"),
        }
        match saved_ssh {
            Some(v) => std::env::set_var("SSH_AUTH_SOCK", v),
            None => std::env::remove_var("SSH_AUTH_SOCK"),
        }
    }

    /// stat on a plain file yields is_socket=false with an explanatory
    /// stat_detail; a missing path likewise explains rather than
    /// erroring. No tempfile dev-dependency exists in this crate, so a
    /// uniquely-named file under env::temp_dir() with explicit cleanup
    /// stands in.
    #[test]
    fn stat_plain_file_is_not_a_socket() {
        let path =
            std::env::temp_dir().join(format!("piggy-health-stat-test-{}", std::process::id()));
        std::fs::File::create(&path).expect("create plain file");
        let (is_socket, detail) = stat_socket_path(&path);
        std::fs::remove_file(&path).ok();
        assert!(!is_socket, "plain file must not be a socket");
        assert!(detail.contains("regular file"), "detail: {detail}");

        // The same path, now removed: missing files explain themselves.
        let (missing_is_socket, missing_detail) = stat_socket_path(&path);
        assert!(!missing_is_socket);
        assert!(
            missing_detail.contains("does not exist"),
            "detail: {missing_detail}"
        );
    }

    // ---- HealthSink rendering ----

    /// Small mixed fixture for sink tests: Pass-with-diags,
    /// Fail-with-diags, Skip-with-reason. Mirrors what evaluate
    /// produces (failures always carry diags; skips never do).
    fn sink_fixture() -> Vec<CheckResult> {
        vec![
            CheckResult {
                name: "agent: socket resolved",
                status: Status::Pass,
                diags: vec![
                    ("source".into(), "PIGGY_AUTH_SOCK".into()),
                    ("path".into(), "/run/user/1000/piggy-agent.sock".into()),
                ],
            },
            CheckResult {
                name: "agent: answers request_identities",
                status: Status::Fail,
                diags: vec![("error".into(), "connection refused".into())],
            },
            CheckResult {
                name: "card: key-management slot 9D populated",
                status: Status::Skip("no card attached".into()),
                diags: vec![],
            },
        ]
    }

    fn render_tap(verbose: bool, results: &[CheckResult]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        TapSink::new(&mut buf, verbose).render(results).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn render_ndjson(verbose: bool, results: &[CheckResult]) -> Vec<serde_json::Value> {
        let mut buf: Vec<u8> = Vec::new();
        NdjsonSink::new(&mut buf, verbose).render(results).unwrap();
        String::from_utf8(buf)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line parses as JSON"))
            .collect()
    }

    /// TAP sink: version line, 1..3 plan, points with SKIP directives,
    /// YAML diags on failures (always) and not on passes (non-verbose).
    /// TapSink builds a plain (colorless, locale-free) writer, so the
    /// full output is deterministic and pinned byte-for-byte. NOTE: the
    /// YAML interior quoting (`key: "value"`) is tap-dancer's
    /// write_yaml_value_field implementation detail, not a spec
    /// guarantee — if a tap-dancer bump changes quote style, update the
    /// YAML lines here (the structure lines are TAP-14-stable).
    #[test]
    fn tap_sink_renders_mixed_results() {
        let out = render_tap(false, &sink_fixture());
        assert_eq!(
            out,
            "TAP version 14\n\
1..3\n\
ok 1 - agent: socket resolved\n\
not ok 2 - agent: answers request_identities\n\
\x20 ---\n\
\x20 error: \"connection refused\"\n\
\x20 ...\n\
ok 3 - card: key-management slot 9D populated # SKIP no card attached\n"
        );
    }

    /// TAP sink, verbose: passes carry their YAML diag block too.
    #[test]
    fn tap_sink_verbose_adds_diags_on_passes() {
        let out = render_tap(true, &sink_fixture());
        assert_eq!(
            out,
            "TAP version 14\n\
1..3\n\
ok 1 - agent: socket resolved\n\
\x20 ---\n\
\x20 source: \"PIGGY_AUTH_SOCK\"\n\
\x20 path: \"/run/user/1000/piggy-agent.sock\"\n\
\x20 ...\n\
not ok 2 - agent: answers request_identities\n\
\x20 ---\n\
\x20 error: \"connection refused\"\n\
\x20 ...\n\
ok 3 - card: key-management slot 9D populated # SKIP no card attached\n"
        );
    }

    /// ndjson sink: one JSON object per line; first = plan record, then
    /// one test record per point (skip reason + diagnostics map), last =
    /// summary record per tap-ndjson(7). Field assertions rather than
    /// byte-equality: tap-dancer owns field ordering.
    #[test]
    fn ndjson_sink_renders_records_per_tap_ndjson_7() {
        let lines = render_ndjson(false, &sink_fixture());
        assert_eq!(lines.len(), 5, "plan + 3 tests + summary");

        assert_eq!(lines[0]["type"], "plan");
        assert_eq!(lines[0]["count"], 3);

        assert_eq!(lines[1]["type"], "test");
        assert_eq!(lines[1]["n"], 1);
        assert_eq!(lines[1]["description"], "agent: socket resolved");
        assert_eq!(lines[1]["ok"], true);
        assert_eq!(
            lines[1]["diagnostic"],
            serde_json::Value::Null,
            "pass diags only render under verbose"
        );
        // Direct producer: no source line (tap-ndjson(7) line-0 rule).
        assert_eq!(lines[1]["line"], 0);

        assert_eq!(lines[2]["ok"], false);
        assert_eq!(lines[2]["diagnostic"]["error"], "connection refused");

        assert_eq!(lines[3]["ok"], true);
        assert_eq!(lines[3]["directive"]["kind"], "skip");
        assert_eq!(lines[3]["directive"]["reason"], "no card attached");

        let summary = &lines[4];
        assert_eq!(summary["type"], "summary");
        assert_eq!(summary["passed"], 1);
        assert_eq!(summary["failed"], 1);
        assert_eq!(summary["skipped"], 1);
        assert_eq!(summary["total"], 3);
        assert_eq!(summary["plan_count"], 3);
        assert_eq!(summary["bailed"], false);
    }

    /// ndjson sink, verbose: pass points carry their diagnostics map,
    /// with values passed through as JSON strings (no int sniffing —
    /// CheckResult diags are (String, String) by contract).
    #[test]
    fn ndjson_sink_verbose_adds_diags_on_passes() {
        let lines = render_ndjson(true, &sink_fixture());
        assert_eq!(lines[1]["diagnostic"]["source"], "PIGGY_AUTH_SOCK");
        assert_eq!(
            lines[1]["diagnostic"]["path"],
            "/run/user/1000/piggy-agent.sock"
        );
        // String pass-through: a numeric-looking diag value stays a
        // JSON string.
        let mut results = sink_fixture();
        results[0].diags = vec![("identities".into(), "0".into())];
        let lines = render_ndjson(true, &results);
        assert_eq!(lines[1]["diagnostic"]["identities"], "0");
        assert!(lines[1]["diagnostic"]["identities"].is_string());
    }

    /// exit code: 0 iff no Fail. Skip counts as ok.
    #[test]
    fn exit_code_zero_iff_no_fail() {
        let mut results = evaluate(&empty_probes());
        assert_ne!(exit_code(&results), 0);
        for r in &mut results {
            r.status = Status::Pass;
        }
        assert_eq!(exit_code(&results), 0);
        results[0].status = Status::Skip("x".into());
        assert_eq!(exit_code(&results), 0);
    }
}
