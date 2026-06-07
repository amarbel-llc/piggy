//! `piggy health` — agent/card/service checks emitting TAP-14 (tty) or
//! tap-ndjson(7) (non-tty). Design: docs/plans/2026-06-07-piggy-health-design.md.
//!
//! Split: probe phase (IO, `gather`) → pure `evaluate` → render via
//! `HealthSink`. All card operations are read-only (enumerate + cert
//! read); nothing here prompts for a PIN or decrypts.

// Not yet reachable from main.rs dispatch — the clap wiring lands in a
// later task. Drop this allow when `piggy health` is dispatched.
#![allow(dead_code)]

use std::time::Duration;

/// Per-probe timeout. Tuning lever (design doc): change signal is false
/// `not ok` timeouts on slow readers/agents.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The extension piggy decrypts require. Built by concatenation so
/// editing tools cannot mangle the literal (see CLAUDE.md memory).
pub const ECDH_EXT: &str = concat!("ecdh@", "joyent.com");

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

pub fn exit_code(results: &[CheckResult]) -> i32 {
    if results.iter().any(|r| matches!(r.status, Status::Fail)) {
        1
    } else {
        0
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
            status: Status::Skip("socket missing".into()),
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
                None => "socket missing".into(),
                Some(_) => "agent did not answer".into(),
            }),
            diags: vec![],
        },
        // The query extension being unsupported is itself a failure:
        // piggy decrypts will fail either way (piggy#123 catch).
        Some(Err(e)) => CheckResult {
            name: "agent: advertises ecdh extension",
            status: Status::Fail,
            diags: vec![("query extension unsupported or failed".into(), e.clone())],
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
    /// agent-side point (3, 4, 5, 9).
    #[test]
    fn unresolved_socket_skips_dependents() {
        let results = evaluate(&empty_probes());
        assert!(matches!(results[1].status, Status::Fail));
        assert!(matches!(results[2].status, Status::Skip(_)));
        assert!(matches!(results[3].status, Status::Skip(_)));
        assert!(matches!(results[4].status, Status::Skip(_)));
        assert!(matches!(results[8].status, Status::Skip(_)));
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
