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
        Some(_) => ServiceProbe::Unit {
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
    match parse_systemctl_show(&String::from_utf8_lossy(&output.stdout)) {
        ServiceProbe::NotAvailable(_) if !output.status.success() => {
            ServiceProbe::NotAvailable(format!(
                "systemctl failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
        probe => probe,
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_service() -> ServiceProbe {
    ServiceProbe::NotAvailable("service check is Linux-only".into())
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

    /// Fully-healthy probe set: every point evaluates Pass. Matrix
    /// tests mutate one field at a time from here.
    fn healthy_probes() -> Probes {
        Probes {
            service: ServiceProbe::Unit {
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
        assert!(matches!(results[3].status, Status::Skip(_)));
        assert!(matches!(results[4].status, Status::Skip(_)));
        assert!(matches!(results[8].status, Status::Skip(_)));
    }

    /// systemctl show parser: a loaded, active unit maps to Unit with
    /// the three states carried through verbatim.
    #[test]
    fn parse_systemctl_show_active_unit() {
        let out = "LoadState=loaded\nActiveState=active\nSubState=running\nExecMainStatus=0\n";
        match parse_systemctl_show(out) {
            ServiceProbe::Unit {
                active_state,
                sub_state,
                exec_main_status,
            } => {
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
