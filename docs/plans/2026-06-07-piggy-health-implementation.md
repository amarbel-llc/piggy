# `piggy health` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** A top-level `piggy health` subcommand running 9 fixed agent/card/service checks, emitting TAP-14 text on a tty and tap-ndjson(7) records otherwise, exiting 0 iff all points pass.

**Architecture:** Probe phase (IO, defensive) fills a `Probes` struct; a pure `evaluate(&Probes) -> Vec<CheckResult>` derives the 9 points including SKIP cascades and the zero-identities-with-card cross-check; a `HealthSink` trait renders to either tap-dancer's `TapWriter` or its tap-ndjson writer. See the approved design: `docs/plans/2026-06-07-piggy-health-design.md`.

**Tech Stack:** Rust (clap, ssh-agent-lib 0.5, tokio current-thread, piggy-piv/pcsc), `tap-dancer` Rust crate as a git dep (gated — see Sequencing), bats for integration.

**Rollback:** N/A — purely additive subcommand; revert the commits.

**Sequencing gate:** Tasks 1–6 are unblocked. Tasks 7–10 are **gated on a tap-dancer release containing the tap-ndjson(7) writer** (spinclass session `tap/clear-cherry`). Do not start Task 7 until that release exists; verify the actual writer API against `~/eng/repos/tap/rust/src/lib.rs` at that point — the code in Tasks 7–8 is indicative, not authoritative.

**Conventions that apply throughout:**
- Run tests via just recipes only: `just test-rust -p piggy`, `just validate-rust -p piggy`, `just build-rust -p piggy`. Never bare cargo.
- Format via `just codemod-fmt` before each commit; never bare rustfmt.
- Do NOT run full `just` before `merge-this-session` — the pre-merge hook runs it.
- Assemble protocol strings like the ecdh extension name by concatenation (`concat!("ecdh@", "joyent.com")` or a `const`) when an editing tool would mangle the literal; verify the final source bytes are correct either way.
- Commit messages: conventional commits, sign-off as Clown 0.3.10+bb6560d with link to https://github.com/amarbel-llc/clown/commit/bb6560dd30e00f9a8e16d720fcc60ab9f97c15c1.

---

### Task 1: Core types + pure evaluation skeleton

**Files:**
- Create: `crates/piggy/src/health.rs`
- Modify: `crates/piggy/src/main.rs` (add `mod health;` to the module list only — no dispatch yet)

**Step 1: Write the failing tests** — in `crates/piggy/src/health.rs`, bottom `#[cfg(test)] mod tests`:

```rust
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
```

**Step 2: Run to verify failure**

Run: `just test-rust -p piggy -- health`
Expected: compile FAILURE (types not defined).

**Step 3: Minimal implementation** — top of `crates/piggy/src/health.rs`:

```rust
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
        /// `Some(true)` = exists and is a unix socket; `Some(false)` =
        /// exists/missing but not a socket; carried diag explains.
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
```

Then `evaluate`, building the 9 results in order. Implement each point per the design table; key excerpts:

```rust
/// The extension piggy decrypts require. Built by concatenation so
/// editing tools cannot mangle the literal (see CLAUDE.md memory).
pub const ECDH_EXT: &str = concat!("ecdh@", "joyent.com");

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
        ServiceProbe::Unit { active_state, sub_state, exec_main_status } => CheckResult {
            name: "service: piggy-agent.service active",
            status: if active_state == "active" { Status::Pass } else { Status::Fail },
            diags: vec![
                ("active_state".into(), active_state.clone()),
                ("sub_state".into(), sub_state.clone()),
                ("exec_main_status".into(), exec_main_status.clone()),
            ],
        },
    });

    // 2 + 3 — socket resolved / exists
    // (Fail 2 on Unresolved; Skip 3 when 2 failed; Fail 3 when
    //  is_socket == false, diag = stat_detail.)
    ...

    // 4 — agent answers: None → Skip("socket missing"); Some(Err(e)) →
    //     Fail with ("error", e); Some(Ok(ids)) → Pass with
    //     ("identities", ids.len()). NOTE: identities: 0 still passes
    //     here — point 9 owns the cross-referenced verdict.
    ...

    // 5 — ecdh extension: None → Skip; Some(Err(e)) → Fail
    //     ("query extension unsupported or failed", e) — piggy decrypts
    //     will fail either way (piggy#123 catch); Some(Ok(names)) →
    //     Pass iff names.iter().any(|n| n == ECDH_EXT), Fail otherwise
    //     with ("advertised", names.join(",")).
    ...

    // 6 — pcsc; 7 — cards (None → Skip "pcscd unreachable"; empty →
    //     Fail; diag per card reader/guid); 8 — any card with
    //     slot_9d_populated (Skip when 7 skipped or found none).
    ...

    // 9 — cross-check: needs Some(Ok(ids)) from agent AND a card with
    //     9D populated. If both present and ids.is_empty() → Fail with
    //     ("hint", "pcscd race or locked agent — restart piggy-agent").
    //     If both present and !ids.is_empty() → Pass. Otherwise
    //     Skip("agent or card data unavailable").
    ...

    out
}
```

(Write the elided arms in full; the tests in Step 1 plus Task 2's tests pin the behavior.)

**Step 4: Run to verify pass**

Run: `just test-rust -p piggy -- health`
Expected: PASS (3 tests).

**Step 5: Format + commit**

```bash
just codemod-fmt
git add crates/piggy/src/health.rs crates/piggy/src/main.rs
git commit  # feat(piggy): health check types + pure evaluation skeleton
```

---

### Task 2: Pin the full evaluation matrix

**Files:**
- Modify: `crates/piggy/src/health.rs` (tests module)

**Step 1: Write failing tests** covering, one test per row:

1. `healthy_probes_all_pass` — fully-populated probes (active unit; resolved socket, is_socket; agent Ok(vec of 3 comments); extensions Ok including `ECDH_EXT`; pcsc Ok; one card 9D populated) → all 9 Pass, `exit_code == 0`.
2. `zero_identities_with_provisioned_card_fails_point_9` — same but agent `Ok(vec![])` → points 4 Pass (`identities: 0` diag), 9 Fail with the restart hint diag.
3. `zero_identities_without_card_skips_point_9` — agent Ok(vec![]), cards `Some(vec![])` → 7 Fail, 8 Skip, 9 Skip.
4. `ecdh_missing_from_query_fails_point_5` — extensions Ok without ECDH_EXT → 5 Fail, diag `advertised`.
5. `query_unsupported_fails_point_5` — extensions `Some(Err(...))` → 5 Fail.
6. `agent_connect_error_fails_4_skips_5_and_9` — agent `Some(Err(...))`.
7. `pcsc_error_fails_6_skips_7_8_9` — pcsc Error, cards None (9 also Skip because card data unavailable).
8. `unit_inactive_fails_point_1` — `ServiceProbe::Unit { active_state: "failed", .. }`.
9. `unit_not_found_skips_point_1`.
10. `socket_path_not_a_socket_fails_point_3` — Resolved with `is_socket: false`.

**Step 2: Run** — `just test-rust -p piggy -- health` — expected: new tests FAIL where the Task-1 elided arms are wrong/incomplete.

**Step 3: Complete `evaluate`** until the matrix passes. No probe IO in this task.

**Step 4: Run** — expected: PASS.

**Step 5: Commit** — `test(piggy): pin the health evaluation matrix`.

---

### Task 3: Agent probes — identity count + query extensions

**Files:**
- Modify: `crates/piggy/src/agent_client.rs`
- Test: same file, `mod tests`

**Step 1: Write failing tests**

```rust
/// Missing socket surfaces a connect error string, not a panic/hang.
#[test]
fn identity_probe_on_missing_socket_errors_fast() {
    let err = probe_identities(Path::new("/nonexistent/health.sock"), Duration::from_secs(2))
        .expect_err("missing socket must fail");
    assert!(err.contains("connect"), "got: {err}");
}

#[test]
fn query_probe_on_missing_socket_errors_fast() {
    let err = probe_extensions(Path::new("/nonexistent/health.sock"), Duration::from_secs(2))
        .expect_err("missing socket must fail");
    assert!(err.contains("connect"), "got: {err}");
}

/// Flat-cstring encoding: repeated u32-len-prefixed strings.
#[test]
fn decode_query_response_flat_cstrings() {
    let mut buf = Vec::new();
    for name in ["query", super::tests_ecdh_name()] {
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
    }
    let names = decode_query_response(&buf).expect("flat encoding");
    assert!(names.iter().any(|n| n == super::tests_ecdh_name()));
}
```

Also add a test for the second wild encoding once read — **read `vendor/pivy/src/piv.c` lines ~6990–7060 first**: it documents the two `query` response encodings pivy tolerates (flat cstrings vs. the alternative). Mirror its dual-encoding parse and pin both with a test each.

**Step 2: Run** — `just test-rust -p piggy -- agent_client` — expected: FAIL (functions not defined).

**Step 3: Implement** in `agent_client.rs`, following the existing `unlock_agent_pin` shape (own current-thread runtime, fresh connection):

```rust
/// List the agent's identities; returns the key comments (count = len).
/// Health-check probe — fresh connection, bounded by `timeout`.
pub fn probe_identities(socket_path: &Path, timeout: Duration) -> Result<Vec<String>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let socket_path = socket_path.to_path_buf();
    runtime.block_on(async move {
        tokio::time::timeout(timeout, async {
            let stream = UnixStream::connect(&socket_path)
                .await
                .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
            let mut client = Client::new(stream);
            let ids = client
                .request_identities()
                .await
                .map_err(|e| format!("request_identities: {e}"))?;
            Ok(ids.iter().map(|i| i.comment.clone()).collect())
        })
        .await
        .map_err(|_| format!("timeout after {timeout:?}"))?
    })
}

/// Send the `query` extension and decode the supported-extension list.
pub fn probe_extensions(socket_path: &Path, timeout: Duration) -> Result<Vec<String>, String> {
    // same runtime/connect/timeout shell; then:
    //   client.extension(Extension { name: "query".into(), details: vec![].into() })
    // a None response (plain SUCCESS) or a failure both => Err.
    // decode_query_response(ext.details.as_ref())
}

/// Decode both wild encodings of the query response (see
/// vendor/pivy/src/piv.c query-response comment). NOTE: depending on the
/// ssh-agent-lib response plumbing, the leading echoed "query" name may
/// already be consumed; verify against the Rust agent in a manual run
/// (`piggy agent` + probe) before trusting the offset.
fn decode_query_response(details: &[u8]) -> Result<Vec<String>, String> { ... }
```

Check ssh-agent-lib 0.5's actual `request_identities` return type (`Vec<Identity>` with `comment: String`) before writing; adjust field access to match.

**Step 4: Run** — expected: PASS.

**Step 5: Commit** — `feat(piggy): agent identity/extension probes for health`.

---

### Task 4: systemctl probe + parser

**Files:**
- Modify: `crates/piggy/src/health.rs`

**Step 1: Failing tests** for the pure parser:

```rust
#[test]
fn parse_systemctl_show_active_unit() {
    let out = "LoadState=loaded\nActiveState=active\nSubState=running\nExecMainStatus=0\n";
    match parse_systemctl_show(out) {
        ServiceProbe::Unit { active_state, sub_state, exec_main_status } => {
            assert_eq!(active_state, "active");
            assert_eq!(sub_state, "running");
            assert_eq!(exec_main_status, "0");
        }
        _ => panic!("expected Unit"),
    }
}

#[test]
fn parse_systemctl_show_not_found_unit() {
    let out = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nExecMainStatus=0\n";
    assert!(matches!(parse_systemctl_show(out), ServiceProbe::UnitNotFound));
}
```

**Step 2: Run** — FAIL. **Step 3: Implement:**

```rust
fn parse_systemctl_show(stdout: &str) -> ServiceProbe { ... } // pure key=value walk

/// Run `systemctl --user show piggy-agent.service
/// --property=LoadState,ActiveState,SubState,ExecMainStatus`.
#[cfg(target_os = "linux")]
fn probe_service() -> ServiceProbe {
    // which-style lookup failure or spawn error -> NotAvailable(reason)
    // non-zero exit with usable stdout still parses (systemctl show
    // exits 0 even for inactive units; not-found is in LoadState)
}
#[cfg(not(target_os = "linux"))]
fn probe_service() -> ServiceProbe {
    ServiceProbe::NotAvailable("service check is Linux-only".into())
}
```

**Step 4: Run** — PASS. **Step 5: Commit** — `feat(piggy): systemd unit probe for health`.

---

### Task 5: Socket + pcsc/card probes and the gather function

**Files:**
- Modify: `crates/piggy/src/health.rs`

**Step 1: Failing tests** (pure/env-driven parts only; pcsc paths are exercised by bats in Task 9 and the fibby follow-up):

```rust
/// resolve_socket honors PIGGY_AUTH_SOCK over SSH_AUTH_SOCK and treats
/// empty as unset. Mutating env: keep this the only test touching these
/// vars in this module; snapshot + restore (see stats.rs env test).
#[test]
fn resolve_socket_precedence() { ... }

/// stat on a plain file yields is_socket=false with a stat_detail.
#[test]
fn stat_plain_file_is_not_a_socket() { ... } // tempdir + File::create
```

**Step 2: Run** — FAIL. **Step 3: Implement:**

```rust
fn resolve_socket() -> SocketProbe {
    // agent_client::piggy_auth_sock_override() else SSH_AUTH_SOCK
    // (non-empty); stat via std::os::unix::fs::FileTypeExt::is_socket.
}

fn probe_cards() -> (PcscProbe, Option<Vec<CardInfo>>) {
    // PivContext::new() error -> (PcscProbe::Error(e.to_string()), None)
    // enumerate_tokens() -> CardInfo per token:
    //   reader: token.reader_name(), guid: token.guid() hex/display,
    //   slot_9d_populated: token.read_slot(0x9d).is_ok()
    //   (read_slot returns Err(SlotEmpty) on empty slots — read-only,
    //    no PIN, per design constraint)
}

/// Probe phase: run everything defensively, short-circuit dependents.
pub fn gather() -> Probes {
    let service = probe_service();
    let socket = resolve_socket();
    let (agent, extensions) = match &socket {
        SocketProbe::Resolved { path, is_socket: true, .. } => {
            let ids = crate::agent_client::probe_identities(path, PROBE_TIMEOUT);
            // only query extensions when the agent answered at all:
            let exts = if ids.is_ok() {
                Some(crate::agent_client::probe_extensions(path, PROBE_TIMEOUT))
            } else {
                None
            };
            (Some(ids), exts)
        }
        _ => (None, None),
    };
    let (pcsc, cards) = probe_cards();
    Probes { service, socket, agent, extensions, pcsc, cards }
}
```

`gather()` itself gets no unit test (pure IO); `evaluate` owns all decisions.

**Step 4: Run** — PASS. **Step 5: Commit** — `feat(piggy): health probe phase (socket, pcsc, cards, gather)`.

> **Milestone: end of unblocked work.** Tasks 6–10 wait for the tap-dancer release from tap/clear-cherry. Park here if it hasn't shipped; check `gh release list -R amarbel-llc/tap` / the tap repo for the ndjson writer landing.

---

### Task 6 (GATED): tap-dancer git dependency

**Files:**
- Modify: `crates/piggy/Cargo.toml`, `Cargo.lock`, `flake.nix`

**Step 1:** Add to `crates/piggy/Cargo.toml` `[dependencies]` (pin the released tag):

```toml
# TAP-14 text + tap-ndjson(7) writers for `piggy health`. Git dep on the
# spec repo's Rust crate; see docs/plans/2026-06-07-piggy-health-design.md.
tap-dancer = { git = "https://github.com/amarbel-llc/tap", tag = "vX.Y.Z" }
```

**Step 2:** `just validate-rust -p piggy` to refresh `Cargo.lock` and confirm resolution.

**Step 3:** Teach the nix build the git dep — in `flake.nix`, BOTH `cargoLock` blocks (piggy-rs at ~:189 and fibby at ~:244) need:

```nix
cargoLock = {
  lockFile = ./Cargo.lock;
  outputHashes = {
    "tap-dancer-<version>" = "sha256-..."; # nix will print the expected hash on first failure
  };
};
```

**Step 4:** `git add Cargo.lock crates/piggy/Cargo.toml flake.nix` (REQUIRED before nix build — untracked/unstaged changes are invisible to it), then `just build` and fix the outputHashes from the mismatch error.

**Step 5: Commit** — `build(piggy): depend on tap-dancer for TAP/ndjson writers`.

---

### Task 7 (GATED): HealthSink trait + both sinks

**Files:**
- Modify: `crates/piggy/src/health.rs`

**Step 1: Failing tests** — byte-exact rendering against `Vec<u8>`, mirroring `reencrypt.rs`'s tap tests:

```rust
/// TAP sink: version line, 1..9 plan, points with SKIP directives, YAML
/// diags on failures (always) and passes (only under verbose).
#[test]
fn tap_sink_renders_mixed_results() { ... } // assert_eq! full string

/// ndjson sink: one JSON object per line; first = plan record, then one
/// test record per point (skip reason + diagnostics map), last =
/// summary record per tap-ndjson(7). Parse each line with serde_json
/// and assert the discriminating fields rather than full byte-equality
/// if tap-dancer owns field ordering.
#[test]
fn ndjson_sink_renders_records_per_tap_ndjson_7() { ... }
```

Consult `man tap-ndjson` for record fields; consult the released tap-dancer API (`~/eng/repos/tap/rust/src/lib.rs`) for the writer's constructor and point-emission calls. **The design's chat-relay to tap/clear-cherry asked for: writer generic over `io::Write`, up-front plan, skip-with-reason, per-point diagnostics, summary record.** If the shipped API diverges, adapt the sink impls — `evaluate` and `CheckResult` must not change.

**Step 2: Run** — FAIL. **Step 3: Implement:**

```rust
pub trait HealthSink {
    fn render(&mut self, results: &[CheckResult]) -> std::io::Result<()>;
}
pub struct TapSink<W: std::io::Write> { /* TapWriter + verbose flag */ }
pub struct NdjsonSink<W: std::io::Write> { /* ndjson writer + verbose */ }
```

**Step 4: Run** — PASS. **Step 5: Commit** — `feat(piggy): TAP and ndjson sinks for health`.

---

### Task 8 (GATED): clap wiring + stats + tty switching

**Files:**
- Modify: `crates/piggy/src/main.rs`, `crates/piggy/src/health.rs`, `crates/piggy/src/stats.rs`

**Step 1: Failing test** in `stats.rs`:

```rust
#[test]
fn payload_health_category() {
    assert!(payload("health", "run", Outcome::Success, 5)
        .starts_with("piggy.health.run.success:1|c|"));
}
```

**Step 2:** FAIL (nothing to fail yet — the payload fn is generic; the test passes immediately. Keep it as a pin, then move on). Add to `stats.rs`:

```rust
/// `piggy health` telemetry: `piggy.health.run`.
pub fn timed_health<F: FnOnce() -> i32>(f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    record("health", "run", outcome_of_code(code), start.elapsed());
    code
}
```

**Step 3:** `main.rs` — new variant after `Version` (visible, proper clap args like `Verify`/`ShowBatch`, NOT trailing_var_arg):

```rust
/// Run piggy-layer health checks (piggy-agent socket/identities/ecdh
/// extension, pcscd + attached cards + 9D slots, piggy-agent.service)
/// and report TAP-14 on a tty or tap-ndjson(7) records otherwise.
Health(HealthCmdArgs),

#[derive(Args, Debug)]
struct HealthCmdArgs {
    /// Output format; `auto` switches on whether stdout is a tty.
    #[arg(long, value_enum, default_value_t = HealthFormat::Auto)]
    format: HealthFormat,
    /// Attach the diagnostic block to every point, not just failures.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum HealthFormat { Auto, Tap, Ndjson }
```

Dispatch:

```rust
Command::Health(args) => std::process::exit(piggy::stats::timed_health(|| {
    health::run(args.format.into(), args.verbose)
})),
```

`health::run(format, verbose) -> i32`: resolve `Auto` via `std::io::IsTerminal` on stdout (`use std::io::IsTerminal; std::io::stdout().is_terminal()`), `gather()` → `evaluate()` → chosen sink → `exit_code()`.

**Step 4:** `just build-rust -p piggy`, then a manual smoke: `target/debug/piggy health --format tap; echo $?` (expect a 1..9 stream; on this dev machine points will reflect the live agent). Confirm `--format ndjson` emits one JSON object per line.

**Step 5: Commit** — `feat(piggy): wire `piggy health` into clap with tty-switched output`.

---

### Task 9 (GATED): bats integration

**Files:**
- Create: `zz-tests_bats/t0800-health.bats`

**Step 1:** Write the tests (sandboxed lane: no pcscd, no tty — both useful). Follow `zz-tests_bats/t0700-verify.bats` for harness shape; `load common` gives the mock PATH + temp HOME. Cases:

```bash
#!/usr/bin/env bats
load common

@test "health: no sockets resolvable -> point 2 not ok, dependents skip, exit nonzero" {
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format tap
  [ "$status" -ne 0 ]
  [[ "${lines[0]}" == "TAP version 14" ]]
  [[ "${lines[1]}" == "1..9" ]]
  echo "$output" | grep -q "not ok 2 - agent: socket resolved"
  echo "$output" | grep -q "ok 3 - agent: socket exists # SKIP"
}

@test "health: PIGGY_AUTH_SOCK at a dead path -> point 3 not ok" {
  export PIGGY_AUTH_SOCK="$BATS_TEST_TMPDIR/nope.sock"
  run "$PIGGY" health --format tap
  [ "$status" -ne 0 ]
  echo "$output" | grep -q "not ok 3 - agent: socket exists"
}

@test "health: ndjson format emits parseable records with a summary" {
  unset PIGGY_AUTH_SOCK SSH_AUTH_SOCK
  run "$PIGGY" health --format ndjson
  [ "$status" -ne 0 ]
  # every line is JSON; the last is the summary record
  while IFS= read -r line; do jq -e . <<<"$line" >/dev/null; done <<<"$output"
  jq -e 'select(.type == "summary")' <<<"${lines[-1]}" >/dev/null
}

@test "health: pcscd absent in sandbox -> point 6 not ok, 7-9 skip" {
  run "$PIGGY" health --format tap
  echo "$output" | grep -q "not ok 6 - pcsc: daemon reachable"
  echo "$output" | grep -q "# SKIP"
}
```

Adjust assertions to the real tap-dancer output (point text casing, SKIP rendering) by running one case first; keep assertions on stable substrings, not full lines, where tap-dancer owns formatting. Verify `jq` is available in the bats lane closure (check `bats.nix` `extraEnv`/inputs; add it if absent).

**Step 2:** `just test-bats-file zz-tests_bats/t0800-health.bats` — iterate to green.

**Step 3:** Confirm the sandboxed lane picks the file up: it matches `zz-tests_bats/t*.bats`, no `file_tags` needed.

**Step 4: Commit** — `test(piggy): bats coverage for piggy health`.

---

### Task 10 (GATED): docs + follow-ups

**Files:**
- Modify: `CLAUDE.md`

**Steps:**
1. CLAUDE.md: add `health` to the Architecture overview (top-level Rust handlers list) and a Key Files entry for `crates/piggy/src/health.rs` (one-line: 9 checks, TAP/ndjson, design-doc pointer). Mention the tap-dancer git dep next to the flake.nix Key Files entry.
2. File the follow-up issue via the `/eng:file-issue` skill: fibby-backed all-green `piggy health` conformance bats (hardware lane) — reference design doc Testing section. Add a TaskCreate entry for it per global CLAUDE.md (followup issues become task-list items).
3. Run `just codemod-fmt`; commit — `docs(piggy): document piggy health`.
4. `mcp__spinclass__nothing-but-the-truth` attestation, then `merge-this-session` (its hook runs the full suite — do NOT pre-run `just`).
