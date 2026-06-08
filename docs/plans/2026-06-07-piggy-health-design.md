# `piggy health` — agent/card/service checks with TAP output

- **Date**: 2026-06-07
- **Status**: approved
- **Driver**: the 2026-06-07 ssh-agent-mux/eng debugging sessions (mux unit
  fight + piggy-agent silently serving 0 identities after losing the
  boot-time pcscd race). `ssh-agent-mux health` (designed in the parallel
  mux session) owns the mux layer; `piggy health` owns the piggy layer.

## Scope

In scope: agent-protocol checks, card/PCSC checks, service-manager check.
Out of scope (explicitly declined): store/recipient checks (store dir,
piggy-ids parse, store-recipients ∩ attached-cards).

## CLI surface

`piggy health` — new **top-level** clap subcommand (sibling of
`list`/`agent`/`box`), handler `crates/piggy/src/health.rs`. Telemetry:
`piggy.health` via `crate::stats` (own category; not a `pass` subcommand).

Flags:

- `-v, --verbose` — diagnostic block on every point, not just failures
  (mirrors `recipients sync -v`).
- `--format <auto|tap|ndjson>` (default `auto`) — `auto` = TAP-14 text
  when stdout is a tty, tap-ndjson(7) records otherwise. Explicit values
  exist so bats can assert both formats without a pty.

Output discipline: stdout carries only the TAP/ndjson stream; probe and
subprocess stderr stays on stderr (same contract as the reencrypt walk).
Plan is known up front (fixed check list) → emitted ahead of points.

Exit code: `0` iff every point is `ok` (SKIP counts as ok); non-zero
otherwise (same propagation rule as `reencrypt::run`).

## Check list (fixed order, `1..9` plan)

Dependent checks **SKIP with a reason** when a prerequisite failed — no
duplicate-fail cascades. All card operations are **read-only** (enumerate
+ cert read): no PIN, no key use, no decrypt, no prompt path.

| # | point | semantics |
|---|---|---|
| 1 | `service: piggy-agent.service active` (Linux) / `service: piggy-agent launchd agent active` (macOS) | **Linux:** `systemctl --user show piggy-agent.service --property=LoadState,ActiveState,SubState,ExecMainStatus`. ok = active; not ok = unit exists but inactive/failed (diag: the four properties); SKIP = no systemctl or `LoadState=not-found` (manual agent setups stay green). **macOS:** `launchctl print gui/$UID/org.nix-community.home.piggy-agent` (the home-manager-assigned label — the `org.nix-community.home.` prefix is launchd-specific). ok = **loaded** (label present in the domain); the real launchd `state`/`last exit code` ride in the `sub_state`/`exec_main_status` diags. "loaded == healthy" because an `OnDemand` agent is legitimately loaded-but-idle (no live PID) between SSH requests — a truly dead agent is caught by points 2–5, not here. SKIP = label absent (exit 113 / "Could not find service" → no unit installed), no launchctl, or unparseable output. **Other unixes:** SKIP (unsupported). |
| 2 | `agent: socket resolved` | `PIGGY_AUTH_SOCK` override else `SSH_AUTH_SOCK` (resolver: `agent_client::piggy_auth_sock_override`). Diag: `source`, `path`. not ok = neither set/non-empty. |
| 3 | `agent: socket exists` | stat: path is a unix socket. SKIP if 2 failed. |
| 4 | `agent: answers request_identities` | connect + list. Diag: `identities: N` (+ key comments under `-v`). SKIP if 3 failed. |
| 5 | `agent: advertises ecdh@joyent.com` | `query` extension, handling both response encodings found in the wild (see `vendor/pivy/src/piv.c` query-response comment). not ok if query unsupported **or** the ecdh extension is absent — either way piggy decrypts will fail; this is the piggy#123 mux-capability-drop catch. SKIP if 4 failed. |
| 6 | `pcsc: daemon reachable` | `PivContext` establish; not ok carries the pcsc error string ("PC/SC system service/daemon not available" symptom from CLAUDE.md). |
| 7 | `card: PIV card attached` | `PivContext::enumerate_tokens()` ≥ 1. Diag per card: reader, guid. SKIP if 6 failed. |
| 8 | `card: key-management slot 9D populated` | ≥1 attached card has 9D occupied; per-card diag. SKIP if 7 found no cards. |
| 9 | `agent serves attached card` | the 2026-06-07 breakage: not ok if 8 passed but point 4 saw `identities: 0` (diag: "pcscd race or locked agent — restart piggy-agent"). SKIP if 4 or 8 produced no data. |

Point 9 is count-based. Pubkey-level matching (agent identity blobs ∩
card pubkeys, catching wrong-card-attached) is deferred as YAGNI until a
real incident needs it.

### Zero-identities semantics (decided)

An agent answering with 0 identities is **only** a failure when
cross-referenced against an attached, provisioned card (point 9). Point 4
itself passes with `identities: 0` as a diagnostic; if no card is
attached, point 7 is the red point and 9 SKIPs.

## Output formats

- **TAP-14 text** (tty): via the `tap-dancer` Rust crate
  (`TapWriterBuilder::auto` — color, locale, tty handling).
- **tap-ndjson(7)** (non-tty): one `test` record per check + a final
  `summary` record, via the ndjson writer being added to the tap-dancer
  Rust crate in the **tap/clear-cherry** spinclass session ("add
  tap-ndjson(7) writer support to the Rust crate (for ssh-agent-mux +
  piggy health commands)").

Rejected alternatives: hand-rolling a third piggy-local emitter
(drift risk vs tap-ndjson(7), mux would duplicate it); piping through the
Go `tap-dancer format-ndjson` CLI (runtime binary dep).

## Architecture

`crates/piggy/src/health.rs`:

- **Probe phase**: each check is a function writing into a shared `Ctx`
  (identity count, enumerated tokens, …) and returning a
  `CheckResult { name, status: Pass | Fail | Skip(reason), diags }`.
  Cross-check 9 reads `Ctx` — plain data flow, no second probe pass.
- **Render phase**: `Vec<CheckResult>` → a thin piggy-internal
  `HealthSink` trait; impls `TapSink` (tap-dancer `TapWriter`) and
  `NdjsonSink` (clear-cherry writer). The trait exists so probe logic and
  unit tests land before the tap-dancer release; the sink impls are the
  only code blocked on it.
- Agent probing reuses the `agent_client.rs` shape (ssh-agent-lib client,
  fresh connection per probe); adds `query_extensions(socket)` there.
  Every probe runs under a timeout so a hung agent yields `not ok`, not a
  hung health command.
- systemd probe is `#[cfg(target_os = "linux")]`; elsewhere SKIP.

Dependency: `tap-dancer = { git = "https://github.com/amarbel-llc/tap" }`
plus one `cargoLock.outputHashes` entry in `flake.nix` (covers both
`piggy-rs` and `fibby`, which share the lockfile).

## Sequencing (blocked on tap/clear-cherry)

1. **Commit 1 (unblocked)**: `health.rs` probe runner, checks, `HealthSink`
   trait, unit tests.
2. **Commit 2 (gated on a tap-dancer release containing the ndjson
   writer)**: git dep + `outputHashes`, both sinks, clap wiring, bats,
   CLAUDE.md docs.

Coordinate by sending the tap/clear-cherry session piggy's consumer
needs: up-front plan, SKIP-with-reason, per-point diagnostics, summary
record, writer generic over `io::Write`.

## Testing

- **Rust unit tests**: SKIP-cascade and cross-check logic against fake
  probe results; byte-exact output pinned for both sinks (like
  `reencrypt`'s tap module tests).
- **bats** `zz-tests_bats/t0800-health.bats` (sandboxed lane): no pcscd
  in the sandbox + `PIGGY_AUTH_SOCK` pointed at controlled fixtures gives
  deterministic fail/skip patterns; assert both `--format`s' wire output.
- **Follow-up issue**: fibby-backed all-green conformance file
  (hardware-tagged lane).

## Rollback

Purely additive subcommand: nothing replaced, no dual-architecture
period needed. Rollback = revert the commits; no persisted state, no
downstream wire consumers at introduction.

## Tuning levers

| lever | initial value | change signal |
|---|---|---|
| per-probe timeout | 2s | false `not ok` timeouts on slow readers/agents |
| point 9 strictness | count-based | a wrong-card-attached incident → pubkey matching |
| check-list composition | agent + card + service | a debugging session that needed a store-layer check |
