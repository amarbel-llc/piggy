---
status: draft
date: 2026-06-15
provenance: |
  Plan to retire the Java-based `fib` virtual PIV card (jCardSim +
  PivApplet + vsmartcard-vpcd + private pcscd) in favor of the pure-Rust
  `fibby` (crates/fibby), now that fibby's virtual backend implements a
  full PIV applet and already backs most of the conformance lane.
  Supersedes the "keep fib as differential oracle" framing in
  docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md once the
  validation gates below are met. Roadmap: umbrella #3, triage #26,
  fib-limitation tracker #83. Companion: docs/virtual-piv.md (the fib
  user guide this plan retires).
---

# Retire `fib` in favor of `fibby`

## TL;DR

`fibby` (`crates/fibby`) is no longer the stub the 2026-05-29 design doc
describes. `crates/fibby/src/virtual_card.rs` is ~3,100 lines of a real
PIV applet — admin-key mutual auth (GENERAL AUTHENTICATE phase 1/2),
slot-9D ECDH, attestation, GENERATE — with tests pinned against real
YubiKey wire captures. The conformance lane already drives **real
crypto** through `--backend virtual` (`zz-tests_bats/lib/fibby.bash:16`,
`spawn_fibby … --backend virtual`). Six conformance bats files run on
fibby today with zero fib.

What still depends on `fib` is a bounded set of conformance/integration
recipes plus the whole Java toolchain (`nix/virtual-piv.nix`,
`crates/fib-wait-ready`, the `fib-*` flake outputs, the `fib-up/down/
shell/smoke` justfile recipes, `docs/virtual-piv.md`). This plan
migrates those lanes to fibby, deletes the fib infrastructure, and keeps
the fib-derived **test fixtures** (they are static data, separable from
the tool).

The single unknown that gates deletion is whether fibby's virtual
backend satisfies every APDU the still-fib lanes issue (notably the C
`pivy-box` interop path and `pass init`). Phase 1 is a spike that
answers that before anything is deleted.

## Why now

`fib`'s cost is unchanged from the fibby design doc's motivation:
heavy Java/Maven/Oracle-JavaCard toolchain, Linux-only (no macOS CI
lane), operationally fiddly (JVM + TCP relay + private pcscd + INSTALL
APDU + readiness probe), and opaque (we debug someone else's Java
applet). What *has* changed is that fibby is now mature enough to carry
the load — so the cost no longer buys us anything the Rust card can't.

## Current state (who uses what)

**Already on fibby** (`spawn_fibby`, no fib):
- `conformance/piggy_recipients_sync_fibby.bats`
- `conformance/age_plugin_piggy_fibby.bats`
- `conformance/piggy_pass_ls_recipients_fibby.bats`
- `conformance/piggy_ssh_via_fibby.bats`
- `conformance/piggy_fibby_pivy_agent_smoke.bats`
- `conformance/piggy_agent_pin_on_demand.bats`
- `conformance/pivy_agent_pin_on_demand.bats`

**Still on fib** (`just fib-up` inside the recipe):
- `test-bats-conformance-interop` → `piggy_box_interop.bats`,
  `piggy_box_decrypt_interop.bats` (piggy-box ↔ **C pivy-box** on one
  card)
- `test-bats-conformance-recipients-add-attached` →
  `piggy_recipients_add_attached.bats`
- `test-bats-conformance-init` → `piggy_pass_init.bats`
- `test-bats-conformance-show-batch` →
  `piggy_pass_show_batch_hardware.bats`
- Rust integration recipes: `test-rust-agent-ecdh`,
  `test-rust-agent-unlock`, `test-rust-card-unlock`,
  `debug-interop-stream-bytes`
- Differential-oracle recipes: `debug-fibby-roundtrip-via-fib`,
  `debug-fibby-proxy-via-fib`
- Operational/debug: `fib-up`, `fib-down`, `fib-shell`, `fib-smoke`,
  `debug-fib-pivy-trace`, `explore-x25519-pivapplet`

## Removal surface

- **nix**: `nix/virtual-piv.nix` (entire file); flake outputs `fib`,
  `fib-bundle`, `fib-reader-conf`, `fib-pcscd`, `jcardsim`, `pivapplet`;
  the Linux-only `virtualPiv.fib` devShell entry. Plus any vendored
  Maven closure under `nix/jcardsim-m2/`.
- **justfile**: delete `fib-up`/`fib-down`/`fib-shell`/`fib-smoke`/
  `debug-fib-pivy-trace`/`explore-x25519-pivapplet`; flip the ~8
  fib-backed test recipes to a fibby spawn pattern; delete the
  `debug-fibby-*-via-fib` oracle recipes last.
- **crate**: delete `crates/fib-wait-ready` (only `fib-up` uses it);
  drop it from the Cargo workspace members.
- **docs**: retire/rewrite `docs/virtual-piv.md`; update the fib
  references in `docs/plans/2026-05-12-recipients-add-attached-{plan,
  design}.md` and the fibby design doc; optional CLAUDE.md note.
- **fixtures** (KEEP): `crates/fibby/tests/fixtures/apdu/fib-*.fixture`
  and `crates/fibby/tests/fixtures/captures/fib/` are fib-derived
  baselines — static regression vectors that replay without the tool.
  They stay.

## Non-goals

- **Not** solving multi-card. fibby replies a single `ReaderState`
  (`crates/fibby/src/server.rs:248`), exactly like fib — so the
  `--all-attached` multi-card permutations are equally unsupported by
  both today. Multi-reader fibby is tracked by #83 and is out of scope
  here; this plan only moves the single-card cases.
- **Not** adding macOS coverage. Neither fib (Linux-only) nor fibby
  (PCSCLITE_CSOCK_NAME ignored on macOS, per the darwin feasibility
  doc) runs there; that stays a separate effort.
- **Not** touching the `bats-default` sandboxed lane (it uses mocks,
  not fib or fibby).

## Plan

### Phase 1 — Spike the unknown lanes (no deletions)

Prove fibby's virtual backend satisfies the still-fib lanes before
removing anything. For each, stand up a fibby-backed variant alongside
the fib one and confirm parity:

1. `pass init` (`test-bats-conformance-init`): the admin-key/PUT-DATA/
   GENERATE init flow is the most applet-exercising path. Run it
   against `spawn_fibby --backend virtual`; fix any APDU the applet
   doesn't answer.
2. `piggy box` interop (`test-bats-conformance-interop`): piggy-box ↔ C
   `pivy-box` against one fibby card. Confirm C pivy-box completes its
   init/encrypt/decrypt APDU sequence against fibby.
3. `show-batch` hardware lane (`test-bats-conformance-show-batch`):
   bulk decrypt; should be covered once #1 works.

**Gate**: every spiked lane is green on fibby. Any applet gap is filed
and fixed in `crates/fibby` (with a unit test pinned to the relevant
capture) before proceeding. If a gap is large enough to be its own
project, pause and re-scope — do not delete fib with a lane still red.

### Phase 2 — Migrate the Rust integration recipes

Move `test-rust-agent-ecdh`, `test-rust-agent-unlock`,
`test-rust-card-unlock`, and `debug-interop-stream-bytes` off
`just fib-up` onto a shared fibby fixture (mirror `lib/fibby.bash`'s
spawn for the Rust harness, or expose a `#[cfg(test)]` fibby spawn
helper). Keep `PIGGY_TEST_FIB_PIN=123456` (fibby honors the same test
PIN). Green on fibby.

### Phase 3 — Flip the conformance recipes & delete fib infra

Once Phases 1–2 are green:
1. Rewrite the fib-backed conformance recipes to spawn fibby; delete
   `fib-up`/`fib-down`/`fib-shell`/`fib-smoke` and the fib-only debug/
   explore recipes.
2. Delete `nix/virtual-piv.nix`, the `fib-*`/`jcardsim`/`pivapplet`
   flake outputs, the devShell entry, and `nix/jcardsim-m2/` if no
   longer referenced.
3. Delete `crates/fib-wait-ready`; drop it from the workspace.
4. Retire/rewrite `docs/virtual-piv.md` and update the plan/design doc
   references.

### Phase 4 — Retire the differential oracle (last)

`debug-fibby-roundtrip-via-fib` / `-proxy-via-fib` use fib to validate
fibby. The fibby design doc planned to keep fib as a differential
oracle "for one release." Remove these recipes only after fibby has
carried the conformance lane through at least one release cycle without
a fib-attributable miss. Keep the fib-derived fixtures regardless.

## Validation gates (must hold before each deletion)

- Every lane being migrated is **green on fibby** before its fib
  counterpart is deleted (no flag-day; fibby variant proven first).
- `nix build .#bats-default` (the authoritative CI gate) stays green
  throughout — it doesn't use fib, so it should be unaffected, which is
  itself a check that the migration didn't leak fib coupling into the
  sandboxed lane.
- The fib-derived fixtures still replay (`crates/fibby/tests/replay.rs`)
  after the tool is gone.

## Rollback

The work lands as separate PRs per phase. Reverting any phase restores
the fib recipe/infra it removed. Until Phase 3 lands, fib and fibby
coexist (Phase 1–2 add fibby variants without deleting fib), so a
regression at any point reverts to the still-present fib lane.

## Open questions

1. Does C `pivy-box` issue any APDU during init/encrypt that fibby's
   virtual backend doesn't yet answer? (Phase 1 #2 answers this.)
2. Does `piggy_recipients_add_attached.bats` exercise only the
   single-card attached case, or does it depend on fib presenting a
   card in a way fibby's single `ReaderState` doesn't match? (Confirm
   before migrating that lane; if it needs multi-card it stays blocked
   on #83 and is excluded from this plan.)
3. Is `nix/jcardsim-m2/` referenced by anything other than
   `nix/virtual-piv.nix`? (Confirm before deleting.)
