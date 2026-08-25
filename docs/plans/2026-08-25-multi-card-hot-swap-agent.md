# Multi-card, hot-swappable piggy-agent: sequenced design

- **Date**: 2026-08-25
- **Status**: proposed
- **Driver**: the 2026-08-25 multi-card user-story survey (validated
  requirements below), folded together with the #179 enumeration-vs-sign
  lessons. Sibling to FDR 0001 (proxy-only agent) and the piggy#215 agent
  arc.

## Motivation

`piggy agent` already serves keys from multiple cards (`-A`) and can pin a
single card (`-g`), with per-card PIN isolation (#177). The survey
validated those as requirements and added one the current code does not
meet: **cards must be hot-swappable at runtime**, not fixed at startup.
Two hazards surfaced alongside it:

- **#244** — the card-presence probe is single-"primary"-card
  (`spawn_probe_loop(primary_guid)`), so under `-A` a removed *secondary*
  card's PIN is never cleared.
- **Story 4 (destructive `ssh-add -X`)** — the per-card PIN *offer*
  speculatively verifies against every card, and a wrong offer consumes
  that card's PIN-retry counter; PIV cards lock after 3 wrong tries, so a
  mis-offered PIN can brick a sibling card.

## Validated requirements (2026-08-25 survey)

1. Serve all attached cards via one agent (`-A`) — **hot-swappable**.
2. Target one card (`-g`) — **hot-swappable** (survive remove + reinsert).
3. Independent per-card PINs (#177) — required; PINs MUST NOT cross cards.
4. `ssh-add -X` per-card offer — **examine; must not be destructive**.
5. On removal: clear the card's PIN **and** drop its keys (full hot-unplug).
6. Startup self-heal (#175) — keep; but its "won't adopt a can't-sign
   card" guarantee is weaker than it reads (see The #179 lesson).
7. Deployment: single-agent `-A` is **primary**; one-instance-per-card
   (#162) secondary.
8. Test substrate: fibby needs insert/remove simulation (#130).

## The #179 lesson (load-bearing)

The card-access layer is **already stateless**: every operation does a
fresh `reconnect_to_token()` (new PCSC context, one-shot transaction, no
persistent handle). #179 proved the recovered-agent "can't sign" wedge was
NOT a stale card session — the sign path is byte-identical whichever way
keys were loaded. The confirmed cause lived *around* the card: a long-lived
`systemd --user` agent whose environment is frozen display-blind at boot,
so its lazy (spawned-at-sign-time) zenity PIN prompt could not open a
display — every enumeration-only check passed while every real sign was
refused. Fixed at the askpass layer (lazy display-reattach in
`contrib/piggy-askpass.sh`), detected by `piggy health --sign-test`.

Two consequences for this design:

- **Statelessness is the asset.** Hot-swap is cheap at the card layer —
  removal is "stop advertising + forget PIN", with no handle to tear down.
- **Enumeration != signable.** Adoption must stay enumeration-based (cheap,
  PIN-free), and "sign-capable" must remain a *separate, observable* fact.
  Never gate adoption on a PIN-costing sign — that would relocate story 4's
  destructiveness into the lifecycle.

## Organizing principle

The hot-swap requirement and the #179 hardening converge on ONE refactor:
replace the single-primary probe loop with a **per-card, event-driven
lifecycle**. The sequence builds that spine, gated behind the test
substrate.

## Sequence

### Phase 0 — Test substrate (gating dependency)

**Goal:** make insert/remove events simulatable, or nothing downstream is
CI-verifiable.

- fibby hot-plug events (#130) — real `SCardGetStatusChange` insert/remove.
- fibby PIN-retry counter — a decrementing counter + lockout, needed by
  Phase 1's test. *(New fibby capability.)*
- Extend the #242 multi-card lane to drive insert/remove/lockout sequences.

**Exit:** a bats test starts an agent, then inserts/removes a fibby card and
observes the socket's identity list change; a card can be driven toward (and
observed at) PIN lockout.

### Phase 1 — `ssh-add -X` lockout safety (story 4)

**Goal:** kill the destructive PIN-retry-lockout path before touching the
lifecycle. Independent of the refactor; highest risk-reduction.

- Before speculatively verifying an offered PIN against a card, **query
  remaining retries** (PIV `VERIFY`-query is non-consuming) and skip any
  card near lockout; keep `offered_rejected_by`.
- **Decision:** retry-guarded broadcast (minimal) vs. **targeted offer**
  (apply an offered PIN only to the card an operation is about to use,
  never speculatively). Recommendation: ship the retry-guard now; decide
  targeted-offer as the cleaner end-state.

**Exit:** a fibby card seeded with a wrong PIN + low retry count is never
driven to lockout by an offered PIN; the test asserts the counter is
preserved.

**Depends on:** Phase 0 (PIN-counter).

### Phase 2 — Per-card presence lifecycle (#244 + hot-swap; the spine)

**Goal:** replace `spawn_probe_loop(primary_guid)` with a per-card,
event-driven tracker.

- **Remove event:** drop that GUID's identities + `PinCache::forget_card`
  (story 5: clear PIN *and* drop keys; closes #244).
- **Insert event:** enumerate + adopt + advertise — for `-A` (hot-add any
  card) and for `-g` (re-adopt the pinned GUID on reinsert = hot-swap).
- **Subsume the #175 recovery loop:** 0-key startup becomes "no card
  present yet"; a later insert is just an insert event — **but** the loop
  must distinguish **transient PCSC denial** (polkit-not-yet-active → retry,
  the #175 trigger) from **genuinely absent** (wait for event). Keep the
  stateless reconnect and the #214 card-lock try-lock discipline.

**Exit:** fibby insert/remove drives the identity list; a removed card's PIN
is forgotten (proven by a subsequent op re-prompting); `-A` adopts a card
inserted at runtime; `-g` survives remove + reinsert.

**Depends on:** Phase 0.

### Phase 3 — Signal honesty (#179 / #178 lesson, per-card)

**Goal:** keep "enumeration != signable" honest across the multi-card
surface — adopt on enumeration, never claim usable without evidence.

- Verify per-card sign-refusal logging (slot + guid + cause, #178) covers
  the multi-card path.
- Verify `--sign-test` reports **per card** PASS/FAIL against a multi-card
  agent.
- **Do not** gate adoption on a PIN-costing sign. Default `piggy health`
  stays PIN-free.

**Exit:** `--sign-test` distinguishes a wedged card from a healthy one in a
multi-card agent; a wedged secondary card is visible, not hidden behind
enumeration.

**Depends on:** Phase 2.

### Phase 4 — Docs + regression guard

- FDR for the multi-card hot-swap agent (or extend the FDR 0001 family);
  update AGENTS.md + the HM module if options change.
- **Guard the already-landed #179 root-cause fix** (askpass lazy
  display-reattach) against regression — inherited free (per-agent,
  orthogonal to cards), but the lazy-prompt-at-sign-time model must stay
  intact.

## Open design decisions

- **Targeted offer vs. retry-guarded broadcast** (Phase 1).
- **Whether Phase 2 fully subsumes the #175 recovery loop** — it must
  distinguish transient PCSC denial from genuinely-absent before the
  recovery loop can be retired.
- **Health verdict for a non-sign-capable advertised card** — surface as a
  warning-class point, or stay opt-in via `--sign-test` only?

## Cross-cutting notes

- Card access stays stateless (its statelessness is *why* hot-swap is cheap).
- `-A` is primary; multi-instance (#162) inherits the lifecycle per-instance.
- The #179 cure already shipped; Phase 4 guards against re-hiding the
  failure, it does not rebuild it.

## Tracking

- **Umbrella: piggy#247.**
- Phase 0 -> #130 (fibby hot-plug) + #246 (fibby PIN-retry counter).
- Phase 1 -> #245 (`ssh-add -X` lockout safety; #177 follow-up).
- Phase 2 -> #244 (per-card presence lifecycle).
- Phase 3 -> #179 / #178.
- Phase 4 -> this doc + an FDR.
