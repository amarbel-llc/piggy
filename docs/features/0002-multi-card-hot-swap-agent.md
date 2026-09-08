---
status: experimental
date: 2026-08-25
promotion-criteria: >
  The per-card hot-swap lifecycle validated on real multi-card hardware
  (two or more physical YubiKeys), not just fibby: removing a card drops
  its keys AND forgets its PIN while a sibling is untouched; re-inserting
  re-adopts it; a card busy with a request under load is never falsely
  evicted; and the `ssh-add -X` lockout guard is confirmed against a real
  card's retry counter. fibby (virtual cards) validates all of this today;
  real hardware is the outstanding soak.
---

# Multi-card hot-swap agent

## Problem Statement

`piggy agent -A` serves keys from every attached PIV card, but the
card-presence machinery was single-card. One probe loop keyed to the
"primary" GUID cleared only that card's PIN on removal; a separate
piggy#175 recovery loop handled a 0-key startup; a piggy#143 loop handled
a CAK swap. Under `-A`, a removed *secondary* card's keys lingered in the
served set and its PIN was never forgotten (piggy#244) — a correctness and
security-hygiene gap.

Two more gaps blocked a real hot-swap story:

- **No test substrate.** fibby's virtual card was fixed at startup, so a
  card being removed or inserted mid-run could not be exercised in CI.
- **A destructive `ssh-add -X`.** The per-card PIN cache (piggy#177) treats
  an `ssh-add -X` PIN as an *offer* speculatively verified against each
  card; a wrong offer consumes that card's PIN-retry counter, and a PIV
  card locks after three wrong tries — so an offer meant for one card could
  brick a sibling (piggy#245).

The 2026-08-25 user-story survey validated runtime hot-swap (add and
remove) as a requirement for both `-A` (serve-all) and `-g` (target-one).

## Interface

One agent, reacting to the cards physically present:

- **`piggy agent -A` is hot-swappable.** A single per-card **reconcile
  loop** (`cmd/agent/card.rs::reconcile_loop`) replaces the three
  single-guid loops. Each tick, under the piggy#214 card lock (`try_lock`,
  so a tick never races an in-flight request), it re-enumerates the desired
  set (`load_cached_keys_from_cards`, which already applies the guid
  filter, all-cards selection, and the piggy#143 CAK anti-swap) and
  reconciles the served `keys` vec by GUID:
  - a served card absent for `PROBE_FAIL_LIMIT` (3) consecutive ticks has
    its keys dropped and its PIN forgotten (`PinCache::forget_card`); a
    per-GUID miss counter debounces a transient blip, and a sibling card is
    untouched (piggy#177);
  - a newly-present card is adopted only once it round-trips the sign-path
    reconnect probe (`session::reconnect_to_token`, the piggy#179 gate), so
    a card that enumerates but cannot sign is never served.
  This subsumes the piggy#175 0-key recovery (a card appearing is just an
  adoption) and the piggy#143 CAK-swap loop (a CAK-mismatched card drops
  out of the enumeration and reconciles as a removal).
- **`--probe-interval <secs>`** (default 10s) tunes the reconcile cadence.
- **Event-driven presence is the near-instant DEFAULT** (piggy#248, made the
  default in piggy#255; `--poll-only` opts out). A dedicated blocking thread
  watches PC/SC reader states via `SCardGetStatusChange`
  (`cmd/agent/card.rs::run_event_source`) and, on any change, records **which**
  reader names transitioned (`State::CHANGED`) and fires a
  `tokio::sync::Notify`; the reconcile loop (`reconcile_loop_with_events`) then
  runs an **immediate** pass instead of waiting for the next poll. That pass
  collapses the removal debounce to a single miss for ONLY the cards whose
  reader the daemon named — dropping a now-absent one at once — while every
  other card keeps its full `PROBE_FAIL_LIMIT` blip debounce. This
  reader-scoping matters: an event about one reader must not evict a
  *different* still-present card that is merely blipping in enumeration (the
  poll path's whole reason for debouncing). The `--probe-interval` poll keeps
  running as the safety net. **`--poll-only`** is the escape hatch — it
  reconciles by polling only (`reconcile_loop`), for a host where the event
  watch ever misbehaves. Neither applies to `--proxy-only` (a cardless agent
  runs no card loop), which rejects both flags.
- **`ssh-add -X` is lockout-safe** (piggy#245). Before verifying an
  *offered* PIN against a card, the agent queries the card's remaining PIN
  retries with a non-consuming VERIFY status query
  (`PinSession::pin_retries_remaining`) and, unless `>= 2` are confirmed
  left, drops the offer for that card and re-prompts instead. A *prompted*
  PIN is not guarded — it is the user deliberately trying that card and
  stays usable at one retry. The guard is applied at every card-verify site
  (sign, ecdh, ecdh-rebox).

Test substrate (fibby, piggy#130 + piggy#246):

- **`--control-socket <path>`** opens a second `AF_UNIX` socket, and
  **`fibby ctl --socket <path> <insert|remove|list> <reader-name>`** toggles
  a card's runtime presence by reader name. A removed card reports ABSENT
  in `readers_state` and refuses `SCardConnect`, so a client's enumerate
  omits it. For the piggy#248 event path, a toggle also **wakes** any client
  blocked in `SCardGetStatusChange`: fibby's `WAIT_READER_STATE_CHANGE`
  (0x13) now registers the connection and replies the reader-state array
  (old-mode `protocol <= 4005` semantics), a toggle delivers the 8-byte async
  notification, and a per-reader `event_counter` advances so libpcsclite sees
  the change — the substrate the `--event-driven` bats e2e drives.
- **`--seed-pin-retries N`** starts a card near PIN lockout so the `ssh-add
  -X` guard can be tested. (fibby already modelled the retry counter +
  lockout; only the seed flag was new.)

## Examples

A live two-card `-A` agent losing and regaining a card
(`piggy_agent_multicard_fibby.bats::hot_swap_removes_then_readopts_a_card`):

    $ ssh-add -L | wc -l          # both cards' keys
    2
    $ fibby ctl --socket "$CTL" remove "Virtual PCD fibby A 00 00"
    ok
    # within ~PROBE_FAIL_LIMIT ticks:
    $ ssh-add -L                  # only card B survives; A's key + PIN gone
    ecdsa-sha2-nistp256 AAAA… PIV_slot_9C B2B2B2B2
    $ fibby ctl --socket "$CTL" insert "Virtual PCD fibby A 00 00"
    ok
    $ ssh-add -L | wc -l          # A re-adopted (sign-path gated)
    2

The lockout guard
(`piggy_agent_multicard_fibby.bats::offered_pin_never_bricks_a_low_retry_card`):
a card seeded one retry from lockout, a *wrong* `ssh-add -X` offer, then a
sign — the offer is dropped (never sent to the card), the card is not
bricked, and the sign succeeds via the correct prompt.

## Limitations

- **Poll latency (under `--poll-only`).** Event-driven presence is the
  default (piggy#255) and reacts near-instantly via `SCardGetStatusChange`.
  Only under the `--poll-only` opt-out is hot-swap reaction bounded by
  `--probe-interval` × the debounce (removal noticed in up to ~`3 × interval`).
  **Startup** latency is separate and hits both modes: a card contended by an
  *outgoing* agent during a deploy (the card stays present, so no event fires)
  is recovered by the fast startup cadence (piggy#251), within ~1s of the
  outgoing agent releasing it rather than up to a full interval.
- **Event source watches a stable reader set.** `run_event_source` watches
  the readers present when its context is established and re-lists on its
  bounded timeout; a whole *reader* plugged/unplugged mid-wait is caught by
  the poll safety net rather than instantly. Per-reader card presence (the
  common hot-swap) is watched directly. Watching the PnP notification reader
  for instant whole-reader events (and the fibby `GET_READER_EVENTS` 0x15 it
  needs) is a deferred follow-up.
- **fibby-validated, not real hardware.** All coverage is against fibby's
  virtual multi-card. Real two-YubiKey hot-swap is the promotion soak.
- **`ssh-add -X` residual.** The guard guarantees a wrong offer never locks
  a card, but a wrong offer can still cost one retry at `>= 2` remaining
  (the offer is tried at most once per card). The clean end-state — a
  *targeted* offer applied only to the card an operation is about to use —
  is deferred.
- **Debounce delays a genuine removal.** A truly-removed card is served for
  up to `PROBE_FAIL_LIMIT` ticks before eviction; the debounce is
  deliberate (a one-tick enumeration blip must not evict a card).
- **`-g` is secondary.** A `-g`-pinned agent hot-swaps its single card
  (remove + reinsert), but `-A` is the primary multi-card model
  (survey decision).

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| `--probe-interval` | 10s | the safety-net poll cadence under event-driven, and the primary cadence under `--poll-only`; ~6× more PCSC enumerate calls than the historic 60s, negligible on a workstation | a `--poll-only` host's removals lingering too long → shorten |
| event-driven default / `--poll-only` | event-driven ON (piggy#255) | proven robust live (nikulin); near-instant hot-swap for every card-backed agent, poll kept as the safety net | a host where the event watch misbehaves → `--poll-only` opts that host back to polling |
| `STARTUP_FAST_INTERVAL` / `STARTUP_FAST_WINDOW` | 1s / 30s | while serving 0 keys at launch, poll fast for a bounded window so a card contended by an *outgoing* agent during a deploy is served within ~1s of release, not up to a full interval later (piggy#251); capped by the configured interval, and only while keyless so a card served from start never fast-polls | deploy serve-delay still too long (widen the window / shorten the interval) or startup PCSC churn on a real card a concern (narrow) |
| `PROBE_FAIL_LIMIT` | 3 | debounce a transient enumeration blip without evicting a present card | a real card being falsely evicted under load (raise) or a removal lingering too long (lower, plus interval) |
| `MIN_RETRIES_FOR_OFFERED_PIN` | 2 | the lockout-safe floor: a wrong offer can cost at most one retry and never the last | a card at 2 retries losing one to a mis-offer becoming a real annoyance → raise to 3, or land the targeted-offer end-state |

## More Information

- `docs/plans/2026-08-25-multi-card-hot-swap-agent.md` — the sequenced
  design (validated requirements, the #179 lesson, the phase breakdown, the
  hybrid decision).
- amarbel-llc/piggy#247 — the umbrella epic.
- Phase issues: #245 / #246 (`ssh-add -X` lockout safety + fibby retry
  seed), #130 (fibby runtime hot-plug substrate), #244 (the per-card
  reconcile lifecycle), #248 (event-driven reaction via `SCardGetStatusChange`
  + fibby's `WAIT_READER_STATE_CHANGE` wake — the "later" half of the hybrid
  decision), #251 (fast startup-recovery cadence for deploy overlap), #254
  (`piggy health` presence-mode point), #255 (event-driven made the default;
  `--poll-only` opt-out).
- Prior art it builds on: #177 (per-card PIN cache), #214 (card lock),
  #175 (0-key recovery, subsumed), #143 (CAK swap, subsumed), #179 / #178
  (sign-path gate + refusal logging — `piggy health --sign-test` already
  probes every served card), #162 (multi-instance `--service-name`).
- FDR 0001 (`0001-proxy-only-agent-universal-front.md`) — the sibling agent
  record; a proxy-only agent serves no local card and runs no reconcile
  loop.
- Code: `crates/piggy/src/cmd/agent/{card,mod,session,pins}.rs`,
  `crates/piggy-piv/src/{apdu,token}.rs`, `crates/fibby/src/{server,main,virtual_card,backend}.rs`.
