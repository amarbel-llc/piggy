# FDR / RFC audit, 2026-10-24

An audit of every FDR in `docs/features/` and RFC in `docs/rfcs/` against
the code at master `c013540`: is the status true, do the claims match the
code and manpages, are links live, is anything shipped but undocumented.

**Method.** A read-only pass searched the code for each doc's named paths,
flags, commands and functions; the findings it used to justify an edit were
then checked again by hand. Evidence labels:

- **observed**: the code, test or file was found (cite given).
- **read**: the doc says so; not confirmed in code.
- **hand-checked**: re-read by hand before an edit in this change.

**Limits.** RFC 0011 was read for lines 1–120 only, the rest by search.
`doc/*.scd` was not read line by line (`man_toc` only). Issue references
were extracted but not checked for being open or closed. External repos
(spinclass, circus, clown, papi, madder, hyphence, eng) were not checked.

## Status lines

All 17 status lines match the design-records table in AGENTS.md
(observed). Three statuses look behind the code; changing them is a
decision, so they are listed under *Needs a decision*.

## Fixed in this change (plain drift)

| Doc | Line | Was | Evidence |
|---|---|---|---|
| RFC 0003 | 269 | cited `src/piggy.sh`'s `git_add_file` | `src/` holds only `completion/`; commits are `crates/piggy/src/git_ops.rs` (hand-checked) |
| RFC 0004 | 126 | "Today, `src/piggy.sh::piggy_decrypt` shells out to C `pivy-box`" | decrypt is in-process in `crates/piggy/src/crypt.rs` (hand-checked) |
| RFC 0004 | 244 | plan item 7 re-points `piggy.sh` | bash path gone; re-pointed to `crypt::decrypt` and `reencrypt.rs` |
| RFC 0004 | 249 | plan item 9 "TODO: new t0150" | `zz-tests_bats/t0150-age-recipients.bats` exists with five refusal tests; marked Partial (hand-checked) |
| FDR 0004 | 211–216, 226, 265 | `piggy luks` is an exec-to-C passthrough with no binary; "exec.rs documents no Rust port" | the shortcut was removed in #265; today's `piggy luks` is `crates/piggy/src/luks.rs` (#277), a store-keyed passphrase command (hand-checked: `main.rs:57`, `:958–1000`) |
| RFC 0006 | 277, 288–289 | "to be implemented with the engine", "Until the engine exists" | the same section says the engine landed in #194 (`card/engine.rs`, observed) |

## Needs a decision

1. **RFC 0010 promises a `--no-cache` flag that does not exist.** L175–177:
   "via the `--no-cache` flag or the `PIGGY_PIGPEN_NO_CACHE` environment
   variable". Only the environment variable exists
   (`crates/piggy/src/pigpen_pointer.rs:255–258`, hand-checked; no
   `no-cache` in `main.rs`). Implement the flag, or drop it from the RFC?
2. **RFC 0010 is `draft` but implemented.** `pigpen_pointer.rs` implements
   resolver dispatch, the 30 s timeout, the cache and the hard-failure rule
   (observed), and `zz-tests_bats/t0900-pigpen-pointer.bats` exists, but the
   RFC has no conformance section. Promote it, and add one?
3. **RFC 0007 is `proposed` but its v1 methods ship and are tested**
   (`crates/piggy/src/manage/`, `piggy_manage_fibby.bats`,
   `piggy_card_add_key_fibby.bats`, observed). Promote it?
4. **FDR 0006 (fibby as guarded key holder) is `proposed` with phase (a)
   in the code**, and its body has stale claims. Left untouched: it is the
   trust-domain design awaiting the operator. Stale points (observed):
   - L65–66 "cards are fixed at start", "no touch policy": fibby has a
     runtime control socket (`crates/fibby/src/server.rs:149–162`) and
     `crates/fibby/src/touch.rs`.
   - L66 "answers attestation with 6A80": `crates/fibby/src/attest.rs`
     attests generated slots; 6A80 only for imported, seeded or empty ones.
   - L77 "card init provisions only 9A and 9D": the engine provisions 9C
     too, as RFC 0007 §5.2 (amended 2026-10-12) requires.
   - L140–142 treats a SCOPES section of piggy-agent(1) as future;
     piggy-agent(1) has OPERATOR ACTS and SCOPES sections.
   - Line citations drifted: L62 `virtual_card.rs:270–298`, L64
     `server.rs:141, :181` (now `:168`, `:209`), L313 `card_oracle.rs:352`
     (now `run_askpass_of_kind`, `:419`).
5. **RFC 0012 says "today's fibby answers ATTEST with 6A80"** (L580–581,
   L595), as FDR 0006 L66 does. Stale for the same reason. L228 names
   `run_askpass` where the kind path is `run_askpass_of_kind`. It is the
   normative operator-act RFC, so not edited here.
6. **RFC 0002's vendor links will dangle** when `vendor/pivy` is deleted
   (epic #289 phase 5): L5, L28, L64, L72, L74, L573, L575 point into
   `vendor/pivy/docs/rfcs/` (observed, live today). Copy those RFCs in, or
   link upstream, before phase 5?
7. **RFC 0010 L10 and L65 cite `docs/rfcs/0002-piggy-mgmt-constraints.md`**,
   which is papi's document, not piggy's (absent here). Make it a papi URL?

### Decided 2026-10-24 (operator)

1. `--no-cache`: dropped from RFC 0010; the environment variable is the
   only switch.
2. and 3. RFC 0010 and RFC 0007 promoted to accepted; RFC 0010 gained a
   conformance section.
4. and 5. FDR 0006's and RFC 0012's stale fibby claims and drifted line
   citations corrected in place, marked as 2026-10-24 corrections; no
   design change.
6. RFC 0002's pivy links point at the archived amarbel-llc/pivy
   repository instead of `vendor/pivy`.
7. RFC 0010 names papi's RFC 0002 as a cross-repository reference.

Also decided: the Rust markl decoder keeps its finer error names, mapped
to RFC 0011 §4's categories in its conformance test (piggy#235).

## Shipped but not in any FDR or RFC

Observed; whether each wants a design record is a judgement call:

- `piggy luks` (#277) and `piggy zfs` (#279): piggy(1) documents them; no
  design record beyond plans.
- `piggy health` (`crates/piggy/src/health.rs`): plans only.
- `crates/piggy-askpass-gtk`: AGENTS.md and RFC 0012 §2.6 mention it; no
  design record of its own.
- `crates/operator-act-probe`, `crates/fib-wait-ready`: no doc references
  (test helpers).
- `zz-tests_bats/conformance/pigpen_open_agent_fibby.bats` exists while
  RFC 0009's `piggy pigpen` command group does not; not investigated.

## Per-doc summary

| Doc | Status | Matches code | Notes |
|---|---|---|---|
| FDR 0001 proxy-only agent | accepted | yes (observed) | multi-host soak read only |
| FDR 0002 multi-card hot-swap | experimental | yes (observed) | real two-card soak read only |
| FDR 0003 ebox secret reconcile | experimental | yes (observed) | circus wiring not checked |
| FDR 0004 LUKS2 hardware unlock | proposed | yes, feature is outside piggy | stale `piggy luks` prose fixed |
| FDR 0005 Rust piggy tool | accepted | yes (observed) | `promotion-criteria:` empty |
| FDR 0006 fibby key holder | proposed | phase (a) present | stale body; decision 4 |
| RFC 0002 box format | adopted | yes (observed vector tests) | decision 6 |
| RFC 0003 piggy-ids | draft | yes | dead `src/piggy.sh` fixed |
| RFC 0004 age recipients | draft | items 1–3 done, 4–8 absent | bash refs fixed; item 9 partial |
| RFC 0005 show-batch | accepted | yes (observed) | |
| RFC 0006 interaction protocol | accepted | yes (observed) | stale headings fixed |
| RFC 0007 command protocol | proposed | v1 shipped | decision 3 |
| RFC 0008 pigpen | accepted | prototypes shipped | |
| RFC 0009 pigpen cutover | draft | consistent with its phase table | |
| RFC 0010 pointer resolution | draft | implemented | decisions 1, 2, 7 |
| RFC 0011 markl-id | proposed | consistent (partial read) | |
| RFC 0012 operator act | accepted | yes (observed) | decision 5 |
