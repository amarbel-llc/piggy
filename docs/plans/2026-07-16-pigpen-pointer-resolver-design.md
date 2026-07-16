# Design: pigpen pointer face + resolver-kind plugin dispatch (piggy#216)

## Status

Design approved by user 2026-07-16. Not yet implemented.

## Problem

piggy#216 (open, canonical; piggy#217 closed as a duplicate) asks for
`piggy-ids` to be sourceable from a PAPI instance so an operator's
encryption-recipient set has a single source of truth instead of being
manually synced (`pass recipients sync <file>`) into every store.

Read literally, "piggy-ids sourced from a PAPI instance" sounds like it
wants papi-specific logic inside piggy. That would violate the layering
directive established by piggy#191 (which removed the `piggy papi`
namespace) and reinforced by papi's own
`docs/rfcs/0002-piggy-mgmt-constraints.md`: piggy signs bytes and reads
cards; papi (or any other domain) owns canonicalization, framing, and
trust policy. piggy#203 additionally has the entire `pass *` surface,
including `recipients sync`, on a roadmap to migrate *into* papi over
JSON-RPC — so piggy growing new papi-flavored logic today would be
building something piggy#203 plans to delete.

The resolution, reached via live cross-repo co-design with the
`papi/bold-cypress` session (krusty) working papi#54 (the publisher
half): piggy exposes a **neutral primitive** — a pigpen document that
points at a resolver by opaque `kind` + `locator`, and an
age-plugin-style PATH convention for discovering and invoking the
binary that knows how to turn that pointer into an actual recipient
set. Papi (or anything else) implements a `pigpen-resolver-<kind>`
binary; piggy never contains a line of papi-specific code.

## Architecture

**1. Where this lands.** RFC 0008 (pigpen document format) gets a small
amendment: a third face added to its §2.2 table. A new **RFC 0010**
("pigpen pointer resolution") specifies the resolver-kind registry, the
plugin discovery/invocation contract, and the caching/failure
semantics — this is a protocol + runtime-behavior spec pulling in
cross-repo concerns, not a documentation footnote, so it earns its own
RFC number rather than bloating RFC 0009's cutover-phasing narrative.
RFC 0009 gets a small addition: §3.2's two-way `piggy-ids` sniff
becomes three-way.

**2. Pointer face wire shape (RFC 0008 §2.2 amendment).** Verified
against hyphence RFC 0001 directly (`/home/sasha/eng/repos/hyphence/docs/rfcs/0001-hyphence.md`)
rather than assumed — the six fixed prefixes (`!`/`@`/`#`/`-`/`<`/`%`)
are the only metadata-line shapes hyphence has; there is no generic
key-value line type. A `-` line's `CONTENT` is "arbitrary UTF-8 except
LF," which legally permits a `key="value"` convention even though it
isn't yet used elsewhere in the hyphence ecosystem (the existing
convention there is hyphen-joined, e.g. `- area-home`):

```
---
- kind="papi-http"
- locator="https://example.com"
! pigpen-pointer-v1
---
```

- `kind` selects the resolver plugin; `locator` is opaque bytes handed
  to it verbatim (a URL, a domain, whatever the kind defines) — piggy
  never parses or interprets it.
- The type line is a **distinct type**, `pigpen-pointer-v1`, not the
  existing `pigpen-v1`. RFC 0008's two current faces (recipient set,
  sealed document) share `pigpen-v1` and are disambiguated
  structurally (wrap locks present or not); a pointer has no recipient
  lines at all to structurally key off, so giving it its own type
  string is cleaner and matches hyphence's own model: "the
  pigpen-specific structure lives entirely in how existing lines are
  populated ... the latitude RFC 0001 grants to the type identified by
  the `!` line."
- A document mixing `-` recipient lines with `kind=`/`locator=` tags is
  malformed and MUST be rejected (matches RFC 0008's existing
  mixed-state rejection for its other two faces).

**3. Resolver contract (RFC 0010).** PATH-discovered
`pigpen-resolver-<kind>` binary, mirroring the existing
`age-plugin-<name>` convention (`age-plugin-piggy` is already
precedent in this codebase). Invocation:
`pigpen-resolver-<kind> resolve <locator>` → a recipient-set-face
pigpen document on stdout, exit 0 on success; non-zero exit + a
human-readable stderr message on failure.

Deliberately a one-shot CLI contract, not the full bidirectional
age-plugin stdin/stdout state machine: resolution (fetch, verify,
return bytes) has no need for interactive negotiation, and every
resolver author having to implement a stateful protocol for what's
almost always fetch-verify-return would be complexity with no payoff.
(Considered and rejected: linking resolver logic directly into piggy —
that's exactly the boundary piggy#191 exists to prevent.)

Piggy's role is pure mechanical dispatch: build argv, capture stdout,
parse the result with the exact same parser as any other `piggy-ids`.
No HTTP, no signature verification, no domain knowledge in piggy
itself — that's entirely the resolver plugin's job.

**4. Integration point.** `find_piggy_ids` (or a thin wrapper around
it) becomes the single choke point: after locating the `piggy-ids`
path, sniff three ways — RFC 0003 legacy lines, recipient-set-face
pigpen doc, or pointer-face pigpen doc (by its distinct `!` type
string, so this sniff is exact rather than heuristic). A pointer
resolves (§5) into an in-memory recipient-set document; every
downstream caller (encrypt-template building, `recipients list`, etc.)
is unchanged, since resolution is centralized at this one read path.

**5. Caching.** Resolved bytes cache under `$XDG_CACHE_HOME/piggy/`
(never inside the store itself — the store is git-synced, and a
resolved-recipients artifact there would leak into git history and go
stale/conflict across machines), keyed by a hash of the pointer file's
path. `--no-cache` / `PIGGY_PIGPEN_NO_CACHE=1` forces always-resolve,
bypassing the cache entirely.

**6. Failure handling.** Cache hit within TTL → used silently, no
resolver invocation. Cache miss or stale → invoke the resolver;
success refreshes the cache; failure **hard-fails the command** (no
fallback to a stale cache) with an error naming the pointer's
kind/locator and the resolver's stderr. A missing resolver binary on
PATH is the same hard-fail path with a distinguishable message. This
matches piggy's existing "never fabricate a result" posture (e.g.
`health.rs`'s `SlotProbe::Error` rather than collapsing an I/O error
into "empty").

**7. CLI surface.** Deliberately minimal — that's the point of
"transparent" resolution. `piggy pigpen inspect` (RFC 0009 §4.2,
already offline/no-card) learns to recognize and describe a pointer
face (kind/locator/cache status) instead of erroring on one. No new
top-level verb. A `piggy health` resolver-reachability point is
plausible future work; explicitly out of scope here.

## Testing

- **RFC 0010:** worked examples (a pointer document, a resolver
  invocation transcript, a failure transcript).
- **Unit tests:** the three-way `piggy-ids` sniff (pure function,
  mirrors RFC 0009's existing two-way sniff test style); the cache
  hit/miss/stale/disable-flag matrix; hard-fail-on-resolver-error and
  hard-fail-on-missing-binary.
- **Bats:** a fake `pigpen-resolver-test` fixture script placed on
  `PATH` (mirrors the existing `helpers/mock-pivy-box.sh` convention),
  driving `pass show` end-to-end through a pointer-face `piggy-ids`.

## Rollback

Purely additive at every layer — existing RFC 0003 `piggy-ids` files
and existing recipient-set-face pigpen documents are completely
untouched; a store that never creates a pointer-face document sees
zero behavior change. No dual-architecture period is needed since
nothing existing is being replaced. Rollback is simply "don't create a
pointer-face `piggy-ids`" (or convert one back manually / via a future
`piggy pigpen convert-ids` extension).

## Tuning levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| Cache TTL | 1 hour (candidate default) | Balances propagation delay (recipients changed at the source) against resolver/network load on every `pass` command | Real usage shows stale-recipient complaints (lower it) or resolver-load complaints (raise it) |
| Cache location/naming scheme | `$XDG_CACHE_HOME/piggy/<hash-of-pointer-path>` | Keeps the resolved artifact out of the git-synced store while staying within existing XDG conventions piggy already uses elsewhere | A multi-store or multi-pointer setup surfaces collisions or discoverability problems |

## Open, not-yet-scoped follow-ups

- `piggy health` resolver-reachability point (deferred, noted in §7).
- The papi-side producer/consumer halves (papi RFC-0001 §14
  self-signed `/papi/pigpen` endpoint, `papi pigpen resolve` /
  `papi-http` resolver plugin) are papi's own scope, already landed
  (§14, RFC-0001 Amendment 23) or in progress (the experimental Go
  validator) on the `papi/bold-cypress` branch — not piggy's to
  implement.
- Exact markl purpose (if any) for signature verification inside a
  resolved recipient-set document is unaffected by this design: the
  pointer face itself carries no signature (that's the resolver's
  concern, per §3's neutral-dispatch boundary) — see papi RFC-0001
  §14.2 for the self-signature scheme papi's `/papi/pigpen` producer
  and resolver use on their side of the boundary.

## Cross-repo coordination log

Live co-design happened across two sessions during 2026-07-15/16: this
session (piggy#216/#217, session id
`f1cf0d20-466f-4dff-b970-db2e8da0ecbd`) and `papi/bold-cypress`
(session id `960c83ac-adf5-4e7e-b08e-b1888e525025`, clownName krusty),
covering the neutral-primitive fetch boundary, the pointer/kind-dispatch
pivot, the age-plugin-style invocation contract, and a review pass on
papi's RFC-0001 §14 draft text (confirmed accurate against piggy's own
RFC 0008 §4.6 before signing off). See krusty's design doc
`docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md` (papi
repo) for the papi-side mirror of this coordination.
