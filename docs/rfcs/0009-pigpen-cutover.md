---
status: draft
date: 2026-06-24
provenance: |
  The cutover companion to RFC 0008 (pigpen scope + prototypes, PR #207).
  Where 0008 pins the wire model, this RFC makes the decisions 0008
  explicitly deferred: file extension and store layout, the CLI surface,
  the piggy-ids ⇄ pigpen migration story, promotion of the markl
  registrations and the hyphence framing out of the prototypes, the
  normative test-vector set and its CI drift gate, and how the WASM
  artifact is produced and shipped. It sequences all of that into phased,
  independently-mergeable work. Umbrella: piggy#69 (the 2.x cutover);
  triage: piggy#26.
---

# RFC 0009 — pigpen cutover: extension, commands, migration, and promotion

## Abstract

RFC 0008 scoped **pigpen** (a hyphence-framed encrypted document + markl
recipient set) and shipped Go and Rust prototypes. This RFC specifies how
pigpen graduates from prototype to a production piggy format. It makes the
following decisions, each justified below and each landing as its own
phase:

1. **Coexistence, then default.** Pigpen ships alongside `.ebox`; readers
   accept both; the write path flips to pigpen by store opt-in, then by
   default. `.ebox` and the RFC 0003 `piggy-ids` line format remain
   **readable indefinitely**.
2. **`.pigpen` extension; `piggy-ids` keeps its name but may hold a
   payload-less pigpen document**, distinguished by a `---` sniff.
3. **A `piggy pigpen` command group** (`seal`/`open`/`inspect`/
   `convert-ids`/`migrate`) plus pigpen-awareness in the existing `pass`
   verbs and the `recipients` family — including the **cheap-add /
   re-key-on-remove** asymmetry.
4. **Promote the markl registrations** of RFC 0008 §5 into `go/` and
   `crates/piggy-markl` proper, with conformance vectors.
5. **Promote the hyphence framing** out of both prototypes into a
   dependency-light, RFC-0001-conforming, **WASM-clean** library piggy
   owns (`crates/piggy-hyphence` + a Go sibling), validated against
   madder's normative vectors. Converging onto a shared dewey-level
   library is tracked but **not** blocking.
6. **A normative pigpen test-vector set** (deterministic, bit-exact)
   replayed in both languages, with **spec/​test drift as a CI failure**
   (mirroring RFC 0002).
7. **Ship the WASM module** from the promoted `piggy-pigpen` crate via
   `wasm-pack` in CI, with the agent-backed `EcdhOracle` wired natively.

## Status and Provenance

Draft. Supersedes none; extends RFC 0008. It is a *planning + decisions*
RFC: it fixes the cutover shape so the implementation phases can land
independently. Each numbered phase in §10 maps to a tracking issue under
the piggy#69 umbrella.

## Requirements Language

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY",
"REQUIRED", "RECOMMENDED", and "OPTIONAL" are to be interpreted as in
RFC 2119.

## 1. Relationship to RFC 0008

RFC 0008 is the **wire** authority: the hyphence framing, the markl-ID
recipient/wrap/MAC encoding, and the §4 `pigpen-v1` crypto suite are
fixed there and are NOT re-opened here. Any change to those is a new
`pigpen-v2` type string and a superseding RFC, per RFC 0008 §3. This RFC
only specifies the **product**: where the bytes live, what commands
produce and consume them, and how the code is factored.

## 2. Coexistence vs. supersession

**Decision: phased coexistence, ending in pigpen-as-default with
read-only legacy support.**

The piggy 1.x→2.x history offers two precedents: the soft `.gpg`→`.ebox`
content migration and the **hard** `.pivy-id`→`piggy-ids` cutover (RFC
0003 "Backwards Compatibility": no in-place migration, re-init required).
A hard cutover was acceptable there because the recipient file is cheap
to recreate. It is **not** acceptable for sealed secrets — re-init would
destroy data. Pigpen therefore takes the softer path, which it can afford
because piggy owns **both** readers:

- **Read**: a conforming piggy MUST read `.ebox` (RFC 0002), the RFC 0003
  `piggy-ids` line format, AND `.pigpen` / payload-less pigpen, for the
  foreseeable future. Dropping a legacy *reader* is itself a future RFC.
- **Write**: governed by a per-store **format marker** (§5). Absent the
  marker, piggy writes `.ebox` + RFC-0003 `piggy-ids` (today's
  behaviour). With `format = pigpen`, piggy writes `.pigpen` +
  payload-less pigpen recipient sets.
- **Default flip**: a later phase makes `format = pigpen` the default for
  *new* stores (`piggy init`). Existing stores are never silently
  rewritten; migration is explicit (§4.4).

This gives a no-data-loss, opt-in, reversible-until-migrated path, unlike
the RFC 0003 hard cutover.

## 3. File layout

### 3.1 Sealed secrets — `.pigpen`

A sealed secret is a file with extension **`.pigpen`** containing a sealed
pigpen document (RFC 0008 §2.2, sealed face). The store walk
(`store.rs::collect_eboxes`, the `find -L … -iname '*.ebox'` canonical
walk) gains `*.pigpen` as a recognized leaf. Mixed stores (some `.ebox`,
some `.pigpen`) MUST be supported during migration; a single logical
secret MUST NOT exist as both simultaneously (the migrator deletes the
`.ebox` only after the `.pigpen` is durably written and verified).

### 3.2 Recipient set — `piggy-ids`, sniffed

**Decision: keep the filename `piggy-ids`** (preserving the established
walk-up lookup `store.rs::find_piggy_ids`), but allow its *content* to be
**one of the following forms**:

- the RFC 0003 line format (legacy), or
- a **payload-less pigpen document** (canonical going forward), or
- a **pigpen pointer** (RFC 0008 §2.2, RFC 0010), resolved into a
  payload-less pigpen document before use.

A reader disambiguates by a one-byte sniff: a `piggy-ids` whose first
bytes are the hyphence opening boundary `---\n` is parsed as a
payload-less pigpen document; otherwise it is parsed as RFC 0003 lines.
The sniff is unambiguous — an RFC 0003 file's first non-blank line is a
`#` comment or a markl ID, never `---`.

A third shape is a **pointer** (RFC 0008 §2.2, RFC 0010): still sniffed by
the same `---\n` opening-boundary check as the payload-less pigpen case,
then disambiguated from a recipient-set document by its type line
(`pigpen-pointer-v1` vs `pigpen-v1`). A pointer resolves — via RFC 0010's
plugin dispatch — into an in-memory recipient-set document before any
downstream consumer sees it; nothing below the sniff point is
pointer-aware.

Rationale for not renaming to `recipients.pigpen`: the walk-up name is
load-bearing across the store, the home-manager module, and user muscle
memory; changing content format under a stable name is the lower-churn
move and matches how hyphence itself evolves type strings under stable
filenames.

## 4. CLI surface

### 4.1 `pass` verbs are format-transparent

`pass show/insert/edit/generate/mv/cp/rm` MUST work unchanged on
`.pigpen` secrets. The crypt shim (`crates/piggy/src/crypt.rs`) selects
the codec by file extension on read and by the store format marker (§5)
on write. Users do not type a different command to use pigpen.

### 4.2 `piggy pigpen` low-level group

A new top-level command group, mirroring how `piggy box` exposes the
ebox primitives:

| Command | Behaviour |
|---|---|
| `piggy pigpen seal [--ids <path>] [-o <out.pigpen>]` | stdin → sealed pigpen to the nearest `piggy-ids` recipients |
| `piggy pigpen open <file.pigpen>` | sealed pigpen → plaintext on stdout (card-bound recipients via piggy-agent) |
| `piggy pigpen inspect <file>` | recipients + suite, offline, no card — a pigpen-aware `hyphence meta` |
| `piggy pigpen convert-ids [--ids <path>]` | RFC 0003 `piggy-ids` ⇄ payload-less pigpen recipient set |
| `piggy pigpen migrate [path]` | re-seal `.ebox` secrets under `path` to `.pigpen` (needs a card) |

`seal`/`open` reuse the promoted `piggy-pigpen` crate; `open` supplies the
agent-backed `EcdhOracle` (§9). Telemetry `piggy.pigpen.<sub>` via the
existing `stats::timed_*` pattern.

### 4.3 `recipients` family — cheap add, re-key on remove

The `recipients add/remove/sync` family becomes pigpen-aware and MUST
honour the RFC 0008 §8 re-keying asymmetry:

- **add** — re-wrap the *existing* file key of every affected `.pigpen`
  to the new recipient. O(recipients), payload untouched. Fast.
- **remove** — **rotate** the file key and re-encrypt every affected
  payload (forward secrecy: the removed party already saw the old key).
  O(payload). Implementations MUST NOT "remove" by deleting a wrap line.
- **sync** — diff the desired set against each document (RFC 0003
  equality: markl-ID identity, comments excluded) and choose add vs.
  remove paths per document.

This replaces the unconditional full re-encryption the `.ebox`
`reencrypt::run` walk does today; the pigpen walk emits the same TAP-14
stream so the operator UX is unchanged, but an add is now a `# SKIP`-fast
re-wrap rather than a decrypt+re-encrypt.

### 4.4 Migration

`piggy pigpen migrate` walks `.ebox` secrets, decrypts each (one card
interaction), re-seals as `.pigpen` to the same recipient set, writes +
fsyncs the `.pigpen`, verifies it round-trips, then removes the `.ebox`
and commits. It is resumable (idempotent per file) and emits TAP-14.
`convert-ids` migrates the recipient file with no card (public keys
only). Neither is run implicitly; the default flip (§2) only affects new
writes.

## 5. Store format marker

A store records its write format in its config. **Decision: a
payload-less pigpen `piggy-ids` is itself the marker** — its presence
(vs. an RFC 0003 line file) signals `format = pigpen` for new writes,
keeping the marker in the one file every store already has and every
operator already reviews. `piggy init --format=pigpen` writes a
payload-less pigpen `piggy-ids`; `piggy init` without the flag writes the
RFC 0003 form until the default flips. No new config file is introduced.

## 6. Promote the markl registrations

RFC 0008 §5's formats and purposes move from prototype shims into the
registries proper:

- **Go (`go/`)** — add to `internal/charlie/markl_registrations`:
  `RegisterFormat` for `pigpen_wrap_p256` (65 B), `pigpen_wrap_x25519`
  (64 B), `pigpen_header_mac` (32 B); `RegisterPurpose` for
  `pigpen-wrap-v1` and `pigpen-doc-v1` with their accepted-format sets.
  Regenerate the `pkgs/` facades (`just codemod-facades`); `lint-facades`
  must stay green. These are piggy-native (like `piggy-recipient-v1`), so
  the cross-domain RFC-0002 fixture is untouched.
- **Rust (`crates/piggy-markl`)** — add the three `FormatId` variants
  (with `size()`/`as_str()`/`parse()`), the two `PurposeId` variants, and
  their `accepts()` rows.
- The prototypes (`go/internal/delta/pigpen`, `crates/piggy-pigpen`) drop their
  blech32-direct shims and build the wrap/MAC IDs through the real
  `markl.Id` / `Id` codec, gaining `(purpose, format)` validation for
  free.

## 7. Promote the hyphence framing

**Decision: piggy owns a dependency-light, WASM-clean, RFC-0001-conforming
hyphence framing library; converging onto a shared dewey-level library is
a tracked follow-up, not a blocker.**

The prototypes carry a deliberately-minimal framing (`hyphence.rs`,
`hyphence.go`). Promotion makes it a real, conforming implementation:

- **`crates/piggy-hyphence`** (new, pure-Rust, no OpenSSL) — full RFC 0001
  prefixes (`! @ # - < %`), the strict body separator + typed
  missing-separator sentinel, comment entanglement, canonical-order
  encoder, and the lenient `AllowMissingSeparator` mode. It MUST pass
  madder's normative `rfc_vectors.txt` (vendored or fetched as a fixture)
  so piggy's framing is provably the same wire format, not a fork.
- **A Go sibling** (`go/internal/delta/hyphence` or `go/hyphence`) with the same
  conformance bar.

Why piggy-owned rather than importing madder's: the `dewey → piggy →
madder` layering forbids piggy importing madder, and — as RFC 0008 §7 and
PR #207 found — madder's hyphence transitively pulls `dewey`, which is
**not WASM-portable today** (`syscall.SIGHUP`, `setUserChanges`). A small
piggy-owned framing crate with zero such deps is what makes the WASM
module buildable now. The long-term convergence target (one hyphence
framing lib at a neutral layer both madder and piggy consume) is recorded
as a cross-repo follow-up; it requires the dewey WASM fix first and so
cannot gate this cutover.

## 8. Normative test vectors and the CI drift gate

**Decision: a deterministic, bit-exact pigpen vector set, replayed in
both languages, with spec/test drift failing CI — exactly the RFC 0002
Appendix A model.**

- An appendix to RFC 0008 (added at promotion) pins vectors with **fixed**
  file key, ephemeral scalars, payload nonce, and recipient keys, yielding
  a byte-exact `.pigpen` document and a byte-exact payload-less recipient
  set, for both a P-256 and an X25519 recipient.
- A `pigpen_vectors.txt` (hyphence-vector style: name, input-b64,
  outcome, expected-b64) covers parse/round-trip/rejection cases
  (mixed-state, `@`-with-body, MAC-mismatch, unknown format).
- Both `crates/piggy-pigpen` and `go/internal/delta/pigpen` replay the full set.
- CI fails on any drift between the RFC appendix and the replay modules
  (the same gate RFC 0002 has against `piv_box.rs::tests::rfc0002_vectors`).

Because the §4 suite is deterministic given its random inputs, the vectors
are reproducible across languages and pin the construction end-to-end
(KDF info strings, STREAM nonce layout, all-zero wrap nonce, MAC
pre-image, blech32 of each blob).

## 9. WASM productionization

- **Promote `crates/piggy-pigpen` into the workspace** (`members`), with
  its RustCrypto deps folded into the shared `Cargo.lock` and the nix
  `sharedCargoLock`. It stays **OpenSSL-free**; it and its only piggy
  deps (`piggy-hyphence`, `piggy-markl`) form a pure-Rust, wasm-clean
  subgraph.
- **Native wiring**: piggy's `pigpen open` constructs an `EcdhOracle`
  backed by `agent_client::AgentEcdhOracle` (the same `ecdh@joyent.com`
  path `age-plugin-piggy` uses), so card-bound decrypt works natively
  with no new agent surface.
- **WASM artifact**: a CI job runs `wasm-pack build crates/piggy-pigpen
  --target web` and publishes the module (encrypt + parse/inspect + the
  X25519 decrypt path; P-256 decrypt via an injected JS oracle per
  `docs/plans/2026-06-24-pigpen-wasm.md`). The job also builds
  `wasm32-unknown-unknown` as a cheap compile gate on every PR so the
  WASM target can never silently regress.
- **Dewey follow-up** (informative): once dewey is WASM-portable, the Go
  package can target WASM too; until then Rust is the production WASM
  module and Go is the native reference + conformance peer.

## 10. Phased rollout

Each phase is an independently-mergeable PR under piggy#69:

| Phase | Deliverable | Gate |
|---|---|---|
| **0** (done, PR #207) | RFC 0008 + prototypes | prototype tests + module gate green |
| **1** | `crates/piggy-hyphence` + Go sibling, RFC-0001-conforming | madder `rfc_vectors.txt` pass; wasm32 build |
| **2** | markl registrations promoted (§6) | `lint-facades`; RFC-0002 fixture unchanged; Rust + Go tests |
| **3** | `piggy-pigpen` into workspace + native `EcdhOracle` (§9) | `just test-rust --workspace`; nix `sharedCargoLock` updated |
| **4** | normative vectors + CI drift gate (§8) | bit-exact replay in both languages |
| **5** | `piggy pigpen seal/open/inspect/convert-ids/migrate`; `pass`/`recipients` pigpen-awareness; recipient-set sniff | bats (sandbox + fibby) |
| **6** | store marker + `piggy init --format=pigpen`; default flip | bats; docs |
| **7** | WASM artifact published in CI | `wasm-pack` job green |

Phases 1–4 are pure refactor/promotion with no user-visible change and
can land in any order relative to each other after 1. Phases 5–7 are the
user-facing cutover and SHOULD land in order.

## 11. Security considerations (delta over RFC 0008)

1. **Migration preserves the recipient set, not forward secrecy.**
   `migrate` re-seals to the *same* recipients with a *fresh* file key,
   so a `.pigpen` is not weaker than the `.ebox` it replaces. But anyone
   who could read the `.ebox` can read the `.pigpen` — migration is not a
   revocation. Revocation is `recipients remove` (§4.3), which rotates.
2. **No silent downgrade.** A reader MUST NOT accept an `.ebox` in place
   of an expected `.pigpen` for the same logical secret, and MUST NOT
   treat a payload-less pigpen as authorization to skip a present sealed
   payload. The format marker (§5) and the per-secret extension are the
   only authorities for which codec applies.
3. **Sniff safety.** The `piggy-ids` `---` sniff (§3.2) is structural and
   cannot be steered by recipient content (markl IDs never begin a line
   with `---`). A malformed-but-`---`-prefixed file fails as a pigpen
   parse error rather than silently falling back to RFC 0003.
4. **Vector determinism is test-only.** The §8 fixed-RNG vectors exist to
   pin the construction; production seals MUST use a CSPRNG. The
   prototype already isolates this (the deterministic path is reachable
   only from tests).

## 12. Backwards compatibility

`.ebox`, the RFC 0003 `piggy-ids` line format, and `age` files (RFC 0004)
all remain readable. Stores are migrated only by explicit operator action.
A piggy that predates pigpen rejects `.pigpen` files and `---`-prefixed
`piggy-ids` with a clear "unsupported format, upgrade piggy" error rather
than misparsing — the type line `! pigpen-v1` and the `.pigpen` extension
are the version signal.

## References

### Normative
- piggy RFC 0008 — pigpen wire model & crypto suite
- piggy RFC 0002 — ebox (the format pigpen coexists with / supersedes)
- piggy RFC 0003 — `piggy-ids` (the recipient format pigpen subsumes)
- madder RFC 0001 — hyphence (the framing being promoted)
- madder RFC 0002 — markl ID format (the registrations being promoted)

### Informative
- PR #207 — RFC 0008 + prototypes (Phase 0)
- piggy#69 — the 2.x cutover umbrella
- piggy#26 — sequenced work / triage
- `docs/plans/2026-06-24-pigpen-wasm.md` — WASM build + host-oracle sketch
- piggy RFC 0004 — age recipients (the X25519 family pigpen wraps)
