# pigsty repo bootstrap spec

Written 2026-10-25 at circus/eager-holly's request so the morning step is a
single go/no-go. Nothing here has been created; the operator decides.
Design: `2026-10-25-pigsty-design.md`. Piggy-side prerequisites:
`2026-10-25-pigsty-piggy-side.md` (landed on `live-sequoia`, merging).

## 1. The repo

| Field | Value | Why |
|---|---|---|
| Name | `pigsty` | Sasha's choice, 2026-10-25 |
| Owner | `linenisgreat` | every fleet repo on the vanity plane is owned here (eng:file-issue table); same as `linenisgreat/piggy` |
| Canonical URL | `https://code.linenisgreat.com/pigsty` (vanity plane, one path segment); forge URL `https://forge.starbrandshoes.com/linenisgreat/pigsty` | mirrors piggy's shape (`smith repo-get linenisgreat/piggy`: owner `linenisgreat`, origin remote on the vanity host, which conformist's git-remotes check requires) |
| Visibility | public (`private: false`) | piggy is public; the design doc is already public on piggy master |
| Description | `pigsty: a pigpen-backed password vault for Linux and Android` | GitHub-description linter wants one |
| Default branch | `master` | fleet convention (piggy, madder) |
| Units | issues, wiki off, releases on, PRs on | match piggy; the wiki is unused fleet-wide |
| Mirror | forge only for now | piggy's GitHub mirror (`amarbel-llc/piggy`) predates the forge; new repos have not been mirrored. Revisit when pigsty has a release worth publishing. |
| Labels | copy piggy's set: `bug`, `documentation`, `duplicate`, `enhancement`, `explore`, `question`, `rust`, `testing`, `triage`, `wontfix`, plus new `flutter`, `android` | the fleet's issue-filer graph expects the common set |
| Milestones | none | phases are tracked in a "Sequenced work" issue (piggy#26 pattern), created by the implementer as its first issue |

Owner afterwards: Sasha. The worker is a spinclass session in the new repo
(the fable implementer below); piggy/live-sequoia stays the owner of the
piggy side only and never commits in pigsty.

## 2. The one command

From a fresh, empty directory that is a git repo with `origin` set to the
vanity URL (so the version key derives as `PIGSTY_VERSION` and the
git-remotes lane is happy):

```sh
git init pigsty && cd pigsty
git remote add origin git@code.linenisgreat.com:pigsty.git
conformist conform <papi-domain>#eng-rust-lib --repair
```

- `<papi-domain>` is the operator's PAPI domain that advertises conformist's
  templates (conformist-conform(7) PAPI TEMPLATE MODE). I have not verified
  which domain that is; eager-holly or the operator knows. The fallback is
  `nix flake init -t <conformist flakeref>#eng-rust-lib` with the same
  follow-up steps conform performs by hand.
- Template `eng-rust-lib`, not `eng-rust-bin`: pigsty-core is a library the
  Flutter app binds (flutter_rust_bridge builds it as a cdylib). The template
  fills `EXAMPLE_CRATE` with `pigsty` and the version key with
  `PIGSTY_VERSION`; rename the crate directory to `crates/pigsty-core` and
  make the root `Cargo.toml` a workspace in the first commit (the eng-rust
  lanes are workspace-aware).
- conform stages what it wrote and runs `nix flake lock`; it never commits.
  `.envrc` is created by hand (`use flake`) and left untracked, per
  conformist#141.

## 3. The first commit

1. The `eng-rust-lib` scaffold as conform left it, with the crate moved to
   `crates/pigsty-core` under a workspace root.
2. `docs/plans/2026-10-25-pigsty-design.md`, moved from piggy (piggy keeps a
   one-line pointer in its copy's header, landed by piggy/live-sequoia after
   the move).
3. `AGENTS.md`: the template stub plus an orientation map: what pigsty is,
   the layering rule (`pigsty → madder → piggy`, piggy never imports
   madder), the two dependencies and where their sessions are, the phases.
4. `app/` is NOT in the first commit. The Flutter scaffold comes with phase
   0's spike result, once the Nix Android question is answered.
5. `sweatfile` from the template, `pre-merge = "just"`.

## 4. Dependencies

| Dependency | Form | Status |
|---|---|---|
| `madder-store` (madder's Rust sealed-key store crate) | cargo git dep on madder, pinned by rev, `cargoLock.outputHashes` in the flake | being written by `madder/live-cedar/giggles` (fable); design `docs/plans/2026-10-25-rust-sealed-key-store-design.md` in madder, all five decisions approved by piggy/live-sequoia on Sasha's behalf; hand-rolled age X25519 subset, ruzstd, `init` in scope |
| `piggy-pigpen`, `piggy-markl`, `piggy-piv` | cargo git deps on piggy, pinned by rev | on piggy master as of the merge in flight: `piggy-piv` exposes `ApduTransport`/`ApduSession`/`PivToken::from_transport` |

Until madder-store lands, pigsty-core's store layer is written against the
API in live-cedar's design doc with an in-memory fake, so phase 2 does not
block on madder.

## 5. The three open design choices

From the design's §7, with my recommendation:

1. **Entry id: registered markl format or opaque ULID?** Recommend an
   opaque ULID (26 chars, Crockford base32) as the `entry=` field value
   now. A markl format would need a registration in `piggy-markl` and
   `go/` for a value that is never hashed or signed; dodder's object ids
   replace it later anyway. Change signal: dodder adoption.
2. **Android build under Nix?** Recommend treating it as the phase-0
   spike it is, with a hard fallback: if `androidenv` + Flutter +
   flutter_rust_bridge does not build a hello-world in two sessions of
   effort, the Android APK is built with the stock Flutter toolchain outside
   Nix for the first releases and the Nix build is an issue, not a blocker.
   Linux stays Nix-built from day one.
3. **Which madder on-disk details must be pinned before pigsty depends on
   them?** Recommend: none in pigsty. pigsty depends on the madder-store
   crate's API, never on the layout; the layout contract is madder's
   (FDR-0011 plus live-cedar's Go-to-Rust fixtures). pigsty adds one
   interop test of its own: a store pigsty wrote is read by `madder cat`.

## 6. The fable implementer's brief (draft)

Scope: phases 0 to 3 of the design (spikes, piggy-side already done,
pigsty-core on Linux, the Flutter Linux app). Phase 4 (Android transport
and release) is a second brief once the spikes report.

First deliverables, in order, each its own merge:
1. The first commit above plus a "Sequenced work" issue listing the phases.
2. Phase 0 spike A: Nix Android build of a flutter_rust_bridge hello-world;
   report pass/fail with evidence, decide per §5.2.
3. Phase 0 spike B: an `ApduTransport` over fibby's VirtualCard in pigsty's
   own tests (copy `crates/piggy-piv/tests/fibby_transport_tests.rs`).
4. pigsty-core: the data model (entry and index documents, parse and
   serialize, hyphence framing via piggy-pigpen's), the version DAG, the
   per-device heads and the merge, all over an in-memory store fake.
5. pigsty-core over madder-store, once it lands; the `madder cat` interop
   test.
6. The Flutter Linux app: store picker, unlock, list, view/edit, history,
   conflicts, generator.

Rules: test-first (bats or Rust tests before code); `just` recipes are the
paved paths; `merge-this-session` is the gate; no bare cargo/flutter in
CI-relevant steps. Must not touch the madder or piggy repos: an API need is
a chat message to `madder/live-cedar` (madder-store) or to the live piggy
session (`chat_list`, decoration `piggy/<session>`); research in those
repos' design space is handed off, not done in place. Must not create
outward-facing artifacts beyond the repo itself (no mirrors, no releases)
without the operator. Reports to circus/eager-holly (coordinator) at each
deliverable and to the piggy session when it needs piggy; signs with its
fully-qualified session id.

Model: fable (Sasha's instruction); mechanical fixture and scaffolding work
may go to lower-tier subagents.
