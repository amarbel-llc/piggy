# markl-id ownership inversion — piggy as the canonical registry + Go library

- **Date**: 2026-06-20
- **Status**: draft (design for review)
- **Driver**: [amarbel-llc/piggy#183](https://github.com/amarbel-llc/piggy/issues/183).
  Today madder (`go/internal/bravo/markl`) is the canonical purpose/format
  registry and piggy's `crates/piggy-markl` is a hand Rust port that mirrors
  it. This inverts that: **piggy becomes the source of truth**, ships a Go
  library that madder (and other Go consumers) depend on, and owns the
  conformance vectors. The cosmetic `markl-id → piggy-id` rename is split out
  to [#184](https://github.com/amarbel-llc/piggy/issues/184) and is **not** in
  scope here.

## Decisions (ruled by maintainer, 2026-06-20)

These were the three open appetite calls flagged by `madder/stark-maple`; the
maintainer ruled:

| # | Question | Ruling |
|---|----------|--------|
| Q2 | madder depends on an **external** piggy Go module vs. a vendored copy | **External module.** madder takes a go.mod dependency on the piggy-published module (+ `gomod2nix.toml`), accepting the cross-repo release-cadence coupling. |
| Q3 | Who owns/generates the RFC-0002 conformance vectors post-move | **piggy generates.** The vector generator moves to piggy; piggy emits the fixture as the source of truth and every consumer (madder Go, piggy Rust) replays it. |
| Q5 | Where the piggy-owned Go module physically lives | **In piggy, under `go/`.** |

## Dependency layering (maintainer direction, 2026-06-20)

piggy should sit **between `purse-first/dewey` and madder** in the Go
dependency graph:

```
purse-first/dewey  →  piggy (go/markl: registry core + signer/agent)  →  madder
```

piggy already lives in the pivy/PIV ecosystem — it vendors pivy, owns
`piggy-piv`, and is the dewey/pivy-centric layer — so it is the natural home
not just for the pure registry/codec core but for **most of what
`internal/bravo/markl` is today, including the dewey-dependent signer/agent
discovery layer.** The goal is for madder to **shed its pivy/dewey deps**:
madder becomes a pure consumer of piggy's markl module, and the
`golang.org/x/crypto/ssh` + `dewey/pivy` weight lives in piggy, where it
belongs. This resolves the signer-discovery question in favor of *move up into
piggy*, not *leave in madder* (see the architecture below). **Scope of the
shed (resolved "direct now, closure later"):** #183 gives madder *no direct*
pivy/ssh import (it consumes `piggy/agent`); fully removing pivy/ssh from
madder's transitive closure requires it to stop signing in-process, deferred to
[#185](https://github.com/amarbel-llc/piggy/issues/185).

## Current state

- **madder is canonical.** `go/internal/bravo/markl` (~49 files, ~2.5–3k LOC
  production): the `Id` type + text/binary/blech32 coding (split-HRP per
  madder#159), the format families (ed25519, ecdsap256, agex25519, pivy_ecdh,
  nonce, hash sha256/blake2b), the purpose/format registries
  (`RegisterPurpose`/`RegisterFormat`), **and** an ssh-agent + pivy-agent
  **signer-discovery** layer. `go/internal/alfa/blech32` is small and
  self-contained — its only importers are markl's own `id_*.go`, the
  `pkgs/blech32` facade, and the RFC-0002 tests, so it moves cleanly as a unit
  with markl.
- **Public facades already exist.** madder exposes `go/pkgs/markl` +
  `go/pkgs/blech32` (dagnabit-generated); `cutting-garden` already consumes
  madder via `pkgs/`. So the inversion does not start from zero — there is an
  established facade boundary. **But** madder's own internals import
  `internal/bravo/markl` **directly** (bypassing the facade): ~dozens of
  packages — `blob_stores` (~25 files), `charlie/blob_store_configs` (~12),
  `india/commands` (~8), `foxtrot/sftp_probe`, `charlie/{fd,arg_resolver,
  tap_diagnostics,hyphence}`, `delta/blob_store_configs`,
  `juliett/inventory_log`, `hotel/blob_transfers`, `golf/command_components`,
  `alfa/scoped_id`. That direct-import set is the real blast radius.
- **piggy mirrors.** `crates/piggy-markl` (Rust) ports the registry + blech32
  codec, pinned to RFC-0002 (post-#159 split-HRP). It replays the shared
  fixture `0002-markl-id-format-vectors.json`, which madder currently
  **generates** via `TestGenerateRFC0002Vectors` (`just codemod-rfc0002-fixture`).
- **piggy's existing Go module** is `github.com/amarbel-llc/piggy/conformance`,
  rooted at `go/` (the SSH-agent protocol conformance binary). The registry
  library is a new, first-class Go artifact alongside it.
- **Joint vocabulary today.** The 4 `piggy-*` purposes + the
  `ssh_ecdsa_nistp256_pub` format already live in madder's registry as
  piggy-owned-and-mirrored. `papi-doc-sig-v1` (`ecdsa_p256_sig`) landed in
  madder `b852d42` and is **already mirrored** into `piggy-markl` (piggy
  `92903ef`). The inversion formalizes ownership of entries that are already
  shared.

## Target architecture

### The piggy Go module(s)

A new Go module under `go/`. madder's heads-up is the key constraint: the
signer-discovery layer pulls host deps (`golang.org/x/crypto/ssh`,
`dewey/pivy`), so a piggy-published module that wants a slim, dependency-light
canonical core must **split the pure codec/registry from the signer/agent
layer**. Proposed split:

- **`go/markl/` — the canonical core** (own `go.mod`, module path
  `github.com/amarbel-llc/piggy/go/markl`). Pure: the `Id` type, text/binary
  /blech32 coding (split-HRP), format families, the purpose/format registries
  + `RegisterPurpose`/`RegisterFormat`. Dependency-light (blech32 is vendored
  in as a sub-package or sibling). **This is what madder depends on.**
- **`go/markl/blech32/`** (or a sibling module) — the blech32 codec, moved
  from madder's `internal/alfa/blech32`.
- **`go/markl/agent/` — signer/agent discovery, moved up into piggy.** Per the
  dependency-layering direction above, the dewey-dependent signer-discovery
  layer moves **out of madder and into piggy** (piggy already sits on
  dewey/pivy; madder should not). It lives in a **separate sub-package** so the
  `golang.org/x/crypto/ssh` + `dewey/pivy` deps stay off the dep-light core —
  consumers that only need the registry import `go/markl`, not `go/markl/agent`.
  **This boundary already exists** in madder as the *stub-format pattern*: the
  core's `init()` registers pure stub SSH formats that error "agent not
  connected," and the agent layer swaps in the real signer at runtime via the
  same `Register*` hook (`RegisterEcdsaP256SSHFormat`, called from
  `ssh_agent_discover`). So the core↔agent split is an existing seam to port,
  not a new cut. Net: madder depends on piggy for the registry core and (where
  it needs signer discovery) `go/markl/agent`; *how completely* madder sheds
  pivy/dewey then turns on the direct-vs-transitive crux (see Open questions).

### Core/agent file boundary (madder first-pass)

`madder/stark-maple`'s first-pass classification of `internal/bravo/markl`'s
files (heavy deps = `x/crypto/ssh`, `ssh/agent`, `dewey/pivy`). A design-stage
map; confirm with a per-symbol audit when the module is stood up.

- **Move up to `go/markl/agent`** (heavy deps): `ssh_agent.go`,
  `ssh_agent_discover.go`, `pivy_agent_discover.go`,
  `format_family_pivyecdhp256.go`.
- **Mixed — symbol-level split:**
  - `format_family_ecdsap256.go`: `EcdsaP256Verify` is pure stdlib
    (`crypto/ecdsa`) → **core**, along with the `Format{ecdsa_p256_sig,64}` +
    `FormatPub{ecdsa_p256_pub,Verify}` registrations; `Connect` /
    `ecdsaP256AgentSigner` / `parseSSHEcdsaSignatureBlob` /
    `RegisterEcdsaP256SSHFormat` are ssh-agent → **agent**.
  - `format.go`: the `init()` registering core formats (incl. the pure
    `makeStub*SSHFormat` stubs) is **core**; the real signer registrations are
    **agent**.
- **Stay in dep-light core** (stdlib crypto + dewey errors/domain interfaces):
  `id*.go`, `purposes.go` / `purpose_type.go` / `registration*.go`,
  `format_pub/sec/hash.go` + `hash.go`, `format_family_ed25519.go` (stdlib),
  `format_family_nonce.go`, `util.go` / `slice.go` / `lock*.go` / `main.go`,
  and the blech32 package.
- **To verify in the audit:** `format_family_ssh_ed25519.go` and
  `format_family_agex25519.go` (agex25519 pulls `x/crypto/curve25519` —
  non-stdlib but lightweight; decide core vs. agent).

### Reference implementation & cross-impl conformance

- piggy's **Go `markl` becomes the reference implementation** (the Rust
  `piggy-markl` was historically the port of madder's Go; that relationship now
  points at piggy's own Go).
- **piggy generates the conformance fixture** (port madder's
  `TestGenerateRFC0002Vectors` + the `codemod-rfc0002-fixture`-style recipe into
  piggy). The fixture is the byte-exact cross-impl contract.
- Both in-repo ports replay it: piggy Go `markl` (generator + round-trip) and
  piggy Rust `piggy-markl` (the existing `rfc_0002_conformance.rs`). madder
  replays the **same** fixture, now sourced from piggy.
- RFC-0002 itself (`docs/rfcs/0002-piv-ecdh-box.md`) already lives in piggy and
  is owned here — the spec, registry, and vectors all converge under piggy.

### madder consumes the piggy module

madder repoints from owning the registry to depending on it:

- Add the `github.com/amarbel-llc/piggy/go/markl` dependency (`go.mod` +
  `gomod2nix.toml`).
- **Migration mechanism — a thin re-export shim.** Rather than rewrite the
  ~dozens of direct `internal/bravo/markl` importers in one big-bang change,
  `internal/bravo/markl` becomes a **thin re-export shim** over the piggy
  module (type aliases + `var`/func forwards). The `pkgs/markl` facade
  repoints similarly. Existing importers keep their import paths; only the
  shim's body changes. A later, optional sweep can repoint importers directly
  at the piggy module and delete the shim.

## Migration plan (cross-repo, sequenced)

1. **Stand up the piggy Go module** (`go/markl` + blech32), porting the codec +
   registries from madder's `internal/bravo/markl` core, plus the
   signer/agent-discovery layer into `go/markl/agent` (piggy takes on the
   dewey/pivy dep here). Add the vector generator. Wire into piggy's nix build
   (git-tracked files only — stage new paths before `nix build`). Gate: Go
   `markl` round-trips the generated fixture; Rust `piggy-markl` still replays
   the same fixture byte-for-byte.
2. **Publish/pin** the module so madder can depend on it (tag or pinned commit
   + `gomod2nix.toml` entry on the madder side).
3. **madder repoints via the shim.** Replace `internal/bravo/markl`'s core with
   a re-export shim over the piggy module; repoint `pkgs/markl`. Drop madder's
   *direct* `dewey/pivy` dep (it reaches signer discovery through
   `piggy/go/markl/agent`). The transitive-closure shed (out-of-process
   delegation) is **out of scope here** — deferred to #185. Gate: madder's full
   suite + the ~dozens of direct importers compile unchanged; madder replays
   piggy's fixture.
4. **Move vector generation to piggy** (retire madder's
   `TestGenerateRFC0002Vectors` as the source; madder replays piggy's emitted
   fixture).
5. **(Decoupled — #184)** rename `markl-id → piggy-id` across both repos in one
   pass; PAPI absorbs its `markl → piggy` vocabulary sweep then.

## Open questions / risks

- **Direct-vs-closure dep shed — RESOLVED (maintainer, 2026-06-20: "direct now,
  closure later").** Today madder signs/encrypts **in-process**
  (`ssh_agent_discover` connects to `SSH_AUTH_SOCK`; the pivy_ecdh recipient
  format encrypts blobs). If the agent layer moves to piggy and madder keeps
  signing in-process, madder still **transitively** pulls `piggy/go/markl/agent`
  (→ pivy/ssh) on those paths — it sheds the *direct* import but not the
  closure. **#183 does the direct shed only** (madder drops its direct pivy/ssh
  imports by consuming `piggy/agent`; no behavioral change). The whole-closure
  shed — madder stops in-process signing/agent-discovery and delegates to the
  piggy CLI out-of-process — is a real behavioral change deferred to its own
  FDR, [#185](https://github.com/amarbel-llc/piggy/issues/185). Either way, no
  madder-only consumer needs a private copy — they consume `piggy/agent`.
- **Core/agent symbol boundary.** First-pass file map captured above
  (`madder/stark-maple`); resolved in direction, pending a per-symbol audit at
  port time — notably the `agex25519` / `x/crypto/curve25519` core-vs-agent
  classification.
- **Module path & granularity.** One module (`go/markl`) with a blech32
  sub-package vs. two modules. Proposal: one module, blech32 as a sub-package,
  unless a consumer needs blech32 independently.
- **Cross-repo release coupling.** An external module means madder's build now
  pins a piggy version; a registry change is a piggy release → madder bump.
  gomod2nix makes this mechanical but it is real coupling the maintainer
  accepted (Q2). Document the bump procedure.
- **FDR-0019 (`dodder/smart-pine`, scoped-id consolidation)** consumes markl
  ids but — per madder — adds/renames no purposes or formats. Confirm with
  smart-pine that there is no registry collision before/while the core moves.
- **`alfa/scoped_id` is in madder's direct-importer set** and is also touched by
  FDR-0019 — coordinate ordering so the shim and the scoped-id work don't race.

## Relationship to adjacent work

- **`papi-doc-sig-v1`** — already mirrored into `piggy-markl` (piggy `92903ef`,
  mirroring madder `b852d42`). When the inversion lands, this purpose is simply
  one more entry that piggy now owns canonically; no re-registration.
- **#184 (rename)** — gated on this inversion landing, so it targets the
  relocated source of truth.
- **#185 (madder out-of-process signing delegation)** — the deferred
  whole-closure pivy/ssh shed; gated on this inversion landing. #183 only does
  the direct-dep shed.
- **papi#7 / RFC-0001 Amendment 9** — downstream and independent: papi's
  verifier consumes the pinned wire form directly and does not import the
  registry. The producer side (`piggy papi sign`) + cross-impl conformance ride
  on this registry, but Amendment 9's landing is gated on the maintainer's
  sequencing ruling, not on the inversion mechanics.
