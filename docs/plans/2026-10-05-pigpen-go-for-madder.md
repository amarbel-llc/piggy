# Pigpen for madder (Go) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Make piggy's Go `pigpen` package safe for madder to persist: pin the `pigpen-v1` bytes with registered markl formats and normative vectors, and add the Go helpers madder needs to seal a blob-store key to a (possibly remotely hosted) pigpen recipient set and open it through the agent.

**Architecture:** Madder keeps one X25519 store key per blob store. That key is the payload of a sealed `pigpen-v1` document in the store config, sealed to the encryption recipients of a pigpen recipient document. Opening costs one agent ECDH per process; blobs stay ordinary age files encrypted to the store's public key. Piggy supplies the format, the vectors, an agent-backed ECDH oracle, a recipients helper and RFC 0010 pointer resolution. Madder supplies everything store-side.

**Tech Stack:** Go (`go/` module, dewey v0.5.0, stdlib crypto), Rust (`crates/piggy-markl`, `crates/piggy-pigpen`, RustCrypto), just recipes, dagnabit facades.

**Rollback:** Purely additive on the Go API. The one behaviour change is Task 3 (pigpen builds wrap/MAC ids through the markl codec); it is guarded by a byte-identity test against the existing interop vectors and reverts as a single commit.

---

## Decisions this plan rests on

Given by Sasha on 2026-10-05:

1. The store key lives in madder's memory for the session. A separate key holder (fibby) is the long-term goal and is out of scope here (piggy#297, session `piggy/green-larch`).
2. Piggy lands format pinning before madder persists a sealed pigpen document.
3. Madder re-reads the recipient document and detects drift; it does not auto re-seal. The recipient document may be remotely hosted, so Go needs pointer resolution.
4. Age recipients become pigpen X25519 recipients.
5. Scope beyond registrations and vectors: agent ECDH oracle, recipients helper, pointer resolution. Re-wrap on `Document` is not in scope.

Decisions 2 to 4 reached this session relayed by `madder/brave-sycamore/bozo`; 1 and 5 came from Sasha directly.

## Triage of #210 (done, no blocker)

#210 is closed. Its one wire-affecting item, non-UTF-8 metadata, is resolved: both parsers reject it (`go/internal/delta/pigpen/hyphence.go:116`, `crates/piggy-pigpen/src/hyphence.rs:96`) and RFC 0008 §2.7 makes that normative. Cross-language interop vectors already exist as duplicated hex in both test suites (`pigpen_test.go:14`, `document.rs:619`), X25519 only. What is still missing is the RFC-level vector file, P-256 coverage, and a single source both languages replay. So the bytes can be frozen as they are.

## Open questions to settle inside the tasks

These were not verified while writing the plan. Each is assigned to the first task that hits it.

- Which `markl.PurposeType` fits a wrapped key and a MAC (Task 1).
- Whether `installed_test.go`, the RFC 0002 fixture or the RFC 0011 identifier corpus enumerate the registry and need new rows (Task 1).
- Whether markl's text coding of `format-data` is byte-identical to the `blech32.Encode(hrp, data)` the prototype uses (Task 3; the byte-identity test answers it).
- How the Go test tree reads a fixture under `docs/rfcs/` in the nix lanes; `identifier_vectors_test.go` is the precedent to copy (Task 5).
- Whether dewey v0.5.0's `pivy.AgentECDHFunc` matches the checkout read while planning (purse-first 9d069d9) (Task 8).

## Out of scope

- The Rust CLI surface of RFC 0009 phases 5 to 7 (`piggy pigpen …`, store marker, WASM artifact).
- Promoting `crates/piggy-pigpen` into the workspace (RFC 0009 phase 3) and the hyphence framing library (phase 1).
- Anything in fibby or the agent.
- Madder's side. Research and changes there belong to `madder/brave-sycamore/bozo`.

## Conventions for every task

- Paved paths only: `just test-go`, `just build-go`, `just test-pigpen`, `just test-rust -p <crate>`, `just test-grammar-vectors`, `just codemod-facades`, `just codemod-fmt`, `just codemod-fmt-go`.
- TDD: write the failing test, run it and see it fail, implement, run it and see it pass, commit.
- One commit per task, then `merge-this-session`. The merge hook is the CI lane; do not run bare `just` before it.
- New Go files under `go/internal/…` need `git add` before any nix lane sees them.

---

### Task 1: Register the pigpen formats and purposes in Go

**Promotion criteria:** N/A (additive).

**Files:**
- Modify: `go/internal/bravo/markl/format.go` (format id constants, next to `FormatIdPivyEcdhP256Pub` at line 41)
- Modify: `go/internal/bravo/markl/purposes.go` (purpose id constants, next to `PurposePiggyRecipientV1` at line 58)
- Modify: `go/internal/charlie/markl_registrations/registrations.go`
- Modify: `go/internal/charlie/markl_registrations/purposes.go`
- Test: `go/internal/charlie/markl_registrations/pigpen_registrations_test.go` (new, `//go:build test`)
- Regenerate: `go/pkgs/markl/main.go`, `go/pkgs/markl_registrations/main.go`

**Step 1: Write the failing test.** For each of `pigpen_wrap_p256` (65 bytes), `pigpen_wrap_x25519` (64), `pigpen_header_mac` (32): build an id of the right size, render it, parse it back, compare. Assert a wrong size is rejected. Assert `pigpen-wrap-v1@pigpen_wrap_p256-…` and `pigpen-wrap-v1@pigpen_wrap_x25519-…` parse, that `pigpen-wrap-v1@pigpen_header_mac-…` is rejected, and that `pigpen-doc-v1` accepts `pigpen_header_mac` and `blake2b256`. Use the id construction helpers the neighbouring tests in this directory use.

**Step 2: Run** `just test-go`. Expected: FAIL, unknown format.

**Step 3: Implement.**

```go
// format.go
FormatIdPigpenWrapP256   = "pigpen_wrap_p256"
FormatIdPigpenWrapX25519 = "pigpen_wrap_x25519"
FormatIdPigpenHeaderMac  = "pigpen_header_mac"

// purposes.go (bravo/markl)
PurposePigpenWrapV1 = "pigpen-wrap-v1"
PurposePigpenDocV1  = "pigpen-doc-v1"
```

```go
// registrations.go, in init(), after the PivyEcdhP256 stub
// Pigpen (RFC 0008 §5): opaque fixed-size blobs, no crypto ops at this layer.
markl.RegisterFormat(markl.Format{Id: markl.FormatIdPigpenWrapP256, Size: 65})
markl.RegisterFormat(markl.Format{Id: markl.FormatIdPigpenWrapX25519, Size: 64})
markl.RegisterFormat(markl.Format{Id: markl.FormatIdPigpenHeaderMac, Size: 32})
```

Add `PurposePigpenWrapV1Opts` and `PurposePigpenDocV1Opts` to `purposes.go` and to `AllPurposes`. Read `go/internal/bravo/markl/purpose_type.go` to choose `Type`; if no existing type fits a wrapped key or a MAC, stop and ask Sasha before adding one.

**Step 4: Regenerate facades** with `just codemod-facades`, then run `just test-go` and `just test-grammar-vectors`. Expected: PASS. If `installed_test.go`, the RFC 0002 fixture test or the RFC 0011 identifier corpus fail because they enumerate the registry, add the rows they demand and note it in the commit. If the frozen grammar export test (`TestGrammarImportSurface`) fails, stop: that is a breaking change for trellis, hyphence and papi and needs Sasha.

**Step 5: Commit.** `go/markl: register pigpen wrap and header-MAC formats (RFC 0008 §5)`

---

### Task 2: Register the same formats and purposes in Rust

**Promotion criteria:** N/A.

**Files:**
- Modify: `crates/piggy-markl/src/format.rs` (`FormatId` variants, `as_str` at line 54, `size`, `parse` at line 99, the all-formats list at line 133)
- Modify: `crates/piggy-markl/src/purpose.rs` (`PurposeId` variants at line 34, `as_str` at 342, `parse` at 358, `accepts` at 388)

**Step 1: Write failing tests** beside the existing ones (`format.rs:182`, `purpose.rs:477`): sizes 65/64/32, name round-trip, `PigpenWrapV1` accepts the two wrap formats and rejects `PivyEcdhP256Pub`, `PigpenDocV1` accepts `PigpenHeaderMac`.

**Step 2: Run** `just test-rust -p piggy-markl`. Expected: FAIL to compile.

**Step 3: Implement** the three `FormatId` and two `PurposeId` variants following the `PivyEcdhP256Pub` / `PiggyRecipientV1` pattern at the lines above.

**Step 4: Run** `just test-rust -p piggy-markl` and `just lint-rust`. Expected: PASS.

**Step 5: Commit.** `piggy-markl: register pigpen wrap and header-MAC formats (RFC 0008 §5)`

---

### Task 3: Move both pigpen implementations onto the markl codec, byte-identically

**Promotion criteria:** the direct-blech32 helpers (`encodeWrap`, `decodeWrap`, `encodeMAC`, `decodeMAC` in `go/internal/delta/pigpen/pigpen.go:175-224`; `encode_wrap`, `decode_wrap`, `encode_mac`, `decode_mac` in `crates/piggy-pigpen/src/document.rs:348-377`) are deleted in this task.

**Files:**
- Modify: `go/internal/delta/pigpen/pigpen.go`, `go/internal/delta/pigpen/codec.go`, `go/internal/delta/pigpen/doc.go`
- Modify: `crates/piggy-pigpen/src/document.rs`
- Test: `go/internal/delta/pigpen/pigpen_test.go`, `crates/piggy-pigpen/src/document.rs` tests

**Step 1: Write the failing test (both languages).** Parse `sealedByRust` and `sealedByGo` (already in both suites), call `MarshalText` / the Rust serializer, and assert the output equals the input bytes exactly. Add a second test: a wrap line whose purpose is `piggy-recipient-v1` instead of `pigpen-wrap-v1` must be rejected, and a MAC lock whose format is a wrap format must be rejected. The second test fails today because the shims check only the HRP.

**Step 2: Run** `just test-go` and `just test-pigpen`. Expected: byte-identity passes, the rejection tests FAIL.

**Step 3: Implement.** Replace the shims with `markl.Id` construction and parsing (`Id.Set`, the format/purpose accessors) using the Task 1 and Task 2 registrations. Replace the string constants `hrpWrap…`, `purposeWrap`, `formatPivyP256` and friends with the `markl.FormatId…` / `markl.Purpose…` constants. Keep the on-disk text exactly as it is: wrap as `pigpen-wrap-v1@<format>-<data>`, MAC as the bare `<format>-<data>` after `pigpen-v1@`. Update `doc.go`: drop the paragraph saying the prototype bypasses the registry.

**Step 4: Run** `just test-go`, `just test-pigpen`. Expected: all PASS. If byte-identity fails, the markl text coding differs from raw blech32 for these formats. Stop and report: that is a wire question for Sasha, not something to paper over.

**Step 5: Commit.** `pigpen: build wrap and MAC ids through the markl codec`

---

### Task 4: Deterministic sealing seam in Rust

Neither implementation can reproduce a fixed vector today. Rust's `Document::seal`, `wrap_x25519`, `wrap_p256`, `seal_payload` and `random_file_key` draw from the OS RNG internally (`crates/piggy-pigpen/src/crypto.rs:47-149`). Go's `Seal` takes an `rng`, but see the design change below.

**Promotion criteria:** N/A.

**Files:**
- Modify: `crates/piggy-pigpen/src/crypto.rs`, `crates/piggy-pigpen/src/document.rs`

**Design change made while starting this task (2026-10-05).** The seam takes EXPLICIT secrets, not an RNG byte stream, and it is added to BOTH languages:

- An RNG stream is not a portable vector input. How many bytes a library draws to make an ephemeral key, and whether it rejection-samples, is an implementation detail that differs between Go's `crypto/ecdh` and RustCrypto. It is also not established that Go's `ecdh.GenerateKey` honours its `rand` argument on the toolchain this module pins (`go 1.26`); recent Go releases have been moving key generation onto the system RNG regardless of that argument. Step 1 measures this.
- Explicit inputs are what RFC 0009 §8 already asks for: "fixed file key, ephemeral scalars, payload nonce".

So both sides gain an internal (test-reachable, not exported from the Go facade) function taking: the 16-byte file key, the 16-byte payload nonce, and one ephemeral private scalar per recipient. Go builds each ephemeral key with `ecdh.X25519().NewPrivateKey` / `ecdh.P256().NewPrivateKey`; Rust with `x25519_dalek::StaticSecret::from` and `p256::NonZeroScalar` plus `p256::ecdh::diffie_hellman`. The production `Seal` / `seal` draw those values from the CSPRNG and call the same function, so the vector path and the production path share all the crypto.

**Files (revised):** `go/internal/delta/pigpen/pigpen.go`, `crypto.go`; `crates/piggy-pigpen/src/crypto.rs`, `document.rs`.

**Step 1: Measure the Go `rng` parameter.** Write a Go test that seals the same plaintext to the same recipients twice with the same deterministic reader. If the outputs differ, the public `Seal`'s `rng` parameter does not control the ephemeral keys; record that in the function's doc comment (do not change the exported signature in this plan; madder is coding against it) and tell Sasha.

**Step 2: Write the failing tests (both languages).** Seal through the new explicit-input function twice with the same inputs: identical bytes. Change one ephemeral scalar: different bytes. Open the result with the matching identity: plaintext round-trips. Wrong number of ephemeral scalars for the recipient list: error.

**Step 3: Run** `just test-go`, `just test-pigpen`. Expected: FAIL to compile.

**Step 4: Implement** as described. (The Rust seal path already wraps the file key in `Zeroizing`; #210 item 3 was done before this plan.)

**Step 5: Run** `just test-go`, `just test-pigpen`. Expected: PASS.

**Step 6: Commit.** `pigpen: explicit-input deterministic seal seam in Go and Rust`

---

### Task 5: Normative vector file and Go replay

**Promotion criteria:** the duplicated interop hex in `pigpen_test.go:14-90` is deleted once the shared file covers it (this task).

**Files:**
- Create: `docs/rfcs/0008-pigpen-vectors.txt`
- Create: `go/internal/delta/pigpen/vectors_test.go` (`//go:build test`)
- Create: `go/internal/delta/pigpen/vectors_generate_test.go` (regeneration, opt-in via env var; copy the shape of `markl_registrations/rfc0002_generate_test.go`)
- Modify: `justfile` (a `codemod-pigpen-vectors` recipe beside `codemod-rfc0002-fixture`)
- Modify: `go/internal/delta/pigpen/pigpen_test.go`

**Vector file format.** One record per blank-line-separated block, `key: value` lines, values hex. Fields: `name`, `outcome` (`open` | `recipient-set` | `reject`), `file-key`, `payload-nonce`, `ephemeral-secrets` (space-separated, one per recipient, in recipient order; see Task 4), `plaintext`, `recipients` (space-separated markl ids), `x25519-secret` / `p256-secret` (test identities), `document` (the full document bytes), `error-contains` for rejects. A header comment states that the file is normative for RFC 0008 and that both implementations replay it.

**Cases:**
1. sealed, one X25519 recipient
2. sealed, one P-256 recipient
3. sealed, P-256 and X25519 together
4. sealed, empty plaintext
5. sealed, plaintext of 64 KiB + 1 (two STREAM chunks)
6. recipient set with a description and a comment
7. recipient set with an ssh-auth line and an unknown-purpose line (both tolerated, neither an encryption recipient)
8. reject: mixed sealed and unsealed recipients
9. reject: sealed without MAC
10. reject: one flipped MAC byte
11. reject: non-UTF-8 description
12. reject: unknown markl format on a `-` line
13. reject: `@` line together with a body
14. reject: wrap lock without the `pigpen-wrap-v1` purpose (bare, and under another purpose)
15. reject: a P-256 recipient locked with an X25519-format wrap, and the reverse
16. reject: a non-encryption recipient (`piggy-piv_auth-v1@ssh_…`) carrying a wrap lock
17. reject: a wrap of the wrong length under the right purpose and format
18. reject: empty MAC lock (`! pigpen-v1@`), empty recipient line, MAC lock carrying a purpose
19. reject: a second `!` type line
20. accept and normalize: a wrap lock whose purpose is written quoted (`"pigpen-wrap-v1"@…`) parses and re-serializes bare

Cases 14 to 20 come from the task 3 review, which found Go/Rust divergences on empty ids and repeated type lines (fixed in task 3). They pin the stricter reader in both languages.

**Step 1: Write the failing replay test.** It reads the file by relative path the way `markl_registrations/identifier_vectors_test.go` reads `docs/rfcs/0011-identifier-vectors.txt`. For `open` cases: parse `document`, open with the given identity (a software `ECDHOracle` built from `p256-secret`), compare plaintext; then re-seal through the Task 4 explicit-input function with the record's `file-key`, `payload-nonce` and `ephemeral-secrets` and compare bytes to `document`. For `recipient-set`: parse, marshal, compare. For `reject`: parse or open must fail with `error-contains`.

**Step 2: Run** `just test-go`. Expected: FAIL, file missing.

**Step 3: Generate the file** with the new recipe from fixed inputs written in the generator (fixed file keys, payload nonces, ephemeral scalars and identity secrets). No independent hand computation is required here; cross-language agreement in Task 6 is the independent check.

**Step 4: Run** `just test-go`. Expected: PASS. Delete the duplicated hex block and its tests from `pigpen_test.go`; run again.

**Step 5: Commit.** `pigpen: normative vector file and Go replay (RFC 0009 §8)`

---

### Task 6: Rust replay of the same file

**Promotion criteria:** the duplicated interop hex in `crates/piggy-pigpen/src/document.rs:619-680` is deleted in this task.

**Files:**
- Create: `crates/piggy-pigpen/tests/vectors.rs`
- Modify: `crates/piggy-pigpen/src/document.rs`

**Step 1: Write the replay test.** `include_str!("../../../docs/rfcs/0008-pigpen-vectors.txt")`, same parser, same three outcomes, re-seal through the Task 4 explicit-input function with the record's `file-key`, `payload-nonce` and `ephemeral-secrets`.

**Step 2: Run** `just test-pigpen`. Expected: this is the real cross-language check. Any mismatch is a wire divergence between the two implementations. Diagnose it with eng:systematic-debugging, and do not edit the vector file to make it pass without understanding which side is wrong against RFC 0008 §4.

**Step 3: Fix** whichever implementation deviates from the RFC. If the RFC itself is ambiguous, stop and ask Sasha.

**Step 4: Run** `just test-pigpen`, `just test-go`. Expected: PASS. Delete the duplicated hex block.

**Step 5: Commit.** `piggy-pigpen: replay the normative pigpen vectors`

Drift is impossible by construction after this task: there is one vector file and both suites read it, and both suites are in the `test` aggregate (`test-go`, `test-pigpen`, justfile line 312).

---

### Task 7: Recipients helper in Go

**Promotion criteria:** N/A.

**Files:**
- Create: `go/internal/delta/pigpen/recipients.go`
- Test: `go/internal/delta/pigpen/recipients_test.go`
- Regenerate: `go/pkgs/pigpen/main.go`

**API:**

```go
// EncryptionRecipients returns the document's encryption recipients:
// piggy-recipient-v1 (or bare) ids in pivy_ecdh_p256_pub or
// age_x25519_pub format, in document order. SSH-auth and
// unknown-purpose lines are skipped (RFC 0008 §2.3).
func (d *Document) EncryptionRecipients() []markl.Id

// ParseRecipients reads a piggy-ids file in either form: a payload-less
// pigpen document (leading "---\n", RFC 0009 §3.2) or RFC 0003 lines.
// A pointer document is an error here; resolve it first.
func ParseRecipients(raw []byte) ([]markl.Id, error)

// SameRecipientSet reports RFC 0003 equality: same ids, order and
// comments ignored.
func SameRecipientSet(a, b []markl.Id) bool

// CanonicalRecipientSet returns the bytes a consumer hashes to detect
// drift: each id in its canonical piggy-recipient-v1@ text form,
// de-duplicated, sorted bytewise, one per line with a trailing newline.
// SameRecipientSet(a, b) is exactly equality of these bytes.
func CanonicalRecipientSet(ids []markl.Id) []byte
```

`CanonicalRecipientSet` was requested by madder, which stores a digest of the recipient set in the store config; it keeps the equality rule in piggy. Add a normative paragraph for the canonical form to RFC 0008 §2.3 in Task 10, and one vector for it to the Task 5 file (a `canonical-set` field on the recipient-set cases).

**Step 1: Write failing tests:** `CanonicalRecipientSet` is order-independent, collapses a bare-format id and its `piggy-recipient-v1@` form to one line, and `SameRecipientSet` agrees with byte equality on every pair in the test table. Also: a pigpen recipient set with one P-256, one X25519, one `piggy-piv_auth-v1@ssh_…` and one unknown-purpose line yields exactly two ids; the same two recipients as RFC 0003 lines (with a `#` comment line, a trailing comment and a bare-format id) yield the same set; a sealed document passed to `ParseRecipients` is accepted and yields its recipients; a pointer document is an error naming RFC 0010; `SameRecipientSet` ignores order.

For the RFC 0003 grammar read piggy-ids(5) GRAMMAR and CANONICAL FORM first. Check whether the current parser tolerates unknown-purpose lines at all (`parseRecipientLine` in `codec.go:136` calls `id.Set`, which may reject an unregistered purpose). RFC 0008 §2.3 requires tolerance; if it rejects, fix it here with its own test.

Also fix here, in BOTH languages with a vector for it: `Document.validate()` (`codec.go`, `document.rs`) counts every line without a wrap as "unwrapped", so a sealed document that also carries an SSH-auth or unknown-purpose line is rejected as "mixed sealed/unsealed recipients". RFC 0008 §2.3 allows such lines in a sealed document and says they carry no wrap. Only encryption recipients may count toward the mixed-state check.

**Step 2: Run** `just test-go`. Expected: FAIL.

**Step 3: Implement.** No new imports beyond what the package has; it must stay buildable for `GOOS=js GOARCH=wasm`.

**Step 4: Run** `just codemod-facades`, `just test-go`. Expected: PASS.

**Step 5: Commit.** `pigpen: encryption-recipient helpers for consumers`

---

### Task 8: Agent-backed ECDH oracle and socket resolution in Go

**Promotion criteria:** N/A. `PivyEcdhP256GetIOWrapper` keeps using dewey's `PIVY_AUTH_SOCK`-only resolver; changing that is a separate decision.

**Files:**
- Create: `go/internal/delta/agent/pigpen_oracle.go`
- Test: `go/internal/delta/agent/pigpen_oracle_test.go`
- Regenerate: `go/pkgs/agent/main.go`

**API:**

```go
// ResolveAuthSock returns the agent socket piggy's decrypts use:
// PIGGY_AUTH_SOCK, else SSH_AUTH_SOCK, else PIVY_AUTH_SOCK (legacy).
func ResolveAuthSock() (string, error)

// AgentECDHOracle performs P-256 ECDH through an agent's
// ecdh@joyent.com extension. It satisfies pigpen.ECDHOracle
// structurally, without importing the pigpen package.
type AgentECDHOracle struct{ SocketPath string }

func (o AgentECDHOracle) ECDH(self markl.Id, partnerEpk []byte) ([]byte, error)
```

`ECDH` decompresses `self.GetBytes()` with `pivy.DecompressP256Point` and calls `pivy.AgentECDHFunc(o.SocketPath, pub)(partnerEpk)`. Before writing it, read dewey v0.5.0's `pivy` package in the Go module cache (not the purse-first checkout) and confirm the function exists with that shape and what form it expects the ephemeral key in. If it needs dewey changes, stop and hand that to the dewey owner.

**Step 1: Write failing tests.** `ResolveAuthSock` precedence with `t.Setenv` across the three variables. For the oracle: start an in-process Unix-socket agent in the test that answers `ecdh@joyent.com` with a software P-256 key (see how `go/cmd/piggy-agent-conformance` drives the extension for the wire shape), seal a pigpen document to that key, open it with `AgentECDHOracle`, compare plaintext. Also assert a compile-time `var _ pigpen.ECDHOracle = AgentECDHOracle{}` in the TEST file only, so the non-test package keeps no pigpen import.

**Step 2: Run** `just test-go`. Expected: FAIL.

**Step 3: Implement.**

**Step 4: Run** `just codemod-facades`, `just test-go`. Expected: PASS.

**Step 5: End-to-end against the Rust agent.** Add one case to `go/cmd/piggy-agent-conformance` (or the lane that runs it; find it via `just --list` and piggy-testing(7)) that seals to the fibby slot-9D test key and opens through `piggy agent` with the oracle. The askpass safety net from piggy-testing(7) PIN PROMPT SAFETY NET is mandatory in any recipe that can reach a PIN prompt.

**Step 6: Commit.** `go/agent: agent-backed pigpen ECDH oracle; PIGGY_AUTH_SOCK resolution`

---

### Task 9: Pointer resolution in Go (RFC 0010)

Kept in its own package so the pigpen core stays free of `os/exec` and remains WASM-buildable.

**Promotion criteria:** N/A.

**Files:**
- Create: `go/internal/delta/pigpen/pointer.go`, `pointer_test.go` (pointer parsing is pure and belongs in the core)
- Create: `go/internal/delta/pigpen_resolve/main.go`, `resolve.go`, `resolve_test.go`
- Create (generated): `go/pkgs/pigpen_resolve/main.go`

**API:**

```go
// package pigpen
type Pointer struct{ Kind, Locator string }

// ParsePointer decodes a pigpen-pointer-v1 document (RFC 0008 §2.2).
func ParsePointer(raw []byte) (*Pointer, error)

// package pigpen_resolve
// Resolve runs `pigpen-resolver-<kind> resolve <locator>` found on PATH
// and parses its stdout as a recipient-set document (RFC 0010 §3).
// Failure is hard: no cache, no stale fallback (§5).
func Resolve(ctx context.Context, p *pigpen.Pointer) (*pigpen.Document, error)

// LoadRecipients reads a piggy-ids file of any of the three forms and
// returns its encryption recipients, resolving a pointer if it is one.
func LoadRecipients(ctx context.Context, raw []byte) ([]markl.Id, error)
```

Decisions baked in, each differing on purpose from the Rust CLI:
- **No cache in the library.** The Rust CLI caches for an hour (`crates/piggy/src/pigpen_pointer.rs:167`). Madder wants drift detection on use, so the library always resolves and the caller decides whether to cache.
- **Timeout via `ctx`.** The Rust dispatch has none (#218); the Go one takes a context.
- **`kind` validation.** Reject a kind containing `/` or NUL (RFC 0010 §2) before building the executable name.

**Step 1: Write failing tests.** `ParsePointer`: the RFC 0010 worked example parses; a pointer carrying a recipient line is rejected; a `pigpen-v1` document is rejected. `Resolve`: write a tiny shell script named `pigpen-resolver-test` into `t.TempDir()`, put it on `PATH` with `t.Setenv`; cover success, non-zero exit with stderr surfaced in the error together with kind and locator, missing binary with a distinguishable message, a kind containing `/` rejected without exec, context cancellation, and stdout that is itself a pointer rejected. Guard against the fork/exec `ETXTBSY` race recorded in #249: write the script, close it, and `chmod` before first exec, and do not run these tests in parallel.

**Step 2: Run** `just test-go`. Expected: FAIL.

**Step 3: Implement.**

**Step 4: Run** `just codemod-facades`, `just test-go`, `just build-go`. Expected: PASS. Confirm the pigpen core still has no `os/exec` import: a search for `os/exec` under `go/internal/delta/pigpen` returns nothing.

**Step 5: Commit.** `pigpen: Go pointer resolution (RFC 0010)`

---

### Task 9a: Encrypt-only IO wrapper for `age_x25519_pub`

Requested by madder after the scope was agreed; Sasha approved it living in piggy on 2026-10-05. Today `age_x25519_pub` is registered as a plain `markl.Format` with no `GetIOWrapper` (`registrations.go:52`), so a consumer cannot encrypt to an age public recipient through `markl.Id.GetIOWrapper()`, which is how madder reaches every other key type. The alternative is for madder to build the age recipient from the raw 32 bytes itself and bypass markl.

**Promotion criteria:** N/A.

**Files:**
- Modify: `go/internal/delta/age/format_family_agex25519.go`
- Test: `go/internal/delta/age/age_test.go`
- Regenerate: `go/pkgs/age/main.go`

**Step 1: Establish feasibility first.** Read dewey v0.5.0's `age` package: is there a recipient-only type implementing `interfaces.IOWrapper`, or only `age.Identity` (which holds the secret)? If dewey has no recipient-only wrapper, stop: the wrapper belongs in dewey, and this task becomes a hand-off to the dewey owner.

**Step 2: Write the failing test.** Generate an identity, take its public id, get the wrapper from the PUBLIC id, encrypt through `WrapWriter`, decrypt with the existing secret-side wrapper, compare. Assert `WrapReader` on the public wrapper fails with an error that says no identity is available.

**Step 3: Run** `just test-go`. Expected: FAIL.

**Step 4: Implement** by swapping a `FormatPub` (or whichever format struct carries `GetIOWrapper` for a public key; check `format_pub.go`) over the plain registration via `markl.SwapFormat`, at `init()`, mirroring `RegisterAgeX25519SecFormat`.

**Step 5: Run** `just codemod-facades`, `just test-go`. Expected: PASS.

**Step 6: Commit.** `go/age: encrypt-only IO wrapper for age_x25519_pub`

---

### Task 10: Documents and hand-off

**Files:**
- Modify: `docs/rfcs/0008-pigpen-encrypted-document.md` (point §10 "Conformance" at the vector file; replace "deferred to the cutover RFC")
- Modify: `docs/rfcs/0009-pigpen-cutover.md` (§10 table: mark phases 2 and 4 done, note phase 4's single-source drift model)
- Modify: `docs/rfcs/0010-pigpen-pointer-resolution.md` (informative note: the Go library does not cache and takes a timeout)
- Modify: `doc/piggy-markl.7.scd` (LAYOUT and recipes: the pigpen, pigpen_resolve and agent-oracle surfaces; `codemod-pigpen-vectors`)
- Modify: `go/internal/delta/pigpen/doc.go` (no longer "a SKETCH"; say what is and is not production: inline payload only, whole-buffer)
- Update: piggy#26 and the tracking issues

**Step 1:** Make the edits. Set RFC 0008's `status:` to `accepted` (Sasha, 2026-10-05: accept when the vectors land, since the bytes are frozen from that point). RFC 0009 and RFC 0010 stay `draft`.

**Step 2: Run** `just lint-worktree` and `just codemod-fmt`. Expected: PASS.

**Step 3: Commit and merge.**

**Step 4: Tell madder.** Message `madder/brave-sycamore/bozo` with the merged commit to pin, the exported API list (`pigpen.Seal`, `Document.Open`, `Document.MarshalText`, `ParseDocument`, `ParseRecipients`, `EncryptionRecipients`, `SameRecipientSet`, `ParsePointer`, `pigpen_resolve.Resolve`, `pigpen_resolve.LoadRecipients`, `agent.AgentECDHOracle`, `agent.ResolveAuthSock`), and the limits that remain: whole-buffer payload, inline only, no re-wrap.

---

## What madder builds on top (for orientation, not piggy work)

1. `-encryption <path>` accepting a pigpen recipient document or pointer.
2. At store init: generate the X25519 store key, `pigpen.Seal` it to `LoadRecipients(...)`, store the sealed document plus the source reference and the recipient ids in the store config.
3. At open: parse the sealed document, `Open` with `agent.AgentECDHOracle{ResolveAuthSock()}` and any local X25519 identities, keep the store key in memory.
4. On use: re-resolve the source, `SameRecipientSet` against the sealed document's recipients, warn or refuse on drift.
5. Encrypting blobs to an `age_x25519_pub` recipient, which madder cannot do today.
