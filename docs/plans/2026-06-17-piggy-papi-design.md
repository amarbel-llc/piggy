# `piggy papi` — produce & verify PAPI identity proofs and document signatures

> **Superseded (2026-06-22, piggy#191): the `piggy papi` namespace was removed.**
> Per the layering directive (papi is downstream of piggy; piggy exposes only
> neutral primitives), papi composes its own document/proof/signature semantics
> caller-side on `piggy sign-bytes` (#190) + the headless `piggy manage`
> JSON-RPC API (#201, RFC 0007). papi never depended on `piggy papi` (confirmed
> with papi/deft-birch). This document is retained as the historical design
> record for the removed feature.

- **Date**: 2026-06-17
- **Status**: superseded (piggy#191 — `piggy papi` removed)
- **Driver**: PAPI RFC-0001 Amendment 3 (amarbel-llc/papi,
  `docs/rfcs/0001-personal-api-papi-wire-format.md` §9–§10) adapts
  Keyoxide/Ariadne's key-anchored, third-party-verifiable identity model into
  PAPI: a document now MAY carry bidirectional ownership **proofs** (§9) and a
  detached **document signature** (§10). The *verification* side is the
  amarbel-llc/papi validator's job; the *producing* side — minting the proof
  backlinks and signing the document with the card — is piggy's, because piggy
  holds the keys (slot-9D ECDH recipients, slot-9A SSH-auth). This doc pins that
  producing surface (plus a convenience verifier) as a `piggy papi` subcommand
  family.

## Why piggy owns this

PAPI's `piggy` block already carries `encryption_recipients[]` (slot-9D) and
`ssh_authorized_keys[]` (slot-9A) — the same key material a §9 proof binds to and
a §10 signature is made with. The recipient ids in a §9 `proof.recipient` use the
exact `piggy-recipient-v1@pivy_ecdh_p256_pub-…` grammar piggy already mints
(`piggy list` / `piggy-ids`), and a §10 `alg: "ssh-9a"` signature is a slot-9A SSH
signature — which the piggy agent already produces (`agent_client::probe_sign`,
the `ssh_copy_id` slot-9A path). So the producing side is assembled from
primitives piggy already ships; no new crypto.

## Scope

In scope:

- `piggy papi sign` — emit a §10 `signature` object for a PAPI source document.
- `piggy papi prove` — emit a §9 proof backlink token to paste into an external
  account (the publisher half of a bidirectional proof).
- `piggy papi verify` — a convenience client that runs the §9.4 / §10.3 verdicts
  against a live domain. This **overlaps** the amarbel-llc/papi validator on
  purpose (ergonomic paved path from the tool that holds the card, mirroring the
  `piggy health` vs `ssh-agent-mux health` split); the papi repo's validator
  stays the authoritative conformance gate.

Out of scope (explicitly declined for v1):

- Authoring/serving a PAPI document or the HTTP endpoints (§4) — that is the
  server's job (friedenberg/linenisgreat reference impl), not piggy's.
- The challenge/response handshake client (§5) — separate surface; if it lands it
  is `piggy papi auth`, sequenced after this.
- `fmt: "signature"` proof backlinks (§9.3) in the **first** cut of `prove`; ship
  `fmt: "recipient"` first (lowest-common-denominator presence proof), add the
  signature format once `sign`'s SSH-sig path is proven.

## CLI surface

`piggy papi` — new **top-level** clap subcommand (sibling of
`list`/`agent`/`box`/`health`/`ssh-copy-id`), handler
`crates/piggy/src/papi.rs` (or a `crates/piggy/src/papi/` module if it grows).
Bare `piggy papi` prints clap help (no implicit subcommand), matching bare
`piggy` / `piggy pass`.

Telemetry: `piggy.papi.<sub>` via `crate::stats` (own category, Rust-only — like
`piggy.health`; not a `pass` subcommand). `<sub>` ∈ `sign|prove|verify`.

### `piggy papi sign`

    piggy papi sign [--in <papi.json>] [--recipient <id> | --ssh-key <authkeys-line>]
                    [--out <path>] [--inline]

- Reads the PAPI **source** document JSON from `--in` (default stdin).
- Removes any existing top-level `signature` member, canonicalizes the remainder
  per RFC 8785 / JCS (§10.2), and signs the UTF-8 bytes with a slot-9A SSH
  signature via the agent (`alg: "ssh-9a"`).
- `--ssh-key` / `--recipient` selects the signing key; it MUST resolve to a key
  the document publishes (an `ssh_authorized_keys[]` line or an
  `encryption_recipients[]` id) so a verifier can find it (§10.1). Default: the
  store's single slot-9A SSH-auth entry if unambiguous, else error listing
  candidates.
- Emits the `signature` object `{alg, key, sig, created}` (§10.1) to stdout
  (default) or, with `--inline`, writes the full document with the `signature`
  member merged in to `--out` (default stdout).

### `piggy papi prove`

    piggy papi prove --claim <uri> --recipient <id> [--service <hint>]
                     [--fmt recipient|signature] [--id <stable-id>]

- Emits the **backlink token** the subject pastes at the external `proof_uri`
  (§9.3) plus the ready-to-merge `proofs[]` entry JSON (§9.1) for the document.
- `--fmt recipient` (default): the token is the bare `--recipient` id (the
  presence proof). `--fmt signature`: the token is a slot-9A SSH signature over
  the exact `--claim` string (reuses the `sign` signing path), for services that
  allow longer free-form content.
- Prints two blocks to stdout: (1) **PASTE THIS** — the literal backlink to put in
  the GitHub bio / gist / pinned toot / DNS TXT; (2) **ADD TO papi.json** — the
  `proofs[]` entry with `id`/`recipient`/`claim`/`proof_uri`/`service`/`fmt`. (The
  subject fills `proof_uri` after pasting, or passes it via a future `--proof-uri`.)

### `piggy papi verify`

    piggy papi verify <domain>[#<proof-id>] [--json] [--require-signed]
                      [--proof <id>...]

- Fetches `https://<domain>/.well-known/papi` (discovery, §4.1), follows
  `resources` to `/papi` and `/papi/proofs`.
- For each proof (or the `#<proof-id>`-selected one): runs the §9.4 three-outcome
  verdict — fetch `proof_uri` (HTTPS, bounded, same-host redirects only), check
  the backlink for the §9.3 `fmt`, confirm `recipient` is published →
  `verified` / `unverified` / `unverifiable`.
- For the document `signature` (§10.3): reconstruct the §10.2 JCS signing input
  from an **anonymous** `GET /papi` (or the discovery `signature`), verify `sig`
  against the published `key` → `signed-and-valid` / `signed-but-invalid` /
  `unsigned`. `--require-signed` makes `unsigned`/`signed-but-invalid` a non-zero
  exit.
- Output discipline mirrors `piggy health`: TAP-14 on a tty / `--json` for
  machines; stdout carries only the verdict stream, fetch errors to stderr. Exit
  `0` iff every selected proof is `verified` and (if `--require-signed`) the
  signature is valid.

## Reused primitives (no new crypto)

| Need | Existing piggy surface |
| --- | --- |
| slot-9A SSH signature over bytes | `agent_client` (the `probe_sign` path; the agent already signs a nonce with a served identity) |
| recipient id grammar / minting | `piggy_ids` / `piggy list` (`piggy-recipient-v1@pivy_ecdh_p256_pub-…`) |
| authorized_keys rendering / key match | `piggy_ids::openssh_authorized_key` (the `ssh_copy_id` slot-9A encoder) |
| `PIGGY_AUTH_SOCK` routing to piggy-agent | `agent_client::piggy_auth_sock_override` |
| store walk / `piggy-ids` discovery | `store::{store_root, find_piggy_ids}` |
| structured TAP/ndjson output | `tap-dancer` (already a dep; powers `health` / reencrypt) |

The only genuinely new building blocks are (a) an **RFC 8785 JCS** canonicalizer
and (b) for `verify`, an **HTTPS fetch**. See Dependencies.

## Dependencies & the JCS / HTTP question

- **JCS (RFC 8785).** §10.2 makes canonicalization load-bearing — the hard part is
  number canonicalization. Prefer a small vetted crate (e.g. `serde_jcs` /
  `json-canon`) over hand-rolling. **Constraint:** the document is author-written
  JSON; if it only ever contains strings/objects/arrays/booleans and integer
  counts (true for a PAPI doc — no floats), a `serde_json::Value` with
  recursively sorted keys and compact separators is JCS-equivalent and avoids a
  new dep. Decision: ship the sorted-`Value` path **gated by a validation pass
  that rejects any non-integer number** (so we never silently mis-canonicalize a
  float), and only pull a JCS crate if a real document needs floats. Document the
  limitation inline.
- **HTTP fetch for `verify`.** A blocking HTTPS client is a heavier dep
  (`reqwest`/`ureq` + TLS). To keep the agent/box build closure lean, `verify`
  SHOULD be feature-gated (`--features papi-verify`) or, simpler for v1, shell out
  to `curl` the way other piggy paths shell out to system tools — `verify` is a
  convenience surface, the authoritative verifier is the papi repo's validator.
  Decision: v1 `verify` shells out to `curl` (bounded `--max-filesize`,
  `--max-time`, `--proto =https`, `-fsSL` with `--location-trusted` **off** so a
  cross-host redirect is not auto-followed); no new Rust HTTP dep. `sign`/`prove`
  need no network and carry no such dep.

## Output & exit discipline

Same contract as `reencrypt::run` / `health`: structured stream on stdout, all
subprocess + fetch stderr stays on stderr; exit non-zero on any failing
verdict. `sign`/`prove` are single-shot emitters (stdout = the artifact, exit 0
on success); `verify` is the TAP/ndjson stream.

## Test plan (bats + Rust unit)

- **Rust unit** (`crates/piggy/src/papi.rs` `#[cfg(test)]`): JCS canonicalization
  vectors (key sorting, the signature-stripped round-trip, integer-only guard);
  proof-entry / signature-object serialization; `fmt` dispatch. No card.
- **bats** `zz-tests_bats/t0900-papi.bats` (non-hardware, sandbox lane):
  - `sign` produces a `signature` whose `key` is a published key and whose `sig`
    verifies against the mock agent (reuse the base64 mock-pivy-box substrate the
    way `t0800-ssh-copy-id.bats` mocks `ssh-copy-id`).
  - `prove --fmt recipient` emits the recipient id verbatim + a well-formed
    `proofs[]` entry.
  - `verify` against a **fixtured** local document + a mock `curl`
    (`helpers/mock-curl.sh`) exercising all three §9.4 outcomes and the §10.3
    signed/invalid/unsigned verdicts, including a cross-host redirect → unverified
    and a non-canonical-bytes → signed-but-invalid.
- **fibby conformance** (`conformance/piggy_papi_fibby.bats`, `hardware` tag):
  real slot-9A `sign` against a fibby card → `verify` the produced signature end
  to end; SKIPs without the piggy toolchain. Parallels the
  `age_plugin_piggy_fibby.bats` real-crypto pin. Cross-checks against the papi
  repo's `test-papi-challenge-fibby` so the two sides agree on the wire bytes.

## Sequencing & status

1. **Done — spec frozen.** PAPI RFC-0001 Amendment 3 (§9–§10) is committed in
   amarbel-llc/papi. The wire contract this implements is stable.
2. **This doc** pins the piggy producing surface against that contract.
3. **Implementation** (`crates/piggy/src/papi.rs` + clap wiring in `main.rs` +
   the `internal-*`/help/version-adjacent plumbing + tests) is the next PR. It is
   **not** landed here: the producing code is straightforward (assembled from the
   reused primitives above) but cannot be build- or test-verified in the
   network-restricted web sandbox (the workspace's `tap-dancer` git dep does not
   resolve offline), and piggy's convention is that code lands only behind a green
   `just build` / `just test`. Implementing it belongs in an environment that can
   run the nix build.
4. Track under the #26 triage / #3 parity roadmap as "PAPI producing surface".

## Open questions

- Should `sign`'s default key be slot-9A (SSH-auth) always, or allow a slot-9D
  recipient to double as the signing identity? RFC §10.1 permits either; piggy's
  natural signer is slot-9A. Default 9A, allow `--recipient` override.
- `prove --fmt signature` over `--claim`: pin the exact signed-string framing
  (raw `claim` vs a namespaced `papi-proof-v1:<claim>`) before shipping the
  signature format, so verifiers and producers agree. Lean toward a namespaced
  prefix to prevent signature reuse across contexts.
- Whether `verify` should also be exposed in the papi repo's validator as a shared
  library vs. duplicated — defer; the two-implementations-one-wire-contract split
  is acceptable per the §ConformanceTesting note in the RFC.
