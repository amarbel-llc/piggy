---
status: accepted
date: 2026-09-22
promotion-criteria:
---

# The Rust `piggy tool` port

## Problem Statement

`piggy tool` was historically a passthrough that exec'd the C `pivy-tool`(1)
for PIV smart-card operations. The C-pivy retirement (piggy#289,
`docs/plans/2026-09-14-retire-c-pivy-rust-nix-migration.md`) ports those
operations to a pure-Rust implementation so piggy can stop shipping the C
binaries. This record captures the resulting `piggy tool` feature — its
interface and the design decisions that shape it — separately from the
migration plan, which is a roadmap that completes once the C stack is deleted.

## Interface

`piggy tool <op> [args]` — the operations piggy implements in Rust
(`crates/piggy/src/cmd/tool/`), each differential-tested against C `pivy-tool`
over the `fibby` virtual card. As of the piggy#289 3.6 cutover it is **NOT a C
superset**: an unported op or an unmodeled option is a **usage error (exit 2)**
that points at `piggy pivy tool`, never a silent hop to C.

Ported ops:

- **Read (PIN-free):** `pubkey <slot>`, `cert <slot>`, `attest <slot>`,
  `pinfo`, `list -j`.
- **Crypto (PIN-gated):** `sign <slot>` (stdin → signature), `ecdh <slot>`
  (peer pubkey on stdin → shared secret), `req-cert <slot>`.
- **Credential / admin:** `change-pin`, `change-puk`, `reset-pin`, `set-admin`
  (3DES mgmt key), `delete-cert <slot>`, `update-keyhist`, `write-cert <slot>`,
  `generate <slot>` (EC), `import <slot>` (EC), `factory-reset`.

Options modeled: `-g <guid>` (select a card), `-P <pin>` (repeatable),
`-K <mgmt-key>`, `-a <alg>`, `-j`/`--json` (list), `-n <cn>` (req-cert),
`--yes`/`--force` (factory-reset). Anything else → usage error.

Notable per-op behavior:

- **`list -j`** — the JSON card listing only, byte-for-byte identical to C's
  `-j` branch (short_id / guid / reader, the full CHUID incl. the BCD-decoded
  FASC-N, ykpiv version/serial, auth / vci / algorithms, per-slot cert fields).
  The `-j` flag must precede `list`. Bare `list` and `list -p` are usage errors.
- **`factory-reset`** — YubicoPIV RESET (INS 0xFB); the card requires the PIN
  and PUK both blocked first (else SW 6985). Gated by a **piggy-native
  confirmation**: a typed `YES` on the controlling tty, or `--yes`/`--force`
  to skip it non-interactively.
- **`req-cert`** — a minimal EC PKCS#10 CSR for the slot's key, signed on the
  card; subject `CN` from `-n`, else `<slot-name>@<short-guid>`.

The full C `pivy-tool` surface stays reachable through the explicit
`piggy pivy tool <args>` escape hatch — but as of Phase 4 the C binaries are no
longer bundled (test-only `.#pivy`), so that escape hatch works only if pivy is
installed separately.

## Examples

    piggy tool pubkey 9a                      # OpenSSH pubkey for slot 9A
    piggy tool -j list                        # JSON listing of all cards
    printf 'msg' | piggy tool -P 123456 sign 9a
    piggy tool -P 123456 req-cert 9a          # PEM CSR for slot 9A's key
    piggy tool --yes factory-reset            # wipe the applet (PIN+PUK must be blocked)
    piggy tool unsupported-op                 # -> usage error (exit 2); names `piggy pivy tool`
    piggy pivy tool <anything>                # explicit C passthrough (needs pivy on PATH)

## Limitations

- **EC-only.** Every crypto / key op supports ECDSA P-256 / P-384 only. RSA and
  Ed25519 were deliberately **dropped**, not ported (operator decision
  2026-09-22) — piggy is EC by design (RFC 0002 is P-256 ECDH). A non-EC slot,
  or `-a rsa2048` / `-a ed25519`, errors and points at `piggy pivy tool`.
- **`req-cert` is a *minimal* CSR** (subject + SPKI + signature, no requested
  extensions) — a valid, equivalent CSR carrying the slot key, NOT a
  byte-for-byte clone of C's cert-template output. C populates KeyUsage / EKU
  from its cert-template engine, which is out of scope here (that engine is
  Phase 3b.3, `piggy ca`). The CSR differential is therefore **structural +
  semantic** (openssl verifies the self-signature; the embedded key matches
  C's), not byte-exact. This mirrors `cert_builder`'s existing self-signed-cert
  minimalism.
- **`list` is JSON-only.** The human and parseable (`-p`) modes stay on C
  (`piggy pivy tool list`). The JSON `auth` / `vci_supported` / `algorithms`
  fields use the no-Discovery-object defaults — correct for a YubiKey; a
  non-YubiKey PIV card with a Discovery object, and the CHUID cardholder hex
  case, are tracked in #293.
- **`factory-reset`'s confirmation gate is piggy-native**, not part of the
  differential contract (C's is tty-only via `RPP_REQUIRE_TTY` and can't run
  headless). Its bats lane is a **state** differential (piggy resets, then both
  C and piggy read the card blank), not a byte differential.
- **The `piggy pivy tool` escape hatch is degrading.** As of Phase 4 the C
  binaries are not bundled; the passthrough reports that and needs pivy on PATH.
  Its code is deleted in Phase 5.

## More Information

- Migration roadmap + per-milestone landed notes:
  `docs/plans/2026-09-14-retire-c-pivy-rust-nix-migration.md` (piggy#289).
- The virtual card the port is differential-tested against: `crates/fibby`,
  piggy-testing(7); the fibby-backed differential lanes are the
  `test-bats-conformance-tool-*-fibby` recipes.
- RFC 0002 (piggy-box wire format) — the reason piggy is EC / P-256-only.
