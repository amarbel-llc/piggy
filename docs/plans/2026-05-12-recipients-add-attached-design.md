---
status: draft
date: 2026-05-12
provenance: |
  Brainstormed in the eager-hemlock worktree, 2026-05-12. Captures
  the design for a new `--all-attached` mode on
  `piggy pass recipients add` that derives recipient markl IDs from
  every plugged-in PIV card and appends the supported ones to the
  store's `piggy-ids`. Companion issue for fib limitations:
  amarbel-llc/piggy#83.
---

# `piggy pass recipients add --all-attached` (design)

## Motivation

Adding a new YubiKey (or any PIV card) to an existing piggy store
today is a two-step manual process: run `piggy-ids detect-pubkey`
once per card to get its markl ID, then paste the IDs into
`piggy pass recipients add <ids>...`. With one card and the
`--guid` selector this is mechanical; with several it's
error-prone. This design adds a single-shot path: enumerate every
attached card, derive its `piggy-recipient-v1@…` markl ID, and
append the supported ones to the active `piggy-ids` in one
command.

## Non-goals

- Not a top-level CLI verb. Surfaces as a flag on the existing
  `piggy pass recipients add` so it shares scope (`-p subfolder`),
  re-encryption, and commit semantics with the literal-IDs form.
- Not a YubiKey-specific filter. Any PIV card with a P-256 ECDH
  key in slot 9D is supported, matching the rest of piggy's
  recipient vocabulary (RFC 0003, `detect-pubkey`).
- No changes to RFC 0003 (`piggy-ids` file format), to
  `RecipientFile` parsing, or to any wire format.
- No new top-level subcommand on the Rust `piggy-ids` helper
  beyond `detect-all-pubkeys`.
- No multi-card real-PCSC test coverage in this PR — see #83.

## Surface

```text
piggy pass recipients add --all-attached [-p subfolder] [--yes]
piggy pass recipients add -A          [-p subfolder] [--yes]
```

- `--all-attached` / `-A` is mutually exclusive with positional
  markl-ID arguments. Combining them is a usage error.
- `-p subfolder` resolves the active `piggy-ids` via the existing
  `find_piggy_ids` walker. Same scoping rules as
  `recipients add <ids>...`.
- `--yes` accepts the "unsupported cards detected, proceed?"
  prompt non-interactively. Required when stdin is not a TTY and
  unsupported cards are present.

## Components

1. **New Rust subcommand**: `piggy-ids detect-all-pubkeys` in
   `crates/piggy-ids/src/main.rs`.
   - No card-selection args; always enumerates all attached PIV
     tokens via `PivContext::enumerate_tokens()`.
   - Per token: read slot 9D. Classify as:
     - `Supported { id, guid }` if the slot returns `EcP256` and
       compresses cleanly to a 33-byte SEC1 point. `id` is the
       canonical `piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>`
       markl ID, produced by the existing `compress_p256_pubkey`
       helper.
     - `Unsupported { guid, reason }` otherwise. Reason strings:
       - `slot 9D is <algorithm>` (e.g. `slot 9D is RsaP2048`)
       - `slot 9D unreadable: <err>` (APDU / transport failure)
       - `pubkey decode failed: <err>` (EcP256 in metadata but
         cert/point decode fails — defensive)
   - Emits one line per token to stdout, sorted by GUID:
     ```text
     supported <markl-id>  <guid-hex>
     unsupported <guid-hex>  <reason>
     ```
   - Exit 0 on every "we successfully enumerated" outcome —
     including empty enumeration and all-unsupported. Nonzero
     only on PCSC context creation failure or
     `enumerate_tokens()` failure.
   - Pure-compute: no `piggy-ids` file reads, no prompts, no
     mutation.

2. **Refactor**: extract the classify-one-token logic into a
   pure function `fn classify_token(token: &PivToken)
   -> CardLine` returning the `Supported`/`Unsupported`
   enum. `cmd_detect_pubkey` (the existing single-card path) and
   `cmd_detect_all_pubkeys` both call into it. Pure-function
   shape supports unit tests without a PIV context.

3. **New shell branch** in `cmd_pass_recipients_add` (`src/piggy.sh`).
   - Parse `-A` / `--all-attached` and `--yes`.
   - Drive `piggy-ids detect-all-pubkeys`, parse stdout.
   - Resolve `piggy-ids` via `find_piggy_ids "$subfolder"`.
   - Compute partition (see Data flow below).
   - Emit info / dialog output and prompt.
   - Reuse the existing add-recipients tail (append +
     canonicalize + reencrypt + commit) for the survivors.

4. **Documentation and tests**: `doc/piggy.1.scd` text update,
   bats tier 1 (mock-driven) and tier 2 (fib-driven conformance).

Nothing else in the tree changes meaning. No new top-level
subcommands, no PCSC code outside `piggy-piv`, no new files in
`crates/piggy/`.

## Data flow

End-to-end for `piggy pass recipients add --all-attached
[-p subfolder] [--yes]`:

1. **Argument parse.** Bash handler validates flag combinations
   (`--all-attached` xor positional IDs).
2. **Locate piggy-ids.** Existing `find_piggy_ids "$subfolder"`
   sets `$PIGGY_IDS`. Missing → existing error path.
3. **Enumerate.** Shell to
   `"${PIGGY_IDS_PATH:-piggy-ids}" detect-all-pubkeys`. Capture
   stdout. Nonzero exit → die with helper's stderr passed
   through.
4. **Parse output.** Sort lines into two bash arrays:
   `supported_ids` (markl ID + GUID) and `unsupported_lines`
   (GUID + reason). Empty both → die `no PIV cards detected`.
5. **Partition supported vs already-present.**
   - Run `piggy-ids canonicalize "$PIGGY_IDS"` (idempotent).
   - Extract current markl IDs into a bash associative array.
   - For each `supported_ids` entry: if present in current set,
     push to `already_present`; else push to `to_add`.
6. **Surface already-present.** For each `already_present`
   entry, print on **stdout**:
   ```text
   already a recipient: <markl-id>  # GUID <guid-hex>
   ```
7. **Unsupported gate.**
   - If `unsupported_lines` is empty, skip to step 8.
   - Otherwise print a single dialog on stderr:
     ```text
     Cannot encrypt to <N> attached card(s) (slot 9D is not P-256 ECDH):
       <guid-hex>: <reason>
       ...
     ```
   - If `--yes`: proceed.
   - Else if stdin is a TTY: prompt
     `Continue and add the <K> supported card(s)? [y/N] `;
     anything other than `y`/`Y`/`yes` → die `aborted`.
   - Else: die `aborted: unsupported cards detected and stdin is
     not a TTY; pass --yes to proceed`.
8. **Empty post-dedup check.** If `to_add` is empty, print
   `nothing to add` on stderr and exit 0 without touching the
   file, the git tree, or the `.ebox` corpus.
9. **Append + reencrypt.** Reuse the existing add-path body:
   append each `to_add` ID to `$PIGGY_IDS`, run
   `piggy-ids canonicalize`, `git_add_file` (message:
   `Add <K> attached card(s) to piggy-ids.`), `reencrypt_path`,
   and a second `git_add_file` for the reencryption commit.

## Error handling and edge cases

**Helper-side (`piggy-ids detect-all-pubkeys`):**

- `PivContext::new()` / `enumerate_tokens()` failure → exit 2
  with `piggy-ids: <op>: <err>` on stderr. Mirrors today's
  `detect-pubkey`.
- Per-token errors are *not* fatal: they become an `unsupported
  <guid>  <reason>` line.
- Output stability: lines sorted by lowercase hex GUID. The
  shell side does not depend on ordering for correctness, but
  the stable order keeps commit-message diffs reproducible
  across re-runs.
- Empty enumeration → exit 0, zero lines. Shell side decides.

**Shell-side:**

- Helper nonzero exit → die with helper stderr passed through.
- Malformed helper line (neither prefix, wrong column count) →
  die `internal error: malformed line from
  piggy-ids detect-all-pubkeys: <line>`. This catches version
  skew between the bash driver and the Rust helper.
- Post-append canonicalize failure → restore `$PIGGY_IDS` from
  a pre-write backup (incidental hardening of the existing add
  path; multi-recipient appends raise the cost of a half-write
  enough to justify it).
- Reencryption mid-failure: inherits current `recipients add`
  semantics — some `.ebox` files rewritten, others not. We do
  not add atomicity here; see piggy's existing `reencrypt_path`
  contract.
- SIGINT during prompt → die `aborted`. No partial state.

**Edge cases worth pinning:**

- `-p subfolder` with a per-folder `piggy-ids`: walks up via
  `find_piggy_ids` exactly as today.
- A card present at enumerate, pulled before reencryption:
  irrelevant to this call. We only needed the 9D pubkey; the
  reencryption pipeline never touches the source card.
- Two attached cards with the same 9D pubkey (cloned import):
  dedupes to one recipient by markl ID equality. Both GUIDs
  appear in `already a recipient` lines on the second run; on
  the first run only one is added.

## Testing

### Tier 1 — mock-driven, fast

`zz-tests_bats/t0610-recipients-add-attached.bats` against a
PATH-shadowed `helpers/mock-piggy-ids.sh`:

The mock intercepts `detect-all-pubkeys` only and emits canned
output from env vars (`MOCK_DETECT_ALL_SUPPORTED`,
`MOCK_DETECT_ALL_UNSUPPORTED`); all other subcommands
(`canonicalize`, `encrypt`, `validate`) exec the real binary.
Same hybrid pattern used by today's `mock-pivy-box.sh` and
`t0600-recipients.bats`.

Cases, one bats test each:

1. Happy path, one new card.
2. Already a recipient.
3. Mixed: one new, one already, one unsupported, `--yes`.
4. Unsupported card without `--yes`, non-TTY → abort.
5. Unsupported card with `--yes`, zero supported → `nothing to add`,
   exit 0.
6. No cards → exit 1.
7. `--all-attached` plus positional ID → usage error.
8. `-p subfolder` scoping.

### Tier 2 — fib-driven, real PCSC

`zz-tests_bats/conformance/piggy_recipients_add_attached.bats`
under `--allow-unix-sockets --allow-local-binding`, lifecycle
via `setup_file()` / `teardown_file()` (mirrors
`piggy_box_interop.bats`).

Cases:

1. Happy path on real card. `pivy-tool generate -a eccp256 9d`
   on fib → init store against the resulting recipient →
   manipulate `piggy-ids` to force a non-empty add → run
   `--all-attached` → assert recipient line + reencryption
   commit.
2. Already a recipient. Run case 1 twice; second run hits the
   info line on stdout, byte-equal `piggy-ids`, no new commit.
3. Unsupported algorithm. `pivy-tool generate -a rsa2048 9d` on
   fib → `--all-attached` → assert dialog on stderr; `--yes`
   with zero supported → `nothing to add`; non-TTY without
   `--yes` → abort.

Cases *not* in tier 2 (covered in tier 1) and the reason:
mixed supported+unsupported, multiple supported, dedup with
multiple cards. fib is single-card by construction. Filed
amarbel-llc/piggy#83 for the upgrade; until that lands, the
multi-card aggregation is exercised in unit tests + tier-1 mock
bats.

### Rust unit tests

`crates/piggy-ids/src/lib.rs` (or a new sibling module):

- `classify_token` (or `classify_slot_9d`) returns
  `Supported`/`Unsupported` against synthetic algorithm values
  and a fixture P-256 certificate. No PIV context required.

### CI gating

- Tier 1 runs under `just test` (default path).
- Tier 2 runs under a new opt-in recipe
  `just test-bats-conformance-recipients-add-attached`,
  mirroring `test-bats-conformance-protocol`. Linux-only because
  fib is Linux-only. Not on the default `just test` lane.

Real-hardware verification is planned for the user after this
lands; it is not part of CI.

## Rollback

Purely additive. No existing flag, file, or subcommand changes
meaning. To roll back:

- Delete the `detect-all-pubkeys` Rust subcommand.
- Delete the `--all-attached` / `-A` branch in
  `cmd_pass_recipients_add`.

No data migration, no stored state. Dual-architecture /
promotion-criteria gates don't apply because the old behavior
continues unchanged.

## References

### Normative

- `docs/rfcs/0003-piggy-ids-file-format.md` — RFC 0003,
  `piggy-ids` text format. Recipient equality, canonical form.

### Informative

- `crates/piggy-ids/src/main.rs` — existing helper binary
  (`encrypt`, `validate`, `canonicalize`, `diff`,
  `detect-pubkey`); this design adds `detect-all-pubkeys`.
- `crates/piggy-piv/src/token.rs` — `enumerate_tokens()`.
- `src/piggy.sh` — `cmd_pass_recipients_add`, `find_piggy_ids`,
  `reencrypt_path`, `git_add_file`.
- `docs/virtual-piv.md` — fib (virtual PIV card) architecture
  and limitations.
- amarbel-llc/piggy#83 — fib multi-card support (follow-up).
- amarbel-llc/piggy#26 — open issue triage; this work hooks into
  the recipients management track.
