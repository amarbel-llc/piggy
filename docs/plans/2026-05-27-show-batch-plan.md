# `piggy pass show-batch` — implementation plan

This is the **single entry-point** for picking up the show-batch
implementation in a fresh session. RFC 0005 is ratified
(`docs/rfcs/0005-pass-show-batch-ndjson.md`, status `accepted`); the
clap wiring, `PinSession` carve-out in `piggy-piv`, and NDJSON
emitter are merged. What remains is the decrypt loop in
`show_batch::run()` plus polish + tests + manpage.

Tracker: amarbel-llc/piggy#121. RFC: #120 (now closed).

---

## What's already in tree (as of master `bafc174` and earlier)

| Commit | What |
|---|---|
| `8fd1fd3` (pre-session) | RFC 0005 drafted (status `draft`). |
| `824d250` | RFC 0005 ratified (`status: accepted`, TBDs resolved, §Single-card Operation added). |
| `80118df` | `piggy pass show-batch` clap subcommand wired with positional names, `--names-from`, `--out-dir`, `--format` (ndjson\|human, default human), `--all-or-nothing`. Stub `run()` exits 2 with not-implemented message. |
| `0863c67` | `piggy_piv::PinSession<'tok>` RAII guard: PIN-bracketed `SCardBeginTransaction` lifetime, bounded `SCARD_W_RESET_CARD` retry (cap = 3), `Drop` ends with `ResetCard` if `pin_verified` else `LeaveCard`, swallowing errors via `tracing::warn`. `PivToken::begin_pin_session(&mut self) -> Result<PinSession<'_>, PivError>` is the entry. |
| `bafc174` | `show_batch::ndjson` submodule: `Record` tagged enum (Plan/Decrypt/Summary/BailOut), 8-value closed `DiagnosticKind`, per-record `emit_*` helpers with stdout flush. 4 cargo unit tests pinning field order, kebab-case rendering, null/omit semantics, LF separation. Module-level `#![allow(dead_code)]` is **the removal trigger for this work** — when `run()` consumes these types, remove that allow. |

The `cmd/pivy_box.rs::cmd_stream_decrypt` function is the reference
implementation to copy and adapt — it does the EboxStream parse +
`unlock_ebox` + chunk decrypt loop. It uses `CardEcdhOracle`
(non-session-aware) because it's the off-the-user-path Rust impl;
show-batch will replace that with `BatchOracle` (session-aware).

## What's left

Three task-list items in the order they should land:

1. **Task #3** — show-batch core: BatchOracle + decrypt flow. (~500 LoC)
2. **Task #8** — show-batch polish: diagnostics, SIGINT, --names-from, --all-or-nothing.
3. **Tasks #5 (bats conformance) and #6 (manpage)** — parallel after #8.

## Architectural decision (single-card path)

show-batch routes through Rust `piggy-box` internals + `PinSession`
rather than shelling out to C `pivy-box` like `verify.rs` / other
existing pass-* handlers do. This makes show-batch the **leading
edge** of the post-v1.0 "Rust impl on user path" arc that
#56/#57/#58/#59 track.

Why this divergence from the v1.0 wrap-C posture:

- The RFC's marquee promise is single PIN per batch. Shelling out
  to `pivy-box` per ebox gives N PIN prompts unless `pivy-agent` is
  caching, which would make the single-PIN guarantee *conditional
  on the user's environment* — not what the RFC says.
- The `PinSession` we just built exists specifically to honor the
  single-PIN promise; not using it for show-batch would leave
  PinSession unused.
- The race condition #56 describes (SW=6982 from another PC/SC
  client's `SCARD_RESET_CARD` between verify-PIN and ECDH) is
  *exactly* the case show-batch exposes — a batch of N ECDH
  operations from a single PIN.

Cost: show-batch consumes Rust crypto code that hasn't been on the
user path before. Mitigations:

- The Rust unlock + chunk-decrypt path is covered by existing
  integration tests (`unlock_ebox_card_integration.rs`,
  `unlock_ebox_agent_integration.rs`).
- The `PinSession` adds transaction wrapping the prior path lacked.
- Bats conformance tests (task #5) cover the user-visible surface.

## API survey

### `piggy_box` — read this in this order

1. `piggy_box::stream::EboxStream::from_bytes(&[u8]) -> Result<EboxStream>`
   parses the on-disk `.ebox` header (Ebox + chunk_size + cipher + mac).
   The struct's `ebox` field is `&mut`-able for `unlock_ebox`.
2. `piggy_box::unlock::unlock_ebox(&mut Ebox, agent, card)`. Pass
   `None` for `agent` (single-card direct PCSC), `Some(&mut BatchOracle)`
   for `card`. Returns `Ok(())` on success; sets the AES key inside
   the ebox.
3. After unlock: re-serialize the header via `stream.to_bytes()?`
   to compute the byte offset where chunks start in the original
   file bytes. (Yes, this is what the reference impl does — see
   pivy_box.rs:256-263.)
4. Loop: parse chunk frame (`u32 seqnr | u32 len | bytes`), call
   `stream.decrypt_chunk(Some(expected_seqnr), frame)`, append the
   returned plaintext to an accumulator. Increment `expected_seqnr`.

The chunk-parsing loop is at `crates/piggy/src/cmd/pivy_box.rs:265-300`
— copy verbatim, adapt the output sink from `io::stdout()` to a
`Vec<u8>` accumulator (we need to write atomically to `out_dir/<name>`
at mode 0600, not stream to stdout, so we buffer first).

### `piggy_box::oracle::EcdhOracle`

```rust
pub trait EcdhOracle {
    fn ecdh(
        &mut self,
        self_pubkey_ssh_blob: &[u8],
        partner_pubkey_ssh_blob: &[u8],
    ) -> Result<Vec<u8>, OracleError>;
}
```

`OracleError::NoKey` is the "this is not my key" signal that lets
`unlock_ebox` try the next PRIMARY config in the ebox. show-batch's
`BatchOracle` returns `NoKey` when `self_pubkey_ssh_blob` doesn't
match the chosen slot's pubkey.

### `piggy_piv::PinSession`

```rust
pub struct PinSession<'tok> { /* ... */ }
impl<'tok> PinSession<'tok> {
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), PivError>;
    pub fn sign_prehash(&mut self, slot_id: u8, data: &[u8]) -> Result<Vec<u8>, PivError>;
    pub fn ecdh_derive(&mut self, slot_id: u8, peer_ec_point: &[u8]) -> Result<Vec<u8>, PivError>;
    pub fn end(self) -> Result<(), PivError>;  // explicit terminator (propagates errors)
}
impl PivToken {
    pub fn begin_pin_session(&mut self) -> Result<PinSession<'_>, PivError>;
}
```

All PIN-using ops take `&mut self`. `Drop` is the safety net for
early-return paths; explicit `end()` propagates errors. The session
type-state is the gate: PIN-using ops are not callable on a bare
`PivToken`.

### `card_oracle::askpass_pin_supplier()`

Returns a `Box<dyn FnMut(&str) -> Result<Zeroizing<String>,
OracleError>>` that spawns `$SSH_ASKPASS` with the prompt as
`argv[1]`, reads one line of stdout, returns it. Reuse this
verbatim for show-batch's PIN prompt — no need to reimplement.
Composes with `contrib/piggy-askpass.sh` (#33) and the test
askpass (#35).

### Card enumeration

`piggy_piv::PivContext::new()?` then `ctx.enumerate_tokens()?`
returns `Vec<PivToken>`. Each `PivToken::read_slot(slot_id)?` gives
a `PivSlot` whose `public_key().key_data()` is an `ssh_key::KeyData`.
The existing `card_oracle::find_token_by_pubkey` (lines 80-103)
shows the pubkey-match pattern; adapt to "pick first card whose
slot decrypts the first ebox" rather than "find by SEC1-pubkey
equality".

### Store + name resolution

- `piggy::store::store_root()` — `$PIGGY_STORE_DIR > $XDG_DATA_HOME/piggy > $HOME/.local/share/piggy`.
- pass-name → ebox path: `<store_root>/<pass_name>.ebox` (the bash
  `cmd_show` already does this; piggy.sh:140-ish).
- Canonicalization: strip leading `/`, strip `.ebox` suffix
  (matches RFC 0005 §Decrypt Record's `name` field semantics).

## BatchOracle shape

```rust
struct BatchOracle<'tok> {
    session: &'tok mut piggy_piv::PinSession<'tok>,
    slot_id: u8,
    /// SSH wire blob of the chosen slot's public key. ecdh() compares
    /// `self_pubkey_ssh_blob` against this; NoKey if they don't match.
    self_pubkey_blob: Vec<u8>,
    /// True after `session.verify_pin` has succeeded. Set on first
    /// `ecdh()` call — that's the point of single-PIN.
    pin_verified: bool,
    /// Closure that supplies the PIN. From `askpass_pin_supplier()`.
    pin_supplier: PinSupplier,
}

impl<'tok> EcdhOracle for BatchOracle<'tok> {
    fn ecdh(
        &mut self,
        self_pubkey_ssh_blob: &[u8],
        partner_pubkey_ssh_blob: &[u8],
    ) -> Result<Vec<u8>, OracleError> {
        if self_pubkey_ssh_blob != self.self_pubkey_blob {
            return Err(OracleError::NoKey);
        }
        if !self.pin_verified {
            let pin = (self.pin_supplier)("Enter PIV PIN")?;
            self.session.verify_pin(&pin)
                .map_err(piv_to_oracle_error)?;
            self.pin_verified = true;
        }
        let partner_point = extract_point_from_sshkey_blob(partner_pubkey_ssh_blob)?;
        let partner_uncompressed = canonicalize_uncompressed(&partner_point)?;
        self.session.ecdh_derive(self.slot_id, &partner_uncompressed)
            .map_err(|e| OracleError::Transport(format!("ecdh_derive: {e}")))
    }
}
```

Reuse `card_oracle::canonicalize_uncompressed` and `piv_to_oracle_pin_error` (the
latter may need to be made `pub(crate)` if not already).

## Flow for `show_batch::run()` (task #3 core, no polish)

```
1. Expand names: positional only for slice 1; --names-from in slice 2.
2. Pre-flight per name:
   - Resolve to <store_root>/<name>.ebox; check exists.
   - Read bytes; EboxStream::from_bytes().
   - Keep (canonical_name, bytes, stream) tuples for the batch.
3. Card selection (decision 3b):
   - PivContext::new() + ctx.enumerate_tokens() (Vec<PivToken>).
   - For each token in enumeration order:
     - For each PRIMARY config part in the FIRST ebox:
       - Read token's slot at part.slot. If pubkey matches the
         part's recipient pubkey, this is our (card, slot).
   - If no match: emit bail-out "no PIV card has a slot matching
     the first ebox's recipients", return 1.
4. Open session:
   - token.begin_pin_session().
   - Build BatchOracle { session: &mut session, slot_id, self_pubkey_blob, ... }.
5. emit_plan(stdout, names.len() as u32).
6. For each (n, name, bytes, stream) in order:
   - try unlock_ebox(&mut stream.ebox, None, Some(&mut oracle as &mut dyn EcdhOracle))
   - on Err: emit_decrypt_failed(n, name, Diagnostic { kind: DecryptFailed,
              message: "<err>", retryable: None }); failed += 1; continue.
   - chunk loop (copy from cmd_stream_decrypt lines 265-300) accumulating
     plaintext into Vec<u8>.
   - chmod 0600 + atomic write to <out_dir>/<name>.
   - emit_decrypt_ok(n, name, out_path); ok += 1.
7. emit_summary(stdout, ok, failed).
8. session.end()?; return 0 if failed == 0 else 1.
```

## Slice boundary between task #3 and task #8

Task #3 lands a *working* show-batch with coarse error mapping:

- All non-IO failures → `DiagnosticKind::Internal` (the catch-all).
- No SIGINT handling — Ctrl-C aborts the process mid-stream, leaving
  a truncated stdout. RFC 0005 says consumers MUST detect this as
  "truncated" (no terminator emitted) — acceptable interim.
- Only positional pass-names — no `--names-from FILE` (the clap
  flag is parsed and ignored, with a comment noting task #8 wires it).
- No `--all-or-nothing` — partial outputs always left in place.
- Human format == ndjson format (same NDJSON output). Polish in #8.

Task #8 fills in the gaps:

- Map every relevant error to its RFC `DiagnosticKind`:
  - `PivError::PinIncorrect` → `PinIncorrect`
  - `PivError::PinBlocked` → `CardLocked`
  - `PivError::CardNotFound`, `Pcsc(_)` connection failures → `CardAbsent`
  - `BoxError::UnlockFailed` (from `unlock_ebox`) → `DecryptFailed`
    with message distinguishing crypto failure from
    wrong-recipient (decision 3c)
  - `std::io::Error` on file ops → `IoError`
  - askpass cancel (non-zero exit) → `PinCancelled`
- Install `signal_hook`-based SIGINT handler that flips an atomic
  flag the run loop checks between decrypts. On detection: emit
  `bail-out` with reason `"SIGINT received after decrypt n=K of N"`,
  return 1.
- Parse `--names-from FILE`: open file, read line-by-line, trim,
  skip blank + `#`-prefixed lines, append to positional names.
- Implement `--all-or-nothing`: track written paths during the
  loop; if any decrypt fails, unlink every written path before
  emitting summary. (Caveat: race with concurrent readers — by
  this point the consumer has already seen `decrypt {ok: true}`
  records, so the "wipe" is best-effort cleanup, not atomic.)
- Human format: lift the NDJSON records into a friendlier shape
  ("[1/3] config/ssh/foo → /tmp/out/config/ssh/foo ok") for
  terminal use. Doesn't need RFC conformance.

## Files to touch (estimated)

- `crates/piggy/src/show_batch.rs` — replace `run()` body, add
  `BatchOracle` struct + impl, helper functions for chunk parsing
  and atomic 0600 write. ~500 LoC added (mostly the run() body).
- `crates/piggy/src/card_oracle.rs` — possibly `pub(crate)` the
  `canonicalize_uncompressed` and `piv_to_oracle_pin_error` helpers
  if not already callable from `show_batch.rs`. Minor.
- `crates/piggy-box/src/oracle.rs` — possibly `pub(crate)` the
  `extract_point_from_sshkey_blob` re-export from `agent_ext`.
  Check current visibility first; if it's already accessible,
  nothing here.
- No changes to `piggy_piv`'s public surface — `PinSession` is
  done.

## After task #3 lands

Remove the `#![allow(dead_code)]` from `show_batch::ndjson` (every
type is now used). Remove the `#[allow(dead_code)]` from
`ShowBatchArgs`. Update the stub-removed comment.

## Gotchas to expect

1. **The borrow-checker dance for `BatchOracle` holding `&mut session`**.
   `BatchOracle` has a `&'tok mut PinSession<'tok>` field; `unlock_ebox`
   takes `&mut dyn EcdhOracle`. The `'tok` lifetime needs to outlive
   the `unlock_ebox` call but not the `run()` function. If clippy
   complains, look at how `cmd_stream_decrypt` does it with the
   `agent_dyn` / `card_dyn` casts (lines 242-247).
2. **The first ebox's recipient pubkey is buried in `ebox.configs[0].parts[0].piv_box`**.
   Read `piggy_box::piv_box::PivBox::recipient_pubkey` (compressed)
   and decompress via `card_oracle::canonicalize_uncompressed` for
   the slot-pubkey comparison.
3. **Atomic 0600 write**. Open with `OpenOptions::new().write(true).
   create_new(true).mode(0o600)`, write, close. If the file
   already exists at `out_dir/name`, the open fails — the RFC
   doesn't say what to do here; default is to fail the per-ebox
   decrypt with `IoError`. If `out_dir` doesn't exist, create with
   `0o700` (parent should be private too).
4. **`PinSession::Drop` runs on early return**. If `run()` errors
   between `begin_pin_session()` and end-of-batch, the session
   drops with `Disposition::ResetCard` (assuming `verify_pin`
   succeeded), which is correct. Don't `?` your way out of the
   loop without first emitting the appropriate `bail-out`.
5. **The treefmt + lint-rust + lint-fmt gate.** Always run
   `just codemod-fmt` before staging. Always run `just lint-rust`
   before committing. The pre-merge `just` hook will redo these,
   but catching them locally saves a 1m40s round-trip per typo.
   See the merge-failure history in this session.

## Verification before commit

```sh
just lint-rust          # clippy with -D warnings
just test-rust -p piggy show_batch  # the 4 ndjson tests should still pass
just codemod-fmt        # treefmt
```

Then `grit_add` the changed files, commit (signed, with
`Refs #121`), `mcp__plugin_spinclass_spinclass__nothing-but-the-truth`
addressing simplify / review / eng:loose-ends, and
`merge-this-session --git_sync true`. The pre-merge hook runs the
full suite — `nix build`, bats lanes, full cargo tests — and
takes ~1m45s. Don't redundantly `just test` before merging.

## Useful refs

- RFC: `docs/rfcs/0005-pass-show-batch-ndjson.md`
- Reference decrypt impl: `crates/piggy/src/cmd/pivy_box.rs::cmd_stream_decrypt`
- Existing oracle: `crates/piggy/src/card_oracle.rs::CardEcdhOracle::ecdh`
- PinSession docs: `crates/piggy-piv/src/token.rs::PinSession` (extensive doc-comments)
- NDJSON emitter: `crates/piggy/src/show_batch.rs::ndjson` (with cargo tests)
- Triage: GitHub piggy#26 (operational), piggy#121 (this work),
  piggy#56 (the broader gating issue this carve-out feeds)

---

🤡 by [Clown](https://github.com/amarbel-llc/clown)
