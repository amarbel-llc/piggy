# pigsty — a pigpen-backed password vault (design)

Status: approved by Sasha section by section on 2026-10-25 in session
`piggy/live-sequoia`. This document lives in piggy until the `pigsty`
repository is bootstrapped, then moves there; piggy keeps a pointer.

## Goal

A KeePassXC-shaped password manager for Linux and Android whose crypto
is piggy's: entries are hyphence documents stored as blobs in a madder
sealed-key store, the store key is sealed to a pigpen recipient set
(RFC 0008), and a P-256 recipient is a YubiKey PIV slot 9D reached
through piggy-agent on Linux and directly over NFC/USB on Android.
Local stores, tags, arbitrary key-values, a password generator, entry
history, attachments, and record-level merge between devices are in
the first cut. TOTP and an Android autofill service are deferred, not
rejected.

## Decisions (2026-10-25, Sasha)

| # | Decision | Alternatives considered |
|---|---|---|
| 1 | Android decrypts with the YubiKey over NFC/USB; no phone-held key, no remote agent. | phone-held X25519 key; both; remote agent over the network |
| 2 | One sealed key per store, every blob encrypted under it (madder's sealed-key store), so one card touch unlocks a session. | one sealed pigpen per entry (pass-style); hybrid with a sealed index |
| 3 | MVP: entries, tags, key-values, generator, history, attachments. TOTP and autofill deferred. | |
| 4 | Flutter UI over a Rust core via flutter_rust_bridge. | Tauri 2; Slint/egui; Kotlin Multiplatform |
| 5 | Record-level merge; the store is a plain directory any file-sync tool moves. | last-writer-wins file; git-backed |
| 6 | Linux card path: piggy-agent first, PC/SC fallback (crypt.rs's rule). piggy#335 filed to rename `ecdh@joyent.com` to `ecdh@code.linenisgreat.com`. | PC/SC only; agent only |
| 7 | Entries are hyphence documents; versions form a content-addressed DAG; dodder is the eventual engine, madder the backing store now. | field-level LWW; dodder immediately |
| 8 | The Rust implementation of madder's sealed-key store is written in the madder repo (session `madder/live-cedar`, fable), bootstrapped from conformist's eng-rust template. | Rust core in piggy speaking madder's format; embedding Go madder via gomobile; a piggy-owned layout |
| 9 | pigsty is its own repo importing madder's Rust crate and piggy's crates, because `dewey → piggy → madder` forbids piggy importing madder. | app in piggy with a Go-only reading of the layering rule; app in piggy with the crate in piggy |
| 10 | Name: `pigsty`. | sty, trough, truffle, hoglet |

## 1. Architecture and repos

`pigsty` has two parts.

- `crates/pigsty-core` (Rust): the application model. Opens a madder
  sealed-key store through madder's Rust crate, unseals the store key
  with a `piggy_pigpen::EcdhOracle`, and exposes: open/lock store,
  list entries, read/edit/save an entry, history, attachments, merge.
  No UI concepts; no card or agent I/O of its own (it receives an
  oracle).
- `app/` (Flutter): the UI, bound by flutter_rust_bridge. Dart owns
  platform plumbing only: file pickers, the Android NFC/USB APDU
  transport, secure-window flags. Nothing cryptographic.

Dependency direction (madder may import piggy, never the reverse):

```
pigsty → madder (Rust store crate) → piggy-pigpen
pigsty → piggy-pigpen, piggy-piv            (git dependencies)
```

Card access is one trait, `ApduTransport`, with three
implementations: PC/SC on Linux (piggy-piv's current code moved behind
the trait), an Android NFC/USB plugin that hands APDUs to Dart, and
fibby for tests. The Linux oracle prefers piggy-agent and falls back
to PC/SC; the Android oracle is always the direct transport.

Build: Nix for the Linux app (`buildFlutterApplication`) and the Rust
crates. Whether a flutter_rust_bridge Android build works reproducibly
under nixpkgs' `androidenv` is unverified and is a phase-0 spike; the
fallback for first releases is the stock Flutter toolchain outside Nix.

## 2. Data model

A pigsty store is one madder sealed-key store directory; several local
stores are several directories. Everything pigsty writes is an
immutable blob. The only mutable files are the per-device heads
(§4), written by atomic rename.

### Entry version (`pigsty-entry-v1`)

One blob per save; the content digest is the version id.

```
---
# Forgejo (work)
- work
- forge
- entry=01JB8M7Q3S4E9RZK2XF0A6W8CD
- parent=@blake2b256-<previous version>
- saved=2026-10-25T02:54:00Z
- username=alice
- password="correct horse battery staple"
- url=https://code.example
- attachment=recovery-codes.txt @blake2b256-<blob digest>
! pigsty-entry-v1
---

Free-text notes go in the body.
```

- Bare `-` lines are tags.
- `key=value` lines are the arbitrary key-values. `username`,
  `password`, `url` are conventional keys the UI renders specially;
  nothing else distinguishes them.
- A locked field (`- attachment=<name> @<digest>`) is an attachment
  edge; the target is an opaque blob.
- `parent` names the prior version; a merge-resolution version
  carries two `parent` lines; the first version has none.
- A deletion is a version with `state=deleted` (a tombstone).
- `entry` is the stable identity across versions. Whether it should
  be a registered markl format rather than an opaque ULID is open
  (§7); do not assume either.
- `saved` orders versions for display only; merge never uses it.

### Index (`pigsty-index-v1`)

One blob per save, chained by `parent`. Its lines are hyphence locked
references pinning each live entry id to its current head:

```
- 01JB8M7Q3S4E9RZK2XF0A6W8CD @blake2b256-<head version>
```

Opening a store is: unseal key, read the heads, read the index, read
entry heads lazily. History is a walk down `parent`. Nothing is ever
rewritten, which is what makes merge a union and what dodder's
inventory lists later replace one for one.

Generator policy and UI preferences stay per device, not in the store.

## 3. Crypto and card paths

**Unlock** is madder's sealed-key read path executed in pigsty-core:
parse `blob_store-key`, pick the wrap line whose recipient matches the
key present, one ECDH through the oracle, unwrap the file key, open
the X25519 store key, then decrypt blobs in software. One card
operation per session; at most one unwrap attempt per distinct
recipient (RFC 0008 §10). The store key lives in memory only and is
zeroized on **lock**: idle timer, app backgrounded (Android), or on
demand. **Writes need no card**: new versions are age-encrypted to
the store's public half.

**Linux oracle**: piggy-agent at `PIGGY_AUTH_SOCK`, then
`SSH_AUTH_SOCK`, via the ECDH extension, sending
`ecdh@code.linenisgreat.com` first and falling back to
`ecdh@joyent.com` (piggy#335); else direct PC/SC through piggy-piv
with an in-app PIN dialog. PIN sessions and multi-card presence stay
the agent's (FDR 0001).

**Android oracle**: piggy-piv's PIV session (SELECT, VERIFY, GENERAL
AUTHENTICATE on 9D) over an `ApduTransport` Dart implements twice: NFC
via IsoDep transceive, USB via a small Kotlin CCID plugin. The UI
holds a "keep your key on the phone" sheet for the whole exchange; a
dropped NFC session fails and is retried. PIN is an in-app secure
field, never persisted; the window is `FLAG_SECURE`. The card is
matched to a recipient by reading the slot-9D certificate and
comparing its public key against the recipient lines, so a store
sealed to several YubiKeys opens with whichever is tapped.

**Recipient management** is madder's `key-status` / `key-reseal`.
v1 shows the sealed set and pigpen drift (no card) and defers in-app
reseal to the madder CLI on Linux. Removing a recipient is not
revocation (madder's own warning); revocation is a new store and a
sync, and the app says so.

**Cleartext**: recipient set, blob count and sizes (RFC 0008 §6.7).

## 4. Merge and sync

Transport is not pigsty's job: Syncthing, rsync, a cable, or on Linux
`madder sync`. Blobs are content-addressed and never conflict; only
the root pointer can diverge.

**Per-device heads.** Each device writes only `heads/<device-id>`,
the digest of the index it last saved, so a file-sync tool never sees
two writers to one path. On open, pigsty reads every head:

- all equal, or each an ancestor of one of them: fast-forward;
- otherwise **auto-merge**: find the nearest common ancestor index by
  walking `parent`; per entry id take the side that changed it; an
  entry changed on both sides where neither head is an ancestor of
  the other is a **conflict**, and the merged index carries two
  locked lines for that id. Delete-versus-edit is a conflict. The
  merged index names both parents and the device's head advances.

Conflicted entries show side by side; resolving writes an entry
version with two `parent` lines, returning the index to one line.

**Partial sync**: a head naming a blob not yet copied shows as
"pending", never corrupt or missing (madder's "unreadable, not
missing" posture).

**Known limitation**: `madder sync` moves blobs only, not `heads/`;
Linux-to-Linux sync by madder alone needs the heads copied separately
until dodder's inventory lists take this role.

## 5. UI surface, errors, testing, rollout

**MVP screens**: store picker (open a directory, recents); unlock
sheet (expected key, PIN, hold-key-to-phone); entry list with search
and tag chips; entry view/edit (conventional fields, key-values,
attachments, notes, reveal/copy per secret); generator in the password
field; history with per-version diff and "restore as new version";
conflict view. No folders: tags, and a `folder=` field later if missed.

**Errors**: piggy-piv's refusal module supplies "wrong PIN, N tries
left", "touch required", "card locked"; a key matching no recipient
names the recipients the store expects; an unreachable agent falls
through to PC/SC with one line of explanation; pending blobs render as
placeholders; every card-path failure is reported as the oracle's,
never as "no recipient" (RFC 0008 §10).

**Testing**: pigsty-core tests without a UI over temp madder stores
with X25519 recipients (no card). Card paths test against fibby
through `ApduTransport`, so the same PIV code runs over PC/SC on
Linux and over fibby in CI. Cross-implementation fixtures come from
`madder/live-cedar`. Flutter widget tests. Android NFC/USB is a manual
checklist on a throwaway YubiKey (`debug-yk-throwaway-*` pattern).

**Phases**:

0. Spikes: Nix Android build of a flutter_rust_bridge hello-world;
   fibby behind `ApduTransport`.
1. Piggy-side work (below).
2. pigsty-core on Linux over the madder crate.
3. Flutter Linux app.
4. Android transport and release.

**Rollback**: pigsty replaces nothing, so no dual-architecture period.
The one change to existing code is the piggy-piv refactor, landing as
one behavior-preserving commit with no wire or CLI change; rollback is
reverting it.

## 6. Piggy-side work (owned by `piggy/live-sequoia`)

- Lift piggy-piv's PIV session off `pcsc::Card` behind `ApduTransport`,
  PC/SC as the first implementation, gated by the existing fibby bats
  lanes.
- Whatever `piggy-pigpen` public API `madder/live-cedar` asks for (a
  sidecar-open helper is likely); align `Pointer::parse` strictness
  with the Go `ParsePointer`.
- piggy#335: the ECDH extension rename with an indefinite alias.
- Update piggy#26.

## 7. Open questions

- Should the entry id be a registered markl format? Check the markl
  registries before deciding; the design works with an opaque ULID.
- Does nixpkgs' `androidenv` + Flutter build a flutter_rust_bridge app
  reproducibly? (Phase 0 spike.)
- Which on-disk details of madder's sealed-key store are pinned by
  FDR-0011 or a vector, and which need pinning before pigsty depends
  on them? (`madder/live-cedar` reports.)

## 8. Tuning levers

| Lever | Start | Change signal |
|---|---|---|
| Idle-lock timeout | 5 min | re-taps annoy (lengthen); shared phone (shorten) |
| Clipboard clear | 45 s (piggy's default) | same |
| Auto-merge on open | silent | merges surprise users (ask first) |
| History compaction | none (waits for dodder) | store size or open latency on the phone |

## References

- piggy RFC 0008 (pigpen), RFC 0009 (cutover, draft), RFC 0010
  (pointer resolution)
- madder FDR-0011 (`docs/features/0011-pigpen-sealed-store-key.md` in
  the madder repo), blob-store(7) SEALED-KEY STORES
- hyphence(7): `-` tag/field/locked-reference grammar, canonical order
- piggy#335 (ECDH extension rename), piggy#26 (triage)
