---
status: accepted
date: 2026-09-15
provenance: |
  Plan to retire the vendored C pivy stack (vendor/pivy, nix/pivy.nix,
  openssh.patch) in favour of the Rust crates plus nix, with the test
  discipline needed to do it without regressing the card paths.
  Consolidates the "pivy-C elimination sequence" from triage #26
  (2026-06-10), the umbrella #3 "done means", the 2026-04-21 `piggy
  tool` scoping doc, and #265 (declared-but-unbuilt passthroughs).
  Written from a full inventory of exec sites, nix outputs, bats lanes,
  and justfile recipes on master at 3fc917e.
---

# Retire the vendored C pivy stack: Rust + nix migration plan

## TL;DR

piggy is already mostly Rust. What still runs C at runtime is small
and well-bounded:

| Surface | Today | Fate |
|---|---|---|
| store decrypt (`show`/`edit`/`generate -i`/`grep`/`verify`/re-encrypt walk) | ~~spawns C `pivy-box stream decrypt`~~ in-process `Decryptor` since 2026-09-15 | ~~port in-process (#164)~~ done |
| `piggy box` residual (`tpl edit`, `key *`, `challenge *`, interactive modes) | falls back to C `pivy-box` | drop (#165) |
| `piggy tool` | exec C `pivy-tool` | port the subset piggy needs |
| `piggy ca` / `luks` / `zfs` | exec binaries nix never builds (#265) | delete the dead exec arms now; re-land each as a Rust command (Phase 3b), `luks` first |
| `piggy pivy <tool>` escape hatch | exec any `pivy-*` | delete last |
| C `pivy-agent` (`-C` confirm, `install-service`) | reachable via `piggy pivy agent` and the HM module's `package = pkgs.pivy` branch | drop |
| C pivy as a **test oracle** (~14 conformance bats + ~20 justfile recipes) | live differential baseline | freeze into golden fixtures, then delete |

The order is chosen so that every phase removes C from a user path
only after a Rust path for it is gated in CI, and so that the
differential-testing discipline C gives us today is converted into
static fixtures before the C binaries disappear.

Five phases. Phases 0 to 2 are small and can start immediately.
Phase 3 (`piggy tool`) is the only large port; Phase 3b re-lands
`luks`, then `zfs`, then `ca` as Rust commands. Phases 4 and 5 are
packaging: first demote C pivy to a test-only nix input, then delete
it.

## Current status (2026-09-22)

**Phase 3 (`piggy tool`) is complete, and Phase 4 has landed.** A fresh
session picking this up should know:

- **`piggy tool` is a Rust re-implementation, not a C superset** (the 3.6
  cutover): every op piggy needs is ported, and an unported op or unmodeled
  option is a usage error (exit 2), not a hop to C. Ported ops: `pubkey`,
  `cert`, `attest`, `sign`, `ecdh`, `change-pin`/`change-puk`/`reset-pin`,
  `set-admin`, `delete-cert`, `update-keyhist`, `write-cert`, `generate`,
  `import` (EC), `pinfo`, `list -j`, `factory-reset`, `req-cert`. See the
  milestone landed-notes below (3.8 `list -j`, 3.9 `factory-reset`, 3.10
  `req-cert`) and FDR 0005 for the interface + design decisions.
- **piggy is EC-only.** RSA and Ed25519 key ops were deliberately **dropped**,
  not ported (operator decision 2026-09-22); they leave with the runtime C.
- **Phase 4 landed 2026-09-22:** C pivy is out of the shipped `piggy` runtime
  closure (test-only `.#pivy` remains), enforced by `checks.lint-closure-no-pivy`.
- **Next is the Phase 4 soak, not code:** run the pivy-free `piggy` on every
  host for ~1 week before Phase 5 (delete the C stack). The soak's statsd
  counter-watch is blocked on a finding — the stats-me instance carries **no
  piggy telemetry** (only the statsd daemon's self-metrics), so either
  `STATSD_HOST`/`STATSD_PORT` need wiring on the piggy hosts, or the soak runs
  on `piggy health` alone. Resolve this before/at the start of the soak.
- **Phase 5** (post-soak): delete `vendor/pivy`, `nix/pivy.nix`, the `.#pivy`
  output, the `piggy pivy` clap arm + `exec_pivy`, the HM `pname == "pivy"`
  C-agent branch, and freeze the oracle bats lanes into replay fixtures.

Follow-ups filed this cycle: #291 (factory-reset — closed), #290
(update-keyhist read-back differential), #292 (PIN-gated PINFO read), #293
(list JSON fidelity gaps: discovery-object auth/vci, algorithms, cardholder
hex, human/parseable modes).

## Where things stand

### Rust already owns

- Encryption: `piggy-ids encrypt` builds the template and seals in
  Rust (`crates/piggy-box`). No C on the encrypt path anywhere.
- `piggy agent`: full SSH agent, all extensions, multi-card hot-swap,
  upstream proxying, proxy-only mode (FDR 0001, FDR 0002).
- `piggy box stream encrypt/decrypt`, `tpl create/show`
  (`crates/piggy/src/cmd/pivy_box.rs`), with both agent and direct-card
  ECDH oracles.
- `piggy card init`: admin auth, CHUID write, GENERATE on 9D and 9A,
  self-signed certs, PIN/PUK change, management-key rotation
  (`crates/piggy/src/card/engine.rs` over `crates/piggy-piv`).
- `sign-bytes`, `health`, `manage`, `ssh-copy-id`, every `pass *`
  handler, `age-plugin-piggy`.
- The virtual card: `crates/fibby` (about 3,800 lines in
  `virtual_card.rs`) models SELECT, GET DATA, PUT DATA, GENERATE,
  VERIFY, CHANGE REFERENCE DATA, GENERAL AUTHENTICATE (ECDH 9D, sign
  9A/9C/9E, admin witness/challenge on 9B), SET MGMT KEY, YK ATTEST,
  YK SERIAL, GET VERSION, multi-card, hot-plug, hardware-proxy.

### piggy-piv already has (relevant to the `piggy tool` port)

`crates/piggy-piv/src/`: `admin.rs` (3-key 3DES mutual auth only),
`pin_mgmt.rs` (`change_pin`, `change_puk`, `set_management_key_3des`),
`put_data.rs` (`put_data`, `put_cert`, `write_chuid`), `keygen.rs`
(`generate_key`), `cert_builder.rs`, `attest.rs`, `policy.rs`. This is
most of what the 2026-04-21 scoping doc listed as "missing"; that doc
predates `card init`.

Still missing in piggy-piv: RESET RETRY COUNTER (INS 2C), Yubico
factory reset (INS FB), Yubico IMPORT ASYMMETRIC (INS FE), Yubico SET
PIN RETRIES (INS FA), GET METADATA (INS F7), AES-128/192/256 management
keys, Ed25519 sign path, Printed Information parse, Key History
rewrite. fibby models none of INS 2C/FB/FE/FA/F7 either.

### C is still on a user path

| Site | What it runs |
|---|---|
| ~~`crypt.rs` / `reencrypt.rs` / `verify.rs` / `grep.rs`~~ | ~~`pivy-box stream decrypt`~~ — **done**: in-process `cmd::pivy_box::Decryptor` (#164/#154) |
| `crates/piggy/src/main.rs:707-709` | `pivy-box` for anything `cmd::pivy_box::run` returns `None` on |
| `crates/piggy/src/main.rs:711-717` | `pivy-tool`, `pivy-ca`, `pivy-luks`, `pivy-zfs`, `pivy-<tool>` |

`pivy-ca`, `pivy-luks`, `pivy-zfs`, `pam_pivy` are never compiled
(`vendor/pivy/Makefile` gates `USE_JSONC`/`USE_LUKS`/`USE_ZFS`/`USE_PAM`
default `no`; `nix/pivy.nix` passes none and installs only
`pivy-tool`, `pivy-agent`, `pivy-box`, `pivy-wire-test`). Those three
subcommands are dead on arrival today (#265).

### C is a test oracle

Conformance bats that invoke a real C binary (not a mock):
`pivy_tool_admin_key.bats`, `pivy_agent_hardware.bats`,
`piggy_agent_pin_on_demand.bats` (C baseline),
`piggy_fibby_pivy_agent_smoke.bats`, `piggy_box_interop.bats`,
`piggy_box_decrypt_interop.bats`, `piggy_ssh_via_fibby.bats`,
`piggy_card_init_fibby.bats` (uses `pivy-tool` to validate the mgmt
key), `age_plugin_piggy_fibby.bats` and several others that set
`PIVY_AGENT`. Plus about twenty `debug-*`/`explore-*` justfile recipes
and the `pivy` output exported from `flake.nix` for the hardware lanes.

The `bats-default` sandboxed lane used `helpers/mock-pivy-box.sh`
(base64) intercepted by PATH. Moving decrypt in-process (#164) broke
that interception; the lane now runs fibby inside the sandbox per test
(`common.bash` → `fibby_up`, #281) with real encrypt and real decrypt.
The mock is gone.

### C sizes, for effort estimation (lines, `vendor/pivy/src`)

| File | Lines | Port? |
|---|---|---|
| `piv.c` | 7,425 | partially, already mostly in `piggy-piv` |
| `pivy-agent.c` | 5,587 | done |
| `piv-ca.c` + `pivy-ca.c` | 7,015 | no (drop) |
| `piv-certs.c` | 3,679 | small subset (CSR + self-signed already done) |
| `pivy-tool.c` | 3,618 | subset |
| `ebox.c` + `ebox-cmd.c` | 5,581 | done except recovery/interactive (drop) |
| `pivy-box.c` | 2,412 | done except residual (drop) |
| `pivy-zfs.c`, `pivy-luks.c`, `pam_pivy.c` | 2,026 | no (drop) |

## Guiding principles

1. **No flag days.** A C path is removed only after the Rust path
   that replaces it is exercised by a lane that runs in
   `merge-this-session`'s pre-merge gate (`just`).
2. **Convert the oracle before deleting it.** While C is around, every
   port ships a differential test against it. Before C is deleted,
   the differential outputs are captured as static golden fixtures
   that replay without the C binary.
3. **Three test layers per port.** Unit tests on wire bytes (vectors,
   proptest); fibby-backed conformance bats; a `hardware`-tagged lane
   run against a throwaway YubiKey before each release.
4. **Product decisions are recorded, not implied.** Everything dropped
   is dropped by an explicit line in this plan and a `Closes` in the
   commit, with the escape hatch named.
5. **Tests move into the sandbox where possible.** fibby is a pure-Rust
   AF_UNIX PC/SC server with no pcscd dependency, so it should be able
   to run inside `nix build .#bats-*` under batman's
   `--allow-local-binding`. If that holds (Phase 1 spike), card-path
   coverage joins the authoritative CI gate instead of living only in
   `just test-bats-conformance-*` recipes.

## Product decisions

Confirmed by the operator on 2026-09-15 (issue numbers in the Issue
map). Where the decision differs from the original recommendation the
recommendation is kept in the rationale column as history.

| Surface | Decision | Rationale / escape hatch |
|---|---|---|
| `piggy luks` | **keep; rewrite in Rust first (Phase 3b.1)** | circus will explore `piggy luks` for LUKS2 unlock from a store secret. The dead C exec arm still goes in Phase 0; the Rust command re-lands the name. The VM LUKS lane is its gate. (Recommendation was drop: FDR 0004 rejects `pivy-luks` for the laptop root, which stays true — this is the non-root, store-keyed use case.) |
| `piggy zfs` | **keep; rewrite in Rust (Phase 3b.2)** | ~300-line command over `piggy-box` key eboxes plus `zfs load-key`; the VM ZFS lane is its gate. (Recommendation was drop.) |
| `piggy ca` | **keep; rewrite in Rust (Phase 3b.3, last)** | The largest of the three (the CA/cert-template stack); scoped after `luks` and `zfs` land and only for the in-house cert workflows. (Recommendation was drop.) |
| `pam_pivy` | **drop** | Never built or exposed. |
| `pivy-wire-test` | **drop** | The Go `piggy-agent-conformance` binary covers the extension wire-shape checks. |
| `piggy box tpl edit`, `tpl create -i`, `tpl list` | **drop** | `piggy-ids` files are the recipient-management surface; templates are derived. |
| `piggy box key generate/lock/unlock/info/relock` | **drop** | No piggy path produces or consumes key eboxes. |
| `piggy box challenge *` and N-of-M recovery configs | **drop; design placeholder filed** | piggy's re-encrypt walk emits primary configs only; recovery is a separate feature to design from scratch, tracked so it is not forgotten, not ported blind. |
| C `pivy-agent -C` confirm | **drop; Rust `--confirm` issue filed** | Not on any piggy workflow; the Rust agent's per-op PIN prompt and `--upstream` model replace the threat model it served. A per-op confirmation prompt in the Rust agent is tracked as its own feature. |
| C `pivy-agent install-service` | **drop** | HM module owns unit installation. |
| `piggy pivy <tool>` | **delete in Phase 5** | Dies with the C stack. |
| `piggy tool` | **port the subset** (table in Phase 3), as a `cmd/tool/` module in the piggy crate | One clap tree; reuses `card_oracle`/`sign_core`. Everything with an in-house workflow: read-only ops, PIN/PUK, keygen/import/certs, factory reset, admin key incl. AES. Drop cert templates (`-T`/`-D`), PKINIT (`-r`), SunSSH, CACS. |

## Phases

### Phase 0: truth in advertising (immediate)

Closes #265. Removes what is already broken.

- Delete the `Ca`, `Luks`, `Zfs` clap variants from `main.rs`, their
  `exec.rs` name-list entries and test, and every doc mention
  (`doc/piggy.1.scd`, `README.md`, `AGENTS.md`, the 2026-04-27 CLI
  scope doc gets a status note, FDR 0004's "rejected" section stays as
  history). The three names come back as Rust commands in Phase 3b;
  until then a user gets clap's unknown-subcommand error instead of
  "pivy-luks: not found".
- Keep `piggy pivy <tool>` for now; it is the documented escape hatch
  until Phase 5.
- Update `exec.rs`'s module doc: "no Rust port planned" becomes "C
  passthrough is transitional; see this plan".

Tests:
- bats: `piggy luks`, `piggy ca`, `piggy zfs` exit 2 with clap's
  unknown-subcommand error (regression guard against re-adding a dead
  arm).
- `exec.rs` unit test list shrinks to `["box", "tool", "agent"]`.

Effort: one merge cycle.

### Phase 1: decrypt in-process (#164, #154)

Re-point `crypt::decrypt`, `reencrypt_one`, `verify`, and `grep` onto
`piggy_box::unlock_ebox` with the existing `AgentEcdhOracle` and
`CardEcdhOracle`, preserving `PIGGY_AUTH_SOCK` override semantics and
`verify -b` (no-PIN/batch means agent-only, no card prompt).

This is the highest-value step: it removes C from every daily
workflow.

Test strategy (this phase sets the pattern for the rest):

1. **Default lane keeps working without a card.** The base64 mock no
   longer intercepts anything, so pick one:
   - (a) a test-only software identity: `PIGGY_TEST_SOFTWARE_IDENTITY`
     names a P-256 private key file; `unlock_ebox` gains a third
     oracle that uses `PivBox::open_offline`. The default lane then
     exercises the real RFC 0002 wire path end-to-end instead of
     base64. The env var is refused outside `cfg(test)`-gated builds
     or when not under bats (mirror the `piggy-test-askpass` safety
     banner).
   - (b) fibby inside the sandbox (see principle 5). Spike first; if
     it works it is strictly better and (a) is unnecessary.
   Recommendation: spike (b) for one cycle; fall back to (a).
   **Resolved 2026-09-15 (#281): (b) works.** fibby is injected into the
   sandboxed lane as `FIBBY_BIN`; `lib/fibby.bash`'s `fibby_up` brings a
   seeded card up per test on a private socket, and
   `t0980-fibby-in-sandbox.bats` proves a real RFC 0002 encrypt followed
   by the in-process agentless decrypt (CardEcdhOracle, PIN via the
   installed test askpass) inside `nix build .#bats-default`. The
   software-identity oracle (a) is not needed. One sandbox trap: the
   askpass must be an installed copy, since `/usr/bin/env` is absent.
2. **Differential corpus, captured now.** New recipe
   `codemod-capture-pivy-oracle-box`: for a matrix of plaintext size and
   recipient count, encrypt with Rust, decrypt with C `pivy-box` and
   with Rust (both against fibby), assert byte equality, and store the
   ebox plus plaintext under `crates/piggy-box/tests/fixtures/`. The
   "agent vs card path" axis is not a fixture axis — the ebox is
   identical regardless of which oracle opens it; the two oracles are a
   capture-time cross-check. These fixtures outlive C: they are replayed
   offline with the RFC 5903 card scalar.
3. **Existing gates stay green:** `piggy_box_decrypt_interop.bats`,
   `piggy_recipients_sync_fibby.bats`, `piggy_pass_init_fibby.bats`,
   `t0700-verify.bats`, `t0110-auth-sock.bats` (the sock-record hook
   in the mock moves to a Rust-side `PIGGY_TEST_SOCK_RECORD`).
4. **Error paths:** fibby gains an SW-injection control (`fibby ctl
   fault <reader> <sw>`) so the Rust side's handling of 6982 (PIN
   required), 63Cx (retries), 6A82 (no such object) is tested without
   hardware. This is reused in Phase 3.

Effort: two merge cycles (one for the spike, one for the port).

**Status 2026-09-15: port landed.** `cmd::pivy_box::Decryptor` is the
one decrypt path (`crypt::decrypt`, `grep`, `verify`, `reencrypt_one`,
`piggy box stream decrypt`); a walk shares one `Decryptor` so the agent
connection and the card PIN are paid once. `verify -b` has no
equivalent: there is no agent-only mode, a no-prompt run is
`SSH_ASKPASS_REQUIRE=never`. The `PIGGY_TEST_SOCK_RECORD` hook moved
into the Rust decryptor. The default lane now runs the harness card
for every test (`common.bash` → `fibby_up`), `mock-pivy-box.sh` is
deleted, and `mock-piggy-ids.sh encrypt` execs the real binary — only
card discovery stays canned. `pass git init`'s textconv is `piggy box
stream decrypt`. Item 4 landed the same day: `fibby ctl fault <INS|*>
<SW>[x<count>] <reader>` (#284) queues a status word for the next
matching APDUs (`t0980` asserts the decrypt's 63C2 and 6983 messages
through it; `fibby_ctl` in `lib/fibby.bash`). Item 2 landed the same
day: `just codemod-capture-pivy-oracle-box` encrypts a size × recipient
matrix (empty, one byte, short text, a full 0x00..0xFF byte range,
128 KiB + 1 for multi-chunk framing; one and two recipients) to fibby's
RFC 5903 slot-9D key, decrypts each ebox with BOTH C `pivy-box` and the
Rust in-process decrypt against the same card, asserts all three agree,
and freezes the ebox + plaintext under
`crates/piggy-box/tests/fixtures/oracle-box/`. `oracle_box_corpus.rs`
replays the frozen corpus **offline** (no card, no C) with the RFC 5903
scalar as a software oracle, so the wire format C accepted stays
decryptable after C is gone. Phase 1 is complete.

### Phase 2: `piggy box` residual (#165)

Per the decisions table, drop everything `cmd::pivy_box::run` returns
`None` for. Delete the `None => exec_pivy("box", …)` arm; unknown box
subcommands become a clap error. Update the man page and
`piggy_box_interop.bats` (its `tpl create/show` interop cases against
C `pivy-box` become fixture replays).

Tests:
- bats: each dropped subcommand is a clean error, not an exec failure.
- `piggy-box` unit: `template.rs`/`ebox.rs` parsers reject recovery
  configs with a clear error rather than silently ignoring them (they
  can still appear in a foreign ebox).

Effort: one merge cycle.

**Status 2026-09-15: landed.** `cmd::pivy_box::run` returns `i32`, not
`Option`; an unrecognized `piggy box` subcommand prints a usage banner
and exits 2 (unit-tested for unknown type, `tpl edit`, unknown stream
op, and the empty/bare-type cases), and the `None => exec_pivy("box",
…)` arm in `main.rs` is gone. The full C surface stays reachable via
`piggy pivy box` while C is shipped. `unlock_ebox` now reports "ebox has
only RECOVERY config(s), which piggy cannot unlock" for a foreign
recovery-only ebox instead of the bare "no configs could be unlocked"
(unit-tested). `piggy_box_interop.bats` is relabelled as what it always
was — Rust ⟂ C template-format interop, not a C passthrough — with its
dead mock-symlink setup removed; it becomes a fixture replay when Phase
5 drops the pivy build. Docs updated: piggy(1), AGENTS.md, the
`cmd/pivy_box.rs` module docstring.

### Phase 3: `piggy tool` port

Reframes the 2026-04-21 scoping doc against what `card init` already
delivered. Layout decided 2026-09-15: a `crates/piggy/src/cmd/tool/`
module in the piggy crate (one clap tree; reuses `card_oracle` and
`sign_core`), not a separate crate.

| Milestone | Ops | New piggy-piv surface | New fibby surface |
|---|---|---|---|
| 3.1 read-only | `list [-p\|-j]`, `pinfo`, `pubkey`, `cert`, `attest`, `version` | Printed Information parse; GET METADATA (F7) for policy without attestation | INS F7 |
| 3.2 PIN/PUK | `change-pin`, `change-puk`, `reset-pin`, `set-pin-retries` | RESET RETRY COUNTER (2C); Yubico SET PIN RETRIES (FA) | INS 2C, FA |
| 3.3 admin | `set-admin` (3DES + AES-128/192/256, `-R` PIN-protected), `init`, `update-keyhist`, `delete-cert` | AES witness/challenge in `admin.rs`; Key History object writer; `put_cert` with empty body | AES mgmt keys on the virtual 9B |
| 3.4 keys | `generate` (policies, algs incl. Ed25519/RSA), `import`, `write-cert`, `req-cert`, `factory-reset` | Yubico IMPORT (FE); Yubico RESET (FB); CSR builder (reuse `cert_builder.rs`) | INS FE, FB |
| 3.5 crypto | `sign` (incl. Ed25519), `ecdh`, `auth` | Ed25519 sign path | Ed25519 on the virtual card (may already exist for 9A; verify) |
| 3.6 cutover | remove `Tool` exec arm; `piggy tool` is Rust | | |

Each milestone is independently mergeable and leaves `piggy tool`
exec-ing C until 3.6. To avoid a long-lived split brain, 3.1 to 3.5
ship as `piggy tool` subcommands that Rust handles when it can and
exec C otherwise, using the same `Some/None` shape as `cmd::pivy_box`.

Tests, per milestone (the rigorous part):

1. **Wire-level unit tests** in `piggy-piv` for every new APDU builder
   and every new response parser, pinned against real YubiKey
   captures. Captures come from the existing
   `debug-fibby-roundtrip-capture` proxy path: run C `pivy-tool` for
   the op through `fibby --hardware-proxy` against a throwaway card,
   keep the trace as a fixture. This is the one place the C binary is
   the oracle for card *behaviour* rather than for piggy's own output.
2. **fibby models each new INS in the same commit** that adds the Rust
   client for it, with a `replay.rs` fixture. The existing
   fibby-vs-hardware `FIB_SW_DIVERGENCES` gate extends to every new
   status word.
3. **Differential bats against C**, fibby-backed, gated by
   `just test-bats-conformance-tool-fibby`: for each op, run the Rust
   command and the C command against freshly seeded fibby cards and
   compare (a) stdout/stderr/exit, normalised for known formatting
   differences, and (b) the resulting card state read back via
   GET DATA on every slot and object. State comparison catches "wrote
   the wrong object" bugs that output comparison misses.
4. **Hardware lane** (`hardware` file tag, `just
   test-bats-conformance-tool-hardware`): the same matrix on a
   throwaway YubiKey. Destructive ops (`factory-reset`, `set-admin`,
   `import`) require `PIGGY_TEST_THROWAWAY_SERIALS` to list the card's
   serial, in the spirit of the askpass safety net; the lane refuses
   any card not on the list. Run before every release tag.
5. **Fault injection** via the Phase 1 `fibby ctl fault` control:
   wrong PIN, wrong PUK, wrong mgmt key, locked PIN, card removed
   mid-op. Each has a Rust error-path test and a bats assertion on
   the user-facing message.
6. **Property tests** for the TLV codec, the Key History object, and
   the Printed Information parser (`proptest`, following the existing
   `proptest_wire` modules in `piggy-box`).

Effort: 3.1 and 3.2 one cycle each; 3.3 and 3.4 two cycles each; 3.5
one; 3.6 one. About eight merge cycles.

**Status 2026-09-15: milestone 3.1a landed** (`pubkey`, `cert`). The
port lives in `crates/piggy/src/cmd/tool/` with the `cmd::pivy_box`
Some/None shape: `piggy tool` handles the ops it has ported and execs C
`pivy-tool` for the rest (and for any invocation carrying an option it
does not model, so the superset stays honest). `pubkey <slot>` and
`cert <slot>` read the slot offline (no PIN) via the existing
`PivToken::read_slot`; `pubkey` reproduces C's exact comment
(`<type> <base64> PIV_slot_<SLOT>@<GUID> "<subject>"`, pivy-tool.c:1762)
and `cert` re-encodes the DER as PEM. The differential lane
`test-bats-conformance-tool-fibby` (in the merge gate) runs BOTH `piggy
tool` and C `pivy-tool` against one fibby card (slots 9A + 9D seeded)
and asserts equality — the external contract.

`attest <slot>` landed next: it prints the slot attestation cert then
the device attestation cert (two PEMs, matching C's two
`PEM_write_X509`). Attestation is unavailable for an imported key
(INS_ATTEST → 6A80), so on fibby — and on a real YubiKey's imported keys
— it fails exactly as C does; the differential lane asserts both fail
and emit no cert, and the two-PEM happy path is deferred to the hardware
lane (a generated, attestable key).

**Scope decision 2026-09-15 (operator: option 3).** `list` and `pinfo`
are NOT "read ops" like `pubkey`/`cert`: matching C `pivy-tool list`
faithfully (any of its human/`-p`/`-j` forms) requires reproducing a
large card-introspection surface piggy-piv does not parse today — CHUID
internals (signed-status, cardholder UUID, FASC-N, expiry), the CCC /
cardcap object, YubiKey applet version/label/URI, the Discovery Object's
auth methods, the algorithm list, VCI — plus teaching fibby to model all
of it so the differential lane can run. A partial `list` would diverge
and the differential test would (correctly) reject it. So `list` and
`pinfo` are DEFERRED and scoped on their own later; the port proceeds to
the cleanly-differentiable ops instead. `version` is likewise deferred
(it would print piggy's version, not pivy's — not a differential
contract).

**Milestone 3.5 landed (`sign`, `ecdh`), taken before 3.2.** These are
the cleanest differential targets — non-destructive, no new fibby INS,
crisp byte outputs — so they went first. `sign <slot>` hashes stdin
(SHA-256 for P-256, SHA-384 for P-384) and ECDSA-signs the digest,
writing the card's raw DER signature (matches C `piv_sign` + `fwrite`);
`ecdh <slot>` reads an OpenSSH pubkey from stdin and writes the raw
shared secret (matches C `piv_ecdh` + `fwrite`). Both reuse
`PinSession::{verify_pin,sign_prehash,ecdh_derive}`; the PIN comes from
`-P` or the same `SSH_ASKPASS` prompt C uses. Because fibby signs with
RFC 6979 deterministic ECDSA and ECDH is deterministic, the differential
lane compares the raw bytes and they match C exactly (via `-P`; a
separate case proves piggy's askpass path yields the same signature).
One contract difference surfaced and is documented: C `pivy-tool
sign`/`ecdh` will not use `SSH_ASKPASS` for the PIN when stdin is the
data pipe, so `-P` is the portable driver; piggy's askpass path works
regardless.

**Milestone 3.2a landed (`change-pin`, `change-puk`).** Both rotate a
credential via CHANGE REFERENCE DATA (INS 0x24), reusing
`PinSession::{change_pin,change_puk}` (already exercised by `card init`
and fibby's INS 0x24 — no new card surface). The current and new values
come from two repeated `-P` options exactly as C consumes them (its
prompt path is tty-only; piggy also offers an `SSH_ASKPASS` fallback).
`set-pin-retries` from the plan's 3.2 row is DROPPED: it is not a
`pivy-tool` op, so there is no C contract to differentially test — it
would be a piggy-native addition, out of scope for a C-parity port. The
new differential lane `test-bats-conformance-tool-pin-fibby` (in the
gate) brings up a FRESH fibby per test (state-modifying ops need pristine
state) and checks both the observable contract (both impls change the
credential silently, exit 0; a wrong old secret fails on both) and card
state (after piggy's change the new PIN verifies via a `sign`, the old is
rejected).

**Milestone 3.2b landed (`reset-pin`), completing 3.2.** PUK-driven PIN
reset via RESET RETRY COUNTER (INS 0x2C) — new surface in both layers:
fibby's `handle_reset_retry_counter` (verify PUK, on success install the
new PIN and reset BOTH the PIN and PUK counters to their card defaults; a
wrong PUK decrements the PUK counter and returns `63 Cx`; a blocked PUK
returns `6983`), and `PinSession::reset_pin(puk, new_pin)` in
`piggy-piv`'s `pin_mgmt.rs` (mirrors `change_reference_data`, mapping a
wrong PUK to `PivError::PinIncorrect`). The `piggy tool reset-pin` command
takes the PUK then the new PIN from two repeated `-P` options exactly as C
consumes them (askpass fallback when either is absent). The differential
lane gains three tests in `piggy_tool_pin_fibby.bats`: a plain
C-then-piggy reset with the new PIN proven via `sign`; a wrong-PUK failure
that leaves the original PIN intact on both impls; and the end-to-end
unblock (exhaust the PIN retry counter with wrong signs → the correct PIN
is blocked → `reset-pin` with the PUK unblocks it → the new PIN verifies).
Still deferred from 3.1's row: `list`/`pinfo`/`version`, scoped on their
own (the large card-introspection surface that would fail the byte-exact
differential contract).

**Milestone 3.3a landed (`set-admin`, 3DES).** Rotates the PIV management
key via mgmt-key mutual authentication with the current key (GENERAL
AUTHENTICATE, INS 0x87 P1=0x03 P2=0x9B) then YubicoPIV SET MANAGEMENT KEY
(INS 0xFF) — reusing `PinSession::{authenticate_admin, set_management_key_3des}`
and fibby's existing mgmt-key + SET MGMT KEY handlers (no new card/piv
surface; these are the same primitives `card init` exercises). The `piggy
tool set-admin <newkey>` command reads the current key from `-K` (`default`
or hex; default: the factory 3DES key) and the new key from the positional
(`default` or hex). **3DES-only:** AES admin keys, `random`, `@file`, and
`-R` PINFO-save fall through to C, rejected in `parse` so the superset stays
honest. The new differential lane `test-bats-conformance-tool-admin-fibby`
(fresh fibby per test) checks the rotate chain (C FACTORY→KEY_A, piggy
KEY_A→KEY_B→default — each link only authenticates if the prior rotation
took), wrong-current-key failure on both impls, and the no-`-K` default.
The lane immediately caught a test-key subtlety worth recording: DES ignores
the low (parity) bit of every key byte, so a "different" key that differs
only there is the *same* effective key — the wrong-key test keys had to
differ in real key bits. Scope decision for the rest of 3.3, mirroring the
3.1 deferral: `init` randomizes the CHUID GUID and CardCap id per run, so it
cannot be byte-differentiated against C and is deferred alongside
`list`/`pinfo`. Remaining tractable admin ops: **3.3b** `delete-cert` (PUT
DATA empty body under mgmt auth — one new `piggy-piv` clear-cert primitive;
fibby's PUT DATA already covers it) and, if it proves cleanly differentiable,
`update-keyhist`.

**Milestone 3.3b landed (`delete-cert`).** Clears a slot's certificate
object: mgmt-key mutual auth with the current key, then PUT DATA at the
slot's cert tag with an empty body (`5C <tag> 53 00`) — matching C's
`piv_write_cert(slot, NULL, 0)`. One new `piggy-piv` primitive,
`PinSession::clear_cert(slot)`, atop the existing `put_data` /
`cert_tag_for_slot`; fibby's PUT DATA already stores the empty object
verbatim, so a subsequent read finds no `70` element and reports the slot
as certless. Ported for the cert-holding slots 9A/9C/9D/9E (retired and
other slots fall through to C). `piggy tool delete-cert <slot>` reads the
current key from `-K` (`default` or hex). The differential lane (folded
into `piggy_tool_admin_fibby.bats`) adds three tests: piggy deletes the 9D
cert and BOTH impls then read it as gone; the mirror (C deletes, piggy sees
it gone); and a wrong-admin-key delete that fails and leaves the cert
intact. This completes the tractable admin ops; `init` stays deferred, and
`update-keyhist` (deterministic Key History writer) is the remaining
candidate before the 3.4 key surface.

**Milestone 3.3b+ landed (`update-keyhist`).** Rescans the retired key slots
and rewrites the PIV Key History object (tag `5FC10C`, body
`C1 01 <oncard> C2 01 <offcard> [F3 <url>]`) — matching C's
`cmd_update_keyhist` / `piv_write_keyhistory`. New `piggy-piv` surface: a
`keyhist` module (encode/parse the object + `PinSession::write_keyhistory`)
plus `PivToken::{read_keyhistory, count_oncard_retired}` (the latter reusing
the existing retired-slot `read_slot` support). `piggy tool update-keyhist`
recomputes `oncard` from the retired slots and preserves `offcard`/URL from
the existing object, under mgmt-key auth (`-K`). The object encoding is
pinned byte-exact in a `keyhist` unit test. **Observability note:** the Key
History object has no ported read-back path, so the e2e differential
compares the *write* — the PUT DATA data field C and piggy each emit in
fibby's wire trace — which is byte-identical. This surfaced a benign framing
difference worth recording: **C frames PUT DATA with extended-length
(`00 DB 3F FF 00 00 <Lc>`), piggy with short-length (`00 DB 3F FF <Lc>`)**;
both are valid ISO 7816-4 and the card stores the identical object, so the
differential is on the data field, not the APDU framing. A fuller read-back
differential (retired-cert seeding + a raw data-object read) is deferred to
**piggy#290**.

**Milestone 3.4 scope (key surface).** The 3.4 ops split by differentiability
and required new surface:

- **Tier 1 — clean differential, primitives already exist:** `write-cert`
  (reuses `put_cert` + fibby PUT DATA) and `generate` (P-256; random key, but
  fibby's `--generate-slot-{9a,9c,9d}-priv` pins the scalar, so both impls emit
  the same pubkey — `generate_key`/`build_self_signed_cert`/`put_cert`/
  `sign_prehash` all exist).
- **Tier 2 — differentiable but needs NEW INS wire on both `piggy-piv` AND
  fibby:** `import` (YubicoPIV IMPORT, INS 0xFE) and `factory-reset`
  (YubicoPIV RESET, INS 0xFB).
- **Tier 3 — deferred:** `req-cert` (PKCS#10 CSR builder; randomized ECDSA
  signing) and the RSA/Ed25519 algorithms (fibby is P-256-only — import and
  generate are scoped to EC P-256).

**Milestone 3.4a landed (`write-cert`).** Reads an X.509 cert (DER or PEM)
from stdin and writes it to a slot's cert object: mgmt-key mutual auth, then
PUT DATA wrapping the DER as `70 <cert> 71 00` — matching C's
`cmd_write_cert` / `piv_write_cert`. Reuses `PinSession::put_cert` (delete-cert's
write twin) and fibby's existing PUT DATA — no new card/piv surface. `piggy
tool write-cert <slot>` reads the current key from `-K`, ported for the
cert-holding slots 9A/9C/9D/9E. The new differential lane
`test-bats-conformance-tool-keys-fibby` (fresh fibby per test) does a
round-trip: capture the seeded 9D cert, delete it, write it back via one
impl, and confirm BOTH impls read back exactly that cert — plus the mirror
(C writes, piggy reads) and a wrong-admin-key failure that leaves the slot
intact. Remaining in 3.4: `generate` (3.4b, Tier 1), then the Tier-2 decision
(`import`, `factory-reset`).

**Milestone 3.4b landed (`generate`, EC).** Generates a new key pair
(GENERATE ASYMMETRIC under mgmt auth), self-signs a minimal cert for it
(PIN-gated — C's `selfsign_slot` signs the cert with the fresh slot key),
writes it, and prints the new public key — matching C's `cmd_generate`.
Reuses `generate_key` + `build_self_signed_cert` + `sign_prehash` + `put_cert`
(all from `card init`); no new piv/fibby surface. `piggy tool generate <slot>
-a <alg>` models the EC algorithms `eccp256`/`eccp384` on slots 9A/9C/9D/9E;
RSA/Ed25519 and other slots fall through to C. It needs `-K` (mgmt) and a PIN
(`-P`/askpass, for the self-sign). The printed line is
`<openssh-pubkey> PIV_slot_XX@<GUID>` (a bare slot/GUID comment, no cert
subject). **Differential:** a random key is not byte-comparable, but fibby's
`--generate-slot-9a-priv <scalar>` pins the generated key (config, not
consumed — it persists across GENERATEs), so both C and piggy emit the same
pubkey; the lane compares the printed line (the self-signed cert's random
serial is a side effect that legitimately differs and is not compared). This
completes Tier 1 of 3.4; the remaining ops are the Tier-2 decision (`import`,
`factory-reset` — both need new INS 0xFE/0xFB wire on `piggy-piv` and fibby)
and the Tier-3 deferrals (`req-cert`, RSA/Ed25519).

**Milestone 3.4c landed (`import`, EC), operator split from `factory-reset`.**
Reads an OpenSSH private key from stdin, imports it (YubicoPIV IMPORT
ASYMMETRIC, INS 0xFE), self-signs a minimal cert (PIN-gated), and writes it —
matching C's `cmd_import`. **New wire on both sides:** `PinSession::import_ec_key`
(INS 0xFE, `06 <len> <scalar>`) in `piggy-piv`, and fibby's
`handle_import_asymmetric` (P-256 only, normalizing the BER bignum scalar and
installing it into the slot — the imported-key counterpart of GENERATE).
`piggy tool import <slot>` parses the OpenSSH key via `ssh-key`, extracts the
EC scalar + public point, and reuses `build_self_signed_cert`/`put_cert`. **EC
P-256/P-384 only** (piggy is EC-only): an RSA/Ed25519 key errors with a
message pointing to `piggy pivy tool import` (piggy cannot peek stdin at parse
time, so this is a loud runtime error rather than a silent C fallthrough).
Differential: on a fresh fibby, C and piggy each import the same throwaway
P-256 key into 9A and both read back exactly the imported public key (compared
as the key blob — the self-signed cert subject legitimately differs per impl).
Slot note: 9A is the differentiable slot because C's 9C/9E cert templates
require an `email` cert var the import path leaves unset. **`factory-reset` is
split into its own pass** (operator call) and tracked in **piggy#291** (needs
INS 0xFB on both sides plus a non-interactive confirmation gate to replace
pivy-tool's tty `YES`). Tier-3 (`req-cert`, RSA/Ed25519) stays deferred.

**Milestone 3.6 landed (cutover).** `piggy tool` is now Rust, not a
superset-by-fallback — mirroring the Phase 2 `box` cutover (#165). The
`None => exec_pivy("tool", …)` arm in `main.rs` is gone; `cmd::tool::run`
returns `i32`, and an unported op (`list`, `version`, `init`,
`req-cert`, `factory-reset`) or an unmodeled option (whatever `parse`
rejects — an RSA/Ed25519 `-a`, a pivy debug flag) prints a usage banner and
exits 2, pointing at the `piggy pivy tool` escape hatch rather than silently
hopping to C. The full C `pivy-tool` surface stays reachable via `piggy pivy
tool` while C is shipped (Phase 4 demotes it to a test-only input, Phase 5
deletes it). The fibby lane's old `unported_op_falls_through_to_c` test is
rewritten to assert the usage error (exit 2, names `piggy pivy tool`, no card
output) and that `piggy pivy tool list` still reaches C. AGENTS.md's
exec-to-C bullet is updated: only `piggy pivy <tool>` execs C now.
**Phase 3 is complete** except the deliberately-deferred `list` (its own
later pass) and factory-reset (piggy#291); the differentiable `pivy-tool`
surface is ported and C is reachable only through the explicit passthrough.

**Milestone 3.7 landed (pinfo).** `piggy tool pinfo` reads the PIV Printed
Information object (tag `5FC109`) and prints it byte-for-byte like C's
`cmd_pinfo` (`%12s: %s` per field — `name`/`affiliation`/`expiry`/`serial`/
`issuer`, an optional two-line `organization`, and a `yubico: contains admin
key` line when the YubicoPIV `88 { 89 … }` escrow is present; absent fields
render `(null)` as glibc `%s` does). New `piggy-piv` surface: `pinfo.rs`
(`Pinfo` struct + `parse_pinfo`, tolerant TLV walk) and `PivToken::read_pinfo`
in `token.rs` (the private `transmit` lives there). fibby grows `--seed-pinfo`,
which installs a canonical PINFO (deterministic non-secret test fields) so the
tool-fibby lane's new `pinfo_matches_c` test is a byte-exact differential
against C. The seeded object is modelled **PIN-free**; a real card gates the
Printed Information read behind the PIN, tracked as piggy#292. This leaves
`list` as the only deferred read op.

**Milestone 3.8 landed (`list -j`).** `piggy tool -j list` emits the JSON card
listing byte-for-byte like C's `cmd_list` `-j` branch — `short_id`/`guid`/
`reader`, the full CHUID (`signed`, `fasc-n`, `expiry`, `expired`; `cardholder`
when present), `ykpiv`/`serial`/`ykpiv_version`, the `auth`/`vci_supported`/
`algorithms` capability block, and every seeded slot's `name`/`algorithm`/
`key_type`/`key_size`/`subject`/`issuer`/`cert_serial`/`pubkey`. New `piggy-piv`
surface: `fascn.rs` (a faithful port of the ISO-7811 5-bit-BCD FASC-N reader —
parity, SS/FS/ES sentinels, LRC — plus the org/assoc maps, unit-tested against
the real card's FASC-N bytes), `chuid.rs` (the CHUID fields the GUID-only
`read_chuid` dropped), `PivToken::{chuid,read_ykpiv_version,read_ykpiv_piv_serial}`,
and per-slot `slot_name`/`algorithm_label`/`key_type`/`key_bits`/
`cert_display_fields`. The two byte-exact fields reuse the `openssl` crate that
already backs piggy-piv: `cert_serial` is `BigNum::to_hex_str` (= C's
`BN_bn2hex`) and `subject`/`issuer` reproduce `X509_NAME_oneline` (exact for the
printable-DN case). A `list_json_matches_c` differential in the tool-fibby lane
compares C and piggy against the same fibby (no new seeding needed — the
existing seeds already produce the whole object).

Scope: **only the JSON mode is ported.** Bare `list` (human) and `list -p`
(parseable) stay usage errors → `piggy pivy tool list`. The `auth`/`vci`/
`algorithms` fields use the no-Discovery-object defaults, which are what a
YubiKey reports (its SELECT FCI is AID-only and it publishes no Discovery
object); a non-YubiKey PIV card that publishes a Discovery object or advertises
an algorithm list — and the CHUID `cardholder` hex case — are a documented
follow-up. This completes the differentiable `pivy-tool` read surface; only
factory-reset (piggy#291) and the human/parseable `list` modes remain on C.

**Milestone 3.9 landed (`factory-reset`, closes piggy#291).** `piggy tool
factory-reset` wipes the PIV applet via YubicoPIV RESET (INS 0xFB). New
`piggy-piv` `PivToken::factory_reset` (the applet permits it only once both PIN
and PUK are blocked, else SW 6985, surfaced with a clear message). fibby grows
an INS-0xFB RESET handler (refuses with `6985` unless both counters are at 0,
else wipes every slot key + data object and restores the factory
PIN/PUK/mgmt-key + counters) and a `--seed-pin-puk-blocked` flag. `piggy tool`
gains a **piggy-native confirmation gate** — a typed `YES` on `/dev/tty` (like
C's `RPP_REQUIRE_TTY` prompt) or `--yes`/`--force` to skip it non-interactively;
there is no stdin fallback, so a stray piped `YES` can't trigger a wipe. Because
C's factory-reset is tty-only and can't run headless, the bats lane is a **state
differential** (piggy resets, then both C and piggy read the card blank) plus
precondition (`6985` when not blocked) and gate checks, with `expect` (added to
the devShell) driving the interactive tty prompt. This leaves only `req-cert`,
RSA/Ed25519, and the human/parseable `list` modes on C.

**Milestone 3.10 landed (`req-cert`, EC-only).** `piggy tool req-cert <slot>`
prints a minimal PKCS#10 CSR for the slot's EC key, signed by that key on the
card (PIN-gated). New `piggy-piv` `cert_builder::build_csr` (the PKCS#10 sibling
of `build_self_signed_cert`, via the `x509-cert` `request` types) and
`cert::ec_sec1_point` / `PivSlot::ec_sec1_point`. Subject CN from `-n`, else
`<slot-name>@<short-guid>`. Following `cert_builder`'s established minimalism,
the CSR carries only subject + SPKI + signature — **no template extensions** —
so it is a *valid, equivalent* CSR rather than a byte-for-byte clone of C's
cert-template output (C's `req-cert` populates KeyUsage/EKU from the pivy-ca
template engine, which stays deferred to Phase 3b.3). The differential is
therefore **structural + semantic** (openssl verifies the CSR self-signature,
and its embedded SPKI equals C's for the same slot key), not byte-exact — the
right bar for a *generated* credential, matching how piggy's own self-signed
slot certs already differ from pivy's. Added to the shared tool-fibby lane
(req-cert mutates no card state); fibby needed no changes.

**Operator decision (2026-09-22): RSA and Ed25519 are dropped, not ported.**
piggy is EC-only by design (RFC 0002 is P-256 ECDH), and RSA/Ed25519 key
generation/signing would be a large expansion of both `piggy-piv` and the
P-256-only fibby. So Phase 4 removes them with the runtime C rather than porting
them; the differential-test oracle (`.#pivy`) survives as a test-only input, so
they could still be ported later if ever needed. With `req-cert` ported, **no
piggy-relevant op depends on the runtime `piggy pivy tool` escape hatch**, which
clears the way for Phase 4.

### Phase 3b: Rust `luks`, `zfs`, `ca` (operator decision 2026-09-15)

Independent of Phase 3 (they need no new `piggy-piv` surface: the key
material is a store secret or a `piggy-box` key ebox, decrypted through
the existing agent/in-process path), so 3b.1 can start as soon as
Phase 0 has removed the dead arms. Order is `luks` first because circus
wants to explore it; `zfs` second because it is the same shape; `ca`
last and only after the first two have real users.

| Milestone | Command | Shape | Gate |
|---|---|---|---|
| 3b.1 `piggy luks` | `luks format\|open\|add-key\|close <dev> [--secret <pass-name>]` | thin driver over `cryptsetup` fed by `crypt::decrypt` on stdin (exactly what `nix/vm-tests/luks.nix` scripts by hand today); primary configs only, no N-of-M | the LUKS VM lane rewritten to call `piggy luks` instead of piping `pass show` into cryptsetup; asserts one card ECDH per open |
| 3b.2 `piggy zfs` | `zfs load-key\|create <dataset> [--secret <pass-name>]` | same driver shape over `zfs load-key -L prompt` | the ZFS VM lane, same rewrite |
| 3b.3 `piggy ca` | scoped separately once 3b.1/3b.2 are in use | the CA/cert-template stack is the bulk of C `pivy-ca`; the Rust port is limited to the in-house cert workflows and reuses `cert_builder.rs` | a fibby-backed bats lane plus a `card init`-style VM lane |

The C `pivy-luks`/`pivy-zfs` key-ebox format is **not** the target:
these are new piggy commands keyed by store secrets (FDR 0004's
"token slot + passphrase" shape), and the LUKS/ZFS VM lanes already
prove that shape end to end. Effort: 3b.1 and 3b.2 one to two cycles
each; 3b.3 to be estimated when scoped.

### Phase 4: demote C pivy to a test-only nix input

**Landed 2026-09-22.** C pivy is out of the shipped `piggy` runtime
closure — it survives only as the test-only `.#pivy` output the
differential bats lanes build. What changed:

- Dropped `pivyPkg` from `runtimeDeps` in `flake.nix`; the wrapped
  `piggy` no longer has any `pivy-*` on PATH.
- Dropped `PIGGY_PIVY_VERSION`/`_REV` from the wrapper and removed the
  `pivy` row from `piggy version` (`version.rs`); only `pcsclite`
  remains as a runtime component (operator decision 2026-09-22).
- `exec_pivy` (the sole `piggy pivy <tool>` path) now reports the
  binaries-not-bundled case plainly instead of a bare `ENOENT`, and
  points at installing pivy separately.
- `.#pivy` stays a flake output consumed only by the oracle bats lanes
  and debug recipes.

Gate: `checks.lint-closure-no-pivy` (a `closureInfo`-based check —
cleaner than the originally-sketched `nix why-depends`, and buildable in
a pure derivation) greps the `piggy` closure's store-paths for the
`pivyPkg` path and fails the build if it reappears; wired into `lint`
via the `lint-closure-no-pivy` recipe.

**Revised phase boundary.** The C *code* deletions this section originally
listed — the `Pivy` clap arm / `piggy_pivy.bats` / `exec_pivy`, and the
HM module's `pname == "pivy"` C-agent branch — are **moved to Phase 5**,
alongside deleting the C *build*. Rationale: Phase 4 is "stop shipping C
and enforce it"; deleting the now-graceful-degrading passthrough and the
HM opt-in is part of "delete all C code" (Phase 5). This also keeps the
"install pivy separately + use the `piggy pivy` escape hatch" path working
through the soak.

Soak: as with FDR 0001, the operator runs the pivy-free `piggy` on
every host for about a week, watching `piggy health` and the
`piggy.pass.*` / `piggy.agent.*` statsd counters, before Phase 5.

Effort: one cycle plus the soak.

### Phase 5: delete the C stack

- Freeze remaining oracle usage into fixtures: run every
  `pivy_*`/`*_interop` conformance bats one last time with a capture
  flag that stores C's outputs, then rewrite those tests as replays
  against the stored outputs. `pivy_agent_hardware.bats` and
  `pivy_tool_admin_key.bats` are deleted outright (they test C).
- Delete the C-code seams Phase 4 left degrading-but-present: the
  `Pivy` clap arm (`piggy pivy <tool>`), `exec_pivy` + its
  `piggy_pivy.bats`, and the HM module's `pname == "pivy"` C-agent
  branch (`nix/hm/piggy-agent.nix`) with its `eval-test.nix` cases.
- Delete `vendor/pivy/`, `nix/pivy.nix`, `vendor/pivy/openssh.patch`,
  the libressl/openssh source pins, the `.#pivy` output, the
  `lint-closure-no-pivy` check (moot once the C build is gone), the ~20
  `debug-*`/`explore-*` recipes that drive C binaries, and
  `pivy_*.bats.skip`.
- Close #3, #28/#42/#43 (patch-upstreaming is moot), #105 to #111
  (C agent askpass restructure), #116, #29, #81, and any other
  `vendor/pivy`-scoped issue.
- Docs: README install callout, AGENTS.md architecture section,
  `docs/virtual-piv.md` references, `piggy(1)`.

Effort: one to two cycles.

## Cross-cutting test infrastructure to build first

These are worth landing before or alongside Phase 1 because every
later phase uses them.

| Item | Why | Phase it unblocks |
|---|---|---|
| fibby-in-sandbox spike | moves card coverage into the merge gate | 1 |
| `fibby ctl fault <reader> <sw>` | deterministic error-path tests | 1, 3 |
| `codemod-capture-pivy-oracle-*` recipes + fixture layout | turns the live C oracle into static fixtures | 1, 2, 3, 5 |
| `PIGGY_TEST_THROWAWAY_SERIALS` guard in `lib/fibby.bash` and the hardware recipes | makes destructive hardware lanes safe to run | 3.3+ |
| `lint-closure-no-pivy` | proves the shipped closure is C-free | 4 |
| NixOS VM lanes (`nix/vm-tests/`, `just test-vm-{luks,zfs,agent}`, in the merge gate) — **landed 2026-09-14** | the only place LUKS/ZFS unlock, the multiplexed agent against sshd, and the shipped closure-as-a-system can be exercised; harness for any future `piggy luks`/`zfs` port | 3+, and the Phase 4 soak |
| VM-lane line coverage (`just test-vm-coverage`, `.#coverage-report`) — **landed 2026-09-14**, 13.4 min serialized, outside the gate | names the migration gaps by file: `unlock.rs`/`cmd/pivy_box.rs` at 0% until #164, the card-admin half of `piggy-piv` at 0% until a `card init` VM lane exists | 1, 3 |
| Adopt igloo's `pkgs.mkVmChecks` + `pkgs.vmTestPrelude` (igloo f235a1f, FDR 0011) in place of piggy's `mkCommon` and the bootstrap helpers — **landed 2026-09-14** with the igloo re-float (#253 closed: the sandboxed fibby lanes expose their socket dir to fence) | one ecosystem-wide VM-lane shape; piggy is FDR 0011's second adopter | done |
| state-readback comparator helper (`helpers/card-state-dump.sh`: GET DATA every object, hex, sorted) | differential tests compare card state, not just stdout | 3 |

## Risks and unknowns

- **fibby may not run under the batman sandbox.** If AF_UNIX listen is
  blocked even with `--allow-local-binding`, the default lane uses the
  software-identity oracle (Phase 1 option a) and card coverage stays
  in the `just test-bats-conformance-*` recipes, which are not in the
  pre-merge gate today. The plan still works but the "CI gate covers
  card paths" property is lost. Decide after the spike.
- **AES management keys have no fibby model and no captures.** Newer
  YubiKeys (5.7+ firmware, per `piggy-piv/src/admin.rs`) default to
  AES. Phase 3.3 needs at least
  one hardware capture per AES size before the Rust side is trusted.
- **Ed25519 and RSA on-card paths** are lightly modelled in fibby.
  Milestone 3.5 may need fibby work of its own; if it balloons, ship
  3.6 with `sign -a ed25519` and RSA generate behind an explicit
  "unsupported" error and file follow-ups rather than block the
  cutover.
- **Recovery-config eboxes from foreign tools.** After Phase 2 piggy
  refuses N-of-M eboxes with a clear error. Confirm no operator store
  contains one (`piggy pass verify` walk with a diagnostic) before
  merging Phase 2.
- **The openssh.patch cipher shim** (`chacha20-poly1305@piggy.amarbel.net`)
  is what lets C `pivy-box` decrypt piggy's RFC 7539 eboxes today.
  Phase 1's differential corpus depends on it still working; capture
  the corpus early, before any unrelated vendor/pivy churn.
- **Operator workflows that shell to `pivy-tool` directly** (not via
  piggy) lose the binary at Phase 5. eng's home-manager profile should
  be checked for direct `pivy-*` references before Phase 4 lands; that
  is an eng-repo question and belongs to an eng session.

## Open questions for the operator

All answered 2026-09-15: (1) confirmed, with luks/zfs/ca kept as Rust
rewrites; (2) yes, `piggy zfs` is re-created, Phase 3b.2; (3) one
throwaway YubiKey 4 on the card host, identified by serial through ykman
(the PIV applet reports none on its firmware) and allowlisted in that
host's environment via `PIGGY_TEST_THROWAWAY_SERIALS` (#286 landed and
validated with a real factory reset); (4) module. Hardware lanes run
from a session on the card host, directed from wherever the plan's
software work runs; the merge gate stays card-free.

## Issue map

Existing: #265 (Phase 0), #164 and #154 (Phase 1), #165 (Phase 2), #3
umbrella, #26 triage, #116 (`pivy_tool_admin_key` sandboxing becomes
moot at Phase 5), #105 to #111 (C agent, moot at Phase 5), #28/#42/#43
(moot at Phase 5), #30 (`tpl create` hardware-free mode, subsumed by
the Phase 2 drop).

Filed 2026-09-15. Epic: #289 (links every item below; child of #3).

- Phase 3 milestones: #272 (3.1), #273 (3.2), #276 (3.3), #274 (3.4),
  #275 (3.5), #278 (3.6).
- Phase 3b rewrites: #277 (`luks`), #279 (`zfs`), #280 (`ca`).
- Placeholders from the product decisions: #282 (recovery/N-of-M
  design), #283 (Rust agent `--confirm`).
- Infrastructure: #281 (fibby-in-sandbox spike), #284 (`fibby ctl
  fault`), #285 (oracle capture recipes + fixtures), #286
  (`PIGGY_TEST_THROWAWAY_SERIALS` guard), #287 (`lint-closure-no-pivy`),
  #288 (card-state-dump helper).
