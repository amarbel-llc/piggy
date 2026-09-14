---
status: draft
date: 2026-09-14
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
| store decrypt (`show`/`edit`/`generate -i`/`grep`/`verify`/re-encrypt walk) | spawns C `pivy-box stream decrypt` | port in-process (#164) |
| `piggy box` residual (`tpl edit`, `key *`, `challenge *`, interactive modes) | falls back to C `pivy-box` | drop (#165) |
| `piggy tool` | exec C `pivy-tool` | port the subset piggy needs |
| `piggy ca` / `luks` / `zfs` | exec binaries nix never builds (#265) | delete now |
| `piggy pivy <tool>` escape hatch | exec any `pivy-*` | delete last |
| C `pivy-agent` (`-C` confirm, `install-service`) | reachable via `piggy pivy agent` and the HM module's `package = pkgs.pivy` branch | drop |
| C pivy as a **test oracle** (~14 conformance bats + ~20 justfile recipes) | live differential baseline | freeze into golden fixtures, then delete |

The order is chosen so that every phase removes C from a user path
only after a Rust path for it is gated in CI, and so that the
differential-testing discipline C gives us today is converted into
static fixtures before the C binaries disappear.

Five phases. Phases 0 to 2 are small and can start immediately.
Phase 3 (`piggy tool`) is the only large port. Phases 4 and 5 are
packaging: first demote C pivy to a test-only nix input, then delete
it.

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
| `crates/piggy/src/crypt.rs:92` | `pivy-box stream decrypt` |
| `crates/piggy/src/reencrypt.rs:388` | `pivy-box stream decrypt` |
| `crates/piggy/src/verify.rs:78` | `pivy-box stream decrypt -b` |
| `crates/piggy/src/grep.rs:71` | `pivy-box stream decrypt` |
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

The `bats-default` sandboxed lane uses `helpers/mock-pivy-box.sh`
(base64) intercepted by PATH. Moving decrypt in-process (#164) breaks
that interception; the lane needs a new strategy (Phase 1).

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

Recommendations; each needs an operator yes/no before its phase starts.

| Surface | Recommendation | Rationale / escape hatch |
|---|---|---|
| `piggy ca` | **drop** | Never built; needs json-c and the 7k-line CA/cert-template stack; no piggy doc, test, or recipe exercises it. Anyone needing a PIV CA can build upstream pivy. |
| `piggy luks` | **drop** | FDR 0003 already rejects `pivy-luks` for the twerk LUKS2 use case in favour of systemd-cryptenroll FIDO2. |
| `piggy zfs` | **drop** | Never built; needs libzfs. If ZFS native-encryption unlock is wanted later it is a ~300-line Rust command over `piggy-box` key eboxes plus `zfs load-key`, not a port. |
| `pam_pivy` | **drop** | Never built or exposed. |
| `pivy-wire-test` | **drop** | The Go `piggy-agent-conformance` binary covers the extension wire-shape checks. |
| `piggy box tpl edit`, `tpl create -i`, `tpl list` | **drop** | `piggy-ids` files are the recipient-management surface; templates are derived. |
| `piggy box key generate/lock/unlock/info/relock` | **drop** | No piggy path produces or consumes key eboxes. |
| `piggy box challenge *` and N-of-M recovery configs | **drop (for now)** | piggy's re-encrypt walk emits primary configs only; recovery is a separate feature to design if wanted (file an issue, do not port blind). |
| C `pivy-agent -C` confirm | **drop** | Not on any piggy workflow; Rust agent's per-op PIN prompt and `--upstream` model replace the threat model it served. File a Rust `--confirm` issue if wanted later. |
| C `pivy-agent install-service` | **drop** | HM module owns unit installation. |
| `piggy pivy <tool>` | **delete in Phase 5** | Dies with the C stack. |
| `piggy tool` | **port the subset** (table in Phase 3) | Everything with an in-house workflow: read-only ops, PIN/PUK, keygen/import/certs, factory reset, admin key incl. AES. Drop cert templates (`-T`/`-D`), PKINIT (`-r`), SunSSH, CACS. |

## Phases

### Phase 0: truth in advertising (immediate)

Closes #265. Removes what is already broken.

- Delete the `Ca`, `Luks`, `Zfs` clap variants from `main.rs`, their
  `exec.rs` name-list entries and test, and every doc mention
  (`doc/piggy.1.scd`, `README.md`, `AGENTS.md`, the 2026-04-27 CLI
  scope doc gets a status note, FDR 0003's "rejected" section stays as
  history).
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
2. **Differential corpus, captured now.** New recipe
   `codemod-capture-pivy-oracle-box`: for a matrix of (plaintext size,
   recipient count, agent vs card path), encrypt with Rust, decrypt
   with C `pivy-box` and with Rust, assert byte equality, and store
   the ebox plus plaintext under `crates/piggy-box/tests/fixtures/`.
   These fixtures outlive C.
3. **Existing gates stay green:** `piggy_box_decrypt_interop.bats`,
   `piggy_recipients_sync_fibby.bats`, `piggy_pass_init_fibby.bats`,
   `t0700-verify.bats`, `t0110-auth-sock.bats` (the sock-record hook
   in the mock moves to a Rust-side `PIGGY_TEST_SOCK_RECORD`).
4. **Error paths:** fibby gains an SW-injection control (`fibby ctl
   fault <reader> <sw>`) so the Rust side's handling of 6982 (PIN
   required), 63Cx (retries), 6A82 (no such object) is tested without
   hardware. This is reused in Phase 3.

Effort: two merge cycles (one for the spike, one for the port).

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

### Phase 3: `piggy tool` port

Reframes the 2026-04-21 scoping doc against what `card init` already
delivered. Crate layout as scoped there (`crates/piggy-tool` or
`crates/piggy/src/cmd/tool/`; choose at implementation time, the
dispatcher shape is the same).

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

### Phase 4: demote C pivy to a test-only nix input

Once Phases 1 to 3 are green:

- Drop `pivyPkg` from `runtimeDeps` in `flake.nix`; the wrapped
  `piggy` no longer has any `pivy-*` on PATH.
- Drop `PIGGY_PIVY_VERSION` from the version table.
- HM module: remove the `pname == "pivy"` branch and its assertions;
  `package` must be piggy.
- Keep `.#pivy` as a flake output consumed only by the oracle bats
  lanes and debug recipes.
- Delete the `Pivy` clap arm (`piggy pivy <tool>`) and
  `piggy_pivy.bats`; delete `exec_pivy` if nothing else uses it.

Gate: a `lint-closure-no-pivy` recipe that fails if
`nix why-depends .#default .#pivy` finds a path; wired into `lint`.

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
- Delete `vendor/pivy/`, `nix/pivy.nix`, `vendor/pivy/openssh.patch`,
  the libressl/openssh source pins, the `.#pivy` output, the ~20
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
| NixOS VM lane (`nix/vm-tests/`, `just test-vm-luks` / `test-vm-zfs`) — **landed 2026-09-14** | the only place LUKS/ZFS unlock and the shipped closure-as-a-system can be exercised; harness for any future `piggy luks`/`zfs` port | 3+, and the Phase 4 soak |
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

1. Confirm the drop list in "Product decisions", in particular
   recovery/N-of-M and the `key *` family.
2. Is there any ZFS native-encryption use in the fleet that would want
   `piggy zfs` re-created in Rust later? (Affects whether the zfs drop
   gets a placeholder issue.)
3. Which throwaway YubiKey serials may the hardware lane treat as
   destructible?
4. Should `piggy tool` be a separate crate (`crates/piggy-tool`) or a
   `cmd/tool/` module in the piggy crate? Recommendation: module, to
   keep one clap tree and reuse `card_oracle`/`sign_core`.

## Issue map

Existing: #265 (Phase 0), #164 and #154 (Phase 1), #165 (Phase 2), #3
umbrella, #26 triage, #116 (`pivy_tool_admin_key` sandboxing becomes
moot at Phase 5), #105 to #111 (C agent, moot at Phase 5), #28/#42/#43
(moot at Phase 5), #30 (`tpl create` hardware-free mode, subsumed by
the Phase 2 drop).

To file when the plan is accepted: one epic linking this doc; one
issue per Phase 3 milestone; one each for the six infrastructure items
above; a "recovery/N-of-M in piggy" design placeholder if the operator
wants it.
