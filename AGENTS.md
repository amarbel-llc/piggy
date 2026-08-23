# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Where to start work

Open the GitHub issue **amarbel-llc/piggy#26 — "Sequenced work: open issue triage"** before doing anything that needs picking-up-where-it-left-off. It maintains a tiered to-do list with a "Recommended next" pointer at the top and links to every active issue. If you finish a chunk of work, update #26 alongside the commit. The umbrella tracker is **#3 — Rust parity roadmap**; #26 is the operational triage that drives day-to-day priorities.

## Overview

Piggy is a passwordstore.org fork that replaces GPG encryption with PIV smart card encryption via pivy-box and ebox templates. Secrets are encrypted to YubiKey PIV slot 9D (Key Management/ECDH) instead of GPG keys. Decryption works transparently over SSH agent forwarding.

## Build & Test Commands

```sh
just build              # Build nix package (nix build --show-trace)
just test               # Full suite: test-bats-default + test-bats-conformance + test-rust + test-go-markl + test-pigpen
just test-bats-default  # Sandboxed bats lane via nix build .#bats-default
just codemod-fmt        # Format nix + shell + rust via conformist (= nix fmt)
just clean              # Remove build artifacts
just release X.Y.Z      # Cut a release: bump version.env, sign+push tags, gh release create
```

Run a single bats test file outside the sandbox (fast iteration):
```sh
just test-bats-file zz-tests_bats/t0100-insert.bats
```

## Just Recipes

Prefer just recipes over direct cargo/bats invocation — they pin consistent flags and keep the justfile the single source of truth, and they're allowlisted (no per-invocation permission prompt):

- `just build-rust -p <crate>` instead of `cargo build --package <crate>`
- `just validate-rust -p <crate>` instead of `cargo check --package <crate>`
- `just test-rust --workspace` instead of `cargo test --workspace`
- `just test-bats-file <path>` instead of `bats --no-sandbox <path>`
- `just lint-rust` for clippy
- `just test` for the full suite

## Architecture

**Pure-Rust CLI** — top-level argv parsing is a Rust `clap` subcommand tree in `crates/piggy/src/main.rs`. Top-level dispatch is exhaustive in clap; there is no bash dispatch path (removed post-#96) and `exec.rs` has no catch-all branch. Bare `piggy` and bare `piggy pass` print clap help.

Command surface:

- **`pass <X>` (Rust handlers)** — `init`, `show`, `find`, `grep`, `insert`, `edit`, `generate`, `rm`, `mv`, `cp`, `git`, `verify`, `show-batch`, and the full `recipients` family (`list`, `list-available`, `add`, `remove`, `sync`). One file per handler under `crates/piggy/src/`. Shared substrate: `store.rs` (store walk + sneaky-path check), `git_ops.rs`, `crypt.rs` (encrypt/decrypt shims), `platform/` (RAII secure-tmpdir, clipboard, qrcode, shred).
- **Top-level native Rust handlers** — `help` (`usage.rs`), `version` (`version.rs`), `health` (`health.rs`), `ssh-copy-id` (`ssh_copy_id.rs`), `sign-bytes` (`sign_bytes.rs`), `list` (delegates to `piggy-ids`), `card init` (`card/`), `manage` (`manage/`).
- **Rust re-impls on the dispatch path** — `piggy agent` and `piggy box` run the Rust re-impls under `crates/piggy/src/cmd/{agent,pivy_box}` (live since the #56–#59 arc closed, 2026-06). `box` falls back to C `pivy-box` for subcommands it doesn't cover yet. `piggy agent` additionally proxies other SSH agents via repeatable `--upstream NAME=SOCKET` flags (piggy#215, `cmd/agent/upstream.rs`): upstream keys are offered after the native PIV keys, sign/extension/add requests route to the owning upstream, and lock/unlock fan out — so piggy's socket can be the sole `SSH_AUTH_SOCK` without an ssh-agent-mux in front. The piggy-native card extensions (`ecdh`, `ecdh-rebox`, `ykpiv-attest`) fall through to the upstreams on a *native miss* (key not served here) — never on a genuine error in a request the agent owns. `--proxy-only` (requires `--upstream`; conflicts with the card-selection flags) runs the agent **cardless** — no PCSC, no probe/recovery loops, upstreams only — the remote-host role of FDR 0001 (`docs/features/0001-proxy-only-agent-universal-front.md`, eng#295): one stable `piggy-agent.sock` on every host, card-backed on workstations, proxy-only on is-ssh-hosts fronting the fixed forwarded backings. Every Rust agent self-reports its role via the piggy-private `agent-mode@piggy` extension (`cmd/agent/mode.rs`); `piggy health` reads it. The agent unlinks its socket on SIGTERM/SIGINT and reclaims a stale (nothing-listening) socket file at bind.
- **exec-to-C passthrough** — `tool`, `ca`, `luks`, `zfs`, and the generic `piggy pivy <tool>` `exec(2)` into the matching C `pivy-*` binary via `exec::exec_pivy`. The C-only `agent` features (`-C` confirm, `-K` CAK, `install-service`) stay reachable via `piggy pivy agent`.

**Crypto layer:**
- Encrypt: `pivy-box stream encrypt <template> < plaintext > file.ebox`
- Decrypt: `pivy-box stream decrypt < file.ebox > plaintext`
- Templates (`.pivy-id` files) replace `.gpg-id` for recipient management
- Encrypted files use `.ebox` extension instead of `.gpg`

**Re-encryption walk & TAP-14 output** — `reencrypt::run` (`reencrypt.rs`) is the shared walk behind `pass init`, `mv`, `cp`, every `recipients add`/`remove`/`sync`, and the hidden `internal-reencrypt-path`. It walks every `*.ebox` under a target (skipping symlinks), re-encrypts each to its nearest `piggy-ids`, and emits a **TAP version 14** stream on stdout (header, `1..N` plan, one `ok`/`not ok`/`ok … # SKIP` per ebox; subprocess stderr stays off the TAP stream). A point is `# SKIP`ped when the ebox already encrypts to exactly the current recipient set (`reencrypt_unnecessary` parses the ebox header offline — no decrypt, no card). It is conservative: any parse failure, age recipient, or empty set re-encrypts, so it never false-SKIPs. `-v` adds a YAML diagnostic block to every point. The walk exits non-zero if any point is `not ok`.

**Platform abstraction** — `platform/{clipboard,qrcode,shred,tmpdir}.rs`. Linux uses `/dev/shm` (preferred) or `${TMPDIR:-/tmp}` for the secure tmpdir; clipboard prefers wl-copy → xclip → error; shred via `shred -f -z`. macOS uses pbcopy/pbpaste, an hdid-backed HFS ramdisk, and `srm -f -z` — selected at compile time via `#[cfg(target_os = "macos")]`.

**Known v1 acceptance**: the Rust `pass git` port does not allocate a ramdisk before exec-ing git on the non-init passthrough path (bash `cmd_git` did, via `tmpdir nowarn`). The Rust port forwards `$SECURE_TMPDIR` to git as `$TMPDIR` only if already set. Documented inline in `git.rs`. Promoting `pass git` onto the `SecureTmpdir` RAII guard (already used by `pass edit`) is a straightforward follow-up.

**Test framework** — BATS in `zz-tests_bats/`. Tests use mock scripts (`helpers/mock-pivy-box.sh`, `helpers/mock-pivy-tool.sh`) that substitute base64 for real encryption, so no physical PIV card is needed.

**Bats lane builder** — `bats.nix` wraps `bats.lib.${system}.batsLane` from the `amarbel-llc/bats` flake. Two scan roots: `zz-tests_bats/t*.bats` and `zz-tests_bats/conformance/*.bats`. `# bats file_tags=` directives are auto-discovered, producing one `bats-<tag>` derivation per tag plus `bats-default`. The default lane filter is `!hardware`: tests tagged `# bats file_tags=hardware` need a real pcscd talking to a card (fibby or hardware) and can't run in the nix sandbox, so they're excluded from `bats-default` and invoked via the `just test-bats-conformance-*-fibby` recipes instead. `zz-tests_bats/explore/` is intentionally not scanned. `nix build .#bats-default` is the authoritative CI gate; the `just test-bats-conformance` recipe is the ergonomic paved path for the non-hardware conformance tests (dual coverage is intentional — piggy#117). fibby (`crates/fibby`) can serve **multiple virtual cards** on one PCSC socket via repeatable `--card NAME [seed-flags…]` groups (piggy#242): each card is its own reader, gets a distinct GUID by default (`--seed-chuid-guid` overrides; `--seed-pin` sets a per-card PIN), and `SCardConnect` routes by reader name — the harness behind the multi-card agent lane (`test-bats-conformance-agent-multicard`).

## Key Files

- `crates/piggy/src/main.rs` — clap subcommand tree; top-level dispatch.
- `crates/piggy/src/exec.rs` — `exec_pivy` (C-pivy handlers + `piggy pivy <tool>` passthrough) + `exec_piggy_ids` (top-level `piggy list`). Module doc explains why each delegation is deliberate (#125).
- `crates/piggy/src/{init,show,insert,edit,generate,verify,find,grep,git,rm,copy_move,recipients,reencrypt,show_batch}.rs` — Rust handlers for the pass-style subcommands.
- `crates/piggy/src/reencrypt.rs` — the shared re-encryption walk; TAP-14 stream with recipients-match `# SKIP`. See the Architecture note.
- `crates/piggy/src/crypt.rs` — `encrypt`/`decrypt` shims used by `show`/`insert`/`edit`/`generate`; honors `PIGGY_AUTH_SOCK`.
- `crates/piggy/src/tree_recipients.rs` — opt-in `pass show -r`/`--recipients` renderer; annotates each ebox leaf with recipients read offline from its wire header (markl IDs, shortest-unique prefix). Default `pass ls` (`tree(1)` shell-out) is untouched.
- `crates/piggy/src/usage.rs` — `piggy help` (byte-for-byte port of bash `cmd_usage`).
- `crates/piggy/src/version.rs` — `piggy version` (eng-versioning(7) self-line + pinned-component table).
- `crates/piggy/src/health.rs` — `piggy health`: 9 fixed read-only/PIN-free agent/card/service checks (split `gather` → pure `evaluate` → `HealthSink`); TAP-14 on a tty / tap-ndjson(7) otherwise. An agent running with `--upstream` proxying (piggy#215) appends one point per upstream after the base nine, fed by the agent's `upstream-status@piggy` self-report (piggy-private extension; the upstreams themselves are probed with plain `request_identities`, so they implement nothing). A `--proxy-only` agent (per its `agent-mode@piggy` self-report, FDR 0001) SKIPs the four local-card points with a `proxy-only agent` reason, and its upstreams are treated as *alternative* backings — a dead one SKIPs while another is live and FAILs only when none is (card-backed agents keep the additive per-upstream FAIL). Anything short of a positive proxy-only report keeps the card-backed plan. Opt-in `--sign-test` adds an agent self-sign probe (the only path exercising the private key — MAY prompt for a PIN), catching the #179 wedge where an agent enumerates keys but refuses every sign. Design: `docs/plans/2026-06-07-piggy-health-design.md`.
- `crates/piggy/src/ssh_copy_id.rs` — `piggy ssh-copy-id`: reads slot-9A SSH-auth entries from a `piggy-ids` file, renders each offline as an `authorized_keys` line, shells out to `ssh-copy-id -f -i`. `--ids <path>` overrides the store's `piggy-ids`. 9A entries are a new non-encryption `piggy-ids` line type (RFC 0003) that `encryption_recipients()` filters out so they never reach the encrypt template. Bats: `t0800-ssh-copy-id.bats`.
- `crates/piggy/src/sign_bytes.rs` — `piggy sign-bytes`: a low-level, caller-agnostic PIV byte-signer (piggy#190). Signs stdin with slot 9A/9C via `piggy_piv` `sign_prehash` (direct-PCSC); output `--format raw` (default, fixed-width `r‖s`) or `der`. piggy applies no canonicalization. `--guid` selects among cards; PIN via `-P` or the RFC 0006 `Frontend`. **Card-first / agent-fallback** (`sign_core`): when no local card is reachable (no PCSC, or no `--guid` match) the signature is requested from a forwarded SSH/piggy agent (`PIGGY_AUTH_SOCK`, else `SSH_AUTH_SOCK`) via `agent_client::agent_sign_message` — the agent must serve the requested slot (typically 9A) and owns its own PIN prompt (`-P` is forwarded as a best-effort agent UNLOCK; `--frontend` is not consulted on the agent path). Thin wrapper over shared `sign_core` (extracted in #201 so `manage`'s `sign_bytes` shares the pipeline). Bats: `t0850-sign-bytes.bats` + `conformance/piggy_sign_bytes_fibby.bats` (hardware).
- `crates/piggy/src/card/` — the `piggy card init` provisioning stack (piggy#194), structured engine ⟂ interaction-seam ⟂ frontend bindings per RFC 0006. `protocol.rs` is the binding-agnostic `Frontend` trait + serde payload types (which double as the JSON-RPC wire shape). `frontend/tty.rs` is the default in-process binding (card-named askpass prompts); `frontend/jsonrpc.rs` is the JSON-RPC binding an external program drives over `--socket`. `engine.rs` orchestrates full-setup (admin-auth → CHUID → generate 9D+9A → self-signed certs → change PIN+PUK → rotate mgmt key) against `&mut dyn Frontend`. `init_cmd.rs` selects a blank card and drives the engine through the `SessionCard` adapter. Mgmt-key policy today is random-displayed-once; PIN-protected storage is piggy#198. Bats: `t0950-card-init.bats` + `conformance/piggy_card_init_fibby.bats` (hardware, both frontends).
- `crates/piggy/src/manage/` — the `piggy manage --jsonrpc` headless command server (piggy#201), the command half of the #197 management-API epic per RFC 0007. `serve(reader, writer)` is a transport-agnostic, blocking, single-flight JSON-RPC 2.0 loop (stdio and `AF_UNIX` socket share one core): `initialize` `piggy-mgmt/1` handshake, then dispatch until EOF. Methods (`manage/methods.rs`): `card.list`, `card.init`, `sign_bytes`. The interactive methods reuse `JsonRpcFrontend::already_initialized` over the live connection to drive PIN/confirm/progress back to the client (composing with RFC 0006 on one connection). Card-touching paths are covered by the `crates/manage-client` peer + `piggy_manage_fibby.bats`, not unit-tested through `serve`.
- `crates/piggy/src/ecdsa_sig.rs` — shared, bounds-checked DER ECDSA signature reframing behind both the agent's SSH-signature path and `sign-bytes`.
- `crates/piggy/src/internal_clipboard_restore.rs` — hidden subcommand backing the deferred-restore worker for `show -c`/`generate -c`.
- `crates/piggy/src/platform/{clipboard,qrcode,shred,tmpdir}.rs` — clipboard tool selection, qrencode viewer plan, shred, and the RAII `SecureTmpdir` guard.
- `crates/piggy/src/store.rs` — `store_root` (`$PIGGY_STORE_DIR > $XDG_DATA_HOME/piggy > $HOME/.local/share/piggy`), `resolve_target` (sneaky-path check), `collect_eboxes`, `find_piggy_ids`.
- `crates/piggy/src/git_ops.rs` — shared git helpers (`find_inner_git_dir`, `add_and_commit`, `commit`, `rm`, `is_inside_work_tree`, `signing_flag`, `git_at`).
- `crates/age-plugin-piggy/` — standalone [age](https://age-encryption.org) plugin binary making piggy's slot-9D key an age identity, so secrets can be plain age files (consumable by `age`, sops-nix) instead of `.ebox`. Stanza is age-plugin-yubikey's `piv-p256` scheme; **encrypt** is pure-software, **decrypt** delegates the ECDH to piggy-agent (`ecdh@joyent.com`, forwardable) so the private key never materializes. Recipient/identity are `age1piggy…`/`AGE-PLUGIN-PIGGY-…` Bech32, minted by `generate [--guid]` (reads slot 9D, PIN-free) or offline `convert <markl-id|hex-pubkey>`. Confirmed on real card crypto by `conformance/age_plugin_piggy_fibby.bats`. Design + sops-nix recipe: `docs/plans/2026-06-09-age-plugin-piggy.md`. Follow-ups: a man page, a version `build.rs`, an end-to-end sops-nix test.
- `flake.nix` — nix package + dev shell. Roots `nixpkgs` and transitive `amarbel-llc/bats` at `amarbel-llc/nixpkgs`. Bats lane builder via `bats.lib.${system}.batsLane`. Pins the `tap-dancer` git dep through a single `sharedCargoLock` shared by both `buildRustPackage` derivations.
- `bats.nix` — sandboxed bats lane builder (see Architecture).
- `go/main.go` — Go SSH agent conformance test binary (protocol wire-format validation).
- `sweatfile` (repo root) — piggy-level spinclass override: `pre-merge = "just"` so `merge-this-session` blocks on full local test pass.
- `version.env` (repo root) — single source of truth for `PIGGY_VERSION`. Read by `flake.nix`, `crates/piggy/build.rs`, and the `just {bump-version,tag,release}` recipes. Follow eng-versioning(7).
- `contrib/emacs/piggy.el` — Emacs integration package.

## Specs

- `docs/rfcs/0002-piv-ecdh-box.md` — normative wire-format spec for `piggy-box` (forked from pivy RFC 0002, owned by piggy). Appendix A pins three bit-exact wire vectors replayed by `crates/piggy-box/src/piv_box.rs::tests::rfc0002_vectors`; drift between spec and test is a CI failure.
- `docs/rfcs/0003` — the `piggy-ids` recipient-file format (incl. the 9A SSH-auth line type).
- `docs/rfcs/0011-markl-id-format.md` — the normative markl-id wire format. **Formerly madder RFC 0002**, moved here to complete the piggy#183 ownership inversion and renumbered only because piggy's 0002 slot was already taken by the PIV-ECDH box spec. Internal section numbers are unchanged, so existing "RFC 0002 §2.1" citations still resolve. `go/internal/bravo/markl/marklid.peg` carries a SYNC OBLIGATION to §2/§2.1/§2.3/§3. madder's copy still needs removing or redirecting in a downstream pass.
- `docs/rfcs/0011-identifier-vectors.txt` — the §7.3 identifier conformance-vector corpus: purpose slots paired with `parse`/`reject`/`parse-invalid` verdicts. Run here by `TestIdentifierVectors`; downstream grammars (trellis foremost) run the **same file** against their own identifier production, and any mismatch not recorded in §7.4's divergence register fails a gate. The invariant is containment — markl `purpose` ⊂ trellis `Ident` — not equality.
- `docs/rfcs/0006-management-interaction-protocol.md` — the `Frontend`/interaction-seam contract behind `card init` and `manage`'s interactive methods.
- `docs/rfcs/0007-management-command-protocol.md` — the `piggy manage` JSON-RPC command surface.

## go/ module (piggy#183)

`go/` (module `code.linenisgreat.com/piggy/go`) is piggy's canonical markl-id (purpose/format registry + Id codec) Go library — inverting the historic relationship where `crates/piggy-markl` was a port of madder's registry. madder consumes this module as an external dep (`dewey → piggy → madder` layering). Design: `docs/plans/2026-06-20-markl-id-ownership-inversion.md`; status: piggy#188; umbrella: piggy#183.

Layout (dagnabit `internal/<layer>/<pkg>` → `pkgs/<pkg>` facades):

- `internal/0/domain_interfaces` — the markl-id interfaces.
- `internal/alfa/blech32` — the split-HRP blech32 codec.
- `internal/bravo/markl` — the **pure framework**: `Id` codec, the registry *mechanism* (`RegisterFormat`/`SwapFormat`/`GetFormatOrError`), the type + vocabulary constants, error sentinels, and the purpose-slot quoting codec (`purpose_quoting.go` — bare/quoted spelling per RFC 0011 §2.1). Installs no concrete format except the hash family. Also home to `marklid.peg`, the normative grammar.
- `internal/charlie/markl_registrations` — piggy's **native registrations** (crypto, the four erroring stubs, piggy's purposes) + the RFC-0002 vector generator/replay. **Opt-in: blank-import to fire `init()`.**
- `internal/delta/agent` (facade `pkgs/agent`) — the heavy ssh/pivy signer-discovery layer; swaps real impls over the ssh/ecdh stubs via `markl.SwapFormat`. Off the dep-light core's import path (importing it pulls `x/crypto/ssh` + `dewey/pivy`).
- `internal/delta/age` (facade `pkgs/age`) — the age x25519 encryption layer; swaps the real Generate/GetIOWrapper over the `age_x25519_sec` stub.
- `internal/delta/pigpen` (facade `pkgs/pigpen`) — the RFC 0008 pigpen encrypted-document + recipient-set codec (pure crypto over the registry).

All three `delta` packages import the internal layers directly (not the `pkgs/` facades) and carry `//go:generate dagnabit export`; their facades are what external consumers (madder) import.

- `cmd/piggy-agent-conformance`, `cmd/piggy-test-sshd` — the two Go test binaries piggy's bats lanes need (SSH-agent wire-protocol conformance tester; test-only SSH server). `package main` with logic inline (matching madder's test-binary practice); they don't import the registry. Absorbed from the former standalone `conformance` module so `go/` is one module.

**Producer (flake-input-go_mod, RFC 0001)**: `go/gomod.nix` calls `mkGoPkgs` (scoped `src = self + "/go"`, `name = "piggy-go"`, bridging only dewey via `passthru.goFlakeInputs`), and `flake.nix` exposes `packages.<sys>.{go-pkgs, go-pkgs-test}`. Downstream (madder/dodder/cutting-garden) bridge `code.linenisgreat.com/piggy/go` = `go-pkgs` with **NO subPath** (the producer tree root carries `go.mod`). `go/gomod2nix.toml` (regen: `just update-gomod2nix`) pins the module's externals (incl. piggy-only `filippo.io/hpke`) for consumers.

**Gate**: `build-go` / `test-go` (compile + `go test -tags test`) are wired into `build`/`test`. The two `cmd/` binaries build via **`buildGoApplication` self-consuming `go-pkgs-test`** (`modules = ./go/gomod2nix.toml`, dewey `goFlakeInputs` threaded); `piggy-agent-conformance`'s `checkPhase` runs `go vet -tags test ./...` over the whole module, so a source-filter regression OR a stale `gomod2nix.toml` fails the gate in piggy (both binaries are built in `build-nix`). Facade drift is gated by conformist's `dewey-facade-export` lane (REPAIR at pre-commit, CHECK at `just lint-worktree`). Per #183/#188 the *library* has no `buildGoModule` gate — it's gated by the dagnabit facade check; the `buildGoApplication` derivations build the *binaries* (always built) and double as the producer self-consume. gomod2nix subdir freshness lint is deferred (conformist#79).

Recipes: `build-go`, `test-go`, `update-go`, `update-gomod2nix`, `codemod-fmt-go`, `codemod-rfc0002-fixture`. (Facade regen/check moved to the conformist lanes; the standalone `codemod-facades`/`lint-facades` recipes were retired.)

**Grammar gates**: `validate-grammar` checks `marklid.peg` is well-formed under langlang; `test-grammar-vectors` runs **three** tests — the RFC 0011 conformance fixture (whole markl-ids, `TestGrammarVectors`), the §7.3 identifier corpus (purpose slots, `TestIdentifierVectors`), and the `@import` contract (`TestGrammarImportSurface`, piggy#236). The recipe's `-run` alternation must be extended when adding a fourth, or the new test silently never runs.

**Grammar export surface (piggy#236)**: piggy is the ROOT of the ecosystem's langlang `@import` chain (piggy → trellis → hyphence; papi consumes validators). The flake exports `.#marklid-grammar` (the peg) and `.#markl-identifier-vectors` (the §7.3 corpus) as store paths so downstreams stage instead of vendoring. The peg's named rules `String`/`Char`/`FormatData`/`Format`/`Data`/`PurposeBare`/`PurposeChar`/`DataChar` are a **frozen contract** — renaming any of them fails `TestGrammarImportSurface`, deliberately: that failure means "breaking change for trellis/hyphence/papi", not "update the test". `String`/`Char` are OWNED here (ownership inverted from trellis, which imports them). `DataChar` (piggy#237) is the blech32 alphabet exported as a bare primitive so a downstream can compose a length-agnostic digest (`Format '-' DataChar+`) — keeping the charset strict while owning its own length policy; piggy deliberately does NOT also export a composed `FormatDataShape`-style production, because length is per-consumer policy (RFC 0011 §4.1) and a frozen export with no in-repo consumer has nothing keeping it honest. Producer conformance pattern: RFC 0011 §7.5.

**Terminology** (piggy#234, salvaged from the dead #184 rename): **markl-id** is the ID *type* (`[purpose@]format-data`, RFC 0011); a **`piggy-ids` file** is a store's recipients file — a file *of* markl-ids, one per line per RFC 0003 (including the non-encryption 9A SSH-auth line type); the **`piggy-ids` crate/binary** is named after the file it manages, not the ID type. The `markl` name is permanent — the markl→piggy-id rename was closed won't-do (#184).

## Code Conventions

- Bash: `set -o pipefail`, `[[ ]]` conditionals
- Functions: `cmd_*` for user-facing commands, lowercase_with_underscores for helpers
- Formatting is driven by **conformist** (treefmt's successor; config in `conformist.nix` + `conformist.lib.presets.eng`): shell `shfmt -i 2 -ci`, nix `nixfmt` (RFC 166), rust `rustfmt`. Go is NOT covered by `nix fmt` — use `just codemod-fmt-go` for go/'s hand-written sources; the `pkgs/` facades are formatted by the dewey-facade-export lane.
- **Always format and check via `just codemod-fmt` (= `nix fmt`); never run `cargo fmt` / `rustfmt` / `shfmt` / `nixfmt` bare.** The bare tools use stock defaults that diverge from conformist's pinned config. `cargo fmt --check` is especially deceptive — it flags unrelated, already-clean files. For a non-mutating check, run `just lint-fmt` (the sandboxed `checks.formatting` gate) or `just codemod-fmt` on a clean tree and inspect `git status`.
- go/ dagnabit facade drift is auto-repaired at commit time by the `conformist-pre-commit` hook (sweatfile `[hooks].pre-commit`) and checked at the merge gate by `just lint-worktree` (in the `lint` aggregate). The old `codemod-facades`/`lint-facades` recipes were retired — see the go/ section and `flake.nix`'s `conformistFacadeModule`.

### Test-fixture ebox part names

When a unit or integration test builds an `EboxTplPart`, set `name: Some("piggy-test:<short-context>".into())`. The `piggy-test:` prefix ensures that if a PIN prompt ever escapes the test harness, the dialog's "token (partname)" line makes the origin obvious rather than looking like a real-card request. See #33 for planned askpass-context improvements that build on this prefix.

## Environment Variables

User config is via `PIGGY_*` env vars. Defaults live alongside their consumer (`generate.rs` for `PIGGY_GENERATED_LENGTH`/`PIGGY_CHARACTER_SET*`; `show.rs` for `PIGGY_CLIP_TIME`; `clipboard.rs` for `PIGGY_X_SELECTION`; `store.rs` for `PIGGY_STORE_DIR`, default `~/.local/share/piggy`).

`PIGGY_AUTH_SOCK` selects the SSH-agent socket used for PIV decrypt. When set and non-empty it overrides the ambient `SSH_AUTH_SOCK` for piggy's own decrypts only. The point is to route decrypts at piggy-agent directly (which advertises `ecdh@joyent.com`) rather than through an ssh-agent-mux that may not — see #123. Honored at every decrypt site (`crypt::decrypt`, `reencrypt_one`, the Rust `AgentEcdhOracle`); canonical resolver is `agent_client::piggy_auth_sock_override`.

`STATSD_HOST` / `STATSD_PORT` opt piggy's SSH agents into [stats-me](https://code.linenisgreat.com/stats-me) telemetry; their *presence* is the opt-in gate (the home-manager module exports them, so when neither is set the agents emit nothing). When present, both agent impls (C `pivy-agent`, Rust `cmd::agent`) emit one fire-and-forget statsd datagram per request: counter `piggy.agent.<op>.<result>:1|c` and timer `piggy.agent.<op>.duration:<ms>|ms`, with DogStatsD `#op:<op>,result:<result>` tags. Host resolution follows stats-me-clients(7) (`STATSD_HOST` empty → `127.0.0.1`, `STATSD_PORT` default `8125`). The shared Rust emitter is `crate::stats`; the C side mirrors it in `stats_send`/`agent_stats_op_done`.

Beyond the per-request `piggy.agent.<op>` surface, the Rust side also emits (same module, same wire shape): `piggy.pass.<cmd>` per pass subcommand (via `stats::timed_pass`), `piggy.box.<op>` for Rust `box` ops, finer agent events (`piggy.agent.cak` #143, `piggy.agent.pin_prompt`, `piggy.agent.pin_cleared` #59), and `piggy.pass.show_batch_item` per ebox. The `agent` category stays byte-identical to the C mirror (pinned by a test); the new categories are Rust-only.

## Debugging

### darwin CI: silent exit 126 under `env -i` with `set -euo pipefail`

On the macos-15 GitHub Actions runner, `/usr/bin/ps` (or `/usr/bin/tr`) exits 126 under a stripped environment (`env -i HOME=$HOME PATH=/usr/bin:/bin ...`), while `/bin/echo` and other `/bin` binaries run fine. Linux runners don't exhibit this. Suspected macOS hardened-runtime + stripped DYLD env, not proven; tracked at #100.

Consequence for `set -euo pipefail`: a pipeline like `var="$(ps … | tr …)"` whose RHS exits 126 propagates through pipefail, the assignment inherits 126, and `set -e` exits the script silently with 126 — no stderr, no failing command. This bit us in #92; fixed in `contrib/piggy-askpass.sh` by appending `|| true` to the pipeline. When porting a shell helper that strips its env or runs under launchd-style fork+exec: pin `|| true` on pipelines whose output is decorative (with a trailing `[[ -z "$var" ]] && var="?"`), or pin specific absolute exec paths and add a diagnostic test.

### bats + PCSC

Any bats recipe whose tests exercise pcscd runs under batman with `--allow-local-binding` so the sandbox permits the local binding the pcscd handshake needs. If pcscd is unreachable, libpcsclite reports "PC/SC system service/daemon not available" even though `PCSCLITE_CSOCK_NAME` reached the subprocess — the symptom looks identical to a missing pcscd; it isn't.

**batman 0.1.3 removed the older `--allow-unix-sockets` flag.** Passing it to current batman is fatal: it's forwarded to bats-core, which exits "Bad command line option" before any test runs (`total: 0`, "no plan line found"). If a recipe regresses with that error, the stale flag is the cause. See `just explore-bats` for the generic `--no-sandbox` driver.

### PIV CLI dispatch (exec-to-C) + pcscd reset semantics

`piggy agent` and `piggy box` run the **Rust** re-impls under `crates/piggy/src/cmd/{agent,pivy_box}`. The Rust `piggy agent` prompts for the PIN on demand via `SSH_ASKPASS` (reusing `card_oracle::run_askpass`), matches guidless piggy 2.x boxes by recipient pubkey in `handle_ecdh_rebox`, and spawns the #59 card-presence probe loop. The re-point is a clean cutover to the Rust flag surface — notably `piggy agent -i` means print-keys-and-exit, NOT C's foreground mode; the home-manager module (`nix/hm/piggy-agent.nix`) emits Rust flags.

Fibby test path: `conformance/piggy_agent_pin_on_demand.bats` drives a guidless slot-9D decrypt through the agent with the PIN supplied on demand, baselined against C `pivy-agent`. The in-process `CardEcdhOracle` test (`crates/piggy/tests/unlock_ebox_card_integration.rs`, hardware mode `PIGGY_TEST_CARD_GUID=<guid>`) remains for direct PinSession hardware validation.

pcsc-lite **refcount-shields** a co-resident `SCardEndTransaction(SCARD_RESET_CARD)` while the victim holds its connection open — the reset is deferred and does NOT clear another open client's PIN. Consequence (piggy#56): the verify→op PIN-clearing race does not reproduce on this stack. Probe with `just debug-lock-contention-probe` / `debug-reset-loop`.

### Test harness safety net for PIN prompts

Any recipe that could invoke `pivy-box`, `pivy-agent`, or any path that might reach pivy's `assert_pin()` interactive fallback MUST set:

```sh
askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
export SSH_ASKPASS="$askpass" \
       SSH_ASKPASS_REQUIRE=force \
       DISPLAY="" \
       PIGGY_TEST_FIB_PIN=123456   # only if the recipe legitimately needs auto-unlock
```

Without these, a failed agent unlock falls through to whatever `SSH_ASKPASS` the operator's shell inherits — typically zenity or ssh-askpass — and renders a GUI dialog indistinguishable from a real unlock. We had exactly this escape on 2026-04-24; see #35. The helper (`zz-tests_bats/helpers/piggy-test-askpass.sh`) either supplies the configured test PIN non-interactively or refuses with a `[piggy-test-askpass]`-prefixed stderr banner. It NEVER prompts and NEVER touches /dev/tty.

### User-facing askpass helper

`contrib/piggy-askpass.sh` is the user-facing sibling: it renders piggy-aware context (parent process, `PIGGY_ASKPASS_CONTEXT`, `[TEST]` heuristic) on top of the prompt, then reads the PIN — preferring `/dev/tty`, falling back to `zenity`, refusing otherwise. Before the `zenity` branch, when the inherited (frozen `systemd --user` agent) env carries no display, it re-derives a live one (importing from `systemctl --user show-environment`, else globbing `$XDG_RUNTIME_DIR/wayland-*`) so a piggy-agent that started before the compositor published `WAYLAND_DISPLAY` can still prompt (#179). The route is caller-selectable via `SSH_ASKPASS_REQUIRE` (#166): `force` → always zenity, `never` → tty-or-refuse, unset/`prefer` → tty-first. The same semantics live in Rust `card_oracle::run_askpass`. Drop in as your `SSH_ASKPASS`:

```sh
export SSH_ASKPASS="$PWD/contrib/piggy-askpass.sh"
```

Smoke-test without entering a PIN via `PIGGY_ASKPASS_DRY_RUN=1` — it emits its rendered context to stderr and exits 0. See `zz-tests_bats/conformance/piggy_askpass.bats` and #33.
