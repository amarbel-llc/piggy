# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. It is an orientation map: the manpages under `doc/` are the reference, and this file points at them rather than repeating them. Read them with the `man.*` MCP tools (`man_toc`, `man_section`).

## Where to start work

Open issue **piggy#26 — "Sequenced work: open issue triage"** in piggy's tracker before doing anything that needs picking-up-where-it-left-off. It maintains a tiered to-do list with a "Recommended next" pointer at the top and links to every active issue. If you finish a chunk of work, update #26 alongside the commit. The umbrella tracker is **#3 — Rust parity roadmap**; the C-pivy retirement epic is **#289** (`docs/plans/2026-09-14-retire-c-pivy-rust-nix-migration.md`).

## Overview

Piggy is a passwordstore.org fork that replaces GPG encryption with PIV smart card encryption: secrets are `.ebox` files encrypted to YubiKey PIV slot 9D (ECDH) via the piggy-box format (RFC 0002), recipients are declared in a `piggy-ids` file (RFC 0003, piggy-ids(5)), and decryption works transparently over SSH agent forwarding through `piggy agent` (piggy-agent(1)).

## Manpages (the reference)

| Page | Covers |
|---|---|
| piggy(1) | every `pass` subcommand, `list`, `ssh-copy-id`, `sign-bytes`, `card init`, `health`, `manage`, `secrets reconcile`, `luks`, `zfs`; `PIGGY_*` and `STATSD_*` environment |
| piggy-agent(1) | the Rust agent: flags, upstream proxying and `--proxy-only` (FDR 0001), card presence, the `agent-mode@piggy` / `upstream-status@piggy` self-reports, PIN prompts, telemetry |
| age-plugin-piggy(1) | the age plugin (slot 9D as an age identity) |
| piggy-ids(5) | the recipients file format |
| piggy-piv-slots(7) | PIV slot conventions |
| piggy-ci(7) | what the merge gate runs (`just` = `lint build test`); there is no hosted CI |
| piggy-testing(7) | how every test tier works: bats over mocks, bats over fibby, the NixOS VM lanes, coverage; the PIN-prompt safety net; PC/SC-in-sandbox and platform gotchas |
| piggy-markl(7) | the `go/` markl-id module: layout, producer/consumer bridge, grammar gates, the frozen grammar export contract, terminology |

Design records live in `docs/features/` (FDRs), `docs/rfcs/` and `docs/plans/`; `docs/rfcs/0002` (piggy-box wire format, with bit-exact vectors replayed in tests), `0003` (piggy-ids), `0006`/`0007` (management interaction and command protocols), `0011` (markl-id format + the §7.3 identifier corpus) are normative.

## Paved paths

Prefer just recipes over direct cargo/bats/nix invocation — they pin flags, keep the justfile the single source of truth, and are allowlisted:

```sh
just                      # the merge gate: lint build test (see piggy-ci(7))
just build-rust -p <crate>            # not cargo build
just validate-rust -p <crate>         # not cargo check
just test-rust -p <crate> -- <filter> # not cargo test
just test-bats-file <path>            # one bats file, unsandboxed, fast
just test-bats-default                # the sandboxed bats lane (nix build .#bats-default)
just test-vm-{luks,zfs,agent}         # the NixOS VM lanes (piggy-testing(7))
just lint-rust                        # clippy
just codemod-fmt                      # nix fmt via conformist — never run cargo fmt/rustfmt/shfmt/nixfmt bare
just release X.Y.Z                    # changelog, version.env bump, signed tags, Forgejo release
```

`just lint-worktree` runs the impure eng-convention checks, including a 40000-character cap on this file.

## Architecture

**Pure-Rust CLI.** Top-level argv is a clap subcommand tree in `crates/piggy/src/main.rs`; dispatch is exhaustive, there is no bash path, and `exec.rs` has no catch-all. Bare `piggy` and bare `piggy pass` print help.

- **`pass <X>`** — one Rust handler file per subcommand under `crates/piggy/src/` (`init`, `show`, `insert`, `edit`, `generate`, `rm`, `mv`/`cp` in `copy_move.rs`, `find`, `grep`, `git`, `verify`, `show_batch`, `recipients`). Shared substrate: `store.rs` (store root, sneaky-path check, ebox walk, `find_piggy_ids`), `git_ops.rs`, `crypt.rs` (`encrypt` via `piggy-ids`; `decrypt` in-process through `cmd::pivy_box::Decryptor` — agent from `PIGGY_AUTH_SOCK`/`SSH_AUTH_SOCK`, else a local card with the askpass PIN — shared by `grep`, `verify` and the re-encryption walk so one walk pays one PIN; `decrypt_first_line` for passphrase-shaped consumers), `platform/` (RAII secure tmpdir, clipboard, qrcode, shred; macOS variants selected at compile time).
- **Top-level handlers** — `usage.rs` (`help`), `version.rs`, `health.rs`, `ssh_copy_id.rs`, `sign_bytes.rs` (thin wrapper over `sign_core.rs`, card-first with agent fallback), `card/` (`card init`: engine ⟂ `Frontend` seam ⟂ tty/jsonrpc bindings per RFC 0006; `seal.rs` escrows the management key into the store), `manage/` (RFC 0007 JSON-RPC server sharing the same `Frontend` over one connection), `secrets.rs` (FDR 0003 reconcile over `show_batch::with_batch_unlock`), `luks.rs` (#277) and `zfs.rs` (#279) (store-keyed volumes over `crypt::decrypt_first_line`), `list` (execs `piggy-ids`).
- **`agent` and `box`** — the Rust re-implementations under `cmd/agent/` and `cmd/pivy_box/`. `box` handles `stream encrypt`/`decrypt` and `tpl create`/`show`; any other subcommand is a usage error (piggy#165 dropped the C fallback), and the full `pivy-box` surface is reachable only via `piggy pivy box`. `agent` semantics are in piggy-agent(1); `mode.rs` is the self-report, `upstream.rs` the proxying, `card.rs` the presence reconcile loop and event source.
- **Re-encryption walk** — `reencrypt.rs` is the shared walk behind `pass init`, `mv`, `cp` and every `recipients` mutation: every `*.ebox` under a target is re-encrypted to its nearest `piggy-ids`, reported as TAP-14, with `# SKIP` when the header already names exactly the current recipient set (offline, conservative: any parse doubt re-encrypts). `tree_recipients.rs` renders `pass show -r` from the same offline header read.
- **`tool`** — the Rust re-implementation under `cmd/tool/`. As of the #289 3.6 cutover it is NOT a superset that falls back to C: it handles `pubkey`, `cert`, `attest`, `sign`, `ecdh`, `change-pin`/`change-puk`/`reset-pin`, `set-admin`, `delete-cert`, `update-keyhist`, `write-cert`, `generate`, `import` (EC P-256/P-384), `pinfo`, `list -j` (the JSON card listing only; bare/`-p` `list` stay usage errors), and any unported op or unmodeled option is a usage error (exit 2), not a hop to C. The rest of the `pivy-tool` surface (`list` human/parseable modes, `version`, `init`, `req-cert`, `factory-reset`, RSA/Ed25519) stays reachable via `piggy pivy tool` while C is shipped (factory-reset in #291).
- **exec-to-C passthrough** — only `piggy pivy <tool>` execs the C binaries now via `exec::exec_pivy` (transitional until #289's Phase 4/5). The never-built `ca`/`luks`/`zfs` arms are gone (#265).
- **`ecdsa_sig.rs`** — the one bounds-checked DER↔SSH ECDSA reframing, shared by the agent and `sign-bytes`.
- **Known v1 acceptance**: the Rust `pass git` port allocates no ramdisk before exec-ing git on the passthrough path and forwards `$SECURE_TMPDIR` as `$TMPDIR` only if set; promoting it onto the `SecureTmpdir` guard is a follow-up.

**Other crates.** `crates/piggy-box` (RFC 0002 codec), `crates/piggy-piv` (PC/SC, PIN sessions, admin), `crates/piggy-ids` (the file + binary), `crates/fibby` (virtual PIV card, piggy-testing(7)), `crates/age-plugin-piggy` (age-plugin-piggy(1); design in `docs/plans/2026-06-09-age-plugin-piggy.md`), `crates/piggy-pigpen` (prototype, excluded from the workspace, `just test-pigpen`). `go/` is piggy-markl(7).

**Nix.** `flake.nix` builds the package (wrapping `pivy-*`, `piggy-ids`, the manpages from `doc/*.scd` by section number), the dev shell, the bats lanes (`bats.nix`), the VM lanes (`nix/vm-tests/`), and exports the home-manager modules `piggy-agent` (`nix/hm/piggy-agent.nix`, emits Rust agent flags) and `piggy-secrets` (`nix/hm/piggy-secrets.nix`; ciphertexts and manifest are context-free store paths GC-rooted at activation, never decrypted during a switch). `version.env` is the single version source (eng-versioning(7)); `sweatfile` sets the spinclass hooks (`pre-merge = "just"`, `pre-commit = "conformist-pre-commit"`).

## Code conventions

- Bash: `set -o pipefail`, `[[ ]]`; `cmd_*` for user-facing functions.
- Formatting is conformist (`conformist.nix` + the eng preset): `shfmt -i 2 -ci`, nixfmt RFC 166, rustfmt. **Always `just codemod-fmt`**; the bare tools use stock defaults and `cargo fmt --check` flags unrelated files. Go is not covered — `just codemod-fmt-go`; the `pkgs/` facades are formatted by the dewey-facade-export lane, which also repairs facade drift at commit time and checks it at `just lint-worktree`.
- Test-fixture ebox part names: `name: Some("piggy-test:<short-context>")` so an escaped PIN prompt is obviously a test (piggy-testing(7)).
- Any recipe or test that can reach a PIN prompt sets the askpass safety net exactly as piggy-testing(7) PIN PROMPT SAFETY NET shows; an escaped GUI prompt is indistinguishable from a real unlock (piggy#35).
- Recipes that spawn fibby and run bats under fence pass `{{ bats-expose-fibby-workdir }}` (piggy#253); those that talk to pcscd use `--allow-local-binding`.
- `Closes #N` in the commit that resolves an issue; the merge closes it.

## Environment variables

User configuration is `PIGGY_*`, documented in piggy(1) ENVIRONMENT VARIABLES; defaults live beside their consumer (`generate.rs`, `show.rs`, `clipboard.rs`, `store.rs`). `PIGGY_AUTH_SOCK` overrides `SSH_AUTH_SOCK` for piggy's own decrypts only (#123), honoured at every decrypt site through `agent_client::piggy_auth_sock_override`. `STATSD_HOST`/`STATSD_PORT` gate stats-me telemetry by presence; the emitter is `crate::stats`, the `piggy.agent.*` category is byte-identical to the C agent's mirror (pinned by a test), every other category is Rust-only (piggy-agent(1) ENVIRONMENT).
