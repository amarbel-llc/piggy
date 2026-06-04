# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Where to start work

Open the GitHub issue **amarbel-llc/piggy#26 — "Sequenced work: open issue triage"** before doing anything that needs picking-up-where-it-left-off. It maintains a tiered to-do list with a "Recommended next" pointer at the top and links to every active issue. If you finish a chunk of work, update #26 alongside the commit. The umbrella tracker is **#3 — Rust parity roadmap**; #26 is the operational triage that drives day-to-day priorities.

## Overview

Piggy is a passwordstore.org fork that replaces GPG encryption with PIV smart card encryption via pivy-box and ebox templates. Secrets are encrypted to YubiKey PIV slot 9D (Key Management/ECDH) instead of GPG keys. Decryption works transparently over SSH agent forwarding.

## Build & Test Commands

```sh
just build              # Build nix package (nix build --show-trace)
just test               # Full suite: test-bats-default + test-bats-conformance + test-rust
just test-bats-default  # Sandboxed bats lane via nix build .#bats-default
just codemod-fmt        # Format nix + shell + rust via treefmt (= nix fmt)
just clean              # Remove build artifacts
just release X.Y.Z      # Cut a release: bump version.env, sign+push v<X.Y.Z>, gh release create
```

Run a single bats test file outside the sandbox (fast iteration):
```sh
bats --no-sandbox zz-tests_bats/t0100-insert.bats
```

Protocol conformance tests (Go binary validates SSH agent wire format):
```sh
just test-bats-conformance-protocol  # Build + run protocol tests against piggy agent
```
The conformance binary is exposed as `piggy.tests.conformance` in
`flake.nix`; the recipe builds it on demand via
`nix build --no-link --print-out-paths` so no extra `result-*` symlink
appears in the worktree.

## Architecture

**Pure-Rust CLI** — top-level argv parsing is a Rust `clap` subcommand tree in `crates/piggy/src/main.rs`. Password-management commands live as nested subcommands under a top-level `pass` namespace. Every `pass <X>` is handled in Rust:

- **Pass-style handlers**: `init`, `show`, `find`, `grep`, `insert`, `edit`, `generate`, `rm`, `mv`, `cp`, `git`, `verify`, `show-batch`, and the full `recipients` family (`list`, `list-available`, `add` incl. `--all-attached`, `remove`, `sync`). Implemented in `crates/piggy/src/{init,show,find,grep,insert,edit,generate,rm,copy_move,git,verify,show_batch,recipients}.rs`. Shared substrate: store walk + sneaky-path check in `store.rs`, git ops in `git_ops.rs`, crypt shims (`pivy-box stream encrypt/decrypt`) in `crypt.rs`, RAII secure-tmpdir + clipboard/qrcode/shred in `platform/`.

`piggy help` is a native Rust handler (`crates/piggy/src/usage.rs`) that emits the pass-style usage banner byte-for-byte from the legacy bash `cmd_usage` (interpolating `$PIGGY_CLIP_TIME`, `$PIGGY_GENERATED_LENGTH`, `${EDITOR:-vi}`). `piggy version` is a pure Rust handler (`crates/piggy/src/version.rs`) that emits the eng-versioning(7) self-line (`piggy <version>+<commit>`) plus a pinned-component table, reading the values from the `PIGGY_VERSION`/`PIGGY_COMMIT`/`PIGGY_<component>_*` env vars `flake.nix`'s makeWrapper bakes in (dev `cargo build` renders `unknown`). The remaining top-level clap handlers (`agent`, `box`, `tool`, `ca`, `luks`, `zfs`, and the generic `piggy pivy <tool>` passthrough) `exec(2)` into the matching C `pivy-*` binary via `fallback::exec_pivy`. Top-level dispatch is exhaustive in clap; `fallback.rs` has no catch-all branch. Bare `piggy` and bare `piggy pass` print clap help (no implicit `cmd_show ""`).

Rust re-implementations of `agent` and `box` live under `crates/piggy/src/cmd/{agent,pivy_box}` (reachable via the `piggy::cmd` library surface) but stay off the user-facing dispatch path in v1.0. They will be re-pointed at once they reach feature parity with the C binaries; see #56 (PC/SC transactions in `piggy-piv`), #57 (direct-PCSC ECDH oracle for `piggy box stream decrypt`), #58 (askpass `[piggy-test]` context tagging), and #59 (probe-loop PIN-clearing in `piggy agent`) for the maturation roadmap.

**Known v1 acceptance**: the Rust `pass git` port (commit `03fb0ca`) does not allocate a ramdisk before exec-ing git on the non-init passthrough path. Bash `cmd_git` called `tmpdir nowarn` to set `$TMPDIR=$SECURE_TMPDIR`; the Rust port forwards `$SECURE_TMPDIR` to git as `$TMPDIR` if already set in the environment but does not create one itself. Documented inline in `crates/piggy/src/git.rs`. The platform layer (`crates/piggy/src/platform/tmpdir.rs`) now exposes a `SecureTmpdir` RAII guard used by `pass edit`; promoting `pass git` onto the same guard is a straightforward follow-up.

**Crypto layer:**
- Encrypt: `pivy-box stream encrypt <template> < plaintext > file.ebox`
- Decrypt: `pivy-box stream decrypt < file.ebox > plaintext`
- Templates (`.pivy-id` files) replace `.gpg-id` for recipient management
- Encrypted files use `.ebox` extension instead of `.gpg`

**Platform abstraction** — `crates/piggy/src/platform/{clipboard,qrcode,shred,tmpdir}.rs` ports the clipboard/qrcode/shred/tmpdir helpers. Linux uses `/dev/shm` (preferred) or `${TMPDIR:-/tmp}` for the secure tmpdir; clipboard prefers wl-copy → xclip → error. macOS uses pbcopy/pbpaste, an hdid-backed HFS ramdisk for tmpdir, and `srm -f -z` for shred — selected at compile time via `#[cfg(target_os = "macos")]`.

**Test framework** — BATS (Bash Automated Testing System) in `zz-tests_bats/`. Tests use mock scripts (`helpers/mock-pivy-box.sh`, `helpers/mock-pivy-tool.sh`) that substitute base64 for real encryption, so no physical PIV card is needed.

**Bats lane builder** — `bats.nix` wraps `bats.lib.${system}.batsLane` (the canonical builder exposed by the `amarbel-llc/bats` flake; the nixpkgs-overlay-provided `pkgs.testers.batsLane` is no longer used and was retired with the bats flake split). Two scan roots: top-level `zz-tests_bats/t*.bats` AND `zz-tests_bats/conformance/*.bats`. `# bats file_tags=` directives in either root are auto-discovered, producing one `bats-<tag>` derivation per unique tag plus `bats-default`. The default lane filter is `!hardware`: tests tagged `# bats file_tags=hardware` (currently `t0610-recipients-add-attached.bats`, `conformance/piggy_box_interop.bats`, `conformance/piggy_box_decrypt_interop.bats`, `conformance/piggy_recipients_add_attached.bats`, `conformance/piggy_pass_init.bats`, `conformance/pivy_agent_hardware.bats`, `explore/explore_local_guid_pcsc.bats`) are excluded from `bats-default` because they need a real pcscd talking to fib or hardware, which can't run inside the nix build sandbox. Those tests stay invoked via the existing `just test-bats-conformance-*` recipes. Non-hardware conformance tests (`piggy_askpass.bats`, `piggy_pivy.bats`, `piggy_agent_protocol.bats`) run under both the sandboxed lane AND the `just test-bats-conformance` recipe. The dual-coverage is intentional (piggy#117): `nix build .#bats-default` is the authoritative CI gate (stronger isolation — sandboxed HOME, no pivy-agent leak path), while the just recipe stays as an ergonomic paved path (no nix build overhead, fast iteration, works without per-invocation user permissions for both humans and agents). `zz-tests_bats/explore/` is intentionally not scanned. The wrapped piggy is injected into the lane via the `binaries` map (`PIGGY=${piggy}/bin/piggy`); `CONFORMANCE_BIN` is similarly threaded for `piggy_agent_protocol.bats`; `PIGGY_IDS_REAL` is pinned at the wrapped `$out/libexec/piggy/piggy-ids` via `extraEnv`.

## Key Files

- `crates/piggy/src/main.rs` — clap subcommand tree; top-level dispatch.
- `crates/piggy/src/fallback.rs` — `exec_pivy(tool, rest)` (C-pivy handlers + `piggy pivy <tool>` passthrough) + `exec_piggy_ids(subcmd, rest)` (top-level `piggy list`). No bash dispatch path survives post-#96.
- `crates/piggy/src/{init,show,insert,edit,generate,verify,find,grep,git,rm,copy_move,recipients,reencrypt,show_batch}.rs` — Rust handlers for every pass-style subcommand.
- `crates/piggy/src/crypt.rs` — `encrypt` / `decrypt` shims used by `show`/`insert`/`edit`/`generate` (pipe plaintext through `piggy-ids encrypt` and decrypt through `pivy-box stream decrypt`; honors `PIGGY_AUTH_SOCK`).
- `crates/piggy/src/usage.rs` — Rust handler for `piggy help` (byte-for-byte port of the legacy bash `cmd_usage`; interpolates `$PIGGY_CLIP_TIME`, `$PIGGY_GENERATED_LENGTH`, `${EDITOR:-vi}`).
- `crates/piggy/src/version.rs` — Rust handler for the top-level `piggy version` (eng-versioning(7) self-line + pinned-component table).
- `crates/piggy/src/internal_clipboard_restore.rs` — hidden subcommand that backs the deferred-restore worker for `show -c` / `generate -c` (`pkill`-named via `argv[0]` rename).
- `crates/piggy/src/platform/{clipboard,qrcode,shred,tmpdir}.rs` — clipboard tool selection (wl-copy/xclip/pbcopy), qrencode viewer plan, `shred -f -z`/`srm -f -z`, and the RAII `SecureTmpdir` guard (`/dev/shm` ramdisk + disk fallback with shred-on-drop; macOS hdid ramdisk under `#[cfg(target_os = "macos")]`).
- `crates/piggy/src/store.rs` — shared store helpers: `store_root` (`$PIGGY_STORE_DIR > $XDG_DATA_HOME/piggy > $HOME/.local/share/piggy`), `resolve_target` (sneaky-path check), `collect_eboxes` (the canonical `find -L $PREFIX -path '*/.git' -prune -o -iname '*.ebox'` walk), `find_piggy_ids` (walk-up-from-subfolder).
- `crates/piggy/src/git_ops.rs` — shared git helpers: `find_inner_git_dir` (mirrors `set_git`), `add_and_commit`, `commit`, `rm`, `is_inside_work_tree`, `signing_flag`, `git_at`.
- `zz-tests_bats/common.bash` — bats test harness (mock PATH, temp store, git identity).
- `zz-tests_bats/helpers/mock-pivy-box.sh` — mock pivy-box using base64 encode/decode.
- `flake.nix` — nix package definition and dev shell. Roots both `nixpkgs` and the transitive `amarbel-llc/bats` flake at `amarbel-llc/nixpkgs`. The bats lane builder is consumed via `bats.lib.${system}.batsLane` directly from the `amarbel-llc/bats` flake (see `bats.nix`).
- `bats.nix` — sandboxed bats lane builder (see Architecture). Generates `bats-default` plus per-tag derivations from `# bats file_tags=` directives.
- `go/main.go` — Go SSH agent conformance test binary (protocol wire format validation).
- `zz-tests_bats/conformance/piggy_agent_protocol.bats` — bats harness for protocol conformance.
- `zz-tests_bats/conformance/piggy_pivy.bats` — bats harness for the `piggy pivy <tool>` passthrough.
- `zz-tests_bats/t0700-verify.bats` — bats coverage for `piggy pass verify`.
- `sweatfile` (repo root) — piggy-level spinclass override: `pre-merge = "just"` so `merge-this-session` blocks on full local test pass (not just `nix build`).
- `version.env` (repo root) — single source of truth for `PIGGY_VERSION`. Read by `flake.nix` at eval time, by `crates/piggy/build.rs` at compile time, and by the `just {bump-version,tag,release}` recipes. Follow eng-versioning(7).
- `contrib/emacs/piggy.el` — Emacs integration package.

## Specs

- `docs/rfcs/0002-piv-ecdh-box.md` — normative wire-format spec for
  `piggy-box`. Forked from pivy RFC 0002, owned by piggy. Appendix A
  pins three bit-exact wire vectors replayed by
  `crates/piggy-box/src/piv_box.rs::tests::rfc0002_vectors`. Drift
  between the spec and the test module is a CI failure.

## Just Recipes

Use just recipes for all cargo and bats operations instead of calling cargo/bats directly via `develop-run` or shell:

- `just build-rust -p <crate>` instead of `cargo build --package <crate>`
- `just validate-rust -p <crate>` instead of `cargo check --package <crate>`
- `just test-rust --workspace` instead of `cargo test --workspace`
- `just test-bats-file <path>` instead of `bats --no-sandbox <path>`
- `just lint-rust` for clippy
- `just test` for the full suite

Recipes ensure consistent flags, proper dependencies, and keep the justfile as the single source of truth.

## Code Conventions

- Bash: `set -o pipefail`, `[[ ]]` conditionals
- Functions: `cmd_*` for user-facing commands, lowercase_with_underscores for helpers
- Shell formatting: `shfmt -s -i=2` (2-space indent, simplified) — driven by treefmt
- Nix formatting: `nixfmt` (RFC 166) — driven by treefmt
- Rust formatting: `rustfmt` — driven by treefmt
- **Always format and check via `just codemod-fmt` (= `nix fmt` = treefmt); never run `cargo fmt` / `rustfmt` / `shfmt` / `nixfmt` bare.** treefmt pins the repo's formatter config, so the bare tools use their stock defaults (notably rustfmt's import grouping/ordering) and report diffs that diverge from what treefmt considers correct. `cargo fmt --check` is especially deceptive: it flags unrelated, already-treefmt-clean files as "unformatted." If you need a non-mutating check, run `just codemod-fmt` on a clean tree and inspect `git status`.

### Test-fixture ebox part names

When a unit or integration test builds an `EboxTplPart`, set `name:
Some("piggy-test:<short-context>".into())`. The `piggy-test:` prefix
ensures that if a PIN prompt ever escapes the test harness — via a
misrouted SSH_AUTH_SOCK, a user's background pivy-agent, a
misconfigured askpass binary, etc — the dialog's "token (partname)"
line makes the origin obvious rather than looking like a real-card
request. Examples: `piggy-test:stream-fixture`,
`piggy-test:unlock-integration`. See #33 for planned askpass-context
improvements that build on this prefix.

## Environment Variables

User config is via `PIGGY_*` env vars (store dir, clip time, generated length, character set, etc.). Defaults live alongside their consumer (`generate.rs` for `PIGGY_GENERATED_LENGTH`/`PIGGY_CHARACTER_SET*`; `show.rs` for `PIGGY_CLIP_TIME`; `clipboard.rs` for `PIGGY_X_SELECTION`; `store.rs` for `PIGGY_STORE_DIR`). `PIGGY_STORE_DIR` defaults to `~/.local/share/piggy`.

`PIGGY_AUTH_SOCK` selects the SSH-agent socket used for PIV decrypt
(`pivy-box stream decrypt`). When set and non-empty it overrides the
ambient `SSH_AUTH_SOCK` for piggy's own decrypts only; when unset, piggy
uses `SSH_AUTH_SOCK` as before. The point is to route decrypts at
piggy-agent directly (which advertises the `ecdh@joyent.com` extension)
rather than through an ssh-agent-mux that may not — see #123 (and
ssh-agent-mux#10 for the mux-side capability drop). Honored at every
decrypt site: the Rust `crypt::decrypt` shim
(`crates/piggy/src/crypt.rs`, used by `show` / `edit` / `generate -i`),
`reencrypt_one` (`crates/piggy/src/reencrypt.rs`), and the Rust
`AgentEcdhOracle` source (`crates/piggy/src/cmd/pivy_box.rs`, off the
v1.0 dispatch path). The canonical resolver is
`agent_client::piggy_auth_sock_override` in the library crate; the
disjoint binary crate mirrors the one-line lookup.

`STATSD_HOST` / `STATSD_PORT` opt piggy's SSH agents into
[stats-me](https://github.com/amarbel-llc/stats-me) telemetry. stats-me
is upstream statsd packaged under Bun; its home-manager module exports
these two vars via `home.sessionVariables` (the eng env piggy runs in),
so their *presence* is the opt-in gate — when neither is set the agents
emit nothing and never spray UDP at a host that hasn't enabled it. When
present, both SSH agent implementations (the C `pivy-agent` in
`vendor/pivy/src/pivy-agent.c` and the Rust `cmd::agent` re-impl in
`crates/piggy/src/cmd/agent/session.rs`) emit one fire-and-forget
statsd datagram per request at the request-terminal site: a counter
`piggy.agent.<op>.<result>:1|c` and a timer
`piggy.agent.<op>.duration:<ms>|ms`, both carrying DogStatsD-style
`#op:<op>,result:<result>` tags. `<op>` is the agent message type
(`sign`, `request_identities`, `lock`, `unlock`) or, for extensions, the
sanitized extension name (`ecdh@joyent.com` → `ecdh_joyent_com`);
`<result>` is `success`/`failure`. Host resolution follows
stats-me-clients(7): `STATSD_HOST` (empty → `127.0.0.1`) and
`STATSD_PORT` (default `8125`). The shared Rust emitter is
`crate::stats` (`crates/piggy/src/stats.rs`); the C side mirrors it in
`stats_send` / `agent_stats_op_done`. In the C agent the prompt-driven
ops (sign/ecdh/rebox/prehash) complete inside `after_prompt_reap`, so
emission is guarded by a per-request `se_stats_done` flag to count each
request exactly once as control unwinds back through `process_message`.

Beyond the per-request `piggy.agent.<op>` surface, the Rust side also
emits (all via the same `crate::stats` module, same wire shape):
`piggy.pass.<cmd>` for every user-facing `pass` subcommand
(`show`/`insert`/`edit`/`generate`/`rm`/`mv`/`cp`/`git`/`verify`/`init`/
`recipients_*`/`show_batch`, wrapped once at the `main.rs` dispatch via
`stats::timed_pass`); `piggy.box.<op>` for the Rust `piggy box`
operations (`stream_encrypt`/`stream_decrypt`/`tpl_create`/`tpl_show`,
via `stats::timed_box` in `cmd::pivy_box`); finer agent-internal events
`piggy.agent.cak` (CAK auth, #143), `piggy.agent.pin_prompt` (each
on-demand askpass prompt — a wrong-PIN retry from #142 emits twice), and
`piggy.agent.pin_cleared` (a probe-loop PIN drop, #59); and
`piggy.pass.show_batch_item` per ebox inside a `show-batch` run. The
`agent` category stays byte-identical to the C mirror (pinned by the
`payload_agent_category_is_byte_identical_to_the_c_mirror` test); the new
categories are Rust-only — the C `pivy-agent` doesn't run the CLI/box
paths.

## Debugging

### darwin CI: silent exit 126 under `env -i` with `set -euo pipefail`

On the macos-15 GitHub Actions runner, `/usr/bin/ps` (or `/usr/bin/tr`,
the bisect is inconclusive at the system level — see #100) exits 126
when invoked under a stripped environment (`env -i HOME=$HOME
PATH=/usr/bin:/bin ...`), while `/bin/echo` and other binaries from
`/bin` run fine. Linux runners don't exhibit this. Root cause is
suspected to be macOS hardened-runtime + stripped DYLD env, but not
proven; tracked at #100.

The consequence for any shell script using `set -euo pipefail`: a
pipeline like `var="$(ps ... | tr ...)"` whose RHS exits 126
propagates through pipefail, the assignment inherits 126, and `set
-e` exits the script silently with 126 — **no stderr, no failing
command shown**. This bit us in #92; the fix landed in
`contrib/piggy-askpass.sh` (commit `5b22031`) by appending `|| true`
to the pipeline.

When writing or porting a shell helper that strips its environment
or runs under launchd-style fork+exec, prefer one of:
- pin `|| true` on pipelines whose output is decorative (parent name,
  diagnostic strings); the trailing `[[ -z "$var" ]] && var="?"`
  handles the empty case
- pin specific exec paths (e.g. `command ps` invoked by absolute
  `/usr/bin/ps`) and add a diagnostic test that exercises the
  failure path explicitly

### bats + PCSC

Any bats recipe whose tests exercise pcscd (directly, via pivy-tool, or
indirectly via piggy's Rust PCSC codepath) runs under batman with
`--allow-local-binding` so the sandbox permits the local binding the
pcscd handshake needs; the `pcscd.comm` AF_UNIX socket path itself is
reachable via `fence`'s broad filesystem `allowRead`. If pcscd is
unreachable, libpcsclite reports "PC/SC system service/daemon not
available" even though `PCSCLITE_CSOCK_NAME` reached the subprocess —
the symptom looks identical to a missing pcscd; it isn't.

**batman 0.1.3 removed the older `--allow-unix-sockets` flag.** Passing
it to current batman is fatal: the wrapper does not recognize it, forwards
it to upstream bats-core, which exits "Bad command line option" before any
test runs (`total: 0`, "no plan line found"). The piggy conformance
recipes were updated to drop it (keeping `--allow-local-binding`); if a
recipe regresses with that error, the stale flag is the cause. See `just
explore-bats` for the generic `--no-sandbox` driver.

### PIV CLI dispatch (exec-to-C) + pcscd reset semantics

`piggy agent` and `piggy box` now run the **Rust** re-impls under
`crates/piggy/src/cmd/{agent,pivy_box}` (post-#57/#58: `main.rs` calls
`piggy::cmd::agent::run(...)` / `piggy::cmd::pivy_box::run(...)`). The Rust
`piggy agent` prompts for the PIN on demand via `SSH_ASKPASS` (reusing
`card_oracle::run_askpass`, which propagates `PIGGY_ASKPASS_CONTEXT`), matches
guidless piggy 2.x boxes by recipient pubkey in `handle_ecdh_rebox`, and spawns
the #59 card-presence probe loop. The re-point is a **clean cutover to the Rust
flag surface** — notably `piggy agent -i` means print-keys-and-exit, NOT C's
foreground mode; the home-manager module (`nix/hm/piggy-agent.nix`) emits Rust
flags (no `-i`, `-S` only for hex whitelists, no `-K`). C-only features (`-C`
confirm, `-K` CAK, `install-service`) stay reachable via the `piggy pivy agent`
passthrough or `package = pkgs.pivy`.

Hardware/fibby test path: the Rust agent's card-crypto is now exercisable
straight through the CLI (`piggy agent` → Rust). The fibby-backed
`zz-tests_bats/conformance/piggy_agent_pin_on_demand.bats`
(`just test-bats-conformance-agent-pin-on-demand`) drives a guidless slot-9D
decrypt through the agent with the PIN supplied on demand, baselined against the
C `pivy-agent` and held to parity by the Rust agent. The in-process
`CardEcdhOracle` test (`crates/piggy/tests/unlock_ebox_card_integration.rs`,
hardware mode `PIGGY_TEST_CARD_GUID=<guid>`; `just explore-rust-card-unlock-hw`)
remains for direct PinSession hardware validation.

pcsc-lite **refcount-shields** a co-resident
`SCardEndTransaction(SCARD_RESET_CARD)` while the victim holds its connection
open — the reset is deferred and does NOT clear another open client's PIN.
Consequence (piggy#56): the verify→op PIN-clearing race does not reproduce on
this stack regardless of binary. Probe with `just debug-lock-contention-probe`
/ `debug-reset-loop`.

### Test harness safety net for PIN prompts

Any recipe that could invoke `pivy-box`, `pivy-agent`, or any path that
might reach pivy's `assert_pin()` interactive fallback MUST set:

```sh
askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
export SSH_ASKPASS="$askpass" \
       SSH_ASKPASS_REQUIRE=force \
       DISPLAY="" \
       PIGGY_TEST_FIB_PIN=123456   # only if the recipe legitimately needs auto-unlock
```

Without these, a failed agent unlock (or any other pivy decrypt-path
error) falls through to whatever `SSH_ASKPASS` the operator's shell
inherits — typically zenity or ssh-askpass — and renders a GUI dialog
on their desktop that looks indistinguishable from a real unlock. We
had exactly this escape on 2026-04-24; see #35.

The helper script in `zz-tests_bats/helpers/piggy-test-askpass.sh`
either supplies the configured test PIN non-interactively (if
`PIGGY_TEST_FIB_PIN` is exported) or refuses with a `[piggy-test-askpass]`-
prefixed stderr banner so test logs show exactly which prompt leaked.
It NEVER prompts and NEVER touches /dev/tty.

### User-facing askpass helper

`contrib/piggy-askpass.sh` is the **user-facing** sibling to the
test-harness askpass above. Where the test askpass refuses to render
any prompt, this one renders piggy-aware context (parent process,
`PIGGY_ASKPASS_CONTEXT` env var, `[TEST]` tag heuristic) on top of
the prompt text, then reads the PIN — preferring `/dev/tty`, falling
back to `zenity` if `$DISPLAY` is set, refusing otherwise. Set in
your shell as a drop-in `SSH_ASKPASS`:

```sh
export SSH_ASKPASS="$PWD/contrib/piggy-askpass.sh"
```

Smoke-test without entering a PIN by setting `PIGGY_ASKPASS_DRY_RUN=1`
— the script emits its rendered context to stderr and exits 0
without reading. See `zz-tests_bats/conformance/piggy_askpass.bats`
for the test surface and #33 for the design discussion (notably: a
shell wrapper around zenity's `--text` was preferred over a bundled
Rust binary because zenity already accepts caller-driven decoration).
