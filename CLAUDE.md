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

**Rust-on-top, bash-on-back CLI** — top-level argv parsing is a Rust `clap` subcommand tree in `crates/piggy/src/main.rs`. Password-management commands live as nested subcommands under a top-level `pass` namespace. Each `pass <X>` is dispatched in one of two ways:

- **Pure Rust handlers** (no bash hop): `find`, `grep`, `git`, `rm`, `verify`, `recipients list`, `recipients list-available`. Implemented in `crates/piggy/src/{find,grep,git,rm,verify,recipients}.rs`. Shared substrate (store walk, sneaky-path check, git ops) in `store.rs` and `git_ops.rs`. See umbrella #96 for the ongoing port; the `piggy pass *` map there tracks the current state.
- **Bash dispatch** (`fallback::exec_bash` / `exec_bash_subcmds` `exec(2)` into `src/piggy.sh`): `init`, `show`, `insert`, `edit`, `generate`, `mv`, `cp`, `recipients add`/`remove`/`sync`. These keep their `cmd_*` functions in `piggy.sh`. The bash subprocesses receive `$PIGGY_BIN=current_exe()` so any helper that needs to call back into Rust (currently only `reencrypt_path`, which exec's the hidden `piggy internal-reencrypt-path <dir>` subcommand) has an absolute path to the same binary.

`piggy help` and `piggy version` stay top-level and dispatch into `cmd_usage`/`cmd_version` directly. `piggy.sh` is installed under `$out/libexec/piggy/`, not on `$PATH`; the Rust dispatcher reaches it via `PIGGY_SH_PATH` baked in by `flake.nix`'s makeWrapper. The remaining top-level clap handlers (`agent`, `box`, `tool`, `ca`, `luks`, `zfs`, and the generic `piggy pivy <tool>` passthrough) `exec(2)` into the matching C `pivy-*` binary via `fallback::exec_pivy`. Top-level dispatch is exhaustive in clap; `fallback.rs` has no catch-all bash branch. Bare `piggy` and bare `piggy pass` print clap help (no implicit `cmd_show ""`).

Rust re-implementations of `agent` and `box` live under `crates/piggy/src/cmd/{agent,pivy_box}` (reachable via the `piggy::cmd` library surface) but stay off the user-facing dispatch path in v1.0. They will be re-pointed at once they reach feature parity with the C binaries; see #56 (PC/SC transactions in `piggy-piv`), #57 (direct-PCSC ECDH oracle for `piggy box stream decrypt`), #58 (askpass `[piggy-test]` context tagging), and #59 (probe-loop PIN-clearing in `piggy agent`) for the maturation roadmap.

**Known v1 acceptance**: the Rust `pass git` port (commit `03fb0ca`) does not allocate a ramdisk before exec-ing git on the non-init passthrough path. Bash `cmd_git` called `tmpdir nowarn` to set `$TMPDIR=$SECURE_TMPDIR`; the Rust port forwards `$SECURE_TMPDIR` to git as `$TMPDIR` if already set in the environment but does not create one itself. Documented inline in `crates/piggy/src/git.rs`; restored once umbrella #96 step 9 (Rust platform layer) lands.

**Crypto layer:**
- Encrypt: `pivy-box stream encrypt <template> < plaintext > file.ebox`
- Decrypt: `pivy-box stream decrypt < file.ebox > plaintext`
- Templates (`.pivy-id` files) replace `.gpg-id` for recipient management
- Encrypted files use `.ebox` extension instead of `.gpg`

**Platform abstraction** — `src/platform/darwin.sh` overrides clipboard (pbcopy/pbpaste), tmpdir (ramdisk via hdid), and getopt resolution for macOS. Linux uses defaults from the main script.

**Test framework** — BATS (Bash Automated Testing System) in `zz-tests_bats/`. Tests use mock scripts (`helpers/mock-pivy-box.sh`, `helpers/mock-pivy-tool.sh`) that substitute base64 for real encryption, so no physical PIV card is needed.

**Bats lane builder** — `bats.nix` wraps `bats.lib.${system}.batsLane` (the canonical builder exposed by the `amarbel-llc/bats` flake; the nixpkgs-overlay-provided `pkgs.testers.batsLane` is no longer used and was retired with the bats flake split). Two scan roots: top-level `zz-tests_bats/t*.bats` AND `zz-tests_bats/conformance/*.bats`. `# bats file_tags=` directives in either root are auto-discovered, producing one `bats-<tag>` derivation per unique tag plus `bats-default`. The default lane filter is `!hardware`: tests tagged `# bats file_tags=hardware` (currently `t0610-recipients-add-attached.bats`, `conformance/piggy_box_interop.bats`, `conformance/piggy_box_decrypt_interop.bats`, `conformance/piggy_recipients_add_attached.bats`, `conformance/pivy_agent_hardware.bats`, `explore/explore_local_guid_pcsc.bats`) are excluded from `bats-default` because they need a real pcscd talking to fib or hardware, which can't run inside the nix build sandbox. Those tests stay invoked via the existing `just test-bats-conformance-*` recipes. Non-hardware conformance tests (`piggy_askpass.bats`, `piggy_pivy.bats`, `piggy_agent_protocol.bats`) run under both the sandboxed lane AND the `just test-bats-conformance` recipe. The dual-coverage is intentional (piggy#117): `nix build .#bats-default` is the authoritative CI gate (stronger isolation — sandboxed HOME, no pivy-agent leak path), while the just recipe stays as an ergonomic paved path (no nix build overhead, fast iteration, works without per-invocation user permissions for both humans and agents). `zz-tests_bats/explore/` is intentionally not scanned. The wrapped piggy is injected into the lane via the `binaries` map (`PIGGY=${piggy}/bin/piggy`); `CONFORMANCE_BIN` is similarly threaded for `piggy_agent_protocol.bats`; `PIGGY_SH_PATH` / `PIGGY_IDS_REAL` are pinned at the wrapped `$out/libexec/piggy/` via `extraEnv`.

## Key Files

- `crates/piggy/src/main.rs` — clap subcommand tree; top-level dispatch.
- `crates/piggy/src/fallback.rs` — `exec_bash(subcmd, rest)` + `exec_bash_subcmds(subcmd, op, rest)` (pass-style handlers still in bash) + `exec_pivy(tool, rest)` (C-pivy handlers + `piggy pivy <tool>` passthrough) + `exec_piggy_ids(subcmd, rest)`. All bash-bound exec paths forward `$PIGGY_BIN=current_exe()` so bash helpers can call back into Rust.
- `crates/piggy/src/{verify,find,grep,git,rm,recipients,reencrypt}.rs` — Rust handlers for the pass-style subcommands that have moved off the bash dispatch path.
- `crates/piggy/src/store.rs` — shared store helpers: `store_root` (`$PIGGY_STORE_DIR > $XDG_DATA_HOME/piggy > $HOME/.local/share/piggy`), `resolve_target` (sneaky-path check), `collect_eboxes` (the canonical `find -L $PREFIX -path '*/.git' -prune -o -iname '*.ebox'` walk), `find_piggy_ids` (walk-up-from-subfolder).
- `crates/piggy/src/git_ops.rs` — shared git helpers: `find_inner_git_dir` (mirrors `set_git`), `add_and_commit`, `commit`, `rm`, `is_inside_work_tree`, `signing_flag`, `git_at`.
- `src/piggy.sh` — bash command bodies for the still-bash pass-style subcommands (init, show, insert, edit, generate, mv, cp, recipients add/remove/sync). Installed under `$out/libexec/piggy/`, not on `$PATH`; reached via `PIGGY_SH_PATH` baked in by `flake.nix`'s makeWrapper.
- `src/platform/darwin.sh` — macOS platform overrides (sourced by `piggy.sh` at runtime).
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
- `just check-rust -p <crate>` instead of `cargo check --package <crate>`
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

User config is via `PIGGY_*` env vars (store dir, clip time, generated length, character set, etc.) — defaults are set at the top of `src/piggy.sh`. `PIGGY_STORE_DIR` defaults to `~/.local/share/piggy`.

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
indirectly via piggy's Rust PCSC codepath) MUST invoke bats with
`--allow-unix-sockets --allow-local-binding`. Without those flags,
batman's sandbox blocks the Unix-domain socket connection to
`pcscd.comm` and libpcsclite reports "PC/SC system service/daemon not
available" — even though `PCSCLITE_CSOCK_NAME` reaches the subprocess.
The symptom looks identical to a missing pcscd; it isn't. This is a
batman property (not piggy-specific), but it bites here often enough to
warrant a local note. See `just explore-bats` for the generic driver
that always sets the flag correctly.

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
