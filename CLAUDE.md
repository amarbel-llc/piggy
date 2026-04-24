# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Piggy is a passwordstore.org fork that replaces GPG encryption with PIV smart card encryption via pivy-box and ebox templates. Secrets are encrypted to YubiKey PIV slot 9D (Key Management/ECDH) instead of GPG keys. Decryption works transparently over SSH agent forwarding.

## Build & Test Commands

```sh
just build          # Build nix package (nix build --show-trace)
just test           # Run bats test suite
just codemod-fmt    # Format nix (nixfmt) and shell (shfmt -s -i=2)
just clean          # Remove build artifacts
```

Run a single bats test file:
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

**Single-script CLI** — the entire tool is `src/piggy.sh` (~800 lines of bash). It implements all passwordstore.org commands (init, show, insert, edit, generate, rm, mv, cp, find, grep, git) with pivy-box as the crypto backend.

**Crypto layer:**
- Encrypt: `pivy-box stream encrypt <template> < plaintext > file.ebox`
- Decrypt: `pivy-box stream decrypt < file.ebox > plaintext`
- Templates (`.pivy-id` files) replace `.gpg-id` for recipient management
- Encrypted files use `.ebox` extension instead of `.gpg`

**Platform abstraction** — `src/platform/darwin.sh` overrides clipboard (pbcopy/pbpaste), tmpdir (ramdisk via hdid), and getopt resolution for macOS. Linux uses defaults from the main script.

**Test framework** — BATS (Bash Automated Testing System) in `zz-tests_bats/`. Tests use mock scripts (`helpers/mock-pivy-box.sh`, `helpers/mock-pivy-tool.sh`) that substitute base64 for real encryption, so no physical PIV card is needed.

## Key Files

- `src/piggy.sh` — main script: env setup, helpers, all command implementations, dispatch
- `src/platform/darwin.sh` — macOS platform overrides
- `zz-tests_bats/common.bash` — bats test harness (mock PATH, temp store, git identity)
- `zz-tests_bats/helpers/mock-pivy-box.sh` — mock pivy-box using base64 encode/decode
- `flake.nix` — nix package definition and dev shell
- `go/main.go` — Go SSH agent conformance test binary (protocol wire format validation)
- `zz-tests_bats/conformance/piggy_agent_protocol.bats` — bats harness for protocol conformance
- `contrib/emacs/piggy.el` — Emacs integration package

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

- Bash: `set -o pipefail`, `[[ ]]` conditionals, all variables quoted
- Functions: `cmd_*` for user-facing commands, lowercase_with_underscores for helpers
- Shell formatting: `shfmt -s -i=2` (2-space indent, simplified)
- Nix formatting: `nixfmt-rfc-style`

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
