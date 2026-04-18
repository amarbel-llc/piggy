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

## Code Conventions

- Bash: `set -o pipefail`, `[[ ]]` conditionals, all variables quoted
- Functions: `cmd_*` for user-facing commands, lowercase_with_underscores for helpers
- Shell formatting: `shfmt -s -i=2` (2-space indent, simplified)
- Nix formatting: `nixfmt-rfc-style`

## Environment Variables

User config is via `PIGGY_*` env vars (store dir, clip time, generated length, character set, etc.) — defaults are set at the top of `src/piggy.sh`. `PIGGY_STORE_DIR` defaults to `~/.local/share/piggy`.
