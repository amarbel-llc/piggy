# Rust Rewrite Design: pivy-agent

## Motivation

Rewrite pivy-agent in Rust for memory safety, maintainability, and future feature development. The C codebase (~47k lines) handles sensitive crypto material and PIN storage; Rust's ownership model eliminates buffer overflows and use-after-free in security-critical paths. The complex Makefile, embedded OpenSSH, and platform ifdefs make the C code hard to modify. Cargo and the Rust crate ecosystem will simplify building and extending.

## Scope

**MVP: pivy-agent only.** The most critical daily-use binary. Other tools (pivy-tool, pivy-box, pivy-ca, pivy-zfs, pivy-luks, pam_pivy) deferred to later phases. The pivy-piv library crate is designed to support them when ready.

## Approach

Hybrid: use `ssh-agent-lib` for SSH agent protocol handling, custom PIV layer built on `pcsc` crate for smartcard interaction. Pure Rust for SSH key types and crypto. `openssl` crate only for X.509 cert parsing.

## Crate Structure

```
pivy/
  Cargo.toml          # workspace root
  crates/
    pivy-piv/         # PIV smartcard library
    pivy-agent/       # SSH agent binary
    pivy-common/      # Shared types: errors, logging, utils
  flake.nix           # Nix build
```

### pivy-piv (PIV smartcard library)

Replaces: piv.c, piv.h, piv-internal.h, tlv.c, piv-apdu.c, piv-chuid.c, piv-fascn.c, piv-cardcap.c, piv-certs.c, slot-spec.c, utils.c

```
pivy-piv/src/
  lib.rs
  context.rs     # PivContext: wraps pcsc::Context, enumerate readers/tokens
  token.rs       # PivToken: represents one PIV card, manages transactions
  slot.rs        # PivSlot: key slot (9a, 9c, 9d, 9e, 82-95) with cert + pubkey
  apdu.rs        # APDU builder/parser for PIV commands
  tlv.rs         # TLV encoder/decoder
  crypto.rs      # Sign, ECDH operations dispatched to card via APDU
  cert.rs        # X.509 cert parsing from card slots (uses openssl crate)
  guid.rs        # GUID type (16-byte PIV card identifier)
  error.rs       # PivError enum with thiserror
  pin.rs         # Secure PIN storage with guard pages + zeroize
```

Key design:
- `PivContext` owns `pcsc::Context`, provides `enumerate() -> Vec<PivToken>`
- `PivToken` wraps `pcsc::Card` with transaction management (begin/end)
- All operations return `Result<T, PivError>`
- PIN stored in mmap'd memory with guard pages (same as C version)
- Supports YubiKey extensions and generic PIV cards

### pivy-agent (SSH agent binary)

Replaces: pivy-agent.c

```
pivy-agent/src/
  main.rs        # CLI parsing (clap), daemon setup, signal handling
  agent.rs       # Implements ssh-agent-lib's Agent trait
  config.rs      # Optional TOML config file support (alongside CLI flags)
  card.rs        # Card management: probe, open, enumerate, CAK verify
  signing.rs     # Dispatches sign requests to the right card/slot
  confirm.rs     # SSH_CONFIRM / connection confirm mode
  askpass.rs     # SSH_ASKPASS integration for PIN prompts
```

Core Agent trait implementation:
- `request_identities()` -> enumerate card slots, return public keys
- `sign()` -> find matching slot, open transaction, PIN if needed, sign via card
- `lock()`/`unlock()` -> PIN management (ssh-add -x / ssh-add -X)
- `extension()` -> session-bind and other SSH extensions

### pivy-common (shared types)

```
pivy-common/src/
  lib.rs
  error.rs       # Common error types
```

## Dependencies

| Crate | Purpose | Replaces |
|-------|---------|----------|
| `ssh-agent-lib` | SSH agent protocol | OpenSSH agent.c protocol |
| `ssh-key` | SSH key types | openssh/sshkey.h |
| `ssh-encoding` | SSH wire encoding | openssh/sshbuf.h |
| `pcsc` | PC/SC smartcard communication | winscard.h/pcsclite |
| `p256`, `p384` | ECDSA operations | libcrypto EC |
| `rsa` | RSA operations | libcrypto RSA |
| `openssl` | X.509 cert parsing only | libcrypto X.509 |
| `clap` | CLI argument parsing | getopt |
| `tracing` | Structured logging | bunyan.c |
| `tokio` | Async runtime | poll() event loop |
| `zeroize` | Secure memory clearing | explicit_bzero |
| `thiserror` | Error derive macros | errf.c |

## CLI Compatibility

Preserved flags:
- `-g <GUID>` -- target specific card
- `-A` -- all-card mode (enumerate all plugged-in PIV cards)
- `-K <pubkey>` -- CAK verification key
- `-C` / `-CC` -- confirm mode (forwarded only / all connections)
- `-a <path>` -- bind to specific socket path
- `-d` / `-D` / `-i` -- debug verbosity levels
- `-S <slotspec>` -- slot filter
- `-k` -- kill existing agent
- `-s` / `-c` -- sh/csh output format
- `-m` -- allow signing with 9D slot

New additions:
- `--config <path>` -- optional TOML config file
- `--json-log` -- structured JSON log output

Socket paths: same `$TMPDIR/ssh-XXXX/agent.<pid>` convention.
Environment variables: `SSH_AUTH_SOCK`, `SSH_AGENT_PID`.
Systemd/launchd service files: same template with `@@BINDIR@@` substitution.

## Nix Build

- Use `crane` for Rust Nix builds
- Dev shell from `devenvs/rust`
- `buildInputs`: openssl.dev, pcsclite.dev (Linux), zlib
- Same LD_PRELOAD wrapper for system pcsclite on non-NixOS
- Install systemd/launchd service files as in C version

## Key Behaviors to Preserve

1. **Card probing**: Periodic background probing with backoff on failure
2. **PIN security**: Guard-page protected memory, mlockall, MADV_DONTDUMP
3. **Transaction management**: Open/close PCSC transactions around card operations with timeout
4. **CAK verification**: Verify card identity via 9E slot signature before trusting
5. **Multi-card mode (-A)**: Discover and cache certs from all tokens
6. **Confirm mode (-C/-CC)**: Prompt via SSH_CONFIRM for forwarded/all connections
7. **Lock/unlock (ssh-add -x/-X)**: PIN caching with lock password
8. **Peer credential checking**: getpeereid/SO_PEERCRED for UID authorization
9. **Parent process monitoring**: Exit when parent shell dies (when run as `pivy-agent bash`)
10. **Fork behavior**: Fork to background on Linux, foreground-only on macOS (PCSC limitation)
