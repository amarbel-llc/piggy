# Plan: `piggy.secrets` nix module (sops-nix-shaped, ebox-backed)

Status: implemented 2026-06-05 on branch
`claude/nix-sops-piggy-eboxes-QI46P`.

## Motivation

[sops-nix](https://github.com/Mic92/sops-nix) gives Nix users a
declarative `sops.secrets.<name>` surface: encrypted secret files live in
the repo / store, and at activation each is decrypted to a runtime
location with the requested owner/mode, behind an atomically-swapped
symlink so consumers never observe a half-written secret.

Piggy already encrypts secrets to PIV keys as `.ebox` files (the password
store). What was missing was the *declarative-deployment* half: a way to
say "decrypt these eboxes into my runtime tree on `home-manager switch`"
the way sops-nix does for age/GPG envelopes. This module is that surface,
backed by piggy eboxes instead of sops.

## Why home-manager, not a NixOS/system activation

sops-nix's headline is a *system* (NixOS) module that decrypts at boot
using host keys (age/SSH) available offline. Piggy decryption is
fundamentally **PIV-interactive**: it needs the YubiKey present and a PIN,
surfaced through the piggy-agent / SSH-agent socket. A root boot-time
activation has neither card nor agent, so decrypting there can't work.

The honest home for ebox decryption is the user's **interactive session**,
where the agent lives and the card can be touched — i.e. `home-manager
switch`. So the canonical surface is a home-manager module
(`homeManagerModules.piggy-secrets`), and the NixOS module
(`nixosModules.piggy-secrets`) is a thin re-export that wires it into
`home-manager.sharedModules` — identical to the decision already made for
`services.piggy-agent` (OQ4 in
`docs/plans/2026-04-27-piggy-agent-nix-module.md`).

## Option surface

Top-level `piggy` namespace (parallel to `services.piggy-agent`):

- `piggy.package` — provides `bin/piggy` for `piggy box stream decrypt`.
  `mkPackageOption pkgs "piggy"`.
- `piggy.secretsDir` — generation root (default
  `$XDG_RUNTIME_DIR/piggy-secrets.d`); tmpfs so plaintext never hits disk.
- `piggy.symlinkPath` — stable symlink to the current generation (default
  `$XDG_RUNTIME_DIR/piggy-secrets`). This is the path consumers hard-code.
- `piggy.agentSocket` — exported as `PIGGY_AUTH_SOCK` for the decrypt
  child so decrypts route at piggy-agent (advertises `ecdh@joyent.com`)
  rather than an ssh-agent-mux that may drop it (#123). `null` ⇒ inherit
  ambient `SSH_AUTH_SOCK`.
- `piggy.askpass` — exported as `SSH_ASKPASS` (+`REQUIRE=force`) for the
  local-card PIN fallback when activation has no usable tty (#35).
- `piggy.secrets.<name>` submodule:
  - `eboxFile` (`types.path`, required) — encrypted source, copied into
    the store as ciphertext (safe — an ebox is encrypted to its PIV
    recipients, mirroring how sops commits encrypted files).
  - `name` — published basename (default: attr name).
  - `mode` — `chmod` bits on the decrypted file (default `0400`).
  - `path` — where it's reachable (default `${symlinkPath}/${name}`);
    custom paths get a back-pointing symlink.

## Decryption

`piggy box stream decrypt` (the Rust `cmd::pivy_box` impl, #57) is the
decrypt engine: it reads the ebox on stdin, honors `PIGGY_AUTH_SOCK`,
builds an `AgentEcdhOracle` (agent-first) and a `CardEcdhOracle`
(local-card fallback), and writes plaintext to stdout. The module pipes
each `eboxFile` in and captures stdout into `$GEN/<name>` under `umask
0077`, then `chmod`s to the requested mode. Plaintext never crosses argv.

## Activation shape (atomic swap, sops-nix parity)

```
mkdir -p -m 0700 $MOUNT
GEN=$(mktemp -d $MOUNT/gen.XXXXXX)
# decrypt each secret into $GEN/<name>, chmod
ln -sfn $GEN $SYMLINK          # single-rename atomic flip
# custom-path secrets: ln -sfn $SYMLINK/<name> <path>
# prune every $MOUNT/gen.* except $GEN
```

`set -eu` + an `ERR` trap mean a failed decrypt (no card, wrong PIN,
missing recipient) aborts loudly and leaves the previous generation's
symlink untouched — a stale-but-consistent secret set beats a
half-written one. The activation is sequenced
`entryAfter [ "writeBoundary" ]`, built as a `{ data; before; after; }`
literal so the module also evaluates under the bare-lib eval-test harness
(which lacks `lib.hm`).

## Out of scope (future work)

- **Structured key extraction.** sops extracts individual keys from
  YAML/JSON documents. Piggy eboxes are opaque whole-file blobs (the
  `piggy show` model), so this module is whole-file only. Per-key
  extraction would need an ebox-of-structured-doc convention first.
- **Arbitrary-owner system secrets.** Owner is always the activating user
  (files live in that user's `$XDG_RUNTIME_DIR`). True multi-user system
  secrets would need the boot-time-decrypt story PIV can't provide.
- **`restartUnits` / reload triggers.** sops-nix restarts units when a
  secret changes. Deferred; can be layered on `home.activation` ordering.

## Tests

`nix/hm/secrets-eval-test.nix` (run via `just test-nix-hm-secrets-module`)
drives `lib.evalModules` over synthetic configs and asserts on the option
schema + rendered activation text: decrypt-command shape, the atomic
symlink flip, default-vs-custom path linking, `mode` threading, custom
`name`, and the `PIGGY_AUTH_SOCK` / `SSH_ASKPASS` env preludes
(bash-expandable, not single-quoted — the #63 lesson). No card / agent /
real home-manager required.
