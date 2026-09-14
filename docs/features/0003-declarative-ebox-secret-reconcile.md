---
status: experimental
date: 2026-09-14
promotion-criteria: >
  experimental → testing: circus wires `services.piggy-secrets` for the
  operator's home on nikulin and twerk (replacing eng
  `bin/bootstrap-piggy-eboxes.bash`), and one secret rotation goes through end
  to end (insert, commit, switch, one prompt, new plaintext), with the
  ciphertext absent from the krone cache after a generation upload.
  testing → accepted: two weeks with no `home-manager switch` failing or
  blocking because of it, no output deleted by it, and no lever change.
---

# Declarative ebox secret reconcile (`piggy secrets` + `services.piggy-secrets`)

## Problem Statement

A home-manager-managed home needs a few plain dotfiles whose content is a
secret kept as a piggy `.ebox`: ssh `config-user-secret` and
`known_hosts`, smith's `keys.json`, and a nix access-token env file. Today
eng's `bin/bootstrap-piggy-eboxes.bash` produces them. It runs by hand or
from `provision.sh`, reads a writable store at a fixed path, and decides
freshness by mtime. eng is being folded into circus and rcm is retiring,
so that script has no home. The replacement must not bring back the two
failures already paid for. First, a locked or absent card must never block
or fail an unrelated home switch (eng FDR-0004). Second, no generation log
may delete outputs that another run is supposed to recreate (circus#178).

## Interface

The feature has two parts, both in piggy.

### 1. `piggy secrets reconcile` (CLI)

    piggy secrets reconcile [--manifest FILE] [--check] [--adopt] [-v] [--frontend tty|jsonrpc] [--socket PATH]

- `--manifest FILE` is a JSON manifest (schema below). It defaults to
  `$XDG_STATE_HOME/piggy/secrets/manifest.json`, which the home-manager
  module keeps as a GC-root symlink.
- Each entry names a ciphertext file (`ebox`, any path, normally a
  `/nix/store` path), an absolute `target`, a `mode` (default `0600`) and
  an `adopt` flag.
- **Freshness is keyed by content, not mtime.** An entry is fresh when
  both of these hold:
  - its target is recorded in `$XDG_STATE_HOME/piggy/secrets/state.json`
    and still matches the recorded stat fingerprint (dev, inode, size,
    mode, mtime; a regular file);
  - the recorded SHA-256 of the ciphertext matches the current `ebox`.

  mtime can't be the key: nix-store files have mtime 1. The state file
  stores no plaintext digest, because a hash of a low-entropy token is an
  offline guessing oracle.
- **Classification is offline.** It reads the ciphertext and `lstat`s the
  targets, and never touches PC/SC. A steady-state run needs no card and no
  PIN.
- **One PIN per batch.** Every entry that needs a write is decrypted in a
  single unlock session through the backend `pass show-batch` uses:
  - Card first: the first attached card whose 9D slot matches, holding one
    PIN session.
  - Otherwise the agent at `PIGGY_AUTH_SOCK`, falling back to
    `SSH_AUTH_SOCK`.
  - The PIN comes through `SSH_ASKPASS` (or the RFC 0006 `--frontend`).

  An ebox that doesn't parse fails on its own. A batch-fatal failure (PIN
  exhausted, card removed) marks the entries after it as not attempted.
- **Writes are atomic and never delete first.** The plaintext goes to a
  mode-`0600` temp file in the target's own directory, which is chmodded to
  `mode`, fsynced, then `rename(2)`d over the target. The rename replaces a
  symlink rather than following it. Only after that is the state entry
  recorded. If any step fails, the previous target is left as it was.
- **Ownership is explicit.** reconcile writes a target only when one of
  these holds:
  - the target is absent;
  - it is recorded as piggy's (stale, or edited since it was written);
  - the entry has `adopt` (or `--adopt` was passed) and the target is an
    unrecorded file or symlink.

  Anything else, including a directory, is a conflict (`not ok`) and is
  left alone, with no prompt.
- **It never deletes outputs.** When a recorded target leaves the
  manifest, its state record is dropped and the file stays. The report
  shows it as `# SKIP orphaned: released; file kept`.
- `--check` classifies entries and reports drift (`would write (missing|
  stale|modified|adopt)`) without decrypting or writing anything.
- Output is TAP-14: one point per entry and then one per orphan. Fresh
  entries are `# SKIP up to date`. Failures and drift carry a YAML
  diagnostic, and `-v` adds one to every point.

  | Exit | Meaning |
  |---|---|
  | 0 | every entry fresh or written |
  | 1 | any failure or conflict, or (under `--check`) any drift |
  | 2 | usage error, or an unreadable manifest or state file |

  An unreadable state file is never replaced with an empty one, since that
  would silently forget what piggy owns.

Manifest (`version` 1; unknown fields are rejected):

    { "version": 1,
      "entries": [
        { "name": "smith-keys",
          "ebox": "/nix/store/…-piggy-secrets-smith-keys.ebox",
          "target": "/home/u/.local/share/smith/keys.json",
          "mode": "0600",
          "adopt": false } ] }

`name` must match `[A-Za-z0-9._-]+`. Names and targets must be unique, and
targets must be absolute file paths.

### 2. `homeManagerModules.piggy-secrets` (option `services.piggy-secrets`)

    services.piggy-secrets = {
      enable       = true;
      package      = piggy.packages.${system}.piggy;   # mkPackageOption
      files.<name> = {
        source = ./piggy-store/rcm/local/share/smith/keys.json.ebox;   # types.path
        target = ".local/share/smith/keys.json";   # home-relative or absolute
        mode   = "0600";                           # default
        adopt  = false;                            # default
      };
      agentSocket  = …;        # default: services.piggy-agent.resolvedSocketPath if that module is enabled, else null
      askpass      = …;        # default: "${package}/libexec/piggy/piggy-askpass.sh"
      onActivation = "start";  # "start" | "check" | "none"
    };

Read-only outputs: `storeNamePrefix` (`"piggy-secrets-"`) and
`manifestFile` (the manifest's store path, as a string without context).

What the module does:

- **Store names.** Every store path it creates has a name (the part after
  `<hash>-`) starting with `piggy-secrets-`:
  `piggy-secrets-<name>.ebox` for each ciphertext copy and
  `piggy-secrets-manifest.json` for the manifest. This prefix is a stable
  contract, so a binary-cache uploader can exclude on it.
- **Keeping secrets material out of the closure.** The ciphertext copies
  (`builtins.path`) and the manifest (`builtins.toFile`) are added to the
  local store at evaluation time. They are referenced only as strings
  without context, so they are **not store references** of the home
  generation, and `nix copy` of the generation never carries them.
  Activation keeps them alive with per-user GC roots:
  `$XDG_STATE_HOME/piggy/secrets/manifest.json` and
  `…/gcroots/<name>.ebox` (`nix-store --add-root`). Roots for entries that
  have been removed are pruned.
- **Unit.** A systemd user unit, `piggy-secrets.service` (`Type=oneshot`),
  runs `piggy secrets reconcile` against the rooted manifest. It sets
  `PIGGY_AUTH_SOCK`, `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force` in
  `Environment=`. There is no `WantedBy`, so no login-time run (an operator
  decision), and no `Restart=`.
- **Activation.** A `home.activation.piggySecrets` step runs after
  `writeBoundary` and `reloadSystemd`. It always refreshes the GC roots
  (skipped under `DRY_RUN`), then:
  - `"start"`: runs `reconcile --check` and, on drift, starts the unit with
    `systemctl --user start --no-block`;
  - `"check"`: prints the hint only;
  - `"none"`: runs no check.

  Every command's failure is caught. A switch never waits on a PIN and
  never fails because of this step.

A NixOS re-export, `nixosModules.piggy-secrets`, puts the module into
`home-manager.sharedModules`, following the piggy-agent pattern.

## Examples

Circus consumer:

    services.piggy-secrets = {
      enable = true;
      package = inputs.piggy.packages.${system}.piggy;
      files = {
        ssh-config-user-secret = {
          source = ./piggy-store/rcm/config/ssh/rcm/config-user-secret.ebox;
          target = ".config/ssh/rcm/config-user-secret";
          adopt = true;           # take over the file the bash bootstrap wrote
        };
        secrets-nix-env = {
          source = ./piggy-store/circus/secrets-nix.env.ebox;
          target = ".config/nix/secrets.env";
          adopt = true;
        };
      };
    };

Steady state. The switch prints nothing and no card is touched:

    $ piggy secrets reconcile
    TAP version 14
    1..2
    ok 1 - secrets-nix-env # SKIP up to date
    ok 2 - ssh-config-user-secret # SKIP up to date

Rotation. There is one askpass prompt, and it comes from the unit, not the
switch:

    $ home-manager switch …
    piggy-secrets: secret files need reconciling; started piggy-secrets.service
    $ journalctl --user -u piggy-secrets
    ok 1 - secrets-nix-env

Locked card and no agent. The old file stays:

    not ok 1 - secrets-nix-env
      ---
      message: "no attached PIV card has a 9D slot matching any of the ebox's recipients; and no agent fallback available (…)"
      target: "/home/u/.config/nix/secrets.env"
      ...

## Limitations

- **The generation must be evaluated on the host that activates it.** The
  ciphertext and manifest are outside the closure, so a generation built
  elsewhere and copied in arrives without them. Activation then reports it
  can't root them and the check exits 2. The switch still succeeds, but no
  secrets are written. The same happens if a GC runs between evaluation and
  activation, which is a narrow window.
- **Bumping piggy can be a long local build.** The default `askpass` pulls
  piggy's own nixpkgs closure into the home, including zenity with its
  gstreamer/pipewire dependencies. A host that can't substitute those
  builds them from source; the first nikulin switch took about 45 minutes.
  Consumers should push piggy's input closure to their binary cache before
  deploying a bump.
- **The PIN prompt depends on the user manager's environment.** The unit
  inherits `systemd --user`'s environment. `piggy-askpass.sh` re-derives a
  missing display from `systemctl --user show-environment` or
  `$XDG_RUNTIME_DIR/wayland-*` (piggy#179). A session whose compositor
  never publishes either gets no dialog, and that entry fails with
  `pin-cancelled`.
- **Whole files only.** No key extraction from structured documents.
- **User-scope secrets only.** Outputs belong to the reconciling user.
  Root and system secrets are out of scope.
- **No `restartUnits`.** Consumers that read a secret only at startup are
  not restarted when it rotates.
- **Linux systemd user units only.** darwin (a launchd agent) comes when a
  live darwin host exists. Without `systemctl`, `"start"` degrades to the
  printed hint.
- **Headless hosts decrypt only while a card-backed agent is reachable.**
  On such hosts that agent is the forwarded one behind a proxy-only
  piggy-agent (FDR 0001).
- **The ciphertext in the store reveals some metadata** (recipients, names,
  sizes) to local users, but no plaintext.
- **`piggy pass` authoring is separate.** Where the writable store lives
  matters only to `pass insert`/`edit`. reconcile reads only manifest paths.
- **This supersedes the unmerged `piggy.secrets` module** (branch
  `claude/nix-sops-piggy-eboxes-QI46P`, fc9aac3). That module:
  - decrypted during activation under `set -e`, so a locked card failed the
    switch;
  - put its outputs in `$XDG_RUNTIME_DIR` behind symlinks;
  - pruned a whole generation on every switch;
  - prompted for a PIN once per file.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| `onActivation` default | `start` (no-block) | rotation lands without a manual step, and the switch never waits | prompts at surprising moments; move to `check` |
| login-time run | none | operator decision: no PIN prompt before the desktop is up | missing outputs after fresh logins go unnoticed |
| default `mode` | `0600` | matches the bash bootstrap | a consumer needs group read |
| freshness fingerprint | ciphertext SHA-256 + (dev, inode, size, mode, mtime) | detects both rotation and local edits | restores that change inodes cause spurious re-decrypts |
| orphan handling | release, keep the file | never delete (circus#178) | stale secrets pile up; add `--prune` |

## More Information

- eng FDR-0004 (relocated), "RCM Piggy Ebox Decryption Hook": why the
  decrypt moved off every rcup, and the circus#178 lesson.
- piggy RFC 0005 (`pass show-batch`): the batch unlock backend, shared
  through `show_batch::with_batch_unlock`. RFC 0006 covers `--frontend`.
- FDR 0001: the proxy-only agent that `agentSocket` resolves to on
  headless hosts.
- Code: `crates/piggy/src/secrets.rs`, `nix/hm/piggy-secrets.nix`,
  `nix/nixos/piggy-secrets.nix`.
- Tests: `nix/hm/secrets-eval-test.nix` (`just test-nix-hm-secrets-module`)
  and `zz-tests_bats/conformance/piggy_secrets_reconcile_fibby.bats`
  (`just test-bats-conformance-secrets-reconcile-fibby`).
- circus `docs/plans/2026-09-14-eng-into-circus.md`, slice S3b: the
  consumer.
