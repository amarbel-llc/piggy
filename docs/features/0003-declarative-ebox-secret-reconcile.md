---
status: proposed
date: 2026-09-14
promotion-criteria: >
  proposed → experimental: `piggy secrets reconcile` and
  `homeManagerModules.piggy-secrets` land, with an eval-test for the module
  and a fibby-backed bats lane that covers a one-PIN batch, a no-op
  steady state (no card touched), a locked card that leaves existing
  outputs byte-identical, and the ownership refusal on an unrecorded file.
  experimental → testing: circus wires it for the operator's home on
  nikulin and twerk (replacing eng `bin/bootstrap-piggy-eboxes.bash`), and
  one secret rotation goes through end to end (insert, commit, switch, one
  prompt, new plaintext).
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

The design has two parts. Piggy owns both.

### 1. `piggy secrets reconcile` (CLI)

    piggy secrets reconcile [--manifest FILE] [--check] [--adopt] [--frontend tty|jsonrpc] [-v]

- `--manifest FILE` is a JSON manifest (schema below). It defaults to
  `$XDG_CONFIG_HOME/piggy/secrets.json`, which the home-manager module
  installs.
- Each entry names a ciphertext file (`ebox`, any path, normally a
  `/nix/store` path), a `target` (an absolute path), a `mode` (default
  `0600`) and an `adopt` flag.
- **Freshness is keyed by content, not mtime.** An entry is fresh when all
  of these hold:
  - the target is a regular file (not a symlink);
  - the target is recorded in the state file
    `$XDG_STATE_HOME/piggy/secrets/state.json`;
  - the recorded ciphertext digest matches the current `ebox`;
  - the target's recorded stat fingerprint (dev, inode, size, mtime)
    still matches.

  mtime cannot be the key: nix-store files have mtime 1, and a git
  checkout sets mtime to checkout time. The state file stores no
  plaintext digest, because a hash of a low-entropy token is an offline
  guessing oracle.
- **The fast path is offline.** Classifying entries reads only the
  ciphertext and `stat`s the targets. It needs no card, no agent, no PIN.
  A steady-state run exits 0 without touching PC/SC.
- **One PIN per batch.** Every stale or missing entry is decrypted in a
  single unlock session through the same core that `pass show-batch` uses
  (RFC 0005). The card is tried first; when no local PC/SC card serves
  the batch, it falls back to the agent in `PIGGY_AUTH_SOCK`, else
  `SSH_AUTH_SOCK`. PIN prompts go through `SSH_ASKPASS`. There is no
  `/dev/tty` dependency.
- **Writes are atomic and never delete first.** Plaintext goes to a
  mode-`0600` temp file created with `O_EXCL` in the target's own
  directory. The file is fsynced, chmodded to `mode`, then `rename(2)`d
  over the target, and only then is the state entry recorded. If any
  step fails, the previous target stays exactly as it was. A failed
  decrypt costs only that entry.
- **Ownership is explicit.** reconcile writes to a target only when one
  of these holds:
  1. the target does not exist;
  2. the target is recorded in the state file as piggy's (whether stale
     or tampered);
  3. `adopt` is set on the entry (or `--adopt` is passed) and the target
     is an unrecorded file or symlink, such as an rcm symlink into
     `~/eng` or a file the bash bootstrap wrote. The adopted target is
     replaced once and recorded.

  An unrecorded target without `adopt` is reported as a conflict
  (`not ok`) and left alone.
- **It never deletes outputs.** An entry that leaves the manifest is
  reported as `orphaned`, and its state record is dropped. The file
  stays, and piggy no longer owns it. Removing the file is the operator's
  call.
- `--check` classifies the entries and reports `STALE`, `MISSING`,
  `CONFLICT` and `ORPHANED`. It never decrypts or writes. It exits 1 if
  any entry would change.
- Output is a TAP-14 stream: one point per entry, `# SKIP up to date` for
  fresh entries, and a YAML diagnostic on failure (and on every point
  with `-v`). This matches the `reencrypt` walk.

  | Exit | Meaning |
  |---|---|
  | 0 | every entry fresh or written |
  | 1 | a conflict, failed decrypt, or (under `--check`) any drift |
  | 2 | usage or manifest error |

Manifest (`piggy-secrets-manifest/1`):

    { "version": 1,
      "entries": [
        { "name": "ssh-config-user-secret",
          "ebox": "/nix/store/…-config-user-secret.ebox",
          "target": "/home/u/.config/ssh/rcm/config-user-secret",
          "mode": "0600",
          "adopt": false } ] }

### 2. `homeManagerModules.piggy-secrets` (option `services.piggy-secrets`)

    services.piggy-secrets = {
      enable      = true;
      package     = piggy.packages.${system}.piggy;         # mkPackageOption
      files.<name> = {
        source = ./piggy-store/rcm/config/ssh/rcm/config-user-secret.ebox;  # types.path
        target = ".config/ssh/rcm/config-user-secret";      # home-relative or absolute
        mode   = "0600";                                    # default
        adopt  = false;                                     # default; true for a cutover
      };
      agentSocket  = …;        # default: services.piggy-agent.resolvedSocketPath when that module is enabled, else null
      askpass      = …;        # default: "${package}/libexec/piggy/piggy-askpass.sh"
      onActivation = "start";  # "start" | "check" | "none"
    };

The module does the following:

- **Manifest.** It renders the manifest into the store and links it to
  `$XDG_CONFIG_HOME/piggy/secrets.json` through `xdg.configFile`. The
  manifest holds only ciphertext paths, so it is safe in the store.
  `source` is a `types.path`, so the ciphertext lands in `/nix/store`,
  which is world-readable. That is acceptable for an ebox: it is
  encrypted to its PIV recipients, as with sops-nix.
- **Unit.** It declares a systemd user unit, `piggy-secrets.service`
  (`Type=oneshot`), that runs `piggy secrets reconcile`. The unit sets
  `PIGGY_AUTH_SOCK`, `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force` in
  `Environment=`, and has `WantedBy=default.target`, so a login also
  reconciles. It has no `Restart=`: a failed run waits for the next
  trigger instead of re-prompting in a loop.
- **Activation.** It adds a `home.activation.piggySecrets` step after
  `writeBoundary` that can neither block nor fail:
  - `"check"` runs `reconcile --check` and prints the drift.
  - `"start"` (the default) does the same and, if anything drifted, runs
    `systemctl --user start --no-block piggy-secrets.service`.
  - `"none"` skips the step.

  Every branch ends in `|| true`. A switch never waits on a PIN prompt
  and never fails because a card is locked or absent.
- **`home.packages`.** It adds nothing there. The CLI is reachable as
  `piggy secrets` from whichever piggy the user already has, and the unit
  and activation step call `package` by absolute store path.

A NixOS re-export, `nixosModules.piggy-secrets`, puts the module into
`home-manager.sharedModules`, following the `piggy-agent` pattern.
Standalone home-manager on Ubuntu uses `homeManagerModules` directly.

## Examples

A circus consumer on a workstation. The secrets-nix target is up to
circus.

    services.piggy-agent.enable = true;   # agentSocket follows it
    services.piggy-secrets = {
      enable = true;
      package = inputs.piggy.packages.${system}.piggy;
      files = {
        ssh-config-user-secret = {
          source = ./piggy-store/rcm/config/ssh/rcm/config-user-secret.ebox;
          target = ".config/ssh/rcm/config-user-secret";
          adopt = true;                   # first switch replaces the bash-written file
        };
        ssh-known-hosts = {
          source = ./piggy-store/rcm/config/ssh/rcm/known_hosts.ebox;
          target = ".config/ssh/rcm/known_hosts";
          adopt = true;
        };
        smith-keys = {
          source = ./piggy-store/rcm/local/share/smith/keys.json.ebox;
          target = ".local/share/smith/keys.json";
          adopt = true;
        };
        secrets-nix-env = {
          source = ./piggy-store/circus/secrets-nix.env.ebox;
          target = ".secrets-nix.env";
          adopt = true;
        };
      };
    };

Steady state. The switch prints nothing and no card is touched:

    $ home-manager switch …
    $ piggy secrets reconcile
    TAP version 14
    1..4
    ok 1 - ssh-config-user-secret # SKIP up to date
    …

Rotation. The operator changes a secret, commits it and switches. That
yields one askpass prompt, from the unit rather than the switch:

    $ piggy pass insert -f rcm/local/share/smith/keys.json   # in the circus checkout's store
    $ git commit … && home-manager switch …
    piggy-secrets: 1 entry drifted; started piggy-secrets.service
    $ journalctl --user -u piggy-secrets
    ok 3 - smith-keys

Locked card or missing agent. The switch still succeeds. The unit fails
that entry and the old file stays in place:

    not ok 3 - smith-keys
      ---
      message: "no local card served the batch; and no agent fallback available"
      ...

Manual rerun after plugging in the card (the paved path):

    $ piggy secrets reconcile            # or: systemctl --user start piggy-secrets

## Limitations

- **Whole files only.** There is no key extraction from a structured
  document. A secret is one ebox mapped to one file, as in the `pass show`
  model.
- **User-scope secrets only.** Outputs belong to the reconciling user and
  live under paths that user can write. Root or system secrets are out of
  scope, since PIV decryption needs the card or a forwarded agent in the
  user's session.
- **No `restartUnits`.** Consumers that read a secret only at startup are
  not restarted when it rotates.
- **Linux systemd user units only at first.** darwin (a launchd agent plus
  activation) will follow the `piggy-agent` module's launchd branch once a
  live darwin host exists. On a host without a user systemd manager,
  `onActivation = "start"` degrades to `"check"`'s printed hint.
- **Headless hosts decrypt only while a card-backed agent is reachable.**
  A proxy-only `piggy-agent` (FDR 0001) fronts an SSH-forwarded workstation
  agent. The unit's login trigger usually fires before any forwarding
  connection exists, so the first reconcile on such a host usually happens
  on an `onActivation` start or a manual run.
- **The world-readable ciphertext reveals some metadata.** Anyone on a
  shared host can see the recipient set, the entry names and the plaintext
  sizes, but no plaintext.
- **`piggy pass` authoring is out of scope.** Where the writable store
  lives (`~/.local/share/piggy` → the circus checkout) matters only to
  `piggy pass insert`/`edit`. reconcile reads ciphertext from the manifest
  and never consults `PIGGY_STORE_DIR`.
- **This supersedes the unmerged `piggy.secrets` module** (branch
  `claude/nix-sops-piggy-eboxes-QI46P`, fc9aac3). That module is not
  revived, for four reasons:
  1. It decrypts inside activation under `set -e`, so a locked card fails
     or blocks the switch.
  2. Its outputs live in `$XDG_RUNTIME_DIR`, which disappears at logout
     and is reached through symlinks rather than plain files.
  3. It rebuilds and prunes a whole generation every switch, which is the
     delete-then-render shape of circus#178.
  4. It decrypts each file separately with `box stream decrypt`, which
     gives no one-PIN batch.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| `onActivation` default | `start` (no-block) | rotation reaches the home without a manual step, and the switch never waits | prompts land at surprising moments, so move to `check` |
| unit `WantedBy` | `default.target` | a fresh login heals a missing output | login-time prompts before the compositor is up are common, so drop it or add a delay |
| default `mode` | `0600` | matches the bash bootstrap | a consumer needs group read |
| freshness fingerprint | ciphertext digest + (dev, inode, size, mtime) | detects both rotation and local edits | backup restores or copies that keep inodes cause spurious re-decrypts |
| orphan handling | forget, keep the file | never delete (circus#178) | stale secrets pile up and the operator asks for `--prune` |

## More Information

- eng FDR-0004 (relocated), "RCM Piggy Ebox Decryption Hook": why the
  decrypt moved off every rcup, and the circus#178 log lesson.
- eng `bin/bootstrap-piggy-eboxes.bash`: the mechanism this replaces.
- piggy RFC 0005 (`pass show-batch`): the batched unlock core reconcile
  shares. RFC 0006 covers the `--frontend` seam.
- FDR 0001: the proxy-only agent that `agentSocket` resolves to on
  headless hosts.
- `nix/hm/piggy-agent.nix`: the module pattern this follows
  (`resolvedSocketPath`, launcher by absolute store path, eval-test
  harness).
- circus `docs/plans/2026-09-14-eng-into-circus.md`, slice S3b: the
  consumer.

Implementation sketch (piggy):

1. Factor the unlock-and-decrypt loop out of `show_batch.rs` so it takes
   `(name, ebox path)` pairs instead of pass-names under `store_root`.
2. Add `crates/piggy/src/secrets.rs` with the manifest parser, state file,
   classification, atomic write and TAP-14 output. Wire it into the clap
   tree.
3. Add `nix/hm/piggy-secrets.nix`, `nix/nixos/piggy-secrets.nix` and an
   eval-test with a `test-nix-hm-secrets-module` recipe.
4. Add `zz-tests_bats/conformance/piggy_secrets_reconcile_fibby.bats`
   covering the promotion cases.
