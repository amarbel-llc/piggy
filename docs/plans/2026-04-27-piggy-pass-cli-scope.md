# `piggy` pass-style CLI — v1.0 scoping

Status: **scope only, no implementation**. Issue: #46.
Milestone: [v1.0.0 — Rust clap CLI shelling out to C `pivy-*`](https://github.com/amarbel-llc/piggy/milestone/4).
(Tracker #45 retired 2026-04-27 — operational state lives on the
milestone description and in #26 Tier 11.)

## Goal (minimal-rewrite framing)

Replace `piggy.sh`'s top-level argv-dispatch (the case statement at
`src/piggy.sh:736-793`) with a Rust `clap` subcommand tree under
`crates/piggy/src/cmd/`. **Everything else stays bash for v1.0** —
the per-subcommand `cmd_*` bodies, the helper functions
(`reencrypt_path`, `set_git`, `set_pivy_template`, `piggy_encrypt`/
`_decrypt`, `check_sneaky_paths`), and the platform overrides under
`src/platform/darwin.sh`. Crypto continues to invoke `pivy-box stream
encrypt|decrypt` from inside the existing bash functions. The
per-subcommand `getopt` blocks inside each `cmd_*` are also preserved
as-is.

The intent is a small, surgical change: clap parses the top-level
subcommand, then exec's into bash to run the corresponding `cmd_*`.
No porting of crypto, clipboard, qrcode, tmpdir, or anything else
that already works in bash.

## Mechanic

Each clap subcommand handler `exec(2)`s the bash side. Two
implementation shapes are reasonable; we pick at impl time in #47:

- **Shape A — keep `piggy.sh` as-is.** Rust handler `exec`s
  `piggy.sh <subcommand> <rest-of-argv>`. The existing case statement
  in `piggy.sh` does the second-level dispatch to `cmd_*`. Smallest
  diff against today's `fallback::dispatch`; case statement is
  duplicated (clap names every subcommand explicitly, then bash also
  branches on the same subcommand string), but that's redundancy, not
  a correctness problem.
- **Shape B — strip `piggy.sh`'s case statement; Rust handlers name
  `cmd_*` directly.** Rust `exec`s `bash -c 'source piggy.sh; cmd_X
  "$@"' -- args...`. Removes the duplicate dispatch; touches
  `piggy.sh` only at the very bottom. Slightly more invasive.

Either is fine. Default to A unless the duplication is annoying once
we see it in code.

`piggy.sh` is **not deleted in v1.0** under this minimal-rewrite
framing. See "#50 cutover under minimal-rewrite" below.

## Pass-style command catalog

Confirming every subcommand currently reachable through `piggy.sh`'s
case statement is wired into the v1.0 clap tree, with its existing
aliases preserved.

| clap subcommand | aliases | bash function | flags (parsed in bash) |
|---|---|---|---|
| `init` | — | `cmd_init` | `-p path` `-g guid` `-e edit` `-i interactive` |
| `show` | `ls`, `list` | `cmd_show` | `-c[N]/--clip[=N]` `-q[N]/--qrcode[=N]` |
| `find` | `search` | `cmd_find` | (positional pass-names) |
| `grep` | — | `cmd_grep` | (forwards `GREPOPTIONS` + search string to `grep`) |
| `insert` | `add` | `cmd_insert` | `-m/--multiline` `-e/--echo` `-f/--force` |
| `edit` | — | `cmd_edit` | (no flags) |
| `generate` | — | `cmd_generate` | `-n/--no-symbols` `-q/--qrcode` `-c/--clip` `-i/--in-place` `-f/--force` |
| `rm` | `delete`, `remove` | `cmd_delete` | `-r/--recursive` `-f/--force` |
| `mv` | `rename` | `cmd_copy_move "move"` | `-f/--force` |
| `cp` | `copy` | `cmd_copy_move "copy"` | `-f/--force` |
| `git` | — | `cmd_git` | (forwards args to `git`) |
| `help` | `--help` | `cmd_usage` | (no args) |
| `version` | `--version` | `cmd_version` | (no args) |
| _(no args / unknown)_ | — | `cmd_show ""` | piggy.sh's default-case = list root |

`mv "move"` / `cp "copy"` is the only quirk: today's bash dispatches
both to `cmd_copy_move` with the mode passed as `$1`. Clap's two
handlers each call the same function with the right mode — trivial.

The default-case fall-through to `cmd_show` (line 789-792 of
`piggy.sh`) is preserved by clap's "no subcommand given" handler.

## New: `piggy pivy <tool> [args...]` passthrough

Add a generic escape hatch alongside the existing per-tool top-level
shortcuts. Behavior:

- `piggy pivy box ...` → exec `pivy-box ...` (the C binary)
- `piggy pivy tool ...` → exec `pivy-tool ...`
- `piggy pivy agent ...` → exec `pivy-agent ...` (or `piggy-agent` —
  decide at impl time whether to honor the Rust agent here too;
  default: C `pivy-agent`)
- `piggy pivy <anything>` → exec `pivy-<anything>` if found on `$PATH`;
  otherwise exit nonzero with a clear error.

Implementation: trivial wrapper around what `fallback::hand_off_to_pivy`
already does, just reachable via clap rather than via the argv-prefix
match in `main.rs`.

This deliberately differs from the existing top-level shortcuts:

| invocation | implementation | notes |
|---|---|---|
| `piggy box ...` | Rust (`crates/piggy/src/cmd/pivy_box.rs`) | first-party Rust pivy-box reimpl |
| `piggy agent ...` | Rust (`crates/piggy/src/cmd/agent/`) | first-party Rust agent |
| `piggy tool ...` | C `pivy-tool` (via `fallback::hand_off_to_pivy`) | scheduled for Rust port post-1.0 (#3, `docs/plans/2026-04-21-piggy-tool-scope.md`) |
| `piggy ca ...` | C `pivy-ca` (via fallback) | not on the Rust roadmap yet |
| `piggy luks ...` | C `pivy-luks` (via fallback) | same |
| `piggy zfs ...` | C `pivy-zfs` (via fallback) | same |
| **`piggy pivy box ...`** | **always C `pivy-box`** (new) | escape hatch around the Rust impl |
| **`piggy pivy tool ...`** | **C `pivy-tool`** (new) | identical effect to `piggy tool` for now; differs once `tool` ports to Rust |
| **`piggy pivy <X> ...`** | **C `pivy-<X>`** (new, generic) | works for any pivy-* binary on `$PATH` |

The value of `piggy pivy` is twofold:

1. **Stable C-side entry.** Once `piggy tool` ports to Rust (#3), users
   who specifically want the C implementation still have `piggy pivy
   tool ...`. Same logic applies if `piggy box` Rust ever drifts from
   C `pivy-box`.
2. **Discovery.** A user who installs piggy and types `piggy pivy
   <Tab>` (with completion) sees the full pivy-* surface in one
   place.

## Post-v1.0 direction (not committed)

Over time, individual pass-style commands can move from "clap →
exec → bash `cmd_*`" to "clap → Rust handler", with argument/
interface cleanup landing per-command. Likewise, the per-tool
shortcuts (`piggy box`, `piggy tool`, …) can move toward a
namespaced `piggy pivy box`-style shape with ergonomic redesign.

Both transitions are out of scope for v1.0 and are explicitly
deferred. v1.0's contract is "same behavior, prettier dispatch, new
`piggy pivy` escape hatch." Nothing else.

## Sequencing for #47 / #48

Collapses dramatically under minimal-rewrite.

**#47 (scaffolding):** clap subcommand tree with handlers that all
exec'd back to `piggy.sh`. The handlers are real (not stubs), but
they're one-liners — `Command::new("piggy.sh").args(["init", …]).exec()`
or equivalent. After #47 lands, `fallback::hand_off_to_bash`'s
catch-all becomes unreachable and can be removed.

**#48 (port commands):** under minimal-rewrite, this issue collapses
into "wire each clap handler to the right `cmd_*` invocation, plus
add the `piggy pivy <tool>` passthrough." There's no per-command
porting work. Single PR, not seven milestones.

Concretely:

1. Each pass-style clap handler exec's bash with the right
   subcommand. Aliases (`ls/list/show`, `add/insert`,
   `delete/rm/remove`, `rename/mv`, `copy/cp`) point at the same
   handler.
2. `piggy pivy <tool>` handler exec's `pivy-<tool>` from `$PATH`.
3. Top-level fallback (`fallback.rs`) is simplified: clap is now
   exhaustive for the supported surface, so only the per-tool
   shortcuts (`tool`, `ca`, `luks`, `zfs`) need fallback — and even
   those become explicit clap handlers under the same shape.

**#49 (bats conformance):** unchanged — the bats harness already
routes through the Rust dispatcher (`common.bash:42-61`). Green
`t0*-*.bats` against the binary verifies behavioral parity. Under
minimal-rewrite the conformance bar is "no behavior changed because
nothing was rewritten" — easier than under a porting approach.

## #50 cutover under minimal-rewrite

Under minimal-rewrite, **`piggy.sh` is not deleted in v1.0** — it
stays as the implementation backing every pass-style clap handler.
The original #45 "done means" listed "`src/piggy.sh` is gone" and
"`flake.nix` no longer puts `piggy.sh` (or bash) on the dispatch
path"; same with #50's original body.

**Reconciliation done 2026-04-27**: #45 retired (closed not-planned;
v1.0 narrative moved to the milestone description); #50 re-scoped
(title + body rewritten) to scope only the catch-all-fallback
removal + "off `$PATH`" + flake.nix/README updates. The actual
`piggy.sh` deletion is explicitly post-v1.0 (probably absorbed into
the per-command Rust ports later).

v1.0's "done means" (now on the milestone description):

- Top-level clap dispatch is exhaustive; no more catch-all
  `hand_off_to_bash` in `fallback.rs`.
- `piggy <subcommand>` is documented under `piggy --help` with
  clap-formatted output.
- `piggy pivy <tool>` exists.
- All `t0*-*.bats` green.
- `piggy.sh` becomes an internal implementation detail (no longer
  exposed on `$PATH`), but is not deleted.

## Things explicitly NOT in v1.0

- Porting any `cmd_*` body to Rust.
- Porting any helper (`reencrypt_path`, `set_git`, `set_pivy_template`,
  `check_sneaky_paths`, `piggy_encrypt`/`_decrypt`) to Rust.
- Porting platform helpers (`clip`, `qrcode`, `tmpdir`,
  `darwin.sh`) to Rust.
- Replacing `pivy-box` / `pivy-tool` C binaries with Rust. (#3, post-1.0.)
- Wire-format work. (v1.1.0.)
- New flags / behaviors not already in `piggy.sh`. v1.0 is strict
  parity plus the new `piggy pivy` passthrough.
- Renaming or restructuring the top-level pivy shortcuts. The
  `piggy pivy box`-style namespace is post-v1.0, gradual,
  per-command.

## Open questions

1. ~~**#45/#50 reconciliation.** Confirm minimal-rewrite means
   `piggy.sh` survives v1.0 and #50 cutover gets re-scoped post-1.0.~~
   **Resolved 2026-04-27** — #45 retired, #50 re-scoped accordingly.
   See "#50 cutover under minimal-rewrite" above.
2. **Shape A vs B.** Decide at impl time (#47) whether to keep
   `piggy.sh`'s case statement (A) or strip it and have Rust handlers
   name `cmd_*` directly (B).
3. **`piggy pivy agent`.** Should the new passthrough exec C
   `pivy-agent` or honor the existing Rust `piggy agent`? Default:
   C, to match the "always C-side escape hatch" framing. Cheap to
   revisit.
4. **Completion files.** `src/completion/pass.{bash,zsh}-completion`
   reference `piggy` subcommands directly. They keep working under
   minimal-rewrite but should be regenerated to surface `piggy pivy`.
   Out of scope for the scoping decision; flag for #48 work.
