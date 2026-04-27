# `services.piggy-agent` nix module — v1.0 scoping

Status: **scope only, no implementation**. Issue: #52.
Milestone: [v1.0.0 — Rust clap CLI shelling out to C `pivy-*`](https://github.com/amarbel-llc/piggy/milestone/4).

This doc mirrors the pattern set by `docs/plans/2026-04-27-piggy-pass-cli-scope.md` (#46 → #47/#48/#50): land scope first, then implement in follow-up commits. v1.0's dispatch piece is functionally complete after #50; this issue closes the v1.0 gap on declarative agent management for users on NixOS, home-manager, and nix-darwin.

## Goal

Ship two flake outputs that let a user declare `services.piggy-agent.enable = true` (plus a card identifier) and get a managed agent on both Linux (systemd user unit) and Darwin (launchd LaunchAgent), without hand-copying unit files or running install scripts.

```
flake.nixosModules.piggy-agent      # NixOS system config integration
flake.homeManagerModules.piggy-agent # home-manager (Linux + Darwin)
```

The two modules cover overlapping surfaces:

- `homeManagerModules.piggy-agent` is the primary surface — per-user agent, follows the user across machines, works under home-manager-darwin via `nix-darwin` integration.
- `nixosModules.piggy-agent` is for NixOS users who don't run home-manager and want a per-user systemd service declared in `/etc/nixos/configuration.nix`. It targets `systemd.user.services.<...>` for the active user under `users.users.<name>`.

Both wrap the **piggy** binary's `piggy agent` subcommand (the Rust agent in `crates/piggy/src/cmd/agent/`). A `package` option lets users swap in `pkgs.pivy` to run the C `pivy-agent` instead.

## Why now (v1.0 framing)

#48 landed `piggy agent` (Rust) + `piggy pivy agent` (C escape hatch) as part of the v1.0 dispatch surface. The agent is the most useful long-running piggy surface — it's what makes `pass`-style workflows ergonomic. Shipping v1.0 without nix-module integration means Linux/Darwin users have to hand-copy systemd units or launchd plists from the repo, defeating the point of the nix packaging.

#52 was originally filed against a hypothetical v1.4 milestone. Moved to v1.0.0 on 2026-04-27: v1.0 should be usable end-to-end on NixOS / nix-darwin out of the box, not just "the binary builds."

## Prior art (what's NOT being copied)

- `amarbel-llc/pivy/pivy-agent@.service` — systemd templated user unit with placeholder `@@BINDIR@@`. Hardcodes `-g $PIV_AGENT_GUID`; **does not expose `-A`** (all-cards mode). Instances driven by `~/.config/pivy-agent/<name>` env files.
- `amarbel-llc/pivy/macosx/net.cooperi.pivy-agent.plist` — launchd LaunchAgent with placeholders `@@GUID@@`, `@@CAK@@`, `@@HOME@@` substituted by the macOS `postinstall` script (which probes the YubiKey to discover the GUID/CAK at install time). Single-instance only. No `-A` either.
- pivy's `flake.nix` substitutes the placeholders at build time and drops the result at `$out/lib/systemd/user/pivy-agent@.service` / `$out/share/pivy/net.cooperi.pivy-agent.plist`. **No NixOS or home-manager module declares those files into the live system.** The user is expected to copy them by hand.

So the prior art is "package the unit files, leave activation to the user." We are designing the option surface fresh.

## Reference points (what IS being copied)

- `nix-community/home-manager/modules/services/gpg-agent.nix` — closest analogue. Single `mkIf cfg.enable { ... }` block produces both `systemd.user.services.gpg-agent` (Linux) and `launchd.agents.gpg-agent` (Darwin) from the same options. We follow that shape.
- `home-manager`'s `lib.hm.shell.mk{Bash,Fish,Zsh,Nushell}IntegrationOption` — for shell-init helpers that export `SSH_AUTH_SOCK`. Optional add-on; not blocking for the initial module.
- `nixpkgs/nixos/modules/programs/ssh.nix` — for the templated multi-instance shape (relevant later).

## Module surface

### Single instance (default)

```nix
services.piggy-agent = {
  enable = true;

  # One of `guid` or `allCards` MUST be set (module assertion).
  # They are mutually exclusive.
  guid = "TESTGUID1234567890";   # → -g <guid>
  # allCards = true;             # → -A; mutex with guid

  # Optional:
  cak = "ecdsa-sha2-nistp256 AAAA...";   # → -K <cak>
  slots = "9a,9e";                       # → -S <spec>; default "all"
  socketPath = null;                     # null → auto (see "Socket path" below)
  extraArgs = [ ];
  package = pkgs.piggy;                  # binary; null → "piggy" on $PATH
  askpass = null;                        # null → contrib/piggy-askpass.sh from package
  logFile = null;                        # null → journal (Linux) / Library/Logs (Darwin)
};
```

### Multi-instance

Mirrors the systemd `pivy-agent@<name>.service` template shape. Each entry becomes its own unit/plist with its own socket.

```nix
services.piggy-agent.instances = {
  default = { guid = "..."; cak = "..."; };
  work    = { guid = "..."; cak = "..."; slots = "9a"; };
  spare   = { allCards = true; };
};
```

When `instances` is non-empty, the top-level `guid`/`allCards`/etc. options are ignored (or treated as defaults that each instance can override — see open question below). Each instance emits:

- Linux: `systemd.user.services.piggy-agent-<name>` with socket `$XDG_STATE_HOME/piggy/piggy-agent-<name>.sock`.
- Darwin: `launchd.agents.piggy-agent-<name>` (label `net.amarbel.piggy-agent.<name>`) with the same socket.

`SSH_AUTH_SOCK` is NOT auto-exported when there's more than one instance — the user picks which one by setting it in their shell. The module emits per-instance shell snippets that home-manager's bash/fish/zsh integration can source.

## Socket path convention

Sockets live under **`$XDG_STATE_HOME/piggy/`**, NOT `$XDG_STATE_HOME/ssh/` (where pivy's prior unit files put them).

Rationale: this is piggy, not pivy. Once a user configures both `pivy-agent` (e.g. via system packaging) and `piggy-agent` (via this module) on the same machine, they MUST NOT collide on the socket path. Reusing pivy's `~/.local/state/ssh/pivy-agent.sock` would force users to choose one or the other.

Defaults:

| | Single-instance | Multi-instance `<name>` |
|---|---|---|
| Linux | `$XDG_STATE_HOME/piggy/piggy-agent.sock` | `$XDG_STATE_HOME/piggy/piggy-agent-<name>.sock` |
| Darwin | `$HOME/.local/state/piggy/piggy-agent.sock` | `$HOME/.local/state/piggy/piggy-agent-<name>.sock` |

Darwin doesn't set `$XDG_STATE_HOME` by default, so the fallback to `$HOME/.local/state/` per the XDG Base Directory Specification applies. We use the same path on both platforms for predictability — users scripting against `$SSH_AUTH_SOCK` get the same shape regardless of OS.

The module is responsible for ensuring `$XDG_STATE_HOME/piggy/` exists with mode 0700 before the agent tries to bind:

- **Linux:** `RuntimeDirectory=piggy` (system services) is wrong — that creates `/run/piggy`. For user services we use `tmpfiles.d` rules under `home.file` / `xdg.stateFile` to ensure the directory exists with the right mode.
- **Darwin:** preflight in the launchd plist's `ProgramArguments` — wrap the agent invocation in a small shell script that does `mkdir -p -m 0700 "$XDG_STATE_HOME/piggy" && exec piggy agent ...`. Or use a bootstrap LaunchAgent that runs `mkdir` once at session start.

`SSH_AUTH_SOCK` is exported via home-manager's `home.sessionVariables` for the single-instance case. For multi-instance, see above.

## Cross-platform unit shape

| | Linux (systemd user) | Darwin (launchd LaunchAgent) |
|---|---|---|
| Trigger module | `systemd.user.services.piggy-agent` | `launchd.agents.piggy-agent` |
| Restart-on-exit | `Restart=always`, `RestartSec=3` | `KeepAlive = { Crashed = true; SuccessfulExit = false; }` |
| Stderr destination | journal (`journalctl --user -u piggy-agent`) | `~/Library/Logs/piggy-agent.log` (or `logFile`) |
| Stale-socket cleanup | `ExecStartPre=/bin/rm -f $SSH_AUTH_SOCK` | preflight `rm` in the wrapper script (see below) |
| Socket dir creation | `tmpfiles.d` user rule: `D %h/.local/state/piggy 0700 - - -` | preflight `mkdir -p -m 0700` in wrapper script |
| Multi-instance | one `systemd.user.services.piggy-agent-<name>` per entry | one `launchd.agents.piggy-agent-<name>` per entry |
| Foreground flag | `-i` (always; matches the prior pivy unit) | `-i` (always) |

### The Darwin wrapper script

Because launchd doesn't have an analogue of `ExecStartPre`, the cleanest way to handle stale-socket cleanup AND `mkdir -p -m 0700 $XDG_STATE_HOME/piggy/` is to wrap the agent invocation in a small shell script generated by the nix module:

```sh
#!/bin/sh
set -e
mkdir -p -m 0700 "$XDG_STATE_HOME/piggy"
rm -f "$SOCK_PATH"
exec @piggy@/bin/piggy agent -i -a "$SOCK_PATH" -g "@guid@" ${cak:+-K "@cak@"} -S "@slots@" @extraArgs@
```

The module emits this script at `${cfg.package}/share/piggy/piggy-agent-launch-<instance>.sh` (or in the user's nix-store via `pkgs.writeShellScript`) and points `ProgramArguments` at it. This keeps the launchd plist itself trivial and matches what the prior pivy macOS `postinstall` did via sed substitution.

## Module assertions

The module emits the following `lib.assertMsg` failures during evaluation, before any unit is generated:

1. `guid` and `allCards` are mutually exclusive per instance.
2. At least one of `guid` / `allCards` must be set per instance (or in single-instance mode at the top level).
3. When `instances` is non-empty, top-level `guid`/`allCards`/`cak`/`slots` are forbidden (or merged as defaults — see open question).
4. `slots` must match `^(all|[0-9a-fA-F]{2}(,[0-9a-fA-F]{2})*)$` if set.
5. `package` must provide a `bin/piggy` executable (or `bin/pivy-agent` if the user opts into the C path — detected by binary name, not just package identity).

## Things explicitly NOT in v1.0

- **Auto-discovering GUID/CAK at install time.** pivy's macOS `postinstall` runs `pivy-tool list`, prompts the user to insert the YubiKey, and bakes the result into the plist. That's interactive flow — doesn't fit nix's purely-declarative model. Users supply `guid`/`cak` themselves. Optional follow-up: a `piggy agent print-config` helper that emits a nix snippet for paste-in (post-1.0).
- **System-level (root) agent.** The module is per-user only. Both home-manager and the templated systemd user-unit shape from prior art are user-scoped. A system-level agent is a different design (different socket path, different auth model) and out of scope.
- **Rewriting `flake.nix`'s existing `piggy` package.** The module consumes `cfg.package` (default `pkgs.piggy`); the package itself is already shipped and unchanged.
- **Replacing `piggy pivy agent`.** That's the runtime escape hatch added in #48 — independent of how the agent is started.
- **Shell integration beyond `SSH_AUTH_SOCK`.** No bash-prompt indicators, no fish completion for instance names, no zsh hooks. Optional add-on later.
- **Socket activation.** Piggy's rust agent doesn't currently support `LISTEN_FDS` / `sd_listen_fds(3)` — verified by grepping `crates/piggy/src/cmd/agent` on 2026-04-27. We use `ExecStartPre=/bin/rm -f` for stale-socket cleanup instead, matching pivy's prior unit. Filed as #53; the nix module will expose a `useSocketActivation` toggle that defaults to false until the agent supports `LISTEN_FDS`, at which point flipping the default to true is a one-line module change.

## Open questions (resolve at impl time)

1. **Top-level options + `instances` interaction.** If a user sets both `services.piggy-agent.guid = "X"; services.piggy-agent.instances.work = { guid = "Y"; }`, do we (a) reject as a config error, (b) treat the top-level as a default that `work` overrides but unspecified keys inherit from, or (c) silently ignore the top-level when `instances` is non-empty? Recommend (a) at impl time — clearest user model — but (b) is what gpg-agent-style modules tend to do. Document the choice in the module.
2. **Multi-instance default name.** When `instances` is empty and top-level options are set, what's the systemd unit name? Recommend `piggy-agent.service` (no template suffix) to match the gpg-agent shape. The pivy prior art used `pivy-agent@default.service` via the templated `DefaultInstance=default` line.
3. **`enable = true` with no instances and no top-level card.** Should this be a config error (assertion) or a soft-deferral (warn + don't generate units)? Recommend assertion — saves users the silent-failure debugging — but the gpg-agent module accepts `enable = true` with a default key set, which is closer to soft-deferral. Decision: **module assertion fails.** (Confirmed at scoping time.)
4. **Where does `nixosModules.piggy-agent` route?** It declares `services.piggy-agent` as a top-level option but most nix users with home-manager already get that through `homeManagerModules.piggy-agent`. Two reasonable paths: (a) `nixosModules.piggy-agent` re-exports the home-manager module under `home-manager.users.<u>.services.piggy-agent`, or (b) it provides a separate `users.users.<u>.services.piggy-agent.<...>` surface that materializes to the same unit. Recommend (a) at impl time — DRY.
5. **`piggy agent kill` integration.** `piggy agent -k` reads `$SSH_AGENT_PID` and SIGTERMs the agent. With systemd-managed services, that's `systemctl --user stop piggy-agent` instead. Document but don't try to bridge — they're meant for different contexts.
6. **Templating cost.** The module evaluates several attrsets per instance (units, sockets, scripts). Worth caching via `lib.foldl'` / `lib.attrsToList` patterns if `instances` is large? Probably not — typical users have 1-3 instances. Skip the optimization.

## Sequencing

This issue lands in three follow-up PRs:

**Step 1 — module skeleton + single-instance home-manager.** Add `flake.homeManagerModules.piggy-agent` and the bare-minimum option surface (`enable`, `guid`, `allCards`, `cak`, `slots`, `package`). Generate `systemd.user.services.piggy-agent` and `launchd.agents.piggy-agent` from one `mkIf cfg.enable` block. Single-instance only. Verify with a smoke-test home-manager config that exercises both Linux and Darwin code paths via `nix flake check` and a manual nix-darwin spin-up.

**Step 2 — multi-instance.** Add the `instances` attrset, generalize the unit-generation helpers, add the assertions for top-level vs `instances` conflict. `piggy-agent@<name>.service` / `net.amarbel.piggy-agent.<name>.plist` per instance.

**Step 3 — `nixosModules.piggy-agent` + shell integration.** Add the NixOS-direct module that re-exports under home-manager's namespace. Add bash/fish/zsh integration helpers for `SSH_AUTH_SOCK` export. Smoke-test with a `nixosTest`.

Each step is a discrete PR. Splits keep the diff reviewable and lets us course-correct on the option surface before locking it in.

## Verification (after step 3)

Echoing #52's verify-before-merging block:

- A user on a fresh NixOS machine declares `services.piggy-agent.enable = true; services.piggy-agent.guid = "<their-guid>";` and after `nixos-rebuild switch` finds:
  - `systemctl --user status piggy-agent.service` is active.
  - `$SSH_AUTH_SOCK` is set to `$XDG_STATE_HOME/piggy/piggy-agent.sock` in the user's session env.
  - `$XDG_STATE_HOME/piggy/` exists with mode 0700.
  - `ssh-add -L` lists the cert from slot 9a.
- Same on Darwin via home-manager-darwin: `launchctl list | grep piggy-agent` shows the agent running; the socket lives at `$HOME/.local/state/piggy/piggy-agent.sock`.
- Multi-instance: `services.piggy-agent.instances = { default = {...}; work = {...}; }` produces two independent agents with two sockets, both reachable via the appropriate `SSH_AUTH_SOCK`.
- `services.piggy-agent.allCards = true` (with `guid` unset) starts the agent with `-A` and exposes keys from every detected card; the module emits an assertion failure if `guid` is also set.
- `services.piggy-agent.package = pkgs.pivy` starts the C `pivy-agent` instead, with the same option surface — confirms the module is binary-agnostic.

## References

- amarbel-llc/pivy `pivy-agent@.service` — prior systemd unit (no `-A`)
- amarbel-llc/pivy `macosx/net.cooperi.pivy-agent.plist` — prior launchd plist (no `-A`)
- pivy `rust/crates/pivy-agent/src/main.rs:17-19` — `-A` flag in the rust agent
- piggy `crates/piggy/src/cmd/agent/mod.rs` — same `-A` flag in piggy's clap parser
- `nix-community/home-manager/modules/services/gpg-agent.nix` — closest existing module pattern; we copy the cross-platform shape (single `mkIf cfg.enable` block emits both systemd + launchd surfaces)
- #46 — v1.0 dispatch scoping doc (this doc mirrors that pattern)
- #48 — `piggy pivy agent` passthrough (the C-side runtime escape hatch)
- #33 — `contrib/piggy-askpass.sh` (askpass default for the module)
- #26 Tier 11 — sequenced work tracker
