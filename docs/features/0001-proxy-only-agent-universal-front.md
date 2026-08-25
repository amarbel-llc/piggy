---
status: accepted
date: 2026-08-23
accepted: 2026-08-25
acceptance-note: >
  Accepted 2026-08-25 by operator decision, ahead of the full ~1-week
  soak the original criteria called for (soak began 2026-08-23). Basis:
  the piggy side and the eng-side cutover both landed 2026-08-23 (eng
  master 3d2052a1, listen-socket variant — the mux listens on the retired
  fish-rendezvous path ssh_client-agent.sock, upstreams posh + the
  RemoteForward'd piggy, default-on per is-ssh-host); and the one soak
  finding — a latent launcher PATH bug that crash-looped the proxy-only
  unit on the first headless is-ssh-host to run it — was fixed (piggy
  b47974b) and confirmed working live on that host, with the fibby health
  gate made hermetic so it no longer couples to the operator's live unit
  (piggy#243, b7e843e).

  NOT independently confirmed at acceptance (accepted on operator
  judgment, not on their completion): the full multi-host, multi-day soak;
  and eng's two canary checks — (1) the mux-targeted `piggy health` green
  fleet-wide, and (2) SSH_AUTH_SOCK resolving to the mux front for BOTH
  login and non-login shells — both documented in eng-ssh(7). The
  mux-targeted health invocation (the bare one goes RED via
  PIGGY_AUTH_SOCK) is
  `env -u PIGGY_AUTH_SOCK SSH_AUTH_SOCK=$HOME/.local/state/ssh/ssh_client-agent.sock piggy health`.
---

# Proxy-only `piggy agent`: one agent front on every host

## Problem Statement

On a remote host, the shells' `SSH_AUTH_SOCK` has to point at *some*
forwarded agent socket, and the candidates differ in lifetime: the
sshd-forwarded socket (`~/.ssh/agent/s.*.sshd.*`) lives exactly as long
as one SSH TCP connection, while posh's endpoint
(`$XDG_RUNTIME_DIR/posh/agent/sock`) and a `RemoteForward`'d socket
survive reconnects. eng's fish login hook picked one with a first-wins
symlink rendezvous and a `test -S` liveness check — which can latch onto
the connection-bound socket (every shell loses its agent when that
connection drops) and which passes for a *dead* socket file
(amarbel-llc/eng#295). Fixing that in shell means hand-rolling
liveness-probe-and-prefer-a-live-backend logic on every login's
critical path. `piggy agent` already *is* that logic, in tested Rust:
since piggy#215 it proxies `--upstream` agents with per-upstream
timeouts, dead-upstream degradation, and a health self-report — but it
assumed a card was present, and its piggy-native card extensions never
fell through to an upstream.

## Interface

One uniform model, two roles, one binary and one home-manager module:

- **Card-backed** (workstation): `piggy agent -A|-g <guid> [--upstream …]`
  — native PIV keys first, upstreams proxied after. Unchanged.
- **Proxy-only** (remote host): `piggy agent --proxy-only --upstream
  NAME=PATH [--upstream …]` — serves **no** native keys, never opens
  PCSC (no card probe, no piggy#175 recovery loop), and proxies
  everything to the configured upstreams. Requires at least one
  `--upstream`; conflicts with `-g`, `-A`, `-K`, `-S`, `-i`.

The upstreams of a proxy-only agent are the host's **fixed, stable**
backings (posh's endpoint, the `RemoteForward`'d socket). The
per-connection sshd socket is never listed — its path varies per
connection — so "latched onto a connection-bound socket" is
structurally impossible. The mux's existing timeout/degrade selection
(`--agent-timeout`, default 5 s) picks whichever backing is live per
request; a dead backing is skipped on listing and tried-next on
forwarding.

Agent changes that make the role work (all also active on card-backed
agents):

- **Native-miss fallthrough for the card extensions.** `ecdh@joyent.com`,
  `ecdh-rebox@joyent.com`, and `ykpiv-attest@joyent.com` used to resolve
  the card key against native keys only and hard-fail on a miss. Now a
  *native miss* with upstreams configured forwards the request to the
  upstreams (first success wins) — the same fallthrough `sign` has for
  non-native keys. A genuine error in a request the agent owns
  (malformed payload, card/PIN failure) is never retried upstream.
  Without upstreams the refusal is unchanged. This is what lets
  `piggy pass show` on a remote host, pointed at the proxy, reach the
  forwarded card.
- **`agent-mode@piggy` self-report.** Every Rust agent advertises and
  answers this piggy-private extension with
  `{"proxy_only": bool, "native_keys": N, "upstreams": N}`.
- **Socket hygiene.** The agent unlinks its socket on SIGTERM as well as
  SIGINT, and binds through stale-socket reclaim: an orphaned socket
  file nothing accepts on (`ECONNREFUSED`) is unlinked and re-bound; a
  live listener is never clobbered (`EADDRINUSE` as before).

`piggy health` reads `agent-mode@piggy`. Against a proxy-only agent the
four local-card points (`pcsc: daemon reachable`, `card: PIV card
attached`, `card: key-management slot 9D populated`, `agent serves
attached card`) SKIP with reason `proxy-only agent: no local card
expected` — the plan keeps its 9-point shape and names. Per-upstream
points treat a proxy-only agent's backings as *alternatives*: a dead
upstream SKIPs while at least one other is reachable and FAILs only when
none is. On a card-backed agent upstreams stay additive and a dead one
still FAILs. Anything short of a positive proxy-only report (an older
agent, a failed probe) keeps the card-backed plan — health never hides a
card failure on a guess.

home-manager: `services.piggy-agent.proxyOnly = true` (top-level or
per-instance) emits `--proxy-only`, replaces the `guid`/`allCards`
requirement, and asserts at eval time: Rust agent only, non-empty
`upstreams`, and none of `guid`/`allCards`/`cak`/`slots`.

## Examples

A remote host (the eng#295 end-state), in home-manager:

    services.piggy-agent = {
      enable = true;
      proxyOnly = true;
      setSshAuthSock = true;
      upstreams = [
        { name = "posh"; socketPath = "$XDG_RUNTIME_DIR/posh/agent/sock"; }
        { name = "fwd";  socketPath = "$HOME/.local/state/ssh/piggy-agent.sock"; }
      ];
    };

renders a launcher that execs

    piggy agent -a "$XDG_STATE_HOME/piggy/piggy-agent.sock" --proxy-only \
      --upstream posh="$XDG_RUNTIME_DIR/posh/agent/sock" \
      --upstream fwd="$HOME/.local/state/ssh/piggy-agent.sock"

With only posh live, a shell on that host sees:

    $ ssh-add -L            # the workstation card's 9A key, via posh
    ecdsa-sha2-nistp256 AAAA… PIV_slot_9A 5da19c98
    $ piggy pass show foo   # ecdh-rebox forwarded to the live backing
    …
    $ piggy health --format tap
    TAP version 14
    1..11
    ok 1 - service: piggy-agent.service active
    …
    ok 6 - pcsc: daemon reachable # SKIP proxy-only agent: no local card expected
    ok 7 - card: PIV card attached # SKIP proxy-only agent: no local card expected
    ok 8 - card: key-management slot 9D populated # SKIP proxy-only agent: no local card expected
    ok 9 - agent serves attached card # SKIP proxy-only agent: no local card expected
    ok 10 - agent: upstream posh answers
    ok 11 - agent: upstream fwd answers # SKIP unreachable; 1 other upstream(s) live (proxy-only backings are alternatives)

When the `fwd` connection comes back, the next request simply uses it —
no relogin, no symlink to repair.

The end-to-end gate is `proxy_only_agent_fronts_forwarded_card_agent` in
`zz-tests_bats/conformance/piggy_agent_upstream_fibby.bats` (recipe
`test-bats-conformance-agent-upstream`): a proxy-only agent with PCSC
deliberately unreachable, a dead upstream listed first, fronting a
fibby-backed card agent — listing, decrypt-through-proxy (ECDH observed
on fibby, none in the proxy), and health.

## Limitations

- **Posture shift.** This puts an agent daemon on every is-ssh-host,
  reversing the earlier "is-ssh-hosts run no local agents" stance
  (piggy#215's verification-model note). The daemon holds no key
  material — it is a socket-level router — but it is one more user
  service to keep healthy; `piggy health` is the tool for that.
- **Only stable backings belong in `upstreams`.** Listing the
  per-connection sshd socket would reintroduce exactly the eng#295
  failure. The path varies per connection anyway, so the module can't
  express it — by design.
- **Identical keys on several backings are first-wins.** When posh and
  `fwd` both forward the same workstation agent, the key is offered once
  and a request for it goes to the first-listed *live* upstream; the
  others are reached only when that one is down at listing time (the
  routing map is rebuilt on every listing and on a sign miss). A `sign`
  has no per-request failover to a second holder of the same key;
  forwarded card extensions (`ecdh-rebox` etc.) do try each upstream in
  order, so a `pass show` survives one backing dying mid-session.
- **Forwarded card extensions inherit the upstream's PIN flow.** A
  proxied `ecdh-rebox` is answered by the card-backed agent at the far
  end, which prompts for the PIN via *its* askpass — the proxy has no
  PIN and never prompts.
- **`piggy agent -i` is meaningless in proxy-only mode** and is rejected
  rather than listing upstream keys; use `ssh-add -L` against the socket.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| `--agent-timeout` (per-upstream connect/list/sign) | 5 s (piggy#215 default) | a hung (not dead) backing costs this per request before the next is tried; dead sockets fail instantly | remote `ssh`/`pass show` stalls of ~5 s become a recurring complaint when a backing is wedged rather than down |
| health verdict for a dead proxy-only backing | SKIP while ≥1 other live; FAIL when none | backings are alternatives by design; a red health on every healthy remote host trains people to ignore it | a dead backing that *should* be live going unnoticed for days — then promote it to a warning-class point |
| stale-socket reclaim probe | `connect` → `ECONNREFUSED` ⇒ reclaim | the only unambiguous dead-listener signal; `ENOENT`/other errors are left alone | a platform whose dead unix sockets report something other than `ECONNREFUSED` |

## Post-acceptance cleanup (done 2026-08-25)

At acceptance the dated "a front-end `ssh-agent-mux` is the typical
deployment" wording was softened across the tree — `AGENTS.md`,
`crypt.rs`, `agent_client.rs`, `reencrypt.rs`, `cmd/pivy_box.rs`,
`doc/piggy.1.scd`, `pivy_agent_hardware.bats`, and the `justfile` explore
recipe — to "an upstream agent that may not advertise `ecdh@joyent.com`".
The mechanism was deliberately KEPT, not rewritten to "piggy is the sole
front": `PIGGY_AUTH_SOCK` is a general robustness measure and
`ssh-agent-mux` still exists as a standalone tool (1Password and other
muxes still front non-eng hosts). The `setSshAuthSock`-default-off
rationale (`eval-test.nix` / `piggy-agent.nix`) was left intact for the
same reason. Correct historical attributions (piggy#215's port from
`ssh-agent-mux`, the piggy#119 query-encoding references) were untouched.

## More Information

- `docs/diagrams/ssh-agent-topology.puml` (rendered `.svg` beside it, `just codemod-diagrams`) — the post-cutover topology: the three ways the workstation agent reaches an is-ssh-host (only the two fixed-path ones are mux upstreams). Its legend tracks the cutover decisions: **(1) SSH_AUTH_SOCK ownership — RESOLVED 2026-08-23** (posh keeps its unconditional per-session export as the spawn-env default; eng's shell-init `SSH_AUTH_SOCK`/mux runs later and overrides it, so the mux is the sole front on eng hosts and posh sessions gain the degrade-select; posh's export is the unmanaged-host fallback — posh#161 / posh FDR 0014); **(2) the `piggy health` mux-targeting invocation — DEFINED**, documented in eng-ssh(7) and the acceptance note (its fleet-wide green was the soak criterion, accepted early 2026-08-25).
- amarbel-llc/eng#295 — the bug and its shell-scoped interim; reframed by this record.
- piggy#215 — the ssh-agent-mux absorb this builds on (`--upstream`, timeouts, `upstream-status@piggy`).
- posh#103 / posh FDR 0014 (`docs/features/0014-stable-forwarded-agent-endpoint.md`) — the "host-global rendezvous, a host facility any tool can share" this is a concrete implementation of.
- eng-ssh(7) — the deployed socket stack; its remote-host section + TROUBLESHOOTING were rewritten for this model in the eng cutover (2026-08-23).
- Code: `crates/piggy/src/cmd/agent/{mod,session,mode,upstream}.rs`, `crates/piggy/src/health.rs`, `nix/hm/piggy-agent.nix`.
