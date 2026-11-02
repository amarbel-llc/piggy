# piggy#351: where a headless host's PIN prompt is raised

Status: diagnosis and the `PIGGY_UNLOCK` override landed (a89ec0a); the
`auto` route change below is the general answer, pending the repro.

## Diagnosis

Evidence labels: R read in code, V observed, I inferred, U unknown.

- **Who prompts.** On the agent route the agent that holds the card asks for
  the PIN, with its own environment's `SSH_ASKPASS`, and caches it per card
  (`cmd/agent/session.rs`, `ensure_pin`) (R). A `--proxy-only` front never
  prompts (R). The client prompts only when it opens a local card itself.
  Its route is `card_oracle::pin_route`: `SSH_ASKPASS_REQUIRE=never` uses the
  tty; otherwise a set `SSH_ASKPASS` is run; with none it falls back to
  `/dev/tty` (R).
- **Why nikulin prompts locally.** `pass show-batch` and `secrets reconcile`
  share `show_batch::with_batch_unlock`, which was card-first: any attached
  card whose 9D key is a recipient wins, and the agent is only a fallback
  (R). The `pin-cancelled` diagnostic is produced only on that card path; the
  agent path reports `decrypt-failed: unlock failed (agent)` (R). nikulin
  reported `pin-cancelled` (V), so its own card (C291D27B) was opened over
  local PC/SC and the forwarded agent was never asked (I, high confidence).
  - The unit's askpass had no tty and no zenity, so it exited 2 (V).
  - The interactive run had `SSH_ASKPASS` set (I: NixOS
    `programs.ssh.askPassword`), so the GUI askpass ran and found no display,
    exiting 1 (V).
- **Order elsewhere.** `pass show`, `edit`, `grep`, `verify` and the
  re-encryption walk go through `cmd::pivy_box::Decryptor`, which asks the
  agent first for each config and the card second (`piggy_box::unlock`) (R).
  So the two paths disagreed exactly in the case nikulin hit.

## Design

The general rule: **a batch unlocks through the card that is meant to answer
it, and the prompt is raised where that card is.** Concretely, under
`PIGGY_UNLOCK=auto` (the default):

1. Find the first local card whose 9D key is a recipient (as before).
2. If one matched, read the agent's key list (`request_identities`, bounded
   at 5 s, never prompts). If the agent offers a recipient key **other than
   that card's**, the batch goes to the agent. That key belongs to a card
   this host cannot see, in practice one forwarded from the operator's
   workstation, whose agent prompts on the workstation's display.
3. Otherwise keep the local card (one PC/SC session, one PIN, RFC 0005).
   That covers the workstation shape, where the local agent serves the same
   card, and agents that offer no recipient key.
4. With no matching card, use the agent (as before).

`--frontend jsonrpc` always keeps the local card: its caller asked to supply
the PIN itself (RFC 0006). `PIGGY_UNLOCK=card|agent` overrides the choice,
and `services.piggy-secrets.unlock` sets it for the unit.

Remaining divergence from `pass show`: when the agent and a local card hold
the same key, `show-batch` keeps the card session. That is deliberate (one
transaction for the batch, and the JSON-RPC frontend sees the PIN request).

### Alternatives weighed

- **(a) Agent-side prompting** (chosen). The PIN never crosses ssh, and the
  dialog appears on the display of the person holding the card. Cost: the
  ECDH shared secret for each ebox crosses the forwarded channel, as it
  already does for `pass show`. Any process on the host that can reach the
  forwarded socket can ask for decrypts while that agent's PIN cache is
  warm; that is true of every forwarded agent today.
- **(b) Fail closed with a clear message** when no render target exists.
  Safe and kept: a cancelled local-card prompt now names the card and
  `PIGGY_UNLOCK=agent`. It is a fallback, not a design.
- **(c) Cache the unlocked state for the unit's lifetime.** A card-backed
  `piggy-agent` on the headless host already caches its PIN per card, and
  `ssh-add -X` against it (from an ssh tty) supplies the PIN without a
  display (`agent_client::unlock_agent_pin`, R). This is the answer for a
  headless host whose **only** recipient card is local. Cost: that card
  stays unlocked on an unattended host until it is removed or the agent
  restarts. Do not make it the default; document it as the operator's
  choice.
- **Rejected: a prompt-forwarding extension**, where the host asks the
  upstream agent to render a prompt for a card on the host. PIN bytes would
  cross ssh, and the agent socket would become a PIN oracle for whoever can
  reach it.

### Security notes

- Reading the agent's key list discloses nothing new: the client could
  already list keys and try them.
- A hostile agent socket that lists a recipient key cannot answer the ECDH
  without the private key; the box's AEAD rejects a wrong secret. The worst
  it can do is make the batch fail, which `PIGGY_UNLOCK=card` sidesteps.
- The change moves prompts **away** from a host with no display, never onto
  a new host: the agent that prompts is the one that holds the forwarded
  card, whose owner forwarded it.

## Repro results (2026-11-02, counterparts on nikulin and twerk)

- **Card-first, confirmed.** N5b on nikulin, with piggy 0.1.23, an askpass of `false`, and no PIN reaching the card, reported `pin-cancelled` (V). v0.1.23 selects the card the same way, and that kind comes only from its local-card path (R). So nikulin decrypted with its own card.
- **twerk's card is a recipient** of all four manifest eboxes, next to nikulin's card and a third card (V, from offline `pass ls -r` plus T2). With piggy ≥ 3b1c454 the `auto` route sees the forwarded agent offer that key and unlocks through twerk.
- **The forward is live** on nikulin's `~/.local/state/ssh/piggy-agent.sock` and serves twerk's card (V). twerk's agent runs `piggy-askpass.sh` with `SSH_ASKPASS_REQUIRE=force`; its unit has no display variables, so the helper re-derives the display itself.
- N6 (the real reconcile) waits for the piggy bump on nikulin.

### Circus follow-up: twerk's forward shadows nikulin's own agent socket

nikulin runs its own card-backed `piggy-agent` on
`~/.local/state/ssh/piggy-agent.sock`, and twerk `RemoteForward`s its agent
onto that same path. The forward replaced the socket file: its mtime is later
than the unit's start (V). While the operator's ssh session is up, nikulin's
own agent is unreachable by path. Once the session ends, the path no longer
reaches either agent. Then `services.piggy-secrets` (whose `agentSocket`
defaults to that path) finds no agent, keeps the local card, and fails closed
with `pin-cancelled` naming the card (I). The reconcile unit therefore
unlocks through twerk only while the forward is up.

Fix belongs in circus's host config, not piggy:
- forward to a distinct path (e.g. `…/piggy-agent-forwarded.sock`);
- either point `services.piggy-secrets.agentSocket` at that path, or run
  nikulin's agent with `--upstream forwarded=<that path>`. The latter is
  piggy FDR 0001's one-socket shape, and piggy#295 tracks local versus
  forwarded agents sharing a socket.

## Repro plan (counterparts)

Nothing below needs the PIN until step N6, and nothing prints a secret.
The commands are read-only except N6, which writes the declared secret
files, the intended outcome.

### twerk (operator workstation; card agent and GUI askpass)

| Step | Command | Proves |
|---|---|---|
| T1 | `piggy version` | which piggy twerk runs |
| T2 | `piggy list --format human` | twerk's card GUID and its 9D `piggy-recipient-v1@…` ID (public key; no PIN) |
| T3 | `SSH_AUTH_SOCK=<twerk piggy-agent socket> ssh-add -L` | the agent offers twerk's 9D key (an `ecdsa-sha2-nistp256` line) |
| T4 | `ssh -G nikulin \| grep -i remoteforward` | which local socket is forwarded to nikulin's `~/.local/state/ssh/piggy-agent.sock` |
| T5 | `systemctl --user show piggy-agent.service -p Environment` | the agent's `SSH_ASKPASS` (where its prompt renders) |
| T6 | during N6: `journalctl --user -u piggy-agent -f` | the PIN prompt fired on twerk (askpass/`pin_prompt` lines) |

### nikulin (own card C291D27B; no display; the failing host)

Run in an ssh session from twerk with the forward up.

| Step | Command | Proves |
|---|---|---|
| N1 | `piggy version` | 0.1.23 lacks the fix; the new `auto` needs piggy ≥ the merge that lands this plan |
| N2 | `piggy list --format human` | nikulin's own card and its 9D ID (no PIN) |
| N3 | `ls -l ~/.local/state/ssh/piggy-agent.sock; SSH_AUTH_SOCK=~/.local/state/ssh/piggy-agent.sock ssh-add -L` | the forward is live and offers twerk's 9D key (compare with T3) |
| N4 | `systemctl --user status piggy-agent.service` | whether nikulin also runs a card-backed agent of its own (U today) |
| N5a | `d=$(mktemp -d); jq -r '.entries[] \| "\(.name) \(.ebox)"' ~/.local/state/piggy/secrets/manifest.json \| while read n e; do mkdir -p "$d/$(dirname "$n")"; ln -s "$e" "$d/$n.ebox"; done; PIGGY_STORE_DIR=$d piggy pass ls -r` | the recipients of every ebox, offline from the headers (no PIN): are both nikulin's (N2) and twerk's (T2) 9D IDs there? |
| N5b | `PIGGY_STORE_DIR=$d PIGGY_UNLOCK=card SSH_ASKPASS=$(command -v false) SSH_ASKPASS_REQUIRE=force piggy pass show-batch --format ndjson --out-dir "$(mktemp -d)" <one name>` (on 0.1.23 drop `PIGGY_UNLOCK`) | card-first: `pin-cancelled` naming the local card. The askpass refuses before any PIN reaches the card, so no retry is spent |
| N6 | needs the operator at twerk (PIN, maybe touch). On the new piggy: `PIGGY_AUTH_SOCK=~/.local/state/ssh/piggy-agent.sock piggy secrets reconcile -v` | `auto` picks the agent; twerk prompts (T6); entries come back `ok`, nothing prompts on nikulin |

If N5a shows only nikulin's key, `auto` keeps the local card and N6 cannot
work. The options then are re-encrypting to add twerk's 9D (circus owns the
recipients), or the (c) route: `ssh-add -X` against a card-backed agent on
nikulin from the ssh tty, then the unit.

Pre-bump workaround: on nikulin, inside the ssh session,
`SSH_ASKPASS_REQUIRE=never piggy secrets reconcile` prompts on that tty for
nikulin's card.

### Counterpart briefs

Each counterpart runs in a checkout of `piggy` (to read this plan) on its
host; `circus` works too if piggy is not checked out there.

**twerk:**

> You are the twerk counterpart for piggy#351. Read
> `docs/plans/2026-11-02-piggy-351-headless-pin-routing.md` in piggy (or ask
> piggy/sharp-hemlock for it). Run steps T1–T5 and report each output to
> piggy/sharp-hemlock/grock via chat. Public keys and GUIDs are fine to
> send; never send a PIN, a secret or a private key. Then stand by for N6:
> when nikulin's counterpart says it is starting N6, run T6 and report
> whether a PIN prompt appeared on twerk. The operator types the PIN; you
> never ask for it or handle it. Do not run any other command that touches
> the card.

**nikulin:**

> You are the nikulin counterpart for piggy#351. Read
> `docs/plans/2026-11-02-piggy-351-headless-pin-routing.md` in piggy (or ask
> piggy/sharp-hemlock for it). You need an ssh session from twerk with the
> agent forward live. Run steps N1–N5b and report each output to
> piggy/sharp-hemlock/grock via chat (public keys, GUIDs, recipient IDs and
> diagnostic kinds only; never a secret or a plaintext). N5b's askpass is
> `false`, so it spends no PIN retry. Do not run N6 until piggy/sharp-hemlock
> says go and the operator is at twerk; you never ask for or handle the
> PIN.
