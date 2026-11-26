---
status: exploring
date: 2026-11-26
promotion-criteria: >
  exploring -> proposed when the operator has ruled the open questions
  marked "blocks". proposed -> experimental when, in a test lane, a sudo
  authentication succeeds through pam_piggy with PIN and touch (plain,
  -i and -A, with no password path in any), is refused with the recovery
  route printed when the card is absent, and the admin account turns
  pam_piggy sudo off and back on with no card and no deploy.
---

# pam_piggy: card-backed PAM authentication

> **Status of this draft.** piggy#408. Nothing is built. The only code is
> throwaway probes (`nix/vm-tests/pam-*-probe.nix`, run with
> `just debug-vm-probe NAME`). A result marked **asserted** is checked by
> its probe, which last passed on 2026-11-26; no gate runs the probes, so
> a later change shows only when one is run. Other results are readings of
> a run's log. "Recommend" marks a recommendation, not a ruling.

## Problem Statement

Becoming root asks for a typed password or relies on account setup,
although a PIV card whose slot 9C needs a PIN and a touch on every use
is available. No PAM module that piggy builds or ships uses it: C pivy's
`pam_pivy` was never built, and the C-pivy retirement plan drops it. piggy#408 asked for polkit/pkexec first; the operator has since
ruled that **sudo is piloted first**.

## The sudo pilot as a user sees it

**Story.** On a host with pam_piggy sudo I type `sudo systemctl restart
nginx` as my normal user account. A piggy dialog, on the machine where
my card is, says which host and account are asking, which user and group
the command would run as, and shows `systemctl restart nginx`. I enter the PIN and touch the card, and the
command runs. With no card, sudo refuses at once and tells me to use the
admin account.

    me        sudo + pam_exec        helper                 piggy-agent / card
     |  sudo CMD  |                    |                            |
     |----------->| auth phase         |                            |
     |            |------------------->| fresh challenge            |
     |            |                    |--- operator act (text) --->|
     |<---------------- dialog: host, accounts, CMD ----------------|
     |------------------------------ PIN, touch ------------------->|
     |            |                    |<-------- signature --------|
     |            |<---- exit 0 -------| verify against root-owned  |
     |<-- CMD runs|                    | key list                   |
     |            |                    |                            |
     |  no card:  |<--- exit nonzero --| prints the recovery route  |

## Threat model

**To protect:** root on each host, and the card PIN.

| Who | What they can do | What stands against it |
|---|---|---|
| Code running as the normal user account, **agent sessions included** | Run sudo and raise a genuine prompt. One PIN and touch gives it root. Signal the helper. | The prompt shows the arguments, and the operator declines what they did not start. **The operator has said agents will later be confined, with no sudo, escalating only through hogtie. That is not built.** |
| The same code, able to draw over windows or read input | Imitate a dialog; capture the PIN, then drive the 9C slot with another tool, leaving only the touch | Nothing in piggy. RFC 0012 relies on a display surface agents cannot write to and says piggy does not provide it. By ruling, no host enables the pilot while this is possible there. |
| A program that reaches the agent socket | Ask for operator acts; fill the screen with prompts | Each act needs PIN and touch and shows its text. The cancel limit is per connection only. |
| A program posing as the agent | Answer the helper | It cannot sign without a listed key. |
| Another local user | Place a socket where the helper looks | Required: the helper checks the socket directory's owner, or the peer's uid, against the user being authenticated. Where it takes the path from is open question 4. Not built. |
| Whoever controls a machine the agent is forwarded through | Relay or raise requests | Same as for the socket above; the prompt appears where the card is. |
| Agent code on another host that can log in to this one | Run sudo here, on a host that runs no agents itself | The prompt and the card, as in the first row. By ruling such logins may reach the pam_piggy account, never the recovery account. Which logins reach a host is checked before it is enabled. |
| An older agent that serves a listed key | Sign the new namespace on an **ordinary** request: no shown text | Only an agent that knows a namespace refuses it. Required below: no older agent ever serves a listed key. |

**Relied on:** the card's attested PIN-always, touch-always 9C policy;
the agent showing exactly the text it signs; the integrity of the sudo
and PAM configuration and of the key list, all writable by root only.

## Ruled by the operator (2026-11-26)

- **Pilot order:** sudo first, polkit later.
- **sudo shape:** the normal user account's sudo accepts **only**
  pam_piggy. Not the shape that authenticates the admin account.
- **Scope:** **any command**, with sudo's arguments shown. Agents will
  later be confined, without sudo, and will escalate only through
  hogtie.
- **Fleet default:** the end state on every host is that the normal user
  account gets sudo through pam_piggy only and the admin account keeps
  full sudo. Where the normal account has no general sudo, this **adds**
  a way to root.
- **Each host is approved:** after the first, a host is enabled only when
  the operator approves it from the pilot's results.
- **New root waits for confinement:** a host where the normal account has
  no general sudo gets it only after agents are confined. Hosts where it
  already has sudo may go first.
- **One exception, newer:** a host that runs no agents directly may be
  the tracer bullet without waiting for confinement.
- **Agent logins from elsewhere:** they may reach the pam_piggy account
  of an enabled host, since each sudo still needs the PIN and a touch.
  They must not reach its recovery account.
- **Fake-dialog protection comes first:** no host enables the pilot while
  agent sessions can draw on or read the operator's display. How a host
  meets this is not designed (open question 13). Whether it binds the
  tracer bullet is **not yet ruled**; until it is, it binds.
- **Recovery:** through the admin account, which is to accept a password
  or one of the card slots registered in PAPI that need PIN and touch on
  every use (which slots, open question 17). The normal account never
  gets password sudo, and no second fallback is added for it. The escape
  hatch required below is the admin account's, not a fallback of the
  normal account.
- **The admin password is a named exception:** a password gives root
  without a card, outside the card's chain of authority. The operator
  accepts this, with no commitment to remove it, so that recovery works
  when cards or card software fail.
- **Host trust:** a list of allowed keys first. CA trust (X.509 chains
  and SSH CA certificates) comes later, tracked in piggy#408.
- **Agent path:** a new `operator-act@piggy` namespace (an RFC 0012
  amendment). The `approval` class is for decisions that grant no right,
  so it does not fit.
- **Module shape:** `pam_exec.so` with a helper for the pilot. Rust
  cdylib alone against cdylib with a helper **must be decided
  afterwards**, with `pam_pivy` as prior art. piggy-agent may need to
  stay in the path because `pcscd` access needs mutual exclusion.
- **Socket (for reaching the agent):** test, then move the main agent
  socket under `/run` with a symlink at the old path, falling back to the
  old behaviour if the directory is missing. A fallback that acts only at
  start is enough.
- **Polkit stage: not approved** (below).

Ownership between repos is not ruled (open question 22). The circus session, which owns the
host side, proposes: piggy designs the helper, the signed act and its
verification; circus the accounts, sudo rules, key-list provisioning,
rollout and recovery.

## Pilot requirements

Required of the sudo pilot. Where one depends on a choice still open, the
open question says so.

- **The act names what it grants:** the target user and group (root
  unless sudo is told otherwise), on this host, for this account, for
  the sudo arguments shown, bound to a fresh challenge.
- **Keys are enrolled only on proof:** a key enters the allowed list only
  after a root-side attestation check that it is a 9C key with PIN always
  and touch always. `piggy tool attest-verify` checks the policies only
  when given `--expect-pin` and `--expect-touch`. How root enrols a key on
  a host where the card is not attached is not designed. The helper
  itself checks only the signature, so a listed key that is anything
  else would be accepted.
- **The prompt fits one screen**, marks the root escalation visibly, and
  never cuts or misstates a command: what does not fit, or cannot be
  shown truthfully, is **refused**. piggy#400 currently waives the
  one-screen rule for operator acts, so this needs its own check.
- **No way around the card:** no sudo approval cache, no password in the
  plain, `-i` or `-A` stacks, and no remaining `NOPASSWD` rule that
  gives the normal user account root an agent could use freely. Each
  existing rule is reviewed before a host is enabled.
- **The new namespace cannot be signed silently:** like the others, an
  ordinary sign over its sshsig data is refused. The refusal is a list
  built into each agent. So the standing rule is that **every agent that
  can serve a listed key knows the namespace, for as long as the key is
  listed**: forwarded agents, agents attached to the card later and
  agents restored by a rollback included. All are upgraded before a key
  is listed or a host enabled, and the refusal is tested. What enforces
  the rule afterwards is open question 21.
- **The caller's `PATH` does not pick the program:** `secure_path` is set
  for the account, naming only directories the caller cannot write.
- **Agent code cannot use the recovery account:** shown for each host
  before it relies on it.
- **Every refusal prints the recovery route:** no card, no agent,
  timeout, unusable socket directory, command that cannot be shown. A
  helper that cannot run or is killed prints nothing, so the PAM stack
  itself must also print the route on failure (not designed).
- **Prove both before removing anything:** on each host a login to the
  admin account with no card is exercised, and a pam_piggy
  authentication succeeds there through a side PAM service, before any
  existing password or `NOPASSWD` route of the normal account is removed.
- **An escape hatch without a deploy:** the admin account, with no card,
  can turn pam_piggy sudo off without building or deploying, and turn it
  back on. How is **not designed**. Activating an earlier system
  generation is a candidate, untested, with known gaps: it helps only
  while such a generation without pam_piggy still exists (after a later
  deploy the previous one has it too, and old ones can be collected), it
  also rolls back other declared system configuration changed since
  (which on a card host may restore an older piggy agent), and whether it
  survives a reboot or the next deploy, and how to return, are not
  traced.
- **Fail closed:** only a clean exit 0 after full verification
  authenticates; the helper has its own time limit, since `pam_exec` has
  none.
- **No new permission logic.** pam_piggy only authenticates. What may run
  stays with sudo's own rules (open question 18).
- **Codec first:** extract the `operator-act@piggy` codec from the
  `piggy` crate into a small crate that both use. No copy.
- **Rollout:** one host at a time behind a per-host option, off by
  default; the least critical host first and the coordinator's host last.

## Intended flow

1. The helper makes a fresh challenge.
2. It asks the user's piggy-agent for an operator act over a text that
   holds the challenge and what is being granted.
3. The agent checks that the card attests a 9C key with PIN and touch
   always, shows the text on its PIN prompt and signs after the touch.
4. The helper verifies the signature, namespace and exact text against a
   root-owned list of keys for the user being authenticated.

The signature decides, not the socket. A malicious process can still pass
a challenge of its own to the real agent, so the prompt text is an
important defence. The CA path is later reused for hogtie operations.

## Examples

Sketches, **not to be applied**: the shape was tested with a stand-in
helper (below), the real helper and its arguments are not designed.
sudoers, for the normal user account:

    Defaults:USER pam_service=sudo-piggy
    Defaults:USER pam_login_service=sudo-piggy
    Defaults:USER pam_askpass_service=sudo-piggy
    Defaults:USER timestamp_timeout=0
    Defaults:USER secure_path="ROOT-OWNED-DIRECTORIES"

and the auth phase of `/etc/pam.d/sudo-piggy` (whether to add `seteuid`
is open question 2):

    auth required pam_exec.so stdout HELPER

## The sudo pilot

`just debug-vm-probe pam-sudo` sets up the examples above on sudo
1.9.17p2, with a stand-in helper that records what it is given and then
allows or refuses. No card or signature is involved. All of this section
is asserted, except what is marked otherwise.

**The setup holds:**

- With the helper refusing, no password path was left: plain, `-i`, `-s`,
  `-A` and `-A -i` all failed although the right password was supplied,
  with and without `seteuid`. A control account's password worked.
- With `timestamp_timeout=0`, two commands in one shell called the helper
  twice. With `-n` sudo refused without calling it.
- `-v` calls the helper with no command to show. `-l` did not call it for
  an account that has a `NOPASSWD` rule.
- A `NOPASSWD` rule runs with no call at all.
- `PAM_USER` and `PAM_RUSER` name the invoking user, also under `-u`.

**The arguments do not say what runs:**

| Case | What happened |
|---|---|
| `sudo id -u`, the caller's `PATH` led by their own directory, no `secure_path` | **the caller's `id` ran as root**; the arguments read `id -u` |
| the same with `secure_path` set for the account | the system `id` ran |
| `SHELL=PROGRAM sudo -s id -u` | **PROGRAM ran as root**, also with `secure_path`; the arguments read `-s id -u` |
| `sudo -s` | a shell |
| `sudo -i id -u` | the target account's login shell ran the command; the caller's `SHELL` was ignored |
| `sudo -e FILE` | the caller's editor ran **as the caller** on a copy (the write back by root is `sudoedit`'s documented behaviour, not asserted): approving it lets the caller put anything in FILE |
| `-u USER`, `VAR=value` | in the arguments only |
| a relative path | depends on the working directory, which is not in the arguments; the helper could read sudo's |

The helper could also read the caller's `PATH` and `SHELL` from
`/proc/PARENT/environ`, but repeating sudo's own resolution from them
would be a second implementation that can disagree with it. sudo's log
named the resolved command even for refused attempts, so sudo had
resolved it before authentication failed.

**A candidate that is not tested:** `sudo_plugin(5)` describes an
*approval plugin*, run after the policy accepts a command, which is
given `command_info`, `run_argv` and `run_envp`. That is sudo's own
account of what will run. It would change the ruled `pam_exec` shape and
put a shared object in sudo's process.

**The helper and its surroundings:**

- sudo gave the helper only `PAM_RUSER`, `PAM_SERVICE`, `PAM_TYPE` and
  `PAM_USER` (and a locale variable). The caller's `SSH_AUTH_SOCK` did
  not reach it.
- Without `seteuid` the helper keeps the caller's real uid, and **the
  caller could stop, continue and kill it**; after the kill sudo refused.
  With `seteuid` all three signals were refused. `ptrace` was not tried.
- From either, the helper reached a `piggy agent` (proxy-only, no card)
  on a socket in the user's mode-0700 directory, with no socket move.
- Not tested: the dialog, a terminal (`PAM_TTY` was unset with none),
  a card, and a forwarded agent. The dialog appears where the card agent
  runs.

## What the module can learn about a request

**PAM carries no command.** The items `pam_get_item(3)` lists are the
service, user names, tty, remote host, tokens, the conversation and a few
Linux-PAM extras.

From the polkit 127 sources (distribution patches not checked), polkit's
helper calls `pam_start("polkit-1", USER)`, sets `PAM_RUSER` to **the
same user** despite its comment calling it the requesting user, sets no
`PAM_TTY` or `PAM_RHOST`, and clears the environment but for `PATH`,
`LANG` and `LANGUAGE`. `pkexec` sends `program` and `command_line` to
polkitd, not to the PAM helper. Its dialog message uses `cmdline_short`,
which for a command over 80 bytes **cuts out the middle**.

`just debug-vm-probe pam-command` runs a `pam_exec` helper under `pkexec`
and sudo (asserted):

| | polkit helper | sudo |
|---|---|---|
| `PAM_TTY` | not set | set |
| Helper's ids | ruid 0, euid 0 | **ruid the user**, euid 0 |
| Parent process | `polkit-agent-helper-1` | **`sudo` with the command's arguments** |
| Process list | with two overlapping requests, each helper saw both `pkexec` command lines at some point during its wait | not probed |

The guest has one user, both requester and admin, so the probe cannot
show whom `PAM_RUSER` names.

Under polkit the process list is **not bound to the request**, and not
every polkit action comes from `pkexec`: by reasoning, another kind of
action raised while the operator's `pkexec` waits would be shown with the
operator's command. **Do not show it.**

Under sudo the parent is the process asking, so the helper can show its
arguments. Those are the arguments given to sudo, **not necessarily what
runs** (below), and an operator-act text is capped at 4096 bytes.

## Module shape and language

What the helper needs from piggy is small: the `operator-act@piggy`
codec, one request, and an sshsig check. It should not link the `piggy`
crate, which brings in OpenSSL, PC/SC and tokio. The existing client has
no timeout. Naming each listed key in turn needs no identity listing: an
agent that does not serve a key answers `no-such-key` with no prompt.

For verification, hogtie is prior art: it links no other piggy crate and
runs `ssh-keygen -Y verify` with an empty environment and a timeout. An
allowed-signers file fits the key list. It does **not** by itself give
SSH CA trust: an operator act's sshsig carries the plain key, not a
certificate, so that step needs a protocol or agent change.

| Shape | Our code in the PAM process | Cost |
|---|---|---|
| Rust cdylib alone | all of it | A PAM binding and the FFI boundary. A panic or a hang is in the host process. |
| cdylib + helper | the binding and the launcher | Two artifacts and the interface between them. |
| `pam_exec.so` + helper | none | No FFI of ours. The PAM stack names `pam_exec.so`, not `pam_piggy.so`. |

From `pam_exec.c` at Linux-PAM v1.7.2:

- Success only when the child's wait status is 0.
- It waits with no timeout.
- The child gets the PAM environment list plus the `PAM_*` items, not the
  caller's process environment.
- Without `seteuid` the child keeps the caller's real uid: under sudo the
  invoking user, with effective uid root. By Linux's rules
  that user can then signal the child (tested, below) but not ptrace it
  (not tested). With equal uids
  the dynamic loader honours `LD_*` from the child's environment.
- With `stdout`, lines the helper prints reach the PAM conversation.

**Ruled for the pilot:** `pam_exec.so` with a small standalone helper. It
adds no FFI to the trusted base. Under a piggy-only sudo, undoing it
needs root through the admin account.

PAM bindings, for the later cdylib decision, from their lib.rs and
docs.rs pages (2026-11-26); code not reviewed, none in `Cargo.lock`:

| Crate | Latest | Licence | Notes |
|---|---|---|---|
| `pam-bindings` | 0.4.0, 2026-10-19 | MIT | depends on `libc`, `zeroize`; Linux-PAM only |
| `nonstick` | 0.1.2, 2026-03-13 | MIT | fork of `pam-bindings`; several PAM implementations; pre-1.0 |
| `pamsm` | 0.5.5, 2024-06-28 | GPL-3.0 | about 550 lines |

Writing the few entry points ourselves is a further option, not sized.

## Prior art

| Existing thing | Why it is not the route |
|---|---|
| `pam-ssh-agent` (1.0.0) | Authenticates with an ordinary agent signature: no shown text, no attested policy. It does not fit the operator-act ruling. |
| `pam_p11` (README, 2026-11-26) | Reaches the card itself through PKCS#11, not through the agent, so no forwarding and a second card client. It is documented to trust files in the user's home, and checks no CA chain. |
| hogtie (this repo) | A root door for agent sessions: named actions under operator-signed grants. Not general sudo for a person. Its verification approach is reused. |
| `pam_pivy` (vendored, never built) | Below. |

`pam_u2f` and `pam_pkcs11` were not examined. From general knowledge,
not from reading them: `pam_u2f` uses FIDO credentials rather than a PIV
slot, and `pam_pkcs11` reaches the card itself, as `pam_p11` does;
neither would use an operator act. Sibling repos were not searched
(open question 20).

From reading `vendor/pivy/src/pam_pivy.c`:

| `pam_pivy` | For pam_piggy |
|---|---|
| Talks to the card itself over PC/SC | Sign through the agent, which keeps card access in one place |
| Trusted keys come from the user's `~/.ssh/authorized_keys` | A root-owned list |
| Finds cards through files under the user's `~/.config/pivy-agent` | Do not let user files choose what is trusted |
| Signs with whichever slot matches, asks for a PIN only if the card demands it, checks no attestation or touch: by this reading a listed key in a no-PIN slot would authenticate with none | Require the attested 9C PIN-always, touch-always policy |
| Asks for the PIN through the PAM conversation | The PIN stays in piggy's prompt |
| Then sends the PIN to the agent at a socket under the process's `XDG_RUNTIME_DIR`; where that environment is the caller's, the caller would choose who receives it (not tested) | Never take the socket path from the environment; never forward a PIN |
| All of it, in C, in the PAM process | A data point for the later cdylib decision |

## Polkit stage: not approved

**The operator ruled the polkit stage not approved** (piggy#417 tracks
it): it does not ship until the request can be tied to what the prompt
shows, or the operator accepts the remaining risk by name. The cause: under polkit the prompt can say host,
user, service, time and challenge, and **cannot say what is being
approved**. Code running as the user can start its own `pkexec` and get a
genuine prompt that looks like the operator's own; approving it gives
that code root. (The socket unit sets no mode, so any local user can
likely raise the prompt too; not tested.)

Mitigations researched at the operator's request. **None closes it**; the
operator leaned to the first two before ruling the stage out for now.

| Mitigation | Helps against | Limits |
|---|---|---|
| **Matching code** in polkit's dialog and the card prompt, compared by eye, or typed (an agent and askpass change) | Approving another request by mistake | Code that can draw or cover windows can show a matching one |
| **One at a time:** the agent refuses a second pending PAM act and says two arrived | A coinciding request | Not a lone prompt; can be used to block |
| **Refusal limit** across connections | Repeated prompts | The existing limit is per connection |
| **Caller details** from `SO_PEERCRED` | A weak clue | Names the authentication agent, which an attacker chooses; by reasoning (not checked) **not available under `pam_exec`**, whose helper does not hold the caller's connection |

A line the helper prints reaches the terminal while the helper still runs,
through `pkttyagent`, `pkexec`'s own agent and sudo (asserted). **No
desktop authentication agent was checked.**

### The built-in `pkexec` agent failed

With `pkexec`'s own textual agent, authentication failed and polkitd
answered `No session for cookie`, both with the probe helper and with the
stock stack and a typed password, where `pkttyagent` succeeded
(asserted). That PAM had approved by then is an inference. The helper instance names end in the connecting uid: 0 for
the built-in agent, the user's for `pkttyagent`. **Theory:** setuid
`pkexec` connects as root and polkitd cannot match the request. Not
tested on a real host or with a desktop agent.

## Reaching the agent

This matters for the polkit stage, which is not approved. The socket
work is ruled but not scheduled (open question 6).

With polkit 127 on NixOS, PAM runs in `polkit-agent-helper@.service`,
which sets `ProtectHome=yes`, `PrivateTmp=yes` and
`ProtectSystem=strict` (read from the unit in the probe's log, not
asserted). `just debug-vm-probe pam-sandbox` replaces only its
`ExecStart` and connects, as the unit's root, to stub listeners owned by
an ordinary user. The table is asserted:

| Socket under | Unit as shipped | `BindReadOnlyPaths=` on `~/.local/state/piggy` | `ProtectHome=tmpfs`, bind `~/.local/state/piggy` | `ProtectHome=tmpfs`, bind `/run/user/UID` |
|---|---|---|---|---|
| `~/.local/state/piggy` | no | no | yes | no |
| `/run/user/UID` | no | no | no | yes |
| `/tmp`, `/var/tmp` | no | no | no | no |
| a directory directly under `/run` | yes | yes | yes | yes |
| a directory under `/var/lib` | yes | yes | yes | yes |

So the home-manager module's default socket is out of reach as the unit
ships. Not probed: a real PAM module inside `polkit-agent-helper-1`, an
agent restart behind a bind mount, a bind source that does not exist.

The agent serves one socket. Options: move it (no agent code); a
`--proxy-only` relay beside it (no agent code, one more unit, had been
recommended); a second listener (new code). Either of the first two
needs a per-user directory under `/run` that root creates. **Ruled:**
move it and leave a symlink.

`just debug-vm-probe pam-socket-move` runs the real `piggy agent`,
proxy-only (no card), behind a **prototype** launcher that uses the
directory only if it is a real directory, owned by the user, mode 0700
(asserted):

| Case | Result |
|---|---|
| Directory missing at first start | serves the old path |
| Directory present, a leftover socket at the old path | moves; the old path works through the link, also after a restart |
| A symlink in place of the directory | serves the old path |
| Directory removed, then restart | serves the old path |
| Directory mode 0755, or owned by root | serves the old path |
| Directory removed **while the agent runs** | **the old path fails although the unit stays active**; a restart recovers |
| No fallback logic, directory missing | the agent exits with an error |
| polkit helper unit, moved | reaches the `/run` path, not the old link |
| polkit helper unit, fallback | reaches neither |
| `--upstream` naming a link to the agent's own socket | **not refused** (piggy#416) |

Not tested: a card-backed agent, boot ordering, the home-manager module,
a sandbox that binds only the old directory (by reasoning it would see a
dangling link), SSH forwarding. The helper must check the directory's
owner, or the peer's uid, against the user being authenticated.

**The link and the fallback are temporary** (piggy#418 tracks the move
and their removal). Remove both once every client uses the new path and every host that runs the agent has the
directory.

## Sharing the card

The agent signs, so the helper needs no PC/SC access. Within one agent,
one lock serializes card sections; it does not cover other processes,
which rely on PC/SC transactions. The PIN prompt is outside that lock,
but prompts take turns, so a request can wait behind another dialog.
While the card waits for a touch, the lock and the transaction are held.
piggy#415 tracks an unconfirmed gap: the operator-act attestation checks
run outside a transaction.

## Open questions

| # | Question, plainly | Recommendation |
|---|---|---|
| 1 | **(blocks)** How does the admin account switch pam_piggy sudo off with no card and no deploy? | Test activating an earlier generation first, since it adds no mechanism; its gaps above may rule it out. |
| 12 | **(blocks)** How is it shown, per host, that agent-run code cannot use the recovery account? | A checklist and a negative test, kept with the host configuration. |
| 17 | **(blocks)** Which PAPI-registered card slots are the canonical ones for the admin account's sudo, and what verifies them? | Settle it with the circus session; require PIN and touch on every use, checked by attestation. |
| 19 | **(blocks)** The design and every probe assume Linux. On any other platform nothing is checked, including whether the `pam_exec` shape exists. | Check on a real system of each such platform before enabling it. If the shape is absent, it comes back to the operator. |
| 21 | **(blocks)** What keeps an agent that does not know the namespace from ever serving a listed key, after rollbacks and for agents attached later? | Not designed. |
| 22 | Which repo owns which part? | The split proposed above. |
| 18 | pam_piggy sits outside the shared policy engine and hogtie's action registry. Is that right? | Yes: hogtie is the door for agent sessions, with named actions under signed grants; this is the operator's interactive sudo, which confined agents will not have. |
| 20 | **(blocks)** Has a sibling repo already built part of this, and could `pam_u2f` or `pam_pkcs11` serve? | Search the repos and examine both modules. |
| 13 | **(blocks)** The pilot waits until agent sessions can neither draw on nor read the operator's display (ruled). How does a host meet that, and how is it checked? | Settle it with the circus session as part of confinement; test it by attempting both from an agent session. |
| 15 | **(blocks)** The command must be shown on every use, but the agent cannot tell what the askpass program displayed: one that ignores the text shows a bare PIN prompt and the act is still signed (piggy-agent(1)). What makes that impossible, or detectable, on the card's host? | Treat the agent and askpass of the card's host as part of the trusted base: both root-owned or otherwise outside what agent sessions can replace. Not designed. |
| 16 | **(blocks)** Which tracked work delivers agent confinement and the display separation? Hosts that already have sudo may go before confinement. A search by the circus session found no single item for either. | The circus session owns it; cite its work here. |
| 14 | **(blocks)** RFC 0012 says callers must not put secrets in an act's text, and sudo arguments can hold one; the text also crosses forwarded agents. | State that secrets on a sudo command line are unsupported, and settle what the helper does when it suspects one. |
| 2 | **(blocks)** Should the helper run as root (`seteuid`)? Without it the user who is asking can stop or kill it (tested). | Yes: with it those signals were refused. Give it a fixed environment. |
| 3 | **(blocks)** The arguments do not say what runs: `-s` runs the program the caller's `SHELL` names, and `sudoedit` lets the caller write any content (tested). The prompt must not misstate a command. Does the ruled `pam_exec` shape stay, refusing what it cannot show truthfully, or does the decision move to a sudo approval plugin? | Test the approval plugin first: whether it is given the resolved program and arguments for each mode above. If the shape stays, refuse `-s`, `-e` and `-v`, require `secure_path`, and show the working directory. |
| 4 | **(blocks)** How does the helper find the right agent socket, including where the user's agent only relays? | A root-owned per-host setting. |
| 5 | The namespace name, display class and text for the RFC 0012 amendment, and whether the text reuses `piggy-act-v1` (RFC 0013). | A namespace of its own, with a class that looks unlike every other. |
| 6 | Does the socket move happen now, or wait for the polkit stage? | Wait, unless the sudo tests show a need. |
| 7 | Who creates the `/run` directory, and what is it called? | A system `tmpfiles` rule, one directory per user, owned by circus's host config. |
| 8 | Where does the allowed-key list live, and in what format? | A root-owned OpenSSH allowed-signers file per host. |
| 9 | What happens on a timeout, or while another prompt is open? | Refuse after a fixed limit and print why. |
| 10 | Repeated prompts: the cancel limit is per connection. | A limit across connections for this namespace, in the agent. |
| 11 | After the pilot: cdylib alone, or cdylib with a helper? (**must** be decided) | Decide from the pilot's evidence. |

## Limitations

- No CA trust in the first version.
- Only sudo, for one account on one host, in the first stage.
- Showing the command does not bound what it does: a shell, an editor,
  an interpreter or a script that changes after the prompt can do more.
- The design and every probe are Linux only (open question 19). Whether
  every host can run this has not been checked.

## More Information

- piggy#408; piggy#415; piggy#416; piggy#417; piggy#418; piggy#289 (the
  C-pivy retirement that drops `pam_pivy`)
- RFC 0012 (`docs/rfcs/0012-operator-act-extension.md`), piggy-agent(1)
  OPERATOR ACTS and PIN PROMPTS, hogtie(8)
- `nix/vm-tests/pam-*-probe.nix` (with `probes.nix` and
  `pam-probe-lib.nix`): probes, to be deleted once the pilot has real
  tests. No gate runs them, so "asserted" means they held when
  this version of the record was written; before deleting one, name here
  the test that replaces it or the commit the result was observed at.
