piggy-agent(1)

# NAME

piggy-agent - PIV-backed SSH signing agent

# SYNOPSIS

*piggy agent* [*-A*] [*-g* _GUID_] [*-K* _PUBKEY_] [*-S* _SLOTS_] [*-a* _SOCKET_] [*--upstream* _NAME_=_PATH_...] [*--add-new-keys-to* _NAME_] [*--service-name* _UNIT_] [*--probe-interval* _SECONDS_] [*--poll-only*]++
*piggy agent* *--proxy-only* *--upstream* _NAME_=_PATH_... [*-a* _SOCKET_] [*--add-new-keys-to* _NAME_] [*--service-name* _UNIT_]++
*piggy agent* [*-s* | *-c*] [*-d*...] [*-D*] [_command_ [_args_...]]++
*piggy agent* *-i* [*-A*] [*-g* _GUID_] [*-S* _SLOTS_]++
*piggy agent* *-k*

# DESCRIPTION

*piggy agent* is a PIV-backed SSH agent that exposes signing keys from PIV
smart cards (such as YubiKeys) over the SSH agent protocol, and can front
other SSH agents so one socket serves every key a host should offer.

It is the Rust re-implementation that replaced the C *pivy-agent* on the
*piggy agent* dispatch path. The agent protocol is unchanged; the flag
surface is piggy's own (notably *-i* prints keys and exits rather than
running in the foreground as C's did). The C binary and its C-only
features (*-C* confirm, *install-service*) remain reachable as
*piggy pivy agent* until the C stack is retired.

On startup, the agent enumerates PIV tokens via PC/SC, reads public keys from
each slot, and begins listening on a Unix domain socket. SSH clients connecting
to that socket can use the PIV keys for authentication and signing — the
physical card must be present for each signing operation. The PIN is
requested on demand through *SSH_ASKPASS* (see *PIN PROMPTS*) and cached
until the card is removed.

If a _command_ is given on the command line, the agent starts in the background,
sets *SSH_AUTH_SOCK* and *SSH_AGENT_PID*, runs the command, and exits when it
completes. Otherwise the agent daemonizes and prints shell variable assignments
for *SSH_AUTH_SOCK* and *SSH_AGENT_PID* to stdout.

The agent unlinks its socket on SIGTERM/SIGINT. At bind it reclaims a
_stale_ socket file (one nothing accepts on) but never clobbers a socket a
live agent is serving — that fails with the usual address-in-use error, so
two agents cannot silently fight over one path.

# OPTIONS

*-g* _GUID_
	Use only the PIV card with the given GUID (full hex or short ID).
	Conflicts with *-A* and *--proxy-only*.

*-A*
	All-card mode: expose keys from every PIV card visible to PC/SC.
	Conflicts with *-g* and *--proxy-only*.

*-K* _PUBKEY_
	Card Authentication Key, an OpenSSH public key string (e.g.
	"ecdsa-sha2-nistp256 AAAA…"). Only cards whose slot 9E answers a
	challenge with this key are exposed: an anti-card-swap check
	matching the C agent's *-K*.

*-a* _SOCKET_
	Bind the agent to _SOCKET_ instead of an auto-generated path under
	_$TMPDIR_.

*-S* _SLOTS_
	Only expose keys from the listed PIV slots. _SLOTS_ is a
	comma-separated list of hex slot IDs, e.g. _9a,9d,9e_. Whitespace
	around each ID is trimmed. See *SLOT SPECIFICATION* below.

*--upstream* _NAME_=_PATH_
	Proxy the SSH agent listening on _PATH_ under the label _NAME_.
	Repeatable. See *UPSTREAM PROXYING*.

*--add-new-keys-to* _NAME_
	Route *ssh-add* (add-identity) requests to the named upstream.
	Without it, adds are refused: piggy's native keys live on the card,
	so an added software key needs a software agent to go to. Requires
	*--upstream*.

*--agent-timeout* _SECONDS_
	Per-upstream request timeout for connect, list and sign (default 5).

*--proxy-only*
	Serve no native PIV keys: never open PC/SC, run no card-presence
	loop, and proxy everything to the upstreams. Requires at least one
	*--upstream*; rejects *-g*, *-A*, *-K*, *-S*, *--probe-interval* and
	*--poll-only*. See *UPSTREAM PROXYING*.

*--probe-interval* _SECONDS_
	Card-presence reconcile interval (default 10). See *CARD PRESENCE*.

*--poll-only*
	Reconcile card presence by polling only, opting out of the default
	event-driven watch. The escape hatch if the PC/SC event path misbehaves
	on a host. Rejected with *--proxy-only*.

*--service-name* _UNIT_
	The systemd unit or launchd label this agent runs under, relayed in
	the *agent-mode@piggy* self-report so *piggy health* probes that unit
	(multi-instance units such as _piggy-agent-<name>.service_ report
	correctly). Unset, *piggy health* assumes the platform default
	(_piggy-agent.service_ or the launchd label). The home-manager module
	sets it.

*-k*
	Kill a running agent. Reads *SSH_AGENT_PID* from the environment, sends
	SIGTERM, and prints *unset* commands for *SSH_AUTH_SOCK* and
	*SSH_AGENT_PID*.

*-d*
	Increase debug verbosity. May be repeated: *-d* enables debug logging,
	*-dd* enables trace logging.

*-D*
	Foreground debug mode. Equivalent to a single *-d* but stays in the
	foreground.

*-i*
	Print key info and exit. For each key, prints the slot ID, algorithm,
	and OpenSSH public key string.

*-s*
	Generate Bourne shell commands on stdout (default unless *$SHELL* ends
	in _csh_).

*-c*
	Generate C-shell commands on stdout.

# UPSTREAM PROXYING

With one or more *--upstream* flags the agent also fronts other SSH
agents, so its socket can be the sole *SSH_AUTH_SOCK* without an
agent multiplexer in between:

- The identity list is the native PIV keys first, then each upstream's
  keys in flag order.
- A sign request is answered natively when the key is on a card here,
  else routed to the upstream that listed it.
- Extension requests the agent owns (the piggy card extensions
  *ecdh@joyent.com*, *ecdh-rebox@joyent.com*, *ykpiv-attest@joyent.com*)
  are answered natively when the key is served here; on a _native miss_
  (the key is not one of ours) they fall through to the first upstream
  that supports them. A genuine error in a request the agent owns is never
  turned into a fallthrough.
- Lock and unlock fan out to every upstream.
- Add-identity goes to the *--add-new-keys-to* upstream or is refused.
- A dead upstream degrades the listing to whatever the others serve; it
  does not break the agent. *piggy health* reports each upstream's state.

*--proxy-only* is the remote-host shape of this (piggy FDR 0001): a host
reached over SSH runs a cardless front on a stable socket path, its
upstreams being the forwarded, card-backed agents. Workstations run the
card-backed agent, optionally proxying a stock *ssh-agent* for software
keys. Either way every host has one *piggy-agent* socket.

# CARD PRESENCE

The card-backed agent re-enumerates PC/SC on a reconcile loop: each pass
drops a removed card's keys and cached PIN and adopts a newly inserted
card (after a successful sign, so a half-inserted card is never
advertised). *--probe-interval* sets the polling cadence; a removed card
clears after a few consecutive misses. While the agent serves no keys in
its first ~30 seconds it polls about once a second, so a card held by an
outgoing agent during a deploy is adopted promptly.

By default presence is also event-driven: a watcher thread blocks in
_SCardGetStatusChange_ and, when a reader transitions, triggers an
immediate pass that collapses the miss debounce for that reader's card
only. The polling loop stays as the safety net. *--poll-only* disables
the watcher.

# SELF-REPORT EXTENSIONS

The agent answers two piggy-private agent extensions that *piggy health*
consumes; other agents need not implement them:

*agent-mode@piggy*
	The agent's role (card-backed or proxy-only), its *--service-name*,
	and whether presence is event-driven.

*upstream-status@piggy*
	One entry per *--upstream*: name, reachable or not, key count.

# PIN PROMPTS

The PIN is requested on demand through the *SSH_ASKPASS* program, with
*SSH_ASKPASS_REQUIRE* selecting the route: _force_ always runs the
program, _never_ reads a tty or refuses, unset or _prefer_ tries a tty
first. _contrib/piggy-askpass.sh_ is the shipped helper: it renders
piggy-aware context above the prompt, re-derives a live Wayland display
when the agent inherited a frozen *systemd --user* environment, and
refuses rather than guessing. Test harnesses must point *SSH_ASKPASS* at
a non-interactive helper; see *piggy-testing*(7).

# SLOT SPECIFICATION

The *-S* option accepts a comma-separated list of PIV slot IDs in hexadecimal.
Each ID must be a valid PIV slot as defined below. Whitespace around each ID is
trimmed.

Examples:

```
piggy agent -S 9a             # authentication slot only
piggy agent -S 9a,9d,9e       # three specific slots
piggy agent -S 82,83,84       # first three retired slots
piggy agent -S " 9a , 9e "    # whitespace is tolerated
```

An invalid hex value or an unrecognized slot ID causes an immediate error.

# PIV SLOTS

The following PIV slot IDs are recognized:

[[ *Slot*
:[ *Purpose*
|  9A
:  Authentication (PIV standard)
|  9C
:  Digital Signature (PIV standard)
|  9D
:  Key Management / ECDH (PIV standard)
|  9E
:  Card Authentication (PIV standard)
|  82–95
:  Retired Key Management (20 slots, PIV standard)
|  F9
:  Attestation (YubiKey-specific)

The slot set is authoritative and derived from _piggy_piv::slot::slot_to_cert_tag_.
Each slot maps to a PIV data object tag used for certificate storage.

The default behavior (no *-S*) is to expose all populated slots from the
selected card(s).

# ENVIRONMENT

_SSH_AUTH_SOCK_
	Set by the agent on startup to the Unix socket path. Inherited by child
	processes when _command_ is given.

_SSH_AGENT_PID_
	Set by the agent on startup to its process ID. Read by *-k* to find the
	agent to kill.

_SSH_ASKPASS_, _SSH_ASKPASS_REQUIRE_
	The PIN prompt program and its route; see *PIN PROMPTS*.

_STATSD_HOST_, _STATSD_PORT_
	Opt in to stats-me telemetry. Their _presence_ is the gate: with
	neither set the agent emits nothing. When present, one fire-and-forget
	statsd datagram per request: counter _piggy.agent.<op>.<result>:1|c_
	and timer _piggy.agent.<op>.duration:<ms>|ms_, tagged
	_#op:<op>,result:<result>_, plus the finer _piggy.agent.pin_prompt_,
	_pin_cleared_ and _cak_ events. An empty _STATSD_HOST_ means
	_127.0.0.1_; _STATSD_PORT_ defaults to _8125_ (stats-me-clients(7)).

_SHELL_
	Consulted to auto-detect shell output format when neither *-s* nor *-c*
	is specified. If *$SHELL* ends in _csh_, C-shell format is used;
	otherwise Bourne shell format.

# EXAMPLES

Start the agent and eval its output in a Bourne shell:

```
eval $(piggy agent)
```

Run a command under the agent:

```
piggy agent ssh user@host
```

Show available keys without starting the agent:

```
piggy agent -i
```

Expose only the authentication and card-auth slots from all cards:

```
eval $(piggy agent -A -S 9a,9e)
```

A workstation agent that also holds software keys added with *ssh-add*:

```
ssh-agent -D -a /run/user/1000/soft.sock &
piggy agent -A -a /run/user/1000/piggy-agent.sock \\
  --upstream soft=/run/user/1000/soft.sock --add-new-keys-to soft
```

A cardless front on a remote host over a forwarded agent socket:

```
piggy agent --proxy-only -a /run/user/1000/piggy-agent.sock \\
  --upstream forwarded=$SSH_AUTH_SOCK --service-name piggy-agent.service
```

Kill a running agent:

```
eval $(piggy agent -k)
```

# SEE ALSO

*piggy*(1), *piggy-testing*(7), *piggy-piv-slots*(7), *ssh-agent*(1),
*ssh-add*(1), *pivy-agent*(1)
