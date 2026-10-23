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

*--upstream-grace* _SECONDS_
	How long a listing that finds every upstream unreachable keeps
	redialing before it answers with a failure (default 3). Applies only
	when the agent serves no native keys. See *UPSTREAM PROXYING*.

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
- When every upstream is unreachable and the agent serves no native keys
  (a *--proxy-only* front during an outage of its backings), the listing
  redials with backoff for *--upstream-grace* seconds and, if none answers,
  fails with SSH_AGENT_FAILURE rather than answering an empty list: a
  client then reports an agent error, not a missing key (*ssh-add -l*
  prints "error fetching identities"). An upstream that answers with no
  keys is an answer, not an outage.
- A sign that never reaches its upstream (the socket is gone, the
  connection dropped) is retried once after a fresh listing, which may
  route it to another upstream serving the same key. A refusal is not
  retried, nor is a timeout: the upstream may still be waiting on a PIN or
  a touch.
- The agent holds at most 64 upstream connections open at once, across all
  upstreams and clients; a request beyond that fails at once rather than
  opening another socket. An upstream that leads back into the agent (a
  cycle through another proxy) is cut there instead of exhausting the
  agent's descriptors, and an *--upstream* naming the agent's own socket is
  refused at start. If the agent does run out of descriptors it keeps
  listening and serves again once they free up (piggy#326).

*--proxy-only* is the remote-host shape of this (piggy FDR 0001): a host
reached over SSH runs a cardless front on a stable socket path, its
upstreams being the forwarded, card-backed agents. Workstations run the
card-backed agent, optionally proxying a stock *ssh-agent* for software
keys. Either way every host has one *piggy-agent* socket.

The home-manager option _services.piggy-agent.softwareKeys.enable_ sets up
that workstation shape for this agent on Linux: it runs a stock *ssh-agent* in a second
unit and passes *--upstream software=*_SOCKET_ *--add-new-keys-to software*,
so *ssh-add* against the piggy socket puts the key in that *ssh-agent*. Such
a key is held in memory, not in a file; any process running as the same
user can use it, and restarting the *ssh-agent* unit forgets it. On macOS,
name the launchd *ssh-agent* with *--upstream* and *--add-new-keys-to*
instead.

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
	One entry per *--upstream*: name, reachable or not, key count, the
	time (Unix seconds) it entered that state as this agent saw it, and,
	when unreachable, the error. Answered even when the agent's listing
	fails, so *piggy health* can show why.

# OPERATOR ACTS

The card-backed agent answers *operator-act@piggy* (piggy RFC 0012), the
extension *piggy operator-sign* speaks. A caller sends a text and an sshsig
namespace; the agent, and only the agent, makes the signature:

. It refuses, before any prompt, a request that is malformed, a namespace
  other than *piggy-quote-v1*, *piggy-escalation-v1* or
  *piggy-certificate-v1*, and a text that cannot be shown whole (not UTF-8,
  empty, over 4096 bytes, or holding a control character other than newline
  and tab).
. It asks the card to attest the slot's key, and refuses unless the
  attestation is for that key, is signed by the card's F9 certificate, and
  states PIN always and touch always. The policy is read from the card for
  every request; nothing configured stands in for it. A key that was
  imported, or that a card cannot attest, is refused.
. It asks for the PIN on a prompt that shows the act: its class (quote,
  escalation or certificate), the card and slot, the namespace, and the
  text, verbatim. The PIN is asked for every act and is never taken from,
  or put in, the agent's PIN cache. *PIGGY_ASKPASS_KIND* carries the class
  to the askpass program so each class gets its own dialog.
. It tells the operator that the card is waiting for a touch (see
  *ENVIRONMENT*), and waits for it.
. It builds the sshsig from the text it showed and returns it. The caller
  never supplies a digest or a pre-built blob.

The classed prompt is only as good as the askpass program the host runs. The
agent hands it the class and the text and cannot tell what it showed: the
shipped _contrib/piggy-askpass.sh_ honours both, while a program that ignores
*PIGGY_ASKPASS_CONTEXT* shows a bare PIN prompt and the act is still signed.

A refusal is an answer, with a status the caller can act on (_refused-policy_,
_refused-namespace_, _refused-text_, _no-such-key_, _cancelled_,
_card-absent_, _bad-request_, _error_); it is not an agent failure, which is
what an agent without the extension returns. Its detail tells apart the
answers a status shares: a PIN prompt that was dismissed, timed out or
failed is _cancelled_ with *no PIN from the askpass:* and its reason; a PIN
the card did not take is _error_ with *wrong PIN (*_N_* retries left)*, *PIN
blocked*, or *PIN verify failed:* and the card's answer.

So that the extension is the only way to such a signature, an ordinary sign
request whose data is sshsig signed data under one of those three namespaces
is refused, whether the key is on a card here or held by an upstream. Signing under *file*, *git* or any
other namespace, and SSH authentication, are unaffected.

With *--upstream*, a request for a key the agent does not hold is forwarded,
unchanged, to the upstream that listed the key, and the answer is relayed
unchanged. A *--proxy-only* front does only that: it never shows the text and
never prompts. The prompt appears on the host where the card is, which is
what lets *piggy operator-sign* work over a forwarded agent.

# SCOPES

An operator act is evidence that a human read a text and chose to sign it.
That holds only if two things are true of where the agent runs, and the agent
cannot check either from the inside:

- The agent, and the askpass program it starts, run outside every agent
  runtime (a *claude* process tree, or any other): as a user service of the
  operator's session, never as a descendant of the thing that asks for the
  act. The prompt is always raised by the agent, never by the caller.
- Nothing an agent runtime controls can write to the surface the operator
  reads the prompt from: the terminal's write side, or the graphical
  session. A process that could draw there could paint a different text
  over the real prompt.

piggy relies on this separation and does not provide it; it is the session
manager's and the terminal owner's to arrange (piggy FDR 0006, "Scopes:
frontend and agent"). What the agent itself guarantees is narrower: the bytes
the card signs are computed by the agent from the text the agent put on its
own prompt, and only a card-attested PIN-always, touch-always key signs them.
Any process that can reach the agent socket can ask for an act, and each
request interrupts the operator with a prompt; an operator who did not expect
one should cancel it.

# PIN PROMPTS

The PIN is requested on demand through the *SSH_ASKPASS* program, with
*SSH_ASKPASS_REQUIRE* selecting the route: _force_ always runs the
program, _never_ reads a tty or refuses, unset or _prefer_ tries a tty
first. _contrib/piggy-askpass.sh_ is the shipped helper: it renders
piggy-aware context above the prompt, re-derives a live Wayland display
when the agent inherited a frozen *systemd --user* environment, and
refuses rather than guessing. For an operator act it reads the class from
*PIGGY_ASKPASS_KIND* and gives each its own banner, window title, button and
dialog, which opens with a band in the class's colour carrying its symbol
(escalation red, certificate amber, quote blue); an escalation also
requires the word ESCALATE to be typed, and then a click on its button.
On Linux every dialog, the routine PIN prompt included, is
*piggy-askpass-gtk*, which the packaged helper finds on its *PATH*; with
*PIGGY_ASKPASS_GTK*=0, or where it is absent, a routine prompt is zenity's
and an operator act is refused before any dialog opens (exit 3 with the
reason, reported _cancelled_), since zenity cannot hold input as RFC 0012
§2.6 requires; such a host answers operator acts on a tty. A routine
prompt carries a slate PIN REQUEST band, none of the operator-act colours. The helper
takes focus when it opens and shows the text as plain text. For its first
2 seconds it takes no input but a cancel, its fields are greyed out, and
it shakes at any keystroke, so a key meant for another window can neither
type into it nor confirm the act. A clock in the band shows the time: whole
orange with the seconds of that block counted over it, then, when the
dialog has a timeout, a green section and a short red one (a tenth of the
time left after the block, at least 3 seconds) with the used part gone
white. Keystrokes and pointer moves pause the clock, under a pause symbol
that fades in and out, and for 2 seconds after they stop, counted down over
the clock; the dialog gives up (exit 5) when the clock runs out, and in any
case 5 minutes after it opened, however much input it has had.
Pressing Return to confirm leaves the clock as it is. The helper
refuses a class it does not know. The dialog that takes the PIN must show
the act's whole text, and neither PIN dialog scrolls, so the helper
refuses an act whose rendered prompt is taller than 24 lines (a line longer
than 80 characters counting as the lines it wraps to) before any dialog
opens; it never elides the text. The refusal exits 3 with its reason on
standard output, naming the limit, and the agent reports the act
_cancelled_ with that reason, so the caller can shorten the text. A tty
prompt has no such limit. On a tty, the helper's and the agent's own, an
operator act holds input the same 2 seconds (RFC 0012 §2.6): the text is
shown with echo off, a countdown line runs, and everything typed meanwhile,
a partial line included, is discarded before the PIN line appears. Any askpass may refuse the same way: exit 3 with
a one-line reason on standard output. Test harnesses must point *SSH_ASKPASS* at
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

_PIGGY_ASKPASS_NOTIFIER_, _SSH_NOTIFY_SEND_
	The program that tells the operator the card is waiting for a touch
	during an operator act, run as _PROGRAM TITLE MESSAGE_ and not waited
	for. The first of these that is set is used; with neither,
	*terminal-notifier* or *notify-send* if _PATH_ has one. The same line
	is always written to the agent's standard error, which is the notice
	when the agent runs in a terminal. An agent running as a service with
	no notifier to call has told nobody, and logs a warning saying so. The
	home-manager option _services.piggy-agent.notifySend_ sets
	_SSH_NOTIFY_SEND_.

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
