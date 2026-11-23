piggy-agent(1)

# NAME

piggy-agent - PIV-backed SSH signing agent

# SYNOPSIS

*piggy agent* [*-A*] [*-g* _GUID_] [*-K* _PUBKEY_] [*-S* _SLOTS_] [*-a* _SOCKET_] [*--upstream* _NAME_=_PATH_...] [*--add-new-keys-to* _NAME_] [*--service-name* _UNIT_] [*--probe-interval* _SECONDS_] [*--poll-only*]++
*piggy agent* *--proxy-only* *--upstream* _NAME_=_PATH_... [*-a* _SOCKET_] [*--add-new-keys-to* _NAME_] [*--service-name* _UNIT_]++
*piggy agent* *--holder* *--holder-fibby-ctl* _PATH_ [*--scope* _NAME_=_RULE_...] [*--cgroup-root* _DIR_] [*--scope-poll-interval* _SECONDS_] [*-a* _SOCKET_] [*-S* _SLOTS_] [*--service-name* _UNIT_]++
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
	Per-upstream request timeout for connect and list (default 5). A sign is
	not bound by it: see *--sign-wait*.

*--sign-wait* _SECONDS_
	How long a sign relayed to an upstream is waited for (default 60). It
	goes to the one upstream that holds the key and may sit behind a PIN
	dialog and a touch on the card's machine (a certificate through a
	front used to fail after 5 s). A sign that times out is never tried on
	another upstream that lists the key, since it may still be waiting on a
	person there and a second request would raise a second prompt. At most
	4 signs wait at one upstream; the rest fail at once, and a listing
	never waits behind them.

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

*--holder*
	Holder mode (FDR 0006 phase (d)): serve *mint@piggy* and
	*retire@piggy*, creating keys on virtual cards in the fibby named by
	*--holder-fibby-ctl* and binding each to the scope that minted it. See
	*HOLDER MODE*. Implies *-A*; conflicts with *--proxy-only*,
	*--upstream*, *-g*, *-K* and *-i*.

*--holder-fibby-ctl* _PATH_
	The control socket of the fibby that holds the minted cards, the
	_PATH_ given to *fibby --control-socket*. Its PC/SC socket is reached
	through *PCSCLITE_CSOCK_NAME*, as for any card. Required by *--holder*.

*--scope* _NAME_=_RULE_
	A scope definition, repeatable: what a mint naming _NAME_ binds to.
	_RULE_ is *caller* (the calling connection's own cgroup) or
	*cgroup:*_/absolute/path_ (that cgroup; the caller must be inside
	it). _NAME_ is opaque and is matched whole; the split is at the first
	*=*. A mint naming no scope, or a name not defined here, is refused.

*--cgroup-root* _DIR_
	Where the cgroup2 filesystem is mounted (default
	_/sys/fs/cgroup_). A bound cgroup whose directory is gone from under
	it has exited, and its card is destroyed.

*--scope-poll-interval* _SECONDS_
	How often the holder checks that every bound cgroup still exists
	(default 2).

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
  *ecdh@code.linenisgreat.com*, answered under its legacy name
  *ecdh@joyent.com* as well, *ecdh-rebox@joyent.com*,
  *ykpiv-attest@joyent.com*)
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

A host with its own card can also be reached from a workstation whose
agent is forwarded to it. Don't forward that agent onto the path the
host's own *piggy agent* listens on. With _StreamLocalBindUnlink yes_, sshd
unlinks the agent's socket and binds the forward in its place. For as long
as the session lasts, every client of that path (*piggy pass*, health
probes, other sessions) talks to the workstation's card instead of the
host's. When the session ends the path can be left pointing at a dead
forward, and the host's agent is unreachable until it is restarted.
Forward onto a path of its own and name it with *--upstream*. The host's
socket then serves both cards: native keys first, the forwarded card's
after. *pass show-batch* then sends a batch to the forwarded card when only
that card holds a recipient key (piggy#351, *piggy*(1) _PIGGY_UNLOCK_).

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
	whether presence is event-driven, and whether it is a holder.

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
  other than *piggy-quote-v1*, *piggy-escalation-v1*,
  *piggy-certificate-v1*, *piggy-approval-v1* or *piggy-revocation-v1*, and
  a text that cannot be shown whole (not UTF-8,
  empty, over 4096 bytes, or holding a control character other than newline
  and tab).
. It asks the card to attest the slot's key, and refuses unless the
  attestation is for that key, is signed by the card's F9 certificate,
  states PIN always and touch always, and names slot 9C as the slot it
  attests. The policy and the slot are read from the card for every
  request; nothing configured stands in for them. A key that was imported,
  or that a card cannot attest, is refused; so is the certificate authority
  key in slot 82, which is enrolled with the same policy as 9C (a
  certificate signature must never pass for an operator act).
. It asks for the PIN on a prompt that shows the act: its class (quote,
  escalation, certificate, approval for a decision that grants no right, or
  revocation for an act that cancels earlier acts), the card and slot, the
  namespace, and the
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
blocked*, or *PIN verify failed:* and the card's answer. A key the agent has
served since it started, whose card has since been removed, is _card-absent_
(worth asking again once the card is back); _no-such-key_ is kept for a key it
never served and no upstream holds.

Prompts are rate-limited per connection: once three operator acts on one
connection have ended _cancelled_ within a minute, that connection's further
acts are _refused-policy_ without a prompt until the oldest of those cancels is
a minute old. A new connection starts afresh. This keeps a misbehaving client
from flooding the operator with dialogs. The three cancels and the minute are
tuning levers, not protocol: they are *OPERATOR_ACT_CANCEL_LIMIT* and
*OPERATOR_ACT_CANCEL_WINDOW* in the agent's session code, and may move.

So that the extension is the only way to such a signature, an ordinary sign
request whose data is sshsig signed data under one of those three namespaces
is refused, whether the key is on a card here or held by an upstream. Signing under *file*, *git* or any
other namespace, and SSH authentication, are unaffected.

With *--upstream*, a request for a key the agent does not hold is forwarded,
unchanged, to the upstream that listed the key, and the answer is relayed
unchanged. A *--proxy-only* front does only that: it never shows the text and
never prompts. The prompt appears on the host where the card is, which is
what lets *piggy operator-sign* work over a forwarded agent.

# SSH CERTIFICATE AUTHORITY

The key in slot 83 (*piggy-piv-slots*(7)) is a certificate authority for
OpenSSH user certificates, and the agent serves it as an ordinary SSH
identity, so *ssh-keygen -U -s* signs with it with no other client:

```
SSH_AUTH_SOCK=... ssh-keygen -U -s ca83.pub -I grant-1 -n deploy-site -V +2h user.pub
```

*ssh-keygen* sends the agent the certificate with everything but its
signature; the agent reads it (its own parser, not OpenSSH's) and signs it
only if it is an unsigned user certificate. Before the card is touched or a
prompt is shown it refuses: data that is not such a certificate (an sshsig, a
login challenge, a TBSCertificate, anything else), a host certificate, a
certificate with no principal, with no end, or valid for more than 24 hours
(the built-in limit, plus five minutes for *ssh-keygen*'s one-minute
back-dating). An OpenSSH certificate sent to any other slot is refused too.
The X.509 CA slot (82) signs nothing through the agent: no TBSCertificate, CRL
or other bytes, a certificate being signed only by *piggy ca*.

The PIN dialog is of kind _ssh-certificate_ (*PIGGY_ASKPASS_KIND*): its own
banner, title ("piggy SSH CA: CERTIFICATE"), band and button ("Issue SSH
certificate"), distinct from every operator act's, and its context is what the
signature certifies, in the order it is read: the card and slot, the key id,
the principals, the certified key's SHA256 fingerprint, the CA key's, the
serial, the validity (UTC) and lifetime, the critical options (a
*force-command* with its command) and the extensions. It is held, shown whole
and timed like an operator act's text. The PIN is asked for every certificate
(see PIN MEMORY); the card's touch, if the slot demands it, is the card's.

The card is asked, on every request, to attest the key: a CA slot's key
signs only if the attestation is for it and states PIN always and touch
always (see *piggy-piv-slots*(7)). The certificate's text reaches the dialog
as *PIGGY_ASKPASS_CONTEXT*, which only a program that understands the kind
shows, so the agent also gives the prompt a nonce in *PIGGY_ASKPASS_NONCE*
and uses the PIN only if the program prints *piggy-askpass-ack* _nonce_ on
the line after it (_contrib/piggy-askpass.sh_ and the test helper do); any
other *SSH_ASKPASS* is refused for this kind, so a certificate is never
signed behind a prompt that did not show it. (Operator acts have the same
weakness and are not yet covered.)

A request for a key an upstream holds is relayed unchanged (see UPSTREAM
PROXYING): the checks and the dialog are the card agent's own, on its host. A
front cannot tell which slot an upstream key is in, so it relays data that is
shaped like a certificate (an OpenSSH certificate or a DER TBSCertificate) only
to an upstream that advertises the extension *ssh-ca-gate@piggy* in its answer
to *query*, which a card agent of this version does for every key it holds;
an older piggy agent, or any other ssh-agent, is refused before the data
leaves the front. The supported topology is a front directly over the card
agent that holds the key, one hop: a front never repeats an upstream's
advertisement of the extension in its own answer, so a second front in the
chain finds it unadvertised and refuses. (An older proxy between a front and a
card agent does repeat it, and is not covered.)

# HOLDER MODE

With *--holder* (FDR 0006 phase (d), piggy#383) the agent is a *key
holder*: it mints short-lived signing keys for unattended sessions, each on
its own virtual card inside a fibby (the key never leaves fibby; FDR 0006
phase (c)), and lets each key be used only from the scope that minted it.
The wire format is piggy RFC 0014; *piggy holder mint* and *piggy holder
retire* (piggy(1)) are the clients.

*mint@piggy*
	A caller names a *scope* and a key type (*ssh-ed25519* or
	*ecdsa-sha2-nistp256*). The scope is a plain versioned name such as
	_piggy-mint-v1_ that selects one of the holder's *--scope* definitions;
	the name is a claim, and the calling connection's peer is checked
	against what the definition resolves to. The holder then has fibby
	create a card whose slot 9A holds a fresh key with PIN policy *never*
	and touch policy *never*, reads the key, replaces the card's factory
	PIN with a random one it keeps on guarded pages (the caller never sees
	it), serves the key with the comment _holder:<card>_, and answers with
	the public key and the card's reader name. Minted keys go in slot 9A
	only: 9C (operator acts) and 9D (the store) are never minted, so a
	holder key can never sign an operator act.

	Refusals are by name: *scope-unbound* (no scope named; the holder
	infers none until the scope split of clown#244 exists),
	*unknown-scope* (no such definition), *not-bound-scope* (the caller
	is outside the scope's cgroup), *refused-key-type*, *cap-reached* (16
	live cards per holder; retire one), *peer-unknown* (the connection's
	peer could not be read), *bad-request* and *error*.

*retire@piggy*
	Names a minted key. From a peer inside the key's scope the holder
	destroys the card (fibby wipes it and removes the reader), forgets the
	PIN and drops the key; from anyone else it is *not-bound-scope*; a key
	the holder did not mint is *no-such-key*.

*Caller binding.*
	The peer of every connection is read once, when it is accepted: its
	credentials from *SO_PEERCRED* and its cgroup v2 path from
	_/proc/<pid>/cgroup_, through a descriptor on _/proc/<pid>_ opened at
	that moment, so a pid reused after accept is not misread as the peer
	(the window between accept and that open remains). A binding is a
	cgroup path; a peer is inside it when its own cgroup is that path or
	one below it, component by component. Every use of a minted key goes
	through that check: an ordinary sign request, ECDH, attestation and
	retire alike, each answered with a failure naming *not-bound-scope*.
	Listing is not gated. A peer whose cgroup cannot be read (no cgroup
	v2 line, no _/proc_) may use no holder key.

*Teardown.*
	A card is destroyed when its scope retires it or when its bound
	cgroup's directory disappears from under *--cgroup-root*, which the
	holder checks every *--scope-poll-interval* seconds. A holder restart
	loses every key by design: fibby's keys live in its memory, and
	sessions mint again.

*PIN policy.*
	A holder key has PIN policy *never*, and the agent asks for no PIN
	before using it. This is general: for every slot it serves, the agent
	reads the PIN policy the card attests for the slot once per key and
	skips the PIN when it is *never* (as it always has for 9E); a slot
	whose policy cannot be read is prompted for as before.

The holder serves only its own fibby's cards: no *--upstream*, no
*--proxy-only*, and a request for a key it does not hold is refused, not
forwarded. It runs as a system service under its own account with the
fibby under another (FDR 0006 "The holder service"): the NixOS module
*services.piggy-holder* (piggy's _nixosModules.piggy-holder_) ships the
two hardened units, _fibby-holder.service_ (the holder build only; the
test double is refused at start) and _piggy-holder.service_, with
_scopes_ as the *--scope* definitions and _clientGroup_ as the group that
may reach the socket; fibby's sockets are reachable by the agent's
account alone. *just explore-fdr0006-d* stages the hand pass on a systemd
host, with a bound and a sibling transient scope; the *vm-piggy-holder*
lane runs the module in a guest (piggy-testing(7) VM LANES).

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
(escalation red, certificate amber, quote blue, approval green, revocation
purple); an approval's banner says it grants no right, a revocation's that
it cancels earlier acts; an escalation also
requires the word ESCALATE to be typed, and then a click on its button.
On Linux every dialog, the routine PIN prompt included, is
*piggy-askpass-gtk*, which the packaged helper finds on its *PATH*; with
*PIGGY_ASKPASS_GTK*=0, or where it is absent, a routine prompt is zenity's
and an operator act is refused before any dialog opens (exit 3 with the
reason, reported _cancelled_), since zenity cannot hold input as RFC 0012
§2.6 requires; such a host answers operator acts on a tty. A routine
prompt carries a slate PIN REQUEST band, none of the operator-act colours. The helper
takes focus when it opens and shows the text as plain text. For its first
2 seconds it takes no input at all, Escape and its Cancel button included
(RFC 0012 §2.6); its fields and buttons are greyed out, and it shakes at
any keystroke, so a key meant for another window can neither type into it,
confirm the act nor dismiss it. Only the window manager's close control,
which the dialog cannot reach, still ends it then, as a cancel. A clock in the band shows the time: whole
orange with the seconds of that block counted over it, then, when the
dialog has a timeout, a green section and a short red one (a tenth of the
time left after the block, at least 3 seconds) with the used part gone
white. Keystrokes and pointer moves pause the clock, under a pause symbol
that fades in and out, and for 2 seconds after they stop, counted down over
the clock; the dialog gives up (exit 5) when the clock runs out, and in any
case 5 minutes after it opened, however much input it has had.
Pressing Return to confirm leaves the clock as it is. The helper
refuses a class it does not know. The dialog that takes the PIN shows
the act's whole text, wrapped at 100 characters (so a markl-id takes one
line), never cut; it does not scroll, and since 2026-11-21 it has no height
limit either (the operator's ruling, piggy#400: the earlier limit of 24
rendered lines refused every _piggy-act-v1_ card act, whose required fields
alone render to more; the one-screen rule is waived for acts until the
re-examination that issue tracks). On a tty, the helper's and the agent's own, an
operator act holds input the same 2 seconds (RFC 0012 §2.6): the text is
shown with echo off, a countdown line runs, and everything typed meanwhile,
a partial line included, is discarded before the PIN line appears. Any askpass may refuse the same way: exit 3 with
a one-line reason on standard output. Test harnesses must point *SSH_ASKPASS* at
a non-interactive helper; see *piggy-testing*(7).

# PIN MEMORY

A PIN that verified on a card, or that *ssh-add -X* offered, stays cached
for that card until the card leaves, *ssh-add -x* clears it, or the agent
exits. The exception is the certificate authority slots, 82 and 83
(*piggy-piv-slots*(7)): their PIN is asked every time and is neither taken
from the cache nor put in it, so a PIN-always key is asked for per signature
by the operator, not only by the card; what 82 and 83 prompt never changes
what is cached for the card's other slots, 9C and 9D included. Each cached PIN is held on pages of its own (FDR 0006 phase (b)):
between two inaccessible guard pages, locked against swap, and unreadable
except while one VERIFY copies it out; its pages are zeroed when it is
forgotten. At start the agent makes itself non-dumpable and sets its core
size limit to zero. It logs what it got at debug level (*-d*, the
_process hardening_ line); a step that fails is a warning and the agent
serves anyway.

What each platform gets:

- Linux: all of the above, and the cached PINs' pages are left out of
  core dumps (*MADV_DONTDUMP*) and read as zeros in a forked child
  (*MADV_WIPEONFORK*, Linux 4.14 and later). Non-dumpable is
  *PR_SET_DUMPABLE* 0, which also refuses a same-user *ptrace*(2) attach
  and makes the files under _/proc/<pid>_ root's.
- macOS: the guard pages, the lock, the seal between uses, the zeroing and
  the zero core limit; there is no non-dumpable flag and neither advice
  flag.

The lock is per PIN: unlike C pivy-agent, the agent does not lock its
whole address space (*mlockall*). A lock the kernel refuses (past
*RLIMIT_MEMLOCK*) leaves the PIN cached but swappable. A PIN that cannot
be put on guarded pages at all is not cached, so the next operation
prompts again.

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
