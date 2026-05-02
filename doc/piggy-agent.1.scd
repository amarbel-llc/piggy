piggy-agent(1)

# NAME

piggy-agent - PIV-backed SSH signing agent

# SYNOPSIS

*piggy agent* [*-A*] [*-g* _GUID_] [*-S* _SLOTS_] [*-a* _SOCKET_]++
*piggy agent* [*-s* | *-c*] [*-d*...] [*-D*] [_command_ [_args_...]]++
*piggy agent* *-i* [*-A*] [*-g* _GUID_] [*-S* _SLOTS_]++
*piggy agent* *-k*

# DESCRIPTION

*piggy agent* is a PIV-backed SSH agent that exposes signing keys from PIV
smart cards (such as YubiKeys) over the SSH agent protocol.

Historically this was the standalone *pivy-agent* binary. It has been absorbed
into *piggy* as a subcommand; the agent protocol handling is unchanged.

On startup, the agent enumerates PIV tokens via PC/SC, reads public keys from
each slot, and begins listening on a Unix domain socket. SSH clients connecting
to that socket can use the PIV keys for authentication and signing — the
physical card must be present for each signing operation.

If a _command_ is given on the command line, the agent starts in the background,
sets *SSH_AUTH_SOCK* and *SSH_AGENT_PID*, runs the command, and exits when it
completes. Otherwise the agent daemonizes and prints shell variable assignments
for *SSH_AUTH_SOCK* and *SSH_AGENT_PID* to stdout.

# OPTIONS

*-g* _GUID_
	Use only the PIV card with the given GUID (full hex or short ID).
	Conflicts with *-A*.

*-A*
	All-card mode: expose keys from every PIV card visible to PC/SC.
	Conflicts with *-g*.

*-a* _SOCKET_
	Bind the agent to _SOCKET_ instead of an auto-generated path under
	_$TMPDIR_.

*-S* _SLOTS_
	Only expose keys from the listed PIV slots. _SLOTS_ is a
	comma-separated list of hex slot IDs, e.g. _9a,9d,9e_. Whitespace
	around each ID is trimmed. See *SLOT SPECIFICATION* below.

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

Kill a running agent:

```
eval $(piggy agent -k)
```

# SEE ALSO

*piggy*(1), *pivy-agent*(1), *pivy-box*(1), *pivy-tool*(1), *ssh-agent*(1),
*ssh-add*(1), *piggy-piv-slots*(7)
