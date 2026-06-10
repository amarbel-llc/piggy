age-plugin-piggy(1)

# NAME

age-plugin-piggy - age plugin: PIV/agent-backed P-256 identities for piggy

# SYNOPSIS

*age-plugin-piggy* generate [*--guid* _GUID_]++
*age-plugin-piggy* convert _RECIPIENT_++
*age-plugin-piggy* --version++
*age-plugin-piggy* --age-plugin=_STATE-MACHINE_

# DESCRIPTION

*age-plugin-piggy* is an *age*(1) plugin that makes a piggy PIV key (NIST
P-256, slot 9D) an age identity. Secrets become plain age files —
encryptable and decryptable by *age*, *rage*, *sops*, or anything that
speaks the C2SP age-plugin protocol — while the private key never leaves
the smart card.

*Encryption* is pure software: a fresh ephemeral key and a local ECDH
against the recipient's public key. No card or agent is touched.

*Decryption* delegates the P-256 scalar-multiplication to *piggy-agent*
over the *ecdh@joyent.com* SSH-agent extension (forwardable over SSH).
The card performs the ECDH on demand; the plugin never sees a private
scalar and nothing is written to disk. The agent owns any PIN or touch
prompt.

The on-the-wire stanza is the *piv-p256* scheme (P-256 ECDH, HKDF-SHA256,
ChaCha20-Poly1305), the same format used by *age-plugin-yubikey*; the only
piggy-specific difference is that the ECDH happens at a forwarded agent
rather than a local PC/SC handle.

*age* invokes the plugin automatically (via *--age-plugin=*) when it
encounters an *age1piggy…* recipient or an *AGE-PLUGIN-PIGGY-…* identity
and finds *age-plugin-piggy* on *PATH*. The subcommands below are the
human-facing surface for minting those strings.

# COMMANDS

*generate* [*--guid* _GUID_]
	Read slot 9D's public key off an attached PIV card (read-only and
	PIN-free — a certificate read, never a decrypt) and print the
	recipient and identity:

	```
	# recipient: age1piggy1…
	AGE-PLUGIN-PIGGY-1…
	```

	With more than one card attached, select one with *--guid* _GUID_
	(the GUIDs *piggy health* and *piggy pass recipients list-available*
	print). With no card, or an unknown GUID, it errors.

*convert* _RECIPIENT_
	The same output, computed offline from an existing piggy recipient —
	no card required. _RECIPIENT_ is either a piggy markl recipient ID
	(*piggy-recipient-v1@pivy_ecdh_p256_pub-…*, or the bare blech32 body)
	or the raw 33-byte compressed P-256 public key in hex.

*--version*
	Print *age-plugin-piggy <version>+<commit>* (eng-versioning(7)),
	sharing piggy's version and commit.

*--age-plugin=*_STATE-MACHINE_
	Run an age plugin state machine (*recipient-v1* for encryption,
	*identity-v1* for decryption). Invoked by age, not by hand.

# OUTPUT

Both *generate* and *convert* print two lines to standard output: a
*# recipient:* comment carrying the *age1piggy…* recipient, and the
*AGE-PLUGIN-PIGGY-…* identity. Redirect them to a file to use as an age
identity file (the comment is ignored by age and travels with the
identity); both encode only the public key.

# ENVIRONMENT

_PIGGY_AUTH_SOCK_
	SSH-agent socket used for the decrypt-path ECDH. Preferred over
	_SSH_AUTH_SOCK_ when set and non-empty. Point it at a *piggy-agent*
	that advertises *ecdh@joyent.com*.

_SSH_AUTH_SOCK_
	Fallback agent socket when _PIGGY_AUTH_SOCK_ is unset.

_SSH_ASKPASS_
	Consulted by *piggy-agent* (not the plugin) to prompt for the PIV PIN
	on demand when a decrypt needs one and none is cached.

# EXAMPLES

Mint your recipient and identity from the card and save the identity:

```
age-plugin-piggy generate > ~/.config/age/piggy-identity.txt
recipient=$(sed -n 's/^# recipient: //p' ~/.config/age/piggy-identity.txt)
```

Encrypt to it (no card needed):

```
echo secret | age -r "$recipient" -o secret.age
```

Decrypt through a forwarded piggy-agent:

```
PIGGY_AUTH_SOCK=$XDG_RUNTIME_DIR/piggy-agent.sock \
  age -d -i ~/.config/age/piggy-identity.txt secret.age
```

Derive the strings offline from a recipient you already have:

```
age-plugin-piggy convert piggy-recipient-v1@pivy_ecdh_p256_pub-…
```

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *age*(1), *sops*(1), *piggy-ids*(5),
*piggy-piv-slots*(7)

The design notes and the sops-nix recipe live in
_docs/plans/2026-06-09-age-plugin-piggy.md_ in the piggy source tree.
