piggy-ids(5)

# NAME

piggy-ids - file format for declaring recipients of a piggy 2.x password store

# SYNOPSIS

_<store-root>_/piggy-ids++
_<store-root>_/_<subfolder>_/piggy-ids

# DESCRIPTION

A *piggy-ids* file declares the set of recipient public keys that the
entries in (and below) its containing directory are encrypted to. It
replaces piggy 1.x's binary _.pivy-id_ ebox-template file with a
hand-editable, version-controlled, line-oriented text format.

Each non-blank, non-comment line carries one recipient, identified by
a markl ID (see madder RFC 0002) under the piggy-owned purpose
*piggy-recipient-v1*. The file is read by *piggy-ids*(1) and consumed
by *piggy pass* operations that need a recipient set
(*init*, *insert*, *generate*, *edit*, *recipients*, _re-encryption_
after recipient changes).

The normative specification of this format is piggy RFC 0003.

# GRAMMAR

```
file           = *( blank-line / comment-line / recipient-line )
blank-line     = *WSP LF
comment-line   = *WSP "#" *VCHAR LF
recipient-line = *WSP markl-id [comment-suffix] LF
comment-suffix = 1*WSP "#" [WSP *VCHAR]
markl-id       = recipient-entry / ssh-auth-entry
recipient-entry = ("piggy-recipient-v1" "@" recipient-blech32) / bare-format
bare-format    = recipient-blech32
recipient-blech32 = pivy-blech32 / age-blech32
pivy-blech32   = "pivy_ecdh_p256_pub" "-" 1*charset
age-blech32    = "age_x25519_pub"    "-" 1*charset
ssh-auth-entry = "piggy-piv_auth-v1" "@" "ssh_ecdsa_nistp256_pub" "-" 1*charset
```

The bech32 _charset_ is the alphabet from madder RFC 0002 §3.1.

# RECIPIENT FORMATS

Two markl formats are accepted under the *piggy-recipient-v1* purpose:

[[ *Format*
:[ *Size*
:[ *Family*
|  *pivy_ecdh_p256_pub*
:  33 bytes
:  PIV slot 9D (Key Management, ECDH over NIST P-256)
|  *age_x25519_pub*
:  32 bytes
:  age v1 X25519 recipient

The 32-byte _age_x25519_pub_ payload is the raw X25519 public key —
the same 32 bytes that the upstream _age1..._ bech32 string encodes;
the two encodings differ only in the surrounding envelope.

A file MAY mix the two families freely. Other markl formats MUST be
rejected at the *piggy-ids* layer (but see *SSH-AUTHENTICATION ENTRIES*
below for the one additional, non-recipient entry type).

# SSH-AUTHENTICATION ENTRIES (SLOT 9A)

A *piggy-ids* file MAY additionally carry PIV slot-9A
(PIV Authentication) SSH keys, tagged with the *piggy-piv_auth-v1*
purpose and the *ssh_ecdsa_nistp256_pub* format:

```
piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-<blech32>  # alice login (9A)
```

These are *not encryption recipients*. They are SSH login keys for the
same identities, kept alongside their 9D decrypt keys so one file
describes both "who can decrypt the store" and "who may log in". They
are:

- *Excluded from encryption.* *piggy pass insert/generate/edit* and the
  re-encryption walk skip 9A entries entirely — a secret is never
  wrapped to an SSH-auth key, and a 9A line never forces re-encryption.
- *Consumed by* *piggy ssh-copy-id*, which renders each 9A entry as an
  *ecdsa-sha2-nistp256* _authorized_keys_ line and installs the set on a
  remote host.
- *Required to be purpose-tagged.* Unlike recipient formats, there is no
  bare-format sugar for SSH-auth entries; a bare
  _ssh_ecdsa_nistp256_pub-..._ (no _piggy-piv_auth-v1@_ prefix) is
  rejected.

Only slot 9A is accepted today; slots 9C (*piggy-piv_sig-v1*) and 9E
(*piggy-piv_card_auth-v1*) are not yet accepted in a *piggy-ids* file.

Discover an attached card's 9A markl ID with *piggy list*
(_--format=human_ / _--format=ndjson_) and add it with *piggy pass
recipients add*.

# CANONICAL FORM

Writers emit each recipient in *piggy-purpose-tagged* form, with two
ASCII spaces separating the markl ID from any inline `#` comment.
Bare-format input (e.g. _pivy_ecdh_p256_pub-..._ with no leading
_piggy-recipient-v1@_) is accepted on read and promoted to the
purpose-tagged form on rewrite, so _parse → render → parse_
round-trips to a stable representation.

Use *piggy-ids canonicalize* to normalise a file in place. Use
*piggy-ids diff* to compare two files at the canonical level
(byte-identical canonical forms compare equal regardless of input
formatting).

# EXAMPLE

```
# piggy-ids - recipients for ~/.local/share/piggy
piggy-recipient-v1@pivy_ecdh_p256_pub-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd  # primary yubikey (9D)
piggy-recipient-v1@pivy_ecdh_p256_pub-qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw7n8w8c0ydp7s8jtgqnxa  # backup yubikey (9D)
piggy-recipient-v1@age_x25519_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu     # age identity (laptop)
piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfv47nat8  # ssh login (9A)
```

# AGE RECIPIENT STATUS

Acceptance of *age_x25519_pub* recipients at the markl/parser layer is
implemented today: such lines parse, validate, canonicalize, and
*diff* cleanly. *piggy pass recipients add/remove/sync* accept them
into a _piggy-ids_ file without error.

The encrypt and decrypt pipelines do _not_ yet handle age recipients.
A _piggy-ids_ file that lists any *age_x25519_pub* recipient will
cause *piggy pass insert*, *generate*, *edit*, *init* (over an
existing store), and any *recipients* operation that triggers
re-encryption to fail with a *BoxError::UnsupportedRecipientFormat*
error, pointing at piggy RFC 0004.

Note: *piggy pass init -k* additionally rejects an age markl ID at a
bash-side prefix check before the parser sees it ("must be a markl
ID with format=pivy_ecdh_p256_pub"). Use *piggy pass init* with a
pivy recipient and then *piggy pass recipients add* (which goes
through the broadened parser) to declare an age recipient today.

Until RFC 0004's wire-format extension lands, _piggy-ids_ files
intended for active use SHOULD list only *pivy_ecdh_p256_pub*
recipients. Mixed files are useful today only for declarative-config
preview and *piggy-ids diff* round-tripping.

# FILE PLACEMENT

A *piggy-ids* file at the root of the store applies to every entry
below it. A *piggy-ids* file in a subdirectory overrides the
root file for entries in that subtree. *piggy pass* walks upward
from the entry's directory and stops at the first *piggy-ids* it
finds.

Set the store root via *PIGGY_STORE_DIR* (default
_~/.local/share/piggy_).

# COMPARISON WITH PIGGY 1.X

Piggy 1.x used a binary _.pivy-id_ file -- an opaque *pivy-box*(1)
ebox template. piggy 2.x's *piggy-ids* file is text:

- hand-editable in any editor
- meaningfully reviewable in code review and *git diff*
- idempotent under _config-as-code_ tooling (write, canonicalise,
  diff, sync)
- portable across recipient families (PIV today, age tomorrow)

# FILES

_<store-root>_/piggy-ids
	Root recipient file for the store.

_<store-root>_/_<subfolder>_/piggy-ids
	Per-subtree override.

_$PIGGY_AGE_IDENTITY_
	Path to the age identity file consulted by the decrypt
	dispatcher when an *AgeBox* part is encountered (RFC 0004).
	Default _~/.config/piggy/age-identity_. Has no effect today
	because the decrypt dispatcher is not yet implemented.

# SEE ALSO

*piggy*(1), *piggy-piv-slots*(7), madder RFC 0002 (markl ID format),
piggy RFC 0003 (this file's normative spec), piggy RFC 0004 (age
recipients wire-format extension), *ssh-copy-id*(1)
