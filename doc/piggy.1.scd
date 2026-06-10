piggy(1)

# NAME

piggy - stores, retrieves, generates, and synchronizes passwords using PIV smart cards

# SYNOPSIS

*piggy pass* _SUBCOMMAND_ [_OPTIONS_]... [_ARGS_]...

*piggy list* [*--format* _human_|_ndjson_|_ssh_]

*piggy help*

*piggy version*

*piggy agent*|*box*|*tool*|*ca*|*luks*|*zfs* [_ARGS_]...

*piggy pivy* _TOOL_ [_ARGS_]...

# DESCRIPTION

*piggy* is a simple password store that keeps passwords inside *pivy-box*(1)
encrypted files (with the _.ebox_ extension) inside a directory tree residing
at _~/.local/share/piggy_. The *piggy pass* family of subcommands provides
utilities for manipulating the password store, allowing the user to add,
remove, edit, synchronize, generate, and manipulate passwords.

Encryption uses PIV slot 9D (Key Management / ECDH key agreement) on a smart
card such as a YubiKey. Encryption requires only the public key and does not
need the card to be present. Decryption requires *pivy-agent* with the physical
card inserted, or a forwarded SSH agent socket when working remotely.

Recipients are managed via _.pivy-id_ template files (analogous to _.gpg-id_ in
*pass*(1)). Each _.pivy-id_ is a *pivy-box*(1) ebox template that lists the PIV
public keys secrets are encrypted to.

Bare *piggy* (no subcommand) and bare *piggy pass* (no nested subcommand) both
print top-level help instead of acting on the store.

Several of the *pass* subcommands rely on or provide additional functionality
if the password store directory is also a git repository. If the password
store directory is a git repository, all password store modification commands
will cause a corresponding git commit. See the _EXTENDED GIT EXAMPLE_ section
for a detailed description using *piggy pass init* and *piggy pass git*.

The *piggy pass init* command must be run before other *pass* subcommands in
order to initialize the password store with a pivy-box template.

In addition to the *pass* family, *piggy* also provides top-level
passthroughs for the C pivy binaries:

- *piggy agent* runs *pivy-agent*(1).
- *piggy box* runs *pivy-box*(1).
- *piggy tool* / *piggy ca* / *piggy luks* / *piggy zfs* run the matching
  pivy binary from _$PATH_.
- *piggy pivy* _TOOL_ is the explicit-escape-hatch form: *piggy pivy box*
  always runs *pivy-box*(1), regardless of whether *piggy box* is later
  rerouted to a Rust reimplementation. See *pivy-box*(1) etc. for their
  own documentation.

# COMMANDS

## piggy pass

*pass init* [*--path*=_sub-folder_, *-p* _sub-folder_] [*-k* _markl-id_ | *-g* _guid_]
	Initialize new password storage with a piggy 2.x recipient template
	written to _piggy-ids_ (RFC 0003). The recipient is identified by a
	markl ID of format *pivy_ecdh_p256_pub*. With *-k* the recipient is
	provided declaratively (bare-format also accepted; canonicalized to
	*piggy-recipient-v1@* on disk). Without *-k*, slot 9D of the attached
	PIV card is auto-detected via *piggy-ids detect-pubkey*; pass *-g*
	to disambiguate when more than one card is attached. If *--path* or
	*-p* is specified, the template covers that sub-folder. If the
	resulting recipient set differs from any existing files, those files
	are re-encrypted to the new template.

*pass recipients list* [*--path*=_sub-folder_, *-p* _sub-folder_]
	Print the recipients listed in the relevant _piggy-ids_, one per line.

*pass recipients list-available* [*--format* _human_|_ndjson_]
	Enumerate every populated recipient-eligible slot on every attached
	PIV card and emit one record per (card, slot) on stdout. The
	eligible slot set is *9D* (key management) plus the retired
	key-management slots *82*..=*95*; empty/unreadable slots are
	skipped silently. Records describe the slot's markl ID, the card's
	CHUID *guid*, the YubiKey factory *serial* (when the card is a
	YubiKey v5+), the PCSC *reader* name, the *slot* id (uppercase
	2-digit hex, e.g. *9D*, *82*), the slot cert's Subject Common
	Name *cn* (the *-n* argument passed to *pivy-tool generate*;
	omitted when the cert has no CN), and the YubiKey *pin_policy* and
	*touch_policy* (the *-i* and *-t* arguments to *pivy-tool generate*;
	omitted on non-YubiKey cards and on YubiKeys whose attestation key
	has been cleared).

	Records are sorted by (*guid*, *slot*) so output is stable across
	runs. A card with multiple populated key-management slots produces
	multiple records — one per slot.

	Format auto-selects from stdout's TTY status: human-readable when
	interactive (the markl ID, followed by a trailing
	"_# guid=<hex>, [serial=<dec>, ]reader=<name>, slot=<id>[, cn=<name>][, pin=<policy>, touch=<policy>]_"
	comment), NDJSON otherwise (one JSON object per line with keys
	*id*, *guid*, *reader*, *slot*, and *serial*/*cn*/*pin_policy*/
	*touch_policy* when present). Pass *--format* to override.

	Policy values are the lowercase names accepted by *pivy-tool
	generate -i/-t*: *default*, *never*, *once*, *always* for PIN
	policy; *default*, *never*, *always*, *cached* for touch policy.
	Policy info is read via INS_ATTEST (the YubiKey attestation
	certificate carries the policy as the *1.3.6.1.4.1.41482.3.8*
	extension); per-slot attestation costs roughly one ECDSA signing
	operation against the card.

	The YubiKey *serial* is read at connect time via the YubicoPIV
	vendor-specific *INS_GET_SERIAL* (0xF8) against the PIV applet;
	non-YubiKey PIV cards reject the instruction and the field is
	simply omitted. In NDJSON output, *serial* is emitted as a JSON
	*number* (not a string) so consumers can compare or sort
	numerically.

	Populated slots with an unsupported algorithm (e.g. RSA) or a
	malformed cert are emitted too: prefixed with
	"_# unsupported: ..._" in human mode, or with *"unsupported":true*
	and a *reason* field in NDJSON mode.

*pass recipients add* [*-A* | *--all-attached*] [*--yes*] [*-p* _subfolder_] [_markl-id_...]
	Append recipients to the store's _piggy-ids_ and re-encrypt.

	With one or more _markl-id_ arguments, append each as a literal
	recipient.

	With *-A* / *--all-attached*, enumerate every attached PIV card
	and add the supported ones (slot 9D, P-256 ECDH). Cards already
	present are reported on stdout as
	"_already a recipient: <markl-id>  # GUID <guid>_" and skipped.
	Cards with an unsupported algorithm in slot 9D are listed in a
	single stderr dialog; the command then prompts on /dev/tty
	or, when stdin is not a TTY, aborts unless *--yes* was passed.

	*--all-attached* and explicit _markl-id_ arguments are mutually
	exclusive.

*pass recipients remove* _markl-id_... [*--path*=_sub-folder_, *-p* _sub-folder_]
	Remove one or more recipients (matched by full markl ID against the
	canonicalized form) and re-encrypt. Idempotent: if no recipients
	match, no commit is made.

*pass recipients sync* [_file_] [*--path*=_sub-folder_, *-p* _sub-folder_]
	With _file_: replace the recipient set with the contents of _file_,
	which must be a valid _piggy-ids_ text file. Idempotent: if the
	on-disk and declared sets match, no commit is made and no
	re-encryption happens. Validation rejects markl IDs whose format is
	not *pivy_ecdh_p256_pub*.

	With no _file_: re-encrypt every entry to the recipients already in
	the _piggy-ids_ file(s), then commit. Bare *sync* walks the whole
	store; with *-p* _sub-folder_ it re-encrypts only that subtree. Each
	entry is re-encrypted to its nearest _piggy-ids_. Use this to refresh
	ciphertext after editing a _piggy-ids_ file by hand.

*pass ls* _subfolder_
	List names of passwords inside the tree at _subfolder_ by using the
	*tree*(1) program. This command is alternatively named *list*.

*pass grep* [_GREPOPTIONS_] _search-string_
	Searches inside each decrypted password file for _search-string_, and
	displays line containing matched string along with filename. Uses
	*grep*(1) for matching. _GREPOPTIONS_ are passed to *grep*(1) as-is.

*pass find* _pass-names_...
	List names of passwords inside the tree that match _pass-names_ by using
	the *tree*(1) program. This command is alternatively named *search*.

*pass show* [*--clip*[=_line-number_], *-c*[_line-number_]] [*--qrcode*[=_line-number_], *-q*[_line-number_]] _pass-name_
	Decrypt and print a password named _pass-name_. If *--clip* or *-c* is
	specified, do not print the password but instead copy the first (or
	otherwise specified) line to the clipboard using *xclip*(1) or
	*wl-clipboard*(1) and then restore the clipboard after 45 (or
	_PIGGY_CLIP_TIME_) seconds. If *--qrcode* or *-q* is specified, do not
	print the password but instead display a QR code using *qrencode*(1)
	either to the terminal or graphically if supported.

*pass show-batch* [*--names-from*=_FILE_] [*--out-dir*=_DIR_] [*--format*=_human_|_ndjson_] [*--all-or-nothing*] [_pass-name_...]
	Decrypt N eboxes in a single PIV-card session — one PIN prompt for
	the whole batch — and emit per-ebox progress as the RFC 0005 NDJSON
	event stream (or as a human-readable line list with *--format human*,
	the default for terminal use).

	Pass-names are read from positional arguments and, if *--names-from*
	is supplied, from the named file (one per line; blank lines and
	lines beginning with _#_ are skipped). The two sources combine in
	order: positional first, file-supplied second.

	Each successfully decrypted plaintext is written to
	_out-dir/<pass-name>_ with mode *0600*. _out-dir_ itself is created
	with mode *0700* if missing. The path is opened with O_CREAT|O_EXCL,
	so an existing file at that path fails the per-ebox decrypt rather
	than silently clobbering. Pass-names containing _/_ produce nested
	directories under _out-dir_, mode *0700*. Defaults to the current
	working directory when *--out-dir* is omitted.

	With *--all-or-nothing*, every plaintext written during a batch
	that subsequently encounters any failure (decrypt failure, PIN
	error, SIGINT, …) is unlinked before the run terminates. Note that
	this is best-effort cleanup: a consumer that has already read a
	*decrypt {ok: true}* record may have copied the bytes out of band.

	Exit codes:[*0*] every ebox decrypted successfully.[*1*] at least
	one ebox failed, or the batch was bailed out (PIN exhaustion,
	card removal, SIGINT, internal error).[*2*] usage error (no
	pass-names supplied, empty positional name, *--names-from* file
	unreadable).

	A single PIN entry authenticates every decrypt in the batch.
	show-batch opens a PIV transaction (*piggy_piv::PinSession*) once,
	matches the first ebox's PRIMARY recipient against connected cards'
	*9D* slots, prompts for the PIN, then issues one *ecdh_derive* per
	ebox. The card transaction holds for the entire batch, so a
	concurrent PC/SC client cannot clear the PIN-verified state between
	decrypts. See *RFC 0005* (_docs/rfcs/0005-pass-show-batch-ndjson.md_)
	for the NDJSON wire format and the diagnostic taxonomy
	(*not-found*, *pin-cancelled*, *pin-incorrect*, *card-locked*,
	*card-absent*, *decrypt-failed*, *io-error*, *internal*).

*pass verify* [_subpath_]
	Decrypt every ebox file under the store (or the specified
	_subpath_ within it) and emit a tree-decorated ok/not-ok report
	mirroring the *tree*(1) layout used by *pass ls*. Each ebox is
	tested by spawning *pivy-box stream decrypt -b*, which exercises
	the full unlock path without writing plaintext to disk.

	The walk is sequential by design — PIV-card serialization makes
	parallelism a non-win and the simple model is easier to reason
	about. PIN entry happens once (the user-running *pivy-agent*
	caches the verify state) and every subsequent decrypt reuses it.

	_subpath_ is canonicalised against the store root and rejected if
	it contains parent-directory components (*..*), is absolute, or
	escapes the store. Missing _subpath_ verifies the whole store. An
	empty store (or missing root) is reported as a no-op success
	(exit 0).

	Exit codes:[*0*] every ebox under _subpath_ decrypted
	successfully (or the tree was empty).[*1*] at least one ebox
	failed to decrypt.[*2*] usage / IO error before verification
	could begin (sneaky-path violation, walk error, …).

*pass insert* [*--echo*, *-e* | *--multiline*, *-m*] [*--force*, *-f*] _pass-name_
	Insert a new password into the password store called _pass-name_. This
	will read the new password from standard input. If *--echo* or *-e* is
	_not_ specified, disable keyboard echo when the password is entered and
	confirm the password by asking for it twice. If *--multiline* or *-m* is
	specified, lines will be read until EOF or Ctrl+D is reached. Otherwise,
	only a single line from standard input is read. Prompt before overwriting
	an existing password, unless *--force* or *-f* is specified. This command
	is alternatively named *add*.

*pass edit* _pass-name_
	Insert a new password or edit an existing password using the default text
	editor specified by the environment variable _EDITOR_ or using *vi*(1) as
	a fallback. This mode makes use of temporary files for editing, but care
	is taken to ensure that temporary files are created in _/dev/shm_ in order
	to avoid writing to difficult-to-erase disk sectors. If _/dev/shm_ is not
	accessible, fallback to the ordinary _TMPDIR_ location, and print a
	warning. On macOS, a RAM disk is created instead.

*pass generate* [*--no-symbols*, *-n*] [*--clip*, *-c*] [*--qrcode*, *-q*] [*--in-place*, *-i* | *--force*, *-f*] _pass-name_ [_pass-length_]
	Generate a new password using */dev/urandom* of length _pass-length_ (or
	_PIGGY_GENERATED_LENGTH_ if unspecified, default 25) and insert into
	_pass-name_. If *--no-symbols* or *-n* is specified, do not use any
	non-alphanumeric characters in the generated password. The character sets
	used in generating passwords can be changed with the
	_PIGGY_CHARACTER_SET_ and _PIGGY_CHARACTER_SET_NO_SYMBOLS_ environment
	variables, described below. If *--clip* or *-c* is specified, do not print
	the password but instead copy it to the clipboard using *xclip*(1) or
	*wl-clipboard*(1) and then restore the clipboard after 45 (or
	_PIGGY_CLIP_TIME_) seconds. If *--qrcode* or *-q* is specified, do not
	print the password but instead display a QR code using *qrencode*(1)
	either to the terminal or graphically if supported. Prompt before
	overwriting an existing password, unless *--force* or *-f* is specified.
	If *--in-place* or *-i* is specified, do not interactively prompt, and
	only replace the first line of the password file with the new generated
	password, keeping the remainder of the file intact.

*pass rm* [*--recursive*, *-r*] [*--force*, *-f*] _pass-name_
	Remove the password named _pass-name_ from the password store. This
	command is alternatively named *remove* or *delete*. If *--recursive* or
	*-r* is specified, delete pass-name recursively if it is a directory. If
	*--force* or *-f* is specified, do not interactively prompt before
	removal.

*pass mv* [*--force*, *-f*] _old-path_ _new-path_
	Renames the password or directory named _old-path_ to _new-path_. This
	command is alternatively named *rename*. If *--force* is specified,
	silently overwrite _new-path_ if it exists. If _new-path_ ends in a
	trailing _/_, it is always treated as a directory. Passwords are
	selectively re-encrypted to the corresponding template of their new
	destination.

*pass cp* [*--force*, *-f*] _old-path_ _new-path_
	Copies the password or directory named _old-path_ to _new-path_. This
	command is alternatively named *copy*. If *--force* is specified, silently
	overwrite _new-path_ if it exists. If _new-path_ ends in a trailing _/_,
	it is always treated as a directory. Passwords are selectively
	re-encrypted to the corresponding template of their new destination.

*pass git* _git-command-args_...
	If the password store is a git repository, pass _git-command-args_ as
	arguments to *git*(1) using the password store as the git repository. If
	_git-command-args_ is *init*, in addition to initializing the git
	repository, add the current contents of the password store to the
	repository in an initial commit and configure _.gitattributes_ so that
	*git-diff*(1) can display decrypted content via *pivy-box*(1) textconv.
	If the git config key _piggy.signcommits_ is set to _true_, then all
	commits will be signed using the default git signing key. This config key
	may be turned on using: *piggy pass git config --bool --add piggy.signcommits true*

## piggy (top-level)

*list* [*--format* _human_|_ndjson_|_ssh_]
	Enumerate every populated PIV slot across all attached cards.
	Superset of *piggy pass recipients list-available*: in addition to
	the recipient-eligible slots (*9D* + retired *82*..=*95*), it also
	includes the SSH-style slots *9A* (authentication), *9C* (digital
	signature), and *9E* (card authentication).

	The markl purpose attached to each record depends on the slot:

	- 9D + retired 82..95 → *piggy-recipient-v1*
	- 9A (authentication) → *piggy-piv_auth-v1*
	- 9C (digital signature) → *piggy-piv_sig-v1*
	- 9E (card authentication) → *piggy-piv_card_auth-v1*

	The format ID for *piggy-piv_\** purposes depends on the slot's key
	algorithm: *ssh_ecdsa_nistp256_pub* (33-byte SEC1-compressed P-256
	point) for ECDSA P-256, *ssh_ed25519_pub* (32-byte raw key) for
	Ed25519. RSA and ECDSA P-384 in 9A/9C/9E emit *# unsupported:*
	lines.

	Same per-record fields (guid, serial, reader, slot, cn, pin_policy,
	touch_policy) and same human/ndjson auto-selection as *piggy pass
	recipients list-available*.

	*--format=ssh* renders OpenSSH _authorized_keys_-style output instead
	of the markl-native human/ndjson forms. Supported 9A/9C/9E slots
	emit one clean line each, keyed by algorithm
	(*ecdsa-sha2-nistp256* or *ssh-ed25519*):

	```
	ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNo… piggy slot=9A guid=…ABCDEF [cn=user@host]
	```

	Every other slot is suppressed entirely — recipient slots
	(9D + retired 82..95), unsupported keys (RSA, P-384),
	and any payload that fails to render as its key type — so
	the output is a strict _authorized_keys_-compatible feed of
	SSH-capable keys. Re-run with *--format=human* to enumerate
	every slot, or *--format=ndjson* to capture them in a structured
	form. Example:

	```
	piggy list --format=ssh | ssh remote 'cat >> ~/.ssh/authorized_keys'
	```

	*piggy pass recipients list-available* rejects *--format=ssh*
	because every recipient slot is ECDH-only and has no
	_authorized_keys_-style representation.

*help*
	Show piggy's pass-style usage message.

*version*
	Print piggy's self-identification line (_piggy <version>+<commit>_)
	followed by a table of the pinned downstream components (pivy,
	pcsclite) with their versions and revisions. See *eng-versioning*(7).

# SIMPLE EXAMPLES

Initialize password store with auto-detected YubiKey:

```
$ piggy pass init
Using PIV device: C291D27B...
Password store initialized.
```

Initialize with a specific PIV device GUID:

```
$ piggy pass init -g C291D27B12345678
Password store initialized.
```

List existing passwords in store:

```
$ piggy pass ls
Password Store
├── Business
│   ├── some-site.com
│   └── another-site.net
└── Email
    ├── personal
    └── work
```

Show existing password:

```
$ piggy pass show Email/work
sup3rh4x3rizmynam3
```

Copy existing password to clipboard:

```
$ piggy pass show -c Email/work
Copied Email/work to clipboard. Will clear in 45 seconds.
```

Decrypt several passwords in a single PIN-prompt batch
(*--format human* is the terminal default; *--format ndjson* is the
machine surface consumed by automation):

```
$ piggy pass show-batch --out-dir /tmp/secrets Email/work Business/some-site.com
Decrypting 2 ebox(es):
[1/2] Email/work → /tmp/secrets/Email/work ok
[2/2] Business/some-site.com → /tmp/secrets/Business/some-site.com ok
Summary: 2 ok, 0 failed
```

Or drive a longer list from a file (blank lines and _#_-comments
ignored), wiping any partial output on the first failure:

```
$ cat secrets-to-rotate.txt
# infra
ops/aws-root
ops/cloudflare

$ piggy pass show-batch --names-from secrets-to-rotate.txt \
    --out-dir ./batch --all-or-nothing --format ndjson
{"type":"plan","count":2}
{"type":"decrypt","n":1,"name":"ops/aws-root","ok":true,"out_path":"./batch/ops/aws-root","diagnostic":null}
{"type":"decrypt","n":2,"name":"ops/cloudflare","ok":true,"out_path":"./batch/ops/cloudflare","diagnostic":null}
{"type":"summary","ok":2,"failed":0}
```

Add password to store:

```
$ piggy pass insert Business/new-site
Enter password for Business/new-site:
Retype password for Business/new-site:
```

Generate new password:

```
$ piggy pass generate Email/new-account 20
The generated password for Email/new-account is:
$(-QF&Q=IN2nFBx!@kz3
```

Generate new alphanumeric password:

```
$ piggy pass generate -n Email/new-account 12
The generated password for Email/new-account is:
YqFsMkBeO6di
```

Remove password from store:

```
$ piggy pass rm Business/old-site
Are you sure you would like to delete Business/old-site? [y/N] y
removed '/home/user/.local/share/piggy/Business/old-site.ebox'
```

# EXTENDED GIT EXAMPLE

Here, we initialize a new password store, create a git repository, and then
manipulate and sync passwords.

```
$ piggy pass init
Using PIV device: C291D27B...
Password store initialized.

$ piggy pass git init
Initialized empty Git repository in /home/user/.local/share/piggy/.git/
[master (root-commit) 998c8fd] Add current contents of password store.

$ piggy pass git remote add origin git@host:secrets.git

$ piggy pass generate Email/account 21
[master 30fdc1e] Add generated password for Email/account to store.
The generated password for Email/account is:
<5m,_BrZY`antNDxKN<0A

$ piggy pass git push -u --all

$ piggy pass insert Email/other-account
Enter password for Email/other-account:
Retype password for Email/other-account:
[master b9b6746] Add given password for Email/other-account to store.

$ piggy pass rm -f Email/account
removed '/home/user/.local/share/piggy/Email/account.ebox'
[master 288b379] Remove Email/account from store.

$ piggy pass git push
```

# FILES

*~/.local/share/piggy*
	The default password storage directory.

*~/.local/share/piggy/.pivy-id*
	Contains the pivy-box ebox template used for encryption. This is a binary
	template file created by *pivy-box*(1) that lists PIV public keys that
	secrets are encrypted to. Sub-directories may contain their own _.pivy-id_
	files; passwords inside those sub-directories are encrypted using those
	templates. This should be set using the *piggy pass init* command.

# ENVIRONMENT VARIABLES

_PIGGY_STORE_DIR_
	Overrides the default password storage directory. Default:
	_$XDG_DATA_HOME/piggy_ or _~/.local/share/piggy_.

_PIGGY_UMASK_
	Sets the umask of all files modified by piggy, by default _077_.

_PIGGY_X_SELECTION_
	Overrides the selection passed to *xclip*, by default _clipboard_. See
	*xclip*(1) for more info.

_PIGGY_CLIP_TIME_
	Specifies the number of seconds to wait before restoring the clipboard, by
	default _45_ seconds.

_PIGGY_GENERATED_LENGTH_
	The default password length if the _pass-length_ parameter to *pass generate*
	is unspecified, by default _25_.

_PIGGY_CHARACTER_SET_
	The character set to be used in password generation for *pass generate*. This
	value is to be interpreted by *tr*. See *tr*(1) for more info. Default:
	_[:punct:][:alnum:]_.

_PIGGY_CHARACTER_SET_NO_SYMBOLS_
	The character set to be used in no-symbol password generation for
	*pass generate*, when *--no-symbols* or *-n* is specified. This value is to be
	interpreted by *tr*. See *tr*(1) for more info. Default: _[:alnum:]_.

_PIGGY_GIT_
	If set, overrides automatic git detection.

_PIGGY_GETOPT_
	Override the path to GNU *getopt*(1). Useful in Nix environments where
	getopt is provided on PATH.

_PIGGY_AUTH_SOCK_
	SSH-agent socket used for PIV decrypt (*pivy-box stream decrypt*). When
	set and non-empty, it overrides _SSH_AUTH_SOCK_ for piggy's own decrypts
	only; when unset, piggy uses _SSH_AUTH_SOCK_. Use it to route decrypts at
	a piggy-agent that advertises the _ecdh@joyent.com_ extension rather than
	through an *ssh-agent-mux*(1) that may not.

_SECURE_TMPDIR_
	If set, skip automatic secure temporary directory creation (ramdisk on
	macOS, /dev/shm on Linux) and use this path instead. Useful in sandboxed
	environments where device operations are restricted.

_EDITOR_
	The location of the text editor used by *pass edit*.

# SEE ALSO

*piggy-agent*(1), *pivy-box*(1), *pivy-tool*(1), *pivy-agent*(1), *git*(1),
*tree*(1), *tr*(1), *xclip*(1), *wl-clipboard*(1), *qrencode*(1),
*piggy-piv-slots*(7)

# AUTHOR

*piggy* is a fork of *pass*(1) by Jason A. Donenfeld <Jason@zx2c4.com>,
rewritten to use PIV smart cards via *pivy-box*(1) instead of GPG.

# COPYING

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301, USA.
