piggy(1)

# NAME

piggy - PIV smart-card backed password store and agent

# SYNOPSIS

*piggy pass* _SUBCOMMAND_ [_OPTIONS_]... [_ARGS_]...

*piggy list* [*--format* _human_|_ndjson_|_ssh_]

*piggy ssh-copy-id* [*--ids* _PATH_] [_SSH-COPY-ID-OPTIONS_]... [_user_@]_host_

*piggy sign-bytes* *--slot* _9a_|_9c_ [*--guid* _GUID_] [*--format* _raw_|_der_] [*-P* _PIN_]

*piggy operator-sign* *--namespace* _NAMESPACE_ [*--slot* _9c_|_9a_] [*--guid* _GUID_] [*--hash* _sha512_|_sha256_]

*piggy help*

*piggy version*

*piggy agent*|*box*|*tool*|*ca*|*luks*|*zfs* [_ARGS_]...

*piggy pivy* _TOOL_ [_ARGS_]...

# DESCRIPTION

*piggy* stores, retrieves, generates, and synchronizes passwords using PIV
smart cards.

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

In addition to the *pass* family, *piggy* provides these top-level PIV
commands:

- *piggy agent* is piggy's own Rust SSH/PIV agent; see *piggy-agent*(1).
- *piggy box* is piggy's Rust re-implementation of the *pivy-box*(1)
  subset piggy uses: *stream encrypt*|*decrypt* and *tpl create*|*show*.
  Any other *box* subcommand is a usage error (piggy#165); the rest of
  the *pivy-box*(1) surface (*tpl edit*, *key*, *challenge*, interactive
  modes) is reachable only through *piggy pivy box* while the C binary is
  still shipped.
- *piggy tool* is piggy's Rust re-implementation of the *pivy-tool*(1)
  operations piggy uses (as of the piggy#289 3.6 cutover it is Rust, not a
  passthrough): *pubkey*, *cert*, *attest*, *sign*, *ecdh*, the PIN/PUK ops,
  *set-admin*, *delete-cert*, *update-keyhist*, *write-cert*, *generate*,
  *import*, *pinfo*, *list -j*, *factory-reset*, and *req-cert*.
  *factory-reset* wipes the PIV applet (YubicoPIV RESET) and is gated by a
  typed *YES* on the tty or the *--yes*/*--force* flag. *req-cert* prints a
  minimal EC PKCS#10 CSR for the slot's key (subject *CN* from *-n*, else
  *<slot>@<short-guid>*); it is EC-only. Any unported op or unmodeled option
  is a usage error; the rest of the *pivy-tool*(1) surface (*list*
  human/parseable modes, *version*, *init*, and the RSA/Ed25519 key ops —
  piggy is EC-only) is reachable only through *piggy pivy tool* (see below,
  and the C-pivy retirement plan in _docs/plans_).
- *piggy pivy* _TOOL_ is the explicit escape hatch to the C binaries:
  *piggy pivy box* runs *pivy-box*(1), *piggy pivy tool* runs *pivy-tool*(1),
  and *piggy pivy agent* runs *pivy-agent*(1), bypassing the Rust
  re-implementations. As of the piggy#289 Phase 4 cutover the C pivy binaries
  are **no longer bundled** with piggy — they survive only as a differential
  test input — so these subcommands find no *pivy-\** on _$PATH_ and report
  that plainly unless you install pivy separately. Their code is removed with
  the C build in Phase 5.

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
	unlocked and decrypted in process (agent first, then a local card),
	which exercises the full unlock path without writing plaintext to
	disk; the shared unlock caches the PIN, so an agentless verify
	prompts at most once per card.

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
	*git-diff*(1) can display decrypted content via a *piggy box stream
	decrypt* textconv.
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
	point) for ECDSA P-256, *ssh_ecdsa_nistp384_pub* (49 bytes, same
	shape one curve up) for ECDSA P-384, *ssh_ed25519_pub* (32-byte raw
	key) for Ed25519. RSA in 9A/9C/9E emits *# unsupported:* lines.

	Same per-record fields (guid, serial, reader, slot, cn, pin_policy,
	touch_policy) and same human/ndjson auto-selection as *piggy pass
	recipients list-available*.

	*Uninitialized cards.* A factory-blank PIV card (no CHUID, so an
	all-zeros GUID and no slots) is also enumerated, as a card-level
	discovery record carrying its *reader* and — on a YubiKey — its
	*serial* (the handle for provisioning). In *--format=ndjson* it is an
	object with *uninitialized* set to true, the all-zeros *guid*, the
	*reader*, and (when available) *serial* — a boolean marker mirroring
	*unsupported:true*, with no *slot* or *id*. In *--format=human* it is
	a *# uninitialized:* comment line; in *--format=ssh* it is suppressed
	(no key). This is the only piggy surface that shows blank cards: every
	other command enumerates strictly, so a blank card never perturbs
	sole-card auto-selection.

	*--format=ssh* renders OpenSSH _authorized_keys_-style output instead
	of the markl-native human/ndjson forms. Supported 9A/9C/9E slots
	emit one clean line each, keyed by algorithm
	(*ecdsa-sha2-nistp256*, *ecdsa-sha2-nistp384*, or *ssh-ed25519*):

	```
	ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNo… piggy slot=9A guid=…ABCDEF [cn=user@host]
	```

	Every other slot is suppressed entirely — recipient slots
	(9D + retired 82..95), unsupported keys (RSA),
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

*ssh-copy-id* [*--ids* _PATH_] [_SSH-COPY-ID-OPTIONS_]... [_user_@]_host_
	Authorize a whole recipient set for SSH login on a remote host.
	Reads the PIV slot-9A SSH-auth keys (*piggy-piv_auth-v1* with an
	_ssh_..._pub_ format: ECDSA P-256/P-384 or Ed25519) declared in a
	*piggy-ids*(5) file, renders each as an _authorized_keys_ line keyed
	by its algorithm (*ecdsa-sha2-nistp256*, *ecdsa-sha2-nistp384*, or
	*ssh-ed25519*), and hands the whole set to the system
	*ssh-copy-id*(1) — installing them all on the remote in one
	invocation.

	The 9D encryption recipients in the same file are ignored; only 9A
	SSH-auth entries are installed. Rendering is offline (the keys come
	straight from the file's markl IDs), so no card or PIN is needed.

	*--ids* _PATH_ reads recipients from _PATH_ instead of the store's
	*piggy-ids* (resolved via *PIGGY_STORE_DIR*). Every other argument —
	including the _[user@]host_ and any *ssh-copy-id*(1) options (*-p*,
	*-o*, …) — is forwarded verbatim to *ssh-copy-id*, which is invoked
	with *-f -i* _<rendered-file>_. *-f* skips ssh-copy-id's
	already-installed probe (the keys are recipients', not the local
	agent's).

	If the file declares no 9A keys, the command refuses with guidance
	rather than invoking *ssh-copy-id*. Discover a card's 9A markl ID
	with *piggy list --format=human* and add it with *piggy pass
	recipients add*.

	```
	piggy ssh-copy-id alice@server.example
	piggy ssh-copy-id --ids ./team-ids -p 2222 deploy@host
	```

*sign-bytes* *--slot* _9a_|_9c_ [*--guid* _GUID_] [*--format* _raw_|_der_] [*-P* _PIN_]
	Sign the bytes read from stdin with a PIV signing-slot key and write
	the signature to stdout. A low-level, caller-agnostic primitive:
	piggy applies no canonicalization to the message — the caller controls
	the exact bytes. *SHA-256* (P-256) / *SHA-384* (P-384) hashing is
	intrinsic to the *ecdsa-sha2-nistp256*/*384* algorithm and is applied
	before the card signs, matching *pivy-tool sign*.

	*--slot* selects the signing slot: *9a* (PIV Authentication) or *9c*
	(Digital Signature). Slot *9d* (Key Management / ECDH) is rejected — it
	cannot sign. The slot must hold an ECDSA P-256 or P-384 key.

	*--format* sets the output framing (default *raw*):
	*raw* emits the fixed-width _r‖s_ (P-256 → 64 bytes, P-384 → 96) — the
	markl *...@ecdsa_p256_sig* payload a downstream consumer can wrap
	directly. *der* emits the card-native ASN.1 _SEQUENCE { INTEGER r,
	INTEGER s }_ (matches *pivy-tool sign*; for callers that already parse
	DER).

	*--guid* _GUID_ selects among several attached cards (direct-PCSC, no
	agent); with one card it is optional. The PIN comes from *-P* _PIN_ or,
	absent that, an *SSH_ASKPASS*/tty prompt (see *ENVIRONMENT VARIABLES*).
	The prompt NAMES the target card — its short GUID, serial (when
	available), and the signing slot's certificate CN — so an operator
	holding more than one card cannot enter the wrong PIN and block a card. Signing on slot 9A/9C exercises the private key and
	requires the card PIN per the slot's policy — this is the only top-level
	command besides the agent that does so.

	The output is binary; redirect it to a file or pipe it. Example
	(produce a raw _r‖s_ signature over a file):

	```
	piggy sign-bytes --slot 9a --guid DEADBEEF... < message > sig.raw
	```

	*sign-bytes* refuses a message that is sshsig signed data under an
	operator-act namespace (see *operator-sign*): such a signature is made
	only where its text is shown first. *piggy tool sign* and the agent's
	ordinary sign request refuse the same bytes.

*operator-sign* *--namespace* _NAMESPACE_ [*--slot* _9c_|_9a_] [*--guid* _GUID_] [*--hash* _sha512_|_sha256_]
	Sign the text read from stdin as an operator act (RFC 0012) and write
	an armored sshsig to stdout. An operator act is a signature a human
	made on purpose, having read what it says: an escalation grant, a
	certificate, a quote of their own words.

	*operator-sign* signs nothing itself. It sends the text and the
	namespace to the agent's *operator-act@piggy* extension (the socket in
	*PIGGY_AUTH_SOCK*, else *SSH_AUTH_SOCK*) and the agent that holds the
	card does the rest: it checks that the card attests the slot's key as
	PIN always and touch always, shows the exact text on the prompt that
	asks for the PIN, waits for the touch, and builds the sshsig from the
	text it showed. There is no flag to skip any of that, and none to
	supply a PIN or a digest. Because everything happens in the agent, the
	command works unchanged over a forwarded agent socket or through a
	*piggy agent --proxy-only* front: the prompt appears where the card is.

	*--namespace* is one of *piggy-quote-v1*, *piggy-escalation-v1* or
	*piggy-certificate-v1*. It is part of what is signed, and it selects
	how the prompt presents the act, so an escalation cannot be obtained
	behind a prompt that looked like a quote. Any other namespace is
	refused.

	*--slot* defaults to *9c*, the key *piggy card init* and *piggy card
	add-key 9c* enroll for this. A slot whose key the card does not attest
	as PIN always and touch always is refused, whatever it is; 9A as
	*card init* enrolls it is. *--guid* picks the card when the agent
	serves the slot for more than one.

	The text must be 1 to 4096 bytes of UTF-8 with no control characters
	other than newline and tab, so that what the prompt shows is what is
	signed. To bind something that is not text, put its markl-id in the
	text. The text is not secret: it is shown on screen and crosses the
	agent socket.

	The signature verifies with *ssh-keygen -Y verify -n* _NAMESPACE_
	against the slot's public key. *piggy card export-attestation* prints
	the evidence that the key is a card's PIN-always, touch-always key.

	Exit status, grouped by what a caller should do next (the RFC's name
	for the outcome is on stderr):

	*0*  signed; the sshsig is on stdout.

	*1*  refused, and asking again will not change the answer: the slot's
	policy, the namespace, the text, a malformed request, a key the agent
	does not serve, or an error.

	*2*  usage error.

	*3*  no agent here serves operator acts: no agent socket, an
	unreachable agent, or one that predates the extension.

	*4*  not signed this time: the operator cancelled or did not touch the
	card in time, or the card was absent. Asking again may succeed.

	```
	piggy operator-sign --namespace piggy-escalation-v1 < grant.txt > grant.sig
	```

*card init* [*--serial* _N_|*--guid* _HEX_|*--reader* _NAME_] [*--allow-reprovision*] [*--pin-policy* _SLOT_=_POLICY_]... [*--touch-policy* _SLOT_=_POLICY_]... [*--seal-management-key*[=_PASS-NAME_]|*--no-seal-management-key*] [*--frontend* _tty_|_jsonrpc_] [*--socket* _PATH_]
	Provision a factory-blank PIV card in one step: write the CHUID (a fresh
	random GUID), generate slot 9D (Key Management / ECDH — piggy's decrypt
	recipient), slot 9A (PIV Authentication — the SSH-auth key) and slot 9C
	(Digital Signature — the operator-act key) as ECDSA P-256, build and
	card-sign a self-signed certificate for each (CN _piv-key-mgmt@<guid8>_ /
	_piv-auth@<guid8>_ / _piv-sign@<guid8>_), change the PIN and PUK off
	their factory defaults, and rotate the management key. The provisioned GUID
	is printed to stdout.

	Each key is generated with a PIN policy and a touch policy. 9A is PIN
	_once_, touch _cached_: one PIN per session, and one touch covers a
	burst of logins. 9C is PIN _always_, touch _always_: every signature is
	a deliberate act, which is what an operator act requires. 9D keeps the
	card's own default, as before.

	Because each certificate is signed by its own new key, the card asks for a
	touch while 9A's and 9C's certificates are signed; piggy says when. For a
	touch _cached_ key piggy says to touch the card if it asks: a touch a few
	seconds earlier still counts, and then the card does not ask. A
	touch that is not given in time stops the command with the card partly
	provisioned and still on its factory PIN, PUK and management key; the
	error says so, and *card init --allow-reprovision* starts again.

	*--pin-policy* _SLOT_=_POLICY_ and *--touch-policy* _SLOT_=_POLICY_
	override one slot each and may be repeated. _SLOT_ is _9a_, _9c_ or _9d_.
	PIN policies are _default_, _never_, _once_, _always_; touch policies are
	_default_, _never_, _always_, _cached_. Slot and policy names are read in
	any case (_9C=Always_ is _9c=always_). _default_ sends no policy to the
	card. A 9C that is not PIN _always_ and touch _always_ cannot serve
	operator acts; piggy warns when it provisions one.

	Policies are a YubiKey feature. On any other PIV card piggy sends none,
	the keys get the card's own defaults, and piggy warns that the card cannot
	serve operator acts.

	*--serial* _N_ selects the card by its YubiKey serial; with exactly one
	factory-blank card attached it is optional, and required only to
	disambiguate when several are present.

	The operator interactions — the new PIN, the new PUK, a proceed
	confirmation, and the management-key source — run through a pluggable
	frontend. *--frontend tty* (the default) prompts via *SSH_ASKPASS*/tty,
	naming the card in each prompt as *sign-bytes* does. *--frontend jsonrpc*
	hands every interaction to an external program (e.g. a richer UI) over the
	*--socket* _PATH_ AF_UNIX stream: the program listens and answers
	newline-framed JSON-RPC, piggy connects as the client. A missing or
	unusable channel fails before any card operation. The management key rotates
	to a fresh random value, displayed once on stderr by the tty frontend
	(record it — it is not recoverable) unless it is sealed.

	*--guid* _HEX_ and *--reader* _NAME_ select a card whose serial is not
	exposed over PIV (e.g. an older YubiKey 4); factory-blank cards share the
	all-zeros GUID, so *--reader* is the one that tells two of them apart.
	*--allow-reprovision* also accepts an already-initialized card still at its
	factory credentials, behind a destructive-overwrite confirmation.

	*--seal-management-key*[=_PASS-NAME_] seals the generated management key
	into the password store instead of displaying it. Like *pass insert*, it is
	encrypted to the recipients of the store's nearest *piggy-ids* for
	_PASS-NAME_ (default _piv/<GUID>/management-key_), so any of those cards can
	recover it with *pass show*. List a backup card there: a reset destroys the
	provisioned card's own key. The seal is checked before the card is touched
	(a path with no encryption recipients, or one that already exists, fails the
	command), and the key is sealed before it is set on the card. Without the
	flag the tty flow offers the seal whenever the store can take it;
	*--no-seal-management-key* suppresses the offer.

	```
	piggy card init
	piggy card init --serial 15909078
	piggy card init --seal-management-key
	piggy card init --touch-policy 9a=never
	piggy card init --frontend jsonrpc --socket /run/user/1000/piggy-ui.sock
	```

*card add-key* _SLOT_ [*--pin-policy* _POLICY_] [*--touch-policy* _POLICY_] [*--replace*] [*--management-key-from-store*[=_PASS-NAME_]] [*--serial* _N_|*--guid* _HEX_|*--reader* _NAME_] [*--frontend* _tty_|_jsonrpc_] [*--socket* _PATH_]
	Add one key to a card that is already provisioned, and change nothing
	else: no other slot, not the PIN, the PUK or the management key. _SLOT_
	is _9c_ or _9a_.

	*card add-key 9c* gives a card provisioned before piggy generated 9C the
	operator-act key: PIN _always_, touch _always_ unless overridden. *card
	add-key 9a --replace* generates a new SSH key (PIN _once_, touch _cached_);
	everything that trusts the old one must be given the new one. Slot _9d_
	is refused: the password store is encrypted to its key, and a new key
	could not decrypt it. *--pin-policy* and *--touch-policy* take the
	policy names of *card init*, in any case.

	A slot that already holds a key is refused unless *--replace* is given;
	with it, piggy asks for confirmation and the old key is destroyed. piggy
	recognises a slot's key by the slot's certificate, as every piggy
	command does: a key whose certificate was deleted looks like an empty
	slot and is replaced without *--replace*.

	If the command stops after the new key is generated (most likely a touch
	that was not given in time), the slot holds a key without a certificate
	and any key it held before is gone; the error says so, and running the
	command again with *--replace* finishes the job.

	The command needs the card's current management key and its PIN, and a
	touch if the new key has a touch policy. The management key is asked for
	through the frontend (48 hex digits, or the word _default_ for a card
	still on the factory key). *--management-key-from-store* reads it from
	the password store instead: from _PASS-NAME_, or from
	_piv/<GUID>/management-key_, where *card init --seal-management-key*
	puts it. Reading it is a normal store decrypt and may ask for a PIN.

	The new public key is printed to stdout as an OpenSSH line with the
	comment *PIV\_slot\_*_SLOT_*@*_GUID_. Exit status is 2 for a request that is
	wrong whatever card is attached (slot _9d_, an unknown slot, an unknown
	policy name, conflicting selectors), refused before any frontend is
	opened or prompt shown, and 1 for any other failure.

	```
	piggy card add-key 9c
	piggy card add-key 9c --management-key-from-store
	piggy card add-key 9a --replace --serial 15909078
	```

*card export-attestation* [_SLOT_] [*--serial* _N_|*--guid* _HEX_|*--reader* _NAME_]
	Print the attestation bundle for a slot's key (RFC 0012 section 5), to
	publish beside the key. _SLOT_ is _9c_ (the default, the operator-act
	key) or _9a_. Read-only; needs no PIN and no touch.

	The bundle is a text document: a header line, a _# key_ line with the
	key's markl id, the key as an OpenSSH line (its comment names the slot
	and the card: *PIV\_slot\_9C card:5da19c98*), the card's attestation
	certificate for the key, and the
	card's own attestation certificate (slot F9), both as PEM. With it a
	verifier can check that the key was generated on a YubiKey and read its
	PIN and touch policy; the verifier supplies the Yubico root itself.

	Only a key generated on a YubiKey can be attested. A key that was
	imported, or a card that is not a YubiKey, fails with the card's answer.
	piggy checks before printing that the attestation is for the slot's key
	and is signed by the card's attestation certificate, and prints nothing
	otherwise. Exit status is 2 for an unknown slot or conflicting
	selectors and 1 for any other failure.

	```
	piggy card export-attestation > 9c.attestation
	piggy card export-attestation 9a --serial 15909078
	```

*help*
	Show piggy's pass-style usage message.

*version*
	Print piggy's self-identification line (_piggy <version>+<commit>_)
	followed by a table of the pinned downstream components (pivy,
	pcsclite) with their versions and revisions. See *eng-versioning*(7).

## piggy health

*health* [*--format* _auto_|_tap_|_ndjson_] [*-v*, *--verbose*] [*--sign-test*]
	Read-only, PIN-free checks of the piggy layer: the agent socket, its
	identities and the *ecdh@joyent.com* extension, pcscd, attached cards
	and their 9D slots, and the agent's service unit. Nine fixed points,
	then the conditional ones described below;
	TAP-14 on a tty, tap-ndjson(7) otherwise; exit 0 iff no point fails
	(SKIPs count as ok). *-v* attaches the diagnostic block to every
	point.

	An agent proxying upstreams (*piggy-agent*(1) *--upstream*) appends
	one point per upstream, read from the agent's *upstream-status@piggy*
	self-report; the upstreams are probed with a plain identity request.
	A *--proxy-only* agent SKIPs the four local-card points and its
	upstreams are treated as alternatives: a dead one SKIPs while another
	is live and FAILs only when none is. Each upstream point carries
	*up_since* or *down_since* and, for a dead one, the *error*. The
	service point probes the unit
	the agent names via *--service-name*, else the platform default. A
	further point reports the agent's presence mode (event-driven or poll).

	Each attached card then gets two points. The first names the PIN and
	touch policy the card attests for slots 9A, 9C and 9D, for example
	_card 5DA19C98: slot policies: 9A PIN once, touch cached; 9C PIN always,
	touch always; 9D not attested_; a slot is _not attested_ when its key
	was imported rather than generated on the card, or the card is not a
	YubiKey (*-v* shows the card's answer). The second, _can sign operator
	acts_, passes when 9C is attested PIN always and touch always. A card
	that cannot is flagged with a SKIP whose reason begins _no:_ and says
	why (9C empty, a weaker policy, or no attestation); it is not a
	failure, and *card add-key 9c* is the remedy for an empty 9C.

	*--sign-test* adds an agent self-sign probe with every served identity
	— the only path that exercises the private key and MAY prompt for a
	PIN — catching an agent that lists keys but refuses to sign.

## piggy manage

*manage* *--jsonrpc* [*--socket* _PATH_]
	Run the headless JSON-RPC 2.0 management server (RFC 0007): piggy's
	neutral management primitives *card.list*, *card.init*, *card.add_key*
	and *sign_bytes* over stdio, or an *AF_UNIX* socket with *--socket*, so an
	external program drives piggy without spawning subprocesses. After an
	*initialize* handshake (*piggy-mgmt/1*) requests are served one at a
	time until EOF. While an interactive method runs, piggy issues the RFC
	0006 interaction requests (PIN, confirm, progress) back over the same
	connection. An error message names the params a caller sent (_'replace':
	true_, _'pin\_policy'_), never the command-line flags of the matching
	*card* subcommand.

## piggy secrets

*secrets reconcile* [*--manifest* _FILE_] [*--check*] [*--adopt*] [*-v*] [*--frontend* _tty_|_jsonrpc_] [*--socket* _PATH_]
	Write the plain secret files a JSON manifest declares from their ebox
	ciphertexts (piggy FDR 0003), decrypting only entries that are missing
	or changed, in one PIN prompt. Freshness is the ciphertext's content
	hash plus the target's recorded stat fingerprint (never mtime), kept
	in _$XDG_STATE_HOME/piggy/secrets/state.json_, so a steady-state run
	touches no card. Writes are atomic renames; a failed decrypt keeps the
	previous file; an existing target not recorded as piggy-managed is a
	conflict unless *--adopt*; nothing is ever deleted. *--check* reports
	drift without decrypting. TAP-14 output; exit 0 when everything is
	fresh or written, 1 on any failure (or any drift with *--check*), 2 on
	a usage or manifest error. The default manifest is the one the
	*services.piggy-secrets* home-manager module maintains, which also
	runs *--check* at activation and starts the oneshot
	_piggy-secrets.service_ on drift without ever decrypting during a
	switch.

## piggy luks

LUKS2 volumes keyed by a store secret. The first line of the *--secret*
entry is the passphrase: it is decrypted the same way *piggy pass show*
does (through the agent, honouring _PIGGY_AUTH_SOCK_) and piped to
*cryptsetup*(8) with *--key-file -*, one card operation per invocation.
Everything after *--* is forwarded to *cryptsetup* verbatim, before the
positional device. piggy interprets none of it.

*luks format* _device_ *--secret* _pass-name_ [*--* _cryptsetup-args_...]
	*cryptsetup luksFormat --type luks2 --key-file -* _device_ with the
	secret as the first keyslot. Destructive.

*luks open* _device_ _name_ *--secret* _pass-name_ [*--* _cryptsetup-args_...]
	*cryptsetup open --key-file -* _device_ _name_.

*luks add-key* _device_ _new-key-file_ *--secret* _pass-name_ [*--* _cryptsetup-args_...]
	*cryptsetup luksAddKey --key-file -* _device_ _new-key-file_: the
	secret authorises, the file's contents become an additional keyslot —
	a passphrase that opens the volume without a card.

*luks close* _name_ [*--* _cryptsetup-args_...]
	*cryptsetup close* _name_. No secret involved.

A missing entry, an empty first line, or a decrypt failure exits 1
before *cryptsetup* runs; otherwise the exit status is *cryptsetup*'s.
Primary keyslots only — there is no N-of-M recovery shape. This is not
the *pivy-luks* key-ebox format; it is a piggy command over ordinary
store entries.

## piggy zfs

ZFS native-encryption datasets keyed by a store secret; the sibling of
*piggy luks* with the same rules: the *--secret* entry's first line is
the passphrase, decrypted like *piggy pass show* and written to *zfs*(8)
on stdin, one card operation per invocation; everything after *--* is
forwarded to *zfs* verbatim before the dataset.

*zfs create* _dataset_ *--secret* _pass-name_ [*--* _zfs-args_...]
	*zfs create -o encryption=aes-256-gcm -o keyformat=passphrase -o
	keylocation=prompt* [_zfs-args_...] _dataset_. Further *-o*
	properties (mountpoint, compression, …) go after *--*.

*zfs load-key* _dataset_ *--secret* _pass-name_ [*--* _zfs-args_...]
	*zfs load-key -L prompt* _dataset_. Unloading needs no secret; use
	*zfs unload-key* directly.

A missing entry, an empty first line, or a decrypt failure exits 1
before *zfs* runs; otherwise the exit status is *zfs*'s. This is not
the *pivy-zfs* key-ebox format.

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

_PIGGY_PIGPEN_NO_CACHE_
	When a _piggy-ids_ file is a pigpen pointer, its resolved recipient set
	is cached for an hour under _$XDG_CACHE_HOME/piggy_. Any non-empty value
	skips the cache and runs _pigpen-resolver-<kind>_ every time.

_PIGGY_PIGPEN_RESOLVER_TIMEOUT_
	Seconds a _pigpen-resolver-<kind>_ may run before it is killed and the
	command fails, by default _30_; at most a day, and a value that is not
	a positive whole number is ignored. The resolver keeps the terminal,
	so it may prompt, and Ctrl-C reaches it. A resolver is looked up only
	in absolute _PATH_ entries, may print at most 1 MiB, and must answer
	with a recipient set naming at least one encryption recipient. When a
	resolver exits successfully but a process it started still holds its
	standard output, the command fails after two seconds; one holding only
	standard error is ignored. Processes a resolver starts are not killed.

_PIGGY_GETOPT_
	Override the path to GNU *getopt*(1). Useful in Nix environments where
	getopt is provided on PATH.

_PIGGY_AUTH_SOCK_
	SSH-agent socket used for PIV decrypt (the in-process unlock behind
	*pass show*, *edit*, *grep*, *verify*, the re-encryption walk and
	*piggy box stream decrypt*). When
	set and non-empty, it overrides _SSH_AUTH_SOCK_ for piggy's own decrypts
	only; when unset, piggy uses _SSH_AUTH_SOCK_. Use it to route decrypts at
	a piggy-agent that advertises the _ecdh@joyent.com_ extension rather than
	through an upstream agent that may not.

_SECURE_TMPDIR_
	If set, skip automatic secure temporary directory creation (ramdisk on
	macOS, /dev/shm on Linux) and use this path instead. Useful in sandboxed
	environments where device operations are restricted.

_EDITOR_
	The location of the text editor used by *pass edit*.

_STATSD_HOST_, _STATSD_PORT_
	Opt in to stats-me telemetry for the pass-style commands
	(_piggy.pass.<cmd>_ counters and timers, plus _piggy.box.<op>_,
	_piggy.luks.<sub>_, _piggy.card.<sub>_, _piggy.health.run_ and the
	others). Their presence is the gate; see *piggy-agent*(1) ENVIRONMENT
	for the wire shape and defaults.

# SEE ALSO

*piggy-agent*(1), *age-plugin-piggy*(1), *pivy-box*(1), *pivy-tool*(1),
*git*(1), *tree*(1), *xclip*(1), *wl-clipboard*(1), *qrencode*(1),
*ssh-copy-id*(1), *piggy-ids*(5), *piggy-piv-slots*(7), *piggy-ci*(7),
*piggy-testing*(7), *piggy-markl*(7)

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
