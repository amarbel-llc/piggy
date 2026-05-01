piggy(1)

# NAME

piggy - stores, retrieves, generates, and synchronizes passwords using PIV smart cards

# SYNOPSIS

*piggy pass* _SUBCOMMAND_ [_OPTIONS_]... [_ARGS_]...

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

*pass init* [*--path*=_sub-folder_, *-p* _sub-folder_] [*--guid*=_GUID_, *-g* _GUID_] [*--edit*, *-e*] [*--interactive*, *-i*]
	Initialize new password storage with a pivy-box ebox template. Without
	flags, the first inserted PIV device is auto-detected via *pivy-tool*(1).
	If *--guid* or *-g* is specified, create a template for the given PIV
	device GUID. If *--interactive* or *-i* is specified, run the interactive
	*pivy-box*(1) template creation menu. If *--edit* or *-e* is specified,
	edit an existing _.pivy-id_ template interactively. If *--path* or *-p* is
	specified, assign a template for that specific sub-folder of the password
	store. If the specified template is different from the one used in any
	existing files, those files will be re-encrypted to the new template.

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

*help*
	Show piggy's pass-style usage message.

*version*
	Show piggy's version banner.

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

_SECURE_TMPDIR_
	If set, skip automatic secure temporary directory creation (ramdisk on
	macOS, /dev/shm on Linux) and use this path instead. Useful in sandboxed
	environments where device operations are restricted.

_EDITOR_
	The location of the text editor used by *pass edit*.

# SEE ALSO

*piggy-agent*(1), *pivy-box*(1), *pivy-tool*(1), *pivy-agent*(1), *git*(1),
*tree*(1), *tr*(1), *xclip*(1), *wl-clipboard*(1), *qrencode*(1)

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
