hogtie(8)

# NAME

hogtie - one door to root for agent sessions, opened by an operator-signed grant

# SYNOPSIS

*hogtie nonce* [*--socket* _PATH_]++
*hogtie message* _NONCE_ _ACTION_ [_ARG_...]++
*hogtie response* _NONCE_ _SIGFILE_++
*sudo hogtie exec* _RESPONSE_ _ACTION_ [_ARG_...]++
*hogtie serve*++
*hogtie --version*

# DESCRIPTION

*hogtie* gives a host one way for an agent session to run something as
root: a fixed, declared *action*, with typed arguments, when the caller
proves it holds a key that an operator-signed *grant* names that action
for. There is no other path and no exemption: a read-only action gets a
long-lived grant, never a free pass. It is a crude bridge to a later
system (ajour); there are no intermediates.

A *grant* is an OpenSSH user certificate signed by the host's SSH
certificate authority (in production the operator's card, slot 83; in
tests a software CA). Its *principals* are the action names it allows and
its validity is the grant's lifetime. The caller proves possession by
making an *sshsig* (*ssh-keygen -Y sign*) with the certified key, in
namespace *hogtie-v1*, over one canonical message that binds a fresh,
single-use *nonce*, the caller's account, the action and its arguments.

This is stage 1: a root-owned socket only hands out nonces, and
*sudo hogtie exec* runs the action. (Stage 2, not built, would do both
over the socket.)

# A WALK THROUGH

```
$ n=$(hogtie nonce)
$ hogtie message "$n" restic-snapshots /srv/backup/a > msg
$ ssh-keygen -Y sign -f grant-cert.pub -n hogtie-v1 msg
$ r=$(hogtie response "$n" msg.sig)
$ sudo hogtie exec "$r" restic-snapshots /srv/backup/a
```

The nonce lives 30 seconds. *exec* claims it first, so it is gone after
one attempt, whether that attempt runs or is refused.

# COMMANDS

*nonce*
	Connect to the nonce socket (default */run/hogtie/nonce.sock*) and
	print the nonce, 64 lowercase hex digits. Any local account may ask;
	each account may hold at most 32 unused nonces, so a flood locks out
	only the account that floods. Exit 1 when refused.

*message* _NONCE_ _ACTION_ [_ARG_...]
	Write to standard output the exact bytes to sign, for the account
	running it (its real uid). See SIGNED MESSAGE.

*response* _NONCE_ _SIGFILE_
	Print the response word for *exec*: *v1.*_nonce_*.*_signature_, the
	signature being the binary sshsig of the armored _SIGFILE_ in standard
	base64. One word, no spaces.

*exec* _RESPONSE_ _ACTION_ [_ARG_...]
	Run through *sudo*. hogtie takes the caller's account from
	*SUDO_UID*, refuses without it, and refuses unless it runs as root.
	It checks, in order, failing closed at the first refusal: the
	response parses; the nonce is claimed from the caller's own account
	directory (from here on it is used up); it has not expired; the
	configuration is owned by root, writable by no one else, and parses;
	the action is declared; the message rebuilt from the nonce, the
	account, the action and the arguments encodes; the grant passes
	hogtie's own checks (see GRANTS); *ssh-keygen* and the action's
	program are files owned by root and writable by no one else (their
	directories are not checked); *ssh-keygen -Y verify* accepts the
	signature for the action; the arguments fit the action's typed
	parameters. It then appends the audit line and only then replaces
	itself with the action's program, with the declared environment and
	nothing else, in */*, its standard input, output and error being the
	action's.

	The response travels on the command line, where other processes of
	the same account can read it while hogtie runs. That is accepted:
	the nonce is single use, so a captured response is worthless once
	*exec* has claimed it.

*serve*
	Run the nonce socket, as root. It creates */run/hogtie* (mode 0711)
	and */run/hogtie/nonces* (0700) if missing, binds
	*/run/hogtie/nonce.sock* (0666) and serves one connection at a time.
	The client sends nothing; it reads one line, *ok* _nonce_ _expiry_ or
	*refused* _reason_. The caller's uid and pid come from the kernel
	(*SO_PEERCRED*), its cgroup from */proc/*_pid_*/cgroup*, read through a
	descriptor on */proc/*_pid_ so a recycled pid is not followed (the
	window between accept and that open remains). The cgroup and the unit
	in it (its last *.service* or *.scope*) are recorded, not enforced:
	a grant cannot name a unit in stage 1.

# SIGNED MESSAGE

SSH wire format: each *string* is a big-endian 32-bit length then its
bytes, so there is nothing to escape and no two requests share an
encoding.

```
string "hogtie-v1-exec"
string nonce          32 bytes
uint32 uid            the caller's account
string action         [a-z0-9][a-z0-9-]{0,62}
uint32 nargs          at most 32
string arg[i]         UTF-8, no NUL, at most 4096 bytes
```

hogtie never reads the message from the caller; *exec* rebuilds it from
the nonce it holds, the account *sudo* names and the arguments it was
given, so a signature over anything else does not verify. The two test
vectors (one argument, and none) are in *crates/hogtie/src/message.rs*.

The account is bound by root twice over: the socket files the nonce under
the asking uid, and *exec* looks only under *SUDO_UID*'s directory, so a
nonce asked by one account is unknown to every other; and the uid is in
the signed bytes, so the signer states which account it acts for.

# GRANTS

*ssh-keygen -Y verify* is run by its absolute configured path, with an
empty environment, in a fresh 0700 directory, against an allowed-signers
file of one line per configured CA:

```
* cert-authority,namespaces="hogtie-v1" <CA key>
```

and with *-I* _action_, so it checks the certificate names the action.
hogtie passes no *-O* option: *-O verify-time* would defeat expiry.
OpenSSH 10.5 refuses an expired, a not-yet-valid or a host certificate, a
principal the certificate does not hold and another CA, but accepts a
certificate with critical options. hogtie therefore also refuses, from
the parsed certificate, before running ssh-keygen:

- a namespace other than *hogtie-v1*, or a hash other than sha256/sha512;
- a signing key that is not a user certificate;
- a certificate signed by a key that is not a configured CA;
- any critical option at all;
- a principal holding a pattern character (*\** *?* *!* *,*), refused
  rather than honoured, though 10.5 matches principals literally;
- an action not exactly among the principals;
- a certificate outside its validity now, or valid for longer than
  *max_grant_seconds*.

The recipe *just explore-hogtie-sshsig-grant-edges* shows ssh-keygen's
own answers.

# CONFIGURATION

*/etc/hogtie/hogtie.toml*, owned by root and writable by no one else (on
NixOS a symlink into the store, checked after the link). Every key is
checked: an unknown key, a relative path or an unused parameter refuses
the whole file, and nothing runs.

```
ssh_keygen = "/nix/store/...-openssh/bin/ssh-keygen"
ca_keys = ["ecdsa-sha2-nistp256 AAAA..."]
max_grant_seconds = 2592000

[action.restic-snapshots]
program = "/nix/store/...-restic/bin/restic"
argv = ["snapshots", "--json", "--repo", "{repo}"]
env = { RESTIC_PASSWORD_FILE = "/run/secrets/restic" }
param = [{ name = "repo", kind = "choice", values = ["/srv/backup/a"] }]
```

*program* is an absolute path with no *.*, *..* or empty component.
*argv* follows it; *{*_name_*}* must be a whole element and every
parameter is used exactly once. *env* is the action's entire environment.
Parameters are positional and all required; their kinds:

*choice*
	One of *values*.

*pattern*
	Characters from *chars*, a class of printable ASCII such as
	*a-z0-9.\_-* (ranges and single characters; a *-* first or last is
	literal), at most *max_len* bytes, never starting with *-*, so no
	value is read as an option, and never only dots (*.* and *..*).
	Not a regular expression.

*path*
	An absolute path under *under* with no *.*, *..* or empty
	component, which must exist; it is passed on as its real path, which
	must still be under *under*'s real path. A symlink swapped in after
	that check is not caught (the action receives the resolved path).

There are no free-form arguments.

# AUDIT

Every *exec* appends one JSON line to */var/log/hogtie/audit.log* (root,
0600, synced): the time, the outcome and reason, the caller's uid, the
action and arguments, the nonce, who asked for it (pid, cgroup, unit,
when), the grant (key id, serial, principals, validity: only once
ssh-keygen has accepted the signature, so a copied certificate in a
forged signature is not logged as its owner's) and the argv. The outcome
is *started* (written just before the exec), *refused* (the caller's
request), *error* (hogtie's own failure) or, on a second line after a
*started* one whose exec returned, *exec-failed*. A line that cannot be
written refuses the action. The action's exit status is not recorded:
hogtie becomes the action.

# EXIT STATUS

*0* success (for *exec*, hogtie becomes the action, so its status is
the action's); *1* refused; *2* usage; *3* hogtie's own failure (not
root, configuration, a program that is not root's, the nonce store, the
scratch directory, running ssh-keygen, the audit log, the socket, an
exec that returned).

# FILES

*/etc/hogtie/hogtie.toml*, */run/hogtie/nonce.sock*,
*/run/hogtie/nonces/*_uid_*/*_nonce_, */run/hogtie/scratch/*,
*/var/log/hogtie/audit.log*.

# TESTING

The paths are compiled in; no flag or environment variable moves them.
Only a binary built with the cargo feature *test-harness* reads
*HOGTIE_TEST_ROOT* and accepts the test's own uid as root;
*just lint-hogtie* checks the shipped binary has neither.
*just test-rust-hogtie* runs every test, the binary ones included, with a
software CA and stock ssh-keygen.

# NOT YET

The NixOS module (the socket unit, the sudo rule, the configuration from
the host's declaration), revocation of a grant before it expires, an
in-process verifier, recording the action's exit status and binding the
caller's unit are not built. Linux only.

# SEE ALSO

*ssh-keygen*(1), *sudo*(8), *piggy-acts*(7)
