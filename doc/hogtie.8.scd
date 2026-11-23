hogtie(8)

# NAME

hogtie - one door to root for agent sessions, opened by an operator-signed grant

# SYNOPSIS

*hogtie nonce* [*--socket* _PATH_]++
*hogtie message* _HOST_ _NONCE_ _ACTION_ [_ARG_...]++
*hogtie response* _NONCE_ _SIGFILE_++
*sudo hogtie exec* _RESPONSE_ _ACTION_ [_ARG_...]++
*hogtie serve*++
*hogtie --version*

# DESCRIPTION

*hogtie* gives a host one way for an agent session to run something as
root: a fixed, declared *action*, with typed arguments, when the caller
proves it holds a key that an operator-signed *grant* names that action
for, on this host. There is no other path and no exemption: a read-only
action gets a long-lived grant, never a free pass. It is a crude bridge
to a later system (ajour); there are no intermediates.

A *grant* is an OpenSSH user certificate signed by the host's SSH
certificate authority (in production the operator's card, slot 83; in
tests a software CA). Each of its *principals* is _host_*:*_action_, an
action it allows on a host it names, and its validity is the grant's
lifetime. A grant for several hosts holds several principals; there is
no wildcard host. The caller proves possession by making an *sshsig*
(*ssh-keygen -Y sign*) with the certified key, in namespace *hogtie-v1*,
over one canonical message that binds the host, a fresh, single-use
*nonce*, the caller's account, the action and its arguments.

This is stage 1: a root-owned socket only hands out nonces, and
*sudo hogtie exec* runs the action. (Stage 2, not built, would do both
over the socket.)

# A WALK THROUGH

```
$ n=$(hogtie nonce)
$ hogtie message flic "$n" restic-snapshots /srv/backup/a > msg
$ ssh-keygen -Y sign -f grant-cert.pub -n hogtie-v1 msg
$ r=$(hogtie response "$n" msg.sig)
$ sudo hogtie exec "$r" restic-snapshots /srv/backup/a
```

The grant here holds the principal *flic:restic-snapshots*. The nonce
lives 30 seconds. *exec* claims it first, so it is gone after one
attempt, whether that attempt runs or is refused.

# COMMANDS

*nonce*
	Connect to the nonce socket (default */run/hogtie/nonce.sock*) and
	print the nonce, 64 lowercase hex digits. Any local account may ask;
	each account may hold at most 32 unused nonces, so a flood locks out
	only the account that floods. Exit 1 when refused.

*message* _HOST_ _NONCE_ _ACTION_ [_ARG_...]
	Write to standard output the exact bytes to sign for _HOST_, for the
	account running it (its real uid). See SIGNED MESSAGE.

*response* _NONCE_ _SIGFILE_
	Print the response word for *exec*: *v1.*_nonce_*.*_signature_, the
	signature being the binary sshsig of the armored _SIGFILE_ in standard
	base64. One word, no spaces.

*exec* _RESPONSE_ _ACTION_ [_ARG_...]
	Run through *sudo*. hogtie takes the caller's account from
	*SUDO_UID*, refuses without it, and refuses unless it runs as root.
	An _ACTION_ that is not an action name (it is never echoed), more
	than 32 arguments, or one longer than 4096 bytes, is refused first.
	Then, in order, failing closed at the first refusal: the response
	parses; */run/hogtie* and its nonce store are root's directories with
	the modes *serve* gives them; the nonce is claimed from the caller's own account
	directory (from here on it is used up); it has not expired; the
	configuration is owned by root, writable by no one else, and parses;
	the action is declared; the message rebuilt from this host's
	configured name, the nonce, the account, the action and the arguments
	encodes; the grant passes hogtie's own checks (see GRANTS);
	*ssh-keygen* and the action's program are files owned by root and
	writable by no one else (their directories are not checked, nor a
	script's interpreter); *ssh-keygen -Y verify* accepts the signature
	for _host_*:*_action_; the arguments fit the action's typed
	parameters. It then appends the audit line and only then replaces
	itself with the action's program.

	The action starts with the declared environment and nothing else, in
	*/*, with umask 022, every signal at its default disposition and none
	blocked, no descriptor but standard input, output and error (which are
	the caller's), fixed resource limits (the kernel's defaults for root,
	with open files 1024 soft and 524288 hard), nice 0, the default
	scheduler, every CPU, oom_score_adj 0 and the default I/O priority.
	Any of these that cannot be set refuses the exec. Left as inherited,
	deliberately: the controlling terminal, the session and process group,
	the cgroup, namespaces, the seccomp filter and the no_new_privs bit.

	Before it opens any file, hogtie sets its own resource limits to the
	same fixed table and its own scheduling (nice, scheduler, CPUs,
	oom_score_adj, I/O priority) to the defaults above, so a caller cannot
	make it run out of descriptors, memory or file size, or starve it while
	it holds a lock, and so cause an error; the action inherits that state.
	Every reset must succeed as root; the client verbs (*nonce*, *message*,
	*response*), run as the caller, skip any reset the caller lacks the
	privilege for (going back to nice 0 from a positive nice, say).
	It ignores SIGXFSZ (a write
	past the file size limit fails instead); and ignores SIGTSTP, SIGTTIN
	and SIGTTOU, so a caller cannot stop it through sudo's signal
	relaying. A line the file size limit would cut is refused before it is
	written. From before the request is evaluated until its outcome is
	logged, and for a run until execve, every signal that can be blocked
	is, so a caller cannot kill hogtie through sudo after seeing how far it
	got; the action starts with none blocked. A clock that cannot be read
	refuses.

	The response travels on the command line, where other processes of
	the same account can read it while hogtie runs. That is accepted:
	the nonce is single use, so a captured response is worthless once
	*exec* has claimed it.

*serve*
	Run the nonce socket, as root. It makes */run/hogtie* (mode 0711),
	*/run/hogtie/nonces*, */run/hogtie/scratch* and
	*/run/hogtie/refusals* (0700), refuses to start unless */run/hogtie*
	is on a tmpfs (a reboot must empty the nonce store), binds
	*/run/hogtie/nonce.sock* (0666, replacing whatever is there) and
	serves one connection at a time. The client sends nothing; it reads
	one line, *ok* _nonce_ _seconds-left_ or *refused* _reason_. An
	account may be issued at most 60 nonces a minute and hold at most 32
	unused. The
	caller's uid and pid come from the kernel (*SO_PEERCRED*), its cgroup
	from */proc/*_pid_*/cgroup*, read through a descriptor on
	*/proc/*_pid_ so a recycled pid is not followed (the window between
	accept and that open remains). The cgroup and the unit in it (its last
	*.service* or *.scope*) are recorded, not enforced: a grant cannot
	name a unit in stage 1. Every 30 seconds it sweeps expired nonces,
	account directories left empty and scratch directories older than 5
	minutes, and writes one *summary* line for every account whose minute
	has closed with refusals that were not logged; one unreadable account
	does not stop the sweep.

# SIGNED MESSAGE

SSH wire format: each *string* is a big-endian 32-bit length then its
bytes, so there is nothing to escape and no two requests share an
encoding.

```
string "hogtie-v1-exec"
string host           [a-z0-9][a-z0-9-]{0,62}, the host it is for
string nonce          32 bytes
uint32 uid            the caller's account
string action         [a-z0-9][a-z0-9-]{0,62}
uint32 nargs          at most 32
string arg[i]         UTF-8, no NUL, at most 4096 bytes
```

hogtie never reads the message from the caller; *exec* rebuilds it from
its own configured host name, the nonce it holds, the account *sudo*
names and the arguments it was given, so a signature over anything else,
a message signed for another host included, does not verify. The two test
vectors (one argument, and none) are in *crates/hogtie/src/message.rs*.

The account is bound by root twice over: the socket files the nonce under
the asking uid, and *exec* looks only under *SUDO_UID*'s directory, so a
nonce asked by one account is unknown to every other; and the uid is in
the signed bytes, so the signer states which account it acts for. A
grant itself names no account.

A nonce's life is counted on the boot clock (*CLOCK_BOOTTIME*), which
nobody can set back; the nonce store is in */run*, emptied by a reboot. A
grant's validity is wall time, as every OpenSSH certificate's is: a wall
clock set back can bring an expired grant back to life, which only root
can do.

# GRANTS

*ssh-keygen -Y verify* is run by its absolute configured path, with an
empty environment, in a fresh 0700 directory (reading the message from a
file, writing to files), against an allowed-signers file of one line per
configured CA:

```
* cert-authority,namespaces="hogtie-v1" <CA key>
```

and with *-I* _host_*:*_action_, so it checks the certificate names the
action on this host. It is killed after 10 seconds. hogtie passes no *-O*
option: *-O verify-time* would defeat expiry. OpenSSH 10.5 refuses an
expired, a not-yet-valid or a host certificate, a principal the
certificate does not hold and another CA, but accepts a certificate with
critical options. hogtie therefore also refuses, from the parsed
certificate, before running ssh-keygen:

- a namespace other than *hogtie-v1*, or a hash other than sha256/sha512;
- a signing key that is not a user certificate;
- a certificate signed by a key that is not a configured CA;
- any critical option at all;
- a principal holding a pattern character (*\** *?* *!* *,*), refused
  rather than honoured, though 10.5 matches principals literally;
- an action not named for this host exactly, as _host_*:*_action_; a bare
  _action_ (unpinned) and _other_*:*_action_ (another host) are refused
  with their own reasons;
- a certificate outside its validity now, or valid for longer than
  *max_grant_seconds*.

The configured CA keys must be *ssh-ed25519* or *ecdsa-sha2-nistp256*,
*-nistp384* or *-nistp521*; an *ssh-rsa* (which may verify with SHA-1) or
DSA key refuses the configuration. The recipe
*just explore-hogtie-sshsig-grant-edges* shows ssh-keygen's own answers.

# CONFIGURATION

*/etc/hogtie/hogtie.toml*, owned by root and writable by no one else (on
NixOS a symlink into the store, checked after the link). Every key is
checked: an unknown key, a relative path or an unused parameter refuses
the whole file, and nothing runs.

```
host = "flic"
ssh_keygen = "/nix/store/...-openssh/bin/ssh-keygen"
ca_keys = ["ecdsa-sha2-nistp256 AAAA..."]
max_grant_seconds = 2592000

[action.restic-snapshots]
program = "/nix/store/...-restic/bin/restic"
argv = ["snapshots", "--json", "--repo", "{repo}"]
env = { RESTIC_PASSWORD_FILE = "/run/secrets/restic" }
param = [{ name = "repo", kind = "choice", values = ["/srv/backup/a"] }]
```

*host* is this host's name as grants name it, from the host's declared
configuration, not from *gethostname*(2) (which any root process, or a
UTS namespace, can change). *program* is an absolute path with no *.*,
*..* or empty component. *argv* follows it; *{*_name_*}* must be a whole
element and every parameter is used exactly once. *env* is the action's
entire environment. Parameters are positional and all required; their
kinds:

*choice*
	One of *values*. Paths are declared this way.

*pattern*
	Characters from *chars*, a class of printable ASCII such as
	*a-z0-9.\_-*: single characters and ranges that are lowercase to
	lowercase, uppercase to uppercase or digit to digit; any other *x-y*
	is refused as ambiguous, so a literal *-* goes first or last; */* is
	refused, a value is never a path. A value is at most *max_len* bytes,
	never starts with *-* (it would be read as an option) and is never
	only dots. Not a regular expression.

There is no *path* kind in stage 1: a path checked and then used by name
can be swapped under the check by anyone who can write a directory on its
way; such a parameter refuses the configuration. There are no free-form
arguments.

# AUDIT

Every *exec* appends one JSON line to */var/log/hogtie/audit.log* (root,
0600, synced), never longer than 4096 bytes. It takes no lock (a stopped
lock holder would block every account): it is one *write*(2) of the whole
line on a file opened *O_APPEND*, and what is relied on is Linux's
behaviour, not POSIX's: a write to a regular file holds the inode lock
for its whole length, so two lines never interleave (POSIX promises only
that each write starts at the end). A line holds the time, the outcome
and reason, the caller's uid, the action and arguments (for a run, the
argv that ran, once), the nonce, who asked for it (pid, cgroup, unit, and
when, on the boot clock), the grant (key id, serial, principals, validity:
only once ssh-keygen has accepted the signature, so a copied certificate
in a forged signature is not logged as its owner's) and a note. The
outcome is *started* (written just before the exec), *refused* (the
caller's request), *error* (hogtie's own failure), *exec-failed* (a second
line after a *started* one whose exec returned) or *summary* (the budget,
below). A *started* line is always whole: a run whose line would not fit
is refused. Any other line too long is cut: every string to 256 bytes and
every list to 32 items, with markers, or, still too long, to a short
record marked *"truncated":true*. A line that cannot be written whole
refuses the action. The action's exit status is not recorded: hogtie
becomes the action.

Anyone the sudo rule admits can be refused at will, so refusals and
errors alike are budgeted per account: 20 per minute (on the boot clock)
are logged in full and the 21st line says the rest are counted, not
logged. Past the budget, for the rest of the minute, the account gets one
fixed answer (*over the refusal budget*, exit 1) and its request is not
evaluated at all, so no two requests can be told apart; the count is
written as a *summary* line by the first of the next minute's lines or by
*serve*'s sweep, whichever comes first. The counts are kept in
*/run/hogtie/refusals*, one fixed-width record per account, rewritten in
place, opened without following links and locked for at most a second. A
count that cannot be read (its lock held past that second, its file cut
short or garbled) is over budget: the fixed answer, nothing evaluated.
A count of unlogged refusals is cleared only once the line reporting it is
written. Runs are always logged.

# DEPLOYMENT

The sudo rule must name the *exec* verb, so that sudo admits
*hogtie exec* and nothing else: *serve*, run as root, removes and binds
the socket path, and the rule must not let a caller do that. All
directories hogtie uses are made with an exact mode, or, when they exist,
must be real directories owned by root with no permission beyond it.

What follows is from reading sudo(8) and sudoers(5) (1.9.17). Each point
says whether circus's NixOS VM test has also seen it under a real sudo
(SEEN) or not (READ, NOT RUN).

What sudo does with the caller's state:

- Resource limits: sudo sets the target user's limits through the
  system's mechanism (on Linux, *pam_limits*); where there is none, the
  command runs with the invoking user's limits, except the core size,
  which sudo sets to 0. *rlimit_\** options in sudoers override this.
  hogtie does not rely on either: it sets its own limits and the action's.
  SEEN: the action had exactly hogtie's table, also for a caller with
  low *ulimit -f*, *-c* and *-t* (which of sudo's rules applied cannot be
  told from that). READ, NOT RUN: *rlimit_\** overrides.
- Signals: sudo relays the signals it receives to the command, SIGINT and
  SIGQUIT only when the command runs in a new pty or a user process sent
  them; SIGSTOP and SIGKILL are not relayed. The caller owns the sudo
  process, so it can have SIGTSTP relayed to hogtie: hogtie ignores it.
  The command runs as root, so the caller should not be able to signal it
  directly (the kernel requires the sender to share the target's real or
  saved uid). SEEN: a SIGINT to the caller's sudo ended the root action;
  the caller's *pkill -INT* against the running action signalled nothing
  (refused or not matched was not told apart). READ, NOT RUN: SIGQUIT,
  SIGSTOP, SIGKILL.
- *use_pty* runs the command in a new pty when sudo has a terminal, and
  then relays SIGINT and SIGQUIT too. hogtie does not need a terminal.
  SEEN: with a terminal the action had its own pts as controlling
  terminal and stdin; without one, no terminal and its own session; its
  output piped by the caller through sudo's pty arrived whole.
- The action's state, SEEN: no signal pending, blocked, ignored or
  caught; an empty environment whatever the caller set; descriptors 0, 1
  and 2 only; cwd /; umask 022; nice 0, also for a niced caller.

READ, NOT RUN: the audit log on a full disk.

The rule this calls for, for the next sprint's module (_agents_ and the
path are placeholders):

```
Defaults!/run/current-system/sw/bin/hogtie env_reset, use_pty
%agents ALL=(root) NOPASSWD: /run/current-system/sw/bin/hogtie exec *
```

sudo matches the command by the path the caller gives it, not by what a
symlink points to: a rule naming the binary's store path is matched only
when the caller runs that full path, and *sudo hogtie* found through
PATH (the profile's symlink) asks for a password (seen in the circus VM
test). Name the path callers use. SEEN: the rule refuses *serve* and an
account outside the rule's group.

*exec \** admits nothing else: *exec* takes only the response, the action
and its arguments, no flag, and its paths are compiled in. *env_reset* is
sudo's default and is named for the record; hogtie clears the environment
itself. *use_pty* (sudo's default too) gives the root action its own
session and terminal: without it the command sits in the caller's
foreground process group, so the kernel delivers keyboard SIGINT and
SIGQUIT to it directly and it shares the caller's terminal.

*serve* tells systemd it is ready: when *NOTIFY_SOCKET* is set (a path,
or an abstract name with a leading *@*), it sends *READY=1* there once
every directory check has passed and the socket is bound, and sends
nothing when it refuses to start (exit 3); a failed send is exit 3 too.
It removes *NOTIFY_SOCKET* from its environment first. So the unit is
*Type=notify* with *NotifyAccess=main*, and a refused start fails it.

# EXIT STATUS

*0* success (for *exec*, hogtie becomes the action, so its status is
the action's); *1* refused; *2* usage; *3* hogtie's own failure (not
root, configuration, a program that is not root's, a directory that is
not right, the nonce store, the scratch directory, running ssh-keygen or
its timeout, the audit log, the socket, an exec that returned); *4* the
audit log now ends in a partial line (a write cut short whose ending
newline could not be written either: only a full disk or an I/O error
does that; the next line will start mid-line until someone repairs it).

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
software CA and stock ssh-keygen. *just explore-hogtie-mutants* breaks
each refusal on purpose (*crates/hogtie/testdata/mutants.tsv*) and checks
a test goes red.

# KNOWN LIMITS

Low findings of the last review, tracked in piggy#406:

- A refusal past the budget gate whose count cannot then be saved is
  logged but not counted.
- Two execs racing on an account's first budget file: the second can see
  the file before its creator writes it and count the account over budget
  for one window.
- A refusal at the gate because the budget cannot be read leaves no audit
  line and no count.
- The socket's sweep and an exec can both report the same count of
  unlogged refusals.
- A rewrite of the budget record cut short over an older one can read as
  a valid mixed record; at worst a window resets early.

# NOT YET

The NixOS module (the socket unit, the sudo rule, the configuration from
the host's declaration), revocation of a grant before it expires, an
in-process verifier, recording the action's exit status, binding the
grant to an account or the caller's unit, a *path* kind that cannot be
swapped (*openat2* *RESOLVE_BENEATH* under a held descriptor) are not
built. Linux only; a kernel without *close_range*(2) refuses every exec.

# SEE ALSO

*ssh-keygen*(1), *sudo*(8), *piggy-acts*(7)
