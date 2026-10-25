piggy-testing(7)

# NAME

piggy-testing - test harnesses, lanes and debugging conventions for piggy

# DESCRIPTION

piggy's tests span four tiers, from a pure unit test to a NixOS guest
booting the shipped closure. This page describes each harness, the
safety rules every lane must follow, and the failure modes that have
bitten before. *piggy-ci*(7) says which lanes the merge gate runs;
this page says how they work.

# TIERS

*Rust unit and integration tests*
	*just test-rust* (cargo). Card-touching integration tests run
	against fibby via *just test-rust-integration-fibby*; the in-process
	_CardEcdhOracle_ test also has a hardware mode gated on
	_PIGGY_TEST_CARD_GUID=<guid>_.

*bats over the harness card*
	_zz-tests_bats/t\*.bats_. The harness (_common.bash_) brings up a
	fibby virtual card per test (see *FIBBY*) and exports
	_PIGGY_TEST_RECIPIENT_, that card's slot-9D key, which
	*create_test_template* writes into the store's _piggy-ids_. Encrypt
	goes through the real _piggy-ids_ and decrypt is the in-process
	unlock against the card, so the lane exercises genuine wire format
	with no pcscd, agent or hardware. Only card *discovery* is mocked:
	_mock-piggy-ids.sh_ cans *detect-pubkey* / *detect-all-pubkeys*
	(driven by _PIGGY_TEST_DETECT_\*_) and _mock-pivy-tool.sh_ cans
	_pivy-tool list_. Additional per-test mocks (_mock-ssh-copy-id.sh_,
	_mock-cryptsetup.sh_, _mock-zfs.sh_) record argv and stdin to
	sentinel files for assertion. _t0980_ pins _PIGGY_TEST_RECIPIENT_
	against what the card reports.

*bats over fibby*
	_zz-tests_bats/conformance/\*.bats_ tagged _hardware_. fibby
	(_crates/fibby_) is a pure-Rust virtual PIV card speaking the
	pcsc-lite socket protocol; a recipe starts it on a private socket and
	points clients at it through _PCSCLITE_CSOCK_NAME_. Real card crypto,
	no hardware.

*NixOS VM lanes*
	_nix/vm-tests/_, exported as _checks.<system>.vm-piggy-{luks,zfs,agent}_
	and part of the gate. A guest runs the shipped *piggy* package with
	fibby and the Rust agent as systemd units, builds a store against the
	virtual card, then unlocks LUKS2 from a store secret, keys a ZFS
	dataset, and drives the multiplexed agent shapes against a real sshd.
	See *VM LANES*.

# BATS LANE BUILDER

_bats.nix_ wraps the *batsLane* builder from the bats flake. Two scan
roots: _zz-tests_bats/t\*.bats_ and _zz-tests_bats/conformance/\*.bats_
(_zz-tests_bats/explore/_ is deliberately not scanned). _# bats
file_tags=_ directives are auto-discovered, producing one _bats-<tag>_
derivation per tag plus _bats-default_, whose filter is _!hardware_: a
test needing a real pcscd (fibby or hardware) cannot run in the nix
sandbox and is invoked by a _just test-bats-conformance-\*-fibby_ recipe
instead. *nix build .#bats-default* is the authoritative sandboxed gate;
*just test-bats-conformance* is the ergonomic path for the non-hardware
conformance files (dual coverage is intentional, piggy#117).

Fast iteration on one file, outside the sandbox:

```
just test-bats-file zz-tests_bats/t0100-insert.bats
```

# FIBBY

*fibby --socket* _PATH_ *--backend virtual* [_seed-flags_...] serves one
or more virtual cards on a pcsc-lite socket. Seeds populate slots from
fixed test vectors (_--seed-rfc5903-slot-9d-cert_,
_--seed-rfc6979-slot-9a-cert_, …); _FIBBY_LOG=wire_ logs every APDU, and
the lines _GA ECDH 9D -> 9000_ / _GA ECDSA 9A -> 9000_ are what lanes
count to prove an operation reached the card.

Repeatable *--card* _NAME_ [_seed-flags_...] groups serve several cards on
one socket (piggy#242): each is its own reader with a distinct GUID
(_--seed-chuid-guid_ overrides; _--seed-pin_ sets a PIN;
_--seed-pin-retries N_ starts a card near lockout). *--control-socket*
_PATH_ opens a second socket and *fibby ctl --socket* _PATH_
*insert*|*remove*|*list* _READER_ toggles a card's presence at runtime,
which is how the agent's hot-swap lifecycle is exercised.
*fibby ctl --socket* _PATH_ *fault* _INS_|*\** _SW_[*x*_COUNT_] _READER_
queues an injected fault (piggy#284): the next _COUNT_ (default 1)
command APDUs with that instruction byte — *\** for any — answer _SW_
verbatim, with
no change to the card's own state, so a client's handling of 63Cx
(wrong PIN, x retries), 6983 (PIN blocked), 6982 (security status not
satisfied) or 6A82 (no such object) is asserted deterministically;
*fault clear* _READER_ drops the queue. fibby also implements the
reader-state wait so the agent's event-driven presence path runs
against it.

fibby stores the PIN and touch policy a key is generated or imported
with and enforces it (piggy#303). A slot whose touch policy is _always_
or _cached_ does not sign or do ECDH until the card is touched:
*fibby ctl --socket* _PATH_ *touch* _READER_ grants that card one touch,
which its next touch-requiring operation consumes. A _cached_ slot then
needs no further touch for 15 seconds; the window is per slot, and a
touch is never carried over to an _always_ slot. An operation whose input
is invalid fails before the touch gate, without waiting or spending a
touch. With no touch granted the operation waits
*--touch-timeout-ms* _MILLIS_ (default 15000) and then answers 6982; if
its client hangs up meanwhile the operation is abandoned untried, so it
never takes a touch meant for the next one.
*--auto-touch* grants every such operation at once, for lanes that are
not about touch. Both flags are global: they apply to every card the
fibby serves. The lines a lane can grep, written at every enabled
_FIBBY_LOG_ level and shown here for slot 9A, are _TOUCH needed 9A_ (the
operation is waiting, so this is when to deliver the touch), _TOUCH
granted 9A_, _TOUCH cached 9A_, _TOUCH auto-granted 9A_, _TOUCH
abandoned 9A_ and _TOUCH timeout 9A -> 6982_. *piggy card init* and *piggy card add-key* give 9A
and 9C a touch policy by default and sign each new certificate with the
new key, so a lane that provisions with the default policies must spawn
fibby with *--auto-touch* or deliver each touch. fibby attests only a
key generated on the card, and the attestation is where *piggy list*
reads a slot's _pin_policy_ and _touch_policy_ from: a seeded or
imported key reports neither.

fibby models two more things a real YubiKey does that client code must
not trip over (piggy#325). A _PIN-always_ key (9C by default) needs its
VERIFY immediately before the operation: any other command in between,
a certificate read included, answers the operation 6982, and the log
says _PIN-always: a command came between VERIFY and the sign_. And a
transaction ended with a reset disposition (as piggy-piv ends every
session that verified a PIN) resets the card for every client: no applet
stays selected and the PIN and management-key authentication are
cleared. *--require-select* makes fibby answer 6D00 while no applet is
selected, as the real card does.

Several clients share one fibby card the way pcscd shares a real one
(piggy#320): the card powers up for the first open handle and down when
the last one closes, so another client's connect or disconnect leaves the
applet selection and PIN state alone; a client whose connection drops
without SCardDisconnect has its handles closed for it. While one handle
holds the card's transaction, other handles' transmits and
SCardBeginTransaction are answered SCARD_E_SHARING_VIOLATION, which
libpcsclite retries for SCardBeginTransaction, so a running *piggy agent*
waits out a *piggy card init* instead of interleaving with it.

*--hardware-proxy* relays a real card and keeps the wire trace; that is
how APDU fixtures for new client code are captured.

The differential lanes that held the Rust port to C *pivy-tool* replay
C's recorded answers instead of running it (piggy#285, ahead of deleting
the C stack, piggy#289). A lane calls *pivy_oracle* _CASE_ _ARGS_...
(_lib/pivy_oracle.bash_), which answers with C's stdout and exit status
for those arguments from _fixtures/pivy-oracle/<lane>/CASE.{out,status}_
and fails the test when the fixture is missing; *assert_oracle_failure*
keeps a missing fixture from passing a test that expects C to fail.
*just codemod-capture-pivy-oracle-<lane>* re-records a lane from the
live C binary against the same fibby card, which works because fibby's
seeded keys and RFC 6979 signing make every recorded answer
reproducible: re-recording an unchanged lane changes no file.

fibby also runs INSIDE the sandboxed default lane (piggy#281, piggy#164):
the lane injects it as _FIBBY_BIN_, and _common.bash_ calls *fibby_up*
(default seed: the RFC 5903 slot-9D key, PIN 123456) for every test,
exporting _PCSCLITE_CSOCK_NAME_, _FIBBY_SOCK_, _FIBBY_LOG_ and the
control socket _FIBBY_CTL_ (so *fibby_ctl* _COMMAND_... — e.g.
*fibby_ctl fault 20 63C2*, *fibby_ctl remove* — drives that card), and
chains *fibby_down* onto the file's *teardown()* (or bats' default
no-op), so a file needs no teardown of its own. The harness
also points _SSH_ASKPASS_ at a *piggy_install_helper_as* copy of the test
askpass (the sandbox has no _/usr/bin/env_ for the helper's shebang, and
a failing askpass is indistinguishable from a card refusing the PIN) with
_PIGGY_TEST_FIB_PIN=123456_. Set _PIGGY_TEST_CARD=none_ before loading
_common.bash_ to opt out (the conformance harness does: those files
spawn their own fibby); a preset _PCSCLITE_CSOCK_NAME_ is left alone.
In the sandboxed lane (which sets _PIGGY_BATS_NO_HOST_PCSC_) a test left
with no card this way gets _PCSCLITE_CSOCK_NAME_ pointed at a socket that
does not exist, so a command that names no fibby of its own cannot reach
the host's pcscd and a real card plugged into it (piggy#305).
Outside the sandbox the harness card needs _target/debug/fibby_ (*just
build-rust*).

# PIN PROMPT SAFETY NET

Any recipe or test that can reach an agent unlock or a card PIN path
MUST set:

```
askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
export SSH_ASKPASS="$askpass" \\
       SSH_ASKPASS_REQUIRE=force \\
       DISPLAY="" \\
       PIGGY_TEST_FIB_PIN=123456   # only if auto-unlock is legitimately needed
```

Without these a failed unlock falls through to whatever *SSH_ASKPASS*
the operator's shell inherits — typically a GUI prompt indistinguishable
from a real one (this happened, piggy#35). The helper either supplies
the configured PIN non-interactively or refuses with a
_[piggy-test-askpass]_ stderr banner; it never prompts and never touches
_/dev/tty_. The VM lanes and the agent units in the guest carry the same
environment. The user-facing sibling is _contrib/piggy-askpass.sh_
(*piggy-agent*(1) PIN PROMPTS); *PIGGY_ASKPASS_DRY_RUN=1* smoke-tests it
without entering a PIN.

When a test builds an ebox template part, name it
_piggy-test:<short-context>_ so an escaped prompt's "token (partname)"
line is obviously a test.

# THROWAWAY CARD GUARD

Anything that writes to a real card — factory reset, key import,
set-admin, PIN/PUK changes, a PIN verify that could consume a retry —
must first pass _zz-tests_bats/helpers/piggy-throwaway-guard.sh_
(piggy#286): *--guid* _HEX_ [*--serial* _N_], or *--probe* to identify
the single inserted card through _pivy-tool list_, falling back to
*ykman list --serials* for the serial when the PIV applet reports none
and ykman is on PATH. In a bats lane, load
_lib/hardware.bash_ and call *require_throwaway_card* _GUID_ [_SERIAL_],
which fails the test loudly before any writing APDU.

The allowlists live in the operator's environment, never in the repo:

_PIGGY_TEST_THROWAWAY_SERIALS_
	Space-separated YubiKey serials.

_PIGGY_TEST_THROWAWAY_GUIDS_
	Space-separated CHUID GUIDs, for cards that report no serial (older
	YubiKey 4 firmware, piggy#256).

A card that reports a serial is judged by the serial alone, even if its
GUID is listed: a re-provisioned throwaway keeps its serial but rolls its
GUID, and a production card must never inherit a stale GUID entry. A
card with no serial is judged by GUID. With neither variable set every
card is refused. The recipes _debug-yk-throwaway-reset_,
_debug-yk-throwaway-import-rfc6979_ and _explore-rust-card-unlock-hw_
call the guard; the Phase 3 hardware lanes of the C-pivy retirement
(piggy#289) will too.

# PC/SC IN THE SANDBOX

A bats recipe whose tests talk to pcscd runs under batman with
*--allow-local-binding*, which the pcscd handshake needs. Recipes that
spawn fibby under _/tmp_ and run bats under the fence sandbox must also
pass *--expose-host-path-rw "$workdir"* (the shared justfile variable
_bats-expose-fibby-workdir_): fence 0.1.66 and later mounts a private
tmpfs over _/tmp_, hiding the host socket (piggy#253). The symptom of
either omission is "PC/SC system service/daemon not available" even
though _PCSCLITE_CSOCK_NAME_ reached the process.

batman 0.1.3 removed *--allow-unix-sockets*; passing it is forwarded to
bats-core and fails before any test runs ("Bad command line option",
"no plan line found").

pcsc-lite refcount-shields a co-resident reset: _SCardEndTransaction_
with _SCARD_RESET_CARD_ is deferred while another client holds the card
open and does not clear that client's PIN, so the verify-then-op
PIN-clearing race does not reproduce on this stack (piggy#56). Probe with
*just debug-lock-contention-probe* and *just debug-reset-loop*.

# VM LANES

The lanes are built on igloo's *pkgs.mkVmChecks* and *pkgs.vmTestPrelude*
(igloo FDR 0011, vm-tests(7)). _piggy-stack.nix_ is the guest module
(fibby and _piggy-agent_ units, parameterised by card seeds and agent
flags); _store-bootstrap.nix_ is the shared script prefix (units up,
store initialised against the card, one generated secret proven to
decrypt through the agent, journal-count helpers). Every decrypt and
sign is asserted against fibby's journal and the askpass banner.

Paved paths: *just test-vm-luks*, *test-vm-zfs*, *test-vm-agent*;
*just debug-vm-dry-run* _CHECK_ lists what a lane would build versus
fetch (the kernel-module cache-miss tripwire for the ZFS guest after a
pin bump). *nix flake check* boots them because they are _checks_.

They run under TCG: the shared build host has no _/dev/kvm_ and its
provider exposes no nested virtualisation. Two to three minutes per lane
once the guest closure is cached; do not judge a lane by wall time on a
loaded host — read the driver log (_nix log_ on the check's derivation).
Never launch several lanes by hand in parallel there.

*A command that reads standard input can hang a lane.* The test driver
sends its commands to a shell in the guest over _/dev/hvc0_, and every
command that shell runs inherits that device as its standard input. A
program that reads stdin by default competes with the shell for what the
driver sends next. _ssh_ does: without _-n_ the agent lane hung at an ssh
step in 2 of 28 runs, the guest idle and the driver waiting for an exit
status until the global timeout; with _-n_, 0 of 40 (piggy#296). Give
such a command _-n_ or _</dev/null_.

The agent lane carries a guest-side watchdog unit for this class of
hang. It is silent on a healthy run. When a command has been alive for
45 seconds, or the driver's shell has read nothing new for 45 seconds,
it writes what is running and what each process is blocked on to the
journal and console, so it reaches the build log (search for _HANG
WATCHDOG_). The lane's global timeout is 15 minutes. *just debug-vm-loop*
_CHECK_ _RUNS_ re-runs a lane and keeps a log per run, for catching an
intermittent failure.

*Coverage.* *just test-vm-coverage* re-runs the same lanes on an
instrumented piggy (_.#piggy-cov_, _.#vm-piggy-\*-cov_; each guest ships
its _.profraw_ files) and _.#coverage-report_ merges them with the
rustc-matched llvm tools into _report.txt_, _summary.json_ and
_lcov.info_. Packages, not checks; outside the gate. It counts only what
the VM lanes exercise, only piggy's crates, and not fibby.

# PLATFORM NOTES

*macOS: silent exit 126.* On some macOS hosts _/usr/bin/ps_ (or _tr_)
exits 126 under a stripped environment (_env -i …_) while _/bin_
binaries run fine (suspected hardened runtime, piggy#100). Under _set -e_
with _pipefail_ a decorative pipeline like _var="$(ps … | tr …)"_ then
exits the script silently with 126. Pin _|| true_ on such pipelines (with
a fallback value) or use absolute exec paths; piggy#92 is the precedent.

*darwin sandbox.* AF_UNIX bind is denied inside the darwin nix sandbox
and long tmpdir paths overrun the sun_path limit; tests that need a real
socket call _skip_unless_af_unix_bind_ (piggy#208).

# SEE ALSO

*piggy-ci*(7), *piggy-agent*(1), *piggy*(1), *fibby*(1) (in-tree help),
*batman*(1), *bats*(7)
