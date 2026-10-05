---
status: proposed
date: 2026-10-05
promotion-criteria: >
  proposed -> experimental when phase (a) has landed and all four hold:
  (1) on one host, a software ed25519 key added through the piggy agent
  socket lands in the stock ssh-agent upstream wired by the shipped
  home-manager option, and an sshsig made with it verifies under
  `ssh-keygen -Y verify`; (2) on one real card, the operator-act extension
  returns a 9C sshsig whose text was shown at the PIN prompt, and the same
  request naming 9A is refused; (3) part 1 of the wire RFC (operator-act
  extension, sshsig namespaces, markl-id purposes) exists; (4) spinclass
  FDR 0032 has been reconciled with the departures listed under
  "Departures from FDR 0032". experimental -> testing when phases (b) to
  (d) have landed and a NixOS VM lane mints a key over the agent
  extension, signs with it from the bound scope, is refused from a
  sibling scope, and observes the card wiped on scope exit, all under the
  hardened units.
---

# fibby as guarded key holder: agent seam, holder tiers, and the 9C operator-act key

> **Parent record:** spinclass FDR 0032, "Principals, handles, and
> provenance" (`docs/features/0032-principals-handles-and-provenance.md`
> in spinclass; status `proposed`, on branch `swift-elder`, not yet on
> `master`). This record was drafted against commit `777b3a8`; the
> spinclass session reports that commits up to `98782c7` revise it to
> match the departures listed below. This session has not read any of
> those commits and relies on that session's quotations. This record is downstream of
> FDR 0032. Where the two disagree, the disagreement is reconciled in
> FDR 0032 first. Tracking issue: piggy#297.

> **Evidence standard.** Every statement about existing code below was
> read at piggy commit `be3da3f`. Nothing was built, run, or measured for
> this record. Statements that are inference rather than reading are
> marked as such.

## Problem Statement

spinclass FDR 0032 makes piggy the owner of **keys**: the SSH-agent seam
that every other tool signs through, the tiers of key holder behind that
seam, and the hardware key that anchors operator acts. Its rule is that
spinclass, troupe and clown never touch private key bytes; they ask an
agent to sign and get an sshsig back. For that rule to mean something,
the thing behind the agent has to be worth trusting, and today the
software options are not:

- `fibby`, piggy's pure-Rust virtual PIV card, is a test double. Slot
  keys are plain `[u8; 32]` struct fields
  (`crates/fibby/src/virtual_card.rs:270-298`). Keys arrive as hex on the
  command line. Both of its sockets are created mode `0777` with no peer
  check (`crates/fibby/src/server.rs:141`, `:181`). Its wire log dumps
  PIN bytes. Cards are fixed at start. It has no ed25519, no touch
  policy, and answers attestation with `6A80`.
- The Rust `piggy agent` caches the card PIN as a `Zeroizing<String>`
  (`crates/piggy/src/cmd/agent/pins.rs:37`) and nothing more. The C
  `pivy-agent` it replaced locked its memory and kept the PIN on a page
  between guard pages (see "Reference: what C pivy-agent did"). No
  `mlock`, `madvise`, `mprotect`, `prctl` or `setrlimit` call exists
  anywhere under `crates/`.
- Operator acts (a root certificate, an escalation grant) need a key
  whose every use is a deliberate human act, and a way to show the
  operator the text being signed that a same-uid process cannot
  subvert. piggy has neither: `piggy card init` provisions only 9A and
  9D with card-default policies (`crates/piggy/src/card/init_cmd.rs:51`),
  and nothing binds a displayed text to the bytes a card signs.

The operator's stated goal is that fibby becomes "a proper and safe
in-memory keystore (with guard pages and flagged not to be core-dumped,
etc -- like the original pivy)", run "via special systemd units that
provide further guards", and that it is the key holder FDR 0032 calls
for. A second consumer, madder, wants a blob-store key held outside its
own process.

## Interface

### The seam

All keys sit behind an SSH agent socket. Callers send agent requests and
receive signatures; signatures over records are sshsig blobs; the key
type for principals is ed25519 at every tier. Plain `ssh-keygen -Y` and
git's `gpg.format = ssh` must be able to drive ordinary signing over the
same socket. Three new piggy-private agent extensions are added by this
record (working names; the RFC fixes the final ones):

| Extension (working name) | Phase | Does |
|---|---|---|
| `operator-act@piggy` | (a) | builds an sshsig over a supplied text, shows that text at PIN time, signs with a PIN-always and touch-always slot |
| `mint@piggy` | (d) | asks the holder service for a new key; returns its public key |
| `retire@piggy` | (d) | destroys a key the caller owns |

### Tiers

FDR 0032 has two tiers as revised at `3d52e6f`. Its earlier text listed
three, with the service as tier 2 and fibby inside it as tier 3; this
record's design is what collapsed them, and "tier 2" below always means
the collapsed tier:

- **Tier 1: software key in a stock ssh-agent upstream.** troupe
  generates an ed25519 key per principal and adds it with an ordinary
  add-identity request to the one piggy agent socket. The piggy agent
  holds no key bytes (piggy#215); it routes the add to a designated
  upstream. The home-manager module gains an option that runs a stock
  OpenSSH `ssh-agent` beside the piggy agent and passes
  `--upstream NAME=PATH --add-new-keys-to NAME`. The VM lane
  `nix/vm-tests/agent.nix` already exercises that routing. On darwin the
  launchd agent plays the upstream role. The property is only what FDR
  0032 states for tier 1: the key is not in a file.
- **Tier 2: the holder service.** A separate-uid service whose only key
  store is fibby, one virtual card per principal. There is no interim
  service that keeps keys anywhere else.

### The holder: fibby as a virtual PIV card

fibby stays a pcsc-lite protocol server, and a card agent treats each
virtual card as a real card. This reuses what already exists: the agent
and `piggy-piv` carry Ed25519 PIV slots end to end
(`crates/piggy-piv/src/slot.rs:11`, `cert.rs:105-110`,
`crates/piggy/src/cmd/agent/session.rs:974`, `:1088`), and `piggy-piv`
already models YubiKey PIN and touch policy
(`crates/piggy-piv/src/policy.rs`). Only fibby lacks the curve. That the
agent's Ed25519 path works against a card is an inference: no card, real
or virtual, has exercised it.

What fibby gains, in the holder build:

- **ed25519** (PIV algorithm `0xE0`) for generate and sign, implemented
  with `ed25519-dalek` directly. `curve25519-dalek` 4.1.3,
  `ed25519-dalek` 2.2.0 and `x25519-dalek` 2.0.1 are already in the
  workspace `Cargo.lock`. No primitive is hand-written, and age's code
  is not vendored: age builds on these same crates and has no ed25519
  signing construction of its own to borrow.
- **Keys generated inside, never exported in plaintext.** A key comes to
  exist by generation inside fibby and dies with the process. No
  private key crosses any socket in either direction. A holder restart
  wipes every key; sessions mint again.
- **Guarded memory** for every key, PIN and management key (next
  section).
- **Runtime card lifecycle.** New control-socket verbs create a card
  (generating its key and a self-signed certificate inside fibby, so the
  agent's certificate-based slot discovery at
  `crates/piggy-piv/src/token.rs:354-371` finds it) and destroy a card
  (wipe, then remove). Minting is **one virtual card per principal**.
- **Per-key policy.** A card's key carries a YubiKey-style PIN policy
  and touch policy, reported through the metadata and attestation
  commands that `piggy-piv` already parses.
- **Attestation.** fibby generates its own attestation key at start, in
  guarded memory, and answers the YubiKey attest command for keys it
  generated, embedding their policies. The agent's existing
  `ykpiv-attest@joyent.com` extension then works for virtual keys
  unchanged. A verifier can tell a holder-held key from a file key.
- **Socket permissions.** fibby's socket is reachable by the holder
  agent's account only. fibby does no caller attribution of its own;
  per-key enforcement inside fibby is deferred by operator decision.

### Guarded memory

A new in-house workspace crate (working name `piggy-guard`), written on
`libc` or `rustix`, with all `unsafe` confined to it. For each secret it
provides an allocation that is:

- on its own pages, between two inaccessible guard pages;
- locked against swap;
- excluded from core dumps (`MADV_DONTDUMP` where defined);
- wiped in a forked child (`MADV_WIPEONFORK` where defined);
- zeroized on drop;
- **inaccessible at rest**, and made readable only for the duration of
  one operation, in the manner of libsodium's guarded allocations.

At process start, consumers also mark the process non-dumpable and set
the core size limit to zero.

Two consumers adopt it: fibby (keys, PINs, management keys, the
attestation key), and the `piggy agent` PIN cache. The agent adopts it
first, in phase (b), which restores what the Rust agent lost relative to
the C agent and gives the primitive a low-risk consumer before the
holder depends on it.

### The holder service

Two system units under two accounts, shipped by a new native NixOS
module (working name `services.piggy-holder`; the existing
`nixosModules` only re-export the home-manager modules,
`nix/nixos/piggy-agent.nix`):

- **fibby** runs alone under its own account and holds the keys.
- **the holder agent** (`piggy agent` in a new holder mode) runs under
  the service account FDR 0032 names, is the only account allowed on
  fibby's socket, parses every request from sessions, and does all
  caller binding. FDR 0032's "records and keys share one service
  account" maps to this account.

Both units are hardened: core dumps off, no new privileges, read-only
system view, private devices and tmp, address families restricted to
`AF_UNIX`, a syscall filter that still admits the memory-locking calls,
a locked-memory limit sized for the card cap, an empty capability set,
and no swap for the fibby unit. The exact directive list is fixed in
phase (d) against what the units actually need.

The VM lanes already run this shape without hardening: fibby under
`DynamicUser`, a card agent under a `piggy-agent` system user, and a
`--proxy-only` front (`nix/vm-tests/piggy-stack.nix:53-108`,
`nix/vm-tests/agent.nix:58-93`).

**Minting.** A session sends `mint@piggy` on the holder agent's socket.
The agent reads the caller's peer credentials and cgroup on that
connection, asks fibby to create a card, records the binding, and
returns the public key. A sign request for that key is honoured only
from the bound scope. Mints beyond the card cap are refused, with an
error the caller can tell apart from every other mint failure: FDR 0032
turns that refusal into a refused session start that names the cap, and
never into a fallback to a tier-1 key.

**Teardown.** A card is wiped when its bound cgroup disappears or when
the owner sends `retire@piggy`, whichever comes first. The holder has no
lifetime timer: validity lives in FDR 0032's certificates.

**PIN policy.** Minted keys carry PIN policy `never`. The agent, which
today demands a PIN for every slot except 9E
(`crates/piggy/src/cmd/agent/session.rs:398`), learns to honour a slot's
reported policy. Real cards behave as before. No PIN secret exists for a
minted key; the gates are the socket permission, the caller binding and
the touch policy.

**Touch policy.** A key minted with a touch policy blocks in fibby until
approved. fibby raises a touch-needed event; the holder agent forwards
it to an **approver** program running in the operator's session, which
shows the key, the principal and the requesting scope and returns
approve or deny. The agent accepts an approver only from a frontend
scope, checked by cgroup exactly as callers are, so a process in an
agent scope cannot approve itself. The approval step is an interface
with more than one possible method: approval by a signature from the
operator's real card is kept open as a stricter method.

### Operator acts and the 9C key

`operator-act@piggy` takes a text and an sshsig namespace. The agent
that is next to the card builds the sshsig itself, shows that exact text
on the PIN prompt through the existing askpass path
(`crates/piggy/src/card_oracle.rs:352`, which already carries a context
string to `contrib/piggy-askpass.sh`), and signs. It refuses any slot
whose attested policy is not PIN-always and touch-always, so 9A can
never serve an operator act. Because the displaying component is the
hashing component, what the operator sees is what is signed, and because
it is an agent extension it also works from a remote host over a
forwarded agent (FDR 0001's proxy-only front forwards card extensions).
A `piggy` CLI verb is a thin client of the extension.

This replaces FDR 0032's sketch of a runtime sidecar rendered beside an
ordinary sign request, where nothing ties the shown text to the signed
bytes.

Card provisioning changes to make 9C usable:

- `piggy card init` gains per-slot PIN and touch policy flags, and on a
  fresh card provisions 9A as PIN `once` and touch `cached`, and 9C as
  PIN `always` and touch `always`, by default.
- A separate, explicit command adds 9C to an existing card. Regenerating
  9A (a new SSH key) stays a deliberate operator choice. **9D is never
  regenerated**; doing so would make the store unreadable.
- `piggy health` reports each slot's attested policy and flags a card
  that cannot serve operator acts.
- A new verb exports the 9C attestation chain so it can be published
  beside the public key as the trust anchor FDR 0032 D11 requires.

papi's enrollment flow is papi's; these are the piggy primitives it
calls.

### Keeping test conveniences out of the holder

Everything that makes fibby a good test double is dangerous in a holder:
command-line key seeding, the fixed RFC test vectors, key import, fault
injection, the hardware proxy, and wire logging. All of it moves behind
one cargo feature. The packaged holder is built without the feature, so
the code is absent from the binary. The test lanes use a second nix
output built with it. A lint in the merge gate, modelled on
`checks.lint-closure-no-pivy`, fails if the holder binary contains a
test flag, and fibby reports its build profile so the holder unit can
refuse the wrong binary.

### Phases

| Phase | Content | Serves |
|---|---|---|
| (a) | tier 1 home-manager wiring; `operator-act@piggy` and its CLI client; card-init policy flags, 9A/9C defaults, health policy report, attestation export; RFC part 1 | spinclass slice 1 |
| (b) | guarded-memory crate; agent PIN cache adopts it; process non-dumpable | parity with the retired C agent |
| (c) | fibby holder build: test lockout, ed25519, guarded keys, policies and metadata, attestation key, runtime card create and destroy | the holder |
| (d) | holder agent mode: `mint@piggy`, `retire@piggy`, caller binding, teardown, agent honours PIN policy; native NixOS module with hardened units; VM lane; RFC part 2 | tier 2 |
| (e) | touch approver in a frontend scope; pluggable approval interface | tier 2's approval prompt |
| (f) | 9C blesses the holder's attestation key once per holder start; approval by real card | hardware-anchored provenance |
| (g) | X25519 key agreement in fibby and in the agent's ECDH extension, opened by a throughput measurement; sealed durable keys | madder |

Deleting `vendor/pivy` (epic #289 phase 5) is independent of all of
this. The C behaviour worth keeping is recorded at the end of this
document so the code can go.

### Wire formats

This record says what each interface must do and who calls it. One
normative piggy RFC fixes the byte-level formats: part 1 with phase (a)
(the operator-act extension, the sshsig namespaces, and the markl-id
purposes FDR 0032 D7 assigns to piggy), part 2 with phase (d) (mint,
retire, and fibby's control verbs).

## Examples

All names below are working names, shown to make the shape concrete.

Tier 1, in home-manager:

    services.piggy-agent = {
      enable = true;
      allCards = true;
      softwareKeys.enable = true;   # runs a stock ssh-agent, designates it for adds
    };

troupe then adds a principal key against the one piggy socket, and plain
tools sign with it:

    $ ssh-add -q principal-key          # routed to the software upstream
    $ ssh-keygen -Y sign -f principal-key.pub -U -n <namespace> record
    $ ssh-keygen -Y verify -f signers -I <principal> -n <namespace> -s record.sig < record

An operator act, from any host that reaches the card's agent:

    $ piggy operator-sign --namespace <namespace> < grant.txt > grant.sig

    ┌ piggy: operator act ───────────────────────────────┐
    │ You are signing, with slot 9C:                     │
    │   grant session "swift-elder" on <host> for 24h    │
    │ PIN for card 5da19c98:                             │
    └────────────────────────────────────────────────────┘
    (then touch the key)

    $ piggy operator-sign --slot 9a --namespace <namespace> < grant.txt
    piggy: slot 9A is not an operator-act slot (PIN once, touch cached)

The holder service on a NixOS host:

    services.piggy-holder.enable = true;

A session minting and using a holder key (phase (d)), by request:

    mint@piggy                      -> ssh-ed25519 AAAA… holder:<card>
    sign (from the bound scope)     -> signature
    sign (from a sibling scope)     -> refused
    scope exits                     -> card wiped; key gone from the listing

## Departures from FDR 0032

This design departed from FDR 0032 as it stood at `777b3a8` in the four
ways below, plus a fifth found while reconciling. The spinclass session
reports that the operator confirmed each in that session and that FDR
0032 at `98782c7` (unmerged) now records them. That is a report, not
something this session read.

1. **The service and fibby are one tier.** The service is never built
   without fibby, so the separate-uid property arrives only after phases
   (b) to (d). Reported outcome: FDR 0032 D3 now has two tiers, and what
   was tier 3 is tier 2.
2. **Operator-act text is bound by an agent extension**, not by a
   sidecar beside an ordinary sign request. Callers send text, not a
   pre-built sshsig. Reported outcome: D10 and D11 adopt the extension
   for the root certificate, the quote fallback and escalation grants.
3. **A holder key does not survive leaving its scope.** A
   `clown --resume` that lands in a new systemd scope gets a new key and
   needs a new certificate. Reported outcome: D1 says the principal
   survives a resume but its tier-2 key does not; D4 becomes one record
   per principal and key; a resumed principal's certificate is reissued
   by its parent, "or for a root by one more 9C touch". A resumed root
   therefore costs the operator a PIN and a touch.
4. **A 16-principal cap per holder instance** exists in the first
   phases. The operator session key counts against it. Reported outcome:
   recorded in FDR 0032 as a limitation, described as a first-phase
   number that is expected to change and that nothing there depends on.
   D3 adds that a refused mint refuses the session start or spawn,
   "with an error naming the cap: nothing runs at lower assurance, and
   there is no fallback to a tier-1 key or to an uncertified session".
5. **Two accounts, not one.** FDR 0032 D14 had the record store and the
   signer "share one service account". Here fibby runs under a second
   account of its own. Reported outcome: D14 now says the shared account
   is the holder agent's, that fibby runs as a second unit under its own
   account, and that the holder agent's account is the only one allowed
   on fibby's socket.

## Limitations

- **Linux (NixOS) only for the holder.** Two causes. fibby is reached
  through `PCSCLITE_CSOCK_NAME`, which only `libpcsclite` honours;
  macOS's `PCSC.framework` ignores it
  (`docs/plans/2026-06-06-fibby-darwin-feasibility.md`, piggy#156). And
  the service's caller binding is defined in terms of systemd scopes and
  cgroups. macOS hosts get tier 1 only. Examining darwin support, with
  its caveats, is future work the operator has asked for.
- **16 live cards per fibby instance.** The pcsc-lite protocol fibby
  mirrors has a fixed table of 16 readers
  (`crates/fibby/src/proto.rs:376`). Whether a larger table can be
  negotiated was not verified. The lift is the agent speaking fibby's
  protocol directly instead of through the platform PC/SC library, which
  is also the seam darwin support would need.
- **One PC/SC endpoint per agent process.** A host with a real YubiKey
  and a holder runs a card agent for each, joined by a proxy-only front
  (the FDR 0001 shape).
- **A holder restart loses every key.** By design in these phases.
  Durable keys are phase (g).
- **Same-uid escape is not solved at tier 1**, as FDR 0032 itself
  states. A tier-1 key can be used by any process running as the
  operator.
- **The approver's protection rests on clown's scope split.** If a
  process can enter a frontend scope, it can approve. Approval by real
  card is the answer when that is not good enough.
- **Guarded memory does not cover transient copies.** The dalek crates
  expand and use key material in ordinary stack and heap memory during
  an operation. The guarantee is for the key at rest.
- **Holder attestation is host-trust until phase (f).** Before 9C
  blesses the attestation key, the claim "this key lives in the holder"
  is only as good as trusting the host.
- **fibby does not enforce who may use which key.** Anything with the
  holder agent's account can use every key. Deferred by decision.
- **piggy stays EC and 25519 only.** No RSA in the holder.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| live cards per fibby instance | 16, mints beyond are refused; a first-phase number the operator expects to change | the pcsc-lite reader table; no transport work needed to ship | a mint is refused in normal use, or FDR 0032 slice 3 (subagents become principals) is scheduled; then build the direct agent-to-fibby transport |
| guarded-memory backing | anonymous locked pages | available everywhere the holder runs | a decision to defend against root reading process memory; then add `memfd_secret` with fallback |
| holder key lifetime | none; scope exit or retire only | validity lives in the certificate chain; a second clock can disagree with it | cards observed outliving their sessions, or a leaked binding found in use |
| minted-key PIN policy | `never` | only the service account reaches fibby; a PIN would be a second secret in the same account | in-fibby per-key enforcement is taken up |
| approval method | approver program in a frontend scope | no hardware touch per approval | a consumer whose approvals must survive a compromised operator uid; then approval by real card |
| holder attestation trust | unblessed per-start key | no PIN and touch at every holder start | a verifier outside the host starts relying on the tier of a key; then phase (f) |
| madder key agreement path | per-operation through agent and card | unmeasured; simplest | the phase (g) measurement misses its stated target; then a batch or session-key operation |

## Open questions

- **Which scope does a minted key bind to?** FDR 0032 D7 places
  troupe's connection owner in a frontend scope, while the signers of a
  principal's key include processes in the agent scope (git commit
  signing, clown's hooks). If troupe sends the mint, the peer on that
  connection is not the scope that will sign. The mint request probably
  has to name a target scope, with a rule for who may mint for it. The
  spinclass session reports the operator's answer as "Leave open for
  now", until clown#244 defines the two scopes. The mint extension's
  wire format must not assume an answer; this blocks RFC part 2, not
  phases (a) to (c).
- **How is a cgroup classified as frontend or agent scope?** No naming
  rule or unit property exists yet; FDR 0032 assigns it to clown#244.
  Phases (d) and (e) depend on it.
- **Does `ssh-agent-lib` 0.5 expose the peer socket?** The agent hands
  `listen` a cloneable session today
  (`crates/piggy/src/cmd/agent/mod.rs:596`). Reading peer credentials
  needs a per-connection hook. Believed available, not read.
- **How is the peer's cgroup read without a pid-reuse race?** A pidfd
  from the socket is the likely answer on recent kernels. Not verified.
- **Does the agent's Ed25519 PIV path work end to end?** Phase (c) is
  its first test.
- **Per-operation latency through agent and fibby.** Unmeasured. Today
  the agent takes one global card lock, reconnects and re-verifies per
  operation (`session.rs:398-436`); fibby runs one thread per connection
  with a lock per card (`crates/fibby/src/server.rs:35`, `:156`).
- **Does any FDR 0032 consumer need a touch-policy key in its first
  version?** The spinclass session found none; phase (e) is
  forward-looking until one appears.

## Decisions taken with the operator (2026-10-05)

Recorded so the reasoning is not re-litigated. Quotation marks are the
operator's words.

| # | Question | Decision |
|---|---|---|
| - | ed25519 in fibby | yes, so the key type is the same at every tier |
| - | holder caller binding | socket permissions only; in-fibby permissions later |
| - | reuse age's code | left to this record: "whichever you believe to be more secure and robust"; dalek crates directly |
| - | holder layer | fibby as a PIV card behind the agent |
| - | record shape | one FDR, phased |
| 1 | platform | Linux only; "in the future I would like to examine how hard darwin support would be" |
| 2 | key origin | generated inside; and "fibby should be able to generate a pigpen document + cyphertext key that becomes durable, and fibby could accept a pigpen doc and cyphertext key to boostrap as well (all of that being later classes)" |
| 3 | where the service keeps keys before fibby is ready | nowhere: collapse the service and fibby into one tier |
| 4 | mint mapping | card per principal, 16-card cap accepted |
| 5 | mint request | agent extension |
| 6 | teardown | scope exit or retire |
| 7 | guard level | sealed at rest "to start, maybe" `memfd_secret` "in the future" |
| 8 | guard home | new crate; fibby and the agent both adopt it |
| 9 | virtual PIN | PIN never; the agent honours policy |
| 10 | touch prompt | approver in a frontend scope, "but I want to keep the door open for" approval by real card |
| 11 | attestation | holder attests; 9C blessing later |
| 12 | test lockout | compile-time feature |
| 13 | unit layout | two units, two accounts |
| 14 | tier 1 agent | stock ssh-agent upstream |
| 15 | operator act | agent extension |
| 16 | 9A/9C defaults | new card-init defaults plus health report |
| 17 | madder | later phase, measure first |
| 18 | sequencing | (a) to (g) in order; #289 independent |
| 19 | wire specs | this FDR now, one RFC written per phase |

## Reference: what C pivy-agent did

`vendor/pivy` is scheduled for deletion (epic #289 phase 5). This is the
memory-hardening behaviour the guarded-memory crate is modelled on, read
at `be3da3f`.

- **Whole-process lock.** `mlockall(MCL_CURRENT | MCL_FUTURE)` at agent
  start; failure only logs a warning that the PIN may be swapped
  (`vendor/pivy/src/pivy-agent.c:5491-5497`).
- **PIN on a guarded page.** Three pages from one anonymous private
  `mmap`; `MADV_DONTDUMP` over all three where defined; the first and
  third made `PROT_NONE`; the PIN lives at the start of the middle page
  and is cleared with `explicit_bzero` (`pivy-agent.c:5499-5515`). The
  PIN buffer is 16 bytes (`pivy-agent.c:164`). The page stays readable
  for the life of the process: C pivy did not seal at rest.
- **Concealed heap allocations.** `set_no_dump` applies
  `MADV_DONTDUMP`, `MADV_NOCORE` (each where defined) and `mlock` to a
  region; `malloc_conceal` and `calloc_conceal` wrap it; `freezero`
  clears before freeing (`vendor/pivy/src/utils.c:44-82`).
- **Not present in C pivy:** no `prctl(PR_SET_DUMPABLE)`, no
  `setrlimit(RLIMIT_CORE)`, no wipe-on-fork, no `memfd_secret`, no peer
  credential check on the agent socket. (Reported by a search of
  `vendor/pivy/src`; the absence was not independently re-checked line
  by line.)
- **Touch and confirm.** A `send_touch_notify` hook
  (`pivy-agent.c:1386`) and a confirm mode
  (`C_NEVER`/`C_CONNECTION`/`C_FORWARDED`, `pivy-agent.c:178`). The Rust
  replacement for confirm is tracked as piggy#283.

## More Information

- spinclass FDR 0032, decisions D3 (tiers), D7 (piggy owns keys), D10
  (operator session key), D11 (9C), D17 (commit signing over the seam).
- piggy#297, the tracking issue for this record.
- FDR 0001 (proxy-only agent) and FDR 0002 (multi-card hot-swap agent):
  the agent shapes the holder reuses.
- RFC 0008 (pigpen), section 4.4: the X25519 wrap that phase (g)'s
  sealed keys follow.
- piggy#215 (the agent holds no key bytes), piggy#283 (agent confirm),
  piggy#11 (X25519 ECDH in the agent, closed as untestable; phase (g)
  removes the blocker), piggy#156 (fibby on darwin), piggy#135 (fibby as
  a complete PIV replacement), epic #289 (retire C pivy).
- `docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md`: fibby's
  original design as a test tool.
- piggy-agent(1), piggy-testing(7) section FIBBY, piggy-piv-slots(7).
