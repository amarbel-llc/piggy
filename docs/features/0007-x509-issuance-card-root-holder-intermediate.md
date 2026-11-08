---
status: proposed
date: 2026-11-08
promotion-criteria: >
  proposed -> experimental when the operator has approved this record and
  phase (i) has landed: `piggy-piv` builds the root, intermediate and leaf
  profiles below, and a bats lane proves with openssl that a leaf for the
  permitted names verifies under the root, that a leaf for any other name
  is rejected, and that a leaf for a foreign name under an unconstrained
  intermediate is rejected too. experimental -> testing when phase (ii)
  replaces openssl in the pilot's renewal: `piggy ca issue` has issued a
  leaf from a CSR against a profile, refused a CSR naming a foreign name,
  and the leaf served `nix flake update` through the proxy once. Every
  phase closes with a human pass (FDR 0006, "Phase acceptance").
---

# X.509 issuance: a card-held root, a holder-held intermediate, and name-constrained leaves

> **Status of this draft.** Written on the operator's ruling of
> 2026-11-08 (relayed by the coordinator, circus/eager-holly) as a
> docs-only design for the operator's review. Not approved; nothing is
> built. The pilot on the cascade host (a card-held CA signing one leaf
> by hand) proceeds without this record and without fibby on its
> critical path.

> **Parent records.** FDR 0006 (fibby as guarded key holder; the holder,
> the frontend and agent scopes, the unit bindings) and RFC 0012 (operator
> acts; the `piggy-certificate-v1` namespace). The first consumer is
> circus's update-time intercepting proxy, read from
> `docs/plans/2026-11-08-shithub-proxy-design.md` in the
> `circus/still-cedar` worktree on 2026-11-08 (not yet on circus master
> when read). Tracking: piggy#297 for the holder; this record has no
> issue of its own yet.

> **Evidence standard.** Every statement about existing code was read at
> piggy master `399afad`. Nothing was built, run or measured. Labels:
> **V** read in a named file; **I** inference; **U** unknown; **R** an
> operator ruling of 2026-11-08 relayed by the coordinator, not heard by
> this session.

## Problem Statement

circus wants `nix flake update` on the cascade host to fetch GitHub
inputs through its own proxy. nix's client then has to accept a TLS
certificate for `github.com`, `api.github.com` and `codeload.github.com`
issued under a private CA that only that one child process trusts (per
process, through `NIX_SSL_CERT_FILE`; never the system store). A spike
showed nix honours a CA with `nameConstraints` and rejects other names
under it (circus plan, O). The operator ruled that the CA key is held or
sealed by fibby/piggy and that the proxy host holds only short-lived
leaves, renewed every few hours or days without the card (R).

piggy has none of this today. `crates/piggy-piv/src/cert_builder.rs`
builds a self-signed certificate (fixed serial 1, fixed validity 2024 to
2074, one `CN`, `extensions: None`) and a PKCS#10 request (one `CN`, no
requested extensions), both for P-256 or P-384 only; Ed25519 is rejected
(V). No function issues a certificate for another party's key. The
holder that would hold an unattended key does not exist: no `mint@piggy`,
`retire@piggy`, holder agent mode or peer-credential code exists under
`crates/` (V, a search on 2026-11-08 found none), so FDR 0006 phases (c)
onward are at most partly built, and a holder restart wipes every key by
design (V, FDR 0006 "The holder" and "Teardown"). This record designs the
missing pieces so that the trust anchor is hardware, the unattended key
is short-lived and bounded, and no caller can widen the names.

## Interface

### The chain

    card root (long-lived; trust anchor)
      -> holder intermediate (days; dies with the holder or its unit)
          -> leaf on the proxy host (hours to days)

What the consumer trusts is the root certificate only. The intermediate
and the leaf rotate. The pilot (R) has no intermediate: the root signs
one leaf directly, by hand, about every 30 days.

### Certificate profiles

Three fixed profiles. For `root-cert` the key is the card slot's; for
`sign` and `issue` the caller supplies a CSR and nothing else about the
certificate comes from the caller. Key types are P-256 (signature
`ecdsa-with-SHA256`) and P-384 (`ecdsa-with-SHA384`), the two
`cert_builder.rs` already encodes (V).

| Field | Root | Intermediate | Leaf |
|---|---|---|---|
| subject | one `CN`, operator's choice | one `CN`, the profile's | `CN` = first permitted name |
| issuer | itself | the root | the intermediate (pilot: the root) |
| basicConstraints | critical, `CA:TRUE`, `pathlen:1` (R, 2026-11-08: one root serves the pilot's leaf now and the intermediate later) | critical, `CA:TRUE`, `pathlen:0` | critical, `CA:FALSE` |
| keyUsage | critical, `keyCertSign`, `cRLSign` | critical, `keyCertSign`, `cRLSign` | critical, `digitalSignature` |
| extendedKeyUsage | absent | absent | `serverAuth` |
| subjectAltName | absent | absent | `DNS:` each permitted name, exactly the profile's set |
| nameConstraints | critical; permitted `DNS:` each permitted name; excluded `IP:0.0.0.0/0.0.0.0` and `IP:::/0` | identical to the root's | absent |
| validity | years (lever) | days (lever) | hours to days (lever; pilot R: ~30 days); never past the issuer's `notAfter` |
| serial | random, at least 64 bits, positive | same | same |
| subjectKeyIdentifier / authorityKeyIdentifier | SKI; AKI = own SKI | SKI; AKI = root's SKI | SKI; AKI = issuer's SKI |
| `notBefore` | now minus a skew (lever) | same | same |

Three readings of RFC 5280 that shape the table (I; the RFC was not
read in this session):

- A `DNS:` name constraint permits the name **and every name under
  it**, so `permitted;DNS:github.com` alone already admits
  `api.github.com`, `codeload.github.com` and any other
  `*.github.com`. Name constraints cannot say "exactly these three". The
  exactness the operator asked for lives in the leaf's `subjectAltName`
  and in the issuance check below; the constraint is the backstop that
  keeps a bad leaf from ever naming a foreign domain.
- Constraints apply only to the name forms they mention. A leaf carrying
  an `IP:` SAN would be unconstrained by a DNS-only constraint, hence the
  excluded IP ranges.
- A verifier **intersects** the constraints it meets down the path; an
  issuer cannot be stopped from writing a wider constraint into an
  intermediate, but a leaf for a foreign name under such an intermediate
  still fails against the root's constraint. That is the property the
  lane tests.

**The backstop rests on OpenSSL, not on RFC 5280.** RFC 5280 §6.1 takes
the trust anchor as an input and does not process the anchor's own
extensions; OpenSSL (and so nix's curl) enforces a trust anchor's
`nameConstraints` and `pathlen` anyway, which is what the spike observed
(circus plan, O). Phase (i)'s lane pins that behaviour, including the
excluded-IP encoding and the intermediate case the spike did not cover.

**`pathlen` (ruled).** An earlier ruling had the pilot root at
`pathlen:0`, which would have let it sign leaves only and forced a new
trust anchor when the intermediate arrived (circus flagged this). On
2026-11-08 the operator ruled `pathlen:1` (R): the one root serves the
pilot's leaf now and the holder-held intermediate later. circus's
runbook owner (circus/still-cedar) was told the same day.

### Keys, policies and bindings

- **Root key: on a card, PIN always, touch always.** Every root
  signature (the root certificate itself; each intermediate; in the
  pilot, each leaf) is a deliberate human act at the card. The key is
  generated on the card and never exported (V: `piggy tool generate`
  generates in-slot, `crates/piggy/src/cmd/tool/mod.rs`). The attestation
  of the slot is the evidence of its policy, read with `piggy tool
  attest`, never assumed. One consequence (V, RFC 0012 §2.4: "any slot
  whose attested policy satisfies §2.4 MAY serve an operator act"): a
  root key with this policy also qualifies to sign operator acts if a
  card agent lists it. Keeping it out of the operator-act path, or
  accepting the overlap, is an open question below.
- **Intermediate key: in the holder, PIN never, touch never, bound to a
  service unit.** This is the unattended key. Its only gates are the
  holder socket's permission, the caller binding, and the issuance
  verb's profile check. Its certificate is short-lived so that a
  restart and a compromise are both bounded by a `notAfter` the card
  set. The binding is to the issuance service's systemd unit, not to a
  session scope; the key is wiped when that unit's cgroup disappears,
  which is FDR 0006's teardown rule applied to a unit. A restart of the
  holder **or** of the issuance unit (a rebuild switch included) ends
  the intermediate.
- **Leaf key.** circus's plan has it generated on the proxy host and
  never leaving it (circus plan, I, theirs). piggy's part is only that
  issuance never needs the leaf's private key: a CSR comes in, a
  certificate goes out.

**Why not FDR 0006's durable sealed-key class.** FDR 0006 names the
sealed durable keys of its phase (g) as the candidate tier for a
service principal's key (V, "Open questions"). The intermediate here is
short-lived by design, so durability would save one card tap per
restart and nothing else, while an ephemeral unit-bound key keeps the
holder's "no key survives its binding" rule intact. The sealed class
stays the candidate for keys that must outlive a restart; this record
does not need one. The operator may prefer it anyway (open question).

**What FDR 0006's service-principal question needs** (FDR 0006 "Open
questions", "Which tier does a service principal's key need?"; this is
the first concrete case):

1. A mint that names its **target binding** as a unit's cgroup rather
   than the caller's own scope, with a rule for who may mint for a unit.
   The candidate rule: the holder's NixOS module mints at the issuance
   unit's start, under the holder agent's account, from a declared list
   of unit-bound keys; no session can mint for a unit.
2. A third peer class beside frontend and agent: **service**. A system
   unit is neither the operator's keyboard nor an agent runtime. The
   classifier FDR 0006 leaves to clown#244 has to name it, and a service
   peer may sign with its own bound key and nothing else (no approve, no
   mint for another scope, no operator act).
3. **No PIN and no touch** on the bound key, by declaration, so the unit
   runs unattended; the mint records that choice in the key's metadata
   so `piggy health` can report it.
4. A **re-mint on restart** that is visible: when the issuance unit or
   the holder restarts, the intermediate is gone, the unit's health
   reports "no intermediate", and the next root signature is the
   operator's, at the card. Nothing re-blesses silently.

### Slot for the root key on the operator's card

The pilot wants the CA key on the operator's existing card, in a slot
that cannot collide with 9A (SSH authentication), 9C (operator acts) or
9D (the store key, never regenerated) (V, FDR 0006 and
`crates/piggy/src/card/slot_policy.rs`).

| Slot | Role today | Verdict |
|---|---|---|
| 9E | Card Authentication Key: PIN-never by design, and `piggy agent -K` signs a challenge with it on every card probe without a PIN (V `crates/piggy/src/cmd/agent/cak.rs:1-54`); the agent skips the PIN for 9E in its sign paths (V `session.rs:423`) | **not a CA slot**: a PIN-always key there breaks the CAK check and inverts the slot's role |
| 82h to 95h (retired key management) | NIST's archive of rotated 9D keys; a YubiKey generates into them and attests them like any slot (V piggy-piv-slots(7)); `piggy-piv` reads their certificates (V `token.rs:372`); `piggy tool sign`, `pubkey`, `cert` and `attest` accept them (V `slot_arg` -> `is_valid_piv_slot`); `piggy tool generate`, `write-cert`, `req-cert`, `import` and `delete-cert` **refuse** them today (V `is_supported_cert_slot`, `mod.rs:357`, and the parse guard at `mod.rs:311-319`), and C `pivy-tool` is no longer in the runtime closure (V AGENTS.md) | **ruled: slot 82 (`retired-1`)** (R, 2026-11-08). The operator called the refusal self-imposed and ruled it lifted for retired slots, 82 at least (implementation item I1 below); until that lands only outside tooling can generate into it and write its certificate, and in every case `piggy tool attest 82` must show PIN always, touch always before the key is trusted |
| a second, dedicated YubiKey | its 9C, PIN always, touch always; kept offline | the cleanest separation, at the cost of a card; needs no piggy change |

Two cautions on a retired slot: piggy-piv-slots(7) warns that a
**generic PKCS#11 backend** may not honour differing policies between 9D
and a retired slot (V; the caution is about middleware, and so bites
route 1 below), so the hand pass reads the slot's attestation, which is
the card's own statement; and an agent that lists retired-slot keys as
SSH identities adds to sshd's `MaxAuthTries` count (same page). Whether
the Rust agent offers them as identities is **U** (its certificate walk
reads them, `token.rs:372`; the offer was not read). The same manpage's
sentence that "no piggy code today reads from or writes to the retired
slots" predates that walk and is stale (V both).

### How the pilot reaches the card today

The pilot signs with openssl on the operator's machine (R). piggy
offers no PKCS#11 module and no X.509 signing verb (V: `pkcs11` appears
only in FDR 0004's survey and the slot manpage; `piggy tool sign` emits a
raw ECDSA DER signature over SHA-256 or SHA-384 of stdin, `mod.rs:585`).
Routes, none of them piggy's today:

1. **PKCS#11** through Yubico's `ykcs11` or OpenSC with openssl's
   provider, the route FDR 0004 found viable for slot 9D. Standard, but
   whether the module is on the operator's host is **U**, and the
   manpage's middleware caution applies.
2. **`piggy tool sign 82 < tbs.der`** plus a script that assembles the
   certificate from the TBS and the returned signature. Possible, with
   two conditions: `cmd_sign` reads the slot's certificate first
   (V `mod.rs:601`), so slot 82 must already hold one, which until phase
   (i) only outside tooling can write; and no piggy verb does the
   assembly (V).
3. **Phase (i) and (ii) verbs** below, which make both unnecessary.

### The issuance verbs (working names)

    piggy ca root-cert --profile NAME                     > root.pem
    piggy ca sign      --profile NAME < intermediate.csr  > intermediate.pem
    piggy ca issue     --profile NAME < leaf.csr          > chain.pem

A **profile** is a file the operator installs (a NixOS module option,
working name `services.piggy-ca.profiles.<name>`, or a TOML file under
piggy's config directory). Its fields have two authors: the **consumer**
writes the policy fields (profile kind: root, intermediate or leaf; the
permitted names as an exact set; the key types accepted; the lifetime;
the EKU), and the **operator** fills the issuer fields at install time
(a card slot and GUID, or a holder key by public key). The profile is
the only source of the issuer: `root-cert` takes no slot flag.

`issue` and `sign`:

1. parse the CSR and require an EC P-256 or P-384 key and a valid
   self-signature;
2. check the names: for a **leaf** profile, the CSR's `CN` and any
   requested SANs must be a subset of the profile's set, and the leaf is
   issued with **the profile's full set** as its SAN, not the request's;
   for an **intermediate** profile, the CSR's `CN` must equal the
   profile's `CN` and no SAN is requested or issued;
3. copy **no** requested extension; every extension comes from the
   profile table above;
4. draw a random serial, set `notBefore` to now minus the skew and
   `notAfter` to the earlier of now plus the profile's lifetime and the
   issuer certificate's `notAfter`;
5. sign with the issuer key: a card through `PinSession` on the local
   host (PIN, then touch), a holder key through the holder agent's
   socket;
6. record one audit line per issuance: profile, serial, the issued
   certificate's and the CSR's digests as markl-ids, and `notAfter`; to
   the journal under systemd, otherwise to an append-only file in
   piggy's state directory;
7. print the issued certificate, followed by the issuer's certificate
   when the issuer is an intermediate (the chain the proxy serves),
   never the root. In the pilot the output is the leaf alone.

Refusals are answers, each with its own exit code so a renewal timer can
tell them apart (working values): 2 usage; 3 profile unknown or
unreadable; 4 CSR malformed or key type refused; 5 names outside the
profile; 6 issuer key unavailable (card absent, holder has no
intermediate); 7 rate limited (state: one timestamp file per profile in
piggy's state directory); 1 other. A refusal issues nothing.

**Who owns names and lifetime.** piggy **enforces**; the profile
**declares**; the consumer **authors** the policy fields. circus writes
the profile text for its proxy (the three names, the lifetime it wants)
and the operator installs it on the signer host; the verb refuses
anything the profile does not say. The root's `nameConstraints` are
defence in depth, and in the hand-signed pilot they are the only
mechanical enforcement.

**Reaching the card from elsewhere.** Phase (ii) signs through a local
card only. Signing through a forwarded piggy agent is not offered: an
ordinary agent sign request over TBS bytes would show the operator a
routine PIN prompt with nothing of the certificate on it, the very gap
RFC 0012 closes for operator acts. If remote root signing is ever
wanted, it is a dedicated agent extension that displays what is being
certified, not the routine path. An intermediate CSR is public data and
travels to the operator's machine as a file.

### Transport and placement

Not decided here (U). Two constraints are piggy's, the rest is circus's
and the operator's: the root never leaves the card, so root operations
happen where the operator and the card are; and FDR 0006 ties the
holder to Linux system units, so the intermediate stage can only run
where a holder runs. Which transport carries a CSR to the signer and
how the proxy host schedules renewals are the consumer's; this record
only requires that a renewal needs no card. Candidate transports, for
the record and without preference: an ssh forced command on the signer
host running `piggy ca issue --profile NAME` with the CSR on stdin; a
tailnet HTTP endpoint (a new service, not piggy's); PAPI.

### Phases

| Phase | Content | Serves |
|---|---|---|
| (i) | `piggy-piv` profile builders (root, intermediate, leaf) over the existing signer-closure shape; the bats lane with openssl, including the negative name and IP cases and the unconstrained-intermediate case; item I1 (retired slots in `piggy tool`) if it has not landed ahead of the phase | the pilot's slot; the certificate shapes |
| (ii) | `piggy ca root-cert`, `sign`, `issue` for a **card-held** issuer, with profiles; replaces openssl in the pilot's renewal | the pilot's renewal |
| (iii) | the holder intermediate: a unit-bound mint (FDR 0006 (d)), `sign` of the intermediate by the card, `issue` with the holder key; health reports the intermediate | unattended renewal |
| (iv) | the issuance service unit in the NixOS module; whatever part of the transport the operator rules is piggy's, if any | the proxy host's renewal |

Every phase closes with the human pass FDR 0006 requires.

## Examples

Hand-signed pilot, once a slot is chosen (sketch; untested; the openssl
side is circus's runbook). `piggy tool` takes its options before the op
(V `mod.rs:155-221`):

    # on the operator's machine, card in; generate needs the management
    # key (-K) and a PIN for the self-signed slot certificate
    piggy tool -K default -a eccp256 -i always -t always generate 82
    piggy tool attest 82          # the policy, as the card states it
    # root certificate: today through openssl + PKCS#11 (route 1), or
    # `piggy ca root-cert --profile shithub-github` after phase (ii)

    # on the proxy host: leaf key and CSR, key never leaves
    # on the operator's machine: sign the leaf under the root (pilot), or
    piggy ca issue --profile shithub-github < leaf.csr > leaf.pem

    # checks, no network
    openssl verify -CAfile root.pem leaf.pem
    openssl x509 -in root.pem -noout -text | grep -A3 'Name Constraints'
    # a leaf for example.org under the same root must fail to verify
    # with an intermediate in play: openssl verify -CAfile root.pem \
    #   -untrusted intermediate.pem leaf.pem

The renewal flow once the holder exists (phase (iii) onward):

    proxy host:        new leaf key -> CSR -> transport -> signer
    signer:            piggy ca issue --profile shithub-github
                         (holder intermediate; no PIN, no touch)
                       -> chain.pem back
    proxy host:        reloads the leaf; its renewal cadence is its own
    holder or unit restart:
                       intermediate gone; health says so;
                       operator: piggy ca sign (card, PIN, touch) once

## Limitations

- **No revocation.** No CRL, no OCSP, no AIA. The leaf's and the
  intermediate's short lifetimes are the backstop; a compromised root is
  retired by replacing the root certificate in the consumer's repository
  (per-process trust means there is no system store to clean).
- **Any restart of the holder or the issuance unit costs the operator a
  card tap** to reissue the intermediate. Until FDR 0006 phases (c) and
  (d) land there is no holder at all, which is why the pilot is
  hand-signed.
- **Linux (NixOS) only** for the intermediate stage, as for the holder.
- **P-256 and P-384 only.** `cert_builder.rs` rejects Ed25519 (V), and
  an Ed25519 CA is untested against nix's curl (circus plan, "Not
  shown").
- **Name constraints cannot express "exactly these names"**; the leaf's
  SAN and the profile do.
- **Retired slots are unsupported by piggy's own tool today** for
  generate, write-cert, req-cert, import and delete-cert (V); ruled
  lifted, item I1.
- **Root signing is local to the card.** No forwarded-agent path, by
  design (see "Reaching the card from elsewhere").
- **Nothing here is an operator act.** X.509 signatures are ordinary
  card or holder signatures, not `operator-act@piggy` sshsigs; RFC 0012's
  display guarantee does not cover them. Whether a root signature should
  also be recorded as a `piggy-certificate-v1` act is an open question.
- **The intermediate's binding** depends on FDR 0006's unresolved
  service-principal question (what it needs is stated above) and on
  clown#244's scope classifier.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| leaf lifetime | pilot: ~30 days by hand (R); target: hours to a few days | bounds a proxy-host compromise; a renewal timer makes short cheap | a renewal fails because the signer was down longer than a lifetime |
| intermediate lifetime | days (proposed 7) | bounds a holder-key compromise; a restart already forces a reissue | the operator is tapping for intermediates more than for anything else |
| root validity | years (operator's choice) | the trust anchor is redistributed by a reviewed commit, which is cheap | a `pathlen` or name change is wanted sooner |
| root `pathlen` | 1 (R) | one root for both stages | a deeper chain is ever wanted |
| serial entropy | at least 64 random bits | collision-free and opaque | none expected |
| `notBefore` skew | 5 minutes | clock drift between signer and verifier | a verifier rejects a fresh leaf as not yet valid |
| issuance rate limit | one per profile per 10 minutes | a runaway timer cannot mint a leaf stream | a legitimate renewal is refused |

## Decisions taken with the operator (2026-11-08)

Relayed by the coordinator (circus/eager-holly) the same day; this
session did not hear them directly.

| # | Topic | Ruling |
|---|---|---|
| 1 | pilot CA slot | slot 82 (`retired-1`) on the operator's card; the retired-slot refusal in `piggy tool` is self-imposed and is lifted (item I1); `piggy tool attest 82` must show PIN always, touch always before the key is trusted |
| 2 | root `pathlen` | 1, so the pilot root also signs the later intermediate |
| 3 | approval display class | RFC 0012 gains a fourth display class, `approval`, with the namespace `piggy-approval-v1` (acks, deploy approvals); not a bend of `escalation`. Amended in RFC 0012 the same day; implementation is item I2 |
| 4 | licence (piggy#327) | MPL-2.0 for the library crates; the main `piggy` package stays GPL-2.0-or-later. Not legal advice. Item I3 |
| 5 | sshsig or a hyphence tree | **Shape C** (ruled 2026-11-08, in session): sshsig stays the signature and RFC 0012's wire layer is unchanged; the signed, displayed text becomes a `piggy-act-v1` hyphence document carrying producer, class, named records and bounds. A comparison of C and A was written for the operator as a Google Doc the same day. Follow-up design, this session: the `piggy-act-v1` type definition, the class-equals-namespace verifier rule, and the RFC 0012 §3 text-shape amendment |

### Implementation items ruled 2026-11-08

This record is docs-only; these go to a piggy worker session, one merge
each, under the host's gate rules.

- **I1 (piggy#354). Retired slots in `piggy tool`.** Lift `is_supported_cert_slot`
  (`crates/piggy/src/cmd/tool/mod.rs:357`) so `generate`, `write-cert`,
  `req-cert`, `import` and `delete-cert` accept 82h to 95h; keep the
  refusal for anything else. The worker found two more refusals of the
  same self-imposed kind, lifted with it: `piggy-piv`'s cert-tag map for
  `PUT DATA` (9A to 9E only; now through `slot_to_cert_tag`, F9 still
  refused) and `piggy tool ecdh`'s own slot check (`mod.rs:763`; the
  retired slots are key-management slots, so ECDH is their NIST
  purpose). Fix the stale sentence in piggy-piv-slots(7)
  USAGE IN PIGGY ("no piggy code today reads from or writes to the
  retired slots"; `token.rs:372` has read them since). A fibby-backed
  lane if fibby models retired slots (**U**: not read), else a parse-level
  test plus the hand pass with `attest 82`.
- **I2 (piggy#355). The `approval` display class.** `DisplayClass::Approval` and the
  `piggy-approval-v1` entry in `crates/piggy/src/operator_act.rs`; a
  fourth dialog in `contrib/piggy-askpass.sh` and `piggy-askpass-gtk`
  whose banner says a decision is being approved and grants nothing; the
  tty route; the `operator_act_prompt.bats` and `operator_act_refusals.bats`
  rows; the piggy-agent(1) OPERATOR ACTS list. The RFC text is already
  amended; until I2 lands an agent refuses the namespace as unregistered,
  which is correct.
- **I3 (piggy#327). Licence.** `license = "MPL-2.0"` and a `LICENSE` file
  in each library crate; the `piggy` crate and the main flake package
  stay GPL-2.0-or-later; `flake.nix` `meta.license` and `README.md:50`
  made consistent; the issue's "not legal advice" label kept.

## Why sshsig? Acts as hyphence trees with markl-ids (options)

The operator asked (2026-11-08, not ruled): "why does this need to be
sshsig? can't we use a tree of hyphence docs + markl ids that include
the producer id?" Options only; the operator decides.

### What an act is today (V)

RFC 0012 makes an act an **sshsig blob** (`PROTOCOL.sshsig` §2: the
`SSHSIG` preamble, version, public key, namespace, reserved, hash
algorithm, signature) over the signed data of `PROTOCOL.sshsig` §3
(`SSHSIG`, namespace, reserved, hash algorithm, `H(text)`). The agent
shows the text and hashes it itself; the namespace carries the display
class; the key names the slot; the attestation bundle (§5) is published
beside the key. Verification is `ssh-keygen -Y verify` with an allowed
signers file and `-n namespace` (RFC 0012 §2.7). **There is no producer
field**: an sshsig from `piggy operator-sign`, from barker's in-app
producer, or from `ssh-keygen -Y sign` against an unguarded agent is the
same shape. The assurance claim rests on the key's attested policy
(§2.4) and on operator namespaces being reachable only through the
extension (§2.7).

### What hyphence and piggy-markl already give (V)

- **hyphence(7).** A document is a metadata section between two `---`
  lines and an optional body, or an `@ <markl-id>` blob reference in
  place of a body. Metadata lines are `#` descriptions; `-` lines, each
  a tag or object reference (`- value`) or a field (`- key=value`), any
  of which may carry an `@markl-id` lock suffix (a locked field is a
  typed edge to the target's content); `<`, a deprecated synonym for
  `-`; `%` comments; the `@` blob line; and the `! type` line, which may
  itself carry a lock (`! type @markl-id`) and should be the last
  non-comment line. Encoders write a canonical line order (descriptions,
  `-` lines, blob, type); decoders accept any order. The exact grammar
  after `- ` is hyphence's RFC 0002 (content grammar; not read here).
- **RFC 0008 (pigpen).** Already defines **canonical header bytes** for
  a hyphence metadata section and puts an HMAC over them in the
  type-line lock (§4.6), and states that sender authentication is "a
  higher layer (e.g. a papi signature over the document)" (§6). The
  construction a signed hyphence document needs exists; only the key
  changes.
- **RFC 0011 (markl-id).** `[purpose@]format-data`; a purpose is owned by
  the system its prefix names (§6.1), so a producer can mint
  `barker-act-sig-v1@ecdsa_p256_sig-…` without piggy registering
  anything; decoders carry unknown purposes opaquely (§6.6), but "contexts
  that need the purpose's semantics (signature verification …) MUST still
  fail on an unknown purpose". The purpose is the only place a producer
  id fits: format and data carry none, and the purpose is outside the
  checksum (§2). `piggy-record-sig-v1` (RFC 0012 §4) and `papi-doc-sig-v1`
  (a raw P-256 signature over canonical JCS bytes) are precedents for a
  signature carried as a markl-id.
- **Record grammar.** FDR 0032 D8's signed records and their canonical
  bytes are troupe's (RFC 0012 "Scope"); piggy fixes only what the
  markl-ids mean when they appear.

### Shape A: the act is a signed hyphence document (I)

    ---
    # operator act: escalation
    - producer=barker-act-v1
    - key=piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…
    - class=escalation
    - names=piggy-record-digest-v1@blake2b256-…
    - attestation=piggy-attestation-bundle-v1@blake2b256-…
    ! piggy-act-v1 @barker-act-sig-v1@ecdsa_p256_sig-…
    ---
    <the text the operator saw, verbatim>

The signature in the type-line lock covers the canonical header bytes
(RFC 0008's construction with a signature in place of the MAC) and the
body's digest. The act names the records it signs by markl-id, those
records are hyphence documents themselves (pigpen for sealed ones), and
a verifier walks the tree by resolving locks. Verification needs
piggy-markl, a hyphence canonicalizer and a raw ECDSA or Ed25519 verify;
OpenSSH is not involved. The display and text rules of RFC 0012 §2.5 and
§2.6 transfer unchanged: the agent shows the body and signs the
canonical bytes it computed. §2.7's guard becomes "refuse `piggy-act-v1`
canonical bytes on the ordinary sign path". That is a weaker check than
§2.7's fixed `SSHSIG` prefix: every hyphence header opens with `---`, so
the guard has to parse the header to its `! piggy-act-v1` type line
(canonically the last non-comment line, V hyphence(7)).

### Shape B: sshsig stays the signature; a hyphence act record wraps it (I)

The act record is a hyphence document with producer, key, class and
named records as fields and the armored sshsig as its body (or as
`piggy-record-sig-v1@…` beside the blob). `ssh-keygen -Y verify` still
verifies the signature; the producer id is outside the signed bytes
unless the text names it. This is close to what FDR 0032 D8 records
already are.

### Shape C: the text is the hyphence document (I)

Keep RFC 0012 as is and make the **text** a hyphence document carrying
producer, class, named records and bounds, shown verbatim and signed as
an sshsig. §2.5 admits it already (UTF-8, LF and TAB only). Then
`ssh-keygen` verifies the signature, the producer id and the fields are
inside the signed bytes, the tree is walked from the document's
markl-ids, and the agent and the wire layer are unchanged; RFC 0012 §3's text shapes
become "the text is a `piggy-act-v1` document". The operator reads
metadata lines on the prompt; §2.6 lets the askpass emphasize spans.

### What sshsig gives that Shape A must rebuild (V where cited)

1. **Zero-code verification everywhere.** `ssh-keygen -Y verify` and
   git's `gpg.format = ssh` exist on every host; RFC 0012 §2.7 requires
   an act to verify under `ssh-keygen -Y verify` (V), and FDR 0006 "The
   seam" requires plain `ssh-keygen -Y` and git to drive ordinary
   signing over the socket (V).
2. **Domain separation in the signed bytes.** The namespace is inside
   the signature (V `PROTOCOL.sshsig` §3); Shape A gets the same only if
   the class field is in the canonical bytes (it would be).
3. **Hash agility** (sha256, sha512) and key-type coverage (P-256,
   Ed25519) fixed by OpenSSH rather than by piggy.
4. **The landed path.** Phase (a)'s agent and client build and consume
   sshsig blobs (V `crates/piggy/src/operator_act.rs` `sshsig_blob`,
   `operator_sign.rs`), the probe prints `sshsig-hex`
   (V `crates/operator-act-probe/src/main.rs`) and the lane verifies with
   `ssh-keygen -Y verify` (V RFC 0012 conformance table,
   `operator_act_sign.bats`); Shape A
   re-does `operator_act_sign.bats` and the §5 bundle's verify step and
   supersedes RFC 0012 at the container layer.

### What a hyphence tree gives that sshsig lacks (I)

1. **A producer id and structured fields inside the signed bytes**
   (producer, class, named records, attestation bundle, time bounds for
   barker's blessing) without a per-namespace text-shape convention.
2. **One grammar** across acts, records, blessings, pigpen documents and
   madder blobs, with content addressing through markl-id locks, so a
   verifier can walk from an act to the records it names.
3. **No OpenSSH on the verifier (Shape A only).** A phone or a wasm
   verifier (RFC 0008 §7 already targets wasm) needs piggy-markl and a
   hyphence parser only; Shapes B and C still verify with `ssh-keygen`.

### Costs and the unregistered-producer point (I)

- Every verifier (troupe's receiver, spinclass, circus's gates, barker's
  badge, papi) needs piggy-markl, a hyphence canonicalizer and a raw
  signature verify; `ssh-keygen` alone no longer suffices. Hyphence
  implementations known from the tree: Go in madder (V, RFC 0008's
  cutover note says the canonical hyphence implementation lives in
  madder) and a Rust parser in `crates/piggy-pigpen/src/document.rs`
  (V the file exists; how complete it is, **U**). Anything else is **U**.
- Canonicalization becomes security-critical. The header construction
  exists (RFC 0008 §4.6); a body rule is new, or the body is referenced by
  digest only.
- **Neither container removes the verifier's policy.** RFC 0011 §6.6 lets
  barker mint its own purposes without piggy, but a verifying context
  MUST fail on a purpose it does not know; RFC 0012 §3 says the same of
  namespaces ("a verifier MUST accept only namespaces its policy
  names"). The difference is where the producer id lives: inside the
  signed bytes (Shapes A and C) or outside them (sshsig as is, Shape B).

### Who the verifiers are

troupe's receiver (barker FDR 0001 T1; FDR 0032 D8), spinclass
(profile-grant records under `piggy-escalation-v1`), circus's gates (FDR
0042's attestation token; this record's issuance audit), barker's verify
badge on the phone, papi's identity document (barker A1), and the
operator at a keyboard with `ssh-keygen -Y verify`, the one verifier
that exists on every host without piggy.

## Open questions

- **Transport and placement.** Which transport carries the CSR, and on
  which host the signer runs (circus and the operator).
- **The `piggy-act-v1` document (Shape C, ruled).** Its field set and
  grammars, whether `producer` values are registered or free, how the
  prompt renders the metadata block, and the RFC 0012 §3 amendment that
  follows. Design here, then an RFC amendment for the operator.
- **The root key and operator acts.** A PIN-always, touch-always key in
  slot 82 satisfies RFC 0012 §2.4 and so may serve operator acts if a
  card agent lists it (V). Either the agent refuses operator acts for
  keys outside the slot `card init` provisions for them, or the overlap
  is accepted and the certificate subject keeps the two keys apart in
  listings. Operator's call.
- **Ledger linkage.** Should each root signature also produce a
  `piggy-certificate-v1` operator act whose text names the issued
  certificate's markl-id, so the ledger records that the operator
  touched for it? RFC 0012 §3 says that text names the certified key and
  the request record (V); an X.509 certificate is neither, so this would
  be an amendment.
- **Durable intermediate.** Whether the operator prefers FDR 0006's
  sealed durable-key class for the intermediate, trading a card tap per
  restart for a key that survives one.
- **A sign guard for TBS data.** The holder agent treats ordinary sign
  data as opaque (V, FDR 0006 "What the signed subject is"), and the
  card agent signs ordinary requests for every slot it lists after a
  routine PIN prompt. If the issuance service is the only client of the
  intermediate key (socket permission plus binding), no guard is needed
  there; for the card root, a routine sign request over a TBSCertificate
  is exactly the unseen signature this record wants to avoid. Whether
  every piggy signing surface should refuse DER that parses as a
  TBSCertificate, the way it refuses operator-act sshsig data (RFC 0012
  §2.7), is decided with phase (ii).
- **Retired-slot policy.** Whether a YubiKey honours PIN always and
  touch always on slot 82 exactly as on 9C (the hand pass reads the
  attestation).
- **Ed25519 X.509.** Not pursued while nix's acceptance is untested.

## More Information

- FDR 0006, "fibby as guarded key holder" (the holder, the scopes, the
  service-principal question this record makes concrete).
- RFC 0012, the `operator-act@piggy` extension and the
  `piggy-certificate-v1` namespace.
- FDR 0004, "Hardware-token LUKS2 unlock", for the PKCS#11 route survey.
- piggy-piv-slots(7), the slot map and the retired-slot cautions.
- circus, `docs/plans/2026-11-08-shithub-proxy-design.md`: the consumer,
  the spike's observations, the hand-signing runbook this record fills
  blanks in.
