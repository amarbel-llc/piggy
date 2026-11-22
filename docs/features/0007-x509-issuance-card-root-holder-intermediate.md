---
status: experimental
date: 2026-11-17
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
>
> **Update, 2026-11-12.** Implementation items I1 (piggy#354, retired
> slots in `piggy tool`), I2 (piggy#355, the `approval` display class)
> and I3 (piggy#327, licence) are Closed on the tracker; this session did
> not re-read their commits, so "landed" is inferred from the Closed
> state. Decision 5 is answered by RFC 0013 (accepted 2026-11-10). What
> remains for the operator is approval of this record, after which phases
> (i) to (iv) each want a tracking issue (none exists; filing waits for
> approval). FDR 0008 (secret proxy) is a sibling consumer of the same
> holder and `piggy-guard`, not a dependency of this record.

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

**Slot 82 as it stands on the operator's card (2026-11-18, relayed by
the coordinator, circus/eager-holly; recorded here by piggy/lucid-larch
for the hung design-owner session).** The slot's attestation was
VERIFIED on the operator's card host against the Yubico root: the chain is the
leaf `YubiKey PIV Attestation 82`, then this card's F9 certificate, then
`Yubico PIV Root CA Serial 263751`; the attested key is slot 82's key
(`ecdsa-sha2-nistp256`, P-256); the attested policy is PIN always and
touch always; firmware 5.2.7; the root's SHA-256 fingerprint as read,
`63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46`.
That fingerprint was compared on 2026-11-19 with Yubico's published PEM,
fetched at 11:26:54Z by the coordinator session with an anonymous GET of
`https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem`
(a 301, through a plain-http hop, to
`https://developers.yubico.com/PKI/yubico-piv-ca-1.pem`): identical, and
that PEM is now embedded in piggy as `piggy tool attest-verify`'s default
root, pinned to the fingerprint and checked at every use (piggy#397).
Both readings come from Yubico's own server over TLS, so the match is a
consistency check between two downloads, not an independent anchor; a
verifier with a root of its own passes `--root`. The stored certificate is
a self-signed placeholder, `CN=PIV slot 82`, with no extensions. The
operator ruled (23:04Z): use slot 82 as it is, do not regenerate. The
first card act with it is the pilot root certificate (the checklist and
the drafted `just explore-fdr0007-root-cert` recipe). No earlier
certificate issued by this key is known: its subject key identifier is
`F7:6B:D0:9E:62:5A:C9:52:DE:FF:EB:7F:FE:29:39:D8:61:DC:3E:77` (RFC 5280
method 1, SHA-1 of the point; `just debug-ssh-key-identifiers`) or
`38:55:AD:D7:AA:F6:96:4B:F1:F6:49:11:4A:0B:F6:D1:F8:54:5A:BE` (RFC 7093
method 1, what piggy-piv's builders write), and a search of every
repository checked out on the build host on 2026-11-19 found neither as
an authority key identifier, nor the placeholder's issuer name, nor a copy
of the key.

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

*Profile fields as built (phase (ii), 2026-11-19; piggy(1) is the
reference):* `kind`, `common_name`, `names`, `lifetime_hours`,
`not_before_skew_minutes` (default 5; the design owner's ruling that the
skew is a profile field, not a flag), `key_types`, and the optional
`principal`, the `subject` of the profile's certificate acts (RFC 0012
§3.2; a bare word, default `piggy:ca:<profile name>`); under `[issuer]`,
`slot` and `guid`, and the optional `attestation_root`, an absolute path
to the PEM certificate the card's attestation chain must reach before
the slot's key counts as the card's own (absent: the embedded Yubico PIV
root; a virtual card's lane names its own F9 certificate; `root-cert`
announces a non-embedded root with its subject and fingerprint; a path
that is relative, missing or not a certificate is exit 3, never a silent
fallback). The file is `ca-profiles/NAME.toml` under `PIGGY_CONFIG_HOME`,
else `$XDG_CONFIG_HOME/piggy`, else `~/.config/piggy`.

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
   certificate's and the CSR's digests as markl-ids, the authorizing
   act's digest as a markl-id when an act authorized the issuance
   (absent otherwise, never empty; the act's contents are not logged),
   and `notAfter`; to
   the journal under systemd, otherwise to an append-only file in
   piggy's state directory;
7. print the issued certificate, followed by the issuer's certificate
   when the issuer is an intermediate (the chain the proxy serves),
   never the root. In the pilot the output is the leaf alone.

Refusals are answers, each with its own exit code so a renewal timer can
tell them apart (working values): 2 usage; 3 profile unknown,
unreadable, or of the wrong kind for the verb (`root-cert`, `sign` and
`issue` alike); 4 CSR malformed or key type refused; 5 names outside the
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
| (i) #393 | `piggy-piv` profile builders (root, intermediate, leaf) over the existing signer-closure shape; the bats lane with openssl, including the negative name and IP cases and the unconstrained-intermediate case; item I1 (retired slots in `piggy tool`) if it has not landed ahead of the phase | the pilot's slot; the certificate shapes |
| (ii) #391 | `piggy ca root-cert`, `sign`, `issue` for a **card-held** issuer, with profiles; replaces openssl in the pilot's renewal | the pilot's renewal |
| (iii) #392 | the holder intermediate: a unit-bound mint (FDR 0006 (d)), `sign` of the intermediate by the card, `issue` with the holder key; health reports the intermediate | unattended renewal |
| (iv) #394 | the issuance service unit in the NixOS module; whatever part of the transport the operator rules is piggy's, if any | the proxy host's renewal |

Every phase closes with the human pass FDR 0006 requires.

**Phase (iii-a) as built (2026-11-18, piggy#392; plan
`docs/plans/2026-11-18-fdr0007-phase-iii-plan.md`).** With phase (ii) not
yet on master, the part of (iii) that needs no `piggy ca sign`/`issue`
landed first, on FDR 0006 phase (d)'s holder: the issuance unit
(`services.piggy-ca`, `nix/nixos/piggy-ca.nix`) mints its own P-256
intermediate key at start from inside its cgroup, under the holder scope
`piggy-ca-intermediate-v1 = cgroup:/system.slice/piggy-ca.service`; so no
session can mint for the unit and nothing outside the unit can sign with
or retire the key, which answers the four needs listed under "What FDR
0006's service-principal question needs" without a service peer class.
`piggy ca csr --key FILE [--cn NAME]` writes the intermediate's PKCS#10
request, signed through the holder agent's ordinary sign path (no PIN, no
touch, no new extension; `agent_client::agent_sign_ecdsa_der`,
`piggy_piv::cert_builder::build_csr_over_info`). The certificate comes
back from the card to `intermediateCertFile`; at every start the unit
retires its previous key (a unit's cgroup can outlive a `systemctl
restart`, so the holder's teardown-on-cgroup-exit is not relied on) and
mints a new one, so after any restart the file names the old key, which
is the visible re-mint. The
intermediate stays in slot 9A of its virtual card (design owner's ruling,
2026-11-18): RFC 0012's TBSCertificate refusal keys on the CA slot 82, so
it does not apply to holder keys, and the cgroup binding is the only gate.
Lanes: `test-bats-conformance-ca-csr-fibby`, the `vm-piggy-holder`
subtests for the unit. `piggy health` reports the intermediate as one
last point on a host with the unit's state directory (or
`PIGGY_CA_STATE`): `issuance: intermediate present` passes with the
subject, the expiry and whether the holder serves the key; each way of
having none fails under its own name, `no intermediate (never minted)`,
`(key minted, not yet signed)`, `(certificate names a previous key)` (the
re-mint after a restart), `(key retired)`, with the remedy as a `hint`
diagnostic; `intermediate expired` and `not yet valid` are failures of
their own, distinct from a missing one. "Served" is checked only against
the holder itself (the probed agent reports holder mode), never guessed.
**Phase (iii-b) as built (2026-11-20, the operator's chain priority).**
`piggy ca issue` with a holder issuer: a leaf profile's `[issuer]
holder_key` (the intermediate's OpenSSH line) and `issuer_cert` (its
card-signed certificate, an absolute path); the leaf is signed through
the holder agent's ordinary sign path over the TBSCertificate (the agent
hashes for itself; `x509_profile::build_leaf_cert_over_tbs`,
`ca_issue::Signer::Tbs`), after the agent reports holder mode and lists
the key (fail closed: a plain ssh-agent never issues, exit 6); no card,
no PIN, no act (step 6: `act=` absent); the output is the leaf then the
intermediate (step 7); `notAfter` capped by the intermediate's; only a
leaf profile may name a holder, and `sign` stays on the card. Beside it,
the same day: `piggy ca leaf-csr` (the card-free leaf key file and
request for a host with no holder), `piggy ca verify` and `piggy cert
show` (the chain checked in piggy, name constraints included; a checker,
not a gate), and the issue-time check of a profile's names against the
issuer's name constraints (exit 3, before the request is read).

**Operator approval, 2026-11-17.** The operator approved this record as
proposed and had the four phase issues filed (the numbers above). Phase
(i) landed the same day (#393, origin/master f3cfe0515b63), which moved
the status to `experimental` (see the promotion criteria); the
operator's acceptance pass on #393 is still to come. Rulings made with the approval, folded into the open
questions below: the agent refuses operator acts for keys outside the
slot `card init` provisions (9C); each root signature also produces a
`piggy-certificate-v1` act, deferred to phase (ii); the intermediate key
is minted per unit and is unit-bound by default; operator-act
verification requires the attested slot 9C; the card agent and
`piggy tool sign` refuse TBSCertificate DER on CA slots. Still open: the
transport and placement question.

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
| 5 | sshsig or a hyphence tree | **Shape C** (ruled 2026-11-08, in session), refined to **Shape E** on 2026-11-09 and accepted as RFC 0013 on 2026-11-10: sshsig stays the signature and RFC 0012's wire layer is unchanged; the signed, displayed text is a `piggy-act-v1` hyphence document whose head carries kind, subject, key, rights and bounds and MAY pin a capability profile by digest (`profile`), and whose body, when present, is a patch in cutting-garden FDR 0028's stencil fragment that may only deny; conditions along a chain are stacked, never compared (RFC 0013 §4.9). The 2026-11-08 text follows. A comparison of C and A was written for the operator as a Google Doc the same day; his comments on it add: the metadata **is** the prompt and is shown in full, never folded; the body may be empty, the head carrying the whole permission declaratively through nested hyphence documents, in a permissions language expressive enough for any permission (his words: "turing complete"); and in any signed hyphence document the signature is its own metadata field, never the type-line lock (unlike RFC 0008's MAC). Two further rulings the same day, in session: **producers are registered per domain, for free**: each system registers its own producer names for itself (as RFC 0011 lets a system own its purpose prefix), and a producer's trust comes from its key's chain to the card, not from a piggy list; piggy supports whoever registers for themselves and enables their chains. And **each act is a small certificate**: the card's key is a CA, every document below it is a signed hyphence document whose power comes only from its chain to the CA, trust is structural and mechanical, not linguistic, the language is the adding and dropping of privileges along the chain, and the privileges to support are those of spinclass FDR 0032 and its epic. RFC 0008 may need an amendment to fit (the signature as its own field). Ownership (ruled the same day): piggy owns the envelope and the chain rules (the signed-document format, the signature field and canonical bytes, chain verification from the card's key, the generic add and drop of privileges); the privilege vocabulary is spinclass's (FDR 0032, FDR 0034). piggy is upstream of spinclass, so piggy's record does not cite spinclass normatively; spinclass's needs inform piggy's design as requirements. Record: a new **RFC 0013**, reviewed through a user-stories tab beside it in a Google Doc. Also the RFC 0012 §3 text-shape amendment and the RFC 0008 question |

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

## Amendment 2026-11-22: slot 83, the SSH certificate authority

Ruled by the operator, relayed by the coordinator (circus/eager-holly) the
same day, for the delegation sprint. It extends decision 1 (the pilot CA
slot): the card holds **two** certificate authorities, one per kind, and a
kind certifies one thing only.

| Slot | Kind | Certifies |
|---|---|---|
| 82 (`retired-1`) | X.509 | X.509 certificates, through `piggy ca` only |
| 83 (`retired-2`) | SSH certificate | OpenSSH user certificates, through the agent (`ssh-keygen -U -s`) |

Both are keys generated on the card with PIN always and touch always, on a
real card and in fibby alike (fibby holds a key in any retired slot, piggy#399).

- **The agent refuses the wrong kind, per slot, before the card is touched or
  a prompt shown.** Slot 82 refuses a TBSCertificate through the agent and
  `piggy tool sign` (as before) and an OpenSSH certificate; slot 83 signs
  only a parsed, unsigned OpenSSH user certificate and refuses a
  TBSCertificate, an sshsig, a login challenge and any other bytes; every
  other slot refuses an OpenSSH certificate. One function
  (`piggy_piv::slot::ca_kind`) says which slot is which kind.
- **A certificate-aware prompt is required.** Signing an OpenSSH certificate
  raises a PIN dialog of its own kind, `ssh-certificate`, whose context is
  what the signature certifies: key id, principals, the certified key's and the
  CA key's fingerprints, serial, validity and lifetime, critical options (a
  `force-command` with its command) and extensions. It is not an operator act
  and shares no wording with one.
- **Lifetimes are variable up to a limit.** The limit is 24 hours, built in
  (`MAX_LIFETIME_SECS`) for now and configurable later, plus five minutes
  for `ssh-keygen`'s one-minute back-dating; a longer certificate, one with
  no end, a host certificate and one with no principal (valid for every
  user) are refused before any prompt. Slot 83 certifies user certificates
  only; widening to host certificates is a later ruling.
- **82 and 83 are never cached.** The agent asks for their PIN every time and
  neither reads it from nor writes it to the PIN cache. 9C and 9D are NOT
  changed by this: whether they too should never be cached, against the
  operator's wish for a single PIN entry, is deferred and tracked as its own
  issue.
- **A CA key must be attested PIN always and touch always.** Added the same
  day after the Fable review of c7dd0561: the agent reads the key's
  attestation on every request and signs nothing with a CA slot's key that is
  not attested for it with PIN always and touch always (an imported key, or
  one generated laxer, signs nothing and raises no prompt); the dialog is
  shown whatever the agent believes of the key's PIN policy; `piggy tool
  generate` on 82 or 83 with no policy generates always and always. No CA
  key performs ECDH on any path (`PinSession::ecdh_derive`). The dialog's
  text is bounded and plain by refusal: strict charsets and counts, a known
  list of options and extensions each at most once, well-formed certified
  keys, a certificate not already over, and a CA key that is the signing key.
  The certificate dialog's askpass must acknowledge a nonce
  (`piggy-askpass-ack`) or its PIN is not used, and a front relays
  certificate-shaped data only to an upstream that advertises
  `ssh-ca-gate@piggy`.
- **Fibby is production software.** The operator wants fibby to be capable of
  everything piggy does that is used regularly, and part of the first real
  run; slot 83 works on it today. Persistence of a fibby card's keys across a
  restart is not part of this amendment (a restarted fibby has an empty slot
  83).

Record of what was checked: `ssh-keygen -U -s` against an agent over fibby's
slot 83 signed a certificate that `ssh-keygen -L` reads and that OpenSSH's
`-Y verify` accepts against a `cert-authority` line; the lane
`test-bats-conformance-ssh-ca-fibby` pins it, and the parser's tests use a
certificate `ssh-keygen` made.

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
  which host the signer runs (circus and the operator). **Ruled
  2026-11-18 (relayed by the coordinator):** an ssh forced command on the
  signer host running `piggy ca issue --profile NAME`, CSR on stdin, "for
  now". The tailnet HTTP endpoint and PAPI stay alternatives, open once
  the ergonomics are known (the operator's words: keep them "in our back
  pocket"). Which host the signer runs on is not ruled by this.
- **Signed hyphence documents as a certificate chain (Shape C, ruled;
  answered by RFC 0013, accepted 2026-11-10).** The `piggy-act-v1` field
  set, the seal, the signed bytes, the chain from the card's key down,
  how rights are added and dropped along it and how conditions stack are
  RFC 0013; the RFC 0012 §3 amendments landed with its acceptance. Still
  open from this item: the RFC 0008 question (whether pigpen moves its
  header MAC to a field), recorded in RFC 0013 Compatibility.
- **The root key and operator acts.** A PIN-always, touch-always key in
  slot 82 satisfies RFC 0012 §2.4 and so may serve operator acts if a
  card agent lists it (V). Either the agent refuses operator acts for
  keys outside the slot `card init` provisions for them, or the overlap
  is accepted and the certificate subject keeps the two keys apart in
  listings. Operator's call. **Ruled 2026-11-17: refuse.** The agent
  refuses operator acts for keys outside the slot `card init`
  provisions for them (9C). RFC 0012 verification of an operator act
  REQUIRES the attested slot 9C, not only the policy: the attestation
  certificate names the slot, so a key in slot 82 presents a slot-82
  attestation and is rejected as an operator act. Stated in RFC 0012
  when phase (ii) opens (#391).
- **Ledger linkage.** Should each root signature also produce a
  `piggy-certificate-v1` operator act whose text names the issued
  certificate's markl-id, so the ledger records that the operator
  touched for it? RFC 0012 §3 says that text names the certified key and
  the request record (V); an X.509 certificate is neither, so this would
  be an amendment. **Ruled 2026-11-17: yes**, deferred to phase (ii)
  (#391), with the RFC 0012 §3 amendment.
- **Durable intermediate.** Whether the operator prefers FDR 0006's
  sealed durable-key class for the intermediate, trading a card tap per
  restart for a key that survives one. **Ruled 2026-11-17:** the
  intermediate key is minted per unit and is unit-bound by default.
- **A sign guard for TBS data.** The holder agent treats ordinary sign
  data as opaque (V, FDR 0006 "What the signed subject is"), and the
  card agent signs ordinary requests for every slot it lists after a
  routine PIN prompt. If the issuance service is the only client of the
  intermediate key (socket permission plus binding), no guard is needed
  there; for the card root, a routine sign request over a TBSCertificate
  is exactly the unseen signature this record wants to avoid. Whether
  every piggy signing surface should refuse DER that parses as a
  TBSCertificate, the way it refuses operator-act sshsig data (RFC 0012
  §2.7), is decided with phase (ii). **Ruled 2026-11-17:** both the
  card agent and `piggy tool sign` refuse DER that parses as a
  TBSCertificate on CA slots (82 today). Not every surface: 9A signs
  SSH challenges and is not a CA, and 9D does not sign. Built in phase
  (ii) (#391).
- **Retired-slot policy.** Whether a YubiKey honours PIN always and
  touch always on slot 82 exactly as on 9C. **Answered 2026-11-18:** it
  does; the attestation was verified on the operator's card host (see
  "Slot 82 as it stands" above: PIN always, touch always, bytes `03 02`,
  which piggy's own decoder reads the same way: `piggy-piv/src/attest.rs`
  `parse_policy` and the `policy.rs` tests, read by me, not run). The
  operator ruled to use the key as it is; regeneration through papi and
  piggy stays pre-approved if a criterion below fails.
  **Provenance, as the operator recalls it (beliefs, not verified; a
  card keeps no signing log):** generated in a prior session, believed
  unused, believed to be the prototype shithub CA key. The two beliefs sit
  uneasily together, and the key-identifier search above found no
  certificate issued by it on the build host, which does not rule out one
  elsewhere. **Criteria for reuse (coordinator's, accepted by the
  operator):** generated on the card (attested); PIN always and touch
  always (fixed at generation); P-256; the stored certificate a
  self-signed placeholder with no CA extensions, replaced by `root-cert`
  with generic placeholder dates (2024 to 2074) not meaning anything; no
  certificate signed by the key found; and the first signature with it
  recorded as a `piggy-certificate-v1` act (RFC 0012 §3.2). Residual
  risk: "nothing was signed" stays the operator's belief, mitigated by
  the new root's name constraints.
  **First act, done 2026-11-19 (operator's account, relayed by the
  coordinator; the card was not touched by this record's author):** the
  placeholder was saved as the rollback; `attest 82` was re-read (same
  key, PIN always, touch always); the pilot root was signed at 09:43:53Z
  with slot 82 through OpenSSL, the pkcs11 provider and libykcs11, not
  through `piggy ca root-cert` (#391 is not built): 180 days, CN
  `circus-pigtrough-github-root-2026-11`, pathlen 1, permitted DNS
  `github.com` only, all IP ranges excluded; it was written with `piggy
  tool -K default write-cert 82`, so the management key is still the
  factory default (rotation is designed for the next sitting); the card's
  certificate and the signed file have the same DER sha256,
  `20a9af00b700d8abe47fdcda82a9a59bd0beb52e589dc14310b7f970223cb095`,
  the key is unchanged and subject equals issuer. **Not done:** the
  `piggy-certificate-v1` act on 9C for this root (RFC 0012 §3.2), which
  needs phase (ii)'s verb and is not improvised. Gaps found in the run,
  filed: #395 (attestation compare), #396 (`piggy tool` management key
  from store or argv), #397 (attestation verification for slots 82 to
  95).
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
