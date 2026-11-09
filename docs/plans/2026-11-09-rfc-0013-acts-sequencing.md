# RFC 0013 acts: sequencing the build

Status: plan, written 2026-11-09 by piggy/green-larch on the operator's
rulings of the same day. Facts about the tree are marked **V** (read in the
named file at this worktree's HEAD, 362a0b3 plus the local commits that
follow it); everything else is a proposal. Nothing below is built.

## 1. Rulings this plan rests on

- **Build the stable parts now; hold the chain walk until acceptance.**
  RFC 0013 is `proposed`. The canonical form, the seal, the act digest,
  signature verification, the display rule and the registry entries are
  stable enough to build against. The chain rules (effective rights,
  expiry, revocation, layers) wait for the operator's acceptance pass on
  the RFC 0013 user-stories tab.
- **Consumers in this order: spinclass, then barker, then circus.**
  spinclass FDR 0034 slice 1 (signed profile grants) drives the first
  verifier slice: software-key acts, the subset check, a store interface.
  barker's device blessing (a card `link` with a short `not-after` and a
  narrow `profile`) comes second. circus's approval acts for merge
  attestation come third.
- **Record as a plan document plus issues**, one issue per slice in
  dependency order, piggy#26 updated, the `_tags.org` records updated. The
  operator sees the order before anything is filed.
- Earlier the same day: Shape E (espalier body as a patch, `profile` edge
  pinning a stencil), conditions stacked never compared, `deny` admitted,
  the derivable head fields stay written out and are judged live first.
  All in RFC 0013's 2026-11-09 amendment and `piggy-acts(7)`.

## 2. What exists today (V)

- `crates/piggy/src/operator_act.rs`: the RFC 0012 wire codec, the
  namespace registry with display classes (`piggy-certificate-v1`,
  `piggy-approval-v1`, ...), `HashAlgorithm`, `signed_data`,
  `sshsig_blob`, `ssh_signature`, `armor`, `prompt_context`,
  `refuse_operator_act_signed_data`.
- `crates/piggy/src/operator_sign.rs`: the thin card-act client
  (`piggy operator-sign`); `cmd/agent/session.rs` holds the
  `operator-act@piggy` handler; `ecdsa_sig.rs` the DER/SSH reframing.
- `crates/piggy-markl`: the Rust markl codec and registries
  (`piggy-record-digest-v1`, `piggy-record-sig-v1` from RFC 0012 §4).
  `go/internal/charlie/markl_registrations/` mirrors them in Go
  (`purposes.go`, `piggy_record_registrations_test.go`).
- `crates/piggy-pigpen/src/hyphence.rs`: a minimal hyphence RFC 0001
  framing (prefixes `# - @ !`, boundaries, the blank-line separator), not
  RFC 0002 field content, and marked by its own comment as the thing the
  RFC 0008 cutover replaces "with either piggy's own conforming framing or
  a shared library".
- No Rust hyphence RFC 0002/0003 field-content parser, no canonicalizer,
  no `piggy act` verb, no act vectors, no `piggy-principal_pub-v1`
  purpose.

## 3. The slices

Sizes are rough and relative. Worker tier follows the standing rule:
mechanical slices to opus-or-lower workers, design and review in the
owning session.

| # | Slice | Depends on | Gate | Size |
|---|---|---|---|---|
| S1 | Registry: `piggy-principal_pub-v1` purpose (RFC 0011 §6.1, `crates/piggy-markl`, `go/.../markl_registrations`, the RFC 0011 vectors) | none | now | small |
| S2 | The act document: a Rust reader and canonical encoder for the `piggy-act-v1` head (hyphence RFC 0001 framing, RFC 0002 field lines, RFC 0003 locked edges for `profile`), the §2 field table with refusals (§5.2 step 1), the body carried verbatim with the §4.9 character check, the canonical form (§3.1), `piggy act canon`; `docs/rfcs/0013-vectors.txt` started; `act_refusals.bats`, `act_canonical.bats` | S1 | now | large |
| S3 | The seal: rebuild the sshsig from the four seal fields, verify under `key` for Ed25519 and P-256, the act digest (§3.5), `piggy act verify --seal-only` (working name) answering valid or invalid for the signature alone, `ssh-keygen -Y verify` interop both ways; `act_seal.bats`, `act_body.bats` (body signed verbatim, one byte changed fails) | S2 | now | medium |
| S4 | Producing acts: `piggy act seal` takes an unsealed head (and optional body), canonicalizes, checks the §4.8 namespace and kind table statically, obtains the signature (card via the existing `operator-sign` path for card namespaces; the agent's ordinary sign path for `piggy-record-v1`), and emits the sealed act. This is the primitive the Go consumers call instead of writing a canonicalizer | S3 | now | medium |
| S5 | Display: the agent shows a `piggy-act-v1` text as RFC 0013 §6 requires (every head line, canonical order), the askpass emphasis of `kind`, `subject`, `right`, `not-after` in `piggy-askpass-gtk` as a MAY; `operator_act_prompt.bats`; answers piggy#332 and #329 from RFC 0013 | S2 | now | medium |
| S6 | The chain walk: store interface (a directory of sealed acts first; a JSON-over-stdin adapter for Go consumers second), §4.1 to §4.8 (kinds, rights never widen, effective rights, keys, validity and expiry, revocation, assurance, namespace table), §5.2 steps 3 to 7, §5.3 verdict with layers marked stencil or patch, undetermined; full `piggy act verify`; `act_chain.bats` | S3, acceptance | held | large |
| S7 | On acceptance: RFC 0013 status to `accepted`; the RFC 0012 §3 amendments listed under Compatibility; FDR 0007 decision 5 updated to Shape E; `piggy-acts(7)` pointer to cutting-garden's `ajour(7)` once it exists | S6 | held | small |
| S8 | Consumer onboarding, in the ruled order: (a) spinclass FDR 0034 slice 1 over `piggy act seal` and `piggy act verify`, the JSON verdict shape agreed with spinclass; (b) barker device blessing as a card `link` with `profile` and a short `not-after`, answering barker P1; (c) circus approval acts naming the merge decision record, answering circus D4 and piggy#329 Q1 | S4, S6 | held, asks now | asks |

S1 to S5 are the "stable parts now" of the ruling. S6 to S8 are held
until the operator accepts RFC 0013; their issues are filed now so the
order is visible, labelled as held.

## 4. Order and parallelism

    S1 ─┐
        ├─► S2 ─► S3 ─► S4 ──────────────► S6 ─► S7 ─► S8
        │         └──► S5 (parallel with S4)
     acceptance pass ──────────────────────┘

- S1 is a half-day and unblocks the vectors in S2.
- S2 is the long pole. It is the first Rust hyphence field-content
  implementation in piggy; its reader and encoder should be written so
  `crates/piggy-pigpen` can adopt them later (RFC 0008 Compatibility), but
  that adoption is not in this plan.
- S3 reuses `operator_act.rs`'s `sshsig_blob`, `signed_data` and
  `ecdsa_sig.rs`; new code is the seal field mapping and the digest.
- S4 and S5 run in parallel once S3 and S2 land respectively; S5 touches
  the agent and the askpass, S4 the CLI.
- S6 starts the day after acceptance. Its store interface is designed
  with spinclass first (S8a), which is why spinclass is the first
  consumer.

## 5. Asks to other lanes (sent as one-line messages, not issues here)

- spinclass (FDR 0034 slice 1): the JSON verdict shape and the store
  adapter it wants from `piggy act verify`; whether its grant becomes a
  `piggy-act-v1` with a `profile` edge or stays a record named from an act
  by digest; the "inherited unchanged" sentence in FDR 0034 Verification
  against the strict stencil rule (cutting-garden/swift-plum's point).
- cutting-garden (ajour, FDR 0028): the stencil fragment's conformance
  vectors, named so RFC 0013's vectors can point at them; the stencil and
  patch distinction in `ajour(7)`.
- barker: whether P1 (the device key's spelling) is answered by a card
  `link` with `profile`; the phone producer builds the canonical head and
  calls the same seal path or reimplements §3.1 against the vectors.
- circus: D1 step 3's "at least one layer allows" against RFC 0013 §4.9's
  strict rule; the approval act text for D4 (piggy#332) is now "the head of
  a `piggy-act-v1` approval", not free text.

## 6. Loose ends recorded, not scheduled

- `crates/piggy-pigpen/src/hyphence.rs` duplication once S2 lands (RFC
  0008 Compatibility names the cutover).
- Who may revoke (RFC 0013 Limitations); the card-revocation banner; a
  narrow outliving an escalation unless named. All flagged for the
  acceptance pass.
- The head consolidation (prompt B) as a Tuning Lever; revisit after live
  use.
- piggy#303 (FDR 0006 phase (a)) still awaits the operator's acceptance
  pass; S5 touches the same agent code and should land after it or be
  rebased over it.

## 7. Records to update when the issues are filed

- piggy#26: a comment pointing here, with S1 as "Recommended next" for a
  worker and the acceptance pass as the operator's item.
- `org://personal/_tags.org` proj `-card_signature_language` (the piggy
  side of this track) and `-ajour` (the cutting-garden side): status lines
  naming the issue numbers.
- The review doc tab: no change; this plan is the durable record.
