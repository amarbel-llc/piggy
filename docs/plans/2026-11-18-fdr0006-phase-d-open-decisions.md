# FDR 0006 phase (d): what has to be settled before code

Date: 2026-11-18. Status: a working note. Nothing here is decided; each
"proposal" is a recommendation awaiting an operator ruling. Tracking issue:
piggy#383. Phase (d) work does not start until the operator has closed #382.

Sources: piggy#383's item list and gates, FDR 0006 (the phase (c) paragraph
that hands "which slot a minted key goes in, and its PIN" to phase (d)),
and the card-init defaults of phase (a). I have not read the agent's
`session.rs` this pass, so statements about it are from #383, not from the code.

## 1. Which slot holds a minted key, and its PIN and touch policy

Today `fibby ctl create` puts the minted key in slot **9A**, with the factory
default PIN, and a random-GUID CHUID. Phase (d) must settle:

| Question | Proposal | Why |
|---|---|---|
| Slot | 9A only. Never 9C, never 9D | 9C is the operator-act slot; a holder card must not be able to produce an operator signature. 9D is the store's decryption slot and is never minted (FDR 0006). |
| PIN | The holder sets a random PIN per minted card and keeps it in guarded memory; the caller never sees it | A caller that never holds the PIN cannot unlock the card outside the holder. Replaces the factory default. |
| Reported PIN policy | `never` for a holder card, honoured by the agent (#383 item 4) | No human is present to type it, and #383 says the agent today demands a PIN for every slot except 9E. |
| Touch policy | `never` | A minted key serves an unattended session. A touch policy nobody can satisfy would only hang the caller. |

Consequence to record, not hide: a holder card's attestation chains to the
fibby attestation key, not to a Yubico root, so no verifier may treat a minted
key as hardware-held. `piggy health` and the attestation export should say so
for these cards.

## 2. The mint and retire wire format (RFC part 2) must not assume a scope

The operator ruled "leave open for now" on which scope a minted key binds to,
so the format cannot hard-code one. Proposal: the `mint@piggy` request carries
the scope as an **opaque, optional binding field**, with no default value:

- absent: the holder binds to the scope it infers from the caller's
  connection, if clown#244 has landed, else it refuses with a distinguishable
  "scope-unbound" error;
- present: the holder checks it against its own configuration (the scope
  mapping is holder configuration until clown#244 lands).

That leaves the field's grammar to the scope decision, and the extension's
shape stable.

## 3. Facts to verify before relying on them (#383's unverified items)

1. Does ssh-agent-lib 0.5 expose the peer socket (for `SO_PEERCRED`)?
2. How to read the peer cgroup without a pid-reuse race. #383's guess is
   `pidfd`: open the pidfd from the peer pid right after accept, then read the
   cgroup through it, and refuse if the pid has gone. Unverified.
3. What the agent does today for a slot whose reported policy is "no PIN"
   (item 4 of #383).

Each should be a small, throwaway check before the RFC text freezes.

## 4. Teardown and caps

- The card cap is 16. A mint beyond it is refused with its own error name,
  distinct from policy refusals, so a caller can retry after a retire.
- Retire is `retire@piggy` by the owning scope, or implicit when the bound
  cgroup disappears. Both must wipe the card and remove its reader (the
  existing `destroy <reader>` does this).
- Open: whether a retire from a sibling scope is refused or silently ignored.
  Proposal: refused, as "not-bound-scope", the same error a sibling's sign
  request gets.

## 5. Not designed here

- Service principals (spinclass FDR 0032) do not fit teardown-on-scope-exit as
  written; #383 leaves them out and so does this note.
- The `services.piggy-holder` module (two hardened units) and its VM lane
  follow the settled behaviour; they carry no open decision of their own yet.

## 6. Acceptance, restated

From a bound scope mint a key and sign with it; from a sibling scope be
refused; retire it; exit the scope and confirm the card is gone. Once in the VM
lane and once on a real host under the hardened units. It lands with an
`explore-fdr0006-d` recipe.

## 7. Rulings needed

1. Slot 9A only, random holder-held PIN, policy `never` for PIN and touch
   (section 1): yes or no?
2. An opaque optional scope field in `mint@piggy` (section 2): yes or no?
3. A sibling's retire is refused as `not-bound-scope` (section 4): yes or no?
