# FDR 0007 phase (iii): the holder-held intermediate (piggy#392), a plan

Date: 2026-11-18. Status: a working plan, written after FDR 0006 phase
(d) landed (master 2233016) and BEFORE the answers to the questions in
the last section. Nothing here is built. Sources: FDR 0007 (approved
2026-11-17; the phase table, "Keys, policies and bindings", "What FDR
0006's service-principal question needs"), #391 and #392, and the phase
(d) code (`cmd/agent/holder.rs`, RFC 0014 draft).

## What phase (iii) must deliver

FDR 0007's row: "the holder intermediate: a unit-bound mint (FDR 0006
(d)), `sign` of the intermediate by the card, `issue` with the holder
key; health reports the intermediate". Operator ruling (2026-11-17): the
intermediate key is minted per unit and is unit-bound by default.

## What phase (d) already gives it

- A scope definition `NAME = cgroup:/absolute/path` binds a mint to that
  cgroup, and the caller must be inside it to mint, sign or retire.
- The key is created inside fibby, slot 9A, PIN and touch `never`,
  usable through the holder agent's socket by ordinary SSH-agent sign
  requests from inside the binding only; it dies with the cgroup.
- `services.piggy-holder` runs fibby and the holder agent as hardened
  system units; `scopes` is where the definition goes.

So the four things FDR 0007 said the service-principal question needs
fall out without new holder code:

| FDR 0007 needs | phase (d) answer |
|---|---|
| a mint naming a unit's cgroup as the binding, with a rule for who may mint for it | the issuance unit mints its own key from inside its cgroup (`ExecStartPre` runs there); a session is outside and cannot |
| a third peer class, "service" | not needed in v1: the `cgroup:` rule is the class |
| no PIN and no touch, recorded | every minted key is `never`/`never`; `piggy health` reads the attestation |
| a visible re-mint on restart | the key dies with the cgroup; the unit mints a new one at start; the old intermediate certificate no longer matches, and health says "no intermediate" |

## The dependency on phase (ii)

Phase (ii) (#391: `piggy ca root-cert`, `sign`, `issue` for a card-held
issuer, with the phase (i) profiles) is **not on master** (no `piggy ca`
in the tree at 2233016). Phase (iii) needs `sign` (the card signs the
intermediate CSR) and `issue` (a leaf under the intermediate). Proposed
split:

### (iii-a): everything that needs no `piggy ca sign`/`issue`

1. **The issuance unit's mint.** A module (working name
   `services.piggy-ca`, or options on `services.piggy-holder`) that adds
   the scope `piggy-ca-intermediate-v1 = cgroup:/system.slice/piggy-ca.service`
   to the holder and runs `piggy-ca.service` under its own account in
   `clientGroup`, whose `ExecStartPre` does
   `piggy holder mint --scope piggy-ca-intermediate-v1 --type p256 >
   $STATE/intermediate.pub`. A restart re-mints; the old key is destroyed
   by the holder when the old cgroup went.
2. **`piggy ca csr --profile NAME`.** A PKCS#10 request for the holder
   key (CN = the intermediate profile's CN, no SAN, FDR 0007 §"The
   issuance verbs" step 2), signed ECDSA-SHA256 through the holder
   agent's ordinary sign request: the agent hashes the
   CertificationRequestInfo with SHA-256 (`prepare_sign_data`), the card
   signs, the SSH signature is reframed to DER (`ecdsa_sig`). No new
   agent extension. The CSR is public data and travels to the operator's
   machine as a file (transport is circus's).
3. **The certificate's home.** An option (working name
   `services.piggy-ca.intermediateCertFile`) where the operator puts the
   card-signed PEM; the unit reads it; nothing in piggy fetches it.
4. **Health.** A `piggy health` point "intermediate: present, matches the
   holder key, within validity"; FAIL with "no intermediate" after any
   restart until the operator signs again. This is the visible re-mint.
5. **Tests.** Unit: the CSR builder over a fake signer (DER shape,
   signature verifies with p256). bats over fibby: a holder with the
   `cgroup:` scope under a staged `--cgroup-root`, a mint from inside the
   staged cgroup, `piggy ca csr` verified by `openssl req -verify`. VM:
   extend `vm-piggy-holder` or a sibling lane with `piggy-ca.service`.

### (iii-b): after phase (ii)

- `piggy ca issue --profile NAME < leaf.csr` with the issuer being the
  holder key (signer = the agent-sign seam of (iii-a) step 2), the
  leaf's `notAfter` capped by the intermediate's.
- The renewal path the proxy host calls; the rate limit; the audit line.

## Rulings from the design owner (piggy/green-larch, 2026-11-18, 22:00Z)

The (iii-a)/(iii-b) split is accepted. Answers to the questions asked:

1. **Slot of the intermediate: 9A** in v1. RFC 0012's sixth amendment
   (on green-larch, merging) keys the TBSCertificate refusal of §2.7 on
   the key's CA slot (82), so a holder key in 9A is outside it, and FDR
   0007 already says no guard is needed when the issuance unit is the
   sole client. **The guard does not apply to holder keys; the only gate
   is the cgroup binding.** Revisit if a frontend mint-for-unit ever
   exists. Reversible, so ruled by the design owner; the operator may
   object through them.
2. **P-256 only** (FDR 0007 issues only P-256).
3. **#391 is unowned** as far as green-larch knows; they are asking the
   coordinator. Until then `piggy ca csr --profile NAME` goes under a
   `piggy ca` tree whose subcommand module stays separate, so phase (ii)
   adds `root-cert`, `sign` and `issue` beside it without conflict.
4. **The certificate's home is a path option** on the module; health is
   the visible state.
5. **`piggy-ca-intermediate-v1`** is fine (an opaque string).

**After a unit restart** (stated here because FDR 0007 lists it as
visible): the old intermediate key is destroyed with the unit's cgroup
and a new one is minted at start; the certificate file at the path
option still names the old key, so `piggy health` reports "no
intermediate" (present but not matching the holder key) until the
operator takes the new CSR to the card and installs the new PEM. Nothing
re-blesses silently.
