# PIN caching for 9A, 9C and 9D (piggy#404): the options and one recommendation

Status: for the operator's decision. Docs only; nothing is built. Slots 82 and
83 are settled (never cached, built 2026-11-22); this page is about 9A, 9C
and 9D. FOUND means read in code or a manpage at origin/master `ecee09b8`;
THEORY means reasoned, not tested on a card.

## What happens today (FOUND)

- The agent keeps ONE verified PIN per card (`pins.rs`, keyed by the card's
  GUID), not per slot. The PIV PIN is the card's, so 9A, 9C and 9D share it.
  It has no time limit: it stays until the card leaves, `ssh-add -x`, a
  rejected PIN, or the agent exits (piggy-agent(1) PIN MEMORY).
- The agent presents the cached PIN to the card again on every sign and ECDH
  (`ensure_pin`). So a slot whose policy is "PIN always" does not prompt
  again after the first PIN in the agent's life: the card sees a fresh VERIFY
  each time, the operator sees nothing. Only the touch is left as the gate.
- Operator acts (`operator-act@piggy`, 9C) do NOT use the cache: they raise
  their own dialog every time (`handle_operator_act`). Plain 9C signing
  through the agent (git signing, `sign-bytes` falling back to the agent) does
  use it.
- Fresh-card policies (`slot_policy.rs`): 9A PIN once, touch cached (a few
  seconds); 9C PIN always, touch always; 9D the card's own default (THEORY:
  PIN once, no touch).

## What a holder of the forwarded socket can do, per slot

"Holder" means a process that can connect to the agent's socket (a forwarded
`SSH_AUTH_SOCK`, or any local process under the same uid). With the PIN
cached:

| slot | what they can do with no prompt | what still stops them |
|---|---|---|
| 9A | log in over ssh as the operator wherever the key is authorised | touch cached for a few seconds: one human touch lets a burst through |
| 9C | have the agent sign git commits and `sign-bytes` data as the operator; NOT an operator act (that has its own dialog) | a touch for every signature |
| 9D | decrypt any ebox they can obtain (tofu state, secrets) and any rebox | nothing, if the card's 9D needs no touch (THEORY) |

9D is the exposed one: the only thing between a socket holder and every
secret the operator can read is the cached PIN. 9C is covered by its touch,
which the operator may give believing the request is their own.

## The options

1. **Cache per slot, with a limit.** Key the cache by (card, slot) and give
   each slot its own idle time and its own hard stop.
2. **Cache only while the machine is unlocked.** Drop the PIN on screen lock
   or suspend. Cheap against a stolen laptop; useless against a socket holder
   on the unlocked machine, which is the case above.
3. **Never cache 9C and 9D, but batch.** Every sign and decrypt prompts,
   except inside a ceremony that asks once for N operations (as `piggy ca`,
   `secrets reconcile` and `pass show-batch` already hold one PIN session).
4. **Touch policy as the real gate.** Leave the cache alone and make the card
   demand a touch on 9D (and 9C already has one). Needs 9D re-generated with
   a touch policy: the key changes, so every ebox is re-encrypted.

## Cost in prompts per day

UNKNOWN for the operator in particular. stats-me carries counters (`pin_prompt`,
`sign`, `ecdh_*`, `operator_act`) with no slot label and no host label, and
they include test and fleet traffic, so they cannot be attributed to the
operator's day. The raw 30-day increases, for scale only: pin_prompt 5,876 ok
and 835 failed; sign 4,495 ok; ecdh (decrypt) 2,540 ok; operator_act 10,929.
(The last seven days: pin_prompt 3,511 ok; sign 2,648 ok; operator_act 6,191.)
To get a real number, add the slot to the agent's `pin_prompt` counter (a
half-hour change) and read a week.

Rough shape, by option (the daily count of decrypts d and 9C signs c is the
unknown): option 1 costs about one PIN per slot per idle window; option 3
costs d + c PINs per day minus whatever is batched; option 4 costs d touches.

## Recommendation

Option 1, with these values:

- **9A**: cached, as now, until the card leaves, plus a hard stop of 12 hours.
- **9D**: cached for 10 minutes since last use, hard stop 1 hour. A tofu run or
  a reconcile is one PIN; a decrypt an hour later is another.
- **9C**: never cached for an ordinary agent sign either (operator acts
  already are not). One PIN and one touch per signature; for a run of git
  commits, a ceremony of option 3 (not built, not named yet) could cover N
  signatures with one PIN.
- The PIN dialog names what a cached PIN is not: when a PIN is taken from the
  cache for 9D, the agent's log line says so (slot, age); no dialog is shown.

Why not option 4 first: it changes the key. Revisit after option 1 is
measured.

## What building it costs (estimates, not measurements)

- Worker hours: about 6 (the cache keyed by slot with the two limits, the
  per-slot counter, the manpage and a fibby lane for expiry).
- Gate runs: 3 (the build, a review round, the doc fix).
- Operator touches: about 4, on one real-card pass (a 9A login, a 9C sign, a
  9D decrypt, and a 9D decrypt after the idle window).
