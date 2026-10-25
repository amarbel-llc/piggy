# pigsty — a pigpen-backed password vault (design)

**Moved.** This design was written in piggy on 2026-10-25 and moved, text
verbatim, to the pigsty repository with its first commit (pigsty master
ac6ae89). The canonical copy is:

<https://code.linenisgreat.com/pigsty/src/branch/master/docs/plans/2026-10-25-pigsty-design.md>

What stays in piggy:

- `2026-10-25-pigsty-piggy-side.md`: the plan for what piggy owes pigsty
  (the piggy-piv `ApduTransport` seam, the `ecdh@code.linenisgreat.com`
  extension alias, piggy#335), landed on piggy master fb39229.
- `2026-10-25-pigsty-bootstrap.md`: the repo bootstrap spec the pigsty
  repo was created from.
- piggy#337: piggy-piv without OpenSSL, pigsty's phase-0 dependency in
  piggy's lane.

Layering, for anyone landing here first: `pigsty → madder → piggy`; piggy
never imports madder or pigsty, so pigsty's design decisions are made and
recorded in pigsty, not here.
