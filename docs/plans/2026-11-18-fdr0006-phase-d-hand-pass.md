# FDR 0006 phase (d) hand pass: the operator's tick sheet (piggy#383)

Date: 2026-11-18. Status: a working note for one hand pass, written from
the recipe, the manpages and the lanes, **before the recipe had been run
on a systemd host**. Where a line says "expect", it is what those sources
promise; correct it from the first real run. The operator closes #383
after this pass (FDR 0006 "Phase acceptance").

## What runs

| Step | Command | Needs | Time |
|---|---|---|---|
| staged hand pass | `just explore-fdr0006-d` (or `NO_SHELL=1 just explore-fdr0006-d` unattended) | a systemd user session (`systemd-run --user`), no card, no PIN | two nix builds, then under a minute |
| the same under the shipped units | `just test-vm-holder` (the `vm-piggy-holder` lane) | Linux, TCG | 2 to 3 minutes once cached |
| the everyday gate | `just test-bats-conformance-holder-mint-fibby` | fibby test double | under a minute |

Nothing here touches a real card: every key is on a virtual card inside
the fibby **holder build**; the askpass safety net is set with no PIN to
supply, so a PIN prompt anywhere is a failure, not a question.

## 1. UX review (read, tick when nothing misleads)

- `piggy agent --help`: the `--holder`, `--holder-fibby-ctl`, `--scope`,
  `--cgroup-root`, `--scope-poll-interval` entries.
- `piggy holder --help`, `piggy holder mint --help`, `piggy holder retire
  --help`.
- piggy-agent(1) HOLDER MODE; piggy(1) `holder mint` and `holder retire`;
  piggy-testing(7) FIBBY (the lane) and VM LANES (`holder.nix`).
- RFC 0014 (draft): the status table reads as the refusals you would
  want at 2am.

## 2. CLI review (the recipe's TAP lines; expect every one `ok`)

`just explore-fdr0006-d` prints TAP-14. Expected lines, in order:

1. `holder fibby reports profile holder`: the holder build, not the
   test double.
2. `a mint naming no scope is refused scope-unbound`: `piggy holder
   mint` with no `--scope`, exit 1, stderr names `scope-unbound`.
3. `a mint naming an undefined scope is refused unknown-scope`: the
   stderr also lists the defined scope (`piggy-mint-v1`).
4. `bound scope: minted two keys, signed and verified with one, retired
   it`: inside a transient user scope, two `piggy holder mint --scope
   piggy-mint-v1`, an `ssh-keygen -Y sign` with the first key with **no
   PIN prompt**, `ssh-keygen -Y verify` good, `piggy holder retire` of
   that key.
5. `bound scope: the retired card is gone, the other stays`: `fibby ctl
   list` shows `piggy-holder 2` and not `piggy-holder 1`.
6. `sibling scope: a sign with the bound key is refused`: a second
   transient scope, same user, cannot sign with the remaining key.
7. `sibling scope: the refusal names not-bound-scope in the agent log`.
8. `sibling scope: a retire of the bound key is refused not-bound-scope`.
9. `scope exit: the remaining card was destroyed by the holder`: the
   bound scope is let go; within the poll interval the card is gone.
10. `scope exit: the agent log says the scope exited`.
11. `scope exit: the key is no longer listed`.

Then the recipe drops you in a shell (unless `NO_SHELL=1`) with
`$PIGGY`, `$FIBBY`, `$FIBBY_CTL` and `SSH_AUTH_SOCK` set. Things worth
typing there:

    systemd-run --user --scope "$PIGGY" holder mint --scope piggy-mint-v1
    ssh-add -L                       # the key, comment holder:piggy-holder N
    "$FIBBY" ctl --socket "$FIBBY_CTL" list
    "$PIGGY" holder mint --scope piggy-mint-v1@anything   # unknown-scope: the value is opaque
    "$PIGGY" holder mint --scope piggy-mint-v1 --type rsa  # exit 2, usage
    cat "$FDR6D_DIR/agent.log"       # one "holder: minted a key" line per mint, with scope and cgroup

Judge the wording of every refusal: it should say what to do next
(name a scope, retire a card) and never leak a PIN or a key.

## 3. QA (break it on purpose)

- **The cap.** Mint 16 keys from one scope (a loop in the shell); the
  17th is `cap-reached`; retire one; the next mint succeeds. (The bats
  lane does this automatically.)
- **No PIN, ever.** `ssh-keygen -Y sign` with a minted key must never
  raise a prompt; if a `piggy PIV PIN` dialog or the safety net's
  "REFUSING to prompt" line appears, that is a failure.
- **The factory PIN is gone.** `PCSCLITE_CSOCK_NAME=… piggy tool -g <guid>
  -P 123456 -P 654321 change-pin` against a minted card fails.
- **A half-minted card never lingers.** Kill fibby mid-mint (or point
  `--holder-fibby-ctl` at a dead socket): the mint is `error`, `fibby ctl
  list` shows no stray card, and the next mint works once fibby is back.
- **Holder restart.** `kill` the agent and start it again: every minted
  key is gone from `ssh-add -L`; sessions mint again. That is the design
  (no durable keys before phase (g)).
- **Peer unknown.** Not reproducible on an ordinary host; the lane
  covers the parse. On a host with `hidepid` on `/proc`, every mint is
  `peer-unknown`, which is the documented limitation.

## 4. End-to-end (the shipped units)

`just test-vm-holder` boots a guest with `services.piggy-holder` enabled
(holder build, scope `piggy-mint-v1 = caller`, `clientGroup = users`)
and plays the same story with transient **system** services as the
sessions. Read its driver log for:

- both units unprivileged (`CapEff` all zero, `NoNewPrivs`), non-dumpable
  (`/proc/<pid>/environ` owned by root), core limit 0, each under its own
  account;
- fibby's sockets unreachable to the session user, reachable to the
  holder agent;
- the bound service's mint, sign, verify and retire; the sibling's
  `not-bound-scope`; the card destroyed when the bound service exits;
- `scope-unbound` and `unknown-scope` creating no card.

On a real NixOS host the same module is `nixosModules.piggy-holder`;
`journalctl -u piggy-holder -u fibby-holder` is where the unit logs are.

## Reporting back

Per section (1 to 4): pass, fail or skipped, plus one line; name the TAP
line numbers that failed. Comment on piggy#383 with the host, the fibby
build profile the recipe printed, and what was sent back; the operator
closes #383.
