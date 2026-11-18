# FDR 0006 phase (d): implementation plan

Date: 2026-11-18. Status: a working plan for piggy#383, written after the
operator rulings recorded in `2026-11-18-fdr0006-phase-d-open-decisions.md`
section 7. Everything below that is not a ruling is this session's design
choice, marked **D**, and is open to the operator; the tracer bullet (the
first mint) is what the FDR says should inform the scope questions.

Rulings this plan builds on: slot 9A only, a random holder-kept PIN, PIN and
touch policy `never`; the scope field is a plain versioned name like
`piggy-mint-v1`, opaque and optional on the wire, with room for an
`@<format>-<data>` payload later; a sibling's retire is `not-bound-scope`;
no RFC 0011 change, no piggy-markl(7) change.

## What lands (items of piggy#383)

| Item | Where | Status |
|---|---|---|
| 1. holder agent mode, `mint@piggy`, `retire@piggy` | `piggy agent --holder …`, `crates/piggy/src/holder_ext.rs` (codec), `cmd/agent/holder.rs` | this plan |
| 2. caller binding by peer credentials and cgroup | `cmd/agent/peer.rs` | this plan |
| 3. teardown on scope exit or retire; the cap | `cmd/agent/holder.rs` watcher | this plan |
| 4. the agent honours a slot's reported PIN policy | `CachedKey::pin_policy`, `on_verified_card` | this plan |
| 5. `services.piggy-holder` NixOS module, VM lane | `nix/nixos/piggy-holder.nix`, `nix/vm-tests/holder.nix` | after 1 to 4 merge |
| 6. RFC part 2 | `docs/rfcs/0014-holder-mint-retire.md` (draft) | with 1 |

A `piggy holder mint` / `piggy holder retire` CLI (thin clients of the two
extensions, the way `piggy operator-sign` is of `operator-act@piggy`) and
the `explore-fdr0006-d` recipe come with item 1, so the hand pass has a
client.

## Design

### The scope field and scope definitions (D1, D2)

The wire carries `string scope`. Grammar of a value: a **name**, which is
an RFC 0011 `ident` (letters, digits, `-`, `_`, `/`), optionally followed
by `@` and a payload. A version-1 holder accepts a bare name and refuses a
value with a payload as `unknown-scope` with a detail saying payloads are
not defined yet; so `piggy-mint-v1` is valid today and stays valid when
`piggy-mint-v1@<format>-<data>` is defined. An empty string is "absent".

A name means nothing by itself: it names a **scope definition** in the
holder's configuration (the plan note's reading of the operator's "name
plus version": the holder's record of which cgroup or scope a mint binds
to). Until clown#244 lands, that configuration is the only mapping:

    piggy agent --holder … --scope piggy-mint-v1=caller
    piggy agent --holder … --scope piggy-ca-intermediate-v1=cgroup:/system.slice/piggy-ca.service

Two rules exist in version 1:

- `caller`: the mint binds to the calling connection's own cgroup, read
  from the peer (section below). This is the FDR acceptance flow: a
  session mints for itself.
- `cgroup:<absolute path>`: the mint binds to that cgroup. This is the
  unit-bound key FDR 0007 phase (iii) needs (the intermediate bound to the
  issuance unit); the caller must itself be inside that cgroup (D3).

A mint with no scope is refused `scope-unbound` (the plan note's reading:
without clown#244 the holder infers nothing). A name with no definition is
`unknown-scope`.

### Binding and who may do what (D3)

A binding is a cgroup path. A peer is **in** a binding when its cgroup is
that path or a descendant of it (path-component prefix, never a string
prefix: `/a/b` is not inside `/a/bc`). The caller must be in the binding to
mint (so no process mints for a scope it is not in: FDR 0006 "may not
mint for another scope"), to sign with the key, and to retire it. A
request from any other peer is `not-bound-scope`, for sign and retire
alike (ruled). A frontend-scope peer minting for a unit it is not in is
phase (e)'s and FDR 0007 (iii)'s to add; it is not in version 1.

### Reading the peer (D4; answers the two "unverified" items)

- ssh-agent-lib 0.5.2 exposes the accepted socket: `Agent::new_session`
  takes `&UnixStream` (`cmd/agent/listener.rs`), and tokio's
  `UnixStream::peer_cred` gives uid, gid and pid (`SO_PEERCRED`).
- The cgroup is read through a `/proc/<pid>` directory descriptor opened in
  `new_session`, right after accept, and `cgroup` is read with `openat` on
  it. Once the process the descriptor was opened on exits, reads through
  it fail, so a pid reused after that point cannot be misread as the peer.
  The remaining window is accept-to-open, documented as a limitation; a
  pidfd adds nothing over the proc descriptor for this read.
- A peer whose credentials or cgroup cannot be read gets every holder
  operation refused (`peer-unknown`); listing is unaffected. The format
  read is cgroup v2 (`0::/path`); a v1-only line is `peer-unknown`.

### Mint, cap, PIN (D6; rulings on slot and PIN)

1. Check the peer, the scope, and the cap (16 live bindings per holder;
   beyond it `cap-reached`, its own status so a caller can retry after a
   retire).
2. `create alg=<ed25519|p256> pin=never touch=never <reader>` over fibby's
   control socket (phase (c)); the reader name is `piggy-holder <n>`.
3. Connect to the new reader over PC/SC, read slot 9A, change the PIN from
   the factory default to 8 random characters, and cache that PIN in the
   agent's guarded PIN cache keyed by the card's GUID. The caller never
   sees it. (The slot's policy is `never`, so no PIN is needed to sign;
   the random PIN keeps anything else on the card from being unlocked
   with the factory default.)
4. Record the binding (key, GUID, reader, cgroup) and add the key to the
   served set with comment `holder:<reader>`; answer with the public key
   blob and the reader name.

`retire@piggy` names the key; from a peer in the binding it destroys the
card (`destroy <reader>`), forgets the PIN and drops the key.

### Teardown (D5)

A watcher task polls, every `--scope-poll-interval` seconds (default 2),
whether each binding's cgroup directory still exists under
`--cgroup-root` (default `/sys/fs/cgroup`); one that is gone is torn down
exactly as a retire is. The root is a flag so the bats lane can stage a
cgroup tree in a temporary directory; it is not a test flag, it is where
cgroup2 is mounted.

### The agent honours the PIN policy (item 4, D7)

`CachedKey` gains `pin_policy: Option<PinPolicy>`. For a key the holder
minted it is `Never` by construction. For a key loaded from a card it is
read once per (card, slot, public key) from the slot's attestation and
memoized for the life of the process, so a real card pays one ATTEST per
slot, not one per reconcile tick. `on_verified_card` then skips the PIN
for slot 9E (as today) and for any slot whose policy is `Never`; everything
else behaves as before.

### Wire format (RFC 0014 draft)

Encoding as RFC 0012 §1. `mint@piggy` request contents: `uint32 version=1;
string scope; string key_type ("ssh-ed25519" | "ecdsa-sha2-nistp256");
uint32 flags=0`. Response: `uint32 version; uint32 status; string key (the
ssh public key blob, empty unless status 0); string card (the reader
name); string detail`. `retire@piggy` request: `uint32 version; string key;
uint32 flags`. Response: `uint32 version; uint32 status; string detail`.
One status table serves both: 0 `ok`, 1 `no-such-key`, 2 `not-bound-scope`,
3 `unknown-scope`, 4 `scope-unbound`, 5 `cap-reached`, 6 `refused-key-type`,
7 `bad-request`, 8 `error`, 9 `peer-unknown`. An agent that is not a
holder does not advertise the extensions and answers
`SSH_AGENT_EXTENSION_FAILURE`, which a caller reads as "not a holder".

## Tests

- Unit: the codec (round trips, every `bad-request` cut), the scope
  grammar (bare name accepted, payload refused, bad characters refused),
  binding containment, the peer cgroup parser, the holder's decisions
  over a fake peer and a fake control socket (mint, sibling sign refused,
  sibling retire refused, cap, teardown when the cgroup directory goes),
  and the PIN-policy skip.
- bats over fibby (`test-bats-conformance-holder-mint-fibby`): a holder
  agent over a yk5.7 fibby with `--scope piggy-mint-v1=caller` and
  `--cgroup-root` pointed at a staged directory; mint from the test (its
  own cgroup), list, sign with `ssh-keygen -Y sign`, verify; an unknown
  scope and a scope with a payload refused; retire; a mint whose cgroup
  directory is removed is torn down. A sibling scope needs a second
  cgroup, which the sandbox cannot make: that is the explore recipe's and
  the VM lane's.
- `explore-fdr0006-d`: on a systemd host, `systemd-run --user --scope` for
  the bound and the sibling scope; the acceptance list of the FDR.

## Commit sequence

1. this plan
2. `holder_ext.rs`: codec, status table, scope grammar
3. `cmd/agent/peer.rs`: peer credentials, cgroup read, containment
4. item 4: `pin_policy` on `CachedKey`, honoured by `on_verified_card`
5. `cmd/agent/holder.rs` + the `--holder` flags + the extension handlers
   + the sign gate + the watcher
6. `piggy holder mint|retire`, piggy(1)
7. the bats lane, the just recipe, piggy-agent(1) HOLDER MODE,
   piggy-testing(7)
8. `explore-fdr0006-d`
9. RFC 0014 draft, FDR 0006 "as built", piggy#26
10. `services.piggy-holder` and the VM lane (a later merge)

## Open for the operator (not blocking)

- Whether `caller` and `cgroup:` are the right first two scope rules, and
  whether a frontend peer may mint for a `cgroup:` scope it is not in.
- The reader name shape `piggy-holder <n>` and the key comment
  `holder:<reader>`.
