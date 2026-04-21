# `piggy tool` — scoping

Status: **scope only, no implementation**. Companion roadmap issue: #3.

## Goal

Port `pivy-tool(1)` to a native `piggy tool` Rust subcommand, then drop
`"tool"` from `PIVY_SUBCOMMANDS` in `crates/piggy/src/fallback.rs`. The
conformance contract is the pivy-tool manpage and the bats oracle at
`zz-tests_bats/conformance/pivy_tool.bats.skip` (to be ported to
`piggy_tool.bats` once the Rust impl lands).

## Command surface (from pivy-tool(1))

Grouped as in the manpage. `~` = in scope for v1, `?` = deferred, `✗` =
out of scope.

### Informational (~)

| op | notes |
|---|---|
| `list` | `-p` parseable, `-j` JSON |
| `pinfo` | decode Printed Information object |
| `pubkey <slot>` | OpenSSH format on stdout |
| `cert <slot>` | PEM on stdout |
| `version` | print `piggy` version |

### Setup

| op | v1 | notes |
|---|---|---|
| `init` | ~ | write GUID + CCC; requires admin auth |
| `setup` | ? | composite interactive; defer — user can run the pieces |

### Key management

| op | v1 | notes |
|---|---|---|
| `generate <slot>` | ~ | `-a`, `-n`, `-t`, `-i` flags; ECDSA/RSA |
| `import <slot>` | ~ | Yubico INS FE |
| `write-cert <slot>` | ~ | PUT DATA + admin auth |
| `req-cert <slot>` | ~ | build CSR via `rcgen` or manual DER |
| `delete-cert <slot>` | ~ | PUT DATA empty cert object |

### PIN and PUK (~)

| op | notes |
|---|---|
| `change-pin` | CHANGE REFERENCE DATA (INS 24, P2=0x80) |
| `change-puk` | CHANGE REFERENCE DATA (INS 24, P2=0x81) |
| `reset-pin` | RESET RETRY COUNTER (INS 2C) |
| `factory-reset` | Yubico-specific APDU |

### Administration

| op | v1 | notes |
|---|---|---|
| `set-admin` | ~ | PUT DATA Printed Information |
| `update-keyhist` | ~ | scan retired slots, rewrite Key History object |

### Cryptographic (~)

| op | notes |
|---|---|
| `sign <slot>` | stdin → sig on stdout; piggy-piv already signs |
| `ecdh <slot>` | stdin pubkey → shared secret |
| `auth <slot>` | round-trip verify against stdin pubkey |
| `attest <slot>` | YubiKey attestation cert + chain; primitive present |

### Box ops

| op | v1 | notes |
|---|---|---|
| `box [slot]` | ? | thin shim over `piggy box` — defer until `piggy box` merges |
| `unbox` | ? | same |
| `box-info` | ? | same |

### Explicitly out of scope (v1)

- Certificate templates (`-T`, `-D`) — large feature, little in-house demand.
- Kerberos PKINIT principal (`-r`) — niche.
- SunSSH, CACS — already excluded in #3's parity analysis.

## `piggy-piv` gap analysis

`piggy-piv` current API (verified today at `crates/piggy-piv/src/token.rs`):
`connect`, `enumerate_tokens`, `transmit_apdu`, `read_slot`, `read_all_slots`,
`sign_prehash`, `ecdh_derive`, `yk_attest`, `verify_pin`. Plus APDU
constructors for `select`, `get_data`, `general_authenticate`, `yk_attest`,
`verify_pin`.

What `piggy tool` needs that `piggy-piv` does **not** yet expose:

| capability | APDU | blocks |
|---|---|---|
| Admin key mutual auth (3DES / AES-128/192/256) | GENERAL AUTHENTICATE (INS 87) witness/challenge flow | every write op |
| PUT DATA | INS DB | write-cert, delete-cert, init, set-admin, update-keyhist |
| CHANGE REFERENCE DATA | INS 24 | change-pin, change-puk |
| RESET RETRY COUNTER | INS 2C | reset-pin |
| GENERATE ASYMMETRIC KEY PAIR | INS 47 + touch/PIN policy TLVs | generate |
| Yubico key IMPORT | INS FE (Yubico ext) | import |
| Yubico factory RESET | Yubico ext | factory-reset |
| Ed25519 signing | algorithm byte `0xE0` already present; sign path missing | `sign -a ed25519` |

Output-side helpers needed (not piggy-piv, but cross-cutting):

- SSH public key encode (for `pubkey`, `auth`).
- PEM wrap (for `cert`, `req-cert`).
- JSON emitter (for `list -j`).
- CSR builder (for `req-cert`) — candidate dep: `rcgen` (pure Rust, already
  transitively in the tree? — check at impl time).

## Proposed crate layout

```
crates/piggy-tool/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── cli.rs        # clap argv
    ├── info.rs       # list, pinfo, pubkey, cert, version
    ├── setup.rs      # init, set-admin, update-keyhist
    ├── keys.rs       # generate, import, write-cert, req-cert, delete-cert
    ├── pin.rs        # change-pin, change-puk, reset-pin, factory-reset
    ├── crypto.rs     # sign, ecdh, auth, attest
    ├── box_ops.rs    # box/unbox/box-info shim over piggy-box
    └── format.rs     # SSH key, PEM, JSON output
```

New `piggy-piv` modules:

```
crates/piggy-piv/src/
├── admin.rs          # AdminKey + mutual auth
├── put_data.rs       # put_data() helper
├── pin_mgmt.rs       # change_pin, change_puk, reset_pin, factory_reset
└── keygen.rs         # generate_key, import_key
```

`crates/piggy/src/cmd/tool.rs` — thin dispatcher that parses `piggy tool …`
and calls into the `piggy_tool` crate.

## Conformance strategy

The upstream `pivy_tool.bats.skip` is only 32 lines (help/usage + bad-subcommand).
That's too thin to be a safety net. Plan:

1. Port upstream tests verbatim to `piggy_tool.bats` (cheap baseline).
2. Add a mock-PC/SC harness (mirror the `mock-pivy-tool.sh` pattern already
   in `zz-tests_bats/helpers/`) so non-hardware CI can run the full matrix.
3. Add a `--hardware`-gated bats file that round-trips each write op with
   the C `pivy-tool` as the oracle — e.g. `piggy tool generate` →
   `pivy-tool pubkey` must match, and vice versa. Same gating pattern as
   `piggy_agent_protocol.bats`.
4. Wire unit tests per piggy-piv module — PIN/PUK wire format, admin-auth
   challenge/response, PUT DATA framing.

## Sequencing (merge-able milestones)

1. **Read-only ops** — `list`, `pinfo`, `pubkey`, `cert`, `version`, `attest`.
   No new piggy-piv surface except a Printed Information parser. Exercises
   `format.rs`. Good warm-up, low risk.
2. **PIN/PUK management** — piggy-piv `pin_mgmt.rs`, then `piggy tool
   change-pin|change-puk|reset-pin`. Single-APDU ops, no admin auth.
3. **Admin auth + PUT DATA** — piggy-piv `admin.rs` + `put_data.rs`. Largest
   chunk. Lands `write-cert`, `delete-cert`, `set-admin`, `update-keyhist`.
4. **Keygen / import / init / setup / factory-reset** — piggy-piv `keygen.rs`.
   Depends on step 3.
5. **Crypto ops** — `sign`, `ecdh`, `auth`. Primitives already in piggy-piv;
   mostly CLI plumbing plus a signature-verify helper for `auth`.
6. **Box ops** — `box`, `unbox`, `box-info`. Defer until `piggy box` (#3)
   lands; these are thin shims.
7. **Ed25519 signing** — small addition on top of (5).

Every milestone is independently shippable and removes nothing from
`PIVY_SUBCOMMANDS`. `"tool"` only leaves the fallback list after step 6, when
the whole surface is covered.

## Known cross-cutting risk

- If and when `piggy box` work surfaces, it will also add modules to
  `piggy-piv`. The two roadmaps touch different APDU families (ECDH/stream
  for box vs admin/PUT DATA/keygen for tool), so file-level conflicts
  should be limited to `piggy-piv/src/lib.rs` re-exports and workspace
  `Cargo.toml`. Resolvable.
- `pin_mgmt.rs` is the only piggy-piv file that both roadmaps might
  plausibly want to touch (box templates sometimes need PIN state). If
  that turns out to overlap, rebase cost is small.

## Deliverables expected once implementation starts

- `crates/piggy-tool/` as above.
- Additions to `crates/piggy-piv/src/`.
- `crates/piggy/src/cmd/tool.rs` dispatch + wire-up in `main.rs`.
- `"tool"` removed from `PIVY_SUBCOMMANDS` after step 6.
- `zz-tests_bats/conformance/piggy_tool.bats` + hardware-gated sibling.
- `pivy-tool` removed from `runtimeDeps` in `flake.nix` after step 6.
