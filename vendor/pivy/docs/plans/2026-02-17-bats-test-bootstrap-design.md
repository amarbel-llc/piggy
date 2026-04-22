# BATS Test Infrastructure Bootstrap

## Goal

Add CLI smoke tests for pivy binaries using bats + batman, with sandcastle
isolation. No PIV hardware required for phase 1.

## Test Scope (Phase 1)

For pivy-tool, pivy-agent, pivy-box:
- No-args prints usage to stderr, exits non-zero
- `pivy-tool version` prints version string, exits 0
- Bad subcommand/option exits non-zero

## Directory Layout

```
zz-tests_bats/
  justfile
  common.bash
  bin/run-sandcastle-bats.bash
  pivy_tool.bats
  pivy_agent.bats
  pivy_box.bats
```

## Flake Changes

Add batman and sandcastle inputs. Add bats, bats-libs, sandcastle, just, gum
to devShell.

## Justfile Wiring

Root justfile delegates `test-bats` to `zz-tests_bats/test`. PATH includes
`./result/bin` from nix build output.

## Virtual PIV (Future)

Defer to phase 2. Options: virt_cacard + vpcd for realistic PCSC, or mock
libpcsclite for simpler but fragile testing.
