# #289 Phase 5 precondition: inventory of C pivy in the justfile and bats

Status: inventory only (2026-10-25), not work. Phase 5 starts only when all
its preconditions hold: #285 done (landed in 58dd3fb), the post-Phase-4
soak recorded by the operator, #272–#278 closed or triaged, and this
inventory. Line numbers are of `justfile` at 5ecfed0 and drift.

48 recipes run C pivy in their body (comment-only mentions excluded). 13 of
them are in the merge gate (`test`, directly or via
`_test-conformance-linux-only`).

## (a) Oracle capture — 9 recipes, keep until the C build goes

C runs only when re-recording frozen fixtures (piggy#285); the replay lanes
run no C. At Phase 5 these become dead with the C build: delete
`codemod-capture-pivy-oracle-*`, the capture branch of `_lane-pivy-oracle`
/ `_lane-tool-fibby`, and the capture half of `lib/pivy_oracle.bash`
(the fixtures stay as the frozen contract).

- `codemod-capture-pivy-oracle-box` (227) — the offline oracle-box corpus
- `_lane-tool-fibby` (649), `_lane-pivy-oracle` (732)
- `codemod-capture-pivy-oracle-{box-interop,tool,tool-pin,tool-factory-reset,tool-admin,tool-keys}-fibby`

## (b) Harness helpers — 12 recipes (11 in the gate), substitute before Phase 5

C is a fixture, not the subject; each has a piggy equivalent.

GUID discovery or card checks with `pivy-tool` → `piggy tool -j list` /
`piggy tool set-admin`:

| Recipe (line) | C use | Bats |
|---|---|---|
| test-bats-conformance-box-agentless-fibby (498) | `pivy-tool list` GUID (523), `.#pivy` on PATH | piggy_box_decrypt_agentless.bats |
| debug-box-agentless-fibby-nosandbox (565, debug) | same (590) | same |
| test-bats-conformance-show-batch-fibby (924) | `pivy-tool list` GUID (947) | piggy_pass_show_batch_hardware.bats |
| test-bats-conformance-secrets-reconcile-fibby (976) | `pivy-tool list` GUID (998) | piggy_secrets_reconcile_fibby.bats |
| test-bats-conformance-init-fibby (897) | `PIVY_TOOL` → GUID in the bats (106–111) | piggy_pass_init_fibby.bats |
| test-bats-conformance-card-init-fibby (1324) | `PIVY_TOOL set-admin` proves the recovered mgmt key (348, 380, 389) | piggy_card_init_fibby.bats |
| test-bats-conformance-recipients-add-attached-fibby (854) | dead `.#pivy` build (857–858) | — |
| test-rust-integration-fibby (1738) | dead `.#pivy` build (1741–1742) | — |

`pivy-agent` as the agent fixture → `piggy agent -A -D -a <sock>` (already
used by `lib/operator_act.bash` and the pin-on-demand lane); the shared
launcher is `lib/fibby.bash:126`:

| Recipe (line) | Bats |
|---|---|
| test-bats-conformance-piggy-ssh-via-fibby (1056) | piggy_ssh_via_fibby.bats (gate at 37) |
| test-bats-conformance-age-plugin-piggy (1210) | age_plugin_piggy_fibby.bats (31) |
| test-bats-conformance-recipients-sync-fibby (1449) | piggy_recipients_sync_fibby.bats (47) |
| test-bats-conformance-pass-ls-recipients-fibby (1472) | piggy_pass_ls_recipients_fibby.bats (35) |

## (c) C-self tests — 4 recipes, delete with the C build

| Recipe (line) | Aggregate | What it tests |
|---|---|---|
| test-bats-conformance (436) | `test` | the conformance glob; on Linux it builds `.#pivy` (449) only for pivy_tool_admin_key.bats (C's `-K default` parsing) |
| test-bats-conformance-fibby-pivy-agent-smoke (1027) | `_test-conformance-linux-only` | pivy-agent against fibby (piggy_fibby_pivy_agent_smoke.bats); no piggy-side assertion |
| test-bats-conformance-pivy-agent-hardware (1493) | `test-optional` | pivy_agent_hardware.bats, real card |
| explore-pivy-tool-bats (3022) | none | pivy_tool_admin_key.bats; greps the piggy wrapper for a pivy path, likely broken since Phase 4 (I, unverified) |

## (d) Debug / explore — 23 recipes, delete or port with the C build

None is in the gate except `verify-fib` (2837, under `verify`). Direct:
debug-interop-stream-bytes, explore-darwin-fibby-csock, debug-pcsclite-opens,
debug-pcsclite-linkage, verify-fib, debug-fib-pivy-trace,
explore-rust-card-unlock-hw, debug-list-piv-cards, debug-lock-contention-probe,
debug-yk-throwaway-reset, debug-yk-throwaway-import-rfc6979,
debug-fibby-pivy-agent-smoke, debug-fibby-slot-9a-sign, debug-ssh-via-fibby,
debug-ssh-decrypt-via-fibby, debug-fibby-slot-9c-sign, debug-fibby-generate,
debug-tool-list-capture. Via helper scripts
(`helpers/fibby-roundtrip.sh`, `helpers/fibby-piggy-roundtrip.sh`):
debug-fibby-roundtrip and its -capture, -capture-test-vector and -via-fib
wrappers, debug-fibby-piggy-roundtrip. `helpers/piggy-throwaway-guard.sh
--probe` and `explore/explore_local_guid_pcsc.bats` also run C.

## Suggested order (proposal)

1. Pre-Phase-5 and C-free in effect: drop the two dead `.#pivy` builds;
   swap the 5 GUID lookups and the card-init admin check to `piggy tool`;
   point the 4 agent-fixture lanes (and `lib/fibby.bash`) at `piggy agent`.
   After this the gate runs no C except the C-self tests.
2. Phase 5 proper: delete the C-self tests and C-dependent debug/explore
   recipes (or port the useful ones to piggy), then the capture paths, then
   the C build and `.#pivy`.
