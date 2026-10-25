# #289 Phase 5 precondition: inventory of C pivy in the justfile and bats

Status: inventory only (2026-10-25), not work. Phase 5 starts only when all
its preconditions hold. Precondition state, 2026-10-25:
- #285: done (58dd3fb).
- The post-Phase-4 soak: recorded clean by the operator on #289.
- #272–#278: triaged by the operator.
  - #277 and #278 closed.
  - #274 kept open for Ed25519 (RSA never).
  - #276 kept open for AES management keys. That is a real gap for
    YubiKey 5.7+ cards, so it still blocks.
  - #272, #273 and #275 to close once their per-op follow-ups are filed.
- This inventory: written; the coordinator still has to check it.

Line numbers are of `justfile` at 5ecfed0 and drift. "What each C
deletion needs", below, is the one-page view.

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

### Progress (2026-10-25)

Substituted, nothing of the C stack deleted: the two dead builds
(f1b8dc5), the five GUID lookups (3e69f3a), the four agent-fixture lanes
(10d0584). Kept until Phase 5 by coordinator decision:
test-bats-conformance-card-init-fibby's `pivy-tool set-admin` proof of the
recovered management key. A piggy swap would have piggy confirm its own
key (management-key territory). It **needs an independent check before
deletion**; candidate: a frozen C-recorded authentication transcript
replayed against piggy's key, decided with the operator.

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

## What each C deletion needs

One row per thing Phase 5 deletes. A deletion is ready when its "needs"
column is met.

| Delete | Needs first | Coverage it removes |
|---|---|---|
| card-init's `pivy-tool set-admin` proof (test-bats-conformance-card-init-fibby) | an independent check of the recovered management key: candidate, a frozen C-recorded mgmt-key auth transcript replayed against piggy's key (operator decision) | C confirming piggy's recovered mgmt key authenticates |
| pivy_tool_admin_key.bats and its `.#pivy` use in test-bats-conformance | nothing (C-self) | C pivy-tool's own `-K default` parsing |
| piggy_fibby_pivy_agent_smoke.bats + its recipe | nothing (C-self) | C pivy-agent against fibby (identities, 9A/9C sign, rebox) |
| pivy_agent_hardware.bats + test-bats-conformance-pivy-agent-hardware | nothing (C-self, card lane) | C pivy-agent on a real card |
| explore-pivy-tool-bats | nothing (likely already broken since Phase 4, I) | none |
| the 23 debug/explore recipes and the helper scripts (fibby-roundtrip.sh, fibby-piggy-roundtrip.sh, piggy-throwaway-guard.sh `--probe`) | per recipe: port it to piggy if it is still a useful dev loop, else delete. `debug-yk-throwaway-*` and `piggy-throwaway-guard.sh` guard real throwaway cards, so they need piggy equivalents before deletion | debugging conveniences only |
| the oracle capture paths (`codemod-capture-pivy-oracle-*`, the capture branch of `_lane-pivy-oracle` / `_lane-tool-fibby`, the capture half of lib/pivy_oracle.bash, codemod-capture-pivy-oracle-box) | nothing; the frozen fixtures stay as the contract | the ability to re-record C's answers (a deliberate contract change would need the C build back) |
| `piggy pivy <tool>` passthrough (`exec::exec_pivy`) | nothing (already finds no `pivy-*` on PATH since Phase 4) | none for users (the soak recorded no use of it) |
| the C build: vendor/pivy, nix/pivy.nix, `.#pivy`, lint-closure-no-pivy's subject | everything above | — |

## Coverage already removed (for the soak record to weigh)

- 58dd3fb (#285): the live-C decrypt of a freshly encrypted ebox
  (piggy_box_decrypt_interop.bats); the oracle-box corpus covers
  capture-time eboxes, the RFC 0002 vectors pin the encoder.
- 58dd3fb (#285): the C pivy-agent baseline of the pin-on-demand lane
  (it compared nothing against piggy).
- 10d0584: the four agent-fixture lanes no longer show, incidentally, that
  piggy decrypts through the C pivy-agent (ssh-via-fibby's forwarded path
  included); they exercise `piggy agent`.

## Suggested order (proposal)

1. Pre-Phase-5 and C-free in effect: drop the two dead `.#pivy` builds;
   swap the 5 GUID lookups and the card-init admin check to `piggy tool`;
   point the 4 agent-fixture lanes (and `lib/fibby.bash`) at `piggy agent`.
   After this the gate runs no C except the C-self tests.
2. Phase 5 proper: delete the C-self tests and C-dependent debug/explore
   recipes (or port the useful ones to piggy), then the capture paths, then
   the C build and `.#pivy`.
