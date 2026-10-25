# piggy card-session runbook (2026-10-25)

Every open piggy item that needs a real card, a display, a Mac, or the
operator, ordered so one sitting clears the most. Card work is grouped by
card: the operator's own card first (nothing destructive), then a
throwaway YubiKey (destructive steps allowed), then the Mac. Items that
are only a decision are listed last.

Labels: **V** checked this session (recipe exists, code read, test run),
**R** read in the issue, **I** inferred. Durations are unknown unless
stated; none was measured.

Recipes named here exist in the justfile (V, checked by name). Never type
the operator's real PIN into a recipe that takes `pin=`; those are for
throwaways only.

## 0. Before the cards come out (no card)

| Step | Command | Check | If it fails |
|---|---|---|---|
| 0.1 Deploy the bump | per `docs/plans/2026-10-25-piggy-bump-review.md` | that doc's per-row checks | repin `b7fac300c0` |
| 0.2 Identify cards | `just debug-list-piv-cards` (read-only, no PIN; V) | GUID, slots and serial of every card; note which are allowlisted throwaways (`PIGGY_TEST_THROWAWAY_GUIDS` / `_SERIALS`) | `just debug-pcsc-env` (read-only survey) |
| 0.3 Health | `just explore-piggy-health` | all points ok; the bump's upstream point shows `up_since` | read the failing point's diag |

## 1. The operator's own card (no destructive step)

| # | Item | Command | Needs | Check after | If it fails |
|---|---|---|---|---|---|
| 1.1 | #303 item 1 and the RFC 0012 §2.6 checks (input hold, 100-column wrap, 24-line limit from #322, bold markl-id leads) | `just explore-fdr0006-a CARD=real PROMPTS=gtk`, then the printed checklist; `piggy operator-sign --namespace piggy-quote-v1 …` with a short text, a 100-column text and a 25-line text | GUI session; the card's 9C at PIN always / touch always | keys ignored for 2 s; text wraps at 100 columns and fits the screen; a 25-line text is refused with the limit named; the sshsig verifies with `ssh-keygen -Y verify` | note which check; the act is refused or cancelled, nothing is signed |
| 1.2 | #306 routine prompt on zenity (closed in code, never seen on a screen) | same shell, `PIGGY_ASKPASS_GTK=0 piggy pass show <entry>` | a store entry | the context line shows `PIV_slot_9D` with its underscores | reopen #306 with a screenshot |
| 1.3 | #317 item 2: the pass should use the packaged askpass | in the 1.1 shell, `echo $SSH_ASKPASS` | | R: it is `contrib/piggy-askpass.sh` (unwrapped). Note the zenity version shown | record it on #317; no card risk |
| 1.4 | #303 item 4, real-card operator act (failed on eb98190, fixed by afa8d88 in a single run) | in the 1.1 shell: `piggy operator-sign` naming 9C, approve; repeat naming 9A | the card's 9C key | 9C signs and verifies; 9A is refused ("PIN once, touch never") | exit 4 "not touched": re-run once; if it repeats, capture `RUST_LOG` and stop |
| 1.5 | Bump checks that want the card | per bump review rows 3, 4, 6, 7 | | as written there | repin |

## 2. A throwaway YubiKey (destructive steps allowed)

Run `just debug-list-piv-cards` again and confirm the GUID is on the
throwaway allowlist before every destructive step.

| # | Item | Command | Destructive? | Check after | If it fails |
|---|---|---|---|---|---|
| 2.1 | #323 / #325: `card add-key 9c` with the agent running (#325 is closed; whether its fix cures #323 is unconfirmed, I) | with `piggy agent` running and signing: `printf 'y\n' \| setsid -w piggy card add-key 9c --guid <GUID>`; then the same with `--replace` | yes: replaces 9C | key and certificate written, no `SW=0x6d00` | stop the agent and retry once to confirm the theory; attach the output to #323 |
| 2.2 | #324: touch request has no notification | during 2.1, watch for a desktop notice when it asks for a touch | no | R: today none appears (product gap, not fixed) | note on #324 |
| 2.3 | #303 item 4, throwaway half (NOT RUN in the pass) | `just debug-yk-throwaway-reset` (YK4 only, allowlisted; V), then `piggy card init --guid <GUID>`, `just explore-piggy-health`, `piggy card export-attestation …` | yes: factory reset | health shows 9A PIN once / touch cached and 9C PIN always / touch always; the attestation chain verifies to the Yubico root | the step that failed, with its stderr, on #303 |
| 2.4 | #43 / #28 vendored-pivy xlen patch (C pivy is test-only since #289 Phase 4, I: may be moot, see decisions) | `nix build .#pivy`, then `pivy-tool list`, `pivy-tool -d list` (look for `xlen_sw`), `pivy-tool -K default sign 9d …` | no (sign uses a PIN retry) | `xlen_sw` absent on a happy enumeration | `xlen_sw` present: record on #28 as a blocker |
| 2.5 | #133 ATR captures (needs a YubiKey 5 and a 5.7+) | per card: `just debug-pcsc-env`, then `FIBBY_KEEP_LOGS=crates/fibby/tests/fixtures/captures/yubikey just debug-fibby-proxy pivy-tool list` | no | the wire log has `card_atr` | R: about 2 minutes per capture |
| 2.6 | Rust card unlock on hardware | `just explore-rust-card-unlock-hw guid=<GUID> pin=<throwaway PIN>` | one PIN verify | the integration test passes | a wrong PIN costs a retry; stop after one |
| 2.7 | C pivy-agent hardware lane | `just test-bats-conformance-pivy-agent-hardware` | no (PIN-free listing) | bats all ok | the failing test's output |

Not card-ready yet: #292 (`piggy tool pinfo` on a PIN-gated real card)
has no code for the PIN retry; it needs implementing first (fibby can
model a PIN-gated PINFO, R), then one `piggy tool pinfo` on a real card.

## 3. On a Mac

| # | Item | What to do | Needs |
|---|---|---|---|
| 3.1 | #168 flaky `k_default_version_prints_version` under full `just` | run `just` a few times on darwin; capture any failure | Mac; R: never reproduced in isolation |
| 3.2 | #208 askpass reattach tests skip on darwin | run `just test-bats-file zz-tests_bats/conformance/piggy_askpass.bats`; confirm the two skips and their reason | Mac (code change follows) |
| 3.3 | #145 macOS ramdisk wiring | code change, then check `piggy pass edit` mounts an HFS ramdisk | Mac |
| 3.4 | #18 / #156 fibby on darwin | the `explore-darwin-*` recipes; POC first | Mac, sudo for the IFD bundle |

## 4. Decisions only (no card)

1. **#189** sandboxed `go test`: skip the two docs-reading tests in the
   sandbox (recommended), widen go-pkgs-test, or stay vet-only.
2. **#137** close as done, or also drop `go` from the devShell.
3. **#240** wait for purse-first's shared wasm init test (recommended),
   or a piggy-local build-only check now.
4. **#43 / #28**: with C pivy test-only and its deletion planned (#289
   Phase 5), is upstreaming the xlen patch still wanted? If not, close
   both and skip 2.4.
5. **#321** a GUI frontend for `card init` confirmations, and **#195**
   naming the card in PIN prompts: priority, they share the Frontend seam.
6. **#198** PIN-protected random management key as `card init`'s default,
   and **#209** exposing 9A/9D attestation certs for papi#30: schedule.

Also found while reading: #158 (an all-green `piggy health` fibby lane)
needs no card and no decision, and is queue work.
