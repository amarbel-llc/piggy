# piggy open-issue grooming, 2026-11-09 (worktree green-larch, HEAD 16c9501)
140 open issues (the brief expected ~77): DONE 27, OBSOLETE 18, DUPLICATE 4, NEEDS RULING 26, READY 49, PARKED 16; close candidates 49.

Context facts used throughout: `vendor/pivy/src` (pivy-agent.c, pivy-tool.c, pivy-box.c, ...) and `nix/pivy.nix` still exist; C is out of the runtime closure (`lint` runs `lint-closure-no-pivy`, justfile:5, :2609). C still runs in two test spots: `piggy_fibby_pivy_agent_smoke.bats` (in the Linux merge gate, justfile:353) and `pivy_tool_admin_key.bats` (`.#pivy` built at justfile:449; `REAL_PIVY_TOOL` at bats.nix:116-119). `exec_pivy` is still in exec.rs:66. The Phase 4 soak was recorded clean on #289 (2026-10-25).

| issue | title (short) | class | evidence | proposed action |
|---|---|---|---|---|
| #3 | Roadmap: Rust parity with C pivy | DONE | Plan "Current status": Phase 3 complete, Phase 4 landed; `fallback.rs` is gone | "Parity reached (Phase 3 done, Phase 4 landed); remaining C deletion is tracked in #289." |
| #68 | `pass recipients` family | DONE | #75 says "Subsumes #68"; `crates/piggy/src/recipients.rs` | "Delivered by #75 (`crates/piggy/src/recipients.rs`)." |
| #71 | Phase 1: Rust markl codec | DONE | `crates/piggy-markl` exists; umbrella #69 closed (#26) | "Landed as crates/piggy-markl; umbrella #69 closed." |
| #72 | Phase 2: piggy-ids reader/writer + RFC | DONE | `crates/piggy-ids`, `docs/rfcs/0003-piggy-ids-file-format.md` | "Landed: crates/piggy-ids + RFC 0003." |
| #73 | Phase 3: Rust ebox encrypt tracer | DONE | `piggy-box/src/recipients.rs` `template_from_recipients`; `crypt::encrypt` | "Rust-native encrypt from markl recipients is the shipped path." |
| #74 | Phase 4: `pass init` writes piggy-ids | DONE | Rust `init` handler (AGENTS.md); `piggy_pass_init_fibby.bats`; `detect-pubkey` (piggy-ids main.rs:14) | "pass init writes piggy-ids from the attached card (Rust handler)." |
| #75 | Phase 5: recipients verbs | DONE | `recipients.rs`; `t0600-recipients.bats` | "Shipped in recipients.rs." |
| #86 | classify_ssh_slot beyond P-256 | DONE | classify.rs:273-297 maps P-384 and Ed25519 (#86); RSA was ruled out (plan: EC-only) | "P-384 and Ed25519 classified (classify.rs:293-294); RSA ruled out 2026-09-22." |
| #112 | justfile verb taxonomy | DONE | No `check-*` recipes remain; `validate-*` exist (justfile:1783-1815); groups set everywhere. Group syntax uses single quotes, which just accepts | "check-* renamed to validate-*, lifecycle groups applied." |
| #116 | Sandbox pivy_tool_admin_key.bats | DONE | bats.nix:116-119 gives the lane `REAL_PIVY_TOOL` | "The sandboxed lane has REAL_PIVY_TOOL (bats.nix:116); the file goes at Phase 5 anyway." |
| #135 | fibby umbrella + SSH-bats harness | DONE | 2026-06-01 comment: "the SSH-bats harness goal is met"; 9C sign, GENERATE and attestation landed later (5516eec). Only `Model::FibPivApplet` is left | "Harness goal met; file FibPivApplet separately if still wanted." |
| #174 | HM lazy, batched secret materialization | DONE | FDR 0003 (one PIN per batch, stale skip); `nix/hm/piggy-secrets.nix` | "Delivered as FDR 0003 + the piggy-secrets HM module." |
| #179 | Recovered agent enumerates but can't sign | DONE | Adoption is gated on the sign-path probe (agent/card.rs:70, :289, :669); mod.rs:496 says presence reconcile replaces the old loop | "Adoption now gated on the sign-path probe (card.rs); #247 lifecycle landed." |
| #181 | piggy-ids holds recipient and auth ids | DONE | piggy-ids lib.rs:47-95: `is_encryption_recipient` and `is_ssh_auth`; encrypt filters through `encryption_recipients` | "Mixed-purpose files are accepted; encrypt filters to recipients (lib.rs:70-95)." |
| #183 | markl ownership moves to piggy + Go lib | DONE | `go/internal/bravo/markl`, `go/internal/delta/{agent,age}`, `rfc0002_generate_test.go`; the rename was split to #184 | "Ownership inversion and Go library landed (go/); the rename was split to #184." |
| #188 | Resume guide for #183 | DONE | Its remaining items (#8 agent, #10 age, #9 vectors) exist under go/internal/delta and go/internal/charlie | "Resume guide superseded: every listed remaining item is on master." |
| #194 | `card init --serial` provisioning | DONE | `card/init_cmd.rs` (37 `serial` refs); `piggy_card_init_fibby.bats`; #26 records a clean real-card run | "card init shipped (init_cmd.rs, fibby lanes, real-card run 2026-09-15)." |
| #215 | Agent absorbs ssh-agent-mux | DONE | 2026-07-12 comment: piggy side complete (steps 1-5); FDR 0001 accepted | "Piggy side complete (2026-07-12); FDR 0001 accepted." |
| #218 | pigpen resolver: no timeout, kind unchecked | DONE | pigpen_pointer.rs:280 calls `validate_pointer_kind`; :330-404 has the deadline (via #302) | "Timeout and kind validation landed with #302 (pigpen_pointer.rs:280, :330)." |
| #247 | Multi-card hot-swap agent epic | DONE | Children #130, #244, #245, #246 and #178 are closed; FDR 0002 exists; `fibby_hotplug_fibby.bats` | "Phases 0-4 landed; FDR 0002 records it." |
| #271 | VM lane boots the shipped HM agent module | DONE | vm-tests/agent.nix:35-45 and :247-386 run the module's units (stub-home-manager) | "agent.nix boots the module's units; reopen if the real HM nixos module is wanted." |
| #285 | Freeze the C oracle into fixtures | DONE | #26 2026-10-25: "done (58dd3fb)" | "Done in 58dd3fb." |
| #287 | lint-closure-no-pivy | DONE | justfile:5 (`lint`), :2609 | "Wired into lint at Phase 4." |
| #298 | Adopt dagnabit facade config | DONE | flake.nix:833 imports `purse-first.lib.conformistModules.dagnabit-facade` | "Adopted (flake.nix:833)." |
| #299 | pigpen for madder | DONE | Last comment: "the four remaining pieces are done" (f344117); #302 closed | "All tasks landed (f344117)." |
| #305 | bats-default not hermetic vs host pcscd | DONE | Commit 1376036; bats.nix:120; `harness_pcsc_isolation.bats`; piggy-testing(7):182-185. A stale note remains at t0800-health.bats:6 | "Fixed in 1376036; drop the stale #305 note in t0800-health.bats:6." |
| #337 | piggy-piv without OpenSSL (pigsty) | DONE | 816098d, e95ecaf, 81e5caa, e7853e5; `lint-piggy-piv-portable` in lint (justfile:2572). The wasm32 check is deferred (justfile:2567) | "Portable core gated by lint-piggy-piv-portable; the wasm32 check waits for a toolchain." |
| #18 | fib on darwin (vpcd) | OBSOLETE | fibby replaced fib as the test card (#26 Tier 15); darwin path is `docs/plans/2026-06-06-fibby-darwin-feasibility.md` and #156 | "fib is no longer the test card; darwin virtual-card work is fibby's (#156)." |
| #29 | piggy box / pivy-box interop | OBSOLETE | Plan §Phase 5 lists it for closing; template interop frozen (c626197) | "C pivy-box is test-only; interop is a frozen replay (c626197)." |
| #30 | tpl create hardware-free mode | OBSOLETE | Plan issue map: "subsumed by the Phase 2 drop" | "Subsumed by the Phase 2 drop (#165)." |
| #42 | Desk check of vendored pivy SW=6986 patch | OBSOLETE | Plan §Phase 5: #28/#42/#43 moot | "Patching the vendored C is moot; C is out of the runtime (#289)." |
| #65 | pivy paths in src/piggy.sh to XDG | OBSOLETE | `src/piggy.sh` is gone (bash path retired, #96/#97) | "src/piggy.sh no longer exists; the Rust port owns paths." |
| #67 | bats: tpl create forwards to pivy-box | OBSOLETE | Phase 2 removed the C fallback; interop lane frozen (c626197) | "No C forwarder since #165; lane is a frozen replay." |
| #78 | Rename .ebox to .pigpen | OBSOLETE | RFC 0009 decisions 1-2: `.pigpen` is a new RFC 0008 format beside `.ebox`, which stays readable | "Superseded by RFC 0009: .pigpen is a separate format, not a rename." |
| #81 | chacha20-poly1305 name collision with pivy | OBSOLETE | Plan §Phase 5 lists it for closing; RFC 0002 uses `chacha20-poly1305@piggy.amarbel.net` | "Resolved by the @piggy cipher name (RFC 0002); C side test-only." |
| #100 | macOS GHA runner exit 126 | OBSOLETE | No `.github/`; piggy-ci(7) says there is no hosted CI | "No hosted CI any more; the `|| true` fix stays (askpass.sh:228)." |
| #102 | CI against amarbel-llc/nixpkgs master | OBSOLETE | No `.github/`; pkgs now come via igloo + nixpkgs-master (flake.nix:17, :240) | "No hosted CI; nixpkgs pinning reworked via igloo (see #266)." |
| #105 | pivy-agent async ASKPASS/CONFIRM | OBSOLETE | C agent not shipped since Phase 4; plan §Phase 5 closes #105-#111 | "C pivy-agent is test-only (#289 Phase 4); the Rust agent replaces it." |
| #106 | pivy-agent usleep in poll loop | OBSOLETE | Same as #105 | Same as #105. |
| #107 | pivy-agent #105 step 3 | OBSOLETE | Same as #105 | Same as #105. |
| #109 | pivy-agent #105 step 5 | OBSOLETE | Same as #105 | Same as #105. |
| #110 | pivy-agent #105 step 6 | OBSOLETE | Same as #105 | Same as #105. |
| #111 | pivy-agent dead try_askpass bodies | OBSOLETE | Same as #105 | Same as #105. |
| #222 | conformance builds .#pivy/.#fibby serially | OBSOLETE | The `.#pivy` build serves only pivy_tool_admin_key.bats (inventory:78), deleted at Phase 5 | "Moot: the .#pivy build leaves with pivy_tool_admin_key.bats at Phase 5." |
| #288 | card-state-dump helper | OBSOLETE | Phase 3 finished without it; live-C differentials retired (58dd3fb); no helper in zz-tests_bats/helpers | "Phase 3 completed and C oracle frozen; nothing left to compare against." |
| #146 | fibby: verify 2nd keyless recipient | DUPLICATE of #147 | Needs the same multi-card harness; recipients_sync bats:26-27 points at #147 | "Folded into #147." |
| #318 | askpass input hold ~3 s | DUPLICATE of #334 | GTK holds 2 s (piggy-askpass-gtk dialog.rs:22); tty holds 2 s (askpass.sh:258); only zenity can't, which is #334 | "GTK/tty hold landed (2 s, the 2026-10-23 rule); zenity part is #334." |
| #329 | Merge-escalation text, software-key namespace | DUPLICATE of #360 | Answered in-thread 2026-10-23; #360's title "answers #332 and #329" | "Answered 2026-10-23; finalized by #360 (S5)." |
| #332 | EPIC 0001 D4 prompt texts | DUPLICATE of #360 | Same as #329 | Same as #329. |
| #13 | Review backlog (medium/low) | NEEDS RULING | Stale: `tag_to_bytes` now only in apdu.rs:367; the "remove Ed25519" item is reversed by the #343 ruling | Close as stale and refile the surviving items, or re-audit in place? |
| #76 | Hard-cutover error for .pivy-id, v2.0 | NEEDS RULING | No `.pivy-id` handling in crates/; version.env is 0.1.23 | Still want a legacy-.pivy-id refusal and a 2.0 bump, or close? |
| #99 | age recipients end-to-end | NEEDS RULING | `age_part_from_markl` still refuses (piggy-box recipients.rs:93); pigpen (RFC 0008) carries X25519 | Still want age parts in ebox now that pigpen exists? |
| #136 | batman lanes fail in dev containers | NEEDS RULING | Environmental; the diagnostic gap is upstream bats#31 | Close as environmental (upstream bats#31), or keep? |
| #144 | `sign` op metric all failures | NEEDS RULING | Data from the C-agent era; stats-me has no piggy telemetry (#26, 2026-09-22) | Close as unreproducible, or wire STATSD and re-check? |
| #155 | ebox part[0] API ergonomics | NEEDS RULING | C half moot; Rust `primary.parts.first()` still at show_batch.rs:1347 | Close as covered by #147, or review show_batch.rs:1347? |
| #161 | Explore SSH certificates | NEEDS RULING | No record covers SSH certs (FDR 0007 is X.509) | Still wanted next to FDR 0007/RFC 0013? |
| #186 | Move papi markl bits to papi | NEEDS RULING | `PurposeTypePapiSig` still in go/internal/bravo/markl/purpose_type.go | Has papi adopted go/markl so this can move? (cross-repo) |
| #187 | RFC: domain markl registrations | NEEDS RULING | Proposal in-thread (per-domain manifest); no RFC yet | Write it now, or is RFC 0011 §6 enough? |
| #196 | `piggy yk` ykman proxy | NEEDS RULING | The Rust `tool` port covers serial, reset and PIN ops; the guard already uses ykman for serial | Still wanted after the tool port? |
| #197 | JSON-RPC management API epic | NEEDS RULING | RFC 0006/0007 and `piggy manage` landed; #201 closed | Close the epic and leave #198-#203 standalone? |
| #200 | Retrofit commands onto Frontend | NEEDS RULING | Last comment proposes descoping the agent on-demand PIN and closing | Accept the descope and close? |
| #202 | charmbracelet TUI | NEEDS RULING | No activity since 2026-06; depends on #197 direction | Still the plan? |
| #203 | `pass *` migrates to papi | NEEDS RULING | 2026-06-22 north star; no piggy work since | Still the north star? |
| #205 | zenity pulls ffmpeg into closure | NEEDS RULING | zenity still a runtime dep (flake.nix:355) | Decide with #334 (drop zenity?) or split askpass into its own output? |
| #206 | PHP box package | NEEDS RULING | Downstream proof exists; nothing in piggy | Should piggy own a PHP package? |
| #211 | piggy-pigpen `wasm` feature | NEEDS RULING | Placeholder that gates no code (piggy-pigpen Cargo.toml:24-31) | Keep or remove? |
| #241 | cargo target/ never GC'd | NEEDS RULING | Cross-repo policy (igloo#61) | Adopt the igloo#61 policy here, or close? |
| #290 | fibby retired-slot seeding for keyhist | NEEDS RULING | Its C-vs-Rust read-back premise is gone (C frozen, 58dd3fb); fibby has no retired-slot seeding | Rescope to a Rust-only read-back test, or close? |
| #295 | Local agent vs forwarded agent | NEEDS RULING | #351 landed agent routing (a89ec0a, a972767); socket shadowing is a follow-up (3c6dbe8) | What does piggy owe on socket shadowing? |
| #297 | FDR 0006 placeholder | NEEDS RULING | FDR 0006 written and approved 2026-10-07; #303 tracks phase (a) | Close now, or keep as FDR 0006's phase parent? |
| #303 | FDR 0006 phase (a) | NEEDS RULING | Code done (2026-10-13); acceptance pass blocked 2026-10-19 (#319/#322/#325, now closed); throwaway-card items not run | Operator acceptance pass (FDR 0006: the operator closes it). |
| #331 | Rust-native replacement for OpenSSH PV drv | NEEDS RULING | One-line issue; "PV derivation" is unclear | What is the "PV derivation"? |
| #334 | zenity vs our own dialog | NEEDS RULING | GTK enforces the hold, zenity can't (#332 comment) | Keep zenity at all? (also decides #205, #318) |
| #339 | Extract signing/approval for XMPP apps | NEEDS RULING | `piggy act seal` (#359) is the planned reuse primitive | Is #359/RFC 0013 the answer, or separate work? |
| #346 | RFC 0008: device signing key in a pigpen | NEEDS RULING | #26 lists it as an open operator question | Answer the RFC 0008 reading. |
| #25 | README overhaul | READY | Still open per #26; not started | docs, medium |
| #51 | Shell completions for piggy | READY | `src/completion/*` are unmodified pass.org forks (body, re-scoped 2026-07-16) | docs/UX, medium |
| #53 | Agent socket activation | READY | No `LISTEN_FDS` in crates/ | agent, medium |
| #77 | piggy-ids cutover docs/bats | READY | piggy(1) still documents `.pivy-id` (piggy.1.scd:55-57, :1061-1066) | docs, small |
| #90 | Wycheproof ChaCha20 adversarial | READY | Gap as filed | hygiene, small |
| #101 | Expose a notify-send wrapper | READY | No notify output in flake.nix; `pivy-notify` dies with vendor/pivy at Phase 5 | #289 phase 5, small |
| #113 | recipients add breaks a symlinked piggy-ids | READY | `rename(tmp, piggy_ids)` at recipients.rs:136/294/361 and piggy-ids main.rs:215-217 replaces the link | store, small |
| #117 | conformance recipe vs sandbox lane | READY | `test-bats-conformance` still globs conformance/*.bats (justfile:436-466) | hygiene, small |
| #133 | fibby YK5/YK5.7 ATR capture | READY | `YK5_ATR` still a placeholder (fibby virtual_card.rs:49-52); no Yk57 (:96) | fibby, small (needs hardware) |
| #139 | piggy-test-sshd direct-tcpip smoke | READY | Gap as filed | hygiene, small |
| #145 | Wire darwin ramdisk into SecureTmpdir | READY | `darwin::new_with_env` still `#[allow(dead_code)]` (tmpdir.rs:248-249) | darwin, small |
| #147 | Multi-card fibby for re-encrypt path | READY | Referenced at recipients_sync bats:26-27; multi-card fibby exists (agent-multicard lane) | fibby, medium |
| #148 | Cross-scope symlink re-encrypts to wrong ids | READY | reencrypt.rs:112-118 still walks from the store-side path | store, small |
| #149 | cp of a symlinked ebox mutates the source | READY | copy_move.rs:248-249 still `cp -r` (no `-L`) | store, small |
| #150 | First-class agent unlock command | READY | `agent_client::unlock_agent_pin` exists (agent_client.rs:153); no CLI verb | agent, small |
| #169 | piggy-ids render --format=ssh | READY | ssh-copy-id renders offline (ssh_copy_id.rs:5-18) but nothing prints to stdout | store, small |
| #195 | Name the card in PIN prompts | READY | sign-bytes passes `CardId` with serial (sign_core.rs:130); scheduled 2026-10-25 (#321 comment) | card UX batch, small |
| #198 | PIN-protected random mgmt key | READY | engine.rs:23 "PIN-protected on-card storage is piggy#198"; scheduled 2026-10-25 | card UX batch, medium |
| #199 | Management-conformance harness | READY | `crates/card-frontend-server` is still the throwaway; #200 waits on it | manage, medium |
| #208 | askpass reattach tests on darwin | READY | Gap as filed | darwin, small |
| #209 | 9A+9D attestation export | READY | export-attestation takes only 9c/9a (attestation_cmd.rs:21-27); scheduled 2026-10-25 | card UX batch, small |
| #238 | Grammar export drags input closure | READY | jcardsim/pivapplet/oracle-javacard-sdks still top-level inputs (flake.nix:79-97) | nix hygiene, medium |
| #240 | Go wasm/js gate | READY | No GOOS=js/wasip1 anywhere in justfile/flake | hygiene (go), medium |
| #252 | jcardsim m2 closure pinned to one Maven | READY | `nix/jcardsim-m2/` still there; depends on #266 | nix hygiene, medium |
| #257 | Multi-card fibby e2e for card init selectors | READY | Gap as filed | fibby, small |
| #261 | Shared store write path | READY | Refactor as filed | store, small |
| #266 | Instantiate pkgs from igloo.inputs.nixpkgs-master | READY | flake.nix:240 still `import igloo {` | nix hygiene, small |
| #268 | VM lane for `card init` | READY | nix/vm-tests has no card-init lane | VM lanes, medium |
| #269 | Coverage merges unit + bats + VM | READY | coverage-report.nix:1-42 merges VM profraw only | VM lanes, medium |
| #274 | tool 3.4 remainder: Ed25519 generate/import | READY | 2026-10-25 triage: narrowed to Ed25519 | tool Ed25519, medium |
| #276 | tool 3.3 remainder: AES mgmt keys | READY | 2026-10-25 triage: "still a Phase 5 precondition" | #289 phase 5, large |
| #289 | Epic: retire C pivy | READY | Soak recorded clean 2026-10-25; deletions wait on #276 and the inventory check | #289 phase 5, large |
| #292 | tool pinfo PIN-gated read | READY | Gap as filed | #289 follow-ups, small |
| #293 | tool list fidelity gaps | READY | Body: tighten before C is deleted | #289 phase 5, medium |
| #308 | operator-act: pulled card reported no-such-key | READY | Ruled a follow-up; fix not confirmed | FDR 0006 (a), small |
| #309 | operator-act prompt rate limit | READY | No rate limiter in crates/piggy/src | FDR 0006 (a), small |
| #310 | FDR 0006 (a) simplify leftovers | READY | Ruled follow-ups (2026-10-13) | FDR 0006 (a), small |
| #315 | Recording fake-zenity acceptance check | READY | Gap as filed | askpass/UX, medium |
| #316 | Xvfb lane screenshots dialogs | READY | Gap as filed | askpass/UX, medium |
| #317 | [TEST] tag missing on operator-act prompts | READY | test_tag logic at askpass.sh:231-240; whether operator acts reach it is unconfirmed | askpass/UX, small |
| #321 | card init GUI frontend | READY | Scheduled 2026-10-25, GTK helper not zenity | card UX batch, medium |
| #323 | add-key 9c SW=6d00 on real YubiKey | READY | Two unconfirmed theories in-thread | card (hardware), medium |
| #324 | Touch prompt has no notification | READY | Touch text is progress only (card/engine.rs:182-188) | card UX batch, small |
| #343 | tool sign Ed25519 + fibby | READY | Operator ruled Ed25519 in scope 2026-10-25 | tool Ed25519, medium |
| #351 | GUI-less hosts: prompt on the client | READY | a89ec0a/a972767 landed; "stays open until the repro on real cards" | agent (hardware), small |
| #352 | Dedupe Java Card flake inputs | READY | flake.nix:79-97 trio; deliverable is a held patch | nix hygiene, small |
| #353 | Report default PIN (GET METADATA) | READY | No GET METADATA APDU (only a doc mention at piggy-piv policy.rs:11) | card, medium |
| #359 | RFC 0013 S4 `piggy act seal` | READY | Acts lane; next per #26 (2026-11-09) | acts (listed only) |
| #360 | RFC 0013 S5 display | READY | Acts lane | acts (listed only) |
| #26 | Sequenced work tracker | PARKED | Standing tracker (AGENTS.md "Where to start work"); title still says "updated 2026-07-22" | Keep; retitle; body's "Recommended next" (#201) is stale |
| #137 | go/ binaries via nix only | PARKED | #26 2026-10-25: "stays deferred until build-go and gofmt also run through nix" | — |
| #156 | nix-darwin vpcd module | PARKED | Body: POC paused, blocked on a non-smartcard USB device | — |
| #167 | pty tests EPERM under sandbox | PARKED | Worked around (justfile:453-466 runs `pty` tests unsandboxed); real fix is upstream fence | — |
| #168 | Flaky k_default_version + unit test | PARKED | Bats half is in pivy_tool_admin_key.bats, deleted at Phase 5 (plan §Phase 5) | Close at Phase 5 unless the unit flake recurs |
| #185 | madder delegates crypto to piggy CLI | PARKED | Body: deferred branch of #183 ("closure later") | — |
| #231 | Flaky teardown in C pivy-agent smoke | PARKED | Lane is C-self, deleted at Phase 5 (inventory:79, :107); still in the Linux gate (justfile:353) | Close at Phase 5 |
| #233 | TestIdentifierVectors spawns per vector | PARKED | Body: act only if runtime becomes a problem | — |
| #280 | piggy ca Rust rewrite | PARKED | Plan §Phase 3b: scoped once luks/zfs have real users | — |
| #282 | N-of-M recovery design | PARKED | Body: "Nothing to implement until an FDR exists" | — |
| #283 | agent --confirm | PARKED | Body: "file-and-forget until someone wants it" | — |
| #349 | Extended-APDU probe fallback | PARKED | Operator deferred 2026-10-26 | — |
| #350 | Remove LibreSSL after Phase 5 | PARKED | Body: once C pivy is gone entirely | Pick up with Phase 5 |
| #361 | RFC 0013 S6 chain walk | PARKED | Held until RFC 0013 acceptance | acts (listed only) |
| #362 | RFC 0013 S7 acceptance paperwork | PARKED | Held | acts (listed only) |
| #363 | RFC 0013 S8 consumer onboarding | PARKED | Held | acts (listed only) |

## Close list

- Done on master (27): #3, #68, #71, #72, #73, #74, #75, #86, #112, #116, #135, #174, #179, #181, #183, #188, #194, #215, #218, #247, #271, #285, #287, #298, #299, #305, #337
- C pivy stack made test-only or removed (11): #29, #42, #81, #105, #106, #107, #109, #110, #111, #222, #288
- Premise gone or superseded by another record (7): #18 (fibby), #30 (Phase 2), #65 and #67 (bash/C forwarder gone), #78 (RFC 0009), #100 and #102 (no hosted CI)
- Duplicates (4): #146 into #147, #318 into #334, #329 and #332 into #360
- Close at #289 Phase 5 (not yet): #168, #231

## Lanes (READY)

1. acts: #359, then #360
2. FDR 0006 phase (a) follow-ups: #308, #309, #310 (the acceptance pass itself, #303, is the operator's)
3. #289 phase 5: #276 (AES mgmt keys, a stated precondition), #293, #289 deletions, #101 (notify wrapper before vendor/pivy goes); follow-up #292
4. tool Ed25519: #343 (fibby sign), #274 (generate/import)
5. card UX batch, scheduled 2026-10-25: #195, #321, #324, #209, #198; also on the card: #353 (papi ask), #323 (hardware)
6. askpass/UX: #317, #315, #316
7. store correctness: #113, #148, #149, #169, #261
8. fibby: #147, #257, #133 (hardware capture)
9. agent: #150, #53, #351 (hardware repro)
10. VM lanes: #268, #269
11. manage: #199
12. nix/hygiene: #266 then #252, #352, #238, #240, #90, #117, #139
13. darwin: #145, #208
14. docs: #77 (piggy(1) still describes .pivy-id), #51, #25

Note on #26: the body's "Recommended next" is #201 Phase 2 (closed). Its latest comments recommend #359 (acts), #337 (pigsty; it looks done here) and #289 Phase 5 after the soak. Operator items it names: the RFC 0013 acceptance pass and the #303 acceptance pass.

## Unverified

- #308: I did not trace whether the post-reconcile card pull still returns no-such-key. A bats case that unplugs fibby between reconcile and request would settle it.
- #317: I did not confirm whether operator-act prompts reach the `[TEST]` branch (askpass.sh:231-240). Running operator_act_prompt.bats with a `piggy-test:` text would settle it.
- #209: does `piggy tool attest 9d` already give the 9D attestation cert? The FDR 0006 export takes only 9c/9a. A run on fibby would settle it.
- #195: what is left beyond sign-bytes' `CardId` (other PIN sites, fresh-card PIN on provision) is unconfirmed.
- #101: whether eng's home/piggy-agent.nix still references `pivy-notify` is a cross-repo check.
- #186: papi's adoption of go/markl (papi#10) is a cross-repo check.
- #323: the root cause needs the throwaway YubiKey.
- #144: no piggy telemetry on stats-me (per #26), so the metric cannot be re-checked.
- #271: judged DONE through stub-home-manager; the real home-manager NixOS module is not booted.
- #337: the wasm32 `cargo check` was not run (justfile:2567 says the devShell lacks the toolchain).
- #74 and #73: judged from the crates and lanes existing, not by reading init.rs end to end.
- #135: `Model::FibPivApplet` was never built; whether it is still wanted is open.
- Older issues whose bodies cite files that are gone: `src/piggy.sh` (#65, #68, #72, #74, #76, #77, #78), `crates/piggy/src/fallback.rs` (#3), `zz-tests_bats/helpers/mock-pivy-box.sh` (#77, #78), `piggy_box_decrypt_interop.bats` (#81).
- Issues naming pivy-agent, pivy-tool or pivy-box (#29, #42, #67, #105-#111, #116, #231): the C source is still in vendor/pivy/src. Nothing in the runtime closure calls it (lint-closure-no-pivy). It still runs in the merge gate through piggy_fibby_pivy_agent_smoke.bats (justfile:353, :1015) and pivy_tool_admin_key.bats (justfile:449, bats.nix:116-119). `piggy pivy` / `exec_pivy` (exec.rs:66) stays until Phase 5.
