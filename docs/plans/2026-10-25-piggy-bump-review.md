# piggy bump review: b7fac300c0 → origin/master

Read-only review for the fleet relock's tier 3 (operator present, card
attached). It lists each piggy commit since the locked rev that changes
what a host or a session sees, what to check on flic after the deploy,
and how to roll back. Nothing here bumps anything.

Range: `b7fac300c0..origin/master`, 28 commits, head `ba89f37` at the
time of writing; `7240d96` (age-plugin-piggy version guard) and
`bf5409a` (#239) were queued to merge and are listed at the end.

Labels: **V** observed in code or a test run this session, **R** read in
a commit message or doc, **I** inferred, to be checked on flic.

**Rollback, for every row:** pin piggy back to `b7fac300c0` in the
consuming flake's lock and redeploy. No commit here migrates on-disk
state: the store, `piggy-ids` and ebox formats are unchanged (V: no
commit in the range touches `crates/piggy-box` wire code or the
piggy-ids format), so going back is safe. The one durable side effect is
git history in a store: commits made under the new version record only
the paths each command touched (row 6), and stay that way after a
rollback.

## Behaviour a host or a session sees

| # | Commit | Change | Check on flic after the deploy | Notes |
|---|---|---|---|---|
| 1 | `3bf8cc1` (#333) | A proxy-only agent with no card answers `SSH_AGENT_FAILURE` when every upstream stays down past `--upstream-grace` (default 3 s), instead of an empty key list; a sign retries once after a dropped upstream connection; `piggy health` reports `up_since` / `down_since` / `error` per upstream. | `ssh-add -L` through the agent lists keys as before. `piggy health -v` shows the upstream point green with `up_since`. With the forwarded agent absent (a session with no forward), `ssh-add -l` should now fail after about 3 s rather than print "no identities"; ssh then falls through to other auth methods. | V (code, bats `every_upstream_down_answers_failure_after_the_grace`). I: a script that treated "no identities" as "no keys, carry on" now sees a failure exit; none known. |
| 2 | `6563fb8` (#330) | `PIGGY_STORE_DIR` may be a colon list; the first store is written, reads take the first store holding the entry. A single path behaves as before. | If flic's `PIGGY_STORE_DIR` is one path: nothing to check beyond `piggy pass ls` and one `pass show`. If it ever gains a colon, `piggy pass ls` shows one tree per store. | V (bats `a_single_store_lists_as_before`). I: a store path containing a colon would now split; check flic's value has none. |
| 3 | `c8c64ba`, `4887680`, `095fca0`, `c8cd5f5` (RFC 0012 §2.6) | Operator-act prompts hold all input for 2 s (tty and GTK, including Escape and Cancel); zenity refuses operator acts; the GTK dialog wraps at 100 columns and bolds each markl id's lead. | Only operator acts are affected. On the card session: run one operator act (`just explore-fdr0006-a`, CARD=real) and confirm the dialog ignores keys for 2 s, then accepts the PIN; confirm `PIGGY_ASKPASS_GTK=0` refuses the act with a reason. Routine PIN prompts: one `piggy pass show` prompts as before. | V (bats `operator_act_on_the_tty_holds_input_and_discards_what_is_typed`, `operator_acts_are_refused_on_zenity_before_any_dialog`). The 100-column width on a real screen is unverified (open since #322). |
| 4 | `a572056` (#306) | Routine zenity PIN prompts show the context text literally (backslashes and underscores no longer read as markup). | One routine prompt through zenity (`PIGGY_ASKPASS_GTK=0`): the card name in the prompt reads correctly. | V (bats `routine_zenity_prompt_escapes_backslashes_and_underscores`). Not seen on a real display. |
| 5 | `ac21c03`, `4b654ff` | An absolute pass-name (`/etc/x`) is refused as a sneaky path everywhere, including the management-key seal. | `piggy pass show /abs` fails with "absolute path". Nothing on flic should pass one. | V (unit tests). I: a consumer passing absolute names (e.g. a secrets manifest) would now fail; check `piggy secrets reconcile --check` stays clean (row 9). |
| 6 | `30114b3` (#307) | Each `pass` write commits only the paths it touched (`git commit --only -- <paths>`), not everything staged in the store. | After one `piggy pass insert`, `git -C <store> show --stat HEAD` lists only that entry. | V (bats t0058). |
| 7 | `99f091c` (#151) | `pass verify` orders siblings by raw file name (as `pass ls -r` does), not by the name with `.ebox` stripped; a directory sharing an entry's name no longer hides that entry. | `piggy pass verify` on flic's store exits 0 and lists every entry. | V (unit and bats). Only output order changes. |
| 8 | `2fbb7d1` (#263) | `pass show -r` shows a lone recipient as `piggy-recipient-v1@pivy_ecdh_p256_pub-` plus 8 key characters instead of `piggy-re…`. | `piggy pass show -r` shows a distinguishable recipient. | V (fibby lane 1/1). Display only. |
| 9 | (none; a check) | `services.piggy-secrets` decrypts through the same store code as rows 2 and 5. | `piggy secrets reconcile --check --manifest <flic's manifest>` reports up to date. | I: no reconcile change in the range; this guards rows 2 and 5. |
| 10 | `ba89f37` (#171) | `crates/piggy/Cargo.toml` says 0.1.23 (was 0.1.0); a build fails if it drifts from `version.env`. `piggy version` output is unchanged (the wrapper's `PIGGY_VERSION` wins). | `piggy version` first line reads `piggy 0.1.23+<rev>`. | V. Build-time only otherwise. |
| 11 | `3702e6e`, `d28e399` | Flake inputs: bats, conformist, igloo, langlang, nixpkgs-x86_64-darwin, purse-first (dewey). | The deploy builds; `piggy version` runs; `piggy health` passes. | R (commit messages). The igloo and purse-first moves change the build closure; nixpkgs-x86_64-darwin does not affect flic. |

## No host effect

Test, lint and doc commits: `75fb1b5` (fibby SIGTERM; I: fibby is a test
double, not deployed on flic, so nothing to check unless a host runs it
under systemd), `d90f6a8`, `1376036`, `f6f3c19`, `464f713`, `def0f1b`
(refactor; V: same error text in its tests), `7043f27`, `81b3f15`,
`94c7ff9`, `71415ab`, `c013540`, `cf02bae`, `c769c4a`.

## Queued, not yet on origin/master when written

- `7240d96`: age-plugin-piggy's Cargo.toml carries 0.1.23 and is guarded
  like row 10; `age-plugin-piggy --version` output unchanged. Check:
  `age-plugin-piggy --version`.
- `bf5409a` (#239): the Go markl library drops dewey's terminal-UI
  import. No piggy binary on flic links it; consumers (papi's wasm
  client) get a lighter init.
