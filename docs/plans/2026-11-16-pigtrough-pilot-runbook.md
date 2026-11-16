# pigtrough pilot: the operator's real-token pass

FDR 0009's pilot closes with a human pass (FDR 0006, "Phase acceptance"):
the operator runs `pigtrough` with the real create token against the real
`api.github.com`, which no automated test does. Every step below is read-only
on GitHub; the write calls (create, edit, topics) are left to the mirror
reconciler's first dry-run-off run. See pigtrough(1) for the commands.

Needs: the operator's card, `curl` with `--unix-socket`, flic's network, and
the create-capable token in the operator's **own** piggy store (the default
`PIGGY_STORE_DIR`, not a session store) at the entry `github/forgejo-mirror`.
Its create capability is not yet verified; this pass does not verify it
either (it only reads). The push-only entry `github/forgejo-mirror-push`
stays outside the proxy by ruling and must **not** be loaded.

## 1. Build and start

    nix build .#pigtrough --out-link "$XDG_RUNTIME_DIR/pigtrough-pkg"
    pigtrough=$XDG_RUNTIME_DIR/pigtrough-pkg/bin/pigtrough
    "$pigtrough" serve

`serve` creates `$XDG_RUNTIME_DIR/pigtrough/` (mode `0700`) with
`proxy.sock` and `control.sock` (mode `0600`), says
`serving route github-api ... (no secret loaded)`, and prints one audit line
per request from then on. Leave it running in its own terminal.

Keep `--dir` short: a unix socket path is limited to about 108 bytes
(`SUN_LEN`), and a deep directory (a worktree's `.tmp`, for example) is
refused with `path must be shorter than SUN_LEN`. `$XDG_RUNTIME_DIR` fits.

In a second terminal:

    sock=$XDG_RUNTIME_DIR/pigtrough/proxy.sock
    api=http://pigtrough/github-api
    repo=repos/amarbel-llc/piggy    # any amarbel-llc repository on GitHub

## 2. Fail closed before the load

    curl -si --unix-socket "$sock" "$api/$repo"

Expect `HTTP/1.1 503` and the body `secret-unavailable`; the audit line says
`decision=refuse-unavailable`. Nothing went to GitHub.

## 3. Load the token

    pigtrough=$XDG_RUNTIME_DIR/pigtrough-pkg/bin/pigtrough
    piggy pass show github/forgejo-mirror | "$pigtrough" load github-api

The PIN prompt, if any, is piggy's (the decrypt), not pigtrough's. Expect
`pigtrough: loaded github-api`; the serve terminal says
`pigtrough control: load github-api: ok`.

## 4. The token is attached

A `200` alone proves nothing: GitHub answers an unauthenticated request
for a public repository with the same `200`. The proof is the rate limit
GitHub reports, which differs for authenticated calls. Per GitHub's REST
documentation (verify against the current docs), an unauthenticated
request reports `x-ratelimit-limit: 60` and a request with a personal or
fine-grained token reports a higher limit (5000 for a standard token).

The baseline, direct and without any token (this does not go through the
proxy):

    curl -si "https://api.github.com/$repo" | grep -i '^x-ratelimit-limit'

Then the same call through the proxy:

    curl -si --unix-socket "$sock" "$api/$repo" | grep -i -e '^HTTP/' -e '^x-ratelimit-limit'

Pass: `HTTP/1.1 200` and a limit above the baseline. The audit line says
`decision=allow`, `status=200`, the path without any query string. A
`200` with the baseline limit means the token was not attached: stop and
report it.

A client credential is dropped, not forwarded:

    curl -si --unix-socket "$sock" -H 'Authorization: Bearer not-a-token' \
      "$api/$repo" | grep -i -e '^HTTP/' -e '^x-ratelimit-limit'

Pass: the same `200` and the same higher limit as above. Had the client's
header been forwarded, the bogus token would have replaced the real one;
per GitHub's docs (verify) an invalid token is answered with `401`.

## 5. Refusals

    curl -si --unix-socket "$sock" "$api/user"
    curl -si --unix-socket "$sock" "$api/repos/someone-else/repo"
    curl -si --unix-socket "$sock" -X DELETE "$api/$repo"
    curl -si --unix-socket "$sock" "http://pigtrough/elsewhere/x"

Each is `HTTP/1.1 403` with the body `refused`, all four identical, and
`decision=refuse-allowlist` in the audit. None reached GitHub.

A percent-encoded path (`curl --path-as-is "$api/repos/amarbel-llc/%2e%2e"`)
is refused the same way. Its audit line shows the path as the HTTP parser
normalised it, with upper-case hex (`%2E%2E`), not byte for byte as sent.

## 6. The token is nowhere visible

    pid=$(pgrep -f 'pigtrough serve')
    tr '\0' ' ' < /proc/$pid/cmdline; echo
    cat /proc/$pid/environ

The command line is `pigtrough serve`; `environ` is `Permission denied`
(serve is non-dumpable). Scroll the serve terminal: no line holds the token.

Non-dumpable shows in `/proc` as ownership: `/proc/$pid/environ` and
`/proc/$pid/fd` belong to uid 0 although `serve` runs as the operator, so
the operator can read neither, and opening `/proc/$pid/mem` (ptrace access)
is refused. Linux's `/proc/$pid/status` has no dumpable field (checked
on flic, 2026-11-16), so ownership is the evidence.

The scripted form of this step, `just explore-pigtrough-pilot-pass BIN
proc`, also searches each readable artifact (command line, environment if
readable, open-fd list if readable, the serve log) for the exact token and
for the `ghp_` / `github_pat_` prefixes. It prints only counts, PASS or
FAIL, and a positive control showing the search finds the token.

## 7. Stop

Ctrl-C the serve terminal. The token lived only in its guarded memory and
is gone with the process; the sockets stay until the next `serve` replaces
them.

`serve` installs no signal handler of its own. Ctrl-C in a terminal ends
it. A script that started it in the background must send `SIGTERM`: a
non-interactive shell starts background jobs with `SIGINT` ignored, which
the child inherits, so `kill -INT` does nothing there.

## Scripted form

`just explore-pigtrough-pilot-pass BIN PHASE` runs this pass with no
terminal, in a throwaway `$XDG_RUNTIME_DIR/pigtrough-pilot.*` directory. It
starts `serve`, prints each command and its result, then stops `serve` with
`SIGTERM`, confirms no `serve` process is left, and removes the directory.
`BIN` is the `nix build .#pigtrough` output.

| `PHASE` | Steps | Card | Network |
|---|---|---|---|
| `pre-load` | 1, 2, 5 (and a client `Authorization` before the load) | no | no |
| `loaded` | 1 to 4 | yes | three read-only GETs to `api.github.com` |
| `proc` | 1 to 3, 6 | yes | none |
| `proc-fake` | `proc` with a fixed fake token, to check the step-6 harness itself | no | none |

`just explore-pigtrough-pilot-pass-clean` stops a `serve` an interrupted
run left behind and removes its directories.

## Report

Send the outcome of each step (pass, or what differed) to piggy/green-larch
and the coordinator. A difference in steps 2, 4 or 5 is a pilot defect; a
`502 upstream-unavailable` in step 4 means the TLS dial or verification
failed, and is worth the exact audit line.

## Pilot result (2026-11-16)

Run by piggy/solid-dogwood/sparkles on flic with the operator's go-ahead
(relayed by circus/eager-holly). The operator was present for the card.
Binary: `/nix/store/4ymbnz41n40vfb3az7wqw1b7ayh0a6jk-pigtrough-0.1.0`, built
from `1ab69e1`, run through the scripted form above. `loaded` and `proc`
ran once each. `pre-load` ran twice: the first run hung at teardown on
`SIGINT` (step 7) and was killed by its timeout, which also ended `serve`.

| Step | Observed | Result |
|---|---|---|
| 1 | runtime dir `0700`, both sockets `0600`, all uid 1001 (the operator) | pass |
| 2 | `503 secret-unavailable`, also with a client `Authorization`; `bytes_out=0` | pass |
| 3 | `pigtrough: loaded github-api`; serve: `control: load github-api: ok` | pass |
| 4 | direct, no token: `200`, `x-ratelimit-limit: 60`. Proxied: `200`, `5000`. Proxied with `Authorization: Bearer not-a-token`: `200`, `5000` | pass: the token is attached and the client's header is dropped |
| 5 | `/user`, another owner, `DELETE`, `/elsewhere/x`, `%2e%2e`: five byte-identical `403 refused`, `bytes_out=0` | pass |
| 6 | cmdline `pigtrough serve --dir <dir>`; `environ`: `Permission denied`, owned by uid 0 | pass, partly (below) |
| 7 | `SIGTERM`; serve gone, directory removed | pass |

Three GETs reached GitHub in all; no write route was called, and
`github/forgejo-mirror-push` was not touched.

**What step 6 did not cover on the real load.** That run read only the
command line and the environment. It did not list the open fds, did not
search any artifact for the token or for its prefixes, and did not check
the dumpable state or ptrace access directly; the root-owned `environ` was
indirect evidence only. The checks the test suite makes against a fake
token (`crates/pigtrough/tests/binary.rs`) are the same kind, but they are
not a real-token pass. The scripted `proc` phase now does all of this, and
`proc-fake` has verified its plumbing without a card. One run of `proc`
with the real token is still to do, and needs the operator and the card.

**Harness findings** (none a pilot defect): the `SUN_LEN` path limit
(step 1), `SIGTERM` rather than `SIGINT` for a backgrounded `serve` (step
7), and the audit line's normalised percent-encoding (step 5).

## Known gaps of the pilot (not tested by this pass)

- No operator-supplied extra trusted roots: upstreams are verified against
  the `webpki-roots` bundle of the build only.
- A client that disconnects does not cancel its in-flight upstream call;
  the call runs to completion or to the 30 s head timeout.
