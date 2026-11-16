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

## 6. The token is nowhere visible

    pid=$(pgrep -f 'pigtrough serve')
    tr '\0' ' ' < /proc/$pid/cmdline; echo
    cat /proc/$pid/environ

The command line is `pigtrough serve`; `environ` is `Permission denied`
(serve is non-dumpable). Scroll the serve terminal: no line holds the token.

## 7. Stop

Ctrl-C the serve terminal. The token lived only in its guarded memory and
is gone with the process; the sockets stay until the next `serve` replaces
them.

## Report

Send the outcome of each step (pass, or what differed) to piggy/green-larch
and the coordinator. A difference in steps 2, 4 or 5 is a pilot defect; a
`502 upstream-unavailable` in step 4 means the TLS dial or verification
failed, and is worth the exact audit line.

## Known gaps of the pilot (not tested by this pass)

- No operator-supplied extra trusted roots: upstreams are verified against
  the `webpki-roots` bundle of the build only.
- A client that disconnects does not cancel its in-flight upstream call;
  the call runs to completion or to the 30 s head timeout.
