# pigtrough pilot: the operator's real-token pass

FDR 0009's pilot closes with a human pass (FDR 0006, "Phase acceptance"):
the operator runs `pigtrough` with the real create token against the real
`api.github.com`, which no automated test does. Every step below is read-only
on GitHub; the write calls (create, edit, topics) are left to the mirror
reconciler's first dry-run-off run.

Needs: the operator's card, the piggy store entry `github/mirror-create`,
`curl` with `--unix-socket`, and flic's network.

## 1. Build and start

    just build-rust -p pigtrough
    target/debug/pigtrough serve

`serve` creates `$XDG_RUNTIME_DIR/pigtrough/` (mode `0700`) with
`proxy.sock` and `control.sock` (mode `0600`), says
`serving route github-api ... (no secret loaded)`, and prints one audit line
per request from then on. Leave it running in its own terminal.

In a second terminal:

    sock=$XDG_RUNTIME_DIR/pigtrough/proxy.sock
    api=http://pigtrough/github-api

## 2. Fail closed before the load

    curl -si --unix-socket "$sock" "$api/repos/amarbel-llc/piggy"

Expect `HTTP/1.1 503` and the body `secret-unavailable`; the audit line says
`decision=refuse-unavailable`. Nothing went to GitHub.

## 3. Load the token

    piggy pass show github/mirror-create | target/debug/pigtrough load github-api

The PIN prompt, if any, is piggy's (the decrypt), not pigtrough's. Expect
`pigtrough: loaded github-api`; the serve terminal says
`pigtrough control: load github-api: ok`.

## 4. An allowed call

    curl -si --unix-socket "$sock" "$api/repos/amarbel-llc/piggy"
    curl -si --unix-socket "$sock" "$api/repos/amarbel-llc/piggy/commits/master"

Use any `amarbel-llc` repository that exists on GitHub and its default
branch; `piggy` and `master` are examples, and a repository that does not
exist answers GitHub's own `404`, which still proves the token was sent.
Expect `HTTP/1.1 200` with GitHub's JSON. The audit lines say
`decision=allow`, `status=200`, the path without any query string.

A client credential is dropped, not forwarded:

    curl -si --unix-socket "$sock" -H 'Authorization: Bearer not-a-token' \
      "$api/repos/amarbel-llc/piggy"

Still `200`: GitHub saw the loaded token, not the client's.

## 5. Refusals

    curl -si --unix-socket "$sock" "$api/user"
    curl -si --unix-socket "$sock" "$api/repos/someone-else/repo"
    curl -si --unix-socket "$sock" -X DELETE "$api/repos/amarbel-llc/piggy"
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
