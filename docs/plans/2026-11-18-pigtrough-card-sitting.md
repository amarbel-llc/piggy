# pigtrough: the card sitting (one sitting, five steps)

Status: DRAFT, nothing here has been run. Written for the operator to run top
to bottom, copy-paste, without reading code. It extends the real-token pass in
`2026-11-16-pigtrough-pilot-runbook.md`; the reference is pigtrough(1).

What the sitting closes, in order:

1. the real `proc` run (real token, real card, no GitHub call)
2. whether one PIN unlock covers every entry
3. the first `systemctl --user start pigtrough-load`
4. the real Forgejo CA and a real Forgejo call
5. other-uid loopback admission (the `/proc/net/tcp` theory)

Needs: the operator's card plugged in and the operator's own piggy agent
running (`ssh-add -L` lists the card key); the entries `github/forgejo-mirror`
and the Forgejo read-only token entry in the operator's **own** store; a second
account or `sudo` for step 5. `github/forgejo-mirror-push` is never loaded.

Two values only the operator knows are written as `FILL-IN` below: the Forgejo
host and its CA file. Set them once:

    export FORGEJO_HOST=FILL-IN            # e.g. forgejo.example.org
    export FORGEJO_CA=FILL-IN              # path to the PEM CA file
    export FORGEJO_SECRET=FILL-IN          # piggy entry name of the read-only token
    export FORGEJO_REPO=FILL-IN            # owner/name of one repo it can read

## 0. Build once

    cd ~/eng/repos/piggy           # the main checkout on master
    nix build .#pigtrough --out-link "$XDG_RUNTIME_DIR/pigtrough-pkg"
    export BIN=$XDG_RUNTIME_DIR/pigtrough-pkg/bin/pigtrough
    "$BIN" --help >/dev/null && echo "BIN ok"

Success: `BIN ok`. Failure: the build output says why; stop.

## 1. The real `proc` run

    just explore-pigtrough-pilot-pass "$BIN" proc

Success: a PIN prompt (the card), then only `PASS` lines, `step 6: 0
artifact(s) failed`, `no serve process left`, and no `FAIL` line. It prints
counts, never the token; the positive control line says the search does find
the token when it is there.

Failure: any `FAIL` line names the artifact (command line, environment, open
fds, serve log) that held the token or its prefix: a pilot defect, stop and
send the output. A `FAIL` on a step before 6 is a load problem, not a leak.
If it was interrupted, run `just explore-pigtrough-pilot-pass-clean`.

## 2. Does one PIN unlock cover every entry?

Run the load helper's shape by hand against two entries and count prompts.
Use a throwaway directory so nothing real is served:

    export D=$XDG_RUNTIME_DIR/pigtrough-sit
    "$BIN" serve --dir "$D" 2>"$D.log" &   # the first run creates $D
    sleep 1
    piggy pass show github/forgejo-mirror | "$BIN" load github-api --dir "$D"
    piggy pass show "$FORGEJO_SECRET" >/dev/null && echo "second decrypt done"

Success, either way is an answer: write down how many PIN prompts appeared.
One prompt for both = one unlock covers both entries (then the load unit
raises one prompt for any number of routes). Two prompts = one per entry.
Neither is a defect; it only decides what to expect in step 3.

Stop it: `pkill -TERM -f "pigtrough serve --dir $D"; rm -rf "$D"*`.
Failure: `pigtrough: ...` on stderr from `load` (route unknown, empty input):
the entry name is wrong or the decrypt failed; the message says which.

## 3. The first `systemctl --user start pigtrough-load`

Prerequisite (once): the home-manager module is enabled with the two routes
in nix (`services.pigtrough.routes`, each with `secret`), and
`services.pigtrough.loadEnvironment` gives the unit the agent socket and the
askpass display, for example `SSH_AUTH_SOCK` and `WAYLAND_DISPLAY` /
`DISPLAY`; then `home-manager switch`. If you have not enabled it, skip this
step and say so: it is not a defect, the unit simply is not installed.

    systemctl --user restart pigtrough          # comes back with every route unloaded
    curl -si --unix-socket "$XDG_RUNTIME_DIR/pigtrough/proxy.sock" \
      "http://pigtrough/github-api/repos/amarbel-llc/piggy" | head -1
    systemctl --user start pigtrough-load
    journalctl --user -u pigtrough-load -n 20 --no-pager

Success: the curl before the load prints `HTTP/1.1 503`; the journal lists each
route name with ok and ends `all N routes loaded`; the start command returns 0.
No secret appears in the journal (look: none should).

Failure meanings:
- stops at a route name with a failure: that route's entry failed to decrypt
  (locked card, wrong name); later routes were deliberately not tried.
- no PIN dialog and a hang or an agent error: the unit does not see the agent
  socket or the display; add them to `loadEnvironment` (this is the untested
  environment question).

## 4. The real Forgejo CA and call

The route needs `extra_roots = [ "<CA file>" ]` in the route table (nix
`routes`), and `upstream = "<FORGEJO_HOST>"`, `auth = "token"`, an allow entry
for `GET api/v1/repos/{owner}/{name}`, and `owners` containing your owner.
After editing, `home-manager switch`, `systemctl --user restart pigtrough`,
`systemctl --user start pigtrough-load`. Then:

    sock=$XDG_RUNTIME_DIR/pigtrough/proxy.sock
    curl -si --unix-socket "$sock" \
      "http://pigtrough/forgejo-api/api/v1/repos/$FORGEJO_REPO" | head -5

Success: `HTTP/1.1 200` and a JSON body for that repository; the serve journal
(`journalctl --user -u pigtrough -n 5`) has one audit line with
`decision=allow`, `status=200`, no token.

Failure meanings:
- `502 upstream-unavailable`: TLS to the upstream failed. Most likely the CA
  file is not the issuer of that host's certificate, or the host name differs
  from the certificate's. Send the exact audit line.
- `503 secret-unavailable`: the route is not loaded; run step 3's load.
- `403 refused`: the path, method or owner is not in the route's allowlist.
- `401` from Forgejo (shown in the body): the token is wrong or expired.

## 5. Other-uid loopback admission

Needs a route with a `loopback_port` (say 8731) in the running table; the
step proves another user is refused and you are admitted.

    curl -si "http://127.0.0.1:8731/api/v1/repos/$FORGEJO_REPO" | head -1

Success (you): `HTTP/1.1 200`. Then as another user:

    sudo -u nobody curl -si "http://127.0.0.1:8731/api/v1/repos/$FORGEJO_REPO" | head -1

Success (other user): the connection is refused or closed with no HTTP
status, and the serve journal does not show an `allow` line for it. Failure:
`HTTP/1.1 200` for the other user means loopback admission does NOT hold:
stop and send it; it would mean the ports must not be used on a shared host.
If `sudo -u nobody` is not possible, report "not run"; that leaves the theory
as it is.

## Stop

    systemctl --user stop pigtrough pigtrough-load 2>/dev/null
    just explore-pigtrough-pilot-pass-clean

## Report

Send, per step, pass or the exact line that differed, plus the number of PIN
prompts from step 2, to the coordinator and piggy/solid-dogwood. After the
sitting solid-dogwood records the result in the runbook and merges it.

## Not in this sitting

The shithub import push is not a pigtrough step; it belongs to its own owner.
