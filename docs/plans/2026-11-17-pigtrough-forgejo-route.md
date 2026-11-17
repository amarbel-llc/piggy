# pigtrough: the forgejo-api route for smith (plan)

Status: plan. Rulings of 2026-11-17 (operator, relayed by the coordinator):

- R1: routes come from a TOML file read once at `serve` start; no hot reload.
- R2: the auth scheme is a per-route field, `token` or `bearer`.
- R3: a systemd user unit supervises `serve`; after a restart it answers
  `503 secret-unavailable` until the operator runs `load` again.
- R4: one `0600` socket per route.
- Addition on R2: it must work through pigtrough, end to end, for smith.

## Steps, in order

1. **Route table library** (pure, offline): parse and validate the TOML into
   the existing `Route` shape (name, upstream host and port, scheme, secret
   name, owners, allow shapes, forwarded headers, extra roots). Refuse to
   start on any parse or validation error; no partial table. The compiled-in
   `github-api` becomes the same record, read from the same parser's output
   or kept as the default when no file is given.
2. **Loopback TCP listener per route** (operator ruling 2026-11-17, option
   A of the blocker below: smith skips vanity discovery for http/localhost,
   and is changed by a smith worker, not by this session): the route table
   gives each route an optional loopback `port`; `serve` binds
   `127.0.0.1:<port>` for it, and a connection there can only name that
   route. No socket-per-route for smith. The existing unix `proxy.sock`
   stays for other clients. The accepted caveat: a loopback port is reachable
   by every local user, so the same-user admission of the unix socket does
   not carry over by itself; how a TCP connection is admitted is evaluated
   in `2026-11-17-pigtrough-listener-options.md`.
3. **Scheme field** (default `token`, which is what smith sends): `token` sends `Authorization: token <secret>`, `bearer`
   sends `Authorization: Bearer <secret>`.
4. **Extra roots** per route (see `2026-11-17-pigtrough-extra-roots.md`).
5. **Unit** (docs and nix only until the card day): a home-manager user unit
   running `pigtrough serve`; the operator runs `load` after each start.
6. **smith end to end** (after the operator's token entry and the card).

## What smith does (answers from smith/loud-fig, read-only, against smith's source)

Relayed by the coordinator on 2026-11-17; file:line are smith's, not
verified here.

1. **Transport**: TCP over http or https only; there is no unix-socket
   connector (`crates/forgejo-api/src/lib.rs:683-711`). There is no
   environment variable for the base URL; `--host` accepts a full URL, so
   `http://127.0.0.1:PORT` works (`src/repo.rs:63-84`). Requests go to
   `{base}/api/v1/{endpoint}`.
2. **Calls**: all `GET` under `/api/v1`: issues, `issues/{n}`, pulls,
   `pulls/{n}`, `pulls/{n}/files`, `pulls/{n}/commits`, `repos/{o}/{r}`,
   `commits/{ref}/status`, tags, releases, contents. Headers: `Authorization`
   and `User-Agent` only. Redirects are disabled.
3. **Scheme**: `Authorization: token <t>`, never `Bearer`
   (`lib.rs:502-503`, `keys.rs:175, 292-299`). So R2's default is `token`.
4. **Credentials**: no environment variable for the token; the keystore is
   `$XDG_DATA_HOME/smith/keys.json` only. With no `keys.json` smith sends no
   `Authorization` header at all (`keys.rs:97-120, 204-205`), which is the
   cleanest shape: an empty keystore, and the proxy adds `token <t>`.
   Aliases exist (`keys.rs:79-86`).

## smith needs a change or an https:443 listener

**Blocker.** Before any call smith does vanity discovery: `GET
https://{host}/.well-known/forgejo-vanity`, hard-coded https, port 443, the
port of `--host` dropped. A connect or TLS failure there is a hard error;
only an HTTP non-2xx is tolerated (`repo.rs:246-247, 465-520`). A loopback
http listener therefore cannot serve smith as smith is, and R4's unix socket
cannot be reached by smith at all (point 1).

Two options, for the operator to rule (the coordinator is asking):

- **A. Change smith**: skip or soften discovery when the host is `http://` or
  localhost, and optionally add a unix connector. pigtrough then needs a
  loopback TCP listener (new, and with it a new admission question: a
  loopback port is reachable by every local user, unlike a `0600` socket;
  the same-user check would have to come from the peer's credentials, which
  TCP does not give without more work). With a smith unix connector the
  `0600` socket of R4 stays as ruled.
- **B. An https:443 listener in pigtrough**: no smith change. Port 443 is
  privileged, so this needs a capability or a redirect (a systemd socket
  unit, or a firewall redirect of a high port); the certificate must be
  trusted by smith, which means a private CA in smith's trust store and a
  listener that terminates TLS. This adds a TLS server side to pigtrough,
  which has only the client side today, and the same loopback admission
  question as A.

**Ruled 2026-11-17:** option A, without the unix connector: smith skips
discovery for http/localhost and pigtrough serves a loopback TCP listener for
smith; the caveat above is accepted. The smith change is filed separately
and owned by a smith worker.

## Test plan for "works for smith"

Offline first: a fake Forgejo upstream (local CA, as the existing tests do)
and a request table built from smith's call list, each entry checked for the
upstream request seen (path, scheme header, dropped client credential) and
for the refusal of everything off the list. Then one read-only pass against
the real instance by the operator, with a read-only token, GET calls only,
smith driven through the proxy. No real credential in any test.
