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
2. **Per-route sockets**: `proxy-<route>.sock` (mode `0600`) in the runtime
   directory; a request on a socket can only name that socket's route, so
   reachability is the scope binding. `load` still names a route.
3. **Scheme field**: `token` sends `Authorization: token <secret>`, `bearer`
   sends `Authorization: Bearer <secret>`.
4. **Extra roots** per route (see `2026-11-17-pigtrough-extra-roots.md`).
5. **Unit** (docs and nix only until the card day): a home-manager user unit
   running `pigtrough serve`; the operator runs `load` after each start.
6. **smith end to end** (after the operator's token entry and the card).

## Needs from smith's lane (no live smith session on 2026-11-17)

Question to put to smith, routed by the coordinator:

1. Can smith talk to a Forgejo over a unix socket, or only over TCP? If only
   TCP, can the base URL be `http://<host>:<port>` for a local listener
   instead (this would need pigtrough to listen on loopback, which R4 does
   not cover)?
2. The exact list of Forgejo calls smith makes for the commands the operator
   wants proxied: method and path shape for each, and which headers it sets
   (the allowlist and `forward_headers` come from this list).
3. Which `Authorization` scheme smith sends today (`token` or `Bearer`).
4. Does smith's keystore take a base URL and a token from the environment, so
   it can be pointed at the proxy without a code change?

## Test plan for "works for smith"

Offline first: a fake Forgejo upstream (local CA, as the existing tests do)
and a request table built from smith's call list, each entry checked for the
upstream request seen (path, scheme header, dropped client credential) and
for the refusal of everything off the list. Then one read-only pass against
the real instance by the operator, with a read-only token, GET calls only,
smith driven through the proxy. No real credential in any test.
