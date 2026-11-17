# pigtrough: how a client reaches the proxy (evaluation)

Status: research, docs only; nothing deployed, nothing built. Claims about
kernel or smith behaviour that this session did not test are marked
**theory**. Smith facts are those relayed from smith/loud-fig (2026-11-17).

Question from the operator: smith's unix-socket connector, a per-user
listener, and other options that improve security and ergonomics, in the
context of "clowncar" with possible host-wide single cutting-garden
instances. This session does not know what clowncar is and has not read its
design; where "host-wide, many users or sessions" matters below, it is
taken as: several local principals (users, sessions, sandboxes) share one
host, and one proxy instance may serve more than one of them. If clowncar's
shape differs, the recommendation needs a second look by whoever owns it.

## What a listener must give

1. **Admission**: only the intended principal reaches a route. Today the unix
   socket gets this from directory mode `0700`, socket mode `0600` and a
   peer-credential check (same uid).
2. **Route binding**: a connection can only use the route (and so the secret)
   it was made for.
3. **Client reach**: smith (and later others) can actually connect. Smith
   speaks TCP http/https only, and today does an https:443 discovery first.
4. **Few new moving parts** in a process that holds a credential.

## Path 1: smith gains a unix-socket connector

The `0600` socket of R4 is kept; admission is the filesystem plus peer uid;
no TCP port exists. Cost: a larger smith change than skipping discovery (a
connector in `crates/forgejo-api`, a way to name the socket, discovery
skipped or run over the socket), and every other TCP-only client needs the
same. Best admission, most client work. In a host-wide setting the socket
path is per user (`$XDG_RUNTIME_DIR`), so each user gets their own proxy and
secret: nothing shared to attack.

## Path 2: a per-user loopback TCP listener (the ruled path)

`127.0.0.1:<port>` per route, port from the route table. Smith needs only
"skip discovery for http/localhost". Cost: a loopback port is reachable by
every local user, so admission needs a mechanism:

- **Port as the only guard**: any local process can use the route and so the
  operator's credential. Acceptable only on a single-user host. Weakest.
- **Peer-uid check via `/proc/net/tcp`**: **theory.** The kernel lists local
  TCP sockets with their owner uid; for an accepted loopback connection the
  peer's socket line (matching the 4-tuple) carries the client's uid, which
  the proxy could compare with its own. To verify before relying on it:
  races (the line may be gone when read), network namespaces (a sandbox with
  its own namespace cannot reach the host's loopback anyway), and a
  same-uid-different-purpose process still passes. Gives per-user admission
  on a shared host; no peer pid.
- **A shared secret in the request**: smith has no environment hook; its
  keystore could hold a per-proxy key and send it as `Authorization`, which
  the proxy would check and then replace with the real token. **Theory**
  that this fits smith's keystore (`keys.json`, aliases) without a code
  change. It moves the secret from "operator token" to "proxy access key", a
  smaller blast radius if leaked, but it is a credential on disk again,
  which the proxy exists to avoid. Not recommended as the only guard.
- **Per-session network namespace or fence**: a sandboxed worker's loopback
  is its own, so the proxy must be exposed into it deliberately. Reuses
  existing confinement; depends on spinclass/clown, not on pigtrough.

## Path 3: a local https:443 listener

No smith change. Needs a privileged port (a capability on the unit, or a
redirect of a high port), TLS termination in pigtrough (it has the client
side only today), and a certificate smith trusts (a private CA placed in
smith's trust store, which smith's HTTP stack may not read; unchecked). Port
443 is one per host address, so a per-user proxy collides: it only fits a
single host-wide instance, which makes route binding and admission harder,
not easier. Largest addition to a credential-holding process; the most
effort for the same loopback-admission problem as Path 2.

## Other options

- **A small shim next to smith** (`socat`-style: a loopback or unix bridge
  started per session, forwarding to the `0600` socket). Smith still needs
  the discovery skip; admission moves to whoever may start the shim and
  reach its port, so it repeats Path 2's problem unless the shim itself is
  per-session in a private namespace. Useful only as a stopgap.
- **Socket activation by systemd** for the unix socket: the socket exists
  before `serve`, restarts do not drop the path, a client sees a refused
  connection (not a missing path) until `load`. Orthogonal to the choice
  above; worth doing with R3's unit regardless.
- **A host-wide single instance (cutting-garden or otherwise)**: one proxy
  for many principals needs real per-principal admission (peer pid/uid and
  an act or stencil that names the route, FDR 0009's deferred part) and a
  per-principal secret store. Not available in the pilot; per-user proxies
  avoid the problem by construction.

## Comparison

| | Admission | Smith work | pigtrough work | Host-wide fit |
|---|---|---|---|---|
| 1 unix connector | filesystem + uid, as ruled | connector + discovery skip | none | per-user, clean |
| 2 loopback TCP | needs a mechanism (above) | discovery skip only | listener + admission | per-user, weaker |
| 3 https:443 | same as 2 | none | TLS server, cert, port | single instance only |

## Recommendation

Rule path 2 now, as the operator did, because it is the smallest smith
change and unblocks the pass; make its admission explicit rather than
trusting the port: first verify the `/proc/net/tcp` uid check (the
**theory** above) in a throwaway test on flic, and ship the listener refusing
any connection it cannot attribute to the proxy's own uid. Keep the unix
socket and ask smith's worker to keep the unix connector as a follow-up
(path 1), since it is the only path whose admission is already proven. Do not
build path 3. If the check cannot be made reliable, fall back to path 1 for
anything beyond a single-user host.

## Throwaway test for the `/proc/net/tcp` uid check (design, not run)

Goal: find out whether, for an accepted loopback connection, the peer's uid
can be attributed reliably. Nothing here is a claim until it runs.

Setup, as a `explore-` justfile recipe (never an ad hoc script), on flic, no
credential, no network beyond loopback:

1. A listener binds `127.0.0.1:0`, prints its port, and for each accepted
   connection records the peer address (ip:port) and looks that 4-tuple up
   in `/proc/net/tcp` (the line whose local address is the peer's and whose
   remote address is the listener's); the `uid` column is the answer.
2. Cases, each compared with the known uid of the connecting process:
   - same uid connects: expect equal.
   - another uid connects (needs a second account or a `systemd-run
     --user`-style different-uid helper; if flic has none, mark the case
     NOT TESTED rather than faking it).
   - a burst of N hundred short connections: count lookups that find no
     line (the race), which decides whether "refuse if unattributable" is
     usable or too lossy.
   - a connection from inside a separate network namespace: expect it cannot
     reach the host's loopback at all.
   - IPv4-mapped and `::1`: the listener binds `127.0.0.1` only, so `::1`
     must be refused by connect; check `/proc/net/tcp6` is not needed.
3. Output: counts per case (match, mismatch, no line), nothing else.

Pass criteria: zero mismatches; the no-line rate low enough that refusing
those connections costs nothing visible (to be set after seeing the number,
not before). Fail or flaky: fall back to path 1 (unix connector) for anything
beyond a single-user host, as the recommendation says.

## Result of the probe run (2026-11-17, flic, uid 1001, not root)

Run through `just explore-pigtrough-admission` (second run; the first run
printed no counts because of a grep bug in the recipe and a probe case that
exceeded the listen backlog, both fixed). Tests ran in 7.4 s. Loopback only,
no credential. What each case shows:

| Case | Counts | What it shows |
|---|---|---|
| same-uid burst: 8 threads x 100 connections open at once, each client having sent a request, server looks each one up | 800 connections: own uid 800, other uid 0, unattributed 0 | For connections that are live when looked up, `/proc/net/tcp` attributed the owner correctly every time, with no missing line (the lookup race did not show). |
| client gone before the lookup: 3 rounds of 100 clients that connect and close, then the server accepts and looks up | 300 connections: own uid 0, **other uid 300**, unattributed 0 | A connection whose client has already closed is not unattributed: the table still has a line for it, owned by a uid other than ours. Likely (a theory, not checked in the table text) the closed socket's line carries uid 0. The listener refuses such a connection, correctly, since nothing is left to serve. If `serve` ever runs as uid 0 the check would admit it; harmless (there is no client) but the decision should not treat "uid 0" as proof of a live root client. |
| `::1` | connected=0, `ConnectionRefused` | The IPv4-only listener cannot be reached over IPv6 loopback. |
| other uid | **NOT TESTED** | Running as uid 1001, not root; no second account is usable from a session. The admission against a foreign uid is therefore still **unverified** against the kernel; only a synthetic table in a unit test covers the foreign-uid parse. |
| separate network namespace | **NOT TESTED** | Not part of this probe. |

Conclusion, no stronger than the evidence: the same-uid path is attributed
reliably under a burst of 800 on flic. Attribution of a *different* user, the
one case that decides whether loopback admission means anything on a shared
host, has not been exercised, so the `/proc/net/tcp` admission stays marked
**THEORY** until the other-uid case is run (it needs root or a second
account, so it is the operator's or a second session's to run).

## Open questions

- What clowncar needs from a host-wide proxy, if it is more than the
  per-user reading used here (its owner to answer).
- Whether smith's HTTP stack can trust a private CA (only for path 3).
- Whether the `/proc/net/tcp` attribution is reliable for loopback under
  load (test before relying on it).
