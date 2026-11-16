---
status: exploring
date: 2026-11-16
promotion-criteria: >
  exploring -> proposed when the operator has ruled the questions marked
  "blocks" below and chosen the first pilot route. proposed -> experimental
  when one route (a bearer token to one allowlisted host) is served through
  a unix socket by a client that holds no credential, proven by a test that
  greps the client's captured bytes, argv and environment for the token.
  Every phase closes with a human pass (FDR 0006, "Phase acceptance").
---

# Auth decoration proxy: clients point at piggy, piggy attaches the credential

> **Status of this draft.** Written on the coordinator's request of
> 2026-11-16 (operator priority 3) for piggy#388, an open-ended design
> issue. Docs only; nothing is built; nothing here is approved. Where it
> says "recommend", it is a recommendation for the operator, not a ruling.
> Sources: piggy#388 and its one comment, cutting-garden#285 and its
> options note (`docs/plans/2026-11-15-wire-plugin-piggy-secrets-options.md`
> in the cutting-garden repo, section Ruling, read 2026-11-16), tent FDR
> 0002 (`docs/features/0002-restricted-kvm-on-nikulin.md`, decisions 3 and
> 4 and the threat table, read 2026-11-16), FDR 0008, FDR 0006, RFC 0013,
> piggy-acts(7).

> **Relation to FDR 0008.** FDR 0008 (the secret proxy) is the same idea
> aimed at one client class: graph runs on krone that call OpenRouter and
> Tinfoil, naming a handle in a purpose-built request. This record is the
> general form: any HTTP client, naming a route, with piggy deciding what
> to attach. FDR 0008 is the first and strictest instance (a handle bound
> to a cgroup, an egress allowlist, a key that never leaves). Recommendation
> below: one proxy binary and one route table serve both; FDR 0008's
> request shape becomes a thin client of this record's transport. If the
> operator prefers two units, everything below still holds for the second.

## Problem Statement

Clients that make outbound authenticated calls today hold or resolve the
credential themselves: cutting-garden's in-tree plugins resolve a piggy
pass entry, out-of-tree plugins (smith's `serve-cutting_garden`, fj-cg)
cannot import that resolver, and circus's GitHub mirror reconciler needs
a create-capable token. Each client that resolves for itself puts a
secret in a process, risks it in argv, logs or the handshake, and causes
its own PIN prompt when no agent runs. The operator ruled on 2026-11-16
(cutting-garden#285, option (d)): piggy is a local network auth decoration
proxy and plugins hold no credential.

## Interface

### The shape

A **decoration proxy**, a local unix-socket service. A client sends an
ordinary HTTP request to it, naming a route. The proxy looks the route up
in its table, applies the route's auth scheme to the outgoing request,
sends it to the route's fixed upstream, and returns the response. The
client never holds, resolves or sees the credential, and no credential
appears in plugin config, argv, the handshake or the response.

### Answers to the open questions of #388

Numbering follows the issue.

**1. Transport and listener.** A unix stream socket, speaking HTTP/1.1.
No inet listener by default: tent's VMM must not gain an inet socket to
reach the proxy, and a unix socket carries peer credentials (SO_PEERCRED,
cgroup) that loopback TCP cannot. Recommend one socket per *caller scope*,
not one shared socket: the socket's directory permissions are the first
gate (an unprivileged client reaches only its own socket), and the proxy
learns the caller from which socket accepted the connection plus the
peer's credentials, the same binding FDR 0006 phase (d) uses. A shared
socket with a route-level check is the fallback if per-scope sockets prove
too many to manage. A loopback TCP listener is deliberately not offered:
it would let any local process try any route and lose the peer's identity.
Clients that can only speak TCP are served through a socket-to-TCP shim
that is itself a bound caller, not by widening the proxy.

**2. How a client names the route.** Recommend an explicit route name in
the request URL path prefix: `http://proxy/<route>/<path>`, with the HTTP
client configured with the proxy as its base URL. This is what the
mirror reconciler's single `--github-api` base-URL setting already
provides, and it works for Go, Rust and shell clients alike (the
language-neutral contract cutting-garden asked for). Rejected as the
primary mechanism: an implicit mapping from a destination host (it
requires the client to send the request as if to the real host through
the proxy, i.e. an HTTP proxy or CONNECT, which forces TLS interception,
see 8) and a header (clients that forward arbitrary headers may be
coaxed into setting it). A `Host` header from the client is ignored, and
so is any `Authorization`, `Cookie` or key-bearing header the client
sets; the route fixes both.

**3. How piggy decides what to attach.** A route table, operator-edited,
read from a configuration file, one entry per route:

| Field | Meaning |
|---|---|
| `name` | the route name clients use |
| `upstream` | scheme, host, port; redirects to any other host are refused |
| `allow` | HTTP methods and path prefixes the route serves |
| `scheme` | `bearer`, `basic`, `header:<name>`; later signed-request schemes |
| `secret` | the name of a secret the proxy holds or can unseal; never the value |

The route table says *what a route is*; it does not say *who may use it*
(question 4). Credentials are not in the table: the table names a secret,
and the secret lives where FDR 0008 puts provider keys (guarded memory,
loaded by a frontend-only verb from the operator's piggy store, per the
recommendation of FDR 0008 for #385). Recommend against deriving routes
from act documents alone: an act can narrow what a caller may use, but it
cannot say what an upstream is or where a key goes, and an act that did
would have to be re-signed whenever an upstream moved.

**4. Authorisation.** Two layers, both fail closed.

- *Binding* (coarse, always answerable): the proxy refuses a connection
  whose peer is not bound to a scope that owns the route. Binding is
  FDR 0006 phase (d) and FDR 0008's handle binding, with the same open
  scope-binding ruling (#386, clown#244) as a dependency.
- *Acts* (fine, optional per route): a route may require that the request
  carry, or the bound scope hold, an RFC 0013 act whose chain verifies
  and whose rights include a route right such as `piggy:route:<name>`.
  Conditions in the act's profile or body (path, method, header values)
  are stencils evaluated by the enforcer; piggy-acts(7) says piggy
  verifies the chain and the rights and the *enforcer* that dispatches the
  call checks the stencil stack, because only it knows what the call is.
  The proxy is that enforcer for its own routes, so it evaluates the
  stencil against the request line and headers. This keeps the issue's
  stated tie to the attestation and profiles arc (circus EPIC 0001)
  without inventing a second permission model. Recommend: pilot routes use
  binding only; acts come in the second slice, once the stencil's
  vocabulary for a request (method, path, host) is agreed with
  cutting-garden, whose ajour work owns the fragment.

**5. Logging.** One audit line per request: time, route name, bound
scope, method, path *without query string*, status, byte counts, and
whether the decision was allow, refuse-binding, refuse-allowlist or
refuse-locked. Never a header value, body, query string or credential.
Refusals are logged at the same level as successes. Where the log goes
(journal versus file) follows FDR 0008 question 9, still open.

**6. Card lock state.** Fail closed and say so. A route whose secret is
unloaded or whose unsealing needs a locked or absent card answers HTTP
`503` with a fixed body naming the cause (`secret-unavailable`,
`card-locked`, `card-absent`); it never forwards without auth, never
substitutes an empty credential, and never queues indefinitely. This
matches the stance cutting-garden asked to keep (a missing binary or a
non-zero exit is a hard error). Prompting is the exception, allowed only
when a frontend scope is attached and the route is marked `prompt`
(FDR 0006 scope rules), so that one proxy holding a secret answers all
plugins from one unlock instead of one PIN prompt each, which is the
requirement the issue gives for a single decoration point.

**7. Relation to piggy-agent.** A sibling, not part of it and not its
client, matching FDR 0008's ruling (a sibling binary in the piggy repo,
not a mode of `piggy agent`). It shares `piggy-guard` and the
caller-binding code with the holder agent; the HTTP and TLS dependency
surface stays out of the agent and of `piggy` itself (the lint FDR 0008
proposes). The proxy obtains secrets through the same channel FDR 0008
uses; it does not speak the SSH-agent protocol to clients.

**8. TLS.** Recommend *terminate and re-originate*, with the client side
of the proxy plain HTTP over the unix socket. The client does not use TLS
to the proxy, because a unix socket reached only by a bound caller already
has the confidentiality TLS would add, and a CONNECT tunnel cannot add
headers. The proxy originates TLS to the route's upstream, verifying the
certificate against the route's expected name and refusing redirects off
the upstream host. Trust cost, stated: the proxy sees every request and
response in plaintext, exactly as FDR 0008 says, and must not log bodies.
Auth schemes needed for the pilots: `bearer` first; `basic` for
caldav-style routes; signed-request schemes (for example AWS-style)
deferred, since they sign the final request and force the proxy to
understand it. Where a provider supports end-to-end body encryption
(Tinfoil's EHBP) the proxy may add only the key header and stay blind to
the body, per FDR 0008.

**9. Approval display (piggy#387).** First use of a route by a new bound
scope, and any request that an act's escalation widens, appear as an
approval in the zellige-rosette dialog idea with: route name, upstream
host, the scope's identity, and the method and path of the request that
triggered it. Never the credential. Not designed further here; piggy#387
owns the dialog.

**10. Scope.** HTTP and HTTPS upstreams only. Other protocols plugins use
(IMAP, SMTP, raw TCP) are out of scope; if a plugin needs one, it is a
separate record, not a mode of this proxy.

### Isolation properties required of any design

- No credential in any client-visible byte: response, error, log line,
  redirect target, or header echoed by the upstream (the proxy strips
  response headers that echo credentials, as FDR 0008 does).
- A client cannot choose the upstream. The route fixes it; a client path
  that normalises outside the route's `allow` list is refused before any
  upstream connection is made.
- Per-microvm identity (tent): a bound scope's routes are its own; one
  scope cannot name, list or probe another's routes. An unbound or
  unknown route and a route the scope may not use answer the same.

## What the first pilot route needs

The candidate named on #388: the circus GitHub-mirror reconciler, which
calls `api.github.com` with a create-capable token and must work without
the proxy.

- **Route.** `github-api`: upstream `https://api.github.com`, scheme
  `bearer`, allowed methods and path prefixes limited to what the
  reconciler uses (creating repositories under named owners; the exact
  list is the reconciler's to supply), secret `github/mirror-create`.
- **From the reconciler.** One configuration value, its GitHub API base
  URL, already planned. Pointed at `http://proxy-socket/github-api`
  (with the socket path given to its HTTP client) the same code runs with
  or without the proxy. It must send no `Authorization` header when
  routed through the proxy, which means its own token path stays off in
  that mode. It must treat `503` with `card-locked` as a stop, not a
  retry loop. HTTP over a unix socket needs client support; if the
  reconciler's client lacks it, a local socket-to-TCP shim run as a bound
  caller is the interim, noted in question 1.
- **From piggy.** A frontend-only way to load the token (the `load` verb
  of FDR 0008), the route table entry, per-scope sockets or the binding
  fallback, the audit line, and the `503` behaviour. The token is the
  operator's create token; the push-only token stays in Forgejo's mirror
  configuration, outside the proxy's reach, as the issue states.
- **Why it is a good first route.** One bearer secret, one host, a small
  allowlist, an operator-run client that is dry-run by default, and a
  fallback (its own token path) if anything is wrong. It exercises
  routing, decoration, binding, fail-closed and logging without needing
  acts, TLS to a provider with end-to-end encryption, or the per-run
  binding of graph runs.

## Examples

**The pilot call.** The operator has loaded `github/mirror-create` into
the proxy after it started. The reconciler runs from a scope bound to
route `github-api` and sends:

    POST /github-api/orgs/example-org/repos HTTP/1.1
    Host: ignored
    Content-Type: application/json

    {"name": "example-mirror", "private": true}

The proxy checks the peer's binding, checks the method and path against
the route's allowlist, adds `Authorization: Bearer <token>`, sends the
request to `api.github.com` and returns the response. The reconciler's
argv, environment, files and memory hold no token.

**Refusals.** A request from an unbound scope, to a route the scope may
not use, or to an unknown route: the same fixed refusal. A path outside
the allowlist: refused before any connection. A card or secret
unavailable: `503` with the cause, no request sent upstream. A client
`Authorization` header: dropped.

## Limitations

- **The proxy is a trusted component** and sees plaintext (see 8).
- **It guards the credential, not what the credential can do.** A bound
  caller can use whatever the token permits on the allowlisted paths.
- **No guest packet path.** Tent v1 gives guests no network; this record
  does not design guest networking or the virtual card device, and does
  not specify how a microvm reaches a socket on the host.
- **Linux only**, as FDR 0006.
- **No RFC 0013 change.** The no-credentials-on-the-wire rule is kept;
  the proxy fits it because a plugin needs only a proxy address and a
  route name, which a handshake can carry.
- **Not a general HTTP proxy.** It serves configured routes only.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| socket per scope | one per bound scope | directory permissions are the first gate | too many scopes to manage |
| route naming | URL path prefix | works for every HTTP client | a client that cannot set a base URL |
| act checks | off for pilot routes | binding is enough for one operator-run client | a second route needs per-request conditions |
| prompting | off | fail closed is the stance cutting-garden wants | a plugin set that cannot work without a prompt |

## What the neighbouring records change

Read after the first draft; none of it contradicts the answers above.

**cutting-garden#285, Ruling (2026-11-16).** Option (d): plugins hold no
credential and resolve no indirection, so not even a key name reaches a
plugin; its config names the proxy. The ruling states what it leaves to
piggy: how the proxy is addressed, how routes map to entries, TLS. It
adds three requirements:

- *One batched PIN session.* The ruling counts "one batched PIN session"
  among the reasons for (d). The design meets it: the proxy holds each
  secret after one load, so any number of plugins share one unlock.
- *Cross-reference, not restatement.* cutting-garden will point RFC 0013's
  Security Considerations and cutting-garden-config(5) at piggy's own
  docs once they exist. This record is therefore the document they cite,
  and should stay stable in its route-naming and addressing sections; a
  change there is a contract change for them.
- *`password_source = "piggy"` stays.* The in-process path remains until
  the proxy supersedes it, so the proxy does not need to be reachable from
  in-tree plugins on day one. Smith's `serve-cutting_garden` is blocked
  on this feature; it is the first out-of-tree client after the pilot.

**Tent FDR 0002.** Decision 4 (ruled) gives the VMM and every guest no
network: `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`, no tap, no
bridge, no user-mode networking. Decision 3's long-range shape (not a
design) is a pod-like unit of microvms, each with a fibby card attached
virtually that also authenticates its network access. What it changes
here:

- The unix socket is the *only* transport tent's units can use; a
  loopback or inet listener is unusable to them, which confirms question
  1. A unit that may speak to the proxy needs the socket's path made
  reachable inside its namespace (a bind mount of that one socket), which
  is a tent decision, not a proxy feature.
- tent's outbound-transfer decision (journal only in v1; a results
  directory or a unix socket later) is a separate channel from the
  decoration proxy; they should not be merged into one socket.
- The virtual card's attachment (a VMM device, a socket into the pod's
  fibby unit, or other) stays undesigned and is outside this record.
  What this record keeps open for it: a route's secret may later be held
  by a per-pod fibby instead of the host proxy, so the route table's
  `secret` field names a secret, not a store location.

## Pilot implementation plan

For the coordinator's timeline (design 2026-11-17, operator decisions
2026-11-17/18, build 2026-11-19 to 21, reconciler pointed at it
2026-11-22). Everything here is a proposal pending the operator's answers
to the "blocks" questions; file and module names are suggestions, not
facts about code that does not exist yet.

**Scope: the minimal pilot.** One listener (a unix stream socket), one
route (`github-api`, a bearer credential for `api.github.com`), fail
closed when the secret is unloaded, no per-caller acts, no route table
beyond the single entry.

**TLS in the pilot (correction to a framing).** Decoration needs the
proxy to see the request, so the client side is plain HTTP on the unix
socket and the proxy originates TLS to the upstream. A pure tunnel cannot
add headers, so "no TLS termination" is not available to a route that
attaches a header. What the pilot omits is TLS *to the client*, not TLS
to GitHub. The library choice is the open FDR 0008 question 1; the pilot
needs only a TLS client and an HTTP/1.1 client with certificate
verification against the fixed name.

**Process and files (proposed).**

- A new workspace crate, a sibling binary (working name `piggy-decorate`),
  holding all HTTP and TLS dependencies; `piggy`, the agent and fibby do
  not link them, enforced by a lint in the style of
  `checks.lint-closure-no-pivy`.
- Modules: listener (socket creation, mode `0600`, peer credentials), a
  route record (name, upstream, allowed methods and path prefixes, scheme
  `bearer`, secret name), the secret holder (one `GuardedBytes` from
  `piggy-guard`), the request path (parse, strip `Host`, `Authorization`
  and credential-echoing headers, check the allowlist, forward), the audit
  line, and a control verb `load`.
- Loading: `piggy pass show <entry> | piggy-decorate load github-api`
  over a control socket reachable only by the operator's own account
  (FDR 0008 candidate 3). The pilot's single-operator, single-host
  binding is the socket's file mode plus a peer-UID check; cgroup binding
  and per-scope sockets wait for the scope-binding ruling (#386).

**Behaviour the tests pin.**

1. A request to `/github-api/<path>` reaches the fake upstream with
   `Authorization: Bearer <token>` and without the client's own
   `Authorization`, `Host` or `Cookie`.
2. The token is absent from every byte the client receives (response
   headers, body, error bodies), from the audit line, and from the proxy's
   own argv and environment; a test greps for it.
3. An unloaded secret answers `503` with the fixed cause `secret-unavailable`
   and the fake upstream sees no connection.
4. A path or method outside the allowlist, or an unknown route, is refused
   before any upstream connection; the two refusal bodies are identical.
5. A redirect from the upstream to another host is not followed and is
   returned as an error, never with the token attached to the second host.
6. A connection from another UID is refused.
7. The audit line has route, method, path without query, status, decision
   and no header values.
8. Reload: a second `load` replaces the held secret; an in-flight request
   finishes on the old one.

**Fake upstream.** A test-only local server with a self-signed
certificate, and the proxy configured to trust only that certificate for
the test's route; no test reaches the real `api.github.com` or a real
card. A real-network check is a human pass, run by the operator with the
real token, which is also the phase-acceptance step FDR 0006 requires.
Tests that could reach a PIN prompt follow the askpass safety net in
piggy-testing(7).

**Unprivileged operation.** The proxy runs as the operator's own account
in the pilot, with no capabilities; the socket directory is `0700`. The
service-account split of FDR 0006 (a dedicated unit) is a later phase and
needs the same ruling as the holder.

**What the pilot deliberately omits.** RFC 0013 act checks and any
stencil evaluation; more than one route and any route table file (the
single route is compiled in or read from a minimal config); per-scope
sockets and cgroup binding; prompting (always fail closed); `basic` and
signed-request schemes; the approval dialog (#387); tent's microvm
attachment and the virtual card; non-HTTP protocols; the second client
(smith).

**Who implements.** Recommend a fresh piggy session spawned for the
build, with this record as its brief, working on the sibling crate only;
this session keeps the design and reviews the result against the
behaviours above. The two RFC 0013 sessions (bright-hemlock,
eager-poplar) are not involved. Mechanical parts (HTTP plumbing, the
fake upstream) go to subagents at opus or lower, as the standing
constraint requires.

**Dependencies on operator answers.** Question 1 (one unit or two) fixes
the crate's name and whether the FDR 0008 request shape ships in the same
binary; the pilot needs neither the handle model nor graph runs. Question
7 (TLS library) must be answered before the build; the recommendation is
to choose the library the build can compile and audit most easily, and to
record the choice in this record. Everything else in the plan above holds
whatever the answers to questions 2, 3 and 4.

## Open questions

For the operator unless noted. "Blocks" blocks the first slice.

1. **One unit or two? (blocks)** Recommended: one proxy binary and one
   route table serving both this record and FDR 0008, FDR 0008's request
   shape becoming a client of the unix-socket transport. Alternative: two
   units. Needs the operator's ruling because FDR 0008's wire form is
   itself still open (its question 6).
2. **Socket per scope or shared socket with route checks? (blocks)**
   Recommended per scope; depends on the scope-binding ruling (#386,
   clown#244).
3. **Route naming in the URL path prefix? (blocks)** Recommended; the
   alternatives are rejected above. Needs cutting-garden's and the
   reconciler's agreement because it is their client contract.
4. **First pilot: the mirror reconciler's `github-api` route?** Recommended
   as above. Needs the reconciler's maintainer (circus, quiet-maple's
   line) to confirm the allowlist it needs and its client's unix-socket
   support.
5. **Which acts and which stencil vocabulary for requests?** For the
   second slice; cutting-garden owns the fragment.
6. **Where does the proxy run?** On the host of its clients (flic for the
   reconciler; krone for graph runs); who loads secrets on each. FDR 0008
   questions 5 and 7.
7. **TLS library.** openssl versus a pure-Rust stack, as FDR 0008
   question 1 left it.
8. **Audit log destination** (FDR 0008 question 9).

## More Information

- piggy#388 (this design discussion), piggy#387 (the approval dialog
  idea), cutting-garden#285 (the ruling, option (d)).
- FDR 0008 (secret proxy for provider keys), FDR 0006 (holder, binding,
  scopes, guarded memory), RFC 0013 and piggy-acts(7) (acts, rights,
  conditions, the enforcer's stencil checks), circus EPIC 0001.
