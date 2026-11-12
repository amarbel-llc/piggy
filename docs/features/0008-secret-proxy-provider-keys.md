---
status: proposed
date: 2026-11-12
promotion-criteria: >
  proposed -> experimental when the operator has approved this record, the
  open questions below marked "blocks" are ruled, and the first slice has
  landed: a proxy unit that holds one provider key in guarded memory, makes
  one allowlisted outbound call for a bound caller, and returns the
  response without the key, proven by a test that greps the caller's
  captured bytes for the key. Every phase closes with a human pass (FDR
  0006, "Phase acceptance").
---

# Secret proxy: provider API keys held by the holder, calls made on the caller's behalf

> **Status of this draft.** Written on the operator's ruling of
> 2026-11-12 (batch 13, relayed by the coordinator, circus/eager-holly):
> design A first (a holder-side proxy), option B (provider-minted scoped
> keys) only as a fallback. Docs only; nothing is built. Not approved.

> **Parent record.** FDR 0006 (fibby as guarded key holder): the holder
> units, guarded memory (`piggy-guard`), caller binding by peer
> credentials and cgroup, and teardown on scope exit (phase (d)). This
> record adds a tier for secrets that are not PIV keys. Where the two
> disagree, FDR 0006 is reconciled first.

## Problem Statement

Graph runs on krone (the issue-filer graph, Pebble, and later anything
roustabout or juggler runs) must call OpenRouter and Tinfoil with an API
key that a run never writes to disk and, ideally, never even holds. FDR
0006's holder cannot do this as written: its invariant is that no private
key crosses a socket, which works for signing because a signature proves
possession without disclosing the key. An API key is a bearer string: any
caller that is handed it can copy it into a file, a log or a child
process. The only way to keep the "never leaves" property is for the
holder to make the call itself.

## Interface

### The tier

A **secret proxy**: a unit beside the holder (same service account family
as FDR 0006's holder agent, its own process so a bug in HTTP handling
cannot reach the PIV keys). It holds provider keys in `piggy-guard`
allocations and exposes one unix socket. A caller asks for a call; the
proxy attaches the key, sends the call, and returns the response. The key
is never in any response, error message or log line.

It is a sibling binary in the piggy repo (ruled by the operator,
2026-11-12; see "Open questions", item 1, for the dependency cost).

### The request

A caller connects to the proxy socket and sends one request:

| Field | Meaning |
|---|---|
| `handle` | the name of a provider secret the caller is bound to (`openrouter`, `tinfoil`) |
| `method`, `path` | the HTTP request line, path relative to the provider's allowlisted base URL |
| `headers` | caller headers; any `Authorization` or key-bearing header the caller sets is dropped, never forwarded |
| `body` | the request body, bytes |

The response is the provider's status, headers (minus any that echo
credentials) and body, streamed for streaming endpoints. A request to a
handle the caller is not bound to, to a path outside the allowlist, or to
a revoked handle is refused with an error distinguishable from a provider
error.

The wire form (an agent-style extension, plain HTTP over the unix socket,
or a small framed protocol) is not fixed here; it is the subject of an RFC
when the first slice is scheduled. Plain HTTP over a unix socket is the
simplest for juggler and roustabout and is the working assumption.

### Egress allowlist

The proxy is configured, not told, where it may send a key. Per provider:
one base URL (scheme, host, port), the HTTP methods and path prefixes
allowed, and the TLS name to verify. A caller cannot name a host; the
`handle` selects it. This is what stops a bound caller from pointing the
proxy at a host it controls and reading the key out of the request. The
proxy also refuses redirects to any other host. Allowlist changes are
operator-only configuration changes, never a request.

### Binding and teardown

Reuses FDR 0006 phase (d), unchanged in kind:

- A handle is bound to a caller scope when the run starts. The proxy reads
  the peer's credentials and cgroup on each connection exactly as the
  holder agent does, and honours a request only from the bound scope.
- Teardown is when the bound cgroup disappears or on an explicit retire,
  whichever comes first. After teardown the handle answers "revoked".
- The proxy holds no lifetime timer of its own; a run's end is the clock.
  An optional per-handle request or spend cap is a lever (below), not a
  clock.

Who binds, and whether a handle binds to a graph, a run or both, is the
per-run binding issue's subject and depends on clown#244 and the open
scope-binding ruling in FDR 0006.

### Loading a key after a restart

A proxy restart wipes every key, as in FDR 0006. Provider keys cannot be
regenerated, so a loading path exists. The design for issue #385 follows. It is a recommendation for the
operator, not a ruling.

**Candidates.**

1. **Operator input.** After each proxy start the operator supplies the
   key at a prompt in a frontend scope. Nothing durable; a restart needs
   a human.
2. **Card-unsealed pigpen blob.** The key lives as a pigpen document (RFC
   0008) sealed to the operator's card; the proxy asks a card agent to
   unseal it, which needs the card and a PIN or touch. The blob is safe
   at rest and ties to FDR 0006 phase (g) durable sealed keys. It needs a
   new sealed-secret format and an unseal verb that does not exist yet.
3. **Load from the operator's piggy password store.** The provider key
   already can live as an ordinary `.ebox` in the operator's store
   (`piggy pass`), encrypted to the card's slot 9D. A small `load` verb
   of the proxy reads the secret from stdin and the operator runs, for
   example, `piggy pass show providers/openrouter | <proxy> load
   openrouter`. Decryption happens through the operator's card agent,
   including over a forwarded agent (FDR 0001), so the proxy host needs
   no card. This is candidate 1 with the prompt replaced by tooling
   piggy already has; no new format.

**Recommendation.** Candidate 3 for the first slice, because it needs no
new cryptographic format, keeps the key encrypted at rest in a store the
operator already backs up, and works when the proxy runs on a host with no
card. Candidate 2 later, only if restarts without the operator present
become a requirement; it is the only candidate that allows an unattended
restart, and it should be designed with phase (g) so there is one sealed
durable key format, not two.

**Behaviour rules, whichever candidate.**

- An unloaded handle answers "unavailable", never an empty or default key.
- The `load` verb is reachable only from a frontend scope (FDR 0006 scope
  rules), never from a bound caller, so a graph run cannot replace a key
  or load one of its own choosing.
- The key crosses a pipe once, into guarded memory; the loader zeroizes
  its own buffer. The operator sees the handle name and provider host at
  load time, not the key.
- Rotation is a repeat `load` of the same handle, replacing the held key
  atomically; in-flight calls finish on the old key.
- A proxy start with nothing loaded is valid (it serves "unavailable");
  it does not fail, so the unit can start before the operator is present.

**Open for the operator.** Whether unattended restarts are a requirement
(decides when candidate 2 is needed); which host runs the proxy and
whether the operator reaches it with a forwarded agent; whether the
provisioning/admin key for option B (below) is loaded the same way.

### Fallback: provider-minted scoped keys (option B)

The proxy can instead hold a long-lived provisioning key and hand each
run a short-lived key. This weakens the guarantee: the run holds a bearer
string and can copy it. The bound is the key's caps and lifetime, and
revocation is the provider's. It is a fallback only, used for a case where
proxying is impractical (for example a client that must speak to the
provider directly) and is not built unless A cannot serve.

**Research result (#384), read from the providers' documentation on
2026-11-12. Both providers support the mechanism; neither was tried
against a live account, so every statement is "documented", not
"verified".**

| | OpenRouter | Tinfoil |
|---|---|---|
| Create a key by API | yes: `POST /api/v1/keys` with a management key | yes: `POST /api/keys` with an admin key |
| Expiry per key | yes: `expires_at` (ISO 8601 UTC, seconds required) | yes: `expires_at`; omitted means non-expiring |
| Spend cap | yes: `limit` in USD, optional `limit_reset` daily/weekly/monthly | yes: `max_cost` in dollars, a lifetime total |
| Token caps | not seen in the create call | yes: `max_input_tokens`, `max_output_tokens` (lifetime) |
| Revoke | yes: delete or `disabled: true` by key hash | yes: delete by full key value |
| Scope by model or endpoint | not seen in the key-create call; the docs list Guardrails and Workspaces as separate management routes, not read | not seen |
| Plaintext returned | once, in the create response only | in the create response; the key value is also what update and delete take |
| Provisioning key power | management key is unscoped across the account's workspaces and cannot call completions; the docs recommend an expiry and warn a leak can create, edit and delete other keys | admin key; personal or organization; a scoped-admin-keys section exists for container routes (not read in detail) |
| Caps are exact | not stated | no: usage records arrive after completion, so limits are soft and in-flight requests overshoot (documented) |

Sources: OpenRouter, "Management API Keys"
(`openrouter.ai/docs/guides/overview/auth/provisioning-api-keys`) and the
API reference page "Create a new API key"; Tinfoil, "Admin API
documentation" (`docs.tinfoil.sh/admin/admin-api`), section API Key
Management. Not read or not verified: OpenRouter Guardrails and
Workspaces as a way to restrict a minted key to models; Tinfoil's
scoped-admin-keys section; rate limits on the create calls; whether
either provider can be reached from krone.

Consequences for the design:

- **B is real for both**, bounded by expiry and a spend cap rather than by
  endpoint scope. A run holding a minted key can spend up to the cap
  against any model the provider allows until expiry or deletion.
- **B moves the high-value secret, it does not remove it.** The proxy (or
  a sibling) would hold a management or admin key, which can create and
  delete every key on the account. That key is more dangerous than a
  single inference key and must live under the same guarded-memory rules,
  loaded as above. A leak of the inference key under A costs spend; a leak
  of the management key under B costs the account's key set.
- **Soft Tinfoil caps** mean a per-run cap is a bound with overshoot, not
  a hard ceiling.
- **Tinfoil changes A's plaintext limitation.** Tinfoil bodies can be
  encrypted end to end to an attested enclave (EHBP, using HPKE) by its
  SDKs, and its documentation describes a backend proxy that adds the
  API key header without being able to read the bodies
  (`docs.tinfoil.sh/guides/proxy-server`). A proxy of ours in that role
  would never see Tinfoil plaintext, but the caller must then use a
  Tinfoil SDK pointed at the proxy with attestation verified in the
  client, the proxy must preserve the EHBP headers, and it must allowlist
  the `X-Tinfoil-Enclave-Url` header's host (the documentation says to
  treat it as untrusted input). OpenRouter has no such mode, so its
  traffic is plaintext to the proxy.

## Examples

**Worked example: a krone graph calls OpenRouter.** A roustabout graph run
on krone needs a chat completion.

1. Before the run, the operator has loaded the OpenRouter key into the
   proxy (once after the proxy started).
2. The runner starts the graph in its own cgroup and binds the handle
   `openrouter` to that cgroup (mechanism: per-run binding issue).
3. The graph node sends `POST /api/v1/chat/completions` with a JSON body
   to the proxy socket, naming handle `openrouter`. It sets no
   `Authorization` header and has no key to set.
4. The proxy checks the peer's cgroup against the binding, checks the path
   against the allowlist, adds the key, calls OpenRouter, and streams the
   response back.
5. The run ends; its cgroup disappears; the binding is dropped. A later
   call from any scope gets "revoked" or "not bound".
6. If the graph's process dumps its environment, files and memory, no
   OpenRouter key is in any of it.

**Refusal examples.** A process in a sibling cgroup sends the same
request: refused (not bound). A bound caller sends `path` pointing outside
the allowlist, or a `Host` header naming another host: refused, and the
header is ignored. A bound caller sends its own `Authorization`: dropped.

## Limitations

- **The proxy sees plaintext.** It terminates TLS to the provider and sees
  every request and response body (for OpenRouter; Tinfoil's end-to-end
  body encryption can avoid this, see option B). It is a trusted
  component; the prompts and completions pass through it. It must not log
  bodies.
- **It guards the key, not what the key can do.** A bound caller can spend
  the provider account's money and read model output through the proxy for
  as long as it is bound. Per-handle caps are a lever, not a guarantee.
- **Root on the host reads process memory.** Guarded pages do not defend
  against root; the same limit as FDR 0006 ("guarded-memory backing").
- **Clients that cannot be proxied.** A client that insists on holding the
  key (an SDK that signs its own requests, a provider-side WebSocket the
  proxy cannot forward) needs option B or an exception. Not designed here.
- **Linux only**, as FDR 0006.
- **Provider API surface.** The proxy forwards generically by allowlisted
  path; it does not understand the providers' APIs. Streaming (server-sent
  events) is a requirement for the first slice, since graphs stream.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| per-handle request cap | none | a run's end already bounds it | a run observed looping on a provider account |
| per-handle spend cap | none | needs provider response parsing the proxy does not do | a spend incident, or a provider reports cost in headers reliably |
| allowlisted paths | explicit prefixes per provider | smallest surface that serves the graphs | a graph needs an endpoint not listed |
| key load path | operator input first | no durable secret material in the first slice | restarts become frequent enough that a human is the bottleneck; then a sealed blob |
| proxy process | separate unit | HTTP and TLS code stays away from PIV keys | the operational cost of a second unit outweighs the isolation |

## Open questions

For the operator unless noted. Each marked "blocks" blocks the first
slice.

1. **Where does the proxy live? Ruled (operator, 2026-11-12): a sibling
   binary in the piggy repo.** Not a mode of `piggy agent`, not a circus
   service. It shares `piggy-guard` and the caller-binding code with the
   holder agent. Consequences, stated so they are not rediscovered:
   - **Dependency cost.** The workspace `Cargo.lock` links `tokio` and
     `openssl` today but no HTTP client, no TLS library other than
     openssl, and no `rustls`, `hyper`, `reqwest` or `ureq` (checked by
     searching the lockfile, 2026-11-12). The proxy needs an HTTP/1.1
     client with streaming and a TLS client with certificate
     verification against the provider's name. That is a new, large
     dependency surface in code that holds provider keys, and it is the
     part of the build most exposed to the network. Choosing between
     openssl (already linked, but piggy is moving off C: see the
     LibreSSL and vendored-pivy retirement issues) and a pure-Rust TLS
     stack is part of the first slice's design and is not decided here.
   - **Isolation.** The binary is its own process and unit, so the HTTP
     and TLS code never shares an address space with the PIV keys, the
     card agent or fibby. The dependencies are gated to that crate only
     (a new workspace member), not the `piggy` binary, and a lint in the
     merge gate, modelled on `checks.lint-closure-no-pivy`, should fail if
     the `piggy` or holder binaries link the HTTP/TLS stack.
   - **Allowlist knowledge.** The provider-specific allowlist is circus's
     knowledge, held in piggy's configuration: operator-edited, never
     supplied by a caller.
2. **How is a key loaded after a restart? (blocks; #385)** Recommended:
   load from the operator's piggy password store through a frontend-only
   `load` verb for the first slice; a card-sealed blob later only if
   unattended restarts are required. Needs the operator's ruling on
   unattended restarts.
3. **What does a handle bind to? (blocks; per-run binding issue)** A
   graph, a run, or both; who may bind; gated on clown#244 and FDR 0006's
   open scope-binding ruling.
4. **Is option B real for either provider? (#384)** Researched
   2026-11-12 from documentation only: yes for both, bounded by expiry and
   spend caps, not by model or endpoint scope (see the table under option
   B). Open: whether OpenRouter Guardrails can restrict a minted key to
   models, and whether to accept holding an account-wide management key.
5. **Does krone run the proxy, or flic, or both?** Where the graphs run
   decides which host's units and which account layout apply. Not checked
   here; FDR 0006's holder is Linux-only and says nothing about krone.
6. **Wire form.** Plain HTTP over a unix socket versus an agent-style
   extension. Working assumption is HTTP; an RFC fixes it with the first
   slice.
7. **Egress allowlist ownership.** Who edits it and how it is reviewed;
   operator-only is assumed.
8. **Multiple keys per provider.** Whether one handle maps to one key or a
   handle can rotate between keys without the caller noticing.
9. **Audit.** Whether the proxy records which handle and bound scope made
   which call (without bodies or keys), and where that record goes.

## More Information

- FDR 0006, "Guarded memory", "The holder service", phase (d) binding and
  teardown, phase (g) sealed durable keys.
- Issues: #382 (phase (c)), #383 (phase (d)), #384 (provider key research),
  #385 (key loading), and #386 (per-run handle binding).
- RFC 0008 (pigpen), for the sealed-blob load path.
- clown#244 (scope definition), a gate for binding.
