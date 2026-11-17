# pigtrough: operator-supplied extra trusted roots (design, not built)

Status: design only. Nothing here is implemented. It closes the first
"known gap" of the pilot runbook and is a precondition for any upstream whose
certificate does not chain to the `webpki-roots` bundle (a Forgejo behind a
private CA is the likely case; whether the operator's instance needs it is
unchecked).

## What exists

`tls.rs` already has `TlsUpstream::with_roots(runtime, RootCertStore)`; the
tests use it with the fake upstream's CA. `with_public_roots` is the only
production constructor. So the change is configuration plumbing, not TLS
work.

## Proposed behaviour

- `pigtrough serve --extra-roots FILE` (repeatable): FILE is a PEM bundle of
  CA certificates. The roots are the bundled Mozilla roots **plus** these.
- Per route, not global, once a route table exists: a route names which
  extra root files it trusts, so a private CA cannot vouch for
  `api.github.com`. Until then (pilot, one compiled-in route) the flag
  applies to every route; that is acceptable only because github-api is the
  sole route.
- Fail closed: an unreadable file, a file with no certificate, or a
  certificate that does not parse refuses to start `serve`. A bad bundle
  never silently falls back to the public roots alone.
- Never print certificate contents; the start line says only how many
  extra roots were added per file.
- Trust is by the CA only; no pinning, no "accept invalid" switch.

## Tests (all offline, no real credential)

1. A locally generated CA signs a leaf for the fake upstream; with
   `--extra-roots` the request succeeds, without it the proxy answers
   `502 upstream-unavailable`.
2. An empty file and a garbage file each make `serve` exit non-zero before
   binding the sockets.
3. With extra roots set on a route, a leaf signed by that CA for a *different*
   host is still refused (hostname verification unchanged).

## Open question for the design owner

Per-route scoping needs the route table (ruling R1). Recommendation: land the
global flag only if the operator wants the Forgejo route before the route
table; otherwise land both together.
