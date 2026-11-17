# pigtrough: the route table (slice 1, on paper)

Status: design only; nothing built. Depends on the open dependency ruling
(a TOML parser; see the coordinator's question to the operator). The parser
choice does not change the schema below.

## File

`pigtrough serve --routes FILE`, read once at start; no reload (ruling R1).
Without `--routes`, `serve` uses the compiled-in `github-api` as today, so
the pilot's behaviour and tests stay as they are. An unreadable file, a
parse error or any validation failure refuses to start `serve`, before any
socket is bound; no partial table.

## Schema

```toml
[[route]]
name = "forgejo-api"          # first path segment; [a-z0-9-]{1,32}, unique
upstream = "forgejo.example:443"   # host:port, port optional (443)
auth = "token"                # "token" | "bearer"  (R2; no default in the file)
secret = "forgejo/smith-readonly"  # the piggy entry NAME, never a value
owners = ["some-org"]         # what an Owner segment may be
loopback_port = 8731          # optional; bind 127.0.0.1:<port> for this route
extra_roots = ["/path/ca.pem"]    # optional PEM files (extra-roots design)
forward_headers = ["accept", "user-agent"]   # optional; default below

  [[route.allow]]
  method = "GET"
  path = ["api", "v1", "repos", "{owner}", "{name}"]
```

Path segments are literals or one of `{owner}`, `{name}`, `{ref}`,
`{ref-range}`: exactly the existing `Segment` kinds, so the matcher in
`route.rs` is reused unchanged. Anything else in braces is a validation
error. `auth` has no default in the file (the plan's "default token" is the
documented recommendation for smith, written by whoever authors the file);
an absent `auth` is a validation error, so a mis-typed route never silently
picks a scheme.

## Owned types

`route.rs` today is `&'static` throughout. The table needs owned data:
`Route { name: String, upstream: Upstream { host: String, port: u16 },
scheme, secret: String, owners: Vec<String>, allow: Vec<Allow>,
forward_headers: Vec<String>, loopback_port: Option<u16>, extra_roots:
Vec<PathBuf> }`, with `Allow { method: String, path: Vec<Segment> }`. The
compiled-in `GITHUB_API` becomes a function returning the same owned record,
so there is one code path. `admit`, `split_target` and the segment checks
change signature only (slices instead of `&'static`).

## Validation (all refuse to start)

- `name`: unique, matches `[a-z0-9-]{1,32}`.
- `upstream`: a host (no scheme, no path, no userinfo) and a port in
  1..=65535.
- `auth`: exactly `token` or `bearer`.
- `secret`: non-empty, no control byte or space.
- `owners`: each non-empty, `[A-Za-z0-9-_.]`; required if any allow path
  has `{owner}`.
- `allow`: at least one entry; `method` one of GET, POST, PUT, PATCH,
  DELETE, upper-case; no DELETE unless the operator spells it (it is
  accepted, never defaulted); at least one literal segment; no empty
  segment; no `.` or `..` literal; the same shape twice is an error.
- `forward_headers`: lower-case names; refuse `authorization`, `cookie`,
  `proxy-authorization`, `host` and any name the filter drops (the
  credential must never be forwarded). Default when absent: `accept`,
  `user-agent`.
- `loopback_port`: 1024..=65535; unique across routes; refused when it
  collides with another route's port. Binding is on `127.0.0.1` only.
- `extra_roots`: each file must read and hold at least one certificate
  (checked in slice 4 with the TLS code, not by the pure parser).

Validation errors name the route and field, never a secret, never file
contents beyond the field path.

## Tests (pure, offline)

1. The compiled-in github-api round-trips: a TOML rendering of it parses to
   an owned record equal to `github_api()`, and `admit` gives the same
   verdicts as the existing table-driven tests (they are reused).
2. A smith table (from smith's relayed call list: GET under `/api/v1`:
   `repos/{owner}/{name}`, issues, `issues/{n}` and the rest, the `token`
   scheme) admits every listed call and refuses a write, another owner and
   a dot segment.
3. One test per validation rule above: the bad table is refused, with the
   field named.
4. Unknown keys are an error (`deny_unknown_fields`), so a typo such as
   `loopbak_port` cannot silently drop a binding.

## Open items

- `{n}` (an issue or pull number) is not an existing `Segment` kind;
  smith's calls need a `{number}` segment (digits only, at most 10) added to
  `Segment`. This is a small change to `route.rs`, in slice 1.
- Smith's call list is the relayed one (issues, pulls, files, commits,
  repos, commit status, tags, releases, contents); the exact paths come from
  smith's source, not from this session. Take them from the smith worker
  before writing the allowlist.
- The `/proc/net/tcp` admission check (slice 4) is still a theory.
