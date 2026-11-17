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
`{ref-range}`, `{number}`, `{number-diff}` (digits plus `.diff` or
`.patch`) and `{rest}` (one or more pieces, last segment only): the
`Segment` kinds, so the matcher in `route.rs` is shared. Anything else in
braces is a validation error.

Implementation note (slice 1 as built): instead of turning every `&'static`
type in `route.rs` into an owned one, the parser (`table.rs`) leaks the
validated strings once to produce the same `&'static Route` the rest of the
crate already takes. The table is read once for the life of the process, so
nothing is lost, and `proxy`, `control` and `filter` need no change in this
slice. `auth` has no default in the file (the plan's "default token" is the
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
- Smith's call list came from smith workers reading smith's source at
  smith master 12444e1 (file and line cited there), relayed by the
  coordinator, not read by this session. All calls are `GET` under `/api/v1`
  with no body; headers are `Authorization` and `User-Agent` only. The
  native CLI's allowlist (paths below `/repos/{owner}/{name}`):
  `issues`, `issues/{number}`, `issues/{number}/comments`, `pulls`,
  `pulls/{number}`, `pulls/{number}/files`, `pulls/{number}/commits`,
  `pulls/{number}.diff` and `.patch` (if wanted), `commits/{ref}/status`,
  `tags`, `releases`, `contents` (the list, no file path) and
  `raw/{filepath}`; plus `repos/{owner}/{name}` itself. `pulls/{n}/files`
  is also called by plain `pr view`, so it is allowed for every PR view.
  `contents/{filepath}` stays OFF the allowlist: smith's Rust code never
  calls it (the moxin content tool might, via `smith api`: a theory, not
  traced), so it is added only if the operator wants that path proxied.
- **Segment kinds to add**: `{number}` (digits only, at most 10), a
  `{number}.diff` / `{number}.patch` form (digits plus one of those two
  suffixes), and a rest-of-path kind for `raw/{filepath}`. The
  rest-of-path kind must keep the traversal rules: it takes one or more
  `/`-separated pieces, each non-empty, none `.` or `..`, no percent
  encoding, only the characters `is_name` allows, and it is the last
  segment of its shape. Smith's template paths (`.github/ISSUE_TEMPLATE/..`)
  start with a dot and pass; `..` does not.
- Paging: calls that page send `page=N` and read `x-total-count` (a
  response header, forwarded to the client as a plain response header).
  Query strings are admitted by the existing plain-character check; the
  allowed query keys per shape are not restricted in the pilot. The
  response-header filter passes `x-total-count`: `RESPONSE_DROPPED` in
  `filter.rs` lists only hop-by-hop headers and cookies (read, not run).
- The `/proc/net/tcp` admission check (slice 4) is still a theory.
