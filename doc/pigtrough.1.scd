pigtrough(1)

# NAME

pigtrough - auth decoration proxy that attaches piggy credentials

# SYNOPSIS

*pigtrough serve* [*--dir* _DIR_] [*--routes* _FILE_]++
*pigtrough load* _ROUTE_ [*--dir* _DIR_]

# DESCRIPTION

*pigtrough* is the pilot of piggy's auth decoration proxy (FDR 0009). A
client sends an ordinary HTTP/1.1 request over a unix socket, naming a
route in the first path segment; *pigtrough* checks the request against
the route's allowlist, attaches the route's credential, sends the request
over TLS to the route's fixed upstream, and returns the response. The
client never holds, resolves or sees the credential.

Without *--routes* the pilot has one route, compiled in:

*github-api*
	Upstream *https://api.github.com*, a bearer token. It serves exactly
	these requests, for the owner *amarbel-llc* only:

	- GET /repos/_owner_/_name_
	- POST /orgs/_owner_/repos
	- PATCH /repos/_owner_/_name_
	- PUT /repos/_owner_/_name_/topics
	- GET /repos/_owner_/_name_/commits/_branch_
	- GET /repos/_owner_/_name_/compare/_a_..._b_

A client configured with the base URL *http://*_any_*/github-api* and
the socket below reaches these as */github-api/repos/...*, and so on.

# COMMANDS

*serve*
	Listen on _DIR_/*proxy.sock* (clients) and _DIR_/*control.sock*
	(*load*). Both sockets are mode *0600* in a directory of mode *0700*
	owned by the invoking user, and every connection is checked against
	the kernel's peer credentials: only the same user is admitted. The
	process makes itself non-dumpable. It starts with no credential
	loaded. Audit lines and control events go to standard error.

	With *--routes* _FILE_, the routes come from the TOML file instead
	(see ROUTE TABLE). Each route has its own credential, empty until
	its own *load*. A route that names a *loopback_port* is also served on
	*127.0.0.1*:_port_, where a client can name only that route. A
	connection there is admitted only if the kernel's table of TCP
	sockets (*/proc/net/tcp*) lists the client's end as owned by the
	invoking user; a connection it cannot attribute is refused. This
	checks who created the client socket, not a peer credential.

*load* _ROUTE_
	Read the credential for _ROUTE_ from standard input and hand it to
	the running *serve* over its control socket. One trailing newline is
	dropped, so the output of *piggy pass show* can be piped in directly.
	The credential is never accepted from an argument or the environment.
	Exits non-zero, with the server's reason, if the route is unknown or
	the input is empty or holds a space or control byte.

# OPTIONS

*--dir* _DIR_
	The directory holding both sockets. Default:
	*$XDG_RUNTIME_DIR/pigtrough*.

# ROUTE TABLE

*--routes* _FILE_ is TOML, read once at start; there is no reload. Any
error refuses to start, with no partial table. Each *[[route]]* has:

*name*
	The first path segment clients use. 1 to 32 of a-z, 0-9 and -; unique.

*upstream*
	_host_ or _host_:_port_ (port defaults to 443); a DNS name or IPv4
	address, nothing else.

*auth*
	*token* (_Authorization: token <secret>_) or *bearer*. There is no
	default.

*secret*
	The name of the piggy entry, never a value.

*owners*
	The owners a *{owner}* segment may be.

*loopback_port*
	Optional, 1024 or higher, unique across routes.

*forward_headers*
	Optional lower-case names; default *accept* and *user-agent*. A
	credential or framing header (_authorization_, _cookie_, _host_, ...)
	is refused.

*[[route.allow]]*
	At least one: a *method* (GET, POST, PUT, PATCH, DELETE) and a *path*
	array of plain literals and the kinds *{owner}*, *{name}*, *{ref}*,
	*{ref-range}*, *{number}*, *{number-diff}* (digits and _.diff_ or
	_.patch_) and *{rest}* (one or more pieces, last only). A path needs
	a literal, and no piece may be empty, _._ or _.._.

*extra_roots* is parsed but not supported yet: a table that sets it is
refused. Unknown keys are refused.

# BEHAVIOUR

- Only the client headers *Accept*, *Content-Type*, *User-Agent*,
  *X-GitHub-Api-Version*, *If-None-Match* and *If-Modified-Since* are
  forwarded. A client's *Authorization*, *Cookie* or *Host* never reaches
  the upstream; the proxy sets *Host* and the credential itself, and asks
  for an unencoded body (*Accept-Encoding: identity*).
- Response headers that carry the credential, cookies and hop-by-hop
  headers are dropped. The response body is scanned as it streams; if
  the upstream echoes the credential, the connection is aborted before
  any part of it is sent.
- Redirects are never followed. A redirect to another host is an error.
- Every request produces one audit line: time, route, scope, method, path
  without query string, status, byte counts and decision. Never a header
  value, body, query string or credential.

# SUPERVISION

The flake exports the home-manager module *services.pigtrough*
(*homeManagerModules.pigtrough*): a systemd user unit that runs *serve*
(with *--routes* and *--dir* from its options) and restarts it when it
exits. A restart comes back with every route unloaded, so each route
answers *503 secret-unavailable* until the operator runs *load* again by
hand; the unit never reads the card and never loads a credential.

# SIGNALS

*serve* installs no signal handler of its own, so *SIGINT* and *SIGTERM*
end it by their default action. The credential lived only in the process's
guarded memory and is gone with it; the sockets stay in _DIR_ until the
next *serve* replaces them. In a terminal, Ctrl-C works. A script that
starts *serve* in the background must stop it with *SIGTERM*: a
non-interactive shell starts background jobs with *SIGINT* ignored, and
the child inherits that, so *kill -INT* does nothing there.

# EXIT AND RESPONSE STATUS

Requests *pigtrough* answers itself carry a fixed body naming the cause:

*403 refused*
	An unknown route, or a method, owner or path outside the allowlist.
	All of these answer the same way, and none reaches the upstream.

*400 request-rejected*
	The request body could not be read whole (over 1 MiB, or shorter than
	its declared length).

*503 secret-unavailable*
	No credential is loaded. Nothing is sent upstream. A client should
	stop on any *503*, not retry.

*502 upstream-unavailable*
	The upstream could not be reached, failed certificate verification
	against the bundled Mozilla roots, or answered unreadably.

*502 upstream-redirect-refused*, *502 upstream-encoded-response*
	The upstream redirected to another host, or sent a content-coded
	body.

# EXAMPLES

Start the proxy, load the token from the operator's piggy store, and make
one call:

```
pigtrough serve &
piggy pass show github/forgejo-mirror | pigtrough load github-api
curl --unix-socket "$XDG_RUNTIME_DIR/pigtrough/proxy.sock" \
  http://pigtrough/github-api/repos/amarbel-llc/piggy
```

# LIMITATIONS

One scope: the invoking user. Prompting is never done: a missing
credential fails closed. A loopback port is reachable by every local
user, and its admission rests on the kernel's TCP socket table (a theory
still being tested for races and other users); the unix socket's peer
credential is the stronger check. The trusted roots are the *webpki-roots* bundle of the build, with
no way yet to add one. A client that disconnects does not cancel its
in-flight upstream call. Linux only.

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *piggy-acts*(7)

FDR 0009 (auth decoration proxy) and FDR 0008 (secret proxy) in the piggy
repository; the operator's acceptance pass is
docs/plans/2026-11-16-pigtrough-pilot-runbook.md.
