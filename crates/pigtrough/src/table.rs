//! The route table file: TOML, read once at `serve` start (FDR 0009; operator
//! ruling R1, 2026-11-17).
//!
//! [`parse`] turns the text into validated [`RouteEntry`]s or refuses the
//! whole file: there is no partial table. A route's strings are leaked once
//! to give it the `'static` shape the rest of the crate uses
//! ([`crate::route::Route`]); the table is read once for the life of the
//! process, so nothing is lost by it.
//!
//! The file names secrets (`secret = "forgejo/smith-readonly"` is a piggy
//! entry name), never holds one. Errors name the route and the field; the
//! TOML parser's own errors quote the offending line of the file, which
//! holds no secret by construction.

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::route::{Allow, Limits, Route, Scheme, Segment, Upstream};

/// One route of the table, with the parts that are not in [`Route`].
#[derive(Debug)]
pub struct RouteEntry {
    pub route: &'static Route,
    /// A loopback TCP port to serve this route on, besides the unix socket.
    pub loopback_port: Option<u16>,
    /// PEM files of extra trusted roots; read and checked by the TLS code,
    /// not here.
    pub extra_roots: Vec<PathBuf>,
}

/// Why a table was refused.
#[derive(Debug, PartialEq, Eq)]
pub struct TableError(pub String);

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TableError {}

fn refuse<T>(route: &str, field: &str, reason: &str) -> Result<T, TableError> {
    Err(TableError(format!("route {route}: {field}: {reason}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    #[serde(default)]
    route: Vec<RouteSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSpec {
    name: String,
    upstream: String,
    auth: String,
    secret: String,
    #[serde(default)]
    owners: Vec<String>,
    loopback_port: Option<u16>,
    #[serde(default)]
    extra_roots: Vec<String>,
    forward_headers: Option<Vec<String>>,
    max_request_body_bytes: Option<u64>,
    response_head_timeout_seconds: Option<u64>,
    #[serde(default)]
    allow: Vec<AllowSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowSpec {
    method: String,
    path: Vec<String>,
}

/// Headers a route may never forward: credentials and hop-by-hop framing.
const FORBIDDEN_FORWARD: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookie2",
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

const DEFAULT_FORWARD: &[&str] = &["accept", "user-agent"];
const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// Parse and validate a route table. The whole file is refused on the first
/// problem.
pub fn parse(text: &str) -> Result<Vec<RouteEntry>, TableError> {
    let file: FileSpec =
        toml::from_str(text).map_err(|e| TableError(format!("route table: {e}")))?;
    if file.route.is_empty() {
        return Err(TableError("route table: no [[route]] entries".to_owned()));
    }
    let mut names = HashSet::new();
    let mut ports = HashSet::new();
    let mut entries = Vec::with_capacity(file.route.len());
    for spec in file.route {
        if !names.insert(spec.name.clone()) {
            return refuse(&spec.name, "name", "used by more than one route");
        }
        if let Some(port) = spec.loopback_port {
            if !ports.insert(port) {
                return refuse(&spec.name, "loopback_port", "used by more than one route");
            }
        }
        entries.push(build(spec)?);
    }
    // Extra roots belong to an upstream (host and port), not to a route, so
    // routes sharing an upstream must trust the same ones: otherwise one
    // route's private CA would vouch for another's calls.
    for (i, a) in entries.iter().enumerate() {
        for b in &entries[..i] {
            if a.route.upstream == b.route.upstream && a.extra_roots != b.extra_roots {
                return refuse(
                    a.route.name,
                    "extra_roots",
                    "a route sharing this upstream trusts different extra roots",
                );
            }
        }
    }
    Ok(entries)
}

fn build(spec: RouteSpec) -> Result<RouteEntry, TableError> {
    let name = spec.name.as_str();
    if !is_route_name(name) {
        return refuse(name, "name", "must be 1 to 32 characters of a-z, 0-9 and -");
    }
    let upstream = parse_upstream(name, &spec.upstream)?;
    let scheme = match spec.auth.as_str() {
        "bearer" => Scheme::Bearer,
        "token" => Scheme::Token,
        _ => return refuse(name, "auth", "must be \"token\" or \"bearer\""),
    };
    if spec.secret.is_empty()
        || spec.secret.len() > 128
        || !spec.secret.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return refuse(
            name,
            "secret",
            "must be 1 to 128 printable characters, no space",
        );
    }
    for owner in &spec.owners {
        if owner.is_empty()
            || owner.len() > 100
            || !owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return refuse(
                name,
                "owners",
                "each owner must be 1 to 100 name characters",
            );
        }
    }
    if let Some(port) = spec.loopback_port {
        if port < 1024 {
            return refuse(name, "loopback_port", "must be 1024 or higher");
        }
    }
    if spec.extra_roots.iter().any(|p| p.is_empty()) {
        return refuse(name, "extra_roots", "a path must not be empty");
    }
    let forward = forward_headers(name, spec.forward_headers)?;
    let allow = allow_list(name, &spec.allow, !spec.owners.is_empty())?;
    let limits = limits(
        name,
        spec.max_request_body_bytes,
        spec.response_head_timeout_seconds,
    )?;

    let route = Route {
        name: leak_str(spec.name),
        upstream,
        scheme,
        secret: leak_str(spec.secret),
        owners: leak_slice(spec.owners.into_iter().map(leak_str).collect()),
        allow: leak_slice(allow),
        forward_headers: leak_slice(forward.into_iter().map(leak_str).collect()),
        limits,
    };
    Ok(RouteEntry {
        route: Box::leak(Box::new(route)),
        loopback_port: spec.loopback_port,
        extra_roots: spec.extra_roots.into_iter().map(PathBuf::from).collect(),
    })
}

/// The route's limits: each is the default unless set, and set values stay
/// within 1 and the compiled ceiling.
fn limits(route: &str, body: Option<u64>, head: Option<u64>) -> Result<Limits, TableError> {
    let within = |field: &str, given: Option<u64>, ceiling: u64| match given {
        Some(n) if n == 0 || n > ceiling => {
            refuse(route, field, &format!("must be 1 to {ceiling}"))
        }
        other => Ok(other),
    };
    let body = within(
        "max_request_body_bytes",
        body,
        Limits::MAX_REQUEST_BODY_CEILING as u64,
    )?;
    let head = within(
        "response_head_timeout_seconds",
        head,
        Limits::HEAD_TIMEOUT_CEILING.as_secs(),
    )?;
    Ok(Limits {
        max_request_body: body.map_or(Limits::DEFAULT.max_request_body, |n| n as usize),
        response_head_timeout: head
            .map_or(Limits::DEFAULT.response_head_timeout, Duration::from_secs),
    })
}

fn is_route_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `host` or `host:port`, port defaulting to 443. A host is a DNS name or an
/// IPv4 literal: no scheme, no path, no userinfo, no brackets.
fn parse_upstream(route: &str, text: &str) -> Result<Upstream, TableError> {
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(p) if p >= 1 => (host, p),
            _ => return refuse(route, "upstream", "the port must be 1 to 65535"),
        },
        None => (text, 443),
    };
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if host.is_empty() || host.len() > 253 || !host.split('.').all(label_ok) {
        return refuse(
            route,
            "upstream",
            "must be a host name or IPv4 address with an optional :port",
        );
    }
    Ok(Upstream {
        host: leak_str(host.to_ascii_lowercase()),
        port,
    })
}

fn forward_headers(route: &str, given: Option<Vec<String>>) -> Result<Vec<String>, TableError> {
    let Some(names) = given else {
        return Ok(DEFAULT_FORWARD.iter().map(|s| (*s).to_owned()).collect());
    };
    for header in &names {
        let plain = !header.is_empty()
            && header
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !plain {
            return refuse(
                route,
                "forward_headers",
                "names are lower-case a-z, 0-9 and -",
            );
        }
        if FORBIDDEN_FORWARD.contains(&header.as_str()) {
            return refuse(
                route,
                "forward_headers",
                "a credential or framing header cannot be forwarded",
            );
        }
    }
    Ok(names)
}

fn allow_list(
    route: &str,
    specs: &[AllowSpec],
    has_owners: bool,
) -> Result<Vec<Allow>, TableError> {
    if specs.is_empty() {
        return refuse(route, "allow", "at least one entry is required");
    }
    let mut seen: Vec<(String, Vec<Segment>)> = Vec::new();
    let mut allow = Vec::with_capacity(specs.len());
    for spec in specs {
        if !METHODS.contains(&spec.method.as_str()) {
            return refuse(
                route,
                "allow.method",
                "must be one of GET, POST, PUT, PATCH, DELETE",
            );
        }
        let segments = segments(route, &spec.path)?;
        if !segments.iter().any(|s| matches!(s, Segment::Literal(_))) {
            return refuse(route, "allow.path", "needs at least one literal segment");
        }
        if !has_owners && segments.contains(&Segment::Owner) {
            return refuse(route, "owners", "required when a path uses {owner}");
        }
        let key = (spec.method.clone(), segments.clone());
        if seen.contains(&key) {
            return refuse(route, "allow", "the same method and path appear twice");
        }
        seen.push(key);
        allow.push(Allow {
            method: leak_str(spec.method.clone()),
            path: leak_slice(segments),
        });
    }
    Ok(allow)
}

fn segments(route: &str, path: &[String]) -> Result<Vec<Segment>, TableError> {
    if path.is_empty() {
        return refuse(route, "allow.path", "must not be empty");
    }
    let mut out = Vec::with_capacity(path.len());
    for (i, text) in path.iter().enumerate() {
        let segment = match text.as_str() {
            "{owner}" => Segment::Owner,
            "{name}" => Segment::Name,
            "{ref}" => Segment::Ref,
            "{ref-range}" => Segment::RefRange,
            "{number}" => Segment::Number,
            "{number-diff}" => Segment::NumberDiff,
            "{rest}" => Segment::Rest,
            literal => {
                let plain = !literal.is_empty()
                    && literal.len() <= 255
                    && literal != "."
                    && literal != ".."
                    && literal
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
                if !plain {
                    return refuse(
                        route,
                        "allow.path",
                        "a segment is a plain literal or one of {owner} {name} {ref} \
                         {ref-range} {number} {number-diff} {rest}",
                    );
                }
                Segment::Literal(leak_str(literal.to_owned()))
            }
        };
        if segment == Segment::Rest && i + 1 != path.len() {
            return refuse(route, "allow.path", "{rest} must be the last segment");
        }
        out.push(segment);
    }
    Ok(out)
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn leak_slice<T>(v: Vec<T>) -> &'static [T] {
    Box::leak(v.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{GITHUB_API, admit};

    /// A table with one valid route, with `extra` lines appended to it.
    fn one(extra: &str) -> String {
        format!(
            "[[route]]\nname = \"r\"\nupstream = \"forgejo.invalid\"\nauth = \"token\"\n\
             secret = \"piggy-test/none\"\nowners = [\"some-org\"]\n{extra}\n\
             [[route.allow]]\nmethod = \"GET\"\npath = [\"api\", \"v1\", \"repos\", \"{{owner}}\", \"{{name}}\"]\n"
        )
    }

    fn refused(text: &str, needle: &str) {
        match parse(text) {
            Ok(_) => panic!("accepted, wanted a refusal naming {needle:?}"),
            Err(e) => assert!(e.0.contains(needle), "{e} lacks {needle:?}"),
        }
    }

    #[test]
    fn the_compiled_in_github_route_round_trips() {
        let text = r#"
[[route]]
name = "github-api"
upstream = "api.github.com:443"
auth = "bearer"
secret = "github/forgejo-mirror"
owners = ["amarbel-llc"]
forward_headers = ["accept", "content-type", "user-agent", "x-github-api-version", "if-none-match", "if-modified-since"]

[[route.allow]]
method = "GET"
path = ["repos", "{owner}", "{name}"]
[[route.allow]]
method = "POST"
path = ["orgs", "{owner}", "repos"]
[[route.allow]]
method = "PATCH"
path = ["repos", "{owner}", "{name}"]
[[route.allow]]
method = "PUT"
path = ["repos", "{owner}", "{name}", "topics"]
[[route.allow]]
method = "GET"
path = ["repos", "{owner}", "{name}", "commits", "{ref}"]
[[route.allow]]
method = "GET"
path = ["repos", "{owner}", "{name}", "compare", "{ref-range}"]
"#;
        let entries = parse(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, &GITHUB_API);
        assert_eq!(entries[0].loopback_port, None);
        assert!(entries[0].extra_roots.is_empty());
    }

    #[test]
    fn a_smith_table_admits_its_calls_and_refuses_the_rest() {
        let text = r#"
[[route]]
name = "forgejo-api"
upstream = "forgejo.invalid:443"
auth = "token"
secret = "piggy-test/none"
owners = ["some-org"]
loopback_port = 8731

[[route.allow]]
method = "GET"
path = ["api", "v1", "repos", "{owner}", "{name}", "issues", "{number}", "comments"]
[[route.allow]]
method = "GET"
path = ["api", "v1", "repos", "{owner}", "{name}", "pulls", "{number-diff}"]
[[route.allow]]
method = "GET"
path = ["api", "v1", "repos", "{owner}", "{name}", "raw", "{rest}"]
"#;
        let entries = parse(text).unwrap();
        let r = entries[0].route;
        assert_eq!(r.scheme, Scheme::Token);
        assert_eq!(entries[0].loopback_port, Some(8731));
        assert_eq!(r.forward_headers, &["accept", "user-agent"]);
        let yes = |m: &str, t: &str| admit(&[r], m, t).is_some();
        assert!(yes(
            "GET",
            "/forgejo-api/api/v1/repos/some-org/x/issues/3/comments"
        ));
        assert!(yes(
            "GET",
            "/forgejo-api/api/v1/repos/some-org/x/pulls/3.diff"
        ));
        assert!(yes(
            "GET",
            "/forgejo-api/api/v1/repos/some-org/x/raw/.github/a.md?ref=m"
        ));
        assert!(!yes(
            "POST",
            "/forgejo-api/api/v1/repos/some-org/x/issues/3/comments"
        ));
        assert!(!yes(
            "GET",
            "/forgejo-api/api/v1/repos/other/x/issues/3/comments"
        ));
        assert!(!yes(
            "GET",
            "/forgejo-api/api/v1/repos/some-org/x/raw/a/../b"
        ));
    }

    #[test]
    fn a_valid_minimal_table_parses() {
        assert!(parse(&one("")).is_ok());
    }

    #[test]
    fn refuses_what_is_not_a_table() {
        refused("", "no [[route]]");
        refused("[[route]]\nname = \"r\"\n", "missing field");
        refused("this is not toml = = =", "route table");
    }

    #[test]
    fn unknown_keys_are_refused() {
        refused(&one("loopbak_port = 8731"), "loopbak_port");
        refused(
            &format!(
                "{}\n[[route.allow]]\nmethod = \"GET\"\npath = [\"a\"]\nextra = 1\n",
                one("")
            ),
            "extra",
        );
    }

    #[test]
    fn names_are_checked_and_unique() {
        refused(&one("").replace("name = \"r\"", "name = \"R\""), "name");
        refused(&one("").replace("name = \"r\"", "name = \"\""), "name");
        let two = format!("{}\n{}", one(""), one(""));
        refused(&two, "more than one route");
    }

    #[test]
    fn upstreams_are_checked() {
        for bad in [
            "https://forgejo.invalid",
            "forgejo.invalid/path",
            "user@forgejo.invalid",
            "[::1]:443",
            "forgejo.invalid:0",
            "forgejo.invalid:99999",
            "forgejo.invalid:x",
            "-bad.invalid",
            "a..b",
            "",
        ] {
            refused(&one("").replace("forgejo.invalid", bad), "upstream");
        }
        let ok = parse(&one("").replace("forgejo.invalid", "Forgejo.Invalid:8443")).unwrap();
        assert_eq!(ok[0].route.upstream.host, "forgejo.invalid");
        assert_eq!(ok[0].route.upstream.port, 8443);
        let default = parse(&one("")).unwrap();
        assert_eq!(default[0].route.upstream.port, 443);
    }

    #[test]
    fn auth_has_no_default_and_two_values() {
        refused(&one("").replace("auth = \"token\"\n", ""), "auth");
        refused(&one("").replace("\"token\"", "\"basic\""), "auth");
        let b = parse(&one("").replace("\"token\"", "\"bearer\"")).unwrap();
        assert_eq!(b[0].route.scheme, Scheme::Bearer);
    }

    #[test]
    fn secret_is_a_name_not_free_text() {
        refused(&one("").replace("piggy-test/none", "has space"), "secret");
        refused(&one("").replace("piggy-test/none", ""), "secret");
        refused(
            &one("").replace("piggy-test/none", &"x".repeat(129)),
            "secret",
        );
    }

    #[test]
    fn owners_are_checked_and_required_by_owner_paths() {
        refused(&one("").replace("[\"some-org\"]", "[\"a b\"]"), "owners");
        refused(&one("").replace("[\"some-org\"]", "[\"\"]"), "owners");
        refused(&one("").replace("owners = [\"some-org\"]\n", ""), "owners");
    }

    #[test]
    fn allow_entries_are_checked() {
        refused(
            &one("").replace("method = \"GET\"", "method = \"get\""),
            "allow.method",
        );
        refused(
            &one("").replace("method = \"GET\"", "method = \"TRACE\""),
            "allow.method",
        );
        refused(
            &one("").replace("\"api\", \"v1\", ", "\"..\", "),
            "allow.path",
        );
        refused(
            &one("").replace("\"{owner}\"", "\"{owners}\""),
            "allow.path",
        );
        refused(
            &one("").replace("\"api\", \"v1\", \"repos\", ", ""),
            "literal",
        );
        refused(
            &one("").replace("\"{name}\"]", "\"{rest}\", \"x\"]"),
            "last",
        );
        refused(&one("").replace("path = [", "path = [\"\", "), "allow.path");
        let dup = format!(
            "{}\n[[route.allow]]\nmethod = \"GET\"\npath = [\"api\", \"v1\", \"repos\", \"{{owner}}\", \"{{name}}\"]\n",
            one("")
        );
        refused(&dup, "twice");
        let none = one("").replace("[[route.allow]]\nmethod = \"GET\"\npath = [\"api\", \"v1\", \"repos\", \"{owner}\", \"{name}\"]\n", "");
        refused(&none, "at least one entry");
        let delete = parse(&one("").replace("\"GET\"", "\"DELETE\""));
        assert!(
            delete.is_ok(),
            "an explicit DELETE is accepted, never defaulted"
        );
    }

    #[test]
    fn forwarded_headers_never_carry_a_credential() {
        for bad in [
            "authorization",
            "cookie",
            "host",
            "proxy-authorization",
            "content-length",
        ] {
            refused(
                &one(&format!("forward_headers = [\"{bad}\"]")),
                "forward_headers",
            );
        }
        refused(&one("forward_headers = [\"Accept\"]"), "forward_headers");
        refused(&one("forward_headers = [\"\"]"), "forward_headers");
        let ok = parse(&one("forward_headers = [\"accept\"]")).unwrap();
        assert_eq!(ok[0].route.forward_headers, &["accept"]);
    }

    #[test]
    fn limits_default_to_the_pilots_values() {
        let limits = parse(&one("")).unwrap()[0].route.limits;
        assert_eq!(limits.max_request_body, 1 << 20);
        assert_eq!(limits.response_head_timeout, Duration::from_secs(30));
    }

    #[test]
    fn limits_are_set_per_route_up_to_the_ceilings() {
        let ok = parse(&format!(
            "{}\n{}",
            one("max_request_body_bytes = 16777216\nresponse_head_timeout_seconds = 600"),
            one("max_request_body_bytes = 1\nresponse_head_timeout_seconds = 1")
                .replace("name = \"r\"", "name = \"s\"")
        ))
        .unwrap();
        assert_eq!(ok[0].route.limits.max_request_body, 16 << 20);
        assert_eq!(
            ok[0].route.limits.response_head_timeout,
            Duration::from_secs(600)
        );
        assert_eq!(ok[1].route.limits.max_request_body, 1);
        assert_eq!(
            ok[1].route.limits.response_head_timeout,
            Duration::from_secs(1)
        );
        for bad in ["0", "16777217", "-1", "\"1MiB\""] {
            let line = format!("max_request_body_bytes = {bad}");
            refused(&one(&line), "max_request_body_bytes");
        }
        for bad in ["0", "601", "-1", "1.5"] {
            let line = format!("response_head_timeout_seconds = {bad}");
            refused(&one(&line), "response_head_timeout_seconds");
        }
    }

    #[test]
    fn loopback_ports_are_checked_and_unique() {
        refused(&one("loopback_port = 80"), "loopback_port");
        refused(&one("loopback_port = 70000"), "route table");
        let two = format!(
            "{}\n{}",
            one("loopback_port = 8731"),
            one("loopback_port = 8731").replace("name = \"r\"", "name = \"s\"")
        );
        refused(&two, "loopback_port");
        let ok = parse(&format!(
            "{}\n{}",
            one("loopback_port = 8731"),
            one("loopback_port = 8732").replace("name = \"r\"", "name = \"s\"")
        ))
        .unwrap();
        assert_eq!(ok.len(), 2);
    }

    #[test]
    fn routes_sharing_an_upstream_must_trust_the_same_extra_roots() {
        let other = |roots: &str| {
            format!(
                "{}\n{}",
                one("extra_roots = [\"/a.pem\"]"),
                one(roots).replace("name = \"r\"", "name = \"s\"")
            )
        };
        refused(
            &other("extra_roots = [\"/b.pem\"]"),
            "different extra roots",
        );
        refused(&other(""), "different extra roots");
        assert!(parse(&other("extra_roots = [\"/a.pem\"]")).is_ok());
        // A different upstream may trust different roots.
        let apart = format!(
            "{}\n{}",
            one("extra_roots = [\"/a.pem\"]"),
            one("")
                .replace("name = \"r\"", "name = \"s\"")
                .replace("forgejo.invalid", "other.invalid")
        );
        assert!(parse(&apart).is_ok());
    }

    #[test]
    fn extra_roots_are_kept_as_paths() {
        refused(&one("extra_roots = [\"\"]"), "extra_roots");
        let ok = parse(&one("extra_roots = [\"/etc/ca.pem\"]")).unwrap();
        assert_eq!(ok[0].extra_roots, vec![PathBuf::from("/etc/ca.pem")]);
    }
}
