//! The route record and its allowlist.
//!
//! The pilot has one route, compiled in ([`GITHUB_API`]); a route table file
//! is out of the pilot's scope (FDR 0009, "What the pilot deliberately
//! omits"). A route fixes its upstream, its auth scheme, the secret it
//! uses, and exactly which methods and path shapes it serves. Anything that
//! does not match is refused before an upstream connection is made.

/// Where a route's requests go. The host is also the only host a redirect
/// may point at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub host: &'static str,
    pub port: u16,
}

/// How the credential is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `Authorization: Bearer <secret>`.
    Bearer,
}

/// One segment of an allowed path shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Exactly this text.
    Literal(&'static str),
    /// One of the route's [`Route::owners`].
    Owner,
    /// A repository name.
    Name,
    /// A branch name or commit id.
    Ref,
    /// `<ref>...<ref>`, as GitHub's compare endpoint takes it.
    RefRange,
}

/// One allowed request shape: a method and a whole path, segment by segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allow {
    pub method: &'static str,
    pub path: &'static [Segment],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Route {
    /// The first path segment clients use to name the route.
    pub name: &'static str,
    pub upstream: Upstream,
    pub scheme: Scheme,
    /// The name of the secret the route uses; never its value.
    pub secret: &'static str,
    /// The owners an [`Segment::Owner`] may be.
    pub owners: &'static [&'static str],
    pub allow: &'static [Allow],
    /// The client request headers forwarded upstream (compared ignoring
    /// case). Every other client header is dropped, so a credential the
    /// client sets under any name never leaves the proxy.
    pub forward_headers: &'static [&'static str],
}

use Segment::{Literal, Name, Owner, Ref, RefRange};

/// The pilot route, for the circus mirror reconciler (FDR 0009, "What the
/// first pilot route needs"); the allowlist is the one its maintainer
/// supplied.
pub static GITHUB_API: Route = Route {
    name: "github-api",
    upstream: Upstream {
        host: "api.github.com",
        port: 443,
    },
    scheme: Scheme::Bearer,
    secret: "github/mirror-create",
    owners: &["amarbel-llc"],
    allow: &[
        Allow {
            method: "GET",
            path: &[Literal("repos"), Owner, Name],
        },
        Allow {
            method: "POST",
            path: &[Literal("orgs"), Owner, Literal("repos")],
        },
        Allow {
            method: "PATCH",
            path: &[Literal("repos"), Owner, Name],
        },
        Allow {
            method: "PUT",
            path: &[Literal("repos"), Owner, Name, Literal("topics")],
        },
        Allow {
            method: "GET",
            path: &[Literal("repos"), Owner, Name, Literal("commits"), Ref],
        },
        Allow {
            method: "GET",
            path: &[Literal("repos"), Owner, Name, Literal("compare"), RefRange],
        },
    ],
    forward_headers: &[
        "accept",
        "content-type",
        "content-length",
        "user-agent",
        "x-github-api-version",
        "if-none-match",
        "if-modified-since",
    ],
};

/// A client request target that names a route and fits its allowlist.
#[derive(Debug, PartialEq, Eq)]
pub struct Admitted<'r, 't> {
    pub route: &'r Route,
    /// The upstream path, starting with `/`, without the route prefix.
    pub path: &'t str,
    /// The query string, without its `?`.
    pub query: Option<&'t str>,
}

impl Admitted<'_, '_> {
    /// The upstream request target.
    pub fn path_and_query(&self) -> String {
        match self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.to_owned(),
        }
    }
}

/// Split a request target into its path and query.
pub fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// Look `target` up among `routes` and check it against the route's
/// allowlist. `None` for every refusal, whatever the reason (behaviour 4).
pub fn admit<'r, 't>(
    routes: &'r [&'r Route],
    method: &str,
    target: &'t str,
) -> Option<Admitted<'r, 't>> {
    let (path, query) = split_target(target);
    if query.is_some_and(|q| !query_is_plain(q)) {
        return None;
    }
    let rest = path.strip_prefix('/')?;
    let split = rest.find('/')?;
    let (name, upstream_path) = rest.split_at(split);
    let route = routes.iter().copied().find(|r| r.name == name)?;
    route
        .allow
        .iter()
        .any(|allow| allow.method == method && path_matches(route, allow.path, upstream_path))
        .then_some(Admitted {
            route,
            path: upstream_path,
            query,
        })
}

fn path_matches(route: &Route, shape: &[Segment], path: &str) -> bool {
    let Some(segments) = path.strip_prefix('/') else {
        return false;
    };
    let segments: Vec<&str> = segments.split('/').collect();
    segments.len() == shape.len()
        && shape
            .iter()
            .zip(&segments)
            .all(|(shape, seg)| segment_matches(route, *shape, seg))
}

fn segment_matches(route: &Route, shape: Segment, seg: &str) -> bool {
    match shape {
        Literal(text) => seg == text,
        Owner => route.owners.contains(&seg),
        Name => is_name(seg),
        Ref => is_ref(seg),
        RefRange => seg
            .split_once("...")
            .is_some_and(|(a, b)| is_ref(a) && is_ref(b)),
    }
}

/// A repository name: GitHub's characters, at most 100 of them, and not a
/// dot segment. Percent-encoding is refused outright, so a path cannot
/// smuggle a `/` or `..` past the segment check.
fn is_name(seg: &str) -> bool {
    !seg.is_empty()
        && seg.len() <= 100
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// A branch name or commit id, limited to one path segment.
fn is_ref(seg: &str) -> bool {
    is_name(seg) && !seg.contains("..") && seg.len() <= 255
}

/// A query string of plain characters only: no space, no control bytes, no
/// fragment.
fn query_is_plain(query: &str) -> bool {
    query.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'=' | b'&' | b'-' | b'_' | b'.' | b'~' | b'%' | b'+' | b','
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted(method: &str, target: &str) -> bool {
        admit(&[&GITHUB_API], method, target).is_some()
    }

    #[test]
    fn every_reconciler_call_is_admitted() {
        for (method, target) in [
            ("GET", "/github-api/repos/amarbel-llc/piggy"),
            ("POST", "/github-api/orgs/amarbel-llc/repos"),
            ("PATCH", "/github-api/repos/amarbel-llc/piggy"),
            ("PUT", "/github-api/repos/amarbel-llc/piggy/topics"),
            ("GET", "/github-api/repos/amarbel-llc/piggy/commits/master"),
            (
                "GET",
                "/github-api/repos/amarbel-llc/piggy/compare/abc123...master",
            ),
            (
                "GET",
                "/github-api/repos/amarbel-llc/piggy.github.io?per_page=1",
            ),
        ] {
            assert!(admitted(method, target), "{method} {target}");
        }
    }

    #[test]
    fn admitted_target_drops_the_route_prefix() {
        let a = admit(
            &[&GITHUB_API],
            "GET",
            "/github-api/repos/amarbel-llc/piggy?x=1",
        )
        .unwrap();
        assert_eq!(a.path, "/repos/amarbel-llc/piggy");
        assert_eq!(a.path_and_query(), "/repos/amarbel-llc/piggy?x=1");
    }

    #[test]
    fn refuses_other_owners_methods_and_shapes() {
        for (method, target) in [
            ("GET", "/github-api/repos/someone-else/piggy"),
            ("GET", "/github-api/repos/Amarbel-llc/piggy"),
            ("DELETE", "/github-api/repos/amarbel-llc/piggy"),
            ("POST", "/github-api/repos/amarbel-llc/piggy"),
            ("GET", "/github-api/user"),
            ("GET", "/github-api/repos/amarbel-llc/piggy/"),
            ("GET", "/github-api/repos/amarbel-llc/piggy/hooks"),
            ("GET", "/github-api/repos/amarbel-llc"),
            ("GET", "/github-api"),
            ("GET", "/github-api/"),
            ("GET", "/elsewhere/repos/amarbel-llc/piggy"),
            ("GET", "github-api/repos/amarbel-llc/piggy"),
            ("GET", "/github-api/repos/amarbel-llc/.."),
            ("GET", "/github-api/repos/amarbel-llc/%2e%2e"),
            ("GET", "/github-api/repos/amarbel-llc/a%2Fb"),
            ("GET", "/github-api/repos//amarbel-llc/piggy"),
            ("GET", "/github-api/repos/amarbel-llc/piggy/commits/a..b"),
            ("GET", "/github-api/repos/amarbel-llc/piggy/compare/a..b"),
            ("GET", "/github-api/repos/amarbel-llc/piggy/compare/master"),
            ("GET", "/github-api/repos/amarbel-llc/piggy?a=b c"),
            ("GET", "/github-api/repos/amarbel-llc/piggy?a=b#frag"),
            ("GET", "https://api.github.com/repos/amarbel-llc/piggy"),
        ] {
            assert!(!admitted(method, target), "{method} {target}");
        }
    }
}
