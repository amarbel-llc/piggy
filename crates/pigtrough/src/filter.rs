//! What crosses the proxy, in each direction.
//!
//! Outbound, the client's headers are filtered by allowlist: only the
//! route's `forward_headers` survive, so `Host`, `Authorization`, `Cookie`
//! and any key-bearing header a client might set are dropped whatever their
//! name (behaviour 1). Inbound, hop-by-hop and cookie headers are dropped,
//! any header whose value contains the secret is dropped, a redirect off
//! the upstream host is refused (behaviour 5), and the body is scanned for
//! the secret as it streams (behaviour 2).

use std::io::{self, Read};
use std::sync::Arc;

use piggy_guard::GuardedBytes;

use crate::Headers;
use crate::refusal::Cause;
use crate::route::{Route, Upstream};

/// The client headers the route forwards, plus the upstream's `Host`.
pub fn outbound_headers(route: &Route, client: &Headers) -> Headers {
    let mut out: Headers = client
        .iter()
        .filter(|(name, _)| {
            route
                .forward_headers
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
        })
        .cloned()
        .collect();
    out.push(("Host".to_owned(), route.upstream.host.as_bytes().to_vec()));
    out
}

/// Response headers the proxy never passes back: hop-by-hop headers (the
/// client side frames its own response) and cookies.
const RESPONSE_DROPPED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "trailer",
    "upgrade",
    "set-cookie",
    "set-cookie2",
];

/// Check an upstream response's status and headers, and return the headers
/// to pass back.
pub fn inbound_headers(
    upstream: &Upstream,
    status: u16,
    headers: Headers,
    secret: &GuardedBytes,
) -> Result<Headers, Cause> {
    if (300..400).contains(&status) {
        let location = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"));
        if let Some((_, value)) = location {
            if !location_stays_on(upstream, value) {
                return Err(Cause::UpstreamRedirectRefused);
            }
        }
    }
    let mut kept = Headers::with_capacity(headers.len());
    for (name, value) in headers {
        if RESPONSE_DROPPED
            .iter()
            .any(|dropped| name.eq_ignore_ascii_case(dropped))
        {
            continue;
        }
        if contains_secret(secret, &value)? {
            continue;
        }
        kept.push((name, value));
    }
    Ok(kept)
}

/// A redirect target the proxy lets the client see: a path on the same
/// upstream (relative, starting with a single `/`), or an absolute `https`
/// URL to exactly the upstream host. Anything else, including a
/// scheme-relative `//host/...`, is off-host.
fn location_stays_on(upstream: &Upstream, location: &[u8]) -> bool {
    let Ok(location) = std::str::from_utf8(location) else {
        return false;
    };
    if location.starts_with('/') {
        return !location.starts_with("//");
    }
    let Some(rest) = location.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let default_port = format!("{}:{}", upstream.host, upstream.port);
    authority.eq_ignore_ascii_case(upstream.host) || authority.eq_ignore_ascii_case(&default_port)
}

fn contains_secret(secret: &GuardedBytes, haystack: &[u8]) -> Result<bool, Cause> {
    secret
        .with(|needle| find(haystack, needle))
        .map_err(|_| Cause::UpstreamUnavailable)
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A response body that fails instead of returning the secret. It holds
/// back the last `len - 1` bytes it has read until more arrive (or the body
/// ends), so no prefix of an echoed secret is released before the whole of
/// it is seen. On a match the read errors and the caller must cut the
/// connection, the only fail-closed answer once headers are sent.
pub struct ScannedBody<R> {
    inner: R,
    secret: Arc<GuardedBytes>,
    /// Read from `inner`, checked, not yet returned.
    pending: Vec<u8>,
    eof: bool,
    /// Bytes returned so far.
    pub count: u64,
}

impl<R: Read> ScannedBody<R> {
    pub fn new(inner: R, secret: Arc<GuardedBytes>) -> Self {
        Self {
            inner,
            secret,
            pending: Vec::new(),
            eof: false,
            count: 0,
        }
    }
}

impl<R: Read> Read for ScannedBody<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let held_back = self.secret.len().saturating_sub(1);
        loop {
            let releasable = if self.eof {
                self.pending.len()
            } else {
                self.pending.len().saturating_sub(held_back)
            };
            if releasable > 0 && !buf.is_empty() {
                let n = releasable.min(buf.len());
                buf[..n].copy_from_slice(&self.pending[..n]);
                self.pending.drain(..n);
                self.count += n as u64;
                return Ok(n);
            }
            if self.eof || buf.is_empty() {
                return Ok(0);
            }
            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk)?;
            if n == 0 {
                self.eof = true;
                continue;
            }
            self.pending.extend_from_slice(&chunk[..n]);
            let echoed = self
                .secret
                .with(|needle| find(&self.pending, needle))
                .map_err(|_| io::Error::other("guarded memory"))?;
            if echoed {
                self.pending.clear();
                return Err(io::Error::other(Cause::UpstreamEchoedCredential.token()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::GITHUB_API;

    fn secret(s: &[u8]) -> Arc<GuardedBytes> {
        Arc::new(GuardedBytes::from_slice(s).unwrap())
    }

    fn h(pairs: &[(&str, &str)]) -> Headers {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn outbound_keeps_only_the_allowlist_and_sets_host() {
        let client = h(&[
            ("Host", "evil.example"),
            ("Authorization", "Bearer client-supplied"),
            ("authorization", "token client-supplied"),
            ("Proxy-Authorization", "x"),
            ("Cookie", "session=1"),
            ("X-Api-Key", "k"),
            ("Accept-Encoding", "gzip"),
            ("Connection", "keep-alive, Accept"),
            ("Accept", "application/vnd.github+json"),
            ("content-type", "application/json"),
            ("User-Agent", "reconciler"),
        ]);
        let out = outbound_headers(&GITHUB_API, &client);
        assert_eq!(
            out,
            h(&[
                ("Accept", "application/vnd.github+json"),
                ("content-type", "application/json"),
                ("User-Agent", "reconciler"),
                ("Host", "api.github.com"),
            ])
        );
    }

    #[test]
    fn inbound_drops_hop_by_hop_cookies_and_echoes() {
        let s = secret(b"piggy-test-tok");
        let got = inbound_headers(
            &GITHUB_API.upstream,
            200,
            h(&[
                ("Content-Type", "application/json"),
                ("Transfer-Encoding", "chunked"),
                ("Set-Cookie", "a=b"),
                ("X-Echo", "you sent Bearer piggy-test-tok"),
                ("ETag", "\"1\""),
            ]),
            &s,
        )
        .unwrap();
        assert_eq!(
            got,
            h(&[("Content-Type", "application/json"), ("ETag", "\"1\"")])
        );
    }

    #[test]
    fn redirects_must_stay_on_the_upstream_host() {
        let s = secret(b"piggy-test-tok");
        let up = &GITHUB_API.upstream;
        for ok in [
            "/repos/amarbel-llc/x",
            "https://api.github.com/repos/amarbel-llc/x",
            "https://API.github.com:443/x",
        ] {
            assert!(
                inbound_headers(up, 301, h(&[("Location", ok)]), &s).is_ok(),
                "{ok}"
            );
        }
        for off in [
            "https://evil.example/",
            "http://api.github.com/x",
            "//evil.example/x",
            "https://api.github.com.evil.example/",
            "https://api.github.com@evil.example/",
            "https://api.github.com:8443/",
            "evil.example",
        ] {
            assert_eq!(
                inbound_headers(up, 302, h(&[("Location", off)]), &s),
                Err(Cause::UpstreamRedirectRefused),
                "{off}"
            );
        }
    }

    /// A reader that hands out one byte per read, so a secret is always
    /// split across reads.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.split_first() {
                Some((b, rest)) if !buf.is_empty() => {
                    buf[0] = *b;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn scanned_body_passes_clean_bodies_and_counts() {
        let mut body = ScannedBody::new(Trickle(b"{\"id\":1}"), secret(b"piggy-test-tok"));
        let mut out = Vec::new();
        body.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"{\"id\":1}");
        assert_eq!(body.count, 8);
    }

    #[test]
    fn scanned_body_fails_on_an_echo_split_across_reads() {
        let mut body = ScannedBody::new(
            Trickle(b"{\"token\":\"piggy-test-tok\"}"),
            secret(b"piggy-test-tok"),
        );
        let mut out = Vec::new();
        let err = body.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.to_string(), "upstream-echoed-credential");
        assert_eq!(
            out, b"{\"token\":\"",
            "no prefix of the secret was released"
        );
    }
}
