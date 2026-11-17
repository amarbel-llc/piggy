//! The audit line: one per request, refusals at the same level as
//! successes (FDR 0009 question 5, behaviour 7).
//!
//! A line carries the route, the bound scope, the method, the path without
//! its query string, the status, byte counts and the decision. Never a
//! header value, a body, a query string or a credential. Method and path
//! come from the client, so they are reduced to a plain character set and
//! truncated before they are written. Where lines go is FDR 0008 question 9,
//! still open; the pilot writes them to stderr through [`StderrSink`].

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// The peer is not bound to the scope (behaviour 6).
    RefuseBinding,
    /// Unknown route, or a method or path outside the allowlist.
    RefuseAllowlist,
    /// The route's secret is not loaded.
    RefuseUnavailable,
    /// The upstream failed, redirected off-host or echoed the credential.
    RefuseUpstream,
    /// The client's request could not be read.
    RefuseMalformed,
    /// The client hung up while the request was in flight; the upstream
    /// call was cancelled.
    ClientGone,
}

impl Decision {
    pub fn token(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::RefuseBinding => "refuse-binding",
            Decision::RefuseAllowlist => "refuse-allowlist",
            Decision::RefuseUnavailable => "refuse-unavailable",
            Decision::RefuseUpstream => "refuse-upstream",
            Decision::RefuseMalformed => "refuse-malformed",
            Decision::ClientGone => "client-gone",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub time: u64,
    /// The route the request named, when it named a known one.
    pub route: Option<&'static str>,
    pub scope: String,
    pub method: Option<String>,
    /// The request path, query string removed.
    pub path: Option<String>,
    pub status: Option<u16>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub decision: Decision,
}

impl AuditRecord {
    pub fn new(scope: &str, decision: Decision) -> Self {
        Self {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            route: None,
            scope: scope.to_owned(),
            method: None,
            path: None,
            status: None,
            bytes_in: 0,
            bytes_out: 0,
            decision,
        }
    }

    /// Record the client's method and request target. The query string is
    /// removed here, before anything is stored.
    pub fn request(mut self, method: &str, target: &str) -> Self {
        let path = target.split('?').next().unwrap_or("");
        self.method = Some(plain(method, 16));
        self.path = Some(plain(path, 256));
        self
    }
}

/// `s` reduced to characters that cannot break a `key=value` line, and at
/// most `max` of them.
fn plain(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_alphanumeric()
                || matches!(c, '/' | '.' | '-' | '_' | '~' | '%' | '+' | ',')
            {
                c
            } else {
                '?'
            }
        })
        .collect()
}

impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_owned());
        write!(
            f,
            "pigtrough audit time={} route={} scope={} method={} path={} status={} bytes_in={} bytes_out={} decision={}",
            self.time,
            self.route.unwrap_or("-"),
            plain(&self.scope, 64),
            dash(&self.method),
            dash(&self.path),
            self.status
                .map_or_else(|| "-".to_owned(), |s| s.to_string()),
            self.bytes_in,
            self.bytes_out,
            self.decision.token(),
        )
    }
}

pub trait AuditSink: Send + Sync {
    fn record(&self, record: &AuditRecord);
}

pub struct StderrSink;

impl AuditSink for StderrSink {
    fn record(&self, record: &AuditRecord) {
        eprintln!("{record}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_has_no_query_and_neutralised_client_text() {
        let mut r = AuditRecord::new("operator", Decision::Allow).request(
            "GET",
            "/github-api/repos/amarbel-llc/x?token=secret-in-query",
        );
        r.time = 1;
        r.route = Some("github-api");
        r.status = Some(200);
        r.bytes_out = 12;
        assert_eq!(
            r.to_string(),
            "pigtrough audit time=1 route=github-api scope=operator method=GET \
             path=/github-api/repos/amarbel-llc/x status=200 bytes_in=0 bytes_out=12 decision=allow"
        );

        let mut r = AuditRecord::new("operator", Decision::RefuseAllowlist)
            .request("GET x=1", "/a b\nforged=1");
        r.time = 1;
        let line = r.to_string();
        assert!(!line.contains('\n'));
        assert!(
            line.contains("method=GET?x?1 path=/a?b?forged?1 "),
            "{line}"
        );
    }
}
