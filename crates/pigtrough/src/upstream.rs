//! The seam to the upstream HTTP/TLS client.
//!
//! The HTTP and TLS stack (FDR 0009 ruling t1: rustls with the ring
//! provider, hyper on tokio) is used only by implementations of
//! [`UpstreamClient`]: one request in, one response out, the response body
//! streamed. The
//! implementation must originate TLS to [`Upstream::host`], verify the
//! certificate against that name, and never follow a redirect; the proxy
//! checks redirects itself ([`crate::filter`]). Until a client is written,
//! the tests drive the proxy through a fake implementation.

use std::fmt;
use std::io::Read;
use std::sync::Arc;

use piggy_guard::{GuardError, GuardedBytes};
use zeroize::Zeroizing;

use crate::Headers;
use crate::route::{Scheme, Upstream};

/// The credential for one outbound request. It renders the header value only
/// inside [`Credential::with_header_value`], into memory it wipes after, and
/// prints as `<redacted>`.
#[derive(Clone)]
pub struct Credential {
    scheme: Scheme,
    secret: Arc<GuardedBytes>,
}

impl Credential {
    pub fn new(scheme: Scheme, secret: Arc<GuardedBytes>) -> Self {
        Self { scheme, secret }
    }

    /// The header the credential goes in.
    pub fn header_name(&self) -> &'static str {
        match self.scheme {
            Scheme::Bearer | Scheme::Token => "Authorization",
        }
    }

    /// Run `f` over the rendered header value (for a bearer secret,
    /// `Bearer <secret>`). The value is wiped when `f` returns; an
    /// implementation that must keep a copy for the length of the request
    /// is responsible for wiping it.
    pub fn with_header_value<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, GuardError> {
        let value = self.secret.with(|secret| {
            let mut value = Zeroizing::new(Vec::with_capacity(7 + secret.len()));
            match self.scheme {
                Scheme::Bearer => value.extend_from_slice(b"Bearer "),
                Scheme::Token => value.extend_from_slice(b"token "),
            }
            value.extend_from_slice(secret);
            value
        })?;
        Ok(f(&value))
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

/// What the proxy sends upstream. `headers` holds the forwarded client
/// headers plus `Host`; the credential header is added by the client from
/// [`Credential`], and nothing else may set it.
#[derive(Debug)]
pub struct OutboundRequest<'a> {
    pub method: &'a str,
    /// Request target on the upstream, starting with `/`.
    pub path_and_query: String,
    pub headers: Headers,
    pub credential: Credential,
    pub body: &'a [u8],
}

pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Headers,
    /// The body with any transfer coding removed.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// Why the upstream gave no response. Deliberately carries no text from the
/// upstream or the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    Connect,
    Tls,
    Protocol,
}

pub trait UpstreamClient: Send + Sync {
    fn send(
        &self,
        upstream: &Upstream,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError>;
}

/// One client shared by several proxies (one per listener).
impl<T: UpstreamClient + ?Sized> UpstreamClient for Arc<T> {
    fn send(
        &self,
        upstream: &Upstream,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError> {
        (**self).send(upstream, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_renders_bearer_and_debug_redacts() {
        let secret = Arc::new(GuardedBytes::from_slice(b"piggy-test-tok").unwrap());
        let c = Credential::new(Scheme::Bearer, secret);
        assert_eq!(c.header_name(), "Authorization");
        assert_eq!(
            c.with_header_value(|v| v.to_vec()).unwrap(),
            b"Bearer piggy-test-tok"
        );
        assert_eq!(format!("{c:?}"), "Credential(<redacted>)");
    }

    #[test]
    fn credential_renders_the_token_scheme() {
        let secret = Arc::new(GuardedBytes::from_slice(b"piggy-test-tok").unwrap());
        let c = Credential::new(Scheme::Token, secret);
        assert_eq!(c.header_name(), "Authorization");
        assert_eq!(
            c.with_header_value(|v| v.to_vec()).unwrap(),
            b"token piggy-test-tok"
        );
    }
}
