//! The upstream client: HTTP/1.1 over rustls (ring provider), with hyper.
//!
//! [`TlsUpstream`] is the production [`UpstreamClient`]. It dials the
//! route's upstream, verifies the certificate against the route's host name
//! and the roots it was built with, sends one request, and never follows a
//! redirect (the proxy checks redirects itself). The pilot builds it with the
//! Mozilla roots of `webpki-roots`; a test builds it with the fake upstream's
//! CA as the only root, and with [`TlsUpstream::connect_to`] pointing the dial
//! at a local address while the name verified stays the route's host.
//!
//! The bundled roots age with the `webpki-roots` version this crate locks;
//! a later slice may add an operator-supplied extra-roots file (the shithub
//! per-process trust bundle idea).
//!
//! The request path is synchronous, so [`UpstreamClient::send`] runs the
//! async client on the given runtime with `Handle::block_on`, which the
//! server calls from a blocking thread, never from a runtime worker.

use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio_rustls::TlsConnector;

use crate::cancel::Cancel;
use crate::route::Upstream;
use crate::upstream::{OutboundRequest, UpstreamClient, UpstreamError, UpstreamResponse};
use crate::wire::{extend_header_map, from_header_map};

/// How long the dial, the TLS handshake and the response head may take
/// together.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TlsUpstream {
    config: Arc<ClientConfig>,
    runtime: Handle,
    connect_to: Option<SocketAddr>,
}

impl TlsUpstream {
    /// Verify upstreams against the Mozilla roots bundled in `webpki-roots`.
    pub fn with_public_roots(runtime: Handle) -> Self {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Self::with_roots(runtime, roots)
    }

    /// Verify upstreams against `roots` only.
    pub fn with_roots(runtime: Handle, roots: RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            config: Arc::new(config),
            runtime,
            connect_to: None,
        }
    }

    /// Dial `addr` instead of the route's host and port; the certificate is
    /// still verified against the route's host. For tests against a local
    /// fake upstream; the binary never sets it.
    pub fn connect_to(mut self, addr: SocketAddr) -> Self {
        self.connect_to = Some(addr);
        self
    }

    async fn send_async(
        &self,
        upstream: &Upstream,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let tcp = match self.connect_to {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((upstream.host, upstream.port)).await,
        }
        .map_err(|_| UpstreamError::Connect)?;
        let name = ServerName::try_from(upstream.host).map_err(|_| UpstreamError::Tls)?;
        let tls = TlsConnector::from(self.config.clone())
            .connect(name, tcp)
            .await
            .map_err(|_| UpstreamError::Tls)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| UpstreamError::Protocol)?;
        self.runtime.spawn(async move {
            let _ = connection.await;
        });

        let mut outbound = Request::builder()
            .method(request.method)
            .uri(request.path_and_query.as_str())
            .body(Full::new(Bytes::copy_from_slice(request.body)))
            .map_err(|_| UpstreamError::Protocol)?;
        extend_header_map(outbound.headers_mut(), &request.headers);
        // hyper keeps its own copy of the value, which is not wiped; marking
        // it sensitive keeps it out of hyper's debug output and HPACK tables.
        let mut credential = request
            .credential
            .with_header_value(HeaderValue::from_bytes)
            .map_err(|_| UpstreamError::Protocol)?
            .map_err(|_| UpstreamError::Protocol)?;
        credential.set_sensitive(true);
        let header = HeaderName::from_bytes(request.credential.header_name().as_bytes())
            .map_err(|_| UpstreamError::Protocol)?;
        outbound.headers_mut().insert(header, credential);

        let response = sender
            .send_request(outbound)
            .await
            .map_err(|_| UpstreamError::Protocol)?;
        let (parts, body) = response.into_parts();
        Ok(UpstreamResponse {
            status: parts.status.as_u16(),
            headers: from_header_map(&parts.headers),
            body: Box::new(BlockingBody {
                body,
                runtime: self.runtime.clone(),
                pending: Bytes::new(),
                done: false,
                cancel: request.cancel.clone(),
            }),
        })
    }
}

impl UpstreamClient for TlsUpstream {
    fn send(
        &self,
        upstream: &Upstream,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let cancel = request.cancel.clone();
        self.runtime.block_on(async {
            // Dropping the call when the client has gone closes its
            // upstream connection.
            tokio::select! {
                result = tokio::time::timeout(HEAD_TIMEOUT, self.send_async(upstream, request)) => {
                    result.unwrap_or(Err(UpstreamError::Connect))
                }
                () = cancel.cancelled() => Err(UpstreamError::Cancelled),
            }
        })
    }
}

/// An upstream body read synchronously, one frame at a time.
struct BlockingBody {
    body: Incoming,
    runtime: Handle,
    pending: Bytes,
    done: bool,
    cancel: Cancel,
}

impl Read for BlockingBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.len());
                buf[..n].copy_from_slice(&self.pending[..n]);
                self.pending.advance(n);
                return Ok(n);
            }
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            let next = self.runtime.block_on(async {
                tokio::select! {
                    frame = self.body.frame() => Some(frame),
                    () = self.cancel.cancelled() => None,
                }
            });
            match next {
                None => return Err(io::Error::other("the client went away")),
                Some(None) => self.done = true,
                Some(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.pending = data;
                    }
                }
                Some(Some(Err(_))) => return Err(io::Error::other("upstream body broke off")),
            }
        }
    }
}
