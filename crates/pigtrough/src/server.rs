//! The client-facing wire adapter: HTTP/1.1 on the unix socket, with hyper.
//!
//! Each accepted connection passes the admission check first (behaviour 6;
//! the decision is [`crate::listener::admit_peer`], passed in as a closure so
//! a test can stand in for a second UID). A request no route admits is
//! refused before its body is read. An admitted one's body is read whole, up
//! to the route's limit and charged to the proxy's [`BodyBudget`], then
//! [`Proxy::handle`] runs on a blocking thread
//! (the request path and its upstream seam are synchronous) and the reply
//! body streams back through a channel. When the reply body fails (an echoed
//! credential, an upstream that broke off), the failure is passed to hyper as
//! a body error, which aborts the connection instead of ending the response
//! cleanly, so a cut response cannot look complete.
//!
//! A client that hangs up cancels its request: each request carries a
//! [`crate::cancel::Cancel`], fired when hyper drops the request future (the
//! proxy is still working) or the response body (it is streaming), and the
//! upstream dial, handshake, head wait or body read stops and closes its
//! connection. One known limit of running the synchronous path on the
//! blocking pool, for a later slice: the pool's size bounds concurrent
//! requests (the binary sets it explicitly, `MAX_IN_FLIGHT`).

use std::convert::Infallible;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::budget::BodyBudget;
use crate::cancel::{Cancel, CancelOnDrop};
use crate::proxy::{ClientRequest, Proxy, Reply, ReplyBody};
use crate::refusal::Cause;
use crate::upstream::UpstreamClient;
use crate::wire::{extend_header_map, from_header_map};

pub type ReplyStream = BoxBody<Bytes, io::Error>;

/// Accept connections on `listener` until it fails. `admit` decides each
/// connection before any byte of it is read; a refused connection is closed
/// and audited.
pub async fn serve<C, A>(listener: UnixListener, proxy: Arc<Proxy<C>>, admit: A) -> io::Result<()>
where
    C: UpstreamClient + 'static,
    A: Fn(&UnixStream) -> bool,
{
    loop {
        let (stream, _) = listener.accept().await?;
        if !admit(&stream) {
            proxy.refuse_binding();
            continue;
        }
        spawn_connection(stream, proxy.clone());
    }
}

/// Like [`serve`], for a loopback TCP listener (FDR 0009 listener options,
/// path 2). `admit` gets the connection's peer and local address; the unix
/// peer-credential check does not exist for TCP, so the caller supplies the
/// decision ([`crate::listener::admit_loopback_peer`]).
pub async fn serve_tcp<C, A>(
    listener: tokio::net::TcpListener,
    proxy: Arc<Proxy<C>>,
    admit: A,
) -> io::Result<()>
where
    C: UpstreamClient + 'static,
    A: Fn(std::net::SocketAddr, std::net::SocketAddr) -> bool,
{
    loop {
        let (stream, peer) = listener.accept().await?;
        let admitted = match stream.local_addr() {
            Ok(local) => admit(peer, local),
            Err(_) => false,
        };
        if !admitted {
            proxy.refuse_binding();
            continue;
        }
        spawn_connection(stream, proxy.clone());
    }
}

fn spawn_connection<C, S>(stream: S, proxy: Arc<Proxy<C>>)
where
    C: UpstreamClient + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let service = service_fn(move |request| respond(proxy.clone(), request));
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
}

async fn respond<C: UpstreamClient + 'static>(
    proxy: Arc<Proxy<C>>,
    request: Request<Incoming>,
) -> Result<Response<ReplyStream>, Infallible> {
    // Fires when hyper drops this future (the client hung up while the
    // proxy works) or, once the reply streams, its body.
    let cancel = Cancel::default();
    let guard = CancelOnDrop::new(cancel.clone());
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_owned();
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();
    let body = match proxy.admitted_limits(&method, &target) {
        Some(limits) => read_body(body, limits.max_request_body, proxy.body_budget()).await,
        None => Err(Cause::Refused),
    };
    let body = match body {
        Ok(body) => body,
        Err(cause) => {
            let reply = proxy.reject(&method, &target, cause);
            return Ok(to_response(reply, guard));
        }
    };
    let request = ClientRequest {
        method,
        target,
        headers: from_header_map(&parts.headers),
        body,
    };
    let reply = tokio::task::spawn_blocking(move || proxy.handle_with(request, cancel))
        .await
        .unwrap_or(Reply::Refusal(Cause::UpstreamUnavailable));
    Ok(to_response(reply, guard))
}

/// Read a request body whole: at most `limit` bytes, charged to `budget` as
/// they arrive, within the budget's read timeout.
async fn read_body(
    mut body: Incoming,
    limit: usize,
    budget: &Arc<BodyBudget>,
) -> Result<Bytes, Cause> {
    // A declared length over the limit is refused before any of it is read.
    if body.size_hint().lower() > limit as u64 {
        return Err(Cause::RequestRejected);
    }
    let mut charge = budget.reservation();
    let mut data = Vec::new();
    let whole = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| Cause::RequestRejected)?;
            let Ok(chunk) = frame.into_data() else {
                continue;
            };
            if chunk.len() > limit - data.len() {
                return Err(Cause::RequestRejected);
            }
            if !charge.grow(chunk.len()) {
                return Err(Cause::Busy);
            }
            data.extend_from_slice(&chunk);
        }
        Ok(())
    };
    tokio::time::timeout(budget.read_timeout(), whole)
        .await
        .map_err(|_| Cause::RequestRejected)??;
    Ok(charge.into_body(data))
}

/// `guard` goes with the response body, so a client that hangs up while the
/// body streams cancels the upstream read.
fn to_response(reply: Reply, guard: CancelOnDrop) -> Response<ReplyStream> {
    match reply {
        Reply::Refusal(cause) => {
            let mut response = Response::new(
                Full::new(Bytes::from(cause.body()))
                    .map_err(|never| match never {})
                    .boxed(),
            );
            *response.status_mut() = status(cause.status());
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            response
        }
        Reply::Upstream {
            status: code,
            headers,
            body,
        } => {
            let mut response = Response::new(stream_body(body, guard).boxed());
            *response.status_mut() = status(code);
            extend_header_map(response.headers_mut(), &headers);
            response
        }
    }
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY)
}

/// Read `body` on a blocking thread and hand its chunks to hyper. A read
/// error is sent on as the last item, which hyper turns into an aborted
/// connection.
fn stream_body(mut body: Box<ReplyBody>, guard: CancelOnDrop) -> ChannelBody {
    let (tx, rx) = mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let item = match body.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => Ok(Bytes::copy_from_slice(&buf[..n])),
                Err(e) => Err(e),
            };
            let failed = item.is_err();
            if tx.blocking_send(item).is_err() || failed {
                break;
            }
        }
    });
    ChannelBody { rx, _cancel: guard }
}

struct ChannelBody {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    /// Fires when the body is dropped, which is when the client is gone (or
    /// the body is done and there is nothing left to cancel).
    _cancel: CancelOnDrop,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.rx
            .poll_recv(cx)
            .map(|item| item.map(|chunk| chunk.map(Frame::data)))
    }
}
