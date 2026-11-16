//! The client-facing wire adapter: HTTP/1.1 on the unix socket, with hyper.
//!
//! Each accepted connection passes the admission check first (behaviour 6;
//! the decision is [`crate::listener::admit_peer`], passed in as a closure so
//! a test can stand in for a second UID). A request's body is read whole, up
//! to [`MAX_REQUEST_BODY`], then [`Proxy::handle`] runs on a blocking thread
//! (the request path and its upstream seam are synchronous) and the reply
//! body streams back through a channel. When the reply body fails (an echoed
//! credential, an upstream that broke off), the failure is passed to hyper as
//! a body error, which aborts the connection instead of ending the response
//! cleanly, so a cut response cannot look complete.
//!
//! Two known limits of running the synchronous path on the blocking pool,
//! for a later slice: the pool's size bounds concurrent requests (the binary
//! sets it explicitly, `MAX_IN_FLIGHT`), and a client that disconnects does
//! not cancel its in-flight upstream call, which runs to completion or to the
//! head timeout.

use std::convert::Infallible;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::proxy::{ClientRequest, Proxy, Reply, ReplyBody};
use crate::refusal::Cause;
use crate::upstream::UpstreamClient;
use crate::wire::{extend_header_map, from_header_map};

/// The largest request body the proxy reads. The pilot's calls send small
/// JSON objects.
pub const MAX_REQUEST_BODY: usize = 1 << 20;

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
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| respond(proxy.clone(), request));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn respond<C: UpstreamClient + 'static>(
    proxy: Arc<Proxy<C>>,
    request: Request<Incoming>,
) -> Result<Response<ReplyStream>, Infallible> {
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_owned();
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();
    let body = match Limited::new(body, MAX_REQUEST_BODY).collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => {
            let reply = proxy.reject(&method, &target, Cause::RequestRejected);
            return Ok(to_response(reply));
        }
    };
    let request = ClientRequest {
        method,
        target,
        headers: from_header_map(&parts.headers),
        body,
    };
    let reply = tokio::task::spawn_blocking(move || proxy.handle(request))
        .await
        .unwrap_or(Reply::Refusal(Cause::UpstreamUnavailable));
    Ok(to_response(reply))
}

fn to_response(reply: Reply) -> Response<ReplyStream> {
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
            let mut response = Response::new(stream_body(body).boxed());
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
fn stream_body(mut body: Box<ReplyBody>) -> ChannelBody {
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
    ChannelBody(rx)
}

struct ChannelBody(mpsc::Receiver<io::Result<Bytes>>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|item| item.map(|chunk| chunk.map(Frame::data)))
    }
}
