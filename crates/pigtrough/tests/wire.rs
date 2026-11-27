//! The proxy on the wire: a real hyper server on a unix socket, the rustls
//! client behind the seam, and a local fake upstream presenting a test
//! certificate for `api.github.com` (crates/pigtrough/testdata, made by
//! `just codemod-pigtrough-test-cert`). The client under test trusts only
//! the test CA, and dials the fake on 127.0.0.1 while verifying the route's
//! host name. No card, no network beyond loopback, a test-only token.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;

use pigtrough::audit::{AuditRecord, AuditSink};
use pigtrough::budget::BodyBudget;
use pigtrough::holder::{Mount, SecretHolder};
use pigtrough::listener::{admit_peer, effective_uid};
use pigtrough::proxy::{Proxy, Scope};
use pigtrough::refusal::Cause;
use pigtrough::route::{GITHUB_API, Limits, Route};
use pigtrough::server::serve;
use pigtrough::tls::TlsUpstream;

const CA: &[u8] = include_bytes!("../testdata/fake-upstream-ca.pem");
const LEAF: &[u8] = include_bytes!("../testdata/fake-upstream-leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("../testdata/fake-upstream-leaf.key.pem");
const TOKEN: &str = "piggy-test-pigtrough-wire-token-0001";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }
}

type Respond = Arc<dyn Fn(&Seen) -> Response<Full<Bytes>> + Send + Sync>;

#[derive(Default)]
struct CaptureSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for CaptureSink {
    fn record(&self, record: &AuditRecord) {
        self.0.lock().unwrap().push(record.clone());
    }
}

struct Running {
    // Held so the runtime, and with it the proxy and the fake, outlive the
    // test body.
    _runtime: Runtime,
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Seen>>>,
    audit: Arc<CaptureSink>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn test_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).unwrap())
        .unwrap();
    roots
}

fn tls_acceptor() -> TlsAcceptor {
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from_pem_slice(LEAF).unwrap(),
                CertificateDer::from_pem_slice(CA).unwrap(),
            ],
            PrivateKeyDer::from_pem_slice(LEAF_KEY).unwrap(),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

/// A fake upstream that accepts TLS, reads the request, says `request`, then
/// never finishes answering and says `closed` when the proxy closes the
/// connection. With `partial` it first sends a response head promising 1000
/// bytes and the first hundred of them (`x`), so the proxy is streaming a
/// body when the client goes.
fn start_hanging_upstream(
    runtime: &Runtime,
    partial: bool,
) -> (SocketAddr, std::sync::mpsc::Receiver<&'static str>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let acceptor = tls_acceptor();
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    runtime.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                if !matches!(tls.read(&mut buf).await, Ok(n) if n > 0) {
                    return;
                }
                let _ = tx.send("request");
                if partial {
                    let mut head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".to_vec();
                    // More than the credential scan holds back at the tail.
                    head.extend_from_slice(&[b'x'; 100]);
                    if tls.write_all(&head).await.is_err() || tls.flush().await.is_err() {
                        return;
                    }
                }
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let _ = tx.send("closed");
            });
        }
    });
    (addr, rx)
}

fn start_fake_upstream(runtime: &Runtime, respond: Respond) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let acceptor = tls_acceptor();
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = seen.clone();
    runtime.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, recorder, respond) =
                (acceptor.clone(), recorder.clone(), respond.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Incoming>| {
                    let (recorder, respond) = (recorder.clone(), respond.clone());
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|c| c.to_bytes().to_vec())
                            .unwrap_or_default();
                        let seen = Seen {
                            method: parts.method.to_string(),
                            target: parts.uri.to_string(),
                            headers: parts
                                .headers
                                .iter()
                                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                                .collect(),
                            body,
                        };
                        let response = respond(&seen);
                        recorder.lock().unwrap().push(seen);
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, seen)
}

/// A fresh directory with a short name, so the socket path fits `sun_path`
/// under a worktree's long `TMPDIR`.
fn short_dir() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("pw-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn start(
    respond: Respond,
    roots: RootCertStore,
    admit: impl Fn(&tokio::net::UnixStream) -> bool + Send + 'static,
) -> Running {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, seen) = start_fake_upstream(&runtime, respond);
    start_proxy(runtime, addr, seen, roots, admit)
}

fn start_proxy(
    runtime: Runtime,
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    roots: RootCertStore,
    admit: impl Fn(&tokio::net::UnixStream) -> bool + Send + 'static,
) -> Running {
    let client = TlsUpstream::with_roots(runtime.handle().clone(), roots).connect_to(addr);
    start_with_client(runtime, client, seen, admit)
}

fn start_with_client<C: pigtrough::upstream::UpstreamClient + 'static>(
    runtime: Runtime,
    client: C,
    seen: Arc<Mutex<Vec<Seen>>>,
    admit: impl Fn(&tokio::net::UnixStream) -> bool + Send + 'static,
) -> Running {
    start_serving(
        runtime,
        client,
        seen,
        &GITHUB_API,
        Arc::new(BodyBudget::default()),
        admit,
    )
}

fn start_serving<C: pigtrough::upstream::UpstreamClient + 'static>(
    runtime: Runtime,
    client: C,
    seen: Arc<Mutex<Vec<Seen>>>,
    route: &'static Route,
    budget: Arc<BodyBudget>,
    admit: impl Fn(&tokio::net::UnixStream) -> bool + Send + 'static,
) -> Running {
    let holder = Arc::new(SecretHolder::empty());
    holder.load(format!("{TOKEN}\n").as_bytes()).unwrap();
    let audit = Arc::new(CaptureSink::default());
    let proxy = Arc::new(Proxy::with_mounts(
        vec![Mount { route, holder }],
        client,
        audit.clone(),
        Scope {
            name: "operator".to_owned(),
        },
        budget,
    ));
    let socket = short_dir().join("s");
    let std_listener = pigtrough::listener::bind(&socket).unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let listener = {
        let _entered = runtime.enter();
        tokio::net::UnixListener::from_std(std_listener).unwrap()
    };
    runtime.spawn(serve(listener, proxy, admit));
    Running {
        _runtime: runtime,
        socket,
        seen,
        audit,
    }
}

fn admit_self(stream: &tokio::net::UnixStream) -> bool {
    admit_peer(stream, effective_uid())
}

fn ok(body: &'static str) -> Respond {
    Arc::new(move |_| Response::new(Full::new(Bytes::from_static(body.as_bytes()))))
}

/// Send `raw` and read until the proxy closes the connection. A reset after
/// a partial response leaves what arrived before it.
fn exchange(running: &Running, raw: &[u8], close_write: bool) -> Vec<u8> {
    let mut stream = StdUnixStream::connect(&running.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    // A refused connection may be closed before the request is written, so a
    // write error here is an outcome to observe, not a test failure.
    let _ = stream.write_all(raw);
    if close_write {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

fn get(running: &Running, target: &str) -> Vec<u8> {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n");
    exchange(running, raw.as_bytes(), false)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn split_response(bytes: &[u8]) -> (String, Vec<u8>) {
    let at = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    (
        String::from_utf8_lossy(&bytes[..at]).into_owned(),
        bytes[at + 4..].to_vec(),
    )
}

#[test]
fn decorates_over_tls_and_forwards_only_what_it_should() {
    let running = start(
        Arc::new(|_| {
            let mut r = Response::new(Full::new(Bytes::from_static(b"{\"id\":1}")));
            *r.status_mut() = hyper::StatusCode::CREATED;
            r
        }),
        test_roots(),
        admit_self,
    );
    let body = "{\"name\":\"example-mirror\"}";
    let raw = format!(
        "POST /github-api/orgs/amarbel-llc/repos HTTP/1.1\r\nHost: proxy\r\n\
         Authorization: Bearer client-supplied\r\nCookie: a=b\r\nAccept-Encoding: gzip\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let reply = exchange(&running, raw.as_bytes(), false);
    let (head, reply_body) = split_response(&reply);
    assert!(head.starts_with("HTTP/1.1 201"), "{head}");
    assert_eq!(reply_body, b"{\"id\":1}");
    assert!(!contains(&reply, TOKEN));

    let seen = running.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let call = &seen[0];
    assert_eq!(
        (call.method.as_str(), call.target.as_str()),
        ("POST", "/orgs/amarbel-llc/repos")
    );
    assert_eq!(
        call.header("authorization"),
        vec![format!("Bearer {TOKEN}")]
    );
    assert_eq!(call.header("host"), vec!["api.github.com".to_owned()]);
    assert_eq!(call.header("accept-encoding"), vec!["identity".to_owned()]);
    assert_eq!(call.header("content-length"), vec![body.len().to_string()]);
    assert!(call.header("cookie").is_empty());
    assert_eq!(call.body, body.as_bytes());
}

#[test]
fn an_upstream_the_roots_do_not_vouch_for_gets_no_request() {
    let running = start(ok("{}"), RootCertStore::empty(), admit_self);
    let reply = get(&running, "/github-api/repos/amarbel-llc/piggy");
    let (head, body) = split_response(&reply);
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(body, b"upstream-unavailable\n");
    assert!(running.seen.lock().unwrap().is_empty());
}

#[test]
fn a_cut_response_does_not_end_cleanly() {
    let running = start(
        Arc::new(|seen| {
            let echo = format!("you sent {}", seen.header("authorization").join(""));
            Response::new(Full::new(Bytes::from(echo)))
        }),
        test_roots(),
        admit_self,
    );
    let reply = get(&running, "/github-api/repos/amarbel-llc/piggy");
    assert!(!contains(&reply, TOKEN));
    // The cut can come before hyper flushes the head (the echo is in the
    // first chunk the scanner reads): the client then sees the connection
    // close with nothing, which is no response at all.
    if reply.is_empty() {
        return;
    }
    let (head, body) = split_response(&reply);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // The head promised the upstream's length; the connection ended short
    // of it, which a client reads as a broken response, not a complete one.
    let declared: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        })
        .expect("content-length passed through")
        .trim()
        .parse()
        .unwrap();
    assert!(body.len() < declared, "{} of {declared} bytes", body.len());
}

#[test]
fn an_encoded_response_is_refused() {
    let running = start(
        Arc::new(|_| {
            let mut r = Response::new(Full::new(Bytes::from_static(b"\x1f\x8b")));
            r.headers_mut()
                .insert("content-encoding", "gzip".parse().unwrap());
            r
        }),
        test_roots(),
        admit_self,
    );
    let (head, body) = split_response(&get(&running, "/github-api/repos/amarbel-llc/piggy"));
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(body, b"upstream-encoded-response\n");
}

#[test]
fn the_upstream_gets_the_length_of_the_body_actually_read() {
    let running = start(ok("{}"), test_roots(), admit_self);
    // Declares two bytes and sends more; only the declared two are a body.
    let raw = "PUT /github-api/repos/amarbel-llc/piggy/topics HTTP/1.1\r\nHost: proxy\r\n\
               Content-Length: 2\r\nConnection: close\r\n\r\n{}TRAILING-BYTES";
    exchange(&running, raw.as_bytes(), false);
    let seen = running.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body, b"{}");
    assert_eq!(seen[0].header("content-length"), vec!["2".to_owned()]);
}

#[test]
fn a_body_shorter_than_declared_is_never_forwarded() {
    let running = start(ok("{}"), test_roots(), admit_self);
    let raw = "PATCH /github-api/repos/amarbel-llc/piggy HTTP/1.1\r\nHost: proxy\r\n\
               Content-Length: 100\r\nConnection: close\r\n\r\n{}";
    exchange(&running, raw.as_bytes(), true);
    assert!(running.seen.lock().unwrap().is_empty());
}

#[test]
fn a_connection_that_fails_admission_is_closed_unread() {
    let running = start(ok("{}"), test_roots(), |_| false);
    let reply = get(&running, "/github-api/repos/amarbel-llc/piggy");
    assert!(reply.is_empty(), "{}", String::from_utf8_lossy(&reply));
    assert!(running.seen.lock().unwrap().is_empty());
    let audit = running.audit.0.lock().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].decision, pigtrough::audit::Decision::RefuseBinding);
}

const CA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/fake-upstream-ca.pem");

/// A private CA named in a route's `extra_roots` vouches for that
/// upstream: the same fake upstream that the public roots refuse is reached
/// once `roots_with` adds its CA (built here as a client of its own, as
/// `HostClients` does per upstream).
#[test]
fn an_extra_root_vouches_for_a_private_upstream() {
    let roots = pigtrough::tls::roots_with(&[PathBuf::from(CA_PATH)]).unwrap();
    let running = start(ok("{\"id\":2}"), roots, admit_self);
    let reply = get(&running, "/github-api/repos/amarbel-llc/piggy");
    let (head, body) = split_response(&reply);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"{\"id\":2}");
    assert_eq!(running.seen.lock().unwrap().len(), 1);
}

#[test]
fn roots_with_refuses_a_bad_bundle() {
    use pigtrough::tls::roots_with;
    let dir = short_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("missing.pem");
    let empty = dir.join("empty.pem");
    let garbage = dir.join("garbage.pem");
    std::fs::write(&empty, b"").unwrap();
    std::fs::write(
        &garbage,
        b"-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    for (file, needle) in [
        (&missing, "missing.pem"),
        (&empty, "no certificate"),
        (&garbage, "garbage.pem"),
    ] {
        match roots_with(std::slice::from_ref(file)) {
            Ok(_) => panic!("{} was accepted", file.display()),
            Err(e) => assert!(e.contains(needle), "{e}"),
        }
    }
    // The public roots stay in alongside the extra ones.
    let with = roots_with(&[PathBuf::from(CA_PATH)]).unwrap();
    assert!(with.roots.len() > 1);
    let _ = std::fs::remove_dir_all(dir);
}

/// A proxy over `HostClients`: the public-roots client by default, and the
/// private-CA client for `private_for` only. The fake upstream is reached
/// through either; only the one trusting its CA completes the handshake.
fn dispatch_rig(private_for: pigtrough::route::Upstream) -> Running {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, seen) = start_fake_upstream(&runtime, ok("{\"id\":3}"));
    let handle = runtime.handle().clone();
    let public = TlsUpstream::with_public_roots(handle.clone()).connect_to(addr);
    let private = TlsUpstream::with_roots(
        handle,
        pigtrough::tls::roots_with(&[PathBuf::from(CA_PATH)]).unwrap(),
    )
    .connect_to(addr);
    let clients = pigtrough::tls::HostClients::new(public).with_host(&private_for, private);
    start_with_client(runtime, clients, seen, admit_self)
}

#[test]
fn host_clients_use_the_private_roots_for_their_own_upstream_only() {
    // Registered for the route's own upstream: the private CA is used.
    let own = dispatch_rig(GITHUB_API.upstream);
    let reply = get(&own, "/github-api/repos/amarbel-llc/piggy");
    let (head, _) = split_response(&reply);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(own.seen.lock().unwrap().len(), 1);

    // Registered for another host, or for the same host on another port:
    // the route falls to the public roots, which do not vouch for the fake.
    for other in [
        pigtrough::route::Upstream {
            host: "other.invalid",
            port: GITHUB_API.upstream.port,
        },
        pigtrough::route::Upstream {
            host: GITHUB_API.upstream.host,
            port: GITHUB_API.upstream.port + 1,
        },
    ] {
        let rig = dispatch_rig(other);
        let reply = get(&rig, "/github-api/repos/amarbel-llc/piggy");
        let (head, body) = split_response(&reply);
        assert!(head.starts_with("HTTP/1.1 502"), "{other:?}: {head}");
        assert_eq!(body, b"upstream-unavailable\n");
        assert!(rig.seen.lock().unwrap().is_empty());
    }
}

/// The pilot route with other limits.
fn route_with(max_request_body: usize, response_head_timeout: Duration) -> &'static Route {
    Box::leak(Box::new(Route {
        limits: Limits {
            max_request_body,
            response_head_timeout,
        },
        ..GITHUB_API.clone()
    }))
}

fn two_workers() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// A proxy serving `route` under `budget` in front of an upstream that
/// answers `{}`.
fn limited(route: &'static Route, budget: Arc<BodyBudget>) -> Running {
    let runtime = two_workers();
    let (addr, seen) = start_fake_upstream(&runtime, ok("{}"));
    let client = TlsUpstream::with_roots(runtime.handle().clone(), test_roots()).connect_to(addr);
    start_serving(runtime, client, seen, route, budget, admit_self)
}

/// The same, in front of an upstream that never finishes answering.
fn limited_hanging(
    route: &'static Route,
    budget: Arc<BodyBudget>,
) -> (Running, std::sync::mpsc::Receiver<&'static str>) {
    let runtime = two_workers();
    let (addr, events) = start_hanging_upstream(&runtime, false);
    let client = TlsUpstream::with_roots(runtime.handle().clone(), test_roots()).connect_to(addr);
    let running = start_serving(runtime, client, Arc::default(), route, budget, admit_self);
    (running, events)
}

/// The head of a request to the route's one `POST` path, `framing` being
/// its body framing header.
fn post_head(framing: &str) -> Vec<u8> {
    format!(
        "POST /github-api/orgs/amarbel-llc/repos HTTP/1.1\r\nHost: proxy\r\n\
         {framing}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn post(len: usize) -> Vec<u8> {
    let mut raw = post_head(&format!("Content-Length: {len}"));
    raw.resize(raw.len() + len, b'b');
    raw
}

/// A body of `len` bytes with no declared length, in 16 KiB chunks.
fn post_chunked(len: usize) -> Vec<u8> {
    let mut raw = post_head("Transfer-Encoding: chunked");
    let mut left = len;
    while left > 0 {
        let n = left.min(16 * 1024);
        raw.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        raw.resize(raw.len() + n, b'b');
        raw.extend_from_slice(b"\r\n");
        left -= n;
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    raw
}

fn head_of(reply: &[u8]) -> (String, Vec<u8>) {
    let (head, body) = split_response(reply);
    (head.lines().next().unwrap_or("").to_owned(), body)
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

const SLOW: Duration = Duration::from_secs(30);

#[test]
fn a_routes_body_limit_replaces_the_default() {
    let limit = 2 << 20;
    let budget = Arc::new(BodyBudget::default());
    let running = limited(route_with(limit, SLOW), budget.clone());
    for (raw, len) in [(post(limit), limit), (post_chunked(limit), limit)] {
        let (status, _) = head_of(&exchange(&running, &raw, false));
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert_eq!(running.seen.lock().unwrap().last().unwrap().body.len(), len);
    }
    // One byte over, with and without a declared length. The proxy may
    // answer and close while the client still writes, so a reset that loses
    // the reply is allowed; reaching the upstream is not.
    for raw in [post(limit + 1), post_chunked(limit + 1)] {
        let reply = exchange(&running, &raw, false);
        if !reply.is_empty() {
            let (status, body) = head_of(&reply);
            assert!(status.starts_with("HTTP/1.1 400"), "{status}");
            assert_eq!(body, Cause::RequestRejected.body().as_bytes());
        }
    }
    assert_eq!(running.seen.lock().unwrap().len(), 2);
    wait_for("the budget to empty", || budget.used() == 0);
}

#[test]
fn a_route_without_limits_keeps_the_one_mebibyte_default() {
    let running = limited(&GITHUB_API, Arc::new(BodyBudget::default()));
    let (status, _) = head_of(&exchange(&running, &post(1 << 20), false));
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    // Declared only: nothing of the body is sent, so the reply is not lost
    // to a reset.
    let over = post_head(&format!("Content-Length: {}", (1 << 20) + 1));
    let (status, body) = head_of(&exchange(&running, &over, false));
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");
    assert_eq!(body, Cause::RequestRejected.body().as_bytes());
    assert_eq!(running.seen.lock().unwrap().len(), 1);
}

#[test]
fn a_request_outside_the_allowlist_is_answered_before_its_body() {
    let budget = Arc::new(BodyBudget::default());
    let running = limited(&GITHUB_API, budget.clone());
    // The body is declared and never sent, and the write side stays open.
    let raw = b"POST /github-api/user HTTP/1.1\r\nHost: proxy\r\n\
                Content-Length: 1000\r\nConnection: close\r\n\r\n";
    let (status, body) = head_of(&exchange(&running, raw, false));
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert_eq!(body, b"refused\n");
    assert_eq!(budget.used(), 0);
    assert!(running.seen.lock().unwrap().is_empty());
}

/// The cap is on all bodies held at once: while one waits on its upstream, a
/// second that does not fit is turned away, a bodyless request is not, and
/// the room comes back when the first ends.
#[test]
fn the_total_budget_turns_away_a_body_that_does_not_fit() {
    let budget = Arc::new(BodyBudget::new(100_000));
    let (running, events) = limited_hanging(route_with(1 << 20, SLOW), budget.clone());
    let wait = Duration::from_secs(10);

    let mut first = StdUnixStream::connect(&running.socket).unwrap();
    first.write_all(&post(60_000)).unwrap();
    assert_eq!(events.recv_timeout(wait), Ok("request"));
    assert_eq!(budget.used(), 60_000);

    for raw in [post(60_000), post_chunked(60_000)] {
        let reply = exchange(&running, &raw, false);
        if !reply.is_empty() {
            let (status, body) = head_of(&reply);
            assert!(status.starts_with("HTTP/1.1 429"), "{status}");
            assert_eq!(body, Cause::Busy.body().as_bytes());
        }
    }
    wait_for("the refused bodies to be released", || {
        budget.used() == 60_000
    });
    wait_for("their audit lines", || {
        let audit = running.audit.0.lock().unwrap();
        audit.len() == 2
            && audit.iter().all(|r| {
                r.decision == pigtrough::audit::Decision::RefuseBusy
                    && r.route == Some("github-api")
            })
    });
    assert!(events.try_recv().is_err(), "neither reached the upstream");

    let mut bodyless = StdUnixStream::connect(&running.socket).unwrap();
    bodyless
        .write_all(b"GET /github-api/repos/amarbel-llc/piggy HTTP/1.1\r\nHost: proxy\r\n\r\n")
        .unwrap();
    assert_eq!(events.recv_timeout(wait), Ok("request"));

    drop(first);
    wait_for("the first body to be released", || budget.used() == 0);
}

#[test]
fn a_body_that_stalls_is_rejected_and_gives_its_room_back() {
    let budget =
        Arc::new(BodyBudget::new(100_000).with_read_timeout(Some(Duration::from_millis(500))));
    let running = limited(&GITHUB_API, budget.clone());
    let mut raw = post_head("Content-Length: 1000");
    raw.extend_from_slice(&[b'b'; 10]);
    let (status, body) = head_of(&exchange(&running, &raw, false));
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");
    assert_eq!(body, Cause::RequestRejected.body().as_bytes());
    assert!(running.seen.lock().unwrap().is_empty());
    wait_for("the budget to empty", || budget.used() == 0);
}

#[test]
fn an_upstream_slower_than_the_routes_head_timeout_is_a_timeout() {
    let (running, events) = limited_hanging(
        route_with(1 << 20, Duration::from_secs(3)),
        Arc::new(BodyBudget::default()),
    );
    let (status, body) = head_of(&get(&running, "/github-api/repos/amarbel-llc/piggy"));
    assert!(status.starts_with("HTTP/1.1 504"), "{status}");
    assert_eq!(body, Cause::UpstreamTimeout.body().as_bytes());
    let wait = Duration::from_secs(10);
    assert_eq!(events.recv_timeout(wait), Ok("request"));
    assert_eq!(events.recv_timeout(wait), Ok("closed"));
    let audit = running.audit.0.lock().unwrap();
    assert_eq!(
        (audit[0].decision, audit[0].status),
        (pigtrough::audit::Decision::RefuseUpstream, Some(504))
    );
}

/// An upstream that accepts TCP and never speaks TLS was not reached: that
/// stays `upstream-unavailable`, within the connect bound, however long the
/// route would wait for an answer.
#[test]
fn a_stalled_handshake_is_unavailable_within_the_connect_bound() {
    let runtime = two_workers();
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TlsUpstream::with_roots(runtime.handle().clone(), test_roots())
        .connect_to(silent.local_addr().unwrap())
        .connect_timeout(Duration::from_millis(500));
    let running = start_serving(
        runtime,
        client,
        Arc::default(),
        route_with(1 << 20, Duration::from_secs(600)),
        Arc::new(BodyBudget::default()),
        admit_self,
    );
    let (status, body) = head_of(&get(&running, "/github-api/repos/amarbel-llc/piggy"));
    assert!(status.starts_with("HTTP/1.1 502"), "{status}");
    assert_eq!(body, b"upstream-unavailable\n");
}

/// The connect bound covers only getting connected: an answer may take
/// longer than it, up to the route's head timeout.
#[test]
fn the_connect_bound_does_not_cut_a_slow_answer() {
    let runtime = two_workers();
    let (addr, seen) = start_fake_upstream(
        &runtime,
        Arc::new(|_| {
            std::thread::sleep(Duration::from_secs(3));
            Response::new(Full::new(Bytes::from_static(b"{}")))
        }),
    );
    let client = TlsUpstream::with_roots(runtime.handle().clone(), test_roots())
        .connect_to(addr)
        .connect_timeout(Duration::from_secs(2));
    let running = start_serving(
        runtime,
        client,
        seen,
        route_with(1 << 20, Duration::from_secs(20)),
        Arc::new(BodyBudget::default()),
        admit_self,
    );
    let (status, _) = head_of(&get(&running, "/github-api/repos/amarbel-llc/piggy"));
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
}

/// The lookup of the upstream's name must not wait for a thread of the pool
/// that requests hold while they wait for it. One request on a pool of one
/// shows it: an upstream named by host still gets the connection.
#[test]
fn looking_up_the_upstream_does_not_wait_for_a_request_thread() {
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    let (tx, connected) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _held = upstream.accept();
        let _ = tx.send(());
        std::thread::sleep(Duration::from_secs(60));
    });
    let route: &'static Route = Box::leak(Box::new(Route {
        upstream: pigtrough::route::Upstream {
            host: "localhost",
            port,
        },
        ..GITHUB_API.clone()
    }));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let client = TlsUpstream::with_roots(runtime.handle().clone(), test_roots());
    let running = start_serving(
        runtime,
        client,
        Arc::default(),
        route,
        Arc::new(BodyBudget::default()),
        admit_self,
    );
    let mut stream = StdUnixStream::connect(&running.socket).unwrap();
    stream
        .write_all(b"GET /github-api/repos/amarbel-llc/piggy HTTP/1.1\r\nHost: proxy\r\n\r\n")
        .unwrap();
    assert_eq!(connected.recv_timeout(Duration::from_secs(10)), Ok(()));
    // Closed first, so the request thread is free when the runtime drops.
    drop(stream);
}

/// An upstream that completes TLS, reads the start of the request and then
/// reads nothing more. With `answer` it then sends those bytes.
fn start_deaf_upstream(runtime: &Runtime, answer: &'static [u8]) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let acceptor = tls_acceptor();
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = listener.local_addr().unwrap();
    runtime.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut start = [0u8; 512];
                if tls.read_exact(&mut start).await.is_err() {
                    return;
                }
                let _ = tls.write_all(answer).await;
                let _ = tls.flush().await;
                std::future::pending::<()>().await;
                drop(tls);
            });
        }
    });
    addr
}

/// A request too large for the sockets' buffers, to an upstream that stops
/// reading: whatever ends the request also ends the upstream connection, so
/// the body's room comes back.
fn a_deaf_upstream_gives_the_room_back(
    answer: &'static [u8],
    head_timeout: Duration,
    status: &str,
) {
    let len = 15 << 20;
    let budget = Arc::new(BodyBudget::default());
    let runtime = two_workers();
    let addr = start_deaf_upstream(&runtime, answer);
    let client = TlsUpstream::with_roots(runtime.handle().clone(), test_roots()).connect_to(addr);
    let running = start_serving(
        runtime,
        client,
        Arc::default(),
        route_with(16 << 20, head_timeout),
        budget.clone(),
        admit_self,
    );
    let reply = exchange(&running, &post(len), false);
    let (got, _) = head_of(&reply);
    assert!(got.starts_with(status), "{got}");
    wait_for("the budget to empty", || budget.used() == 0);
}

#[test]
fn a_timed_out_call_to_an_upstream_that_stopped_reading_frees_its_body() {
    a_deaf_upstream_gives_the_room_back(b"", Duration::from_secs(3), "HTTP/1.1 504");
}

#[test]
fn an_early_answer_from_an_upstream_that_stopped_reading_frees_the_body() {
    a_deaf_upstream_gives_the_room_back(
        b"HTTP/1.1 413 Too Large\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno",
        SLOW,
        "HTTP/1.1 413",
    );
}

/// A client that hangs up while the response body is streaming: the
/// upstream sees its connection close, and the audit line is written once.
#[test]
fn a_client_that_hangs_up_while_the_body_streams_cancels_the_upstream_read() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, events) = start_hanging_upstream(&runtime, true);
    let running = start_proxy(
        runtime,
        addr,
        Arc::new(Mutex::new(Vec::new())),
        test_roots(),
        admit_self,
    );
    let mut stream = StdUnixStream::connect(&running.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(b"GET /github-api/repos/amarbel-llc/piggy HTTP/1.1\r\nHost: proxy\r\n\r\n")
        .unwrap();
    let wait = Duration::from_secs(10);
    assert_eq!(events.recv_timeout(wait), Ok("request"));

    // Read until some of the streamed body has reached the client.
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = stream
            .read(&mut buf)
            .expect("body bytes before the timeout");
        assert!(n > 0, "the proxy closed before any body arrived");
        got.extend_from_slice(&buf[..n]);
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            if got.len() - (at + 4) >= 16 {
                break;
            }
        }
    }
    drop(stream);
    assert_eq!(
        events.recv_timeout(wait),
        Ok("closed"),
        "the upstream connection was not closed after the client hung up mid-body"
    );

    // One audit line, written once the body was dropped.
    let deadline = std::time::Instant::now() + wait;
    loop {
        let lines: Vec<_> = running
            .audit
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|r| (r.decision, r.status))
            .collect();
        if lines.len() == 1 {
            assert_eq!(
                lines[0],
                (pigtrough::audit::Decision::RefuseUpstream, Some(200)),
                "audit: {lines:?}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "audit lines: {lines:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // And no second line shows up late.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(running.audit.0.lock().unwrap().len(), 1);
}

/// A client that hangs up while the upstream is still thinking: the
/// upstream sees its connection closed within moments, long before the 30 s
/// head timeout, and the audit line says the client went.
#[test]
fn a_client_that_hangs_up_cancels_its_upstream_call() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, events) = start_hanging_upstream(&runtime, false);
    let running = start_proxy(
        runtime,
        addr,
        Arc::new(Mutex::new(Vec::new())),
        test_roots(),
        admit_self,
    );

    let mut stream = StdUnixStream::connect(&running.socket).unwrap();
    stream
        .write_all(b"GET /github-api/repos/amarbel-llc/piggy HTTP/1.1\r\nHost: proxy\r\n\r\n")
        .unwrap();
    let wait = Duration::from_secs(10);
    assert_eq!(
        events.recv_timeout(wait),
        Ok("request"),
        "the upstream saw the call"
    );
    // The client goes away with the upstream call in flight.
    drop(stream);
    assert_eq!(
        events.recv_timeout(wait),
        Ok("closed"),
        "the upstream connection was not closed after the client hung up"
    );

    // The audit line names the cause, once the proxy has written it.
    let deadline = std::time::Instant::now() + wait;
    loop {
        let decisions: Vec<_> = running
            .audit
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.decision)
            .collect();
        if decisions == [pigtrough::audit::Decision::ClientGone] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "audit decisions: {decisions:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
