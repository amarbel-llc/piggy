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
use pigtrough::holder::SecretHolder;
use pigtrough::listener::{admit_peer, effective_uid};
use pigtrough::proxy::{Proxy, Scope};
use pigtrough::route::GITHUB_API;
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
/// never answers and says `closed` when the proxy closes the connection.
fn start_hanging_upstream(
    runtime: &Runtime,
) -> (SocketAddr, std::sync::mpsc::Receiver<&'static str>) {
    use tokio::io::AsyncReadExt;
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
    let holder = Arc::new(SecretHolder::empty());
    holder.load(format!("{TOKEN}\n").as_bytes()).unwrap();
    let audit = Arc::new(CaptureSink::default());
    let client = TlsUpstream::with_roots(runtime.handle().clone(), roots).connect_to(addr);
    let proxy = Arc::new(Proxy::new(
        &GITHUB_API,
        holder,
        client,
        audit.clone(),
        Scope {
            name: "operator".to_owned(),
        },
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
    let (addr, events) = start_hanging_upstream(&runtime);
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
