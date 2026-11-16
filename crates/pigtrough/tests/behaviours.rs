//! The eight behaviours FDR 0009's pilot plan pins, driven through
//! `Proxy::handle` against a fake upstream behind the `UpstreamClient` seam.
//! No card, no network, no real credential: the token is a test constant.
//!
//! Not covered here yet, because they need the hyper/rustls slice: the
//! client-side wire adapter, the self-signed TLS upstream, and the binary's
//! argv and environment (behaviour 2's last clause). Behaviour 6 is tested against the kernel's
//! peer credentials in `listener`'s unit tests and as a decision here.

use std::io::Read;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use pigtrough::Headers;
use pigtrough::audit::{AuditRecord, AuditSink, Decision};
use pigtrough::holder::SecretHolder;
use pigtrough::listener::admit_peer;
use pigtrough::proxy::{ClientRequest, Proxy, Reply, Scope};
use pigtrough::refusal::Cause;
use pigtrough::route::{GITHUB_API, Upstream};
use pigtrough::upstream::{OutboundRequest, UpstreamClient, UpstreamError, UpstreamResponse};

const TOKEN: &str = "piggy-test-decorate-token-0001";
const NEXT_TOKEN: &str = "piggy-test-decorate-token-0002";

#[derive(Clone, Debug)]
struct Recorded {
    host: String,
    method: String,
    path_and_query: String,
    headers: Headers,
    authorization: String,
    body: Vec<u8>,
}

type Respond = dyn Fn(&Recorded) -> (u16, Headers, Vec<u8>) + Send + Sync;

/// Two channels that hold a call in `send` until the test lets it go.
struct Gate {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

struct FakeUpstream {
    calls: Mutex<Vec<Recorded>>,
    respond: Box<Respond>,
    gate: Option<Gate>,
}

struct FakeClient(Arc<FakeUpstream>);

impl UpstreamClient for FakeClient {
    fn send(
        &self,
        upstream: &Upstream,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError> {
        if let Some(gate) = &self.0.gate {
            gate.entered.send(()).unwrap();
            gate.release.lock().unwrap().recv().unwrap();
        }
        let authorization = request
            .credential
            .with_header_value(|v| String::from_utf8(v.to_vec()).unwrap())
            .unwrap();
        let recorded = Recorded {
            host: upstream.host.to_owned(),
            method: request.method.to_owned(),
            path_and_query: request.path_and_query,
            headers: request.headers,
            authorization,
            body: request.body.to_vec(),
        };
        let (status, headers, body) = (self.0.respond)(&recorded);
        self.0.calls.lock().unwrap().push(recorded);
        Ok(UpstreamResponse {
            status,
            headers,
            body: Box::new(std::io::Cursor::new(body)),
        })
    }
}

#[derive(Default)]
struct CaptureSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for CaptureSink {
    fn record(&self, record: &AuditRecord) {
        self.0.lock().unwrap().push(record.clone());
    }
}

struct Harness {
    proxy: Arc<Proxy<FakeClient>>,
    upstream: Arc<FakeUpstream>,
    holder: Arc<SecretHolder>,
    audit: Arc<CaptureSink>,
}

fn harness_with(respond: Box<Respond>, gate: Option<Gate>) -> Harness {
    let upstream = Arc::new(FakeUpstream {
        calls: Mutex::new(Vec::new()),
        respond,
        gate,
    });
    let holder = Arc::new(SecretHolder::empty());
    let audit = Arc::new(CaptureSink::default());
    let proxy = Proxy::new(
        &GITHUB_API,
        holder.clone(),
        FakeClient(upstream.clone()),
        audit.clone(),
        Scope {
            name: "operator".to_owned(),
        },
    );
    Harness {
        proxy: Arc::new(proxy),
        upstream,
        holder,
        audit,
    }
}

fn harness() -> Harness {
    harness_with(
        Box::new(|_| {
            (
                200,
                headers(&[("Content-Type", "application/json")]),
                b"{\"full_name\":\"amarbel-llc/piggy\"}".to_vec(),
            )
        }),
        None,
    )
}

fn headers(pairs: &[(&str, &str)]) -> Headers {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.as_bytes().to_vec()))
        .collect()
}

fn request(method: &str, target: &str) -> ClientRequest {
    ClientRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: headers(&[
            ("Host", "proxy"),
            ("Accept", "application/vnd.github+json"),
            ("User-Agent", "mirror-reconciler"),
        ]),
        body: Vec::new(),
    }
}

/// Every byte the client would receive: status, headers, body. A body read
/// that fails stops the bytes there, as the wire adapter cuts the
/// connection.
fn client_bytes(reply: Reply) -> Vec<u8> {
    let mut out = format!("{}\n", reply.status()).into_bytes();
    match reply {
        Reply::Refusal(cause) => out.extend_from_slice(cause.body().as_bytes()),
        Reply::Upstream {
            headers, mut body, ..
        } => {
            for (name, value) in headers {
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(&value);
                out.push(b'\n');
            }
            let mut buf = [0u8; 64];
            while let Ok(n) = body.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn audit_lines(h: &Harness) -> String {
    h.audit
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|r| format!("{r}\n"))
        .collect()
}

#[test]
fn b1_decorates_with_the_bearer_and_drops_client_credentials() {
    let h = harness();
    h.holder.load(format!("{TOKEN}\n").as_bytes()).unwrap();
    let mut req = request("POST", "/github-api/orgs/amarbel-llc/repos");
    req.headers.extend(headers(&[
        ("Authorization", "Bearer client-supplied"),
        ("Cookie", "session=client"),
        ("Content-Type", "application/json"),
    ]));
    req.body = b"{\"name\":\"example-mirror\",\"private\":true}".to_vec();
    let reply = h.proxy.handle(req);
    assert_eq!(reply.status(), 200);
    drop(reply);

    let calls = h.upstream.calls.lock().unwrap();
    let call = &calls[0];
    assert_eq!(call.host, "api.github.com");
    assert_eq!(
        (call.method.as_str(), call.path_and_query.as_str()),
        ("POST", "/orgs/amarbel-llc/repos")
    );
    assert_eq!(call.authorization, format!("Bearer {TOKEN}"));
    assert_eq!(call.body, b"{\"name\":\"example-mirror\",\"private\":true}");
    let names: Vec<String> = call
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    assert!(!names.contains(&"authorization".to_owned()), "{names:?}");
    assert!(!names.contains(&"cookie".to_owned()), "{names:?}");
    assert_eq!(
        call.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
            .collect::<Vec<_>>(),
        vec![&("Host".to_owned(), b"api.github.com".to_vec())]
    );
}

#[test]
fn b2_the_token_never_reaches_the_client_or_the_audit_line() {
    // An upstream that echoes the credential everywhere it can.
    let h = harness_with(
        Box::new(|call| {
            let echo = call.authorization.clone();
            (
                200,
                headers(&[("X-Echo", echo.as_str()), ("Content-Type", "text/plain")]),
                format!("you sent: {echo}").into_bytes(),
            )
        }),
        None,
    );
    h.holder.load(TOKEN.as_bytes()).unwrap();
    let mut seen = client_bytes(
        h.proxy
            .handle(request("GET", "/github-api/repos/amarbel-llc/piggy")),
    );
    for target in [
        "/github-api/user",
        "/nope/x",
        "/github-api/repos/amarbel-llc/piggy?q=1",
    ] {
        seen.extend(client_bytes(h.proxy.handle(request("GET", target))));
    }
    assert!(
        !contains(&seen, TOKEN),
        "{}",
        String::from_utf8_lossy(&seen)
    );
    assert!(!contains(audit_lines(&h).as_bytes(), TOKEN));
    // The echoing response was cut off and recorded as such.
    let first = h.audit.0.lock().unwrap()[0].clone();
    assert_eq!(first.decision, Decision::RefuseUpstream);
}

#[test]
fn b3_unloaded_secret_answers_503_and_makes_no_upstream_call() {
    let h = harness();
    let reply = h
        .proxy
        .handle(request("GET", "/github-api/repos/amarbel-llc/piggy"));
    assert!(matches!(reply, Reply::Refusal(Cause::SecretUnavailable)));
    assert_eq!(client_bytes(reply), b"503\nsecret-unavailable\n");
    assert!(h.upstream.calls.lock().unwrap().is_empty());
}

#[test]
fn b4_outside_the_allowlist_is_refused_identically_before_any_call() {
    let h = harness();
    h.holder.load(TOKEN.as_bytes()).unwrap();
    let refusals: Vec<Vec<u8>> = [
        ("GET", "/unknown-route/repos/amarbel-llc/piggy"),
        ("DELETE", "/github-api/repos/amarbel-llc/piggy"),
        ("GET", "/github-api/repos/someone-else/piggy"),
        ("GET", "/github-api/user/repos"),
        ("GET", "/github-api/repos/amarbel-llc/%2e%2e"),
    ]
    .iter()
    .map(|(m, t)| client_bytes(h.proxy.handle(request(m, t))))
    .collect();
    assert!(
        refusals.iter().all(|r| r == b"403\nrefused\n"),
        "{refusals:?}"
    );
    assert!(h.upstream.calls.lock().unwrap().is_empty());
}

#[test]
fn b5_a_redirect_off_the_upstream_host_is_an_error() {
    let h = harness_with(
        Box::new(|_| {
            (
                302,
                headers(&[("Location", "https://evil.example/collect")]),
                Vec::new(),
            )
        }),
        None,
    );
    h.holder.load(TOKEN.as_bytes()).unwrap();
    let reply = h
        .proxy
        .handle(request("GET", "/github-api/repos/amarbel-llc/piggy"));
    assert_eq!(client_bytes(reply), b"502\nupstream-redirect-refused\n");
    // The proxy never follows: one call, to the route's own host.
    let calls = h.upstream.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].host, "api.github.com");
}

#[test]
fn b6_a_connection_from_another_uid_is_refused() {
    let (_client, server) = std::os::unix::net::UnixStream::pair().unwrap();
    let me = pigtrough::listener::effective_uid();
    assert!(admit_peer(&server, me));
    assert!(!admit_peer(&server, me.wrapping_add(1)));
    let h = harness();
    h.proxy.refuse_binding();
    let line = audit_lines(&h);
    assert!(line.contains("decision=refuse-binding"), "{line}");
}

#[test]
fn b7_audit_line_has_the_fields_and_nothing_else() {
    let h = harness();
    h.holder.load(TOKEN.as_bytes()).unwrap();
    let mut req = request("GET", "/github-api/repos/amarbel-llc/piggy?per_page=100");
    req.headers
        .push(("X-Github-Api-Version".to_owned(), b"2022-11-28".to_vec()));
    let body = client_bytes(h.proxy.handle(req));
    client_bytes(
        h.proxy
            .handle(request("DELETE", "/github-api/repos/amarbel-llc/piggy")),
    );

    let records = h.audit.0.lock().unwrap().clone();
    assert_eq!(records.len(), 2);
    let allowed = &records[0];
    assert_eq!(allowed.route, Some("github-api"));
    assert_eq!(allowed.method.as_deref(), Some("GET"));
    assert_eq!(
        allowed.path.as_deref(),
        Some("/github-api/repos/amarbel-llc/piggy")
    );
    assert_eq!(allowed.status, Some(200));
    assert_eq!(allowed.decision, Decision::Allow);
    assert_eq!(
        allowed.bytes_out as usize,
        b"{\"full_name\":\"amarbel-llc/piggy\"}".len()
    );
    assert!(contains(&body, "full_name"));
    let refused = &records[1];
    assert_eq!(refused.decision, Decision::RefuseAllowlist);
    assert_eq!(refused.status, Some(403));

    let lines = audit_lines(&h);
    for absent in [
        "per_page",
        "2022-11-28",
        "mirror-reconciler",
        "application/vnd.github+json",
        "full_name",
    ] {
        assert!(!lines.contains(absent), "{absent} in {lines}");
    }
}

#[test]
fn b8_reload_replaces_the_secret_and_in_flight_requests_keep_the_old_one() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::channel();
    let h = harness_with(
        Box::new(|_| (200, Headers::new(), b"ok".to_vec())),
        Some(Gate {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }),
    );
    h.holder.load(TOKEN.as_bytes()).unwrap();

    let proxy = h.proxy.clone();
    let in_flight = std::thread::spawn(move || {
        client_bytes(proxy.handle(request("GET", "/github-api/repos/amarbel-llc/piggy")))
    });
    entered_rx.recv().unwrap();
    h.holder.load(NEXT_TOKEN.as_bytes()).unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(in_flight.join().unwrap(), b"200\nok");

    let proxy = h.proxy.clone();
    let next = std::thread::spawn(move || {
        client_bytes(proxy.handle(request("GET", "/github-api/repos/amarbel-llc/piggy")))
    });
    entered_rx.recv().unwrap();
    release_tx.send(()).unwrap();
    next.join().unwrap();

    let auths: Vec<String> = h
        .upstream
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|c| c.authorization.clone())
        .collect();
    assert_eq!(
        auths,
        vec![format!("Bearer {TOKEN}"), format!("Bearer {NEXT_TOKEN}")]
    );
}
