//! Several routes through one proxy (slice 2) and a proxy restricted to one
//! of them (the loopback listener's shape, slice 3), driven through
//! `Proxy::handle` against a fake upstream. The routes come from a route
//! table parsed in the test. No card, no network, no real credential.

use std::sync::{Arc, Mutex};

use pigtrough::Headers;
use pigtrough::audit::{AuditRecord, AuditSink};
use pigtrough::holder::Mount;
use pigtrough::proxy::{ClientRequest, Proxy, Scope};
use pigtrough::table;
use pigtrough::upstream::{OutboundRequest, UpstreamClient, UpstreamError, UpstreamResponse};

const TABLE: &str = r#"
[[route]]
name = "alpha"
upstream = "alpha.invalid"
auth = "bearer"
secret = "piggy-test/alpha"
owners = ["some-org"]
[[route.allow]]
method = "GET"
path = ["repos", "{owner}", "{name}"]

[[route]]
name = "beta"
upstream = "beta.invalid:8443"
auth = "token"
secret = "piggy-test/beta"
owners = ["some-org"]
[[route.allow]]
method = "GET"
path = ["api", "v1", "repos", "{owner}", "{name}"]
"#;

/// What the fake upstream saw: the host and port dialled and the
/// `Authorization` value.
type Calls = Arc<Mutex<Vec<(String, u16, String)>>>;

struct FakeClient(Calls);

impl UpstreamClient for FakeClient {
    fn send(
        &self,
        upstream: &pigtrough::route::Upstream,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let authorization = request
            .credential
            .with_header_value(|v| String::from_utf8(v.to_vec()).unwrap())
            .unwrap();
        self.0
            .lock()
            .unwrap()
            .push((upstream.host.to_owned(), upstream.port, authorization));
        Ok(UpstreamResponse {
            status: 200,
            headers: Headers::new(),
            body: Box::new(std::io::Cursor::new(b"ok".to_vec())),
        })
    }
}

struct NullSink;

impl AuditSink for NullSink {
    fn record(&self, _record: &AuditRecord) {}
}

struct Rig {
    mounts: Vec<Mount>,
    calls: Calls,
}

fn rig() -> Rig {
    let mounts = table::parse(TABLE)
        .unwrap()
        .into_iter()
        .map(|e| Mount::empty(e.route))
        .collect();
    Rig {
        mounts,
        calls: Arc::default(),
    }
}

fn proxy(rig: &Rig, mounts: Vec<Mount>) -> Proxy<FakeClient> {
    Proxy::with_mounts(
        mounts,
        FakeClient(rig.calls.clone()),
        Arc::new(NullSink),
        Scope {
            name: "operator".to_owned(),
        },
        Arc::default(),
    )
}

fn get(proxy: &Proxy<FakeClient>, target: &str) -> u16 {
    let reply = proxy.handle(ClientRequest {
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: Headers::new(),
        body: Default::default(),
    });
    // The body is dropped unread; the fake upstream has nothing to cut.
    reply.status()
}

#[test]
fn each_route_decorates_with_its_own_secret_scheme_and_upstream() {
    let rig = rig();
    let proxy = proxy(&rig, rig.mounts.clone());
    rig.mounts[0].holder.load(b"alpha-secret").unwrap();
    rig.mounts[1].holder.load(b"beta-secret").unwrap();
    assert_eq!(get(&proxy, "/alpha/repos/some-org/x"), 200);
    assert_eq!(get(&proxy, "/beta/api/v1/repos/some-org/x"), 200);
    assert_eq!(
        *rig.calls.lock().unwrap(),
        vec![
            (
                "alpha.invalid".to_owned(),
                443,
                "Bearer alpha-secret".to_owned()
            ),
            (
                "beta.invalid".to_owned(),
                8443,
                "token beta-secret".to_owned()
            ),
        ]
    );
}

#[test]
fn a_route_with_no_secret_is_unavailable_while_the_other_serves() {
    let rig = rig();
    let proxy = proxy(&rig, rig.mounts.clone());
    rig.mounts[1].holder.load(b"beta-secret").unwrap();
    assert_eq!(get(&proxy, "/alpha/repos/some-org/x"), 503);
    assert_eq!(get(&proxy, "/beta/api/v1/repos/some-org/x"), 200);
    assert_eq!(rig.calls.lock().unwrap().len(), 1, "alpha made no call");
}

#[test]
fn a_proxy_over_one_mount_cannot_name_the_other_route() {
    let rig = rig();
    rig.mounts[0].holder.load(b"alpha-secret").unwrap();
    rig.mounts[1].holder.load(b"beta-secret").unwrap();
    let only_beta = proxy(&rig, vec![rig.mounts[1].clone()]);
    assert_eq!(get(&only_beta, "/alpha/repos/some-org/x"), 403);
    assert_eq!(get(&only_beta, "/beta/api/v1/repos/some-org/x"), 200);
    assert_eq!(
        rig.calls.lock().unwrap().len(),
        1,
        "the refused call reached no upstream"
    );
}

/// A client whose call is always cancelled, as the TLS client reports it.
struct CancelledClient;

impl UpstreamClient for CancelledClient {
    fn send(
        &self,
        _upstream: &pigtrough::route::Upstream,
        _request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, UpstreamError> {
        Err(UpstreamError::Cancelled)
    }
}

fn request(target: &str) -> ClientRequest {
    ClientRequest {
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: Headers::new(),
        body: Default::default(),
    }
}

#[test]
fn a_cancel_that_fired_before_the_call_makes_no_upstream_call() {
    let rig = rig();
    rig.mounts[0].holder.load(b"alpha-secret").unwrap();
    let proxy = proxy(&rig, rig.mounts.clone());
    let cancel = pigtrough::cancel::Cancel::default();
    cancel.cancel();
    let reply = proxy.handle_with(request("/alpha/repos/some-org/x"), cancel);
    assert_eq!(reply.status(), 499);
    assert!(rig.calls.lock().unwrap().is_empty());
}

#[test]
fn an_upstream_that_reports_cancelled_is_client_gone_not_unavailable() {
    let rig = rig();
    rig.mounts[0].holder.load(b"alpha-secret").unwrap();
    let proxy = Proxy::with_mounts(
        rig.mounts.clone(),
        CancelledClient,
        Arc::new(NullSink),
        Scope {
            name: "operator".to_owned(),
        },
        Arc::default(),
    );
    let reply = proxy.handle(request("/alpha/repos/some-org/x"));
    assert_eq!(reply.status(), 499);
}

#[test]
fn a_route_cannot_use_another_routes_shapes() {
    let rig = rig();
    let proxy = proxy(&rig, rig.mounts.clone());
    rig.mounts[0].holder.load(b"alpha-secret").unwrap();
    rig.mounts[1].holder.load(b"beta-secret").unwrap();
    assert_eq!(get(&proxy, "/alpha/api/v1/repos/some-org/x"), 403);
    assert_eq!(get(&proxy, "/beta/repos/some-org/x"), 403);
    assert!(rig.calls.lock().unwrap().is_empty());
}
