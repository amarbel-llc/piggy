//! The request path: admit, decorate, forward, check, return.
//!
//! [`Proxy::handle`] takes a request already read off the wire and returns
//! what to write back, so it does not depend on the HTTP library (FDR 0009
//! question 7). Its order fixes the fail-closed properties: the allowlist
//! and the secret are both checked before the upstream is called, so a
//! refused or undecoratable request makes no upstream connection
//! (behaviours 3 and 4).

use std::io::{self, Read};
use std::sync::Arc;

use bytes::Bytes;

use crate::Headers;
use crate::audit::{AuditRecord, AuditSink, Decision};
use crate::budget::BodyBudget;
use crate::cancel::Cancel;
use crate::filter::{ScannedBody, inbound_headers, outbound_headers};
use crate::holder::{Mount, SecretHolder};
use crate::refusal::Cause;
use crate::route::{Limits, Route, admit};
use crate::upstream::{Credential, OutboundRequest, UpstreamClient, UpstreamError};

/// A client request, as the wire adapter read it. A body with a transfer
/// coding has already been decoded or refused by the adapter.
#[derive(Debug)]
pub struct ClientRequest {
    pub method: String,
    pub target: String,
    pub headers: Headers,
    pub body: Bytes,
}

/// What to send back to the client.
pub enum Reply {
    /// A fixed refusal: the status and body come from the cause alone.
    Refusal(Cause),
    Upstream {
        status: u16,
        headers: Headers,
        body: Box<ReplyBody>,
    },
}

impl Reply {
    pub fn status(&self) -> u16 {
        match self {
            Reply::Refusal(cause) => cause.status(),
            Reply::Upstream { status, .. } => *status,
        }
    }
}

/// The scope one proxy serves. In the pilot it is fixed (FDR 0009, ruling
/// p2): one socket, one bound UID.
pub struct Scope {
    pub name: String,
}

pub struct Proxy<C> {
    routes: Vec<&'static Route>,
    /// Parallel to `routes`: each route's own secret.
    holders: Vec<Arc<SecretHolder>>,
    client: C,
    audit: Arc<dyn AuditSink>,
    scope: Scope,
    /// Shared with every other proxy of the process.
    budget: Arc<BodyBudget>,
}

impl<C: UpstreamClient> Proxy<C> {
    /// A proxy serving `route` for `scope`, its secret in `holder`, with a
    /// body budget of its own.
    pub fn new(
        route: &'static Route,
        holder: Arc<SecretHolder>,
        client: C,
        audit: Arc<dyn AuditSink>,
        scope: Scope,
    ) -> Self {
        Self::with_mounts(
            vec![Mount { route, holder }],
            client,
            audit,
            scope,
            Arc::default(),
        )
    }

    /// A proxy serving every mounted route for `scope`, each decorated with
    /// its own holder's secret. A request can only reach a route in `mounts`.
    /// Proxies that share a process must share `budget`.
    pub fn with_mounts(
        mounts: Vec<Mount>,
        client: C,
        audit: Arc<dyn AuditSink>,
        scope: Scope,
        budget: Arc<BodyBudget>,
    ) -> Self {
        Self {
            routes: mounts.iter().map(|m| m.route).collect(),
            holders: mounts.into_iter().map(|m| m.holder).collect(),
            client,
            audit,
            scope,
            budget,
        }
    }

    /// What request bodies held in memory are charged against.
    pub fn body_budget(&self) -> &Arc<BodyBudget> {
        &self.budget
    }

    /// The limits of the route that admits `method` and `target`, so the wire
    /// adapter can tell before it reads a body whether to read one and how
    /// much. `None` is a [`Cause::Refused`] request.
    pub fn admitted_limits(&self, method: &str, target: &str) -> Option<Limits> {
        admit(&self.routes, method, target).map(|admitted| admitted.route.limits)
    }

    /// Record a connection refused before any request was read.
    pub fn refuse_binding(&self) {
        self.audit
            .record(&AuditRecord::new(&self.scope.name, Decision::RefuseBinding));
    }

    /// Handle `request` with nothing able to cancel it.
    pub fn handle(&self, request: ClientRequest) -> Reply {
        self.handle_with(request, Cancel::default())
    }

    /// Handle `request`; when `cancel` fires (the client hung up) the
    /// upstream call stops and the reply is [`Cause::ClientGone`].
    pub fn handle_with(&self, request: ClientRequest, cancel: Cancel) -> Reply {
        let mut record = AuditRecord::new(&self.scope.name, Decision::Allow)
            .request(&request.method, &request.target);
        record.bytes_in = request.body.len() as u64;

        let Some(admitted) = admit(&self.routes, &request.method, &request.target) else {
            return self.refuse(record, Cause::Refused);
        };
        record.route = Some(admitted.route.name);

        // `admit` returns one of `self.routes`, so the name finds its holder.
        let holder = self
            .routes
            .iter()
            .position(|r| r.name == admitted.route.name)
            .map(|i| &self.holders[i]);
        let Some(secret) = holder.and_then(|h| h.current()) else {
            return self.refuse(record, Cause::SecretUnavailable);
        };
        if cancel.is_cancelled() {
            return self.refuse(record, Cause::ClientGone);
        }
        let credential = Credential::new(admitted.route.scheme, secret.clone());
        let outbound = OutboundRequest {
            method: &request.method,
            path_and_query: admitted.path_and_query(),
            headers: outbound_headers(admitted.route, &request.headers),
            credential,
            // A clone, so the body stays charged until the upstream has
            // answered: the client may hold copies of it that long.
            body: request.body.clone(),
            head_timeout: admitted.route.limits.response_head_timeout,
            cancel,
        };
        let upstream = &admitted.route.upstream;
        let response = match self.client.send(upstream, outbound) {
            Ok(response) => response,
            Err(UpstreamError::Cancelled) => return self.refuse(record, Cause::ClientGone),
            Err(UpstreamError::Timeout) => return self.refuse(record, Cause::UpstreamTimeout),
            Err(_) => return self.refuse(record, Cause::UpstreamUnavailable),
        };
        let headers = match inbound_headers(upstream, response.status, response.headers, &secret) {
            Ok(headers) => headers,
            Err(cause) => return self.refuse(record, cause),
        };
        record.status = Some(response.status);
        Reply::Upstream {
            status: response.status,
            headers,
            body: Box::new(ReplyBody {
                inner: ScannedBody::new(response.body, secret),
                record: Some(record),
                audit: self.audit.clone(),
            }),
        }
    }

    /// Refuse a request the wire adapter will not hand to
    /// [`Proxy::handle`], with its audit line.
    pub fn reject(&self, method: &str, target: &str, cause: Cause) -> Reply {
        let mut record =
            AuditRecord::new(&self.scope.name, Decision::Allow).request(method, target);
        record.route = admit(&self.routes, method, target).map(|a| a.route.name);
        self.refuse(record, cause)
    }

    fn refuse(&self, mut record: AuditRecord, cause: Cause) -> Reply {
        record.decision = cause.decision();
        record.status = Some(cause.status());
        self.audit.record(&record);
        Reply::Refusal(cause)
    }
}

/// An upstream response body on its way to the client. It writes the
/// request's audit line when it is dropped, with the bytes actually
/// returned, so a line is written whether the body was read to the end, cut
/// off by an echoed credential, or abandoned by the client.
pub struct ReplyBody {
    inner: ScannedBody<Box<dyn Read + Send>>,
    record: Option<AuditRecord>,
    audit: Arc<dyn AuditSink>,
}

impl Read for ReplyBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buf);
        if result.is_err() {
            if let Some(record) = self.record.as_mut() {
                record.decision = Decision::RefuseUpstream;
            }
        }
        result
    }
}

impl Drop for ReplyBody {
    fn drop(&mut self) {
        if let Some(mut record) = self.record.take() {
            record.bytes_out = self.inner.count;
            self.audit.record(&record);
        }
    }
}
