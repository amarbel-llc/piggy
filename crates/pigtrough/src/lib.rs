//! The auth decoration proxy pilot (FDR 0009, "Pilot implementation plan").
//!
//! A client sends an ordinary HTTP request naming a route in the first path
//! segment (`/github-api/repos/...`); the proxy checks the route's allowlist,
//! attaches the route's credential and sends the request to the route's fixed
//! upstream. The client never holds the credential.
//!
//! The modules are kept apart so the provisional operator rulings stay cheap
//! to reverse (FDR 0009, ruling p1):
//!
//! - [`listener`]: the unix socket, its directory, and the peer-UID check.
//! - [`route`]: the route record and its allowlist (one compiled-in route).
//! - [`holder`]: the secret holder, one [`piggy_guard::GuardedBytes`] per
//!   route, replaced whole on `load`.
//! - [`filter`]: what the proxy forwards from the client and returns from
//!   the upstream.
//! - [`upstream`]: the seam to the HTTP/TLS client (FDR 0009 ruling t1:
//!   rustls with ring, hyper on tokio), the only module that will depend on
//!   that stack.
//! - [`audit`]: the one audit line per request.
//! - [`proxy`]: the request path that ties them together, independent of how
//!   the client's request arrived on the wire.
//!
//! The crate and its binary are `pigtrough` (operator ruling, 2026-11-16).

pub mod audit;
pub mod filter;
pub mod holder;
pub mod listener;
pub mod proxy;
pub mod refusal;
pub mod route;
pub mod upstream;

/// HTTP header fields in arrival order, names as received. The proxy's own
/// type, so nothing outside [`upstream`] depends on an HTTP library.
pub type Headers = Vec<(String, Vec<u8>)>;
