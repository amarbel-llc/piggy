//! The fixed answers the proxy gives instead of an upstream response.
//!
//! Every body is a constant naming the cause (FDR 0009 question 6), so no
//! refusal can carry request data, upstream data or a credential.

use crate::audit::Decision;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// An unknown route, or a method or path the route does not allow. One
    /// cause for all of them, so a client cannot tell which (behaviour 4).
    Refused,
    /// The client's request could not be read whole: a body larger than the
    /// limit, or shorter than its declared length.
    RequestRejected,
    /// The route's secret is not loaded (behaviour 3).
    SecretUnavailable,
    /// The upstream could not be reached, failed TLS verification, or
    /// answered with something the proxy could not read.
    UpstreamUnavailable,
    /// The upstream redirected off its own host (behaviour 5).
    UpstreamRedirectRefused,
    /// The upstream sent a content-coded body, which the credential scan
    /// cannot read.
    UpstreamEncodedResponse,
    /// The upstream echoed the credential in its response body; the
    /// response is cut off.
    UpstreamEchoedCredential,
    /// The client hung up while its request was in flight; the upstream
    /// call was cancelled. Nothing is sent (there is no one to send to), so
    /// the status is only for the audit line.
    ClientGone,
}

impl Cause {
    pub fn status(self) -> u16 {
        match self {
            Cause::ClientGone => 499,
            Cause::Refused => 403,
            Cause::RequestRejected => 400,
            Cause::SecretUnavailable => 503,
            Cause::UpstreamUnavailable
            | Cause::UpstreamRedirectRefused
            | Cause::UpstreamEncodedResponse
            | Cause::UpstreamEchoedCredential => 502,
        }
    }

    /// The cause token, which is also the whole response body (plus a
    /// newline).
    pub fn token(self) -> &'static str {
        match self {
            Cause::Refused => "refused",
            Cause::RequestRejected => "request-rejected",
            Cause::SecretUnavailable => "secret-unavailable",
            Cause::UpstreamUnavailable => "upstream-unavailable",
            Cause::UpstreamRedirectRefused => "upstream-redirect-refused",
            Cause::UpstreamEncodedResponse => "upstream-encoded-response",
            Cause::UpstreamEchoedCredential => "upstream-echoed-credential",
            Cause::ClientGone => "client-gone",
        }
    }

    pub fn body(self) -> String {
        format!("{}\n", self.token())
    }

    pub fn decision(self) -> Decision {
        match self {
            Cause::ClientGone => Decision::ClientGone,
            Cause::Refused => Decision::RefuseAllowlist,
            Cause::RequestRejected => Decision::RefuseMalformed,
            Cause::SecretUnavailable => Decision::RefuseUnavailable,
            Cause::UpstreamUnavailable
            | Cause::UpstreamRedirectRefused
            | Cause::UpstreamEncodedResponse
            | Cause::UpstreamEchoedCredential => Decision::RefuseUpstream,
        }
    }
}
