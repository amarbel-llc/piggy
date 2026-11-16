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
    /// The route's secret is not loaded (behaviour 3).
    SecretUnavailable,
    /// The upstream could not be reached or answered with something the
    /// proxy could not read.
    UpstreamUnavailable,
    /// The upstream redirected off its own host (behaviour 5).
    UpstreamRedirectRefused,
    /// The upstream echoed the credential in its response body; the
    /// response is cut off.
    UpstreamEchoedCredential,
}

impl Cause {
    pub fn status(self) -> u16 {
        match self {
            Cause::Refused => 403,
            Cause::SecretUnavailable => 503,
            Cause::UpstreamUnavailable
            | Cause::UpstreamRedirectRefused
            | Cause::UpstreamEchoedCredential => 502,
        }
    }

    /// The cause token, which is also the whole response body (plus a
    /// newline).
    pub fn token(self) -> &'static str {
        match self {
            Cause::Refused => "refused",
            Cause::SecretUnavailable => "secret-unavailable",
            Cause::UpstreamUnavailable => "upstream-unavailable",
            Cause::UpstreamRedirectRefused => "upstream-redirect-refused",
            Cause::UpstreamEchoedCredential => "upstream-echoed-credential",
        }
    }

    pub fn body(self) -> String {
        format!("{}\n", self.token())
    }

    pub fn decision(self) -> Decision {
        match self {
            Cause::Refused => Decision::RefuseAllowlist,
            Cause::SecretUnavailable => Decision::RefuseUnavailable,
            Cause::UpstreamUnavailable
            | Cause::UpstreamRedirectRefused
            | Cause::UpstreamEchoedCredential => Decision::RefuseUpstream,
        }
    }
}
