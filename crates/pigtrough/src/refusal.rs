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
    /// limit, shorter than its declared length, or too slow to arrive.
    RequestRejected,
    /// The request's body does not fit in the memory the proxy keeps for
    /// bodies at once; the same request may pass later.
    Busy,
    /// The upstream was reached and did not start answering within the
    /// route's response-head timeout. It may have acted on the request.
    UpstreamTimeout,
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
            Cause::Busy => 429,
            Cause::UpstreamTimeout => 504,
            Cause::SecretUnavailable => 503,
            Cause::UpstreamUnavailable
            | Cause::UpstreamRedirectRefused
            | Cause::UpstreamEncodedResponse
            | Cause::UpstreamEchoedCredential => 502,
        }
    }

    /// The cause token, the first line of the response body.
    pub fn token(self) -> &'static str {
        match self {
            Cause::Refused => "refused",
            Cause::RequestRejected => "request-rejected",
            Cause::Busy => "proxy-busy",
            Cause::UpstreamTimeout => "upstream-timeout",
            Cause::SecretUnavailable => "secret-unavailable",
            Cause::UpstreamUnavailable => "upstream-unavailable",
            Cause::UpstreamRedirectRefused => "upstream-redirect-refused",
            Cause::UpstreamEncodedResponse => "upstream-encoded-response",
            Cause::UpstreamEchoedCredential => "upstream-echoed-credential",
            Cause::ClientGone => "client-gone",
        }
    }

    /// What gets a client past a limit of the proxy's own, naming the
    /// setting to change.
    pub fn hint(self) -> Option<&'static str> {
        match self {
            Cause::RequestRejected => Some(
                "The body may be over the route's max_request_body_bytes, or too slow \
                 for serve --body-read-timeout-seconds.",
            ),
            Cause::Busy => Some(
                "Retry later (a body larger than the whole cap never fits). The operator \
                 can change the cap with serve --max-buffered-bytes.",
            ),
            Cause::UpstreamTimeout => Some(
                "The upstream may have acted on the request. The operator can raise the \
                 route's response_head_timeout_seconds.",
            ),
            _ => None,
        }
    }

    /// The cause token on a line of its own, then the hint if it has one.
    pub fn body(self) -> String {
        match self.hint() {
            Some(hint) => format!("{}\n{hint}\n", self.token()),
            None => format!("{}\n", self.token()),
        }
    }

    pub fn decision(self) -> Decision {
        match self {
            Cause::ClientGone => Decision::ClientGone,
            Cause::Refused => Decision::RefuseAllowlist,
            Cause::RequestRejected => Decision::RefuseMalformed,
            Cause::Busy => Decision::RefuseBusy,
            Cause::SecretUnavailable => Decision::RefuseUnavailable,
            Cause::UpstreamTimeout
            | Cause::UpstreamUnavailable
            | Cause::UpstreamRedirectRefused
            | Cause::UpstreamEncodedResponse
            | Cause::UpstreamEchoedCredential => Decision::RefuseUpstream,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limits_refusal_names_the_setting_that_changes_it() {
        for (cause, settings) in [
            (
                Cause::RequestRejected,
                &["max_request_body_bytes", "--body-read-timeout-seconds"][..],
            ),
            (Cause::Busy, &["--max-buffered-bytes"]),
            (Cause::UpstreamTimeout, &["response_head_timeout_seconds"]),
        ] {
            let body = cause.body();
            assert!(body.starts_with(&format!("{}\n", cause.token())), "{body}");
            assert_eq!(body.lines().count(), 2, "{body}");
            for setting in settings {
                assert!(body.contains(setting), "{body} lacks {setting}");
            }
        }
        assert_eq!(Cause::Refused.body(), "refused\n");
    }
}
