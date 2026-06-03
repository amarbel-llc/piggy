//! Best-effort stats-me / statsd telemetry.
//!
//! stats-me is upstream statsd packaged under Bun; clients publish by
//! sending UDP datagrams in the statsd wire format to the daemon (see
//! `stats-me-clients(7)` in the amarbel-llc/stats-me repo). There is no
//! library API and no auth — anything that can write UDP can publish.
//!
//! Emission is gated on the *presence* of the `STATSD_HOST` /
//! `STATSD_PORT` environment variables that the stats-me home-manager
//! module exports via `home.sessionVariables`. When neither is set every
//! call is a no-op, so piggy never sprays UDP at a host that has not
//! opted in. When at least one is present we follow the documented
//! resolution order: `STATSD_HOST` (present-but-empty treated as unset,
//! defaulting to the loopback `127.0.0.1`) and `STATSD_PORT` (default
//! `8125`).
//!
//! UDP is fire-and-forget: any failure to resolve, bind, or send is
//! swallowed. Telemetry must never perturb the agent's behaviour.

use std::net::UdpSocket;
use std::time::Duration;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8125;

/// Outcome of an operation, encoded into the metric name and a tag.
#[derive(Clone, Copy)]
pub enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        }
    }
}

/// Map a `Result` to an [`Outcome`] for the common "did it error?" case.
pub fn outcome_of<T, E>(r: &Result<T, E>) -> Outcome {
    match r {
        Ok(_) => Outcome::Success,
        Err(_) => Outcome::Failure,
    }
}

/// Resolve the stats-me endpoint from the environment, returning `None`
/// when neither `STATSD_HOST` nor `STATSD_PORT` is present (the opt-in
/// gate). Present-but-empty `STATSD_HOST` falls back to loopback per
/// `stats-me-clients(7)`.
fn endpoint() -> Option<(String, u16)> {
    let host_var = std::env::var("STATSD_HOST").ok();
    let port_var = std::env::var("STATSD_PORT").ok();

    if host_var.is_none() && port_var.is_none() {
        return None;
    }

    let host = match host_var {
        Some(h) if !h.is_empty() => h,
        _ => DEFAULT_HOST.to_string(),
    };
    let port = port_var
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    Some((host, port))
}

/// Send a statsd payload (one or more newline-separated lines),
/// fire-and-forget. Every error is swallowed.
fn send(payload: &str) {
    let Some((host, port)) = endpoint() else {
        return;
    };
    let _ = (|| -> std::io::Result<()> {
        let sock = UdpSocket::bind(("0.0.0.0", 0))?;
        sock.connect((host.as_str(), port))?;
        sock.send(payload.as_bytes())?;
        Ok(())
    })();
}

/// statsd treats `.` as the hierarchy separator and the joyent
/// extension names carry `@` and `.`, so map anything outside
/// `[A-Za-z0-9_]` to `_` and lowercase the alphabetics.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Record the completion of one SSH-agent operation: a counter keyed by
/// operation type and outcome, plus a timer carrying the elapsed
/// milliseconds. Both lines also carry DogStatsD-style `op`/`result`
/// tags for tag-aware backends (the console backend ignores them).
pub fn agent_op(op: &str, outcome: Outcome, elapsed: Duration) {
    let op = sanitize(op);
    let result = outcome.as_str();
    let ms = elapsed.as_millis();
    let payload = format!(
        "piggy.agent.{op}.{result}:1|c|#op:{op},result:{result}\n\
         piggy.agent.{op}.duration:{ms}|ms|#op:{op},result:{result}"
    );
    send(&payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_maps_reserved_chars() {
        assert_eq!(sanitize("ecdh@joyent.com"), "ecdh_joyent_com");
        assert_eq!(
            sanitize("session-bind@openssh.com"),
            "session_bind_openssh_com"
        );
        assert_eq!(sanitize("SIGN_REQUEST"), "sign_request");
    }

    #[test]
    fn endpoint_gated_on_env_presence() {
        // Snapshot + clear so the test is order-independent.
        let saved_host = std::env::var("STATSD_HOST").ok();
        let saved_port = std::env::var("STATSD_PORT").ok();
        std::env::remove_var("STATSD_HOST");
        std::env::remove_var("STATSD_PORT");
        assert!(endpoint().is_none(), "no env -> no endpoint");

        std::env::set_var("STATSD_PORT", "9999");
        assert_eq!(endpoint(), Some((DEFAULT_HOST.to_string(), 9999)));

        std::env::set_var("STATSD_HOST", "");
        assert_eq!(
            endpoint(),
            Some((DEFAULT_HOST.to_string(), 9999)),
            "empty host falls back to loopback"
        );

        std::env::set_var("STATSD_HOST", "10.0.0.5");
        std::env::remove_var("STATSD_PORT");
        assert_eq!(endpoint(), Some(("10.0.0.5".to_string(), DEFAULT_PORT)));

        // Restore.
        match saved_host {
            Some(v) => std::env::set_var("STATSD_HOST", v),
            None => std::env::remove_var("STATSD_HOST"),
        }
        match saved_port {
            Some(v) => std::env::set_var("STATSD_PORT", v),
            None => std::env::remove_var("STATSD_PORT"),
        }
    }
}
