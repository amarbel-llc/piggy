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
use std::time::{Duration, Instant};

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

/// Map a process exit code to an [`Outcome`] (0 = success). Used by the
/// CLI emitters, whose handlers return their exit code.
pub fn outcome_of_code(code: i32) -> Outcome {
    if code == 0 {
        Outcome::Success
    } else {
        Outcome::Failure
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

/// Build the two-line statsd payload (counter + duration timer) for a
/// completed operation under `piggy.<category>.<op>`. Pure — the wire shape
/// is asserted in tests; `op` is assumed already sanitized.
fn payload(category: &str, op: &str, outcome: Outcome, ms: u128) -> String {
    let result = outcome.as_str();
    format!(
        "piggy.{category}.{op}.{result}:1|c|#op:{op},result:{result}\n\
         piggy.{category}.{op}.duration:{ms}|ms|#op:{op},result:{result}"
    )
}

/// Record the completion of one operation: a counter keyed by op + outcome
/// plus a duration timer, under the `piggy.<category>` namespace. Both
/// lines carry DogStatsD-style `op`/`result` tags for tag-aware backends.
fn record(category: &str, op: &str, outcome: Outcome, elapsed: Duration) {
    let op = sanitize(op);
    send(&payload(category, &op, outcome, elapsed.as_millis()));
}

/// SSH-agent request telemetry: `piggy.agent.<op>`. The C `pivy-agent`
/// mirrors this exact wire shape (`stats_send` / `agent_stats_op_done`), so
/// the `agent` category must stay byte-compatible.
pub fn agent_op(op: &str, outcome: Outcome, elapsed: Duration) {
    record("agent", op, outcome, elapsed);
}

/// User-facing `pass` subcommand telemetry: `piggy.pass.<cmd>`.
pub fn pass_op(cmd: &str, outcome: Outcome, elapsed: Duration) {
    record("pass", cmd, outcome, elapsed);
}

/// `piggy box` telemetry: `piggy.box.<op>` (e.g. `stream_decrypt`).
pub fn box_op(op: &str, outcome: Outcome, elapsed: Duration) {
    record("box", op, outcome, elapsed);
}

/// `piggy papi` telemetry: `piggy.papi.<sub>` (`sign`/`prove`/`verify`).
/// Rust-only category, like `piggy.health` — the C agent has no PAPI path.
pub fn papi_op(sub: &str, outcome: Outcome, elapsed: Duration) {
    record("papi", sub, outcome, elapsed);
}

/// Time `f` — a `pass` subcommand handler returning its process exit code —
/// emit a `piggy.pass.<cmd>` counter + timer, and return the code so the
/// caller can `std::process::exit` it. The closure runs even when telemetry
/// is disabled (the emit is the only conditional part).
pub fn timed_pass<F: FnOnce() -> i32>(cmd: &str, f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    pass_op(cmd, outcome_of_code(code), start.elapsed());
    code
}

/// Time `f` — a `piggy box` operation handler returning its exit code — and
/// emit a `piggy.box.<op>` counter + timer. Returns the code.
pub fn timed_box<F: FnOnce() -> i32>(op: &str, f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    box_op(op, outcome_of_code(code), start.elapsed());
    code
}

/// Time `f` — the `piggy health` handler returning its exit code — and
/// emit a `piggy.health.run` counter + timer. Returns the code.
pub fn timed_health<F: FnOnce() -> i32>(f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    record("health", "run", outcome_of_code(code), start.elapsed());
    code
}

/// Time `f` — a `piggy papi` subcommand handler returning its exit code — and
/// emit a `piggy.papi.<sub>` counter + timer. Returns the code.
pub fn timed_papi<F: FnOnce() -> i32>(sub: &str, f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    papi_op(sub, outcome_of_code(code), start.elapsed());
    code
}

/// Time `f` — a `piggy card` subcommand handler returning its exit code — and
/// emit a `piggy.card.<sub>` counter + timer. Returns the code. Rust-only
/// category (provisioning has no C-agent path).
pub fn timed_card<F: FnOnce() -> i32>(sub: &str, f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    record("card", sub, outcome_of_code(code), start.elapsed());
    code
}

/// Time `f` — the `piggy sign-bytes` handler returning its exit code — and
/// emit a `piggy.sign_bytes.run` counter + timer. Returns the code. Rust-only
/// category, like `piggy.health` — the C agent has no CLI sign-bytes path.
pub fn timed_sign_bytes<F: FnOnce() -> i32>(f: F) -> i32 {
    let start = Instant::now();
    let code = f();
    record("sign_bytes", "run", outcome_of_code(code), start.elapsed());
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_agent_category_is_byte_identical_to_the_c_mirror() {
        // The `agent` category must reproduce the pre-refactor wire shape
        // exactly, since the C pivy-agent emits the same metric.
        assert_eq!(
            payload("agent", "sign", Outcome::Success, 7),
            "piggy.agent.sign.success:1|c|#op:sign,result:success\n\
             piggy.agent.sign.duration:7|ms|#op:sign,result:success"
        );
    }

    #[test]
    fn payload_categories_and_failure_outcome() {
        assert!(
            payload("pass", "show", Outcome::Failure, 3)
                .starts_with("piggy.pass.show.failure:1|c|#op:show,result:failure")
        );
        assert!(
            payload("box", "stream_decrypt", Outcome::Success, 0)
                .starts_with("piggy.box.stream_decrypt.success:1|c|")
        );
    }

    #[test]
    fn payload_health_category() {
        assert!(
            payload("health", "run", Outcome::Success, 5)
                .starts_with("piggy.health.run.success:1|c|")
        );
    }

    #[test]
    fn outcome_of_code_maps_zero_to_success() {
        assert!(matches!(outcome_of_code(0), Outcome::Success));
        assert!(matches!(outcome_of_code(1), Outcome::Failure));
        assert!(matches!(outcome_of_code(-1), Outcome::Failure));
    }

    #[test]
    fn timed_pass_returns_the_handler_code() {
        // Telemetry is gated off here (no STATSD_* env), so this just
        // exercises the closure + passthrough.
        assert_eq!(timed_pass("noop", || 0), 0);
        assert_eq!(timed_pass("noop", || 42), 42);
    }

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
