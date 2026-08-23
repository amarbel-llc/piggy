//! The `agent-mode@piggy` self-report: which role this agent is running
//! in (eng#295). Piggy-private, advertised in `query` and answered by
//! every Rust `piggy agent`; `piggy health` reads it to shape its plan —
//! a proxy-only agent has no card, so the pcsc/card points are SKIPped
//! rather than failed. Agents predating the extension don't advertise
//! it, and health treats that as "card-backed" (the only role that
//! existed).
//!
//! Kept next to [`super::upstream::UPSTREAM_STATUS_EXT`] in spirit: the
//! agent is the one source of truth about its own configuration, so
//! health never needs a parallel flag surface.

/// The piggy-private extension name.
pub const AGENT_MODE_EXT: &str = "agent-mode@piggy";

/// The [`AGENT_MODE_EXT`] JSON payload.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentMode {
    /// `--proxy-only`: no native PIV keys, upstreams only.
    pub proxy_only: bool,
    /// Native (card) keys currently served — 0 for proxy-only, and for a
    /// card-backed agent whose card is absent / not yet recovered.
    pub native_keys: usize,
    /// Number of configured `--upstream` agents (0 = none).
    pub upstreams: usize,
    /// The service unit / launchd label this agent runs under, as told to
    /// it via `--service-name` (piggy#162). `piggy health` probes THIS
    /// unit for its point-1 service check instead of hardcoding
    /// `piggy-agent.service`, so multi-instance units
    /// (`piggy-agent-<name>.service`) and non-home-manager labels report
    /// correctly. `None` (older agent, or no `--service-name`) → health
    /// falls back to the platform default, exactly as before.
    /// `#[serde(default)]` keeps the payload forward/backward compatible
    /// across agent/health version skew.
    #[serde(default)]
    pub service: Option<String>,
}
