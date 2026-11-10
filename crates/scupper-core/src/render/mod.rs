//! Pure M2 namespace rules, route arguments and ordered sysctl values.
//!
//! Renderers consume only validated configuration and supplied state. They do
//! not load rules, execute commands, inspect links or read/write sysctls.

mod netns;
mod routes;
mod sysctls;

pub use netns::render_netns;
pub use routes::{Family, RouteTarget, desired_routes, route_argv};
pub use sysctls::{Scope, Sysctl, SysctlFamily, SysctlKey, desired_sysctls};

/// Configuration identity supplied by the caller, without observing a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionStamp {
    /// Monotonically increasing configuration version.
    pub version: u64,
    /// SHA-256 of the configuration, printed in full in the ruleset header.
    pub sha256: [u8; 32],
}

/// A failure to select validated renderer inputs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// The requested gateway does not exist; no ruleset is produced.
    #[error("render: unknown gateway")]
    UnknownGateway,
}

pub mod units;
