//! Shared value types for the engine platform boundary.
use scupper_core::mac::{
    Inputs,
    verify::{Qualification, Transport},
};
use serde::{Deserialize, Serialize};

/// Absolute deadline in the sleep-counting clock domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(pub u64);
/// An operation failure; timeouts do not imply rollback.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SysError {
    /// Confirmed failure with a static, secret-free diagnostic.
    #[error("{0}")]
    Failed(&'static str),
    /// Waiting ended; the effect may have happened.
    #[error("command deadline")]
    TimedOut,
    /// No confirmed outcome is available.
    #[error("outcome unknown")]
    Unknown,
}
/// Version-independent helper DNS dictionary identity for discovery and cleanup.
pub const OWNED_DNS_KEY: &str = "State:/Network/Service/com.scupper.tunnel/DNS";
/// Independently checked configuration component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfigKey {
    /// `WireGuard` UAPI configuration.
    Uapi,
    /// Tunnel addresses.
    Addresses,
    /// Tunnel MTU.
    Mtu,
    /// Endpoint's physical route.
    EndpointRoute,
    /// Split default routes.
    SplitRoutes,
    /// Owned DNS dictionary.
    Dns,
}
/// Non-secret typed settings. Secret UAPI material belongs to the platform adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Setting {
    /// Public readiness and generation marker, not private key material.
    Uapi(u64),
    /// Numeric tunnel addresses.
    Addresses(Vec<std::net::IpAddr>),
    /// Validated MTU supplied by setup.
    Mtu(u16),
    /// Numeric destination, interface, and gateway.
    Route {
        /// Numeric destination.
        destination: std::net::IpAddr,
        /// Validated interface name; checked before use by the adapter.
        interface: String,
        /// Numeric gateway.
        gateway: Option<std::net::IpAddr>,
    },
    /// Numeric split destinations.
    SplitRoutes(Vec<std::net::IpAddr>),
    /// Numeric resolver addresses.
    Dns(Vec<std::net::IpAddr>),
}
/// Provisional cadence and freshness inputs, in sleep-counting seconds.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    /// Positive-only cheap monitor cadence.
    pub cheap_check: u64,
    /// Complete qualified observation cadence.
    pub full_walk: u64,
    /// Maximum age measured from the oldest contributing read.
    pub max_age: u64,
    /// Bound on waiting for any one platform call.
    pub command_deadline: u64,
    /// Maximum interval before refreshing state cleanliness.
    pub state_flush: u64,
}
impl Default for Timings {
    fn default() -> Self {
        Self {
            cheap_check: 1,
            full_walk: 5,
            max_age: 15,
            command_deadline: 5,
            state_flush: 10,
        }
    }
}
/// Policy and qualification inputs supplied by setup and later pure collectors.
#[derive(Clone, Debug)]
pub struct Config {
    /// Validated renderer inputs.
    pub inputs: Inputs,
    /// Qualified surrounding pf configuration.
    pub qualification: Qualification,
    /// Explicit provisional cadence/freshness policy.
    pub timings: Timings,
    /// Independently selected transport.
    pub transport: Transport,
    /// Provisional MTU input, until platform qualification.
    pub mtu: u16,
    /// Numeric tunnel addresses supplied by setup.
    pub addresses: Vec<std::net::IpAddr>,
    /// Numeric resolver addresses supplied by setup.
    pub dns: Vec<std::net::IpAddr>,
}
/// Separate root-owned setup record; no writer is defined in this slice.
#[derive(Clone, Debug)]
pub struct InstallRecord {
    /// Authorized local owner.
    pub owner_uid: u32,
    /// Stable installation ownership identity.
    pub installation: String,
    /// Helper configuration and qualification.
    pub config: Config,
}
/// Read-only install record boundary.
pub trait InstallRecordReader {
    /// Read and validate the independently protected setup record.
    ///
    /// # Errors
    /// Refuses unreadable or untrusted setup metadata.
    fn read_install_record(&mut self, deadline: Deadline) -> Result<InstallRecord, SysError>;
}
/// Cheap monitor facts; positive checks never refresh a full protection proof.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent observed kernel facts.
pub struct CheapObservation {
    /// pf enabled at this read.
    pub pf_enabled: bool,
    /// Helper anchor exists and is reachable from the main ruleset.
    pub anchor_present: bool,
    /// The supervised current generation is still alive.
    pub child_alive: bool,
    /// Endpoint route is still installed.
    pub route_present: bool,
}
