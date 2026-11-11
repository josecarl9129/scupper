//! Pure site parsing and exhaustive validation for the M2 topology.
//!
//! `SiteConfig` is editable, untrusted input. Only `ValidatedSite`, constructed
//! by `validate`, may be passed to a renderer. No operation here reads the host,
//! resolves DNS, opens secret files, or observes a clock.

mod model;
mod network;
mod parse;
mod types;
mod validate;
mod validated;

pub use model::*;
pub use parse::{ConfigError, ParseRule, parse_site};
pub use types::*;
pub use validate::validate;
pub use validated::*;

use std::fmt;

/// A value-free validation failure, safe even when input contains pasted secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Full dotted field path, with zero-based array indexes.
    pub path: String,
    /// The violated invariant.
    pub rule: Rule,
}
impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.rule)
    }
}
impl std::error::Error for ValidationError {}

macro_rules! rules {
    ($($name:ident => $doc:literal),+ $(,)?) => {
        /// Stable, value-free validation rule identifiers.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Rule { $(#[doc = $doc] $name),+ }
        impl fmt::Display for Rule {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
        }
    };
}
rules! {
    UnsupportedSchema => "Only schema version 1 is accepted.",
    NotSupportedInThisRelease => "This configuration feature is reserved for a later release.",
    InvalidIfname => "Interface names start with a lowercase letter or digit and contain 1–15 lowercase letters, digits or hyphens; lo and ex- are reserved.",
    ExitIfnamePrefix => "Exit interfaces must be ex- followed by one or more lowercase letters or digits.",
    InterfaceConflict => "Tunnel and uplink interface names must be pairwise disjoint and unique.",
    InvalidId => "Identifiers must use the required lowercase ID grammar.",
    DuplicateExitId => "Exit IDs must be unique within a gateway.",
    InvalidSiteName => "Site names must contain 1–64 printable characters.",
    InvalidExitName => "Exit names must contain 1–32 printable characters and must not be blank.",
    DuplicateExitName => "Exit names must be unique ignoring case.",
    ExitNameMatchesId => "An exit name must not equal another exit's ID.",
    InvalidTag => "Tags must contain lowercase letters, digits or hyphens.",
    EmptyPolicy => "The ordered exit policy must not be empty.",
    UnknownExit => "Every policy exit must exist.",
    DisabledExit => "Policy exits must be enabled.",
    DuplicatePolicyExit => "Policy exits must not repeat.",
    InvalidAddress => "An address must be a literal IP of the expected family and prefix form.",
    DeviceHostPrefix => "Client peers must have IPv4 host prefixes (/32), never default routes.",
    DeviceOutsideClientPrefix => "Device addresses must lie within the selected client subnet.",
    DuplicateDeviceAddress => "Device addresses must be unique.",
    DeviceAddressOverlap => "Device addresses must not overlap exit address prefixes or DNS servers.",
    UnknownGateway => "A device must reference existing gateways.",
    UnknownUser => "A device must reference an existing user.",
    InvalidEndpoint => "Endpoints must contain a literal IP and port 1–65535.",
    InvalidDnsServer => "DNS servers must be literal IP addresses.",
    InvalidAlertGrace => "Alert qualification grace must be between 1 and 300 seconds inclusive.",
    InvalidHeartbeatInterval => "Heartbeat interval must be between 10 seconds and 1 hour inclusive.",
    InvalidDuration => "Durations must be positive integer seconds, minutes or hours without overflow.",
    FailoverGraceNotLessThanHandshakeStale => "Failover grace must be less than the stale handshake threshold.",
    LooksLikeKeyMaterial => "A non-public-key string contains 32-byte base64 key material.",
    InvalidSecretRef => "Secret references must match `[a-z0-9][a-z0-9-]{0,62}`.",
    SecretKindMismatch => "Programmatically assembled references must use the directory required by their field.",
    InvalidPublicKey => "Public keys must decode to exactly 32 base64 bytes.",
    UnknownIdentity => "A client tunnel must reference an existing identity.",
    IdentityShared => "An identity may be used by at most one gateway.",
    PrimaryGatewayMismatch => "The primary ID must equal the only configured gateway.",
    BlockDotRequired => "DNS-over-TLS blocking must be enabled when DNS settings are present.",
    InvalidPort => "Listen ports must be between 1 and 65535.",
    InvalidNamespace => "The owned namespace must be scupper.",
    InvalidMtu => "Tunnel MTUs must fit the supported IPv4 range (576–65535).",
    InvalidTokenHash => "API token hashes must contain exactly 64 hex digits.",
    InvalidProbeUrl => "Probe and speed-test URLs must use HTTPS, valid DNS or literal IP hosts, and optional ports 1–65535 without userinfo.",
    InvalidClientPrefix => "Client subnets must be RFC 1918 /16–/30 networks with a host gateway address.",
    ClientPrefixOverlap => "Client subnets must not overlap provider addresses, endpoints or probes.",
    EmptyUplinks => "A gateway must have at least one uplink.",
    EmptyProbeTargets => "Health checks must have at least one HTTPS probe target.",
    ExitHostPrefix => "Exit IPv4 addresses must use /32 host prefixes.",
    InvalidRouteProbe => "Route probes must use public unicast destinations outside local tunnel addresses.",
    DuplicatePublicKey => "A gateway identity and all of its peer public keys must be distinct.",
    InvalidKeepalive => "Keepalive must be 1–65535 seconds and allow 150 seconds before handshake stale.",
    InvalidHandshakeStale => "Handshake stale must be at least 150 seconds.",
    KeyLintFailed => "Internal conversion for the mandatory key lint failed.",
    EmptyDnsServers => "An exit must have at least one IPv4 DNS server.",
    EmptyDeviceGateways => "Devices must select at least one gateway.",
    DuplicateDeviceGateway => "A device must not repeat a gateway.",
}

pub(super) fn child(path: &str, name: &str) -> String {
    // Even a malicious map key or unknown field must not leak a pasted key.
    let safe = if types::contains_key(name) {
        "<redacted>"
    } else {
        name
    };
    if path.is_empty() {
        safe.to_owned()
    } else {
        format!("{path}.{safe}")
    }
}
