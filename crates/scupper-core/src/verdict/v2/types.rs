//! Public observations and results for the staged namespace check.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use ipnet::IpNet;

use crate::{
    config::ExitId,
    parse::{Handshake, RouteLookup, UdpSocket},
    render::RouteTarget,
};

pub use super::super::v1::{Probe, ProbeError};

/// A forwarded client source address.
pub type ClientAddr = IpAddr;
/// A kernel lookup answer, including rejecting and unrecognized devices.
pub type RouteAnswer = RouteLookup;

/// Persisted operator selection, distinct from route intent and kernel state.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Selection {
    /// Use the configured candidate order.
    #[default]
    Auto,
    /// Prefer an exit, permitting fallback in a future multi-exit release.
    Prefer(ExitId),
    /// Use only this exit.
    Pin(ExitId),
    /// Require observed closure before reporting an administrative disconnect.
    Disconnected,
}

/// Full filesystem identity from a namespace handle or boot record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct NetnsIdentity {
    /// Filesystem device number (`st_dev`).
    pub device: u64,
    /// Namespace inode (`st_ino`).
    pub inode: u64,
}

/// Namespace identity observed against the boot record supplied to the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsObs {
    /// The namespace exists; the engine compares both identity components.
    Present {
        /// Observed filesystem device number.
        device: u64,
        /// Observed namespace inode.
        inode: u64,
    },
    /// No namespace exists at the owned name.
    Missing,
    /// The collector already established a different namespace identity.
    WrongInode,
}

/// A link inventory entry. Raw names retain foreign kernel interface names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkObs {
    /// Kernel interface name; loopback is permitted as the sole exception to T.
    pub name: String,
    /// Detailed kind; configured non-loopback links must be `wireguard`.
    pub kind: Option<String>,
    /// Administrative UP flag.
    pub up: bool,
    /// Assigned addresses with prefix lengths.
    pub addresses: Vec<IpNet>,
}

/// Public peer state, assembled from the public-only `WireGuard` parsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerObs {
    /// Decoded public key, never a private key.
    pub public_key: [u8; 32],
    /// Allowed prefixes; compared without relying on output order.
    pub allowed_ips: Vec<IpNet>,
    /// Numeric learned endpoint. Client roaming endpoints are informational.
    pub endpoint: Option<SocketAddr>,
}

/// Result of comparing canonical JSON rulesets, never rendered/live text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesetObs {
    /// Canonical semantic equality was verified.
    Exact,
    /// Required ruleset is absent.
    Missing,
    /// Canonical fingerprints differ.
    Differs {
        /// Live canonical fingerprint.
        live: [u8; 32],
        /// Expected canonical fingerprint.
        want: [u8; 32],
    },
}

impl From<super::super::v1::RulesetObs> for RulesetObs {
    fn from(value: super::super::v1::RulesetObs) -> Self {
        match value {
            super::super::v1::RulesetObs::Exact => Self::Exact,
            super::super::v1::RulesetObs::Missing => Self::Missing,
            super::super::v1::RulesetObs::Differs {
                live_sha256,
                want_sha256,
            } => Self::Differs {
                live: live_sha256,
                want: want_sha256,
            },
        }
    }
}

/// A namespace default route, including absence and nonstandard route types.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DefaultRouteObs {
    /// Default through a named link; raw names preserve foreign devices.
    Dev(String),
    /// Explicit rejecting default.
    Unreachable,
    /// No default route exists for this family.
    Missing,
    /// Another route type or an unrecognized lookup device.
    Other(RouteAnswer),
}

impl From<RouteAnswer> for DefaultRouteObs {
    fn from(answer: RouteAnswer) -> Self {
        match answer {
            RouteAnswer::Dev(name) => Self::Dev(name.as_str().to_owned()),
            RouteAnswer::Unreachable => Self::Unreachable,
            other => Self::Other(other),
        }
    }
}

/// Main-table inventory summarized by the collector, distinct from intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoutes {
    /// The observed IPv4 default, or explicit absence.
    pub v4: DefaultRouteObs,
    /// The single observed IPv6 default, even in IPv4-only M2.
    pub v6: DefaultRouteObs,
    /// Routes beyond the single default and expected kernel routes.
    /// The collector must include duplicate defaults and unexpected kernel routes.
    pub extra: Vec<DefaultRouteObs>,
}

/// Complete containment inventory, collected independently of default routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyObs {
    /// Namespace identity.
    pub netns: NetnsObs,
    /// Complete link inventory, optionally including loopback.
    pub links: Vec<LinkObs>,
    /// Complete public peer inventory per interface.
    pub peers: BTreeMap<String, Vec<PeerObs>>,
    /// Semantic whole-namespace ruleset comparison.
    pub ruleset: RulesetObs,
    /// RPDB entries differing from kernel defaults, including missing defaults.
    pub extra_rules: Vec<String>,
    /// Interfaces with traffic control beyond the baseline (including tcx/XDP).
    pub tc_hooks: Vec<String>,
}

/// Reason retained by the persisted quarantine latch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum RepairKind {
    /// Containment drift exhausted its repair budget.
    SafetyDrift,
}

/// Forwarding and the listening side of the client tunnel, observed together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarding {
    /// Exact IPv4 forwarding sysctl value; only 1 passes.
    pub v4: i64,
    /// Hardening keys whose observed values differ from desired values.
    pub hardening: Vec<String>,
    /// IPv6 forwarding value; not required in M2 (no IPv6 clients).
    pub v6: i64,
    /// Persisted quarantine latch, if set.
    pub quarantine: Option<RepairKind>,
    /// Client-facing interface public identity; None means unset.
    pub client_public_key: Option<[u8; 32]>,
    /// Client-facing interface listen port.
    pub listen_port: u16,
    /// Host UDP sockets, parsed without reading any credentials.
    pub host_sockets: Vec<UdpSocket>,
    /// Every configured client peer's handshake, including explicit Never.
    pub client_handshakes: BTreeMap<[u8; 32], Handshake>,
}

/// One client's forwarded lookup results for both address families.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteObs {
    /// IPv4 lookup with the client source and incoming client tunnel.
    pub v4: Probe<RouteAnswer>,
    /// IPv6 rejecting lookup with the incoming client tunnel.
    pub v6: Probe<RouteAnswer>,
}

/// Client listener disagreement; client reachability beyond the host is unproven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ClientFault {
    /// Client-facing link is administratively down.
    LinkDown,
    /// Client-facing public identity differs or is unset.
    PublicKey,
    /// `WireGuard` is listening on a different port.
    ListenPort,
    /// No host UDP socket is bound to the configured port.
    HostSocket,
}

/// Supervisor ping result; iteration age is a monotonic duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    /// Ping answered within its deadline.
    Alive {
        /// Age of the last complete loop iteration.
        iteration_age: Duration,
        /// Identity of the namespace held by the daemon.
        netns: NetnsIdentity,
    },
    /// Ping failed or the daemon is absent.
    Dead,
    /// Supervision was explicitly not requested.
    NotRequired,
}

/// Why a verified data path lacks required supervision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SupervisorFault {
    /// Supervisor did not answer.
    Dead,
    /// Last complete iteration is at least 30 seconds old.
    Stale,
    /// A caller skipped supervision despite `require_daemon`.
    NotRequired,
}

/// Independently supplied stages. None is unobserved, never success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observations {
    /// Containment inventory.
    pub topology: Option<Probe<TopologyObs>>,
    /// Independent per-family defaults and unexpected main-table routes.
    pub defaults: Option<Probe<DefaultRoutes>>,
    /// Persisted administrative selection.
    pub selection: Selection,
    /// Route intent; cannot substitute for observed defaults.
    pub active: RouteTarget,
    /// Exit handshake collection; missing configured entries are collection errors.
    pub handshakes: Option<Probe<BTreeMap<ExitId, Handshake>>>,
    /// Forwarding and client listener observations.
    pub forwarding: Option<Probe<Forwarding>>,
    /// Both families for every configured route source, answered in one stage.
    pub routes: Option<Vec<(ClientAddr, RouteObs)>>,
    /// IPv4 public address returned by the exit path probe.
    pub exit_probe: Option<Probe<IpAddr>>,
    /// Reserved for multi-exit checks; M2 never requests or evaluates it.
    pub standby_probe: Option<Probe<()>>,
    /// Reserved for the M4 forwarder; M2 never requests or evaluates it.
    pub dns: Option<Probe<()>>,
    /// Supervisor observation; required only when configured.
    pub supervisor: Option<Supervisor>,
}

impl Default for Observations {
    fn default() -> Self {
        Self {
            topology: None,
            defaults: None,
            selection: Selection::Auto,
            active: RouteTarget::Unreachable,
            handshakes: None,
            forwarding: None,
            routes: None,
            exit_probe: None,
            standby_probe: None,
            dns: None,
            supervisor: None,
        }
    }
}

/// Nonempty findings; an unprotected verdict always explains at least one fact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NonEmpty<T>(Vec<T>);
impl<T> NonEmpty<T> {
    /// Starts with one required finding.
    #[must_use]
    pub fn new(first: T) -> Self {
        Self(vec![first])
    }
    /// Adds a finding without permitting an empty collection.
    pub fn push(&mut self, value: T) {
        self.0.push(value);
    }
    /// Borrows findings in deterministic observation order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
    pub(super) fn from_vec(values: Vec<T>) -> Option<Self> {
        if values.is_empty() {
            None
        } else {
            Some(Self(values))
        }
    }
}

/// Observed containment violations, all collected before availability decisions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Violation {
    /// Owned namespace does not exist.
    NetnsMissing,
    /// Namespace identity differs from the expected boot record inode.
    NetnsWrongInode,
    /// Link set differs: unexpected, missing, or duplicate name.
    ForeignLink(String),
    /// A non-loopback link is not `WireGuard`.
    LinkKind(String),
    /// Public peer keys or `AllowedIPs` differ, including missing peers.
    PeerDiffers {
        /// Interface whose peers differ.
        ifname: String,
    },
    /// Required namespace ruleset is absent.
    RulesetMissing,
    /// Canonical semantic rulesets differ.
    RulesetDiffers {
        /// Live fingerprint.
        live: [u8; 32],
        /// Expected fingerprint.
        want: [u8; 32],
    },
    /// RPDB differs from kernel defaults.
    ExtraPolicyRule(String),
    /// Unexpected traffic-control or BPF hook.
    TrafficControlHook(String),
    /// Exit probe returned a host uplink address.
    ExitIpIsUplinkAddress(IpAddr),
    /// Assigned tunnel addresses disagree with validated config.
    ConfigMismatch(String),
}

/// Availability failures after containment passed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Degraded {
    /// Reserved for M2k multi-exit failover; unreachable in this engine.
    FailoverStuck {
        /// Stale active exit.
        exit: ExitId,
        /// Available standby candidates.
        fresh_standbys: Vec<ExitId>,
    },
    /// Quarantine is latched but IPv4 forwarding is not zero.
    QuarantineNotEffective,
    /// Required IPv4 forwarding is not exactly 1.
    ForwardingDisabled,
    /// Observed default or client lookup disagrees with required routing.
    RouteWrong {
        /// Source being checked (gateway source for defaults).
        client: ClientAddr,
        /// Observed answer.
        got: DefaultRouteObs,
        /// Required target.
        want: RouteTarget,
    },
    /// Administrative disconnect has not closed the kernel path.
    DisconnectNotEffective,
    /// The gateway's client listener is broken.
    ClientSideBroken(ClientFault),
    /// Probe ran but the exit path failed.
    ExitProbeFailed(ProbeError),
    /// Probe returned an implausible public IPv4 exit address.
    ExitProbeImplausible {
        /// Original observed address.
        ip: IpAddr,
    },
    /// Reserved for multi-exit comparison; no switch on probe failure in M2.
    CommonModeProbeFailure,
    /// Reserved for the M4 DNS forwarder.
    DnsFailed(ProbeError),
}

/// Contained but deliberately or necessarily unavailable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum FailClosed {
    /// Kernel closure verified for administrative disconnect.
    AdminDisconnected,
    /// Both defaults unreachable or the sole exit handshake is stale/never.
    NoHealthyExit,
    /// Pinned selection with observed unreachable defaults.
    PinnedExitDown(ExitId),
    /// Reserved for M2k multi-exit failover; unreachable in this engine.
    FailoverPending {
        /// Previous active exit.
        from: ExitId,
    },
    /// Persisted quarantine and observed forwarding 0.
    Quarantined {
        /// Persisted latch reason.
        reason: RepairKind,
    },
}

/// Caveats; M2 emits clock skew, stale clients and optional daemon death.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Warning {
    /// Reserved for standby checks.
    StandbyUnhealthy(ExitId),
    /// A future handshake timestamp, including beyond the freshness tolerance.
    ClockSkew,
    /// Reserved for installer hardening observations.
    KeyFileMode(PathBuf),
    /// Namespace hardening key differs from its desired value.
    HardeningSysctl(String),
    /// Reserved for host forwarding diagnostics.
    HostForwardingOn,
    /// Reserved for installer unit diagnostics.
    LegacyUnitEnabled(String),
    /// A persisted quarantine latch suppresses repairs.
    RepairSuppressed(RepairKind),
    /// Supervisor is dead but supervision was optional.
    DaemonDead,
    /// Optional supervisor answered but its last iteration is stale.
    DaemonStale,
    /// At least one configured client has a stale or never handshake.
    ClientHandshakesStale,
}

/// Observation stage, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Stage {
    /// Namespace containment inventory.
    Topology,
    /// Default-route inventory and persisted selection consistency.
    Defaults,
    /// Exit handshake freshness.
    Handshakes,
    /// Forwarding and client listener.
    Forwarding,
    /// Forwarded-client route lookups.
    Routes,
    /// Exit public address probe.
    ExitProbe,
    /// Reserved for standby probing.
    StandbyProbe,
    /// Reserved for M4 DNS checks.
    Dns,
    /// Supervisor ping.
    Supervisor,
}

/// Required observation failed; this can never assert a safe outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, serde::Serialize)]
#[error("{stage:?} observation failed: {source}")]
pub struct CheckError {
    /// Failed stage.
    pub stage: Stage,
    /// Bounded diagnostic.
    pub source: ProbeError,
}
impl CheckError {
    /// Observation errors always use process code 1.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        1
    }
}

/// Namespace health outcome. Code 5 requires the same data-path proof as 0.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Verdict {
    /// All applicable M2 stages verified.
    Protected {
        /// Verified active exit.
        exit: ExitId,
        /// Verified public IPv4 address.
        exit_ip: IpAddr,
    },
    /// At least one known containment violation.
    Unprotected(NonEmpty<Violation>),
    /// Availability or route failure.
    Degraded(Degraded),
    /// Verified closure or unavailable tunnel.
    FailClosed(FailClosed),
    /// Verified data path with failed required supervision.
    Unsupervised {
        /// Verified active exit.
        exit: ExitId,
        /// Verified public address.
        exit_ip: IpAddr,
        /// Supervisor failure.
        why: SupervisorFault,
    },
}
impl Verdict {
    /// Stable process codes from DESIGN §12.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Protected { .. } => 0,
            Self::Unprotected(_) => 2,
            Self::Degraded(_) => 3,
            Self::FailClosed(_) => 4,
            Self::Unsupervised { .. } => 5,
        }
    }
}

/// Completed health report with caller-supplied time and applied config version.
/// Each stage is verified at its observation time; this is not an atomic snapshot.
/// JSON serialization includes the stable top-level `schema: 1` discriminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Completed verdict.
    pub verdict: Verdict,
    /// Visible caveats from stages evaluated.
    pub warnings: Vec<Warning>,
    /// Supplied Unix timestamp; the engine reads no clock.
    pub at: u64,
    /// Applied configuration version supplied to the health config constructor.
    pub config_version: u64,
}

/// Next required stage, or a decisive report/error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Collect containment first.
    Topology,
    /// Collect defaults independently of containment.
    Defaults,
    /// Collect active exit handshakes.
    Handshakes,
    /// Collect forwarding and the client listener.
    Forwarding,
    /// Collect all client IPv4 and the IPv6 rejecting lookup.
    Routes,
    /// Run the exit path probe after route verification.
    ExitProbe,
    /// Reserved; never requested in single-exit M2.
    StandbyProbe,
    /// Reserved; never requested before M4.
    Dns,
    /// Ping the supervisor only if required.
    Supervisor,
    /// Completed report or observation failure.
    Done(Result<Report, CheckError>),
}

impl serde::Serialize for Report {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut report = serializer.serialize_struct("Report", 5)?;
        report.serialize_field("schema", &1_u32)?;
        report.serialize_field("verdict", &self.verdict)?;
        report.serialize_field("warnings", &self.warnings)?;
        report.serialize_field("at", &self.at)?;
        report.serialize_field("config_version", &self.config_version)?;
        report.end()
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protected { exit, exit_ip } => write!(f, "protected: {exit} ({exit_ip})"),
            Self::Unprotected(violations) => write!(f, "UNPROTECTED: {:?}", violations.as_slice()),
            Self::Degraded(reason) => write!(f, "degraded: {reason:?}"),
            Self::FailClosed(reason) => write!(f, "fail closed: {reason:?}"),
            Self::Unsupervised { exit, exit_ip, why } => {
                write!(f, "unsupervised: {exit} ({exit_ip}): {why:?}")
            }
        }
    }
}
