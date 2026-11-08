//! Pure, staged M1 health decisions: containment precedes tunnel availability,
//! routing precedes the bound exit probe, and every stage must pass for code 0.
//!
//! M1 cannot compare the observed handshake peer key with a configured exit key:
//! [`V1Config`] has no exit peer key. Callers must supply the exit interface's
//! single-peer handshake, rather than a handshake from an unrelated interface.

use std::{fmt, net::IpAddr, time::Duration};

use thiserror::Error;

use crate::{
    parse::{Handshake, HandshakeAge, ParseError, RouteLookup, RouteType},
    rules::{IfName, V1Config},
};

/// A completed observation, distinguished from a stage not yet requested.
pub type Probe<T> = Result<T, ProbeError>;

/// A failed observation; it never establishes that a stage passed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProbeError {
    /// The observation did not complete within its deadline.
    #[error("probe timed out")]
    Timeout,
    /// The observation command failed before producing usable output.
    #[error("probe exited unsuccessfully (code {code:?})")]
    ExitStatus {
        /// Exit code, or `None` when terminated without a code.
        code: Option<i32>,
    },
    /// Output could not be interpreted as a trustworthy observation.
    #[error("{0}")]
    Parse(#[from] ParseError),
    /// I/O failed; use [`Self::io`] to bound stored text to 200 characters.
    ///
    /// Directly constructed values are bounded when reported by [`next`],
    /// and their display is always bounded, including multibyte characters.
    #[error("I/O error: {}", bounded_io(.0))]
    Io(String),
}

fn bounded_io(message: &str) -> String {
    message.chars().take(200).collect()
}

impl ProbeError {
    /// Bounds an I/O diagnostic before retaining it in an observation.
    #[must_use]
    pub fn io(message: &str) -> Self {
        Self::Io(bounded_io(message))
    }

    fn bounded(&self) -> Self {
        match self {
            Self::Io(message) => Self::io(message),
            other => other.clone(),
        }
    }
}

/// Whole-host ruleset comparison, checked before availability probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesetObs {
    /// Every expected rule was observed with no unexpected rules.
    Exact,
    /// The required ruleset is absent.
    Missing,
    /// Canonical live and expected rulesets differ.
    Differs {
        /// Fingerprint of the observed ruleset.
        live_sha256: [u8; 32],
        /// Fingerprint of the required ruleset.
        want_sha256: [u8; 32],
    },
}

/// A configuration/kernel disagreement that invalidates containment claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigMismatch {
    /// The configured uplink is not the host default route's device.
    UplinkNotDefaultRouteDev,
    /// The exit address is not assigned to the exit interface.
    ExitAddrNotOnExitIface,
    /// The client address is outside the client peer's allowed IPs.
    ClientAddrNotInPeerAllowedIps,
    /// A configured interface does not exist.
    InterfaceMissing(IfName),
}

/// Containment observations collected together before any availability stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M1Topology {
    /// Exactness of the complete host ruleset.
    pub ruleset: RulesetObs,
    /// Interfaces with traffic-control hooks beyond the permitted baseline.
    pub tc_hooks: Vec<IfName>,
    /// All observed configuration/kernel disagreements.
    pub config_mismatches: Vec<ConfigMismatch>,
    /// Host uplink addresses that must never be reported as protected exits.
    pub uplink_addrs: Vec<IpAddr>,
}

/// Independently supplied stages; `None` means not yet observed, never passed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct M1Observations {
    /// First stage: establish containment before testing availability.
    pub topology: Option<Probe<M1Topology>>,
    /// Second stage: the exit interface's single-peer handshake.
    pub handshake: Option<Probe<Handshake>>,
    /// Third stage: the route selected for forwarded client traffic.
    pub route: Option<Probe<RouteLookup>>,
    /// Fourth stage: public IP returned by the bound HTTPS exit probe.
    pub exit_probe: Option<Probe<IpAddr>>,
}

/// Expected exit and time bounds, supplied without reading a clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthConfig {
    /// Required output interface for forwarded client traffic.
    pub exit_iface: IfName,
    /// Inclusive handshake age limit (180 seconds by default).
    pub max_handshake_age: Duration,
    /// Inclusive future timestamp tolerance (5 seconds by default).
    pub max_clock_skew: Duration,
}

impl From<&V1Config> for HealthConfig {
    fn from(config: &V1Config) -> Self {
        Self {
            exit_iface: config.exit_iface.clone(),
            max_handshake_age: Duration::from_secs(180),
            max_clock_skew: Duration::from_secs(5),
        }
    }
}

/// A stage named in an observation error, in safety-preserving execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Whole-host containment and configuration cross-check.
    Topology,
    /// Exit tunnel handshake freshness.
    Handshake,
    /// Forwarded-client route selection.
    Route,
    /// Bound HTTPS exit address observation.
    ExitProbe,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Topology => "topology",
            Self::Handshake => "handshake",
            Self::Route => "route",
            Self::ExitProbe => "exit probe",
        })
    }
}

/// Failure to observe a required stage; no safe verdict may replace this error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{stage} observation failed: {source}")]
pub struct CheckError {
    /// Earliest required stage whose observation failed.
    pub stage: Stage,
    /// Bounded diagnostic explaining why no trustworthy observation exists.
    pub source: ProbeError,
}

impl CheckError {
    /// Observation errors always use code 1, never a safe health code.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        1
    }
}

/// A containment violation, taking precedence over later availability failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The required host ruleset is absent.
    RulesetMissing,
    /// Whole-host canonical rulesets differ.
    RulesetDiffers {
        /// Observed fingerprint, retained for diagnosis.
        live_sha256: [u8; 32],
        /// Required fingerprint, retained for diagnosis.
        want_sha256: [u8; 32],
    },
    /// An interface has an unexpected traffic-control hook.
    TrafficControlHook(IfName),
    /// The bound probe returned a host uplink address.
    ExitIpIsUplinkAddress(IpAddr),
    /// Configuration disagrees with the observed kernel state.
    ConfigMismatch(ConfigMismatch),
}

/// A nonempty collection, preventing an unexplained unprotected verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violations(Vec<Violation>);

impl Violations {
    /// Starts a collection with a required, observed violation.
    #[must_use]
    pub fn new(first: Violation) -> Self {
        Self(vec![first])
    }

    /// Borrows all violations in deterministic observation order.
    #[must_use]
    pub fn as_slice(&self) -> &[Violation] {
        &self.0
    }
}

/// Availability failure after all preceding containment checks passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Degraded {
    /// Forwarded traffic would not use the expected exit, despite a fresh tunnel.
    RouteWrong {
        /// Actual forwarded-client route, including non-device route types.
        got: RouteLookup,
        /// Required exit device, retained for a useful human diagnostic.
        want: IfName,
    },
    /// The final bound exit probe failed after routing passed.
    ExitProbeFailed(ProbeError),
}

/// A contained but unavailable tunnel, established before route/probe work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClosed {
    /// The exit handshake is absent, stale, or beyond the clock-skew bound.
    NoHealthyExit,
}

/// An observation caveat that must not silently weaken a freshness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// A future handshake was observed, whether tolerated or rejected as stale.
    ClockSkew,
}

/// M1 health outcome; only all four observed, passing stages yield code 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Containment, freshness, routing and the exit address all passed.
    Protected {
        /// Public exit address, distinct from every observed uplink address.
        exit_ip: IpAddr,
    },
    /// One or more observed containment violations.
    Unprotected(Violations),
    /// Containment passed but the path is unavailable or wrongly routed.
    Degraded(Degraded),
    /// Containment passed but no fresh exit handshake was observed.
    FailClosed(FailClosed),
}

impl Verdict {
    /// Maps M1 health outcomes to stable process exit codes.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Protected { .. } => 0,
            Self::Unprotected(_) => 2,
            Self::Degraded(_) => 3,
            Self::FailClosed(_) => 4,
        }
    }
}

/// Completed health decision with caveats from the stages actually reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The earliest decisive outcome in safety-preserving stage order.
    pub verdict: Verdict,
    /// Warnings collected only from stages evaluated for this decision.
    pub warnings: Vec<Warning>,
}

/// Next required observation, or the earliest decisive completed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Observe topology first, before any availability work.
    Topology,
    /// Observe freshness only after containment passed.
    Handshake,
    /// Observe forwarded-client routing only after freshness passed.
    Route,
    /// Run the costly bound probe only after routing passed.
    ExitProbe,
    /// A verdict or required-observation error; later observations are ignored.
    Done(Result<Report, CheckError>),
}

fn failed(stage: Stage, source: &ProbeError) -> Next {
    Next::Done(Err(CheckError {
        stage,
        source: source.bounded(),
    }))
}

fn done(verdict: Verdict, warnings: Vec<Warning>) -> Next {
    Next::Done(Ok(Report { verdict, warnings }))
}

fn topology_violations(topology: &M1Topology) -> Option<Violations> {
    let mut violations = match topology.ruleset {
        RulesetObs::Exact => Vec::new(),
        RulesetObs::Missing => vec![Violation::RulesetMissing],
        RulesetObs::Differs {
            live_sha256,
            want_sha256,
        } => {
            vec![Violation::RulesetDiffers {
                live_sha256,
                want_sha256,
            }]
        }
    };
    violations.extend(
        topology
            .tc_hooks
            .iter()
            .cloned()
            .map(Violation::TrafficControlHook),
    );
    violations.extend(
        topology
            .config_mismatches
            .iter()
            .cloned()
            .map(Violation::ConfigMismatch),
    );
    if violations.is_empty() {
        None
    } else {
        Some(Violations(violations))
    }
}

/// Advances topology → handshake → route → exit probe, without I/O or a clock.
///
/// Stops at the first missing or failed stage and ignores all later observations.
/// Topology, handshake and route observation errors return code 1; the final
/// bound-probe error is an availability failure (`ExitProbeFailed`, code 3).
/// Topology violations are collected before consulting later errors, so a known
/// unsafe configuration cannot be hidden by an availability or probe failure.
/// A future timestamp warns in all cases and is fresh only within the configured
/// skew bound; it cannot make a far-future peer appear healthy.
#[must_use]
pub fn next(obs: &M1Observations, cfg: &HealthConfig, now_unix_secs: u64) -> Next {
    let topology = match &obs.topology {
        None => return Next::Topology,
        Some(Err(source)) => return failed(Stage::Topology, source),
        Some(Ok(topology)) => topology,
    };
    if let Some(violations) = topology_violations(topology) {
        return done(Verdict::Unprotected(violations), Vec::new());
    }
    let handshake = match &obs.handshake {
        None => return Next::Handshake,
        Some(Err(source)) => return failed(Stage::Handshake, source),
        Some(Ok(handshake)) => handshake,
    };
    let mut warnings = Vec::new();
    let fresh = match handshake.age_at(now_unix_secs) {
        HandshakeAge::Never => false,
        HandshakeAge::Age(age) => age <= cfg.max_handshake_age,
        HandshakeAge::InFuture(skew) => {
            warnings.push(Warning::ClockSkew);
            skew <= cfg.max_clock_skew
        }
    };
    if !fresh {
        return done(Verdict::FailClosed(FailClosed::NoHealthyExit), warnings);
    }
    let route = match &obs.route {
        None => return Next::Route,
        Some(Err(source)) => return failed(Stage::Route, source),
        Some(Ok(route)) => route,
    };
    if !matches!(route, RouteLookup::Dev(name) if name == &cfg.exit_iface) {
        return done(
            Verdict::Degraded(Degraded::RouteWrong {
                got: route.clone(),
                want: cfg.exit_iface.clone(),
            }),
            warnings,
        );
    }
    match &obs.exit_probe {
        None => Next::ExitProbe,
        Some(Err(source)) => done(
            Verdict::Degraded(Degraded::ExitProbeFailed(source.bounded())),
            warnings,
        ),
        Some(Ok(ip)) if topology.uplink_addrs.contains(ip) => done(
            Verdict::Unprotected(Violations::new(Violation::ExitIpIsUplinkAddress(*ip))),
            warnings,
        ),
        Some(Ok(ip)) => done(Verdict::Protected { exit_ip: *ip }, warnings),
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protected { exit_ip } => {
                write!(f, "connected through {exit_ip}, kill switch in place")
            }
            Self::FailClosed(FailClosed::NoHealthyExit) => {
                f.write_str("exit tunnel is down, traffic is blocked (fail closed)")
            }
            Self::Degraded(Degraded::ExitProbeFailed(_)) => {
                f.write_str("exit probe failed, exit connectivity could not be verified")
            }
            Self::Degraded(Degraded::RouteWrong { got, want }) => {
                f.write_str("client route uses ")?;
                display_route(got, f)?;
                write!(f, ", expected {want}; traffic is blocked")
            }
            Self::Unprotected(violations) => {
                f.write_str("unprotected: ")?;
                for (index, violation) in violations.as_slice().iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    display_violation(violation, f)?;
                }
                Ok(())
            }
        }
    }
}

fn display_route(route: &RouteLookup, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match route {
        RouteLookup::Dev(name) => write!(f, "{name}"),
        RouteLookup::OtherDev => f.write_str("an unrecognized device"),
        RouteLookup::OtherType(kind) => f.write_str(match kind {
            RouteType::Broadcast => "broadcast",
            RouteType::Anycast => "anycast",
            RouteType::Multicast => "multicast",
            RouteType::Nat => "nat",
            RouteType::Xresolve => "xresolve",
        }),
        RouteLookup::Local => f.write_str("local"),
        RouteLookup::Unreachable => f.write_str("unreachable"),
        RouteLookup::Blackhole => f.write_str("blackhole"),
        RouteLookup::Prohibit => f.write_str("prohibit"),
        RouteLookup::Throw => f.write_str("throw"),
    }
}

fn display_violation(violation: &Violation, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match violation {
        Violation::RulesetMissing => f.write_str("ruleset missing"),
        Violation::RulesetDiffers { .. } => f.write_str("ruleset differs from policy"),
        Violation::TrafficControlHook(name) => {
            write!(f, "unexpected traffic-control hook on {name}")
        }
        Violation::ExitIpIsUplinkAddress(ip) => write!(f, "exit IP {ip} is an uplink address"),
        Violation::ConfigMismatch(mismatch) => match mismatch {
            ConfigMismatch::UplinkNotDefaultRouteDev => {
                f.write_str("configured uplink is not the default-route device")
            }
            ConfigMismatch::ExitAddrNotOnExitIface => {
                f.write_str("exit address is not on the exit interface")
            }
            ConfigMismatch::ClientAddrNotInPeerAllowedIps => {
                f.write_str("client address is not in peer AllowedIPs")
            }
            ConfigMismatch::InterfaceMissing(name) => {
                write!(f, "configured interface {name} is missing")
            }
        },
    }
}
