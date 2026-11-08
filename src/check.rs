//! Staged health checks and independent, informational v1 status observations.

use std::{fmt, net::IpAddr};

use crate::{
    parse::{self, Handshake, HandshakeAge, RouteLookup, RouteType},
    rules::{IfName, V1Config},
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, System},
    verdict::{
        self, CheckError, ExitLink, HealthConfig, M1Observations, M1Topology, Next, Probe,
        ProbeError, Report, RulesetObs, Stage, Violations,
    },
};

/// Containment collector implemented separately from these command drivers.
pub trait TopologySource {
    /// Observes whole-host rules, tc, configuration agreement and uplink addresses.
    ///
    /// # Errors
    ///
    /// Returns an observation error when containment cannot be inspected.
    fn observe(&self, sys: &dyn System, cfg: &V1Config) -> Probe<M1Topology>;
}

/// Bound exit-path observation, implemented in the next milestone step.
///
/// Implementations must report local setup failures (permission, socket creation,
/// binding the device) as [`ProbeError::Setup`] (code 1). Every other error,
/// including [`ProbeError::Io`], is a path failure (code 3).
/// The setup/path distinction must be preserved when implementing this probe.
pub trait ExitProbe {
    /// Observes the external address through the configured exit interface.
    ///
    /// # Errors
    ///
    /// Returns a local setup error or path failure as described by [`ExitProbe`].
    fn probe(&self, cfg: &V1Config) -> Probe<IpAddr>;
}

fn exec_error(error: ExecError) -> ProbeError {
    match error {
        ExecError::Timeout { .. } => ProbeError::Timeout,
        other => ProbeError::io(&other.to_string()),
    }
}

fn wg_output(sys: &dyn System, iface: &IfName) -> Probe<ExecOutput> {
    sys.run(
        Program::Wg,
        &[
            "show".into(),
            iface.as_str().into(),
            "latest-handshakes".into(),
        ],
        EXEC_TIMEOUT,
    )
    .map_err(exec_error)
}

fn missing_device(output: &ExecOutput) -> bool {
    output.status.is_some_and(|code| code != 0)
        && output.stderr.trim() == "Unable to access interface: No such device"
}

fn successful(output: ExecOutput) -> Probe<ExecOutput> {
    if output.status == Some(0) {
        Ok(output)
    } else {
        Err(ProbeError::exit_status(output.status, &output.stderr))
    }
}

/// Observes the exit tunnel's single-peer handshake with the exec deadline.
///
/// A missing interface is `Never` (v1's fail-closed code 4); other unsuccessful
/// commands are observation errors. M1 does not compare the peer key with a
/// configured exit key, since [`V1Config`] does not contain one.
///
/// # Errors
///
/// Returns execution, exit-status or single-peer parsing errors.
pub fn observe_handshake(sys: &dyn System, cfg: &V1Config) -> Probe<Handshake> {
    exit_handshake(sys, cfg).map(|(handshake, _)| handshake)
}

// Query just the verdict engine's handshake stage. These synthetic topology
// inputs let that stage run; they are never reported as containment observations.
// Leave the route unobserved: requesting it means freshness passed.
pub(crate) fn handshake_is_fresh(handshake: Handshake, cfg: &HealthConfig, now: u64) -> bool {
    let observations = M1Observations {
        topology: Some(Ok(M1Topology {
            exit_link: ExitLink::Up,
            ruleset: RulesetObs::Exact,
            tc_hooks: Vec::new(),
            legacy_tables: Vec::new(),
            config_mismatches: Vec::new(),
            uplink_addrs: vec![cfg.exit_addr.into()],
        })),
        handshake: Some(Ok(handshake)),
        ..M1Observations::default()
    };
    matches!(verdict::next(&observations, cfg, now), Next::Route)
}

fn exit_handshake(sys: &dyn System, cfg: &V1Config) -> Probe<(Handshake, usize)> {
    let output = wg_output(sys, &cfg.exit_iface)?;
    if missing_device(&output) {
        return Ok((Handshake::Never, 0));
    }
    let output = successful(output)?;
    Ok((parse::single_peer_handshake(&output.stdout)?, 1))
}

/// Looks up the forwarded-client route, never parsing failed command output.
///
/// # Errors
///
/// Returns execution, exit-status (including RTNETLINK failures), or parse errors.
pub fn observe_route(sys: &dyn System, cfg: &V1Config) -> Probe<RouteLookup> {
    let output = successful(
        sys.run(Program::Ip, &parse::route_probe_argv(cfg), EXEC_TIMEOUT)
            .map_err(exec_error)?,
    )?;
    Ok(parse::parse_route_get(&output.stdout)?)
}

fn internal_error(stage: Stage) -> CheckError {
    CheckError {
        stage,
        source: ProbeError::io("internal error: repeated or excessive observation request"),
    }
}

/// Drives the pure verdict engine with at most four collection iterations.
///
/// No stage runs until requested, and each stage runs at most once. Exit-probe
/// local setup failures follow the [`ExitProbe`] contract and return code 1.
///
/// # Errors
///
/// Returns a required-observation error or a bounded internal protocol error.
pub fn run_check(
    sys: &dyn System,
    topo: &dyn TopologySource,
    probe: &dyn ExitProbe,
    cfg: &V1Config,
) -> Result<Report, CheckError> {
    let mut observations = M1Observations::default();
    let health = HealthConfig::from(cfg);
    for _ in 0..4 {
        match verdict::next(&observations, &health, sys.now_unix_secs()) {
            Next::Done(result) => return result,
            Next::Topology if observations.topology.is_none() => {
                observations.topology = Some(topo.observe(sys, cfg));
            }
            Next::Handshake if observations.handshake.is_none() => {
                observations.handshake = Some(observe_handshake(sys, cfg));
            }
            Next::Route if observations.route.is_none() => {
                observations.route = Some(observe_route(sys, cfg));
            }
            Next::ExitProbe if observations.exit_probe.is_none() => {
                observations.exit_probe = Some(probe.probe(cfg));
            }
            request => return Err(internal_error(request_stage(&request))),
        }
    }
    match verdict::next(&observations, &health, sys.now_unix_secs()) {
        Next::Done(result) => result,
        request => Err(internal_error(request_stage(&request))),
    }
}

fn request_stage(request: &Next) -> Stage {
    match request {
        Next::Topology | Next::Done(_) => Stage::Topology,
        Next::Handshake => Stage::Handshake,
        Next::Route => Stage::Route,
        Next::ExitProbe => Stage::ExitProbe,
    }
}

/// Most recent handshake age among the observed peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeStatus {
    /// Age of the most recent nonzero timestamp, or `Never` for no handshake.
    pub age: HandshakeAge,
    /// Total number of peers, including peers that never handshook.
    pub peer_count: usize,
}

/// Whether containment was verified, absent, or invalidated by violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillSwitchStatus {
    /// Exact ruleset, no unexpected tc hooks, and no config mismatches.
    InPlace,
    /// The required ruleset is absent.
    Missing,
    /// Containment cannot be claimed because of these violations.
    NotVerified(Violations),
}

/// Informational observations; each field retains its own success or error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// Configured client interface, used as the display label.
    pub client_iface: IfName,
    /// Configured exit interface, also the expected route device.
    pub exit_iface: IfName,
    /// Most recent client handshake across all peers.
    pub client_handshake: Probe<HandshakeStatus>,
    /// Single exit peer's handshake age.
    pub exit_handshake: Probe<HandshakeStatus>,
    /// Forwarded-client route.
    pub client_route: Probe<RouteLookup>,
    /// Containment status, retaining violations and observation errors.
    pub kill_switch: Probe<KillSwitchStatus>,
}

fn client_handshake(sys: &dyn System, cfg: &V1Config) -> Probe<HandshakeStatus> {
    let output = wg_output(sys, &cfg.client_iface)?;
    if missing_device(&output) {
        return Ok(HandshakeStatus {
            age: HandshakeAge::Never,
            peer_count: 0,
        });
    }
    let peers = parse::parse_latest_handshakes(&successful(output)?.stdout)?;
    let latest = peers
        .iter()
        .filter_map(|peer| match peer.handshake {
            Handshake::Never => None,
            Handshake::At { unix_secs } => Some(unix_secs),
        })
        .max()
        .map_or(Handshake::Never, |unix_secs| Handshake::At { unix_secs });
    Ok(HandshakeStatus {
        age: latest.age_at(sys.now_unix_secs()),
        peer_count: peers.len(),
    })
}

/// Collects every status field independently, without running an exit probe.
#[must_use]
pub fn run_status(sys: &dyn System, topo: &dyn TopologySource, cfg: &V1Config) -> StatusReport {
    StatusReport {
        client_iface: cfg.client_iface.clone(),
        exit_iface: cfg.exit_iface.clone(),
        client_handshake: client_handshake(sys, cfg),
        exit_handshake: exit_handshake(sys, cfg).map(|(handshake, peer_count)| HandshakeStatus {
            age: handshake.age_at(sys.now_unix_secs()),
            peer_count,
        }),
        client_route: observe_route(sys, cfg),
        kill_switch: topo.observe(sys, cfg).map(|topology| {
            if topology.ruleset == RulesetObs::Missing {
                KillSwitchStatus::Missing
            } else if let Some(violations) = verdict::topology_violations(&topology) {
                KillSwitchStatus::NotVerified(violations)
            } else {
                KillSwitchStatus::InPlace
            }
        }),
    }
}

fn display_handshake(result: &Probe<HandshakeStatus>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let status = match result {
        Ok(status) => status,
        Err(error) => return write!(f, "unknown ({error})"),
    };
    match status.age {
        HandshakeAge::Never => {
            f.write_str("no handshake (interface down or peer never connected)")?;
        }
        HandshakeAge::Age(age) => write!(f, "last handshake {}s ago", age.as_secs())?,
        HandshakeAge::InFuture(skew) => write!(
            f,
            "timestamp {}s in the future (clock skew?)",
            skew.as_secs()
        )?,
    }
    if status.peer_count > 1 {
        write!(f, " ({} peers)", status.peer_count)?;
    }
    Ok(())
}

impl fmt::Display for StatusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Align the values even when configured interface names differ in length.
        let client = format!("client {}:", self.client_iface);
        let exit = format!("exit   {}:", self.exit_iface);
        let width = 15.max(client.len() + 1).max(exit.len() + 1);
        write!(f, "{client:<width$}")?;
        display_handshake(&self.client_handshake, f)?;
        write!(f, "\n{exit:<width$}")?;
        display_handshake(&self.exit_handshake, f)?;
        write!(f, "\n{:<width$}", "client route:")?;
        match &self.client_route {
            Err(error) => write!(f, "unknown ({error})")?,
            Ok(RouteLookup::Dev(name)) if name == &self.exit_iface => write!(f, "via {name}")?,
            Ok(RouteLookup::Dev(name)) => write!(
                f,
                "via {name}, NOT {} (clients are blocked)",
                self.exit_iface
            )?,
            Ok(route) => write!(
                f,
                "{}, NOT via {} (clients are blocked)",
                route_description(route),
                self.exit_iface
            )?,
        }
        write!(f, "\n{:<width$}", "kill switch:")?;
        match &self.kill_switch {
            Ok(KillSwitchStatus::InPlace) => f.write_str("in place"),
            Ok(KillSwitchStatus::Missing) => f.write_str("MISSING"),
            Ok(KillSwitchStatus::NotVerified(violations)) => {
                f.write_str("NOT VERIFIED: ")?;
                for (index, violation) in violations.as_slice().iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    verdict::display_violation(violation, f)?;
                }
                Ok(())
            }
            Err(error) => write!(f, "unknown ({error})"),
        }
    }
}

fn route_description(route: &RouteLookup) -> &'static str {
    match route {
        RouteLookup::Dev(_) => "via device",
        RouteLookup::OtherDev => "via an unrecognized device",
        RouteLookup::Unreachable => "unreachable",
        RouteLookup::Blackhole => "blackhole",
        RouteLookup::Prohibit => "prohibit",
        RouteLookup::Throw => "throw",
        RouteLookup::Local => "local",
        RouteLookup::OtherType(kind) => match kind {
            RouteType::Broadcast => "broadcast",
            RouteType::Anycast => "anycast",
            RouteType::Multicast => "multicast",
            RouteType::Nat => "nat",
            RouteType::Xresolve => "xresolve",
        },
    }
}
