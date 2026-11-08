//! Staged health checks and independent, informational v1 status observations.

use std::{fmt, net::IpAddr};

use crate::{
    parse::{self, Handshake, HandshakeAge, RouteLookup, RouteType},
    rules::{IfName, V1Config},
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, System},
    verdict::{
        self, CheckError, HealthConfig, M1Observations, M1Topology, Next, Probe, ProbeError,
        Report, RulesetObs, Stage,
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
/// binding the device) as [`ProbeError::Io`]. [`run_check`] promotes these to
/// observation errors (code 1). Path failures use other errors, such as
/// [`ProbeError::Timeout`] or [`ProbeError::ExitStatus`], and yield code 3.
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
        && output
            .stderr
            .lines()
            .any(|line| line.trim() == "Unable to access interface: No such device")
}

fn successful(output: ExecOutput) -> Probe<ExecOutput> {
    if output.status == Some(0) {
        Ok(output)
    } else {
        Err(ProbeError::ExitStatus {
            code: output.status,
        })
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
                let result = probe.probe(cfg);
                if let Err(ProbeError::Io(message)) = result {
                    return Err(CheckError {
                        stage: Stage::ExitProbe,
                        source: ProbeError::io(&message),
                    });
                }
                observations.exit_probe = Some(result);
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
    /// True only when the observed ruleset is exact with no tc/config violations.
    pub kill_switch: Probe<bool>,
}

fn client_handshake(sys: &dyn System, cfg: &V1Config, now: u64) -> Probe<HandshakeStatus> {
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
        age: latest.age_at(now),
        peer_count: peers.len(),
    })
}

/// Collects every status field independently, without running an exit probe.
#[must_use]
pub fn run_status(sys: &dyn System, topo: &dyn TopologySource, cfg: &V1Config) -> StatusReport {
    let now = sys.now_unix_secs();
    StatusReport {
        client_iface: cfg.client_iface.clone(),
        exit_iface: cfg.exit_iface.clone(),
        client_handshake: client_handshake(sys, cfg, now),
        exit_handshake: exit_handshake(sys, cfg).map(|(handshake, peer_count)| HandshakeStatus {
            age: handshake.age_at(now),
            peer_count,
        }),
        client_route: observe_route(sys, cfg),
        kill_switch: topo.observe(sys, cfg).map(|topology| {
            topology.ruleset == RulesetObs::Exact
                && topology.tc_hooks.is_empty()
                && topology.config_mismatches.is_empty()
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
            Ok(true) => f.write_str("in place"),
            Ok(false) => f.write_str("MISSING"),
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
