//! Bounded M2 driver. Only the pure verdict engine chooses the next observation.

use crate::{
    canon::command_result,
    cmd::{IpCmd, KernelCmd, run_cmd},
    collect,
    netns::NetnsHandle,
    probe_child::ProbeExec,
    system::{EXEC_TIMEOUT, ExecTarget, System},
};
use scupper_core::{
    config::{GatewayId, ValidatedSite},
    parse::parse_ip_addr,
    render::{RouteTarget, VersionStamp},
    verdict::v2::{
        self, CheckError, HealthConfigV2, NetnsObs, Next, Observations, Probe, ProbeError, Report,
        RulesetObs, Selection, Stage, TopologyObs,
    },
};
use std::{collections::BTreeMap, path::Path};

/// I/O boundaries and pinned gateway identity for a single check.
pub struct Dependencies<'a> {
    /// Kernel commands and clock; host reads always use the original namespace.
    pub system: &'a dyn System,
    /// Isolated HTTPS child execution.
    pub probe_exec: &'a dyn ProbeExec,
    /// Held namespace, or None when the owned name is missing.
    pub handle: Option<&'a NetnsHandle>,
    /// Persistent boot and safety-state root (production /var/lib/scupper).
    pub state_root: &'a Path,
}

/// Applied immutable site and version, never a mirror or pending candidate.
pub struct Config<'a> {
    /// Validated head configuration.
    pub site: &'a ValidatedSite,
    /// Local gateway ID.
    pub gateway: &'a GatewayId,
    /// Head version and exact source digest.
    pub stamp: VersionStamp,
}

fn error(stage: Stage, source: ProbeError) -> CheckError {
    CheckError { stage, source }
}

fn health(deps: &Dependencies<'_>, cfg: &Config<'_>) -> Probe<HealthConfigV2> {
    let identity = collect::boot_identity(deps.state_root)?;
    let gateway = cfg
        .site
        .gateway(cfg.gateway)
        .ok_or_else(|| ProbeError::setup("unknown gateway"))?;
    let output = command_result(run_cmd(
        deps.system,
        ExecTarget::Host,
        &KernelCmd::Ip(IpCmd::AddrShowJson),
        EXEC_TIMEOUT,
    ))?;
    let uplinks = parse_ip_addr(&output)?
        .into_iter()
        .filter(|iface| {
            gateway
                .uplinks()
                .iter()
                .any(|name| name.as_str() == iface.ifname)
        })
        .flat_map(|iface| iface.addresses.into_iter().map(|address| address.local))
        .collect();
    HealthConfigV2::new(cfg.site, cfg.gateway, identity, uplinks, cfg.stamp.version)
        .map_err(|error| ProbeError::setup(&error.to_string()))
}

/// Runs the staged check. A repeated or unsupported stage is an internal error.
/// Each supported stage executes at most once; costly probes are verdict-gated.
///
/// # Errors
/// Returns required-observation errors, including missing boot.json/state.json.
pub fn run_check_v2(deps: &Dependencies<'_>, cfg: &Config<'_>) -> Result<Report, CheckError> {
    run_with_observations(deps, cfg).0
}

/// Runs the same gated driver while retaining each requested stage for status.
/// Unrequested stages remain None (not observed); status must label them so.
pub fn run_with_observations(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
) -> (Result<Report, CheckError>, Observations) {
    let mut obs = Observations::default();
    let health = match health(deps, cfg) {
        Ok(health) => health,
        Err(source) => {
            obs.topology = Some(Err(source.clone()));
            return (Err(error(Stage::Topology, source)), obs);
        }
    };
    let state = match collect::selection(deps.state_root) {
        Ok(state) => state,
        Err(source) => {
            // Persisted intent is needed even for topology's disconnected peers.
            obs.topology = Some(Err(source.clone()));
            return (Err(error(Stage::Topology, source)), obs);
        }
    };
    obs.selection = state.selection.clone();
    obs.active = if obs.selection == Selection::Disconnected {
        RouteTarget::Unreachable
    } else {
        RouteTarget::Exit(health.exit_iface.clone())
    };
    let Some(handle) = deps.handle else {
        obs.topology = Some(Ok(TopologyObs {
            netns: NetnsObs::Missing,
            links: vec![],
            peers: BTreeMap::new(),
            ruleset: RulesetObs::Missing,
            extra_rules: vec![],
            tc_hooks: vec![],
        }));
        return (done(&obs, &health, deps.system), obs);
    };
    if !health.require_daemon {
        obs.supervisor = Some(collect::supervisor(deps.system, handle, &health));
    }
    let mut seen = Vec::new();
    loop {
        let request = v2::next(&obs, &health, deps.system.now_unix_secs());
        if let Next::Done(result) = request {
            return (result, obs);
        }
        if seen.contains(&request) || seen.len() >= 7 {
            return (
                Err(error(
                    Stage::Topology,
                    ProbeError::setup("internal check stage protocol error"),
                )),
                obs,
            );
        }
        seen.push(request.clone());
        match request {
            Next::Topology => {
                obs.topology = Some(collect::topology(
                    deps.system,
                    handle,
                    cfg.site,
                    cfg.gateway,
                    &cfg.stamp,
                ));
            }
            Next::Defaults => obs.defaults = Some(collect::defaults(deps.system, handle, &health)),
            Next::Handshakes => {
                obs.handshakes = Some(collect::handshakes(deps.system, handle, &health));
            }
            Next::Forwarding => {
                obs.forwarding = Some(collect::forwarding(deps.system, handle, &health, &state));
            }
            Next::Routes => match collect::routes(deps.system, handle, &health) {
                Ok(routes) => obs.routes = Some(routes),
                Err(source) => return (Err(error(Stage::Routes, source)), obs),
            },
            Next::ExitProbe => {
                obs.exit_probe = Some(collect::exit_probe(
                    deps.system,
                    deps.probe_exec,
                    handle,
                    cfg.site,
                    cfg.gateway,
                ));
            }
            Next::Supervisor => {
                obs.supervisor = Some(collect::supervisor(deps.system, handle, &health));
            }
            Next::StandbyProbe | Next::Dns | Next::Done(_) => {
                return (
                    Err(error(
                        Stage::Topology,
                        ProbeError::setup("internal unsupported check stage"),
                    )),
                    obs,
                );
            }
        }
    }
}

fn done(obs: &Observations, cfg: &HealthConfigV2, sys: &dyn System) -> Result<Report, CheckError> {
    match v2::next(obs, cfg, sys.now_unix_secs()) {
        Next::Done(result) => result,
        _ => Err(error(
            Stage::Topology,
            ProbeError::setup("internal missing namespace verdict"),
        )),
    }
}
