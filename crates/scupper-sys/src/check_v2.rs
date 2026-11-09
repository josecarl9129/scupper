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
    /// Per-boot identity root (production /run/scupper).
    pub run_root: &'a Path,
    /// Persistent safety-state root (production /var/lib/scupper).
    pub state_root: &'a Path,
}

/// Applied immutable site and version, never a mirror or pending candidate.
pub struct Config<'a> {
    /// Validated applied configuration.
    pub site: &'a ValidatedSite,
    /// Local gateway ID.
    pub gateway: &'a GatewayId,
    /// Applied version and exact source digest.
    pub stamp: VersionStamp,
}

fn error(stage: Stage, source: ProbeError) -> CheckError {
    CheckError { stage, source }
}

fn health(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
    identity: v2::NetnsIdentity,
) -> Probe<HealthConfigV2> {
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

// A fallback config is used only to classify containment. Its placeholder uplink
// never reaches availability checks: a precondition error returns after violations.
fn prepare(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
    obs: &mut Observations,
) -> Probe<(HealthConfigV2, crate::state::State, Option<ProbeError>)> {
    // Preconditions are observations too: inventory containment even when boot,
    // persisted intent or host addresses cannot be read.
    let identity = collect::boot_identity(deps.run_root);
    let health_result = identity
        .clone()
        .and_then(|identity| health(deps, cfg, identity));
    let state_result = collect::selection(deps.state_root);
    let pending = health_result
        .as_ref()
        .err()
        .or(state_result.as_ref().err())
        .cloned();
    let health = if let Ok(health) = health_result {
        health
    } else {
        let (device, inode) = deps.handle.map_or((0, 1), NetnsHandle::identity);
        HealthConfigV2::new(
            cfg.site,
            cfg.gateway,
            identity.unwrap_or(v2::NetnsIdentity { device, inode }),
            vec![std::net::Ipv4Addr::UNSPECIFIED.into()],
            cfg.stamp.version,
        )
        .map_err(|source| ProbeError::setup(&source.to_string()))?
    };
    let state = state_result.unwrap_or_default();
    obs.selection = if pending.is_some() {
        Selection::Auto
    } else {
        state.selection.clone()
    };
    obs.active = if obs.selection == Selection::Disconnected {
        RouteTarget::Unreachable
    } else {
        RouteTarget::Exit(health.exit_iface.clone())
    };
    obs.topology = Some(match deps.handle {
        Some(handle) => collect::topology(deps.system, handle, cfg.site, cfg.gateway, &cfg.stamp),
        None => Ok(TopologyObs {
            host_wireguard_on_client_port: vec![],
            errors: vec![],
            links_complete: false,
            addresses_complete: false,
            netns: NetnsObs::Missing,
            links: vec![],
            peers: BTreeMap::new(),
            ruleset: RulesetObs::Exact,
            extra_rules: vec![],
            tc_hooks: vec![],
        }),
    });
    Ok((health, state, pending))
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
    let (health, state, pending) = match prepare(deps, cfg, &mut obs) {
        Ok(prepared) => prepared,
        Err(source) => return (Err(error(Stage::Topology, source)), obs),
    };
    if v2::violations(&obs, &health).is_some() {
        return (done(&obs, &health, deps.system), obs);
    }
    if let Some(source) = pending {
        return (Err(error(Stage::Topology, source)), obs);
    }
    let Some(handle) = deps.handle else {
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
                Err(source) => {
                    obs.routes = Some(
                        health
                            .route_sources
                            .iter()
                            .map(|client| {
                                (
                                    *client,
                                    v2::RouteObs {
                                        v4: Err(source.clone()),
                                        v6: Err(source.clone()),
                                    },
                                )
                            })
                            .collect(),
                    );
                }
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
