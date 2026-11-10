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
    run_driver(deps, cfg, None, None)
}

/// Fresh stages 1–7 on the supervisor tick owner; no recursive socket Ping.
/// # Errors
/// Returns required-observation failures from stages 1–7.
pub fn run_supervised(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
    age: Option<u64>,
) -> Result<Report, CheckError> {
    let supervisor = age
        .zip(deps.handle)
        .map_or(v2::Supervisor::Dead, |(age, held)| {
            let (device, inode) = held.identity();
            v2::Supervisor::Alive {
                iteration_age: std::time::Duration::from_secs(age),
                netns: v2::NetnsIdentity { device, inode },
            }
        });
    run_driver(deps, cfg, Some(supervisor), None).0
}

/// Read the current completed iteration at evaluation time, including during observation.
/// # Errors
/// Returns required observation failures.
pub fn run_supervised_live(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
    last_complete: &dyn Fn() -> Option<std::time::Instant>,
) -> Result<Report, CheckError> {
    run_driver(deps, cfg, Some(v2::Supervisor::Dead), Some(last_complete)).0
}

/// Local fallback after a bounded control request already failed. Reuse that
/// supervision observation instead of waiting for a second two-second timeout.
pub fn run_after_unavailable(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
) -> (Result<Report, CheckError>, Observations) {
    run_driver(deps, cfg, Some(v2::Supervisor::Dead), None)
}

/// Local observations using the supervisor identity and age already read by the CLI.
pub fn run_with_supervisor(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
    supervisor: v2::Supervisor,
) -> (Result<Report, CheckError>, Observations) {
    run_driver(deps, cfg, Some(supervisor), None)
}

#[allow(clippy::too_many_lines)] // Keep the staged observation dispatch together.
fn run_driver(
    deps: &Dependencies<'_>,
    cfg: &Config<'_>,
    supervisor: Option<v2::Supervisor>,
    last_complete: Option<&dyn Fn() -> Option<std::time::Instant>>,
) -> (Result<Report, CheckError>, Observations) {
    let started = std::time::Instant::now();
    let original_supervisor = supervisor;
    let mut obs = Observations {
        supervisor,
        ..Observations::default()
    };
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
        if health.require_daemon
            && let Some(v2::Supervisor::Alive {
                iteration_age,
                netns,
            }) = original_supervisor
        {
            obs.supervisor = Some(v2::Supervisor::Alive {
                iteration_age: iteration_age + started.elapsed(),
                netns,
            });
        }
        if health.require_daemon
            && let Some(completed) = last_complete
        {
            obs.supervisor = Some(completed().zip(deps.handle).map_or(
                v2::Supervisor::Dead,
                |(at, held)| {
                    let (device, inode) = held.identity();
                    v2::Supervisor::Alive {
                        iteration_age: at.elapsed(),
                        netns: v2::NetnsIdentity { device, inode },
                    }
                },
            ));
        }
        let request = v2::next(&obs, &health, deps.system.now_unix_secs());
        if let Next::Done(result) = request {
            return (result, obs);
        }
        if seen.contains(&request) || seen.len() >= 8 {
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
                obs.supervisor = Some(socket_supervisor(deps.run_root));
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

/// Stage 8: a failed or stale Ping is supervision loss, never an observation
/// error that hides an earlier safety violation.
#[must_use]
pub fn socket_supervisor(root: &Path) -> v2::Supervisor {
    use crate::daemon::control::{call, request};
    match call(
        root,
        &request(scupper_proto::Op::Ping {}),
        std::time::Duration::from_secs(2),
    ) {
        Ok(scupper_proto::Response {
            result:
                Ok(scupper_proto::OpResult::Ping {
                    last_complete_iteration_age: Some(age),
                    netns,
                    ..
                }),
            ..
        }) => v2::Supervisor::Alive {
            iteration_age: std::time::Duration::from_secs(age),
            netns,
        },
        _ => v2::Supervisor::Dead,
    }
}
