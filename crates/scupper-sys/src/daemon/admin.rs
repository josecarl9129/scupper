//! Shared tick-owner operations, used by both scupperd and local fallback.
use super::control::api;
use super::{StartupRead, initialize, unix};
use crate::{
    boot::BootDeps,
    events::LogHandle,
    lock::{SupervisorLease, WriterGuard, WriterLock},
    reconcile::{Config, Kernel, Reconciler, StateStore},
    state::{StateFile, StateRead},
    store::{MetaInput, VersionStore},
};
use scupper_core::{
    failover::MonoTime,
    verdict::v2::{FailClosed, Report, Selection, Verdict},
};
use scupper_proto::{
    Actor, ApiError, ApiErrorCode, Command, EventKind, HealthSummary, Op, OpResult,
};
use std::time::{Duration, Instant};

fn internal(_: impl std::fmt::Display) -> ApiError {
    api(ApiErrorCode::Internal)
}

/// Execute an operation against the one owned reconciler. A fresh independent
/// check is mandatory before claiming either connection or disconnection.
/// # Errors
/// Returns typed validation, persistence, observation or readiness failures.
#[allow(clippy::too_many_lines)]
pub fn execute<K: Kernel, S: StateStore, C: Fn() -> (MonoTime, u64)>(
    machine: &mut Reconciler<K, S, C>,
    op: Op,
    uid: u32,
    age: Option<u64>,
    check: impl FnMut(Option<Instant>) -> Result<Report, ApiError>,
) -> Result<OpResult, ApiError> {
    if !super::control::authorized(uid) {
        return Err(api(ApiErrorCode::Unauthorized));
    }
    match op {
        Op::Ping {} => {
            return Ok(OpResult::Ping {
                last_complete_iteration_age: age,
                netns: machine.netns_identity(),
                version: machine.version(),
                quarantined: machine.latch().is_some(),
                selection: machine.selection(),
            });
        }
        Op::RepairStatus {} => {
            return Ok(OpResult::RepairStatus {
                quarantined: machine.latch().is_some(),
                reason: machine.latch().map(|latch| latch.reason.clone()),
            });
        }
        _ => {}
    }
    let guard = machine.writer_guard().map_err(internal)?;
    execute_locked(machine, &guard, op, uid, age, check)
}
/// Execute using one writer capability for the whole operation.
/// # Errors
/// Returns validation, observation or persistence failures.
#[allow(clippy::too_many_lines)]
pub fn execute_locked<K: Kernel, S: StateStore, C: Fn() -> (MonoTime, u64)>(
    machine: &mut Reconciler<K, S, C>,
    guard: &WriterGuard,
    op: Op,
    uid: u32,
    age: Option<u64>,
    mut check: impl FnMut(Option<Instant>) -> Result<Report, ApiError>,
) -> Result<OpResult, ApiError> {
    if !super::control::authorized(uid) {
        return Err(api(ApiErrorCode::Unauthorized));
    }
    let actor = Actor::Local { uid };
    match op {
        Op::Ping {} => Ok(OpResult::Ping {
            last_complete_iteration_age: age,
            netns: machine.netns_identity(),
            version: machine.version(),
            quarantined: machine.latch().is_some(),
            selection: machine.selection(),
        }),
        Op::Check {} => {
            let report = check(None)?;
            Ok(OpResult::Check {
                health: HealthSummary::from(&report),
                report: serde_json::to_value(report).map_err(internal)?,
            })
        }
        Op::RepairStatus {} => Ok(OpResult::RepairStatus {
            quarantined: machine.latch().is_some(),
            reason: machine.latch().map(|latch| latch.reason.clone()),
        }),
        Op::RepairClear { reason } => {
            machine
                .clear_latch_with_reason_locked(
                    guard,
                    actor,
                    scupper_core::planner::ClearLatch::RepairClear,
                    reason,
                )
                .map_err(|_| api(ApiErrorCode::PersistenceUnavailable))?;
            machine.tick_with_guard(guard);
            Ok(OpResult::RepairClear {})
        }
        Op::Connect { exit } => {
            let selection = exit.map_or(Selection::Auto, |id| {
                Selection::Prefer(scupper_core::config::ExitId(String::from(id)))
            });
            if machine.latch().is_some() {
                return Err(api(ApiErrorCode::Quarantined));
            }
            machine
                .set_selection_locked(guard, selection, actor)
                .map_err(|e| {
                    if e.to_string() == "unconfigured exit" {
                        api(ApiErrorCode::InvalidRequest)
                    } else {
                        internal(e)
                    }
                })?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(report) = check(Some(deadline))
                    && let Verdict::Protected { exit, .. } | Verdict::Unsupervised { exit, .. } =
                        report.verdict
                {
                    return Ok(OpResult::Connect {
                        exit: (&exit).into(),
                    });
                }
                if Instant::now() >= deadline {
                    return Err(api(ApiErrorCode::NotReady));
                }
                machine.tick_with_guard(guard);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Op::Disconnect {} => {
            let closed = machine.set_selection_locked(guard, Selection::Disconnected, actor);
            let report = check(None)?;
            if closed.is_ok()
                && report.verdict == Verdict::FailClosed(FailClosed::AdminDisconnected)
            {
                Ok(OpResult::Disconnect {})
            } else {
                Err(ApiError {
                    code: ApiErrorCode::DisconnectNotEffective,
                    observation: Some(serde_json::to_value(report).map_err(internal)?),
                })
            }
        }
        Op::Status {} | Op::Apply { .. } | Op::Commit { .. } => {
            Err(api(ApiErrorCode::InvalidRequest))
        }
    }
}

struct DeadlineProbe<'a> {
    inner: &'a dyn crate::probe_child::ProbeExec,
    until: Instant,
}
impl crate::probe_child::ProbeExec for DeadlineProbe<'_> {
    #[cfg(any(test, feature = "testing"))]
    fn accepts_test_namespace(&self) -> bool {
        self.inner.accepts_test_namespace()
    }
    fn execute_probe(
        &self,
        json: &str,
        namespace: std::fs::File,
        timeout: Duration,
    ) -> Result<crate::system::ExecOutput, crate::system::ExecError> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(crate::system::ExecError::Timeout {
                after: Duration::from_secs(10),
            });
        }
        self.inner
            .execute_probe(json, namespace, timeout.min(remaining))
    }
}

// BootDeps has a generic System, so callers supply the independent probe boundary.
/// Run a fresh bounded staged check through the held namespace.
/// # Errors
/// Returns observation or probe failures.
pub fn check(
    deps: &BootDeps<'_>,
    probe: &dyn crate::probe_child::ProbeExec,
    held: &crate::netns::NetnsHandle,
    config: &Config,
    deadline: Option<Instant>,
    age: Option<u64>,
) -> Result<Report, ApiError> {
    let completed = age.and_then(|age| Instant::now().checked_sub(Duration::from_secs(age)));
    check_live(deps, probe, held, config, deadline, &|| completed)
}

pub(super) fn check_live(
    deps: &BootDeps<'_>,
    probe: &dyn crate::probe_child::ProbeExec,
    held: &crate::netns::NetnsHandle,
    config: &Config,
    deadline: Option<Instant>,
    last_complete: &dyn Fn() -> Option<Instant>,
) -> Result<Report, ApiError> {
    let bounded = crate::collect::reconcile::SafetySystem {
        system: deps.system,
        deadline: deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(45)),
        failed: std::cell::Cell::new(false),
    };
    let probe = DeadlineProbe {
        inner: probe,
        until: bounded.deadline,
    };
    crate::check_v2::run_supervised_live(
        &crate::check_v2::Dependencies {
            system: &bounded,
            probe_exec: &probe,
            handle: Some(held),
            run_root: deps.run_root,
            state_root: deps.state_root,
        },
        &crate::check_v2::Config {
            site: &config.site,
            gateway: &config.gateway,
            stamp: config.stamp,
        },
        last_complete,
    )
    .map_err(internal)
}

/// Commit an immutable version under the global writer capability.
/// # Errors
/// Returns authorization, CAS, validation or durability failures.
pub fn commit(
    deps: &BootDeps<'_>,
    log: &LogHandle,
    parent: Option<u64>,
    toml: &str,
    reason: scupper_proto::Reason,
    uid: u32,
) -> Result<OpResult, ApiError> {
    if !super::control::authorized(uid) {
        return Err(api(ApiErrorCode::Unauthorized));
    }
    let guard =
        WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2)).map_err(internal)?;
    commit_locked(deps, log, &guard, parent, toml, reason, uid)
}
/// Commit while retaining a caller-owned writer lock.
/// # Errors
/// Returns validation, CAS or durability errors.
pub fn commit_locked(
    deps: &BootDeps<'_>,
    log: &LogHandle,
    guard: &WriterGuard,
    parent: Option<u64>,
    toml: &str,
    reason: scupper_proto::Reason,
    uid: u32,
) -> Result<OpResult, ApiError> {
    let store = VersionStore::open_with_mirror_root(deps.state_root, deps.config_root, Some(guard))
        .map_err(internal)?;
    let version = store
        .commit(
            guard,
            parent,
            toml,
            MetaInput {
                actor: format!("uid-{uid}"),
                at: unix(),
                reason: format!("{reason:?}"),
            },
        )
        .map_err(|error| match error {
            crate::store::StoreError::Conflict { .. } => api(ApiErrorCode::Conflict),
            _ => internal(error),
        })?;
    let _ = log.emit(
        EventKind::AdminAction {
            reason: None,
            command: Command::Commit,
        },
        Actor::Local { uid },
        Some(version),
    );
    Ok(OpResult::Commit { version })
}

/// Explicit full apply: close first, run boot, then durably clear quarantine
/// after verification while retaining the writer capability.
/// # Errors
/// Returns authorization, version, lock, boot or durability failures.
pub fn apply(
    deps: &BootDeps<'_>,
    log: &LogHandle,
    version: Option<u64>,
    dry_run: bool,
    uid: u32,
) -> Result<OpResult, ApiError> {
    if !super::control::authorized(uid) {
        return Err(api(ApiErrorCode::Unauthorized));
    }
    let guard =
        WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2)).map_err(internal)?;
    apply_locked(deps, log, &guard, version, dry_run, uid)
}
/// Full apply with a caller-owned writer capability.
/// # Errors
/// Returns version, verification or persistence errors.
pub fn apply_locked(
    deps: &BootDeps<'_>,
    log: &LogHandle,
    guard: &WriterGuard,
    version: Option<u64>,
    dry_run: bool,
    uid: u32,
) -> Result<OpResult, ApiError> {
    let store = VersionStore::read_only(deps.state_root, deps.config_root);
    let target = match version {
        Some(version) => Some(version),
        None => store.head().map_err(internal)?,
    }
    .ok_or_else(|| api(ApiErrorCode::NotFound))?;
    store
        .read(target)
        .map_err(|_| api(ApiErrorCode::NotFound))?;
    // Across versions the final operation is always a complete boot. Closing
    // before publishing the version makes a crash leave the old handoff closed.
    let plan = vec![
        scupper_proto::StepKind::ForwardingOff,
        scupper_proto::StepKind::WriteSysctl,
        scupper_proto::StepKind::ReadBackSysctls,
        scupper_proto::StepKind::LoadRuleset,
        scupper_proto::StepKind::VerifyRuleset,
        scupper_proto::StepKind::FlushConntrack,
        scupper_proto::StepKind::LinkCreate,
        scupper_proto::StepKind::LinkReconfigure,
        scupper_proto::StepKind::RouteReplace,
        scupper_proto::StepKind::ForwardingOn,
    ];
    if dry_run {
        return Ok(OpResult::Apply {
            version: target,
            dry_run,
            repair_plan: Vec::new(),
            plan,
        });
    }
    if let Some(held) = deps.namespace.open().map_err(internal)? {
        crate::reconcile::forwarding_gates(deps, &held, false, None).map_err(internal)?;
    }
    #[cfg(feature = "testing")]
    if deps.run_root.join("pause-apply").exists() {
        std::fs::write(
            deps.run_root.join("apply-paused"),
            b"writer held; gates closed",
        )
        .map_err(internal)?;
        while deps.run_root.join("pause-apply").exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let file = StateFile::open(deps.state_root, None).map_err(internal)?;
    let StateRead::Present(mut state) = file.read().map_err(internal)? else {
        return Err(api(ApiErrorCode::PersistenceUnavailable));
    };
    state.applied_version = Some(target);
    file.write(guard, &state)
        .map_err(|_| api(ApiErrorCode::PersistenceUnavailable))?;
    let _ = log.emit(
        EventKind::AdminAction {
            reason: None,
            command: Command::Apply,
        },
        Actor::Local { uid },
        Some(target),
    );
    if !crate::boot::boot_apply_with_guard(deps, guard, true).succeeded() {
        if let Ok(Some(held)) = deps.namespace.open() {
            let _ = crate::reconcile::forwarding_gates(deps, &held, false, None);
        }
        return Err(api(ApiErrorCode::Internal));
    }
    if let Some(quarantine) = state.quarantine.take() {
        let latch = scupper_core::planner::Latch {
            reason: quarantine.reason,
            object: quarantine.object,
        };
        let cleared = scupper_core::planner::clear_latch(
            &latch,
            scupper_core::planner::ClearLatch::VerifiedFullApply,
            &scupper_core::planner::Budgets::default(),
        );
        if file.write(guard, &state).is_err() {
            if let Ok(Some(held)) = deps.namespace.open() {
                let _ = crate::reconcile::forwarding_gates(deps, &held, false, None);
            }
            return Err(api(ApiErrorCode::PersistenceUnavailable));
        }
        let _ = log.emit(cleared.event.into(), Actor::Local { uid }, Some(target));
    }
    Ok(OpResult::Apply {
        version: target,
        dry_run,
        repair_plan: Vec::new(),
        plan,
    })
}

/// Read-only same-version repair plan, independent of daemon attachment or probe qualification.
/// # Errors
/// Returns immutable configuration or observation failures.
#[allow(clippy::too_many_lines)] // Keep the read-only observation and planner inputs together.
pub fn preview_locked(
    deps: &BootDeps<'_>,
    _guard: &WriterGuard,
    target: Option<u64>,
) -> Result<Vec<scupper_proto::StepKind>, ApiError> {
    use scupper_core::{
        planner::{Budgets, Debounce, Desired, Latch},
        render::{RouteTarget, VersionStamp, render_netns},
        verdict::v2::{HealthConfigV2, NetnsIdentity},
    };
    use sha2::{Digest, Sha256};
    let file = StateFile::open(deps.state_root, None).map_err(internal)?;
    let StateRead::Present(state) = file.read().map_err(internal)? else {
        return Ok(Vec::new());
    };
    let Some(version) = state
        .applied_version
        .filter(|version| Some(*version) == target)
    else {
        return Ok(Vec::new());
    };
    let Some(held) = deps.namespace.open().map_err(internal)? else {
        return Ok(Vec::new());
    };
    let (text, _) = VersionStore::read_only(deps.state_root, deps.config_root)
        .read(version)
        .map_err(internal)?;
    let site =
        scupper_core::config::validate(scupper_core::config::parse_site(&text).map_err(internal)?)
            .map_err(|_| api(ApiErrorCode::Internal))?;
    let gateway = scupper_core::config::GatewayId(
        std::fs::read_to_string(deps.config_root.join("gateway-id"))
            .map_err(internal)?
            .trim()
            .into(),
    );
    let stamp = VersionStamp {
        version,
        sha256: Sha256::digest(text.as_bytes()).into(),
    };
    let rendered = render_netns(&site, &gateway, &stamp).map_err(internal)?;
    let want = if deps.system.canon_cache().is_some() {
        crate::canon::prepare_netns_ruleset(
            deps.system,
            &held,
            &rendered,
            Instant::now() + Duration::from_secs(6),
        )
    } else {
        crate::canon::netns_rulesets(deps.system, &held, &rendered).map(|(want, _)| want)
    }
    .map_err(internal)?;
    let fingerprint = crate::canon::fingerprint(&want).map_err(internal)?;
    let (device, inode) = held.identity();
    let health = HealthConfigV2::new(
        &site,
        &gateway,
        NetnsIdentity { device, inode },
        super::uplink_addresses(deps.system).map_err(internal)?,
        version,
    )
    .map_err(internal)?;
    let target = if state.selection == Selection::Disconnected {
        RouteTarget::Unreachable
    } else {
        RouteTarget::Exit(health.exit_iface.clone())
    };
    let desired = Desired::new(
        &site,
        &gateway,
        &stamp,
        fingerprint,
        &target,
        &state.selection,
    )
    .map_err(internal)?;
    let report: Option<crate::boot::BootReport> = std::fs::read(deps.run_root.join("boot.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let owned = report.map_or_else(std::collections::BTreeMap::new, |report| report.owned_links);
    let safety = crate::collect::reconcile::observe(
        deps.system,
        &held,
        &desired,
        &health,
        &held.fd_path(),
        None,
        &owned,
    );
    let observed = crate::collect::reconcile::observe_rest(
        deps.system,
        &held,
        &desired,
        &health,
        safety,
        Instant::now() + Duration::from_secs(6),
    );
    let latch = state.quarantine.map(|q| Latch {
        reason: q.reason,
        object: q.object,
    });
    let budgets = Budgets::default();
    let first = scupper_core::planner::plan(
        &desired,
        &observed.model,
        &budgets,
        latch.as_ref(),
        &Debounce::default(),
        MonoTime(Duration::ZERO),
    );
    let planned = scupper_core::planner::plan(
        &desired,
        &observed.model,
        &budgets,
        latch.as_ref(),
        &first.debounce,
        MonoTime(Duration::ZERO),
    );
    Ok(planned
        .steps
        .iter()
        .map(scupper_proto::StepKind::from)
        .collect())
}

pub(super) fn repair_status(root: &std::path::Path) -> Result<OpResult, ApiError> {
    let file = StateFile::open(root, None).map_err(internal)?;
    let StateRead::Present(state) = file.read().map_err(internal)? else {
        return Err(api(ApiErrorCode::PersistenceUnavailable));
    };
    Ok(OpResult::RepairStatus {
        quarantined: state.quarantine.is_some(),
        reason: state.quarantine.map(|quarantine| quarantine.reason),
    })
}

/// Persist administrative recovery intent even before a reconciler can initialize.
/// # Errors
/// Returns validation or durable state failures.
pub fn durable_intent(deps: &BootDeps<'_>, op: &Op, uid: u32) -> Result<(), ApiError> {
    if !super::control::authorized(uid) {
        return Err(api(ApiErrorCode::Unauthorized));
    }
    let guard =
        WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2)).map_err(internal)?;
    let file = StateFile::open(deps.state_root, None).map_err(internal)?;
    let StateRead::Present(mut state) = file.read().map_err(internal)? else {
        return Err(api(ApiErrorCode::PersistenceUnavailable));
    };
    match op {
        Op::Disconnect {} => {
            state.selection = Selection::Disconnected;
        }
        Op::RepairClear { reason } => {
            state.quarantine = None;
            if reason
                .as_ref()
                .is_some_and(|text| text.len() > 1024 || text.contains(['\n', '\r']))
            {
                return Err(api(ApiErrorCode::InvalidRequest));
            }
        }
        Op::Connect { exit } => {
            if state.quarantine.is_some() {
                return Err(api(ApiErrorCode::Quarantined));
            }
            if let Some(id) = exit {
                let version = state
                    .applied_version
                    .ok_or_else(|| api(ApiErrorCode::NotFound))?;
                let (text, _) = VersionStore::read_only(deps.state_root, deps.config_root)
                    .read(version)
                    .map_err(internal)?;
                let site = scupper_core::config::validate(
                    scupper_core::config::parse_site(&text).map_err(internal)?,
                )
                .map_err(|_| api(ApiErrorCode::Internal))?;
                let gateway = std::fs::read_to_string(deps.config_root.join("gateway-id"))
                    .map_err(internal)?;
                if !site
                    .gateway(&scupper_core::config::GatewayId(gateway.trim().into()))
                    .is_some_and(|gw| {
                        gw.exits()
                            .iter()
                            .any(|exit| exit.id().as_str() == String::from(id.clone()))
                    })
                {
                    return Err(api(ApiErrorCode::InvalidRequest));
                }
            }
            state.selection = exit.as_ref().map_or(Selection::Auto, |id| {
                Selection::Prefer(scupper_core::config::ExitId(String::from(id.clone())))
            });
            // This is only a durable transition; readiness is verified asynchronously.
        }
        _ => return Err(api(ApiErrorCode::InvalidRequest)),
    }
    file.write(&guard, &state)
        .map_err(|_| api(ApiErrorCode::PersistenceUnavailable))?;
    Ok(())
}

/// Distinguishes startup diagnostics from typed operation outcomes.
#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    /// Local startup or writer-lock refusal.
    #[error("{0}")]
    Startup(String),
    /// Correlated control operation failure.
    #[error(transparent)]
    Api(#[from] ApiError),
}
impl From<String> for LocalError {
    fn from(value: String) -> Self {
        Self::Startup(value)
    }
}
impl From<&str> for LocalError {
    fn from(value: &str) -> Self {
        Self::Startup(value.into())
    }
}

/// Local fallback uses exactly the daemon's initializer and operation dispatcher.
/// It obtains the writer lock before any mutable operation and refuses contention.
/// # Errors
/// Returns bounded lock/startup or typed operation failure.
pub fn local(
    deps: BootDeps<'_>,
    probe: &dyn crate::probe_child::ProbeExec,
    op: Op,
    uid: u32,
) -> Result<OpResult, LocalError> {
    if !super::control::authorized(uid) {
        return Err("control operations must run as root".into());
    }
    if matches!(op, Op::RepairStatus {}) {
        return repair_status(deps.state_root).map_err(LocalError::Api);
    }
    let _lease = SupervisorLease::try_acquire(deps.run_root)
        .map_err(|e| format!("scupperd control socket unavailable: {e}; stop scupperd with systemctl stop scupperd before using the local writer"))?;
    let guard = WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2))
        .map_err(|e| format!("another writer holds the writer lock: {e}"))?;
    let gateway = scupper_core::config::GatewayId(
        std::fs::read_to_string(deps.config_root.join("gateway-id"))
            .map_err(|e| e.to_string())?
            .trim()
            .into(),
    );
    let log = crate::reconcile::open_event_log(deps.state_root, gateway.clone(), || {
        scupper_proto::UnixSeconds(unix())
    })
    .map_err(|e| e.to_string())?;
    if let Op::Commit {
        parent,
        toml,
        reason,
    } = op
    {
        return commit_locked(&deps, &log.handle, &guard, parent, &toml, reason, uid)
            .map_err(LocalError::Api);
    }
    if let Op::Apply { version, dry_run } = op {
        let target = match version {
            Some(version) => Some(version),
            None => VersionStore::read_only(deps.state_root, deps.config_root)
                .head()
                .map_err(|e| e.to_string())?,
        };
        let prefix = if dry_run {
            preview_locked(&deps, &guard, target)?
        } else {
            Vec::new()
        };
        let mut result = apply_locked(&deps, &log.handle, &guard, version, dry_run, uid)?;
        if let OpResult::Apply { repair_plan, .. } = &mut result {
            *repair_plan = prefix;
        }
        let _ = log.handle.flush_blocking(Duration::from_secs(2));
        return Ok(result);
    }
    let (mut machine, held, config) = initialize(
        deps,
        gateway,
        log.handle.clone(),
        Instant::now(),
        Instant::now() + Duration::from_secs(30),
        &mut StartupRead::default(),
        Some((&guard, true)),
    )
    .map_err(|e| e.to_string())?;
    let result = execute_locked(&mut machine, &guard, op, uid, None, |deadline| {
        check(&deps, probe, &held, &config, deadline, None)
    });
    let _ = log.handle.flush_blocking(Duration::from_secs(2));
    result.map_err(LocalError::Api)
}
