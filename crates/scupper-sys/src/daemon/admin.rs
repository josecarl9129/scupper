//! Shared tick-owner operations, used by both scupperd and local fallback.
use super::control::api;
use super::{StartupRead, initialize, unix};
use crate::{
    boot::BootDeps,
    events::LogHandle,
    lock::WriterLock,
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
    mut check: impl FnMut(Option<Instant>) -> Result<Report, ApiError>,
) -> Result<OpResult, ApiError> {
    if !super::control::authorized(uid) {
        return Err(api(ApiErrorCode::Unauthorized));
    }
    let actor = Actor::Local { uid };
    match op {
        Op::Ping {} => Ok(OpResult::Ping {
            last_complete_iteration_age: age,
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
            reason: machine.latch().map(|_| scupper_proto::Reason::RepairBudget),
        }),
        Op::RepairClear {} => {
            machine
                .clear_latch(actor)
                .map_err(|_| api(ApiErrorCode::PersistenceUnavailable))?;
            machine.tick();
            Ok(OpResult::RepairClear {})
        }
        Op::Connect { exit } => {
            let selection = exit.map_or(Selection::Auto, |id| {
                Selection::Prefer(scupper_core::config::ExitId(String::from(id)))
            });
            machine.set_selection(selection, actor).map_err(internal)?;
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
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Op::Disconnect {} => {
            let closed = machine.set_selection(Selection::Disconnected, actor);
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
pub(super) fn check(
    deps: &BootDeps<'_>,
    probe: &dyn crate::probe_child::ProbeExec,
    held: &crate::netns::NetnsHandle,
    config: &Config,
    deadline: Option<Instant>,
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
    crate::check_v2::run_supervised(
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
    let store =
        VersionStore::open_with_mirror_root(deps.state_root, deps.config_root, Some(&guard))
            .map_err(internal)?;
    let version = store
        .commit(
            &guard,
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
    let store = VersionStore::read_only(deps.state_root, deps.config_root);
    let target = version
        .or(store.head().map_err(internal)?)
        .ok_or_else(|| api(ApiErrorCode::NotFound))?;
    store
        .read(target)
        .map_err(|_| api(ApiErrorCode::NotFound))?;
    // Across versions the final operation is always a complete boot. Closing
    // before publishing the version makes a crash leave the old handoff closed.
    let plan = vec![
        scupper_proto::StepKind::ForwardingOff,
        scupper_proto::StepKind::LoadRuleset,
        scupper_proto::StepKind::VerifyRuleset,
        scupper_proto::StepKind::FlushConntrack,
        scupper_proto::StepKind::LinkReconfigure,
        scupper_proto::StepKind::RouteReplace,
        scupper_proto::StepKind::ForwardingOn,
    ];
    if dry_run {
        return Ok(OpResult::Apply {
            version: target,
            dry_run,
            plan,
        });
    }
    let guard =
        WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2)).map_err(internal)?;
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
        let until = Instant::now() + Duration::from_secs(8);
        while deps.run_root.join("pause-apply").exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let file = StateFile::open(deps.state_root, None).map_err(internal)?;
    let StateRead::Present(mut state) = file.read().map_err(internal)? else {
        return Err(api(ApiErrorCode::PersistenceUnavailable));
    };
    state.applied_version = Some(target);
    file.write(&guard, &state)
        .map_err(|_| api(ApiErrorCode::PersistenceUnavailable))?;
    let _ = log.emit(
        EventKind::AdminAction {
            command: Command::Apply,
        },
        Actor::Local { uid },
        Some(target),
    );
    if !crate::boot::boot_with_guard(deps, &guard).succeeded() {
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
        file.write(&guard, &state)
            .map_err(|_| api(ApiErrorCode::PersistenceUnavailable))?;
        let _ = log.emit(cleared.event.into(), Actor::Local { uid }, Some(target));
        // Boot verified every object with the latch held. Re-verify under the
        // same writer capability before enabling the gate after explicit clear.
        if !crate::boot::boot_with_guard(deps, &guard).succeeded() {
            return Err(api(ApiErrorCode::Internal));
        }
    }
    Ok(OpResult::Apply {
        version: target,
        dry_run,
        plan,
    })
}

pub(super) fn repair_status(root: &std::path::Path) -> Result<OpResult, ApiError> {
    let file = StateFile::open(root, None).map_err(internal)?;
    let StateRead::Present(state) = file.read().map_err(internal)? else {
        return Err(api(ApiErrorCode::PersistenceUnavailable));
    };
    Ok(OpResult::RepairStatus {
        quarantined: state.quarantine.is_some(),
        reason: state
            .quarantine
            .map(|_| scupper_proto::Reason::RepairBudget),
    })
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
    let guard = WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2))
        .map_err(|e| format!("another writer holds the writer lock: {e}"))?;
    drop(guard);
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
        return commit(&deps, &log.handle, parent, &toml, reason, uid).map_err(LocalError::Api);
    }
    let applied = if let Op::Apply { version, dry_run } = op {
        let target = version.or(VersionStore::read_only(deps.state_root, deps.config_root)
            .head()
            .map_err(|e| e.to_string())?);
        let prefix = if dry_run {
            Vec::new()
        } else if let Ok((mut machine, _, _)) = initialize(
            deps,
            gateway.clone(),
            log.handle.clone(),
            Instant::now(),
            Instant::now() + Duration::from_secs(30),
            &mut StartupRead::default(),
        ) {
            if Some(machine.version()) == target {
                machine
                    .apply_plan(false, Actor::Local { uid })
                    .map_err(|e| e.to_string())?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let mut result = apply(&deps, &log.handle, version, dry_run, uid)?;
        if let OpResult::Apply { plan, .. } = &mut result {
            plan.splice(0..0, prefix);
        }
        if dry_run {
            return Ok(result);
        }
        Some(result)
    } else {
        None
    };
    let (mut machine, held, config) = initialize(
        deps,
        gateway,
        log.handle.clone(),
        Instant::now(),
        Instant::now() + Duration::from_secs(30),
        &mut StartupRead::default(),
    )
    .map_err(|e| e.to_string())?;
    let result = if let Some(result) = applied {
        machine.tick();
        Ok(result)
    } else {
        execute(&mut machine, op, uid, None, |deadline| {
            check(&deps, probe, &held, &config, deadline)
        })
    };
    let _ = log.handle.flush_blocking(Duration::from_secs(2));
    result.map_err(LocalError::Api)
}
