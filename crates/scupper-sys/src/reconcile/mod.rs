//! Level-triggered, single-writer reconciliation of the last applied version.

mod real;
pub use real::RealKernel;
#[cfg(any(test, feature = "testing"))]
pub mod fake;

use crate::{
    events::LogHandle,
    lock::{WriterGuard, WriterLock},
    netns::NetnsHandle,
    state::{Quarantine, State, StateFile, StateRead},
};
use scupper_core::{
    config::{ExitId, GatewayId, ValidatedSite},
    failover::{ExitLinkState, Failover, FailoverAction, FailoverConfig, FailoverInput, MonoTime},
    planner::{
        self, Budgets, ClearLatch, Debounce, Desired, KernelModel, Latch, Plan, Step, StepFailure,
    },
    render::VersionStamp,
    verdict::v2::Selection,
};
use scupper_proto::{Actor, Command, EventKind, Outcome, Reason, StepKind, VerdictCode};
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

/// Fresh kernel and health observations. Unknown values remain unknown.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Planner input through the held inode; phase A leaves non-safety fields Unknown.
    pub model: KernelModel,
    /// All required safety observations succeeded within their group deadline.
    pub safety_complete: bool,
    /// Elapsed safety collection time, in milliseconds.
    pub safety_ms: u64,
    /// All collection finished before the overall tick deadline.
    pub complete: bool,
    /// Handshake ages; absent entries indicate observation failure.
    pub handshakes: BTreeMap<ExitId, Option<Duration>>,
    /// Public link/peer/key availability.
    pub exit_links: BTreeMap<ExitId, ExitLinkState>,
}

/// A bounded operational execution error; never contains command output or secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct StepError(pub &'static str);

/// Namespace kernel adapter. Implementations must bound every exec to three seconds
/// and collect safety first with a six-second shared deadline.
pub trait Kernel {
    /// Observe the original inode even if its mount name was removed or hijacked.
    fn observe(&self, held: &NetnsHandle) -> Observation;
    /// Complete non-safety observations after emergency containment, before deadline.
    fn observe_rest(
        &self,
        held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation;
    /// Whether execution may still start a Restore within this tick.
    fn within_deadline(&self, deadline: Instant) -> bool {
        Instant::now() < deadline
    }
    /// Start a new locked tick, discarding older durable reads.
    fn begin_tick(&self) {
        self.invalidate_state();
    }
    /// Invalidate durable reads at the current writer-lock boundary or after a write.
    fn invalidate_state(&self) {}
    /// Execute one idempotent operation, preserving partial failure effects.
    ///
    /// # Errors
    /// Returns an error if execution or required readback failed.
    fn execute(&self, step: &Step) -> Result<(), StepError>;
    /// Restore the mount name to the held inode, without creating a namespace.
    ///
    /// # Errors
    /// Returns a mount or identity error.
    fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError>;
    /// Install the effective process latch before any planned action.
    fn hold_latch(&self, _latch: Option<&Latch>) {}
    /// Refresh the adapter's independent durable latch view after a state read/write.
    fn persisted_latch(&self, _latch: Option<&Latch>) {}
    /// Test/lifecycle boundary after an action and before its bookkeeping.
    /// Production implementations return normally; crash tests may unwind here.
    fn step_boundary(&self, _step: &Step) {}
}

/// Durable state boundary. Implementations must not acknowledge a write before fsync.
pub trait StateStore {
    /// Read the complete durable state, refusing absence or corruption.
    ///
    /// # Errors
    /// Returns missing, invalid or unreadable state.
    fn read(&self) -> io::Result<State>;
    /// Read by an absolute deadline without waiting for stalled storage.
    ///
    /// # Errors
    /// Returns read failure or timeout.
    fn read_until(&self, deadline: Instant) -> io::Result<State>;
    /// Discard reads started before the current writer-lock acquisition.
    fn begin_tick(&self) {}
    /// Durably replace state under the global writer capability.
    ///
    /// # Errors
    /// Returns serialization or durability failure, including uncertain rename outcomes.
    fn write(&self, guard: &WriterGuard, state: &State) -> io::Result<()>;
}
impl StateStore for StateFile {
    fn begin_tick(&self) {
        self.invalidate_reads();
    }
    fn read(&self) -> io::Result<State> {
        match Self::read(self)? {
            StateRead::Present(state) => Ok(state),
            StateRead::Missing => Err(io::Error::new(io::ErrorKind::NotFound, "missing state")),
        }
    }
    fn read_until(&self, deadline: Instant) -> io::Result<State> {
        match Self::read_until(self, deadline)? {
            StateRead::Present(state) => Ok(state),
            StateRead::Missing => Err(io::Error::new(io::ErrorKind::NotFound, "missing state")),
        }
    }
    fn write(&self, guard: &WriterGuard, state: &State) -> io::Result<()> {
        Self::write(self, guard, state)
    }
}

/// Immutable applied configuration and configurable writer-lock location.
pub struct Config {
    /// Validated applied site, never a pending candidate.
    pub site: ValidatedSite,
    /// Local gateway identity.
    pub gateway: GatewayId,
    /// Applied version and source digest.
    pub stamp: VersionStamp,
    /// Kernel-canonical fingerprint of the rendered applied ruleset.
    pub fingerprint: [u8; 32],
    /// `/run/scupper` in production.
    pub run_root: PathBuf,
    /// Bounded per-tick lock wait (normally at most 100 ms).
    pub lock_wait: Duration,
}
impl Config {
    fn desired(
        &self,
        selection: &Selection,
        route: &scupper_core::render::RouteTarget,
    ) -> io::Result<Desired> {
        Desired::new(
            &self.site,
            &self.gateway,
            &self.stamp,
            self.fingerprint,
            route,
            selection,
        )
        .map_err(io::Error::other)
    }
}

/// Lifecycle requests and namespace-name repair attempts reported by a tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Escalation {
    /// Stop edge, call rebuild, then restart edge.
    RebuildRequired,
    /// Restart edge in the held namespace.
    RestartEdge,
    /// A host/namespace interface collision needs operator attention.
    LinkCollision,
    /// The tick attempted to rebind the namespace name before restarting edge.
    RebindNamespace,
}
/// Results of one tick; only complete ticks may feed the watchdog.
#[derive(Debug, Clone, Default)]
pub struct TickReport {
    /// Safety collection and kernel work completed. Non-fatal persistence or
    /// event failures alone do not make a tick incomplete.
    pub complete: bool,
    /// Total safety collection milliseconds, including recovery observations.
    pub safety_ms: u64,
    /// Attempted steps in execution order, including recovery.
    pub steps: Vec<Step>,
    /// Failed attempted steps.
    pub failures: Vec<(Step, StepError)>,
    /// All required lifecycle transitions; rebuild makes the tick incomplete.
    pub escalations: Vec<Escalation>,
    /// Events offered to the nonblocking log handle during this tick.
    pub events: Vec<EventKind>,
    /// Events refused by the log handle, retained in `events` for this report.
    pub dropped_events: u64,
    /// Failover output for the scheduler, including edge upstream notifications.
    pub failover_actions: Vec<FailoverAction>,
}

/// One lifetime of the gateway writer. Time is supplied as (monotonic, Unix seconds).
pub struct Reconciler<K, S, C> {
    kernel: K,
    store: S,
    log: LogHandle,
    config: Config,
    failover: Failover,
    failover_config: FailoverConfig,
    budgets: Budgets,
    debounce: Debounce,
    latch: Option<Latch>,
    persisted: State,
    held: Arc<NetnsHandle>,
    clock: C,
    probe_rounds: Vec<BTreeMap<ExitId, bool>>,
    actions: Vec<FailoverAction>,
    verdict: Option<VerdictCode>,
    forwarding: bool,
    deadline: Option<Instant>,
    // Evidence only: no reservations or debounce are committed by emergency work.
    emergency_steps: Vec<Step>,
}
impl<K: Kernel, S: StateStore, C: Fn() -> (MonoTime, u64)> Reconciler<K, S, C> {
    /// Resume from durable selection/quarantine, starting failover qualification afresh.
    ///
    /// # Errors
    /// Refuses missing/corrupt state, an applied-version mismatch or unknown gateway.
    pub fn new(
        kernel: K,
        store: S,
        log: LogHandle,
        config: Config,
        held: Arc<NetnsHandle>,
        clock: C,
    ) -> io::Result<Self> {
        let persisted = store.read()?;
        if persisted.applied_version != Some(config.stamp.version) {
            return Err(io::Error::other("applied version mismatch"));
        }
        let failover_config =
            FailoverConfig::from_site(&config.site, &config.gateway).map_err(io::Error::other)?;
        let (failover, actions) =
            Failover::new(clock().0, persisted.selection.clone(), &failover_config);
        let latch = persisted.quarantine.as_ref().map(|q| Latch {
            reason: q.reason.clone(),
            object: q.object.clone(),
        });
        config.desired(&persisted.selection, failover.desired_route())?;
        kernel.hold_latch(latch.as_ref());
        kernel.persisted_latch(latch.as_ref());
        Ok(Self {
            kernel,
            store,
            log,
            config,
            failover,
            failover_config,
            budgets: Budgets::default(),
            debounce: Debounce::default(),
            latch,
            persisted,
            held,
            clock,
            probe_rounds: vec![],
            actions,
            verdict: None,
            forwarding: false,
            deadline: None,
            emergency_steps: vec![],
        })
    }
    /// Adapter access for lifecycle updates such as edge's new namespace path.
    pub fn kernel(&self) -> &K {
        &self.kernel
    }
    /// Queue one complete probe round, preserving batch boundaries and order.
    pub fn submit_probe_round(&mut self, batch: BTreeMap<ExitId, bool>) {
        self.probe_rounds.push(batch);
    }
    /// Current memory quarantine, including a latch whose durable write failed.
    pub fn latch(&self) -> Option<&Latch> {
        self.latch.as_ref()
    }
    /// Applied desired state using failover's current route, read on every tick.
    ///
    /// # Errors
    /// Returns an invalid applied configuration error.
    pub fn desired(&self) -> io::Result<Desired> {
        self.config
            .desired(&self.persisted.selection, self.failover.desired_route())
    }
    fn feed(&mut self, now: MonoTime, input: FailoverInput) {
        let (next, actions) = self.failover.step(now, input, &self.failover_config);
        self.failover = next;
        self.actions.extend(actions);
    }
    /// Observe, plan and execute once, with bounded same-tick failure recovery.
    #[allow(clippy::manual_let_else, clippy::single_match_else)] // Keep lock-failure reporting together.
    pub fn tick(&mut self) -> TickReport {
        let mut report = TickReport {
            complete: true,
            ..TickReport::default()
        };
        let guard = match WriterLock::acquire_timeout(&self.config.run_root, self.config.lock_wait)
        {
            Ok(guard) => guard,
            Err(_) => {
                report.complete = false;
                self.emit(
                    EventKind::DriftDetected {
                        object: scupper_proto::ObjectKind::Unknown,
                        reason: Reason::ExecutionFailed,
                    },
                    Actor::Daemon,
                    &mut report,
                );
                return report;
            }
        };
        self.tick_locked(&guard, &mut report);
        let mut seen = Vec::new();
        report.escalations.retain(|item| {
            if seen.contains(item) {
                false
            } else {
                seen.push(item.clone());
                true
            }
        });
        report
    }
    #[allow(clippy::single_match_else)] // Durable success and failure retain different latch views.
    fn observe(&mut self, report: &mut TickReport) -> Observation {
        let mut observation = self.kernel.observe(&self.held);
        observation.model.latch = self.persisted.quarantine.as_ref().map(|q| Latch {
            reason: q.reason.clone(),
            object: q.object.clone(),
        });
        self.forwarding = observation.model.forwarding_v4 == planner::Known::Value(1)
            && observation.model.forwarding_v6 == planner::Known::Value(1)
            && observation.model.client_forwarding_v4 == planner::Known::Value(1);
        report.complete &= observation.safety_complete;
        report.safety_ms = report.safety_ms.saturating_add(observation.safety_ms);
        observation
    }
    #[allow(clippy::single_match_else)]
    fn observe_rest(
        &mut self,
        safety: Observation,
        deadline: Instant,
        report: &mut TickReport,
    ) -> Observation {
        let mut observation = self.kernel.observe_rest(&self.held, safety, deadline);
        report.complete &= observation.safety_complete;
        report.complete &= observation.complete;
        // Persisted view is deliberately separate from the memory latch.
        match self.store.read_until(deadline) {
            Ok(state) => {
                observation.model.latch = state.quarantine.as_ref().map(|q| Latch {
                    reason: q.reason.clone(),
                    object: q.object.clone(),
                });
                self.kernel
                    .persisted_latch(observation.model.latch.as_ref());
                if self.latch.is_none() {
                    self.latch.clone_from(&observation.model.latch);
                }
                if state.applied_version != self.persisted.applied_version {
                    report.complete = false;
                    observation.complete = false;
                    observation.model.ruleset = planner::Known::Unknown;
                }
                if state.selection != self.persisted.selection {
                    self.feed(
                        (self.clock)().0,
                        FailoverInput::SelectionChanged(state.selection.clone()),
                    );
                    self.persisted.selection = state.selection;
                }
                self.persisted.quarantine = state.quarantine;
            }
            Err(_) => {
                report.complete = false;
                observation.complete = false;
                // Do not turn unreadable persisted quarantine into an implicit clear.
                observation.model.ruleset = planner::Known::Unknown;
                observation.model.latch = self.persisted.quarantine.as_ref().map(|q| Latch {
                    reason: q.reason.clone(),
                    object: q.object.clone(),
                });
            }
        }
        report.complete &= Instant::now() < deadline;
        observation.complete &= Instant::now() < deadline;
        observation
    }
    #[allow(clippy::too_many_lines)] // Preserve the observe/health/plan/execute ordering in one place.
    fn tick_locked(&mut self, guard: &WriterGuard, report: &mut TickReport) {
        self.store.begin_tick();
        self.kernel.begin_tick();
        self.tick_inner(guard, report);
        if self
            .deadline
            .is_some_and(|d| !self.kernel.within_deadline(d))
        {
            report.complete = false;
        }
        self.report_verdict(report);
    }
    #[allow(clippy::too_many_lines)]
    fn tick_inner(&mut self, guard: &WriterGuard, report: &mut TickReport) {
        let deadline = Instant::now() + Duration::from_secs(20);
        self.deadline = Some(deadline);
        let mut safety = self.observe(report);
        match safety.model.namespace {
            planner::NamespaceState::InodeGone => {
                report.complete = false;
                report.escalations.push(Escalation::RebuildRequired);
            }
            planner::NamespaceState::EdgeElsewhere => {
                report.escalations.push(Escalation::RestartEdge);
            }
            _ => {}
        }
        if let Ok(desired) = self.desired()
            && safety_drift(&safety.model, &desired, self.latch.is_some())
        {
            let prefix = planner::plan(
                &desired,
                &safety.model,
                &self.budgets,
                self.latch.as_ref(),
                &self.debounce,
                (self.clock)().0,
            );
            if self.latch.is_none() {
                self.latch = prefix.latch;
            }
            self.kernel.hold_latch(self.latch.as_ref());
            self.run_emergency(prefix.steps, &mut safety.model, &desired, guard, report);
        }
        // Rebinding the held inode's name is namespace containment, not a
        // network Restore. It must not depend on availability/storage reads.
        if safety.model.namespace == planner::NamespaceState::NameGone {
            self.restore_namespace(guard, report);
        }
        if !report.steps.is_empty() {
            safety = self.observe(report);
        }
        let observed = self.observe_rest(safety, deadline, report);
        if !observed.complete {
            report.complete = false;
            return;
        }
        let now = (self.clock)().0;
        self.feed(now, FailoverInput::Handshakes(observed.handshakes));
        for (exit, state) in observed.exit_links {
            self.feed(now, FailoverInput::LinkState(exit, state));
        }
        for round in std::mem::take(&mut self.probe_rounds) {
            self.feed(now, FailoverInput::PathProbe(round));
        }
        self.feed(now, FailoverInput::Tick);
        let Ok(desired) = self.desired() else {
            report.complete = false;
            return;
        };
        let route_transition = self
            .actions
            .iter()
            .any(|action| matches!(action, FailoverAction::SetRoute(_)));
        let mut planning_budgets = self.budgets.clone();
        for step in std::mem::take(&mut self.emergency_steps) {
            match step {
                Step::ForwardingOff | Step::LinkForwardingOff { .. } => {
                    planning_budgets.closed_by_planner = true;
                }
                Step::TcDelete { .. } => {
                    planning_budgets
                        .pending_safety
                        .insert(planner::SafetyClass::TcHook);
                }
                Step::LinkDown { name } => {
                    if !desired.links().contains_key(&name) {
                        planning_budgets
                            .pending_safety
                            .insert(planner::SafetyClass::ForeignLink);
                    }
                    planning_budgets.downed_by_planner.insert(name);
                }
                _ => {}
            }
        }
        if route_transition {
            for key in ["route:V4", "route:V6"] {
                planning_budgets.attempts.remove(key);
                planning_budgets.suppressed.remove(key);
            }
        }
        let mut planned = planner::plan(
            &desired,
            &observed.model,
            &planning_budgets,
            self.latch.as_ref(),
            &self.debounce,
            now,
        );
        if observed.model.forwarding_off()
            && report.steps.contains(&Step::ForwardingOff)
            && !report
                .failures
                .iter()
                .any(|(step, _)| *step == Step::ForwardingOff)
            && planned.steps.first() == Some(&Step::ForwardingOff)
        {
            planned.steps.remove(0);
        }
        // Route intent is authoritative on every tick. Failover transitions additionally
        // require an immediate route write and flush, bypassing drift debounce.
        let actions = std::mem::take(&mut self.actions);
        let mut transition = Vec::new();
        report.failover_actions.extend(actions.clone());
        for action in actions {
            match action {
                FailoverAction::SetRoute(_) => {
                    transition.extend(
                        desired
                            .routes()
                            .iter()
                            .filter(|(_, target)| match target {
                                scupper_core::render::RouteTarget::Unreachable => true,
                                scupper_core::render::RouteTarget::Exit(_) => {
                                    observed.model.route_ready(&desired, target)
                                }
                            })
                            .map(|(family, target)| Step::RouteReplace {
                                family: *family,
                                target: target.clone(),
                            }),
                    );
                }
                FailoverAction::FlushConntrack => transition.push(Step::FlushConntrack),
                FailoverAction::Emit(event) => self.emit(event.into(), Actor::Daemon, report),
                FailoverAction::SetExitsDown => transition.extend(
                    desired
                        .exits()
                        .values()
                        .map(|name| Step::LinkDown { name: name.clone() }),
                ),
                FailoverAction::NotifyEdge(_) => {} // Delivered by the scheduler's future edge channel.
            }
        }
        // Emergency closures remain first. Route transitions follow containment and
        // precede Restore; planner still owns all safety gates.
        let boundary = planned
            .steps
            .iter()
            .position(|s| s.failure() == StepFailure::Stop)
            .unwrap_or(planned.steps.len());
        planned.steps.splice(boundary..boundary, transition);
        if route_transition {
            for key in ["route:V4", "route:V6"] {
                planned.budgets.attempts.remove(key);
                planned.budgets.suppressed.remove(key);
            }
        }
        if report
            .failures
            .iter()
            .any(|(step, _)| step.failure() != StepFailure::NonFatal)
        {
            planned
                .steps
                .retain(|step| step.failure() != StepFailure::Stop);
        }
        self.run_plan(planned, &desired, guard, report, true);
    }
    fn report_verdict(&mut self, report: &mut TickReport) {
        let verdict = if !report.complete {
            VerdictCode::ObservationError
        } else if self.latch.is_some()
            || !self.forwarding
            || self.persisted.selection == Selection::Disconnected
            || *self.failover.desired_route() == scupper_core::render::RouteTarget::Unreachable
        {
            VerdictCode::FailClosed
        } else {
            VerdictCode::Protected
        };
        if let Some(from) = self.verdict
            && from != verdict
        {
            self.emit(
                EventKind::VerdictChanged { from, to: verdict },
                Actor::Daemon,
                report,
            );
        }
        self.verdict = Some(verdict);
    }
    fn run_emergency(
        &mut self,
        steps: Vec<Step>,
        model: &mut KernelModel,
        desired: &Desired,
        guard: &WriterGuard,
        report: &mut TickReport,
    ) {
        // Last-chance recovery may arrive from a full observation. Failure
        // replanning here must still use only the phase-A projection.
        unknown_nonsafety(model);
        let mut steps = std::collections::VecDeque::from(steps);
        let mut retried = false;
        while let Some(step) = steps.pop_front() {
            if !emergency_allowed(&step, model, desired) {
                continue;
            }
            if !self.emergency_steps.contains(&step) {
                self.emergency_steps.push(step.clone());
            }
            report.steps.push(step.clone());
            let result = self.execute_step(&step, guard, report);
            self.kernel.step_boundary(&step);
            if result.is_ok() && !matches!(step, Step::Emit(_)) {
                *model = model.apply(&step);
            }
            if !matches!(step, Step::Emit(_)) {
                self.emit(
                    EventKind::Repair {
                        kind: StepKind::from(&step),
                        class: repair_class(&step),
                        result: if result.is_ok() {
                            Outcome::Succeeded
                        } else {
                            Outcome::Failed
                        },
                    },
                    Actor::Daemon,
                    report,
                );
            }
            if let Err(error) = result {
                if step.failure() != StepFailure::NonFatal {
                    // Failure replanning is immediate, even when phase B cannot finish.
                    let recovery = planner::replan_after_failure(
                        &step,
                        desired,
                        model,
                        &self.budgets,
                        self.latch.as_ref(),
                        &self.debounce,
                        (self.clock)().0,
                    );
                    self.adopt_safety(&recovery);
                    if !retried {
                        steps.extend(recovery.steps);
                        retried = true;
                    }
                    report.complete = false;
                } else if matches!(step, Step::PersistLatch { .. }) {
                    self.persistence_failure(report);
                }
                report.failures.push((step, error));
            }
        }
    }
    fn persistence_failure(&mut self, report: &mut TickReport) {
        self.budgets.persistence_failed = true;
        self.emit(
            EventKind::PersistenceFailed {
                reason: Reason::StateWrite,
            },
            Actor::Daemon,
            report,
        );
    }
    // Phase-A replans may retain containment evidence, never reservations made
    // from the deliberately Unknown availability fields.
    fn adopt_safety(&mut self, plan: &Plan) {
        if self.latch.is_none() {
            self.latch.clone_from(&plan.latch);
        }
        self.kernel.hold_latch(self.latch.as_ref());
        self.budgets.persistence_failed = plan.budgets.persistence_failed;
        self.budgets.closed_by_planner = plan.budgets.closed_by_planner;
        self.budgets
            .pending_safety
            .clone_from(&plan.budgets.pending_safety);
    }
    fn adopt(&mut self, plan: &Plan) {
        self.adopt_safety(plan);
        self.budgets.clone_from(&plan.budgets);
        self.debounce.clone_from(&plan.debounce);
    }
    #[allow(clippy::too_many_lines)] // Keep failure ordering and bounded recovery auditable together.
    fn run_plan(
        &mut self,
        plan: Plan,
        desired: &Desired,
        guard: &WriterGuard,
        report: &mut TickReport,
        recover: bool,
    ) {
        self.adopt(&plan); // In memory before step zero; no disk I/O here.
        let mut restore_name = false;
        for escalation in plan.escalations {
            match escalation {
                planner::Escalation::NamespaceNameGone => {
                    restore_name = !report.escalations.contains(&Escalation::RebindNamespace);
                }
                planner::Escalation::NamespaceInodeGone => {
                    if !report.escalations.contains(&Escalation::RebuildRequired) {
                        report.escalations.push(Escalation::RebuildRequired);
                    }
                }
                planner::Escalation::EdgeInAnotherNamespace => {
                    if !report.escalations.contains(&Escalation::RestartEdge) {
                        report.escalations.push(Escalation::RestartEdge);
                    }
                }
                planner::Escalation::HostLinkCollision(_)
                | planner::Escalation::NamespaceLinkCollision(_) => {
                    if !report.escalations.contains(&Escalation::LinkCollision) {
                        report.escalations.push(Escalation::LinkCollision);
                    }
                }
            }
        }
        let inode_gone = report.escalations.contains(&Escalation::RebuildRequired);
        if inode_gone {
            report.complete = false;
        }
        let mut contained = false;
        let mut may_recover = recover;
        let mut refresh_before_restore = false;
        for step in plan.steps {
            // Namespace loss prevents kernel execution, but never drops a
            // planned audit or durable quarantine operation.
            if inode_gone && !matches!(step, Step::Emit(_) | Step::PersistLatch { .. }) {
                continue;
            }
            if refresh_before_restore && repair_class(&step) == scupper_proto::RepairClass::Restore
            {
                let safety = self.observe(report);
                let deadline = self.deadline.unwrap_or_else(Instant::now);
                if !self.observe_rest(safety, deadline, report).complete {
                    contained = true;
                }
                refresh_before_restore = false;
            }
            if repair_class(&step) == scupper_proto::RepairClass::Restore
                && self
                    .deadline
                    .is_some_and(|d| !self.kernel.within_deadline(d))
            {
                report.complete = false;
                continue;
            }
            if contained && step.failure() == StepFailure::Stop {
                continue;
            }
            report.steps.push(step.clone());
            let result = self.execute_step(&step, guard, report);
            self.kernel.step_boundary(&step);
            if let Err(error) = result {
                if step.failure() == StepFailure::NonFatal {
                    if !matches!(step, Step::Emit(_)) {
                        refresh_before_restore = true;
                    }
                    if matches!(step, Step::PersistLatch { .. }) {
                        self.budgets.persistence_failed = true;
                        self.emit(
                            EventKind::PersistenceFailed {
                                reason: Reason::StateWrite,
                            },
                            Actor::Daemon,
                            report,
                        );
                    }
                    report.failures.push((step, error));
                    continue;
                }
                // Nothing else may run between a failed action and failure replanning.
                let mut safety = self.observe(report);
                if step.failure() == StepFailure::Contain {
                    let containment = planner::replan_after_failure(
                        &step,
                        desired,
                        &safety.model,
                        &self.budgets,
                        self.latch.as_ref(),
                        &self.debounce,
                        (self.clock)().0,
                    );
                    self.adopt_safety(&containment);
                    self.run_emergency(
                        containment.steps,
                        &mut safety.model,
                        desired,
                        guard,
                        report,
                    );
                    safety = self.observe(report);
                }
                let deadline = self.deadline.unwrap_or_else(Instant::now);
                let mut observed = if self.kernel.within_deadline(deadline) {
                    self.observe_rest(safety, deadline, report)
                } else {
                    Observation {
                        complete: false,
                        ..safety
                    }
                };
                let mut recovery = planner::replan_after_failure(
                    &step,
                    desired,
                    &observed.model,
                    &self.budgets,
                    self.latch.as_ref(),
                    &self.debounce,
                    (self.clock)().0,
                );
                if !observed.complete {
                    recovery
                        .steps
                        .retain(|s| emergency_allowed(s, &observed.model, desired));
                    self.adopt_safety(&recovery);
                    recovery.budgets.clone_from(&self.budgets);
                    recovery.debounce.clone_from(&self.debounce);
                }
                self.adopt(&recovery);
                report.complete = false;
                report.failures.push((step.clone(), error));
                self.emit(
                    EventKind::Repair {
                        kind: StepKind::from(&step),
                        class: repair_class(&step),
                        result: Outcome::Failed,
                    },
                    Actor::Daemon,
                    report,
                );
                if may_recover {
                    may_recover = false;
                    self.run_plan(recovery, desired, guard, report, false);
                } else {
                    // Bounded recovery may also fail partially. Execute its emergency
                    // closure and all remaining tightening, never recurse into Restore.
                    self.run_emergency(recovery.steps, &mut observed.model, desired, guard, report);
                }
                match step.failure() {
                    StepFailure::Stop => break,
                    StepFailure::Contain => contained = true,
                    StepFailure::NonFatal => {}
                }
            } else if !matches!(step, Step::Emit(_)) {
                self.emit(
                    EventKind::Repair {
                        kind: StepKind::from(&step),
                        class: repair_class(&step),
                        result: Outcome::Succeeded,
                    },
                    Actor::Daemon,
                    report,
                );
            }
        }
        if restore_name {
            self.restore_namespace(guard, report);
        }
    }
    fn restore_namespace(&self, guard: &WriterGuard, report: &mut TickReport) {
        if !report.escalations.contains(&Escalation::RebindNamespace) {
            report.escalations.push(Escalation::RebindNamespace);
        }
        if self.kernel.restore_name(&self.held, guard).is_err() {
            report.complete = false;
            self.emit(
                EventKind::DriftDetected {
                    object: scupper_proto::ObjectKind::Unknown,
                    reason: Reason::ExecutionFailed,
                },
                Actor::Daemon,
                report,
            );
        }
    }
    fn execute_step(
        &mut self,
        step: &Step,
        guard: &WriterGuard,
        report: &mut TickReport,
    ) -> Result<(), StepError> {
        let result = match step {
            Step::PersistLatch { reason, object } => {
                let mut state = self.persisted.clone();
                state.quarantine = Some(Quarantine {
                    reason: reason.clone(),
                    object: object.clone(),
                    since_unix: (self.clock)().1,
                });
                self.kernel.invalidate_state();
                self.store
                    .write(guard, &state)
                    .map(|()| {
                        self.kernel.persisted_latch(Some(&Latch {
                            reason: reason.clone(),
                            object: object.clone(),
                        }));
                        self.persisted = state;
                    })
                    .map_err(|_| StepError("latch persistence failed"))
            }
            Step::Emit(event) => {
                let event = EventKind::from(event.clone());
                report.events.push(event.clone());
                self.log
                    .emit(event, Actor::Daemon, self.persisted.applied_version)
                    .map(|_| ())
                    .map_err(|_| {
                        report.dropped_events = report.dropped_events.saturating_add(1);
                        StepError("event emission failed")
                    })
            }
            Step::ForwardingOn { .. } if self.latch.is_some() => {
                Err(StepError("quarantine blocks forwarding"))
            }
            _ => self.kernel.execute(step),
        };
        if result.is_ok() {
            match step {
                Step::ForwardingOn { .. } => self.forwarding = true,
                Step::ForwardingOff => self.forwarding = false,
                _ => {}
            }
        }
        result
    }
    fn emit(&self, event: EventKind, actor: Actor, report: &mut TickReport) {
        if self
            .log
            .emit(event.clone(), actor, self.persisted.applied_version)
            .is_err()
        {
            report.dropped_events = report.dropped_events.saturating_add(1);
        }
        report.events.push(event);
    }
    /// Persist intent before executing a tick; Disconnected is acknowledged only
    /// after closing steps succeeded, with the same writer lock held throughout.
    ///
    /// # Errors
    /// Returns validation, lock, persistence or closing-step failure.
    #[allow(clippy::needless_pass_by_value)] // The administrative API consumes an intent transition.
    pub fn set_selection(&mut self, selection: Selection, actor: Actor) -> io::Result<TickReport> {
        if let Selection::Pin(id) | Selection::Prefer(id) = &selection
            && !self
                .failover_config
                .exits
                .iter()
                .any(|(exit, _)| exit == id)
        {
            return Err(io::Error::other("unconfigured exit"));
        }
        let guard = WriterLock::acquire_timeout(&self.config.run_root, self.config.lock_wait)?;
        let mut state = self.persisted.clone();
        state.selection = selection.clone();
        self.kernel.invalidate_state();
        self.store.write(&guard, &state)?;
        self.persisted = state;
        self.feed(
            (self.clock)().0,
            FailoverInput::SelectionChanged(selection.clone()),
        );
        let mut report = TickReport {
            complete: true,
            ..TickReport::default()
        };
        self.emit(
            EventKind::AdminAction {
                command: if selection == Selection::Disconnected {
                    Command::Disconnect
                } else {
                    Command::Connect
                },
            },
            actor,
            &mut report,
        );
        self.tick_locked(&guard, &mut report);
        if selection == Selection::Disconnected
            && (!report.complete
                || report
                    .failures
                    .iter()
                    .any(|(step, _)| step.failure() != StepFailure::NonFatal))
        {
            return Err(io::Error::other("disconnect closing steps incomplete"));
        }
        Ok(report)
    }
    /// Persist any memory quarantine before invoking boot for a lost inode.
    /// The scheduler stops edge before this call and creates a new reconciler
    /// with boot's new held namespace after a successful report.
    ///
    /// # Errors
    /// Returns lock/persistence failure; boot is not run when the memory latch
    /// cannot be made durable.
    pub fn rebuild(
        &mut self,
        deps: &crate::boot::BootDeps<'_>,
    ) -> io::Result<crate::boot::BootReport> {
        if deps.run_root != self.config.run_root {
            return Err(io::Error::other("rebuild writer root mismatch"));
        }
        let guard = WriterLock::acquire_timeout(&self.config.run_root, self.config.lock_wait)?;
        if let Some(latch) = &self.latch {
            let mut state = self.persisted.clone();
            if state.quarantine.is_none() {
                state.quarantine = Some(Quarantine {
                    reason: latch.reason.clone(),
                    object: latch.object.clone(),
                    since_unix: (self.clock)().1,
                });
                self.kernel.invalidate_state();
                if let Err(error) = self.store.write(&guard, &state) {
                    let _ = self.log.emit(
                        EventKind::PersistenceFailed {
                            reason: Reason::StateWrite,
                        },
                        Actor::Daemon,
                        self.persisted.applied_version,
                    );
                    return Err(error);
                }
                self.persisted = state;
            }
        }
        Ok(crate::boot::boot_with_guard(deps, &guard))
    }
    /// Explicit repair-clear transition. Memory quarantine remains if durability fails.
    ///
    /// # Errors
    /// Returns lock or state persistence failure.
    pub fn clear_latch(&mut self, actor: Actor) -> io::Result<()> {
        let guard = WriterLock::acquire_timeout(&self.config.run_root, self.config.lock_wait)?;
        let Some(latch) = &self.latch else {
            return Ok(());
        };
        let transition = planner::clear_latch(latch, ClearLatch::RepairClear, &self.budgets);
        let mut state = self.persisted.clone();
        state.quarantine = None;
        self.kernel.invalidate_state();
        self.store.write(&guard, &state)?;
        self.persisted = state;
        self.latch = transition.latch;
        self.kernel.persisted_latch(None);
        self.kernel.hold_latch(self.latch.as_ref());
        self.budgets = transition.budgets;
        let _ = self.log.emit(
            transition.event.into(),
            actor,
            self.persisted.applied_version,
        );
        Ok(())
    }
}

/// Open the audit log with an immediate memory-only fallback on disk failure.
/// Keep the returned owner alive for as long as its handle is used.
///
/// # Errors
/// Returns an invalid gateway error if neither log can be constructed.
pub fn open_event_log(
    root: &std::path::Path,
    gateway: GatewayId,
    clock: impl Fn() -> scupper_proto::UnixSeconds + Send + Sync + 'static,
) -> Result<crate::events::OpenedLog, crate::events::OpenError> {
    let clock = Arc::new(clock);
    let disk_clock = clock.clone();
    crate::events::EventLog::open(root, gateway.clone(), move || disk_clock())
        .or_else(|_| crate::events::EventLog::memory_only(gateway, move || clock()))
}

// Execution failure policy and policy effect are independent: a failed flush
// stops Restore, while flushing itself is a tightening operation.
const fn repair_class(step: &Step) -> scupper_proto::RepairClass {
    match step {
        Step::ForwardingOff
        | Step::FlushConntrack
        | Step::RouteDelete { .. }
        | Step::LinkDown { .. }
        | Step::LinkForwardingOff { .. }
        | Step::RuleDelete { .. }
        | Step::TcDelete { .. }
        | Step::PersistLatch { .. }
        | Step::Emit(_)
        | Step::RouteReplace {
            target: scupper_core::render::RouteTarget::Unreachable,
            ..
        } => scupper_proto::RepairClass::Tighten,
        Step::ForwardingOn { .. }
        | Step::LoadRuleset { .. }
        | Step::VerifyRuleset { .. }
        | Step::WriteSysctl { .. }
        | Step::ReadBackSysctls
        | Step::LinkCreate { .. }
        | Step::LinkReconfigure { .. }
        | Step::ReResolveEndpoint { .. }
        | Step::RouteReplace {
            target: scupper_core::render::RouteTarget::Exit(_),
            ..
        } => scupper_proto::RepairClass::Restore,
    }
}

// Phase A deliberately cannot certify addresses, peers, configuration or routing.
pub(crate) fn unknown_nonsafety(model: &mut KernelModel) {
    model.default_v4 = planner::Known::Unknown;
    model.default_v6 = planner::Known::Unknown;
    model.extra_routes = planner::Known::Unknown;
    model.extra_rules = planner::Known::Unknown;
    model.host_links.clear();
    model
        .hardening
        .values_mut()
        .for_each(|v| *v = planner::Known::Unknown);
    model.stale_exits.clear();
    for link in model.links.values_mut() {
        link.addresses = planner::Known::Unknown;
        link.settings = planner::Known::Unknown;
        if link.kind == planner::Known::Value("wireguard".into()) {
            link.peers = planner::Known::Unknown;
        }
    }
}
// A phase-A plan may act only on objects actually observed by phase A.
fn emergency_allowed(step: &Step, model: &KernelModel, desired: &Desired) -> bool {
    match step {
        Step::Emit(planner::PlannerEvent::ObservationUnknown) => phase_a_unknown(model),
        Step::ForwardingOff
        | Step::LinkForwardingOff { .. }
        | Step::TcDelete { .. }
        | Step::PersistLatch { .. }
        | Step::Emit(_) => true,
        Step::LinkDown { name } => {
            name == &model.client_link
                && (!model.links_complete
                    || model
                        .links
                        .values()
                        .any(|l| l.tc_hooks == planner::Known::Unknown))
                || desired.disconnected() && desired.exits().values().any(|n| n == name)
                || model.links.get(name).is_some_and(|link| {
                    link.kind != planner::Known::Value("loopback".into())
                        && (!desired.links().contains_key(name)
                            || link.ours != planner::Known::Value(true)
                            || link.kind != planner::Known::Value("wireguard".into()))
                })
        }
        _ => false,
    }
}
fn safety_drift(model: &KernelModel, desired: &Desired, latched: bool) -> bool {
    use planner::{Known, NamespaceState, Ruleset};
    let verified = model.ruleset == Known::Value(Ruleset::Verified(desired.fingerprint()));
    let gate = Known::Value(i64::from(!(latched || desired.disconnected() || !verified)));
    model.namespace == NamespaceState::Unknown
        || !model.links_complete
        || !verified
        || [
            &model.forwarding_v4,
            &model.forwarding_v6,
            &model.default_forwarding_v4,
            &model.default_forwarding_v6,
            &model.client_forwarding_v4,
        ]
        .iter()
        .any(|v| **v != gate)
        || model.links.iter().any(|(name, link)| {
            let owned = desired.links().contains_key(name)
                && link.ours == Known::Value(true)
                && link.kind == Known::Value("wireguard".into());
            let up_drift = !matches!(link.up, Known::Value(_))
                || link.kind != Known::Value("loopback".into())
                    && link.up == Known::Value(true)
                    && (!owned || desired.disconnected() && name != &model.client_link);
            link.tc_hooks != Known::Value(vec![])
                || up_drift
                || [&link.forwarding_v4, &link.forwarding_v6]
                    .iter()
                    .any(|v| **v != gate)
                || (name != "lo" && desired.links().contains_key(name) && !owned)
        })
}

// Availability fields deliberately omitted by phase A cannot raise this alert.
fn phase_a_unknown(model: &KernelModel) -> bool {
    use planner::{Known, NamespaceState};
    model.namespace == NamespaceState::Unknown
        || !model.links_complete
        || [
            &model.forwarding_v4,
            &model.forwarding_v6,
            &model.default_forwarding_v4,
            &model.default_forwarding_v6,
            &model.client_forwarding_v4,
        ]
        .contains(&&Known::Unknown)
        || model.ruleset == Known::Unknown
        || model.links.values().any(|link| {
            link.tc_hooks == Known::Unknown
                || link.forwarding_v4 == Known::Unknown
                || link.forwarding_v6 == Known::Unknown
                || link.kind == Known::Unknown
                || link.ours == Known::Unknown
                || link.up == Known::Unknown
        })
}
