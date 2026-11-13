//! Stateful kernel, external mutations, partial failures and crash boundaries.
//! `restore_name` and `InodeGone` lifecycle scenarios are exercised only here
//! until the 2o namespace lab validates the real mount and supervisor behavior.
#![allow(clippy::panic)] // Deliberate process-death simulation, caught by the harness.
use super::{Kernel, Observation, StateStore, StepError};
use crate::{lock::WriterGuard, netns::NetnsHandle, state::State};
use scupper_core::{
    failover::ExitLinkState,
    planner::{Desired, KernelModel, Known, Latch, ObservationItem, Ruleset, Step},
};
use scupper_proto::StepKind;
use std::{
    cell::RefCell,
    collections::BTreeSet,
    io,
    rc::Rc,
    time::{Duration, Instant},
};

/// Failure of one step category, optionally after a partial forwarding write.
#[derive(Debug, Clone)]
pub struct Fault {
    /// Category to fail.
    pub step: StepKind,
    /// Remaining failures; None means always.
    pub remaining: Option<usize>,
    /// `ForwardingOn` writes IPv4 before returning an error.
    pub partial: bool,
}
/// Shared fake state survives destruction and recreation of a reconciler.
#[derive(Clone)]
pub struct FakeKernel {
    inner: Rc<RefCell<Inner>>,
}
struct Inner {
    model: KernelModel,
    desired: Desired,
    faults: Vec<Fault>,
    timeouts: BTreeSet<ObservationItem>,
    history: Vec<(Step, KernelModel)>,
    crash_after: Option<usize>,
    boundaries: usize,
    remounts: usize,
    edge_elsewhere: bool,
    memory_latch: Option<Latch>,
    flushed: bool,
    safety_latency: Duration,
    rest_latency: Duration,
    execution_latency: Duration,
    expire_after: Option<StepKind>,
    rest_reads: usize,
    step_rest_reads: Vec<usize>,
    elapsed: Duration,
    step_times: Vec<Duration>,
    guard_history: Vec<bool>,
    handshakes: std::collections::BTreeMap<scupper_core::config::ExitId, Option<Duration>>,
}
impl FakeKernel {
    /// Start at a fully configured kernel state.
    #[must_use]
    pub fn new(desired: Desired) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Inner {
                model: KernelModel::desired(&desired),
                desired,
                faults: vec![],
                timeouts: BTreeSet::new(),
                history: vec![],
                crash_after: None,
                boundaries: 0,
                remounts: 0,
                edge_elsewhere: false,
                memory_latch: None,
                flushed: false,
                safety_latency: Duration::ZERO,
                rest_latency: Duration::ZERO,
                execution_latency: Duration::ZERO,
                expire_after: None,
                rest_reads: 0,
                step_rest_reads: vec![],
                elapsed: Duration::ZERO,
                step_times: vec![],
                guard_history: vec![],
                handshakes: std::collections::BTreeMap::new(),
            })),
        }
    }
    /// A complete current kernel snapshot, independent of process bookkeeping.
    #[must_use]
    pub fn model(&self) -> KernelModel {
        self.inner.borrow().model.clone()
    }
    /// Apply an external adversary mutation between ticks.
    pub fn mutate(&self, mutate: impl FnOnce(&mut KernelModel)) {
        mutate(&mut self.inner.borrow_mut().model);
    }
    /// Add a once/repeated/always execution failure.
    pub fn inject(&self, fault: Fault) {
        self.inner.borrow_mut().faults.push(fault);
    }
    /// Replace observation timeout injections. These affect observations, not the kernel.
    pub fn timeouts(&self, items: BTreeSet<ObservationItem>) {
        self.inner.borrow_mut().timeouts = items;
    }
    /// The name was hijacked and edge was started in that replacement namespace.
    pub fn hijack_name_with_edge(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.model.namespace = scupper_core::planner::NamespaceState::NameGone;
        inner.edge_elsewhere = true;
    }
    /// Simulate process death after the nth following step, before bookkeeping.
    pub fn crash_after(&self, boundary: usize) {
        let mut inner = self.inner.borrow_mut();
        inner.boundaries = 0;
        inner.crash_after = Some(boundary);
    }
    /// Every executed kernel step and its resulting state, including partial failures.
    #[must_use]
    pub fn history(&self) -> Vec<(Step, KernelModel)> {
        self.inner.borrow().history.clone()
    }
    /// Number of held-inode remounts (never namespace creates).
    #[must_use]
    pub fn remounts(&self) -> usize {
        self.inner.borrow().remounts
    }
    /// Clear history without changing kernel state.
    pub fn clear_history(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.history.clear();
        inner.step_times.clear();
        inner.guard_history.clear();
        inner.step_rest_reads.clear();
    }
    /// Inject aggregate collection delay without sleeping; safety is capped at six seconds.
    pub fn observation_latency(&self, safety: Duration, rest: Duration) {
        let mut inner = self.inner.borrow_mut();
        inner.safety_latency = safety;
        inner.rest_latency = rest;
    }
    /// Add simulated elapsed time to every kernel step without sleeping.
    pub fn execution_latency(&self, latency: Duration) {
        self.inner.borrow_mut().execution_latency = latency;
    }
    /// Expire the tick immediately after the next matching kernel step.
    pub fn expire_after(&self, step: StepKind) {
        self.inner.borrow_mut().expire_after = Some(step);
    }
    /// Number of completed phase-B collection attempts.
    #[must_use]
    pub fn rest_reads(&self) -> usize {
        self.inner.borrow().rest_reads
    }
    /// Phase-B collection count at each attempted kernel step.
    #[must_use]
    pub fn step_rest_reads(&self) -> Vec<usize> {
        self.inner.borrow().step_rest_reads.clone()
    }
    /// Measured collection budget at each attempted kernel action in the last tick.
    #[must_use]
    pub fn step_times(&self) -> Vec<Duration> {
        self.inner.borrow().step_times.clone()
    }
    /// Independent executor latch guard recorded alongside each kernel history entry.
    #[must_use]
    pub fn guard_history(&self) -> Vec<bool> {
        self.inner.borrow().guard_history.clone()
    }
    /// Override handshake age for an exit, including unavailable observations.
    pub fn handshake(&self, exit: scupper_core::config::ExitId, age: Option<Duration>) {
        self.inner.borrow_mut().handshakes.insert(exit, age);
    }
}
impl FakeKernel {
    fn snapshot(&self) -> Observation {
        let mut inner = self.inner.borrow_mut();
        let mut model = inner.model.clone();
        // Fresh positive canonical observation verifies a matching installed ruleset.
        if matches!(model.ruleset, Known::Value(Ruleset::Unverified(f)) if f == inner.desired.fingerprint())
        {
            model.ruleset = Known::Value(Ruleset::Verified(inner.desired.fingerprint()));
            inner.model.ruleset.clone_from(&model.ruleset);
        }
        let mut complete = true;
        for item in &inner.timeouts {
            match item {
                ObservationItem::Ruleset => {
                    model.ruleset = Known::Unknown;
                    complete = false;
                }
                ObservationItem::ForwardingV4 => {
                    model.forwarding_v4 = Known::Unknown;
                    complete = false;
                }
                ObservationItem::ForwardingV6 => {
                    model.forwarding_v6 = Known::Unknown;
                    complete = false;
                }
                ObservationItem::ClientForwardingV4 => {
                    model.client_forwarding_v4 = Known::Unknown;
                    complete = false;
                }
                ObservationItem::Links => {
                    model.links_complete = false;
                    model.links.clear();
                    complete = false;
                }
                ObservationItem::Tc(name) => {
                    if let Some(l) = model.links.get_mut(name) {
                        l.tc_hooks = Known::Unknown;
                    }
                    complete = false;
                }
                ObservationItem::Addresses(name) => {
                    if let Some(l) = model.links.get_mut(name) {
                        l.addresses = Known::Unknown;
                    }
                }
                ObservationItem::Peers(name) => {
                    if let Some(l) = model.links.get_mut(name) {
                        l.peers = Known::Unknown;
                    }
                }
                ObservationItem::Rules => model.extra_rules = Known::Unknown,
                ObservationItem::DefaultV4 => model.default_v4 = Known::Unknown,
                ObservationItem::DefaultV6 => model.default_v6 = Known::Unknown,
                ObservationItem::ExtraRoutes => model.extra_routes = Known::Unknown,
            }
        }
        model.conntrack_flushed = false;
        let exit_links = inner
            .desired
            .exits()
            .iter()
            .map(|(id, name)| {
                let link = model.links.get(name);
                (
                    id.clone(),
                    ExitLinkState {
                        link_up: link.is_some_and(|l| l.up == Known::Value(true)),
                        peer_present: link
                            .is_some_and(|l| l.peers.value().is_some_and(|p| !p.is_empty())),
                        key_present: true,
                    },
                )
            })
            .collect();
        let handshakes = inner
            .desired
            .exits()
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    inner
                        .handshakes
                        .get(id)
                        .copied()
                        .unwrap_or(Some(Duration::from_secs(1))),
                )
            })
            .collect();
        Observation {
            model,
            safety_complete: complete,
            safety_ms: if complete { 0 } else { 3_000 },
            complete,
            handshakes,
            exit_links,
        }
    }
}
impl Kernel for FakeKernel {
    fn within_deadline(&self, deadline: Instant) -> bool {
        Instant::now() < deadline && self.inner.borrow().elapsed < Duration::from_secs(20)
    }
    fn begin_tick(&self) {
        self.inner.borrow_mut().elapsed = Duration::ZERO;
    }
    fn observe(&self, _held: &NetnsHandle) -> Observation {
        let mut observation = self.snapshot();
        let mut inner = self.inner.borrow_mut();
        inner.flushed = false;
        inner.elapsed = inner
            .elapsed
            .saturating_add(inner.safety_latency.min(Duration::from_secs(6)));
        if inner.safety_latency >= Duration::from_secs(6) {
            observation.safety_complete = false;
            observation.model.ruleset = Known::Unknown;
        }
        observation.safety_ms = observation
            .safety_ms
            .max(u64::try_from(inner.elapsed.as_millis()).unwrap_or(u64::MAX));
        super::unknown_nonsafety(&mut observation.model);
        observation.handshakes.clear();
        observation.exit_links.clear();
        observation
    }
    fn observe_rest(
        &self,
        _held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation {
        let mut observation = self.snapshot();
        // Availability collection cannot turn a failed phase-A fingerprint into
        // a successful safety observation without actually collecting it again.
        observation.model.ruleset.clone_from(&safety.model.ruleset);
        observation.model.namespace = safety.model.namespace;
        let mut inner = self.inner.borrow_mut();
        inner.elapsed = inner.elapsed.saturating_add(inner.rest_latency);
        inner.rest_reads += 1;
        observation.safety_complete &= safety.safety_complete;
        observation.safety_ms = safety.safety_ms;
        observation.complete = inner.elapsed < Duration::from_secs(20) && Instant::now() < deadline;
        observation
    }
    fn persisted_latch(&self, latch: Option<&Latch>) {
        self.inner.borrow_mut().model.latch = latch.cloned();
    }
    #[allow(clippy::too_many_lines)] // Keep guards, injected failures and partial effects in order.
    fn execute(&self, step: &Step) -> Result<(), StepError> {
        let mut inner = self.inner.borrow_mut();
        if let Step::ForwardingOn { requires } | Step::LinkUp { requires, .. } = step {
            if inner.memory_latch.is_some()
                || inner.model.latch.is_some()
                || !matches!(inner.model.ruleset, Known::Value(Ruleset::Verified(f) | Ruleset::Unverified(f)) if f == *requires)
                || !inner.flushed
            {
                let model = inner.model.clone();
                let guard = inner.memory_latch.is_some();
                let elapsed = inner.elapsed;
                let reads = inner.rest_reads;
                inner.step_rest_reads.push(reads);
                inner.history.push((step.clone(), model));
                inner.guard_history.push(guard);
                inner.step_times.push(elapsed);
                return Err(StepError("fake forwarding guard refused"));
            }
            inner.model.ruleset = Known::Value(Ruleset::Verified(*requires));
        }
        inner.elapsed = inner.elapsed.saturating_add(inner.execution_latency);
        if inner.expire_after == Some(StepKind::from(step)) {
            inner.expire_after = None;
            inner.elapsed = Duration::from_secs(20);
        }
        let fault = inner
            .faults
            .iter_mut()
            .find(|f| f.step == StepKind::from(step) && f.remaining != Some(0));
        let fail = fault.map(|fault| {
            if let Some(remaining) = &mut fault.remaining {
                *remaining -= 1;
            }
            fault.partial
        });
        let result = if let Some(partial) = fail {
            if partial && matches!(step, Step::ForwardingOn { .. }) {
                inner.model.forwarding_v4 = Known::Value(1);
            }
            Err(StepError("injected step failure"))
        } else {
            match step {
                Step::ForwardingOn { requires }
                    if inner.memory_latch.is_some()
                        || inner.model.latch.is_some()
                        || inner.model.ruleset != Known::Value(Ruleset::Verified(*requires))
                        || !inner.flushed =>
                {
                    Err(StepError("fake forwarding guard refused"))
                }
                Step::RouteReplace {
                    target: scupper_core::render::RouteTarget::Exit(name),
                    ..
                } if !inner
                    .model
                    .links
                    .get(name.as_str())
                    .is_some_and(|link| link.up == Known::Value(true)) =>
                {
                    Err(StepError("ENETDOWN"))
                }
                Step::VerifyRuleset { fingerprint } if !matches!(inner.model.ruleset, Known::Value(Ruleset::Unverified(f) | Ruleset::Verified(f)) if f == *fingerprint) => {
                    Err(StepError("fake verification failed"))
                }
                Step::ReadBackSysctls
                    if inner.desired.hardening().iter().any(|s| {
                        inner.model.hardening.get(&s.key.to_string())
                            != Some(&Known::Value(s.value.clone()))
                    }) =>
                {
                    Err(StepError("fake sysctl mismatch"))
                }
                _ => {
                    inner.model = inner.model.apply(step);
                    if let Step::LinkDown { name } = step {
                        use scupper_core::verdict::v2::DefaultRouteObs;
                        let model = &mut inner.model;
                        for route in [&mut model.default_v4, &mut model.default_v6] {
                            if *route == Known::Value(DefaultRouteObs::Dev(name.clone())) {
                                *route = Known::Value(DefaultRouteObs::Missing);
                            }
                        }
                        if let Known::Value(routes) = &mut inner.model.extra_routes {
                            routes.retain(|route| route.entry.dev.as_deref() != Some(name));
                        }
                    }
                    if matches!(step, Step::FlushConntrack) {
                        inner.flushed = true;
                    }
                    if matches!(step, Step::LoadRuleset { .. }) {
                        inner.flushed = false;
                    }
                    Ok(())
                }
            }
        };
        let model = inner.model.clone();
        let guard = inner.memory_latch.is_some();
        let elapsed = inner.elapsed;
        let reads = inner.rest_reads;
        inner.step_rest_reads.push(reads);
        inner.history.push((step.clone(), model));
        inner.guard_history.push(guard);
        inner.step_times.push(elapsed);
        result
    }
    fn restore_name(&self, _held: &NetnsHandle, _guard: &WriterGuard) -> Result<(), StepError> {
        let mut inner = self.inner.borrow_mut();
        inner.model.namespace = if inner.edge_elsewhere {
            scupper_core::planner::NamespaceState::EdgeElsewhere
        } else {
            scupper_core::planner::NamespaceState::Ready
        };
        inner.remounts += 1;
        Ok(())
    }
    fn hold_latch(&self, latch: Option<&Latch>) {
        let mut inner = self.inner.borrow_mut();
        inner.memory_latch = latch.cloned();
    }
    fn step_boundary(&self, _step: &Step) {
        let crash = {
            let mut inner = self.inner.borrow_mut();
            inner.boundaries += 1;
            if inner.crash_after == Some(inner.boundaries) {
                inner.crash_after = None;
                true
            } else {
                false
            }
        };
        if crash {
            std::panic::panic_any(Crash);
        }
    }
}
/// Deliberately distinguish an injected process crash from an assertion failure.
#[derive(Debug)]
pub struct Crash;

/// Shared durable state with injectable writes, used for memory-only latch tests.
#[derive(Clone)]
pub struct MemoryStore {
    state: Rc<RefCell<State>>,
    fail: Rc<RefCell<bool>>,
    repair: Rc<RefCell<crate::state::RepairState>>,
}
impl MemoryStore {
    /// Create a durable reference snapshot.
    #[must_use]
    pub fn new(state: State) -> Self {
        Self {
            state: Rc::new(RefCell::new(state)),
            fail: Rc::new(RefCell::new(false)),
            repair: Rc::new(RefCell::new(crate::state::RepairState::default())),
        }
    }
    /// Fail every write until reset, leaving the previous durable state intact.
    pub fn fail_writes(&self, fail: bool) {
        *self.fail.borrow_mut() = fail;
    }
    /// Inspect the durable snapshot independently of the reconciler.
    #[must_use]
    pub fn state(&self) -> State {
        self.state.borrow().clone()
    }
}
impl StateStore for MemoryStore {
    fn repair_state(&self) -> Option<crate::state::RepairState> {
        Some(self.repair.borrow().clone())
    }
    fn write_repair_state(
        &self,
        _guard: &WriterGuard,
        repair: &crate::state::RepairState,
    ) -> io::Result<()> {
        *self.repair.borrow_mut() = repair.clone();
        Ok(())
    }
    fn clear_repair_state(&self, _guard: &WriterGuard, _root: &std::path::Path) -> io::Result<()> {
        *self.repair.borrow_mut() = crate::state::RepairState::default();
        Ok(())
    }
    fn applied_snapshot_until(&self, _deadline: Instant) -> Option<State> {
        Some(self.state())
    }
    fn read(&self) -> io::Result<State> {
        Ok(self.state())
    }
    fn read_until(&self, deadline: Instant) -> io::Result<State> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "state read deadline",
            ));
        }
        self.read()
    }
    fn write(&self, _guard: &WriterGuard, state: &State) -> io::Result<()> {
        if *self.fail.borrow() {
            Err(io::Error::other("injected persistence failure"))
        } else {
            *self.state.borrow_mut() = state.clone();
            Ok(())
        }
    }
}
