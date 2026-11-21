//! Serialized executor for the macOS helper, driven by the resource-model engine.
//!
//! With the instance lock, the start fence precedes ordinary tools and spawn.
//! D-3 exempts pinned stateless Lockdown, reference-free enable, verification and
//! state-only flushing, so inventory and quiescence cannot withhold containment.
//! Structural lock failures permit stateless, reference-free Lockdown and
//! guarded timeout cancellation of exact own tool children. The new helper
//! identity commits only after lock and fence closure. Child identities and
//! dispatch ids are local; snapshots contain reference accounting, not resources.
//! Locked startup probes intent with a shared 1 s read budget. Uncertainty runs
//! containment before the 5 s install read and separate 16 s copy-read budgets.
//! Those budgets bound storage reads, not full startup or containment tool calls.
//! Starting retries poll inventory and fences without retry sleeps; emergency
//! sweep, kill and reap share a 1 s deadline. Storage commits retain their own
//! budgets, and ordinary startup still needs ownership and closed fences.
//! Emergency attempts have bounded tool deadlines and a 1 s cadence; the first
//! attempt precedes internal-error persistence.
//! Leave remains available through storage failure and internal errors. Held
//! machines execute only the core safety prefix and cleanup, never a rejoin.
use crate::{
    platform::{
        self, Child, Commit, Deadline, Enumeration, Fence, InstallRecord, Platform, StartFence,
        Sweep, SysError, Timings, Tool,
    },
    snapshot::{
        self, Copy, CopyClass, DurableRecord, RefEvidence, RequestRecord, Snapshot, StartDecision,
    },
};
use scupper_core::mac::{
    Inputs, Tunnel, TunnelGeneration,
    lifecycle::{
        Durable, Event, Machine, ReferenceEntry, ReferenceIntent, ReferenceSettlement, Step,
    },
    policy::{Form, Kind},
    verify::{self, Baseline, Reason, SleepCountingClock, Verdict},
};
use std::{collections::VecDeque, path::Path};

mod emergency;
mod execute;
mod lockless;
mod protocol;
mod reference;
#[cfg(test)]
mod tests;

/// Foreground child pin; setup qualification must verify its ownership and hash.
pub const CHILD_PATH: &str = "/opt/scupper/wireguard-go";
pub(crate) const PINNED_TOOLS: [&str; 4] = [
    "/sbin/pfctl",
    "/sbin/route",
    "/usr/sbin/scutil",
    "/sbin/ifconfig",
];

/// Dispatch state, independent of reference accounting and held policy kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The previous incarnation has not yet been fenced.
    Starting,
    /// Serialized core-driven execution, including Leave and hold.
    Normal,
    /// D-class persistence waits; N-class safety and Leave work continue.
    PersistBlocked,
    /// Internal failure; emergency lockdown and fixed Leave bypass the core.
    Stuck,
}
/// Explicit outcome for a caller driving the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Continue serving requests and observations.
    Continue,
    /// A contender took the lock while structural failure was being retried.
    InstanceContended,
    /// Stuck Leave durably finished; the installer must arrange an unconditional supervisor restart.
    Exit0,
    /// Startup ownership invariant failed after taking the instance lock.
    StartupInvariantFailed,
}
/// Closed startup result, before an engine may serve requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartOutcome {
    /// Another helper owns the instance lock.
    InstanceContended,
    /// This process is not the launchd-owned process-group leader.
    StartupInvariantFailed,
}
/// Startup refusal, retaining the platform for diagnostics or process teardown.
#[derive(Debug)]
pub struct StartError<P> {
    /// Distinct reason the caller must exit without serving requests.
    pub outcome: StartOutcome,
    /// Platform still owns any acquired lock until process teardown.
    pub platform: P,
}
/// Durability class, decided in one exhaustive step table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Reservation/intent must be committed before exposure.
    D,
    /// Re-observable work; completion persistence may lag.
    N,
}
/// Classify every core step. Numeric release additionally pre-marks its evidence.
#[must_use]
pub const fn step_class(step: Step) -> Class {
    match step {
        Step::PersistIntent
        | Step::PersistLeaving
        | Step::ClearIntent
        | Step::ReserveGeneration
        | Step::AcquireReference
        | Step::ReleaseReference => Class::D,
        Step::Backoff { .. }
        | Step::ReconcileReference
        | Step::LoadPreTunnel
        | Step::VerifyPreTunnelLoad
        | Step::FlushStates
        | Step::VerifyPreTunnel
        | Step::CheckTools
        | Step::StartChild
        | Step::ConfigureUapi
        | Step::ConfigureAddresses
        | Step::ConfigureMtu
        | Step::ConfigureEndpointRoute
        | Step::ConfigureSplitRoutes
        | Step::ConfigureDns
        | Step::VerifyIdentity
        | Step::LoadJoined
        | Step::VerifyJoinedLoad
        | Step::VerifyJoined
        | Step::RemoveVanishedInterfaceStates
        | Step::ReplaceAnchor(_)
        | Step::VerifyReplacement(_)
        | Step::StopChild
        | Step::CleanupRoutes
        | Step::CleanupDns
        | Step::CleanupArtifacts
        | Step::RemoveAnchor => Class::N,
    }
}
/// Caller request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    /// Join the configured endpoint.
    Join,
    /// Restore connectivity and clear durable intent.
    Leave,
}
/// Stable caller id in the bounded replay window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// Nonzero id below the snapshot counter limit.
    pub id: u64,
    /// Desired action.
    pub kind: RequestKind,
}
/// A synchronous result still joins the serialized queue behind earlier input.
#[derive(Clone, Debug)]
pub struct Completion {
    /// In-memory dispatch fence; never persisted.
    pub dispatch: u64,
    /// Checked core result.
    pub event: Event,
    /// Token annotation obtained from the same complete reference enumeration.
    pub acquired: Option<RefEvidence>,
    /// Proven no-ioctl acquisition failure; settle only after Failed is accepted.
    pub not_started: Option<u64>,
}
/// Serialized engine inputs.
#[derive(Clone, Debug)]
pub enum QueueEvent {
    /// Caller intent.
    Request(Request),
    /// Context-bearing collector result or lifecycle notification.
    Monitor(Event),
    /// Effect result; stale dispatch ids never reach the core.
    Completion(Completion),
    /// Poll due observations; coalescible under backpressure.
    Timer,
}
/// Reference accounting is published separately from enforcement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accounting {
    /// Known numeric tokens retained.
    pub held: usize,
    /// Active or uncertain acquisition reservations.
    pub uncertain: usize,
    /// Tokens with a possibly completed release.
    pub release_unknown: usize,
}
/// Consumer-facing status. Open fences retain their pid/tool diagnostics.
#[derive(Clone, Debug)]
pub struct Status {
    /// Fresh verifier proof, or an explicit mask/refusal.
    pub enforcement: Verdict,
    /// Publication of verified connectivity restoration or pending cleanup item.
    pub text: String,
    /// Fresh blocking evidence under a hold or storage mask.
    pub blocking_verified: bool,
    /// Full global verification of the independent Stuck lockdown.
    pub emergency_blocking_verified: bool,
    /// Inclusive sleep-counting expiry of the published blocking claim.
    pub blocking_expires_at: Option<u64>,
    /// Inclusive sleep-counting expiry of the emergency blocking claim.
    pub emergency_expires_at: Option<u64>,
    /// No endpoint was available for a host-route absence claim.
    pub endpoint_unknown: bool,
    /// Accounting never determines whether connectivity is restored.
    pub accounting: Accounting,
    /// Current dispatch mode.
    pub mode: Mode,
    /// Previous-incarnation process/tool fence, including survivor identities.
    pub start_fence: StartFence,
    /// In-process tool fence, naming each outstanding pid and family.
    pub mutation_fence: Fence,
    /// Most recent unconfirmed child sweep.
    pub sweep: Option<Sweep>,
}
impl Status {
    /// Expire a published snapshot at the consumer, even if the engine stops.
    #[must_use]
    pub fn at(mut self, now: u64) -> Self {
        self.enforcement = self.enforcement.at(&Clock(now));
        self.blocking_verified &= self.blocking_expires_at.is_some_and(|expiry| now <= expiry);
        self.emergency_blocking_verified &= self
            .emergency_expires_at
            .is_some_and(|expiry| now <= expiry);
        self
    }
}
#[derive(Clone, Copy)]
struct Clock(u64);
impl SleepCountingClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum StartFault {
    Validate,
    Settlement,
    Conversion,
    Staging,
    Encode,
    Refresh,
}

struct StartupStorage {
    repair: Option<Copy>,
    recovery: bool,
    bytes: Box<[u8; snapshot::COPY_BYTES]>,
    missing: [bool; 2],
}

/// One serialized engine over the independent platform boundary.
#[allow(clippy::struct_excessive_bools)] // Independent storage, fence and publication evidence.
pub struct Engine<P: Platform> {
    platform: P,
    install: Option<InstallRecord>,
    timings: Timings,
    machine: Machine,
    adopted: bool,
    snapshot: Snapshot,
    committed: Snapshot,
    seq: u64,
    mode: Mode,
    start_fence: StartFence,
    helper_committed: bool,
    previous_helper: platform::PreviousHelper,
    queue: VecDeque<QueueEvent>,
    capacity: usize,
    next_dispatch: u64,
    in_flight: Option<(u64, Step)>,
    child: Option<Child>,
    baseline: Option<Baseline>,
    last_sweep: Option<Sweep>,
    overflowed: bool,
    rejected: u64,
    next_cheap: u64,
    next_full: u64,
    next_flush: u64,
    storage_blocked: bool,
    missing_storage: bool,
    repair_pending: Option<(Copy, Box<[u8; snapshot::COPY_BYTES]>)>,
    startup_storage: Option<StartupStorage>,
    next_storage: u64,
    storage_delay: u64,
    storage_waiting: bool,
    in_emergency_step: bool,
    emergency_frame_disturbed: bool,
    emergency_guard_reload_pending: bool,
    emergency_guard_flush_pending: bool,
    emergency_guard_next_reload: u64,
    emergency_guard_next_flush: u64,
    waiting: Option<(Machine, Snapshot)>,
    unexposed_acquires: Vec<u64>,
    left_verified: bool,
    leave_item: Option<&'static str>,
    next_leave: u64,
    leave_delay: u64,
    leave_unknown: bool,
    stuck_leave: Option<VecDeque<Step>>,
    retained_completion: Option<(Step, Completion)>,
    stuck_accounting: Vec<RefEvidence>,
    outcome: Outcome,
    control_socket_created: bool,
    next_socket: u64,
    lockless: Option<lockless::Fallback>,
    startup_error: Option<SysError>,
    verified_enforcement: bool,
    emergency_proof: Option<verify::Proof>,
    last_fresh_proof_at: Option<u64>,
    emergency_loaded: bool,
    emergency_readback: Option<String>,
    emergency_anchor_absent: bool,
    emergency_last_load_at: Option<u64>,
    last_ordinary_load_at: Option<u64>,
    emergency_drain_until: Option<Deadline>,
    containment_cleanup_only: bool,
    emergency_next_reload: u64,
    emergency_reload_delay: u64,
    emergency_next_acquire: u64,
    emergency_acquire_delay: u64,
    emergency_states_clean_at: Option<u64>,
    emergency_next_flush: u64,
    emergency_flush_delay: u64,
    emergency_references: Vec<RefEvidence>,
    emergency_settled: Vec<ReferenceEntry>,
    emergency_unreserved_consumed: bool,
    anonymous_enable_confirmed: bool,
    emergency_commit_failed: bool,
    emergency_enable_pending: bool,
    emergency_needs_reference: bool,
    emergency_annotation_due: u64,
    emergency_revoked: bool,
    next_emergency: u64,
    emergency_baseline: Option<(Baseline, u64)>,
    startup_invariant_failed: bool,
    startup_invariant_checked: bool,
    #[cfg(test)]
    reject_fallback: bool,
    #[cfg(test)]
    start_fault: Option<StartFault>,
    #[cfg(test)]
    stuck_entry: Option<(&'static str, u32)>,
}
impl<P: Platform> Engine<P> {
    /// Read, classify/repair, fence, commit this incarnation, then restart the core.
    /// With the lock held, tools and spawn follow the start fence. Missing copies never mean
    /// fresh installation; a missing Recovery destination makes persistence fail.
    ///
    /// # Errors
    /// Contention and definite ownership failures return a closed outcome.
    /// Structural lock errors retain a read-only, stateless fallback engine;
    /// socket failures retain an engine enforcing emergency policy while retrying.
    pub fn start(mut platform: P) -> Result<Self, StartError<P>> {
        let mut interrupts = 0;
        loop {
            match platform.acquire_instance_lock() {
                Ok(()) => break,
                Err(platform::InstanceLockError::Interrupted) => {
                    interrupts += 1;
                    if interrupts >= 8 {
                        return Ok(Self::start_lockless(platform, SysError::Unknown));
                    }
                }
                Err(platform::InstanceLockError::Contended) => {
                    return Err(StartError {
                        outcome: StartOutcome::InstanceContended,
                        platform,
                    });
                }
                Err(platform::InstanceLockError::Failed(error)) => {
                    return Ok(Self::start_lockless(platform, error));
                }
            }
        }
        // The read-only intent budget precedes even the install-record read.
        let block = lockless::lockless_intent(&mut platform);
        let mut engine = Self::start_selected_inner(
            platform,
            None,
            StartDecision::Recovery {
                seq: 1,
                helper: None,
            },
            [false, false],
            None,
            true,
        );
        if block {
            engine.attempt_stateless_containment();
            engine.next_emergency = engine.platform.now().saturating_add(1);
        }
        engine.resume_locked_start(block);
        if engine.outcome == Outcome::StartupInvariantFailed {
            return Err(StartError {
                outcome: StartOutcome::StartupInvariantFailed,
                platform: engine.into_platform(),
            });
        }
        Ok(engine)
    }

    #[cfg(test)]
    fn start_selected(
        platform: P,
        install: Option<InstallRecord>,
        decision: StartDecision,
        missing: [bool; 2],
    ) -> Self {
        Self::start_selected_inner(platform, install, decision, missing, None, false)
    }

    #[allow(clippy::too_many_lines)] // Initialize normal and read-only fallback with identical volatile defaults.
    fn start_selected_inner(
        mut platform: P,
        install: Option<InstallRecord>,
        decision: StartDecision,
        missing: [bool; 2],
        lockless: Option<lockless::Fallback>,
        defer_start: bool,
    ) -> Self {
        // All cadences share the platform sleep-counting clock.
        let now = platform.now();
        let timings = install
            .as_ref()
            .map_or(Timings::default(), |r| r.config.timings);

        let (seq, mut snapshot, repair, recovery) = match decision {
            StartDecision::Trust {
                seq,
                snapshot,
                repair,
                ..
            } => (seq, snapshot, repair, false),
            StartDecision::Recovery { seq, helper } => {
                let snapshot = Snapshot::recovery(
                    platform.boot_id(),
                    install
                        .as_ref()
                        .map(|r| execute::endpoint(&r.config.inputs)),
                    install.as_ref().map(|r| r.owner_uid),
                    helper,
                );
                (seq, snapshot, None, true)
            }
        };
        let committed = snapshot.clone();
        snapshot.image_history.observe_boot(platform.boot_id());
        let bytes = snapshot::encode(seq, &snapshot).ok();
        let invalid = bytes.is_none() || snapshot.validate().is_err();
        // Preserve the original repair/Recovery protocol, but defer every write
        // until ownership is known. An incomplete inventory remains retryable.
        let startup_storage = bytes
            .filter(|_| !invalid && (repair.is_some() || recovery))
            .map(|bytes| StartupStorage {
                repair,
                recovery,
                bytes,
                missing,
            });
        let mut engine = Self {
            platform,
            install,
            timings,
            machine: Machine::restart(Durable::default()),
            adopted: false,
            committed,
            snapshot: snapshot.clone(),
            seq,
            mode: Mode::Starting,
            start_fence: StartFence::Uncommitted,
            helper_committed: false,
            previous_helper: match snapshot.helper.clone() {
                Some(helper) => platform::PreviousHelper::Known(helper),
                // Recovery commits hold before fencing. A helperless held copy
                // retains that provenance if this helper dies before closure.
                None if recovery || snapshot.machine.hold => platform::PreviousHelper::Unknown,
                None => platform::PreviousHelper::None,
            },
            queue: VecDeque::new(),
            capacity: 64,
            next_dispatch: 1,
            in_flight: None,
            child: None,
            baseline: None,
            last_sweep: None,
            overflowed: false,
            rejected: 0,
            next_cheap: now.saturating_add(timings.cheap_check),
            next_full: now.saturating_add(timings.full_walk),
            next_flush: now.saturating_add(timings.state_flush),
            storage_blocked: false,
            missing_storage: missing == [true, true],
            repair_pending: None,
            startup_storage,
            next_storage: now.saturating_add(1),
            storage_delay: 1,
            storage_waiting: false,
            in_emergency_step: false,
            emergency_frame_disturbed: false,
            emergency_guard_reload_pending: false,
            emergency_guard_flush_pending: false,
            emergency_guard_next_reload: now,
            emergency_guard_next_flush: now,
            waiting: None,
            unexposed_acquires: Vec::new(),
            left_verified: false,
            leave_item: None,
            next_leave: 0,
            leave_delay: 0,
            leave_unknown: false,
            stuck_leave: None,
            retained_completion: None,
            stuck_accounting: Vec::new(),
            outcome: Outcome::Continue,
            control_socket_created: false,
            next_socket: now,
            lockless,
            startup_error: None,
            verified_enforcement: false,
            emergency_proof: None,
            last_fresh_proof_at: None,
            emergency_loaded: false,
            emergency_readback: None,
            emergency_anchor_absent: false,
            emergency_last_load_at: None,
            last_ordinary_load_at: None,
            emergency_drain_until: None,
            containment_cleanup_only: false,
            emergency_next_reload: now,
            emergency_reload_delay: 1,
            emergency_next_acquire: now,
            emergency_acquire_delay: 1,
            emergency_states_clean_at: None,
            emergency_next_flush: now,
            emergency_flush_delay: 1,
            emergency_references: Vec::new(),
            emergency_settled: Vec::new(),
            emergency_unreserved_consumed: false,
            anonymous_enable_confirmed: false,
            emergency_commit_failed: false,
            emergency_enable_pending: false,
            emergency_needs_reference: false,
            emergency_annotation_due: now,
            emergency_revoked: false,
            next_emergency: 0,
            emergency_baseline: None,
            startup_invariant_failed: false,
            startup_invariant_checked: false,
            #[cfg(test)]
            reject_fallback: false,
            #[cfg(test)]
            start_fault: None,
            #[cfg(test)]
            stuck_entry: None,
        };
        if defer_start {
            return engine;
        }
        if engine.lockless.is_some() {
            engine.run_lockless();
        } else if invalid {
            engine.enter_stuck();
        } else if engine.mode == Mode::Starting {
            engine.finish_start();
        } else if engine.mode == Mode::PersistBlocked {
            engine.mode = Mode::Starting;
            engine.finish_start();
        } else {
            engine.observe_only();
        }
        engine
    }

    #[allow(clippy::too_many_lines)] // Ordered startup gates and accounting reducer stay together.
    fn finish_start(&mut self) {
        // D-3 precedes even a slow first inventory or sweep. Ordinary startup
        // still needs ownership, storage and quiescence before its own effects.
        if self.snapshot.machine.join_intended
            && self.containment_allowed()
            && !self.startup_invariant_failed
            && self.platform.now() >= self.next_emergency
            && self.emergency_is_stateless()
        {
            self.attempt_stateless_containment();
            self.next_emergency = self.platform.now().saturating_add(1);
        }
        let startup_poll_until = Deadline(self.platform.now().saturating_add(1));
        self.emergency_drain_until = Some(startup_poll_until);
        let invariant = self.check_startup_invariant();
        self.emergency_drain_until = None;
        if !invariant {
            if self.startup_invariant_failed {
                // Ownership refusal must never annotate shared state.
                self.outcome = Outcome::StartupInvariantFailed;
            } else {
                // Unknown inventory cannot withhold own-child drainage or add
                // a second sweep behind this tick's containment attempt.
                let _ = self.platform.reap_children(startup_poll_until);
                self.emergency_drain_until = Some(startup_poll_until);
                self.cancel_emergency_tools();
                self.emergency_drain_until = None;
            }
            return;
        }
        if !self.ensure_control_socket() {
            self.emergency_drain_until = Some(Deadline(self.platform.now().saturating_add(1)));
            self.cancel_emergency_tools();
            self.emergency_drain_until = None;
            return;
        }
        self.initialize_start_storage();
        if self.storage_blocked && !self.helper_committed {
            self.retry_storage();
        }
        let own = self.platform.incarnation();
        let tools: Vec<_> = PINNED_TOOLS.iter().map(Path::new).collect();
        let overall = Deadline(self.platform.now().saturating_add(1));
        self.start_fence = platform::poll_start_fence_with_history(
            &mut self.platform,
            self.previous_helper.clone(),
            &tools,
            Path::new(CHILD_PATH),
            &[],
            &self.snapshot.image_history,
            &self.timings,
            overall,
        );
        if self.start_fence != StartFence::Closed {
            // Already swept this tick. Drain only the remaining slice, so the
            // next containment attempt cannot wait behind a second sweep.
            self.emergency_drain_until = Some(overall);
            self.cancel_emergency_tools();
            self.emergency_drain_until = None;
            return;
        }
        self.snapshot.helper = Some(own);
        self.helper_committed = self.commit_if_changed();
        if self.mode == Mode::Stuck {
            return;
        }
        // Settle the disk's entries before constructing the executable restart
        // plan. The staging reducer never dispatches its speculative plan.
        let validated = self.snapshot.validate().ok();
        #[cfg(test)]
        let validated = validated.filter(|_| self.start_fault != Some(StartFault::Validate));
        let Some(mut durable) = validated else {
            self.enter_stuck();
            return;
        };
        let boot = self.platform.boot_id();
        let entries: Vec<_> = self
            .snapshot
            .references
            .iter()
            .flatten()
            .filter(|e| reference::boot_changed(e, boot.as_ref()))
            .map(|e| e.key)
            .collect();
        if !entries.is_empty() {
            let mut accounting = Machine::restart(durable.clone());
            let clock = Clock(self.platform.now());
            for entry in &entries {
                let event = Event::ReferenceSettled {
                    entry: *entry,
                    how: ReferenceSettlement::Void,
                };
                let next = accounting.transition(event, &clock).ok();
                #[cfg(test)]
                let next = next.filter(|_| self.start_fault != Some(StartFault::Settlement));
                let Some(next) = next else {
                    self.enter_stuck();
                    return;
                };
                accounting = next;
            }
            // Keep the reducer's exact settlement semantics, but discard any
            // acquisition it only planned speculatively (no effect was exposed).
            let disk_keys = reference_keys(&durable);
            durable = accounting.durable().clone();
            if matches!(durable.reference_intent, Some(ReferenceIntent::Acquire(seq)) if !disk_keys.contains(&ReferenceEntry::Acquire(seq)))
            {
                durable.reference_intent = None;
            }
            durable
                .uncertain_acquires
                .retain(|seq| disk_keys.contains(&ReferenceEntry::Acquire(*seq)));
            let retained: Vec<_> = self
                .snapshot
                .references
                .iter()
                .flatten()
                .filter(|e| !entries.contains(&e.key))
                .cloned()
                .collect();
            self.snapshot.references = std::array::from_fn(|i| retained.get(i).cloned());
            let record = DurableRecord::try_from(&durable).ok();
            #[cfg(test)]
            let record = record.filter(|_| self.start_fault != Some(StartFault::Conversion));
            let Some(record) = record else {
                self.enter_stuck();
                return;
            };
            self.snapshot.machine = record;
            let _ = self.commit_if_changed();
            if self.mode == Mode::Stuck {
                return;
            }
        }
        let install_hold = self.install.is_none() && durable.join_intended;
        // Stuck relies on this incarnation's anchor. After a restart, rebuild
        // verified enforcement under hold and retain the error only for status.
        if install_hold
            || self.snapshot.internal_error.is_some()
                && (self.committed.machine.join_intended || self.committed.machine.leaving)
        {
            durable.hold = true;
        }
        let next = if durable.hold && self.install.is_none() {
            Machine::restart_lockdown(durable)
        } else {
            Machine::restart(durable)
        };
        self.adopt(next, &Event::Join, None);
        if self.mode == Mode::Stuck {
            return;
        }
        self.mode = if self.storage_blocked {
            Mode::PersistBlocked
        } else {
            Mode::Normal
        };
        if self.emergency_loaded {
            // Fence closure permits immediate reconciliation and fresh proof;
            // the pre-fence attempt's cadence must not delay that handoff.
            self.next_emergency = self.platform.now();
        }
        let _ = self.commit_if_changed();
        if self
            .snapshot
            .requests
            .iter()
            .any(|r| r.kind == snapshot::RequestKind::Join)
            && !self.machine.durable().join_intended
            && !self.machine.durable().leaving
            && self.snapshot.internal_error.is_none()
        {
            self.apply(Event::Join);
        }
        if !self.machine.durable().join_intended && !self.machine.durable().leaving {
            self.confirm_sweep();
        }
    }

    fn initialize_start_storage(&mut self) {
        let Some(startup) = self.startup_storage.take() else {
            return;
        };
        if let Some(copy) = startup.repair {
            let overall = Deadline(
                self.platform
                    .now()
                    .saturating_add(self.timings.command_deadline),
            );
            let absent = startup.missing[usize::from(copy == Copy::B)];
            let outcome = self.storage_write(copy, &startup.bytes, absent, overall);
            self.storage_blocked = outcome != platform::WriteOutcome::Synced;
            if self.storage_blocked && absent {
                self.repair_pending = Some((copy, startup.bytes.clone()));
            }
        }
        if startup.recovery {
            self.storage_blocked = self
                .storage_commit(&startup.bytes, 2 * self.timings.command_deadline)
                != Commit::Committed;
        }
    }

    fn ensure_control_socket(&mut self) -> bool {
        if self.control_socket_created {
            return true;
        }
        if self.platform.now() < self.next_socket {
            return false;
        }
        match self.platform.create_control_socket() {
            Ok(()) => {
                self.control_socket_created = true;
                self.startup_error = None;
                true
            }
            Err(error) => {
                self.platform
                    .report_safety(platform::SafetyEvent::SocketFailed(error.clone()));
                self.startup_error = Some(error);
                self.next_socket = self.platform.now().saturating_add(1);
                false
            }
        }
    }

    /// Inspect lifecycle state (meaningful after Starting; publication uses `status`).
    #[must_use]
    pub fn machine(&self) -> &Machine {
        &self.machine
    }
    /// Inspect pending durable content, including any tolerated N-class lag.
    #[must_use]
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    /// Current explicit mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }
    /// Borrow platform for deterministic observations and fault injection.
    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }
    /// Inspect platform oracle and call history.
    #[must_use]
    pub fn platform(&self) -> &P {
        &self.platform
    }
    /// Recover the surviving platform for a new helper incarnation.
    #[must_use]
    pub fn into_platform(self) -> P {
        self.platform
    }
    /// Number of rejected/stale inputs, never fed back as evidence.
    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected
    }
    /// True when no ready serialized work remains.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.mode != Mode::Starting
            && !self.storage_blocked
            && self.queue.is_empty()
            && self.in_flight.is_none()
            && (self.machine.pending().is_none()
                || matches!(self.machine.pending(), Some(Step::Backoff { .. })))
    }
    /// Whether a request has a committed successful outcome. Storage failure
    /// masks Join acknowledgements even if an older completed record survives.
    #[must_use]
    pub fn request_completed(&self, id: u64) -> bool {
        self.mode == Mode::Normal
            && self.committed.requests.iter().any(|request| {
                request.id == id
                    && matches!(
                        request.kind,
                        snapshot::RequestKind::JoinDone | snapshot::RequestKind::LeaveDone
                    )
            })
    }
    /// Set a positive queue bound without dropping retained inputs.
    ///
    /// # Errors
    /// Refuses zero or a bound smaller than the current queue.
    pub fn set_queue_capacity(&mut self, capacity: usize) -> Result<(), SysError> {
        if capacity == 0 || capacity < self.queue.len() {
            return Err(SysError::Failed("queue capacity"));
        }
        self.capacity = capacity;
        Ok(())
    }
    /// Retain a caller request; duplicate ids with the same kind are idempotent.
    /// Leave after independent emergency lockdown synchronously cancels/reaps
    /// tools, taking up to two command deadlines before returning.
    ///
    /// # Errors
    /// Refuses id collisions, full replay windows, and queue backpressure.
    pub fn submit(&mut self, request: Request) -> Result<(), SysError> {
        if self.lockless.is_some() {
            return Err(SysError::Failed("instance lock unavailable"));
        }
        if request.id == 0 || request.id >= snapshot::COUNTER_MAX {
            return Err(SysError::Failed("request identity"));
        }
        if request.kind == RequestKind::Join
            && (self.mode != Mode::Normal
                || self.install.is_none()
                || self.snapshot.internal_error.is_some()
                || self.machine.durable().hold
                || self.machine.durable().leaving
                || self.machine.durable().leave_requested)
        {
            return Err(SysError::Failed("join refused: run leave"));
        }
        if request.kind == RequestKind::Leave && self.mode != Mode::Starting {
            return self.accept_leave(request);
        }
        if let Some(old) = self.snapshot.requests.iter().find(|r| r.id == request.id) {
            let same = matches!(
                (request.kind, old.kind),
                (
                    RequestKind::Join,
                    snapshot::RequestKind::Join | snapshot::RequestKind::JoinDone
                ) | (
                    RequestKind::Leave,
                    snapshot::RequestKind::Leave | snapshot::RequestKind::LeaveDone
                )
            );
            return if same {
                Ok(())
            } else {
                Err(SysError::Failed("request identity collision"))
            };
        }
        if request.kind == RequestKind::Join {
            // Include queued admissions, so a successful submit cannot silently
            // lose its identity when earlier requests consume the replay window.
            if self.queue.iter().any(|event| matches!(event, QueueEvent::Request(old) if old.id == request.id && old.kind == request.kind)) {
                return Ok(());
            }
            let queued = self.queue.iter().filter(|event| matches!(event, QueueEvent::Request(old) if old.kind == RequestKind::Join)).count();
            // Reserve the eighth replay slot for Leave and the cancellations
            // of every admitted Join in the same operation.
            let active = self
                .snapshot
                .requests
                .iter()
                .filter(|record| !protocol::settled_request(record.kind))
                .count();
            if active + queued >= 7 {
                return Err(SysError::Failed("request replay window full"));
            }
        }
        self.enqueue(QueueEvent::Request(request))
    }
    /// Enqueue serialized input. Overflow discards only coalescible observations.
    ///
    /// # Errors
    /// Returns backpressure; caller retains and retries non-droppable input.
    pub fn enqueue(&mut self, event: QueueEvent) -> Result<(), SysError> {
        if self.lockless.is_some() {
            return Err(SysError::Failed("instance lock unavailable"));
        }
        if self.queue.len() >= self.capacity {
            self.overflowed = true;
            self.queue
                .retain(|e| !matches!(e, QueueEvent::Monitor(_) | QueueEvent::Timer));
            let since = self.platform.now();
            self.apply(Event::InvalidateObservations { since });
            if self.queue.len() >= self.capacity {
                return Err(SysError::Failed("queue backpressure"));
            }
        }
        self.queue.push_back(event);
        Ok(())
    }
    /// Run at most `budget` serialized boundaries; future backoffs yield.
    pub fn run_until_quiescent(&mut self, budget: usize) -> Outcome {
        for _ in 0..budget {
            if self.outcome != Outcome::Continue {
                break;
            }
            if self.lockless.is_some() {
                self.run_lockless();
                break;
            }
            if self.runnable() {
                self.retry_storage();
            }
            if self.outcome != Outcome::Continue {
                break;
            }
            if self.mode == Mode::Starting {
                self.finish_start();
                if self.outcome != Outcome::Continue {
                    break;
                }
                if self.mode == Mode::Starting {
                    // finish_start already polled inventory and drained its
                    // bounded slice. A full observe-only reap here would put
                    // another tool deadline ahead of D-3 maintenance.
                    break;
                }
            }
            if self.mode == Mode::Stuck {
                self.run_stuck();
                break;
            }
            self.run_unreservable_containment();
            // A different open family can prevent verification before the core
            // ever reaches another mutation in that family. Always poll reaping,
            // rather than relying on the same-family dispatch gate to do it.
            if self.platform.fence() != Fence::Closed
                && !(self.queue.is_empty() && self.in_flight.is_none() && self.held_emergency_due())
            {
                let d = Deadline(
                    self.platform
                        .now()
                        .saturating_add(self.timings.command_deadline.min(2)),
                );
                let _ = self.platform.reap(d);
            }
            if let Some(event) = self.queue.pop_front() {
                self.process(event);
                continue;
            }
            if self.in_flight.is_some() {
                break;
            }
            if self.run_held_emergency() {
                // Park the held reducer while independent Lockdown owns the
                // anchor. Its incompatible prefix must not replace that policy;
                // Leave revokes emergency and resumes normal cleanup.
                break;
            }
            self.retry_leave();
            self.poll_monitors();
            if !self.runnable() {
                continue;
            }
            if let Some(step) = self.machine.pending() {
                if matches!(step, Step::Backoff { until } if self.platform.now() < until) {
                    break;
                }
                if self.waiting.is_some()
                    || (self.mode == Mode::PersistBlocked
                        && step_class(step) == Class::D
                        && !matches!(step, Step::PersistLeaving | Step::ClearIntent))
                {
                    self.observe_only();
                    break;
                }
                if self.tool_blocked(step) && !self.machine.durable().leaving {
                    self.observe_only();
                    break;
                }
                self.dispatch(step);
            } else {
                break;
            }
        }
        self.outcome
    }
    fn process(&mut self, event: QueueEvent) {
        match event {
            QueueEvent::Request(r) => {
                if r.kind == RequestKind::Leave {
                    let _ = self.accept_leave(r);
                    return;
                }
                if self.mode != Mode::Normal
                    || self.install.is_none()
                    || self.snapshot.internal_error.is_some()
                    || self.machine.durable().hold
                    || self.machine.durable().leaving
                    || self.machine.durable().leave_requested
                {
                    return;
                }
                if self.snapshot.requests.iter().any(|p| p.id == r.id) {
                    return;
                }
                if self
                    .push_request(
                        RequestRecord {
                            id: r.id,
                            kind: snapshot::RequestKind::Join,
                        },
                        false,
                    )
                    .is_err()
                {
                    return;
                }
                self.left_verified = false;
                self.emergency_revoked = false;
                self.leave_delay = 0;
                self.next_leave = 0;
                self.apply(Event::Join);
            }
            QueueEvent::Monitor(event) => match event {
                Event::Leave => self.feed_leave(),
                Event::Repair(_)
                | Event::ChildDied
                | Event::InvalidateObservations { .. }
                | Event::PfEnabledObserved { .. }
                | Event::Observed { .. }
                | Event::Handshake { .. } => self.apply(event),
                _ => self.rejected += 1, // Collector input cannot manufacture completions/accounting.
            },
            QueueEvent::Timer => {
                if !self.run_held_emergency() {
                    self.poll_monitors();
                }
            }
            QueueEvent::Completion(c) => self.complete(c),
        }
    }
    fn complete(&mut self, c: Completion) {
        let Some((id, step)) = self.in_flight else {
            self.rejected += 1;
            return;
        };
        if id != c.dispatch {
            self.rejected += 1;
            return;
        }
        self.in_flight = None;
        let retained = c.clone();
        let clock = Clock(self.platform.now());
        if let Ok(next) = self.machine.transition(c.event.clone(), &clock) {
            let old_machine = self.machine.clone();
            let old_snapshot = self.snapshot.clone();
            self.adopt(next, &c.event, c.acquired);
            if !self.runnable() {
                self.retained_completion = Some((step, retained));
                return;
            }
            let commit_only = step_class(step) == Class::D && step != Step::AcquireReference;
            if step == Step::ClearIntent && matches!(c.event, Event::Completed(Step::ClearIntent)) {
                // Removing a probe's policy over trusted Left is not an
                // authorized Leave and must not clear a durable internal error.
                if !self.containment_cleanup_only {
                    self.snapshot.internal_error = None;
                    self.complete_leave_requests();
                }
            }
            let before_storage = self.machine.context();
            let committed = self.commit_if_changed();
            if commit_only
                && !committed
                && !matches!(step, Step::PersistLeaving | Step::ClearIntent)
            {
                self.waiting = Some((self.machine.clone(), self.snapshot.clone()));
                self.machine = self.carry_storage_observation(old_machine, before_storage);
                self.snapshot = old_snapshot;
                return;
            }
            if step == Step::ClearIntent && matches!(c.event, Event::Completed(Step::ClearIntent)) {
                self.left_verified =
                    !self.containment_cleanup_only || self.snapshot.internal_error.is_none();
                if self.containment_cleanup_only {
                    self.emergency_last_load_at = None;
                    self.emergency_loaded = false;
                    self.emergency_proof = None;
                }
                self.containment_cleanup_only = false;
                self.leave_item = None;
            }
            if matches!(c.event, Event::Failed(_)) && self.machine.durable().leaving {
                if step != Step::ClearIntent {
                    self.leave_item = Some(cleanup_item(step));
                }
                self.leave_unknown |= matches!(c.event, Event::Failed(Reason::Unknown { .. }));
            }
            if let Some(sequence) = c.not_started {
                self.apply(Event::ReferenceSettled {
                    entry: ReferenceEntry::Acquire(sequence),
                    how: ReferenceSettlement::Void,
                });
            }
            if step == Step::ReconcileReference && self.machine.durable().join_intended {
                // Settlement changes acquisition context. Refresh after the final
                // summary, never from a round started before the last settlement.
                self.next_full = 0;
                let _ = self.enqueue(QueueEvent::Timer);
            }
            if matches!(
                c.event,
                Event::Observed {
                    verdict: Verdict::Protected(_),
                    ..
                }
            ) {
                self.overflowed = false;
            }
        } else {
            self.rejected_completion();
            if self.mode == Mode::Stuck {
                self.retained_completion = Some((step, retained));
            }
        }
    }
    #[allow(clippy::needless_pass_by_value)] // Own queued events, retaining a reference for evidence updates.
    fn apply(&mut self, event: Event) {
        if !self.runnable() {
            return;
        }
        if matches!(event, Event::ReferenceSettled { .. }) && !self.freeing_allowed() {
            self.rejected += 1;
            return;
        }
        self.invalidate_blocking(&event);
        let clock = Clock(self.platform.now());
        self.cancel_storage_wait_for_safety(&event, clock);
        if !self.runnable() {
            return;
        }
        if let Ok(next) = self.machine.transition(event.clone(), &clock) {
            self.adopt(next, &event, None);
            if self.runnable() {
                let _ = self.commit_if_changed();
            }
        } else {
            self.rejected += 1;
            if let Ok(next) = self
                .machine
                .transition(Event::InvalidateObservations { since: clock.0 }, &clock)
            {
                self.adopt(
                    next,
                    &Event::InvalidateObservations { since: clock.0 },
                    None,
                );
            }
        }
    }

    fn rejected_completion(&mut self) {
        if !self.runnable() {
            return;
        }
        let event = Event::Failed(Reason::Observation("rejected completion"));
        let next = self
            .machine
            .transition(event.clone(), &Clock(self.platform.now()))
            .ok();
        #[cfg(test)]
        let next = if self.reject_fallback { None } else { next };
        if let Some(next) = next {
            self.adopt(next, &event, None);
            let _ = self.commit_if_changed();
        } else {
            self.enter_stuck();
        }
    }
    fn adopt(&mut self, mut next: Machine, event: &Event, acquired: Option<RefEvidence>) {
        self.invalidate_blocking(event);
        // A speculative core reservation is not durable ownership. Unknown boot
        // must skip it before either the snapshot or the ioctl can expose it.
        if let Some(ReferenceIntent::Acquire(seq)) = next.durable().reference_intent
            && !self
                .snapshot
                .references
                .iter()
                .flatten()
                .any(|entry| entry.key == ReferenceEntry::Acquire(seq))
            && self.platform.boot_id().is_none()
        {
            next = next.defer_unstarted_acquisition(&Clock(self.platform.now()));
        }
        let mut evidence: Vec<_> = self.snapshot.references.iter().flatten().cloned().collect();
        match event {
            Event::ReferenceSettled { entry, .. } => evidence.retain(|e| e.key != *entry),
            Event::ReferenceAcquiredFor { sequence, token } => {
                self.emergency_needs_reference = false;
                // Kernel token values recur after disable/release. The core
                // retains the existing Token key when a new acquisition returns
                // that number; replace its annotation, not the accounting key.
                let reused = evidence
                    .iter()
                    .any(|e| e.key == ReferenceEntry::Token(*token));
                if reused {
                    evidence.retain(|e| e.key != ReferenceEntry::Acquire(*sequence));
                }
                if let Some(e) = evidence.iter_mut().find(|e| {
                    e.key
                        == if reused {
                            ReferenceEntry::Token(*token)
                        } else {
                            ReferenceEntry::Acquire(*sequence)
                        }
                }) {
                    e.key = ReferenceEntry::Token(*token);
                    e.release_unknown = false;
                    e.fingerprint = acquired.and_then(|e| e.fingerprint);
                }
            }
            _ => {}
        }
        if let Some(ReferenceIntent::Acquire(seq)) = next.durable().reference_intent
            && !evidence
                .iter()
                .any(|e| e.key == ReferenceEntry::Acquire(seq))
        {
            evidence.push(RefEvidence {
                key: ReferenceEntry::Acquire(seq),
                boot: self.platform.boot_id(),
                release_unknown: false,
                fingerprint: None,
            });
        }
        let keys = reference_keys(next.durable());
        if evidence.len() != keys.len()
            || keys
                .iter()
                .any(|key| !evidence.iter().any(|e| e.key == *key))
        {
            self.enter_stuck();
            return;
        }
        self.snapshot.references = std::array::from_fn(|i| {
            keys.get(i)
                .and_then(|key| evidence.iter().find(|e| e.key == *key).cloned())
        });
        self.machine = next;
        self.adopted = true;
        let clock = Clock(self.platform.now());
        if let Verdict::Protected(proof) = self.machine.enforcement_at(&clock) {
            self.last_fresh_proof_at = Some(proof.verified_at());
        }
        self.verified_enforcement |= self.machine.blocking_verified_at(&clock)
            || matches!(self.machine.enforcement_at(&clock), Verdict::Protected(_));
        if matches!(self.machine.enforcement_at(&Clock(self.platform.now())), Verdict::Protected(ref p) if p.kind() == Kind::Installed(Form::Joined))
        {
            self.finish_join_requests();
        }
        self.refresh_snapshot();
    }
    fn refresh_snapshot(&mut self) {
        // Observation timestamps are volatile, including reference/cleanup errors.
        // Persist Unknown's category so identical retries do not sync both copies.
        let mut durable = self.machine.durable().clone();
        for reason in [
            &mut durable.last_error,
            &mut durable.enforcement_error,
            &mut durable.reference_error,
        ]
        .into_iter()
        .flatten()
        .chain(durable.cleanup_errors.iter_mut().map(|(_, r)| r))
        {
            if let Reason::Unknown { since } = reason {
                *since = 0;
            }
        }
        // Do not feed reference debt back through the legacy enforcement-error
        // migration on restart. Normalise first, then strip the duplicate mirror.
        if durable.last_error == durable.reference_error {
            durable.last_error = None;
        }
        let record = DurableRecord::try_from(&durable).ok();
        #[cfg(test)]
        let record = record.filter(|_| self.start_fault != Some(StartFault::Refresh));
        match record {
            Some(durable) => self.snapshot.machine = durable,
            None => self.enter_stuck(),
        }
    }
    fn commit_if_changed(&mut self) -> bool {
        self.commit_if_changed_with_budget(2 * self.timings.command_deadline)
    }
    fn commit_if_changed_with_budget(&mut self, budget: u64) -> bool {
        if self.snapshot.validate().is_err() {
            self.enter_stuck();
            return false;
        }
        if self.storage_blocked && self.platform.now() < self.next_storage {
            return false;
        }
        if !self.storage_blocked && self.snapshot == self.committed {
            return true;
        }
        let Some(seq) = self
            .seq
            .checked_add(1)
            .filter(|s| *s < snapshot::COUNTER_MAX)
        else {
            self.enter_stuck();
            return false;
        };
        let bytes = snapshot::encode(seq, &self.snapshot).ok();
        #[cfg(test)]
        let bytes = bytes.filter(|_| self.start_fault != Some(StartFault::Encode));
        let Some(bytes) = bytes else {
            self.enter_stuck();
            return false;
        };
        if self.storage_commit(&bytes, budget) != Commit::Committed {
            self.emergency_commit_failed |= self.mode == Mode::Stuck;
            self.block_storage();
            return false;
        }
        self.seq = seq;
        self.committed = self.snapshot.clone();
        self.storage_blocked = false;
        self.missing_storage = false;
        self.storage_delay = 0;
        self.helper_committed = self.snapshot.helper.is_some();
        if self.mode == Mode::PersistBlocked {
            self.mode = Mode::Normal;
        }
        true
    }
    /// Slice safety-sensitive storage waits, including while a live proof keeps
    /// the current policy. Cheap negative observations revoke that exemption.
    fn safety_storage_deadline(&mut self, budget: u64) -> Deadline {
        let now = self.platform.now();
        let protecting = (self.machine.durable().join_intended
            || self.snapshot.machine.join_intended
            || self.committed.machine.join_intended)
            && self.containment_allowed()
            && !self.startup_invariant_failed
            && (matches!(
                self.mode,
                Mode::Starting | Mode::Stuck | Mode::PersistBlocked
            ) || self.lockless.is_some()
                || self.emergency_loaded);
        if protecting {
            let exempt = self.storage_proof_exemption(now);
            if !exempt && now >= self.next_emergency && self.emergency_is_stateless() {
                self.attempt_stateless_containment();
                self.next_emergency = self.platform.now().saturating_add(1);
            }
            let now = self.platform.now();
            debug_assert!(self.next_emergency <= now.saturating_add(1));
            return Deadline(
                now.saturating_add(budget.min(1))
                    .min(if self.next_emergency > now {
                        self.next_emergency
                    } else {
                        now.saturating_add(1)
                    }),
            );
        }
        Deadline(now.saturating_add(budget))
    }

    fn storage_proof_exemption(&mut self, now: u64) -> bool {
        if !self.current_blocking_verified(now) || self.unreaped_pfctl() != 0 {
            return false;
        }
        let d = self.deadline();
        if let Ok(cheap) = self.platform.cheap_check(self.child.as_ref(), d)
            && (!cheap.pf_enabled || !cheap.anchor_present)
        {
            self.verified_enforcement = false;
            self.emergency_proof = None;
            // Observe loss without recursively committing or changing the
            // snapshot whose encoded bytes are already being written. The next
            // normal reducer boundary refreshes its durable status fields.
            let event = Event::InvalidateObservations { since: now };
            if let Ok(next) = self.machine.transition(event, &Clock(now)) {
                self.machine = next;
            }
            self.next_emergency = now;
            return false;
        }
        let now = self.platform.now();
        self.current_blocking_verified(now) && self.unreaped_pfctl() == 0
    }

    /// Saved/speculative reducers must inherit observations made while their
    /// snapshot commit waited. Never restore a pre-loss proof at the handoff.
    fn carry_storage_observation(&mut self, machine: Machine, before: verify::Context) -> Machine {
        if self.machine.context() == before {
            return machine;
        }
        let now = self.platform.now();
        let event = Event::InvalidateObservations {
            since: self.machine.gap_after().unwrap_or(now),
        };
        // Pure invalidation is accepted at every boundary. If an invariant ever
        // rejects it, retain the already-invalidated current reducer.
        machine
            .transition(event, &Clock(now))
            .unwrap_or_else(|_| self.machine.clone())
    }

    fn current_blocking_verified(&self, now: u64) -> bool {
        self.containment_allowed()
            && self.verified_enforcement
            && (self.machine.blocking_verified_at(&Clock(now))
                || matches!(
                    self.machine.enforcement_at(&Clock(now)),
                    Verdict::Protected(_)
                )
                || self.emergency_proof.as_ref().is_some_and(|proof| {
                    proof.kind() != Kind::Lockdown
                        && matches!(
                            Verdict::Protected(proof.clone()).at(&Clock(now)),
                            Verdict::Protected(_)
                        )
                }))
    }

    /// Poll the same read until its original total budget expires. A timeout
    /// abandons only the read result, never starts a replacement inside a slice.
    fn storage_read<T>(
        &mut self,
        budget: u64,
        contain: bool,
        mut poll: impl FnMut(&mut P, Deadline) -> std::task::Poll<T>,
    ) -> Option<T> {
        let overall = Deadline(self.platform.now().saturating_add(budget));
        let was_waiting = self.storage_waiting;
        loop {
            let d = if contain {
                self.safety_storage_deadline(budget)
            } else {
                overall
            };
            let d = Deadline(d.0.min(overall.0));
            if let std::task::Poll::Ready(result) = poll(&mut self.platform, d) {
                self.storage_waiting = was_waiting;
                return Some(result);
            }
            if self.platform.now() >= overall.0 {
                self.platform.abandon_storage_read();
                self.storage_waiting = was_waiting;
                return None;
            }
            self.storage_waiting = true;
        }
    }

    fn storage_write(
        &mut self,
        copy: Copy,
        bytes: &[u8; snapshot::COPY_BYTES],
        create: bool,
        overall: Deadline,
    ) -> platform::WriteOutcome {
        let d = self.safety_storage_deadline(self.timings.command_deadline);
        let d = Deadline(d.0.min(overall.0));
        let mut outcome = if create {
            self.platform.create_copy(copy, bytes, d)
        } else {
            self.platform.write_copy(copy, bytes, d)
        };
        let was_waiting = self.storage_waiting;
        while outcome == platform::WriteOutcome::TimedOut && self.platform.now() < overall.0 {
            self.storage_waiting = true;
            let d = self.safety_storage_deadline(self.timings.command_deadline);
            outcome = self.platform.wait_write(Deadline(d.0.min(overall.0)));
        }
        self.storage_waiting = was_waiting;
        outcome
    }

    fn storage_commit(&mut self, bytes: &[u8; snapshot::COPY_BYTES], budget: u64) -> Commit {
        let overall = Deadline(self.platform.now().saturating_add(budget));
        for copy in [Copy::A, Copy::B] {
            let copy_deadline = Deadline(
                overall.0.min(
                    self.platform
                        .now()
                        .saturating_add(self.timings.command_deadline),
                ),
            );
            if self.storage_write(copy, bytes, false, copy_deadline)
                != platform::WriteOutcome::Synced
            {
                return Commit::Failed {
                    after_a: copy == Copy::B,
                };
            }
        }
        Commit::Committed
    }

    fn deadline(&mut self) -> Deadline {
        Deadline(
            self.platform
                .now()
                .saturating_add(self.timings.command_deadline),
        )
    }
    fn confirm_sweep(&mut self) -> bool {
        let overall = self.deadline();
        let pins: Vec<_> = PINNED_TOOLS.iter().map(Path::new).collect();
        let swept = platform::sweep_with_history(
            &mut self.platform,
            Path::new(CHILD_PATH),
            &[],
            &self.snapshot.image_history,
            &pins,
            &self.timings,
            overall,
        );
        let ok = swept == Sweep::Swept;
        self.last_sweep = if ok { None } else { Some(swept) };
        ok
    }
    fn tool_blocked(&mut self, step: Step) -> bool {
        let family = tool_family(step);
        match self.platform.fence() {
            Fence::Closed => false,
            Fence::Open(children) => {
                family.is_some_and(|family| children.iter().any(|c| c.tool == family))
            }
        }
    }
    fn inputs(&self) -> Result<Inputs, SysError> {
        let old = &self
            .install
            .as_ref()
            .ok_or(SysError::Failed("install record unreadable"))?
            .config
            .inputs;
        let generation = self
            .machine
            .durable()
            .previous_generation
            .map_or(1, TunnelGeneration::value);
        let tunnel = self.machine.tunnel().cloned().unwrap_or(Tunnel {
            name: old.tunnel().name.clone(),
            generation: TunnelGeneration::new(generation)
                .map_err(|_| SysError::Failed("generation"))?,
        });
        Inputs::new(
            old.selected().clone(),
            old.endpoint().clone(),
            old.physical().clone(),
            tunnel,
            old.hop_limit().clone(),
        )
        .map_err(|_| SysError::Failed("policy inputs"))
    }
    fn status_emergency_verified(&self, clock: Clock, fence: &Fence) -> bool {
        self.containment_allowed()
            && *fence == Fence::Closed
            && self.start_fence == StartFence::Closed
            && self.emergency_proof.as_ref().is_some_and(|p| {
                p.kind() == Kind::Lockdown
                    && matches!(
                        Verdict::Protected(p.clone()).at(&clock),
                        Verdict::Protected(_)
                    )
            })
    }

    /// Read status at the consumer's current time, masking stale/foreign proofs.
    #[allow(clippy::too_many_lines)] // Keep all publication evidence gates together.
    pub fn status(&mut self) -> Status {
        let clock = Clock(self.platform.now());
        let mutation_fence = self.platform.fence();
        let enforcement = if self.mode == Mode::Stuck {
            Verdict::NotProtected(Reason::Observation(if self.startup_invariant_failed {
                "containment may be loaded; not maintained"
            } else {
                "internal"
            }))
        } else if self.mode == Mode::PersistBlocked {
            let d = self.deadline();
            let disabled = self.platform.pf_info(d) == platform::PfInfo::Disabled;
            Verdict::NotProtected(Reason::Observation(if self.missing_storage {
                "storage missing: reinstall"
            } else if disabled {
                "storage failing; pf reference cannot be reserved"
            } else {
                "storage failing"
            }))
        } else if self.mode == Mode::Starting || !self.helper_committed {
            Verdict::NotProtected(Reason::Observation("engine: start fence open"))
        } else if mutation_fence != Fence::Closed || self.last_sweep.is_some() {
            Verdict::NotProtected(Reason::Observation("engine: mutation fence or survivors"))
        } else if self.overflowed {
            Verdict::NotProtected(Reason::Observation("queue overflow"))
        } else if self.snapshot.internal_error.is_some() {
            Verdict::NotProtected(Reason::Observation("internal"))
        } else {
            match self.machine.enforcement_at(&clock) {
                Verdict::Protected(p) if p.context() != self.machine.context() => {
                    Verdict::Unknown { since: clock.0 }
                }
                verdict => verdict,
            }
        };
        let mut accounting = Accounting::default();
        for e in self
            .snapshot
            .references
            .iter()
            .flatten()
            .filter(|_| self.stuck_accounting.is_empty())
            .chain(self.stuck_accounting.iter())
        {
            match e.key {
                ReferenceEntry::Token(_) => accounting.held += 1,
                ReferenceEntry::Acquire(_) => accounting.uncertain += 1,
            }
            accounting.release_unknown += usize::from(e.release_unknown);
        }
        let text = if self.startup_invariant_failed {
            "misconfiguration: helper must be owned by launchd; containment may be loaded; not maintained; Leave refused".into()
        } else if self.left_verified && mutation_fence != Fence::Closed {
            "leaving: fence open".into()
        } else if self.left_verified {
            if self.storage_blocked
                || self.mode == Mode::Stuck && self.snapshot.internal_error.is_some()
                || self.committed.machine.join_intended
                || self.committed.machine.leaving
            {
                "left (not durable)".into()
            } else if self.snapshot.endpoint.is_none() && self.install.is_none() {
                "left (endpoint route not checked)".into()
            } else {
                "left".into()
            }
        } else if self.machine.durable().leaving
            || self.machine.durable().leave_requested
            || self.stuck_leave.is_some()
        {
            format!("leaving: {}", self.leave_item.unwrap_or("cleanup"))
        } else if self.emergency_last_load_at.is_some()
            && !matches!(&enforcement, Verdict::Protected(_))
            && !self.status_emergency_verified(clock, &mutation_fence)
        {
            "containment attempted; safety unproven".into()
        } else if self.snapshot.internal_error.is_some() || self.machine.durable().hold {
            "state untrusted: run leave".into()
        } else {
            match &enforcement {
                Verdict::Protected(_) => self.machine.status_text_at(&clock),
                Verdict::NotProtected(reason) => format!("not protected: {reason}"),
                Verdict::Repair(action) => format!("not protected: repair required ({action:?})"),
                Verdict::Unknown { since } => {
                    format!("not protected: enforcement unknown since {since}")
                }
                Verdict::NeverVerified => "not protected: never verified".into(),
            }
        };
        Status {
            enforcement,
            text,
            blocking_verified: self.containment_allowed()
                && mutation_fence == Fence::Closed
                && self.verified_enforcement
                && !self.overflowed
                && (self.machine.blocking_verified_at(&clock)
                    || self.emergency_proof.as_ref().is_some_and(|p| {
                        p.kind() != Kind::Lockdown
                            && matches!(
                                Verdict::Protected(p.clone()).at(&clock),
                                Verdict::Protected(_)
                            )
                    })),
            emergency_blocking_verified: self.status_emergency_verified(clock, &mutation_fence),
            blocking_expires_at: if self.machine.blocking_verified_at(&clock) {
                self.machine
                    .last_verified()
                    .map(|at| at.saturating_add(self.timings.max_age))
            } else {
                self.emergency_proof
                    .as_ref()
                    .filter(|p| p.kind() != Kind::Lockdown)
                    .map(verify::Proof::expires_at)
            },
            emergency_expires_at: self
                .emergency_proof
                .as_ref()
                .filter(|p| p.kind() == Kind::Lockdown)
                .map(verify::Proof::expires_at),
            endpoint_unknown: self.snapshot.endpoint.is_none() && self.install.is_none(),
            accounting,
            mode: self.mode,
            start_fence: self.start_fence.clone(),
            mutation_fence,
            sweep: self.last_sweep.clone(),
        }
    }
}
fn reference_keys(d: &Durable) -> Vec<ReferenceEntry> {
    d.pf_reference
        .into_iter()
        .map(ReferenceEntry::Token)
        .chain(
            d.older_references
                .iter()
                .copied()
                .map(ReferenceEntry::Token),
        )
        .chain(
            d.uncertain_acquires
                .iter()
                .copied()
                .map(ReferenceEntry::Acquire),
        )
        .chain(match d.reference_intent {
            Some(ReferenceIntent::Acquire(seq)) => Some(ReferenceEntry::Acquire(seq)),
            _ => None,
        })
        .collect()
}
fn tool_family(step: Step) -> Option<Tool> {
    match step {
        Step::AcquireReference
        | Step::ReleaseReference
        | Step::ReconcileReference
        | Step::LoadPreTunnel
        | Step::LoadJoined
        | Step::ReplaceAnchor(_)
        | Step::RemoveAnchor
        | Step::FlushStates
        | Step::RemoveVanishedInterfaceStates => Some(Tool::Pfctl),
        Step::ConfigureEndpointRoute | Step::ConfigureSplitRoutes | Step::CleanupRoutes => {
            Some(Tool::Route)
        }
        Step::ConfigureDns | Step::CleanupDns => Some(Tool::Scutil),
        Step::ConfigureAddresses | Step::ConfigureMtu => Some(Tool::Ifconfig),
        _ => None,
    }
}

fn cleanup_item(step: Step) -> &'static str {
    match step {
        Step::StopChild => "owned process",
        Step::CleanupRoutes => "routes",
        Step::CleanupDns => "DNS key",
        Step::CleanupArtifacts => "artifacts",
        Step::RemoveAnchor => "anchor",
        Step::ClearIntent => "connectivity verification",
        _ => "cleanup",
    }
}
