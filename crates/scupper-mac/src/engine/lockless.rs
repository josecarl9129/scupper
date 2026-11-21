//! Best-effort stateless blocking while a structural lock failure is retried.
use super::{
    Copy, CopyClass, Deadline, Engine, Fence, Mode, Platform, Snapshot, StartDecision,
    StartupStorage, SysError, platform, snapshot,
};

pub(super) struct Fallback {
    next_lock: u64,
    delay: u64,
    acquired: bool,
    drain_deadline: Option<u64>,
}

impl<P: Platform> Engine<P> {
    pub(super) fn start_lockless(mut platform: P, error: SysError) -> Self {
        platform.report_safety(platform::SafetyEvent::LockFailed(error));
        let now = platform.now();
        Self::start_selected_inner(
            platform,
            None,
            StartDecision::Recovery {
                seq: 1,
                helper: None,
            },
            [false, false],
            Some(Fallback {
                next_lock: now.saturating_add(1),
                delay: 1,
                acquired: false,
                drain_deadline: None,
            }),
            false,
        )
    }

    pub(super) fn run_lockless(&mut self) {
        let Some(mut fallback) = self.lockless.take() else {
            return;
        };
        let now = self.platform.now();
        if !fallback.acquired && now >= fallback.next_lock {
            let mut interrupts = 0;
            loop {
                match self.platform.acquire_instance_lock() {
                    Ok(()) => {
                        fallback.acquired = true;
                        if !self.emergency_loaded {
                            // The locked handoff must attempt containment before
                            // waiting on a failed fallback load's own children.
                            self.emergency_next_reload = self.platform.now();
                        }
                        break;
                    }
                    Err(platform::InstanceLockError::Interrupted) => {
                        interrupts += 1;
                        if interrupts >= 8 {
                            self.platform
                                .report_safety(platform::SafetyEvent::LockFailed(
                                    SysError::Unknown,
                                ));
                            fallback.delay = (fallback.delay * 2).min(5);
                            fallback.next_lock = self.platform.now().saturating_add(fallback.delay);
                            break;
                        }
                    }
                    Err(platform::InstanceLockError::Contended) => {
                        // No signalling authority without the lock. Give our own
                        // tools their normal deadline to finish before exiting.
                        let d = self.deadline();
                        let _ = self.platform.reap(d);
                        self.outcome = super::Outcome::InstanceContended;
                        self.lockless = Some(fallback);
                        return;
                    }
                    Err(platform::InstanceLockError::Failed(error)) => {
                        self.platform
                            .report_safety(platform::SafetyEvent::LockFailed(error));
                        fallback.delay = (fallback.delay * 2).min(5);
                        fallback.next_lock = self.platform.now().saturating_add(fallback.delay);
                        break;
                    }
                }
            }
        }
        if fallback.acquired {
            // Keep containment alive while draining. With the lock retained,
            // exact own tools may be killed after their normal tool deadline.
            let drain_deadline = *fallback.drain_deadline.get_or_insert_with(|| {
                self.platform
                    .now()
                    .saturating_add(self.timings.command_deadline)
            });
            self.lockless = Some(fallback);
            if (!self.emergency_loaded || self.platform.now() >= self.next_emergency)
                && lockless_intent(&mut self.platform)
            {
                let verdict = self.load_emergency();
                self.platform
                    .report_safety(platform::SafetyEvent::LocklessVerdict(Box::new(verdict)));
                self.next_emergency = self.platform.now().saturating_add(1);
            }
            // Poll in one-second slices so Lockdown maintenance continues
            // throughout the normal tool deadline, rather than waiting behind it.
            let d = Deadline(self.platform.now().saturating_add(1).min(drain_deadline));
            if self.platform.reap(d) == Fence::Closed
                || self.platform.now() >= drain_deadline && self.cancel_emergency_tools()
            {
                self.lockless = None;
                let contain =
                    self.emergency_last_load_at.is_some() || lockless_intent(&mut self.platform);
                self.resume_locked_start(contain);
            }
            return;
        }
        if now >= self.next_emergency {
            let block = lockless_intent(&mut self.platform);
            self.lockless = Some(fallback);
            if block {
                // Maintenance must not wait behind a previous own writer.
                let verdict = self.load_emergency();
                self.platform
                    .report_safety(platform::SafetyEvent::LocklessVerdict(Box::new(verdict)));
            }
            // Tool calls include their normal timeout. Only exact children
            // still parented to this incarnation may be cancelled lockless,
            // including after a new read-only probe finds Left.
            self.cancel_lockless_tools();
            self.next_emergency = self.platform.now().saturating_add(1);
        } else {
            self.lockless = Some(fallback);
        }
    }

    fn cancel_lockless_tools(&mut self) {
        let d = Deadline(self.platform.now().saturating_add(1));
        if let Fence::Open(tools) = self.platform.fence()
            && let platform::Enumeration::Complete(procs) = self.platform.processes(d)
        {
            let own = self.platform.incarnation();
            for tool in tools {
                if let Some(proc) = procs.iter().find(|proc| {
                    proc.pid == tool.pid && proc.ppid == own.pid && proc.pgid == own.pgid
                }) {
                    let _ = self.platform.kill_process(proc.pid, proc.start, d);
                }
            }
        }
        let _ = self.platform.reap(d);
    }

    /// Keep the three-attempt policy and full per-attempt budget, with D-3
    /// maintenance between slices of the same read as well as between retries.
    fn read_locked_copy(&mut self, copy: Copy, contain: bool) -> snapshot::CopyRead {
        for attempt in 0..3 {
            let read = self
                .storage_read(self.timings.command_deadline, contain, |p, d| {
                    p.poll_copy(copy, d)
                })
                .unwrap_or(snapshot::CopyRead::Unreadable);
            if read != snapshot::CopyRead::Unreadable || attempt == 2 {
                return read;
            }
            let d = if contain {
                self.safety_storage_deadline(1)
            } else {
                Deadline(self.platform.now().saturating_add(1))
            };
            self.platform
                .pause(std::time::Duration::from_millis(100), d);
        }
        snapshot::CopyRead::Unreadable
    }

    #[allow(clippy::too_many_lines)] // Keep selection, provenance and durable cleanup handoff together.
    pub(super) fn resume_locked_start(&mut self, contain: bool) {
        self.install = self
            .storage_read(5, contain, Platform::poll_install_record)
            .and_then(Result::ok);
        self.timings = self
            .install
            .as_ref()
            .map_or_else(platform::Timings::default, |r| r.config.timings);
        let a = snapshot::classify_copy(self.read_locked_copy(Copy::A, contain));
        let b = snapshot::classify_copy(self.read_locked_copy(Copy::B, contain));
        let missing = [matches!(a, CopyClass::M), matches!(b, CopyClass::M)];
        let (seq, mut state, repair, recovery) = match snapshot::decide(a, b) {
            StartDecision::Trust {
                seq,
                snapshot,
                repair,
                ..
            } => (seq, snapshot, repair, false),
            StartDecision::Recovery { seq, helper } => (
                seq,
                Snapshot::recovery(
                    self.platform.boot_id(),
                    self.install
                        .as_ref()
                        .map(|r| super::execute::endpoint(&r.config.inputs)),
                    self.install.as_ref().map(|r| r.owner_uid),
                    helper,
                ),
                None,
                true,
            ),
        };
        let committed = state.clone();
        state.image_history.observe_boot(self.platform.boot_id());
        self.previous_helper = match state.helper.clone() {
            Some(helper) => platform::PreviousHelper::Known(helper),
            None if recovery || state.machine.hold => platform::PreviousHelper::Unknown,
            None => platform::PreviousHelper::None,
        };
        self.startup_storage = snapshot::encode(seq, &state)
            .ok()
            .filter(|_| repair.is_some() || recovery)
            .map(|bytes| StartupStorage {
                repair,
                recovery,
                bytes,
                missing,
            });
        self.seq = seq;
        self.snapshot = state.clone();
        self.committed = committed;
        let mut staging_failed = false;
        // Read-only uncertainty may have installed Lockdown over durable
        // Left. Once locked and fenced, normal Leave must remove our policy.
        // This is only staged in memory here; ownership still gates writes.
        if self.emergency_last_load_at.is_some() && !self.snapshot.machine.join_intended {
            let remove = snapshot::StepRecord::from(super::Step::RemoveAnchor);
            // A crash can persist probe-only Leave staging before removal.
            // Its anchor-only tail has no admitted Leave request; preserve the
            // internal error when resuming that tail in a new incarnation.
            if self.snapshot.internal_error.is_some()
                && !self
                    .snapshot
                    .requests
                    .iter()
                    .any(|request| request.kind == snapshot::RequestKind::Leave)
                && self
                    .snapshot
                    .machine
                    .pending_cleanup
                    .iter()
                    .all(|step| *step == remove)
            {
                self.containment_cleanup_only = true;
            }
            let clock = super::Clock(self.platform.now());
            let machine = &mut self.snapshot.machine;
            if machine.leaving || machine.leave_requested {
                if !machine.leaving {
                    // Derive the pre-PersistLeaving plan from the core itself.
                    // Only stage these cleanup facts; speculative restart
                    // accounting must not replace the snapshot's evidence.
                    let staged = machine
                        .to_core()
                        .ok()
                        .and_then(|durable| {
                            super::Machine::restart(durable)
                                .transition(
                                    super::Event::Completed(super::Step::PersistLeaving),
                                    &clock,
                                )
                                .ok()
                        })
                        .and_then(|next| snapshot::DurableRecord::try_from(next.durable()).ok());
                    #[cfg(test)]
                    let staged =
                        staged.filter(|_| self.start_fault != Some(super::StartFault::Staging));
                    if let Some(staged) = staged {
                        machine.leaving = staged.leaving;
                        machine.pending_cleanup = staged.pending_cleanup;
                    } else {
                        staging_failed = true;
                    }
                }
                // Durable Leave owns its entire remaining cleanup plan.
                if !staging_failed && !machine.pending_cleanup.contains(&remove) {
                    let mut cleanup = machine.pending_cleanup.to_vec();
                    cleanup.push(remove);
                    if let Ok(cleanup) = cleanup.try_into() {
                        machine.pending_cleanup = cleanup;
                    }
                }
            } else if machine.pending_cleanup.is_empty() {
                self.containment_cleanup_only = true;
                machine.leave_requested = true;
                machine.leaving = true;
                if let Ok(cleanup) = vec![remove].try_into() {
                    machine.pending_cleanup = cleanup;
                }
            }
        }
        self.missing_storage = missing == [true, true];
        self.mode = Mode::Starting;
        // The input-free policy is still our successful load. Retain that
        // installation knowledge, but require fresh fenced verification.
        self.emergency_baseline = None;
        self.emergency_states_clean_at = None;
        self.emergency_next_flush = self.platform.now();
        self.emergency_next_reload = self.platform.now();
        self.emergency_enable_pending = false;
        if staging_failed || self.snapshot.validate().is_err() {
            self.enter_stuck();
        } else {
            self.finish_start();
        }
    }
}

pub(super) fn lockless_intent<P: Platform>(platform: &mut P) -> bool {
    let d = Deadline(platform.now().saturating_add(1));
    let a = snapshot::classify_copy(platform.read_copy(Copy::A, d));
    // Both read-only copies share one budget; unavailable intent must not put
    // a second read timeout ahead of the first best-effort lockdown.
    let b = snapshot::classify_copy(platform.read_copy(Copy::B, d));
    !matches!((a, b),
        (CopyClass::V { seq: a_seq, bytes: a, snapshot, .. }, CopyClass::V { seq: b_seq, bytes: b, .. })
        if a_seq == b_seq && a == b && !snapshot.machine.join_intended
            && !snapshot.machine.leaving && !snapshot.machine.leave_requested
            && !snapshot.machine.hold
            && snapshot.internal_error.is_none())
}
