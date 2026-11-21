//! Persistence retry, connectivity verification and the fixed internal-error exit.
use super::{
    CHILD_PATH, Class, Clock, Durable, DurableRecord, Engine, Enumeration, Event, Fence, Mode,
    Outcome, Path, Platform, QueueEvent, Reason, ReferenceEntry, ReferenceIntent,
    ReferenceSettlement, Request, RequestKind, RequestRecord, StartFence, Step, SysError, VecDeque,
    execute, platform, reference_keys, snapshot, step_class,
};
use crate::{platform::ConfigKey, snapshot::InternalError};

pub(super) fn settled_request(kind: snapshot::RequestKind) -> bool {
    matches!(
        kind,
        snapshot::RequestKind::JoinDone
            | snapshot::RequestKind::LeaveDone
            | snapshot::RequestKind::JoinCancelled
            | snapshot::RequestKind::JoinDoneCancelled
    )
}

impl<P: Platform> Engine<P> {
    pub(super) fn push_request(
        &mut self,
        record: RequestRecord,
        leave: bool,
    ) -> Result<(), SysError> {
        if self.snapshot.requests.try_push(record.clone()).is_ok() {
            return Ok(());
        }
        let mut requests = self.snapshot.requests.to_vec();
        let oldest = requests.iter().position(|old| settled_request(old.kind));
        // Leave is an unconditional escape. If every record is still pending,
        // sacrifice replay of the oldest id rather than refuse connectivity.
        let Some(index) = oldest.or(leave.then_some(0)) else {
            return Err(SysError::Failed("request replay window full"));
        };
        requests.remove(index);
        requests.push(record);
        self.snapshot.requests = requests
            .try_into()
            .map_err(|_| SysError::Failed("request replay window full"))?;
        Ok(())
    }
    fn push_leave_record(
        &mut self,
        record: RequestRecord,
        preexisting: &[u64],
    ) -> Result<(), SysError> {
        let mut records = self.snapshot.requests.to_vec();
        if records.len() == 8 {
            let index = records
                .iter()
                .position(|old| preexisting.contains(&old.id))
                .or_else(|| {
                    records
                        .iter()
                        .position(|old| old.kind == snapshot::RequestKind::Leave)
                })
                // Only predeployment snapshots with the old eight-Join cap
                // can reach this fallback; current admission reserves a slot.
                .unwrap_or(0);
            records.remove(index);
        }
        records.push(record);
        self.snapshot.requests = records
            .try_into()
            .map_err(|_| SysError::Failed("request replay window full"))?;
        Ok(())
    }
    pub(super) fn runnable(&self) -> bool {
        matches!(self.mode, Mode::Normal | Mode::PersistBlocked)
    }
    pub(super) fn block_storage(&mut self) {
        self.storage_blocked = true;
        self.storage_delay = if self.storage_delay == 0 {
            1
        } else {
            (self.storage_delay * 2).min(60)
        };
        self.next_storage = self.platform.now().saturating_add(self.storage_delay);
        if self.mode != Mode::Stuck && self.mode != Mode::Starting {
            self.mode = Mode::PersistBlocked;
        }
    }
    pub(super) fn retry_storage(&mut self) {
        if !self.storage_blocked || self.platform.now() < self.next_storage {
            return;
        }
        if let Some((copy, bytes)) = self.repair_pending.take() {
            let read = self
                .storage_read(self.timings.command_deadline, true, |p, d| {
                    p.poll_copy(copy, d)
                })
                .unwrap_or(snapshot::CopyRead::Unreadable);
            let overall = platform::Deadline(
                self.platform
                    .now()
                    .saturating_add(self.timings.command_deadline),
            );
            let repaired = match read {
                snapshot::CopyRead::Missing => self.storage_write(copy, &bytes, true, overall),
                snapshot::CopyRead::Bytes(_) => self.storage_write(copy, &bytes, false, overall),
                snapshot::CopyRead::Unreadable => {
                    platform::WriteOutcome::NotStarted(SysError::Failed("pair repair unreadable"))
                }
            };
            if repaired != platform::WriteOutcome::Synced {
                self.repair_pending = Some((copy, bytes));
                self.block_storage();
                return;
            }
        }
        if let Some((machine, snapshot)) = self.waiting.take() {
            let old = std::mem::replace(&mut self.snapshot, snapshot);
            let before = self.machine.context();
            let committed = self.commit_if_changed();
            let machine = self.carry_storage_observation(machine, before);
            if committed {
                self.machine = machine;
            } else {
                let pending = std::mem::replace(&mut self.snapshot, old);
                self.waiting = Some((machine, pending));
            }
        } else {
            let _ = self.commit_if_changed();
        }
        if self.runnable() && !self.storage_blocked && self.freeing_allowed() {
            for sequence in std::mem::take(&mut self.unexposed_acquires) {
                self.apply(Event::ReferenceSettled {
                    entry: ReferenceEntry::Acquire(sequence),
                    how: ReferenceSettlement::Void,
                });
            }
        }
    }
    pub(super) fn cancel_storage_wait_for_safety(&mut self, event: &Event, clock: Clock) {
        // Any accepted observation supersedes a speculative D completion, not
        // only losses. Replacing the machine later must never resurrect the old
        // pf, handshake, or proof context over an intervening observation.
        let Some(step) = self.machine.pending() else {
            return;
        };
        if self.mode != Mode::PersistBlocked
            || self.waiting.is_none()
            || self.in_flight.is_some()
            || step_class(step) != Class::D
            || matches!(step, Step::PersistLeaving | Step::ClearIntent)
        {
            return;
        }
        if self.machine.transition(event.clone(), &clock).is_err() {
            return;
        }
        // No D effect has been exposed. Cancel that attempt through the core's
        // normal failure boundary so a fresh N-class closing prefix can run.
        // Discarding a speculative completion cannot discard an actual ioctl.
        self.waiting = None;
        let void = if step == Step::AcquireReference {
            match self.machine.durable().reference_intent {
                Some(ReferenceIntent::Acquire(seq)) => Some(seq),
                _ => None,
            }
        } else {
            None
        };
        let failed = Event::Failed(Reason::Observation(
            "storage wait superseded by safety repair",
        ));
        let next = self.machine.transition(failed.clone(), &clock).ok();
        self.finish_safety_transition(next, &failed, void, step);
    }
    // Separate the result handoff so impossible core-result failures can be
    // exercised without inventing invalid reducer internals.
    pub(super) fn finish_safety_transition(
        &mut self,
        next: Option<super::Machine>,
        failed: &Event,
        void: Option<u64>,
        step: Step,
    ) {
        match next {
            Some(next) => {
                self.adopt(next, failed, None);
                // PersistIntent's speculative success was never durable. Its
                // failure returns the core to Left, so replay the admitted Join
                // as a new plan rather than resurrecting the discarded machine.
                if step == Step::PersistIntent && self.runnable() {
                    self.apply(Event::Join);
                }
                if let Some(seq) = void {
                    self.unexposed_acquires.push(seq);
                }
            }
            None => self.enter_stuck(),
        }
    }
    pub(super) fn accept_leave(&mut self, request: Request) -> Result<(), SysError> {
        if let Some(kind) = self
            .snapshot
            .requests
            .iter()
            .find(|old| old.id == request.id)
            .map(|old| old.kind)
        {
            if kind == snapshot::RequestKind::Leave && self.mode == Mode::Stuck {
                self.begin_stuck_leave();
                return Ok(());
            }
            return if matches!(
                kind,
                snapshot::RequestKind::Leave | snapshot::RequestKind::LeaveDone
            ) {
                Ok(())
            } else {
                Err(SysError::Failed("request identity collision"))
            };
        }
        // Revoke and invalidate before cancellation or any persistence wait.
        self.emergency_revoked = true;
        self.emergency_proof = None;
        self.verified_enforcement = false;
        self.containment_cleanup_only = false;
        if self.mode == Mode::Stuck {
            self.begin_stuck_leave();
        } else if self.emergency_loaded || self.platform.fence() != Fence::Closed {
            self.cancel_emergency_tools();
        }
        // Leave supersedes a waiting speculative D commit. No exposed effect is
        // discarded: acquisition completions never use this waiting slot.
        self.waiting = None;
        let preexisting_settled: Vec<_> = self
            .snapshot
            .requests
            .iter()
            .filter(|old| settled_request(old.kind))
            .map(|old| old.id)
            .collect();
        let mut requests = self.snapshot.requests.to_vec();
        for old in &mut requests {
            old.kind = match old.kind {
                snapshot::RequestKind::Join => snapshot::RequestKind::JoinCancelled,
                snapshot::RequestKind::JoinDone => snapshot::RequestKind::JoinDoneCancelled,
                kind => kind,
            };
        }
        self.snapshot.requests = requests
            .try_into()
            .map_err(|_| SysError::Failed("request replay window full"))?;
        // A Join already accepted into the queue must resolve as cancelled.
        let queued: Vec<_> = self
            .queue
            .iter()
            .filter_map(|event| match event {
                QueueEvent::Request(old) if old.kind == super::RequestKind::Join => Some(*old),
                _ => None,
            })
            .collect();
        self.queue.retain(|event| !matches!(event, QueueEvent::Request(old) if old.kind == super::RequestKind::Join));
        self.push_leave_record(
            RequestRecord {
                id: request.id,
                kind: snapshot::RequestKind::Leave,
            },
            &preexisting_settled,
        )?;
        for old in queued {
            if !self
                .snapshot
                .requests
                .iter()
                .any(|record| record.id == old.id)
            {
                self.push_leave_record(
                    RequestRecord {
                        id: old.id,
                        kind: snapshot::RequestKind::JoinCancelled,
                    },
                    &preexisting_settled,
                )?;
            }
        }
        if !self.machine.durable().leaving && !self.machine.durable().leave_requested {
            self.storage_delay = 0;
            self.next_storage = self.platform.now();
        }
        self.left_verified = false;
        self.leave_item = None;
        self.next_leave = 0;
        self.leave_delay = 0;
        if self.mode != Mode::Stuck {
            // The accepted record and revocation survive until retry_leave
            // can merge accounting and feed the core after an in-flight effect.
            if self.machine.durable().hold && self.resume_emergency_accounting_for_leave().is_err()
            {
                return Ok(());
            }
            self.feed_leave();
        }
        Ok(())
    }
    fn begin_stuck_leave(&mut self) {
        self.emergency_revoked = true;
        self.emergency_proof = None;
        self.verified_enforcement = false;
        self.outcome = Outcome::Continue;
        self.waiting = None;
        if self.check_startup_invariant() {
            self.cancel_emergency_tools();
        }
        if self.stuck_leave.is_none() {
            self.left_verified = false;
            self.next_leave = 0;
            self.stuck_leave = Some(VecDeque::from([
                Step::StopChild,
                Step::CleanupRoutes,
                Step::CleanupDns,
                Step::CleanupArtifacts,
                Step::RemoveAnchor,
                Step::ClearIntent,
            ]));
        }
    }
    pub(super) fn feed_leave(&mut self) {
        if let Some((dispatch, Step::Backoff { .. })) = self.in_flight {
            // Leave cancels a timer immediately in the core. Its queued
            // no-effect completion no longer belongs to a pending step.
            self.in_flight = None;
            self.queue.retain(
                |event| !matches!(event, QueueEvent::Completion(c) if c.dispatch == dispatch),
            );
        }
        self.waiting = None;
        self.apply(Event::Leave);
        // A planned but undispatched core head has no effect to await. Feed
        // its checked cancellation boundary immediately; real completions
        // retain their dispatch identity and settle in queue order.
        if self.in_flight.is_none()
            && self.machine.pending() != Some(Step::PersistLeaving)
            && !self.machine.durable().leaving
        {
            self.apply(Event::Failed(Reason::Observation("cancelled by leave")));
        }
    }
    pub(super) fn retry_leave(&mut self) {
        if self.emergency_revoked
            && !self.left_verified
            && !self.machine.durable().leaving
            && !self.machine.durable().leave_requested
            && self
                .snapshot
                .requests
                .iter()
                .any(|request| request.kind == snapshot::RequestKind::Leave)
            && self.resume_emergency_accounting_for_leave().is_ok()
        {
            self.feed_leave();
        }
        if !self.machine.durable().leaving || self.machine.pending().is_some() {
            return;
        }
        let now = self.platform.now();
        if self.next_leave == 0 {
            self.leave_delay = if self.leave_delay == 0 {
                1
            } else {
                (self.leave_delay * 2).min(60)
            };
            self.next_leave = now.saturating_add(self.leave_delay);
        }
        if self.leave_unknown && self.platform.fence() == Fence::Closed || now >= self.next_leave {
            self.next_leave = 0;
            self.leave_unknown = false;
            self.apply(Event::Leave);
        }
    }
    /// Every read is complete and independent of a successful cleanup command.
    pub(super) fn verify_clear_intent(&mut self) -> Result<(), SysError> {
        self.leave_item = Some("fence open");
        if self.start_fence != StartFence::Closed || self.platform.fence() != Fence::Closed {
            return Err(SysError::Failed("fence open"));
        }
        self.leave_item = Some("anchor");
        let d = self.deadline();
        if self
            .platform
            .read_anchor(d)?
            .is_some_and(|text| !text.trim().is_empty())
        {
            return Err(SysError::Failed("anchor"));
        }
        self.leave_item = Some("DNS key");
        let d = self.deadline();
        if self.platform.read_config(ConfigKey::Dns, d)?.is_some() {
            return Err(SysError::Failed("DNS key"));
        }
        self.leave_item = Some("owned process");
        let d = self.deadline();
        let pin = self.platform.executable_id(Path::new(CHILD_PATH), d).ok();
        let d = self.deadline();
        let Enumeration::Complete(processes) = self.platform.processes(d) else {
            return Err(SysError::Failed("owned process inventory"));
        };
        let own = self.platform.incarnation();
        let pin_uuids: Option<Vec<_>> = super::PINNED_TOOLS
            .iter()
            .map(Path::new)
            .chain(std::iter::once(Path::new(CHILD_PATH)))
            .map(|path| {
                let d = self.deadline();
                self.platform.image_uuid(path, d).ok()
            })
            .collect();
        let boot = self.platform.boot_id();
        let owned = |proc: &platform::ProcInfo| {
            proc.path.as_deref() == Some(Path::new(CHILD_PATH))
                || pin.is_some() && proc.exe == pin
                || self
                    .platform
                    .spawned_children()
                    .iter()
                    .any(|child| child.pid == proc.pid && child.start_time == proc.start)
        };
        let qualified = platform::qualify_pathless(
            Enumeration::Complete(processes),
            pin.is_none(),
            &self.snapshot.image_history,
            boot.as_ref(),
            pin_uuids.as_deref(),
            |proc, _| proc.pid != own.pid && !owned(proc),
        );
        let Enumeration::Complete(processes) = qualified else {
            if let Enumeration::Incomplete(error) = qualified {
                self.last_sweep = Some(platform::Sweep::Incomplete(error));
            }
            return Err(SysError::Failed("owned process inventory"));
        };
        if processes.iter().any(|proc| {
            proc.pid != own.pid
                && (proc.state != platform::ProcState::Zombie || proc.ppid == own.pid)
                && owned(proc)
        }) {
            return Err(SysError::Failed("owned process"));
        }
        self.leave_item = Some("artifacts");
        let d = self.deadline();
        match self.platform.managed_artifacts(d) {
            Enumeration::Complete(entries) if entries.is_empty() => {}
            Enumeration::Complete(_) => {
                // A child may have recreated a socket after an earlier cleanup
                // attempt. Writers are now gone; retry removal, then require a
                // fresh complete absence read on the next ClearIntent attempt.
                let d = self.deadline();
                self.platform.cleanup_artifacts(d)?;
                return Err(SysError::Failed("artifacts"));
            }
            Enumeration::Incomplete(error) => return Err(error),
        }
        self.leave_item = Some("split route");
        let endpoint = self.snapshot.endpoint.or_else(|| {
            self.install
                .as_ref()
                .map(|r| execute::endpoint(&r.config.inputs))
        });
        let d = self.deadline();
        let routes = self.platform.leave_routes(endpoint, d)?;
        if routes.split_owned {
            return Err(SysError::Failed("split route"));
        }
        self.leave_item = Some("host route");
        if routes.endpoint_host {
            return Err(SysError::Failed("host route"));
        }
        self.leave_item = Some("fence open");
        if self.start_fence != StartFence::Closed || self.platform.fence() != Fence::Closed {
            return Err(SysError::Failed("fence open"));
        }
        self.leave_item = None;
        Ok(())
    }
    pub(super) fn run_stuck(&mut self) {
        self.run_emergency();
        if !self.check_startup_invariant() {
            if self.startup_invariant_failed {
                self.outcome = Outcome::StartupInvariantFailed;
            }
            return;
        }
        self.ensure_control_socket();
        // Leave is accepted directly by submit, even without a healthy core.
        let leaves: Vec<_> = self
            .queue
            .iter()
            .filter_map(|event| match event {
                QueueEvent::Request(r) if r.kind == RequestKind::Leave => Some(*r),
                _ => None,
            })
            .collect();
        self.queue.retain(|event| {
            !matches!(event,
            QueueEvent::Request(r) if r.kind == RequestKind::Leave)
        });
        for request in leaves {
            let _ = self.accept_leave(request);
        }
        if !(self.machine.durable().join_intended
            || self.snapshot.machine.join_intended
            || self.committed.machine.join_intended)
        {
            self.observe_only();
        }
        self.run_stuck_leave();
        if self.stuck_leave.is_none()
            && self.outcome == Outcome::Continue
            && self.platform.now() >= self.emergency_annotation_due
        {
            if !self.storage_blocked && self.snapshot != self.committed {
                let _ = self.commit_if_changed();
            } else {
                self.retry_storage();
            }
        }
    }

    #[track_caller]
    pub(super) fn enter_stuck(&mut self) {
        if self.mode == Mode::Stuck {
            return;
        }
        #[cfg(test)]
        {
            let location = std::panic::Location::caller();
            self.stuck_entry = Some((location.file(), location.line()));
        }
        // A queued completion may carry the only evidence of an exposed ioctl.
        // Freeze it with the core instead of stranding it behind the Stuck loop.
        if let Some((dispatch, step)) = self.in_flight
            && let Some(index) = self.queue.iter().position(
                |event| matches!(event, QueueEvent::Completion(c) if c.dispatch == dispatch),
            )
            && let Some(QueueEvent::Completion(completion)) = self.queue.remove(index)
        {
            self.retained_completion = Some((step, completion));
            self.in_flight = None;
        }
        self.mode = Mode::Stuck;
        self.next_full = 0;
        self.next_emergency = 0;
        self.waiting = None;
        self.snapshot.internal_error = Some(InternalError::Other);
        if self.machine.durable().leaving
            || self.machine.durable().leave_requested
            || self
                .snapshot
                .requests
                .iter()
                .any(|r| r.kind == snapshot::RequestKind::Leave)
        {
            self.begin_stuck_leave();
        }
        // Close first: even a bounded failing storage write must not precede
        // the independent emergency attempt.
        self.run_emergency();
        self.emergency_annotation_due = self.platform.now().saturating_add(1);
        // Keep the machine and annotations intact. Invalid snapshots cannot be
        // committed, but a representable internal error still survives restart.
        if !(self.machine.durable().join_intended
            || self.snapshot.machine.join_intended
            || self.committed.machine.join_intended)
        {
            // With no emergency to run, still check ownership once before a
            // representable constructor error can write shared state.
            self.check_startup_invariant();
        }
        if self.startup_invariant_checked
            && !self.startup_invariant_failed
            && self.ensure_control_socket()
            && self.snapshot.validate().is_ok()
            && (!self.emergency_enable_pending || self.emergency_revoked)
        {
            let _ = self.commit_if_changed();
        } else if self.startup_invariant_failed {
            self.outcome = Outcome::StartupInvariantFailed;
        }
    }
    pub(super) fn finish_join_requests(&mut self) {
        let mut requests = self.snapshot.requests.to_vec();
        for request in &mut requests {
            if request.kind == snapshot::RequestKind::Join {
                request.kind = snapshot::RequestKind::JoinDone;
            }
        }
        if let Ok(requests) = requests.try_into() {
            self.snapshot.requests = requests;
        }
    }
    pub(super) fn complete_leave_requests(&mut self) {
        let mut requests = self.snapshot.requests.to_vec();
        for request in &mut requests {
            if request.kind == snapshot::RequestKind::Leave {
                request.kind = snapshot::RequestKind::LeaveDone;
            }
        }
        if let Ok(requests) = requests.try_into() {
            self.snapshot.requests = requests;
        }
    }
    pub(super) fn run_stuck_leave(&mut self) {
        if self.stuck_leave.is_some() {
            let ready = self.prepare_emergency_fence();
            // Own writers can themselves keep the start fence open. Drain them
            // even before closure; removal still requires both conditions.
            let reaped = !self.startup_invariant_failed && self.cancel_emergency_tools();
            if !ready || !reaped {
                return;
            }
        }
        if self.start_fence != StartFence::Closed || self.platform.now() < self.next_leave {
            return;
        }
        let Some(mut pending) = self.stuck_leave.take() else {
            return;
        };
        let mut failed = VecDeque::new();
        while let Some(step) = pending.pop_front() {
            if self.execute(step).is_err() {
                if step == Step::ClearIntent {
                    self.left_verified = false;
                }
                failed.push_back(step);
            }
        }
        if !failed.is_empty() {
            // ClearIntent must be repeated after the last possible late effect.
            if !failed.contains(&Step::ClearIntent) {
                failed.push_back(Step::ClearIntent);
            }
            self.stuck_leave = Some(failed);
            self.leave_delay = if self.leave_delay == 0 {
                1
            } else {
                (self.leave_delay * 2).min(60)
            };
            self.next_leave = self.platform.now().saturating_add(self.leave_delay);
            return;
        }
        if self.commit_stuck_left() {
            self.outcome = Outcome::Exit0;
        } else {
            self.stuck_leave = Some(VecDeque::from([Step::ClearIntent]));
            self.leave_delay = if self.leave_delay == 0 {
                1
            } else {
                (self.leave_delay * 2).min(60)
            };
            self.next_leave = self.platform.now().saturating_add(self.leave_delay);
        }
    }
    #[allow(clippy::too_many_lines)] // Preserve the complete evidence union and commit Left together.
    fn commit_stuck_left(&mut self) -> bool {
        self.left_verified = true;
        // Before startup adopts its reducer, the default machine is only a
        // placeholder. The validated snapshot still owns release authority.
        let startup = (!self.adopted)
            .then(|| self.snapshot.validate().ok())
            .flatten();
        let old = startup.as_ref().unwrap_or_else(|| self.machine.durable());
        let mut durable = Durable {
            pf_reference: old.pf_reference,
            older_references: old.older_references.clone(),
            reference_intent: old.reference_intent,
            uncertain_acquires: old.uncertain_acquires.clone(),
            reference_needs_reconcile: old.reference_needs_reconcile,
            reference_error: old.reference_error.clone(),
            reference_sequence: old.reference_sequence,
            ..Durable::default()
        };
        durable.reference_sequence = durable
            .reference_sequence
            .max(self.snapshot.machine.reference_sequence);
        for key in &self.emergency_settled {
            match key {
                ReferenceEntry::Token(token) => {
                    if durable.pf_reference == Some(*token) {
                        durable.pf_reference = None;
                    }
                    durable.older_references.retain(|t| t != token);
                }
                ReferenceEntry::Acquire(seq) => {
                    if durable.reference_intent == Some(ReferenceIntent::Acquire(*seq)) {
                        durable.reference_intent = None;
                    }
                    durable.uncertain_acquires.retain(|s| s != seq);
                }
            }
        }
        // Emergency accounting is independent of the frozen reducer, but joins
        // its durable union before cleanup can release any numeric token.
        for entry in &self.emergency_references {
            match entry.key {
                ReferenceEntry::Token(token) => {
                    if durable.pf_reference.is_none() {
                        durable.pf_reference = Some(token);
                    } else if durable.pf_reference != Some(token)
                        && !durable.older_references.contains(&token)
                    {
                        durable.older_references.push(token);
                    }
                }
                ReferenceEntry::Acquire(seq) => {
                    if !durable.uncertain_acquires.contains(&seq) {
                        durable.uncertain_acquires.push(seq);
                    }
                    durable.reference_sequence = durable.reference_sequence.max(seq);
                }
            }
        }
        let mut evidence = self
            .snapshot
            .references
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for entry in &self.emergency_references {
            if !evidence.iter().any(|e| e.key == entry.key) {
                evidence.push(entry.clone());
            }
        }
        // An annotation mismatch must not erase a core entry. Missing metadata
        // grants no release authority; retain the key with unknown provenance.
        for key in reference_keys(&durable) {
            if !evidence.iter().any(|entry| entry.key == key) {
                evidence.push(super::RefEvidence {
                    key,
                    boot: None,
                    fingerprint: None,
                    release_unknown: matches!(key, ReferenceEntry::Token(_)),
                });
            }
        }
        // A real acquisition may have completed just before the fallback was
        // rejected. Keep that result without feeding the broken core again.
        if let Some((Step::AcquireReference, completion)) = &self.retained_completion
            && let Some(acquired) = &completion.acquired
            && let ReferenceEntry::Token(token) = acquired.key
        {
            if let Some(ReferenceIntent::Acquire(sequence)) = durable.reference_intent {
                durable.reference_intent = None;
                durable.uncertain_acquires.retain(|old| *old != sequence);
                evidence.retain(|entry| entry.key != ReferenceEntry::Acquire(sequence));
            }
            if durable.pf_reference.is_none() {
                durable.pf_reference = Some(token);
            } else if durable.pf_reference != Some(token)
                && !durable.older_references.contains(&token)
            {
                durable.older_references.push(token);
            }
            evidence.retain(|entry| entry.key != acquired.key);
            evidence.push(acquired.clone());
        }
        if let Some(Reason::Unknown { since }) = &mut durable.reference_error {
            *since = 0;
        }
        let mut keys = reference_keys(&durable);
        let mismatch = evidence.len() != keys.len()
            || evidence.iter().any(|entry| !keys.contains(&entry.key))
            || self.snapshot.references.iter().flatten().count() != keys.len();
        if mismatch {
            for entry in &mut evidence {
                entry.release_unknown = matches!(entry.key, ReferenceEntry::Token(_));
                if !keys.contains(&entry.key) {
                    match entry.key {
                        ReferenceEntry::Token(token) => {
                            if durable.pf_reference.is_none() {
                                durable.pf_reference = Some(token);
                            } else {
                                durable.older_references.push(token);
                            }
                        }
                        ReferenceEntry::Acquire(seq) => {
                            durable.uncertain_acquires.push(seq);
                            durable.reference_sequence = durable.reference_sequence.max(seq);
                        }
                    }
                    keys.push(entry.key);
                }
            }
            durable.reference_needs_reconcile = true;
            // Keep both original sets in memory if their union cannot fit the
            // frozen schema. Connectivity is Left (not durable), with no Exit0
            // or numeric release; persistence retries with the Leave back-off.
            for entry in self.snapshot.references.iter_mut().flatten() {
                entry.release_unknown = matches!(entry.key, ReferenceEntry::Token(_));
            }
        }
        let keys = reference_keys(&durable);
        if keys.len() > 2 {
            self.stuck_accounting = evidence;
            return false;
        }
        self.stuck_accounting.clear();
        self.snapshot.references = std::array::from_fn(|index| {
            keys.get(index)
                .and_then(|key| evidence.iter().find(|entry| entry.key == *key).cloned())
        });
        let Ok(record) = DurableRecord::try_from(&durable) else {
            return false;
        };
        self.snapshot.machine = record;
        self.snapshot.internal_error = None;
        self.complete_leave_requests();
        self.left_verified = true;
        self.commit_if_changed()
    }
}
