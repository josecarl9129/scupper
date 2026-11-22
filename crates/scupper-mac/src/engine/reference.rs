//! Reservation-before-ioctl reference accounting and the three freeing rules.
//! Numeric release requires qualified fingerprints and a complete post-fence read
//! matching the recorded PID/calendar timestamp; token values alone are reused.
use super::{
    Engine, Enumeration, Event, Fence, Mode, Platform, Reason, RefEvidence, ReferenceEntry,
    ReferenceIntent, ReferenceSettlement, StartFence, SysError,
};
use crate::{
    platform::{PfInfo, Release, ToolOutcome},
    snapshot::RefFingerprint,
};

impl<P: Platform> Engine<P> {
    /// Emergency uses the same durable reservation-before-effect ordering, but
    /// cannot depend on the rejected reducer accepting a completion.
    pub(super) fn enable_emergency_pf(&mut self) -> Result<bool, SysError> {
        if !self.containment_allowed() {
            return Err(SysError::Failed("containment revoked"));
        }
        let was_in_step = self.in_emergency_step;
        if !was_in_step {
            self.reset_emergency_frame();
        }
        self.in_emergency_step |= self.emergency_frame_needs_guard();
        let result = self.enable_emergency_pf_inner();
        self.in_emergency_step = was_in_step;
        result
    }

    #[allow(clippy::too_many_lines)] // Keep reservation, effect, and settlement ordering together.
    fn enable_emergency_pf_inner(&mut self) -> Result<bool, SysError> {
        self.emergency_enable_pending = true;
        let stateless = self.emergency_is_stateless();
        if stateless && self.lockless.is_none() && self.startup_error.is_none() {
            // D-3 must not consume a reference before ownership and quiescence.
            // Once closed, healthy storage restores the reserved reference model.
            self.emergency_needs_reference = true;
        }
        let d = self.deadline();
        let info = self.platform.pf_info(d);
        let enabled = info == PfInfo::Enabled;
        if info == PfInfo::Disabled {
            if self.anonymous_enable_confirmed || self.emergency_states_clean_at.is_some() {
                self.reset_emergency_flush();
            }
            self.anonymous_enable_confirmed = false;
        }
        if self.platform.boot_id().is_none() || self.mode == Mode::PersistBlocked {
            self.enable_emergency_without_reference(enabled)?;
            return Ok(!enabled);
        }
        match info {
            PfInfo::Enabled if stateless => {
                self.enable_emergency_without_reference(enabled)?;
                return Ok(false);
            }
            PfInfo::Enabled
                if !self.emergency_needs_reference && self.has_confirmed_reference() =>
            {
                self.emergency_enable_pending = false;
                return Ok(false);
            }
            PfInfo::Incomplete(_) => {
                self.enable_emergency_without_reference(enabled)?;
                return Ok(false);
            }
            PfInfo::Disabled if stateless => {
                self.enable_emergency_without_reference(enabled)?;
                return Ok(true);
            }
            PfInfo::Enabled => self.emergency_needs_reference = true,
            PfInfo::Disabled => {}
        }
        // Rule 2: a complete post-fence inventory can settle absent numeric
        // tokens, including tokens invalidated by an external pf disable.
        if self.platform.now() < self.emergency_next_acquire {
            self.enable_emergency_without_reference(enabled)?;
            return Ok(true);
        }
        let (reservation, committed, unreserved_allowed) =
            if self.storage_blocked || self.emergency_commit_failed {
                // Known storage failure must not put another commit deadline
                // ahead of filtering. Preserve the cap and one-shot allowance.
                (None, false, self.emergency_unreserved_allowed())
            } else {
                self.settle_emergency_absent_tokens();
                self.reserve_emergency_reference()
            };
        // Storage maintenance may have re-enabled pf while reservation waited.
        let d = self.deadline();
        let enabled = self.platform.pf_info(d) == PfInfo::Enabled;
        if enabled && self.emergency_needs_reference && !committed {
            self.enable_emergency_without_reference(enabled)?;
            return Ok(false);
        }
        let Some(acquisition_boot) = self.platform.boot_id() else {
            self.enable_emergency_without_reference(enabled)?;
            return Ok(!enabled);
        };
        if !committed {
            if !unreserved_allowed || self.emergency_unreserved_consumed {
                self.enable_emergency_without_reference(enabled)?;
                return Ok(true);
            }
            // Consume before effect; only definite NotStarted restores it.
            self.emergency_unreserved_consumed = true;
        }
        let d = self.deadline();
        self.emergency_pfctl_capacity()?;
        let outcome = self.platform.acquire(d);
        if let ToolOutcome::NotStarted(_) = outcome {
            if !committed {
                self.emergency_unreserved_consumed = false;
            }
            if let Some(seq) = reservation {
                self.settle_emergency_not_started(seq);
            }
            self.emergency_next_acquire = self
                .platform
                .now()
                .saturating_add(self.emergency_acquire_delay);
            self.emergency_acquire_delay = self.emergency_acquire_delay.saturating_mul(2).min(60);
            self.enable_emergency_without_reference(enabled)?;
            return Ok(true);
        }
        if let ToolOutcome::Ok((token, pid)) = outcome
            && token != 0
        {
            self.emergency_enable_pending = false;
            self.emergency_needs_reference = false;
            self.emergency_acquire_delay = 1;
            self.emergency_next_acquire = self.platform.now();
            let d = self.deadline();
            let fingerprint = match self.platform.references(d) {
                Enumeration::Complete(lines) => lines
                    .iter()
                    .find(|r| r.token == token && r.pid == pid)
                    .map(|r| RefFingerprint {
                        pid: r.pid,
                        timestamp: r.timestamp,
                    }),
                Enumeration::Incomplete(_) => None,
            };
            let Some(fingerprint) = fingerprint else {
                // Match the normal acquisition path: a numeric token without
                // one complete fingerprint read grants no release authority.
                return Err(SysError::Unknown);
            };
            let entry = super::RefEvidence {
                key: ReferenceEntry::Token(token),
                boot: match reservation {
                    Some(seq) => self
                        .snapshot
                        .references
                        .iter()
                        .flatten()
                        .find(|e| e.key == ReferenceEntry::Acquire(seq))
                        .and_then(|e| e.boot.clone()),
                    None => Some(acquisition_boot),
                },
                release_unknown: false,
                fingerprint: Some(fingerprint),
            };
            if let Some(seq) = reservation {
                self.emergency_references
                    .retain(|e| e.key != ReferenceEntry::Acquire(seq));
                self.remember_emergency_settlement(ReferenceEntry::Acquire(seq));
            }
            self.emergency_references.retain(|e| e.key != entry.key);
            self.emergency_references.push(entry.clone());
            if let Ok(mut durable) = self.snapshot.validate() {
                if let Some(seq) = reservation {
                    durable.uncertain_acquires.retain(|s| *s != seq);
                    if durable.reference_intent == Some(ReferenceIntent::Acquire(seq)) {
                        durable.reference_intent = None;
                    }
                }
                let mut evidence: Vec<_> = self
                    .snapshot
                    .references
                    .iter()
                    .flatten()
                    .filter(|e| {
                        Some(e.key) != reservation.map(ReferenceEntry::Acquire)
                            && e.key != entry.key
                    })
                    .cloned()
                    .collect();
                evidence.push(entry.clone());
                if durable.pf_reference.is_none() {
                    durable.pf_reference = Some(token);
                } else if durable.pf_reference != Some(token)
                    && !durable.older_references.contains(&token)
                {
                    durable.older_references.push(token);
                }
                if self.stage_emergency_accounting(&durable, &evidence) {
                    self.commit_if_changed();
                }
            }
            return Ok(true);
        }
        // Ambiguous reserved effects remain durably accounted. They do not
        // consume the failing-storage allowance; the two-key cap still applies.
        self.emergency_next_acquire = self
            .platform
            .now()
            .saturating_add(self.emergency_acquire_delay);
        self.emergency_acquire_delay = self.emergency_acquire_delay.saturating_mul(2).min(60);
        // An ambiguous acquisition may already have enabled pf. Observe that
        // before the reference-free fallback, without retrying acquisition.
        let d = self.deadline();
        let now_enabled = self.platform.pf_info(d) == PfInfo::Enabled;
        self.enable_emergency_without_reference(now_enabled)?;
        Err(SysError::Unknown)
    }

    pub(super) fn enable_emergency_without_reference(
        &mut self,
        enabled: bool,
    ) -> Result<(), SysError> {
        if !enabled {
            if self.anonymous_enable_confirmed || self.emergency_states_clean_at.is_some() {
                self.reset_emergency_flush();
            }
            self.anonymous_enable_confirmed = false;
        }
        if !self.anonymous_enable_confirmed && (!enabled || !self.has_confirmed_reference()) {
            if !enabled {
                self.emergency_pfctl_capacity()?;
                let _ = self.prepare_anonymous_enable();
            }
            // Preparation orders policy repair before enablement, but cannot
            // withhold filtering. Only integrity, capacity and revocation gate it.
            if !self.containment_allowed() {
                return Err(SysError::Failed("containment revoked"));
            }
            self.emergency_pfctl_capacity()?;
            let d = self.deadline();
            self.platform.check_pfctl(d)?;
            self.emergency_pfctl_capacity()?;
            let d = self.deadline();
            self.platform.enable_pf(d)?;
            self.anonymous_enable_confirmed = true;
        }
        self.emergency_enable_pending = false;
        Ok(())
    }

    pub(super) fn has_confirmed_reference(&mut self) -> bool {
        if self.unreaped_pfctl() >= 2 {
            return false;
        }
        let boot = self.platform.boot_id();
        let d = self.deadline();
        let Enumeration::Complete(lines) = self.platform.references(d) else {
            return false;
        };
        self.snapshot.references.iter().flatten().any(|entry| {
            entry.boot.is_some()
                && entry.boot == boot
                && !entry.release_unknown
                && matches!(entry.key, ReferenceEntry::Token(token)
                    if lines.iter().any(|line| line.token == token
                        && entry.fingerprint.as_ref().is_some_and(|f|
                            f.pid == line.pid && f.timestamp == line.timestamp)))
        })
    }

    pub(super) fn run_unreservable_containment(&mut self) {
        if !self.containment_allowed()
            || !self.machine.durable().join_intended
            || self.held_emergency_due()
            || self.platform.now() < self.next_emergency
        {
            return;
        }
        let unavailable = self.storage_blocked
            || self.platform.boot_id().is_none()
            || super::reference_keys(self.machine.durable()).len() >= 2;
        if !unavailable || self.machine.pending() == Some(super::Step::LoadPreTunnel) {
            // Let the dispatched ordinary load run first. Its retry backoff
            // must not postpone reference-free enablement after a failed load.
            return;
        }
        let d = self.deadline();
        let info = self.platform.pf_info(d);
        let enabled = info == PfInfo::Enabled;
        if info == PfInfo::Disabled
            || (!self.anonymous_enable_confirmed && !self.has_confirmed_reference())
        {
            let since = self.platform.now();
            let had_proof = self.machine.blocking_verified_at(&super::Clock(since))
                || matches!(
                    self.machine.enforcement_at(&super::Clock(since)),
                    super::Verdict::Protected(_)
                );
            self.verified_enforcement = false;
            self.emergency_proof = None;
            if had_proof {
                self.apply(Event::InvalidateObservations { since });
            }
            // This path cannot reserve a counted reference. Use only the
            // stateless prefix; it never consumes the emergency allowance.
            let was_waiting = self.storage_waiting;
            self.storage_waiting = true;
            let _ = self.enable_emergency_without_reference(enabled);
            self.storage_waiting = was_waiting;
            self.next_emergency = self.platform.now().saturating_add(1);
        }
    }

    fn emergency_unreserved_allowed(&self) -> bool {
        if self.emergency_unreserved_consumed {
            return false;
        }
        let Ok(durable) = self.snapshot.validate() else {
            return true;
        };
        durable
            .reference_sequence
            .checked_add(1)
            .is_some_and(|seq| {
                seq < crate::snapshot::COUNTER_MAX && super::reference_keys(&durable).len() < 2
            })
    }

    fn reserve_emergency_reference(&mut self) -> (Option<u64>, bool, bool) {
        let Some(boot) = self.platform.boot_id() else {
            return (None, false, false);
        };
        if !self.emergency_unreserved_allowed() {
            return (None, false, false);
        }
        let Ok(durable) = self.snapshot.validate() else {
            return (None, false, true);
        };
        let Some(seq) = durable.reference_sequence.checked_add(1) else {
            return (None, false, false);
        };
        if seq >= crate::snapshot::COUNTER_MAX || super::reference_keys(&durable).len() >= 2 {
            return (None, false, false);
        }
        let entry = super::RefEvidence {
            key: ReferenceEntry::Acquire(seq),
            boot: Some(boot),
            release_unknown: false,
            fingerprint: None,
        };
        let committed = self.persist_emergency_entry(entry.clone());
        self.emergency_commit_failed |= !committed;
        // Retain the uncertain annotation even on write failure: either copy
        // may contain it. The same acquisition replaces it if a token is known.
        let staged = self
            .snapshot
            .references
            .iter()
            .flatten()
            .any(|e| e.key == entry.key);
        if staged {
            self.emergency_references.push(entry);
        }
        (staged.then_some(seq), committed, !committed)
    }

    fn settle_emergency_not_started(&mut self, seq: u64) {
        let Ok(mut durable) = self.snapshot.validate() else {
            return;
        };
        let key = ReferenceEntry::Acquire(seq);
        durable.uncertain_acquires.retain(|s| *s != seq);
        if durable.reference_intent == Some(ReferenceIntent::Acquire(seq)) {
            durable.reference_intent = None;
        }
        let evidence: Vec<_> = self
            .snapshot
            .references
            .iter()
            .flatten()
            .filter(|e| e.key != key)
            .cloned()
            .collect();
        if self.stage_emergency_accounting(&durable, &evidence) {
            self.emergency_references.retain(|e| e.key != key);
            self.remember_emergency_settlement(key);
            self.commit_if_changed();
        }
    }

    fn persist_emergency_entry(&mut self, entry: super::RefEvidence) -> bool {
        let Ok(mut durable) = self.snapshot.validate() else {
            return false;
        };
        if super::reference_keys(&durable).len() >= 2 {
            return false;
        }
        match entry.key {
            ReferenceEntry::Acquire(seq) => {
                durable.uncertain_acquires.push(seq);
                durable.reference_sequence = seq;
            }
            ReferenceEntry::Token(token) => {
                if durable.pf_reference.is_none() {
                    durable.pf_reference = Some(token);
                } else {
                    durable.older_references.push(token);
                }
            }
        }
        let mut evidence: Vec<_> = self.snapshot.references.iter().flatten().cloned().collect();
        evidence.push(entry);
        self.stage_emergency_accounting(&durable, &evidence)
            && self.commit_if_changed_with_budget(2 * self.timings.command_deadline)
    }

    pub(super) fn stage_emergency_accounting(
        &mut self,
        durable: &super::Durable,
        evidence: &[RefEvidence],
    ) -> bool {
        let Ok(record) = crate::snapshot::DurableRecord::try_from(durable) else {
            return false;
        };
        let keys = super::reference_keys(durable);
        let mut candidate = self.snapshot.clone();
        candidate.machine = record;
        candidate.references = std::array::from_fn(|i| {
            keys.get(i)
                .and_then(|key| evidence.iter().find(|e| e.key == *key).cloned())
        });
        if candidate.validate().is_err() {
            return false;
        }
        self.snapshot = candidate;
        true
    }

    fn settle_emergency_absent_tokens(&mut self) {
        let Ok(mut durable) = self.snapshot.validate() else {
            return;
        };
        let d = self.deadline();
        let Enumeration::Complete(lines) = self.platform.references(d) else {
            return;
        };
        let absent: Vec<_> = super::reference_keys(&durable).into_iter().filter(|key|
            matches!(key, ReferenceEntry::Token(token) if !lines.iter().any(|r| r.token == *token)))
            .collect();
        if absent.is_empty() {
            return;
        }
        if durable
            .pf_reference
            .is_some_and(|t| absent.contains(&ReferenceEntry::Token(t)))
        {
            durable.pf_reference = None;
        }
        durable
            .older_references
            .retain(|t| !absent.contains(&ReferenceEntry::Token(*t)));
        let evidence: Vec<_> = self
            .snapshot
            .references
            .iter()
            .flatten()
            .filter(|e| !absent.contains(&e.key))
            .cloned()
            .collect();
        if self.stage_emergency_accounting(&durable, &evidence) {
            self.emergency_references
                .retain(|e| !absent.contains(&e.key));
            for key in absent {
                self.remember_emergency_settlement(key);
            }
        }
    }

    fn remember_emergency_settlement(&mut self, key: ReferenceEntry) {
        // The frozen core's original entries are the only ones Leave could
        // resurrect. Keep at most those two, regardless of external pf churn.
        if super::reference_keys(self.machine.durable()).contains(&key)
            && !self.emergency_settled.contains(&key)
        {
            self.emergency_settled.push(key);
        }
    }

    pub(super) fn resume_emergency_accounting_for_leave(&mut self) -> Result<(), SysError> {
        if self.emergency_references.is_empty() && self.emergency_settled.is_empty() {
            return Ok(());
        }
        if self.in_flight.is_some() {
            return Err(SysError::Failed("emergency accounting effect in flight"));
        }
        let mut durable = self
            .snapshot
            .validate()
            .map_err(|_| SysError::Failed("emergency accounting invalid"))?;
        let unexposed = if self.in_flight.is_none()
            && self.machine.pending() == Some(super::Step::AcquireReference)
        {
            self.machine
                .durable()
                .reference_intent
                .and_then(|intent| match intent {
                    ReferenceIntent::Acquire(seq) => Some(seq),
                    ReferenceIntent::Release => None,
                })
        } else {
            None
        };
        if let Some(seq) = unexposed {
            if durable.reference_intent == Some(ReferenceIntent::Acquire(seq)) {
                durable.reference_intent = None;
            }
            durable.uncertain_acquires.retain(|old| *old != seq);
        }
        let evidence: Vec<_> = self
            .snapshot
            .references
            .iter()
            .flatten()
            .filter(|entry| Some(entry.key) != unexposed.map(ReferenceEntry::Acquire))
            .cloned()
            .collect();
        durable.leave_requested = true;
        if !self.stage_emergency_accounting(&durable, &evidence) {
            return Err(SysError::Failed("emergency accounting invalid"));
        }
        // No effect is in flight: the parked reducer can resume from the current
        // durable ledger without resurrecting settled or superseded references.
        self.machine = super::Machine::restart(durable);
        self.emergency_references.clear();
        self.emergency_settled.clear();
        Ok(())
    }

    pub(super) fn acquire_reference(
        &mut self,
    ) -> Result<(Event, Option<RefEvidence>, Option<u64>), SysError> {
        let Some(ReferenceIntent::Acquire(sequence)) = self.machine.durable().reference_intent
        else {
            return Err(SysError::Failed("missing acquisition intent"));
        };
        if self.platform.boot_id().is_none() {
            // The reservation may predate this observation failure. No ioctl is
            // exposed; the normal NotStarted settlement retains its identity.
            let _ = self.load_emergency();
            return Ok((
                failure(&SysError::Unknown, self.platform.now()),
                None,
                Some(sequence),
            ));
        }
        let acquisition_boot = self
            .snapshot
            .references
            .iter()
            .flatten()
            .find(|entry| entry.key == ReferenceEntry::Acquire(sequence))
            .and_then(|entry| entry.boot.clone());
        let d = self.deadline();
        match self.platform.acquire(d) {
            ToolOutcome::Ok((token, pid)) if token != 0 => {
                let d = self.deadline();
                // One complete enumeration supplies both the token and its pid/
                // timestamp fingerprint. Never splice separate reads together.
                let fingerprint = match self.platform.references(d) {
                    Enumeration::Complete(lines) => lines
                        .iter()
                        .find(|r| r.token == token && r.pid == pid)
                        .map(|r| RefFingerprint {
                            pid: r.pid,
                            timestamp: r.timestamp,
                        }),
                    Enumeration::Incomplete(_) => None,
                };
                let Some(fingerprint) = fingerprint else {
                    // The ioctl may have succeeded, but a token annotation is
                    // accepted only with one complete matching fingerprint read.
                    // Retain the reservation as an uncertain acquisition.
                    return Err(SysError::Unknown);
                };
                Ok((
                    Event::ReferenceAcquiredFor { sequence, token },
                    Some(RefEvidence {
                        key: ReferenceEntry::Token(token),
                        boot: acquisition_boot,
                        release_unknown: false,
                        fingerprint: Some(fingerprint),
                    }),
                    None,
                ))
            }
            ToolOutcome::NotStarted(error) => {
                Ok((failure(&error, self.platform.now()), None, Some(sequence)))
            }
            ToolOutcome::Failed(error) => Err(error),
            ToolOutcome::Unknown { .. } | ToolOutcome::Ok(_) => Err(SysError::Unknown),
        }
    }
    pub(super) fn settle_boot_changes(&mut self) {
        let boot = self.platform.boot_id();
        let entries: Vec<_> = self
            .snapshot
            .references
            .iter()
            .flatten()
            .filter(|e| boot_changed(e, boot.as_ref()))
            .map(|e| e.key)
            .collect();
        for entry in entries {
            self.apply(Event::ReferenceSettled {
                entry,
                how: ReferenceSettlement::Void,
            });
        }
    }
    pub(super) fn freeing_allowed(&mut self) -> bool {
        self.helper_committed
            && self.start_fence == StartFence::Closed
            && self.last_sweep.is_none()
            && self.platform.fence() == Fence::Closed
    }
    #[allow(clippy::too_many_lines)] // Keep freeing and numeric-release gates in one protocol.
    pub(super) fn reconcile_references(&mut self) -> Result<Event, SysError> {
        if !self.freeing_allowed() {
            return Err(SysError::Failed("reference mutation fence open"));
        }
        self.settle_boot_changes();
        if self.mode == Mode::Stuck {
            return Err(SysError::Failed("reference accounting invalid"));
        }
        let qualification = self.platform.reference_qualification();
        // Fence closure is checked BEFORE either read, never after a read that
        // overlapped an outstanding mutation. Incomplete enumeration frees nothing.
        let d = self.deadline();
        let disabled = self.platform.pf_info(d) == PfInfo::Disabled;
        if disabled && qualification.disable_voids_references {
            let keys: Vec<_> = self
                .snapshot
                .references
                .iter()
                .flatten()
                .map(|e| e.key)
                .collect();
            for entry in keys {
                self.apply(Event::ReferenceSettled {
                    entry,
                    how: ReferenceSettlement::Void,
                });
            }
        }
        let d = self.deadline();
        let lines = match self.platform.references(d) {
            Enumeration::Complete(lines) => lines,
            Enumeration::Incomplete(error) => return Err(error),
        };
        let evidence: Vec<_> = self.snapshot.references.iter().flatten().cloned().collect();
        for e in evidence {
            if let ReferenceEntry::Token(token) = e.key
                && !lines.iter().any(|r| r.token == token)
            {
                self.apply(Event::ReferenceSettled {
                    entry: e.key,
                    how: ReferenceSettlement::Absent,
                });
            }
        }
        let boot = self.platform.boot_id();
        let keeper = self
            .machine
            .durable()
            .pf_reference
            .or_else(|| self.machine.durable().older_references.first().copied());
        let evidence: Vec<_> = self.snapshot.references.iter().flatten().cloned().collect();
        for e in evidence {
            let ReferenceEntry::Token(token) = e.key else {
                continue;
            };
            // While joined, never release the last/current enabling reference.
            let releasable = !self.machine.durable().join_intended || Some(token) != keeper;
            if !releasable
                || e.release_unknown
                || e.boot.is_none()
                || boot.is_none()
                || e.boot != boot
            {
                continue;
            }
            let Some(line) = lines.iter().find(|r| r.token == token) else {
                continue;
            };
            if !qualification.fingerprints
                || !e
                    .fingerprint
                    .as_ref()
                    .is_some_and(|f| f.pid == line.pid && f.timestamp == line.timestamp)
            {
                continue;
            }
            if !self.freeing_allowed() {
                return Err(SysError::Failed("reference mutation fence open"));
            }
            if let Some(entry) = self
                .snapshot
                .references
                .iter_mut()
                .flatten()
                .find(|r| r.key == e.key)
            {
                entry.release_unknown = true;
            }
            if !self.commit_if_changed() {
                if self.mode == Mode::Normal {
                    self.block_storage();
                }
                return Err(SysError::Failed("reference release persistence blocked"));
            }
            let d = self.deadline();
            let how = match self.platform.release(token, d) {
                ToolOutcome::Ok(Release::Released) => Some(ReferenceSettlement::Released),
                ToolOutcome::Ok(Release::TokenInvalid) => Some(ReferenceSettlement::Absent),
                _ => None,
            };
            if let Some(how) = how {
                self.apply(Event::ReferenceSettled { entry: e.key, how });
            }
            if !self.freeing_allowed() {
                return Err(SysError::Failed("reference mutation fence open"));
            }
        }
        if !self.machine.durable().uncertain_acquires.is_empty()
            || matches!(
                self.machine.durable().reference_intent,
                Some(ReferenceIntent::Acquire(_))
            )
        {
            return Err(SysError::Failed("pf reference ownership unknown"));
        }
        // Capture AFTER every settlement, which increments acquisition_revision.
        let durable = self.machine.durable();
        let current = durable
            .pf_reference
            .or_else(|| durable.older_references.first().copied());
        Ok(Event::ReferenceReconciled {
            context: self.machine.context(),
            current,
            predecessor: durable
                .older_references
                .iter()
                .copied()
                .find(|t| Some(*t) != current),
        })
    }
}
fn failure(error: &SysError, now: u64) -> Event {
    match error {
        SysError::Failed(reason) => Event::Failed(Reason::Observation(reason)),
        _ => Event::Failed(Reason::Unknown { since: now }),
    }
}

/// Rule 1 requires two known, different boots at every settlement entry point.
pub(super) fn boot_changed(entry: &RefEvidence, current: Option<&crate::snapshot::BootId>) -> bool {
    entry
        .boot
        .as_ref()
        .zip(current)
        .is_some_and(|(old, now)| old != now)
}
