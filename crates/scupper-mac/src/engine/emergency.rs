//! Independent bounded safety path: no reducer completion is required.
use super::{
    CHILD_PATH, Clock, Deadline, Engine, Enumeration, Event, Fence, PINNED_TOOLS, Path, Platform,
    StartFence, Step, Sweep, SysError, Verdict, platform, verify,
};
use scupper_core::mac::{
    parse, policy,
    verify::{Action, Reason, StateEvidence},
};

impl<P: Platform> Engine<P> {
    pub(super) fn invalidate_blocking(&mut self, event: &Event) {
        if matches!(
            event,
            Event::Completed(Step::RemoveAnchor | Step::ClearIntent)
                | Event::Repair(_)
                | Event::Observed {
                    verdict: Verdict::Repair(_),
                    ..
                }
                | Event::Failed(Reason::Observation(
                    "anchor readback mismatch" | "anchor missing on readback"
                ))
        ) {
            self.verified_enforcement = false;
            self.emergency_proof = None;
        }
    }

    /// Cache only definite results. An incomplete first read must retry, while
    /// later enumeration glitches cannot change this incarnation's ownership.
    pub(super) fn check_startup_invariant(&mut self) -> bool {
        if !self.startup_invariant_checked && !self.startup_invariant_failed {
            let own = self.platform.incarnation();
            if own.pid == own.pgid {
                let d = self.emergency_drain_deadline();
                let procs = match self.platform.processes(d) {
                    Enumeration::Complete(procs) => procs,
                    Enumeration::Incomplete(error) => {
                        debug_assert_ne!(self.start_fence, StartFence::Closed);
                        self.start_fence = StartFence::Processes(Sweep::Incomplete(error));
                        return false;
                    }
                };
                self.startup_invariant_failed = !procs.iter().any(|p| {
                    p.pid == own.pid && p.start == own.start && p.ppid == 1 && p.pgid == own.pid
                });
            } else {
                self.startup_invariant_failed = true;
            }
            self.startup_invariant_checked = true;
        }
        self.startup_invariant_checked && !self.startup_invariant_failed
    }

    pub(super) fn prepare_emergency_fence(&mut self) -> bool {
        self.check_startup_invariant() && self.close_emergency_fence()
    }

    pub(super) fn close_emergency_fence(&mut self) -> bool {
        if self.start_fence != StartFence::Closed {
            let tools: Vec<_> = PINNED_TOOLS.iter().map(Path::new).collect();
            let overall = self.emergency_drain_deadline();
            self.start_fence = platform::poll_start_fence(
                &mut self.platform,
                self.previous_helper.clone(),
                &tools,
                Path::new(CHILD_PATH),
                &[],
                &self.timings,
                overall,
            );
        }
        self.start_fence == StartFence::Closed
    }

    fn emergency_drain_deadline(&mut self) -> Deadline {
        self.emergency_drain_until
            .unwrap_or_else(|| Deadline(self.platform.now().saturating_add(1)))
    }

    /// Revoke first, then kill exact live tool identities and reap before removal.
    pub(super) fn cancel_emergency_tools(&mut self) -> bool {
        if let Fence::Open(tools) = self.platform.fence() {
            let d = self.emergency_drain_deadline();
            if let Enumeration::Complete(procs) = self.platform.processes(d) {
                for tool in tools {
                    if let Some(proc) = procs.iter().find(|proc| proc.pid == tool.pid) {
                        let d = self.emergency_drain_deadline();
                        let _ = self.platform.kill_process(proc.pid, proc.start, d);
                    }
                }
            }
        }
        let d = self.emergency_drain_deadline();
        self.platform.reap(d) == Fence::Closed
    }

    pub(super) fn held_emergency_due(&self) -> bool {
        let durable = self.machine.durable();
        if self.emergency_revoked
            || self.snapshot.internal_error.is_none()
            || !durable.hold
            || !durable.join_intended
            || durable.leaving
            || durable.leave_requested
        {
            return false;
        }
        // Park only when reference debt puts reconciliation ahead of the
        // blocking prefix. Every token/acquisition shape follows the same rule.
        if !self.emergency_loaded
            && (self.verified_enforcement
                || matches!(
                    self.machine.pending(),
                    Some(
                        Step::AcquireReference
                            | Step::LoadPreTunnel
                            | Step::VerifyPreTunnelLoad
                            | Step::FlushStates
                            | Step::VerifyPreTunnel
                            | Step::CheckTools
                    )
                ))
        {
            return false;
        }
        true
    }

    pub(super) fn run_held_emergency(&mut self) -> bool {
        if !self.held_emergency_due() {
            return false;
        }
        self.run_emergency();
        true
    }

    pub(super) fn emergency_is_stateless(&mut self) -> bool {
        self.lockless.is_some()
            || self.storage_waiting
            || self.startup_error.is_some()
            || !self.startup_invariant_checked
            || self.start_fence != StartFence::Closed
            || self.platform.fence() != Fence::Closed
    }

    pub(super) fn containment_allowed(&self) -> bool {
        let durable = self.machine.durable();
        !self.emergency_revoked
            && !durable.leaving
            && !durable.leave_requested
            && !self.snapshot.machine.leaving
            && !self.snapshot.machine.leave_requested
            && !self.left_verified
    }

    pub(super) fn attempt_stateless_containment(&mut self) {
        if !self.containment_allowed() {
            return;
        }
        let now = self.platform.now();
        if self.storage_proof_exemption(now) {
            return;
        }
        if self.in_emergency_step {
            self.maintain_emergency_frame();
            return;
        }
        let verdict = self.load_emergency();
        self.platform
            .report_safety(platform::SafetyEvent::LocklessVerdict(Box::new(verdict)));
    }

    fn maintain_emergency_frame(&mut self) {
        if !self.containment_allowed() {
            return;
        }
        // Repair and verify policy before any enable, including after a
        // simultaneous foreign disable and anchor replacement.
        let verified = if self.emergency_pfctl_capacity().is_ok() {
            let d = self.deadline();
            match self.platform.read_anchor(d) {
                Ok(Some(text)) => self.guarded_lockdown_matches(&text),
                Ok(None) | Err(_) => false,
            }
        } else {
            false
        };
        if !verified {
            self.emergency_guard_reload_pending = true;
            self.emergency_guard_flush_pending = true;
            self.emergency_frame_disturbed = true;
        }
        let now = self.platform.now();
        let reload_at = self.emergency_guard_next_reload.max(
            self.emergency_last_load_at
                .map_or(0, |at| at.saturating_add(1)),
        );
        if self.emergency_guard_reload_pending
            && now >= reload_at
            && self.emergency_pfctl_capacity().is_ok()
        {
            self.emergency_guard_next_reload = now.saturating_add(1);
            let d = self.deadline();
            if self.platform.check_pfctl(d).is_ok() && self.emergency_pfctl_capacity().is_ok() {
                // A failed load may still have changed policy. It also needs
                // a flush, and neither failure can clear the repair latch.
                self.emergency_guard_flush_pending = true;
                self.emergency_frame_disturbed = true;
                let d = self.deadline();
                let loaded = self.platform.load_anchor(&policy::render_lockdown(), d);
                self.emergency_last_load_at = Some(self.platform.now());
                if loaded.is_ok() && self.capture_guarded_lockdown() {
                    self.emergency_guard_reload_pending = false;
                }
            }
        }
        if self.emergency_pfctl_capacity().is_ok() {
            let d = self.deadline();
            if self.platform.pf_info(d) != platform::PfInfo::Enabled {
                self.anonymous_enable_confirmed = false;
                self.emergency_guard_flush_pending = true;
                self.emergency_frame_disturbed = true;
                self.reset_emergency_flush();
                self.emergency_needs_reference = true;
                let _ = self.enable_guarded_anonymous();
            }
        }
        // Flush once, after all policy/enable repairs in this slice. This is
        // containment only: it never establishes outer clean-state evidence.
        if self.emergency_guard_flush_pending
            && self.platform.now() >= self.emergency_guard_next_flush
            && self.emergency_pfctl_capacity().is_ok()
        {
            self.emergency_guard_next_flush = self.platform.now().saturating_add(1);
            let d = self.deadline();
            if self.platform.flush_states(d).is_ok() {
                self.emergency_guard_flush_pending = false;
            }
        }
    }

    pub(super) fn prepare_anonymous_enable(&mut self) -> Result<(), SysError> {
        if !self.containment_allowed() {
            return Err(SysError::Failed("containment revoked"));
        }
        self.emergency_pfctl_capacity()?;
        let d = self.deadline();
        self.platform.check_pfctl(d)?;
        if !self.capture_guarded_lockdown() {
            if self
                .emergency_last_load_at
                .is_some_and(|at| self.platform.now() <= at)
                || self.machine.pre_tunnel_policy() == super::Kind::Lockdown
                    && self
                        .last_ordinary_load_at
                        .is_some_and(|at| self.platform.now() <= at)
            {
                return Err(SysError::Failed("policy load pending"));
            }
            self.emergency_pfctl_capacity()?;
            let d = self.deadline();
            let loaded = self.platform.load_anchor(&policy::render_lockdown(), d);
            self.emergency_last_load_at = Some(self.platform.now());
            loaded?;
            self.emergency_loaded = true;
            if !self.capture_guarded_lockdown() {
                return Err(SysError::Failed("blocking policy readback unavailable"));
            }
        }
        // An installation's reviewed policy can check invocation without
        // qualifying this build for a protection claim.
        let qualification = self
            .platform
            .firewall_qualification()
            .or_else(|| {
                self.install
                    .as_ref()
                    .map(|install| install.config.qualification.clone())
            })
            .ok_or(SysError::Failed("firewall unqualified"))?;
        let text = self.emergency_readback.as_ref().ok_or(SysError::Unknown)?;
        let baseline = verify::capture_lockdown_baseline(text, &qualification.normalization)
            .map_err(|_| SysError::Failed("blocking policy mismatch"))?;
        let context = self.machine.context();
        let expected = verify::LockdownExpected {
            context,
            baseline,
            qualification,
            max_age: self.timings.max_age,
        };
        self.emergency_pfctl_capacity()?;
        let d = self.deadline();
        let observations = self
            .platform
            .collect_lockdown(context, StateEvidence::Unproven, d)?;
        verify::verify_lockdown_policy(&observations, &expected, &Clock(self.platform.now()))
            .map_err(|_| SysError::Failed("blocking policy unavailable"))?;
        // Pass states from the disabled interval must not survive enablement.
        let now = self.platform.now();
        let guarded = self.in_emergency_step;
        let next_flush = if guarded {
            self.emergency_guard_next_flush
        } else {
            self.emergency_next_flush
        };
        if now < next_flush {
            return Err(SysError::Failed("pre-enable flush pending"));
        }
        self.emergency_pfctl_capacity()?;
        let d = self.deadline();
        let flushed = self.platform.flush_states(d);
        if guarded {
            self.emergency_guard_next_flush = self.platform.now().saturating_add(1);
            self.emergency_guard_flush_pending = flushed.is_err();
        } else if flushed.is_err() {
            self.emergency_next_flush = self
                .platform
                .now()
                .saturating_add(self.emergency_flush_delay);
            self.emergency_flush_delay = self.emergency_flush_delay.saturating_mul(2).min(60);
        }
        flushed
    }

    fn enable_guarded_anonymous(&mut self) -> Result<(), SysError> {
        self.enable_emergency_without_reference(false)
    }

    fn guarded_lockdown_matches(&self, text: &str) -> bool {
        let normalization = self.platform.firewall_qualification().map_or_else(
            || verify::Normalization {
                expanded_lists: true,
                named_icmp: true,
                implicit_tcp_flags: true,
            },
            |q| q.normalization,
        );
        verify::capture_lockdown_baseline(text, &normalization).is_ok()
    }

    fn capture_guarded_lockdown(&mut self) -> bool {
        let mut reads = Vec::new();
        for _ in 0..2 {
            if self.emergency_pfctl_capacity().is_err() {
                self.emergency_readback = None;
                return false;
            }
            let d = self.deadline();
            reads.push(self.platform.read_anchor(d));
        }
        self.emergency_readback = match (&reads[0], &reads[1]) {
            (Ok(Some(first)), Ok(Some(second)))
                if first == second && self.guarded_lockdown_matches(second) =>
            {
                Some(second.clone())
            }
            _ => None,
        };
        self.emergency_readback.is_some()
    }

    pub(super) fn reset_emergency_frame(&mut self) {
        self.emergency_frame_disturbed = false;
        self.emergency_guard_reload_pending = false;
        self.emergency_guard_flush_pending = false;
        self.emergency_guard_next_reload = self.platform.now();
        self.emergency_guard_next_flush = self.platform.now();
    }

    pub(super) fn run_emergency(&mut self) {
        if self.startup_invariant_failed
            || !self.containment_allowed()
            || !(self.machine.durable().join_intended
                || self.snapshot.machine.join_intended
                || self.committed.machine.join_intended)
            || self.platform.now() < self.next_emergency
        {
            return;
        }
        let cadence = self.platform.now().saturating_add(1);
        // D-3: containment precedes inventory, sweeping and own-tool drainage.
        // These exact stateless commands may race stale writers; no proof is
        // published until all writers are reaped and the fence has closed.
        if self.emergency_is_stateless() {
            self.attempt_stateless_containment();
        }
        self.emergency_drain_until = Some(Deadline(self.platform.now().saturating_add(1)));
        let ready = self.prepare_emergency_fence();
        // waitpid for our children is safe even while the first process inventory
        // is incomplete. It neither signals nor grants mutation authority.
        if !self.startup_invariant_failed {
            let d = self.emergency_drain_deadline();
            let _ = self.platform.reap_children(d);
        }
        let reaped = !self.startup_invariant_failed && self.cancel_emergency_tools();
        self.emergency_drain_until = None;
        if ready && reaped {
            let d = self.deadline();
            // Cheap checks also detect anchor loss while readback is unavailable.
            // Positive checks never extend proof age.
            if let Ok(cheap) = self.platform.cheap_check(self.child.as_ref(), d) {
                if !cheap.anchor_present {
                    if !self.emergency_anchor_absent {
                        self.reset_emergency_flush();
                    }
                    self.reset_reload_after_absence();
                }
                self.emergency_anchor_absent = !cheap.anchor_present;
                if !cheap.pf_enabled {
                    // States created while pf was off require a fresh flush,
                    // even if the independent pf-info read is unavailable.
                    self.reset_emergency_flush();
                }
                if !cheap.pf_enabled || !cheap.anchor_present {
                    self.verified_enforcement = false;
                    self.emergency_proof = None;
                }
            }
            if self.verified_enforcement {
                if self.emergency_anchor_drifted() {
                    self.verified_enforcement = false;
                    self.emergency_proof = None;
                }
                if self.verified_enforcement && self.platform.now() >= self.next_full {
                    self.next_full = self.platform.now().saturating_add(self.timings.full_walk);
                    self.reverify_emergency();
                }
            }
            // Unknown observations preserve installation knowledge only while
            // the last full proof is fresh. Cheap positives never renew it.
            if self.verified_enforcement
                && self
                    .last_fresh_proof_at
                    .is_none_or(|at| self.platform.now().saturating_sub(at) > self.timings.max_age)
            {
                self.verified_enforcement = false;
            }
            if !self.verified_enforcement {
                self.emergency_proof = None;
                if let Ok(Verdict::Protected(proof)) = self.load_emergency() {
                    self.last_fresh_proof_at = Some(proof.verified_at());
                    self.emergency_flush_delay = 1;
                    self.emergency_proof = Some(proof);
                    self.verified_enforcement = true;
                    self.next_full = self.platform.now().saturating_add(self.timings.full_walk);
                }
            }
        } else {
            let now = self.platform.now();
            // An unreapable non-Pfctl tool cannot change the firewall. Keep
            // this incarnation's current policy proof until expiry or loss;
            // publication still masks it while the general fence is open.
            if !self.storage_proof_exemption(now) {
                self.verified_enforcement = false;
                self.emergency_proof = None;
            }
        }
        // Cadence is anchored before drainage, not one second after it.
        self.next_emergency = cadence;
    }

    fn emergency_anchor_drifted(&mut self) -> bool {
        let baseline = self
            .emergency_baseline
            .as_ref()
            .map(|(b, _)| b)
            .or(self.baseline.as_ref())
            .cloned();
        let Some(baseline) = baseline else {
            return false;
        };
        let d = self.deadline();
        match self.platform.read_anchor(d) {
            Ok(Some(text)) => {
                let changed = self
                    .emergency_readback
                    .as_ref()
                    .is_some_and(|old| *old != text);
                if changed {
                    self.reset_reload_after_absence();
                }
                changed || normalized_readback(&text) != baseline.text()
            }
            // An unavailable observation preserves the proof only until max_age.
            Ok(None) => true,
            Err(_) => false,
        }
    }

    fn reverify_emergency(&mut self) {
        if self.platform.firewall_qualification().is_none() {
            self.verified_enforcement = false;
            self.emergency_proof = None;
            return;
        }
        let verdict = if self.emergency_baseline.is_some() {
            self.verify_emergency()
        } else {
            let form = self
                .baseline
                .as_ref()
                .map_or(super::Form::PreTunnel, verify::Baseline::form);
            self.collect_verdict(form).and_then(|event| match event {
                Event::Observed { verdict, .. } => Ok(verdict),
                _ => Err(SysError::Unknown),
            })
        };
        match verdict {
            Ok(Verdict::Protected(proof))
                if matches!(
                    Verdict::Protected(proof.clone()).at(&Clock(self.platform.now())),
                    Verdict::Protected(_)
                ) =>
            {
                self.last_fresh_proof_at = Some(proof.verified_at());
                self.emergency_flush_delay = 1;
                self.emergency_proof = Some(proof);
            }
            Ok(
                Verdict::Repair(Action::EnableAndRejoin | Action::Rejoin)
                | Verdict::NotProtected(
                    Reason::HookMissing
                    | Reason::QuickPass
                    | Reason::TranslationPresent
                    | Reason::Skip(_)
                    | Reason::Unsupported(_)
                    | Reason::ToolIntegrity,
                ),
            ) => {
                self.verified_enforcement = false;
                self.emergency_proof = None;
            }
            // Unknown, collection errors, and tunnel-only repairs neither
            // revoke an installed kill switch nor renew a proof.
            _ => {
                self.emergency_proof = None;
            }
        }
    }

    /// The fence contains only this engine's unreaped mutating tool children.
    /// Even an ineffective SIGKILL must not permit unlimited pfctl accumulation.
    pub(super) fn emergency_pfctl_capacity(&mut self) -> Result<(), SysError> {
        let unreaped = self.unreaped_pfctl();
        if unreaped >= 2 {
            self.platform
                .report_safety(platform::SafetyEvent::PfctlCapacity { unreaped });
            return Err(SysError::Failed("own pfctl child limit"));
        }
        Ok(())
    }

    pub(super) fn unreaped_pfctl(&mut self) -> usize {
        match self.platform.fence() {
            Fence::Closed => 0,
            Fence::Open(tools) => tools
                .iter()
                .filter(|tool| tool.tool == platform::Tool::Pfctl)
                .count(),
        }
    }

    pub(super) fn emergency_frame_needs_guard(&mut self) -> bool {
        !self.emergency_is_stateless()
    }

    pub(super) fn load_emergency(&mut self) -> Result<Verdict, SysError> {
        if !self.containment_allowed() {
            return Err(SysError::Failed("containment revoked"));
        }
        let was_in_step = self.in_emergency_step;
        if !was_in_step {
            self.reset_emergency_frame();
        }
        self.in_emergency_step |= self.emergency_frame_needs_guard();
        let result = self.load_emergency_inner();
        self.in_emergency_step = was_in_step;
        result
    }

    #[allow(clippy::too_many_lines)] // Keep load, enable, pre-flush verification and final proof in order.
    fn load_emergency_inner(&mut self) -> Result<Verdict, SysError> {
        self.emergency_pfctl_capacity()?;
        let d = self.deadline();
        let integrity = if self.emergency_is_stateless() {
            self.platform.check_pfctl(d)
        } else {
            self.platform.check_tools(d)
        };
        if let Err(error) = integrity {
            // Other tools can prevent a proof, but only pfctl integrity gates
            // containment. Keep the all-tools failure for the caller's verdict.
            self.emergency_pfctl_capacity()?;
            let d = self.deadline();
            self.platform.check_pfctl(d)?;
            self.emergency_pfctl_capacity()?;
            let d = self.deadline();
            if self.platform.pf_info(d) != platform::PfInfo::Enabled {
                let _ = self.prepare_anonymous_enable();
            }
            let _ = self.enable_emergency_pf();
            return Err(error);
        }
        let qualification = self.platform.firewall_qualification();
        let normalization = qualification.as_ref().map_or_else(
            || verify::Normalization {
                expanded_lists: true,
                named_icmp: true,
                implicit_tcp_flags: true,
            },
            |q| q.normalization.clone(),
        );
        let mut readback = if self.emergency_loaded {
            let d = self.deadline();
            self.platform.read_anchor(d)
        } else {
            Err(SysError::Unknown)
        };
        if matches!(readback, Ok(None)) {
            self.reset_reload_after_absence();
        }
        if matches!(&readback, Ok(Some(text))
            if self.emergency_readback.as_ref().is_some_and(|old| old != text))
        {
            // A positive raw change overrides observation backoff, including on
            // unqualified builds and stale qualification records.
            self.reset_reload_after_absence();
        }
        let stable = matches!(&readback, Ok(Some(text))
            if self.emergency_readback.as_ref().is_some_and(|loaded|
                *loaded == *text)
            && !matches!(verify::capture_lockdown_baseline(text, &normalization),
                Err(verify::CaptureError::Mismatch(_))));
        if stable {
            self.emergency_reload_delay = 1;
            self.emergency_next_reload = self.platform.now();
        } else if self.platform.now() >= self.emergency_next_reload {
            let d = self.deadline();
            self.emergency_pfctl_capacity()?;
            let loaded = self.platform.load_anchor(&policy::render_lockdown(), d);
            let now = self.platform.now();
            self.emergency_last_load_at = Some(now);
            // Observation drift backs off only after an own load has succeeded.
            // Before that, tool recovery must restore protection within 1 s.
            if !self.emergency_loaded && loaded.is_err() {
                self.emergency_reload_delay = 1;
                self.emergency_next_reload = now.saturating_add(1);
            } else {
                self.emergency_next_reload = now.saturating_add(self.emergency_reload_delay);
                self.emergency_reload_delay = self.emergency_reload_delay.saturating_mul(2).min(60);
            }
            if let Err(error) = loaded {
                // A failed policy load still reaches enablement. Reserve a
                // counted reference when possible; otherwise use containment.
                let _ = self.enable_emergency_pf();
                return Err(error);
            }
            if self.emergency_loaded {
                // Reload closes a possible foreign-policy gap. Flush now, but
                // preserve D3 so persistent observation drift cannot reset it.
                self.emergency_states_clean_at = None;
                self.emergency_next_flush = self.platform.now();
            } else {
                self.reset_emergency_flush();
            }
            self.emergency_loaded = true;
            self.emergency_anchor_absent = false;
            self.emergency_baseline = None;
            readback = self.capture_post_load_readback();
        }
        if !self.emergency_loaded {
            return Err(SysError::Failed("emergency load pending"));
        }
        // A successful own load always reaches enablement. Read-back failures
        // govern reload and proof, never permission to turn filtering on.
        let mut baseline = readback
            .ok()
            .flatten()
            .filter(|text| self.emergency_readback.as_ref() == Some(text))
            .and_then(|text| verify::capture_lockdown_baseline(&text, &normalization).ok());
        let enabled = self.enable_emergency_pf();
        if self.emergency_frame_disturbed {
            // Losing the comparison readback must also reset observation backoff,
            // even when guarded repair has already cleared both latches.
            self.reset_reload_after_absence();
            self.emergency_readback = None;
            self.emergency_baseline = None;
            self.emergency_proof = None;
            self.verified_enforcement = false;
            baseline = None;
            self.reset_emergency_flush();
        }
        if enabled == Ok(true) && self.emergency_states_clean_at.is_some() {
            self.reset_emergency_flush();
        }
        // A failed enable can have taken effect. It must not strand old states.
        // Read enabled status again before verification and the state-only flush.
        let d = self.deadline();
        let pf_enabled = self.platform.pf_info(d) == platform::PfInfo::Enabled;
        if pf_enabled && self.emergency_states_clean_at.is_none() && self.emergency_flush_delay == 1
        {
            // The pre-enable flush must not postpone the first post-fence proof.
            // Guarded/pre-fence containment never grants outer clean evidence.
            self.reset_emergency_flush();
        }
        if let (Some(baseline), Some(_)) = (baseline.clone(), qualification.as_ref()) {
            self.emergency_baseline = Some((baseline, self.platform.now()));
            let verdict = self.verify_emergency_with_states(StateEvidence::Unproven);
            self.platform
                .report_safety(platform::SafetyEvent::LocklessVerdict(Box::new(verdict)));
            self.emergency_baseline = None;
        }
        if self.platform.now() >= self.emergency_next_flush {
            let d = self.deadline();
            self.emergency_pfctl_capacity()?;
            let flushed = self.platform.flush_states(d);
            self.emergency_next_flush = self
                .platform
                .now()
                .saturating_add(self.emergency_flush_delay);
            self.emergency_flush_delay = self.emergency_flush_delay.saturating_mul(2).min(60);
            flushed?;
            self.emergency_states_clean_at = Some(self.platform.now());
        }
        enabled?;
        if qualification.is_none() {
            return Err(SysError::Failed("firewall unqualified"));
        }
        let baseline = baseline.ok_or(SysError::Failed("emergency readback unavailable"))?;
        let completed_at = self
            .emergency_states_clean_at
            .ok_or(SysError::Failed("emergency flush unavailable"))?;
        self.emergency_baseline = Some((baseline, completed_at));
        let verdict = self.verify_emergency()?;
        if matches!(verdict, Verdict::Protected(_)) {
            self.emergency_reload_delay = 1;
            self.emergency_next_reload = self.platform.now().saturating_add(1);
        }
        Ok(verdict)
    }

    fn capture_post_load_readback(&mut self) -> Result<Option<String>, SysError> {
        let d = self.deadline();
        let first = self.platform.read_anchor(d);
        let d = self.deadline();
        let second = self.platform.read_anchor(d);
        self.emergency_readback = match (&first, &second) {
            (Ok(Some(first)), Ok(Some(second))) if first == second => Some(first.clone()),
            _ => None,
        };
        if matches!((&first, &second), (Ok(Some(a)), Ok(Some(b))) if a != b)
            || matches!(first, Ok(None))
            || matches!(second, Ok(None))
        {
            // Positive drift/absence retries in 1 s. Unreadable observations
            // after a successful load retain the existing bounded backoff.
            self.reset_reload_after_absence();
        }
        second
    }

    fn reset_reload_after_absence(&mut self) {
        self.emergency_readback = None;
        self.emergency_reload_delay = 1;
        // Positive absence overrides drift backoff without allowing load storms.
        self.emergency_next_reload = self
            .emergency_last_load_at
            .map_or_else(|| self.platform.now(), |at| at.saturating_add(1));
    }

    pub(super) fn reset_emergency_flush(&mut self) {
        self.emergency_states_clean_at = None;
        self.emergency_next_flush = self.platform.now();
        self.emergency_flush_delay = 1;
    }

    fn verify_emergency(&mut self) -> Result<Verdict, SysError> {
        let (_, completed_at) = self
            .emergency_baseline
            .clone()
            .ok_or(SysError::Failed("emergency baseline absent"))?;
        let context = self.machine.context();
        self.verify_emergency_with_states(StateEvidence::Clean {
            epoch: context.state_epoch,
            completed_at,
        })
    }

    fn verify_emergency_with_states(&mut self, states: StateEvidence) -> Result<Verdict, SysError> {
        let (baseline, _) = self
            .emergency_baseline
            .clone()
            .ok_or(SysError::Failed("emergency baseline absent"))?;
        let context = self.machine.context();
        let expected = verify::LockdownExpected {
            context,
            baseline,
            qualification: self
                .platform
                .firewall_qualification()
                .ok_or(SysError::Failed("firewall unqualified"))?,
            max_age: self.timings.max_age,
        };
        let d = self.deadline();
        let observations = self.platform.collect_lockdown(context, states, d)?;
        Ok(verify::verify_lockdown(
            &observations,
            &expected,
            &Clock(self.platform.now()),
        ))
    }
}

// Valid text uses exactly the verifier's normalization. Unsupported output is
// retained byte-for-byte: stable unparseable output must not cause a load storm.
fn normalized_readback(text: &str) -> String {
    parse::pf_rules(text).map_or_else(|_| text.to_owned(), |rules| rules.normalized().to_owned())
}
