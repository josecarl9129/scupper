//! Serialized checked effects and durable, resumable owned cleanup.
use std::collections::BTreeSet;

use super::{
    Error, PhysicalInterface, Tunnel, TunnelGeneration,
    policy::Form,
    verify::{Action, Baseline, Context, Reason, SleepCountingClock, Transport, Verdict},
};

/// One bounded serialized effect. Completion confirms its outcome, not just exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Idle until this deadline in the injected sleep-counting clock (seconds).
    /// The executor waits interruptibly; Leave cancels this step immediately.
    Backoff {
        /// Earliest time at which the delayed effect may start.
        until: u64,
    },
    /// Persist join intent.
    PersistIntent,
    /// Persist cancellation of join and the complete owned-cleanup journal.
    PersistLeaving,
    /// Acquire a reference only after its intent is journaled.
    AcquireReference,
    /// Resolve ownership debt; one uncertain acquire permits one replacement.
    ReconcileReference,
    /// Load the complete pre-tunnel anchor.
    LoadPreTunnel,
    /// Semantically check the planned pre-tunnel read-back (not full enforcement).
    VerifyPreTunnelLoad,
    /// Flush all states with a checked outcome.
    FlushStates,
    /// Full pre-tunnel verification.
    VerifyPreTunnel,
    /// Check installed executables after enforcement.
    CheckTools,
    /// Persist the next child generation before spawning.
    ReserveGeneration,
    /// Spawn the reserved generation.
    StartChild,
    /// Configure/read back UAPI.
    ConfigureUapi,
    /// Configure/read back addresses.
    ConfigureAddresses,
    /// Configure/read back MTU.
    ConfigureMtu,
    /// Configure/read back endpoint route.
    ConfigureEndpointRoute,
    /// Configure/read back split routes.
    ConfigureSplitRoutes,
    /// Configure/read back DNS.
    ConfigureDns,
    /// Check supervised current-generation identity.
    VerifyIdentity,
    /// Load joined anchor.
    LoadJoined,
    /// Semantically validate joined read-back and capture its intended baseline.
    VerifyJoinedLoad,
    /// Full joined verification.
    VerifyJoined,
    /// Remove and verify absence of states bound to vanished DHCP interfaces.
    RemoveVanishedInterfaceStates,
    /// Replace current policy without stopping the child.
    ReplaceAnchor(Form),
    /// Semantically validate replacement read-back and capture its new baseline.
    VerifyReplacement(Form),
    /// Stop and reap owned child.
    StopChild,
    /// Remove owned routes.
    CleanupRoutes,
    /// Remove owned DNS key.
    CleanupDns,
    /// Remove owned sockets and generation artifacts.
    CleanupArtifacts,
    /// Confirm owned anchor contents removed.
    RemoveAnchor,
    /// Confirm every recorded owned reference released; retain unresolved tokens on failure.
    ReleaseReference,
    /// Clear Leave intent after connectivity cleanup, retaining reference accounting.
    ClearIntent,
}
const CLEANUP: [Step; 5] = [
    Step::StopChild,
    Step::CleanupRoutes,
    Step::CleanupDns,
    Step::CleanupArtifacts,
    Step::RemoveAnchor,
];
/// Tunnel health is independent of firewall enforcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelHealth {
    /// No configured child.
    Down,
    /// Configured, awaiting fresh handshake.
    AwaitingHandshake,
    /// Fresh current-generation handshake.
    Healthy,
}
/// Connection progress, separate from enforcement and handshake health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// No join is intended.
    Idle,
    /// Join is intended but fresh joined enforcement has not been established.
    JoiningRecovering,
    /// Automatic recovery is delayed; the durable last error remains available via `failure`.
    Recovering {
        /// Seconds remaining in the sleep-counting clock domain.
        retry_in: u64,
    },
    /// Recovery hold cannot claim protection or promise an automatic rejoin.
    NotProtected {
        /// Explanation for the user.
        reason: &'static str,
        /// The latest pre-tunnel blocking proof is still fresh.
        blocking_verified: bool,
    },
    /// Fresh joined enforcement with a supervised child; handshake health is separate.
    Joined,
    /// Authorized leave or its cleanup is pending.
    Leaving,
}
impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => f.write_str("idle"),
            Self::JoiningRecovering => f.write_str("joining/recovering"),
            Self::Joined => f.write_str("joined"),
            Self::Leaving => f.write_str("leaving"),
            Self::Recovering { retry_in } => write!(f, "recovering (retry in {retry_in}s)"),
            Self::NotProtected {
                reason,
                blocking_verified,
            } => {
                f.write_str(reason)?;
                if *blocking_verified {
                    f.write_str("; blocking verified")?;
                }
                Ok(())
            }
        }
    }
}
/// Unresolved kernel reference operation. Persist before executing the effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceIntent {
    /// Acquisition identified by the durable sequence; an unknown outcome occupies a slot.
    Acquire(u64),
    /// Checked release of all recorded tokens.
    Release,
}
/// Exact identity of one accounted pf reference or acquisition reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceEntry {
    /// A held kernel enable token.
    Token(u64),
    /// An active or uncertain acquisition sequence.
    Acquire(u64),
}
/// Checked evidence allowing one accounting entry to be removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceSettlement {
    /// A confirmed release.
    Released,
    /// Complete evidence proves the entry absent.
    Absent,
    /// The acquisition had no effect, or its reference has been invalidated.
    Void,
}
/// A closing or joined-verification failure has one immutable retry deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosingRetry {
    /// Observation or failed-effect time.
    pub failed_at: u64,
    /// Next delayed effect, including a bounded same-attempt `VerifyJoined` retry.
    pub target: Step,
    /// Earliest retry time, exactly one second after failure.
    pub until: u64,
}
/// Journal facts persisted by the executor at each checked boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent persisted intent, cancellation and ownership facts.
pub struct Durable {
    /// Monotonic verification identity, persisted at checked boundaries.
    pub verification_context: Context,
    /// Join intent; durably cancelled by `PersistLeaving`.
    pub join_intended: bool,
    /// Recovery refuses Join and keeps only pre-tunnel enforcement until Leave.
    /// Retained through Leaving; `ClearIntent` clears both hold and join intent.
    pub hold: bool,
    /// Failed rejoin attempts, saturated at the 60-second delay cap.
    /// Persist with intent before exposing the next effect, including across restart.
    pub retry_attempts: u8,
    /// Authorized cancellation, persisted even while a subprocess settles.
    pub leave_requested: bool,
    /// Suppresses automatic rejoin and uninstall metadata deletion.
    pub leaving: bool,
    /// Most recently acquired owned reference.
    pub pf_reference: Option<u64>,
    /// At most one possibly live unresolved predecessor; never truncate live tokens.
    pub older_references: Vec<u64>,
    /// Persisted before a kernel reference operation is exposed.
    pub reference_intent: Option<ReferenceIntent>,
    /// Acquisitions whose kernel outcome is unresolved, each occupying one ownership slot.
    pub uncertain_acquires: Vec<u64>,
    /// Reconcile ordering after a disable observed while an acquire was in flight.
    /// Separate from the sequenced intent, which observations must never rewrite.
    pub reference_needs_reconcile: bool,
    /// Last reconciliation failure, retained independently of enforcement proofs.
    pub reference_error: Option<Reason>,
    /// Never reuse an acquire transaction identity across restart.
    pub reference_sequence: u64,
    /// Latest enforcement evidence, separate from connection failures.
    pub enforcement_error: Option<Reason>,
    /// Reserved child generation; reservation precedes spawn.
    pub previous_generation: Option<TunnelGeneration>,
    /// Unconfirmed owned cleanup, retried after restart.
    pub pending_cleanup: Vec<Step>,
    /// Per-step unresolved cleanup failures, retained until confirmed success.
    pub cleanup_errors: Vec<(Step, Reason)>,
    /// Durable failure retained through pre-tunnel recovery until Joined or completed leave.
    /// A resolved reference/cleanup error clears its matching last error independently.
    /// Never fed back into the verifier.
    pub last_error: Option<Reason>,
}
/// Checked collector/executor events. Protected proofs can only come from verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Explicit join.
    Join,
    /// Authorized leave, accepted even during repair.
    Leave,
    /// Request a checked repair or planned policy replacement.
    Repair(Action),
    /// Supervised child loss.
    ChildDied,
    /// Invalidate evidence, including on wake.
    InvalidateObservations {
        /// Start of the gap.
        since: u64,
    },
    /// A complete read shows pf enabled, independent of the full verdict.
    /// Executors send this even when another read makes that verdict Unknown.
    PfEnabledObserved {
        /// Context captured before the read.
        context: Context,
    },
    /// Ordinary checked effect completion.
    Completed(Step),
    /// Acquire and persist the active transaction; use `ReferenceAcquiredFor` for late results.
    ReferenceAcquired(u64),
    /// Completion of a specific acquisition, including after cancellation or restart.
    ReferenceAcquiredFor {
        /// Durable acquisition transaction identity.
        sequence: u64,
        /// Successfully acquired kernel token.
        token: u64,
    },
    /// Settle exactly one held or uncertain entry. An active acquisition must
    /// first resolve through its own completion (or Failed, then settlement).
    ReferenceSettled {
        /// Exact token or acquisition sequence whose disposition is known.
        entry: ReferenceEntry,
        /// Checked disposition supplied by the executor.
        how: ReferenceSettlement,
    },
    /// Checked reconciliation after exact settlements; these tokens remain owned.
    /// Unresolved acquisitions require Failed, never a guessed summary.
    ReferenceReconciled {
        /// Recaptured after the last settlement of this reference step. The
        /// acquisition revision fences acquisitions/settlements outside that step.
        /// Executors must emit settlements only from the in-flight reference step,
        /// never during verification (where they would stale its proof).
        context: Context,
        /// Checked valid current token. If validity/outcome cannot be established,
        /// reconciliation fails and retains every possibly live token and intent.
        current: Option<u64>,
        /// At most one possibly live predecessor.
        predecessor: Option<u64>,
    },
    /// Durable reservation, before spawning this generation.
    GenerationReserved(TunnelGeneration),
    /// Spawned child identity.
    ChildStarted(Tunnel),
    /// Checked current-generation identity.
    IdentityVerified(Tunnel),
    /// Semantically validated planned read-back; does not publish Protected.
    ReadbackValidated(Baseline),
    /// Checked completion of the pending all-state flush.
    StatesClean {
        /// Current state epoch.
        epoch: u64,
        /// Completion in the sleep-counting clock domain.
        completed_at: u64,
    },
    /// Checked removal and absence of states on exactly the requested interfaces.
    InterfaceStatesRemoved {
        /// Interfaces from `vanished_interfaces`.
        interfaces: BTreeSet<PhysicalInterface>,
        /// Completion in the sleep-counting clock domain.
        completed_at: u64,
    },
    /// Full verifier result.
    Observed {
        /// Context captured before collecting this round, including negative results.
        context: Context,
        /// Observed form.
        form: Form,
        /// Verifier-issued proof or failure.
        verdict: Verdict,
    },
    /// Handshake health only.
    Handshake {
        /// Child incarnation.
        generation: TunnelGeneration,
        /// Fresh handshake.
        fresh: bool,
    },
    /// Checked failed/unknown effect outcome.
    Failed(Reason),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Join,
    Recover,
    Replace,
    Recheck,
    Leave,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClosingRerun {
    Repair(Action),
    Flush,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Closing {
    active: bool,
    rerun: Option<ClosingRerun>,
    unknown: bool,
    retry: Option<ClosingRetry>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct References {
    // Repeated disabled observations must not restart idle exponential backoff.
    observed_pf_disabled: bool,
    // Revision at which pf was observed disabled; never a reference intent.
    pf_disabled_seen: Option<u64>,
    needed: bool,
    retry_at: u64,
    retry_delay: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct HoldCleanupRetry {
    step: Step,
    until: u64,
    delay: u64,
}
/// Pure serialized lifecycle. The executor must persist returned journal changes
/// before exposing the next effect; subprocesses are bounded and settled at boundaries.
/// A deferred Join is in-memory: the executor must replay an unfinished Join after
/// restart and acknowledge it only after `PersistIntent` completes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent cancellation and initial hold cleanup facts.
pub struct Machine {
    durable: Durable,
    pending: Vec<Step>,
    effect_since: u64,
    operation: Option<Operation>,
    leave_requested: bool,
    // An idle reference step already in flight must settle before PersistIntent.
    join_requested: bool,
    abort_requested: bool,
    deferred_repair: Option<Action>,
    baseline: Option<Baseline>,
    transport: Option<Transport>,
    vanished_interfaces: BTreeSet<PhysicalInterface>,
    interface_states_removed_at: Option<u64>,
    enforcement: Verdict,
    context: Context,
    states_clean_at: Option<u64>,
    gap_after: Option<u64>,
    prior_expiry: Option<u64>,
    tunnel_health: TunnelHealth,
    tunnel: Option<Tunnel>,
    last_verified: Option<u64>,
    installed_form: Option<Form>,
    // Start the rejoin timer only when the safety prefix has completed.
    rejoin_delay: Option<u64>,
    rejoin_deadline: Option<u64>,
    closing: Closing,
    invalidated_at: u64,
    references: References,
    settling_flush: Option<u64>,
    joined_unknown_retries: u8,
    // A held restart sweeps old resources once, before becoming idle-held.
    hold_policy: super::policy::Kind,
    hold_cleanup: bool,
    hold_cleanup_retries: Vec<HoldCleanupRetry>,
}
impl Machine {
    /// Restart never restores successful evidence. Authorized cleanup wins over join.
    #[must_use]
    pub fn restart(mut durable: Durable) -> Self {
        if durable.pending_cleanup.contains(&Step::ReleaseReference) {
            durable
                .pending_cleanup
                .retain(|step| *step != Step::ReleaseReference);
            durable.cleanup_errors.push((
                Step::ReleaseReference,
                Reason::Observation("legacy reference release removed from cleanup"),
            ));
        }
        // Migrate the enforcement-only reasons used by the earlier journal.
        if durable.enforcement_error.is_none()
            && matches!(
                durable.last_error,
                Some(Reason::Unknown { .. } | Reason::Repair(_))
            )
        {
            durable.enforcement_error.clone_from(&durable.last_error);
        }
        // Restart has no trusted clock domain/boot identity. No persisted timestamp
        // is evidence in this run, even if its numerical value happens to be small.
        for reason in [&mut durable.last_error, &mut durable.enforcement_error] {
            if matches!(reason, Some(Reason::Unknown { .. })) {
                *reason = Some(Reason::Unknown { since: 0 });
            }
        }
        if let Some(ReferenceIntent::Acquire(sequence)) = durable.reference_intent {
            if !durable.uncertain_acquires.contains(&sequence) {
                durable.uncertain_acquires.push(sequence);
            }
            durable.reference_intent = None;
        }
        let enforcement = durable
            .enforcement_error
            .clone()
            .map_or(Verdict::NeverVerified, Verdict::NotProtected);
        let hold_cleanup = durable.hold && durable.join_intended;
        let mut m = Self {
            durable,
            pending: Vec::new(),
            effect_since: 0,
            operation: None,
            leave_requested: false,
            join_requested: false,
            abort_requested: false,
            deferred_repair: None,
            baseline: None,
            transport: None,
            vanished_interfaces: BTreeSet::new(),
            interface_states_removed_at: None,
            enforcement,
            context: Context::default(),
            states_clean_at: None,
            gap_after: None,
            prior_expiry: None,
            tunnel_health: TunnelHealth::Down,
            tunnel: None,
            last_verified: None,
            installed_form: None,
            rejoin_delay: None,
            rejoin_deadline: None,
            closing: Closing::default(),
            invalidated_at: 0,
            references: References::default(),
            settling_flush: None,
            joined_unknown_retries: 0,
            hold_policy: super::policy::Kind::Installed(Form::PreTunnel),
            hold_cleanup,
            hold_cleanup_retries: Vec::new(),
        };
        m.context = m.durable.verification_context;
        m.invalidate(true);
        if m.durable.leaving {
            m.resume_cleanup();
        } else if m.durable.leave_requested {
            m.operation = Some(Operation::Leave);
            m.pending = vec![Step::PersistLeaving];
        } else if m.durable.join_intended {
            m.references.needed = true;
            m.begin(Operation::Recover, false, 0);
        }
        if m.operation != Some(Operation::Leave)
            && !m.durable.hold
            && (m.reference_debt() || m.durable.reference_intent.is_some())
            && !matches!(
                m.pending(),
                Some(Step::PersistLeaving | Step::ReconcileReference)
            )
        {
            m.pending.insert(0, Step::ReconcileReference);
        }
        m.schedule_reference(0);
        m.prepare_reference();
        m
    }
    /// Restart a held machine with an input-free lockdown expectation.
    /// The expected kind is process-local and recomputed from installation trust
    /// on every restart. Leave is the only transition that clears the hold.
    #[must_use]
    pub fn restart_lockdown(mut durable: Durable) -> Self {
        durable.hold = true;
        let mut machine = Self::restart(durable);
        machine.hold_policy = super::policy::Kind::Lockdown;
        machine
    }
    /// Exact policy required by the closing prefix.
    #[must_use]
    pub fn pre_tunnel_policy(&self) -> super::policy::Kind {
        if self.durable.hold {
            self.hold_policy
        } else {
            super::policy::Kind::Installed(Form::PreTunnel)
        }
    }
    /// Next effect, with at most one in flight.
    #[must_use]
    pub fn pending(&self) -> Option<Step> {
        self.pending.first().copied()
    }
    /// Remaining serialized plan, for executor scheduling and invariant checks.
    #[must_use]
    pub fn plan(&self) -> &[Step] {
        &self.pending
    }
    /// Recorded retry deadline and delayed effect, retained through coalesced evidence.
    #[must_use]
    pub fn closing_retry(&self) -> Option<ClosingRetry> {
        self.closing.retry
    }
    /// Latest recorded gap; a proof cannot validate cleanup predating it.
    #[must_use]
    pub fn gap_after(&self) -> Option<u64> {
        self.gap_after
    }
    /// Human-readable enforcement and recovery status.
    #[must_use]
    pub fn status_text_at(&self, clock: &impl SleepCountingClock) -> String {
        let mut text = if matches!(self.status_at(clock), ConnectionStatus::Recovering { .. })
            && matches!(self.enforcement_at(clock), Verdict::Protected(p) if p.form() == Form::PreTunnel)
        {
            "traffic blocked; tunnel recovering".into()
        } else {
            self.status_at(clock).to_string()
        };
        if let Some(reason) = &self.durable.reference_error {
            use std::fmt::Write;
            let _ = write!(text, "; pf ownership cleanup debt: {reason:?}");
        }
        text
    }
    /// Resumable journal, including unresolved owned tokens.
    #[must_use]
    pub fn durable(&self) -> &Durable {
        &self.durable
    }
    /// Context to capture before starting a full observation round.
    #[must_use]
    pub fn context(&self) -> Context {
        self.context
    }
    /// Installed intended form.
    #[must_use]
    pub fn installed_form(&self) -> Option<Form> {
        self.installed_form
    }
    /// Last checked all-state flush completion, for the current epoch.
    #[must_use]
    pub fn states_clean_at(&self) -> Option<u64> {
        self.states_clean_at
    }
    /// Interfaces whose states the pending removal must eliminate and verify.
    #[must_use]
    pub fn vanished_interfaces(&self) -> &BTreeSet<PhysicalInterface> {
        &self.vanished_interfaces
    }
    /// Current supervised child.
    #[must_use]
    pub fn tunnel(&self) -> Option<&Tunnel> {
        self.tunnel.as_ref()
    }
    /// Expiry is derived at the consumer even if no monitor event arrives.
    #[must_use]
    pub fn enforcement_at(&self, clock: &impl SleepCountingClock) -> Verdict {
        if self.durable.hold {
            Verdict::NotProtected(Reason::Observation("state untrusted: run leave"))
        } else {
            self.enforcement.at(clock)
        }
    }
    /// Fresh pre-tunnel blocking evidence, independent of hold's Protected mask.
    #[must_use]
    pub fn blocking_verified_at(&self, clock: &impl SleepCountingClock) -> bool {
        matches!(self.enforcement.at(clock), Verdict::Protected(proof) if proof.form() == Form::PreTunnel)
    }
    /// Consumer-facing progress; pre-tunnel protection never means a finished join.
    #[must_use]
    pub fn status_at(&self, clock: &impl SleepCountingClock) -> ConnectionStatus {
        if self.durable.leaving || self.durable.leave_requested || self.leave_requested {
            ConnectionStatus::Leaving
        } else if self.durable.hold {
            ConnectionStatus::NotProtected {
                reason: "state untrusted: run leave",
                blocking_verified: self.blocking_verified_at(clock),
            }
        } else if self.durable.join_intended
            && self.tunnel.is_some()
            && matches!(self.enforcement_at(clock), Verdict::Protected(p) if p.form() == Form::Joined)
        {
            ConnectionStatus::Joined
        } else if let Some(Step::Backoff { until }) = self.pending()
            && self.durable.join_intended
        {
            ConnectionStatus::Recovering {
                retry_in: until.saturating_sub(clock.now()),
            }
        } else if self.durable.join_intended
            || self.join_requested
            || matches!(self.operation, Some(Operation::Join | Operation::Recover))
        {
            ConnectionStatus::JoiningRecovering
        } else {
            ConnectionStatus::Idle
        }
    }
    /// Independent handshake health.
    #[must_use]
    pub fn tunnel_health(&self) -> &TunnelHealth {
        &self.tunnel_health
    }
    /// Historical oldest-read time of the last complete verification.
    #[must_use]
    pub fn last_verified(&self) -> Option<u64> {
        self.last_verified
    }
    /// Durable failure for status/notification, never verifier input.
    #[must_use]
    pub fn failure(&self) -> Option<&Reason> {
        self.durable.last_error.as_ref()
    }
    /// Whether all cleanup has been confirmed; uninstall may delete recovery data only then.
    #[must_use]
    pub fn cleanup_confirmed(&self) -> bool {
        self.connectivity_restored()
            && self.pending.is_empty()
            && self.durable.pf_reference.is_none()
            && self.durable.older_references.is_empty()
            && self.durable.reference_intent.is_none()
            && !self.durable.reference_needs_reconcile
            && self.durable.uncertain_acquires.is_empty()
    }
    /// Whether Leave restored connectivity, independently of reference accounting.
    #[must_use]
    pub fn connectivity_restored(&self) -> bool {
        !self.durable.leaving
            && !self.durable.leave_requested
            && !self.leave_requested
            && !self.join_requested
            && !self.durable.join_intended
            && !self.durable.hold
            && self
                .pending
                .iter()
                .all(|s| matches!(s, Step::ReconcileReference | Step::Backoff { .. }))
            && self.durable.pending_cleanup.is_empty()
            && self.tunnel.is_none()
            && self.installed_form.is_none()
    }
    /// Defer a planned acquisition before its reservation is exposed, when the
    /// executor cannot identify the current boot. Existing ledger entries must
    /// never use this operation; it provides no evidence about an ioctl.
    /// Returns unchanged unless an acquisition is at the head of the plan.
    #[must_use]
    pub fn defer_unstarted_acquisition(&self, clock: &impl SleepCountingClock) -> Self {
        let mut next = self.clone();
        if next.pending() == Some(Step::AcquireReference) {
            next.durable.reference_intent = None;
            next.references.needed = true;
            next.reference_retry(clock.now());
            next.advance(clock.now());
        }
        next
    }
    /// Atomic transition using the same sleep-counting clock as verification.
    /// Invalid results cannot mutate the source; expired cleanliness schedules repair.
    ///
    /// # Errors
    /// Rejects out-of-order completions and stale/wrong-generation proofs.
    pub fn transition(&self, event: Event, clock: &impl SleepCountingClock) -> Result<Self, Error> {
        let now = clock.now();
        let mut next = self.clone();
        // Retained independently of status: replacement/invalidation cannot erase expiry.
        if let Some(expiry) = next.prior_expiry
            && now > expiry
        {
            next.mark_gap(expiry);
        }
        next.observe_disabled(&event);
        if next.coalesce(&event, now) {
            if next.pending() != self.pending() {
                next.effect_since = now;
            }
            next.prepare_reference();
            return Ok(next);
        }
        let acquisition_boundary = matches!(event, Event::ReferenceAcquiredFor { sequence, .. }
            if self.pending() == Some(Step::AcquireReference)
                && self.durable.reference_intent == Some(ReferenceIntent::Acquire(sequence)));
        let boundary = acquisition_boundary
            || matches!(
                event,
                Event::Completed(_)
                    | Event::Failed(_)
                    | Event::ReferenceAcquired(_)
                    | Event::ReferenceReconciled { .. }
                    | Event::GenerationReserved(_)
                    | Event::ChildStarted(_)
                    | Event::IdentityVerified(_)
                    | Event::ReadbackValidated(_)
                    | Event::StatesClean { .. }
                    | Event::InterfaceStatesRemoved { .. }
            )
            || (matches!(event, Event::Observed { .. })
                && matches!(
                    self.pending(),
                    Some(Step::VerifyJoined | Step::VerifyPreTunnel)
                ));
        // A result from an already-running verification settles its boundary;
        // leave discards it and never publishes its stale proof.
        if !((next.leave_requested || next.abort_requested || next.deferred_repair.is_some())
            && boundary
            && matches!(event, Event::Observed { .. }))
        {
            next.apply(event, now)?;
        }
        if next.leave_requested && boundary {
            next.pending = vec![Step::PersistLeaving];
            next.operation = Some(Operation::Leave);
            next.leave_requested = false;
            next.join_requested = false;
            next.abort_requested = false;
            next.deferred_repair = None;
        } else if next.join_requested && boundary {
            next.join_requested = false;
            next.begin(Operation::Join, true, now);
        } else if boundary && let Some(action) = next.deferred_repair.take() {
            next.pending.clear();
            next.operation = None;
            next.abort_requested = false;
            next.apply(Event::Repair(action), now)?;
        } else if next.abort_requested && boundary {
            next.pending.clear();
            next.operation = None;
            next.abort_requested = false;
        }
        if (boundary
            || next.pending().is_none()
            || matches!(next.pending(), Some(Step::Backoff { .. })))
            && next.closing.rerun.is_some()
            && next.durable.join_intended
            && !next.durable.leaving
            && !next.durable.leave_requested
            && next.operation != Some(Operation::Leave)
        {
            next.rerun_closing(now);
        }
        next.schedule_state_recheck(now);
        if boundary
            || self.pending().is_none()
            || matches!(self.pending(), Some(Step::Backoff { .. }))
        {
            next.schedule_reference(now);
        }
        // Merge cleanup into the background accounting queue, so either retry
        // may share its timer without discarding the other kind of debt.
        next.schedule_hold_cleanup(now);
        if boundary || next.pending() != self.pending() {
            next.effect_since = now;
        }
        next.clear_reference_error();
        next.prepare_reference();
        Ok(next)
    }
    fn observe_disabled(&mut self, event: &Event) {
        let disabled = match event {
            Event::Repair(Action::EnableAndRejoin) => true,
            Event::Observed {
                context,
                verdict: Verdict::Repair(Action::EnableAndRejoin),
                ..
            } => *context == self.context,
            _ => false,
        };
        if matches!(event,
            Event::PfEnabledObserved { context }
                | Event::Observed { context, verdict: Verdict::Protected(_), .. }
                if *context == self.context)
        {
            self.references.observed_pf_disabled = false;
        }
        if disabled {
            if !self.references.observed_pf_disabled {
                if self.durable.hold {
                    // Preserve the waiting/in-flight distinction until the
                    // held repair decides whether to preempt background work.
                    self.references.retry_at = 0;
                    self.references.retry_delay = 0;
                } else {
                    self.reset_reference_retry();
                }
            }
            self.references.observed_pf_disabled = true;
        }
    }
    fn prepare_reference(&mut self) {
        if self.durable.reference_intent.is_none() {
            match self.pending() {
                Some(Step::AcquireReference) => {
                    debug_assert!(self.reference_slots() < 2);
                    self.durable.reference_sequence += 1;
                    self.durable.reference_intent =
                        Some(ReferenceIntent::Acquire(self.durable.reference_sequence));
                }
                Some(Step::ReleaseReference) => {
                    self.durable.reference_intent = Some(ReferenceIntent::Release);
                }
                _ => {}
            }
        }
        debug_assert!(
            self.pending() != Some(Step::AcquireReference)
                || matches!(
                    self.durable.reference_intent,
                    Some(ReferenceIntent::Acquire(_))
                )
        );
    }
    fn clear_reference_error(&mut self) {
        if !self.reference_debt() && self.durable.older_references.is_empty() {
            if self.durable.reference_error.is_some()
                && self.durable.last_error == self.durable.reference_error
            {
                self.durable.last_error = self.durable.enforcement_error.clone();
            }
            self.durable.reference_error = None;
            self.durable
                .cleanup_errors
                .retain(|(s, _)| *s != Step::ReconcileReference);
        }
    }
    fn reference_slots(&self) -> usize {
        usize::from(self.durable.pf_reference.is_some())
            + self.durable.older_references.len()
            + self.durable.uncertain_acquires.len()
    }
    fn reference_debt(&self) -> bool {
        (!self.durable.join_intended && self.reference_slots() > 0)
            || !self.durable.older_references.is_empty()
                && matches!(&self.enforcement, Verdict::Protected(proof)
                    if proof.form() == Form::Joined || self.durable.hold && !self.closing.active)
            || self.durable.reference_needs_reconcile
            || !self.durable.uncertain_acquires.is_empty()
            || self.durable.reference_intent == Some(ReferenceIntent::Release)
                && self.pending() != Some(Step::ReleaseReference)
            || self.references.needed && self.reference_slots() >= 2
    }
    fn reference_retry(&mut self, now: u64) {
        self.references.retry_delay = if self.durable.join_intended {
            1
        } else {
            self.references.retry_delay.saturating_mul(2).clamp(1, 60)
        };
        self.references.retry_at = now.saturating_add(self.references.retry_delay);
    }
    fn reset_reference_retry(&mut self) {
        self.references.retry_at = 0;
        self.references.retry_delay = 0;
        if matches!(self.pending(), Some(Step::Backoff { .. }))
            && self.pending.get(1) == Some(&Step::ReconcileReference)
        {
            self.pending.remove(0);
        }
    }
    fn settle_reference(&mut self, entry: ReferenceEntry, now: u64) -> Result<(), Error> {
        let exists = match entry {
            ReferenceEntry::Token(token) => {
                if self.durable.pf_reference == Some(token) {
                    self.durable.pf_reference = None;
                    true
                } else if let Some(index) = self
                    .durable
                    .older_references
                    .iter()
                    .position(|t| *t == token)
                {
                    self.durable.older_references.remove(index);
                    true
                } else {
                    false
                }
            }
            ReferenceEntry::Acquire(sequence) => {
                if self.durable.reference_intent == Some(ReferenceIntent::Acquire(sequence)) {
                    return Err(Error("cannot settle active acquisition"));
                } else if let Some(index) = self
                    .durable
                    .uncertain_acquires
                    .iter()
                    .position(|s| *s == sequence)
                {
                    self.durable.uncertain_acquires.remove(index);
                    true
                } else {
                    false
                }
            }
        };
        if !exists {
            return Err(Error("unknown reference settlement entry"));
        }
        self.context.acquisition_revision += 1;
        self.durable.verification_context = self.context;
        self.reset_reference_retry();
        if self.durable.join_intended && self.durable.pf_reference.is_none() {
            self.references.needed = true;
            self.invalidate(false);
            self.invalidated_at = now;
            if self.reference_slots() < 2 && !self.pending.contains(&Step::AcquireReference) {
                self.closing.rerun = Some(ClosingRerun::Repair(Action::EnableAndRejoin));
            }
        }
        if self.reference_slots() == 0
            && !matches!(
                self.durable.reference_intent,
                Some(ReferenceIntent::Acquire(_))
            )
        {
            self.durable.reference_intent = None;
            self.durable.reference_needs_reconcile = false;
        }
        self.clear_reference_error();
        Ok(())
    }
    fn schedule_reference(&mut self, now: u64) {
        // Joined predecessor cleanup is background work. Finish a cleanliness
        // recheck before retrying it; accounting must not displace VerifyJoined
        // at each boundary and expire the proof it is meant to preserve.
        if self.operation == Some(Operation::Recheck)
            && !self.references.needed
            && self.durable.uncertain_acquires.is_empty()
            && !self.durable.reference_needs_reconcile
            && self.durable.reference_intent != Some(ReferenceIntent::Release)
        {
            return;
        }
        // Held accounting is background work: never insert it or its timer
        // between the closing prefix's load, flush and verification steps.
        if self.durable.hold
            && !self.pending.is_empty()
            && (!self.held_background() || !matches!(self.pending(), Some(Step::Backoff { .. })))
        {
            return;
        }
        if !self.reference_debt()
            || self.pending.contains(&Step::ReconcileReference)
            || matches!(
                self.pending(),
                Some(Step::PersistIntent | Step::PersistLeaving | Step::ReconcileReference)
            )
            || (self.pending() == Some(Step::AcquireReference)
                && matches!(
                    self.durable.reference_intent,
                    Some(ReferenceIntent::Acquire(_))
                ))
            || self.operation == Some(Operation::Leave)
            || self.durable.leaving
            || self.durable.leave_requested
        {
            return;
        }
        // An available acquisition slot lets safety run before ownership cleanup.
        if self.reference_slots() < 2
            && self.durable.reference_needs_reconcile
            && let Some(index) = self.pending.iter().position(|s| *s == Step::FlushStates)
        {
            if !self.pending.contains(&Step::ReconcileReference) {
                self.pending.insert(index + 1, Step::ReconcileReference);
                if now < self.references.retry_at {
                    self.pending.insert(
                        index + 1,
                        Step::Backoff {
                            until: self.references.retry_at,
                        },
                    );
                }
            }
            return;
        }
        // This timer belongs to ownership debt, not the closing/rejoin retry.
        if now >= self.references.retry_at {
            self.pending.insert(0, Step::ReconcileReference);
        } else if self.pending().is_none()
            || self.pending() == Some(Step::ReleaseReference)
            || matches!(self.pending(), Some(Step::Backoff { until }) if until > self.references.retry_at)
        {
            self.pending.insert(0, Step::ReconcileReference);
            self.pending.insert(
                0,
                Step::Backoff {
                    until: self.references.retry_at,
                },
            );
        }
    }
    fn is_hold_cleanup(step: Step) -> bool {
        matches!(
            step,
            Step::StopChild | Step::CleanupRoutes | Step::CleanupDns | Step::CleanupArtifacts
        )
    }
    fn background_only(&self) -> bool {
        self.operation.is_none()
            && self.pending.iter().all(|step| {
                matches!(step, Step::Backoff { .. } | Step::ReconcileReference)
                    || self.durable.hold && Self::is_hold_cleanup(*step)
            })
    }
    fn held_background(&self) -> bool {
        self.durable.hold && !self.closing.active && self.background_only()
    }
    fn schedule_hold_cleanup(&mut self, now: u64) {
        if !self.held_background()
            || !self.durable.join_intended
            || self.durable.leaving
            || self.durable.leave_requested
            || self.leave_requested
            || self.deferred_repair.is_some()
            || self
                .pending()
                .is_some_and(|step| !matches!(step, Step::Backoff { .. }))
        {
            return;
        }
        let Some(retry) = self
            .hold_cleanup_retries
            .iter()
            .min_by_key(|retry| retry.until)
        else {
            return;
        };
        if self.pending().is_none()
            || matches!(self.pending(), Some(Step::Backoff { until }) if retry.until <= until)
        {
            // Background work can share the idle timer. Never put a cleanup wait
            // into the closing prefix, or interrupt an in-flight accounting call.
            if self.pending.contains(&retry.step) {
                return;
            }
            self.pending.insert(0, retry.step);
            if now < retry.until {
                self.pending.insert(0, Step::Backoff { until: retry.until });
            }
        }
    }
    fn require_reference(&mut self) {
        if matches!(
            self.pending(),
            Some(Step::AcquireReference | Step::ReconcileReference)
        ) {
            self.references.pf_disabled_seen = Some(self.context.lifecycle_revision);
        }
        // Negative observations are not checked releases. Keep every identity.
        self.references.needed = true;
    }
    fn closing_wait(&mut self, target: Step, now: u64) {
        let retry = *self.closing.retry.get_or_insert(ClosingRetry {
            failed_at: now,
            target,
            until: now.saturating_add(1),
        });
        if let Some(index) = self.pending.iter().position(|s| *s == retry.target)
            && retry.until > now
            && (index == 0 || self.pending[index - 1] != (Step::Backoff { until: retry.until }))
        {
            self.pending
                .insert(index, Step::Backoff { until: retry.until });
        }
    }
    #[allow(clippy::too_many_lines)] // Evidence ordering and the single queued prefix share one policy.
    fn coalesce(&mut self, event: &Event, now: u64) -> bool {
        if (!self.closing.active
            && !matches!(self.operation, Some(Operation::Join | Operation::Recover)))
            || self.operation == Some(Operation::Leave)
            || (!self.durable.join_intended && self.operation != Some(Operation::Join))
            || self.leave_requested
            || self.durable.leave_requested
            || matches!(
                self.pending(),
                Some(Step::VerifyPreTunnel | Step::VerifyJoined)
            )
        {
            return false;
        }
        let (action, unknown) = match event {
            Event::Repair(a)
            | Event::Observed {
                verdict: Verdict::Repair(a),
                ..
            } => (Some(*a), None),
            Event::Observed {
                verdict: Verdict::Unknown { since },
                ..
            }
            | Event::InvalidateObservations { since } => (None, Some(*since)),
            Event::ChildDied if self.tunnel.is_some() => (Some(Action::RecreateChild), None),
            Event::ChildDied => return true,
            Event::Observed {
                verdict: Verdict::NotProtected(_),
                ..
            } => (Some(Action::Rejoin), None),
            _ => return false,
        };
        if let Event::Observed { context, .. } = event
            && *context != self.context
        {
            return false;
        }
        // Every accepted loss is uncovered, including before the first prefix.
        // Stale round contexts are rejected above and by apply().
        let wake = matches!(event, Event::InvalidateObservations { .. });
        let fresh_loss = action.is_some() || wake;
        let waiting_unknown = unknown.is_some()
            && (!self.closing.unknown || self.states_clean_at.is_some())
            && matches!(self.pending(), Some(Step::Backoff { .. }));
        let first_unknown =
            unknown.is_some() && (!self.closing.unknown || self.states_clean_at.is_some());
        let since = unknown.unwrap_or(now);
        let evidence = match event {
            Event::Observed {
                verdict: Verdict::NotProtected(reason),
                ..
            } => reason.clone(),
            _ => action.map_or(Reason::Unknown { since }, Reason::Repair),
        };
        if action.is_some() {
            self.durable.last_error = Some(evidence.clone());
        }
        self.durable.enforcement_error = Some(evidence);
        self.enforcement = Verdict::Unknown { since };
        self.invalidated_at = now;
        if unknown.is_some() {
            self.closing.unknown = true;
        }
        if action == Some(Action::EnableAndRejoin) && self.pending() == Some(Step::AcquireReference)
        {
            self.references.pf_disabled_seen = Some(self.context.lifecycle_revision);
        }
        if matches!(event, Event::ChildDied) {
            self.tunnel = None;
            self.tunnel_health = TunnelHealth::Down;
        }
        self.mark_gap(since);
        if fresh_loss || first_unknown {
            if self.pending() == Some(Step::FlushStates) && self.settling_flush.is_none() {
                self.settling_flush = Some(self.context.state_epoch);
            }
            self.invalidate(true);
            self.mark_gap(since);
        }
        let joined_wait = matches!(self.pending(), Some(Step::Backoff { .. }))
            && self.pending.contains(&Step::VerifyJoined)
            && !self.pending.contains(&Step::CheckTools);
        if !self.closing.active
            && (!matches!(self.pending(), Some(Step::Backoff { .. })) || joined_wait)
        {
            // Setup Unknown needs cleanup, but keeps this child attempt.
            if first_unknown {
                self.queue_joined_flush();
            }
            if fresh_loss {
                if !wake && !matches!(action, Some(Action::Rerender { .. })) {
                    self.note_rejoin_failure();
                }
                if action == Some(Action::EnableAndRejoin) {
                    self.require_reference();
                }
                self.pending.truncate(1);
                self.deferred_repair = Some(match action {
                    Some(Action::Rerender { .. }) | None => Action::Rejoin,
                    Some(action) => action,
                });
                if joined_wait {
                    // Backoff is idle scheduling, so a real loss repairs now.
                    self.begin(Operation::Recover, false, now);
                }
            }
            return true;
        }
        if fresh_loss || waiting_unknown {
            if !self.closing.active && self.closing.retry.is_none() {
                self.closing_wait(Step::VerifyPreTunnel, now);
            }
            if action == Some(Action::EnableAndRejoin) {
                self.require_reference();
            }
            if fresh_loss
                && self.closing.rerun != Some(ClosingRerun::Repair(Action::EnableAndRejoin))
            {
                self.closing.rerun = Some(ClosingRerun::Repair(action.unwrap_or(Action::Rejoin)));
            } else if self.closing.rerun.is_none() {
                self.closing.rerun = Some(ClosingRerun::Flush);
            }
        }
        if matches!(self.pending(), Some(Step::Backoff { .. })) && self.closing.rerun.is_some() {
            self.rerun_closing(now);
        }
        true
    }
    fn queue_joined_flush(&mut self) {
        // Never move an already dispatched step. Before loading joined policy,
        // flush first; after that boundary, flush immediately before verification.
        let target = self
            .pending
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, s)| matches!(s, Step::LoadJoined | Step::VerifyJoined))
            .map(|(i, _)| i);
        if let Some(index) = target
            && !self.pending[1..index].contains(&Step::FlushStates)
        {
            self.pending.insert(index, Step::FlushStates);
        }
        self.retarget_joined_wait();
    }
    fn retarget_joined_wait(&mut self) {
        // A queued cleanup may become the delayed effect. Retarget only once
        // the timer is at the head, so an earlier in-flight flush cannot clear it.
        if let Some(Step::Backoff { until }) = self.pending()
            && let Some(retry) = &mut self.closing.retry
            && retry.until == until
            && retry.target == Step::VerifyJoined
        {
            retry.target = self.pending[1];
        }
    }
    fn rerun_closing(&mut self, now: u64) {
        let Some(rerun) = self.closing.rerun.take() else {
            return;
        };
        let unknown = self.closing.unknown;
        let retry = self.closing.retry;
        self.begin(Operation::Recover, false, now);
        if rerun == ClosingRerun::Flush
            && self.installed_form == Some(Form::PreTunnel)
            && self
                .baseline
                .as_ref()
                .is_some_and(|b| b.kind() == self.pre_tunnel_policy())
        {
            self.pending
                .retain(|step| !matches!(step, Step::LoadPreTunnel | Step::VerifyPreTunnelLoad));
        }
        self.closing.unknown = unknown;
        self.closing.retry = retry;
        if let Some(retry) = retry {
            self.closing_wait(retry.target, now);
        }
    }
    fn mark_gap(&mut self, since: u64) {
        self.gap_after = Some(self.gap_after.map_or(since, |old| old.max(since)));
    }
    fn schedule_state_recheck(&mut self, now: u64) {
        if self.durable.hold
            && self.durable.join_intended
            && !self.closing.active
            && self.operation.is_none()
            && !self.durable.leaving
            && !self.durable.leave_requested
            && !self.leave_requested
            && (self.states_clean_at.is_none()
                || self
                    .gap_after
                    .is_some_and(|gap| self.states_clean_at.is_none_or(|at| at < gap)))
        {
            self.recheck_hold();
        }
        // Even an otherwise harmless event can be the first notice of expiry.
        // A rejoin wait may retain only cleanup that still covers every gap.
        if matches!(self.pending(), Some(Step::Backoff { .. }))
            && self.pending.get(1) == Some(&Step::CheckTools)
            && self
                .gap_after
                .is_some_and(|gap| self.states_clean_at.is_none_or(|at| at < gap))
            && !self.durable.leaving
            && !self.durable.leave_requested
            && !self.leave_requested
            && self.operation != Some(Operation::Leave)
        {
            self.begin(Operation::Recover, false, now);
        }
        if self.pending.is_empty()
            && self.durable.join_intended
            && !self.durable.leaving
            && !self.durable.leave_requested
            && !self.leave_requested
            && self.operation != Some(Operation::Leave)
        {
            if self.durable.hold {
                if self.installed_form != Some(Form::PreTunnel)
                    || self
                        .baseline
                        .as_ref()
                        .is_none_or(|b| b.kind() != self.pre_tunnel_policy())
                {
                    self.begin(Operation::Recover, false, now);
                } else if self.states_clean_at.is_none()
                    || self
                        .gap_after
                        .is_some_and(|gap| self.states_clean_at.is_none_or(|at| at < gap))
                {
                    self.recheck_hold();
                }
                return;
            }
            if self.installed_form != Some(Form::Joined)
                || self.tunnel.is_none()
                || self
                    .baseline
                    .as_ref()
                    .is_none_or(|b| b.form() != Form::Joined)
            {
                self.begin(Operation::Recover, false, now);
            } else if self.states_clean_at.is_none()
                || self
                    .gap_after
                    .is_some_and(|gap| self.states_clean_at.is_none_or(|at| at < gap))
            {
                self.operation = Some(Operation::Recheck);
                self.pending = vec![Step::FlushStates, Step::VerifyJoined];
            }
        }
    }
    fn recheck_hold(&mut self) {
        debug_assert!(self.durable.hold && self.durable.join_intended);
        self.operation = Some(Operation::Recheck);
        self.closing.active = true;
        let in_flight = self
            .pending()
            .filter(|step| !matches!(step, Step::Backoff { .. }));
        self.pending = vec![Step::FlushStates, Step::VerifyPreTunnel];
        if let Some(step) = in_flight {
            self.pending.insert(0, step);
            // The dispatched result still belongs to this head. Keep any
            // separately requested repair for the boundary after its result.
            if Self::is_hold_cleanup(step) {
                self.abort_requested = false;
            }
        }
    }
    fn invalidate(&mut self, states: bool) {
        self.context.lifecycle_revision += 1;
        if states {
            self.context.state_epoch += 1;
            self.states_clean_at = None;
        }
        self.durable.verification_context = self.context;
        self.enforcement = match &self.durable.enforcement_error {
            Some(Reason::Unknown { since }) => Verdict::Unknown { since: *since },
            Some(Reason::Repair(_)) => match self.enforcement {
                Verdict::Unknown { since } => Verdict::Unknown { since },
                _ => Verdict::Unknown {
                    since: self.invalidated_at,
                },
            },
            Some(reason) => Verdict::NotProtected(reason.clone()),
            None => match self.enforcement {
                Verdict::Unknown { since } => Verdict::Unknown { since },
                _ => Verdict::NeverVerified,
            },
        };
    }
    fn begin(&mut self, op: Operation, persist: bool, now: u64) {
        let joined_retry = self.closing.retry.filter(|retry| {
            !self.closing.active && matches!(retry.target, Step::FlushStates | Step::VerifyJoined)
        });
        self.invalidate(true);
        self.operation = Some(op);
        self.pending.clear();
        self.abort_requested = false;
        self.deferred_repair = None;
        self.references.pf_disabled_seen = None;
        if op == Operation::Join && self.reference_slots() > 0 && self.reference_slots() < 2 {
            self.references.needed = true;
        }
        self.rejoin_delay =
            if !self.durable.hold && op == Operation::Recover && self.durable.retry_attempts > 0 {
                Some((1u64 << (self.durable.retry_attempts.min(7) - 1)).min(60))
            } else {
                None
            };
        self.closing.active = true;
        self.settling_flush = None;
        self.joined_unknown_retries = 0;
        self.closing.rerun = None;
        self.closing.unknown = false;
        if persist {
            self.pending.push(Step::PersistIntent);
        }
        // Only debt that blocks enabling pf may precede the safety prefix.
        if self.durable.hold && self.references.needed && self.reference_slots() >= 2 {
            self.pending.push(Step::ReconcileReference);
        }
        if (self.durable.pf_reference.is_none() || self.references.needed)
            && self.reference_slots() < 2
            && self.durable.reference_intent.is_none()
        {
            self.pending.push(Step::AcquireReference);
        }
        self.pending.extend([
            Step::LoadPreTunnel,
            Step::VerifyPreTunnelLoad,
            Step::FlushStates,
            Step::VerifyPreTunnel,
        ]);
        // Otherwise accounting follows verification in the same held prefix,
        // without a timer, so repeated safety repairs cannot starve it.
        if self.durable.hold
            && !self.pending.contains(&Step::ReconcileReference)
            && (self.reference_slots() >= 2
                || self.reference_debt() && now >= self.references.retry_at)
        {
            self.pending.push(Step::ReconcileReference);
        }
        if op == Operation::Recover && (!self.durable.hold || self.hold_cleanup) {
            self.pending.extend([
                Step::StopChild,
                Step::CleanupRoutes,
                Step::CleanupDns,
                Step::CleanupArtifacts,
            ]);
        }
        if self.durable.hold {
            return;
        }
        if let Some(delay) = self.rejoin_delay {
            self.pending.push(Step::Backoff {
                until: now.saturating_add(delay),
            });
        }
        self.pending.extend([
            Step::CheckTools,
            Step::ReserveGeneration,
            Step::StartChild,
            Step::ConfigureUapi,
            Step::ConfigureAddresses,
            Step::ConfigureMtu,
            Step::ConfigureEndpointRoute,
            Step::ConfigureSplitRoutes,
            Step::ConfigureDns,
            Step::VerifyIdentity,
            Step::LoadJoined,
            Step::VerifyJoinedLoad,
            Step::VerifyJoined,
        ]);
        if let Some(retry) = joined_retry {
            // A real loss ends the same-child retry, but cannot move its wait.
            self.closing.retry = Some(ClosingRetry {
                target: Step::VerifyPreTunnel,
                ..retry
            });
            self.closing_wait(Step::VerifyPreTunnel, now);
        }
    }
    fn resume_cleanup(&mut self) {
        self.invalidate(true);
        self.operation = Some(Operation::Leave);
        self.references.pf_disabled_seen = None;
        self.pending.clone_from(&self.durable.pending_cleanup);
        if self.pending.is_empty() {
            self.pending.push(Step::ClearIntent);
        }
    }
    fn advance(&mut self, now: u64) {
        let completed = self.pending.remove(0);
        if self.closing.retry.is_some_and(|r| r.target == completed) {
            self.closing.retry = None;
        }
        self.retarget_joined_wait();
        if (self.pending() == Some(Step::VerifyPreTunnel)
            || matches!(self.pending(), Some(Step::Backoff { .. }))
                && self.pending.get(1) == Some(&Step::VerifyPreTunnel)
            || self.operation == Some(Operation::Replace)
                && self.pending() == Some(Step::VerifyJoined)
            || self.pending() == Some(Step::CheckTools)
            || matches!(self.pending(), Some(Step::Backoff { .. }))
                && self.pending.get(1) == Some(&Step::CheckTools))
            && let Some(action) = self.closing.rerun.take()
        {
            self.closing.rerun = Some(action);
            self.rerun_closing(now);
        }
        if matches!(self.pending(), Some(Step::Backoff { .. }))
            && self.pending.get(1) == Some(&Step::CheckTools)
            && let Some(delay) = self.rejoin_delay.take()
        {
            let until = *self
                .rejoin_deadline
                .get_or_insert(now.saturating_add(delay));
            if until <= now {
                self.pending.remove(0); // expired delay is satisfied by the prefix
            } else {
                self.pending[0] = Step::Backoff { until };
            }
        }
        if self.pending() == Some(Step::CheckTools)
            || matches!(self.pending(), Some(Step::Backoff { .. }))
                && self.pending.get(1) == Some(&Step::CheckTools)
        {
            if self.states_clean_at.is_none()
                || self
                    .gap_after
                    .is_some_and(|gap| self.states_clean_at.is_none_or(|at| at < gap))
            {
                self.begin(Operation::Recover, false, now);
                if let Some(retry) = self.closing.retry {
                    self.closing_wait(retry.target, now);
                }
            } else {
                self.closing.active = false;
            }
        }
        if self.pending.is_empty() {
            if self.durable.hold && self.operation != Some(Operation::Leave) {
                self.closing.active = false;
                self.closing.retry = None;
                self.hold_cleanup = false;
            }
            if self.operation == Some(Operation::Leave)
                && self.durable.pending_cleanup.is_empty()
                && self.durable.leaving
            {
                self.pending.push(Step::ClearIntent);
            } else {
                self.operation = None;
            }
        }
    }
    fn note_rejoin_failure(&mut self) {
        let failed_rejoin = matches!(self.operation, Some(Operation::Join | Operation::Recover))
            && self.deferred_repair.is_none()
            && !self.abort_requested
            && (matches!(self.pending(), Some(Step::Backoff { .. }))
                && self.pending.contains(&Step::VerifyJoined)
                && !self.pending.contains(&Step::CheckTools)
                || matches!(
                    self.pending(),
                    Some(
                        Step::CheckTools
                            | Step::ReserveGeneration
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
                    )
                ));
        if failed_rejoin {
            self.durable.retry_attempts = self.durable.retry_attempts.saturating_add(1).min(7);
            self.rejoin_deadline = None;
        }
    }
    fn record_acquisition(&mut self, sequence: u64, token: u64, now: u64) -> Result<(), Error> {
        let active = self.durable.reference_intent == Some(ReferenceIntent::Acquire(sequence));
        let uncertain = self.durable.uncertain_acquires.contains(&sequence);
        if token == 0 || (!active && !uncertain) {
            return Err(Error("unexpected pf acquisition identity"));
        }
        // A successful kernel effect must be journaled even after cancellation.
        if self.durable.pf_reference != Some(token)
            && !self.durable.older_references.contains(&token)
            && let Some(old) = self.durable.pf_reference.replace(token)
        {
            self.durable.older_references.push(old);
        }
        self.durable.uncertain_acquires.retain(|s| *s != sequence);
        if active {
            self.durable.reference_intent = None;
            self.references.needed = false;
        }
        // A late result cannot cancel a newer request to enable pf.
        self.context.acquisition_revision += 1;
        self.invalidate(false); // acquisition invalidates every round started before it
        self.invalidated_at = now;
        if active && self.references.pf_disabled_seen.take().is_some() {
            self.durable.reference_needs_reconcile = true;
        }
        if active && self.pending() == Some(Step::AcquireReference) {
            self.advance(now);
        }
        self.clear_reference_error();
        debug_assert!(self.reference_slots() <= 2);
        Ok(())
    }
    fn retry_hold_cleanup(&mut self, step: Step, reason: Reason, now: u64) {
        self.durable.cleanup_errors.retain(|(s, _)| *s != step);
        self.durable.cleanup_errors.push((step, reason.clone()));
        self.durable.last_error = Some(reason);
        if let Some(retry) = self
            .hold_cleanup_retries
            .iter_mut()
            .find(|retry| retry.step == step)
        {
            retry.delay = retry.delay.saturating_mul(2).clamp(1, 60);
            retry.until = now.saturating_add(retry.delay);
        } else {
            self.hold_cleanup_retries.push(HoldCleanupRetry {
                step,
                until: now.saturating_add(1),
                delay: 1,
            });
        }
        // Cleanup failure says nothing about enforcement. Advance exactly as
        // Leave does, preserving the proof and attempting independent work.
        self.advance(now);
    }
    fn fail(&mut self, reason: Reason, now: u64) {
        if self.pending() == Some(Step::ReconcileReference) {
            self.durable.reference_error = Some(reason.clone());
            self.durable.last_error = Some(reason.clone());
            if self.durable.leaving {
                self.durable
                    .cleanup_errors
                    .retain(|(s, _)| *s != Step::ReconcileReference);
                self.durable
                    .cleanup_errors
                    .push((Step::ReconcileReference, reason));
            }
            self.reference_retry(now);
            self.advance(now);
            return;
        }
        if self.durable.hold
            && self.operation != Some(Operation::Leave)
            && let Some(step) = self.pending().filter(|step| Self::is_hold_cleanup(*step))
        {
            self.retry_hold_cleanup(step, reason, now);
            return;
        }
        if self.pending() == Some(Step::AcquireReference)
            && let Some(ReferenceIntent::Acquire(sequence)) = self.durable.reference_intent.take()
        {
            self.durable.uncertain_acquires.push(sequence);
        }
        self.references.pf_disabled_seen = None;
        // Only a closing action that itself just failed may wait before retrying.
        // A failed joined Recheck flush instead starts LoadPreTunnel immediately.
        let was_waiting = matches!(self.pending(), Some(Step::Backoff { .. }));
        let closing_retry = self.pending().filter(|step| {
            (matches!(self.operation, Some(Operation::Join | Operation::Recover))
                || self.durable.hold && self.operation == Some(Operation::Recheck))
                && matches!(
                    step,
                    Step::AcquireReference
                        | Step::LoadPreTunnel
                        | Step::VerifyPreTunnelLoad
                        | Step::FlushStates
                        | Step::VerifyPreTunnel
                        | Step::StopChild
                        | Step::CleanupRoutes
                        | Step::CleanupDns
                        | Step::CleanupArtifacts
                )
        });
        self.note_rejoin_failure();
        self.mark_gap(now);
        self.deferred_repair = None;
        self.invalidate(true);
        self.enforcement = Verdict::NotProtected(reason.clone());
        self.durable.last_error = Some(reason.clone());
        self.durable.enforcement_error = Some(reason.clone());
        if let Reason::Unknown { since } = reason {
            self.enforcement = Verdict::Unknown { since };
        }
        if self.operation == Some(Operation::Leave) && self.durable.leaving {
            if let Some(step) = self.pending() {
                self.durable.cleanup_errors.retain(|(s, _)| *s != step);
                self.durable.cleanup_errors.push((step, reason));
                if step == Step::ReleaseReference {
                    self.references.retry_at = now.saturating_add(1);
                }
                if step == Step::ClearIntent {
                    self.pending.clear();
                    self.operation = None;
                } else {
                    self.advance(now);
                } // independent cleanup is attempted despite this failure
            }
        } else {
            self.pending.clear();
            if self.operation != Some(Operation::Leave) {
                self.operation = None;
                if self.durable.join_intended
                    && !self.durable.leaving
                    && !self.durable.leave_requested
                    && !self.leave_requested
                {
                    // A failed Recheck/Replace also delays its rejoin suffix.
                    self.begin(Operation::Recover, false, now);
                    if let Some(step) = closing_retry {
                        self.closing.retry = None;
                        self.closing_wait(
                            if step == Step::AcquireReference {
                                Step::VerifyPreTunnel
                            } else {
                                step
                            },
                            now,
                        );
                    }
                    if was_waiting {
                        self.closing_wait(Step::VerifyPreTunnel, now);
                    }
                    self.schedule_reference(now);
                }
            }
        }
    }
    #[allow(clippy::too_many_lines)] // Keep serialized event guards and effects auditable together.
    fn apply(&mut self, event: Event, now: u64) -> Result<(), Error> {
        match event {
            Event::Leave => {
                let waiting = matches!(self.pending(), Some(Step::Backoff { .. }));
                self.reset_reference_retry();
                self.references.pf_disabled_seen = None;
                self.references.needed = false;
                self.join_requested = false;
                self.durable.leave_requested = true;
                if self.durable.leaving {
                    if self.pending.is_empty() {
                        self.resume_cleanup();
                    }
                    return Ok(());
                }
                self.invalidate(true);
                self.operation = Some(Operation::Leave);
                self.closing.active = false;
                self.closing.rerun = None;
                if waiting || self.pending.is_empty() {
                    self.pending = vec![Step::PersistLeaving];
                    self.abort_requested = false;
                    self.deferred_repair = None;
                } else {
                    self.pending.truncate(1);
                    self.leave_requested = true;
                }
            }
            Event::Join => {
                if self
                    .pending
                    .iter()
                    .any(|s| !matches!(s, Step::ReconcileReference | Step::Backoff { .. }))
                    || self.durable.hold
                    || self.durable.leaving
                    || self.durable.join_intended
                    || self.join_requested
                    || self.leave_requested
                    || self.operation == Some(Operation::Leave)
                {
                    return Err(Error("join already intended or mutation pending"));
                }
                let reconciling = self.pending() == Some(Step::ReconcileReference);
                self.reset_reference_retry();
                if self.reference_slots() > 0 && self.reference_slots() < 2 {
                    self.references.needed = true;
                }
                if reconciling {
                    self.pending.truncate(1);
                    self.join_requested = true;
                } else {
                    self.begin(Operation::Join, true, now);
                }
            }
            Event::Repair(action) => {
                if (!self.pending.is_empty() && !self.held_background())
                    || !self.durable.join_intended
                    || self.durable.leaving
                    || self.leave_requested
                    || self.operation == Some(Operation::Leave)
                {
                    return Err(Error("repair without available join intent"));
                }
                if self.durable.hold {
                    if action == Action::EnableAndRejoin {
                        self.require_reference();
                    }
                    if self
                        .pending()
                        .is_some_and(|step| !matches!(step, Step::Backoff { .. }))
                    {
                        self.pending.truncate(1);
                        self.deferred_repair = Some(action);
                    } else {
                        self.begin(Operation::Recover, false, now);
                    }
                    return Ok(());
                }
                if let Action::Rerender { form } = action {
                    if !matches!(self.enforcement.at(&Now(now)), Verdict::Protected(_)) {
                        self.durable.last_error = Some(Reason::Repair(action));
                    }
                    if self.installed_form != Some(form) {
                        return Err(Error("replacement form mismatch"));
                    }
                    if form == Form::Joined && self.tunnel.is_none() {
                        // A later rerender cannot turn deferred child recovery
                        // into a replacement of policy for a child that died.
                        self.begin(Operation::Recover, false, now);
                        return Ok(());
                    }
                    self.invalidate(false);
                    self.interface_states_removed_at = None;
                    self.operation = Some(Operation::Replace);
                    self.closing = Closing {
                        active: true,
                        ..Closing::default()
                    };
                    let flush = self.states_clean_at.is_none()
                        || self
                            .gap_after
                            .is_some_and(|gap| self.states_clean_at.is_none_or(|at| at < gap));
                    if flush {
                        self.invalidate(true);
                    }
                    self.pending = vec![
                        Step::ReplaceAnchor(form),
                        Step::VerifyReplacement(form),
                        if form == Form::Joined {
                            Step::VerifyJoined
                        } else {
                            Step::VerifyPreTunnel
                        },
                    ];
                    if flush {
                        self.pending.insert(2, Step::FlushStates);
                    }
                } else {
                    self.begin(Operation::Recover, false, now);
                }
            }
            Event::ChildDied => {
                if self.durable.hold {
                    return Ok(());
                }
                if self.tunnel.is_none() {
                    return Ok(());
                }
                self.note_rejoin_failure();
                self.tunnel = None;
                self.tunnel_health = TunnelHealth::Down;
                if self.operation != Some(Operation::Leave)
                    && !self.leave_requested
                    && !self.durable.leaving
                {
                    self.invalidate(true);
                    if self.durable.join_intended {
                        if self.pending.is_empty()
                            || matches!(self.pending(), Some(Step::Backoff { .. }))
                        {
                            let waiting = matches!(self.pending(), Some(Step::Backoff { .. }));
                            self.begin(Operation::Recover, false, now);
                            if waiting {
                                self.closing_wait(Step::VerifyPreTunnel, now);
                            }
                        } else {
                            self.pending.truncate(1);
                            self.deferred_repair = Some(Action::RecreateChild);
                        }
                    }
                }
            }
            Event::InvalidateObservations { since } => {
                self.invalidate(true);
                if self.pending().is_some()
                    && self.durable.join_intended
                    && !matches!(self.pending(), Some(Step::Backoff { .. }))
                    && self.operation != Some(Operation::Leave)
                    && !self.leave_requested
                    && !self.durable.leaving
                    && !self.durable.leave_requested
                {
                    self.pending.truncate(1);
                    self.abort_requested = true;
                    self.deferred_repair = None;
                }
                self.mark_gap(since);
                if matches!(self.pending(), Some(Step::Backoff { .. }))
                    && self.durable.join_intended
                    && self.operation != Some(Operation::Leave)
                    && !self.leave_requested
                    && !self.durable.leaving
                    && !self.durable.leave_requested
                {
                    if self.durable.hold && !self.closing.active {
                        self.recheck_hold();
                    } else {
                        self.begin(Operation::Recover, false, now);
                        self.closing_wait(Step::VerifyPreTunnel, now);
                    }
                }
                self.durable.enforcement_error = Some(Reason::Unknown { since });
                self.enforcement = Verdict::Unknown { since };
                self.invalidated_at = now;
            }
            Event::PfEnabledObserved { context } => {
                if context != self.context {
                    return Err(Error("stale pf observation"));
                }
            }
            Event::Completed(step) => {
                if self.pending() != Some(step) {
                    return Err(Error("out-of-order completion"));
                }
                if matches!(
                    step,
                    Step::AcquireReference
                        | Step::ReconcileReference
                        | Step::ReserveGeneration
                        | Step::StartChild
                        | Step::VerifyIdentity
                        | Step::VerifyPreTunnelLoad
                        | Step::VerifyPreTunnel
                        | Step::VerifyJoinedLoad
                        | Step::VerifyJoined
                        | Step::VerifyReplacement(_)
                        | Step::FlushStates
                        | Step::RemoveVanishedInterfaceStates
                ) {
                    return Err(Error("step requires typed evidence"));
                }
                match step {
                    Step::Backoff { until } if now < until => {
                        return Err(Error("retry backoff has not elapsed"));
                    }
                    Step::PersistIntent => {
                        self.durable.join_intended = true;
                        self.reset_reference_retry();
                    }
                    Step::PersistLeaving => {
                        self.reset_reference_retry();
                        let had_intent = self.durable.join_intended;
                        self.durable.leaving = true;
                        self.durable.join_intended = false;
                        self.durable.pending_cleanup = if had_intent
                            || self.installed_form.is_some()
                            || self.tunnel.is_some()
                            || self.durable.pf_reference.is_some()
                            || self.durable.previous_generation.is_some()
                            || !self.durable.older_references.is_empty()
                            || !self.durable.uncertain_acquires.is_empty()
                        {
                            CLEANUP.to_vec()
                        } else {
                            Vec::new()
                        };
                        self.resume_cleanup();
                        return Ok(());
                    }
                    Step::LoadPreTunnel | Step::LoadJoined | Step::ReplaceAnchor(_) => {
                        self.context.policy_generation += 1;
                        if !matches!(step, Step::ReplaceAnchor(_)) {
                            self.baseline = None;
                        }
                        self.invalidate(false);
                        self.installed_form = Some(match step {
                            Step::LoadPreTunnel => Form::PreTunnel,
                            Step::ReplaceAnchor(form) => form,
                            _ => Form::Joined,
                        });
                    }
                    Step::StopChild => {
                        self.tunnel = None;
                        self.tunnel_health = TunnelHealth::Down;
                    }
                    Step::RemoveAnchor => {
                        self.installed_form = None;
                        self.invalidate(true);
                    }
                    Step::ReleaseReference => {
                        return Err(Error("reference release requires exact settlements"));
                    }
                    Step::ClearIntent => {
                        if !self.durable.pending_cleanup.is_empty() {
                            return Err(Error("cleanup unconfirmed"));
                        }
                        self.reset_reference_retry();
                        self.durable.leaving = false;
                        self.durable.leave_requested = false;
                        self.durable.join_intended = false;
                        self.durable.hold = false;
                        self.hold_cleanup = false;
                        self.hold_cleanup_retries.clear();
                        self.durable.cleanup_errors.clear();
                        self.durable.last_error = None;
                        self.durable.enforcement_error = None;
                        self.durable.retry_attempts = 0;
                        self.enforcement = Verdict::NeverVerified;
                    }
                    _ => {}
                }
                if self.durable.leaving {
                    self.durable.pending_cleanup.retain(|s| *s != step);
                    self.durable.cleanup_errors.retain(|(s, _)| *s != step);
                }
                if self.durable.hold && Self::is_hold_cleanup(step) {
                    if self.durable.cleanup_errors.iter().any(|(failed, reason)| {
                        *failed == step && self.durable.last_error.as_ref() == Some(reason)
                    }) {
                        self.durable.last_error = None;
                    }
                    self.hold_cleanup_retries.retain(|retry| retry.step != step);
                    self.durable.cleanup_errors.retain(|(s, _)| *s != step);
                }
                self.advance(now);
            }
            Event::ReferenceAcquired(token) => {
                let Some(ReferenceIntent::Acquire(sequence)) = self.durable.reference_intent else {
                    return Err(Error("acquisition requires transaction identity"));
                };
                self.record_acquisition(sequence, token, now)?;
            }
            Event::ReferenceAcquiredFor { sequence, token } => {
                self.record_acquisition(sequence, token, now)?;
            }
            Event::ReferenceSettled { entry, how: _ } => {
                self.settle_reference(entry, now)?;
            }
            Event::ReferenceReconciled {
                context,
                current,
                predecessor,
            } => {
                if self.pending() != Some(Step::ReconcileReference)
                    || context.acquisition_revision != self.context.acquisition_revision
                    || current == Some(0)
                    || predecessor == Some(0)
                    || predecessor.is_some() && (current.is_none() || current == predecessor)
                    || !self.durable.uncertain_acquires.is_empty()
                    || matches!(
                        self.durable.reference_intent,
                        Some(ReferenceIntent::Acquire(_))
                    )
                    || current
                        .into_iter()
                        .chain(predecessor)
                        .collect::<BTreeSet<_>>()
                        != self
                            .durable
                            .pf_reference
                            .into_iter()
                            .chain(self.durable.older_references.iter().copied())
                            .collect::<BTreeSet<_>>()
                {
                    return Err(Error("invalid reference reconciliation"));
                }
                // Every removal must already have arrived as ReferenceSettled.
                self.durable.pf_reference = current;
                self.durable.older_references = predecessor.into_iter().collect();
                self.durable.reference_intent = None;
                self.durable.reference_needs_reconcile = false;
                let disable_seen = self.references.pf_disabled_seen.take().is_some();
                self.references.needed = self.durable.join_intended
                    && (current.is_none()
                        || disable_seen
                        || (self.operation == Some(Operation::Join) || self.durable.hold)
                            && self.references.needed
                            && self.pending.contains(&Step::AcquireReference));
                // A successful inventory that still retains a predecessor has
                // not resolved its cleanup error.
                self.clear_reference_error();
                self.advance(now);
                if self.reference_slots() > 0
                    && (!self.durable.join_intended || !self.durable.older_references.is_empty())
                {
                    self.reference_retry(now);
                }
                if current.is_some() && !self.references.needed {
                    if let Some(index) = self
                        .pending
                        .iter()
                        .position(|s| *s == Step::AcquireReference)
                    {
                        self.pending.remove(index);
                    }
                } else if !self.durable.leaving
                    && !self.durable.leave_requested
                    && self.durable.join_intended
                    && self.reference_slots() < 2
                    && !self.pending.contains(&Step::AcquireReference)
                {
                    // Reconciliation may free a slot after the prefix's flush.
                    // Enabling still precedes load/read-back/flush, never a bare
                    // acquisition inserted immediately before verification.
                    self.closing.rerun = Some(ClosingRerun::Repair(Action::EnableAndRejoin));
                    self.rerun_closing(now);
                }
                if self.durable.leaving && self.pending.is_empty() {
                    self.pending.clone_from(&self.durable.pending_cleanup);
                    if self.pending.is_empty() {
                        self.pending.push(Step::ClearIntent);
                    }
                }
            }
            Event::GenerationReserved(generation) => {
                if self.pending() != Some(Step::ReserveGeneration)
                    || self
                        .durable
                        .previous_generation
                        .is_some_and(|g| generation <= g)
                {
                    return Err(Error("unexpected or reused generation reservation"));
                }
                self.durable.previous_generation = Some(generation);
                self.advance(now);
            }
            Event::ChildStarted(tunnel) => {
                if self.pending() != Some(Step::StartChild)
                    || self.durable.previous_generation != Some(tunnel.generation)
                {
                    return Err(Error("unreserved child generation"));
                }
                self.tunnel = Some(tunnel);
                self.tunnel_health = TunnelHealth::AwaitingHandshake;
                self.invalidate(false);
                self.advance(now);
            }
            Event::IdentityVerified(tunnel) => {
                if self.pending() != Some(Step::VerifyIdentity)
                    || (!self.leave_requested
                        && !self.abort_requested
                        && self.deferred_repair.is_none()
                        && self.tunnel.as_ref() != Some(&tunnel))
                {
                    return Err(Error("wrong child identity"));
                }
                self.advance(now);
            }
            Event::ReadbackValidated(baseline) => {
                let valid = match self.pending() {
                    Some(Step::VerifyPreTunnelLoad) => baseline.kind() == self.pre_tunnel_policy(),
                    Some(Step::VerifyJoinedLoad) => {
                        baseline.kind() == super::policy::Kind::Installed(Form::Joined)
                    }
                    Some(Step::VerifyReplacement(expected)) => {
                        baseline.kind()
                            == if expected == Form::PreTunnel {
                                self.pre_tunnel_policy()
                            } else {
                                super::policy::Kind::Installed(expected)
                            }
                    }
                    _ => false,
                };
                if !valid {
                    return Err(Error("unexpected planned readback"));
                }
                if matches!(self.pending(), Some(Step::VerifyReplacement(_))) {
                    let Some(old) = &self.baseline else {
                        self.begin(Operation::Recover, false, now);
                        return Ok(());
                    };
                    if !old.same_stateful_permissions(&baseline) {
                        self.begin(Operation::Recover, false, now);
                        return Ok(());
                    }
                    self.vanished_interfaces = old
                        .interfaces()
                        .difference(&baseline.interfaces())
                        .cloned()
                        .collect();
                    if !self.vanished_interfaces.is_empty() {
                        self.pending.insert(1, Step::RemoveVanishedInterfaceStates);
                    }
                }
                self.baseline = Some(baseline);
                self.advance(now);
            }
            Event::StatesClean {
                epoch,
                completed_at,
            } => {
                // Successful periodic ownerless maintenance can refresh cleanliness
                // while idle. It cannot satisfy a pending lifecycle effect or cross
                // a gap, epoch, Leave, or deferred repair boundary.
                let maintenance = self.background_only()
                    && self.operation.is_none()
                    && (self.installed_form == Some(Form::Joined)
                        || self.durable.hold && self.installed_form == Some(Form::PreTunnel))
                    && self.durable.join_intended
                    && !self.durable.leaving
                    && !self.durable.leave_requested
                    && !self.leave_requested
                    && !self.abort_requested
                    && self.deferred_repair.is_none()
                    && self.gap_after.is_none();
                if self.pending() != Some(Step::FlushStates) && !maintenance {
                    return Err(Error("unexpected state-clean observation"));
                }
                if !self.leave_requested && !self.abort_requested && self.deferred_repair.is_none()
                {
                    if self.settling_flush == Some(epoch) && self.closing.active {
                        self.settling_flush = None;
                        self.closing.rerun = Some(ClosingRerun::Repair(Action::Rejoin));
                        self.advance(now);
                        return Ok(());
                    }
                    if epoch != self.context.state_epoch
                        || completed_at > now
                        || completed_at < self.effect_since
                        || self.gap_after.is_some_and(|since| completed_at < since)
                    {
                        return Err(Error("stale state-flush completion"));
                    }
                    self.settling_flush = None;
                    self.states_clean_at = Some(completed_at);
                    if self.closing.active {
                        self.invalidate(false);
                    }
                }
                if !maintenance {
                    self.advance(now);
                }
            }
            Event::InterfaceStatesRemoved {
                interfaces,
                completed_at,
            } => {
                if self.pending() != Some(Step::RemoveVanishedInterfaceStates)
                    || interfaces != self.vanished_interfaces
                    || completed_at > now
                    || completed_at < self.effect_since
                {
                    return Err(Error("unexpected interface-state removal evidence"));
                }
                self.interface_states_removed_at = Some(completed_at);
                self.vanished_interfaces.clear();
                self.advance(now);
            }
            Event::Observed {
                context,
                form,
                verdict,
            } => {
                if context != self.context {
                    return Err(Error("stale enforcement observation"));
                }
                match verdict {
                    Verdict::Protected(proof) => {
                        self.references.observed_pf_disabled = false;
                        let expected_step = if form == Form::Joined {
                            Step::VerifyJoined
                        } else {
                            Step::VerifyPreTunnel
                        };
                        let refresh = (form == Form::PreTunnel
                            && (matches!(self.pending(), Some(Step::Backoff { .. }))
                                && self.pending.get(1) == Some(&Step::CheckTools)
                                || self.background_only()))
                            || form == Form::Joined
                                && !self.pending.is_empty()
                                && self.background_only();
                        if (self.pending().is_some()
                            && self.pending() != Some(expected_step)
                            && !refresh)
                            || self.installed_form != Some(form)
                            || proof.kind()
                                != if form == Form::PreTunnel {
                                    self.pre_tunnel_policy()
                                } else {
                                    super::policy::Kind::Installed(Form::Joined)
                                }
                            || proof.form() != form
                            || proof.context() != self.context
                            || self.baseline.as_ref().map(Baseline::hash)
                                != Some(proof.baseline_hash())
                            || self.states_clean_at != Some(proof.states_clean_at())
                            || proof.completed_at() > now
                            || proof.verified_at() < self.invalidated_at
                            || !self.durable.join_intended
                            || self.durable.leaving
                            || self.leave_requested
                            || (form == Form::Joined
                                && (self.tunnel.is_none()
                                    || self.tunnel.as_ref() != proof.tunnel()))
                        {
                            return Err(Error("stale or unsolicited protected proof"));
                        }
                        if self.durable.pf_reference.is_none() && !self.durable.hold {
                            self.references.needed = true;
                            self.fail(Reason::Observation("unresolved acquisition debt"), now);
                            return Ok(());
                        }
                        if (matches!(
                            self.operation,
                            Some(Operation::Replace | Operation::Recheck)
                        ) || self.operation.is_none()
                            || refresh)
                            && (self.transport.as_ref() != proof.transport()
                                || self
                                    .interface_states_removed_at
                                    .is_some_and(|at| proof.verified_at() < at))
                        {
                            self.begin(Operation::Recover, false, now);
                            return Ok(());
                        }
                        if refresh
                            && (now > proof.expires_at()
                                || self
                                    .gap_after
                                    .is_some_and(|since| proof.states_clean_at() < since))
                        {
                            self.begin(Operation::Recover, false, now);
                            return Ok(());
                        }
                        if now > proof.expires_at() {
                            self.mark_gap(proof.expires_at());
                        }
                        if now > proof.expires_at()
                            || self
                                .gap_after
                                .is_some_and(|since| proof.states_clean_at() < since)
                        {
                            if form == Form::PreTunnel && !refresh {
                                self.fail(
                                    Reason::Unknown {
                                        since: self.gap_after.unwrap_or(now),
                                    },
                                    now,
                                );
                                return Ok(());
                            }
                            self.invalidate(true);
                            self.enforcement = Verdict::Unknown {
                                since: self.gap_after.unwrap_or(now),
                            };
                            self.pending.clear();
                            self.operation = None;
                            return Ok(());
                        }
                        self.prior_expiry = Some(proof.expires_at());
                        self.transport = proof.transport().cloned();
                        self.last_verified = Some(proof.verified_at());
                        self.gap_after = None;
                        self.durable.enforcement_error = None;
                        if self.durable.hold {
                            // A full held proof establishes that pf is enabled,
                            // even when another owner holds its only live token.
                            self.references.needed = false;
                        }
                        if form == Form::Joined || refresh {
                            self.closing.active = false;
                            self.closing.retry = None;
                        }
                        self.closing.rerun = None;
                        if form == Form::Joined {
                            self.durable.last_error = None;
                            self.durable.retry_attempts = 0;
                            self.rejoin_deadline = None;
                        }
                        self.enforcement = Verdict::Protected(proof);
                        if self.pending() == Some(expected_step) {
                            self.advance(now);
                        }
                    }
                    Verdict::NotProtected(reason) => {
                        if !self.durable.join_intended {
                            return Ok(());
                        }
                        self.durable.enforcement_error = Some(reason.clone());
                        if self.operation == Some(Operation::Leave) || self.leave_requested {
                            self.enforcement = Verdict::NotProtected(reason.clone());
                            self.durable.last_error = Some(reason);
                        } else if self.pending().is_some()
                            && !matches!(self.pending(), Some(Step::Backoff { .. }))
                            && !matches!(
                                self.pending(),
                                Some(Step::VerifyPreTunnel | Step::VerifyJoined)
                            )
                        {
                            self.mark_gap(now);
                            self.invalidate(true);
                            self.enforcement = Verdict::NotProtected(reason.clone());
                            self.durable.last_error = Some(reason);
                            self.pending.truncate(1);
                            self.abort_requested = true;
                            self.deferred_repair = self.durable.hold.then_some(Action::Rejoin);
                        } else {
                            self.fail(reason, now);
                        }
                    }
                    Verdict::Unknown { since } => {
                        self.durable.enforcement_error = Some(Reason::Unknown { since });
                        if self.durable.join_intended && self.durable.last_error.is_none() {
                            self.durable.last_error = Some(Reason::Unknown { since });
                        }
                        self.invalidate(true);
                        self.invalidated_at = now;
                        self.mark_gap(since);
                        self.enforcement = Verdict::Unknown { since };
                        if self.operation != Some(Operation::Leave)
                            && self.durable.join_intended
                            && !self.leave_requested
                            && !self.durable.leaving
                            && !self.durable.leave_requested
                        {
                            if matches!(self.pending(), Some(Step::Backoff { .. })) {
                                if self.durable.hold && !self.closing.active {
                                    self.recheck_hold();
                                } else {
                                    self.begin(Operation::Recover, false, now);
                                    self.closing_wait(Step::VerifyPreTunnel, now);
                                }
                            } else if self.pending() == Some(Step::VerifyJoined)
                                && matches!(
                                    self.operation,
                                    Some(Operation::Join | Operation::Recover)
                                )
                                && self.joined_unknown_retries < 3
                            {
                                self.joined_unknown_retries += 1;
                                self.pending = vec![Step::FlushStates, Step::VerifyJoined];
                                self.closing.retry = None;
                                self.closing_wait(Step::VerifyJoined, now);
                            } else if self.pending() == Some(Step::VerifyPreTunnel)
                                || self.pending() == Some(Step::VerifyJoined)
                                    && matches!(
                                        self.operation,
                                        Some(Operation::Join | Operation::Recover)
                                    )
                            {
                                let connection_error = self.durable.last_error.clone();
                                self.fail(Reason::Unknown { since }, now);
                                self.durable.last_error = connection_error;
                            } else if self.pending().is_some()
                                && self.pending() != Some(Step::VerifyJoined)
                            {
                                self.pending.truncate(1);
                                self.abort_requested = true;
                                self.deferred_repair = None;
                            } else {
                                self.pending.clear();
                                self.operation = None;
                            }
                        }
                    }
                    Verdict::Repair(action) => {
                        if self.operation == Some(Operation::Leave)
                            || self.leave_requested
                            || self.durable.leave_requested
                            || !self.durable.join_intended
                        {
                            self.durable.enforcement_error = Some(Reason::Repair(action));
                            self.enforcement = Verdict::Unknown { since: now };
                            return Ok(());
                        }
                        if action == Action::EnableAndRejoin {
                            self.require_reference();
                        }
                        let verification = matches!(
                            self.pending(),
                            Some(Step::VerifyPreTunnel | Step::VerifyJoined)
                        );
                        let planned = matches!(action, Action::Rerender { .. })
                            && self.pending.is_empty()
                            && matches!(self.enforcement.at(&Now(now)), Verdict::Protected(_));
                        let prior_error = self.durable.last_error.clone();
                        if !planned {
                            self.durable.last_error = Some(Reason::Repair(action));
                        }
                        self.durable.enforcement_error = Some(Reason::Repair(action));
                        self.enforcement = Verdict::Unknown { since: now };
                        self.invalidated_at = now;
                        if !planned {
                            self.mark_gap(now);
                        }
                        if verification || matches!(self.pending(), Some(Step::Backoff { .. })) {
                            let held_background = self.held_background();
                            if self.pending() == Some(Step::VerifyJoined) {
                                self.note_rejoin_failure();
                            }
                            self.closing.retry = None;
                            self.begin(Operation::Recover, false, now);
                            if !held_background {
                                self.closing_wait(Step::VerifyPreTunnel, now);
                            }
                        } else if self.pending().is_some() {
                            self.invalidate(true);
                            self.pending.truncate(1);
                            self.deferred_repair = Some(action);
                        } else {
                            self.apply(Event::Repair(action), now)?;
                            if planned {
                                self.durable.last_error = prior_error;
                            }
                        }
                    }
                    Verdict::NeverVerified => return Err(Error("not a verification result")),
                }
            }
            Event::Handshake { generation, fresh } => {
                if self.background_only()
                    && self
                        .tunnel
                        .as_ref()
                        .is_some_and(|t| t.generation == generation)
                {
                    self.tunnel_health = if fresh {
                        TunnelHealth::Healthy
                    } else {
                        TunnelHealth::AwaitingHandshake
                    };
                }
            }
            Event::Failed(reason) => self.fail(reason, now),
        }
        Ok(())
    }
}

struct Now(u64);
impl SleepCountingClock for Now {
    fn now(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod expected_policy_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::mac::{policy, verify};

    fn lockdown_baseline() -> Baseline {
        verify::capture_lockdown_baseline(
            policy::render_lockdown().as_str(),
            &verify::Normalization {
                expanded_lists: false,
                named_icmp: false,
                implicit_tcp_flags: false,
            },
        )
        .unwrap()
    }

    fn held_with_stale_lockdown_baseline() -> Machine {
        let mut machine = Machine::restart(Durable {
            hold: true,
            join_intended: true,
            pf_reference: Some(1),
            ..Durable::default()
        });
        machine.pending.clear();
        machine.operation = None;
        machine.closing.active = false;
        machine.references.needed = false;
        machine.installed_form = Some(Form::PreTunnel);
        machine.baseline = Some(lockdown_baseline());
        machine.states_clean_at = Some(100);
        machine
    }

    #[test]
    fn held_state_recheck_and_flush_rerun_require_expected_policy_kind() {
        let mut machine = held_with_stale_lockdown_baseline();
        assert_eq!(
            machine.pre_tunnel_policy(),
            policy::Kind::Installed(Form::PreTunnel)
        );
        machine.schedule_state_recheck(100);
        assert!(machine.plan().contains(&Step::LoadPreTunnel));
        let mut machine = held_with_stale_lockdown_baseline();
        machine.closing.rerun = Some(ClosingRerun::Flush);
        machine.rerun_closing(100);
        assert!(machine.plan().contains(&Step::LoadPreTunnel));
    }

    #[test]
    fn held_replacement_readback_requires_expected_policy_kind() {
        let mut installed = held_with_stale_lockdown_baseline();
        installed.pending = vec![Step::VerifyReplacement(Form::PreTunnel)];
        assert!(
            installed
                .transition(Event::ReadbackValidated(lockdown_baseline()), &Now(100))
                .is_err()
        );
        let mut lockdown = Machine::restart_lockdown(Durable {
            hold: true,
            join_intended: true,
            pf_reference: Some(1),
            ..Durable::default()
        });
        lockdown.pending = vec![Step::VerifyReplacement(Form::PreTunnel)];
        lockdown.baseline = Some(lockdown_baseline());
        assert!(
            lockdown
                .transition(Event::ReadbackValidated(lockdown_baseline()), &Now(100))
                .is_ok()
        );
    }
}
