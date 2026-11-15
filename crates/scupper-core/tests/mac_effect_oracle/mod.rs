//! Executor-side oracle. No inspection of Machine retry/deadline/closing records.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
enum Effect {
    Dispatch(Step, u64),
    Finish(Step, u64, bool),
    Acquire(u64, u64),
    Uncertain(u64),
    Resolve(Vec<u64>),
    Release(Vec<u64>, bool),
    Void(Vec<u64>),
    Round(u64),
    Loss(u64, u64),
    VerificationFailed(u64),
    AttemptFailed,
    Joined,
    PfDisabled,
    Leave,
    StaleRoundAccepted(bool),
}

#[derive(Default, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent stream facts, not production state.
struct Oracle {
    in_flight: Option<Step>,
    prefix: bool,
    loaded: bool,
    queued: bool,
    must_dispatch: bool,
    safety_at: Option<u64>,
    serial: u64,
    completed_prefix: u64,
    rounds: BTreeMap<u64, u64>,
    verify_after: u64,
    reconcile_after: u64,
    attempts: u8,
    rejoin_after: Option<u64>,
    tokens: BTreeSet<u64>,
    acquisitions: BTreeSet<u64>,
    released: BTreeSet<u64>,
    voided: BTreeSet<u64>,
    uncertain: BTreeSet<u64>,
    leaving: bool,
    pf_enabled: bool,
    same_instant: usize,
    last_time: u64,
}
impl Oracle {
    #[allow(clippy::too_many_lines)] // Audit the complete stream contract in one match.
    fn read(&mut self, effect: &Effect) {
        self.serial += 1;
        match effect {
            Effect::Dispatch(step, now) => {
                if *now == self.last_time {
                    self.same_instant += 1;
                } else {
                    self.same_instant = 1;
                    self.last_time = *now;
                }
                assert!(
                    self.same_instant <= 128,
                    "same-instant transition budget exceeded: {self:?}"
                );
                assert!(
                    self.in_flight.replace(*step).is_none(),
                    "overlapping effects"
                );
                if self.must_dispatch {
                    assert!(
                        matches!(
                            step,
                            Step::AcquireReference | Step::LoadPreTunnel | Step::ReconcileReference
                        ),
                        "fresh loss absorbed at executor boundary: {step:?}"
                    );
                    if *step != Step::ReconcileReference {
                        assert_eq!(
                            Some(*now),
                            self.safety_at,
                            "safety prefix delayed past next executor boundary"
                        );
                        self.must_dispatch = false;
                        self.safety_at = None;
                    }
                }
                match step {
                    Step::AcquireReference | Step::LoadPreTunnel => {
                        if *step == Step::LoadPreTunnel {
                            assert!(!self.loaded, "overlapping repair prefixes");
                            self.loaded = true;
                        }
                        self.prefix = true;
                    }
                    Step::ReconcileReference => assert!(
                        *now >= self.reconcile_after,
                        "reconciliation retried before one second"
                    ),
                    Step::VerifyPreTunnel => assert!(
                        *now >= self.verify_after,
                        "verification before independent deadline {} at {now}",
                        self.verify_after
                    ),
                    Step::CheckTools => {
                        assert!(!self.prefix, "rejoin before prefix completion");
                        assert!(
                            *now >= self.rejoin_after.unwrap_or(0),
                            "rejoin at {now} before independent deadline {}",
                            self.rejoin_after.unwrap_or(0)
                        );
                    }
                    Step::ClearIntent => {
                        assert!(
                            self.tokens.is_empty(),
                            "leaked token at ClearIntent: {self:?}"
                        );
                        assert!(
                            self.uncertain.is_empty(),
                            "uncertain acquisition lost at ClearIntent"
                        );
                    }
                    _ => {}
                }
            }
            Effect::Finish(step, now, success) => {
                assert_eq!(self.in_flight.take(), Some(*step));
                if !success && *step == Step::ReconcileReference {
                    self.reconcile_after = now + 1;
                }
                if !success && !self.leaving && *step != Step::ReconcileReference {
                    self.must_dispatch = true;
                    self.safety_at = Some(*now);
                }
                if !success && self.prefix && *step != Step::ReconcileReference {
                    self.prefix = false;
                    self.loaded = false;
                }
                if self.queued {
                    // A loss during any dispatched effect requires repair at its
                    // completion, including the first prefix and replacements.
                    self.must_dispatch = true;
                    self.safety_at = Some(*now);
                    self.queued = false;
                    self.prefix = false;
                    self.loaded = false;
                }
                if *success && *step == Step::FlushStates {
                    self.prefix = false;
                    self.loaded = false;
                    self.completed_prefix = self.serial;
                }
                if *success && *step == Step::CleanupArtifacts && !self.leaving && self.attempts > 0
                {
                    self.rejoin_after
                        .get_or_insert(now + (1u64 << (self.attempts.min(7) - 1)).min(60));
                }
            }
            Effect::Acquire(sequence, token) => {
                self.pf_enabled = true;
                assert!(self.acquisitions.insert(*token), "token acquired twice");
                self.uncertain.remove(sequence);
                assert!(self.tokens.insert(*token));
            }
            Effect::Uncertain(sequence) => {
                assert!(self.uncertain.insert(*sequence));
            }
            Effect::Resolve(sequences) => {
                for sequence in sequences {
                    self.uncertain.remove(sequence);
                }
            }
            Effect::Release(tokens, leaving) => {
                for token in tokens {
                    assert!(self.tokens.remove(token), "release of unknown identity");
                    assert!(self.released.insert(*token), "double release");
                    assert!(
                        *leaving || !self.tokens.is_empty(),
                        "last reference released before replacement"
                    );
                }
            }
            Effect::Void(tokens) => {
                for token in tokens {
                    assert!(self.tokens.remove(token), "void proof for unknown identity");
                    assert!(self.voided.insert(*token), "duplicate void proof");
                }
            }
            Effect::Round(id) => {
                self.rounds.insert(*id, self.serial);
                self.same_instant = 0;
            }
            Effect::Loss(id, now) => {
                if self.rounds[id] > self.completed_prefix {
                    if self.in_flight.is_some() {
                        self.queued = true;
                    } else {
                        self.must_dispatch = true;
                        self.safety_at = Some(*now);
                        self.prefix = false;
                        self.loaded = false;
                    }
                }
            }
            Effect::VerificationFailed(now) => {
                self.verify_after = now + 1;
            }
            Effect::AttemptFailed => {
                self.attempts = self.attempts.saturating_add(1).min(7);
                self.rejoin_after = None;
                self.queued = true;
            }
            Effect::PfDisabled => self.pf_enabled = false,
            Effect::Joined => {
                assert!(self.pf_enabled, "Joined while modeled pf is disabled");
                self.attempts = 0;
                self.rejoin_after = None;
            }
            Effect::StaleRoundAccepted(accepted) => {
                assert!(!accepted, "pre-acquire monitor round accepted");
            }
            Effect::Leave => {
                self.leaving = true;
                self.queued = false;
                self.must_dispatch = false;
                self.prefix = false;
                self.loaded = false;
            }
        }
        assert!(
            self.tokens.len() + self.uncertain.len() <= 2,
            "ownership slots exceeded: {self:?}"
        );
        assert!(self.acquisitions.len() - self.released.len() - self.voided.len() <= 2);
    }
}

struct Executor {
    machine: Machine,
    oracle: Oracle,
    stream: Vec<Effect>,
    now_ms: u64,
    token: u64,
    round: u64,
    voidable: BTreeSet<u64>,
    dispatched_acquires: BTreeSet<u64>,
}
impl Executor {
    fn new() -> Self {
        let machine = Machine::restart(Durable::default())
            .transition(Event::Join, &Clock(102))
            .unwrap();
        Self {
            machine,
            oracle: Oracle::default(),
            stream: Vec::new(),
            now_ms: 102_000,
            token: 1000,
            round: 0,
            voidable: BTreeSet::new(),
            dispatched_acquires: BTreeSet::new(),
        }
    }
    fn now(&self) -> u64 {
        self.now_ms / 1000
    }
    fn emit(&mut self, effect: Effect) {
        if matches!(effect, Effect::Dispatch(Step::AcquireReference, _)) {
            let Some(ReferenceIntent::Acquire(sequence)) = self.machine.durable().reference_intent
            else {
                panic!("missing acquisition intent before dispatch")
            };
            assert!(
                self.dispatched_acquires.insert(sequence),
                "reused acquire intent at dispatch"
            );
        }
        self.oracle.read(&effect);
        self.stream.push(effect);
    }
    fn transition(&mut self, event: Event) {
        self.machine = self.machine.transition(event, &Clock(self.now())).unwrap();
    }
    fn complete(&mut self, fail_verify: bool, fail_suffix: bool) -> bool {
        let Some(step) = self.machine.pending() else {
            return false;
        };
        let now = self.now();
        if matches!(step, Step::Backoff { until } if until > now) {
            return false;
        }
        self.emit(Effect::Dispatch(step, now));
        let mut event = checked_completion_at(&self.machine, now);
        let disabled_verify =
            !self.oracle.pf_enabled && matches!(step, Step::VerifyPreTunnel | Step::VerifyJoined);
        let failed = fail_verify && step == Step::VerifyPreTunnel
            || fail_suffix && step == Step::ConfigureDns
            || disabled_verify;
        if failed {
            if disabled_verify {
                self.emit(Effect::VerificationFailed(now));
                if step == Step::VerifyJoined {
                    self.emit(Effect::AttemptFailed);
                }
                event = observed(
                    &self.machine,
                    self.machine.installed_form().unwrap(),
                    Verdict::Repair(Action::EnableAndRejoin),
                );
            } else if step == Step::VerifyPreTunnel {
                self.emit(Effect::VerificationFailed(now));
                event = observed(
                    &self.machine,
                    Form::PreTunnel,
                    Verdict::Repair(Action::Rejoin),
                );
            } else {
                self.emit(Effect::AttemptFailed);
                event = Event::Failed(Reason::Observation("oracle DNS failure"));
            }
        } else if step == Step::AcquireReference {
            self.token += 1;
            let Some(ReferenceIntent::Acquire(seq)) = self.machine.durable().reference_intent
            else {
                panic!("missing acquisition intent")
            };
            self.emit(Effect::Acquire(seq, self.token));
            event = Event::ReferenceAcquired(self.token);
        } else if step == Step::ReconcileReference {
            let voided: Vec<_> = self
                .oracle
                .tokens
                .intersection(&self.voidable)
                .copied()
                .collect();
            self.emit(Effect::Void(voided));
            let mut live = self.oracle.tokens.iter().copied();
            event = Event::ReferenceReconciled {
                context: self.machine.context(),
                current: live.next(),
                predecessor: live.next(),
            };
            self.emit(Effect::Resolve(
                self.machine.durable().uncertain_acquires.clone(),
            ));
        } else if step == Step::ReleaseReference {
            let tokens = self
                .machine
                .durable()
                .pf_reference
                .into_iter()
                .chain(self.machine.durable().older_references.iter().copied())
                .collect();
            self.emit(Effect::Release(tokens, self.oracle.leaving));
        } else if step == Step::VerifyJoined
            && matches!(
                event,
                Event::Observed {
                    verdict: Verdict::Protected(_),
                    ..
                }
            )
        {
            self.emit(Effect::Joined);
        }
        self.transition(event);
        self.emit(Effect::Finish(step, now, !failed));
        true
    }
    fn drain(&mut self, target: Option<Step>) {
        for _ in 0..128 {
            if self.machine.pending() == target {
                return;
            }
            if !self.complete(false, false) {
                if let Some(Step::Backoff { until }) = self.machine.pending() {
                    self.now_ms = until * 1000;
                } else {
                    return;
                }
            }
        }
        panic!("finite executor drain budget exceeded: {:?}", self.stream);
    }
    fn fail_verification(&mut self, kind: u16) {
        assert_eq!(self.machine.pending(), Some(Step::VerifyPreTunnel));
        if kind.is_multiple_of(4) {
            assert!(self.complete(true, false));
            return;
        }
        self.emit(Effect::Dispatch(Step::VerifyPreTunnel, self.now()));
        self.emit(Effect::VerificationFailed(self.now()));
        let verdict = match kind % 4 {
            1 => Verdict::Unknown { since: self.now() },
            2 => Verdict::NotProtected(Reason::HookMissing),
            _ => Verdict::Repair(Action::Rerender {
                form: Form::PreTunnel,
            }),
        };
        self.transition(observed(&self.machine, Form::PreTunnel, verdict));
        self.emit(Effect::Finish(Step::VerifyPreTunnel, self.now(), false));
    }
    fn uncertain_acquire(&mut self) -> u64 {
        self.drain(Some(Step::AcquireReference));
        let Some(ReferenceIntent::Acquire(sequence)) = self.machine.durable().reference_intent
        else {
            panic!("missing intent")
        };
        self.emit(Effect::Dispatch(Step::AcquireReference, self.now()));
        self.emit(Effect::Uncertain(sequence));
        self.transition(Event::Failed(Reason::Observation("lost acquire result")));
        self.emit(Effect::Finish(Step::AcquireReference, self.now(), false));
        sequence
    }
    fn fail_reconciliation(&mut self) {
        assert_eq!(self.machine.pending(), Some(Step::ReconcileReference));
        self.emit(Effect::Dispatch(Step::ReconcileReference, self.now()));
        self.transition(Event::Failed(Reason::Observation("unresolved reference")));
        self.emit(Effect::Finish(Step::ReconcileReference, self.now(), false));
    }
    fn loss(&mut self, action: Action) {
        self.round += 1;
        self.emit(Effect::Round(self.round));
        if action == Action::EnableAndRejoin {
            self.emit(Effect::PfDisabled);
            self.voidable.extend(self.oracle.tokens.iter().copied());
        }
        let step = self.machine.pending();
        let suffix = matches!(
            step,
            Some(Step::ConfigureDns | Step::ConfigureUapi | Step::ConfigureAddresses)
        );
        // Hold the already-dispatched effect while observations arrive.
        let held = step.filter(|s| {
            !matches!(
                s,
                Step::Backoff { .. } | Step::VerifyPreTunnel | Step::VerifyJoined
            )
        });
        if let Some(step) = held {
            self.emit(Effect::Dispatch(step, self.now()));
        }
        self.emit(Effect::Loss(self.round, self.now()));
        if matches!(step, Some(Step::VerifyPreTunnel | Step::VerifyJoined)) {
            self.emit(Effect::VerificationFailed(self.now()));
        }
        if suffix {
            self.emit(Effect::AttemptFailed);
        }
        let event = observed(
            &self.machine,
            self.machine.installed_form().unwrap_or(Form::PreTunnel),
            Verdict::Repair(action),
        );
        self.transition(event);
        if suffix {
            // Repeated losses belong to the same aborted attempt until its boundary.
            for _ in 0..3 {
                self.round += 1;
                self.emit(Effect::Round(self.round));
                self.emit(Effect::Loss(self.round, self.now()));
                self.transition(observed(
                    &self.machine,
                    Form::PreTunnel,
                    Verdict::Repair(action),
                ));
            }
        }
        if let Some(step) = held {
            let mut event = checked_completion_at(&self.machine, self.now());
            if step == Step::AcquireReference {
                let Some(ReferenceIntent::Acquire(sequence)) =
                    self.machine.durable().reference_intent
                else {
                    panic!("missing acquisition intent")
                };
                self.token += 1;
                self.emit(Effect::Acquire(sequence, self.token));
                // Model DIOCSTOP after the kernel acquire but before its result.
                self.voidable.insert(self.token);
                self.emit(Effect::PfDisabled); // stop occurred after kernel acquire, before result
                event = Event::ReferenceAcquiredFor {
                    sequence,
                    token: self.token,
                };
            }
            self.transition(event);
            self.emit(Effect::Finish(step, self.now(), true));
        }
    }
    fn assert_accounted(&self) {
        assert_eq!(
            self.oracle.acquisitions,
            self.oracle
                .released
                .union(&self.oracle.voided)
                .copied()
                .collect()
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct("tests/mac.proptest-regressions"))),
        ..ProptestConfig::default()
    })]
    #[test]
    fn external_effects_obey_ownership_repair_and_pacing(
        deltas in prop::collection::vec(0u16..1500, 0..30),
        suffix_loss in any::<bool>(),
        failures in 1usize..6,
        stage in 0u8..6,
        acquire_shape in any::<bool>(),
    ) {
        let mut e = Executor::new();
        let target = match stage {
            0 => Some(Step::VerifyPreTunnelLoad), // first prefix after Join
            1 => { e.drain(None); e.machine = Machine::restart(e.machine.durable().clone()); Some(Step::VerifyPreTunnelLoad) }
            2 => { e.drain(None); e.transition(Event::Repair(Action::Rerender { form: Form::Joined })); Some(Step::VerifyReplacement(Form::Joined)) }
            3 => { e.drain(Some(Step::ConfigureDns)); e.complete(false, true); while !matches!(e.machine.pending(), Some(Step::Backoff { .. })) { assert!(e.complete(false, false)); } e.machine.pending() }
            4 => Some(Step::ConfigureAddresses),
            _ => None,
        };
        e.drain(target);
        e.loss(Action::EnableAndRejoin);
        e.drain(Some(Step::FlushStates));
        e.round += 1;
        e.emit(Effect::Round(e.round));
        let covered = observed(&e.machine, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin));
        e.complete(false, false);
        e.emit(Effect::Loss(e.round, e.now()));
        e.emit(Effect::StaleRoundAccepted(e.machine.transition(covered, &Clock(e.now())).is_ok()));
        e.drain(None);
        // Acquire while pf is disabled: completion must not rewrite another intent.
        for late in [acquire_shape, !acquire_shape] {
            let mut b = Executor::new();
            if late {
                let first = b.uncertain_acquire();
                b.fail_reconciliation();
                assert_eq!(b.machine.pending(), Some(Step::AcquireReference));
                let Some(ReferenceIntent::Acquire(second)) = b.machine.durable().reference_intent else { panic!("missing replacement intent") };
                b.emit(Effect::Dispatch(Step::AcquireReference, b.now()));
                b.now_ms += 1_000; // replacement remains in flight past the debt deadline
                b.round += 1;
                b.emit(Effect::Round(b.round));
                b.emit(Effect::Loss(b.round, b.now()));
                b.emit(Effect::PfDisabled);
                b.transition(observed(&b.machine, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin)));
                b.token += 1;
                b.emit(Effect::Acquire(first, b.token));
                b.transition(Event::ReferenceAcquiredFor { sequence: first, token: b.token });
                prop_assert_eq!(b.machine.pending(), Some(Step::AcquireReference));
                prop_assert_eq!(b.machine.durable().reference_intent, Some(ReferenceIntent::Acquire(second)));
                b.token += 1;
                b.emit(Effect::Acquire(second, b.token));
                b.transition(Event::ReferenceAcquiredFor { sequence: second, token: b.token });
                b.emit(Effect::Finish(Step::AcquireReference, b.now(), true));
            } else {
                b.drain(Some(Step::AcquireReference));
                b.loss(Action::EnableAndRejoin);
            }
            b.fail_reconciliation();
            // Another disable before the debt retry expires used to expose an acquire
            // without an Acquire intent after the failed reconcile retained Release.
            b.loss(Action::EnableAndRejoin);
            b.drain(None);
            b.emit(Effect::Leave);
            b.transition(Event::Leave);
            b.drain(None);
            b.assert_accounted();
            prop_assert!(b.machine.cleanup_confirmed());
        }
        // Independently compute the exponential deadline from actual failed effects.
        e.loss(Action::Rejoin);
        for _ in 0..failures {
            e.drain(Some(Step::ConfigureDns));
            assert!(e.complete(false, true));
        }
        // Fail verification with zero-duration effects: the next execution must wait 1s.
        e.drain(Some(Step::VerifyPreTunnel));
        e.fail_verification(deltas.first().copied().unwrap_or(0));
        e.drain(Some(Step::VerifyPreTunnel));
        for delta in deltas {
            e.now_ms += u64::from(delta); // includes zero and sub-second advances
            e.loss(Action::Rejoin);
            e.drain(Some(match delta % 3 {
                0 => Step::VerifyPreTunnelLoad,
                1 => Step::ConfigureAddresses,
                _ => Step::VerifyPreTunnel,
            }));
            if e.machine.pending().is_none() { e.loss(Action::Rejoin); e.drain(Some(Step::VerifyPreTunnelLoad)); }
            e.loss(Action::Rejoin);
            e.drain(Some(Step::VerifyPreTunnel));
        }
        e.drain(Some(Step::ConfigureUapi));
        if suffix_loss { e.loss(Action::Rejoin); }
        e.drain(None);
        // Exercise the acquire boundary with a round started before the kernel result.
        e.loss(Action::EnableAndRejoin);
        e.drain(Some(Step::AcquireReference));
        let stale = observed(&e.machine, Form::PreTunnel, Verdict::Repair(Action::EnableAndRejoin));
        assert_eq!(e.machine.pending(), Some(Step::AcquireReference));
        assert!(e.complete(false, false));
        let accepted = e.machine.transition(stale, &Clock(e.now())).is_ok();
        e.emit(Effect::StaleRoundAccepted(accepted));
        e.drain(None);
        e.emit(Effect::Leave);
        e.transition(Event::Leave);
        e.transition(observed(&e.machine, Form::Joined, Verdict::Repair(Action::EnableAndRejoin)));
        e.drain(None);
        e.assert_accounted();
        prop_assert!(e.machine.cleanup_confirmed());
        // An uncertain acquire occupies a slot; one replacement enables pf.
        let mut u = Executor::new();
        let sequence = u.uncertain_acquire();
        u.fail_reconciliation();
        prop_assert_eq!(u.machine.pending(), Some(Step::AcquireReference));
        prop_assert!(u.complete(false, false));
        u.drain(Some(Step::FlushStates));
        prop_assert!(u.complete(false, false));
        prop_assert!(u.machine.states_clean_at().is_some());
        u.emit(Effect::Leave);
        u.transition(Event::Leave);
        // All independent cleanup completes at the same instant, before the debt timer.
        for _ in 0..16 {
            if !u.complete(false, false) { break; }
        }
        prop_assert!(u.stream.iter().any(|effect| matches!(effect, Effect::Finish(Step::RemoveAnchor, _, true))));
        prop_assert!(!u.machine.cleanup_confirmed());
        for _ in 0..3 {
            let Some(Step::Backoff { until }) = u.machine.pending() else { panic!("missing debt cadence") };
            // Disturbances cannot bring reconciliation forward.
            for _ in 0..10 { u.transition(Event::InvalidateObservations { since: u.now() }); }
            prop_assert!(!u.complete(false, false));
            prop_assert!(u.machine.status_text_at(&Clock(u.now())).contains("ownership cleanup debt"));
            u.now_ms = until * 1000;
            prop_assert!(u.complete(false, false));
            u.fail_reconciliation();
        }
        // A real successful completion after Leave is still recorded by identity.
        u.token += 1;
        u.emit(Effect::Acquire(sequence, u.token));
        u.transition(Event::ReferenceAcquiredFor { sequence, token: u.token });
        u.drain(None);
        u.assert_accounted();
        prop_assert!(u.machine.cleanup_confirmed());
    }
}

#[test]
fn two_uncertain_results_never_allow_a_third_acquire_and_late_results_do_not_settle_other_effects()
{
    let mut e = Executor::new();
    let first = e.uncertain_acquire();
    e.fail_reconciliation();
    let second = e.uncertain_acquire();
    assert_ne!(first, second);
    assert_eq!(e.machine.pending(), Some(Step::LoadPreTunnel));
    assert!(!e.machine.plan().contains(&Step::AcquireReference));
    // A late result is a journal update, not completion of the current load.
    let pending = e.machine.pending();
    e.emit(Effect::Acquire(first, 2001));
    e.transition(Event::ReferenceAcquiredFor {
        sequence: first,
        token: 2001,
    });
    assert_eq!(e.machine.pending(), pending);
    e.emit(Effect::Acquire(second, 2002));
    e.transition(Event::ReferenceAcquiredFor {
        sequence: second,
        token: 2002,
    });
    assert_eq!(e.machine.pending(), pending);
    e.drain(None);
    e.emit(Effect::Leave);
    e.transition(Event::Leave);
    e.drain(None);
    e.assert_accounted();
    assert!(e.machine.cleanup_confirmed());
}

#[test]
fn reconciliation_preserves_verification_and_rejoin_waits_with_equal_deadlines() {
    let mut e = Executor::new();
    e.drain(Some(Step::ConfigureDns));
    assert!(e.complete(false, true));
    // A failed replacement acquire and a failed rejoin can both request +1s.
    e.loss(Action::EnableAndRejoin);
    e.uncertain_acquire();
    assert_eq!(e.machine.pending(), Some(Step::ReconcileReference));
    assert!(e.complete(false, false));
    e.drain(None);
    // The oracle derived both deadlines solely from effects and checked every dispatch.
    e.emit(Effect::Leave);
    e.transition(Event::Leave);
    e.drain(None);
    e.assert_accounted();
    assert!(e.machine.cleanup_confirmed());
}

#[test]
fn repeated_disables_reenable_pf_with_two_slots_and_account_for_proven_void_tokens() {
    let mut e = Executor::new();
    e.drain(None);
    for _ in 0..6 {
        e.loss(Action::EnableAndRejoin);
        e.drain(None);
        assert!(e.oracle.pf_enabled);
        assert_eq!(
            e.machine.status_at(&Clock(e.now())),
            ConnectionStatus::Joined
        );
    }
    assert!(e.oracle.voided.len() >= 2);
    e.emit(Effect::Leave);
    e.transition(Event::Leave);
    e.drain(None);
    e.assert_accounted();
    assert!(e.machine.cleanup_confirmed());
}
