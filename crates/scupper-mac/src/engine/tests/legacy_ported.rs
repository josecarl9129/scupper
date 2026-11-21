//! Safety contracts carried forward from the removed executor.
use super::*;

#[test]
fn reboot_rejoins_with_new_reference_then_leave_cleans() {
    let e = joined();
    assert!(e.request_completed(1));
    let boot = e.platform.boot.clone();
    let mut p = e.into_platform();
    p.mutate(Mutation::Reboot);
    assert_ne!(p.boot, boot);
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    drive(&mut e, 700);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined)
    );
    assert!(e.platform.calls.contains(&Call::Acquire));
    let token = e.machine.durable().pf_reference.unwrap();
    assert!(e.platform.tokens.contains_key(&token));
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .any(|r| { r.key == ReferenceEntry::Token(token) && r.boot == e.platform.boot })
    );
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_left(&mut e, 2);
    assert!(e.platform.tokens.is_empty());
}

#[test]
fn monitor_before_reconcile_completion_preserves_disable_observation() {
    let mut e = joined();
    let mut durable = e.machine.durable().clone();
    durable.older_references = vec![123];
    durable.reference_needs_reconcile = true;
    e.snapshot.machine = DurableRecord::try_from(&durable).unwrap();
    e.snapshot.references[1] = Some(RefEvidence {
        key: ReferenceEntry::Token(123),
        boot: e.platform.boot.clone(),
        release_unknown: false,
        fingerprint: None,
    });
    e.machine = Machine::restart(durable);
    e.apply(Event::ReferenceSettled {
        entry: ReferenceEntry::Token(123),
        how: ReferenceSettlement::Absent,
    });
    assert_eq!(e.machine.pending(), Some(Step::ReconcileReference));
    let context = e.machine.context();
    e.queue.push_back(QueueEvent::Monitor(Event::Observed {
        context,
        form: Form::PreTunnel,
        verdict: Verdict::Repair(verify::Action::EnableAndRejoin),
    }));
    e.dispatch(Step::ReconcileReference);
    e.run_until_quiescent(2);
    assert_eq!(e.machine.pending(), Some(Step::AcquireReference));
    assert!(!e.machine.durable().reference_needs_reconcile);
    oracle(&mut e);
}

#[test]
fn rejected_monitors_preserve_pending_cleanup_and_verification() {
    for monitor in [Event::Repair(verify::Action::Rejoin), Event::ChildDied] {
        for target in [
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor,
            Step::VerifyJoined,
        ] {
            let mut e = joined();
            if target == Step::VerifyJoined {
                e.apply(Event::Repair(verify::Action::Rejoin));
            } else {
                leave(&mut e, 2);
            }
            before_pending(&mut e, target);
            e.dispatch(target);
            e.queue.push_front(QueueEvent::Monitor(monitor.clone()));
            let attempts = e.machine.durable().retry_attempts;
            e.run_until_quiescent(1);
            assert_eq!(e.machine.pending(), Some(target), "{monitor:?}/{target:?}");
            if matches!(monitor, Event::Repair(_)) {
                assert_eq!(e.machine.durable().retry_attempts, attempts);
            }
            e.run_until_quiescent(1);
            assert_eq!(
                e.machine.durable().cleanup_errors,
                [] as [(Step, Reason); 0]
            );
            assert_ne!(e.mode, Mode::Stuck);
            oracle(&mut e);
        }
    }
}

#[test]
fn qualification_recovers_across_restart_and_leave() {
    let mut e = joined();
    let rules = e.platform.main_rules.clone();
    e.platform.main_rules.clear();
    let since = e.platform.now();
    e.apply(Event::InvalidateObservations { since });
    drive(&mut e, 400);
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::HookMissing)
    );
    let mut p = e.into_platform();
    p.main_rules = rules;
    p.restart();
    let mut e = Engine::start(p).unwrap();
    let start = e.platform.calls.len();
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_left(&mut e, 2);
    e.submit(Request {
        id: 3,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 700);
    assert!(e.request_completed(3));
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined)
    );
    let calls = &e.platform.calls[start..];
    assert!(
        calls.iter().position(|c| *c == Call::LoadAnchor).unwrap()
            < calls.iter().position(|c| *c == Call::CheckTools).unwrap()
    );
}

#[test]
fn leave_preserves_foreign_reference_and_main_rules() {
    let mut e = joined();
    let owned = e.platform.tokens.clone();
    e.platform.mutate(Mutation::ForeignEnable);
    let foreign = e
        .platform
        .tokens
        .values()
        .find(|r| !owned.contains_key(&r.token))
        .unwrap()
        .clone();
    let rules = e.platform.main_rules.clone();
    // Persisted internal failure resumes under hold, where cleanup must still
    // distinguish an unrelated holder from this helper's known reference.
    e.enter_stuck();
    let mut p = e.into_platform();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    assert!(e.machine.durable().hold);
    leave(&mut e, 2);
    drive(&mut e, 700);
    assert_left(&mut e, 2);
    assert_eq!(
        e.platform.tokens.values().collect::<Vec<_>>(),
        vec![&foreign]
    );
    assert!(e.platform.enabled);
    assert_eq!(e.platform.main_rules, rules);
    assert!(!e.platform.calls.contains(&Call::Release(foreign.token)));
}

#[test]
fn completed_leave_never_cleans_a_later_join_after_restart() {
    let mut e = joined();
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_left(&mut e, 2);
    e.submit(Request {
        id: 3,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 500);
    assert!(e.request_completed(3));
    let generation = e.machine.durable().previous_generation.unwrap();
    let mut p = e.into_platform();
    p.restart();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 700);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined)
    );
    assert!(e.machine.durable().previous_generation.unwrap() > generation);
    assert!(!e.platform.calls.contains(&Call::RemoveAnchor));
    leave(&mut e, 4);
    drive(&mut e, 500);
    assert_left(&mut e, 4);
}

#[test]
fn snapshot_hold_round_trips_and_requires_intent_or_leaving() {
    for leaving in [false, true] {
        let durable = Durable {
            hold: true,
            join_intended: !leaving,
            leaving,
            leave_requested: leaving,
            ..Durable::default()
        };
        let mut snapshot = Snapshot::initial(Some(501), None);
        snapshot.machine = DurableRecord::try_from(&durable).unwrap();
        let bytes = snapshot::encode(1, &snapshot).unwrap();
        let CopyClass::V { snapshot, .. } =
            snapshot::classify_copy(snapshot::CopyRead::Bytes(bytes.to_vec()))
        else {
            panic!("valid held snapshot rejected")
        };
        assert_eq!(snapshot.validate().unwrap(), durable);
    }
    let mut snapshot = Snapshot::initial(Some(501), None);
    snapshot.machine.hold = true;
    assert!(snapshot.validate().is_err());
    assert!(snapshot::encode(1, &snapshot).is_err());
    let mut value = serde_json::to_value(Snapshot::initial(None, None)).unwrap();
    value["machine"].as_object_mut().unwrap().remove("hold");
    assert!(serde_json::from_value::<Snapshot>(value).is_err());
}

// Recreate deterministic scenarios instead of copying private engine state.
// Startup injection happens after helper death, which clears local faults.
fn scenario_base(scenario: usize) -> Engine<FakePlatform> {
    if scenario == 0 { fresh() } else { joined() }
}

fn begin_scenario(mut e: Engine<FakePlatform>, scenario: usize) -> Engine<FakePlatform> {
    match scenario {
        0 => {
            e.submit(Request {
                id: 10,
                kind: RequestKind::Join,
            })
            .unwrap();
        }
        1 => leave(&mut e, 11),
        2..=5 => e.apply(Event::Repair(match scenario {
            2 => verify::Action::Rejoin,
            3 => verify::Action::EnableAndRejoin,
            4 => verify::Action::RecreateChild,
            _ => verify::Action::Rerender { form: Form::Joined },
        })),
        _ => panic!("startup is prepared separately"),
    }
    e
}

fn scenario(
    scenario: usize,
    injection: Option<(Call, usize, Fault, bool)>,
) -> Engine<FakePlatform> {
    let mut e = scenario_base(scenario);
    if scenario == 6 {
        let mut p = e.into_platform();
        p.restart();
        p.calls.clear();
        inject(&mut p, injection);
        Engine::start(p).unwrap()
    } else {
        e.platform.calls.clear();
        inject(&mut e.platform, injection);
        begin_scenario(e, scenario)
    }
}

fn inject(p: &mut FakePlatform, injection: Option<(Call, usize, Fault, bool)>) {
    if let Some((call, nth, fault, persistent)) = injection {
        p.inject(call, nth, fault);
        if persistent {
            p.inject_persistent(call, fault);
        }
    }
}

fn occurrences(calls: &[Call]) -> Vec<(Call, usize)> {
    calls
        .iter()
        .enumerate()
        .map(|(index, call)| (*call, calls[..=index].iter().filter(|c| *c == call).count()))
        .collect()
}

fn faults(call: Call) -> Vec<Fault> {
    match call {
        Call::Configure(ConfigKey::Uapi)
        | Call::CleanupArtifacts
        | Call::ReadAnchor
        | Call::ReadConfig(_)
        | Call::References
        | Call::PfInfo
        | Call::CheckTools
        | Call::Identity
        | Call::Cheap
        | Call::Collect
        | Call::LeaveRoutes
        | Call::Processes
        | Call::ExecutableId
        | Call::Kill(..)
        | Call::KillProcess(..)
        | Call::ReapChildren => vec![
            Fault::ReadFail,
            Fault::Incomplete,
            Fault::ToolHang {
                reaped: true,
                effect: false,
            },
        ],
        Call::Acquire
        | Call::Release(_)
        | Call::LoadAnchor
        | Call::Flush
        | Call::InterfaceStates
        | Call::Configure(_)
        | Call::CleanupRoutes(_)
        | Call::CleanupDns
        | Call::RemoveAnchor => vec![
            Fault::NotStarted,
            Fault::ToolFail { effect: false },
            Fault::ToolFail { effect: true },
            Fault::ToolHang {
                reaped: true,
                effect: false,
            },
            Fault::ToolHang {
                reaped: true,
                effect: true,
            },
            Fault::ToolHang {
                reaped: false,
                effect: false,
            },
            Fault::ToolHang {
                reaped: false,
                effect: true,
            },
            Fault::ToolLate { ticks: None },
        ],
        Call::Spawn => vec![
            Fault::NotStarted,
            Fault::SpawnHang { child: false },
            Fault::SpawnHang { child: true },
        ],
        _ => vec![],
    }
}

fn crash_at_boundary(phase: usize, call: Call, nth: usize, before: bool, repeated: bool) {
    let mut e = scenario_base(phase);
    let capture = |p: &mut FakePlatform, nth| {
        if before {
            p.capture_before(call, nth);
        } else {
            p.capture_after(call, nth);
        }
    };
    if phase == 6 {
        let mut p = e.into_platform();
        p.restart();
        capture(&mut p, nth);
        e = Engine::start(p).unwrap();
    } else {
        capture(&mut e.platform, nth);
        e = begin_scenario(e, phase);
    }
    drive(&mut e, 700);
    // This prefix is captured inside the platform, before the engine can
    // persist or process the effect's completion.
    let mut p = e
        .platform
        .take_capture()
        .unwrap_or_else(|| panic!("no effect capture: {phase}/{call:?}/{nth}"));
    p.restart();
    if repeated {
        capture(&mut p, 1);
    }
    let mut e = Engine::start(p).unwrap();
    if repeated {
        for _ in 0..32 {
            tick(&mut e);
            if let Some(mut p) = e.platform.take_capture() {
                p.restart();
                capture(&mut p, 1);
                e = Engine::start(p).unwrap();
            }
        }
    }
    drive(&mut e, 3000);
    assert_converged_or_accounted(&mut e, phase, (call, nth, Fault::FailedDurable, false));
}

#[test]
fn crashes_before_and_after_effects_and_reads_preserve_safety() {
    for phase in 0..7 {
        let mut baseline = scenario(phase, None);
        drive(&mut baseline, 700);
        for (call, nth) in occurrences(&baseline.platform.calls) {
            if faults(call).is_empty()
                && !matches!(
                    call,
                    Call::Install | Call::Read(_) | Call::CheckPfctl | Call::Reap
                )
            {
                continue;
            }
            for before in [false, true] {
                for repeated in [false, true] {
                    crash_at_boundary(phase, call, nth, before, repeated);
                }
            }
        }
    }
}

fn assert_converged_or_accounted(
    e: &mut Engine<FakePlatform>,
    scenario: usize,
    context: (Call, usize, Fault, bool),
) {
    oracle(e);
    if scenario >= 2 {
        assert!(
            e.machine.durable().join_intended,
            "lost Joined intent: {scenario}/{context:?}"
        );
    }
    let status = e.status();
    if scenario == 1 {
        if status.text != "left"
            && e.request_completed(11)
            && !e.machine.durable().join_intended
            && !e.machine.durable().leaving
        {
            // Restart expires the volatile Left proof even when LeaveDone is
            // durable. Check resources before any new request can clean them.
            assert_left_resources(e);
            assert_references_released_or_accounted(e);
            return;
        }
        if e.status().text != "left" {
            // Failed cleanup is resumable by an explicit Leave. The incomplete
            // result must never acknowledge success while an owned child lives.
            assert!(
                !e.request_completed(11),
                "{context:?}: {status:?}; {:?}; {:?}",
                e.machine.durable(),
                e.machine.plan()
            );
            assert!(
                e.machine.durable().leaving
                    || matches!(context.0, Call::Write(_)) && context.1 == 1,
                "lost durable Leave: {context:?}"
            );
            let retry_id = if e.snapshot.requests.iter().any(|request| request.id == 11) {
                12
            } else {
                11
            };
            leave(e, retry_id);
            drive(e, 3000);
            assert!(e.request_completed(retry_id), "{context:?}");
        }
        assert_left(e, 11);
        assert_references_released_or_accounted(e);
    } else if scenario == 0 && !e.machine.durable().join_intended && e.machine.pending().is_none() {
        assert!(
            matches!(context.0, Call::Write(_)) && context.1 <= 2,
            "lost Join after intent commit: {context:?}"
        );
        // The first pair admits the request; the second completes PersistIntent.
        // Only a fault before that pair completes may restart from durable Left.
        assert!(e.platform.anchor.is_none());
        assert!(e.platform.children.is_empty());
        assert!(!e.request_completed(10));
    } else if !matches!(status.enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined) {
        // One uncertain acquisition does not prevent protection. A full pair
        // of unresolved acquisitions is the irreducible bounded-ledger escape.
        assert!(
            e.mode == Mode::Stuck
                || e.machine.durable().hold
                || (status.accounting.uncertain == 2
                    && status.accounting.held == 0
                    && e.machine.durable().uncertain_acquires.len() == 2
                    && e.machine.durable().reference_intent.is_none()
                    && e.snapshot.references.iter().flatten().count() == 2
                    && e.snapshot
                        .references
                        .iter()
                        .flatten()
                        .all(|entry| matches!(entry.key, ReferenceEntry::Acquire(_)))
                    && e.machine.durable().pf_reference.is_none())
                || status.accounting.release_unknown > 0,
            "{scenario}/{context:?}: {:?}; {:?}; {:?}; {:?}",
            status,
            e.machine.plan(),
            e.machine.durable(),
            e.snapshot.requests
        );
        assert!(!matches!(status.enforcement, Verdict::Protected(_)));
    }
}

#[test]
fn convergence_rejects_one_uncertain_reference_as_an_availability_escape() {
    let mut e = joined_with_reference_debt();
    let since = e.platform.now();
    e.apply(Event::InvalidateObservations { since });
    assert_eq!(e.status().accounting.uncertain, 1);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_converged_or_accounted(
                &mut e,
                2,
                (Call::Acquire, 1, Fault::ToolFail { effect: true }, false),
            );
        }))
        .is_err()
    );
}

#[test]
fn convergence_rejects_lost_join_after_privileged_effect() {
    let mut e = fresh();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_converged_or_accounted(&mut e, 0, (Call::Acquire, 1, Fault::NotStarted, false));
        }))
        .is_err()
    );
}

#[test]
fn convergence_rejects_an_unexposed_reservation_as_irreducible_debt() {
    let mut e = fresh();
    e.platform
        .inject(Call::Acquire, 1, Fault::ToolFail { effect: false });
    e.submit(Request {
        id: 10,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    e.dispatch(Step::AcquireReference);
    e.run_until_quiescent(1);
    before_pending(&mut e, Step::AcquireReference);
    assert_eq!(e.status().accounting.uncertain, 2);
    assert_eq!(e.machine.durable().uncertain_acquires.len(), 1);
    assert!(e.machine.durable().reference_intent.is_some());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_converged_or_accounted(
                &mut e,
                0,
                (Call::Acquire, 1, Fault::ToolFail { effect: false }, false),
            );
        }))
        .is_err()
    );
}

#[test]
fn privileged_faults_preserve_safety_at_each_effect_boundary() {
    let mut cases = 0;
    for phase in 0..7 {
        let mut baseline = scenario(phase, None);
        drive(&mut baseline, 700);
        for (call, nth) in occurrences(&baseline.platform.calls) {
            for persistent in [false, true] {
                for fault in faults(call) {
                    let mut e = scenario(phase, Some((call, nth, fault, persistent)));
                    for _ in 0..700 {
                        tick(&mut e);
                        if e.platform.calls.iter().filter(|c| **c == call).count() >= nth {
                            break;
                        }
                    }
                    assert!(
                        e.platform.calls.iter().filter(|c| **c == call).count() >= nth,
                        "unreached {phase}/{call:?}/{nth}/{fault:?}"
                    );
                    elapse(&mut e, if persistent { 8 } else { 1 });
                    e.platform.clear_faults();
                    e.platform.release_unreaped();
                    drive(&mut e, 3000);
                    assert_converged_or_accounted(&mut e, phase, (call, nth, fault, persistent));
                    if phase != 1 {
                        assert!(
                            !e.platform.calls.contains(&Call::RemoveAnchor),
                            "premature cleanup {phase}/{call:?}/{nth}/{fault:?}"
                        );
                    }
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 1000, "unexpectedly small fault table: {cases}");
}

#[test]
fn commit_faults_preserve_safety_at_every_join_repair_restart_boundary() {
    let mut cases = 0;
    for phase in 0..7 {
        let mut baseline = scenario(phase, None);
        drive(&mut baseline, 700);
        let boundaries = occurrences(&baseline.platform.calls)
            .into_iter()
            .filter(|(call, _)| matches!(call, Call::Write(_)))
            .collect::<Vec<_>>();
        assert!(!boundaries.is_empty(), "phase {phase}");
        for (call, nth) in boundaries {
            for fault in [
                Fault::WriteFail,
                Fault::WriteHang,
                Fault::TornWrite(24),
                Fault::LostBeforeSync,
                Fault::FailedPending,
                Fault::FailedDurable,
            ] {
                let mut e = scenario(phase, Some((call, nth, fault, false)));
                for _ in 0..700 {
                    tick(&mut e);
                    if e.platform.calls.iter().filter(|c| **c == call).count() >= nth {
                        break;
                    }
                }
                assert!(e.platform.calls.iter().filter(|c| **c == call).count() >= nth);
                let mut p = e.into_platform();
                p.restart();
                p.calls.clear();
                let mut e = Engine::start(p).unwrap();
                drive(&mut e, 3000);
                assert_converged_or_accounted(&mut e, phase, (call, nth, fault, false));
                if phase >= 2 || e.machine.durable().join_intended {
                    assert!(!e.platform.calls.contains(&Call::RemoveAnchor));
                }
                cases += 1;
            }
        }
    }
    assert!(cases >= 100, "unexpectedly small commit table: {cases}");
}

fn leave_base(hold: bool) -> Engine<FakePlatform> {
    let mut e = joined();
    if hold {
        e.enter_stuck();
        let mut p = e.into_platform();
        p.restart();
        e = Engine::start(p).unwrap();
        assert!(e.machine.durable().hold);
    }
    e.platform.calls.clear();
    e
}

#[test]
fn leave_storage_faults_cleanup_before_durable_ack() {
    for hold in [false, true] {
        let mut baseline = leave_base(hold);
        leave(&mut baseline, 2);
        drive(&mut baseline, 500);
        assert_left(&mut baseline, 2);
        let boundaries = occurrences(&baseline.platform.calls)
            .into_iter()
            .filter(|(call, _)| matches!(call, Call::Write(_)))
            .collect::<Vec<_>>();
        assert!(boundaries.len() >= 6);
        for (call, nth) in boundaries {
            for persistent in [false, true] {
                let mut e = leave_base(hold);
                inject(
                    &mut e.platform,
                    Some((call, nth, Fault::WriteFail, persistent)),
                );
                leave(&mut e, 2);
                for _ in 0..700 {
                    tick(&mut e);
                    if e.platform.calls.iter().filter(|c| **c == call).count() >= nth {
                        break;
                    }
                }
                assert!(e.platform.calls.iter().filter(|c| **c == call).count() >= nth);
                elapse(&mut e, 5);
                if persistent {
                    assert_eq!(e.mode, Mode::PersistBlocked);
                    assert!(!e.request_completed(2));
                    assert!(e.platform.anchor.is_none());
                    assert!(e.platform.children.is_empty());
                    for key in [
                        ConfigKey::Dns,
                        ConfigKey::SplitRoutes,
                        ConfigKey::EndpointRoute,
                    ] {
                        assert!(!e.platform.settings.contains_key(&key), "{key:?}");
                    }
                }
                e.platform.clear_faults();
                drive(&mut e, 3000);
                assert_left(&mut e, 2);
                for token in e.platform.tokens.keys() {
                    // Failure of the durable release premark can leave a known
                    // numeric token with a possibly-completed release. Leave
                    // restores connectivity but must not guess and release it twice.
                    assert!(
                        e.snapshot.references.iter().flatten().any(|r| {
                            r.key == ReferenceEntry::Token(*token) && r.release_unknown
                        }),
                        "held={hold} {call:?}/{nth} persistent={persistent}: {:?}",
                        e.snapshot.references
                    );
                    assert!(
                        e.platform
                            .calls
                            .iter()
                            .filter(|c| **c == Call::Release(*token))
                            .count()
                            <= 1
                    );
                }
                assert!(!e.platform.calls.contains(&Call::Spawn));
            }
        }
    }
}

#[test]
fn incomplete_pf_info_during_recovery_preserves_policy_proof_consistency() {
    let mut baseline = scenario(6, None);
    drive(&mut baseline, 700);
    for (call, nth) in occurrences(&baseline.platform.calls) {
        if call != Call::PfInfo {
            continue;
        }
        for fault in [Fault::ReadFail, Fault::Incomplete] {
            let mut e = scenario(6, Some((call, nth, fault, false)));
            drive(&mut e, 3000);
            assert_converged_or_accounted(&mut e, 6, (call, nth, fault, false));
        }
    }
}
