//! Engine contracts exercise deterministic model time at every serialized boundary.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use crate::{
    platform::{
        ConfigKey, ExeId, ProcState, RefLine, WriteOutcome,
        fake::{Call, FakePlatform, Fault, Mutation},
    },
    snapshot::{BootId, RefFingerprint},
};
use scupper_core::mac::{parse, policy};
use std::time::Duration;

fn fixture(snapshot: &Snapshot) -> FakePlatform {
    let mut p = FakePlatform::new().unwrap();
    let bytes = snapshot::encode(1, snapshot).unwrap();
    for copy in [Copy::A, Copy::B] {
        assert_eq!(
            p.create_copy(copy, &bytes, Deadline(105)),
            WriteOutcome::Synced
        );
    }
    p.calls.clear();
    p
}
fn fresh() -> Engine<FakePlatform> {
    let p = FakePlatform::new().unwrap();
    let mut snapshot = Snapshot::initial(Some(501), p.boot.clone());
    snapshot.endpoint = Some(execute::endpoint(&p.install.config.inputs));
    Engine::start(fixture(&snapshot)).unwrap()
}
fn tick(e: &mut Engine<FakePlatform>) {
    e.platform.tick();
    e.run_until_quiescent(1);
    oracle(e);
}
fn elapse(e: &mut Engine<FakePlatform>, seconds: u64) {
    for _ in 0..seconds * 20 {
        tick(e);
    }
}
fn drive(e: &mut Engine<FakePlatform>, cap: usize) {
    for _ in 0..cap {
        tick(e);
        if e.is_quiescent() && e.machine.pending().is_none() {
            return;
        }
    }
}
fn joined() -> Engine<FakePlatform> {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 300);
    assert_eq!(e.mode(), Mode::Normal);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined),
        "{:?}; {:?}",
        e.status(),
        e.machine.plan()
    );
    e
}
fn assert_left(e: &mut Engine<FakePlatform>, id: u64) {
    assert_eq!(e.status().text, "left");
    assert!(e.request_completed(id));
    assert!(!e.machine.durable().join_intended);
    assert!(!e.machine.durable().leaving);
    assert_left_resources(e);
}
fn assert_left_resources(e: &Engine<FakePlatform>) {
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
fn assert_references_released_or_accounted(e: &Engine<FakePlatform>) {
    for token in e.platform.tokens.keys() {
        assert!(
            e.snapshot.references.iter().flatten().any(|entry| {
                entry.key == ReferenceEntry::Token(*token) && entry.release_unknown
            }),
            "unaccounted token {token}"
        );
    }
}
fn reacquiring_after_verified_enforcement() -> Engine<FakePlatform> {
    let mut e = joined();
    e.platform.mutate(Mutation::PfDisable);
    e.apply(Event::Repair(verify::Action::EnableAndRejoin));
    before_pending(&mut e, Step::AcquireReference);
    assert!(!e.verified_enforcement);
    e
}
fn oracle(e: &mut Engine<FakePlatform>) {
    assert!(
        e.platform.violations.is_empty(),
        "{:?}",
        e.platform.violations
    );
    assert!(e.snapshot.validate().is_ok(), "{:?}", e.snapshot);
    assert!(e.snapshot.references.iter().flatten().count() <= 2);
    if let Verdict::Protected(proof) = e.status().enforcement {
        assert_eq!(e.mode(), Mode::Normal);
        assert_eq!(proof.context(), e.machine.context());
        assert!(e.platform.enabled);
        assert_eq!(e.platform.fence(), Fence::Closed);
        assert!(e.helper_committed);
        assert!(e.platform.main_rules.contains("anchor \"com.apple/*\""));
        assert!(!e.platform.main_rules.contains("pass quick"));
        assert!(e.platform.skipped.is_empty());
        let inputs = e.inputs().unwrap();
        let expected = match proof.form() {
            Form::PreTunnel => policy::render_pre_tunnel(&inputs),
            Form::Joined => policy::render_joined(&inputs),
        };
        assert_eq!(e.platform.anchor.as_deref(), Some(expected.as_str()));
        assert!(!e.platform.states.iter().any(|permissive| *permissive));
        assert!(
            !e.platform
                .interface_states
                .values()
                .flatten()
                .any(|permissive| *permissive)
        );
        if proof.form() == Form::Joined {
            assert_eq!(e.platform.children.len(), 1);
            assert!(e.platform.settings.contains_key(&ConfigKey::EndpointRoute));
        }
    }
    // Every exposed child generation is present in a completely synced pair,
    // or in a later superset after an N-class failure. The engine's successful
    // commit cache is the last complete pair, not whichever copy happens to read.
    if let Some(child) = &e.child {
        assert!(
            e.committed
                .machine
                .previous_generation
                .is_some_and(|g| g >= child.generation)
        );
    }
}
fn writes(p: &FakePlatform) -> usize {
    p.calls
        .iter()
        .filter(|c| matches!(c, Call::Write(_) | Call::Create(_)))
        .count()
}
fn read_snapshot(p: &mut FakePlatform, copy: Copy) -> Snapshot {
    let d = Deadline(p.now() + 5);
    match snapshot::classify_copy(p.read_copy(copy, d)) {
        CopyClass::V { snapshot, .. } => snapshot,
        class => panic!("unexpected copy {class:?}"),
    }
}
fn before_pending(e: &mut Engine<FakePlatform>, target: Step) {
    for _ in 0..600 {
        if e.machine.pending() == Some(target) && e.in_flight.is_none() {
            return;
        }
        tick(e);
    }
    panic!(
        "did not reach {target:?}: {:?} {:?}",
        e.mode,
        e.machine.plan()
    );
}

#[test]
fn happy_join_has_reservations_readbacks_and_fresh_proofs() {
    let mut e = joined();
    let calls = &e.platform.calls;
    let acquire = calls.iter().position(|c| *c == Call::Acquire).unwrap();
    let spawn = calls.iter().position(|c| *c == Call::Spawn).unwrap();
    assert!(calls[..acquire].contains(&Call::Write(Copy::B)));
    assert!(calls[acquire..spawn].contains(&Call::Write(Copy::B)));
    assert!(calls[acquire..spawn].contains(&Call::Processes));
    assert!(calls.contains(&Call::ReadAnchor));
    for key in [
        ConfigKey::Uapi,
        ConfigKey::Addresses,
        ConfigKey::Mtu,
        ConfigKey::EndpointRoute,
        ConfigKey::SplitRoutes,
        ConfigKey::Dns,
    ] {
        assert!(calls.contains(&Call::Configure(key)));
        assert!(calls.contains(&Call::ReadConfig(key)));
    }
    assert_eq!(
        e.status().accounting,
        Accounting {
            held: 1,
            uncertain: 0,
            release_unknown: 0
        }
    );
}
#[test]
fn startup_probes_left_then_reads_install_and_retries_full_copies_before_any_tool() {
    let mut p = fixture(&Snapshot::initial(Some(501), None));
    p.inject(Call::Read(Copy::A), 2, Fault::ReadFail);
    p.inject(Call::Read(Copy::B), 2, Fault::ReadFail);
    let e = Engine::start(p).unwrap();
    assert_eq!(e.mode(), Mode::Normal);
    let calls = &e.platform.calls;
    let install = calls.iter().position(|c| *c == Call::Install).unwrap();
    let read = calls
        .iter()
        .position(|c| *c == Call::Read(Copy::A))
        .unwrap();
    assert!(read < install);
    for copy in [Copy::A, Copy::B] {
        assert_eq!(calls.iter().filter(|c| **c == Call::Read(copy)).count(), 3);
    }
    assert_eq!(
        calls
            .iter()
            .filter(|c| **c == Call::Pause(Duration::from_millis(100)))
            .count(),
        2
    );
    assert!(!calls.iter().any(|c| matches!(
        c,
        Call::Acquire | Call::Spawn | Call::CheckTools | Call::Collect
    )));
}
#[test]
fn pair_repair_creates_missing_and_rewrites_stale_before_helper_commit() {
    for missing in [true, false] {
        for destination in [Copy::A, Copy::B] {
            // A can only be repaired from B when A is torn/missing.
            let mut p = fixture(&Snapshot::initial(Some(501), None));
            if missing {
                p.mutate(Mutation::MissingCopy(destination));
            } else {
                p.mutate(Mutation::CopyRot(destination));
            }
            p.calls.clear();
            let mut e = Engine::start(p).unwrap();
            assert_eq!(e.mode, Mode::Normal);
            let first = e
                .platform
                .calls
                .iter()
                .find(|c| matches!(c, Call::Create(_) | Call::Write(_)))
                .unwrap();
            assert_eq!(
                *first,
                if missing {
                    Call::Create(destination)
                } else {
                    Call::Write(destination)
                }
            );
            assert_eq!(
                read_snapshot(&mut e.platform, Copy::A),
                read_snapshot(&mut e.platform, Copy::B)
            );
        }
    }
}
#[test]
fn failed_pair_repair_is_explicit_and_never_runs_a_tool() {
    for missing in [true, false] {
        let mut p = fixture(&Snapshot::initial(Some(501), None));
        p.mutate(if missing {
            Mutation::MissingCopy(Copy::B)
        } else {
            Mutation::CopyRot(Copy::B)
        });
        p.inject(
            if missing {
                Call::Create(Copy::B)
            } else {
                Call::Write(Copy::B)
            },
            1,
            Fault::NoSpace,
        );
        let mut e = Engine::start(p).unwrap();
        assert_eq!(e.mode(), Mode::PersistBlocked);
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        assert!(!e.platform.calls.contains(&Call::Spawn));
    }
}
#[test]
fn recovery_commit_precedes_start_fence_and_crashes_leave_conservative_copies() {
    for copy in [Copy::A, Copy::B] {
        for fault in [Fault::LostBeforeSync, Fault::FailedDurable] {
            let mut p = fixture(&Snapshot::initial(Some(501), None));
            p.mutate(Mutation::CopyRot(Copy::A));
            p.mutate(Mutation::CopyRot(Copy::B));
            p.inject(Call::Write(copy), 1, fault);
            let mut e = Engine::start(p).unwrap();
            assert_eq!(e.mode(), Mode::PersistBlocked);
            assert!(e.platform.calls.contains(&Call::Processes));
            assert!(!e.platform.calls.contains(&Call::Spawn));
            e.platform.restart();
            let mut restarted = Engine::start(e.into_platform()).unwrap();
            assert_eq!(restarted.mode(), Mode::Normal);
            assert!(restarted.snapshot.machine.hold);
            assert_eq!(restarted.status().accounting.uncertain, 2);
        }
    }
    let mut p = fixture(&Snapshot::initial(Some(501), None));
    p.mutate(Mutation::CopyRot(Copy::A));
    p.mutate(Mutation::CopyRot(Copy::B));
    p.calls.clear();
    let e = Engine::start(p).unwrap();
    let write = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Write(Copy::B))
        .unwrap();
    let enumerate = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Processes)
        .unwrap();
    let fence_enumerate = e.platform.calls[enumerate + 1..]
        .iter()
        .position(|c| *c == Call::Processes)
        .unwrap()
        + enumerate
        + 1;
    assert!(enumerate < write && write < fence_enumerate);
    assert_eq!(e.mode, Mode::Normal);
}
#[test]
fn crash_before_helper_commit_keeps_previous_and_prevents_spawn() {
    for copy in [Copy::A, Copy::B] {
        let mut p = fixture(&Snapshot::initial(Some(501), None));
        let previous = p.helper.clone();
        let mut old = Snapshot::initial(Some(501), None);
        old.helper = Some(previous.clone());
        let bytes = snapshot::encode(1, &old).unwrap();
        for slot in &mut p.copies {
            slot.durable = Some(bytes.clone());
        }
        p.restart();
        p.inject(Call::Write(copy), 1, Fault::LostBeforeSync);
        let mut e = Engine::start(p).unwrap();
        assert_eq!(e.mode, Mode::PersistBlocked);
        assert!(!e.helper_committed);
        assert!(!e.platform.calls.contains(&Call::Spawn));
        if copy == Copy::A {
            assert_eq!(
                read_snapshot(&mut e.platform, Copy::A).helper,
                Some(previous)
            );
        }
        e.platform.restart();
        let resumed = Engine::start(e.into_platform()).unwrap();
        assert_eq!(resumed.mode, Mode::Normal);
        assert!(resumed.helper_committed);
    }
}
#[test]
fn invalid_helper_group_or_parent_exits_before_shared_writes_or_tools() {
    for parent in [false, true] {
        let mut p = fixture(&Snapshot::initial(Some(501), None));
        if parent {
            p.procs.get_mut(&p.helper.pid).unwrap().ppid = 22;
        } else {
            p.helper.pgid = 99;
        }
        let Err(failure) = Engine::start(p) else {
            panic!("ownership accepted")
        };
        assert_eq!(failure.outcome, StartOutcome::StartupInvariantFailed);
        assert_eq!(writes(&failure.platform), 0);
        assert!(!failure.platform.calls.iter().any(|c| matches!(
            c,
            Call::CreateControlSocket
                | Call::Spawn
                | Call::LoadAnchor
                | Call::Acquire
                | Call::Kill(..)
                | Call::KillProcess(..)
        )));
    }
}

#[test]
fn recovery_ambiguity_is_narrow_and_never_establishes_ownership() {
    for recovery in [false, true] {
        for state in [
            ProcState::Running,
            ProcState::Sleeping,
            ProcState::Stopped,
            ProcState::Zombie,
        ] {
            for (path, name, parent, seconds, ambiguous) in [
                (None, None, 1, 90, true),
                (
                    Some("/opt/scupper/wireguard-go.old"),
                    Some("wireguard-go"),
                    1,
                    90,
                    true,
                ),
                (None, None, 77, 90, false),
                (None, None, 1, 101, false),
                (Some("/foreign"), None, 1, 90, false),
            ] {
                let mut p = fixture(&Snapshot::initial(Some(501), None));
                let mut proc = p.procs[&p.helper.pid].clone();
                proc.pid = 333;
                proc.pgid = 222;
                proc.ppid = parent;
                proc.start.seconds = seconds;
                proc.state = state;
                proc.path = path.map(Into::into);
                proc.name = name.map(Into::into);
                proc.exe = Some(ExeId { dev: 77, ino: 88 });
                proc.image = Some(platform::ImageId {
                    uuid: [9; 16],
                    uniqueid: 333,
                });
                p.procs.insert(333, proc);
                if recovery {
                    p.mutate(Mutation::CopyRot(Copy::A));
                    p.mutate(Mutation::CopyRot(Copy::B));
                }
                let mut e = Engine::start(p).unwrap();
                if path.is_none() && state != ProcState::Zombie && !(recovery && ambiguous) {
                    assert!(
                        matches!(e.start_fence, StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(333))
                    );
                    assert_eq!(e.platform.signals, []);
                    e.platform.procs.remove(&333);
                    tick(&mut e);
                    assert_eq!(e.mode, Mode::Normal);
                    continue;
                }
                if recovery && ambiguous && state != ProcState::Zombie {
                    assert_eq!(e.mode, Mode::Starting);
                    assert!(
                        matches!(e.start_fence, StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(333))
                    );
                    assert!(!e.helper_committed);
                    let before = writes(&e.platform);
                    tick(&mut e);
                    assert_eq!(writes(&e.platform), before);
                    // The Recovery pair is now valid, but cannot erase unknown
                    // provenance if we crash before committing a helper.
                    let mut p = e.into_platform();
                    // The host's other orphan completes exec before this restart;
                    // isolate the older survivor whose uncertainty must persist.
                    // First pin the documented pathless-launchd residual.
                    let mut residual = p.clone();
                    residual.procs.remove(&333);
                    residual.procs.get_mut(&14).unwrap().path = None;
                    let d = Deadline(residual.now() + 2);
                    residual.pause(Duration::from_secs(2), d);
                    residual.restart();
                    let residual = Engine::start(residual).unwrap();
                    assert_eq!(residual.mode, Mode::Starting);
                    assert!(
                        matches!(residual.start_fence, StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(14))
                    );
                    assert_eq!(residual.platform.signals, []);
                    p.procs.get_mut(&14).unwrap().path = Some("/usr/bin/foreign-orphan".into());
                    p.restart();
                    e = Engine::start(p).unwrap();
                    assert_eq!(e.mode, Mode::Starting);
                    assert!(
                        matches!(e.start_fence, StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(333))
                    );
                    assert!(!e.helper_committed);
                    e.platform.procs.remove(&333);
                    tick(&mut e);
                    assert_eq!(e.start_fence, StartFence::Closed);
                }
                assert_eq!(e.platform.signals, []);
                assert_eq!(e.mode, Mode::Normal);
            }
        }
    }
}

#[test]
fn startup_settles_only_two_known_different_boots_before_restart_plan() {
    for (old_known, now_known, different) in [
        (true, true, true),
        (true, true, false),
        (false, true, true),
        (true, false, true),
        (false, false, true),
    ] {
        let mut p = FakePlatform::new().unwrap();
        let mut snapshot = Snapshot::initial(Some(501), None);
        snapshot.machine.pf_reference = Some(900);
        let old = if old_known {
            if different {
                Some(BootId::try_from("00000000-0000-0000-0000-000000000077").unwrap())
            } else {
                p.boot.clone()
            }
        } else {
            None
        };
        snapshot.references[0] = Some(RefEvidence {
            key: ReferenceEntry::Token(900),
            boot: old,
            release_unknown: false,
            fingerprint: None,
        });
        p = fixture(&snapshot);
        if !now_known {
            p.mutate(Mutation::BootIdUnavailable);
        }
        let e = Engine::start(p).unwrap();
        assert_eq!(
            e.machine.durable().pf_reference.is_none(),
            old_known && now_known && different
        );
        assert!(!e.platform.calls.contains(&Call::Release(900)));
    }
}
#[test]
fn unreadable_install_joined_sets_and_commits_hold_without_dispatch() {
    let e = joined();
    let mut p = e.into_platform();
    p.restart();
    p.inject(Call::Install, 1, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.mode, Mode::Normal);
    assert!(read_snapshot(&mut e.platform, Copy::B).machine.hold);
    assert!(e.machine.durable().hold);
    drive(&mut e, 400);
    assert!(e.status().blocking_verified);
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
}
#[test]
fn reservation_commit_failure_exposes_neither_acquire_nor_spawn() {
    for step in [
        Step::PersistIntent,
        Step::AcquireReference,
        Step::ReserveGeneration,
    ] {
        for copy in [Copy::A, Copy::B] {
            let mut e = fresh();
            e.submit(Request {
                id: 1,
                kind: RequestKind::Join,
            })
            .unwrap();
            before_pending(&mut e, step);
            // Force a changed Acquire reservation even when the prior D completion
            // already committed it; its failed N completion must be retried here.
            if step == Step::AcquireReference {
                e.committed = Snapshot::initial(Some(501), None);
            }
            e.platform.inject(Call::Write(copy), 1, Fault::WriteFail);
            let start = e.platform.calls.len();
            for _ in 0..3 {
                tick(&mut e);
            }
            assert_eq!(e.mode, Mode::PersistBlocked, "{step:?}");
            assert!(!e.platform.calls[start..].contains(&Call::Acquire));
            assert!(!e.platform.calls[start..].contains(&Call::Spawn));
        }
    }
}
#[test]
fn n_class_commit_failure_runs_safety_while_storage_retries() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::LoadPreTunnel);
    e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteFail);
    tick(&mut e); // effect
    tick(&mut e); // completion, failed N persistence
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert_ne!(e.snapshot, e.committed);
    drive(&mut e, 400);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    assert_eq!(e.snapshot, e.committed);
}
fn joined_with_reference_debt() -> Engine<FakePlatform> {
    let mut e = fresh();
    e.platform
        .inject(Call::Acquire, 1, Fault::ToolFail { effect: true });
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    elapse(&mut e, 30);
    assert_eq!(e.mode, Mode::Normal);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(_)),
        "{:?} {:?}",
        e.status(),
        e.machine.plan()
    );
    assert_eq!(e.status().accounting.uncertain, 1);
    e
}

#[test]
fn million_idle_ticks_write_nothing() {
    for debt in [false, true] {
        let mut e = if debt {
            joined_with_reference_debt()
        } else {
            joined()
        };
        e.platform.calls.clear();
        let original = e.snapshot.clone();
        let mut idle_writes = 0;
        let mut cheap = 0;
        let mut full = 0;
        let mut flush = 0;
        let mut references = 0;
        for _ in 0..1_000_000 {
            e.platform.tick();
            e.enqueue(QueueEvent::Timer).unwrap();
            // Drain ready work, including the debt retry's dispatch/completion.
            e.run_until_quiescent(8);
            let tick_writes = writes(&e.platform);
            assert_eq!(tick_writes, 0, "idle tick with debt={debt}");
            idle_writes += tick_writes;
            cheap += e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::Cheap)
                .count();
            full += e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::Collect)
                .count();
            flush += e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::Flush)
                .count();
            references += e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::References)
                .count();
            e.platform.calls.clear();
        }
        assert_eq!(idle_writes, 0, "debt={debt}");
        assert_eq!(e.snapshot, original);
        assert!(cheap >= 49_000 && full >= 9_000 && flush >= 4_000);
        assert_eq!(e.mode, Mode::Normal);
        assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
        if debt {
            assert!(references >= 49_000);
            assert_eq!(e.status().accounting.uncertain, 1);
        }
    }
}

#[test]
fn persistent_reference_timeout_does_not_rewrite_unknown_since() {
    const UNKNOWN_REASON_KIND: u8 = 7;
    let mut e = joined_with_reference_debt();
    e.platform.calls.clear();
    let start = e.platform.now();
    e.platform
        .inject_persistent(Call::References, Fault::WriteHang);
    // Include the first changed category and every subsequent retry in 120 s.
    before_pending(&mut e, Step::ReconcileReference);
    tick(&mut e);
    tick(&mut e);
    assert_eq!(
        e.snapshot.machine.reference_error.as_ref().unwrap().kind,
        UNKNOWN_REASON_KIND
    );
    while e.platform.now() < start + 120 {
        tick(&mut e);
    }
    assert!(writes(&e.platform) <= 2); // At most one A/B transaction.
    assert!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::References)
            .count()
            >= 15
    );
    assert_eq!(e.status().accounting.uncertain, 1);
}

#[test]
fn mismatched_evidence_at_commit_is_stuck_without_storage_write() {
    let mut e = joined();
    e.snapshot.references = [None, None];
    let before = writes(&e.platform);
    assert!(!e.commit_if_changed());
    assert_eq!(e.mode, Mode::Stuck);
    assert_eq!(writes(&e.platform), before);
}
#[test]
fn stale_dispatch_is_ignored_and_rejected_completion_falls_back() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::PersistIntent);
    tick(&mut e);
    let flight = e.in_flight;
    let state = e.machine.clone();
    e.process(QueueEvent::Completion(Completion {
        dispatch: 999,
        event: Event::Completed(Step::PersistIntent),
        acquired: None,
        not_started: None,
    }));
    assert_eq!(e.machine, state);
    assert_eq!(e.in_flight, flight);
    let id = flight.unwrap().0;
    e.queue.clear();
    e.complete(Completion {
        dispatch: id,
        event: Event::Completed(Step::StartChild),
        acquired: None,
        not_started: None,
    });
    assert_ne!(e.mode, Mode::Stuck);
    assert!(e.machine.failure().is_some());
}
#[test]
fn rejected_fallback_enters_stuck_and_observes_without_effects() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::PersistIntent);
    tick(&mut e);
    e.reject_fallback = true;
    e.queue.clear();
    let id = e.in_flight.unwrap().0;
    e.complete(Completion {
        dispatch: id,
        event: Event::Completed(Step::StartChild),
        acquired: None,
        not_started: None,
    });
    assert_stuck_observes(&mut e);
}
#[test]
fn joined_restart_closes_previous_group_before_new_helper_and_recreates() {
    let e = joined();
    let old_generation = e.machine.durable().previous_generation.unwrap();
    let old_child = e.child.clone().unwrap();
    let mut p = e.into_platform();
    p.abandon_process_group = true;
    p.restart();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    let at = e.platform.now();
    for _ in 0..40 {
        if e.start_fence == StartFence::Closed {
            break;
        }
        tick(&mut e);
    }
    assert_eq!(e.start_fence, StartFence::Closed);
    assert!(e.platform.now() - at <= 2);
    let kill = e
        .platform
        .calls
        .iter()
        .position(|c| matches!(c, Call::Kill(pid, _) if *pid == old_child.pid))
        .unwrap();
    let commit = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Write(Copy::A))
        .unwrap();
    assert!(kill < commit);
    drive(&mut e, 800);
    assert_eq!(e.mode, Mode::Normal);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(_)),
        "{:?} {:?}",
        e.status(),
        e.machine.plan()
    );
    assert!(e.machine.durable().previous_generation.unwrap() > old_generation);
}
#[test]
fn stop_child_signals_pid_before_reaping_and_never_our_group() {
    let mut e = joined();
    let child = e.child.clone().unwrap();
    e.apply(Event::ChildDied);
    before_pending(&mut e, Step::StopChild);
    let start = e.platform.calls.len();
    tick(&mut e);
    let calls = &e.platform.calls[start..];
    let kill = calls
        .iter()
        .position(|c| *c == Call::KillProcess(child.pid, child.start_time))
        .unwrap();
    let reap = calls.iter().position(|c| *c == Call::ReapChildren).unwrap();
    assert!(kill < reap);
    assert!(!calls.iter().any(|c| matches!(c, Call::Kill(_, _))));
}
#[test]
fn uncertain_spawn_is_swept_and_never_overlaps_retry() {
    let mut e = fresh();
    e.platform
        .inject(Call::Spawn, 1, Fault::SpawnHang { child: true });
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    elapse(&mut e, 25);
    assert_eq!(e.mode, Mode::Normal);
    assert_eq!(e.platform.violations, [] as [&str; 0]);
    assert!(e.platform.spawned_children().len() >= 2);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(_)),
        "{:?} {:?}",
        e.status(),
        e.machine.plan()
    );
}
#[test]
fn open_mutation_fence_blocks_same_family_and_frees_no_entries() {
    let mut e = fresh();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    elapse(&mut e, 3);
    let before = e
        .platform
        .calls
        .iter()
        .filter(|c| **c == Call::LoadAnchor)
        .count();
    let accounting = e.status().accounting;
    elapse(&mut e, 10);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::LoadAnchor)
            .count(),
        before
    );
    assert_eq!(e.status().accounting, accounting);
    assert!(matches!(e.status().mutation_fence, Fence::Open(ref children) if !children.is_empty()));
    e.platform.release_unreaped();
    elapse(&mut e, 25);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(_)),
        "{:?} {:?}",
        e.status(),
        e.machine.plan()
    );
}
fn assert_stuck_observes(e: &mut Engine<FakePlatform>) {
    assert_eq!(e.mode, Mode::Stuck);
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::Observation(if e.startup_invariant_failed {
            "containment may be loaded; not maintained"
        } else {
            "internal"
        }))
    );
    let start = e.platform.calls.len();
    elapse(e, 6);
    if e.start_fence == StartFence::Closed {
        assert!(e.platform.calls[start..].contains(&Call::Cheap));
    } else {
        assert!(e.platform.calls[start..].contains(&Call::Processes));
        assert!(!e.platform.calls[start..].contains(&Call::Cheap));
    }
    assert!(!e.platform.calls[start..].iter().any(|c| matches!(
        c,
        Call::Spawn | Call::Acquire | Call::LoadAnchor | Call::Flush
    )));
}
#[test]
fn leave_restores_connectivity_from_joined() {
    let mut e = joined();
    e.submit(Request {
        id: 2,
        kind: RequestKind::Leave,
    })
    .unwrap();
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left");
    assert!(!e.machine.durable().join_intended);
    assert!(!e.machine.durable().leaving);
    assert!(e.platform.anchor.is_none());
    assert!(!e.platform.settings.contains_key(&ConfigKey::Dns));
    assert!(!e.platform.settings.contains_key(&ConfigKey::SplitRoutes));
    assert!(!e.platform.settings.contains_key(&ConfigKey::EndpointRoute));
    assert!(e.platform.children.is_empty());
    assert!(e.request_completed(2));
}

fn accounted(token: bool, unknown: bool) -> Engine<FakePlatform> {
    let p = FakePlatform::new().unwrap();
    let mut snapshot = Snapshot::initial(Some(501), None);
    let key = if token {
        snapshot.machine.pf_reference = Some(901);
        ReferenceEntry::Token(901)
    } else {
        snapshot.machine.uncertain_acquires = vec![1].try_into().unwrap();
        snapshot.machine.reference_sequence = 1;
        ReferenceEntry::Acquire(1)
    };
    snapshot.references[0] = Some(RefEvidence {
        key,
        boot: p.boot.clone(),
        release_unknown: unknown,
        fingerprint: token.then_some(RefFingerprint {
            pid: 777,
            timestamp: 12,
        }),
    });
    let mut p = fixture(&snapshot);
    if token {
        p.tokens.insert(
            901,
            RefLine {
                token: 901,
                pid: 777,
                timestamp: 12,
            },
        );
        p.enabled = true;
    }
    Engine::start(p).unwrap()
}
#[test]
fn acquire_table_ok_not_started_failure_and_unknown_are_accounted() {
    for fault in [
        None,
        Some(Fault::NotStarted),
        Some(Fault::ToolFail { effect: false }),
        Some(Fault::ToolFail { effect: true }),
        Some(Fault::ToolHang {
            reaped: true,
            effect: true,
        }),
        Some(Fault::ToolHang {
            reaped: false,
            effect: false,
        }),
    ] {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::AcquireReference);
        if let Some(fault) = fault {
            e.platform.inject(Call::Acquire, 1, fault);
        }
        let sequence = match e.machine.durable().reference_intent.unwrap() {
            ReferenceIntent::Acquire(s) => s,
            ReferenceIntent::Release => panic!("wrong intent"),
        };
        tick(&mut e);
        // The reservation exists in both copies even before its completion.
        let reserved = read_snapshot(&mut e.platform, Copy::B);
        assert!(
            reserved
                .references
                .iter()
                .flatten()
                .any(|r| r.key == ReferenceEntry::Acquire(sequence))
        );
        tick(&mut e);
        match fault {
            None => {
                assert_eq!(e.status().accounting.held, 1);
                let evidence = e
                    .snapshot
                    .references
                    .iter()
                    .flatten()
                    .find(|e| matches!(e.key, ReferenceEntry::Token(_)))
                    .unwrap();
                assert_eq!(
                    evidence.fingerprint.as_ref().unwrap().pid,
                    e.platform.tokens.values().next().unwrap().pid
                );
                assert_eq!(
                    evidence.fingerprint.as_ref().unwrap().timestamp,
                    e.platform.tokens.values().next().unwrap().timestamp
                );
            }
            Some(Fault::NotStarted) => assert!(
                !e.snapshot
                    .references
                    .iter()
                    .flatten()
                    .any(|r| r.key == ReferenceEntry::Acquire(sequence))
            ),
            Some(_) => assert!(
                e.snapshot
                    .references
                    .iter()
                    .flatten()
                    .any(|r| r.key == ReferenceEntry::Acquire(sequence))
            ),
        }
        oracle(&mut e);
    }
}
#[test]
fn acquisition_fingerprint_never_comes_from_incomplete_enumeration() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    e.platform.inject(Call::References, 1, Fault::Incomplete);
    tick(&mut e);
    tick(&mut e);
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .any(|e| matches!(e.key, ReferenceEntry::Acquire(_)))
    );
    assert_eq!(
        e.status().accounting,
        Accounting {
            held: 0,
            uncertain: 1,
            release_unknown: 0
        }
    );
    assert_eq!(e.platform.tokens.len(), 1); // The possible effect is still accounted.
}

#[test]
fn release_table_premarks_and_only_confirmed_results_settle() {
    for fault in [
        None,
        Some(Fault::NotStarted),
        Some(Fault::ToolFail { effect: true }),
        Some(Fault::ToolFail { effect: false }),
        Some(Fault::ToolHang {
            reaped: true,
            effect: true,
        }),
        Some(Fault::ToolHang {
            reaped: false,
            effect: false,
        }),
    ] {
        let mut e = accounted(true, false);
        if let Some(fault) = fault {
            e.platform.inject(Call::Release(901), 1, fault);
        }
        let start = e.platform.calls.len();
        let _ = e.reconcile_references();
        let calls = &e.platform.calls[start..];
        let release = calls.iter().position(|c| *c == Call::Release(901)).unwrap();
        assert!(calls[..release].contains(&Call::Write(Copy::B)));
        if fault.is_none() {
            assert_eq!(e.status().accounting.held, 0);
        } else {
            assert_eq!(
                e.status().accounting,
                Accounting {
                    held: 1,
                    uncertain: 0,
                    release_unknown: 1
                }
            );
        }
    }
}
#[test]
fn unrecognized_release_keeps_debt_until_independent_read() {
    let mut e = accounted(true, false);
    e.platform
        .inject(Call::Release(901), 1, Fault::TokenGoneBeforeRelease);
    let _ = e.reconcile_references();
    assert!(e.platform.calls.contains(&Call::Release(901)));
    assert_eq!(e.status().accounting.held, 1);
    assert_eq!(e.status().accounting.release_unknown, 1);
}

#[test]
fn release_requires_fresh_complete_post_read_and_never_retries_reissued_number() {
    for scenario in 0..6 {
        let mut e = accounted(true, false);
        let owned = e.platform.tokens[&901].clone();
        let mut foreign = owned.clone();
        foreign.pid += 1;
        match scenario {
            0 => e.platform.inject(Call::References, 2, Fault::Incomplete),
            1 => e
                .platform
                .references_script
                .extend([vec![owned.clone()], vec![owned.clone()]]),
            2 => e
                .platform
                .references_script
                .extend([vec![owned.clone()], vec![foreign.clone()]]),
            3 => {
                e.platform
                    .references_script
                    .extend([vec![owned.clone(), foreign.clone()], vec![]]);
                // Different number, so the pre-read inventory remains well formed.
                e.platform.references_script[0][1].token = 902;
            }
            5 => {
                let mut acquired_after_release = foreign.clone();
                acquired_after_release.token = 902;
                e.platform
                    .references_script
                    .extend([vec![owned.clone()], vec![acquired_after_release]]);
            }
            _ => (),
        }
        e.platform.calls.clear();
        let outcome = e.reconcile_references();
        let release = e
            .platform
            .calls
            .iter()
            .position(|c| *c == Call::Release(901))
            .unwrap();
        assert!(
            e.platform.calls[release + 1..].contains(&Call::References),
            "assertion: release requires a read begun after the call"
        );
        if scenario <= 1 {
            assert_eq!(
                e.status().accounting.held,
                1,
                "assertion: missing/contradictory post-read"
            );
            assert_eq!(e.status().accounting.release_unknown, 1);
            assert!(!e.platform.safety_events.is_empty());
            assert!(scenario != 0 || outcome.is_err());
        } else {
            assert_eq!(e.status().accounting.held, 0);
        }
        if scenario == 2 {
            assert_eq!(e.platform.tokens.get(&901), Some(&foreign));
        }
        if scenario == 3 {
            assert!(e.platform.safety_events.iter().any(|event| matches!(event,
                platform::SafetyEvent::ForeignReferenceVanished { reference } if reference.token == 902)));
        }
        let _ = e.reconcile_references();
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Release(901))
                .count(),
            1,
            "assertion: never reuse authorization for a reissued number"
        );
    }
}

#[test]
fn sole_ack_uses_fingerprints_and_later_enabled_status_is_diagnostic() {
    use crate::decode::pftext::{self, Build, ToolEvidence};
    for scenario in 0..7 {
        let mut e = accounted(true, false);
        let row = include_bytes!("../../tests/fixtures/pf-sole-release-24H232.stderr");
        e.platform.release_reply = Some(pftext::release_outcome(
            Ok((
                &Build::fixture("24H232"),
                ToolEvidence {
                    pid: 42,
                    reap: platform::runtime::Reap::Status(0),
                    stdout: b"",
                    stderr: row,
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    io_failed: false,
                    stdin_unsent: 0,
                },
            )),
            901,
        ));
        let owned = e.platform.tokens[&901].clone();
        match scenario {
            0 => {
                e.snapshot
                    .references
                    .iter_mut()
                    .flatten()
                    .for_each(|r| r.fingerprint = None);
            }
            1 => {
                e.platform.tokens.get_mut(&901).unwrap().pid += 1;
            }
            2 => {
                e.platform.tokens.get_mut(&901).unwrap().timestamp += 1;
            }
            3 => e.platform.inject(Call::References, 2, Fault::Incomplete),
            4 => {
                e.platform
                    .references_script
                    .extend([vec![owned.clone()], vec![owned]]);
            }
            5 => {
                e.platform
                    .pf_info_script
                    .extend([platform::PfInfo::Enabled, platform::PfInfo::Enabled]);
                let foreign = RefLine {
                    token: 902,
                    pid: 778,
                    timestamp: 13,
                };
                e.platform
                    .references_script
                    .extend([vec![owned], vec![foreign]]);
            }
            _ => (),
        }
        e.platform.calls.clear();
        let _ = e.reconcile_references();
        if scenario < 5 {
            assert_eq!(e.status().accounting.held, 1);
        } else {
            assert_eq!(e.status().accounting.held, 0);
            assert!(e.platform.safety_events.iter().any(|event| matches!(event,
                platform::SafetyEvent::ReferenceReleaseStatus { token: 901, status } if scenario != 5 || *status == platform::PfInfo::Enabled)));
        }
        if scenario <= 2 {
            assert!(!e.platform.calls.contains(&Call::Release(901)));
        }
    }
}

#[test]
fn diagnostic_runs_after_all_releases_and_skips_an_open_pfctl_fence() {
    let initial = accounted(true, false);
    let mut snapshot = initial.snapshot.clone();
    snapshot.machine.older_references.try_push(902).unwrap();
    let mut second = snapshot.references[0].clone().unwrap();
    second.key = ReferenceEntry::Token(902);
    snapshot.references[1] = Some(second);
    let mut p = fixture(&snapshot);
    for token in [901, 902] {
        p.tokens.insert(
            token,
            RefLine {
                token,
                pid: 777,
                timestamp: 12,
            },
        );
    }
    p.enabled = true;
    let mut e = Engine::start(p).unwrap();
    e.platform.calls.clear();
    // A stalled diagnostic opens the fence. It must see both settlements done,
    // and no subsequent diagnostic may consume another containment slot.
    e.platform.inject(
        Call::PfInfo,
        2,
        Fault::ToolHang {
            reaped: false,
            effect: false,
        },
    );
    e.platform
        .inject_fence_after(Call::PfInfo, 2, Fault::Incomplete);
    let _ = e.reconcile_references();
    assert_eq!(e.status().accounting.held, 0);
    let calls = &e.platform.calls;
    let infos: Vec<_> = calls
        .iter()
        .enumerate()
        .filter_map(|(i, c)| (*c == Call::PfInfo).then_some(i))
        .collect();
    assert_eq!(
        infos.len(),
        2,
        "assertion: only initial status and one diagnostic"
    );
    for token in [901, 902] {
        let release = calls
            .iter()
            .position(|c| *c == Call::Release(token))
            .unwrap();
        assert!(
            release < infos[1],
            "assertion: diagnostics must follow all releases"
        );
    }
}

#[test]
fn incomplete_enumeration_never_frees_or_releases() {
    let mut e = accounted(true, false);
    e.platform.tokens.clear();
    e.platform.inject(Call::References, 1, Fault::Incomplete);
    assert!(e.reconcile_references().is_err());
    assert_eq!(e.status().accounting.held, 1);
    assert!(!e.platform.calls.contains(&Call::Release(901)));
}
#[test]
fn token_absence_frees_even_release_unknown_but_never_uncertain_acquire() {
    for unknown in [false, true] {
        let mut e = accounted(true, unknown);
        e.platform.tokens.clear();
        let event = e.reconcile_references().unwrap();
        assert_eq!(e.status().accounting.held, 0);
        assert!(
            matches!(event, Event::ReferenceReconciled { current: None, predecessor: None, context } if context == e.machine.context())
        );
    }
    let mut e = accounted(false, false);
    assert!(e.reconcile_references().is_err());
    assert_eq!(e.status().accounting.uncertain, 1);
}
#[test]
fn unknown_boot_on_either_side_neither_frees_nor_releases() {
    for entry_unknown in [false, true] {
        let mut e = accounted(true, false);
        if entry_unknown {
            e.snapshot.references[0].as_mut().unwrap().boot = None;
        } else {
            e.platform.mutate(Mutation::BootIdUnavailable);
        }
        let _ = e.reconcile_references();
        assert_eq!(e.status().accounting.held, 1);
        assert!(!e.platform.calls.contains(&Call::Release(901)));
    }
}
#[test]
fn release_unknown_and_fingerprint_mismatch_prevent_numeric_release() {
    for unknown in [false, true] {
        let mut e = accounted(true, unknown);
        if !unknown {
            e.platform.tokens.get_mut(&901).unwrap().timestamp += 1;
        }
        let _ = e.reconcile_references();
        assert_eq!(e.status().accounting.held, 1);
        assert!(!e.platform.calls.contains(&Call::Release(901)));
    }
}
#[test]
fn release_premark_commit_failure_never_exposes_ioctl() {
    for copy in [Copy::A, Copy::B] {
        let mut e = accounted(true, false);
        e.platform.inject(Call::Write(copy), 1, Fault::WriteFail);
        assert!(e.reconcile_references().is_err());
        assert_eq!(e.mode, Mode::PersistBlocked);
        assert!(!e.platform.calls.contains(&Call::Release(901)));
        assert_eq!(e.status().accounting.held, 1);
    }
}
#[test]
fn disabled_rule_requires_x_qualification_complete_info_and_closed_fences() {
    for qualified in [false, true] {
        for open in [false, true] {
            for incomplete in [false, true] {
                let mut e = accounted(false, false);
                e.platform.x_qualified = qualified;
                if open {
                    e.platform.unreaped.push(crate::platform::Unreaped {
                        tool: Tool::Pfctl,
                        pid: 678,
                    });
                }
                if incomplete {
                    e.platform.inject(Call::PfInfo, 1, Fault::Incomplete);
                }
                let _ = e.reconcile_references();
                assert_eq!(
                    e.status().accounting.uncertain == 0,
                    qualified && !open && !incomplete,
                    "{qualified} {open} {incomplete}"
                );
            }
        }
    }
}
#[test]
fn status_expires_and_cheap_checks_never_refresh_full_proof() {
    let mut e = joined();
    let old = match e.status().enforcement {
        Verdict::Protected(p) => p,
        v => panic!("{v:?}"),
    };
    // Keep cadence events out while advancing the platform's sleep-counting clock.
    for _ in 0..320 {
        e.platform.tick();
    }
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    let d = e.deadline();
    assert!(e.platform.cheap_check(e.child.as_ref(), d).is_ok());
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(old.expires_at() < e.platform.now());
}
#[test]
fn joined_monitor_cadence_and_maintenance_write_nothing() {
    let mut e = joined();
    e.platform.calls.clear();
    let snapshot = e.snapshot.clone();
    elapse(&mut e, 31);
    let calls = &e.platform.calls;
    assert!(calls.iter().filter(|c| **c == Call::Cheap).count() >= 30);
    assert!(calls.iter().filter(|c| **c == Call::Collect).count() >= 6);
    assert!(calls.iter().filter(|c| **c == Call::Flush).count() >= 3);
    assert_eq!(writes(&e.platform), 0);
    assert_eq!(e.snapshot, snapshot);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}
#[test]
fn queue_overflow_masks_protection_and_preserves_caller_input() {
    let mut e = joined();
    e.set_queue_capacity(1).unwrap();
    e.enqueue(QueueEvent::Request(Request {
        id: 2,
        kind: RequestKind::Leave,
    }))
    .unwrap();
    assert!(e.enqueue(QueueEvent::Timer).is_err());
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    tick(&mut e);
    assert_eq!(e.mode, Mode::Normal);
}
#[test]
fn deferred_join_is_replayed_after_restart_before_any_effect() {
    let mut snapshot = Snapshot::initial(Some(501), None);
    snapshot
        .requests
        .try_push(RequestRecord {
            id: 44,
            kind: snapshot::RequestKind::Join,
        })
        .unwrap();
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    assert_eq!(e.machine.pending(), Some(Step::PersistIntent));
    assert!(!e.platform.calls.contains(&Call::Acquire));
    drive(&mut e, 400);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}

#[derive(Clone, Copy)]
enum External {
    PfDisable,
    AnchorFlush,
    HookRemoved,
    QuickPass,
    Skip,
    ChildDied,
    UtunReused,
    AnchorChanged,
}
fn external_change(change: External) {
    let mut e = joined();
    let original_spawns = e.platform.spawned_children().len();
    let child = e.child.clone().unwrap();
    match change {
        External::PfDisable => e.platform.mutate(Mutation::PfDisable),
        External::AnchorFlush => e.platform.anchor = None,
        External::AnchorChanged => e.platform.anchor = Some("block all\n".into()),
        External::HookRemoved => e.platform.main_rules.clear(),
        External::QuickPass => {
            e.platform.main_rules = "pass quick all\nanchor \"com.apple/*\" all\n".into();
        }
        External::Skip => {
            e.platform.skipped.insert("en0".parse().unwrap());
        }
        External::ChildDied => {
            e.platform.procs.get_mut(&child.pid).unwrap().state = ProcState::Zombie;
        }
        External::UtunReused => {
            e.platform
                .procs
                .get_mut(&child.pid)
                .unwrap()
                .start
                .microseconds += 1;
        }
    }
    let since = e.platform.now();
    e.enqueue(QueueEvent::Monitor(Event::InvalidateObservations { since }))
        .unwrap();
    drive(&mut e, 900);
    match change {
        External::HookRemoved => assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::HookMissing)
        ),
        External::QuickPass => assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::QuickPass)
        ),
        External::Skip => assert!(matches!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Skip(_))
        )),
        _ => assert!(
            matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined),
            "{:?} {:?}",
            e.status(),
            e.machine.plan()
        ),
    }
    if matches!(
        change,
        External::HookRemoved | External::QuickPass | External::Skip
    ) {
        assert_eq!(e.platform.spawned_children().len(), original_spawns);
    }
}
#[test]
fn external_pf_disable_reenables_and_rejoins() {
    external_change(External::PfDisable);
}
#[test]
fn external_anchor_flush_restores_and_rejoins() {
    external_change(External::AnchorFlush);
}
#[test]
fn external_hook_loss_refuses_repair() {
    external_change(External::HookRemoved);
}
#[test]
fn external_quick_pass_refuses_repair() {
    external_change(External::QuickPass);
}
#[test]
fn external_skip_flag_refuses_repair() {
    external_change(External::Skip);
}
#[test]
fn external_child_death_recreates() {
    external_change(External::ChildDied);
}
#[test]
fn external_route_loss_stays_closed_until_transport_returns() {
    let mut e = joined();
    let host_route = e
        .platform
        .settings
        .remove(&ConfigKey::EndpointRoute)
        .unwrap();
    elapse(&mut e, 15);
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    assert_eq!(e.machine.installed_form(), Some(Form::PreTunnel));
    e.platform
        .settings
        .insert(ConfigKey::EndpointRoute, host_route);
    elapse(&mut e, 30);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}
#[test]
fn external_utun_reuse_recreates() {
    external_change(External::UtunReused);
}
#[test]
fn cheap_monitor_detects_changed_anchor_hash() {
    let mut e = joined();
    e.platform.anchor = Some("block all\n".into());
    // No injected invalidation: only the one-second cheap check can notice this.
    for _ in 0..20 {
        e.platform.tick();
    }
    e.run_until_quiescent(1);
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    drive(&mut e, 900);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}
#[test]
fn external_changed_anchor_is_repaired() {
    external_change(External::AnchorChanged);
}

#[test]
fn missing_recovery_destinations_never_mean_fresh_install() {
    let mut e = Engine::start(FakePlatform::new().unwrap()).unwrap();
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert!(e.snapshot.machine.hold);
    assert_eq!(e.status().accounting.uncertain, 2);
    elapse(&mut e, 10);
    assert!(e.status().blocking_verified);
    assert!(e.platform.enabled);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(!e.platform.calls.contains(&Call::Spawn));
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|call| matches!(call, Call::Create(_)))
    );
}
#[test]
fn helper_commit_failure_preserves_native_fence_and_retries_durability() {
    let mut p = fixture(&Snapshot::initial(Some(501), None));
    p.inject(Call::Write(Copy::B), 1, Fault::WriteHang);
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.status().start_fence, StartFence::Closed);
    assert!(!e.helper_committed);
    e.platform.complete_late(Copy::B, true);
    // A late sync alone is not authority; the serialized pair retry is.
    elapse(&mut e, 6);
    assert_eq!(e.mode, Mode::Normal);
    assert!(!e.platform.calls.contains(&Call::Spawn));
}
#[test]
fn crash_after_acquire_reservation_keeps_the_sequence_uncertain() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    let sequence = match e.machine.durable().reference_intent.unwrap() {
        ReferenceIntent::Acquire(seq) => seq,
        ReferenceIntent::Release => panic!("wrong intent"),
    };
    e.platform.restart();
    let mut e = Engine::start(e.into_platform()).unwrap();
    assert!(e.machine.durable().uncertain_acquires.contains(&sequence));
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .any(|e| e.key == ReferenceEntry::Acquire(sequence))
    );
    // Debt never prevents a closing prefix or ongoing full observations.
    elapse(&mut e, 30);
    assert!(e.machine.durable().uncertain_acquires.contains(&sequence));
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Collect)
            .count()
            >= 5
    );
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(_)),
        "{:?} {:?}",
        e.status(),
        e.machine.plan()
    );
}
#[test]
fn crash_after_generation_reservation_restarts_with_a_new_generation() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::StartChild);
    let generation = e.machine.durable().previous_generation.unwrap();
    assert!(!e.platform.calls.contains(&Call::Spawn));
    e.platform.restart();
    let mut e = Engine::start(e.into_platform()).unwrap();
    drive(&mut e, 900);
    assert!(e.machine.durable().previous_generation.unwrap() > generation);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}
#[test]
fn release_premark_survives_restart_and_forbids_a_second_numeric_release() {
    let mut e = accounted(true, false);
    e.platform.inject(Call::Release(901), 1, Fault::NotStarted);
    let _ = e.reconcile_references();
    e.platform.restart();
    let mut e = Engine::start(e.into_platform()).unwrap();
    let start = e.platform.calls.len();
    let _ = e.reconcile_references();
    assert_eq!(e.status().accounting.release_unknown, 1);
    assert!(!e.platform.calls[start..].contains(&Call::Release(901)));
    e.platform.mutate(Mutation::ForeignRelease(901));
    let _ = e.reconcile_references();
    assert_eq!(e.status().accounting.held, 0);
}
#[test]
fn collector_input_cannot_settle_accounting_or_skip_a_pending_step() {
    let mut e = accounted(true, true);
    let before = e.machine.clone();
    e.enqueue(QueueEvent::Monitor(Event::ReferenceSettled {
        entry: ReferenceEntry::Token(901),
        how: ReferenceSettlement::Absent,
    }))
    .unwrap();
    tick(&mut e);
    assert_eq!(e.machine, before);
    assert_eq!(e.status().accounting.held, 1);
    assert_eq!(e.rejected, 1);
}
#[test]
fn refused_sweep_names_survivor_and_never_starts_another_child() {
    let mut e = joined();
    let child = e.child.clone().unwrap();
    e.platform.unkillable.insert(child.pid);
    e.apply(Event::ChildDied);
    before_pending(&mut e, Step::StopChild);
    let start = e.platform.calls.len();
    elapse(&mut e, 10);
    assert!(
        matches!(e.status().sweep, Some(Sweep::Survivors(ref p)) if p.iter().any(|p| p.pid == child.pid))
    );
    assert!(!e.platform.calls[start..].contains(&Call::Spawn));
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
}
#[test]
fn post_settlement_reconcile_context_is_recaptured_and_proof_is_refreshed() {
    let e = joined();
    let mut p = e.into_platform();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    elapse(&mut e, 15);
    assert_eq!(e.rejected, 0);
    assert_eq!(e.status().accounting.held, 1);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref p) if p.context() == e.machine.context())
    );
}

#[test]
fn incomplete_startup_enumeration_retains_the_named_pid_and_can_retry() {
    let mut p = fixture(&Snapshot::initial(Some(501), None));
    let mut hidden = p.procs[&p.helper.pid].clone();
    hidden.pid = 333;
    hidden.pgid = 222;
    hidden.ppid = 1;
    hidden.path = None;
    hidden.exe = None;
    hidden.start.seconds = 90;
    p.procs.insert(333, hidden);
    p.mutate(Mutation::CopyRot(Copy::A));
    p.mutate(Mutation::CopyRot(Copy::B));
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.mode, Mode::Starting);
    assert!(
        matches!(e.status().start_fence, StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(333))
    );
    assert_eq!(writes(&e.platform), 0); // Ownership is still unconfirmed.
    e.platform.procs.remove(&333);
    tick(&mut e);
    assert_eq!(e.mode, Mode::Normal);
    assert!(e.helper_committed);
}

#[test]
fn reaping_another_tool_family_never_depends_on_reaching_its_next_mutation() {
    let mut e = joined();
    let value = e.platform.settings[&ConfigKey::EndpointRoute].clone();
    e.platform.inject(
        Call::Configure(ConfigKey::EndpointRoute),
        1,
        Fault::ToolLate { ticks: None },
    );
    let d = e.deadline();
    assert!(
        e.platform
            .configure(ConfigKey::EndpointRoute, &value, d)
            .is_err()
    );
    assert!(matches!(e.platform.fence(), Fence::Open(_)));
    e.platform.release_unreaped();
    // There is no pending route mutation. The ordinary loop must still reap it.
    tick(&mut e);
    assert_eq!(e.platform.fence(), Fence::Closed);
}

#[test]
fn a_lone_predecessor_is_promoted_and_never_released_while_joining() {
    let e = joined();
    let mut p = e.into_platform();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    before_pending(&mut e, Step::ReconcileReference);
    let current = e.machine.durable().pf_reference.unwrap();
    let predecessor = e.machine.durable().older_references[0];
    e.platform.mutate(Mutation::ForeignRelease(current));
    e.apply(Event::ReferenceSettled {
        entry: ReferenceEntry::Token(current),
        how: ReferenceSettlement::Absent,
    });
    let event = e.reconcile_references().unwrap();
    assert!(
        matches!(event, Event::ReferenceReconciled { current: Some(token), predecessor: None, .. } if token == predecessor)
    );
    e.apply(event);
    assert_eq!(e.machine.durable().pf_reference, Some(predecessor));
    assert!(!e.platform.calls.contains(&Call::Release(predecessor)));
    assert_eq!(e.status().accounting.held, 1);
}

#[test]
fn fresh_foreign_host_reaches_normal_and_can_join() {
    let e = joined();
    for pid in [1, 10, 11, 12, 13, 14] {
        assert!(e.platform.procs.contains_key(&pid));
    }
    assert_eq!(e.platform.signals, []);
}

#[test]
fn starting_overflow_preserves_joined_intent_with_and_without_entries() {
    for entries in [false, true] {
        let mut snapshot = Snapshot::initial(Some(501), None);
        snapshot.machine.join_intended = true;
        if entries {
            snapshot.machine.pf_reference = Some(901);
            snapshot.references[0] = Some(RefEvidence {
                key: ReferenceEntry::Token(901),
                boot: FakePlatform::new().unwrap().boot,
                release_unknown: false,
                fingerprint: None,
            });
        }
        let mut p = fixture(&snapshot);
        let mut blocker = p.procs[&p.helper.pid].clone();
        blocker.pid = 333;
        blocker.pgid = 333;
        blocker.start.seconds = 90;
        blocker.path = Some(CHILD_PATH.into());
        p.procs.insert(333, blocker);
        p.unkillable.insert(333);
        let mut e = Engine::start(p).unwrap();
        let before = e.snapshot.clone();
        assert_eq!(e.mode, Mode::Starting);
        for _ in 0..100 {
            let _ = e.enqueue(QueueEvent::Timer);
            let _ = e.submit(Request {
                id: 1,
                kind: RequestKind::Join,
            });
        }
        e.apply(Event::Join);
        e.rejected_completion();
        e.run_until_quiescent(1);
        assert_eq!(writes(&e.platform), 0);
        assert_eq!(e.snapshot, before);
        assert!(e.overflowed);
        assert_eq!(e.mode, Mode::Starting);
        e.platform.procs.remove(&333);
        e.run_until_quiescent(1);
        assert_eq!(e.mode, Mode::Normal);
        assert!(e.machine.durable().join_intended);
        drive(&mut e, 500);
        assert_eq!(e.mode, Mode::Normal);
        assert!(matches!(e.status().enforcement,
            Verdict::Protected(ref proof) if proof.form() == Form::Joined));
    }
}

#[test]
fn spawn_attributes_are_chosen_by_engine() {
    let e = joined();
    assert_eq!(
        e.platform.spawn_attributes,
        [platform::SpawnAttributes {
            default_signals: true,
            empty_signal_mask: true,
            cloexec_default: true,
            synchronous: true,
        }]
    );
}

#[test]
fn legacy_release_is_explicitly_stuck() {
    let mut e = joined();
    let before = writes(&e.platform);
    e.dispatch(Step::ReleaseReference);
    assert_eq!(e.mode, Mode::Stuck);
    assert_eq!(writes(&e.platform), before + 2); // internal_error commit
}

#[test]
fn route_loss_is_observed_with_pre_tunnel_anchor() {
    let mut e = joined();
    e.platform
        .inject_persistent(Call::CheckTools, Fault::ReadFail);
    e.apply(Event::Repair(verify::Action::Rejoin));
    elapse(&mut e, 8);
    assert_eq!(e.machine.installed_form(), Some(Form::PreTunnel));
    e.platform.settings.remove(&ConfigKey::EndpointRoute);
    e.platform.settings.remove(&ConfigKey::SplitRoutes);
    e.platform.default_route_present = false;
    let start = e.platform.calls.len();
    elapse(&mut e, 6);
    assert!(e.platform.calls[start..].contains(&Call::Collect));
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(e.machine.durable().enforcement_error.is_some());
}

// Join/restart portions of the frozen executor ledger, using only Platform.
#[test]
fn repeated_same_boot_restart_keeps_room_to_enable_pf() {
    let mut e = joined();
    for _ in 0..6 {
        let previous = e.machine.durable().previous_generation.unwrap();
        let mut p = e.into_platform();
        p.restart();
        e = Engine::start(p).unwrap();
        elapse(&mut e, 20);
        assert_eq!(e.mode, Mode::Normal);
        assert!(
            matches!(e.status().enforcement, Verdict::Protected(_)),
            "{:?} {:?}",
            e.status(),
            e.machine.plan()
        );
        assert!(e.machine.durable().previous_generation.unwrap().value() > previous.value());
        assert!(e.platform.tokens.len() <= 2);
        assert!(e.snapshot.references.iter().flatten().count() <= 2);
    }
    e.platform.mutate(Mutation::PfDisable);
    elapse(&mut e, 20);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(e.platform.tokens.len() <= 2);
}

#[test]
fn predecessor_release_faults_reconcile_before_retry_and_keep_current_token() {
    for fault in [
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
    ] {
        let e = joined();
        let mut snapshot = e.snapshot.clone();
        let current = snapshot.machine.pf_reference.unwrap();
        let predecessor = 999;
        snapshot.machine.older_references = vec![predecessor].try_into().unwrap();
        snapshot.references[1] = Some(RefEvidence {
            key: ReferenceEntry::Token(predecessor),
            boot: e.platform.boot.clone(),
            release_unknown: false,
            fingerprint: Some(RefFingerprint {
                pid: 777,
                timestamp: 12,
            }),
        });
        let mut p = e.into_platform();
        let bytes = snapshot::encode(100, &snapshot).unwrap();
        for slot in &mut p.copies {
            slot.durable = Some(bytes.clone());
        }
        p.tokens.insert(
            predecessor,
            RefLine {
                token: predecessor,
                pid: 777,
                timestamp: 12,
            },
        );
        p.restart();
        p.inject(Call::Release(predecessor), 1, fault);
        let mut e = Engine::start(p).unwrap();
        let start = e.platform.calls.len();
        let _ = e.reconcile_references();
        assert!(e.platform.calls[start..].contains(&Call::Release(predecessor)));
        assert!(e.platform.tokens.contains_key(&current));
        assert!(!e.platform.calls[start..].contains(&Call::Release(current)));
        // A possibly completed release must be reconciled by complete absence,
        // never reissued, even if the first call failed before applying its effect.
        e.platform.release_unreaped();
        let d = e.deadline();
        e.platform.reap(d);
        let before = e.platform.calls.len();
        let _ = e.reconcile_references();
        assert!(!e.platform.calls[before..].contains(&Call::Release(predecessor)));
        assert!(e.platform.tokens.contains_key(&current));
        assert!(!e.platform.calls[before..].contains(&Call::Release(current)));
    }
}

#[test]
fn cheap_monitor_detects_pf_disable_during_capped_backoff() {
    let mut e = joined();
    e.platform
        .inject_persistent(Call::CheckTools, Fault::ReadFail);
    e.apply(Event::Repair(verify::Action::Rejoin));
    let until = loop {
        tick(&mut e);
        if let Some(Step::Backoff { until }) = e.machine.pending()
            && until >= e.platform.now() + 50
        {
            break until;
        }
        assert!(e.platform.now() < 1000, "never reached capped backoff");
    };
    e.platform.mutate(Mutation::PfDisable);
    let start = e.platform.calls.len();
    elapse(&mut e, 2);
    assert!(e.platform.now() < until);
    assert!(e.platform.calls[start..].contains(&Call::Cheap));
    assert!(e.platform.enabled);
    if let Verdict::Protected(proof) = e.status().enforcement {
        assert_eq!(proof.form(), Form::PreTunnel);
    }
    e.platform.clear_faults();
    elapse(&mut e, 70);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}

#[test]
fn full_walk_observes_live_route_and_selected_address_loss() {
    for route in [false, true] {
        let mut e = joined();
        if route {
            e.platform.settings.remove(&ConfigKey::EndpointRoute);
        } else {
            e.platform.install.config.transport.local_address = std::net::Ipv4Addr::UNSPECIFIED;
        }
        e.platform
            .inject_persistent(Call::CheckTools, Fault::ReadFail);
        let start = e.platform.calls.len();
        elapse(&mut e, 6);
        assert!(e.platform.calls[start..].contains(&Call::Collect));
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    }
}

#[test]
fn changed_readback_is_a_failure() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::VerifyPreTunnelLoad);
    e.platform.anchor = Some("block all\n".into());
    let start = e.platform.calls.len();
    tick(&mut e);
    tick(&mut e);
    assert!(e.platform.calls[start..].contains(&Call::ReadAnchor));
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(!e.platform.calls.contains(&Call::Spawn));
    assert!(e.machine.failure().is_some());
}

#[test]
fn unrelated_queue_overflow_does_not_drop_join() {
    let mut e = fresh();
    e.set_queue_capacity(2).unwrap();
    for id in [1, 2] {
        e.submit(Request {
            id,
            kind: RequestKind::Join,
        })
        .unwrap();
    }
    assert!(e.enqueue(QueueEvent::Timer).is_err());
    drive(&mut e, 400);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(e.snapshot.requests.iter().any(|r| r.id == 1));
    assert!(e.snapshot.requests.iter().any(|r| r.id == 2));
}

#[test]
fn stop_child_does_not_signal_historical_reaped_records() {
    let mut e = joined();
    let old = e.child.clone().unwrap();
    e.apply(Event::ChildDied);
    drive(&mut e, 500);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    let current = e.child.clone().unwrap();
    assert_ne!(old.pid, current.pid);
    assert!(
        e.platform
            .spawned_children()
            .iter()
            .any(|c| c.pid == old.pid)
    );
    e.apply(Event::ChildDied);
    before_pending(&mut e, Step::StopChild);
    let start = e.platform.calls.len();
    tick(&mut e);
    assert!(
        e.platform.calls[start..].contains(&Call::KillProcess(current.pid, current.start_time))
    );
    assert!(!e.platform.calls[start..].contains(&Call::KillProcess(old.pid, old.start_time)));
}

#[test]
fn unsupported_monitor_cadence_uses_only_platform_time() {
    for committed in [false, true] {
        let mut e = if committed {
            let mut e = joined();
            e.enter_stuck();
            e
        } else {
            let mut e = fresh();
            e.platform
                .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
            e.helper_committed = false;
            e.start_fence = StartFence::Uncommitted;
            e.enter_stuck();
            e
        };
        let now = e.platform.now();
        e.next_cheap = now + 1;
        e.next_full = now + 5;
        e.next_emergency = now + 1;
        e.platform.calls.clear();
        // Repeated engine polls without a platform tick cannot advance cadence.
        for _ in 0..100 {
            e.run_until_quiescent(1);
        }
        assert!(!e.platform.calls.contains(&Call::Cheap));
        assert!(!e.platform.calls.contains(&Call::Processes));
        assert!(!e.platform.calls.contains(&Call::Collect));
        elapse(&mut e, 1);
        assert!(e.platform.calls.contains(if committed {
            &Call::Cheap
        } else {
            &Call::Processes
        }));
        let start = e.platform.calls.len();
        elapse(&mut e, 4);
        if committed {
            assert!(e.platform.calls[start..].contains(&Call::Collect));
        } else {
            assert!(!e.platform.calls[start..].contains(&Call::Cheap));
            assert!(!e.platform.calls[start..].contains(&Call::PfInfo));
        }
    }
}

#[test]
fn unrepresentable_start_selection_is_observable_stuck() {
    for invalid_snapshot in [false, true] {
        let mut snapshot = Snapshot::initial(Some(501), None);
        let mut p = fixture(&snapshot);
        p.acquire_instance_lock().unwrap();
        let install = Some(p.install.clone());
        if invalid_snapshot {
            snapshot.machine.pf_reference = Some(901); // Missing required evidence.
        }
        let mut e = Engine::start_selected(
            p,
            install,
            StartDecision::Trust {
                source: Copy::A,
                seq: if invalid_snapshot {
                    1
                } else {
                    snapshot::COUNTER_MAX
                },
                snapshot,
                repair: Some(Copy::B),
            },
            [false, false],
        );
        assert_eq!(e.mode, Mode::Stuck);
        assert_eq!(writes(&e.platform), 0);
        for _ in 0..120 {
            e.platform.tick();
            e.run_until_quiescent(1);
        }
        assert_eq!(e.mode, Mode::Stuck);
        assert_eq!(writes(&e.platform), 0);
        assert!(e.platform.calls.contains(&Call::Processes));
        assert!(!e.platform.calls.contains(&Call::Cheap));
        assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Observation("internal"))
        );
    }
}

#[test]
fn recovery_sleeping_and_stopped_orphans_each_withhold_closure() {
    let mut p = fixture(&Snapshot::initial(Some(501), None));
    for (pid, state, path, name) in [
        (333, ProcState::Sleeping, None, None),
        (
            334,
            ProcState::Stopped,
            Some("/opt/scupper/wireguard-go.old"),
            Some("wireguard-go"),
        ),
    ] {
        let mut orphan = p.procs[&p.helper.pid].clone();
        orphan.pid = pid;
        orphan.pgid = pid;
        orphan.start.seconds = 90;
        orphan.state = state;
        orphan.path = path.map(Into::into);
        orphan.name = name.map(Into::into);
        orphan.image = Some(platform::ImageId {
            uuid: [9; 16],
            uniqueid: u64::from(pid),
        });
        orphan.exe = Some(ExeId {
            dev: 77,
            ino: u64::from(pid),
        });
        p.procs.insert(pid, orphan);
    }
    p.mutate(Mutation::CopyRot(Copy::A));
    p.mutate(Mutation::CopyRot(Copy::B));
    let mut e = Engine::start(p).unwrap();
    for pid in [333, 334] {
        assert_eq!(e.mode, Mode::Starting);
        assert!(matches!(e.start_fence,
            StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(pid)));
        assert!(!e.helper_committed);
        assert_eq!(e.snapshot.helper, None);
        assert_eq!(writes(&e.platform), 2); // Recovery pair only.
        assert_eq!(e.platform.signals, []);
        e.platform.procs.remove(&pid);
        tick(&mut e);
    }
    assert_eq!(e.start_fence, StartFence::Closed);
    assert!(e.helper_committed);
    assert_eq!(e.platform.signals, []);
    assert_eq!(e.mode, Mode::Normal);
}

fn leave(e: &mut Engine<FakePlatform>, id: u64) {
    e.submit(Request {
        id,
        kind: RequestKind::Leave,
    })
    .unwrap();
}
fn held(unreadable: bool, missing: bool) -> Engine<FakePlatform> {
    let mut p = if missing {
        FakePlatform::new().unwrap()
    } else {
        let mut snapshot = Snapshot::initial(Some(501), None);
        snapshot.machine.join_intended = true;
        snapshot.machine.hold = true;
        snapshot.endpoint = Some(execute::endpoint(
            &FakePlatform::new().unwrap().install.config.inputs,
        ));
        fixture(&snapshot)
    };
    if missing {
        p.mutate(Mutation::ForeignEnable);
    }
    if unreadable {
        p.inject(Call::Install, 1, Fault::ReadFail);
    }
    Engine::start(p).unwrap()
}

#[test]
fn leave_from_hold_missing_storage_persist_blocked_and_backoff() {
    for scenario in 0..6 {
        let mut e = match scenario {
            0 => joined(),
            1 => held(false, false),
            2 => held(true, false),
            3 => held(false, true),
            4 => held(true, true),
            _ => {
                let mut e = joined();
                e.platform
                    .inject_persistent(Call::CheckTools, Fault::ReadFail);
                e.apply(Event::Repair(verify::Action::Rejoin));
                elapse(&mut e, 10);
                assert!(matches!(e.machine.pending(), Some(Step::Backoff { .. })));
                e
            }
        };
        let missing = scenario == 3 || scenario == 4;
        let start = e.platform.calls.len();
        leave(&mut e, 21);
        assert!(
            e.submit(Request {
                id: 22,
                kind: RequestKind::Join
            })
            .is_err()
        );
        assert!(!e.snapshot.requests.iter().any(|r| r.id == 22));
        drive(&mut e, 500);
        assert_eq!(
            e.status().text,
            if missing {
                "left (not durable)"
            } else {
                "left"
            },
            "scenario {scenario}: {:?}",
            e.machine.plan()
        );
        assert!(!e.machine.durable().hold);
        assert!(!e.machine.durable().join_intended);
        assert!(!e.platform.calls[start..].contains(&Call::LoadAnchor));
        assert!(!e.platform.calls[start..].contains(&Call::Spawn));
        assert!(!e.platform.calls[start..].contains(&Call::Acquire));
        assert!(e.platform.anchor.is_none());
    }
    let mut e = joined();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.apply(Event::InvalidateObservations { since: 100 });
    assert_eq!(e.mode, Mode::PersistBlocked);
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left (not durable)");
    e.platform.clear_faults();
    elapse(&mut e, 65);
    assert_eq!(e.status().text, "left");
}

#[test]
fn clear_intent_complete_reads_name_each_failure_then_recover() {
    for item in [
        "anchor",
        "DNS key",
        "owned process",
        "split route",
        "host route",
        "fence open",
    ] {
        let mut e = joined();
        leave(&mut e, 2);
        before_pending(&mut e, Step::ClearIntent);
        let saved = e.platform.clone();
        match item {
            "anchor" => e.platform.anchor = Some("block all\n".into()),
            "DNS key" => {
                e.platform.settings.insert(
                    ConfigKey::Dns,
                    platform::Setting::Dns(vec!["192.0.2.53".parse().unwrap()]),
                );
            }
            "owned process" => {
                let mut proc = e.platform.procs[&e.platform.helper.pid].clone();
                proc.pid = 333;
                proc.pgid = e.platform.helper.pid;
                proc.path = Some(CHILD_PATH.into());
                e.platform.procs.insert(333, proc);
            }
            "split route" => {
                e.platform.settings.insert(
                    ConfigKey::SplitRoutes,
                    platform::Setting::SplitRoutes(vec!["0.0.0.0".parse().unwrap()]),
                );
            }
            "host route" => {
                e.platform.settings.insert(
                    ConfigKey::EndpointRoute,
                    platform::Setting::Route {
                        destination: (*e.snapshot.endpoint.unwrap().ip()).into(),
                        interface: "en0".into(),
                        gateway: None,
                    },
                );
            }
            _ => {
                e.platform.inject(
                    Call::Flush,
                    1,
                    Fault::ToolHang {
                        effect: false,
                        reaped: false,
                    },
                );
                let d = e.deadline();
                let _ = e.platform.flush_states(d);
            }
        }
        tick(&mut e);
        tick(&mut e);
        assert_eq!(e.status().text, format!("leaving: {item}"));
        assert!(e.machine.durable().leaving);
        assert!(!e.left_verified);
        // Remove the external residual, then drive the core's resume_cleanup.
        e.platform = saved;
        elapse(&mut e, 4);
        assert_eq!(e.status().text, "left", "{item}: {:?}", e.machine.plan());
    }
    for call in [
        Call::ReadAnchor,
        Call::ReadConfig(ConfigKey::Dns),
        Call::Processes,
        Call::LeaveRoutes,
    ] {
        let mut e = joined();
        leave(&mut e, 2);
        before_pending(&mut e, Step::ClearIntent);
        e.platform.inject(call, 1, Fault::Incomplete);
        tick(&mut e);
        tick(&mut e);
        assert!(!e.left_verified, "{call:?}");
        elapse(&mut e, 4);
        assert_eq!(e.status().text, "left");
    }
}

#[test]
fn leave_does_not_wait_on_reference_debt_or_open_cleanup_family() {
    let mut e = joined_with_reference_debt();
    e.platform
        .inject_persistent(Call::References, Fault::ReadFail);
    e.platform.inject(
        Call::CleanupDns,
        1,
        Fault::ToolHang {
            effect: false,
            reaped: false,
        },
    );
    leave(&mut e, 2);
    let start = e.platform.calls.len();
    for _ in 0..100 {
        tick(&mut e);
        if e.platform.calls[start..].contains(&Call::RemoveAnchor) {
            break;
        }
    }
    assert!(
        e.platform.calls[start..].contains(&Call::RemoveAnchor),
        "{:?} {:?} {:?}",
        e.status(),
        e.machine.plan(),
        &e.platform.calls[start..]
    );
    assert!(!e.left_verified);
    e.platform.release_unreaped();
    elapse(&mut e, 5);
    assert_eq!(e.status().text, "left");
    assert!(e.status().accounting.uncertain > 0);
    assert!(!e.platform.calls[start..].contains(&Call::Acquire));
}

#[test]
fn leave_crash_at_each_commit_resumes_cleanup_without_spawn() {
    // First count actual Leave commits, then crash each A/B boundary against
    // all possible write outcomes. Recovery never replays a child start.
    let mut counted = joined();
    let start = counted.platform.calls.len();
    leave(&mut counted, 2);
    let mut left_commit = None;
    for _ in 0..500 {
        tick(&mut counted);
        if counted.left_verified && left_commit.is_none() {
            left_commit = Some(
                counted.platform.calls[start..]
                    .iter()
                    .filter(|call| **call == Call::Write(Copy::B))
                    .count(),
            );
        }
        if counted.is_quiescent() && counted.machine.pending().is_none() {
            break;
        }
    }
    let left_commit = left_commit.unwrap();
    let commits = counted.platform.calls[start..]
        .iter()
        .filter(|c| **c == Call::Write(Copy::B))
        .count();
    assert!(commits >= 3);
    for nth in 1..=commits {
        for copy in [Copy::A, Copy::B] {
            let mut e = joined();
            e.platform.inject(Call::Write(copy), nth, Fault::WriteHang);
            leave(&mut e, 2);
            for _ in 0..500 {
                tick(&mut e);
                if e.storage_blocked {
                    break;
                }
            }
            assert!(e.storage_blocked, "{nth} {copy:?}");
            let mut p = e.into_platform();
            p.restart();
            let start = p.calls.len();
            let mut e = Engine::start(p).unwrap();
            // The first request commit can leave the prior Joined state on disk;
            // it remains fail-closed. A persisted Leave must never spawn.
            let leaving = e.machine.durable().leaving || e.machine.durable().leave_requested;
            if nth > 1 && nth < left_commit {
                assert!(leaving, "lost durable Leave at {nth} {copy:?}");
                if nth > 2 {
                    // Both PersistLeaving copies synced before this crash.
                    // Never re-submit Leave to hide lost durable Leaving.
                    assert!(
                        e.machine.durable().leaving,
                        "lost durable Leaving at {nth} {copy:?}"
                    );
                }
            }
            if !leaving {
                // Re-check only a legitimate durable Left, or the very first
                // interrupted request commit that may still be Joined.
                assert!(nth == 1 || nth >= left_commit && !e.machine.durable().join_intended);
                leave(&mut e, 3);
            }
            drive(&mut e, 700);
            assert_left(&mut e, if leaving { 2 } else { 3 });
            assert_references_released_or_accounted(&e);
            assert!(!e.platform.calls[start..].contains(&Call::Spawn));
        }
    }
}

#[test]
fn storage_failures_retry_a_between_copies_b_and_late_completion() {
    for (copy, fault) in [
        (Copy::A, Fault::WriteFail),
        (Copy::A, Fault::FailedDurable),
        (Copy::B, Fault::WriteFail),
        (Copy::B, Fault::WriteHang),
    ] {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::ReserveGeneration);
        e.platform.inject(Call::Write(copy), 1, fault);
        tick(&mut e);
        tick(&mut e);
        assert_eq!(e.mode, Mode::PersistBlocked);
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        assert!(!e.platform.calls.contains(&Call::Spawn));
        assert!(e.waiting.is_some());
        if fault == Fault::WriteHang {
            e.platform.complete_late(copy, true);
        }
        elapse(&mut e, 5);
        assert_eq!(e.mode, Mode::Normal);
        assert!(
            matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined)
        );
    }
}

#[test]
fn persist_blocked_masks_protected_and_reenables_pf_without_acquiring() {
    let mut e = joined();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.apply(Event::InvalidateObservations { since: 100 });
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(
        e.submit(Request {
            id: 2,
            kind: RequestKind::Join
        })
        .is_err()
    );
    let start = e.platform.calls.len();
    e.platform.anchor = None;
    elapse(&mut e, 8);
    assert!(e.platform.calls[start..].contains(&Call::LoadAnchor));
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    e.platform.mutate(Mutation::PfDisable);
    elapse(&mut e, 4);
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::Observation("storage failing"))
    );
    assert!(e.platform.enabled);
    assert!(e.platform.calls[start..].contains(&Call::EnablePf));
    assert!(!e.platform.calls[start..].contains(&Call::Acquire));
}

#[test]
fn missing_pair_holds_expected_policy_refuses_join_and_setup_repairs() {
    for unreadable in [false, true] {
        let mut e = held(unreadable, true);
        drive(&mut e, 400);
        assert_eq!(e.mode, Mode::PersistBlocked);
        assert_eq!(
            e.machine.pre_tunnel_policy(),
            if unreadable {
                Kind::Lockdown
            } else {
                Kind::Installed(Form::PreTunnel)
            }
        );
        assert!(
            e.status().blocking_verified,
            "{:?} {:?}",
            e.status(),
            e.machine.plan()
        );
        assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Observation("storage missing: reinstall"))
        );
        assert!(
            e.submit(Request {
                id: 1,
                kind: RequestKind::Join
            })
            .is_err()
        );
        assert!(
            !e.platform
                .calls
                .iter()
                .any(|c| matches!(c, Call::Create(_)))
        );
        // Setup owns creation. Recovery retries only writes to the existing pair.
        let bytes = snapshot::encode(1, &Snapshot::initial(Some(501), None)).unwrap();
        for copy in [Copy::A, Copy::B] {
            let d = e.deadline();
            assert_eq!(
                e.platform.create_copy(copy, &bytes, d),
                WriteOutcome::Synced
            );
        }
        elapse(&mut e, 65);
        assert_eq!(e.mode, Mode::Normal);
        assert!(e.snapshot.machine.hold);
        assert!(e.status().blocking_verified);
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    }
}

#[test]
fn timing_missing_lockdown_load_failures_retry_each_second() {
    let mut p = FakePlatform::new().unwrap();
    p.mutate(Mutation::ForeignEnable);
    p.inject(Call::Install, 1, Fault::ReadFail);
    p.inject_persistent(Call::LoadAnchor, Fault::ToolFail { effect: false });
    let mut e = Engine::start(p).unwrap();
    e.run_until_quiescent(100);
    let start = e.platform.now();
    for previous in start..start + 5 {
        assert!(!e.status().blocking_verified);
        let loads = e
            .platform
            .calls
            .iter()
            .filter(|c| **c == Call::LoadAnchor)
            .count();
        e.platform
            .pause(Duration::from_millis(1000), Deadline(previous + 1));
        e.run_until_quiescent(100);
        assert_eq!(e.platform.now(), previous + 1);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count(),
            loads + 1
        );
    }
    e.platform.clear_faults();
    elapse(&mut e, 2);
    assert!(e.status().blocking_verified);
}

#[test]
fn hold_table_repairs_refreshes_ignores_child_and_never_plans_suffix() {
    for unreadable in [false, true] {
        let mut e = held(unreadable, false);
        e.platform
            .inject_persistent(Call::References, Fault::ReadFail);
        elapse(&mut e, 4);
        assert!(e.status().blocking_verified);
        assert!(!e.platform.calls.contains(&Call::Spawn));
        assert!(!e.platform.calls.contains(&Call::CheckTools));
        assert!(
            e.submit(Request {
                id: 1,
                kind: RequestKind::Join
            })
            .is_err()
        );
        let context = e.machine.context();
        e.apply(Event::ChildDied);
        assert_eq!(e.machine.context(), context);
        for action in [
            verify::Action::Rejoin,
            verify::Action::RecreateChild,
            verify::Action::Rerender { form: Form::Joined },
        ] {
            e.apply(Event::Repair(action));
            elapse(&mut e, 2);
            assert!(e.status().blocking_verified);
        }
        for loss in [0, 1, 2, 3] {
            match loss {
                0 => e.platform.anchor = None,
                1 => {
                    let now = e.platform.now();
                    e.apply(Event::InvalidateObservations { since: now });
                }
                2 => {
                    e.platform.clear_faults();
                    e.platform.x_qualified = true;
                    e.platform.mutate(Mutation::PfDisable);
                }
                _ => e.platform.anchor = Some("block all\n".into()),
            }
            elapse(&mut e, 4);
            assert!(
                e.status().blocking_verified,
                "loss {loss}: {:?} {:?}",
                e.status(),
                e.machine.plan()
            );
            assert!(!e.platform.calls.contains(&Call::CheckTools));
            assert!(!e.platform.calls.contains(&Call::Spawn));
        }
        assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Observation("state untrusted: run leave"))
        );
        let calls = e.platform.calls.len();
        elapse(&mut e, 11);
        assert!(e.platform.calls[calls..].contains(&Call::Cheap));
        assert!(e.platform.calls[calls..].contains(&Call::Collect));
        assert!(e.platform.calls[calls..].contains(&Call::Flush));
    }
}

#[test]
fn stuck_triggers_preserve_evidence_and_leave_returns_exit_zero() {
    for mismatch in [false, true] {
        let mut e = joined_with_reference_debt();
        let references = e.snapshot.references.clone();
        if mismatch {
            let mut wrong = e.machine.durable().clone();
            wrong.uncertain_acquires.clear();
            e.adopt(Machine::restart(wrong), &Event::Join, None);
        } else {
            e.reject_fallback = true;
            e.rejected_completion();
        }
        assert_eq!(e.mode, Mode::Stuck);
        assert_eq!(e.snapshot.references, references);
        assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Observation("internal"))
        );
        let state = e.machine.clone();
        e.apply(Event::ChildDied);
        assert_eq!(e.machine, state);
        let anchor = e.platform.anchor.clone();
        elapse(&mut e, 6);
        assert_eq!(e.platform.anchor, anchor);
        assert!(
            e.submit(Request {
                id: 2,
                kind: RequestKind::Join
            })
            .is_err()
        );
        leave(&mut e, 3);
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
        assert_eq!(e.snapshot.references, references);
        let mut p = e.into_platform();
        p.restart();
        let start = p.calls.len();
        let mut e = Engine::start(p).unwrap();
        assert!(!e.machine.durable().join_intended);
        assert!(!e.machine.durable().leaving);
        assert_eq!(e.snapshot.references, references);
        e.run_until_quiescent(1);
        assert!(!e.platform.calls[start..].contains(&Call::Spawn));
    }
}

#[test]
fn standing_reference_error_restart_never_becomes_enforcement_error() {
    let mut e = joined_with_reference_debt();
    e.platform
        .inject_persistent(Call::References, Fault::Incomplete);
    elapse(&mut e, 15);
    assert!(e.machine.durable().reference_error.is_some());
    assert!(e.snapshot.machine.last_error.is_none());
    let mut p = e.into_platform();
    p.restart();
    p.calls.clear();
    let e = Engine::start(p).unwrap();
    assert!(e.machine.durable().enforcement_error.is_none());
    assert_eq!(
        e.machine.enforcement_at(&Clock(100)),
        Verdict::NeverVerified
    );
    assert_eq!(writes(&e.platform), 4); // helper + the ordinary restart context
}

#[test]
fn timing_ambiguous_start_returns_early_and_reenumerates() {
    let mut p = FakePlatform::new().unwrap();
    let mut proc = p.procs[&14].clone();
    proc.start.seconds = 90;
    proc.path = None;
    proc.image = Some(platform::ImageId {
        uuid: [9; 16],
        uniqueid: 14,
    });
    p.procs.insert(14, proc);
    let before = p.now();
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.mode, Mode::Starting);
    assert_eq!(e.platform.now(), before);
    let reads = e
        .platform
        .calls
        .iter()
        .filter(|c| **c == Call::Processes)
        .count();
    elapse(&mut e, 1);
    assert_eq!(e.platform.now(), before + 1);
    assert!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Processes)
            .count()
            > reads
    );
    assert_eq!(e.platform.signals, []);
    e.platform.procs.remove(&14);
    tick(&mut e);
    assert_eq!(e.mode, Mode::PersistBlocked);
}

#[test]
fn persist_blocked_waiting_d_commit_cannot_resurrect_observations_and_n_repairs_run() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::ReserveGeneration);
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    tick(&mut e);
    tick(&mut e);
    assert!(e.waiting.is_some());
    let context = e.machine.context();
    e.platform.anchor = None;
    let start = e.platform.calls.len();
    elapse(&mut e, 5);
    assert!(e.platform.calls[start..].contains(&Call::LoadAnchor));
    assert!(e.machine.context().lifecycle_revision > context.lifecycle_revision);
    assert!(!e.platform.calls[start..].contains(&Call::Spawn));
    assert!(!e.platform.calls[start..].contains(&Call::Acquire));
    assert!(!e.request_completed(1));
    e.platform.clear_faults();
    elapse(&mut e, 10);
    assert!(e.request_completed(1));
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined)
    );
}

#[test]
fn timing_storage_and_leave_failures_back_off_one_two_four_to_sixty() {
    let mut e = joined();
    assert!(e.request_completed(1));
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.apply(Event::InvalidateObservations { since: 100 });
    let mut delay = 1;
    for _ in 0..9 {
        let now = e.platform.now();
        assert_eq!(e.next_storage, now + delay);
        e.platform.calls.clear();
        for _ in 0..20 {
            e.retry_storage();
        }
        assert_eq!(writes(&e.platform), 0);
        e.platform
            .pause(Duration::from_secs(delay), Deadline(now + delay));
        e.retry_storage();
        assert_eq!(writes(&e.platform), 1);
        delay = (delay * 2).min(60);
    }
    assert!(!e.request_completed(1));
    let mut e = joined();
    e.platform
        .inject_persistent(Call::CleanupDns, Fault::ToolFail { effect: false });
    leave(&mut e, 2);
    e.run_until_quiescent(100);
    let mut delay = 1;
    for _ in 0..9 {
        // idle Leaving schedules its own retry, independent of reference work.
        e.retry_leave();
        let now = e.platform.now();
        assert_eq!(e.next_leave, now + delay);
        e.platform
            .pause(Duration::from_secs(delay), Deadline(now + delay));
        e.run_until_quiescent(100);
        delay = (delay * 2).min(60);
        assert!(e.machine.durable().leaving);
    }
    e.platform.clear_faults();
    elapse(&mut e, 65);
    assert_eq!(e.status().text, "left");
    assert!(e.request_completed(2));
}

#[test]
fn persist_blocked_masks_a_previously_protected_machine_and_join_ack() {
    let mut e = joined();
    assert!(e.request_completed(1));
    assert!(matches!(
        e.machine.enforcement_at(&Clock(e.platform.now())),
        Verdict::Protected(_)
    ));
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.snapshot.owner_uid = None;
    assert!(!e.commit_if_changed());
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::Observation("storage failing"))
    );
    assert!(!e.request_completed(1));
    assert_eq!(
        e.status().text,
        "not protected: verification failure: storage failing"
    );
    assert!(
        e.submit(Request {
            id: 2,
            kind: RequestKind::Join
        })
        .is_err()
    );
}

#[test]
fn stuck_leave_retains_an_acquisition_whose_completion_was_rejected() {
    let mut e = reacquiring_after_verified_enforcement();
    tick(&mut e); // Real ioctl, complete fingerprint, queued completion.
    let QueueEvent::Completion(mut completion) = e.queue.pop_front().unwrap() else {
        panic!("missing completion")
    };
    let mut acquired = completion.acquired.clone().unwrap();
    completion.event = Event::Completed(Step::LoadJoined); // rejected, then rejected fallback
    e.reject_fallback = true;
    e.complete(completion);
    assert_eq!(e.mode, Mode::Stuck);
    assert!(e.retained_completion.is_some());
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
    leave(&mut e, 2);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    // The reacquisition's old token adds an accounting mismatch. Retain the
    // exact new fingerprint, but conservatively withhold release authority.
    // One owned pf reference remains unreleased; removing the anchor restores
    // connectivity independently of that conservative accounting debt.
    acquired.release_unknown = true;
    assert_eq!(e.snapshot.references[0].as_ref(), Some(&acquired));
    let mut p = e.into_platform();
    p.restart();
    let e = Engine::start(p).unwrap();
    assert!(!e.machine.durable().join_intended);
    assert_eq!(e.snapshot.references[0].as_ref(), Some(&acquired));
}

#[test]
fn fresh_leave_without_inputs_or_storage_never_installs_enforcement() {
    for storage in [false, true] {
        let mut p = fixture(&Snapshot::initial(Some(501), None));
        p.inject(Call::Install, 1, Fault::ReadFail);
        if storage {
            p.inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
        }
        let mut e = Engine::start(p).unwrap();
        let start = e.platform.calls.len();
        leave(&mut e, 1);
        drive(&mut e, 500);
        assert_eq!(
            e.status().text,
            if storage {
                "left (not durable)"
            } else {
                "left (endpoint route not checked)"
            }
        );
        assert!(e.status().endpoint_unknown);
        if !storage {
            assert!(
                e.submit(Request {
                    id: 2,
                    kind: RequestKind::Join
                })
                .is_err()
            );
        }
        assert!(!e.platform.calls[start..].iter().any(|call| matches!(
            call,
            Call::LoadAnchor | Call::Acquire | Call::Spawn | Call::Flush
        )));
    }
}

#[test]
fn timing_hold_prefix_read_failures_retry_each_second_without_flushing() {
    let mut e = held(true, true);
    e.platform
        .inject_persistent(Call::ReadAnchor, Fault::ReadFail);
    e.platform.calls.clear();
    e.run_until_quiescent(100);
    for _ in 0..4 {
        let reads = e
            .platform
            .calls
            .iter()
            .filter(|call| **call == Call::ReadAnchor)
            .count();
        let now = e.platform.now();
        e.platform.pause(Duration::from_secs(1), Deadline(now + 1));
        e.run_until_quiescent(100);
        assert!(
            e.platform
                .calls
                .iter()
                .filter(|call| **call == Call::ReadAnchor)
                .count()
                > reads
        );
        assert!(!e.platform.calls.contains(&Call::Flush));
        assert!(!e.status().blocking_verified);
    }
    e.platform.clear_faults();
    elapse(&mut e, 3);
    assert!(e.status().blocking_verified);
}

#[test]
fn pair_repair_create_failures_resume_after_storage_recovers() {
    for copy in [Copy::A, Copy::B] {
        for fault in [Fault::NoSpace, Fault::FailedDurable, Fault::WriteHang] {
            let mut p = fixture(&Snapshot::initial(Some(501), None));
            p.mutate(Mutation::MissingCopy(copy));
            p.inject(Call::Create(copy), 1, fault);
            let mut e = Engine::start(p).unwrap();
            assert_eq!(e.mode, Mode::PersistBlocked);
            assert!(e.repair_pending.is_some());
            if fault == Fault::WriteHang {
                e.platform.complete_late(copy, true);
            }
            elapse(&mut e, 5);
            assert_eq!(e.mode, Mode::Normal);
            assert!(e.repair_pending.is_none());
            assert!(e.helper_committed);
            assert_eq!(
                read_snapshot(&mut e.platform, Copy::A),
                read_snapshot(&mut e.platform, Copy::B)
            );
            assert!(!e.platform.calls.contains(&Call::Spawn));
            assert!(!e.platform.calls.contains(&Call::Acquire));
        }
    }
}

#[test]
fn stuck_never_adopts_a_waiting_d_completion_when_storage_recovers() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::ReserveGeneration);
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    tick(&mut e);
    tick(&mut e);
    assert!(e.waiting.is_some());
    let state = e.machine.clone();
    e.enter_stuck();
    assert!(e.waiting.is_none());
    e.platform.clear_faults();
    elapse(&mut e, 5);
    assert_eq!(e.mode, Mode::Stuck);
    assert_eq!(e.machine, state);
    leave(&mut e, 2);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
}

#[test]
fn leave_late_anchor_effect_is_reaped_before_immediate_cleanup_retry() {
    let mut e = joined();
    e.apply(Event::Repair(verify::Action::Rejoin));
    before_pending(&mut e, Step::LoadPreTunnel);
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    tick(&mut e);
    tick(&mut e);
    assert_ne!(e.platform.fence(), Fence::Closed);
    leave(&mut e, 2);
    let start = e.platform.calls.len();
    for _ in 0..100 {
        tick(&mut e);
        if e.platform.calls[start..].contains(&Call::RemoveAnchor) {
            break;
        }
    }
    assert!(e.platform.calls[start..].contains(&Call::RemoveAnchor));
    assert!(e.platform.anchor.is_none());
    assert!(!e.left_verified);
    let now = e.platform.now();
    e.platform.release_unreaped();
    e.run_until_quiescent(100);
    assert_eq!(
        e.platform.now(),
        now,
        "Unknown cleanup retries immediately after reap"
    );
    assert_eq!(e.status().text, "left");
    assert!(e.platform.anchor.is_none());
    assert!(!e.platform.calls[start..].contains(&Call::LoadAnchor));
    assert!(!e.platform.calls[start..].contains(&Call::Flush));
    assert!(!e.platform.calls[start..].contains(&Call::Acquire));
}

#[test]
fn leave_preserves_an_unrelated_static_host_route() {
    let mut e = joined();
    leave(&mut e, 2);
    before_pending(&mut e, Step::ClearIntent);
    let foreign = platform::Setting::Route {
        destination: "203.0.113.9".parse().unwrap(),
        interface: "en0".into(),
        gateway: None,
    };
    e.platform
        .settings
        .insert(ConfigKey::EndpointRoute, foreign.clone());
    e.run_until_quiescent(100);
    assert_eq!(e.status().text, "left");
    assert_eq!(
        e.platform.settings.get(&ConfigKey::EndpointRoute),
        Some(&foreign)
    );
}

#[test]
fn timing_persisted_internal_error_restarts_in_verified_hold_and_leave_runs_normally() {
    for unreadable in [false, true] {
        let mut e = joined();
        e.enter_stuck();
        assert!(e.committed.internal_error.is_some());
        let mut p = e.into_platform();
        p.restart();
        p.anchor = None;
        p.mutate(Mutation::PfDisable);
        p.calls.clear();
        if unreadable {
            p.inject(Call::Install, 1, Fault::ReadFail);
        }
        let mut e = Engine::start(p).unwrap();
        assert_ne!(e.mode, Mode::Stuck);
        assert!(e.machine.durable().hold);
        assert_eq!(
            e.machine.pre_tunnel_policy(),
            if unreadable {
                Kind::Lockdown
            } else {
                Kind::Installed(Form::PreTunnel)
            }
        );
        let started = e.platform.now();
        e.run_until_quiescent(100);
        elapse(&mut e, 2);
        assert!(e.platform.calls.contains(&Call::LoadAnchor));
        assert!(
            e.status().emergency_blocking_verified,
            "{:?} {:?}",
            e.status(),
            e.machine.plan()
        );
        assert!(e.platform.now() <= started + 2);
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert!(!e.platform.calls.contains(&Call::Spawn));
        assert!(e.snapshot.internal_error.is_some());
        assert_eq!(e.status().text, "state untrusted: run leave");
        assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Observation("internal"))
        );
        assert!(
            e.submit(Request {
                id: 2,
                kind: RequestKind::Join
            })
            .is_err()
        );
        leave(&mut e, 3);
        drive(&mut e, 500);
        assert_eq!(e.status().text, "left");
        assert!(!e.machine.durable().hold);
        assert!(e.snapshot.internal_error.is_none());
        assert_eq!(e.outcome, Outcome::Continue);
    }
}

#[test]
fn internal_error_left_restart_removes_probe_containment_but_preserves_error_until_leave() {
    let mut e = fresh();
    e.enter_stuck();
    assert_eq!(e.mode, Mode::Stuck);
    assert!(e.committed.internal_error.is_some());
    assert_eq!(e.run_until_quiescent(100), Outcome::Continue);
    let mut p = e.into_platform();
    p.restart();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    e.run_until_quiescent(100);
    elapse(&mut e, 3);
    assert_eq!(e.mode, Mode::Normal);
    assert!(!e.machine.durable().join_intended);
    assert!(!e.machine.durable().hold);
    assert!(e.committed.internal_error.is_some());
    assert_eq!(e.status().text, "state untrusted: run leave");
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.platform.calls.contains(&Call::RemoveAnchor));
    assert!(e.platform.anchor.is_none());
    assert!(e.platform.enabled);
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|call| matches!(call, Call::Acquire | Call::Spawn))
    );
    assert!(
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join
        })
        .is_err()
    );
    // The serialized path must enforce the same refusal.
    e.process(QueueEvent::Request(Request {
        id: 1,
        kind: RequestKind::Join,
    }));
    assert!(!e.machine.durable().join_intended);
    assert!(e.machine.pending().is_none());
    assert!(!e.snapshot.requests.iter().any(|r| r.id == 1));
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert!(e.committed.internal_error.is_none());
    assert_eq!(e.status().text, "left");
    e.submit(Request {
        id: 3,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 500);
    assert!(e.request_completed(3));
}

#[test]
fn internal_error_leaving_restart_resumes_leave_under_hold() {
    let mut e = joined();
    leave(&mut e, 2);
    before_pending(&mut e, Step::StopChild);
    assert!(e.committed.machine.leaving);
    e.enter_stuck();
    let mut p = e.into_platform();
    p.restart();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    assert!(e.machine.durable().leaving);
    assert!(e.machine.durable().hold);
    assert!(e.snapshot.internal_error.is_some());
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left");
    assert!(e.request_completed(2));
    assert!(e.committed.internal_error.is_none());
    assert!(!e.platform.calls.contains(&Call::Spawn));
}

#[test]
fn reboot_rejection_before_enforcement_reaches_emergency_even_without_storage() {
    for storage_fails in [false, true] {
        let mut p = joined().into_platform();
        p.mutate(Mutation::Reboot);
        p.calls.clear();
        let mut e = Engine::start(p).unwrap();
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert!(e.platform.enabled);
        assert!(!e.verified_enforcement);
        let step = e.machine.pending().unwrap();
        e.dispatch(step);
        let dispatch = e.in_flight.unwrap().0;
        e.queue.clear();
        e.reject_fallback = true;
        if storage_fails {
            e.platform
                .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
        }
        e.complete(Completion {
            dispatch,
            event: Event::Completed(Step::StartChild),
            acquired: None,
            not_started: None,
        });
        assert_eq!(e.run_until_quiescent(100), Outcome::Continue);
        assert_emergency(&mut e);
        assert_eq!(e.committed.internal_error.is_some(), !storage_fails);
        assert!(!e.platform.calls.contains(&Call::Spawn));
    }
}

#[test]
fn stuck_after_verified_enforcement_stays_in_process_even_after_proof_expires() {
    for held in [false, true] {
        let mut e = joined();
        if held {
            e.enter_stuck();
            let mut p = e.into_platform();
            p.restart();
            e = Engine::start(p).unwrap();
            e.run_until_quiescent(100);
            assert!(e.status().blocking_verified || e.status().emergency_blocking_verified);
        }
        assert!(e.verified_enforcement);
        let loads = e
            .platform
            .calls
            .iter()
            .filter(|c| **c == Call::LoadAnchor)
            .count();
        // No new proof is collected during this clock jump.
        for _ in 0..120 * 20 {
            e.platform.tick();
        }
        e.enter_stuck();
        assert_eq!(e.mode, Mode::Stuck);
        assert_eq!(e.run_until_quiescent(100), Outcome::Continue);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count(),
            loads
        );
        assert_eq!(e.status().emergency_blocking_verified, held);
        assert!(e.committed.internal_error.is_some());
    }
}

#[test]
fn settled_requests_are_evicted_oldest_first_and_six_join_leave_cycles_reach_left() {
    let mut e = fresh();
    for cycle in 0..6 {
        let join_id = cycle * 2 + 1;
        e.submit(Request {
            id: join_id,
            kind: RequestKind::Join,
        })
        .unwrap();
        drive(&mut e, 500);
        assert!(e.request_completed(join_id));
        leave(&mut e, join_id + 1);
        drive(&mut e, 500);
        assert_left(&mut e, join_id + 1);
        assert!(e.platform.tokens.is_empty());
        assert_eq!(e.mode, Mode::Normal);
    }
    assert_eq!(
        e.snapshot.requests.iter().map(|r| r.id).collect::<Vec<_>>(),
        (5..=12).collect::<Vec<_>>()
    );
}

#[test]
fn full_unsettled_window_refuses_join_without_stuck_but_always_accepts_leave() {
    let mut e = fresh();
    e.snapshot.requests = (1..=8)
        .map(|id| RequestRecord {
            id,
            kind: snapshot::RequestKind::Leave,
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert!(
        e.submit(Request {
            id: 9,
            kind: RequestKind::Join
        })
        .is_err()
    );
    e.process(QueueEvent::Request(Request {
        id: 9,
        kind: RequestKind::Join,
    }));
    assert_eq!(e.mode, Mode::Normal);
    leave(&mut e, 10);
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left");
    assert!(e.request_completed(10));
    assert!(!e.snapshot.requests.iter().any(|r| r.id == 1));
}

#[test]
fn leave_records_a_queued_join_as_cancelled_without_exposing_it() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert!(
        e.committed
            .requests
            .iter()
            .any(|r| r.id == 1 && r.kind == snapshot::RequestKind::JoinCancelled)
    );
    assert!(e.request_completed(2));
    assert!(!e.platform.calls.contains(&Call::Spawn));
}

#[test]
fn full_pending_leave_window_retains_two_queued_join_cancellations() {
    let mut e = fresh();
    e.submit(Request {
        id: 9,
        kind: RequestKind::Join,
    })
    .unwrap();
    e.submit(Request {
        id: 11,
        kind: RequestKind::Join,
    })
    .unwrap();
    // Model the window filling between admission and synchronous Leave.
    e.snapshot.requests = (1..=8)
        .map(|id| RequestRecord {
            id,
            kind: snapshot::RequestKind::Leave,
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    leave(&mut e, 10);
    assert!(
        e.snapshot
            .requests
            .iter()
            .any(|r| r.id == 9 && r.kind == snapshot::RequestKind::JoinCancelled)
    );
    drive(&mut e, 500);
    assert!(
        e.committed
            .requests
            .iter()
            .any(|r| r.id == 9 && r.kind == snapshot::RequestKind::JoinCancelled)
    );
    assert!(
        e.committed
            .requests
            .iter()
            .any(|r| r.id == 11 && r.kind == snapshot::RequestKind::JoinCancelled)
    );
    assert!(e.request_completed(10));
    assert!(!e.platform.calls.contains(&Call::Spawn));
}

#[test]
fn persist_blocked_waiting_d_gate_does_not_redispatch_a_failed_commit() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::ReserveGeneration);
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    tick(&mut e);
    tick(&mut e);
    assert!(e.waiting.is_some());
    let dispatch = e.next_dispatch;
    let writes_before = writes(&e.platform);
    e.run_until_quiescent(100);
    assert_eq!(
        e.next_dispatch, dispatch,
        "D commit must wait without redispatch"
    );
    assert_eq!(writes(&e.platform), writes_before);
}

#[test]
fn acquire_dispatch_requires_committed_reservation_even_without_scheduler() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    e.snapshot.owner_uid = None;
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    let dispatch = e.next_dispatch;
    let calls = e.platform.calls.len();
    e.dispatch(Step::AcquireReference);
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert_eq!(e.next_dispatch, dispatch);
    assert!(!e.platform.calls[calls..].contains(&Call::Acquire));
}

#[test]
fn storage_retry_rewrites_equal_snapshot_and_abandoned_newer_copy() {
    let mut e = fresh();
    let original = e.committed.clone();
    e.snapshot.owner_uid = None;
    e.platform.inject(Call::Write(Copy::B), 1, Fault::WriteFail);
    assert!(!e.commit_if_changed());
    assert_eq!(e.mode, Mode::PersistBlocked);
    e.snapshot = original.clone();
    let calls = e.platform.calls.len();
    let now = e.platform.now();
    e.platform.pause(Duration::from_secs(1), Deadline(now + 1));
    e.retry_storage();
    assert_eq!(e.mode, Mode::Normal);
    assert!(!e.storage_blocked);
    assert_eq!(e.storage_delay, 0);
    assert_eq!(
        writes(&e.platform)
            - e.platform.calls[..calls]
                .iter()
                .filter(|c| matches!(c, Call::Write(_) | Call::Create(_)))
                .count(),
        2
    );
    assert_eq!(read_snapshot(&mut e.platform, Copy::A), original);
    assert_eq!(read_snapshot(&mut e.platform, Copy::B), original);
    let mut p = e.into_platform();
    p.restart();
    let e = Engine::start(p).unwrap();
    assert_eq!(e.snapshot.owner_uid, Some(501));
}

#[test]
fn status_text_masks_stuck_overflow_and_open_fence_with_a_fresh_joined_proof() {
    for mask in 0..3 {
        let mut e = joined();
        match mask {
            0 => e.enter_stuck(),
            1 => e.overflowed = true,
            _ => e
                .platform
                .inject(Call::Flush, 1, Fault::ToolLate { ticks: None }),
        }
        if mask == 2 {
            assert!(e.execute(Step::FlushStates).is_err());
        }
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        assert!(!e.status().text.contains("joined"), "{:?}", e.status());
    }
}

#[test]
fn installed_policy_uses_install_qualification_when_platform_has_none() {
    let mut e = fresh();
    e.platform.firewall_qualification = None;
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 500);
    assert!(e.request_completed(1));
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    let calls = e.platform.calls.len();
    e.platform.anchor = Some("block all\n".into());
    elapse(&mut e, 2);
    assert!(e.platform.calls[calls..].contains(&Call::LoadAnchor));
    let mut e = held(true, false);
    e.platform.firewall_qualification = None;
    elapse(&mut e, 3);
    assert!(!e.status().blocking_verified);
    assert!(!e.platform.calls.contains(&Call::Spawn));
}

#[test]
fn entering_stuck_retains_the_matching_queued_acquisition_completion() {
    let mut e = reacquiring_after_verified_enforcement();
    tick(&mut e);
    let mut acquired = e
        .queue
        .iter()
        .find_map(|event| match event {
            QueueEvent::Completion(c) => c.acquired.clone(),
            _ => None,
        })
        .unwrap();
    e.enter_stuck();
    assert!(e.retained_completion.is_some());
    assert!(e.in_flight.is_none());
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
    leave(&mut e, 2);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    acquired.release_unknown = true;
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .any(|entry| entry == &acquired)
    );
}

#[test]
fn uncommitted_helper_tool_orphan_is_killed_by_next_start_fence_before_effects() {
    // M,M permits the held N-class prefix, while no helper record can commit.
    let mut p = FakePlatform::new().unwrap();
    p.mutate(Mutation::ForeignEnable);
    let mut e = Engine::start(p).unwrap();
    assert!(!e.helper_committed);
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    e.platform.anchor = None;
    elapse(&mut e, 1);
    for _ in 0..100 {
        if !e.platform.unreaped.is_empty() {
            break;
        }
        tick(&mut e);
    }
    let tool = e
        .platform
        .procs
        .values()
        .find(|proc| {
            proc.path.as_deref() == Some(Path::new("/sbin/pfctl"))
                && proc.ppid == e.platform.helper.pid
        })
        .cloned()
        .unwrap();
    let mut p = e.into_platform();
    p.abandon_process_group = true;
    // Independently pin the documented pathless-host-process residual, so it
    // cannot hide whether the orphaned pinned tool itself was swept.
    p.procs.get_mut(&14).unwrap().path = Some("/foreign/ordinary".into());
    p.restart();
    p.calls.clear();
    assert_eq!(p.procs[&tool.pid].ppid, 1);
    let mut e = Engine::start(p).unwrap();
    // The deadline fault initially models an unkillable process. Withhold all
    // ordinary effects until SIGKILL is confirmed; D-3 contains beforehand.
    assert_eq!(e.mode, Mode::Starting);
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|call| matches!(call, Call::Acquire | Call::Spawn))
    );
    e.platform.unkillable.remove(&tool.pid);
    let at = e.platform.now();
    for _ in 0..40 {
        tick(&mut e);
        if e.start_fence == StartFence::Closed {
            break;
        }
    }
    assert_eq!(e.start_fence, StartFence::Closed);
    assert!(e.platform.now() - at <= 2);
    e.run_until_quiescent(100);
    // A verified pre-fence Lockdown can satisfy the same core load. Force a
    // fresh mutation to retain the kill-before-new-effect ordering witness.
    e.platform.mutate(Mutation::AnchorLoss);
    elapse(&mut e, 2);
    let kill = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::KillProcess(tool.pid, tool.start))
        .unwrap();
    let effect = e
        .platform
        .calls
        .iter()
        .enumerate()
        .find(|(index, c)| {
            *index > kill && matches!(c, Call::LoadAnchor | Call::Acquire | Call::Spawn)
        })
        .map(|(index, _)| index)
        .unwrap();
    assert!(kill < effect);
    let containment = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::LoadAnchor)
        .unwrap();
    assert!(containment < kill);
    assert!(
        e.platform
            .procs
            .get(&tool.pid)
            .is_none_or(|proc| proc.state == ProcState::Zombie)
    );
    e.run_until_quiescent(100);
    oracle(&mut e);
}

#[test]
fn timing_stuck_left_commit_failure_backs_off_without_repeating_clear_intent_reads() {
    let mut e = joined();
    e.enter_stuck();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    leave(&mut e, 2);
    e.run_until_quiescent(100);
    assert!(e.left_verified);
    assert_eq!(e.status().text, "left (not durable)");
    assert_eq!(e.next_leave, e.platform.now() + 1);
    let reads = e
        .platform
        .calls
        .iter()
        .filter(|call| **call == Call::ReadAnchor)
        .count();
    for _ in 0..100 {
        e.run_until_quiescent(100);
    }
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::ReadAnchor)
            .count(),
        reads
    );
    e.platform
        .inject_persistent(Call::ReadConfig(ConfigKey::Dns), Fault::ReadFail);
    elapse(&mut e, 1);
    assert!(!e.left_verified);
    assert_eq!(e.status().text, "leaving: DNS key");
    assert_eq!(e.outcome, Outcome::Continue);
    e.platform.clear_faults();
    elapse(&mut e, 3);
    assert_eq!(e.outcome, Outcome::Exit0);
}

#[test]
fn stuck_leave_keeps_mismatched_accounting_keys_unknown_and_reports_left() {
    for extra in [false, true] {
        let mut e = joined();
        let key = reference_keys(e.machine.durable())[0];
        if extra {
            e.snapshot.references[1] = Some(RefEvidence {
                key: ReferenceEntry::Token(999),
                boot: None,
                fingerprint: None,
                release_unknown: false,
            });
        } else {
            e.snapshot.references = [None, None];
        }
        e.enter_stuck();
        leave(&mut e, 2);
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
        assert!(e.left_verified);
        assert!(e.snapshot.validate().is_ok());
        assert!(
            e.snapshot
                .references
                .iter()
                .flatten()
                .any(|entry| entry.key == key && entry.release_unknown)
        );
        if extra {
            assert!(
                e.snapshot
                    .references
                    .iter()
                    .flatten()
                    .any(|entry| entry.key == ReferenceEntry::Token(999) && entry.release_unknown)
            );
        }
        assert_eq!(e.status().text, "left");
    }
}

#[test]
fn held_refresh_gap_and_expiry_do_not_reload_matching_policy() {
    for unreadable in [false, true] {
        let mut e = held(unreadable, false);
        elapse(&mut e, 3);
        assert!(e.status().blocking_verified);
        let now = e.platform.now();
        e.platform.pause(Duration::from_secs(1), Deadline(now + 1));
        let calls = e.platform.calls.len();
        let refresh = e.collect_verdict(Form::PreTunnel).unwrap();
        assert!(matches!(
            refresh,
            Event::Observed {
                verdict: Verdict::Protected(_),
                ..
            }
        ));
        e.apply(refresh);
        assert!(e.status().blocking_verified);
        assert!(
            !e.platform.calls[calls..]
                .iter()
                .any(|c| matches!(c, Call::LoadAnchor | Call::Flush))
        );
        for expired in [false, true] {
            let calls = e.platform.calls.len();
            if expired {
                let now = e.platform.now();
                e.platform.pause(
                    Duration::from_secs(e.timings.max_age + 1),
                    Deadline(now + e.timings.max_age + 1),
                );
                e.apply(Event::ChildDied);
            } else {
                let since = e.platform.now();
                e.apply(Event::InvalidateObservations { since });
            }
            e.run_until_quiescent(100);
            assert!(
                e.status().blocking_verified,
                "{:?} {:?}",
                e.status(),
                e.machine.plan()
            );
            let calls = &e.platform.calls[calls..];
            assert!(
                !calls.contains(&Call::LoadAnchor),
                "matching held policy must not reload: {calls:?}"
            );
            let flush = calls.iter().position(|call| *call == Call::Flush).unwrap();
            let verify = calls
                .iter()
                .position(|call| *call == Call::Collect)
                .unwrap();
            assert!(flush < verify);
        }
    }
}

#[test]
fn left_publication_rechecks_a_newly_opened_fence() {
    let mut e = joined();
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left");
    e.platform
        .inject(Call::Flush, 1, Fault::ToolLate { ticks: None });
    assert!(e.execute(Step::FlushStates).is_err());
    assert!(e.left_verified);
    assert_eq!(e.status().text, "leaving: fence open");
    e.platform.release_unreaped();
    e.run_until_quiescent(100);
    assert_eq!(e.status().text, "left");
}

#[test]
fn persist_blocked_pf_and_handshake_observations_supersede_waiting_d_commit() {
    for observation in 0..3 {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::ReserveGeneration);
        e.platform
            .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
        tick(&mut e);
        tick(&mut e);
        assert!(e.waiting.is_some());
        let context = e.machine.context();
        let event = if observation == 0 {
            Event::Handshake {
                generation: TunnelGeneration::new(1).unwrap(),
                fresh: true,
            }
        } else if observation == 1 {
            Event::PfEnabledObserved { context }
        } else {
            e.platform.mutate(Mutation::PfDisable);
            Event::Repair(verify::Action::EnableAndRejoin)
        };
        assert!(
            e.machine
                .transition(event.clone(), &Clock(e.platform.now()))
                .is_ok()
        );
        e.apply(event);
        assert!(
            e.waiting.is_none(),
            "an accepted observation must supersede the speculative machine"
        );
        assert_ne!(e.machine.context(), context);
        let calls = e.platform.calls.len();
        e.run_until_quiescent(100);
        assert!(!e.platform.calls[calls..].contains(&Call::Spawn));
        assert!(!e.platform.calls[calls..].contains(&Call::Acquire));
        e.platform.clear_faults();
        elapse(&mut e, 10);
        assert_eq!(e.mode, Mode::Normal);
        assert!(e.request_completed(1));
    }
}

#[test]
fn superseded_persist_intent_is_replanned_without_dispatching_its_discarded_plan() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::PersistIntent);
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    tick(&mut e);
    tick(&mut e);
    assert!(e.waiting.is_some());
    assert!(!e.machine.durable().join_intended);
    let context = e.machine.context();
    e.apply(Event::PfEnabledObserved { context });
    assert!(e.waiting.is_none());
    assert_eq!(e.machine.pending(), Some(Step::PersistIntent));
    assert!(!e.machine.durable().join_intended);
    let dispatch = e.next_dispatch;
    let calls = e.platform.calls.len();
    elapse(&mut e, 60);
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert_eq!(e.next_dispatch, dispatch);
    assert!(!e.platform.calls[calls..].iter().any(|call| matches!(
        call,
        Call::Acquire | Call::Spawn | Call::LoadAnchor | Call::Flush
    )));
    e.platform.clear_faults();
    elapse(&mut e, 65);
    assert_eq!(e.mode, Mode::Normal);
    assert!(e.request_completed(1));
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref proof) if proof.form() == Form::Joined)
    );
}

#[test]
fn persist_blocked_without_speculative_wait_keeps_d_plan_during_sixty_seconds_of_checks() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::ReserveGeneration);
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.snapshot.owner_uid = None;
    assert!(!e.commit_if_changed());
    assert!(e.waiting.is_none());
    let machine = e.machine.clone();
    let context = machine.context();
    let clock = Clock(e.platform.now());
    e.cancel_storage_wait_for_safety(&Event::PfEnabledObserved { context }, clock);
    assert_eq!(e.machine, machine);
    let calls = e.platform.calls.len();
    let dispatch = e.next_dispatch;
    for _ in 0..60 * 20 {
        tick(&mut e);
        assert_eq!(e.mode, Mode::PersistBlocked);
        assert!(e.unexposed_acquires.len() <= 2);
        assert!(e.machine.durable().uncertain_acquires.len() <= 2);
    }
    assert_eq!(e.machine.pending(), Some(Step::ReserveGeneration));
    assert_eq!(e.next_dispatch, dispatch);
    assert!(e.platform.calls[calls..].contains(&Call::Cheap));
    assert!(!e.platform.calls[calls..].contains(&Call::LoadAnchor));
    e.platform.clear_faults();
    elapse(&mut e, 65);
    assert!(e.request_completed(1));
}

#[test]
fn stuck_accounting_overflow_preserves_every_key_without_refusing_connectivity() {
    let mut e = joined();
    let mut durable = e.machine.durable().clone();
    durable.older_references.push(998);
    e.machine = Machine::restart(durable);
    e.snapshot.references[1] = Some(RefEvidence {
        key: ReferenceEntry::Token(999),
        boot: None,
        fingerprint: None,
        release_unknown: false,
    });
    e.enter_stuck();
    leave(&mut e, 2);
    assert_eq!(e.run_until_quiescent(100), Outcome::Continue);
    assert!(e.left_verified);
    assert_eq!(e.status().text, "left (not durable)");
    assert_eq!(e.status().accounting.held, 3);
    assert_eq!(e.status().accounting.release_unknown, 3);
    assert_eq!(e.stuck_accounting.len(), 3);
    let reads = e
        .platform
        .calls
        .iter()
        .filter(|call| **call == Call::ReadAnchor)
        .count();
    e.run_until_quiescent(100);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::ReadAnchor)
            .count(),
        reads
    );
    assert!(e.platform.anchor.is_none());
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|call| matches!(call, Call::Release(_)))
    );
}

#[test]
fn completion_backpressure_keeps_acquired_token_for_stuck_leave() {
    let mut e = reacquiring_after_verified_enforcement();
    e.capacity = 1;
    e.queue.push_back(QueueEvent::Request(Request {
        id: 9,
        kind: RequestKind::Join,
    }));
    e.dispatch(Step::AcquireReference);
    assert_eq!(e.mode, Mode::Stuck);
    let mut acquired = e
        .retained_completion
        .as_ref()
        .unwrap()
        .1
        .acquired
        .clone()
        .unwrap();
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
    leave(&mut e, 2);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    acquired.release_unknown = true;
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .any(|entry| entry == &acquired)
    );
}

fn assert_emergency(e: &mut Engine<FakePlatform>) {
    assert_eq!(e.mode, Mode::Stuck);
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::Observation("internal"))
    );
    assert!(e.status().emergency_blocking_verified, "{:?}", e.status());
    assert!(e.platform.enabled);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(scupper_core::mac::policy::render_lockdown().as_str())
    );
    assert_eq!(e.platform.fence(), Fence::Closed);
}

#[test]
fn join_leave_join_rejection_before_load_revokes_old_verification_and_blocks() {
    let mut e = joined();
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert!(!e.verified_enforcement);
    assert!(e.platform.anchor.is_none());
    e.submit(Request {
        id: 3,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    e.reject_fallback = true;
    e.rejected_completion();
    assert_eq!(e.mode, Mode::Stuck);
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
}

#[test]
fn disabled_pf_then_stuck_reasserts_and_reloads_only_on_anchor_loss_or_drift() {
    for loss in [0, 1, 2] {
        let mut e = reacquiring_after_verified_enforcement();
        e.reject_fallback = true;
        e.rejected_completion();
        e.run_until_quiescent(100);
        assert_emergency(&mut e);
        let before = e
            .platform
            .calls
            .iter()
            .filter(|c| **c == Call::LoadAnchor)
            .count();
        match loss {
            0 => e.platform.anchor = None,
            1 => e.platform.mutate(Mutation::PfDisable),
            _ => e.platform.anchor = Some("pass all\n".into()),
        }
        elapse(&mut e, 1);
        assert_emergency(&mut e);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count(),
            before + usize::from(loss != 1)
        );
    }
}

#[test]
fn emergency_retry_is_one_second_and_leave_reaps_late_load_before_anchor_removal() {
    for late_ticks in [None, Some(40)] {
        let mut e = reacquiring_after_verified_enforcement();
        e.platform
            .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: late_ticks });
        e.enter_stuck();
        e.run_until_quiescent(100);
        assert!(!e.status().emergency_blocking_verified);
        assert!(matches!(e.platform.fence(), Fence::Open(_)));
        let loads = e
            .platform
            .calls
            .iter()
            .filter(|c| **c == Call::LoadAnchor)
            .count();
        let mut previous_loads = loads;
        for _ in 0..100 {
            let at = e.platform.now();
            e.run_until_quiescent(1);
            let after = e.platform.now();
            // An actual one-second reap slice advances time even without an
            // external tick. D-3 may repair on that cadence beside the writer.
            let current_loads = e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count();
            assert!(after - at <= 1);
            if after == at {
                assert_eq!(current_loads, previous_loads);
            }
            previous_loads = current_loads;
        }
        // The fake keeps a timed-out tool unkillable until explicitly released.
        e.platform.unkillable.clear();
        let start = e.platform.calls.len();
        leave(&mut e, 2);
        assert!(e.emergency_revoked);
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
        assert_eq!(e.status().text, "left");
        assert!(!e.status().blocking_verified);
        assert!(e.platform.anchor.is_none());
        let calls = &e.platform.calls[start..];
        let kill = calls
            .iter()
            .position(|c| matches!(c, Call::KillProcess(..)))
            .unwrap();
        let remove = calls.iter().position(|c| *c == Call::RemoveAnchor).unwrap();
        assert!(kill < remove);
        for _ in 0..100 {
            e.platform.tick();
            e.run_until_quiescent(100);
        }
        assert!(e.platform.anchor.is_none());
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count(),
            previous_loads
        );
        // A subsequent Leave after Exit0 must also run, not disappear at the outcome gate.
        leave(&mut e, 3);
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
        assert!(
            e.committed
                .requests
                .iter()
                .any(|r| r.id == 3 && r.kind == snapshot::RequestKind::LeaveDone)
        );
    }
}

#[test]
fn emergency_failed_load_retries_at_one_second_without_concurrent_attempts() {
    let mut e = reacquiring_after_verified_enforcement();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolFail { effect: false });
    e.enter_stuck();
    e.run_until_quiescent(100);
    assert!(!e.status().emergency_blocking_verified);
    let start = e.platform.calls.len();
    let retry_at = e.next_emergency;
    loop {
        e.platform.tick();
        if e.platform.now() >= retry_at {
            break;
        }
        e.run_until_quiescent(1);
        assert!(!e.platform.calls[start..].contains(&Call::LoadAnchor));
    }
    e.run_until_quiescent(1);
    assert_emergency(&mut e);
}

#[test]
fn stuck_without_join_intent_never_loads_emergency() {
    let mut e = fresh();
    e.enter_stuck();
    e.platform.calls.clear();
    elapse(&mut e, 3);
    assert!(!e.status().emergency_blocking_verified);
    assert!(!e.platform.calls.iter().any(|c| matches!(
        c,
        Call::LoadAnchor | Call::EnablePf | Call::Acquire | Call::Spawn | Call::Flush
    )));
    leave(&mut e, 1);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
}

#[test]
fn internal_error_skips_unpersisted_startup_join_replay() {
    let mut snapshot = Snapshot::initial(Some(501), None);
    snapshot.internal_error = Some(snapshot::InternalError::Other);
    snapshot
        .requests
        .try_push(RequestRecord {
            id: 1,
            kind: snapshot::RequestKind::Join,
        })
        .unwrap();
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    drive(&mut e, 500);
    e.run_until_quiescent(100);
    assert!(!e.machine.durable().join_intended);
    assert!(e.machine.pending().is_none());
    assert!(e.snapshot.internal_error.is_some());
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.platform.calls.contains(&Call::RemoveAnchor));
    assert!(e.platform.anchor.is_none());
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|c| matches!(c, Call::Acquire | Call::Spawn))
    );
}

#[test]
fn first_join_rejected_acquire_is_retained_through_emergency_leave_and_reconciled() {
    for backpressure in [false, true] {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::AcquireReference);
        if backpressure {
            e.capacity = 1;
            e.queue.push_back(QueueEvent::Request(Request {
                id: 9,
                kind: RequestKind::Join,
            }));
            e.dispatch(Step::AcquireReference);
        } else {
            e.dispatch(Step::AcquireReference);
            let QueueEvent::Completion(mut c) = e.queue.pop_front().unwrap() else {
                panic!("completion")
            };
            c.event = Event::Completed(Step::LoadJoined);
            e.reject_fallback = true;
            e.complete(c);
        }
        let token = match e
            .retained_completion
            .as_ref()
            .unwrap()
            .1
            .acquired
            .as_ref()
            .unwrap()
            .key
        {
            ReferenceEntry::Token(t) => t,
            ReferenceEntry::Acquire(_) => panic!("token"),
        };
        assert!(e.committed.machine.reference_intent.is_some());
        e.run_until_quiescent(100);
        assert_emergency(&mut e);
        leave(&mut e, 2);
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
        assert!(e.platform.anchor.is_none());
        assert!(
            e.snapshot
                .references
                .iter()
                .flatten()
                .any(|r| r.key == ReferenceEntry::Token(token) && !r.release_unknown)
        );
        let mut p = e.into_platform();
        p.restart();
        let mut e = Engine::start(p).unwrap();
        drive(&mut e, 500);
        assert!(!e.machine.durable().join_intended);
        assert!(e.platform.anchor.is_none());
        assert!(!e.platform.tokens.contains_key(&token));
        assert_eq!(e.status().accounting, Accounting::default());
    }
}

#[test]
fn reboot_start_failures_reach_emergency_after_ownership_gate() {
    // Test-only result faults exercise the actual error branches, including
    // representability failures a valid present-day core cannot naturally emit.
    for cause in (0..11).filter(|cause| *cause != 2 && *cause != 3) {
        let mut p = joined().into_platform();
        let old = read_snapshot(&mut p, Copy::A);
        p.mutate(Mutation::Reboot);
        p.calls.clear();
        let mut e = match cause {
            0 | 1 | 10 => {
                let mut snapshot = old.clone();
                if cause == 0 {
                    snapshot.references = [None, None];
                }
                p.acquire_instance_lock().unwrap();
                let install = Some(p.install.clone());
                Engine::start_selected(
                    p,
                    install,
                    StartDecision::Trust {
                        source: Copy::A,
                        seq: if cause == 1 {
                            snapshot::COUNTER_MAX - 1
                        } else if cause == 10 {
                            snapshot::COUNTER_MAX
                        } else {
                            1
                        },
                        snapshot,
                        repair: None,
                    },
                    [false, false],
                )
            }
            _ => {
                let mut e = Engine::start(p).unwrap();
                assert_eq!(
                    e.platform.anchor.as_deref(),
                    Some(policy::render_lockdown().as_str())
                );
                assert!(e.platform.enabled);
                match cause {
                    4..=7 => {
                        e.snapshot = old.clone();
                        e.committed = old.clone();
                        e.mode = Mode::Starting;
                        e.start_fault = Some(match cause {
                            4 => StartFault::Validate,
                            5 => StartFault::Settlement,
                            6 => StartFault::Conversion,
                            _ => StartFault::Encode,
                        });
                        e.finish_start();
                    }
                    8 => {
                        e.snapshot.references = old.references.clone();
                        e.adopt(
                            Machine::restart(Durable {
                                join_intended: true,
                                ..Durable::default()
                            }),
                            &Event::Join,
                            None,
                        );
                    }
                    _ => {
                        e.reject_fallback = true;
                        e.rejected_completion();
                    }
                }
                e
            }
        };
        assert_eq!(e.mode, Mode::Stuck, "cause {cause}");
        e.run_until_quiescent(100);
        assert_emergency(&mut e);
        assert!(!e.platform.calls.contains(&Call::Spawn));
    }
}

#[test]
fn emergency_open_start_fence_keeps_recovery_unknown_sweeping_until_closed() {
    let mut p = joined().into_platform();
    let mut snapshot = read_snapshot(&mut p, Copy::A);
    let mut proc = p.procs[&14].clone();
    p.mutate(Mutation::Reboot);
    proc.path = None;
    proc.exe = None;
    proc.start.seconds = 1;
    p.procs.insert(proc.pid, proc);
    snapshot.references = [None, None]; // Constructor Stuck bypass used to skip the decision.
    p.calls.clear();
    let install = Some(p.install.clone());
    p.acquire_instance_lock().unwrap();
    let mut e = Engine::start_selected(
        p,
        install,
        StartDecision::Trust {
            source: Copy::A,
            seq: 1,
            snapshot,
            repair: None,
        },
        [false, false],
    );
    e.run_until_quiescent(100);
    assert_ne!(e.start_fence, StartFence::Closed);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.platform.enabled);
    assert!(!e.status().emergency_blocking_verified);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    e.platform.procs.get_mut(&14).unwrap().path = Some("/foreign/ordinary".into());
    for _ in 0..20 {
        e.platform.tick();
    }
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
}

#[test]
fn stuck_leave_behind_other_queued_events_is_not_lost() {
    let mut e = fresh();
    e.mode = Mode::Starting;
    e.queue.push_back(QueueEvent::Timer);
    leave(&mut e, 1);
    e.enter_stuck();
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    assert_eq!(e.status().text, "left");
    assert!(
        e.committed
            .requests
            .iter()
            .any(|r| r.id == 1 && r.kind == snapshot::RequestKind::LeaveDone)
    );
    assert!(e.platform.anchor.is_none());
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
}

#[test]
fn seven_queued_joins_leave_room_for_leave_and_all_cancellations() {
    let mut e = fresh();
    for id in 1..=7 {
        e.submit(Request {
            id,
            kind: RequestKind::Join,
        })
        .unwrap();
    }
    assert!(
        e.submit(Request {
            id: 8,
            kind: RequestKind::Join
        })
        .is_err()
    );
    leave(&mut e, 9);
    drive(&mut e, 500);
    assert!(e.request_completed(9));
    for id in 1..=7 {
        assert!(
            e.committed
                .requests
                .iter()
                .any(|r| r.id == id && r.kind == snapshot::RequestKind::JoinCancelled)
        );
    }
}

#[test]
fn emergency_uses_full_global_verification_and_never_publishes_protected() {
    for fault in 0..4 {
        let mut e = if fault == 3 {
            joined()
        } else {
            reacquiring_after_verified_enforcement()
        };
        match fault {
            0 => e.platform.main_rules = "pass quick all\nanchor \"com.apple/*\" all\n".into(),
            1 => e.platform.firewall_qualification = None,
            2 => e.platform.inject_persistent(Call::Collect, Fault::ReadFail),
            _ => {
                e.platform.skipped.insert("en0".parse().unwrap());
            }
        }
        e.platform.calls.clear();
        e.enter_stuck();
        e.run_until_quiescent(100);
        assert_eq!(e.mode, Mode::Stuck);
        assert_eq!(
            e.status().enforcement,
            Verdict::NotProtected(Reason::Observation("internal"))
        );
        assert!(!e.status().emergency_blocking_verified);
        elapse(&mut e, 2);
        assert!(!e.status().emergency_blocking_verified);
        assert!(!e.platform.calls.contains(&Call::Spawn));
        if fault == 3 {
            assert!(!e.verified_enforcement);
            let rules = e.platform.main_rules.clone();
            leave(&mut e, 2);
            drive(&mut e, 500);
            assert_eq!(e.status().text, "left");
            assert!(e.committed.requests.iter().any(|request| {
                request.id == 2 && request.kind == snapshot::RequestKind::LeaveDone
            }));
            assert_eq!(e.platform.main_rules, rules);
        }
    }
}

#[test]
fn pending_leave_replayed_or_resubmitted_in_stuck_always_starts_fixed_cleanup() {
    for resubmit in [false, true] {
        let mut e = joined();
        e.snapshot
            .requests
            .try_push(RequestRecord {
                id: 2,
                kind: snapshot::RequestKind::Leave,
            })
            .unwrap();
        e.enter_stuck();
        if resubmit {
            // Also cover an existing pending identity, rather than just new ids.
            e.stuck_leave = None;
            e.submit(Request {
                id: 2,
                kind: RequestKind::Leave,
            })
            .unwrap();
        }
        assert!(e.emergency_revoked);
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
        assert_eq!(e.status().text, "left");
        assert!(e.platform.anchor.is_none());
        assert!(
            e.committed
                .requests
                .iter()
                .any(|r| r.id == 2 && r.kind == snapshot::RequestKind::LeaveDone)
        );
    }
}

#[test]
fn emergency_precedes_internal_error_persistence_and_storage_retries() {
    let mut e = reacquiring_after_verified_enforcement();
    e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
    let start = e.platform.calls.len();
    e.enter_stuck();
    // Re-enable during the hung reservation disturbs this frame. Containment
    // precedes storage, but proof requires the next fresh frame.
    assert!(e.platform.enabled);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.emergency_frame_disturbed);
    assert!(!e.status().emergency_blocking_verified);
    let calls = &e.platform.calls[start..];
    let load = calls.iter().position(|c| *c == Call::LoadAnchor).unwrap();
    let write = calls
        .iter()
        .position(|c| *c == Call::Write(Copy::A))
        .unwrap();
    assert!(load < write);
    assert!(e.storage_blocked);
    assert!(e.platform.now() > e.emergency_last_load_at.unwrap());
    e.platform.anchor = None;
    e.next_storage = 0;
    e.next_emergency = 0;
    e.run_until_quiescent(100);
    // The hanging commit advanced time past the preceding load's cadence:
    // positive absence must reload immediately, ahead of storage retries.
    assert_emergency(&mut e);
    e.platform.calls.clear();
    e.platform.anchor = None;
    e.next_emergency = 0;
    e.run_until_quiescent(100);
    // Another removal in this same second must not create a load storm.
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    assert!(!e.status().emergency_blocking_verified);
    elapse(&mut e, 1);
    assert_emergency(&mut e);
}

#[test]
fn stuck_invalidates_prior_blocking_on_global_hook_drift() {
    let mut e = joined();
    assert!(e.verified_enforcement);
    e.platform.main_rules = "pass quick all\nanchor \"com.apple/*\" all\n".into();
    e.platform.calls.clear();
    e.enter_stuck();
    assert!(!e.verified_enforcement);
    assert!(!e.status().blocking_verified);
    assert!(!e.status().emergency_blocking_verified);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(scupper_core::mac::policy::render_lockdown().as_str())
    );
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::Observation("internal"))
    );
}

#[test]
fn emergency_ownership_is_cached_across_a_glitchy_process_inventory() {
    let mut e = reacquiring_after_verified_enforcement();
    e.enter_stuck();
    assert_emergency(&mut e);
    let own = e.platform.procs.remove(&e.platform.helper.pid).unwrap();
    e.platform.anchor = None;
    elapse(&mut e, 1);
    assert_emergency(&mut e);
    assert!(!e.startup_invariant_failed);
    e.platform.procs.insert(own.pid, own);
    e.platform.anchor = None;
    elapse(&mut e, 1);
    assert_emergency(&mut e);
}

#[test]
fn verified_stuck_preserves_joined_on_unknown_read_failure_and_tunnel_repair() {
    for fault in 0..3 {
        let mut e = joined();
        let anchor = e.platform.anchor.clone();
        e.enter_stuck();
        e.platform.calls.clear();
        match fault {
            0 => e.platform.inventory_race = true,
            1 => e.platform.inject(Call::Collect, 1, Fault::ReadFail),
            _ => {
                let pid = *e.platform.children.keys().next().unwrap();
                e.platform.procs.get_mut(&pid).unwrap().state = ProcState::Zombie;
            }
        }
        // Force exactly the next scheduled full observation.
        e.next_full = 0;
        elapse(&mut e, 1);
        assert_eq!(e.platform.anchor, anchor, "fault {fault}");
        assert!(
            !e.platform.calls.contains(&Call::LoadAnchor),
            "fault {fault}"
        );
        assert!(e.verified_enforcement);
        if fault == 2 {
            assert!(e.platform.children.is_empty());
            assert!(e.platform.calls.contains(&Call::ReapChildren));
            assert!(
                !e.platform
                    .procs
                    .values()
                    .any(|p| p.state == ProcState::Zombie)
            );
        }
        e.platform.inventory_race = false;
        e.platform.mutate(Mutation::PfDisable);
        elapse(&mut e, 1);
        assert_emergency(&mut e);
    }
}

#[test]
fn verified_stuck_uses_one_second_cheap_and_five_second_full_cadence() {
    let mut e = joined();
    e.enter_stuck();
    e.platform.calls.clear();
    elapse(&mut e, 4);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Cheap)
            .count(),
        4
    );
    assert!(!e.platform.calls.contains(&Call::Collect));
    elapse(&mut e, 1);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Collect)
            .count(),
        1
    );
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.status().blocking_verified);
}

#[test]
fn emergency_status_expires_without_driving_and_recovers_on_full_verification() {
    let mut e = reacquiring_after_verified_enforcement();
    e.enter_stuck();
    assert_emergency(&mut e);
    for _ in 0..(e.timings.max_age + 1) * 20 {
        e.platform.tick();
    }
    assert!(!e.status().emergency_blocking_verified);
    assert!(!e.status().blocking_verified);
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
}

#[test]
fn failed_startup_ownership_exits_without_shared_state_writes() {
    for bad_group in [false, true] {
        let mut p = joined().into_platform();
        if bad_group {
            p.helper.pgid = 99;
        } else {
            p.procs.get_mut(&p.helper.pid).unwrap().ppid = 22;
        }
        let copies = p.copies.clone();
        p.calls.clear();
        p.signals.clear();
        let Err(failure) = Engine::start(p) else {
            panic!("ownership accepted")
        };
        assert_eq!(failure.outcome, StartOutcome::StartupInvariantFailed);
        assert_eq!(
            failure.platform.calls.first(),
            Some(&Call::AcquireInstanceLock)
        );
        assert_eq!(failure.platform.signals, []);
        assert_eq!(failure.platform.copies, copies);
        // D-3 may contain before the first inventory proves ownership invalid.
        assert_eq!(
            failure.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert!(!failure.platform.calls.iter().any(|c| matches!(
            c,
            Call::CreateControlSocket
                | Call::Write(_)
                | Call::Create(_)
                | Call::Spawn
                | Call::Acquire
                | Call::RemoveAnchor
                | Call::Kill(..)
                | Call::KillProcess(..)
                | Call::CleanupDns
                | Call::CleanupArtifacts
                | Call::CleanupRoutes(_)
        )));
    }
}

#[test]
fn leave_partial_clear_failure_never_reinstalls_emergency_after_late_load() {
    let mut e = reacquiring_after_verified_enforcement();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    e.enter_stuck();
    e.platform.unkillable.clear();
    // Leave reaps the late load first. Then one ClearIntent observation fails.
    e.platform.inject(Call::LeaveRoutes, 1, Fault::ReadFail);
    leave(&mut e, 2);
    e.run_until_quiescent(100);
    assert!(
        e.stuck_leave
            .as_ref()
            .is_some_and(|steps| steps.contains(&Step::ClearIntent))
    );
    assert!(e.platform.anchor.is_none());
    let removed = e
        .platform
        .calls
        .iter()
        .rposition(|c| *c == Call::RemoveAnchor)
        .unwrap();
    elapse(&mut e, 5);
    assert!(!e.platform.calls[removed + 1..].contains(&Call::LoadAnchor));
    assert!(e.platform.anchor.is_none());
    assert_eq!(e.outcome, Outcome::Exit0);
}

fn reboot_before_emergency() -> Engine<FakePlatform> {
    let mut p = joined().into_platform();
    p.mutate(Mutation::Reboot);
    let mut e = Engine::start(p).unwrap();
    // Startup now performs D-3 containment. Isolate the subsequent independent
    // emergency under test by modelling a fresh external disable/anchor loss.
    assert!(e.platform.enabled);
    e.platform.mutate(Mutation::PfDisable);
    e.anonymous_enable_confirmed = false;
    e.platform.anchor = None;
    e.emergency_loaded = false;
    e.emergency_readback = None;
    e.emergency_baseline = None;
    e.emergency_states_clean_at = None;
    e.emergency_last_load_at = None;
    e.emergency_next_reload = e.platform.now();
    e.emergency_next_flush = e.platform.now();
    e.emergency_needs_reference = false;
    e.next_emergency = 0;
    e.platform.calls.clear();
    e
}

#[test]
fn emergency_unqualified_reboot_and_unparseable_readback_enable_and_flush_without_claim() {
    for fault in 0..3 {
        let mut e = reboot_before_emergency();
        match fault {
            0 => e.platform.firewall_qualification = None,
            1 => e.platform.anchor_readback = Some("unknown pf output\n".into()),
            _ => e.platform.inject(Call::ReadAnchor, 1, Fault::ReadFail),
        }
        e.enter_stuck();
        assert!(e.platform.enabled, "fault {fault}");
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert!(e.platform.calls.contains(&Call::Flush));
        assert!(!e.status().emergency_blocking_verified);
    }
}

#[test]
fn emergency_parsed_wrong_policy_or_target_enables_without_claim_and_reloads() {
    for readback in ["pass all\n", "anchor \"foreign/target\" all\n"] {
        let mut e = reboot_before_emergency();
        e.platform.anchor_readback = Some(readback.into());
        e.enter_stuck();
        elapse(&mut e, 2);
        assert!(e.platform.enabled);
        assert!(!e.status().emergency_blocking_verified);
        assert!(e.platform.calls.contains(&Call::Flush));
        assert!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count()
                >= 2
        );
    }
}

#[test]
fn emergency_already_enabled_reserves_missing_counted_reference() {
    let mut e = reboot_before_emergency();
    e.platform.mutate(Mutation::ForeignEnable);
    e.enter_stuck();
    assert_emergency(&mut e);
    let acquire = e
        .platform
        .calls
        .iter()
        .position(|call| *call == Call::Acquire)
        .unwrap();
    assert!(e.platform.calls[..acquire].contains(&Call::Write(Copy::A)));
    assert!(e.platform.calls[..acquire].contains(&Call::Write(Copy::B)));
    assert!(!e.platform.calls.contains(&Call::EnablePf));
}

#[test]
fn emergency_reserves_before_acquiring_and_leave_releases_only_known_token() {
    let mut e = reboot_before_emergency();
    e.enter_stuck();
    assert_emergency(&mut e);
    let acquire = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Acquire)
        .unwrap();
    assert!(e.platform.calls[..acquire].contains(&Call::Write(Copy::A)));
    assert!(e.platform.calls[..acquire].contains(&Call::Write(Copy::B)));
    let token = match e.emergency_references.last().unwrap().key {
        ReferenceEntry::Token(token) => token,
        other @ ReferenceEntry::Acquire(_) => panic!("expected token, got {other:?}"),
    };
    assert!(
        e.committed
            .references
            .iter()
            .flatten()
            .any(|r| r.key == ReferenceEntry::Token(token))
    );
    e.platform.mutate(Mutation::ForeignEnable);
    let foreign: Vec<_> = e
        .platform
        .tokens
        .keys()
        .copied()
        .filter(|t| *t != token)
        .collect();
    leave(&mut e, 2);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    let mut p = e.into_platform();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert!(!e.platform.tokens.contains_key(&token));
    assert!(e.platform.calls.contains(&Call::Release(token)));
    for token in foreign {
        assert!(e.platform.tokens.contains_key(&token));
        assert!(!e.platform.calls.contains(&Call::Release(token)));
    }
}

#[test]
fn emergency_failing_storage_timeout_retries_without_accumulating_references() {
    for effect in [false, true] {
        let mut e = reboot_before_emergency();
        e.platform
            .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
        e.platform.inject(
            Call::Acquire,
            1,
            Fault::ToolHang {
                reaped: true,
                effect,
            },
        );
        e.enter_stuck();
        assert!(e.emergency_unreserved_consumed);
        elapse(&mut e, 1);
        assert!(e.platform.enabled);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Acquire)
                .count(),
            1
        );
        assert!(e.platform.calls.contains(&Call::EnablePf));
        assert_eq!(e.platform.tokens.len(), usize::from(effect));
        elapse(&mut e, 10);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Acquire)
                .count(),
            1
        );
        assert_eq!(e.platform.tokens.len(), usize::from(effect));
        assert_emergency(&mut e);
    }
}

#[test]
fn observed_repair_and_both_readback_failures_clear_published_blocking() {
    for cause in 0..3 {
        let mut e = joined();
        let event = match cause {
            0 => Event::Observed {
                context: e.machine.context(),
                form: Form::Joined,
                verdict: Verdict::Repair(verify::Action::Rejoin),
            },
            1 => Event::Failed(Reason::Observation("anchor readback mismatch")),
            _ => Event::Failed(Reason::Observation("anchor missing on readback")),
        };
        // Isolate the invalidation boundary: the frozen reducer must not
        // independently erase the proof and conceal a reverted clause.
        e.enter_stuck();
        assert!(e.status().blocking_verified);
        e.invalidate_blocking(&event);
        assert!(!e.status().blocking_verified, "cause {cause}");
        assert!(!e.verified_enforcement, "cause {cause}");
    }
}

#[test]
fn constructor_stuck_retries_unknown_ownership_then_caches_the_definite_result() {
    let mut p = joined().into_platform();
    let mut snapshot = read_snapshot(&mut p, Copy::A);
    p.mutate(Mutation::Reboot);
    snapshot.references = [None, None];
    p.inject(Call::Processes, 1, Fault::Incomplete);
    let install = Some(p.install.clone());
    p.acquire_instance_lock().unwrap();
    let mut e = Engine::start_selected(
        p,
        install,
        StartDecision::Trust {
            source: Copy::A,
            seq: 1,
            snapshot,
            repair: None,
        },
        [false, false],
    );
    assert_eq!(e.mode, Mode::Stuck);
    assert!(!e.startup_invariant_checked);
    assert!(!e.startup_invariant_failed);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.platform.enabled);
    assert_eq!(e.status().text, "containment attempted; safety unproven");
    for _ in 0..20 {
        e.platform.tick();
    }
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
    assert!(e.startup_invariant_checked);
    e.platform.procs.remove(&e.platform.helper.pid);
    e.platform.anchor = None;
    for _ in 0..20 {
        e.platform.tick();
    }
    e.run_until_quiescent(100);
    assert_emergency(&mut e);
    assert!(!e.startup_invariant_failed);
}

#[test]
fn emergency_spawn_timeout_consumes_nothing_and_retries_reserved_or_unreserved() {
    for failing_storage in [false, true] {
        let mut e = reboot_before_emergency();
        if failing_storage {
            e.platform
                .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
        }
        e.platform
            .inject(Call::Acquire, 1, Fault::NotStartedTimeout);
        e.enter_stuck();
        assert!(e.platform.enabled);
        assert!(e.platform.calls.contains(&Call::EnablePf));
        assert!(!e.emergency_unreserved_consumed);
        assert_eq!(
            e.snapshot.validate().unwrap().uncertain_acquires,
            [0_u64; 0]
        );
        assert_eq!(e.emergency_references, []);
        e.platform.mutate(Mutation::PfDisable);
        elapse(&mut e, 1);
        assert_emergency(&mut e);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Acquire)
                .count(),
            2
        );
        assert_eq!(e.platform.tokens.len(), 1);
        assert_eq!(e.emergency_unreserved_consumed, failing_storage);
        if !failing_storage {
            assert!(
                e.committed
                    .references
                    .iter()
                    .flatten()
                    .any(|e| matches!(e.key, ReferenceEntry::Token(_)))
            );
        }
    }
}

#[test]
fn emergency_unreserved_success_external_disable_uses_reference_free_enable() {
    let mut e = reboot_before_emergency();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.enter_stuck();
    assert_emergency(&mut e);
    assert!(e.emergency_unreserved_consumed);
    e.platform.mutate(Mutation::PfDisable);
    elapse(&mut e, 1);
    assert_emergency(&mut e);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Acquire)
            .count(),
        1
    );
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert!(e.platform.tokens.is_empty());
    elapse(&mut e, 10);
    assert!(e.platform.tokens.is_empty());
}

#[test]
fn emergency_reserved_ambiguity_keeps_accounting_and_cap_uses_no_reference() {
    let mut e = reboot_before_emergency();
    e.platform
        .inject_persistent(Call::Acquire, Fault::ToolFail { effect: false });
    e.enter_stuck();
    assert!(!e.emergency_unreserved_consumed);
    // Startup already reserved a normal acquisition. The emergency's
    // committed ambiguous attempt fills the other durable slot.
    let durable = e.snapshot.validate().unwrap();
    assert_eq!(durable.uncertain_acquires.len(), 1);
    assert_eq!(reference_keys(&durable).len(), 2);
    assert!(
        e.committed
            .references
            .iter()
            .flatten()
            .any(|entry| matches!(entry.key, ReferenceEntry::Acquire(_)))
    );
    assert!(!e.emergency_unreserved_consumed);
    elapse(&mut e, 1);
    assert_emergency(&mut e);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Acquire)
            .count(),
        1
    );
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert!(e.platform.tokens.is_empty());
    assert!(!e.emergency_unreserved_consumed);
    elapse(&mut e, 10);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Acquire)
            .count(),
        1
    );
}

#[test]
fn emergency_pf_info_read_failure_never_authorizes_acquisition() {
    for first_acquire in [false, true] {
        let mut e = reboot_before_emergency();
        e.platform.firewall_qualification = None;
        if first_acquire {
            e.enter_stuck();
        }
        e.platform
            .inject_persistent(Call::PfInfo, Fault::Incomplete);
        e.enter_stuck();
        elapse(&mut e, 1);
        assert!(e.platform.enabled);
        assert!(e.platform.calls.contains(&Call::EnablePf));
        elapse(&mut e, 10);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Acquire)
                .count(),
            usize::from(first_acquire)
        );
        assert_eq!(e.platform.tokens.len(), usize::from(first_acquire));
        // A disable hidden from pf-info is repaired without another token.
        // The cheap observation also resets the flush backoff on this transition.
        e.platform.calls.clear();
        e.platform.mutate(Mutation::PfDisableKeepTokens);
        elapse(&mut e, 1);
        assert!(e.platform.enabled);
        assert!(!e.platform.calls.contains(&Call::Acquire));
        assert!(e.platform.calls.contains(&Call::Flush));
        assert_eq!(e.platform.tokens.len(), usize::from(first_acquire));
    }
}

#[test]
fn emergency_macos_update_implicit_state_enables_lockdown_without_claim() {
    let mut e = reboot_before_emergency();
    e.platform.firewall_qualification = None;
    let text = policy::render_lockdown().as_str().replace("no state", "");
    assert!(parse::pf_rules(&text).is_ok());
    assert!(
        verify::capture_lockdown_baseline(
            &text,
            &verify::Normalization {
                expanded_lists: true,
                named_icmp: true,
                implicit_tcp_flags: true,
            }
        )
        .is_err_and(
            |error| error == verify::CaptureError::Unqualified(verify::UnqualifiedKind::StateFlags)
        )
    );
    e.platform.anchor_readback = Some(text);
    e.enter_stuck();
    assert!(e.platform.enabled);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.platform.calls.contains(&Call::Flush));
    assert!(!e.status().emergency_blocking_verified);
}

#[test]
fn verified_stuck_sustained_unknown_expires_joined_and_loads_lockdown() {
    let mut e = joined();
    e.platform.inject_persistent(Call::Collect, Fault::ReadFail);
    e.platform.inject_persistent(Call::Cheap, Fault::ReadFail);
    e.platform.inventory_race = true;
    e.enter_stuck();
    e.platform.calls.clear();
    elapse(&mut e, 14);
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    // The previous proof must not hide an external disable during the gap.
    e.platform.mutate(Mutation::PfDisable);
    elapse(&mut e, 2);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.platform.enabled);
    assert!(!e.status().blocking_verified);
}

#[test]
fn emergency_unverifiable_flushes_with_d3_backoff() {
    for fault in 0..3 {
        let mut e = reboot_before_emergency();
        match fault {
            0 => e.platform.firewall_qualification = None,
            1 => e.platform.anchor_readback = Some("unparseable output".into()),
            _ => e.platform.inject_persistent(Call::Collect, Fault::ReadFail),
        }
        e.enter_stuck();
        assert!(e.platform.enabled);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Flush)
                .count(),
            1
        );
        // Initial flush, then 1, 2, 4, 8, 16, 32, 60-second gaps.
        for gap in [1, 2, 4, 8, 16, 32, 60, 60] {
            e.platform.calls.clear();
            elapse(&mut e, gap - 1);
            assert!(
                !e.platform.calls.contains(&Call::Flush),
                "fault {fault}, gap {gap}"
            );
            elapse(&mut e, 1);
            assert_eq!(
                e.platform
                    .calls
                    .iter()
                    .filter(|c| **c == Call::Flush)
                    .count(),
                1,
                "fault {fault}, gap {gap}"
            );
            // Stable raw unsupported text no longer reloads.
            assert!(
                !e.platform.calls.contains(&Call::LoadAnchor),
                "fault {fault}"
            );
        }
        // Observed loss resets the flush delay and reinstalls Lockdown.
        e.platform.calls.clear();
        e.platform.anchor = None;
        elapse(&mut e, 1);
        assert!(e.platform.calls.contains(&Call::LoadAnchor));
        assert!(e.platform.calls.contains(&Call::Flush));
        e.platform.calls.clear();
        elapse(&mut e, 1);
        assert!(e.platform.calls.contains(&Call::Flush));
        if fault == 2 {
            // A fresh verified block resets D3. A later sustained observation
            // gap must resume with a one-second flush interval.
            e.platform.clear_faults();
            elapse(&mut e, 1);
            assert_emergency(&mut e);
            e.platform.inject_persistent(Call::Collect, Fault::ReadFail);
            elapse(&mut e, 16);
            e.platform.calls.clear();
            elapse(&mut e, 1);
            assert!(e.platform.calls.contains(&Call::Flush));
        }
    }
}

#[test]
fn emergency_foreign_unqualified_content_is_reloaded_after_verified_lockdown() {
    for text in [
        "pass out quick all\nblock drop quick all\n",
        "pass out quick inet6 proto ipv6-icmp all icmp6-type routersol no state\nblock drop quick all\n",
    ] {
        let mut e = reboot_before_emergency();
        e.platform
            .firewall_qualification
            .as_mut()
            .unwrap()
            .normalization
            .named_icmp = false;
        e.enter_stuck();
        assert_emergency(&mut e);
        assert!(matches!(
            verify::capture_lockdown_baseline(
                text,
                &e.platform
                    .firewall_qualification
                    .as_ref()
                    .unwrap()
                    .normalization
            ),
            Err(verify::CaptureError::Unqualified(_))
        ));
        e.platform.anchor = Some(text.into());
        e.platform.calls.clear();
        elapse(&mut e, 6);
        assert!(e.platform.calls.contains(&Call::LoadAnchor));
        assert_emergency(&mut e);
    }
}

#[test]
fn emergency_double_observation_failure_reloads_with_d3_backoff() {
    let mut e = reboot_before_emergency();
    e.platform.firewall_qualification = None;
    e.enter_stuck();
    e.platform.inject_persistent(Call::Cheap, Fault::ReadFail);
    e.platform
        .inject_persistent(Call::ReadAnchor, Fault::ReadFail);
    e.platform.anchor = None;
    for gap in [1, 2, 4, 8, 16, 32, 60, 60] {
        e.platform.calls.clear();
        elapse(&mut e, gap - 1);
        assert!(!e.platform.calls.contains(&Call::LoadAnchor), "gap {gap}");
        elapse(&mut e, 1);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::LoadAnchor)
                .count(),
            1,
            "gap {gap}"
        );
        assert!(e.platform.enabled);
        assert!(!e.status().emergency_blocking_verified);
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        e.platform.anchor = None;
    }
}

mod generated;

mod followups;

mod mutants_group1;

mod mutants_group2;

mod legacy_ported;

mod ledger_review;

mod containment;
mod leave_storage;

#[test]
fn image_history_is_durable_before_spawn_and_failed_write_prevents_spawn() {
    for fail in [false, true] {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::StartChild);
        e.platform.calls.clear();
        let uuid = e
            .platform
            .image_uuid(Path::new(CHILD_PATH), Deadline(1000))
            .unwrap();
        if fail {
            e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteFail);
        }
        let result = e.execute(Step::StartChild);
        if fail {
            assert_eq!(result, Err(SysError::Failed("image history write failed")));
            assert!(!e.platform.calls.contains(&Call::Spawn));
        } else {
            assert!(result.is_ok());
            assert!(e.committed.image_history.uuids.contains(&uuid));
            let spawn = e
                .platform
                .calls
                .iter()
                .position(|c| *c == Call::Spawn)
                .unwrap();
            assert!(e.platform.calls[..spawn].contains(&Call::Write(Copy::B)));
            assert!(
                read_snapshot(&mut e.platform, Copy::A)
                    .image_history
                    .uuids
                    .contains(&uuid)
            );
        }
    }
}

#[test]
fn image_spawn_mismatch_is_recorded_killed_and_failed() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::StartChild);
    e.platform.spawn_image = Some(platform::ImageId {
        uuid: [88; 16],
        uniqueid: 1234,
    });
    assert_eq!(
        e.execute(Step::StartChild),
        Err(SysError::Failed("spawn image mismatch"))
    );
    assert!(e.committed.image_history.uuids.contains(&[88; 16]));
    let child = e.platform.spawned_children().last().unwrap();
    assert!(e.platform.signals.contains(&(child.pid, child.start_time)));
    assert!(
        read_snapshot(&mut e.platform, Copy::A)
            .image_history
            .uuids
            .contains(&[88; 16])
    );
}

#[test]
fn image_upgrade_retains_spawned_build_after_crash_and_pin_replacement() {
    let e = joined();
    let child = e.child.clone().unwrap();
    let history = e.snapshot.image_history.clone();
    let u1 = child.image.unwrap().uuid;
    assert!(history.uuids.contains(&u1));
    let mut p = e.into_platform();
    p.abandon_process_group = true;
    p.restart();
    p.image_uuids.insert(CHILD_PATH.into(), Some([22; 16]));
    let proc = p.procs.get_mut(&child.pid).unwrap();
    proc.path = None;
    proc.exe = None;
    proc.name = Some("renamed-child".into()); // isolate history from the name guard
    p.signals.clear();
    let d = Deadline(p.now() + 2);
    let result = platform::sweep_with_history(
        &mut p,
        Path::new(CHILD_PATH),
        &[],
        &history,
        &[],
        &Timings::default(),
        d,
    );
    assert!(matches!(result, Sweep::Incomplete(ref e) if e.pid == Some(child.pid)));
    assert_eq!(p.signals, []);
}

#[test]
fn image_proven_reboot_resets_and_persists_history() {
    let mut snapshot = Snapshot::initial(Some(501), None);
    let mut p = fixture(&snapshot);
    snapshot.image_history = snapshot::ImageHistory::empty_for_boot(p.boot.clone().unwrap());
    snapshot.image_history.record([44; 16]);
    p = fixture(&snapshot);
    p.mutate(Mutation::Reboot);
    let mut e = Engine::start(p).unwrap();
    assert!(e.snapshot.image_history.known);
    assert_eq!(e.snapshot.image_history.boot, e.platform.boot);
    assert_eq!(e.snapshot.image_history.uuids.len(), 0);
    assert_eq!(
        read_snapshot(&mut e.platform, Copy::A).image_history,
        e.snapshot.image_history
    );
}

#[test]
fn image_sweep_and_leave_require_all_pin_uuids() {
    let mut e = fresh();
    e.snapshot.image_history =
        snapshot::ImageHistory::empty_for_boot(e.platform.boot.clone().unwrap());
    let mut proc = e.platform.procs[&e.platform.helper.pid].clone();
    proc.pid = 888;
    proc.pgid = 888;
    proc.ppid = 2;
    proc.path = None;
    proc.exe = None;
    proc.image = Some(platform::ImageId {
        uuid: [88; 16],
        uniqueid: 888,
    });
    proc.name = Some("foreign".into());
    e.platform.procs.insert(888, proc);
    e.platform.image_uuids.insert("/sbin/pfctl".into(), None);
    assert!(!e.confirm_sweep());
    assert!(matches!(e.last_sweep, Some(Sweep::Incomplete(ref e)) if e.pid == Some(888)));
    assert_eq!(
        e.verify_clear_intent(),
        Err(SysError::Failed("owned process inventory"))
    );
    assert_eq!(e.platform.signals, []);
    e.platform.image_uuids.remove(Path::new("/sbin/pfctl"));
    assert!(e.confirm_sweep());
    assert!(e.verify_clear_intent().is_ok());
    assert_eq!(e.platform.signals, []);
}

mod r3b_fix1;

mod r7;
