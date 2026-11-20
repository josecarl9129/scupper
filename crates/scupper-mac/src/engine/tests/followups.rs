//! Run 7b: ownership, crash prefixes and sustained queue/storage regressions.
use super::*;
use crate::platform::Setting;
use std::time::Instant;

fn refused(
    result: Result<Engine<FakePlatform>, StartError<FakePlatform>>,
) -> StartError<FakePlatform> {
    match result {
        Err(failure) => failure,
        Ok(_) => panic!("startup unexpectedly accepted"),
    }
}

#[test]
fn instance_lock_is_first_and_socket_creation_requires_it() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    assert!(p.create_control_socket().is_err());
    p.calls.clear();
    let e = Engine::start(p).unwrap();
    assert_eq!(e.platform.calls[0], Call::AcquireInstanceLock);
    let socket = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::CreateControlSocket)
        .unwrap();
    let install = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Install)
        .unwrap();
    assert!(socket > install);
    let write = e
        .platform
        .calls
        .iter()
        .position(|c| matches!(c, Call::Write(_) | Call::Create(_)))
        .unwrap();
    assert!(socket < write);
}

#[test]
fn competing_invalid_incarnation_cannot_write_leave_signal_or_spawn_then_starts_after_exit() {
    let mut first = joined();
    let child = first.child.clone().unwrap();
    let mut second = first.platform.competing_instance();
    second.helper.pgid = 99; // Would also fail the startup ownership invariant.
    let copies = first.platform.copies.clone();
    let failure = refused(Engine::start(second));
    assert_eq!(failure.outcome, StartOutcome::InstanceContended);
    assert_eq!(failure.platform.calls, [Call::AcquireInstanceLock]);
    assert_eq!(failure.platform.copies, copies);
    assert_eq!(failure.platform.signals, []);
    assert!(first.platform.children.contains_key(&child.pid));
    assert_eq!(
        first.platform.procs[&child.pid].state,
        platform::ProcState::Running
    );
    // There is no engine/transport on which the stray can submit Leave or write
    // an invalid identity into the pair. The only exposed result is refusal.
    leave(&mut first, 2);
    drive(&mut first, 500);
    assert!(first.request_completed(2));
    let mut first_platform = first.into_platform();
    first_platform.crash(); // Release only at process exit, after cleanup.
    first_platform.restart();
    first_platform.calls.clear();
    let mut second = Engine::start(first_platform).unwrap();
    drive(&mut second, 500);
    assert_eq!(second.platform.calls[0], Call::AcquireInstanceLock);
    assert!(!second.machine.durable().join_intended);
    assert!(
        second
            .committed
            .requests
            .iter()
            .any(|r| r.id == 2 && r.kind == snapshot::RequestKind::LeaveDone)
    );
    second
        .submit(Request {
            id: 3,
            kind: RequestKind::Join,
        })
        .unwrap();
    drive(&mut second, 500);
    assert!(second.request_completed(3));
}

#[test]
fn instance_lock_survives_exit0_until_process_teardown() {
    let mut first = fresh();
    first.enter_stuck();
    leave(&mut first, 1);
    assert_eq!(first.run_until_quiescent(100), Outcome::Exit0);
    let second = first.platform.competing_instance();
    let failure = refused(Engine::start(second));
    assert_eq!(failure.outcome, StartOutcome::InstanceContended);
    assert_eq!(failure.platform.calls, [Call::AcquireInstanceLock]);
    drop(first);
    assert!(Engine::start(failure.platform).is_ok());
}

#[test]
fn ownership_failure_before_recovery_or_pair_repair_never_writes() {
    for recovery in [false, true] {
        let mut p = fixture(&Snapshot::initial(Some(501)));
        p.mutate(Mutation::MissingCopy(Copy::B));
        if recovery {
            p.mutate(Mutation::CopyRot(Copy::A));
        }
        p.helper.pgid = 99;
        let copies = p.copies.clone();
        p.calls.clear();
        let failure = refused(Engine::start(p));
        assert_eq!(failure.outcome, StartOutcome::StartupInvariantFailed);
        assert_eq!(failure.platform.copies, copies);
        assert_eq!(writes(&failure.platform), 0);
        assert_eq!(failure.platform.signals, []);
    }
}

#[test]
fn raw_anchor_change_repairs_within_one_second_despite_stale_qualification_or_backoff() {
    let started = Instant::now();
    for observation in ["pass all\n", "pass out quick all\nblock drop quick all\n"] {
        for qualified in [false, true] {
            let mut e = reboot_before_emergency();
            if !qualified {
                e.platform.firewall_qualification = None;
            }
            e.platform.anchor_readback = Some(observation.into());
            e.enter_stuck();
            elapse(&mut e, 130);
            assert_eq!(e.emergency_readback.as_deref(), Some(observation));
            e.platform.anchor_readback = None;
            e.platform.anchor = Some("pass in quick all\n".into());
            let changed_at = e.platform.now();
            e.platform.calls.clear();
            elapse(&mut e, 1);
            assert_eq!(e.platform.now() - changed_at, 1);
            assert!(e.platform.calls.contains(&Call::LoadAnchor));
            assert_eq!(
                e.platform.anchor.as_deref(),
                Some(policy::render_lockdown().as_str())
            );
            if qualified {
                assert_emergency(&mut e);
            }
        }
    }
    eprintln!("TABLE RawDrift: 4 rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn persistent_absence_bounds_reload_and_flush_churn_to_one_hz() {
    let started = Instant::now();
    let mut e = reboot_before_emergency();
    e.platform.main_rules.clear(); // The absent hook keeps cheap absence true.
    e.enter_stuck();
    let mut loads = 0;
    let mut flushes = 0;
    for _ in 0..60 {
        e.platform.calls.clear();
        elapse(&mut e, 1);
        let count = |call| e.platform.calls.iter().filter(|c| **c == call).count();
        assert_eq!(count(Call::LoadAnchor), 1);
        assert_eq!(count(Call::Flush), 1);
        loads += count(Call::LoadAnchor);
        flushes += count(Call::Flush);
        assert!(!e.status().emergency_blocking_verified);
    }
    assert_eq!((loads, flushes), (60, 60));
    eprintln!("TABLE AbsentHook: 60 seconds, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn sustained_blocked_storage_external_disable_uses_one_unreserved_acquire() {
    let started = Instant::now();
    let mut e = reboot_before_emergency();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.block_storage();
    e.enter_stuck();
    assert!(e.emergency_unreserved_consumed);
    e.platform.calls.clear();
    for _ in 0..60 {
        e.platform.mutate(Mutation::PfDisable);
        elapse(&mut e, 1);
        assert!(e.platform.enabled);
        assert!(e.platform.tokens.len() <= 1);
        assert!(e.snapshot.references.iter().flatten().count() <= 2);
    }
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::EnablePf)
            .count(),
        60
    );
    eprintln!("TABLE ExternalDisable: 60 seconds, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashBoundary {
    LoadBeforeReservation,
    ReservationCopyA,
    ReservationPairBeforeAcquire,
    ReservedAcquireBeforeFlush,
    UnreservedAcquireBeforeFlush,
    EnableBeforeFlush,
    ReloadWithFailedCommit,
    RemoveAnchorBeforeClearIntent,
    InternalErrorFailed,
    InternalErrorTorn,
    InternalErrorSplit,
    InternalErrorPending,
    InternalErrorFailedDurable,
    InternalErrorPair,
}
const CRASH_BOUNDARIES: [CrashBoundary; 14] = [
    CrashBoundary::LoadBeforeReservation,
    CrashBoundary::ReservationCopyA,
    CrashBoundary::ReservationPairBeforeAcquire,
    CrashBoundary::ReservedAcquireBeforeFlush,
    CrashBoundary::UnreservedAcquireBeforeFlush,
    CrashBoundary::EnableBeforeFlush,
    CrashBoundary::ReloadWithFailedCommit,
    CrashBoundary::RemoveAnchorBeforeClearIntent,
    CrashBoundary::InternalErrorFailed,
    CrashBoundary::InternalErrorTorn,
    CrashBoundary::InternalErrorSplit,
    CrashBoundary::InternalErrorPending,
    CrashBoundary::InternalErrorFailedDurable,
    CrashBoundary::InternalErrorPair,
];

#[allow(clippy::too_many_lines)] // Keep exact capture and crash-point preconditions adjacent.
fn crash_prefix(boundary: CrashBoundary) -> FakePlatform {
    let mut e = if matches!(
        boundary,
        CrashBoundary::InternalErrorFailed
            | CrashBoundary::InternalErrorTorn
            | CrashBoundary::InternalErrorSplit
            | CrashBoundary::InternalErrorPending
            | CrashBoundary::InternalErrorFailedDurable
            | CrashBoundary::InternalErrorPair
    ) {
        joined()
    } else {
        reboot_before_emergency()
    };
    let capture = match boundary {
        CrashBoundary::LoadBeforeReservation | CrashBoundary::ReloadWithFailedCommit => {
            Call::LoadAnchor
        }
        CrashBoundary::ReservationCopyA => Call::Write(Copy::A),
        CrashBoundary::ReservationPairBeforeAcquire => Call::Write(Copy::B),
        CrashBoundary::ReservedAcquireBeforeFlush | CrashBoundary::UnreservedAcquireBeforeFlush => {
            Call::Acquire
        }
        CrashBoundary::EnableBeforeFlush => Call::EnablePf,
        CrashBoundary::RemoveAnchorBeforeClearIntent => Call::RemoveAnchor,
        _ => Call::Write(
            if matches!(
                boundary,
                CrashBoundary::InternalErrorSplit | CrashBoundary::InternalErrorPair
            ) {
                Copy::B
            } else {
                Copy::A
            },
        ),
    };
    match boundary {
        CrashBoundary::UnreservedAcquireBeforeFlush
        | CrashBoundary::EnableBeforeFlush
        | CrashBoundary::ReloadWithFailedCommit => {
            e.platform
                .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
            e.block_storage();
            e.emergency_unreserved_consumed = boundary == CrashBoundary::EnableBeforeFlush;
        }
        CrashBoundary::InternalErrorFailed => e
            .platform
            .inject_persistent(Call::Write(Copy::A), Fault::WriteFail),
        CrashBoundary::InternalErrorTorn => e
            .platform
            .inject_persistent(Call::Write(Copy::A), Fault::TornWrite(64)),
        CrashBoundary::InternalErrorSplit => e
            .platform
            .inject_persistent(Call::Write(Copy::B), Fault::WriteFail),
        CrashBoundary::InternalErrorPending => e
            .platform
            .inject_persistent(Call::Write(Copy::A), Fault::FailedPending),
        CrashBoundary::InternalErrorFailedDurable => e
            .platform
            .inject_persistent(Call::Write(Copy::A), Fault::FailedDurable),
        _ => {}
    }
    if matches!(
        boundary,
        CrashBoundary::RemoveAnchorBeforeClearIntent | CrashBoundary::ReloadWithFailedCommit
    ) {
        if boundary == CrashBoundary::ReloadWithFailedCommit {
            e.next_storage = 0;
        }
        e.enter_stuck();
        if boundary == CrashBoundary::ReloadWithFailedCommit {
            assert!(e.emergency_commit_failed);
            e.platform.anchor = Some("pass all\n".into());
        }
    }
    e.platform.capture_after(capture, 1);
    match boundary {
        CrashBoundary::RemoveAnchorBeforeClearIntent => {
            leave(&mut e, 50);
            e.run_until_quiescent(100);
        }
        CrashBoundary::ReloadWithFailedCommit => elapse(&mut e, 1),
        _ => e.enter_stuck(),
    }
    let captured = e
        .platform
        .take_capture()
        .unwrap_or_else(|| panic!("no capture at {boundary:?}"));
    let tail = captured.calls.last().unwrap();
    assert_eq!(*tail, capture, "{boundary:?}");
    if matches!(
        boundary,
        CrashBoundary::ReservedAcquireBeforeFlush
            | CrashBoundary::UnreservedAcquireBeforeFlush
            | CrashBoundary::EnableBeforeFlush
    ) {
        assert!(captured.enabled);
        if boundary == CrashBoundary::EnableBeforeFlush {
            assert!(captured.calls.contains(&Call::Flush), "{boundary:?}");
            assert_eq!(captured.states, [] as [bool; 0]);
        } else {
            assert!(!captured.calls.contains(&Call::Flush), "{boundary:?}");
        }
    }
    if boundary == CrashBoundary::LoadBeforeReservation {
        assert!(captured.anchor.is_some());
        assert!(!captured.enabled);
        assert_eq!(writes(&captured), 0);
    }
    if boundary == CrashBoundary::RemoveAnchorBeforeClearIntent {
        assert!(captured.anchor.is_none());
    }
    captured
}

#[test]
#[allow(clippy::too_many_lines)] // Each crash boundary retains its restart/accounting assertions.
fn generated_emergency_and_stuck_crash_restart_matrix() {
    let started = Instant::now();
    let mut rows = 0;
    for boundary in CRASH_BOUNDARIES {
        for reboot in [false, true] {
            let row = (boundary, reboot);
            let mut p = crash_prefix(boundary);
            let before_tokens: Vec<_> = p.tokens.keys().copied().collect();
            let reservation = matches!(
                boundary,
                CrashBoundary::ReservationCopyA
                    | CrashBoundary::ReservationPairBeforeAcquire
                    | CrashBoundary::ReservedAcquireBeforeFlush
            );
            let hold = matches!(
                boundary,
                CrashBoundary::ReservationCopyA
                    | CrashBoundary::ReservationPairBeforeAcquire
                    | CrashBoundary::ReservedAcquireBeforeFlush
                    | CrashBoundary::RemoveAnchorBeforeClearIntent
                    | CrashBoundary::InternalErrorSplit
                    | CrashBoundary::InternalErrorFailedDurable
                    | CrashBoundary::InternalErrorPair
            ) || boundary == CrashBoundary::InternalErrorPending && !reboot;
            if reboot {
                p.mutate(Mutation::Reboot);
            } else {
                p.restart();
            }
            p.calls.clear();
            let restart_at = p.now();
            p.calls.clear();
            let mut next = Engine::start(p).unwrap();
            assert_eq!(next.platform.calls[0], Call::AcquireInstanceLock, "{row:?}");
            assert_eq!(next.machine.durable().hold, hold, "{row:?}");
            assert!(next.machine.durable().join_intended, "{row:?}");
            if reservation && !reboot {
                // The pre-emergency normal acquisition was already reserved;
                // emergency reserve-before-effect consumes the second slot.
                assert_eq!(next.status().accounting.uncertain, 2, "{row:?}");
                assert_eq!(
                    reference_keys(&next.snapshot.validate().unwrap())
                        .iter()
                        .filter(|key| matches!(key, ReferenceEntry::Acquire(_)))
                        .count(),
                    2,
                    "{row:?}"
                );
            }
            let known = matches!(
                boundary,
                CrashBoundary::RemoveAnchorBeforeClearIntent
                    | CrashBoundary::InternalErrorFailed
                    | CrashBoundary::InternalErrorTorn
                    | CrashBoundary::InternalErrorSplit
                    | CrashBoundary::InternalErrorPending
                    | CrashBoundary::InternalErrorFailedDurable
                    | CrashBoundary::InternalErrorPair
            );
            if known && !reboot {
                assert_eq!(next.status().accounting.held, 1, "{row:?}");
            }
            let lockdown = policy::render_lockdown();
            let pre = policy::render_pre_tunnel(&next.platform.install.config.inputs);
            let bound = 1;
            let expected = if hold {
                lockdown.as_str()
            } else {
                pre.as_str()
            };
            let mut blocked_at = None;
            for _ in 0..(bound + 1) * 20 {
                tick(&mut next);
                if next.platform.enabled
                    && next.platform.calls.contains(&Call::LoadAnchor)
                    && next.platform.anchor.as_deref() == Some(expected)
                {
                    blocked_at = Some(next.platform.now());
                    break;
                }
            }
            assert!(
                blocked_at.is_some_and(|at| at - restart_at <= bound),
                "latency {row:?}"
            );
            oracle(&mut next);
            drive(&mut next, 800);
            oracle(&mut next);
            elapse(&mut next, 2);
            assert_ne!(next.mode, Mode::Stuck, "{row:?}");
            assert!(next.platform.enabled, "{row:?}");
            let joined = policy::render_joined(&next.inputs().unwrap());
            let text = next.platform.anchor.as_deref().unwrap();
            assert!(
                if hold {
                    text == lockdown.as_str()
                } else {
                    text == pre.as_str() || text == joined.as_str()
                },
                "policy {row:?}: {text}"
            );
            // Check token evidence against the kernel oracle, independently of
            // status flags. Unknown acquisitions never confer release authority.
            for evidence in next.snapshot.references.iter().flatten() {
                if let ReferenceEntry::Token(token) = evidence.key {
                    let live = next.platform.tokens.get(&token).unwrap();
                    let fingerprint = evidence.fingerprint.as_ref().unwrap();
                    assert_eq!(
                        (live.pid, live.timestamp),
                        (fingerprint.pid, fingerprint.timestamp),
                        "{row:?}"
                    );
                }
            }
            assert!(
                next.snapshot.references.iter().flatten().count() <= 2,
                "{row:?}"
            );
            if hold {
                assert!(!next.platform.calls.contains(&Call::Spawn), "{row:?}");
                assert!(
                    next.submit(Request {
                        id: 60,
                        kind: RequestKind::Join
                    })
                    .is_err()
                );
            }
            if reservation && !reboot {
                assert_eq!(next.status().accounting.uncertain, 2, "{row:?}");
                for token in &before_tokens {
                    assert!(
                        !next.platform.calls.contains(&Call::Release(*token)),
                        "{row:?}"
                    );
                }
            }
            // A fixed Leave, including the restart-under-hold case, restores
            // connectivity. It cannot invent release authority for an ioctl
            // whose token was not recorded before the crash.
            leave(&mut next, 61);
            drive(&mut next, 800);
            assert!(
                !next.machine.durable().join_intended,
                "{row:?}: {:?}, {:?}, {:?}",
                next.machine.durable(),
                next.machine.plan(),
                next.mode
            );
            assert!(next.platform.anchor.is_none(), "{row:?}");
            assert_eq!(next.status().text, "left", "{row:?}");
            if reservation && !reboot {
                assert_eq!(next.status().accounting.uncertain, 2, "{row:?}");
            }
            if boundary == CrashBoundary::UnreservedAcquireBeforeFlush && !reboot {
                for token in &before_tokens {
                    assert!(next.platform.tokens.contains_key(token), "{row:?}");
                    assert!(
                        !next.platform.calls.contains(&Call::Release(*token)),
                        "{row:?}"
                    );
                }
            }
            if known && !reboot {
                assert_eq!(next.status().accounting.held, 0, "{row:?}");
                for token in &before_tokens {
                    assert!(
                        next.platform.calls.contains(&Call::Release(*token)),
                        "{row:?}"
                    );
                    assert!(!next.platform.tokens.contains_key(token), "{row:?}");
                }
            }
            if reboot {
                assert_eq!(next.status().accounting.uncertain, 0, "{row:?}");
                assert_eq!(next.status().accounting.held, 0, "{row:?}");
            }
            rows += 1;
        }
    }
    assert_eq!(rows, 28);
    eprintln!("TABLE CrashRestart: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn requests_after_exit0_preserve_left_and_fresh_leave_completes() {
    let mut e = reboot_before_emergency();
    e.enter_stuck();
    leave(&mut e, 80);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    e.platform.calls.clear();
    let committed = e.committed.clone();
    for id in [80, 81, 82] {
        assert!(
            e.submit(Request {
                id,
                kind: RequestKind::Join
            })
            .is_err()
        );
        e.process(QueueEvent::Request(Request {
            id,
            kind: RequestKind::Join,
        }));
        assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    }
    e.submit(Request {
        id: 80,
        kind: RequestKind::Leave,
    })
    .unwrap();
    assert_eq!(e.committed, committed);
    assert_eq!(e.platform.calls, []);
    leave(&mut e, 83);
    assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
    assert!(
        e.committed
            .requests
            .iter()
            .any(|r| r.id == 83 && r.kind == snapshot::RequestKind::LeaveDone)
    );
    assert!(!e.platform.calls.iter().any(|call| matches!(
        call,
        Call::Acquire | Call::EnablePf | Call::LoadAnchor | Call::Spawn
    )));
    assert!(e.platform.anchor.is_none());
}

#[test]
fn generated_queued_joins_full_window_cancel_without_losing_admitted_ids() {
    let started = Instant::now();
    let mut rows = 0;
    for active in 0..=5 {
        let mut e = fresh();
        e.snapshot.requests = (1..=8)
            .map(|id| RequestRecord {
                id,
                kind: if id <= active {
                    snapshot::RequestKind::Join
                } else {
                    snapshot::RequestKind::JoinDone
                },
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert!(e.commit_if_changed());
        let queued: Vec<_> = (100..100 + 7 - active).collect();
        for id in &queued {
            e.submit(Request {
                id: *id,
                kind: RequestKind::Join,
            })
            .unwrap();
        }
        assert!(
            e.submit(Request {
                id: 200,
                kind: RequestKind::Join
            })
            .is_err()
        );
        e.platform.calls.clear();
        leave(&mut e, 201);
        assert!(!e.queue.iter().any(|event| matches!(
            event,
            QueueEvent::Request(Request {
                kind: RequestKind::Join,
                ..
            })
        )));
        let admitted: Vec<_> = (1..=active).chain(queued).collect();
        for id in &admitted {
            assert!(
                e.snapshot
                    .requests
                    .iter()
                    .any(|r| r.id == *id && r.kind == snapshot::RequestKind::JoinCancelled),
                "active={active}, id={id}"
            );
        }
        assert_eq!(e.snapshot.requests.len(), 8);
        drive(&mut e, 500);
        assert!(e.request_completed(201));
        assert!(
            !e.platform
                .calls
                .iter()
                .any(|c| matches!(c, Call::Acquire | Call::Spawn))
        );
        let mut p = e.into_platform();
        p.restart();
        let mut next = Engine::start(p).unwrap();
        for id in admitted {
            assert!(
                next.committed
                    .requests
                    .iter()
                    .any(|r| r.id == id && r.kind == snapshot::RequestKind::JoinCancelled)
            );
            assert!(
                next.submit(Request {
                    id,
                    kind: RequestKind::Join
                })
                .is_err()
            );
        }
        assert!(!next.machine.durable().join_intended);
        rows += 1;
    }
    assert_eq!(rows, 6);
    eprintln!("TABLE QueuedJoins: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn old_eight_join_snapshot_fallback_sacrifices_only_oldest_replay_for_leave() {
    let mut snapshot = Snapshot::initial(Some(501));
    snapshot.requests = (1..=8)
        .map(|id| RequestRecord {
            id,
            kind: snapshot::RequestKind::Join,
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    assert_eq!(e.machine.pending(), Some(Step::PersistIntent));
    e.platform.calls.clear();
    assert!(
        e.submit(Request {
            id: 9,
            kind: RequestKind::Join
        })
        .is_err()
    );
    leave(&mut e, 10);
    assert_eq!(e.snapshot.requests.len(), 8);
    assert!(!e.snapshot.requests.iter().any(|r| r.id == 1));
    for id in 2..=8 {
        assert!(
            e.snapshot
                .requests
                .iter()
                .any(|r| r.id == id && r.kind == snapshot::RequestKind::JoinCancelled)
        );
    }
    assert!(
        e.snapshot
            .requests
            .iter()
            .any(|r| r.id == 10 && r.kind == snapshot::RequestKind::Leave)
    );
    drive(&mut e, 500);
    assert!(e.request_completed(10));
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|c| matches!(c, Call::Acquire | Call::Spawn))
    );
}

#[test]
fn generated_sixty_second_persist_intent_supersession_and_storage_heal() {
    let started = Instant::now();
    for repeated_boundary in [false, true] {
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
        let entered = e.platform.now();
        let mut superseded = 0;
        e.platform.calls.clear();
        for second in 0..60 {
            assert_eq!(e.platform.now() - entered, second);
            if repeated_boundary && e.waiting.is_none() {
                // Stress the pure PersistIntent completion boundary repeatedly.
                // The ordinary scheduler row below correctly stalls D dispatch
                // after the first failure. No resource effect is fabricated.
                assert_eq!(e.machine.pending(), Some(Step::PersistIntent));
                e.dispatch(Step::PersistIntent);
                let QueueEvent::Completion(c) = e.queue.pop_front().unwrap() else {
                    panic!("completion")
                };
                e.complete(c);
                assert!(e.waiting.is_some());
            }
            let since = e.platform.now();
            let waiting = e.waiting.is_some();
            e.enqueue(QueueEvent::Monitor(Event::InvalidateObservations { since }))
                .unwrap();
            e.run_until_quiescent(1);
            if waiting {
                superseded += 1;
            }
            assert!(e.waiting.is_none());
            assert_eq!(e.machine.pending(), Some(Step::PersistIntent));
            assert_eq!(e.mode, Mode::PersistBlocked);
            assert!(!e.machine.durable().join_intended);
            assert!(e.unexposed_acquires.len() <= 2);
            assert!(e.machine.durable().uncertain_acquires.len() <= 2);
            assert!(!e.request_completed(1));
            elapse(&mut e, 1);
            assert_ne!(e.mode, Mode::Stuck);
        }
        assert_eq!(superseded, if repeated_boundary { 60 } else { 1 });
        assert!(!e.platform.calls.iter().any(|c| matches!(
            c,
            Call::Acquire | Call::Spawn | Call::LoadAnchor | Call::Flush
        )));
        e.platform.clear_faults();
        elapse(&mut e, 65);
        assert_eq!(e.mode, Mode::Normal);
        assert_eq!(e.unexposed_acquires, [] as [u64; 0]);
        assert!(e.request_completed(1));
        assert!(
            matches!(e.status().enforcement, Verdict::Protected(ref p) if p.form() == Form::Joined)
        );
    }
    eprintln!("TABLE PersistIntent60s: 2 rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn deferred_ownership_failure_never_repairs_or_commits_recovery() {
    for recovery in [false, true] {
        let mut p = fixture(&Snapshot::initial(Some(501)));
        p.mutate(Mutation::MissingCopy(Copy::B));
        if recovery {
            p.mutate(Mutation::CopyRot(Copy::A));
        }
        let copies = p.copies.clone();
        p.inject(Call::Processes, 1, Fault::Incomplete);
        let mut e = Engine::start(p).unwrap();
        assert_eq!(e.mode, Mode::Starting);
        assert_eq!(writes(&e.platform), 0);
        assert!(!e.platform.calls.contains(&Call::CreateControlSocket));
        e.platform
            .procs
            .get_mut(&e.platform.helper.pid)
            .unwrap()
            .ppid = 22;
        assert_eq!(e.run_until_quiescent(100), Outcome::StartupInvariantFailed);
        assert_eq!(e.platform.copies, copies);
        assert_eq!(writes(&e.platform), 0);
        assert_eq!(e.platform.signals, []);
        assert!(!e.platform.calls.contains(&Call::CreateControlSocket));
    }
}

#[test]
fn held_emergency_keeps_two_debts_and_revokes_before_leave_then_rearms_on_new_join() {
    let mut p = crash_prefix(CrashBoundary::ReservationPairBeforeAcquire);
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    for tick_index in 0..30 * 20 {
        e.platform.tick();
        e.enqueue(QueueEvent::Timer).unwrap();
        e.run_until_quiescent(4);
        assert!(
            e.status().emergency_blocking_verified,
            "tick {tick_index}, now {}, verified {}, proof {:?}, next full {}, next emergency {}, plan {:?}",
            e.platform.now(),
            e.verified_enforcement,
            e.emergency_proof,
            e.next_full,
            e.next_emergency,
            e.machine.plan()
        );
        oracle(&mut e);
    }
    assert!(e.machine.durable().hold);
    assert!(e.status().emergency_blocking_verified);
    assert_eq!(e.status().accounting.uncertain, 2);
    assert!(e.platform.tokens.is_empty());
    assert!(!e.platform.calls.contains(&Call::Acquire));
    e.execute(Step::LoadPreTunnel).unwrap();
    assert!(!e.status().emergency_blocking_verified);
    elapse(&mut e, 1);
    assert!(e.status().emergency_blocking_verified);
    leave(&mut e, 1001);
    assert!(e.emergency_revoked);
    assert!(!e.status().emergency_blocking_verified);
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left");
    assert_eq!(e.status().accounting.uncertain, 2);
    assert!(e.platform.anchor.is_none());
    e.platform.calls.clear();
    elapse(&mut e, 2);
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    e.submit(Request {
        id: 1002,
        kind: RequestKind::Join,
    })
    .unwrap();
    tick(&mut e);
    assert!(!e.emergency_revoked);
    assert_eq!(e.outcome, Outcome::Continue);
    for _ in 0..100 {
        if e.machine.durable().join_intended {
            break;
        }
        tick(&mut e);
    }
    assert!(e.machine.durable().join_intended);
    let at = e.platform.now();
    e.platform.anchor = None;
    e.enter_stuck();
    elapse(&mut e, 1);
    assert!(e.platform.now() - at <= 1);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.platform.enabled);
}

#[test]
fn socket_failure_blocks_without_references_across_restarts_and_retries_service() {
    for reboot in [false, true] {
        for stuck in [false, true] {
            let mut p = joined().into_platform();
            if reboot {
                p.mutate(Mutation::Reboot);
            } else {
                p.restart();
            }
            for _ in 0..3 {
                p.calls.clear();
                p.inject_persistent(Call::CreateControlSocket, Fault::NoSpace);
                let start = p.now();
                let mut e = Engine::start(p).unwrap();
                if stuck {
                    e.enter_stuck();
                }
                elapse(&mut e, 1);
                assert!(e.platform.now() - start <= 1);
                assert!(e.platform.enabled);
                assert_eq!(
                    e.platform.anchor.as_deref(),
                    Some(policy::render_lockdown().as_str()),
                    "reboot={reboot} stuck={stuck}: {:?}; fence {:?}; ownership {:?}",
                    e.platform.calls,
                    e.start_fence,
                    (e.startup_invariant_checked, e.startup_invariant_failed)
                );
                assert!(e.platform.calls.contains(&Call::EnablePf));
                assert!(e.platform.calls.contains(&Call::Flush));
                assert!(e.platform.calls.contains(&Call::Collect));
                assert!(!e.platform.calls.contains(&Call::Acquire));
                assert!(!e.platform.calls.contains(&Call::Spawn));
                assert!(
                    e.platform
                        .safety_events
                        .iter()
                        .any(|event| matches!(event, platform::SafetyEvent::SocketFailed(_)))
                );
                let sockets = e
                    .platform
                    .calls
                    .iter()
                    .filter(|c| **c == Call::CreateControlSocket)
                    .count();
                elapse(&mut e, 3);
                assert_eq!(
                    e.platform
                        .calls
                        .iter()
                        .filter(|c| **c == Call::CreateControlSocket)
                        .count(),
                    sockets + 3
                );
                p = e.into_platform();
                p.restart();
            }
            p.inject(Call::CreateControlSocket, 1, Fault::NoSpace);
            let mut e = Engine::start(p).unwrap();
            elapse(&mut e, 1);
            assert!(e.control_socket_created);
            assert_ne!(e.mode, Mode::Starting);
            oracle(&mut e);
        }
    }
}

fn assert_lockless_effects(p: &FakePlatform) {
    for forbidden in ["write", "sweep", "kill", "spawn", "-E", "socket"] {
        assert!(
            !p.calls.iter().any(|call| match forbidden {
                "write" => matches!(call, Call::Write(_) | Call::Create(_)),
                "sweep" => matches!(
                    call,
                    Call::Processes | Call::Kill(..) | Call::KillProcess(..)
                ),
                "kill" => matches!(call, Call::Kill(..) | Call::KillProcess(..)),
                "spawn" => *call == Call::Spawn,
                "-E" => matches!(call, Call::Acquire | Call::Release(_)),
                "socket" => *call == Call::CreateControlSocket,
                _ => unreachable!(),
            }),
            "forbidden {forbidden}: {:?}",
            p.calls
        );
    }
}

#[test]
fn lockless_error_intent_product_is_read_only_and_reloads_within_one_second() {
    for fault in [
        Fault::ReadFail,
        Fault::LockTimedOut,
        Fault::LockUnknown,
        Fault::LockInterrupted,
    ] {
        for intent in 0..10 {
            let mut snapshot = Snapshot::initial(Some(501));
            snapshot.machine.join_intended = intent == 0 || intent == 8;
            snapshot.machine.hold = intent == 6;
            snapshot.internal_error = (intent == 7).then_some(snapshot::InternalError::Other);
            snapshot.machine.leave_requested = matches!(intent, 4 | 5);
            snapshot.machine.leaving = intent == 5;
            let mut p = if intent == 6 {
                // Left+hold is semantically invalid by the snapshot contract.
                // Preserve a valid checksum so this tests that uncertain intent,
                // rather than physical corruption, still requests containment.
                use sha2::{Digest, Sha256};
                let mut p = fixture(&Snapshot::initial(Some(501)));
                let body = serde_json::to_vec(&snapshot).unwrap();
                let mut bytes = Box::new([0; snapshot::COPY_BYTES]);
                bytes[..8].copy_from_slice(&snapshot::MAGIC);
                bytes[8..12].copy_from_slice(&snapshot::FORMAT.to_le_bytes());
                bytes[12..20].copy_from_slice(&1_u64.to_le_bytes());
                bytes[20..24].copy_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
                let end = 24 + body.len();
                bytes[24..end].copy_from_slice(&body);
                let digest = Sha256::digest(&bytes[..end]);
                bytes[end..end + 32].copy_from_slice(&digest);
                for copy in &mut p.copies {
                    copy.durable = Some(bytes.clone());
                }
                p
            } else {
                fixture(&snapshot)
            };
            if matches!(intent, 2 | 8) {
                // Two individually valid Left copies with different generations.
                p.copies[1].durable = Some(snapshot::encode(2, &snapshot).unwrap());
            }
            if intent == 9 {
                p.mutate(Mutation::MissingCopy(Copy::B));
            }
            if intent == 3 {
                p.inject_persistent(Call::Read(Copy::A), Fault::ReadFail);
            }
            if fault == Fault::LockInterrupted {
                p.inject(Call::AcquireInstanceLock, 1, fault);
                p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
            } else {
                p.inject_persistent(Call::AcquireInstanceLock, fault);
            }
            let copies = p.copies.clone();
            let start = p.now();
            p.calls.clear();
            let mut e = Engine::start(p).unwrap();
            if fault == Fault::LockInterrupted {
                assert_eq!(&e.platform.calls[..2], &[Call::AcquireInstanceLock; 2]);
            }
            assert!(e.lockless.is_some());
            assert_eq!(e.platform.enabled, intent != 1);
            if intent != 1 {
                assert!(e.platform.now() - start <= 1);
                assert_eq!(
                    e.platform.anchor.as_deref(),
                    Some(policy::render_lockdown().as_str())
                );
                assert!(e.platform.calls.contains(&Call::EnablePf));
                assert!(e.platform.calls.contains(&Call::Flush));
                assert!(e.platform.calls.contains(&Call::Collect));
                assert!(e.platform.safety_events.iter().any(|event| matches!(
                    event,
                    platform::SafetyEvent::LocklessVerdict(verdict) if matches!(verdict.as_ref(), Ok(Verdict::Protected(_)))
                )));
                for anchor in [None, Some("pass all\n".into())] {
                    e.platform.anchor = anchor;
                    let at = e.platform.now();
                    elapse(&mut e, 1);
                    assert!(e.platform.now() - at <= 1);
                    assert_eq!(
                        e.platform.anchor.as_deref(),
                        Some(policy::render_lockdown().as_str())
                    );
                }
            }
            assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
            assert!(!e.status().emergency_blocking_verified);
            assert_eq!(e.platform.copies, copies);
            assert_lockless_effects(&e.platform);
            assert!(
                e.submit(Request {
                    id: 1,
                    kind: RequestKind::Leave
                })
                .is_err()
            );
            assert!(e.enqueue(QueueEvent::Timer).is_err());
            assert!(e.queue.is_empty());
            oracle(&mut e);
        }
    }
}

#[test]
fn lockless_retries_structural_errors_at_bounded_cadence_then_starts_without_disabling_pf() {
    let mut state = Snapshot::initial(Some(501));
    state.machine.join_intended = true;
    for failures in [1, 2, 5] {
        let mut p = if failures == 5 {
            let mut p = joined().into_platform();
            p.crash();
            p.restart();
            assert_eq!(p.tokens.len(), 1);
            p
        } else {
            fixture(&state)
        };
        for _ in 0..failures {
            p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
        }
        let mut e = Engine::start(p).unwrap();
        let mut previous = e.platform.now();
        let mut attempts = 1;
        for _ in 0..30 * 20 {
            let before = e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::AcquireInstanceLock)
                .count();
            tick(&mut e);
            assert!(e.platform.enabled);
            let after = e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::AcquireInstanceLock)
                .count();
            if after > before {
                let at = e.platform.now();
                assert!((1..=5).contains(&(at - previous)));
                previous = at;
                attempts += 1;
            }
            if e.lockless.is_none() {
                break;
            }
        }
        assert_eq!(attempts, failures + 1);
        assert!(e.lockless.is_none());
        assert!(e.control_socket_created);
        for _ in 0..500 {
            tick(&mut e);
            assert!(
                e.platform.enabled,
                "pf gap after handoff, failures={failures}"
            );
        }
        assert!(e.request_completed(1) || matches!(e.status().enforcement, Verdict::Protected(_)));
    }
}

#[test]
fn lockless_handoff_reaps_delayed_load_before_normal_policy_and_no_later_overwrite() {
    let mut snapshot = Snapshot::initial(Some(501));
    snapshot.machine.join_intended = true;
    let mut p = fixture(&snapshot);
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.platform.unreaped.len(), 1);
    e.platform.release_unreaped();
    let handoff = e.platform.calls.len();
    elapse(&mut e, 1);
    assert!(e.lockless.is_none());
    let calls = &e.platform.calls[handoff..];
    let drained = calls.iter().position(|call| *call == Call::Reap).unwrap();
    let normal_start = calls
        .iter()
        .position(|call| *call == Call::Install)
        .unwrap();
    assert!(drained < normal_start);
    drive(&mut e, 500);
    let expected = policy::render_joined(&e.inputs().unwrap());
    assert_eq!(e.platform.anchor.as_deref(), Some(expected.as_str()));
    e.platform.calls.clear();
    elapse(&mut e, 3);
    assert_eq!(e.platform.anchor.as_deref(), Some(expected.as_str()));
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
}

#[test]
fn stuck_deferred_ownership_product_decides_with_and_without_join_intent() {
    for join in [false, true] {
        for pass in [false, true] {
            let mut snapshot = Snapshot::initial(Some(501));
            snapshot.machine.join_intended = join;
            let mut p = fixture(&snapshot);
            p.acquire_instance_lock().unwrap();
            p.calls.clear();
            p.inject(Call::Processes, 1, Fault::Incomplete);
            let install = Some(p.install.clone());
            let copies = p.copies.clone();
            let mut e = Engine::start_selected(
                p,
                install,
                StartDecision::Trust {
                    source: Copy::A,
                    seq: snapshot::COUNTER_MAX,
                    snapshot,
                    repair: None,
                },
                [false, false],
            );
            assert_eq!(e.mode, Mode::Stuck);
            assert!(!e.startup_invariant_checked);
            if !pass {
                e.platform
                    .procs
                    .get_mut(&e.platform.helper.pid)
                    .unwrap()
                    .ppid = 22;
            }
            let outcome = e.run_until_quiescent(100);
            assert!(e.startup_invariant_checked);
            if pass {
                assert_eq!(outcome, Outcome::Continue);
                assert!(e.control_socket_created);
                if join {
                    elapse(&mut e, 1);
                    assert!(e.platform.enabled);
                }
                leave(&mut e, 55);
                e.run_until_quiescent(100);
                assert!(e.platform.calls.contains(&Call::CreateControlSocket));
            } else {
                assert_eq!(outcome, Outcome::StartupInvariantFailed);
                assert_eq!(e.platform.copies, copies);
                assert_eq!(writes(&e.platform), 0);
                assert_eq!(e.platform.signals, []);
                assert!(!e.platform.calls.contains(&Call::CreateControlSocket));
                let contender = e.platform.competing_instance();
                assert_eq!(
                    refused(Engine::start(contender)).outcome,
                    StartOutcome::InstanceContended
                );
                let next = e.platform.competing_instance();
                drop(e);
                assert!(Engine::start(next).is_ok());
            }
        }
    }
}

#[test]
fn persistent_reference_free_enable_failure_still_persists_internal_error_on_its_cadence() {
    let mut e = reboot_before_emergency();
    e.platform
        .inject_persistent(Call::PfInfo, Fault::Incomplete);
    e.platform
        .inject_persistent(Call::EnablePf, Fault::ToolFail { effect: false });
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.enter_stuck();
    assert_eq!(writes(&e.platform), 0);
    elapse(&mut e, 1);
    assert_eq!(writes(&e.platform), 1);
    elapse(&mut e, 1);
    assert_eq!(writes(&e.platform), 2);
    elapse(&mut e, 1);
    assert_eq!(writes(&e.platform), 2);
    e.platform.clear_faults();
    e.platform
        .inject_persistent(Call::EnablePf, Fault::ToolFail { effect: false });
    e.platform
        .inject_persistent(Call::PfInfo, Fault::Incomplete);
    elapse(&mut e, 4);
    assert!(!e.platform.enabled);
    assert!(e.committed.internal_error.is_some());
    assert!(
        read_snapshot(&mut e.platform, Copy::A)
            .internal_error
            .is_some()
    );
    assert!(
        read_snapshot(&mut e.platform, Copy::B)
            .internal_error
            .is_some()
    );
}

#[test]
fn held_emergency_revocation_stops_parking_even_without_a_leave_transition() {
    let mut p = crash_prefix(CrashBoundary::ReservationPairBeforeAcquire);
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert!(e.run_held_emergency());
    e.emergency_revoked = true;
    e.platform.calls.clear();
    assert!(!e.run_held_emergency());
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
}

#[derive(Clone, Copy, Debug)]
enum AddedCrashBoundary {
    TimeoutReservationLost,
    TimeoutReservationLands,
    HeldLeaveRevoked,
    HeldLeaveRemoved,
    Parked,
}

fn added_crash_prefix(boundary: AddedCrashBoundary) -> FakePlatform {
    match boundary {
        AddedCrashBoundary::TimeoutReservationLost
        | AddedCrashBoundary::TimeoutReservationLands => {
            let capture_prefix = |call| {
                let mut e = reboot_before_emergency();
                e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
                e.platform.capture_after(call, 1);
                // Reach the failed-reservation acquisition boundary after the
                // first containment enable, whose original 1 s bound still holds.
                e.platform
                    .mutate_after_ticks(e.timings.command_deadline * 20 - 1, Mutation::PfDisable);
                let at = e.platform.now();
                e.enter_stuck();
                (e.platform.take_capture().unwrap(), at)
            };
            let (mut first_enable, at) = capture_prefix(Call::EnablePf);
            assert_eq!(first_enable.now() - at, 1);
            assert_eq!(first_enable.pf_enabled_at.unwrap() - at, 1);
            let (mut p, _) = capture_prefix(Call::Acquire);
            assert_eq!(p.outstanding, Some(Copy::A));
            assert!(p.copies[0].pending.is_some());
            assert!(p.enabled);
            p.complete_late(
                Copy::A,
                matches!(boundary, AddedCrashBoundary::TimeoutReservationLands),
            );
            p
        }
        _ => {
            let mut p = crash_prefix(CrashBoundary::ReservationPairBeforeAcquire);
            p.restart();
            let mut e = Engine::start(p).unwrap();
            drive(&mut e, 500);
            assert!(e.run_held_emergency());
            assert_eq!(e.status().accounting.uncertain, 2);
            e.platform.calls.clear();
            if matches!(boundary, AddedCrashBoundary::Parked) {
                return e.into_platform();
            }
            e.platform.capture_after(
                if matches!(boundary, AddedCrashBoundary::HeldLeaveRevoked) {
                    Call::Reap
                } else {
                    Call::RemoveAnchor
                },
                1,
            );
            leave(&mut e, 900);
            assert!(e.emergency_revoked);
            drive(&mut e, 500);
            let p = e.platform.take_capture().unwrap();
            assert_eq!(
                p.anchor.is_none(),
                matches!(boundary, AddedCrashBoundary::HeldLeaveRemoved)
            );
            p
        }
    }
}

#[test]
fn added_crash_timeout_held_leave_and_parked_rows() {
    for boundary in [
        AddedCrashBoundary::TimeoutReservationLost,
        AddedCrashBoundary::TimeoutReservationLands,
        AddedCrashBoundary::HeldLeaveRevoked,
        AddedCrashBoundary::HeldLeaveRemoved,
        AddedCrashBoundary::Parked,
    ] {
        for reboot in [false, true] {
            let row = (boundary, reboot);
            let mut p = added_crash_prefix(boundary);
            let unrecorded: Vec<_> = p.tokens.keys().copied().collect();
            let debts = reference_keys(&read_snapshot(&mut p, Copy::A).validate().unwrap());
            if reboot {
                p.mutate(Mutation::Reboot);
            } else {
                p.restart();
            }
            p.calls.clear();
            let at = p.now();
            let mut e = Engine::start(p).unwrap();
            if matches!(boundary, AddedCrashBoundary::HeldLeaveRemoved) {
                drive(&mut e, 800);
                assert!(
                    e.platform.now() - at <= 43 + 9 * e.timings.command_deadline,
                    "{row:?}"
                );
                assert!(!e.machine.durable().join_intended, "{row:?}");
                assert!(e.platform.anchor.is_none(), "{row:?}");
                assert!(!e.platform.calls.contains(&Call::Acquire), "{row:?}");
                assert!(!e.platform.calls.contains(&Call::Spawn), "{row:?}");
                oracle(&mut e);
                continue;
            }
            let bound = 1;
            let lockdown = policy::render_lockdown();
            let pre = policy::render_pre_tunnel(&e.platform.install.config.inputs);
            let expected = if matches!(boundary, AddedCrashBoundary::TimeoutReservationLost) {
                pre.as_str()
            } else {
                lockdown.as_str()
            };
            for _ in 0..bound * 20 {
                if e.platform.enabled && e.platform.anchor.as_deref() == Some(expected) {
                    break;
                }
                tick(&mut e);
            }
            assert!(e.platform.now() - at <= bound, "{row:?}");
            assert!(e.platform.enabled, "{row:?}");
            assert!(e.platform.anchor.as_deref() == Some(expected), "{row:?}");
            drive(&mut e, 500);
            oracle(&mut e);
            if !reboot && !matches!(boundary, AddedCrashBoundary::TimeoutReservationLost) {
                assert_eq!(
                    reference_keys(&e.snapshot.validate().unwrap()),
                    debts,
                    "{row:?}"
                );
                assert!(!e.platform.calls.contains(&Call::Acquire), "{row:?}");
            }
            if matches!(boundary, AddedCrashBoundary::Parked) && !reboot {
                assert!(e.run_held_emergency());
                assert_eq!(e.platform.anchor.as_deref(), Some(lockdown.as_str()));
            }
            if !reboot && matches!(boundary, AddedCrashBoundary::TimeoutReservationLost) {
                assert!(e.platform.tokens.len() <= 2, "{row:?}");
                for token in &unrecorded {
                    assert!(
                        e.platform.tokens.contains_key(token),
                        "unrecorded token {row:?}"
                    );
                    assert!(
                        !e.platform.calls.contains(&Call::Release(*token)),
                        "{row:?}"
                    );
                }
            }
            leave(&mut e, 901);
            drive(&mut e, 800);
            assert!(e.platform.anchor.is_none(), "{row:?}");
            if !reboot && matches!(boundary, AddedCrashBoundary::TimeoutReservationLost) {
                for token in &unrecorded {
                    assert!(e.platform.tokens.contains_key(token), "{row:?}");
                    assert!(
                        !e.platform.calls.contains(&Call::Release(*token)),
                        "{row:?}"
                    );
                }
            }
            assert!(
                !e.machine.durable().join_intended,
                "{row:?}: {:?}, {:?}, {:?}",
                e.machine.durable(),
                e.machine.plan(),
                e.mode
            );
            oracle(&mut e);
        }
    }
}

#[test]
fn held_two_slot_shapes_block_without_reference_allocation() {
    for shape in ["TT", "TA", "AA"] {
        let mut p = FakePlatform::new().unwrap();
        let mut snapshot = Snapshot::recovery(p.boot_id(), None, Some(501), None);
        snapshot.internal_error = Some(snapshot::InternalError::Other);
        let mut tokens = Vec::new();
        for (index, kind) in shape.chars().enumerate() {
            if kind == 'T' {
                p.mutate(Mutation::ForeignEnable);
                let token = *p.tokens.keys().next_back().unwrap();
                tokens.push(token);
                let live = &p.tokens[&token];
                snapshot.references[index] = Some(RefEvidence {
                    key: ReferenceEntry::Token(token),
                    boot: snapshot.references[index].as_ref().unwrap().boot.clone(),
                    release_unknown: false,
                    fingerprint: Some(RefFingerprint {
                        pid: live.pid,
                        timestamp: live.timestamp,
                    }),
                });
            }
        }
        snapshot.machine.pf_reference = tokens.first().copied();
        snapshot.machine.older_references = tokens
            .iter()
            .skip(1)
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        snapshot.machine.uncertain_acquires = shape
            .chars()
            .enumerate()
            .filter(|(_, kind)| *kind == 'A')
            .map(|(i, _)| u64::try_from(i + 1).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let bytes = snapshot::encode(1, &snapshot).unwrap();
        for copy in [Copy::A, Copy::B] {
            p.create_copy(copy, &bytes, Deadline(105));
        }
        p.calls.clear();
        let at = p.now();
        let mut e = Engine::start(p).unwrap();
        drive(&mut e, 500);
        assert!(
            e.platform.now() - at <= 44 + 9 * e.timings.command_deadline,
            "{shape}"
        );
        assert!(e.platform.enabled, "{shape}");
        let lockdown = policy::render_lockdown();
        let pre = policy::render_pre_tunnel(&e.platform.install.config.inputs);
        assert!(
            matches!(e.platform.anchor.as_deref(), Some(text) if text == lockdown.as_str() || text == pre.as_str()),
            "{shape}"
        );
        assert!(!e.platform.calls.contains(&Call::Acquire), "{shape}");
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|call| **call == Call::EnablePf)
                .count(),
            1,
            "startup establishes anonymous ownership before trusting token metadata: {shape}"
        );
        assert!(!e.platform.calls.contains(&Call::Spawn), "{shape}");
        oracle(&mut e);
    }
}

#[test]
fn lockless_checks_only_pfctl_and_preserves_flush_backoff_with_persistent_failure() {
    let mut state = Snapshot::initial(Some(501));
    state.machine.join_intended = true;
    let mut p = fixture(&state);
    p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
    p.executable_symlinks.insert(Path::new(CHILD_PATH).into());
    p.executables.remove(Path::new("/sbin/route"));
    p.inject_persistent(Call::Flush, Fault::ToolFail { effect: false });
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.enabled);
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert!(e.platform.calls.contains(&Call::CheckPfctl));
    assert!(!e.platform.calls.contains(&Call::CheckTools));
    let flushes = |e: &Engine<FakePlatform>| {
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Flush)
            .count()
    };
    assert_eq!(flushes(&e), 1);
    elapse(&mut e, 1);
    assert_eq!(flushes(&e), 2);
    elapse(&mut e, 1);
    assert_eq!(flushes(&e), 2);
    elapse(&mut e, 1);
    assert_eq!(flushes(&e), 3);
    assert_lockless_effects(&e.platform);
    e.platform
        .executable_symlinks
        .insert(Path::new("/sbin/pfctl").into());
    e.platform.calls.clear();
    elapse(&mut e, 1);
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    assert!(!e.platform.calls.contains(&Call::EnablePf));
    assert!(e.platform.safety_events.iter().any(|event| matches!(event,
        platform::SafetyEvent::LocklessVerdict(verdict) if verdict.is_err())));
}

#[test]
fn lockless_unreadable_intent_shares_one_second_budget_before_first_lockdown() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
    for copy in [Copy::A, Copy::B] {
        p.inject_persistent(Call::Read(copy), Fault::WriteHang);
    }
    let at = p.now();
    let e = Engine::start(p).unwrap();
    assert!(e.platform.enabled);
    assert_eq!(e.platform.pf_enabled_at.unwrap() - at, 1);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert_lockless_effects(&e.platform);
}

#[test]
fn contention_intent_product_exits_before_any_read_or_effect() {
    for intent in 0..4 {
        let mut state = Snapshot::initial(Some(501));
        state.machine.join_intended = intent == 0;
        let mut owner = fixture(&state);
        if intent == 2 {
            owner.copies[1].durable = Some(snapshot::encode(2, &state).unwrap());
        }
        owner.acquire_instance_lock().unwrap();
        let mut contender = owner.competing_instance();
        if intent == 3 {
            contender.inject_persistent(Call::Read(Copy::A), Fault::ReadFail);
        }
        let copies = contender.copies.clone();
        let failure = refused(Engine::start(contender));
        assert_eq!(failure.outcome, StartOutcome::InstanceContended);
        assert_eq!(failure.platform.calls, [Call::AcquireInstanceLock]);
        assert_eq!(failure.platform.copies, copies);
        assert_eq!(failure.platform.signals, []);
    }
}

#[test]
fn lockless_handoff_to_left_cleans_its_fallback_policy_under_the_normal_lock() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    p.inject(Call::Read(Copy::A), 1, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.enabled);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert_lockless_effects(&e.platform);
    elapse(&mut e, 1);
    assert!(e.lockless.is_none());
    drive(&mut e, 500);
    assert!(e.platform.anchor.is_none());
    assert_eq!(e.status().text, "left");
    assert!(!e.machine.durable().join_intended);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(!e.platform.calls.contains(&Call::Spawn));
    assert!(e.platform.calls.contains(&Call::CreateControlSocket));
    assert!(e.platform.calls.contains(&Call::RemoveAnchor));
    oracle(&mut e);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep initial containment and bounded repair rows together.
fn d3_locked_inventory_fence_and_reap_faults_contain_reboot_within_one_second() {
    for fault in ["inventory", "fence", "reap"] {
        let mut p = joined().into_platform();
        let mut orphan = p.procs[&14].clone();
        p.mutate(Mutation::Reboot);
        match fault {
            "inventory" => p.inject_persistent(Call::Processes, Fault::Incomplete),
            "fence" => {
                orphan.path = Some("/sbin/route".into());
                orphan.ppid = 1;
                orphan.start.seconds = 1;
                p.unkillable.insert(orphan.pid);
                p.procs.insert(orphan.pid, orphan);
            }
            "reap" => {
                p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
                let d = Deadline(p.now() + 5);
                assert!(p.load_anchor(&policy::render_lockdown(), d).is_err());
                p.unkillable.insert(p.unreaped[0].pid);
            }
            _ => unreachable!(),
        }
        p.pause_advances_clock = false;
        let at = p.now();
        p.calls.clear();
        let mut e = Engine::start(p).unwrap();
        assert!(
            e.platform
                .pf_enabled_at
                .is_some_and(|enabled| enabled - at <= 1),
            "{fault}"
        );
        assert!(e.platform.enabled, "{fault}");
        let inventory = e
            .platform
            .calls
            .iter()
            .position(|c| *c == Call::Processes)
            .unwrap();
        for command in [
            Call::CheckPfctl,
            Call::LoadAnchor,
            Call::EnablePf,
            Call::Flush,
        ] {
            assert!(
                e.platform.calls.iter().position(|c| *c == command).unwrap() < inventory,
                "first containment command {command:?}, {fault}"
            );
        }
        assert!(!e.platform.calls[..inventory].iter().any(|c| matches!(
            c,
            Call::Kill(..)
                | Call::KillProcess(..)
                | Call::Acquire
                | Call::Release(_)
                | Call::Write(_)
                | Call::Create(_)
                | Call::Spawn
        )));

        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str()),
            "{fault}"
        );
        assert!(!e.platform.calls.contains(&Call::Acquire), "{fault}");
        assert!(!e.platform.calls.contains(&Call::Spawn), "{fault}");
        assert_ne!(e.start_fence, StartFence::Closed, "{fault}");
        assert_eq!(
            e.status().text,
            "containment attempted; safety unproven",
            "{fault}"
        );
        assert!(!e.status().emergency_blocking_verified, "{fault}");
        e.platform.anchor = Some("pass all\n".into());
        e.platform.states.push(true);
        e.platform.calls.clear();
        let repair_at = e.platform.now();
        for _ in 0..40 {
            tick(&mut e);
            if e.platform.anchor.as_deref() == Some(policy::render_lockdown().as_str())
                && e.platform.states.is_empty()
            {
                break;
            }
        }
        assert!(e.platform.now() - repair_at <= 2, "repair latency {fault}");
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str()),
            "{fault}"
        );
        assert!(e.platform.states.is_empty(), "{fault}");
        let calls = &e.platform.calls;
        let load = calls.iter().position(|c| *c == Call::LoadAnchor).unwrap();
        let verify = calls
            .iter()
            .skip(load)
            .position(|c| *c == Call::Collect)
            .unwrap()
            + load;
        let flush = calls
            .iter()
            .skip(load)
            .position(|c| *c == Call::Flush)
            .unwrap()
            + load;
        assert!(load < verify && verify < flush, "repair ordering {fault}");
        assert!(calls.contains(&Call::Reap), "{fault}");
        assert!(calls.contains(&Call::Processes), "{fault}");
        let disabled_at = e.platform.now();
        e.platform.mutate(Mutation::PfDisable);
        e.platform.states.push(true);
        for _ in 0..40 {
            tick(&mut e);
            if e.platform.enabled && e.platform.states.is_empty() {
                break;
            }
        }
        assert!(
            e.platform.enabled && e.platform.states.is_empty(),
            "disable {fault}"
        );
        assert!(
            e.platform.now() - disabled_at <= 2,
            "disable latency {fault}"
        );
        assert!(
            !e.platform.calls.iter().any(|c| matches!(c, Call::Pause(_))),
            "blocking sweep {fault}"
        );
    }
}

#[test]
fn d3_leave_waits_for_start_fence_and_emergency_writers() {
    let mut e = reboot_before_emergency();
    let mut orphan = e.platform.procs[&e.platform.helper.pid].clone();
    orphan.pid = 333;
    orphan.ppid = 1;
    orphan.pgid = 333;
    orphan.start.seconds = 1;
    orphan.path = Some("/sbin/route".into());
    e.platform.unkillable.insert(orphan.pid);
    e.platform.procs.insert(orphan.pid, orphan);
    e.start_fence = StartFence::Uncommitted;
    e.enter_stuck();
    assert!(e.platform.enabled);
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    let writer = e.platform.unreaped[0].pid;
    e.platform.unkillable.insert(writer);
    e.platform.calls.clear();
    leave(&mut e, 90);
    drive(&mut e, 10);
    assert!(!e.platform.calls.contains(&Call::RemoveAnchor));
    e.platform.unkillable.remove(&333);
    drive(&mut e, 10);
    assert!(!e.platform.calls.contains(&Call::RemoveAnchor));
    e.platform.unkillable.remove(&writer);
    elapse(&mut e, 65);
    assert!(e.platform.calls.contains(&Call::RemoveAnchor));
    assert!(e.platform.anchor.is_none());
    assert_eq!(e.platform.fence(), Fence::Closed);
    e.platform.release_unreaped();
    elapse(&mut e, 2);
    assert!(e.platform.anchor.is_none());
}

#[test]
fn lockless_handoff_preserves_durable_leaving_cleanup_and_reference_release() {
    let mut original = joined();
    let token = original.machine.durable().pf_reference.unwrap();
    leave(&mut original, 91);
    // Capture the durable Leave plan before any cleanup effects.
    while !original.committed.machine.leaving {
        tick(&mut original);
    }
    let plan = original.committed.machine.pending_cleanup.clone();
    assert!(plan.contains(&snapshot::StepRecord::from(Step::CleanupRoutes)));
    assert!(plan.contains(&snapshot::StepRecord::from(Step::CleanupDns)));
    let mut p = original.into_platform();
    p.crash();
    p.restart();
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    p.calls.clear();
    let copies = p.copies.clone();
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.platform.copies, copies);
    assert_eq!(
        read_snapshot(&mut e.platform, Copy::A)
            .machine
            .pending_cleanup,
        plan
    );
    assert_lockless_effects(&e.platform);
    elapse(&mut e, 1);
    assert!(e.lockless.is_none());
    assert_eq!(e.snapshot.machine.pending_cleanup, plan);
    drive(&mut e, 800);
    assert!(e.platform.calls.contains(&Call::CleanupDns));
    assert!(
        e.platform
            .calls
            .iter()
            .any(|c| matches!(c, Call::CleanupRoutes(_)))
    );
    assert!(e.platform.calls.contains(&Call::CleanupArtifacts));
    assert!(e.platform.calls.contains(&Call::Release(token)));
    assert!(!e.platform.tokens.contains_key(&token));
    assert!(e.platform.anchor.is_none());
    assert_eq!(e.status().text, "left");
}

#[test]
fn lockless_handoff_kills_hung_load_after_deadline_and_maintains_lockdown() {
    let mut state = Snapshot::initial(Some(501));
    state.machine.join_intended = true;
    let mut p = fixture(&state);
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let mut e = Engine::start(p).unwrap();
    let writer = e.platform.unreaped[0].pid;
    // ToolLate also models an unkillable process by default; here the tool
    // hangs forever but a guarded kill must terminate it.
    e.platform.unkillable.remove(&writer);
    let at = e.platform.now();
    e.platform.calls.clear();
    e.platform.anchor = Some("pass all\n".into());
    e.platform.states.push(true);
    let mut maintenance_passes = 0;
    for _ in 0..=e.timings.command_deadline {
        e.platform.anchor = Some("pass all\n".into());
        e.platform.states.push(true);
        tick(&mut e);
        assert!(e.platform.enabled);
        if e.lockless.is_none() {
            assert!(e.platform.now() - at >= e.timings.command_deadline);
            break;
        }
        maintenance_passes += 1;
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert_eq!(e.platform.states, [] as [bool; 0]);
        if e.lockless.is_none() {
            break;
        }
    }
    assert!(e.lockless.is_none());
    assert!(maintenance_passes >= 2);
    assert!(e.platform.now() - at <= 1 + 2 * e.timings.command_deadline);
    let calls = &e.platform.calls;
    let load = calls.iter().position(|c| *c == Call::LoadAnchor).unwrap();
    let flush = calls.iter().position(|c| *c == Call::Flush).unwrap();
    let kill = calls
        .iter()
        .position(|c| matches!(c, Call::KillProcess(pid, _) if *pid == writer))
        .unwrap();
    let install = calls.iter().position(|c| *c == Call::Install).unwrap();
    assert!(load < flush && flush < kill && kill < install);
    assert_eq!(e.platform.unreaped, [] as [platform::Unreaped; 0]);
    drive(&mut e, 500);
    let expected = policy::render_joined(&e.inputs().unwrap());
    assert_eq!(e.platform.anchor.as_deref(), Some(expected.as_str()));
    e.platform.release_unreaped();
    elapse(&mut e, 3);
    assert_eq!(e.platform.anchor.as_deref(), Some(expected.as_str()));
}

#[test]
fn constructor_stuck_healthy_storage_reserves_reference_after_d3_containment() {
    let mut e = reboot_before_emergency();
    // Reproduce constructor Stuck's emergency-before-socket order with a valid,
    // reservable ledger. A malformed ledger could only exercise the separate
    // unreserved allowance, concealing the socket-not-created regression.
    e.control_socket_created = false;
    assert!(e.startup_error.is_none());
    e.start_fence = StartFence::Uncommitted;
    e.enter_stuck();
    assert_eq!(e.mode, Mode::Stuck);
    assert!(e.platform.enabled);
    let acquire = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Acquire)
        .unwrap();
    let reserved = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Write(Copy::A))
        .unwrap();
    assert!(reserved < acquire);
    assert!(e.platform.calls[..acquire].contains(&Call::EnablePf));
    assert!(
        matches!(snapshot::classify_copy(e.platform.read_copy(Copy::A, Deadline(u64::MAX))), CopyClass::V { snapshot, .. } if snapshot.references.iter().flatten().next().is_some())
    );
}

#[test]
fn lockless_contention_drains_and_retry_eintr_is_bounded() {
    let mut snapshot = Snapshot::initial(Some(501));
    snapshot.machine.join_intended = true;
    let mut p = fixture(&snapshot);
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: Some(25) });
    let mut e = Engine::start(p).unwrap();
    e.platform.release_unreaped();
    let copies = e.platform.copies.clone();
    let mut contender = e.platform.competing_instance();
    contender.acquire_instance_lock().unwrap();
    e.platform.calls.clear();
    elapse(&mut e, 1);
    assert_eq!(e.outcome, Outcome::InstanceContended);
    assert!(e.platform.calls.contains(&Call::Reap));
    assert_eq!(e.platform.unreaped, [] as [platform::Unreaped; 0]);
    assert_eq!(e.platform.copies, copies);
    assert_lockless_effects(&e.platform);

    let mut p = fixture(&snapshot);
    p.inject_persistent(Call::AcquireInstanceLock, Fault::LockInterrupted);
    let mut e = Engine::start(p).unwrap();
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::AcquireInstanceLock)
            .count(),
        8
    );
    assert!(e.platform.enabled);
    e.platform.calls.clear();
    elapse(&mut e, 1);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::AcquireInstanceLock)
            .count(),
        8
    );
    assert!(e.platform.enabled);
    assert!(e.lockless.is_some());
    e.platform.clear_faults();
    elapse(&mut e, 2);
    assert!(e.lockless.is_none());
}

#[test]
fn enabled_stateless_emergency_skips_enable_and_failed_enable_still_flushes() {
    let mut snapshot = Snapshot::initial(Some(501));
    snapshot.machine.join_intended = true;
    let mut p = fixture(&snapshot);
    p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    e.platform.calls.clear();
    elapse(&mut e, 3);
    assert!(!e.platform.calls.contains(&Call::EnablePf));
    e.platform.mutate(Mutation::PfDisable);
    e.platform.states.push(true);
    e.platform
        .inject(Call::EnablePf, 1, Fault::ToolFail { effect: true });
    e.platform.calls.clear();
    elapse(&mut e, 1);
    assert!(e.platform.enabled);
    assert!(e.platform.calls.contains(&Call::Flush));
    assert_eq!(e.platform.states, [] as [bool; 0]);
}

#[test]
fn healthy_held_normal_emergency_uses_reserved_acquire_after_fence_closes() {
    let mut e = joined();
    let mut durable = e.machine.durable().clone();
    durable.hold = true;
    e.snapshot.machine = snapshot::DurableRecord::try_from(&durable).unwrap();
    e.machine = Machine::restart(durable);
    e.snapshot.internal_error = Some(snapshot::InternalError::Other);
    assert!(e.machine.durable().hold);
    e.mode = Mode::Normal;
    e.platform.mutate(Mutation::PfDisable);
    e.platform.calls.clear();
    e.run_emergency();
    assert!(e.platform.enabled);
    let acquire = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Acquire)
        .unwrap();
    assert!(e.platform.calls[..acquire].contains(&Call::Write(Copy::A)));
    assert!(!e.platform.calls[..acquire].contains(&Call::EnablePf));
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    leave(&mut e, 92);
    drive(&mut e, 800);
    assert_ne!(e.mode, Mode::Stuck);
    assert!(!e.machine.durable().join_intended);
    assert!(e.platform.anchor.is_none());
}

#[test]
fn locked_intent_probe_contains_before_thirty_second_storage_stall() {
    let mut p = joined().into_platform();
    p.mutate(Mutation::Reboot);
    for copy in [Copy::A, Copy::B] {
        p.inject_persistent(Call::Read(copy), Fault::WriteHang);
    }
    let at = p.now();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.now() - at >= 6);
    assert!(e.platform.pf_enabled_at.unwrap() - at <= 1);
    assert!(e.platform.enabled);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    let calls = &e.platform.calls;
    let load = calls.iter().position(|c| *c == Call::LoadAnchor).unwrap();
    let install = calls.iter().position(|c| *c == Call::Install).unwrap();
    assert!(load < install);
    let decided = calls
        .iter()
        .rposition(|c| matches!(c, Call::Read(_)))
        .unwrap();
    assert!(install < decided);
    assert!(
        !calls[..=decided]
            .iter()
            .any(|c| matches!(c, Call::Write(_) | Call::Create(_) | Call::Acquire))
    );
}

#[test]
fn locked_slow_left_probe_removes_containment_after_full_start() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    // One abandoned probe occupies a worker. The remaining worker completes
    // the full read across slices, returning two equal valid Left copies.
    p.inject(Call::Read(Copy::A), 1, Fault::WriteHang);
    p.inject(Call::Read(Copy::A), 1, Fault::StorageDelay(60));
    let at = p.now();
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.pf_enabled_at.unwrap() - at <= 1);
    assert!(e.platform.now() - at >= 2);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    drive(&mut e, 500);
    assert_eq!(e.status().text, "left");
    assert!(e.platform.anchor.is_none());
    assert!(e.platform.enabled);
    assert!(e.platform.calls.contains(&Call::RemoveAnchor));
    assert!(!e.platform.calls.contains(&Call::Acquire));
}

#[test]
fn locked_equal_left_probe_never_runs_containment() {
    let mut e = Engine::start(fixture(&Snapshot::initial(Some(501)))).unwrap();
    drive(&mut e, 100);
    assert!(!e.platform.enabled);
    for call in [
        Call::CheckPfctl,
        Call::LoadAnchor,
        Call::EnablePf,
        Call::Flush,
    ] {
        assert!(!e.platform.calls.contains(&call), "{call:?}");
    }
}

#[test]
fn lockless_persistent_error_kills_and_reaps_hung_own_tool_then_maintains() {
    let mut state = Snapshot::initial(Some(501));
    state.machine.join_intended = true;
    let mut p = fixture(&state);
    p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
    p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let entered = p.now();
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.now() - entered >= e.timings.command_deadline);
    let writer = e.platform.unreaped[0].pid;
    e.platform.unkillable.remove(&writer);
    let at = e.platform.now();
    for _ in 0..40 {
        tick(&mut e);
        if e.platform.unreaped.is_empty() && e.platform.enabled {
            break;
        }
    }
    assert!(e.lockless.is_some());
    assert!(e.platform.now() - at <= 2);
    assert_eq!(e.platform.unreaped, [] as [platform::Unreaped; 0]);
    assert!(e.platform.signals.iter().any(|(pid, _)| *pid == writer));
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    e.platform.anchor = Some("pass all\n".into());
    let at = e.platform.now();
    for _ in 0..40 {
        tick(&mut e);
        if e.platform.anchor.as_deref() == Some(policy::render_lockdown().as_str()) {
            break;
        }
    }
    assert!(e.platform.now() - at <= 2);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert_eq!(writes(&e.platform), 0);
    assert!(!e.platform.calls.contains(&Call::Acquire));
}

#[test]
fn emergency_accounting_restart_rejects_an_in_flight_effect() {
    let mut e = reboot_before_emergency();
    e.enter_stuck();
    assert_ne!(e.emergency_references, [] as [RefEvidence; 0]);
    let durable = e.machine.durable().clone();
    let snapshot = e.snapshot.clone();
    let references = e.emergency_references.clone();
    e.in_flight = Some((123, Step::AcquireReference));
    assert_eq!(
        e.resume_emergency_accounting_for_leave(),
        Err(SysError::Failed("emergency accounting effect in flight"))
    );
    assert_eq!(*e.machine.durable(), durable);
    assert_eq!(e.snapshot, snapshot);
    assert_eq!(e.emergency_references, references);
    assert_eq!(e.in_flight, Some((123, Step::AcquireReference)));
}

#[test]
fn locked_same_boot_joined_restart_keeps_pf_enabled_on_every_tick() {
    let mut p = joined().into_platform();
    let old_token = *p.tokens.keys().next().unwrap();
    p.crash();
    p.restart();
    p.calls.clear();
    let disabled_at = p.pf_disabled_at;
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.platform.pf_disabled_at, disabled_at);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.platform.enabled);
    assert!(e.platform.tokens.contains_key(&old_token));
    // Include the constructor and all intermediate calls, not only tick boundaries.
    let first_acquire = e
        .platform
        .calls
        .iter()
        .position(|call| *call == Call::Acquire)
        .unwrap_or(e.platform.calls.len());
    assert!(!e.platform.calls[..first_acquire].contains(&Call::Release(old_token)));
    for _ in 0..500 {
        tick(&mut e);
        assert!(e.platform.enabled);
        assert_eq!(e.platform.pf_disabled_at, disabled_at);
    }
    let first_acquire = e
        .platform
        .calls
        .iter()
        .position(|call| *call == Call::Acquire)
        .unwrap();
    assert!(!e.platform.calls[..first_acquire].contains(&Call::Release(old_token)));

    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref proof) if proof.form() == Form::Joined)
    );
}

#[test]
fn failed_or_ambiguous_emergency_acquire_enables_immediately_and_backs_off() {
    for fault in [
        Fault::ToolFail { effect: false },
        Fault::ToolFail { effect: true },
        Fault::ToolHang {
            reaped: true,
            effect: false,
        },
    ] {
        let mut e = reboot_before_emergency();
        e.platform.inject(Call::Acquire, 1, fault);
        assert_eq!(e.enable_emergency_pf(), Err(SysError::Unknown));
        assert!(e.platform.enabled, "{fault:?}");
        assert!(e.emergency_next_acquire > e.platform.now(), "{fault:?}");
        let acquire = e
            .platform
            .calls
            .iter()
            .position(|c| *c == Call::Acquire)
            .unwrap();
        let enable = e
            .platform
            .calls
            .iter()
            .position(|c| *c == Call::EnablePf)
            .unwrap();
        assert!(acquire < enable, "{fault:?}");
        e.platform.mutate(Mutation::PfDisable);
        e.platform.calls.clear();
        assert_eq!(e.enable_emergency_pf(), Ok(true));
        assert!(e.platform.enabled);
        assert!(!e.platform.calls.contains(&Call::Acquire), "{fault:?}");
        assert!(e.platform.calls.contains(&Call::EnablePf), "{fault:?}");
    }
}

#[test]
fn emergency_pre_flush_verdict_is_logged_without_claiming_clean_states() {
    let mut e = reboot_before_emergency();
    e.platform.safety_events.clear();
    assert!(e.load_emergency().is_ok());
    assert!(e.platform.safety_events.iter().any(|event| matches!(event,
        platform::SafetyEvent::LocklessVerdict(verdict)
            if matches!(verdict.as_ref(), Ok(Verdict::Unknown { .. }))
    )));
}

#[test]
fn invariant_refusal_status_acknowledges_prior_containment() {
    let mut e = reboot_before_emergency();
    e.startup_invariant_checked = false;
    e.platform.helper.pgid = 99;
    e.enter_stuck();
    let status = e.status();
    assert!(e.startup_invariant_failed);
    assert!(e.platform.enabled);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert_eq!(
        status.enforcement,
        Verdict::NotProtected(Reason::Observation(
            "containment may be loaded; not maintained"
        ))
    );
    assert_eq!(
        status.text,
        "misconfiguration: helper must be owned by launchd; containment may be loaded; not maintained; Leave refused"
    );
}

#[test]
fn locked_probe_left_cleanup_crash_preserves_error_until_explicit_leave() {
    let mut state = Snapshot::initial(Some(501));
    state.internal_error = Some(snapshot::InternalError::Other);
    let e = Engine::start(fixture(&state)).unwrap();
    assert!(e.containment_cleanup_only);
    assert!(e.committed.machine.leaving || e.committed.machine.leave_requested);
    let mut p = e.into_platform();
    p.crash();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert!(e.snapshot.internal_error.is_some());
    assert!(e.committed.internal_error.is_some());
    assert!(e.platform.anchor.is_none());
    assert!(e.platform.enabled);
    assert!(
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join
        })
        .is_err()
    );
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert!(e.committed.internal_error.is_none());
    assert_eq!(e.status().text, "left");
}

#[test]
fn d3_storage_hangs_repair_pf_disable_during_constructor_and_between_attempts() {
    for (stuck, disable_ticks, disable_delay) in
        [(false, 40, 2), (true, 40, 2), (false, 81, 4), (true, 81, 4)]
    {
        let mut p = joined().into_platform();
        let mut orphan = p.procs[&14].clone();
        p.mutate(Mutation::Reboot);
        orphan.path = Some("/sbin/route".into());
        orphan.ppid = 1;
        orphan.start.seconds = 1;
        p.unkillable.insert(orphan.pid);
        p.procs.insert(orphan.pid, orphan);
        p.inject_persistent(Call::Read(Copy::A), Fault::WriteHang);
        p.inject_persistent(Call::Write(Copy::A), Fault::WriteHang);
        p.pause_advances_clock = false;
        // The probe contains at t=1. Interfere during a later read (t=2)
        // or just inside the first recovery write (t=4.05).
        let disabled_at = p.now() + disable_delay;
        p.mutate_after_ticks(disable_ticks, Mutation::PfDisable);
        let mut e = Engine::start(p).unwrap();
        assert!(e.platform.enabled);
        assert!(e.platform.pf_enabled_at.unwrap() - disabled_at <= 2);
        if stuck {
            e.enter_stuck();
        }
        for _ in 0..4 {
            // Complete the previous timed-out worker so each retry really hangs
            // again instead of returning Busy. Interfere inside that write.
            e.platform.complete_late(Copy::A, false);
            e.storage_blocked = true;
            e.next_storage = e.platform.now();
            let disabled_at = e.platform.now();
            e.platform.mutate_after_ticks(1, Mutation::PfDisable);
            e.retry_storage();
            assert_eq!(e.platform.outstanding, Some(Copy::A));
            // Containment now runs inside the full write budget, before retry returns.
            assert!(e.platform.enabled);
            for _ in 0..40 {
                tick(&mut e);
                if e.platform.enabled {
                    break;
                }
            }
            assert!(e.platform.enabled, "stuck={stuck}");
            assert!(
                e.platform.pf_enabled_at.unwrap() - disabled_at <= 2,
                "stuck={stuck}"
            );
        }
        assert!(e.platform.calls.contains(&Call::Write(Copy::A)));
    }
}

#[test]
fn held_emergency_unkillable_own_tool_repairs_on_one_second_cadence() {
    let mut p = crash_prefix(CrashBoundary::ReservationPairBeforeAcquire);
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert!(e.held_emergency_due());
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = Deadline(e.platform.now() + 5);
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    assert_eq!(e.platform.unreaped.len(), 1);
    for _ in 0..4 {
        let at = e.platform.now();
        e.platform.mutate(Mutation::PfDisable);
        e.run_until_quiescent(1);
        assert!(e.platform.enabled);
        assert!(e.platform.pf_enabled_at.unwrap() - at <= 1);
        assert!(e.platform.now() - at <= 1);
    }
}

#[test]
fn emergency_caps_unkillable_own_pfctl_children_and_reports_capacity() {
    for lockless in [false, true] {
        let mut state = Snapshot::initial(Some(501));
        state.machine.join_intended = true;
        let mut p = fixture(&state);
        if lockless {
            p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
        } else {
            p.inject_persistent(Call::Processes, Fault::Incomplete);
        }
        p.inject_persistent(Call::LoadAnchor, Fault::ToolLate { ticks: None });
        let mut e = Engine::start(p).unwrap();
        for _ in 0..200 {
            tick(&mut e);
            assert!(e.platform.unreaped.len() <= 2);
        }
        assert_eq!(e.platform.unreaped.len(), 2);
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|call| **call == Call::LoadAnchor)
                .count(),
            2
        );
        assert!(
            e.platform
                .safety_events
                .iter()
                .any(|event| matches!(event, platform::SafetyEvent::PfctlCapacity { unreaped: 2 }))
        );
        assert!(!e.status().emergency_blocking_verified);
    }
}

#[test]
fn socket_failure_drains_own_tools_without_a_second_emergency_step() {
    let mut state = Snapshot::initial(Some(501));
    state.machine.join_intended = true;
    let mut p = fixture(&state);
    p.inject_persistent(Call::CreateControlSocket, Fault::NoSpace);
    p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let mut e = Engine::start(p).unwrap();
    let writer = e.platform.unreaped[0].pid;
    e.platform.unkillable.remove(&writer);
    tick(&mut e);
    assert!(e.platform.signals.iter().any(|(pid, _)| *pid == writer));
    assert_eq!(e.platform.unreaped, vec![]);
    assert_eq!(e.mode, Mode::Starting);
}

#[test]
fn locked_storage_reads_stay_sliced_after_initial_pfctl_failure() {
    let mut p = joined().into_platform();
    p.mutate(Mutation::Reboot);
    p.inject(Call::CheckPfctl, 1, Fault::ReadFail);
    p.inject_persistent(Call::Read(Copy::A), Fault::WriteHang);
    let at = p.now();
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.enabled);
    assert!(e.platform.pf_enabled_at.unwrap() - at <= 2);
    assert!(e.platform.now() - at <= 20);
}

#[test]
fn persist_blocked_keeps_current_joined_anchor_with_unreaped_own_tool() {
    for form in [Form::Joined, Form::PreTunnel] {
        let mut e = if form == Form::Joined {
            joined()
        } else {
            let mut e = fresh();
            e.submit(Request {
                id: 1,
                kind: RequestKind::Join,
            })
            .unwrap();
            before_pending(&mut e, Step::StartChild);
            assert!(e.machine.blocking_verified_at(&Clock(e.platform.now())));
            e
        };
        let anchor = e.platform.anchor.clone();
        e.platform.inject(
            Call::Configure(ConfigKey::Mtu),
            1,
            Fault::ToolLate { ticks: None },
        );
        let d = Deadline(e.platform.now() + 1);
        let _ = e.platform.configure(ConfigKey::Mtu, &Setting::Mtu(1420), d);
        assert_eq!(e.platform.unreaped.len(), 1);
        let now = e.platform.now();
        assert!(e.current_blocking_verified(now));
        e.platform
            .inject_persistent(Call::Write(Copy::A), Fault::NoSpace);
        e.block_storage();
        assert_eq!(e.mode, Mode::PersistBlocked);
        e.next_storage = e.platform.now();
        e.platform.calls.clear();
        e.attempt_stateless_containment();
        e.retry_storage();
        assert_eq!(e.platform.anchor, anchor);
        assert!(!e.platform.calls.contains(&Call::LoadAnchor));
        assert!(!e.emergency_loaded);

        let expiry = match e.machine.enforcement_at(&Clock(now)) {
            Verdict::Protected(proof) => proof.expires_at(),
            other => panic!("expected current proof: {other:?}"),
        };
        let until = e.platform.now() + 20;
        while e.platform.now() < until {
            e.platform.tick();
            e.next_storage = e.platform.now();
            e.next_emergency = e.platform.now();
            e.run_emergency();
            e.retry_storage();
            if e.emergency_loaded {
                assert!(e.emergency_last_load_at.unwrap() > expiry);
            }
            if e.platform.now() <= expiry {
                assert_eq!(e.platform.anchor, anchor);
                assert!(!e.platform.calls.contains(&Call::LoadAnchor));
            } else if e.platform.calls.contains(&Call::LoadAnchor) {
                assert!(e.emergency_loaded);
            }
        }
        assert!(e.emergency_loaded);
        assert_eq!(
            e.platform.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
    }
}

#[test]
fn slow_install_and_copy_reads_keep_full_budgets_and_maintain_containment() {
    let mut p = joined().into_platform();
    p.mutate(Mutation::Reboot);
    p.calls.clear();
    // The 1 s intent probe consumes the first A read; the full read then
    // takes three seconds on one operation, just like the install record.
    p.inject(Call::Install, 1, Fault::StorageDelay(60));
    p.inject(Call::Read(Copy::A), 2, Fault::StorageDelay(60));
    p.inject(Call::Read(Copy::B), 2, Fault::StorageDelay(60));
    p.mutate_after_ticks(40, Mutation::PfDisable);
    let mut e = Engine::start(p).unwrap();
    assert!(e.install.is_some());
    assert!(e.platform.enabled);
    assert!(e.platform.pf_enabled_at.unwrap() <= 3);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::Install)
            .count(),
        1
    );
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::Read(Copy::A))
            .count(),
        2
    );
    drive(&mut e, 500);
    assert!(!e.machine.durable().hold);
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref proof) if proof.form() == Form::Joined)
    );
}

#[test]
fn slow_commits_wait_on_same_writes_with_containment_between_slices() {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.platform
        .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(60));
    e.platform
        .inject(Call::Write(Copy::B), 1, Fault::StorageDelay(60));
    e.platform.calls.clear();
    let bytes = snapshot::encode(e.seq + 1, &e.snapshot).unwrap();
    let at = e.platform.now();
    e.platform.mutate_after_ticks(20, Mutation::PfDisable);
    assert_eq!(e.storage_commit(&bytes, 10), Commit::Committed);
    assert!(e.platform.now() - at >= 6);
    assert!(e.platform.enabled);
    assert!(e.platform.pf_enabled_at.unwrap() - at <= 2);
    for copy in [Copy::A, Copy::B] {
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|call| **call == Call::Write(copy))
                .count(),
            1
        );
        assert_eq!(
            e.platform.copies[usize::from(copy == Copy::B)]
                .durable
                .as_deref(),
            Some(bytes.as_ref())
        );
    }
}

#[test]
fn nonheld_normal_open_fence_reaps_with_two_second_budget() {
    let mut e = joined();
    e.platform.inject(
        Call::Configure(ConfigKey::Mtu),
        1,
        Fault::ToolLate { ticks: None },
    );
    let d = Deadline(e.platform.now() + 1);
    let _ = e.platform.configure(ConfigKey::Mtu, &Setting::Mtu(1420), d);
    assert!(!e.held_emergency_due());
    e.platform.calls.clear();
    let at = e.platform.now();
    e.run_until_quiescent(1);
    assert!(e.platform.calls.contains(&Call::Reap));
    assert_eq!(e.platform.now() - at, 2);
}

#[test]
fn held_emergency_queue_and_in_flight_still_reap_generically() {
    for queued in [false, true] {
        let mut p = crash_prefix(CrashBoundary::ReservationPairBeforeAcquire);
        p.restart();
        let mut e = Engine::start(p).unwrap();
        drive(&mut e, 500);
        assert!(e.held_emergency_due());
        e.platform
            .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
        let d = Deadline(e.platform.now() + 1);
        let _ = e.platform.load_anchor(&policy::render_lockdown(), d);
        if queued {
            e.queue.push_back(QueueEvent::Timer);
        } else {
            e.in_flight = Some((123, Step::AcquireReference));
        }
        e.platform.calls.clear();
        e.run_until_quiescent(1);
        assert!(e.platform.calls.contains(&Call::Reap), "queued={queued}");
    }
}

#[test]
fn slow_emergency_reservation_keeps_full_commit_budget() {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.platform
        .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(60));
    e.platform
        .inject(Call::Write(Copy::B), 1, Fault::StorageDelay(60));
    let at = e.platform.now();
    assert_eq!(e.enable_emergency_pf(), Ok(true));
    assert!(e.platform.enabled);
    assert!(e.platform.pf_enabled_at.unwrap() - at <= 2);
    assert!(e.platform.now() - at >= 6);
    assert!(!e.storage_blocked);
    assert!(e.platform.outstanding.is_none());
    assert_eq!(e.snapshot, e.committed);
    assert!(
        e.emergency_references
            .iter()
            .any(|entry| matches!(entry.key, ReferenceEntry::Token(_)))
    );
}

#[test]
fn persist_blocked_with_unreaped_pfctl_contains_despite_current_joined_proof() {
    let mut e = joined();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = Deadline(e.platform.now() + 1);
    let _ = e.platform.load_anchor(&policy::render_lockdown(), d);
    let now = e.platform.now();
    assert!(e.current_blocking_verified(now));
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::NoSpace);
    e.block_storage();
    assert_eq!(e.mode, Mode::PersistBlocked);
    e.next_storage = e.platform.now();
    e.next_emergency = e.platform.now();
    e.platform.calls.clear();
    e.retry_storage();
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.emergency_loaded);
}

#[test]
fn current_proof_slow_commit_observes_external_disable_between_slices() {
    let mut e = joined();
    e.mode = Mode::PersistBlocked;
    // Positive proof checks keep the policy; a negative must override cadence.
    // Use the production timer bound enforced by safety_storage_deadline.
    e.next_emergency = e.platform.now().saturating_add(1);
    for copy in [Copy::A, Copy::B] {
        e.platform
            .inject(Call::Write(copy), 1, Fault::StorageDelay(60));
    }
    e.platform.mutate_after_ticks(40, Mutation::PfDisable);
    let bytes = snapshot::encode(e.seq + 1, &e.snapshot).unwrap();
    assert_eq!(e.storage_commit(&bytes, 10), Commit::Committed);
    assert!(e.platform.enabled);
    assert!(e.platform.pf_enabled_at.unwrap() - e.platform.pf_disabled_at.unwrap() <= 2);
    assert!(e.emergency_loaded);
    assert!(!matches!(
        e.machine.enforcement_at(&Clock(e.platform.now())),
        Verdict::Protected(_)
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // Keep both commit points and containment/proof assertions together.
fn stateful_emergency_storage_wait_never_reenters_outer_frame() {
    for (commit, disturbance_ticks) in [(1, 40), (1, 100), (2, 40), (2, 100)] {
        for disturbance in [
            Mutation::PfDisable,
            Mutation::AnchorLoss,
            Mutation::AnchorChange,
        ] {
            let lose_anchor = disturbance != Mutation::PfDisable;
            let mut e = reboot_before_emergency();
            e.mode = Mode::Stuck;
            e.platform.model_firewall = true;
            for copy in [Copy::A, Copy::B] {
                e.platform
                    .inject(Call::Write(copy), commit, Fault::StorageDelay(60));
            }
            e.platform
                .mutate_after_ticks(disturbance_ticks, disturbance);
            // Reservation waits first re-enable the initially disabled pf.
            // Capture the later disturbance flush, not that initial flush.
            e.platform
                .capture_after(Call::Flush, if commit == 1 { 2 } else { 1 });
            let at = e.platform.now();
            e.run_emergency();
            let mut flushed = e.platform.take_capture().unwrap();
            let loss_at = if lose_anchor {
                flushed.anchor_lost_at.unwrap()
            } else {
                flushed.pf_disabled_at.unwrap()
            };
            assert_eq!(
                Some(loss_at),
                if lose_anchor {
                    e.platform.anchor_lost_at
                } else {
                    e.platform.pf_disabled_at
                }
            );
            assert!(
                flushed.now() - loss_at <= 2,
                "commit={commit}, {disturbance:?}"
            );
            assert_eq!(
                flushed.anchor.as_deref(),
                Some(policy::render_lockdown().as_str())
            );
            if !flushed.enabled {
                let enable = e
                    .platform
                    .firewall_events
                    .iter()
                    .find(|event| {
                        event.call == Call::EnablePf
                            && event.at >= loss_at * 1000
                            && event.succeeded
                    })
                    .unwrap();
                assert_eq!(enable.at / 1000, flushed.now());
                assert_eq!(
                    enable.anchor.as_deref(),
                    Some(policy::render_lockdown().as_str())
                );
            }
            assert_eq!(flushed.states, [] as [bool; 0]);
            assert!(flushed.interface_states.is_empty());
            assert!(!e.in_emergency_step);
            assert!(e.platform.enabled);
            assert!(e.platform.now() - at >= 6);
            if lose_anchor || commit == 2 {
                assert!(e.emergency_frame_disturbed);
                assert!(e.emergency_proof.is_none());
                assert!(e.emergency_readback.is_none());
            }
            assert!(e.platform.calls.contains(&Call::Flush));
            let acquisitions = e
                .platform
                .calls
                .iter()
                .filter(|c| **c == Call::Acquire)
                .count();
            assert_eq!(acquisitions, 1, "commit={commit}, anchor={lose_anchor}");
            if lose_anchor {
                assert!(
                    e.platform.anchor_loaded_at.unwrap() - e.platform.anchor_lost_at.unwrap() <= 2
                );
                assert_eq!(
                    e.platform
                        .calls
                        .iter()
                        .filter(|c| **c == Call::LoadAnchor)
                        .count(),
                    2
                );
            } else {
                assert!(
                    e.platform.pf_enabled_at.unwrap() - e.platform.pf_disabled_at.unwrap() <= 2
                );
                if commit == 2 {
                    // Disable invalidated the acquired token: settlement/reacquire
                    // is required on the next stateful step.
                    assert!(e.platform.tokens.is_empty());
                    assert!(e.emergency_needs_reference);
                }
            }
            let repaired_at = if lose_anchor {
                e.platform.anchor_loaded_at.unwrap()
            } else {
                e.platform.pf_enabled_at.unwrap()
            };
            let flush_at = e.emergency_states_clean_at.unwrap();
            assert!(flush_at >= repaired_at);
            e.platform.calls.clear();
            e.run_emergency();
            assert!(!e.in_emergency_step);
            assert_eq!(e.platform.tokens.len(), 1);
            let tokens: Vec<_> = e
                .emergency_references
                .iter()
                .map(|entry| entry.key)
                .collect();
            assert_eq!(
                tokens,
                e.platform
                    .tokens
                    .keys()
                    .copied()
                    .map(ReferenceEntry::Token)
                    .collect::<Vec<_>>()
            );
            assert!(!e.emergency_unreserved_consumed);
            assert!(!e.emergency_needs_reference);
            assert_eq!(e.snapshot, e.committed);
            let proof = e.emergency_proof.as_ref().unwrap();
            assert!(proof.verified_at() >= repaired_at);
            if lose_anchor || commit == 2 {
                assert!(e.platform.calls.contains(&Call::Collect));
            }
            assert_eq!(
                proof.states_clean_at(),
                e.emergency_states_clean_at.unwrap()
            );
        }
    }
}

#[test]
fn constructor_recovery_slow_pair_commit_keeps_full_budget() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    for copy in [Copy::A, Copy::B] {
        p.mutate(Mutation::CopyRot(copy));
        p.inject(Call::Write(copy), 1, Fault::StorageDelay(60));
    }
    let at = p.now();
    let e = Engine::start(p).unwrap();
    assert!(!e.storage_blocked);
    assert_eq!(e.mode, Mode::Normal);
    assert!(e.platform.calls.contains(&Call::Write(Copy::A)));
    assert!(e.platform.calls.contains(&Call::Write(Copy::B)));
    let mut p = e.into_platform();
    assert!(p.now() - at >= 6);
    assert!(p.outstanding.is_none());
    for copy in [Copy::A, Copy::B] {
        assert!(matches!(
            snapshot::classify_copy(p.read_copy(copy, Deadline(u64::MAX))),
            snapshot::CopyClass::V { .. }
        ));
    }
}

#[test]
fn retry_storage_missing_repair_slow_create_keeps_full_budget() {
    let mut e = fresh();
    let bytes = snapshot::encode(e.seq, &e.snapshot).unwrap();
    e.platform.mutate(Mutation::MissingCopy(Copy::B));
    e.repair_pending = Some((Copy::B, bytes.clone()));
    e.block_storage();
    e.next_storage = e.platform.now();
    e.platform
        .inject(Call::Create(Copy::B), 1, Fault::StorageDelay(60));
    let at = e.platform.now();
    e.retry_storage();
    assert!(e.platform.now() - at >= 3);
    assert!(e.repair_pending.is_none());
    assert!(!e.storage_blocked);
    assert!(e.platform.outstanding.is_none());
    let committed = snapshot::encode(e.seq, &e.committed).unwrap();
    assert_eq!(
        e.platform.copies[1].durable.as_deref(),
        Some(committed.as_ref())
    );
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Create(Copy::B))
            .count(),
        1
    );
}

#[test]
fn guarded_reservation_failure_rechecks_pf_before_unreserved_acquire() {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.platform
        .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(60));
    e.platform.inject(Call::Write(Copy::B), 1, Fault::NoSpace);
    e.run_emergency();
    assert!(e.platform.enabled);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(!e.emergency_unreserved_consumed);
    assert!(e.storage_blocked);
}

#[test]
fn negative_storage_check_survives_saved_reducer_handoff() {
    for fail in [false, true] {
        let mut e = joined();
        let mut pending = e.snapshot.clone();
        pending
            .requests
            .try_push(RequestRecord {
                id: 900,
                kind: snapshot::RequestKind::JoinDone,
            })
            .unwrap();
        e.waiting = Some((e.machine.clone(), pending));
        e.mode = Mode::PersistBlocked;
        e.storage_blocked = true;
        e.next_storage = e.platform.now();
        e.next_emergency = e.platform.now().saturating_add(1);
        e.platform
            .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(60));
        if fail {
            e.platform.inject(Call::Write(Copy::B), 1, Fault::NoSpace);
        } else {
            e.platform
                .inject(Call::Write(Copy::B), 1, Fault::StorageDelay(60));
        }
        e.platform.mutate_after_ticks(40, Mutation::PfDisable);
        e.retry_storage();
        assert!(e.platform.enabled);
        assert!(!matches!(
            e.machine.enforcement_at(&Clock(e.platform.now())),
            Verdict::Protected(_)
        ));
        if fail {
            assert!(e.waiting.is_some());
            e.next_storage = e.platform.now();
            e.retry_storage();
        }
        assert_eq!(e.mode, Mode::Normal);
        assert!(e.waiting.is_none());
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    }
}

#[test]
fn guarded_unknown_readback_retries_until_verified() {
    for (readback, verified) in [
        (
            policy::render_lockdown()
                .as_str()
                .replace("block drop", "block   drop"),
            true,
        ),
        (
            policy::render_lockdown().as_str().replace("no state", ""),
            false,
        ),
        ("normalized but unsupported lockdown output".into(), false),
    ] {
        let mut e = reboot_before_emergency();
        e.mode = Mode::Stuck;
        e.platform.enabled = true;
        e.emergency_needs_reference = true;
        e.platform.anchor_readback = Some(readback);
        for copy in [Copy::A, Copy::B] {
            e.platform
                .inject(Call::Write(copy), 1, Fault::StorageDelay(90));
        }
        e.platform.model_firewall = true;
        e.run_emergency();
        assert_eq!(e.emergency_frame_disturbed, !verified);
        assert_eq!(e.emergency_guard_reload_pending, !verified);
        assert_eq!(e.emergency_readback.is_none(), !verified);
        assert_eq!(e.emergency_proof.is_some(), verified);
        let loads: Vec<_> = e
            .platform
            .firewall_events
            .iter()
            .filter(|event| event.call == Call::LoadAnchor)
            .collect();
        if verified {
            assert_eq!(loads.len(), 1);
        } else {
            assert!(loads.len() >= 3);
        }
        assert!(loads.windows(2).all(|pair| pair[1].at > pair[0].at));
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Generated orderings share one timing/order/state oracle.
fn guarded_frame_generated_repair_orderings() {
    for commit in [1, 2] {
        // Each row interferes inside one reservation or post-acquire commit. Include the first
        // outer-load second, either side of its gate, and later slices.
        for loss_tick in [0, 1, 19, 20, 21, 40] {
            for scenario in 0..11 {
                let mut e = reboot_before_emergency();
                e.mode = Mode::Stuck;
                e.platform.enabled = true;
                e.emergency_needs_reference = false;
                e.storage_waiting = true;
                assert!(e.load_emergency().is_ok());
                e.storage_waiting = false;
                e.emergency_needs_reference = true;
                e.platform.model_firewall = true;
                if commit == 2 {
                    e.platform.capture_after(Call::Acquire, 1);
                }
                for copy in [Copy::A, Copy::B] {
                    e.platform
                        .inject(Call::Write(copy), commit, Fault::StorageDelay(90));
                }
                if (1..=3).contains(&scenario) {
                    // Start before the first timed detection, including gate-open
                    // loss rows, and retain capacity pressure across a full slice.
                    e.platform.mutate_after_ticks(
                        1,
                        Mutation::PfctlCapacity(loss_tick + 20 * scenario + 20),
                    );
                }
                let change_tick = if (1..=3).contains(&scenario) && loss_tick == 1 {
                    2 // The scheduler stores one mutation per tick.
                } else {
                    loss_tick
                };
                if change_tick == 0 {
                    // Detect in the outer load's same second, before the first
                    // wait. All other rows write during an outstanding slice.
                    e.platform.mutate(Mutation::AnchorChange);
                } else {
                    e.platform
                        .mutate_after_ticks(change_tick, Mutation::AnchorChange);
                }
                match scenario {
                    4 => e.platform.inject(Call::CheckPfctl, 1, Fault::ReadFail),
                    5 => e
                        .platform
                        .inject(Call::LoadAnchor, 1, Fault::ToolFail { effect: false }),
                    6 | 7 => e.platform.mutate(Mutation::CaptureRace(scenario == 7)),
                    8 => e
                        .platform
                        .mutate_after_ticks(loss_tick + 65, Mutation::AnchorChange),
                    9 => e
                        .platform
                        .inject(Call::Flush, 1, Fault::ToolFail { effect: false }),
                    10 => e
                        .platform
                        .mutate_after_ticks(loss_tick + 1, Mutation::PfDisable),
                    _ => {}
                }
                assert!(
                    e.load_emergency().is_err(),
                    "tick={loss_tick} scenario={scenario}"
                );
                if commit == 2 {
                    let acquired = e.platform.take_capture().unwrap();
                    assert!(acquired.calls.contains(&Call::Acquire));
                    assert!(
                        acquired.firewall_events.iter().all(|event| !event.guarded),
                        "acquire must precede the first guarded event: {loss_tick}/{scenario}"
                    );
                }
                assert!(e.emergency_frame_disturbed);
                assert!(e.emergency_proof.is_none());
                assert!(!e.verified_enforcement);
                assert!(e.emergency_readback.is_none());
                assert!(!e.emergency_guard_reload_pending, "{loss_tick}/{scenario}");
                assert!(!e.emergency_guard_flush_pending, "{loss_tick}/{scenario}");
                let events = &e.platform.firewall_events;
                let changes: Vec<_> = events
                    .iter()
                    .enumerate()
                    .filter(|(_, event)| event.call == Call::Mutation(Mutation::AnchorChange))
                    .collect();
                assert_eq!(
                    changes.len(),
                    if (6..=8).contains(&scenario) { 2 } else { 1 },
                    "capture race/two changes must be reached: {loss_tick}/{scenario}"
                );
                for (index, change) in changes {
                    let (reload_index, reload) = events
                        .iter()
                        .enumerate()
                        .skip(index + 1)
                        .find(|(_, event)| {
                            event.call == Call::LoadAnchor
                                && event.succeeded
                                && event.anchor.as_deref()
                                    == Some(policy::render_lockdown().as_str())
                        })
                        .unwrap();
                    assert!(
                        reload.guarded,
                        "repair escaped commit: {loss_tick}/{scenario}"
                    );
                    let recovered = events
                        .iter()
                        .skip(index + 1)
                        .take(reload_index - index)
                        .find(|event| event.call == Call::Mutation(Mutation::PfctlCapacity(0)))
                        .map_or(change.at, |event| event.at);
                    if (1..=3).contains(&scenario) {
                        assert_ne!(recovered, change.at, "capacity must precede repair");
                        assert!(
                            recovered > change.at + 1000,
                            "capacity must remain refused through the next detection slice: {loss_tick}/{scenario}"
                        );
                    }
                    let possible = recovered
                        .max(change.at)
                        .max(e.platform.firewall_events.first().unwrap().at);
                    assert!(
                        reload.at.saturating_sub(possible) <= 2000,
                        "repair after recovery: {loss_tick}/{scenario}: {events:?}"
                    );
                    if !(1..=3).contains(&scenario) {
                        assert!(
                            reload.at - change.at <= 3000,
                            "{loss_tick}/{scenario}: {events:?}"
                        );
                    }
                    let (flush_index, flush) = events
                        .iter()
                        .enumerate()
                        .skip(reload_index + 1)
                        .find(|(_, event)| {
                            event.call == Call::Flush
                                && event.succeeded
                                && event.anchor.as_deref()
                                    == Some(policy::render_lockdown().as_str())
                        })
                        .unwrap();
                    assert!(
                        flush.guarded,
                        "flush escaped commit: {loss_tick}/{scenario}"
                    );
                    if !flush.enabled {
                        let enable = events
                            .iter()
                            .skip(flush_index + 1)
                            .find(|event| event.call == Call::EnablePf && event.succeeded)
                            .unwrap();
                        assert_eq!(enable.at, flush.at);
                        assert_eq!(
                            enable.anchor.as_deref(),
                            Some(policy::render_lockdown().as_str())
                        );
                    }
                    // Without an intervening writer or a failed flush, the
                    // repair's flush must complete in the same slice/second.
                    // A flush moved before load would instead wait another slice.
                    let raced = events[reload_index + 1..flush_index]
                        .iter()
                        .any(|event| event.call == Call::Mutation(Mutation::AnchorChange));
                    if !raced && scenario != 9 {
                        assert_eq!(
                            flush.at, reload.at,
                            "deferred flush: {loss_tick}/{scenario}"
                        );
                    }
                    assert!(change.created > change.flushed, "no real state created");
                    assert!(flush.flushed >= change.created);
                    assert!(
                        flush.at.saturating_sub(recovered) <= 3000,
                        "flush after recovery: {loss_tick}/{scenario}: {events:?}"
                    );
                }
                for call in [Call::Flush, Call::LoadAnchor] {
                    let attempts: Vec<_> = events
                        .iter()
                        .filter(|event| event.guarded && event.call == call)
                        .collect();
                    assert!(
                        attempts
                            .windows(2)
                            .all(|pair| pair[1].at / 1000 > pair[0].at / 1000),
                        "cadence: {loss_tick}/{scenario}: {events:?}"
                    );
                }
                // A distinct forced outer flush follows the last guarded repair.
                let last_guarded_reload = events
                    .iter()
                    .rposition(|event| event.call == Call::LoadAnchor && event.guarded)
                    .unwrap();
                let outer_flush = events
                    .iter()
                    .position(|event| {
                        event.call == Call::Flush && !event.guarded && event.succeeded
                    })
                    .unwrap();
                assert!(
                    outer_flush > last_guarded_reload,
                    "outer flush must follow repair"
                );
            }
        }
    }
}

#[test]
fn verified_guarded_repair_resets_grown_backoff_across_frames() {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.platform.enabled = true;
    e.emergency_needs_reference = false;
    e.storage_waiting = true;
    // Build real observation backoff without ever publishing protection.
    e.platform
        .inject_persistent(Call::ReadAnchor, Fault::ReadFail);
    for _ in 0..5 {
        let wait = e.emergency_next_reload.saturating_sub(e.platform.now());
        let d = Deadline(e.platform.now() + wait);
        e.platform.pause(Duration::from_secs(wait), d);
        assert!(e.load_emergency().is_err());
        assert!(e.emergency_proof.is_none());
    }
    assert!(e.emergency_reload_delay >= 16);
    e.platform.clear_faults();
    let wait = e.emergency_next_reload.saturating_sub(e.platform.now());
    let d = Deadline(e.platform.now() + wait);
    e.platform.pause(Duration::from_secs(wait), d);
    e.storage_waiting = false;
    e.emergency_needs_reference = true;
    e.platform.model_firewall = true;
    for copy in [Copy::A, Copy::B] {
        e.platform
            .inject(Call::Write(copy), 1, Fault::StorageDelay(90));
    }
    e.platform.mutate_after_ticks(1, Mutation::AnchorChange);
    assert!(e.load_emergency().is_err());
    assert!(e.emergency_frame_disturbed);
    assert!(!e.emergency_guard_reload_pending);
    assert!(!e.emergency_guard_flush_pending);
    assert!(e.emergency_readback.is_none());
    assert!(e.emergency_proof.is_none());
    assert!(!e.verified_enforcement);
    assert_eq!(e.emergency_reload_delay, 1);
    assert!(e.emergency_next_reload <= e.platform.now() + 1);
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(
        e.platform
            .firewall_events
            .iter()
            .any(|event| { event.call == Call::LoadAnchor && event.guarded && event.succeeded })
    );

    // With no more storage waits, only the outer path can see the next writer.
    e.storage_blocked = true;
    e.platform.firewall_events.clear();
    e.platform.mutate(Mutation::AnchorChange);
    let change = e.platform.firewall_events.last().unwrap().at;
    assert_eq!(e.platform.anchor.as_deref(), Some("pass quick all\n"));
    assert!(e.platform.enabled);
    for _ in 0..=40 {
        let _ = e.load_emergency();
        if e.platform.anchor.as_deref() == Some(policy::render_lockdown().as_str()) {
            break;
        }
        let d = Deadline(e.platform.now() + 1);
        e.platform.pause(Duration::from_millis(50), d);
    }
    let reload = e
        .platform
        .firewall_events
        .iter()
        .find(|event| event.call == Call::LoadAnchor && event.succeeded)
        .unwrap();
    assert!(!reload.guarded);
    assert!(reload.at - change <= 2000);
    assert_eq!(
        reload.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(
        e.platform
            .firewall_events
            .iter()
            .all(|event| !event.guarded)
    );
}

#[test]
fn pending_guarded_reload_resets_grown_backoff_across_frames() {
    for pin_failure in [false, true] {
        let mut e = reboot_before_emergency();
        e.mode = Mode::Stuck;
        e.platform.enabled = true;
        e.emergency_needs_reference = false;
        e.storage_waiting = true;
        // Grow the real outer backoff through consecutive unprotected frames.
        e.platform
            .inject_persistent(Call::ReadAnchor, Fault::ReadFail);
        for _ in 0..5 {
            let wait = e.emergency_next_reload.saturating_sub(e.platform.now());
            let d = Deadline(e.platform.now() + wait);
            e.platform.pause(std::time::Duration::from_secs(wait), d);
            assert!(e.load_emergency().is_err());
            assert!(e.emergency_proof.is_none());
        }
        assert!(e.emergency_reload_delay >= 16);
        e.platform.clear_faults();
        let wait = e.emergency_next_reload.saturating_sub(e.platform.now());
        let d = Deadline(e.platform.now() + wait);
        e.platform.pause(std::time::Duration::from_secs(wait), d);
        e.storage_waiting = false;
        e.emergency_needs_reference = true;
        e.platform.model_firewall = true;
        // Both post-load reads see the same foreign text, so capture itself
        // cannot reset the grown backoff. The guard must retain reload debt.
        e.platform.mutate(Mutation::CaptureRace(false));
        for copy in [Copy::A, Copy::B] {
            e.platform.inject(
                Call::Write(copy),
                1,
                Fault::StorageDelay(if pin_failure { 90 } else { 21 }),
            );
        }
        if pin_failure {
            e.platform
                .inject_persistent(Call::CheckPfctl, Fault::ReadFail);
        } else {
            // Refuse both detection slices, including the final slice at 2 s.
            // Capacity recovers at 2.05 s, just before the commit ends at 2.1 s.
            e.platform
                .mutate_after_ticks(1, Mutation::PfctlCapacity(40));
        }
        assert!(e.load_emergency().is_err());
        assert!(e.emergency_frame_disturbed);
        assert!(e.emergency_guard_reload_pending);
        assert!(e.emergency_proof.is_none());
        assert!(e.emergency_readback.is_none());
        assert_eq!(e.platform.anchor.as_deref(), Some("pass quick all\n"));
        assert!(e.platform.enabled);
        assert_eq!(e.emergency_reload_delay, 1);
        assert!(e.emergency_next_reload <= e.platform.now() + 1);
        // No guarded load succeeded: one branch deferred its final slice for
        // capacity; the other failed pin checks through commit completion.
        assert!(
            !e.platform
                .firewall_events
                .iter()
                .any(|event| { event.call == Call::LoadAnchor && event.guarded })
        );
        if !pin_failure {
            assert!(
                e.platform
                    .safety_events
                    .iter()
                    .any(|event| matches!(event, platform::SafetyEvent::PfctlCapacity { .. }))
            );
            assert!(
                e.platform
                    .firewall_events
                    .iter()
                    .any(|event| { event.call == Call::Mutation(Mutation::PfctlCapacity(0)) })
            );
        }
        let frame_end = e.platform.firewall_events.last().unwrap().at;
        e.platform.clear_faults();
        // Exercise the no-storage-wait handoff rather than another guard.
        e.storage_blocked = true;
        e.platform.firewall_events.clear();
        for _ in 0..=20 {
            let _ = e.load_emergency();
            if e.platform.anchor.as_deref() == Some(policy::render_lockdown().as_str()) {
                break;
            }
            let d = Deadline(e.platform.now() + 1);
            e.platform.pause(std::time::Duration::from_millis(50), d);
        }
        let reload = e
            .platform
            .firewall_events
            .iter()
            .find(|event| event.call == Call::LoadAnchor && event.succeeded)
            .unwrap();
        assert!(!reload.guarded);
        assert!(reload.at - frame_end <= 1000);
        assert_eq!(
            reload.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert!(
            e.platform
                .firewall_events
                .iter()
                .all(|event| !event.guarded)
        );
    }
}

#[test]
fn guarded_anchor_change_failed_reservation_forces_outer_flush() {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    // Install once without acquiring, then request a stateful reservation with
    // a fresh clean timestamp and a long flush backoff already in force.
    e.emergency_needs_reference = false;
    e.storage_waiting = true;
    e.platform.enabled = true;
    assert!(e.load_emergency().is_ok());
    e.storage_waiting = false;
    e.emergency_needs_reference = true;
    e.emergency_states_clean_at = Some(e.platform.now());
    e.emergency_next_flush = e.platform.now() + 60;
    e.emergency_flush_delay = 60;
    e.platform
        .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(90));
    e.platform.inject(Call::Write(Copy::B), 1, Fault::NoSpace);
    e.platform.mutate_after_ticks(40, Mutation::AnchorChange);
    e.platform.calls.clear();
    e.platform.capture_after(Call::Flush, 1);
    assert!(matches!(
        e.load_emergency(),
        Err(SysError::Failed("emergency readback unavailable"))
    ));
    let mut guarded = e.platform.take_capture().unwrap();
    assert!(guarded.now() - guarded.anchor_lost_at.unwrap() <= 2);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(e.emergency_frame_disturbed);
    assert!(e.emergency_proof.is_none());
    // One flush inside the wait and a distinct forced outer flush, even though
    // enable returned Ok(false) after the failed reservation.
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::Flush)
            .count(),
        2
    );
    assert_eq!(e.emergency_states_clean_at, Some(e.platform.now()));
    assert!(e.storage_blocked);
}

fn guarded_test_frame() -> Engine<FakePlatform> {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.platform.enabled = true;
    e.emergency_needs_reference = false;
    e.storage_waiting = true;
    assert!(e.load_emergency().is_ok());
    e.storage_waiting = false;
    e.reset_emergency_frame();
    e.in_emergency_step = true;
    e.platform.model_firewall = true;
    e
}

fn next_guard_slice(e: &mut Engine<FakePlatform>) {
    let d = Deadline(e.platform.now() + 2);
    e.platform.pause(std::time::Duration::from_secs(1), d);
    e.attempt_stateless_containment();
}

#[test]
fn guarded_latches_survive_deferral_and_foreign_restoration() {
    let mut e = guarded_test_frame();
    e.platform.mutate(Mutation::AnchorChange);
    assert_ne!(e.platform.states, [] as [bool; 0]);
    e.attempt_stateless_containment();
    assert!(e.emergency_guard_reload_pending);
    assert!(!e.emergency_guard_flush_pending);
    assert_eq!(e.platform.states, [] as [bool; 0]);
    assert_eq!(e.platform.firewall_events.last().unwrap().call, Call::Flush);
    // A verified observation without our own reload must not discharge debt.
    e.platform.anchor = Some(policy::render_lockdown().as_str().into());
    e.platform.inject(Call::CheckPfctl, 1, Fault::ReadFail);
    next_guard_slice(&mut e);
    assert!(e.emergency_guard_reload_pending);
    assert!(!e.emergency_guard_flush_pending);
    let before = e.platform.firewall_events.len();
    next_guard_slice(&mut e);
    assert!(!e.emergency_guard_reload_pending);
    assert!(!e.emergency_guard_flush_pending);
    assert_eq!(
        e.emergency_readback.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    let repaired = &e.platform.firewall_events[before..];
    assert_eq!(repaired[0].call, Call::LoadAnchor);
    assert_eq!(repaired[1].call, Call::Flush);
    assert!(e.emergency_frame_disturbed);
    assert!(e.emergency_proof.is_none());
}

#[test]
fn guarded_reload_latch_requires_successful_load_and_verified_capture() {
    for failure in 0..7 {
        let mut e = guarded_test_frame();
        e.platform.mutate(Mutation::AnchorChange);
        match failure {
            0 => e
                .platform
                .inject(Call::LoadAnchor, 1, Fault::ToolFail { effect: false }),
            1 => e
                .platform
                .inject(Call::LoadAnchor, 1, Fault::ToolFail { effect: true }),
            2 => e.platform.inject(Call::ReadAnchor, 2, Fault::ReadFail),
            3 => e.platform.inject(Call::ReadAnchor, 3, Fault::ReadFail),
            4 | 5 => e.platform.mutate(Mutation::CaptureRace(failure == 5)),
            6 => e.platform.anchor_readback_absent = true,
            _ => unreachable!(),
        }
        next_guard_slice(&mut e);
        assert!(e.emergency_guard_reload_pending, "failure={failure}");
        // A failed/unverified guarded load never installs a raw reference.
        assert_ne!(e.emergency_readback.as_deref(), Some("pass quick all\n"));
        if (2..=6).contains(&failure) {
            assert!(e.emergency_readback.is_none());
        }
        e.platform.anchor_readback_absent = false;
        next_guard_slice(&mut e);
        assert!(!e.emergency_guard_reload_pending, "failure={failure}");
        assert!(!e.emergency_guard_flush_pending);
        assert!(e.emergency_frame_disturbed);
    }
}

#[test]
fn guarded_flush_latch_retries_enable_failure_and_capacity_refusal() {
    for capacity in [false, true] {
        let mut e = guarded_test_frame();
        e.platform.mutate(Mutation::PfDisable);
        e.platform.states.push(true);
        let before = e.platform.calls.len();
        e.platform
            .inject(Call::Flush, 1, Fault::ToolFail { effect: false });
        e.attempt_stateless_containment();
        assert!(e.platform.enabled);
        assert!(e.platform.calls[before..].contains(&Call::EnablePf));
        assert!(e.emergency_guard_flush_pending);
        assert!(!e.emergency_guard_reload_pending);
        assert_ne!(e.platform.states, [] as [bool; 0]);
        if capacity {
            e.platform.mutate(Mutation::PfctlCapacity(40));
            let before = e.platform.firewall_events.len();
            next_guard_slice(&mut e);
            assert!(e.emergency_guard_flush_pending);
            assert!(e.emergency_guard_reload_pending);
            assert_eq!(e.platform.firewall_events.len(), before);
        }
        next_guard_slice(&mut e);
        assert!(!e.emergency_guard_flush_pending);
        assert!(!e.emergency_guard_reload_pending);
        assert_eq!(e.platform.states, [] as [bool; 0]);
        assert!(e.emergency_frame_disturbed);
        assert!(e.emergency_states_clean_at.is_none());
        assert!(e.emergency_proof.is_none());
    }
}

#[test]
fn guarded_cadence_applies_to_repeated_slices() {
    let mut e = guarded_test_frame();
    e.platform.anchor_readback = Some("unsupported readback".into());
    next_guard_slice(&mut e);
    assert!(e.emergency_guard_reload_pending);
    let before = e.platform.firewall_events.len();
    e.attempt_stateless_containment();
    assert!(e.emergency_guard_reload_pending);
    assert!(e.emergency_guard_flush_pending);
    assert_eq!(e.platform.firewall_events.len(), before);
    next_guard_slice(&mut e);
    assert_eq!(e.platform.firewall_events.len(), before + 2);
    assert!(e.emergency_frame_disturbed);
}
