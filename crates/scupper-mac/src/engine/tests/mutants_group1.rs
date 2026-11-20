//! Focused source-reviewed witnesses for the group-1 survivors.
use super::*;

fn startup() -> Engine<FakePlatform> {
    let mut e = fresh();
    e.mode = Mode::Starting;
    e.helper_committed = false;
    e.start_fence = StartFence::Uncommitted;
    e.startup_invariant_checked = false;
    e.platform.calls.clear();
    e
}

#[test]
fn startup_containment_respects_revocation_refusal_and_cadence() {
    for gate in 0..3 {
        let mut e = startup();
        e.snapshot.machine.join_intended = true;
        e.emergency_revoked = gate == 0;
        e.startup_invariant_failed = gate == 1;
        e.next_emergency = if gate == 2 { u64::MAX } else { 0 };
        // Stop after the prestep so later startup work cannot hide its effects.
        e.platform
            .inject_persistent(Call::Processes, Fault::Incomplete);
        e.finish_start();
        assert!(!e.platform.calls.contains(&Call::CheckPfctl), "gate {gate}");
    }
}

#[test]
fn unknown_startup_inventory_uses_one_second_and_reaps_children() {
    let mut e = startup();
    e.platform.inject(Call::Processes, 1, Fault::WriteHang);
    let at = e.platform.now();
    e.finish_start();
    assert_eq!(e.platform.now() - at, 1);
    assert!(e.platform.calls.contains(&Call::ReapChildren));
}

#[test]
fn startup_retries_due_missing_copy_repair_before_helper_commit() {
    let mut e = startup();
    e.platform.mutate(Mutation::MissingCopy(Copy::B));
    e.storage_blocked = true;
    e.next_storage = e.platform.now();
    e.repair_pending = Some((Copy::B, snapshot::encode(e.seq, &e.snapshot).unwrap()));
    e.finish_start();
    assert!(e.platform.calls.contains(&Call::Create(Copy::B)));
}

#[test]
fn startup_open_fence_does_not_add_a_second_drain_budget() {
    let mut e = startup();
    e.startup_invariant_checked = true;
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    e.platform.inject(Call::ReapChildren, 1, Fault::WriteHang);
    let at = e.platform.now();
    e.finish_start();
    assert_eq!(e.platform.now() - at, 1);
}

#[test]
fn startup_does_not_replay_join_over_internal_error() {
    let mut e = startup();
    e.snapshot.internal_error = Some(snapshot::InternalError::Other);
    e.snapshot
        .requests
        .try_push(RequestRecord {
            id: 77,
            kind: snapshot::RequestKind::Join,
        })
        .unwrap();
    e.finish_start();
    // Join becomes durable only when PersistIntent completes, two boundaries
    // after replay. An immediate durable-intent check would miss the mutation.
    e.run_until_quiescent(2);
    assert!(!e.machine.durable().join_intended);
}

#[test]
fn recovery_pair_commit_retains_full_write_budget() {
    let mut e = fresh();
    e.startup_storage = Some(StartupStorage {
        repair: None,
        recovery: true,
        missing: [false, false],
        bytes: snapshot::encode(e.seq, &e.snapshot).unwrap(),
    });
    e.platform.calls.clear();
    e.platform
        .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(30));
    e.platform
        .inject(Call::Write(Copy::B), 1, Fault::StorageDelay(30));
    e.initialize_start_storage();
    assert!(e.platform.calls.contains(&Call::Write(Copy::B)));
}

#[test]
fn lockless_join_reports_lock_refusal_before_mode_refusal() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    assert_eq!(
        e.submit(Request {
            id: 22,
            kind: RequestKind::Join
        }),
        Err(SysError::Failed("instance lock unavailable"))
    );
}

#[test]
fn accepted_core_acquisition_prevents_duplicate_emergency_reference() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    e.emergency_needs_reference = true;
    e.dispatch(Step::AcquireReference);
    let completion = e.queue.pop_front().unwrap();
    e.process(completion);
    e.platform.calls.clear();
    e.enable_emergency_pf().unwrap();
    assert!(!e.platform.calls.contains(&Call::Acquire));
}

fn emergency() -> Engine<FakePlatform> {
    let mut e = reboot_before_emergency();
    e.enter_stuck();
    assert_emergency(&mut e);
    e
}

#[test]
fn emergency_publication_requires_both_fences() {
    for start in [false, true] {
        let mut e = emergency();
        if start {
            e.start_fence = StartFence::Uncommitted;
        } else {
            e.platform.unreaped.push(platform::Unreaped {
                tool: Tool::Pfctl,
                pid: 900,
            });
        }
        assert_eq!(e.status().text, "containment attempted; safety unproven");
        assert!(!e.status().emergency_blocking_verified);
    }
}

#[test]
fn installed_proof_cannot_certify_emergency_lockdown() {
    let mut e = joined();
    let Verdict::Protected(proof) = e.machine.enforcement_at(&Clock(e.platform.now())) else {
        panic!("proof missing")
    };
    e.emergency_proof = Some(proof);
    e.emergency_last_load_at = Some(e.platform.now());
    e.mode = Mode::Stuck;
    assert_eq!(e.status().text, "containment attempted; safety unproven");
}

#[test]
fn expired_emergency_proof_changes_publication_text() {
    let mut e = emergency();
    for _ in 0..(e.timings.max_age + 1) * 20 {
        e.platform.tick();
    }
    assert_eq!(e.status().text, "containment attempted; safety unproven");
}

#[test]
fn ordinary_blocking_publication_requires_fence_and_no_overflow() {
    for overflow in [false, true] {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::CheckTools);
        assert!(
            e.status().blocking_verified,
            "fixture needs a PreTunnel proof"
        );
        // Preserve the verified proof at the publication boundary; queue ingress
        // also invalidates the reducer, which would conceal the overflow guard.
        if overflow {
            e.overflowed = true;
        } else {
            e.platform.unreaped.push(platform::Unreaped {
                tool: Tool::Route,
                pid: 900,
            });
        }
        assert!(!e.status().blocking_verified);
    }
}

#[test]
fn uncommitted_helper_masks_a_fresh_joined_proof() {
    let mut e = joined();
    e.helper_committed = false;
    assert_eq!(
        e.status().enforcement,
        Verdict::NotProtected(Reason::Observation("engine: start fence open"))
    );
}

#[test]
fn repeated_lock_interrupts_back_off_even_without_clock_progress() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    p.inject_persistent(Call::AcquireInstanceLock, Fault::LockInterrupted);
    let mut e = Engine::start(p).unwrap();
    for _ in 0..20 {
        e.platform.tick();
    }
    e.run_lockless();
    e.platform.calls.clear();
    e.run_lockless();
    assert!(!e.platform.calls.contains(&Call::AcquireInstanceLock));
}

fn lockless_writer() -> Engine<FakePlatform> {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    p.inject_persistent(Call::AcquireInstanceLock, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    e
}

#[test]
fn lockless_cancellation_requires_parent_and_group() {
    for parent in [false, true] {
        let mut e = lockless_writer();
        let pid = e.platform.unreaped[0].pid;
        let proc = e.platform.procs.get_mut(&pid).unwrap();
        if parent {
            proc.ppid = 444;
        } else {
            proc.pgid = 444;
        }
        e.platform.calls.clear();
        e.run_lockless();
        assert!(
            !e.platform
                .calls
                .iter()
                .any(|call| matches!(call, Call::KillProcess(target, _) if *target == pid))
        );
    }
}

#[test]
fn lockless_cancellation_inventory_has_one_second_budget() {
    let mut e = lockless_writer();
    e.platform.inject(Call::Processes, 1, Fault::WriteHang);
    let at = e.platform.now();
    e.run_lockless();
    assert_eq!(e.platform.now() - at, 1);
}

#[test]
fn unequal_same_sequence_left_copies_require_containment() {
    let a = Snapshot::initial(Some(501));
    let mut b = a.clone();
    b.owner_uid = Some(502);
    let mut p = fixture(&a);
    let bytes = snapshot::encode(1, &b).unwrap();
    p.write_copy(Copy::B, &bytes, Deadline(u64::MAX));
    assert!(lockless::lockless_intent(&mut p));
}

#[test]
fn handoff_resets_reload_backoff_before_fenced_retry() {
    let mut e = fresh();
    e.snapshot.machine.join_intended = true;
    let bytes = snapshot::encode(2, &e.snapshot).unwrap();
    for copy in [Copy::A, Copy::B] {
        e.platform.write_copy(copy, &bytes, Deadline(u64::MAX));
    }
    e.emergency_next_reload = u64::MAX;
    e.emergency_loaded = false;
    e.platform.calls.clear();
    e.resume_locked_start(false);
    e.load_emergency().unwrap();
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
}

#[test]
fn ordinary_load_unparks_held_core_and_clears_attempt_publication() {
    let mut e = joined();
    let mut durable = e.machine.durable().clone();
    durable.hold = true;
    e.machine = Machine::restart(durable);
    e.snapshot.internal_error = Some(snapshot::InternalError::Other);
    e.emergency_loaded = true;
    e.emergency_last_load_at = Some(e.platform.now());
    e.execute(Step::LoadPreTunnel).unwrap();
    assert_ne!(e.status().text, "containment attempted; safety unproven");
    e.run_until_quiescent(1);
    assert!(e.in_flight.is_some(), "ordinary core prefix must dispatch");
}

#[test]
fn repair_read_maintains_containment_during_storage_delay() {
    let mut e = reboot_before_emergency();
    e.storage_blocked = true;
    e.mode = Mode::PersistBlocked;
    e.next_storage = e.platform.now();
    e.repair_pending = Some((Copy::B, snapshot::encode(e.seq, &e.snapshot).unwrap()));
    e.platform
        .inject(Call::Read(Copy::B), 1, Fault::StorageDelay(80));
    e.platform.mutate_after_ticks(1, Mutation::PfDisable);
    let at = e.platform.now();
    e.retry_storage();
    assert!(
        e.platform
            .pf_enabled_at
            .is_some_and(|enabled| enabled <= at + 2)
    );
    assert!(e.platform.enabled);
}

#[test]
fn explicit_leave_clears_probe_only_error_retention() {
    let mut state = Snapshot::initial(Some(501));
    state.internal_error = Some(snapshot::InternalError::Other);
    let mut e = Engine::start(fixture(&state)).unwrap();
    assert!(e.containment_cleanup_only);
    leave(&mut e, 22);
    drive(&mut e, 500);
    assert!(e.committed.internal_error.is_none());
}

#[test]
fn stuck_leave_does_not_cancel_tools_before_ownership() {
    let mut e = lockless_writer();
    e.lockless = None;
    e.mode = Mode::Stuck;
    e.startup_invariant_checked = false;
    e.start_fence = StartFence::Uncommitted;
    e.platform.inject(Call::Processes, 1, Fault::Incomplete);
    e.platform.calls.clear();
    e.accept_leave(Request {
        id: 2,
        kind: RequestKind::Leave,
    })
    .unwrap();
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|call| matches!(call, Call::KillProcess(..)))
    );
}

#[test]
fn stuck_leave_waits_for_own_writer_even_with_closed_start_fence() {
    let mut e = emergency();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    e.emergency_revoked = true;
    e.stuck_leave = Some(VecDeque::from([Step::CleanupDns]));
    e.platform.calls.clear();
    e.run_stuck_leave();
    assert!(!e.platform.calls.contains(&Call::CleanupDns));
}

#[test]
fn ordinary_load_does_not_reuse_lockdown_readback_for_drift() {
    let mut e = joined();
    e.emergency_readback = Some(policy::render_lockdown().as_str().into());
    e.execute(Step::LoadJoined).unwrap();
    e.execute(Step::VerifyJoinedLoad).unwrap();
    e.platform.calls.clear();
    e.enter_stuck();
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
}

#[test]
fn non_leave_record_does_not_claim_explicit_leave_cleanup() {
    let mut state = Snapshot::initial(Some(501));
    state.internal_error = Some(snapshot::InternalError::Other);
    state
        .requests
        .try_push(RequestRecord {
            id: 41,
            kind: snapshot::RequestKind::JoinCancelled,
        })
        .unwrap();
    let e = Engine::start(fixture(&state)).unwrap();
    let mut p = e.into_platform();
    p.crash();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert!(e.committed.internal_error.is_some());
}

pub(super) fn pre_persist_leaving() -> Snapshot {
    let mut state = Snapshot::initial(Some(501));
    state.machine.leave_requested = true;
    state
        .requests
        .try_push(RequestRecord {
            id: 42,
            kind: snapshot::RequestKind::Leave,
        })
        .unwrap();
    state.validate().unwrap();
    state
}

pub(super) fn pre_persist_leaving_with_reference() -> FakePlatform {
    let mut state = pre_persist_leaving();
    state.machine.pf_reference = Some(901);
    state.references[0] = Some(RefEvidence {
        key: ReferenceEntry::Token(901),
        boot: FakePlatform::new().unwrap().boot,
        fingerprint: Some(RefFingerprint {
            pid: 777,
            timestamp: 12,
        }),
        release_unknown: false,
    });
    state.validate().unwrap();
    let mut p = fixture(&state);
    p.tokens.insert(
        901,
        RefLine {
            token: 901,
            pid: 777,
            timestamp: 12,
        },
    );
    p.enabled = true;
    p
}

pub(super) fn assert_probe_leave_completed(e: &mut Engine<FakePlatform>) {
    assert!(e.platform.anchor.is_none());
    assert!(!e.committed.machine.join_intended);
    assert!(!e.committed.machine.leaving);
    assert!(!e.committed.machine.leave_requested);
    assert!(e.committed.machine.pending_cleanup.is_empty());
    assert!(e.committed.internal_error.is_none());
    assert!(e.committed.validate().is_ok());
    assert!(
        e.committed.requests.iter().any(|request| {
            request.id == 42 && request.kind == snapshot::RequestKind::LeaveDone
        })
    );
    assert_eq!(e.status().text, "left");
}

#[test]
fn probe_containment_preserves_pre_persist_leaving_snapshot_validity() {
    let mut e = Engine::start(fixture(&pre_persist_leaving())).unwrap();
    assert!(e.snapshot.validate().is_ok());
    assert!(e.snapshot.machine.leaving);
    assert_eq!(
        e.snapshot.machine.pending_cleanup.to_vec(),
        vec![snapshot::StepRecord::from(Step::RemoveAnchor)]
    );
    assert!(e.stuck_entry.is_none());
    assert_ne!(e.mode, Mode::Stuck);
    assert!(!e.containment_cleanup_only);
    assert!(e.platform.anchor.is_some());
    drive(&mut e, 500);
    assert!(e.stuck_entry.is_none());
    assert_probe_leave_completed(&mut e);
}

#[test]
fn probe_containment_pre_persist_leaving_keeps_full_reference_cleanup() {
    let mut e = Engine::start(pre_persist_leaving_with_reference()).unwrap();
    assert!(e.snapshot.validate().is_ok());
    assert!(e.snapshot.machine.leaving);
    assert_eq!(
        e.snapshot.machine.pending_cleanup.to_vec(),
        [
            Step::StopChild,
            Step::CleanupRoutes,
            Step::CleanupDns,
            Step::CleanupArtifacts,
            Step::RemoveAnchor,
        ]
        .map(snapshot::StepRecord::from)
        .to_vec()
    );
    assert!(e.stuck_entry.is_none());
    assert_ne!(e.mode, Mode::Stuck);
    assert!(!e.containment_cleanup_only);
    drive(&mut e, 500);
    assert!(e.stuck_entry.is_none());
    assert_probe_leave_completed(&mut e);
    let retained =
        reference_keys(&e.committed.validate().unwrap()).contains(&ReferenceEntry::Token(901));
    assert!(retained || e.platform.calls.contains(&Call::Release(901)));
    assert!(retained || !e.platform.tokens.contains_key(&901));
}

#[test]
fn stuck_leave_placeholder_releases_consistent_snapshot_reference() {
    let mut p = pre_persist_leaving_with_reference();
    p.inject_persistent(Call::Processes, Fault::Incomplete);
    let mut e = Engine::start(p).unwrap();
    assert_eq!(e.mode, Mode::Starting);
    assert!(!e.adopted);
    assert_eq!(
        reference_keys(e.machine.durable()),
        [] as [ReferenceEntry; 0]
    );
    assert_eq!(e.snapshot.machine.pf_reference, Some(901));
    e.enter_stuck();
    e.platform.clear_faults();
    drive(&mut e, 500);
    assert_eq!(e.outcome, Outcome::Exit0);
    assert_probe_leave_completed(&mut e);
    assert!(!e.committed.references[0].as_ref().unwrap().release_unknown);
    let mut p = e.into_platform();
    p.crash();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert_eq!(e.committed.machine.pf_reference, None);
    assert!(!e.platform.tokens.contains_key(&901));
    assert!(e.platform.calls.contains(&Call::Release(901)));
    assert!(e.platform.enabled);
    assert!(e.platform.anonymous_enabled);
    assert!(e.platform.anchor.is_none());
}
