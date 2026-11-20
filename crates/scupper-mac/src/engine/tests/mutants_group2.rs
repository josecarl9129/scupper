//! Boundary witnesses for group 2. No mutated implementation is executed here.
use super::*;
use crate::platform::PfInfo;
use scupper_core::mac::verify::{Observations, StateEvidence, ToolIntegrity};

fn emergency() -> Engine<FakePlatform> {
    let mut e = reboot_before_emergency();
    e.enter_stuck();
    assert_emergency(&mut e);
    e.platform.calls.clear();
    e
}

fn held() -> Engine<FakePlatform> {
    let mut e = fresh();
    let d = Durable {
        join_intended: true,
        hold: true,
        ..Durable::default()
    };
    e.machine = Machine::restart(d);
    e.snapshot.internal_error = Some(snapshot::InternalError::Other);
    e.emergency_loaded = true;
    e
}

#[test]
fn ownership_and_start_fence_share_the_emergency_drain_budget() {
    for site in 0..3 {
        let mut e = fresh();
        e.startup_invariant_checked = false;
        e.start_fence = StartFence::Uncommitted;
        if site != 0 {
            e.startup_invariant_checked = true;
        }
        if site == 0 || site == 1 {
            e.emergency_drain_until = Some(Deadline(e.platform.now() + 1));
        }
        e.platform.inject(Call::Processes, 1, Fault::WriteHang);
        let at = e.platform.now();
        if site == 0 {
            assert!(!e.check_startup_invariant());
        } else {
            assert!(!e.close_emergency_fence());
        }
        assert_eq!(e.platform.now() - at, 1, "site {site}");
    }
}

#[test]
fn emergency_drain_uses_one_total_budget_across_inventory_and_reaping() {
    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.startup_invariant_checked = false;
    e.start_fence = StartFence::Uncommitted;
    e.platform.inject(Call::Processes, 1, Fault::WriteHang);
    e.platform.inject(Call::ReapChildren, 1, Fault::WriteHang);
    let at = e.platform.now();
    e.run_emergency();
    assert_eq!(e.platform.now() - at, 1);
}

#[test]
fn held_parking_requires_hold_and_no_pending_leave() {
    for leaving in [false, true] {
        let mut e = held();
        let mut d = e.machine.durable().clone();
        if leaving {
            d.leave_requested = true;
        } else {
            d.hold = false;
        }
        e.machine = Machine::restart(d);
        assert!(!e.held_emergency_due(), "leave_requested={leaving}");
    }
}

#[test]
fn held_without_independent_load_runs_the_ordinary_blocking_prefix() {
    let mut e = held();
    e.emergency_loaded = false;
    assert!(matches!(
        e.machine.pending(),
        Some(Step::AcquireReference | Step::LoadPreTunnel)
    ));
    assert!(!e.held_emergency_due());
}

#[test]
fn stateless_containment_reports_its_actual_verdict() {
    let mut e = reboot_before_emergency();
    e.storage_waiting = true;
    e.platform.safety_events.clear();
    e.attempt_stateless_containment();
    assert!(e.platform.safety_events.iter().any(|event| matches!(event,
        platform::SafetyEvent::LocklessVerdict(result) if matches!(result.as_ref(), Ok(Verdict::Protected(_))))));
}

#[test]
fn failed_ownership_cannot_run_emergency_even_with_join_intent() {
    let mut e = reboot_before_emergency();
    e.startup_invariant_failed = true;
    e.startup_invariant_checked = true;
    e.start_fence = StartFence::Uncommitted;
    e.mode = Mode::Stuck;
    e.platform.calls.clear();
    e.run_emergency();
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
}

#[test]
fn unreaped_pfctl_revokes_cached_verification_on_failed_drain() {
    let mut e = emergency();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    let pid = e.platform.unreaped[0].pid;
    e.platform.unkillable.insert(pid);
    e.platform
        .inject_persistent(Call::CheckPfctl, Fault::ReadFail);
    e.next_emergency = 0;
    e.run_emergency();
    assert!(!e.verified_enforcement);
}

#[test]
fn positive_anchor_absence_revokes_verification_when_cheap_read_is_unknown() {
    let mut e = emergency();
    e.platform.anchor_readback_absent = true;
    e.platform.inject(Call::Cheap, 1, Fault::ReadFail);
    e.next_emergency = 0;
    e.next_full = u64::MAX;
    e.run_emergency();
    assert!(!e.verified_enforcement);
}

#[test]
fn qualification_loss_revokes_cached_verification() {
    let mut e = emergency();
    e.platform.firewall_qualification = None;
    e.next_emergency = 0;
    e.next_full = 0;
    e.run_emergency();
    assert!(!e.verified_enforcement);
    assert!(e.platform.calls.contains(&Call::CheckTools));
}

fn lockdown_observation(e: &mut Engine<FakePlatform>) -> Observations {
    let context = e.machine.context();
    let d = e.deadline();
    let completed_at = e.platform.now();
    e.platform
        .collect_lockdown(
            context,
            StateEvidence::Clean {
                epoch: context.state_epoch,
                completed_at,
            },
            d,
        )
        .unwrap()
}

#[test]
fn negative_full_walk_reasons_revoke_cached_emergency_verification() {
    for reason in 0..6 {
        let mut e = emergency();
        let mut o = lockdown_observation(&mut e);
        match reason {
            0 => o.main = parse::pf_rules(""),
            1 => o.translation = parse::translation("nat on en0 from any to any -> 192.0.2.1\n"),
            2 => {
                o.skips
                    .as_mut()
                    .unwrap()
                    .insert("en0".parse().unwrap(), true);
            }
            3 => o.os_build = "unqualified".into(),
            4 => o.pf = Ok(parse::PfInfo { enabled: false }),
            5 => o.anchor = Ok(None),
            _ => unreachable!(),
        }
        let expected = verify::LockdownExpected {
            context: e.machine.context(),
            baseline: e.emergency_baseline.as_ref().unwrap().0.clone(),
            qualification: e.platform.firewall_qualification.clone().unwrap(),
            max_age: e.timings.max_age,
        };
        let verdict = verify::verify_lockdown(&o, &expected, &Clock(e.platform.now()));
        assert!(
            matches!(
                (&verdict, reason),
                (Verdict::NotProtected(Reason::HookMissing), 0)
                    | (Verdict::NotProtected(Reason::TranslationPresent), 1)
                    | (Verdict::NotProtected(Reason::Skip(_)), 2)
                    | (Verdict::NotProtected(Reason::Unsupported(_)), 3)
                    | (Verdict::Repair(verify::Action::EnableAndRejoin), 4)
                    | (Verdict::Repair(verify::Action::Rejoin), 5)
            ),
            "reason {reason}: {verdict:?}"
        );
        e.platform.observation_override = Some(o);
        e.next_full = 0;
        e.next_emergency = 0;
        e.run_emergency();
        assert!(!e.verified_enforcement, "reason {reason}");
        assert!(
            e.platform.calls.contains(&Call::CheckTools),
            "reason {reason}"
        );
    }
}

#[test]
fn tool_integrity_failure_in_joined_full_walk_revokes_emergency_cache() {
    let mut e = joined();
    let collection = e.collection().unwrap();
    let d = e.deadline();
    let mut o = e.platform.collect(&collection, d).unwrap();
    o.tool_integrity = ToolIntegrity::Mismatch;
    e.platform.observation_override = Some(o);
    assert!(matches!(
        e.collect_verdict(Form::Joined).unwrap(),
        Event::Observed {
            verdict: Verdict::NotProtected(Reason::ToolIntegrity),
            ..
        }
    ));
    e.mode = Mode::Stuck;
    e.next_full = 0;
    e.next_emergency = 0;
    e.run_emergency();
    assert!(!e.verified_enforcement);
}

#[test]
fn raw_spelling_drift_during_reload_backoff_does_not_reset_backoff() {
    let mut e = emergency();
    let text = policy::render_lockdown().as_str().replace(' ', "   ");
    e.platform.anchor_readback = Some(text);
    e.emergency_next_reload = u64::MAX;
    e.platform.calls.clear();
    let _ = e.load_emergency();
    assert_eq!(
        e.emergency_next_reload,
        e.emergency_last_load_at.unwrap() + 1
    );
}

#[test]
fn failed_enable_after_effect_cannot_return_a_protected_result() {
    let mut e = reboot_before_emergency();
    e.platform
        .inject(Call::Acquire, 1, Fault::ToolFail { effect: true });
    assert!(e.load_emergency().is_err());
    assert!(e.platform.calls.contains(&Call::Flush));
}

#[test]
fn unequal_post_load_reads_do_not_establish_comparison_evidence() {
    let mut e = reboot_before_emergency();
    e.platform.anchor_write_between_readbacks =
        Some(policy::render_lockdown().as_str().replace(' ', "   "));
    let _ = e.load_emergency();
    assert!(e.emergency_readback.is_none());
}

#[test]
fn enable_reset_discards_clean_state_time_before_a_failed_flush() {
    let mut e = emergency();
    e.platform.mutate(Mutation::PfDisable);
    e.emergency_states_clean_at = Some(1);
    e.platform.inject(Call::Flush, 1, Fault::WriteFail);
    let _ = e.load_emergency();
    assert!(e.emergency_states_clean_at.is_none());
}

#[test]
fn enabled_unreserved_path_without_reference_debt_can_acquire_once() {
    let mut e = fresh();
    e.storage_blocked = true;
    e.platform.enabled = true;
    e.platform
        .pf_info_script
        .extend([PfInfo::Disabled, PfInfo::Enabled]);
    e.platform.calls.clear();
    e.enable_emergency_pf().unwrap();
    assert!(e.platform.calls.contains(&Call::Acquire));
}

#[test]
fn successful_emergency_acquisition_satisfies_reference_debt() {
    let mut e = fresh();
    e.emergency_needs_reference = true;
    e.enable_emergency_pf().unwrap();
    e.platform.calls.clear();
    e.enable_emergency_pf().unwrap();
    assert!(!e.platform.calls.contains(&Call::Acquire));
}

#[test]
fn zero_emergency_token_is_ambiguous_and_keeps_the_reservation() {
    let mut e = fresh();
    e.platform.acquire_zero = true;
    e.emergency_needs_reference = true;
    assert!(e.enable_emergency_pf().is_err());
    assert!(e.emergency_needs_reference);
    assert!(e.emergency_next_acquire > e.platform.now());
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .any(|entry| matches!(entry.key, ReferenceEntry::Acquire(_)))
    );
}

#[test]
fn two_keys_forbid_unreserved_emergency_acquisition() {
    let mut e = fresh();
    let mut d = e.snapshot.validate().unwrap();
    d.uncertain_acquires = vec![1, 2];
    d.reference_sequence = 2;
    e.snapshot.machine = snapshot::DurableRecord::try_from(&d).unwrap();
    e.snapshot.references = [1, 2].map(|n| {
        Some(RefEvidence {
            key: ReferenceEntry::Acquire(n),
            boot: e.platform.boot.clone(),
            fingerprint: None,
            release_unknown: false,
        })
    });
    e.snapshot.validate().unwrap();
    e.storage_blocked = true;
    e.platform.calls.clear();
    e.enable_emergency_pf().unwrap();
    assert!(!e.platform.calls.contains(&Call::Acquire));
}

#[test]
fn failed_reservation_latches_commit_failure_after_storage_recovers() {
    // A successful first acquisition consumes the unreserved allowance, so
    // this remains a smoke test even without the reservation-failure latch.
    // The NotStarted witness below isolates the latch after storage recovery.
    let mut e = fresh();
    e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteFail);
    let _ = e.enable_emergency_pf();
    e.platform.clear_faults();
    e.next_storage = 0;
    e.retry_storage();
    assert!(!e.storage_blocked);
    e.platform.mutate(Mutation::PfDisable);
    e.platform.calls.clear();
    let _ = e.enable_emergency_pf();
    assert!(!e.platform.calls.contains(&Call::Write(Copy::A)));
}

#[test]
fn failed_reservation_not_started_retry_skips_storage_after_recovery() {
    let mut e = fresh();
    // Normal mode matters: a Stuck commit failure independently sets the latch.
    assert_eq!(e.mode, Mode::Normal);
    e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteFail);
    e.platform.inject(Call::Acquire, 1, Fault::NotStarted);
    e.enable_emergency_pf().unwrap();
    assert!(e.platform.calls.contains(&Call::Acquire));
    assert!(e.storage_blocked);
    // Unlike a successful/ambiguous acquisition, NotStarted restores the
    // one-shot allowance and removes the staged reservation before retry.
    assert!(!e.emergency_unreserved_consumed);
    assert!(e.snapshot.references.iter().all(Option::is_none));

    e.platform.clear_faults();
    e.next_storage = 0;
    e.retry_storage();
    assert!(!e.storage_blocked);
    assert_eq!(e.mode, Mode::Normal);
    while e.platform.now() < e.emergency_next_acquire {
        e.platform.tick();
    }
    e.platform.mutate(Mutation::PfDisable);
    e.platform.inject(Call::Acquire, 1, Fault::NotStarted);
    e.platform.calls.clear();
    e.enable_emergency_pf().unwrap();
    // The remembered failure keeps reservation writes out of the filtering
    // path even after storage recovers. NotStarted also avoids token-result
    // persistence, so any write here would be an unwanted reservation attempt.
    assert!(e.platform.calls.contains(&Call::Acquire));
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert!(e.platform.enabled);
    assert!(!e.platform.calls.contains(&Call::Write(Copy::A)));
    assert!(!e.platform.calls.contains(&Call::Write(Copy::B)));
}

#[test]
fn storage_slices_consider_each_intent_source_and_refusal_gate() {
    for source in 0..5 {
        let mut e = fresh();
        e.mode = Mode::Starting;
        if source == 0 {
            e.machine = Machine::restart(Durable {
                join_intended: true,
                ..Durable::default()
            });
        } else if source == 1 {
            e.snapshot.machine.join_intended = true;
        } else {
            e.committed.machine.join_intended = true;
        }
        e.emergency_revoked = source == 3;
        e.startup_invariant_failed = source == 4;
        e.next_emergency = e.platform.now() + 1;
        let at = e.platform.now();
        assert_eq!(
            e.safety_storage_deadline(5),
            Deadline(at + if source < 3 { 1 } else { 5 }),
            "source {source}"
        );
    }
}

#[test]
fn loaded_emergency_slices_storage_in_normal_mode() {
    let mut e = fresh();
    e.snapshot.machine.join_intended = true;
    e.emergency_loaded = true;
    e.next_emergency = e.platform.now() + 1;
    let at = e.platform.now();
    assert_eq!(e.safety_storage_deadline(5), Deadline(at + 1));
}

#[test]
fn current_joined_proof_avoids_stateless_policy_replacement() {
    let mut e = joined();
    e.mode = Mode::PersistBlocked;
    e.storage_waiting = true;
    e.next_emergency = 0;
    e.platform.calls.clear();
    e.safety_storage_deadline(5);
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
}

#[test]
fn zero_budget_cannot_be_extended_by_emergency_cadence() {
    let mut e = fresh();
    e.mode = Mode::Starting;
    e.snapshot.machine.join_intended = true;
    e.next_emergency = e.platform.now() + 1;
    let at = e.platform.now();
    assert_eq!(e.safety_storage_deadline(0), Deadline(at));
}

#[test]
fn queued_held_event_reaps_before_processing_even_if_emergency_would_park() {
    let mut e = held();
    e.snapshot.machine = snapshot::DurableRecord::try_from(e.machine.durable()).unwrap();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    let _ = e.platform.load_anchor(&policy::render_lockdown(), d);
    e.queue.push_back(QueueEvent::Timer);
    e.next_emergency = u64::MAX;
    e.platform.calls.clear();
    // Prove Timer processing cannot supply the reap being asserted below.
    let before = e.machine.clone();
    e.process(QueueEvent::Timer);
    assert!(!e.platform.calls.contains(&Call::Reap));
    assert_eq!(e.machine, before);
    assert_eq!(e.queue.len(), 1);
    assert!(e.held_emergency_due());
    e.platform.calls.clear();
    e.run_until_quiescent(1);
    assert!(e.queue.is_empty());
    assert!(
        e.platform.calls.contains(&Call::Reap),
        "a queued timer must not bypass generic reaping"
    );
}

#[test]
fn capacity_is_checked_at_each_emergency_effect_boundary() {
    for (effect, enable) in [
        (Call::LoadAnchor, false),
        (Call::Flush, false),
        (Call::Acquire, true),
        (Call::EnablePf, true),
    ] {
        // Name the observation immediately before this effect's capacity gate.
        // Additional unrelated fence observations must not move the fault.
        let (after, occurrence) = match effect {
            Call::LoadAnchor => (Call::CheckTools, 1),
            Call::Flush => (Call::PfInfo, 3),
            Call::Acquire => (Call::PfInfo, 2),
            Call::EnablePf => (Call::PfInfo, 1),
            _ => unreachable!(),
        };
        let prepare = || {
            let mut e = fresh();
            e.in_emergency_step = true;
            if effect == Call::EnablePf {
                e.storage_waiting = true;
            }
            e.platform.calls.clear();
            e
        };
        let mut e = prepare();
        e.platform
            .inject_fence_after(after, occurrence, Fault::Incomplete);
        if enable {
            let _ = e.enable_emergency_pf();
        } else {
            let _ = e.load_emergency();
        }
        assert!(
            !e.platform.calls.contains(&effect),
            "{effect:?}, fence after {after:?} #{occurrence}"
        );
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|call| **call == after)
                .count(),
            occurrence,
            "the refusal must reach {effect:?}'s observation boundary"
        );
        assert_eq!(
            e.platform
                .safety_events
                .iter()
                .filter(|event| matches!(event, platform::SafetyEvent::PfctlCapacity { .. }))
                .count(),
            1,
            "{effect:?} must refuse at its capacity gate"
        );
    }
}

#[test]
fn capacity_at_load_entry_refuses_integrity_tool_start() {
    let mut e = fresh();
    e.in_emergency_step = true;
    // Frame classification observes the general fence before load entry.
    e.platform.inject(Call::Fence, 2, Fault::Incomplete);
    e.platform.calls.clear();
    assert!(e.load_emergency().is_err());
    assert!(!e.platform.calls.contains(&Call::CheckTools));
    assert!(!e.platform.calls.contains(&Call::CheckPfctl));
}

#[test]
fn stuck_leave_unknown_ownership_does_not_even_attempt_drainage() {
    let mut e = fresh();
    e.mode = Mode::Stuck;
    e.startup_invariant_checked = false;
    e.start_fence = StartFence::Uncommitted;
    e.platform.inject(Call::Processes, 1, Fault::Incomplete);
    e.platform.calls.clear();
    e.accept_leave(Request {
        id: 71,
        kind: RequestKind::Leave,
    })
    .unwrap();
    assert!(!e.platform.calls.contains(&Call::Reap));
}

/// Reach staging through the production lock-failure/probe handoff. No reducer
/// or ownership state is pre-adopted by this fixture.
fn staging_failure_handoff(mut p: FakePlatform) -> Engine<FakePlatform> {
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    assert!(e.lockless.is_some());
    assert_eq!(e.mode, Mode::Starting);
    assert!(!e.startup_invariant_checked);
    assert!(!e.adopted);
    assert!(e.emergency_last_load_at.is_some());
    assert!(e.platform.anchor.is_some());
    // The fallback reaches a verified baseline naturally before the locked
    // staging handoff; that handoff must discard these earlier observations.
    assert!(e.emergency_baseline.is_some());
    e.emergency_states_clean_at = Some(1);
    e.emergency_next_reload = u64::MAX;
    e.emergency_next_flush = u64::MAX;
    e.emergency_enable_pending = true;
    e.start_fault = Some(StartFault::Staging);
    for _ in 0..20 {
        e.platform.tick();
    }
    // Keep the successful probe and its observations until the locked handoff.
    e.next_emergency = e.platform.now().saturating_add(1);
    e.run_lockless();
    assert!(e.lockless.is_none());
    assert!(e.stuck_leave.is_some());
    assert!(e.snapshot.validate().is_ok());
    assert_eq!(e.mode, Mode::Stuck);
    assert!(!e.adopted);
    let (file, line) = e.stuck_entry.unwrap();
    assert!(file.ends_with("engine/lockless.rs"));
    let source = include_str!("../lockless.rs");
    // Locate the call itself: changing the guard text must not kill a mutant
    // merely because an expected source spelling disappeared.
    let entry = source
        .lines()
        .position(|line| line.trim() == "self.enter_stuck();")
        .unwrap();
    assert_eq!(usize::try_from(line).unwrap(), entry + 1);
    assert!(e.emergency_baseline.is_none());
    assert!(e.emergency_states_clean_at.is_none());
    assert_eq!(e.emergency_next_reload, e.platform.now());
    assert_eq!(e.emergency_next_flush, e.platform.now());
    assert!(!e.emergency_enable_pending);
    assert!(e.platform.anchor.is_some());
    e
}

#[test]
fn persist_leaving_staging_failure_resets_handoff_observations() {
    staging_failure_handoff(fixture(&mutants_group1::pre_persist_leaving()));
}

#[test]
fn persist_leaving_staging_failure_with_previous_boot_reference() {
    let mut p = mutants_group1::pre_persist_leaving_with_reference();
    // A real reboot preserves the snapshots but invalidates old kernel tokens.
    p.mutate(Mutation::Reboot);
    let e = staging_failure_handoff(p);
    assert_ne!(
        e.snapshot.references[0].as_ref().unwrap().boot,
        e.platform.boot
    );
    assert_eq!(e.snapshot.machine.pf_reference, Some(901));
}

#[test]
fn staging_failure_then_stuck_leave_releases_reference_after_restart() {
    let mut e = staging_failure_handoff(mutants_group1::pre_persist_leaving_with_reference());
    drive(&mut e, 500);
    assert_eq!(e.outcome, Outcome::Exit0);
    mutants_group1::assert_probe_leave_completed(&mut e);
    assert!(e.platform.enabled);
    assert!(e.platform.tokens.contains_key(&901));
    assert!(!e.platform.calls.contains(&Call::Release(901)));
    assert!(!e.committed.references[0].as_ref().unwrap().release_unknown);
    let mut p = e.into_platform();
    p.crash();
    p.restart();
    let mut e = Engine::start(p).unwrap();
    assert!(e.adopted);
    drive(&mut e, 500);
    assert_eq!(e.committed.machine.pf_reference, None);
    assert!(e.platform.calls.contains(&Call::Release(901)));
    assert!(!e.platform.tokens.contains_key(&901));
    assert!(e.platform.enabled);
    assert!(e.platform.anonymous_enabled);
    assert!(e.platform.anchor.is_none());
}

#[test]
fn emergency_accounting_rejects_three_keys_without_changing_snapshot() {
    let mut e = fresh();
    let before = e.snapshot.clone();
    let durable = Durable {
        pf_reference: Some(901),
        older_references: vec![902],
        uncertain_acquires: vec![1],
        reference_sequence: 1,
        ..Durable::default()
    };
    // Each field fits its wire bound: only semantic validation rejects the union.
    assert!(snapshot::DurableRecord::try_from(&durable).is_ok());
    let evidence: Vec<_> = [
        ReferenceEntry::Token(901),
        ReferenceEntry::Token(902),
        ReferenceEntry::Acquire(1),
    ]
    .into_iter()
    .map(|key| RefEvidence {
        key,
        boot: e.platform.boot.clone(),
        fingerprint: None,
        release_unknown: false,
    })
    .collect();
    assert!(!e.stage_emergency_accounting(&durable, &evidence));
    assert_eq!(e.snapshot, before);
}

#[test]
fn emergency_accounting_rejects_mismatched_evidence_without_changing_snapshot() {
    let mut e = fresh();
    let before = e.snapshot.clone();
    let durable = Durable {
        pf_reference: Some(901),
        ..Durable::default()
    };
    let evidence = [RefEvidence {
        key: ReferenceEntry::Token(902),
        boot: e.platform.boot.clone(),
        fingerprint: None,
        release_unknown: false,
    }];
    assert!(!e.stage_emergency_accounting(&durable, &evidence));
    assert_eq!(e.snapshot, before);
}

#[test]
fn rejected_ownership_never_signals_a_stuck_leave_writer() {
    let mut e = fresh();
    e.platform
        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
    let d = e.deadline();
    assert!(
        e.platform
            .load_anchor(&policy::render_lockdown(), d)
            .is_err()
    );
    let pid = e.platform.unreaped[0].pid;
    e.mode = Mode::Stuck;
    e.startup_invariant_checked = false;
    e.start_fence = StartFence::Uncommitted;
    // Unlike a one-shot incomplete inventory, this refusal takes no process
    // read. Skipping the guard therefore leaves a complete inventory for kill.
    e.platform.helper.pgid = 99;
    e.platform.calls.clear();
    e.accept_leave(Request {
        id: 72,
        kind: RequestKind::Leave,
    })
    .unwrap();
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|c| matches!(c, Call::KillProcess(target, _) if *target == pid))
    );
}

#[test]
fn prior_fallback_load_keeps_slow_left_handoff_reads_contained() {
    let mut p = fixture(&Snapshot::initial(Some(501)));
    p.inject(Call::AcquireInstanceLock, 1, Fault::ReadFail);
    p.inject(Call::Read(Copy::A), 1, Fault::ReadFail);
    let mut e = Engine::start(p).unwrap();
    assert!(e.emergency_last_load_at.is_some());
    for _ in 0..20 {
        e.platform.tick();
    }
    e.platform.inject(Call::Install, 1, Fault::StorageDelay(60));
    e.platform.mutate_after_ticks(20, Mutation::PfDisable);
    let at = e.platform.now();
    e.run_lockless();
    assert!(e.lockless.is_none());
    assert!(
        e.platform
            .pf_enabled_at
            .is_some_and(|enabled| enabled > at && enabled <= at + 2)
    );
}

#[test]
fn missing_copy_repair_has_the_full_write_budget() {
    let mut e = fresh();
    e.platform.mutate(Mutation::MissingCopy(Copy::B));
    e.storage_blocked = true;
    e.mode = Mode::PersistBlocked;
    e.next_storage = 0;
    e.repair_pending = Some((Copy::B, snapshot::encode(e.seq, &e.snapshot).unwrap()));
    e.platform
        .inject(Call::Create(Copy::B), 1, Fault::StorageDelay(60));
    e.retry_storage();
    assert!(e.repair_pending.is_none());
    assert!(!e.storage_blocked);
}
