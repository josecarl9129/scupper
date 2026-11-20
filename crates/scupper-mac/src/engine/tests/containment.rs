use super::*;
use crate::platform::ToolOutcome;

#[test]
fn recovery_disable_reenables_without_acquisition_or_settling_debt() {
    let mut p = FakePlatform::new().unwrap();
    let snapshot = Snapshot::recovery(p.boot_id(), None, Some(501), None);
    let debt = snapshot.references.clone();
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    drive(&mut e, 500);
    e.platform.mutate(Mutation::PfDisable);
    e.platform.calls.clear();
    elapse(&mut e, 4);
    assert!(e.platform.enabled);
    assert!(e.platform.anonymous_enabled);
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert_eq!(e.snapshot.references, debt);
    assert!(e.machine.durable().hold);
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    // Fresh global disable must override an old flush retry deadline.
    for round in 0..20 {
        e.platform.mutate(Mutation::PfDisable);
        elapse(&mut e, 1);
        assert!(
            e.platform.enabled,
            "round {round}, now {}, flush {}, emergency {}, anon {}, plan {:?}",
            e.platform.now(),
            e.emergency_next_flush,
            e.next_emergency,
            e.anonymous_enable_confirmed,
            e.machine.plan()
        );
        assert_eq!(e.snapshot.references, debt);
        assert!(!e.platform.calls.contains(&Call::Acquire));
    }
    leave(&mut e, 12);
    drive(&mut e, 500);
    assert_left(&mut e, 12);
    assert!(e.platform.enabled);
    assert_eq!(e.snapshot.references, debt);
}

#[test]
fn anonymous_enable_survives_token_releases_and_is_reset_by_disable_and_reboot() {
    for reboot in [false, true] {
        for owned_last in [false, true] {
            let mut p = FakePlatform::new().unwrap();
            let d = Deadline(p.now() + 5);
            let ToolOutcome::Ok((owned, _)) = p.acquire(d) else {
                panic!("acquire")
            };
            p.mutate(Mutation::ForeignEnable);
            let foreign = *p.tokens.keys().find(|token| **token != owned).unwrap();
            for _ in 0..3 {
                p.enable_pf(d).unwrap();
            }
            assert!(p.anonymous_enabled);
            assert_eq!(p.tokens.len(), 2);
            if owned_last {
                p.mutate(Mutation::ForeignRelease(foreign));
            }
            assert_eq!(
                p.release(owned, d),
                ToolOutcome::Ok(platform::Release::Released)
            );
            if !owned_last {
                p.mutate(Mutation::ForeignRelease(foreign));
            }
            assert!(p.tokens.is_empty());
            assert!(p.enabled);
            p.restart();
            assert!(p.enabled);
            assert!(p.anonymous_enabled);
            assert!(matches!(p.acquire(d), ToolOutcome::Ok(_)));
            assert!(!p.tokens.is_empty());
            assert!(p.anonymous_enabled);
            p.mutate(if reboot {
                Mutation::Reboot
            } else {
                Mutation::PfDisable
            });
            assert!(!p.enabled);
            assert!(!p.anonymous_enabled);
            assert!(p.tokens.is_empty());
        }
    }
}

#[test]
fn enabled_foreign_reference_gets_anonymous_enable_even_when_it_reports_exists() {
    let mut e = reboot_before_emergency();
    e.storage_blocked = true;
    e.mode = Mode::PersistBlocked;
    e.platform.mutate(Mutation::ForeignEnable);
    let foreign = *e.platform.tokens.keys().next().unwrap();
    let debt = e.snapshot.references.clone();
    e.platform.inject(Call::EnablePf, 1, Fault::EnableExists);
    assert!(matches!(e.load_emergency(), Ok(Verdict::Protected(_))));
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert!(e.platform.anonymous_enabled);
    assert_eq!(e.snapshot.references, debt);
    e.platform.mutate(Mutation::ForeignRelease(foreign));
    assert!(e.platform.enabled);
    assert!(e.platform.tokens.is_empty());
    assert!(matches!(e.load_emergency(), Ok(Verdict::Protected(_))));
    assert_eq!(e.snapshot.references, debt);
}

#[test]
fn anonymous_enable_checks_policy_path_and_flushes_before_enabling() {
    for guarded in [false, true] {
        let mut e = reboot_before_emergency();
        e.storage_blocked = true;
        e.mode = Mode::PersistBlocked;
        e.in_emergency_step = guarded;
        e.platform.model_firewall = true;
        e.platform.anchor = Some("pass quick all\n".into());
        e.platform.states.push(true);
        e.platform.capture_before(Call::EnablePf, 1);
        if guarded {
            e.attempt_stateless_containment();
        } else {
            let _ = e.load_emergency();
        }
        let mut prefix = e.platform.take_capture().unwrap();
        assert!(!prefix.enabled);
        assert_eq!(
            prefix.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
        assert_eq!(prefix.states, [] as [bool; 0]);
        let load = prefix
            .calls
            .iter()
            .position(|call| *call == Call::LoadAnchor)
            .unwrap();
        let collect = prefix
            .calls
            .iter()
            .position(|call| *call == Call::Collect)
            .unwrap();
        let flush = prefix
            .calls
            .iter()
            .position(|call| *call == Call::Flush)
            .unwrap();
        assert!(load < collect && collect < flush);
        prefix.crash();
        assert!(!prefix.enabled);
        assert_eq!(
            prefix.anchor.as_deref(),
            Some(policy::render_lockdown().as_str())
        );
    }
    for qualified in [false, true] {
        for rules in ["pass quick all\n", "block all\n"] {
            let mut e = reboot_before_emergency();
            e.mode = Mode::PersistBlocked;
            e.storage_blocked = true;
            if !qualified {
                e.platform.firewall_qualification = None;
            }
            e.platform.main_rules = rules.into();
            let _ = e.load_emergency();
            assert!(e.platform.calls.contains(&Call::EnablePf));
            assert!(e.platform.enabled);
            assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        }
    }
}

#[test]
fn unknown_boot_never_reserves_or_acquires_in_ordinary_or_emergency_paths() {
    let mut e = fresh();
    e.platform.mutate(Mutation::BootIdUnavailable);
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 800);
    assert!(e.platform.enabled);
    assert!(e.platform.anonymous_enabled);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(e.snapshot.references.iter().flatten().next().is_none());
    assert!(e.committed.references.iter().flatten().next().is_none());
    for blocked in [false, true] {
        let mut e = reboot_before_emergency();
        e.platform.mutate(Mutation::BootIdUnavailable);
        e.storage_blocked = blocked;
        let debt = e.snapshot.references.clone();
        let _ = e.enable_emergency_pf();
        assert!(e.platform.enabled);
        assert!(e.platform.calls.contains(&Call::EnablePf));
        assert!(!e.platform.calls.contains(&Call::Acquire));
        assert_eq!(e.snapshot.references, debt);
        assert!(!e.emergency_unreserved_consumed);
    }
}

#[test]
fn existing_unknown_boot_debt_survives_known_boot_and_reboot() {
    let snapshot = Snapshot::recovery(None, None, Some(501), None);
    let debt = snapshot.references.clone();
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    drive(&mut e, 500);
    assert_eq!(e.snapshot.references, debt);
    let mut p = e.into_platform();
    p.mutate(Mutation::Reboot);
    p.mutate(Mutation::ForeignEnable);
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert_eq!(e.snapshot.references, debt);
    assert!(e.machine.durable().hold);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(e.platform.enabled);
}

#[test]
fn leave_rejects_recreated_or_unknown_managed_artifacts() {
    for incomplete in [false, true] {
        let mut e = joined();
        leave(&mut e, 2);
        before_pending(&mut e, Step::ClearIntent);
        if incomplete {
            e.platform.inject(Call::Artifacts, 1, Fault::ReadFail);
        } else {
            // A child that survived an earlier StopChild/CleanupArtifacts pair
            // may have recreated its socket before the final successful stop.
            e.platform.artifacts.insert("child.sock".into());
        }
        tick(&mut e);
        tick(&mut e);
        assert!(!e.left_verified);
        assert_eq!(e.status().text, "leaving: artifacts");
        assert!(e.committed.machine.leaving);
        elapse(&mut e, 5);
        assert_left(&mut e, 2);
        assert!(e.platform.artifacts.is_empty());
    }
}

#[test]
fn leave_gates_direct_containment_and_rearms_only_an_accepted_new_join() {
    let mut e = joined();
    let Ok(Verdict::Protected(proof)) = e.load_emergency() else {
        panic!("lockdown")
    };
    e.emergency_proof = Some(proof);
    e.emergency_loaded = false;
    e.verified_enforcement = true;
    leave(&mut e, 2);
    assert!(e.emergency_revoked);
    assert!(!e.verified_enforcement);
    assert!(e.emergency_proof.is_none());
    e.platform.calls.clear();
    e.in_emergency_step = true;
    e.attempt_stateless_containment();
    let _ = e.load_emergency();
    let _ = e.enable_emergency_pf();
    e.run_emergency();
    assert!(!e.platform.calls.iter().any(|call| matches!(
        call,
        Call::LoadAnchor | Call::EnablePf | Call::Acquire | Call::Flush
    )));
    e.in_emergency_step = false;
    drive(&mut e, 500);
    assert_left(&mut e, 2);
    assert!(
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join
        })
        .is_err()
    );
    e.process(QueueEvent::Request(Request {
        id: 1,
        kind: RequestKind::Join,
    }));
    e.run_until_quiescent(1);
    assert!(e.emergency_revoked);
    assert!(e.left_verified);
    e.submit(Request {
        id: 3,
        kind: RequestKind::Join,
    })
    .unwrap();
    tick(&mut e);
    assert!(!e.emergency_revoked);
    assert!(!e.left_verified);
    let snapshot = Snapshot::recovery(None, None, Some(501), None);
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    e.emergency_revoked = true;
    assert!(
        e.submit(Request {
            id: 4,
            kind: RequestKind::Join
        })
        .is_err()
    );
    e.process(QueueEvent::Request(Request {
        id: 5,
        kind: RequestKind::Join,
    }));
    assert!(e.emergency_revoked);
    assert!(e.machine.durable().hold);
}

#[test]
fn cleanup_with_joined_snapshot_reports_not_durable_and_restart_resumes_join() {
    let mut e = joined();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert!(e.left_verified);
    assert_eq!(e.status().text, "left (not durable)");
    assert!(e.committed.machine.join_intended);
    assert_left_resources(&e);
    let mut p = e.into_platform();
    p.restart();
    p.clear_faults();
    p.artifacts.insert("old-child.sock".into());
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 800);
    assert!(e.machine.durable().join_intended);
    assert!(e.platform.enabled);
    assert!(e.platform.anchor.is_some());
    leave(&mut e, 3);
    drive(&mut e, 500);
    assert_left(&mut e, 3);
    let mut p = e.into_platform();
    p.restart();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    assert!(!e.machine.durable().join_intended);
    assert!(!e.committed.machine.join_intended);
    assert_left_resources(&e);
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.platform.artifacts.is_empty());
}

#[test]
fn acquisition_completion_preserves_unknown_reservation_boot() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    let Some(ReferenceIntent::Acquire(sequence)) = e.machine.durable().reference_intent else {
        panic!("reservation");
    };
    let entry = e
        .snapshot
        .references
        .iter_mut()
        .flatten()
        .find(|entry| entry.key == ReferenceEntry::Acquire(sequence))
        .unwrap();
    entry.boot = None;
    let event = Event::ReferenceAcquiredFor {
        sequence,
        token: 1200,
    };
    let next = e
        .machine
        .transition(event.clone(), &Clock(e.platform.now()))
        .unwrap();
    let acquired = RefEvidence {
        key: ReferenceEntry::Token(1200),
        boot: e.platform.boot_id(),
        release_unknown: false,
        fingerprint: Some(RefFingerprint {
            pid: 1000,
            timestamp: 1,
        }),
    };
    e.adopt(next, &event, Some(acquired));
    let entry = e
        .snapshot
        .references
        .iter()
        .flatten()
        .find(|entry| entry.key == ReferenceEntry::Token(1200))
        .unwrap();
    assert!(entry.boot.is_none());
}

#[test]
fn leave_fences_delayed_containment_effects_before_final_absence() {
    for call in [Call::LoadAnchor, Call::EnablePf] {
        let mut e = joined();
        e.platform.inject(call, 1, Fault::ToolLate { ticks: None });
        let d = Deadline(e.platform.now() + 1);
        let result = if call == Call::LoadAnchor {
            e.platform.load_anchor(&policy::render_lockdown(), d)
        } else {
            e.platform.enable_pf(d).map(|_| ())
        };
        assert!(result.is_err());
        leave(&mut e, 2);
        let start = e.platform.calls.len();
        drive(&mut e, 500);
        assert!(!e.left_verified);
        assert_ne!(e.status().text, "left");
        e.platform.release_unreaped();
        elapse(&mut e, 90);
        assert_left(&mut e, 2);
        assert!(e.platform.artifacts.is_empty());
        assert!(
            !e.platform.calls[start..]
                .iter()
                .any(|call| matches!(call, Call::LoadAnchor | Call::EnablePf | Call::Acquire))
        );
        elapse(&mut e, 3);
        assert!(e.platform.anchor.is_none());
    }
}

#[test]
fn boot_loss_after_reservation_prevents_ordinary_and_emergency_acquisition() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    let debt = e.snapshot.references.clone();
    e.platform.mutate(Mutation::BootIdUnavailable);
    e.platform.calls.clear();
    e.dispatch(Step::AcquireReference);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(e.platform.calls.contains(&Call::EnablePf));
    assert_eq!(e.snapshot.references, debt);

    let mut e = reboot_before_emergency();
    e.mode = Mode::Stuck;
    e.platform
        .inject(Call::Write(Copy::A), 1, Fault::StorageDelay(90));
    e.platform
        .mutate_after_ticks(40, Mutation::BootIdUnavailable);
    let _ = e.load_emergency();
    assert!(e.platform.boot.is_none());
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(e.platform.enabled);
    assert!(
        e.snapshot
            .references
            .iter()
            .flatten()
            .all(|entry| entry.boot.is_some())
    );
}

#[test]
fn child_recreation_after_artifact_cleanup_is_removed_before_left() {
    let mut e = joined();
    let child = e.child.clone().unwrap();
    e.platform.unkillable.insert(child.pid);
    leave(&mut e, 2);
    before_pending(&mut e, Step::CleanupArtifacts);
    tick(&mut e);
    tick(&mut e);
    assert!(e.platform.children.contains_key(&child.pid));
    assert!(e.platform.artifacts.is_empty());
    e.platform.artifacts.insert("child.sock".into());
    e.platform.unkillable.remove(&child.pid);
    for _ in 0..600 {
        tick(&mut e);
        if e.status().text.starts_with("left") {
            assert!(e.platform.artifacts.is_empty());
            break;
        }
    }
    assert_left(&mut e, 2);
    assert!(e.platform.artifacts.is_empty());
}

fn persist_blocked_after_disable() -> Engine<FakePlatform> {
    let mut e = joined();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.apply(Event::InvalidateObservations { since: 100 });
    assert_eq!(e.mode, Mode::PersistBlocked);
    e.platform.mutate(Mutation::PfDisable);
    e.platform.mutate(Mutation::AnchorLoss);
    e.next_emergency = 0;
    e.platform.calls.clear();
    e
}

#[test]
fn failed_preparation_never_delays_enablement_or_claims_protection() {
    for guarded in [false, true] {
        for failure in 0..5 {
            let mut e = persist_blocked_after_disable();
            e.in_emergency_step = guarded;
            match failure {
                0 => e
                    .platform
                    .inject_persistent(Call::Flush, Fault::ToolFail { effect: false }),
                1 => e.platform.main_rules = "block all\n".into(),
                2 => e.platform.anchor_readback_absent = true,
                3 => e
                    .platform
                    .inject_persistent(Call::LoadAnchor, Fault::ToolFail { effect: false }),
                _ => e.platform.firewall_qualification = None,
            }
            let start = e.platform.now();
            if guarded {
                e.attempt_stateless_containment();
            } else {
                let _ = e.load_emergency();
            }
            assert!(e.platform.enabled, "guarded={guarded}, failure={failure}");
            assert!(e.platform.now() <= start + 1);
            assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
            assert!(!e.status().emergency_blocking_verified);
            e.in_emergency_step = false;
            for _ in 0..60 {
                elapse(&mut e, 1);
                assert!(e.platform.enabled, "guarded={guarded}, failure={failure}");
                assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
                assert!(!e.status().emergency_blocking_verified);
            }
        }
    }
}

#[test]
fn enable_failure_retries_each_second_independently_of_flush_backoff() {
    let mut e = persist_blocked_after_disable();
    e.platform
        .inject_persistent(Call::EnablePf, Fault::ToolFail { effect: false });
    e.platform
        .inject_persistent(Call::Flush, Fault::ToolFail { effect: false });
    let _ = e.load_emergency();
    for _ in 0..60 {
        let before = e
            .platform
            .calls
            .iter()
            .filter(|call| **call == Call::EnablePf)
            .count();
        elapse(&mut e, 1);
        let after = e
            .platform
            .calls
            .iter()
            .filter(|call| **call == Call::EnablePf)
            .count();
        assert!(
            after > before,
            "enable retry suppressed at {}",
            e.platform.now()
        );
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        assert!(!e.status().emergency_blocking_verified);
    }
    assert!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::Flush)
            .count()
            < 15
    );
}

#[test]
fn persistent_already_running_confirms_once_and_finishes_verification() {
    let mut e = persist_blocked_after_disable();
    e.platform.mutate(Mutation::ForeignEnable);
    let foreign = *e.platform.tokens.keys().next().unwrap();
    e.run_emergency();
    assert!(e.status().emergency_blocking_verified);
    assert!(e.anonymous_enable_confirmed);
    for _ in 0..60 {
        let d = Deadline(e.platform.now() + 1);
        e.platform.pause(Duration::from_secs(1), d);
        e.run_unreservable_containment();
        e.run_emergency();
        assert!(e.status().emergency_blocking_verified);
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
    }
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::EnablePf)
            .count(),
        1
    );
    assert!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::Flush)
            .count()
            < 15
    );
    e.platform.mutate(Mutation::ForeignRelease(foreign));
    assert!(e.platform.enabled);
    for _ in 0..3 {
        let d = Deadline(e.platform.now() + 1);
        assert_eq!(
            e.platform.enable_pf(d),
            Ok(platform::PfEnable::AlreadyRunning)
        );
    }
    e.platform.clear_faults();
    elapse(&mut e, 90);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}

#[test]
fn unknown_boot_join_crash_at_every_write_never_commits_acquisition_debt() {
    let start = || {
        let mut e = fresh();
        e.platform.mutate(Mutation::BootIdUnavailable);
        e.platform.calls.clear();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        e
    };
    let advance = |e: &mut Engine<FakePlatform>| {
        // Cover every write in the initial Join prefix and its first retry.
        for _ in 0..40 {
            tick(e);
        }
        assert!(e.platform.enabled);
    };
    let mut control = start();
    advance(&mut control);
    for copy in [Copy::A, Copy::B] {
        let count = control
            .platform
            .calls
            .iter()
            .filter(|call| **call == Call::Write(copy))
            .count();
        assert!(count > 0);
        for occurrence in 1..=count {
            let mut e = start();
            e.platform.capture_after(Call::Write(copy), occurrence);
            advance(&mut e);
            let mut prefix = e.platform.take_capture().unwrap();
            for stored in [Copy::A, Copy::B] {
                let snapshot = read_snapshot(&mut prefix, stored);
                assert!(
                    snapshot
                        .references
                        .iter()
                        .flatten()
                        .all(|entry| !matches!(entry.key, ReferenceEntry::Acquire(_))
                            || entry.boot.is_some()),
                    "copy={copy:?}, occurrence={occurrence}, stored={stored:?}"
                );
            }
            prefix.crash();
            prefix.restart();
            let mut restarted = Engine::start(prefix).unwrap();
            advance(&mut restarted);
            assert!(
                restarted
                    .snapshot
                    .references
                    .iter()
                    .flatten()
                    .next()
                    .is_none()
            );
            assert!(!restarted.platform.calls.contains(&Call::Acquire));
        }
    }
}

#[test]
fn boot_loss_with_failed_load_settles_unissued_acquisition_after_completion() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::AcquireReference);
    e.platform.mutate(Mutation::BootIdUnavailable);
    e.platform
        .inject_persistent(Call::LoadAnchor, Fault::ToolFail { effect: false });
    e.platform.calls.clear();
    e.dispatch(Step::AcquireReference);
    drive(&mut e, 800);
    elapse(&mut e, 40);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(e.snapshot.references.iter().flatten().next().is_none());
    assert!(e.committed.references.iter().flatten().next().is_none());
    assert_eq!(e.machine.durable().uncertain_acquires, [] as [u64; 0]);
}

#[test]
fn accepted_leave_revokes_while_accounting_waits_then_retries_core_leave() {
    let mut p = FakePlatform::new().unwrap();
    let snapshot = Snapshot::recovery(p.boot_id(), None, Some(501), None);
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    drive(&mut e, 500);
    e.emergency_references = e.snapshot.references.iter().flatten().cloned().collect();
    e.in_flight = Some((123, Step::CheckTools));
    e.emergency_loaded = false;
    e.accept_leave(Request {
        id: 2,
        kind: RequestKind::Leave,
    })
    .unwrap();
    assert!(!e.machine.durable().leaving);
    assert!(!e.machine.durable().leave_requested);
    assert!(!e.snapshot.machine.leaving);
    let before = e.platform.calls.len();
    e.platform.mutate(Mutation::PfDisable);
    e.in_emergency_step = true;
    e.attempt_stateless_containment();
    let _ = e.load_emergency();
    let _ = e.enable_emergency_pf();
    e.run_emergency();
    assert!(!e.platform.calls[before..].iter().any(|call| matches!(
        call,
        Call::LoadAnchor | Call::EnablePf | Call::Flush | Call::Acquire
    )));
    e.in_emergency_step = false;
    e.in_flight = None;
    e.accept_leave(Request {
        id: 2,
        kind: RequestKind::Leave,
    })
    .unwrap();
    e.retry_leave();
    drive(&mut e, 800);
    assert_left(&mut e, 2);
}

#[test]
fn left_status_pins_each_independent_durability_obligation() {
    let mut e = joined();
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_left(&mut e, 2);
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    e.snapshot.owner_uid = None;
    assert!(!e.commit_if_changed());
    assert!(e.storage_blocked);
    assert!(!e.committed.machine.join_intended);
    assert!(!e.committed.machine.leaving);
    assert_eq!(e.status().text, "left (not durable)");
    e.storage_blocked = false;
    assert_eq!(e.status().text, "left");

    let mut e = joined();
    e.platform
        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert!(e.left_verified);
    assert!(e.committed.machine.join_intended);
    assert!(!e.committed.machine.leaving);
    e.platform.clear_faults();
    // Storage has recovered, but no retry has committed the cleared intent yet.
    e.storage_blocked = false;
    assert_eq!(e.status().text, "left (not durable)");
}

#[test]
fn reservable_reference_avoids_anonymous_enable_when_pf_is_running() {
    let mut e = reboot_before_emergency();
    e.platform.mutate(Mutation::ForeignEnable);
    assert!(!e.storage_blocked);
    assert!(e.platform.boot_id().is_some());
    assert!(e.enable_emergency_pf().is_ok());
    assert!(e.platform.calls.contains(&Call::Acquire));
    assert!(!e.platform.calls.contains(&Call::EnablePf));
    assert!(!e.platform.anonymous_enabled);
}

#[test]
fn reused_prefence_lockdown_requires_postfence_readback_after_orphan_write() {
    let mut p = FakePlatform::new().unwrap();
    let snapshot = Snapshot::recovery(p.boot_id(), None, Some(501), None);
    let mut e = Engine::start(fixture(&snapshot)).unwrap();
    e.machine = Machine::restart_lockdown(e.machine.durable().clone());
    assert_eq!(e.machine.pre_tunnel_policy(), Kind::Lockdown);
    e.start_fence = StartFence::Uncommitted;
    e.emergency_loaded = false;
    e.emergency_last_load_at = None;
    e.emergency_next_reload = e.platform.now();
    let _ = e.load_emergency();
    assert!(e.emergency_loaded);
    assert!(e.emergency_readback.is_some());
    assert!(e.prepare_emergency_fence());
    assert_eq!(e.start_fence, StartFence::Closed);
    e.platform.calls.clear();
    e.execute(Step::LoadPreTunnel).unwrap();
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    // A writer's last effect can follow the reused load. The core must observe
    // again after fencing, rather than using the earlier comparison readback.
    e.platform.anchor = Some("pass quick all\n".into());
    e.platform.calls.clear();
    assert!(matches!(
        e.execute(Step::VerifyPreTunnelLoad),
        Err(SysError::Failed("anchor readback mismatch"))
    ));
    assert!(e.platform.calls.contains(&Call::ReadAnchor));
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
}

#[test]
fn persistent_artifact_cleanup_failure_has_bounded_retries_and_withholds_left() {
    let mut e = joined();
    e.platform
        .inject_persistent(Call::CleanupArtifacts, Fault::ReadFail);
    e.platform.artifacts.insert("child.sock".into());
    leave(&mut e, 2);
    elapse(&mut e, 180);
    assert!(!e.left_verified);
    assert!(!e.request_completed(2));
    assert_eq!(e.status().text, "leaving: artifacts");
    let attempts = e
        .platform
        .calls
        .iter()
        .filter(|call| **call == Call::CleanupArtifacts)
        .count();
    assert!(attempts > 1 && attempts < 15, "{attempts}");
    e.platform.clear_faults();
    elapse(&mut e, 65);
    assert_left(&mut e, 2);
}

#[test]
fn unknown_boot_with_persistent_ordinary_load_failure_still_enables_on_poll() {
    let mut e = fresh();
    e.platform.mutate(Mutation::BootIdUnavailable);
    e.platform
        .inject_persistent(Call::LoadAnchor, Fault::ToolFail { effect: false });
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    elapse(&mut e, 2);
    assert!(e.platform.enabled);
    assert!(e.platform.anonymous_enabled);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
}

#[test]
fn joined_storage_failure_enables_within_one_poll_despite_flush_or_hook_failure() {
    for flush_failure in [false, true] {
        let mut e = persist_blocked_after_disable();
        if flush_failure {
            e.platform
                .inject_persistent(Call::Flush, Fault::ToolFail { effect: false });
        } else {
            e.platform.main_rules = "block all\n".into();
        }
        let disabled_at = e.platform.now();
        for _ in 0..60 {
            elapse(&mut e, 1);
            assert!(e.platform.enabled);
            assert!(e.platform.pf_enabled_at.unwrap() <= disabled_at + 1);
            assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
            assert!(!e.status().emergency_blocking_verified);
        }
        assert!(e.platform.calls.contains(&Call::EnablePf));
        assert!(!e.platform.calls.contains(&Call::Acquire));
    }
}

#[test]
fn unrelated_tool_integrity_failure_cannot_suppress_pfctl_containment() {
    for pfctl_untrusted in [false, true] {
        let mut e = persist_blocked_after_disable();
        e.platform.executable_symlinks.insert(
            Path::new(if pfctl_untrusted {
                "/sbin/pfctl"
            } else {
                CHILD_PATH
            })
            .into(),
        );
        assert!(e.load_emergency().is_err());
        assert_eq!(e.platform.enabled, !pfctl_untrusted);
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        assert!(!e.status().emergency_blocking_verified);
        assert!(!e.platform.calls.contains(&Call::Acquire));
        for effect in [Call::LoadAnchor, Call::Flush, Call::EnablePf] {
            assert_eq!(e.platform.calls.contains(&effect), !pfctl_untrusted);
        }
    }
}
