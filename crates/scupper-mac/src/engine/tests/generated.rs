//! Generated products use model time; the wall-clock bound includes fixture setup.
use super::*;
use crate::platform::Setting;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Constructor,
    StartupValidate,
    StartupSettlement,
    StartupConversion,
    RejectedFallback,
    AccountingMismatch,
    RefreshConversion,
    CommitValidate,
    CommitCounter,
    CommitEncode,
    LegacyRelease,
    DispatchCounter,
    CompletionBackpressure,
    SafetyFallback,
}
const ENTRIES: [Entry; 14] = [
    Entry::Constructor,
    Entry::StartupValidate,
    Entry::StartupSettlement,
    Entry::StartupConversion,
    Entry::RejectedFallback,
    Entry::AccountingMismatch,
    Entry::RefreshConversion,
    Entry::CommitValidate,
    Entry::CommitCounter,
    Entry::CommitEncode,
    Entry::LegacyRelease,
    Entry::DispatchCounter,
    Entry::CompletionBackpressure,
    Entry::SafetyFallback,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Left,
    Joining,
    Joined,
    Disabled,
    Rejoin,
    BeforeLeaving,
    AfterLeaving,
}
const SCENARIOS: [Scenario; 7] = [
    Scenario::Left,
    Scenario::Joining,
    Scenario::Joined,
    Scenario::Disabled,
    Scenario::Rejoin,
    Scenario::BeforeLeaving,
    Scenario::AfterLeaving,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootKind {
    Live,
    HelperRestart,
    FreshBoot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Left,
    Kept,
    Emergency,
}

// Independent safety oracle: intent/Leave and proof provenance determine the
// required outcome, not the implementation's load/enable/error classifications.
// Only non-Pfctl own tools may coexist with a current-proof policy exemption.
fn stuck_outcome(entry: Entry, state: Scenario, boot: BootKind, own_pfctl: bool) -> Expected {
    if matches!(
        state,
        Scenario::Left | Scenario::BeforeLeaving | Scenario::AfterLeaving
    ) {
        Expected::Left
    } else if state == Scenario::Joined
        && entry != Entry::Constructor
        && boot == BootKind::Live
        && !own_pfctl
    {
        Expected::Kept
    } else {
        Expected::Emergency
    }
}

fn scenario(state: Scenario) -> Engine<FakePlatform> {
    let mut e = fresh();
    // Keep the named entry fault independent of the fake's opaque foreign
    // process. Persistent undecidable ownership has its own open-fence test.
    e.platform.procs.get_mut(&14).unwrap().path = Some("/foreign/ordinary".into());
    if state == Scenario::Left {
        return e;
    }
    e.submit(Request {
        id: 10,
        kind: RequestKind::Join,
    })
    .unwrap();
    if state == Scenario::Joining {
        before_pending(&mut e, Step::LoadPreTunnel);
        return e;
    }
    drive(&mut e, 500);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    match state {
        Scenario::Disabled => {
            e.platform.mutate(Mutation::PfDisable);
            e.apply(Event::Repair(verify::Action::EnableAndRejoin));
            before_pending(&mut e, Step::AcquireReference);
        }
        Scenario::Rejoin => {
            leave(&mut e, 11);
            drive(&mut e, 500);
            e.submit(Request {
                id: 12,
                kind: RequestKind::Join,
            })
            .unwrap();
            before_pending(&mut e, Step::AcquireReference);
        }
        Scenario::BeforeLeaving | Scenario::AfterLeaving => {
            leave(&mut e, 11);
            assert_eq!(e.machine.pending(), Some(Step::PersistLeaving));
            assert!(!e.machine.durable().leaving);
            if state == Scenario::AfterLeaving {
                e.dispatch(Step::PersistLeaving);
                let QueueEvent::Completion(c) = e.queue.pop_front().unwrap() else {
                    panic!("completion")
                };
                e.complete(c);
                assert!(e.machine.durable().leaving);
            }
        }
        _ => {}
    }
    e
}

fn old_boot_entry(e: &mut Engine<FakePlatform>) {
    if e.snapshot.references.iter().all(Option::is_none) {
        e.snapshot.machine.uncertain_acquires = vec![1].try_into().unwrap();
        e.snapshot.machine.reference_sequence = 1;
        e.snapshot.references[0] = Some(RefEvidence {
            key: ReferenceEntry::Acquire(1),
            boot: None,
            release_unknown: false,
            fingerprint: None,
        });
    }
    for entry in e.snapshot.references.iter_mut().flatten() {
        entry.boot = Some(BootId::try_from("00000000-0000-0000-0000-000000000099").unwrap());
    }
    assert!(e.snapshot.validate().is_ok());
    e.committed = e.snapshot.clone();
}

// Result faults are limited to representation failures that the present core
// cannot emit naturally. All remaining rows enter through actual public/private
// production operations. The recorded caller proves which Stuck arm was hit.
fn trigger(mut e: Engine<FakePlatform>, entry: Entry) -> Engine<FakePlatform> {
    match entry {
        Entry::Constructor => {
            let mut snapshot = e.snapshot.clone();
            snapshot.references = [None, None];
            // Invalid initial selection even for an empty Left snapshot.
            let install = e.install.clone();
            // A constructor starts a new helper incarnation. Reusing the live
            // helper's own pgid incorrectly asks the fence to kill our group.
            let mut platform = e.into_platform();
            platform.restart();
            platform.acquire_instance_lock().unwrap();
            e = Engine::start_selected(
                platform,
                install,
                StartDecision::Trust {
                    source: Copy::A,
                    seq: snapshot::COUNTER_MAX,
                    snapshot,
                    repair: None,
                },
                [false, false],
            );
        }
        Entry::StartupValidate | Entry::StartupSettlement | Entry::StartupConversion => {
            if entry != Entry::StartupValidate {
                old_boot_entry(&mut e);
            }
            e.mode = Mode::Starting;
            e.start_fault = Some(match entry {
                Entry::StartupValidate => StartFault::Validate,
                Entry::StartupSettlement => StartFault::Settlement,
                _ => StartFault::Conversion,
            });
            e.finish_start();
        }
        Entry::RejectedFallback => {
            e.reject_fallback = true;
            e.rejected_completion();
        }
        Entry::AccountingMismatch => {
            let mut wrong = e.machine.durable().clone();
            wrong.pf_reference = Some(777);
            wrong.older_references.clear();
            wrong.uncertain_acquires.clear();
            wrong.reference_intent = None;
            e.adopt(Machine::restart(wrong), &Event::Join, None);
        }
        Entry::RefreshConversion => {
            e.start_fault = Some(StartFault::Refresh);
            e.refresh_snapshot();
        }
        Entry::CommitValidate => {
            e.snapshot.references[0] = Some(RefEvidence {
                key: ReferenceEntry::Acquire(999),
                boot: None,
                release_unknown: false,
                fingerprint: None,
            });
            e.commit_if_changed();
        }
        Entry::CommitCounter => {
            e.seq = snapshot::COUNTER_MAX - 1;
            e.snapshot.internal_error = Some(snapshot::InternalError::Other);
            e.commit_if_changed();
        }
        Entry::CommitEncode => {
            e.start_fault = Some(StartFault::Encode);
            e.snapshot.internal_error = Some(snapshot::InternalError::Other);
            e.commit_if_changed();
        }
        Entry::LegacyRelease => e.dispatch(Step::ReleaseReference),
        Entry::DispatchCounter | Entry::CompletionBackpressure => {
            // Dispatch cannot reach these sites with an open start fence. Prove
            // the gate first, then close it and expose the same operation.
            if e.start_fence != StartFence::Closed {
                e.dispatch(Step::PersistIntent);
                assert_ne!(e.mode, Mode::Stuck);
                assert!(e.close_emergency_fence());
            }
            if entry == Entry::DispatchCounter {
                e.next_dispatch = u64::MAX;
            } else {
                e.capacity = e.queue.len();
            }
            e.dispatch(Step::PersistIntent);
        }
        Entry::SafetyFallback => e.finish_safety_transition(
            None,
            &Event::Failed(Reason::Observation(
                "storage wait superseded by safety repair",
            )),
            None,
            Step::PersistIntent,
        ),
    }
    e
}

#[allow(clippy::too_many_lines)] // Exhaustive source map for all fourteen production entry arms.
fn expected_entry(entry: Entry) -> (&'static str, u32) {
    let (file, source, needle) = match entry {
        Entry::Constructor => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "if invalid {\n            engine.enter_stuck();",
        ),
        Entry::StartupValidate => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "let Some(mut durable) = validated else {\n            self.enter_stuck();",
        ),
        Entry::StartupSettlement => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "let Some(next) = next else {\n                    self.enter_stuck();",
        ),
        Entry::StartupConversion => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "let Some(record) = record else {\n                self.enter_stuck();",
        ),
        Entry::RejectedFallback => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "} else {\n            self.enter_stuck();\n        }\n    }\n    fn adopt",
        ),
        Entry::AccountingMismatch => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "self.enter_stuck();\n            return;\n        }\n        self.snapshot.references",
        ),
        Entry::RefreshConversion => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "None => self.enter_stuck(),",
        ),
        Entry::CommitValidate => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "if self.snapshot.validate().is_err() {\n            self.enter_stuck();",
        ),
        Entry::CommitCounter => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "else {\n            self.enter_stuck();\n            return false;\n        };\n        let bytes",
        ),
        Entry::CommitEncode => (
            "engine.rs",
            include_str!("../../engine.rs"),
            "let Some(bytes) = bytes else {\n            self.enter_stuck();",
        ),
        Entry::LegacyRelease => (
            "execute.rs",
            include_str!("../execute.rs"),
            "if step == Step::ReleaseReference {\n            self.enter_stuck();",
        ),
        Entry::DispatchCounter => (
            "execute.rs",
            include_str!("../execute.rs"),
            "let Some(next) = self.next_dispatch.checked_add(1) else {\n            self.enter_stuck();",
        ),
        Entry::CompletionBackpressure => (
            "execute.rs",
            include_str!("../execute.rs"),
            "self.in_flight = None;\n            self.enter_stuck();",
        ),
        Entry::SafetyFallback => (
            "protocol.rs",
            include_str!("../protocol.rs"),
            "None => self.enter_stuck(),",
        ),
    };
    let start = source.find(needle).unwrap();
    let offset = needle.find("enter_stuck()").unwrap();
    (
        file,
        u32::try_from(source[..start + offset].lines().count()).unwrap(),
    )
}

#[test]
#[allow(clippy::too_many_lines)] // Keep site inventory, the full product, and outcome assertions together.
fn generated_stuck_entry_product() {
    let started = Instant::now();
    let expected_sites: std::collections::BTreeSet<_> =
        ENTRIES.into_iter().map(expected_entry).collect();
    let actual_sites: std::collections::BTreeSet<_> = [
        ("engine.rs", include_str!("../../engine.rs")),
        ("execute.rs", include_str!("../execute.rs")),
        ("protocol.rs", include_str!("../protocol.rs")),
    ]
    .into_iter()
    .flat_map(|(file, source)| {
        source
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(".enter_stuck()"))
            .map(move |(line, _)| (file, u32::try_from(line + 1).unwrap()))
    })
    .collect();
    assert_eq!(
        actual_sites, expected_sites,
        "Every production Stuck entry needs product rows"
    );
    let mut rows = 0;
    for entry in ENTRIES {
        for state in SCENARIOS {
            for boot in [BootKind::Live, BootKind::HelperRestart, BootKind::FreshBoot] {
                for open in [false, true] {
                    // Constructor creates a new engine and discards both axes.
                    if entry == Entry::Constructor && (boot != BootKind::Live || open) {
                        continue;
                    }
                    let mut e = scenario(state);
                    if boot != BootKind::Live {
                        let mut p = e.into_platform();
                        if boot == BootKind::FreshBoot {
                            p.mutate(Mutation::Reboot);
                        } else {
                            p.restart();
                        }
                        e = Engine::start(p).unwrap();
                        // Incarnations cannot inherit volatile verification.
                        assert!(!e.verified_enforcement);
                        assert!(e.last_fresh_proof_at.is_none());
                        if boot == BootKind::FreshBoot {
                            let contains = e.snapshot.machine.join_intended
                                || e.snapshot.machine.leaving
                                || e.snapshot.machine.leave_requested
                                || e.snapshot.internal_error.is_some();
                            assert_eq!(e.platform.enabled, contains);
                            if contains {
                                assert_eq!(
                                    e.platform.anchor.as_deref(),
                                    Some(policy::render_lockdown().as_str())
                                );
                            } else {
                                assert!(e.platform.anchor.is_none());
                            }
                        } else if state == Scenario::Joined {
                            assert!(e.platform.enabled && e.platform.anchor.is_some());
                        }
                    }
                    if open {
                        e.start_fence = StartFence::Uncommitted;
                    }
                    e.platform.calls.clear();
                    let mut e = trigger(e, entry);
                    let row = (entry, state, boot, open);
                    assert_eq!(e.mode, Mode::Stuck, "{row:?}");
                    let (file, line) = e.stuck_entry.unwrap();
                    let (expected_file, expected_line) = expected_entry(entry);
                    assert!(file.ends_with(expected_file), "{row:?}: {file}");
                    assert_eq!(line, expected_line, "{row:?}");
                    match stuck_outcome(entry, state, boot, false) {
                        Expected::Left => {
                            if state == Scenario::Left {
                                leave(&mut e, 20);
                            }
                            e.run_until_quiescent(100);
                            assert!(e.emergency_revoked, "{row:?}");
                            assert!(e.platform.anchor.is_none(), "{row:?}");
                            assert!(e.left_verified, "{row:?}: {:?}", e.status());
                        }
                        Expected::Kept => {
                            e.run_until_quiescent(100);
                            assert!(e.verified_enforcement, "{row:?}");
                            assert_eq!(e.status().blocking_verified, !e.overflowed, "{row:?}");
                            assert!(e.platform.enabled && e.platform.anchor.is_some(), "{row:?}");
                            assert!(!e.platform.calls.contains(&Call::LoadAnchor), "{row:?}");
                        }
                        Expected::Emergency => {
                            e.run_until_quiescent(100);
                            if !e.status().emergency_blocking_verified {
                                elapse_unchecked(&mut e, 2);
                            }
                            let status = e.status();
                            assert!(status.emergency_blocking_verified, "{row:?}: {status:?}");
                            assert_emergency(&mut e);
                        }
                    }
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 553); // 13 × 7 × 3 × 2, plus 7 constructor rows.
    eprintln!("TABLE Stuck: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcquireFault {
    Ok,
    NotStarted,
    NotStartedTimeout,
    Failed,
    FailedEffect,
    UnknownNoEffect,
    UnknownEffect,
    NoFingerprint,
}
const ACQUIRES: [AcquireFault; 8] = [
    AcquireFault::Ok,
    AcquireFault::NotStarted,
    AcquireFault::NotStartedTimeout,
    AcquireFault::Failed,
    AcquireFault::FailedEffect,
    AcquireFault::UnknownNoEffect,
    AcquireFault::UnknownEffect,
    AcquireFault::NoFingerprint,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageFault {
    Healthy,
    WriteFail,
    WriteHang,
    Validate,
    Cap,
    Counter,
}
const STORAGE: [StorageFault; 6] = [
    StorageFault::Healthy,
    StorageFault::WriteFail,
    StorageFault::WriteHang,
    StorageFault::Validate,
    StorageFault::Cap,
    StorageFault::Counter,
];

fn fault_storage(e: &mut Engine<FakePlatform>, storage: StorageFault) {
    match storage {
        StorageFault::Healthy => {}
        StorageFault::WriteFail => e
            .platform
            .inject_persistent(Call::Write(Copy::A), Fault::WriteFail),
        StorageFault::WriteHang => e
            .platform
            .inject_persistent(Call::Write(Copy::A), Fault::WriteHang),
        StorageFault::Validate => {
            e.snapshot.references[0] = Some(RefEvidence {
                key: ReferenceEntry::Acquire(999),
                boot: None,
                release_unknown: false,
                fingerprint: None,
            });
        }
        StorageFault::Cap | StorageFault::Counter => {
            let mut durable = e.snapshot.validate().unwrap();
            if storage == StorageFault::Cap {
                durable.reference_intent = None;
                durable.pf_reference = None;
                durable.older_references.clear();
                durable.uncertain_acquires = vec![1, 2];
                durable.reference_sequence = 2;
                e.snapshot.references = std::array::from_fn(|i| {
                    Some(RefEvidence {
                        key: ReferenceEntry::Acquire(u64::try_from(i + 1).unwrap()),
                        boot: e.platform.boot.clone(),
                        release_unknown: false,
                        fingerprint: None,
                    })
                });
            } else {
                durable.reference_sequence = snapshot::COUNTER_MAX - 1;
            }
            e.snapshot.machine = DurableRecord::try_from(&durable).unwrap();
            assert!(e.snapshot.validate().is_ok());
        }
    }
}
fn fault_acquire(e: &mut Engine<FakePlatform>, fault: AcquireFault) {
    match fault {
        AcquireFault::Ok => {}
        AcquireFault::NotStarted => e.platform.inject(Call::Acquire, 1, Fault::NotStarted),
        AcquireFault::NotStartedTimeout => {
            e.platform
                .inject(Call::Acquire, 1, Fault::NotStartedTimeout);
        }
        AcquireFault::Failed | AcquireFault::FailedEffect => {
            e.platform.inject(
                Call::Acquire,
                1,
                Fault::ToolFail {
                    effect: fault == AcquireFault::FailedEffect,
                },
            );
        }
        AcquireFault::UnknownNoEffect | AcquireFault::UnknownEffect => e.platform.inject(
            Call::Acquire,
            1,
            Fault::ToolHang {
                reaped: true,
                effect: fault == AcquireFault::UnknownEffect,
            },
        ),
        // Running pf first needs an ownership inventory, followed by absent-token
        // settlement. The acquisition fingerprint is the next inventory.
        AcquireFault::NoFingerprint => e.platform.inject(
            Call::References,
            if e.platform.enabled { 3 } else { 2 },
            Fault::Incomplete,
        ),
    }
}
fn enable_possible(
    acquire: AcquireFault,
    storage: StorageFault,
    info: usize,
    enable: usize,
) -> bool {
    // Every disabled residual requires persistently failing reference-free -e.
    // An incomplete pf-info forbids -E (unknown ownership). Cap/Counter forbid
    // another reservation or unreserved reference (two-key/counter safety bound).
    // Failed/UnknownNoEffect can also leave an ambiguous reservation: with
    // Healthy storage the pre-existing key plus that reservation fills the cap;
    // with failing storage the one unreserved allowance is already consumed.
    // Thus those no-effect rows cannot retry -E, even after its injected fault
    // heals. FailedEffect/UnknownEffect already enabled pf despite lost success.
    if info == 0 || enable != 2 {
        return true;
    }
    if info == 2 || matches!(storage, StorageFault::Cap | StorageFault::Counter) {
        return false;
    }
    !matches!(
        acquire,
        AcquireFault::Failed | AcquireFault::UnknownNoEffect
    )
}

fn unaccounted(e: &Engine<FakePlatform>) -> usize {
    let unknown = e
        .platform
        .tokens
        .values()
        .filter(|token| token.pid != 77)
        .filter(|token| {
            !e.committed
                .references
                .iter()
                .flatten()
                .any(|r| r.key == ReferenceEntry::Token(token.token))
        })
        .count();
    let reserved = e
        .committed
        .references
        .iter()
        .flatten()
        .filter(|r| matches!(r.key, ReferenceEntry::Acquire(_)))
        .count();
    unknown.saturating_sub(reserved)
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the generated product and both loss phases auditable together.
fn generated_emergency_enablement_product() {
    let started = Instant::now();
    let mut rows = 0;
    let mut unavailable = 0;
    let mut max_entry_latency = 0;
    let mut max_first_attempt = 0;
    // Full Cartesian product fits the budget; no pairwise reduction is needed.
    for acquire in ACQUIRES {
        for storage in STORAGE {
            for info in 0..3 {
                // Enabled, Disabled, Incomplete
                for enable in 0..3 {
                    // Ok, fail once, fail persistently
                    for after in 0..2 {
                        // external -d, foreign last -X after -e
                        let row = (acquire, storage, info, enable, after);
                        let mut e = reboot_before_emergency();
                        e.timings.command_deadline = 1;
                        fault_storage(&mut e, storage);
                        if info == 0 {
                            e.platform.mutate(Mutation::ForeignEnable);
                        }
                        if info == 2 {
                            e.platform
                                .inject_persistent(Call::PfInfo, Fault::Incomplete);
                        }
                        fault_acquire(&mut e, acquire);
                        match enable {
                            1 => e.platform.inject(
                                Call::EnablePf,
                                1,
                                Fault::ToolFail { effect: false },
                            ),
                            2 => e.platform.inject_persistent(
                                Call::EnablePf,
                                Fault::ToolFail { effect: false },
                            ),
                            _ => {}
                        }
                        e.platform.calls.clear();
                        let entered = e.platform.now();
                        e.enter_stuck();
                        let returned = e.platform.now();
                        if info == 0
                            && storage == StorageFault::Healthy
                            && acquire == AcquireFault::NoFingerprint
                        {
                            assert!(!e.status().emergency_blocking_verified, "{row:?}");
                            assert!(
                                e.snapshot
                                    .references
                                    .iter()
                                    .flatten()
                                    .any(|entry| matches!(entry.key, ReferenceEntry::Acquire(_))),
                                "{row:?}"
                            );
                        }
                        max_first_attempt = max_first_attempt.max(returned - entered);
                        if info == 2 || info == 0 && storage != StorageFault::Healthy {
                            assert!(!e.platform.calls.contains(&Call::Acquire), "{row:?}");
                        }
                        if info == 0 && storage == StorageFault::Healthy {
                            let acquire = e
                                .platform
                                .calls
                                .iter()
                                .position(|call| *call == Call::Acquire)
                                .unwrap();
                            assert!(
                                e.platform.calls[..acquire].contains(&Call::Write(Copy::B)),
                                "{row:?}"
                            );
                        }
                        // Two one-second closing cadences after bounded tools
                        // return. Timeout time is accounted separately below.
                        for _ in 0..2 {
                            if e.platform.enabled {
                                break;
                            }
                            elapse_unchecked(&mut e, 1);
                        }
                        assert_eq!(
                            e.platform.enabled,
                            enable_possible(acquire, storage, info, enable),
                            "{row:?}"
                        );
                        if e.platform.enabled {
                            assert!(e.platform.now() <= returned + 2, "retry cadence {row:?}");
                            max_entry_latency = max_entry_latency.max(e.platform.now() - entered);
                        }
                        assert!(unaccounted(&e) <= 1, "{row:?}");
                        if info == 2 {
                            assert!(!e.platform.calls.contains(&Call::Acquire), "{row:?}");
                        }
                        if e.platform.enabled {
                            // Confirmed ownership needs no additional token.
                            // Otherwise healthy storage may reserve the missing
                            // counted reference even while filtering is running.
                            let confirmed = e.has_confirmed_reference();
                            let calls = e.platform.calls.len();
                            elapse_unchecked(&mut e, 1);
                            if confirmed || info == 2 || storage != StorageFault::Healthy {
                                assert!(
                                    !e.platform.calls[calls..].contains(&Call::Acquire),
                                    "{row:?}"
                                );
                            }
                            assert!(unaccounted(&e) <= 1, "{row:?}");
                            assert!(e.platform.now() >= returned);
                        } else {
                            unavailable += 1;
                            assert!(!e.status().emergency_blocking_verified, "{row:?}");
                            assert!(e.next_emergency <= e.platform.now() + 1, "{row:?}");
                        }
                        // Heal command faults for a successful external-loss
                        // phase; retain storage/accounting limitations.
                        e.platform.clear_faults();
                        if after == 0 {
                            e.platform.mutate(Mutation::PfDisable);
                        } else {
                            e.platform.mutate(Mutation::PfDisable);
                            e.platform.mutate(Mutation::ForeignEnable);
                            let foreign = *e.platform.tokens.keys().next().unwrap();
                            e.platform
                                .inject_persistent(Call::PfInfo, Fault::Incomplete);
                            e.verified_enforcement = false;
                            e.emergency_proof = None;
                            e.next_emergency = 0;
                            let fallback = e.platform.calls.len();
                            e.run_emergency();
                            assert!(
                                e.platform.calls[fallback..].contains(&Call::EnablePf),
                                "{row:?}"
                            );
                            assert!(
                                !e.platform.calls[fallback..].contains(&Call::Acquire),
                                "{row:?}"
                            );
                            assert!(e.platform.enabled);
                            e.platform.mutate(Mutation::ForeignRelease(foreign));
                            assert!(e.platform.enabled);
                            assert!(e.platform.anonymous_enabled);
                        }
                        let calls = e.platform.calls.len();
                        let allowance_consumed = e.emergency_unreserved_consumed;
                        elapse_unchecked(&mut e, 2);
                        assert!(e.platform.enabled, "after-loss {row:?}");
                        if allowance_consumed {
                            assert!(
                                !e.platform.calls[calls..].contains(&Call::Acquire),
                                "allowance reused {row:?}"
                            );
                        }
                        if after == 1 {
                            assert!(e.platform.anonymous_enabled, "{row:?}");
                            assert!(
                                !e.platform.calls[calls..].contains(&Call::Acquire),
                                "{row:?}"
                            );
                        }
                        assert!(unaccounted(&e) <= 1, "after-loss {row:?}");
                        rows += 1;
                    }
                }
            }
        }
    }
    assert_eq!(rows, 864);
    eprintln!(
        "TABLE Enablement: {rows} rows, {unavailable} persistently unavailable, max entry latency {max_entry_latency}s, max first attempt {max_first_attempt}s, {:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(60));
}

// Deliberately malformed-snapshot rows exercise the emergency fallback itself;
// the general test oracle requires snapshot validity and cannot drive these rows.
fn elapse_unchecked(e: &mut Engine<FakePlatform>, seconds: u64) {
    for _ in 0..seconds * 20 {
        e.platform.tick();
        e.run_until_quiescent(1);
    }
    assert!(
        e.platform.violations.is_empty(),
        "{:?}",
        e.platform.violations
    );
}

#[test]
fn generated_reload_recovery_within_one_second() {
    let started = Instant::now();
    for row in [
        "cheap_absence_after_mismatch",
        "readback_absence_after_mismatch",
        "three_failed_boot_loads",
        "three_failed_boot_loads_unreadable_cheap",
    ] {
        let mut e = reboot_before_emergency();
        if row.starts_with("three_failed_boot_loads") {
            if row.ends_with("unreadable_cheap") {
                // Isolate the first-load cadence from the independent positive
                // absence reset. Reverting either fix must fail its own row.
                e.platform.inject_persistent(Call::Cheap, Fault::ReadFail);
            }
            for _ in 0..3 {
                e.platform
                    .inject(Call::LoadAnchor, 1, Fault::ToolFail { effect: false });
            }
            e.enter_stuck();
            elapse(&mut e, 2);
            assert_eq!(
                e.platform
                    .calls
                    .iter()
                    .filter(|c| **c == Call::LoadAnchor)
                    .count(),
                3,
                "{row}"
            );
            assert!(e.platform.enabled, "{row}");
            let healed = e.platform.now();
            elapse(&mut e, 1);
            assert!(e.platform.enabled, "{row}");
            assert!(e.platform.pf_enabled_at.unwrap() <= healed + 1, "{row}");
        } else {
            e.platform.anchor_readback = Some("pass all\n".into());
            e.enter_stuck();
            elapse(&mut e, 130);
            assert!(e.platform.enabled, "{row}");
            assert_eq!(e.emergency_reload_delay, 60, "{row}");
            assert!(e.emergency_next_reload > e.platform.now() + 1, "{row}");
            e.platform.anchor = None;
            if row == "readback_absence_after_mismatch" {
                e.platform.inject_persistent(Call::Cheap, Fault::ReadFail);
                e.platform.anchor_readback = None;
            }
            e.platform.calls.clear();
            elapse(&mut e, 1);
            assert!(e.platform.calls.contains(&Call::LoadAnchor), "{row}");
            assert_eq!(
                e.platform.anchor.as_deref(),
                Some(policy::render_lockdown().as_str()),
                "{row}"
            );
        }
    }
    eprintln!("TABLE ReloadRecovery: 4 rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn generated_storage_entry_to_enable_production_deadline() {
    let started = Instant::now();
    // T2 follow-up: exercise both unreserved -E and consumed-allowance -e with
    // the production deadline, measuring the effect rather than method return.
    for row in [
        "persist_blocked_unreserved",
        "persist_blocked_consumed",
        "persist_blocked_acquire_hang",
        "earlier_failed_commit",
        "first_unknown_hang",
        "first_unknown_hang_acquire_hang",
    ] {
        let mut e = reboot_before_emergency();
        assert_eq!(e.timings.command_deadline, 5);
        e.platform
            .inject_persistent(Call::Write(Copy::A), Fault::WriteHang);
        if row.starts_with("persist_blocked") {
            e.block_storage();
            assert_eq!(e.mode, Mode::PersistBlocked);
            // Force a due retry: skipping only until next_storage is too weak.
            e.next_storage = 0;
            e.emergency_unreserved_consumed = row == "persist_blocked_consumed";
        } else if row == "earlier_failed_commit" {
            // Sliced storage waits retry containment. Keep the load unavailable
            // until the remembered-failure branch is explicitly isolated below.
            e.platform
                .inject_persistent(Call::LoadAnchor, Fault::ToolFail { effect: false });
            e.enter_stuck();
            assert!(e.emergency_commit_failed);
            assert!(e.platform.enabled);
            // A later successful commit must not reintroduce reservation waits
            // during the same episode. Isolate that remembered-failure branch.
            e.platform.clear_faults();
            e.platform.complete_late(Copy::A, false);
            e.next_storage = 0;
            assert!(e.commit_if_changed());
            assert!(!e.storage_blocked);
            assert!(!e.emergency_unreserved_consumed);
            e.platform
                .inject_persistent(Call::Write(Copy::A), Fault::WriteHang);
            e.next_emergency = 0;
            // Measure a fresh disable after the earlier failed-load episode;
            // that episode already restored filtering despite its load failure.
            e.platform.mutate(Mutation::PfDisable);
        }
        if row.ends_with("acquire_hang") {
            e.platform.inject(
                Call::Acquire,
                1,
                Fault::ToolHang {
                    reaped: true,
                    effect: false,
                },
            );
        }
        e.platform.calls.clear();
        let entered = e.platform.now();
        if e.mode == Mode::Stuck {
            e.run_emergency();
        } else {
            e.enter_stuck();
        }
        if !e.platform.enabled {
            elapse_unchecked(&mut e, 1);
        }
        assert!(e.platform.enabled, "{row}");
        let latency = e.platform.pf_enabled_at.unwrap() - entered;
        let effect = e
            .platform
            .calls
            .iter()
            .position(|c| matches!(c, Call::Acquire | Call::EnablePf))
            .unwrap();
        if row.starts_with("persist_blocked") || row == "earlier_failed_commit" {
            assert!(
                !e.platform.calls[..effect]
                    .iter()
                    .any(|c| matches!(c, Call::Write(_))),
                "{row}"
            );
            assert_eq!(
                latency,
                if row.ends_with("acquire_hang") { 5 } else { 0 },
                "{row}"
            );
        } else {
            // The first storage slice enables through stateless containment,
            // before a later reference acquisition can spend its tool budget.
            assert_eq!(latency, 1, "{row}");
        }
        eprintln!("TABLE ProductionTiming: {row}, entry-to-enable {latency}s");
    }
    eprintln!(
        "TABLE ProductionTiming total: 6 rows, {:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn emergency_success_resets_acquisition_backoff() {
    let mut e = reboot_before_emergency();
    for _ in 0..2 {
        e.platform.inject(Call::Acquire, 1, Fault::NotStarted);
        e.enable_emergency_pf().unwrap();
        e.platform.mutate(Mutation::PfDisable);
        e.next_emergency = e.platform.now();
        e.platform.pause(Duration::from_secs(2), Deadline(u64::MAX));
    }
    assert_eq!(e.emergency_acquire_delay, 4);
    e.enable_emergency_pf().unwrap();
    assert_eq!(e.emergency_acquire_delay, 1);
    e.platform.mutate(Mutation::PfDisable);
    e.platform.inject(Call::Acquire, 1, Fault::NotStarted);
    e.enable_emergency_pf().unwrap();
    assert_eq!(e.emergency_next_acquire, e.platform.now() + 1);
}

#[test]
fn generated_post_load_stray_write_window() {
    let started = Instant::now();
    let foreign = "pass out quick all\nblock drop quick all\n";
    for qualified in [false, true] {
        let row = ("stray_write_in_window", qualified);
        let mut e = reboot_before_emergency();
        assert!(matches!(
            verify::capture_lockdown_baseline(
                foreign,
                &e.platform
                    .firewall_qualification
                    .as_ref()
                    .unwrap()
                    .normalization
            ),
            Err(verify::CaptureError::Unqualified(
                verify::UnqualifiedKind::StateFlags
            ))
        ));
        if !qualified {
            e.platform.firewall_qualification = None;
        }
        e.platform.anchor_write_between_readbacks = Some(foreign.into());
        e.enter_stuck();
        assert!(
            e.emergency_readback.is_none(),
            "two unequal immediate reads must not be accepted: {row:?}"
        );
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::ReadAnchor)
                .count(),
            2,
            "{row:?}"
        );
        assert!(e.platform.enabled, "{row:?}");
        assert_eq!(e.platform.anchor.as_deref(), Some(foreign), "{row:?}");
        assert!(!e.status().emergency_blocking_verified, "{row:?}");
        e.platform.calls.clear();
        elapse(&mut e, 1);
        assert!(e.platform.calls.contains(&Call::LoadAnchor), "{row:?}");
        if qualified {
            assert_emergency(&mut e);
        } else {
            assert_eq!(
                e.platform.anchor.as_deref(),
                Some(policy::render_lockdown().as_str()),
                "{row:?}"
            );
            assert!(!e.status().emergency_blocking_verified, "{row:?}");
        }
    }
    eprintln!("TABLE ReadbackWindow: 2 rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn persistent_not_started_bounds_snapshot_churn_and_retries_enable_within_one_second() {
    let mut e = reboot_before_emergency();
    e.platform
        .inject_persistent(Call::Acquire, Fault::NotStarted);
    e.platform
        .inject_persistent(Call::EnablePf, Fault::ToolFail { effect: false });
    e.enter_stuck();
    let mut acquisitions = 1;
    for gap in [1, 2, 4, 8, 16, 32, 60, 60] {
        let before = writes(&e.platform);
        let calls = e.platform.calls.len();
        elapse(&mut e, gap);
        acquisitions += 1;
        assert_eq!(
            e.platform
                .calls
                .iter()
                .filter(|c| **c == Call::Acquire)
                .count(),
            acquisitions
        );
        assert!(writes(&e.platform) - before <= 4, "gap {gap}");
        assert!(
            e.platform.calls[calls..]
                .iter()
                .filter(|c| **c == Call::EnablePf)
                .count()
                >= usize::try_from(gap).unwrap()
        );
        assert!(e.platform.tokens.is_empty());
    }
    e.platform.clear_faults();
    elapse(&mut e, 1);
    assert_emergency(&mut e);
}

#[test]
fn generated_unqualified_readback_product() {
    let started = Instant::now();
    let lockdown = policy::render_lockdown();
    let extra = lockdown.as_str().replace(
        "block drop quick all",
        "pass out quick all keep state (if-bound)\nblock drop quick all",
    );
    let texts = [
        "unparseable output".to_owned(),
        lockdown.as_str().replace("no state", ""),
        "pass out quick inet6 proto ipv6-icmp all icmp6-type routersol no state\nblock drop quick all\n".into(),
        extra.clone(), // strict unexpanded-list qualification
        extra,
        "anchor \"foreign/target\" all\nblock drop quick all\n".into(),
        String::new(),
        "pass all\n".into(),
        "anchor \"foreign/target\" all\n".into(),
        String::new(), // absent command read-back
    ];
    let mut rows = 0;
    for (variant, text) in texts.iter().enumerate() {
        for qualified in [false, true] {
            let row = (variant, qualified);
            let mut e = reboot_before_emergency();
            if qualified {
                let q = e.platform.firewall_qualification.as_mut().unwrap();
                if variant == 2 {
                    q.normalization.named_icmp = false;
                }
                if variant == 3 {
                    q.normalization.expanded_lists = false;
                }
            } else {
                e.platform.firewall_qualification = None;
            }
            e.platform.anchor_readback = Some(text.clone());
            e.platform.anchor_readback_absent = variant == 9;
            // Two identical raw post-load reads establish stability even when
            // stale qualification cannot capture a verifier baseline.
            let reload = variant >= 4 || (2..=3).contains(&variant) && !qualified;
            e.enter_stuck();
            assert!(e.platform.enabled, "{row:?}");
            assert!(!e.status().blocking_verified, "{row:?}");
            assert!(!e.status().emergency_blocking_verified, "{row:?}");
            assert_eq!(
                e.platform
                    .calls
                    .iter()
                    .filter(|c| **c == Call::Flush)
                    .count(),
                1,
                "{row:?}"
            );
            let gaps = if matches!(variant, 6 | 9) {
                [1; 8] // Empty listed configuration and missing anchors are both positive absence.
            } else {
                [1, 2, 4, 8, 16, 32, 60, 60]
            };
            for gap in gaps {
                e.platform.calls.clear();
                elapse(&mut e, gap - 1);
                assert!(
                    !e.platform.calls.contains(&Call::LoadAnchor),
                    "{row:?}, gap {gap}"
                );
                assert!(
                    !e.platform.calls.contains(&Call::Flush),
                    "{row:?}, gap {gap}"
                );
                elapse(&mut e, 1);
                assert_eq!(
                    e.platform
                        .calls
                        .iter()
                        .filter(|c| **c == Call::LoadAnchor)
                        .count(),
                    usize::from(reload),
                    "{row:?}, gap {gap}"
                );
                assert_eq!(
                    e.platform
                        .calls
                        .iter()
                        .filter(|c| **c == Call::Flush)
                        .count(),
                    1,
                    "{row:?}, gap {gap}"
                );
                assert!(e.platform.enabled, "{row:?}");
                assert!(!e.status().emergency_blocking_verified, "{row:?}");
            }
            rows += 1;
        }
    }
    assert_eq!(rows, 20);
    eprintln!("TABLE Readback: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn generated_verified_stuck_transient_and_sustained_faults() {
    let started = Instant::now();
    let mut rows = 0;
    for lockdown in [false, true] {
        for fault in 0..3 {
            for sustained in [false, true] {
                if fault == 2 && sustained {
                    continue; // Cached ownership glitch has no duration axis.
                }
                let mut e = if lockdown {
                    reboot_before_emergency()
                } else {
                    joined()
                };
                e.enter_stuck();
                let anchor = e.platform.anchor.clone();
                e.platform.calls.clear();
                match fault {
                    0 => e.platform.inject_persistent(Call::Collect, Fault::ReadFail),
                    1 => e.platform.inventory_race = true,
                    _ => e
                        .platform
                        .inject_persistent(Call::Processes, Fault::Incomplete),
                }
                e.next_full = 0;
                elapse(&mut e, 1);
                assert!(!e.startup_invariant_failed);
                assert!(e.startup_invariant_checked);
                assert!(e.verified_enforcement);
                assert_eq!(e.platform.anchor, anchor);
                assert!(!e.platform.calls.contains(&Call::LoadAnchor));
                if sustained && fault != 2 {
                    elapse(&mut e, 16);
                    assert_eq!(
                        e.platform.anchor.as_deref(),
                        Some(policy::render_lockdown().as_str())
                    );
                    assert!(!e.status().blocking_verified);
                    assert!(!e.status().emergency_blocking_verified);
                    assert_eq!(e.platform.calls.contains(&Call::LoadAnchor), !lockdown);
                } else {
                    e.platform.clear_faults();
                    e.platform.inventory_race = false;
                    elapse(&mut e, 5);
                    let status = e.status();
                    assert!(status.blocking_verified || status.emergency_blocking_verified);
                    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
                }
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 10);
    eprintln!("TABLE Transient: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn blocking_without_unmasked_protected_proof_revokes_immediately() {
    let mut e = held(false, false);
    drive(&mut e, 500);
    assert!(e.machine.blocking_verified_at(&Clock(e.platform.now())));
    assert!(!matches!(
        e.machine.enforcement_at(&Clock(e.platform.now())),
        Verdict::Protected(_)
    ));
    assert!(e.last_fresh_proof_at.is_none());
    e.platform.inject_persistent(Call::Collect, Fault::ReadFail);
    e.platform.calls.clear();
    e.enter_stuck();
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    assert!(e.platform.enabled);
    assert!(!e.status().blocking_verified);
    assert!(!e.status().emergency_blocking_verified);
}

#[test]
fn first_incomplete_startup_inventory_reaps_children_and_contains_without_latching() {
    let mut e = reboot_before_emergency();
    e.startup_invariant_checked = false;
    e.start_fence = StartFence::Uncommitted;
    e.platform.inject(Call::Processes, 1, Fault::Incomplete);
    e.platform.calls.clear();
    e.enter_stuck();
    assert!(!e.startup_invariant_checked);
    assert!(!e.startup_invariant_failed);
    assert!(e.platform.calls.contains(&Call::ReapChildren));
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.platform.enabled);
    assert!(!e.platform.calls.contains(&Call::Acquire));
    assert!(!e.platform.calls.contains(&Call::Spawn));
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    elapse(&mut e, 1);
    assert_emergency(&mut e);
}

#[test]
fn published_status_carries_expiry_for_both_blocking_claims() {
    let started = Instant::now();
    for variant in 0..3 {
        let emergency = variant == 1;
        let mut e = match variant {
            0 => joined(),
            1 => reboot_before_emergency(),
            _ => {
                let mut e = held(false, false);
                drive(&mut e, 500);
                e
            }
        };
        if variant != 2 {
            e.enter_stuck();
        }
        let published = e.status();
        assert_eq!(published.blocking_verified, !emergency);
        assert_eq!(published.emergency_blocking_verified, emergency);
        let expiry = if emergency {
            published.emergency_expires_at
        } else {
            published.blocking_expires_at
        }
        .unwrap();
        let at_boundary = published.clone().at(expiry);
        assert!(at_boundary.blocking_verified || at_boundary.emergency_blocking_verified);
        for _ in 0..(e.timings.max_age + 1) * 20 {
            e.platform.tick();
        }
        let expired = published.at(e.platform.now());
        assert!(!expired.blocking_verified);
        assert!(!expired.emergency_blocking_verified);
        assert!(!e.status().blocking_verified);
        assert!(!e.status().emergency_blocking_verified);
    }
    eprintln!("TABLE Status expiry: 3 rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn generated_emergency_leave_partial_failures() {
    let started = Instant::now();
    let mut rows = 0;
    for clear_fail in [false, true] {
        for storage_fail in [false, true] {
            for late in 0..3 {
                let row = (clear_fail, storage_fail, late);
                let mut e = reacquiring_after_verified_enforcement();
                if late == 1 {
                    e.platform
                        .inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: Some(40) });
                }
                e.enter_stuck();
                if clear_fail {
                    e.platform.inject(Call::LeaveRoutes, 1, Fault::ReadFail);
                }
                if storage_fail {
                    e.platform
                        .inject_persistent(Call::Write(Copy::A), Fault::WriteFail);
                }
                if late == 2 {
                    e.platform
                        .inject(Call::CleanupDns, 1, Fault::ToolLate { ticks: Some(20) });
                }
                e.platform.unkillable.clear();
                let calls = e.platform.calls.len();
                leave(&mut e, 50);
                e.run_until_quiescent(100);
                assert!(e.emergency_revoked, "{row:?}");
                // A late cleanup tool may be alive on the first pass. Let its
                // effect finish, then reap it before final absence verification.
                for _ in 0..40 {
                    e.platform.tick();
                }
                e.platform.unkillable.clear();
                e.platform.release_unreaped();
                elapse(&mut e, 5);
                assert!(
                    !e.platform.calls[calls..].contains(&Call::LoadAnchor),
                    "{row:?}"
                );
                assert!(e.platform.anchor.is_none(), "{row:?}");
                assert!(!e.status().emergency_blocking_verified, "{row:?}");
                if storage_fail {
                    assert_ne!(e.outcome, Outcome::Exit0, "{row:?}");
                    assert!(e.storage_blocked, "{row:?}");
                }
                e.platform.clear_faults();
                elapse(&mut e, 65);
                let status = e.status();
                assert_eq!(e.outcome, Outcome::Exit0, "{row:?}: {status:?}");
                assert_eq!(e.status().text, "left");
                assert!(
                    !e.platform.calls[calls..].contains(&Call::LoadAnchor),
                    "{row:?}"
                );
                assert!(e.platform.anchor.is_none());
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 12);
    eprintln!("TABLE Leave: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn generated_next_incarnation_releases_only_known_emergency_references() {
    let started = Instant::now();
    let mut rows = 0;
    for acquisition in [
        AcquireFault::Ok,
        AcquireFault::UnknownEffect,
        AcquireFault::NoFingerprint,
    ] {
        for reboot in [false, true] {
            let mut e = reboot_before_emergency();
            fault_acquire(&mut e, acquisition);
            e.enter_stuck();
            elapse(&mut e, 1);
            assert!(e.platform.enabled);
            let owned: Vec<_> = e.platform.tokens.keys().copied().collect();
            assert_eq!(owned.len(), 1);
            e.platform.mutate(Mutation::ForeignEnable);
            let foreign = *e
                .platform
                .tokens
                .keys()
                .find(|t| !owned.contains(t))
                .unwrap();
            leave(&mut e, 70);
            assert_eq!(e.run_until_quiescent(100), Outcome::Exit0);
            let mut p = e.into_platform();
            if reboot {
                p.mutate(Mutation::Reboot);
            } else {
                p.restart();
            }
            p.calls.clear();
            let mut e = Engine::start(p).unwrap();
            drive(&mut e, 500);
            for token in owned {
                let release = acquisition == AcquireFault::Ok && !reboot;
                assert_eq!(
                    e.platform.calls.contains(&Call::Release(token)),
                    release,
                    "{acquisition:?}, reboot {reboot}"
                );
                assert_eq!(e.platform.tokens.contains_key(&token), !reboot && !release);
            }
            assert!(!e.platform.calls.contains(&Call::Release(foreign)));
            assert_eq!(e.platform.tokens.contains_key(&foreign), !reboot);
            assert!(e.platform.anchor.is_none());
            assert!(!e.machine.durable().join_intended);
            rows += 1;
        }
    }
    assert_eq!(rows, 6);
    eprintln!("TABLE References: {rows} rows, {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn not_started_settlement_commit_failure_survives_as_uncertain_after_crash() {
    let mut e = reboot_before_emergency();
    e.platform.inject(Call::Acquire, 1, Fault::NotStarted);
    // Reservation pair commits first; fail A of the settlement pair.
    e.platform.inject(Call::Write(Copy::A), 2, Fault::WriteFail);
    e.enter_stuck();
    assert!(e.platform.enabled);
    assert!(!e.emergency_unreserved_consumed);
    assert!(e.platform.tokens.is_empty());
    let disk = read_snapshot(&mut e.platform, Copy::A);
    let uncertain: Vec<_> = disk
        .references
        .iter()
        .flatten()
        .filter_map(|r| {
            if let ReferenceEntry::Acquire(seq) = r.key {
                Some(seq)
            } else {
                None
            }
        })
        .collect();
    assert!(uncertain.len() >= 2, "{disk:?}");
    e.platform.mutate(Mutation::ForeignEnable);
    let foreign = *e.platform.tokens.keys().next().unwrap();
    // Crash immediately: no subsequent storage retry can persist settlement.
    let mut p = e.into_platform();
    p.crash();
    p.clear_faults();
    p.restart();
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 500);
    leave(&mut e, 80);
    drive(&mut e, 500);
    assert!(e.platform.anchor.is_none());
    assert!(e.platform.tokens.contains_key(&foreign));
    assert!(
        !e.platform
            .calls
            .iter()
            .any(|call| matches!(call, Call::Release(_)))
    );
    let durable = e.snapshot.validate().unwrap();
    assert!(
        uncertain
            .iter()
            .all(|seq| reference_keys(&durable).contains(&ReferenceEntry::Acquire(*seq))),
        "{durable:?}"
    );
}

#[test]
fn raw_readback_gate_reloads_whitespace_and_semantically_equal_spelling() {
    let mut e = reboot_before_emergency();
    e.enter_stuck();
    assert_emergency(&mut e);
    let lockdown = policy::render_lockdown();
    e.platform.anchor_readback = Some(lockdown.as_str().replace(' ', "   "));
    e.platform.calls.clear();
    elapse(&mut e, 1);
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|c| **c == Call::LoadAnchor)
            .count(),
        1
    );
    e.platform.calls.clear();
    elapse(&mut e, 5);
    assert!(!e.platform.calls.contains(&Call::LoadAnchor));
    assert!(e.status().emergency_blocking_verified);
    let spelling = lockdown
        .as_str()
        .replace("all no state", "from any to any no state");
    assert!(
        verify::capture_lockdown_baseline(
            &spelling,
            &e.platform
                .firewall_qualification
                .as_ref()
                .unwrap()
                .normalization
        )
        .is_ok()
    );
    e.platform.anchor_readback = None;
    e.platform.anchor = Some(spelling);
    e.platform.calls.clear();
    elapse(&mut e, 1);
    assert!(e.platform.calls.contains(&Call::LoadAnchor));
    assert_emergency(&mut e);
}

#[test]
fn post_d3_enabled_reference_product_requires_a_committed_reservation() {
    for storage in [
        StorageFault::Healthy,
        StorageFault::WriteFail,
        StorageFault::Cap,
    ] {
        let mut p = joined().into_platform();
        p.mutate(Mutation::Reboot);
        let mut e = Engine::start(p).unwrap();
        assert!(e.platform.enabled);
        assert!(e.emergency_needs_reference);
        fault_storage(&mut e, storage);
        e.platform.calls.clear();
        e.enter_stuck();
        assert!(e.platform.enabled);
        assert_eq!(
            e.platform.calls.contains(&Call::Acquire),
            storage == StorageFault::Healthy,
            "{storage:?}"
        );
        assert!(!e.emergency_unreserved_consumed, "{storage:?}");
        if storage == StorageFault::Healthy {
            let acquire = e
                .platform
                .calls
                .iter()
                .position(|c| *c == Call::Acquire)
                .unwrap();
            assert!(e.platform.calls[..acquire].contains(&Call::Write(Copy::B)));
        }
    }
}

#[test]
fn generated_stuck_current_proof_distinguishes_pfctl_from_mtu_tools() {
    for entry in ENTRIES {
        for own_pfctl in [false, true] {
            // Open tools gate some entry operations (notably dispatch). Reach
            // each entry first, then exercise its continuing Stuck maintenance.
            let e = scenario(Scenario::Joined);
            let joined_anchor = e.platform.anchor.clone();
            let mut e = trigger(e, entry);
            assert_eq!(e.mode, Mode::Stuck, "{entry:?}");
            // Fixed entry table: a constructor has no incarnation proof, and
            // CompletionBackpressure invalidates it through queue overflow.
            // Other entries reject before replacing the Joined reducer.
            let current_proof =
                !matches!(entry, Entry::Constructor | Entry::CompletionBackpressure);
            let clock = Clock(e.platform.now());
            let observed_proof = e.machine.blocking_verified_at(&clock)
                || matches!(e.machine.enforcement_at(&clock), Verdict::Protected(_))
                || e.emergency_proof.as_ref().is_some_and(|proof| {
                    proof.kind() != Kind::Lockdown
                        && matches!(
                            Verdict::Protected(proof.clone()).at(&clock),
                            Verdict::Protected(_)
                        )
                });
            assert_eq!(observed_proof, current_proof, "{entry:?}");
            if current_proof {
                assert_eq!(e.platform.anchor, joined_anchor, "{entry:?}");
            }
            let already_lockdown =
                e.platform.anchor.as_deref() == Some(policy::render_lockdown().as_str());
            let call = if own_pfctl {
                Call::LoadAnchor
            } else {
                Call::Configure(ConfigKey::Mtu)
            };
            e.platform.inject(call, 1, Fault::ToolLate { ticks: None });
            let d = Deadline(e.platform.now() + 1);
            if own_pfctl {
                let _ = e.platform.load_anchor(&policy::render_lockdown(), d);
            } else {
                let _ = e.platform.configure(ConfigKey::Mtu, &Setting::Mtu(1420), d);
            }
            e.platform.calls.clear();
            let now = e.platform.now();
            let expected = if current_proof {
                stuck_outcome(entry, Scenario::Joined, BootKind::Live, own_pfctl)
            } else {
                Expected::Emergency
            };
            e.next_emergency = now;
            e.run_emergency();
            let loads = e.platform.calls.contains(&Call::LoadAnchor);
            match expected {
                Expected::Kept => assert!(!loads, "{entry:?}, own_pfctl={own_pfctl}"),
                Expected::Emergency => {
                    assert!(
                        loads || already_lockdown,
                        "{entry:?}, own_pfctl={own_pfctl}"
                    );
                    assert!(e.platform.enabled);
                    assert_eq!(
                        e.platform.anchor.as_deref(),
                        Some(policy::render_lockdown().as_str())
                    );
                }
                Expected::Left => unreachable!(),
            }
        }
    }
}
