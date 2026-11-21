//! Fresh-install certainty and uncertainty epochs, exercised through real startup.
use super::*;
use crate::snapshot::{HelperIncarnation, ImageHistory};

fn initial() -> Snapshot {
    Snapshot::initial(Some(501), FakePlatform::new().unwrap().boot)
}
fn foreign(p: &mut FakePlatform, orphan: bool) {
    let mut proc = p.procs[&p.helper.pid].clone();
    proc.pid = 888;
    proc.pgid = 888;
    proc.ppid = if orphan { 1 } else { 2 };
    proc.start.seconds = 10;
    proc.path = None;
    proc.exe = None;
    proc.name = Some("foreign".into());
    proc.image = Some(platform::ImageId {
        uuid: [88; 16],
        uniqueid: 888,
    });
    p.procs.insert(proc.pid, proc);
}
fn withheld(e: &Engine<FakePlatform>) {
    assert!(
        matches!(e.start_fence,
        StartFence::Processes(Sweep::Incomplete(ref error)) if error.pid == Some(888)),
        "{:?}",
        e.start_fence
    );
    assert_eq!(e.platform.signals, []);
}
fn legacy(snapshot: &Snapshot) -> Box<[u8; snapshot::COPY_BYTES]> {
    use sha2::{Digest, Sha256};
    // Preserve the struct's canonical field order: a Value map sorts keys and
    // would exercise Recovery instead of the strict format-1 migration path.
    let history = format!(
        "\"image_history\":{},",
        serde_json::to_string(&snapshot.image_history).unwrap()
    );
    let body = serde_json::to_string(snapshot).unwrap();
    assert_eq!(body.matches(&history).count(), 1);
    let body = body.replace(&history, "").into_bytes();
    let mut bytes = snapshot::encode(1, snapshot).unwrap();
    bytes.fill(0);
    bytes[..8].copy_from_slice(b"SCPMACS\x01");
    bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes[12..20].copy_from_slice(&1_u64.to_le_bytes());
    bytes[20..24].copy_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    let end = 24 + body.len();
    bytes[24..end].copy_from_slice(&body);
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..end + 32].copy_from_slice(&digest);
    assert!(
        matches!(snapshot::classify_copy(snapshot::CopyRead::Bytes(bytes.to_vec())),
        CopyClass::V { snapshot: migrated, .. }
            if !migrated.image_history.known && migrated.helper == snapshot.helper)
    );
    bytes
}
fn older_boot() -> BootId {
    "00112233-4455-6677-8899-AABBCCDDEEFF".try_into().unwrap()
}
fn previous(boot: Option<BootId>) -> HelperIncarnation {
    HelperIncarnation {
        pid: 777,
        pgid: 777,
        start: snapshot::StartTime {
            seconds: 50,
            microseconds: 0,
        },
        boot,
    }
}

#[test]
fn fresh_initial_foreign_allows_start_join_and_leave() {
    let mut p = fixture(&initial());
    foreign(&mut p, true);
    let mut e = Engine::start(p).unwrap();
    assert!(e.snapshot.image_history.known_on(e.platform.boot.as_ref()));
    assert!(e.snapshot.image_history.uuids.is_empty());
    assert_eq!(e.start_fence, StartFence::Closed);
    assert!(e.confirm_sweep());
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 300);
    assert!(e.child.is_some(), "{:?}", e.status());
    assert!(e.platform.calls.contains(&Call::Spawn));
    leave(&mut e, 2);
    drive(&mut e, 500);
    assert_left(&mut e, 2);
    assert!(e.verify_clear_intent().is_ok());
    assert!(!e.platform.signals.iter().any(|(pid, _)| *pid == 888));
}

#[test]
fn recovery_uses_current_epoch_even_with_older_helper_and_only_reboot_resets() {
    for readable_boot in [true, false] {
        let mut s = initial();
        s.helper = Some(previous(Some(older_boot())));
        let mut p = fixture(&s);
        // A valid old copy and a newer invalid one force Recovery while retaining
        // the old helper. Its boot is deliberately older than the observed boot.
        let mut invalid = s.clone();
        invalid.owner_uid = Some(502);
        p.copies[1].durable = Some(snapshot::encode(1, &invalid).unwrap());
        if !readable_boot {
            p.mutate(Mutation::BootIdUnavailable);
        }
        foreign(&mut p, false);
        let mut e = Engine::start(p).unwrap();
        assert!(!e.snapshot.image_history.known);
        assert_eq!(e.snapshot.image_history.boot, e.platform.boot);
        withheld(&e);
        e.platform.procs.remove(&888);
        drive(&mut e, 50);
        assert!(!e.snapshot.image_history.known);
        let epoch = e.platform.boot.clone();
        let mut p = e.into_platform();
        if readable_boot {
            p.mutate(Mutation::Reboot);
            let mut e = Engine::start(p).unwrap();
            assert_ne!(epoch, e.platform.boot);
            assert!(e.snapshot.image_history.known_on(e.platform.boot.as_ref()));
            assert!(e.snapshot.image_history.uuids.is_empty());
            assert_eq!(
                read_snapshot(&mut e.platform, Copy::A).image_history,
                e.snapshot.image_history
            );
        }
    }
}

#[test]
fn legacy_same_and_older_boots_need_a_further_proven_boot() {
    for old in [false, true] {
        let mut s = initial();
        let mut p = fixture(&s);
        s.helper = Some(previous(if old {
            Some(older_boot())
        } else {
            p.boot.clone()
        }));
        for copy in &mut p.copies {
            copy.durable = Some(legacy(&s));
        }
        foreign(&mut p, false);
        let mut e = Engine::start(p).unwrap();
        assert!(!e.snapshot.image_history.known, "old={old}");
        assert_eq!(e.snapshot.image_history.boot, e.platform.boot);
        withheld(&e);
        e.platform.procs.remove(&888);
        drive(&mut e, 50);
        let mut p = e.into_platform();
        p.restart();
        let e = Engine::start(p).unwrap();
        assert!(!e.snapshot.image_history.known);
        let mut p = e.into_platform();
        p.mutate(Mutation::Reboot);
        let e = Engine::start(p).unwrap();
        assert!(e.snapshot.image_history.known_on(e.platform.boot.as_ref()));
        assert!(e.snapshot.image_history.uuids.is_empty());
    }
}

#[test]
fn torn_pair_uses_current_epoch_not_surviving_old_epoch() {
    for disagreement in 0..4 {
        let mut s = initial();
        s.image_history = ImageHistory::empty_for_boot(older_boot());
        let mut p = fixture(&s);
        if disagreement == 3 {
            p.inject_persistent(Call::Read(Copy::B), Fault::ReadFail);
        } else if disagreement != 0 {
            if disagreement == 1 {
                s.image_history.record([3; 16]);
            }
            p.copies[0].durable = Some(snapshot::encode(2, &s).unwrap());
        } else {
            p.mutate(Mutation::CopyRot(Copy::B));
        }
        foreign(&mut p, false);
        let e = Engine::start(p).unwrap();
        assert!(!e.snapshot.image_history.known);
        assert_eq!(e.snapshot.image_history.boot, e.platform.boot);
        withheld(&e);
    }
}

#[test]
fn known_previous_helper_withholds_older_orphan_history_and_name() {
    for name_guard in [false, true] {
        let mut s = initial();
        s.helper = Some(previous(s.image_history.boot.clone()));
        if !name_guard {
            s.image_history.record([88; 16]);
        }
        let mut p = fixture(&s);
        foreign(&mut p, true);
        if name_guard {
            p.procs.get_mut(&888).unwrap().name = Some("wireguard-go".into());
        }
        let e = Engine::start(p).unwrap();
        assert!(matches!(
            e.previous_helper,
            platform::PreviousHelper::Known(_)
        ));
        withheld(&e);
    }
}

#[test]
fn emergency_start_foreign_proceeds_only_with_known_history() {
    for known in [false, true] {
        let mut s = initial();
        s.machine.join_intended = true;
        s.machine.hold = true;
        s.image_history.known = known;
        let mut p = fixture(&s);
        foreign(&mut p, false);
        let mut e = Engine::start(p).unwrap();
        e.enter_stuck();
        drive(&mut e, 100);
        assert_eq!(e.start_fence == StartFence::Closed, known);
        assert_eq!(e.prepare_emergency_fence(), known);
        assert!(e.platform.calls.contains(&Call::LoadAnchor));
        assert!(!e.platform.signals.iter().any(|(pid, _)| *pid == 888));
        if !known {
            withheld(&e);
        }
    }
}

#[test]
fn known_history_recovery_ambiguity_retains_original_pathless_assertions() {
    for previous in [
        platform::PreviousHelper::None,
        platform::PreviousHelper::Unknown,
    ] {
        for state in [
            ProcState::Running,
            ProcState::Sleeping,
            ProcState::Stopped,
            ProcState::Zombie,
        ] {
            for (parent, seconds, ambiguous) in [(1, 90, true), (77, 90, false), (1, 101, false)] {
                let mut e = fresh();
                foreign(&mut e.platform, false);
                let proc = e.platform.procs.get_mut(&888).unwrap();
                proc.ppid = parent;
                proc.start.seconds = seconds;
                proc.state = state;
                e.previous_helper = previous.clone();
                e.start_fence = StartFence::Uncommitted;
                let closed = e.close_emergency_fence();
                let uncertain = previous == platform::PreviousHelper::Unknown
                    && ambiguous
                    && state != ProcState::Zombie;
                assert_eq!(
                    closed, !uncertain,
                    "{previous:?} {state:?} {parent} {seconds}"
                );
                assert_eq!(e.platform.signals, []);
                if uncertain {
                    withheld(&e);
                }
            }
        }
    }
}

#[test]
fn mismatched_child_commit_failure_and_kill_failure_stay_unconfirmed() {
    for commit_fails in [false, true] {
        let mut e = fresh();
        e.submit(Request {
            id: 1,
            kind: RequestKind::Join,
        })
        .unwrap();
        before_pending(&mut e, Step::StartChild);
        e.platform.spawn_image = Some(platform::ImageId {
            uuid: [88; 16],
            uniqueid: 99,
        });
        if commit_fails {
            e.platform.inject(Call::Write(Copy::A), 2, Fault::WriteFail);
        } else {
            let mut preview = e.platform.clone();
            let d = Deadline(preview.now() + 2);
            let child = preview
                .spawn(
                    TunnelGeneration::new(1).unwrap(),
                    execute::CHILD_SPAWN_ATTRIBUTES,
                    d,
                )
                .unwrap();
            e.platform.inject(
                Call::KillProcess(child.pid, child.start_time),
                1,
                Fault::Incomplete,
            );
        }
        assert!(e.execute(Step::StartChild).is_err());
        assert!(e.platform.spawn_image.is_none());
        assert!(e.child.is_some());
        assert!(e.last_sweep.is_some());
        if commit_fails {
            assert!(e.storage_blocked);
            assert_eq!(e.mode, Mode::PersistBlocked);
            assert!(!e.committed.image_history.uuids.contains(&[88; 16]));
        } else {
            assert!(e.committed.image_history.uuids.contains(&[88; 16]));
        }
    }
}

#[test]
fn failed_and_timed_out_spawn_record_changed_pin_before_sweep() {
    for timeout in [false, true] {
        for readable in [false, true] {
            let mut e = fresh();
            e.submit(Request {
                id: 1,
                kind: RequestKind::Join,
            })
            .unwrap();
            before_pending(&mut e, Step::StartChild);
            e.platform.inject(
                Call::Spawn,
                1,
                Fault::SpawnPinChange {
                    uuid: readable.then_some([99; 16]),
                    timeout,
                },
            );
            e.platform.calls.clear();
            assert!(e.execute(Step::StartChild).is_err());
            let history = read_snapshot(&mut e.platform, Copy::A).image_history;
            assert_eq!(history.known, readable);
            if readable {
                assert!(history.uuids.contains(&[99; 16]));
            }
            let spawn = e
                .platform
                .calls
                .iter()
                .position(|c| *c == Call::Spawn)
                .unwrap();
            let after = &e.platform.calls[spawn + 1..];
            let write = after
                .iter()
                .position(|c| *c == Call::Write(Copy::B))
                .unwrap();
            assert!(after[..write].contains(&Call::ImageUuid));
            assert!(!after[..write].contains(&Call::Processes));
        }
    }
}

#[test]
fn failed_spawn_history_commit_blocks_before_another_inventory() {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, Step::StartChild);
    e.platform.inject(
        Call::Spawn,
        1,
        Fault::SpawnPinChange {
            uuid: Some([99; 16]),
            timeout: true,
        },
    );
    e.platform.inject(Call::Write(Copy::A), 2, Fault::WriteFail);
    e.platform.calls.clear();
    assert_eq!(
        e.execute(Step::StartChild),
        Err(SysError::Failed("image history write failed"))
    );
    assert_eq!(e.mode, Mode::PersistBlocked);
    assert!(e.snapshot.image_history.uuids.contains(&[99; 16]));
    assert!(!e.committed.image_history.uuids.contains(&[99; 16]));
    let spawn = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::Spawn)
        .unwrap();
    assert!(!e.platform.calls[spawn + 1..].contains(&Call::Processes));
}
