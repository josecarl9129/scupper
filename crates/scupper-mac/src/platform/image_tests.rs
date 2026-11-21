//! Negative-only UUID evidence must never weaken existing ownership rules.
use super::*;
use fake::{CHILD_PATH, Call, FakePlatform};

fn fixture() -> Result<(FakePlatform, ImageHistory), SysError> {
    let mut p = FakePlatform::new()?;
    let mut history = ImageHistory::empty_for_boot(p.boot.clone().ok_or(SysError::Unknown)?);
    history.record([55; 16]);
    let mut proc = p
        .procs
        .get(&p.helper.pid)
        .cloned()
        .ok_or(SysError::Unknown)?;
    proc.pid = 777;
    proc.pgid = 777;
    proc.ppid = 2;
    proc.start.seconds = 50;
    proc.path = None;
    proc.exe = None;
    proc.name = Some("foreign".into());
    proc.image = Some(ImageId {
        uuid: [77; 16],
        uniqueid: 777,
    });
    p.procs.insert(proc.pid, proc);
    Ok((p, history))
}
fn run(p: &mut FakePlatform, h: &ImageHistory) -> Sweep {
    sweep_with_history(
        p,
        Path::new(CHILD_PATH),
        &[],
        h,
        &[],
        &Timings::default(),
        Deadline(110),
    )
}
#[test]
fn image_foreign_needs_two_reads_and_never_signals() -> Result<(), SysError> {
    let (mut p, h) = fixture()?;
    assert_eq!(run(&mut p, &h), Sweep::Swept);
    assert_eq!(p.calls.iter().filter(|c| **c == Call::Processes).count(), 2);
    assert_eq!(p.signals, []);
    assert!(p.procs.contains_key(&777));
    Ok(())
}
#[test]
fn image_every_unknown_or_equal_clause_withholds_pid() -> Result<(), SysError> {
    for clause in 0..10 {
        let (mut p, mut h) = fixture()?;
        match clause {
            0 => h.record([77; 16]),
            1 => {
                p.image_uuids.insert(CHILD_PATH.into(), Some([77; 16]));
            }
            2 => h.known = false,
            3 => {
                p.image_uuids.insert(CHILD_PATH.into(), None);
            }
            4 => p.procs.get_mut(&777).ok_or(SysError::Unknown)?.image = None,
            5 => p.procs.get_mut(&777).ok_or(SysError::Unknown)?.name = Some("wireguard-go".into()),
            6 => p.boot = None,
            7 => h.boot = None,
            8 => {
                p.procs
                    .get_mut(&777)
                    .ok_or(SysError::Unknown)?
                    .image
                    .as_mut()
                    .ok_or(SysError::Unknown)?
                    .uuid = [0; 16];
            }
            _ => p.procs.get_mut(&777).ok_or(SysError::Unknown)?.name = None,
        }
        assert!(
            matches!(
                run(&mut p, &h),
                Sweep::Incomplete(ProcessError { pid: Some(777), .. })
            ),
            "clause {clause}"
        );
        assert_eq!(p.signals, []);
    }
    Ok(())
}
#[test]
fn image_exact_record_precedes_different_uuid_and_unknown_history() -> Result<(), SysError> {
    for known in [false, true] {
        let (mut p, mut h) = fixture()?;
        h.known = known;
        let proc = p.procs[&777].clone();
        let child = Child {
            boot: p.boot.clone(),
            generation: 1,
            pid: proc.pid,
            start_time: proc.start,
            exe: None,
            image: Some(ImageId {
                uuid: [2; 16],
                uniqueid: 1,
            }),
            pgid: 777,
            utun: "utun6".into(),
        };
        assert_eq!(
            sweep_with_history(
                &mut p,
                Path::new(CHILD_PATH),
                &[child],
                &h,
                &[],
                &Timings::default(),
                Deadline(110)
            ),
            Sweep::Swept
        );
        assert_eq!(p.signals, [(777, proc.start)]);
    }
    Ok(())
}
#[test]
fn image_previous_group_and_ambiguity_precede_negative_evidence() -> Result<(), SysError> {
    for ambiguity in [false, true] {
        let (mut p, h) = fixture()?;
        p.procs.get_mut(&777).ok_or(SysError::Unknown)?.ppid = 1;
        let previous = if ambiguity {
            PreviousHelper::Unknown
        } else {
            p.procs.get_mut(&777).ok_or(SysError::Unknown)?.pgid = 776;
            PreviousHelper::Known(HelperIncarnation {
                pid: 776,
                pgid: 776,
                start: StartTime {
                    seconds: 40,
                    microseconds: 0,
                },
                boot: p.boot.clone(),
            })
        };
        let result = start_fence_inner(
            &mut p,
            previous,
            &[],
            Path::new(CHILD_PATH),
            &[],
            &Timings::default(),
            Deadline(110),
            false,
            &h,
        );
        if ambiguity {
            assert!(matches!(
                result,
                StartFence::Processes(Sweep::Incomplete(ProcessError { pid: Some(777), .. }))
            ));
            assert_eq!(p.signals, []);
        } else {
            assert_eq!(result, StartFence::Closed);
            assert_eq!(p.signals.len(), 1);
        }
    }
    Ok(())
}
#[test]
fn image_upgrade_history_and_overflow_remain_uncertain() -> Result<(), SysError> {
    let (mut p, mut h) = fixture()?;
    // U1 was spawned, helper crashed and current pin is U2.
    h.record([77; 16]);
    p.image_uuids.insert(CHILD_PATH.into(), Some([2; 16]));
    assert!(matches!(
        run(&mut p, &h),
        Sweep::Incomplete(ProcessError { pid: Some(777), .. })
    ));
    assert_eq!(p.signals, []);
    for i in 1..=9 {
        h.record([i; 16]);
    }
    assert!(!h.known);
    assert_eq!(h.uuids.len(), 8);
    Ok(())
}

#[test]
fn image_pin_path_ownership_and_all_current_pins_precede_foreign_rule() -> Result<(), SysError> {
    let (mut p, h) = fixture()?;
    p.procs.get_mut(&777).ok_or(SysError::Unknown)?.path = Some(CHILD_PATH.into());
    assert_eq!(run(&mut p, &h), Sweep::Swept);
    assert_eq!(p.signals.len(), 1);
    let (mut p, h) = fixture()?;
    p.image_uuids.insert("/sbin/pfctl".into(), None);
    let result = poll_start_fence_with_history(
        &mut p,
        PreviousHelper::None,
        &[Path::new("/sbin/pfctl")],
        Path::new(CHILD_PATH),
        &[],
        &h,
        &Timings::default(),
        Deadline(110),
    );
    assert!(matches!(
        result,
        StartFence::Processes(Sweep::Incomplete(ProcessError { pid: Some(777), .. }))
    ));
    assert_eq!(p.signals, []);
    Ok(())
}

#[test]
fn image_additional_pins_only_withhold_and_never_select() -> Result<(), SysError> {
    let (mut p, h) = fixture()?;
    p.image_uuids.insert("/sbin/pfctl".into(), Some([77; 16]));
    let result = sweep_with_history(
        &mut p,
        Path::new(CHILD_PATH),
        &[],
        &h,
        &[Path::new("/sbin/pfctl")],
        &Timings::default(),
        Deadline(110),
    );
    assert!(matches!(
        result,
        Sweep::Incomplete(ProcessError { pid: Some(777), .. })
    ));
    assert_eq!(p.signals, []);
    p.image_uuids.insert("/sbin/pfctl".into(), Some([66; 16]));
    assert_eq!(
        sweep_with_history(
            &mut p,
            Path::new(CHILD_PATH),
            &[],
            &h,
            &[Path::new("/sbin/pfctl")],
            &Timings::default(),
            Deadline(120)
        ),
        Sweep::Swept
    );
    assert_eq!(p.signals, []);
    Ok(())
}
