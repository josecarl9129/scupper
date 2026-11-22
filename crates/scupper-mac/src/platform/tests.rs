//! Reusable no-fault adapter contracts, plus the fake's fault and protocol tests.
//!
//! The real adapter harness must supply isolated scratch copies, a supervised
//! helper process group and exclusive access to its test accounting effects.
use super::{
    Deadline, Enumeration, Fence, KillOutcome, Platform, Release, SysError, ToolOutcome,
    WriteOutcome,
};
use crate::snapshot::{COPY_BYTES, Copy, CopyRead};

/// Minimal fixture hooks for the same suite on fake and real adapters.
pub trait ContractHarness<P: Platform> {
    /// Platform using empty scratch copy paths, never production copies.
    fn platform(&mut self) -> &mut P;
    /// Create a foreground child in the suite helper's process group through the
    /// adapter's `spawn` semantics (and register it for `reap_children`). The
    /// harness must use disposable scratch executables, never production children.
    ///
    /// # Errors
    /// Reports fixture setup failure.
    fn scratch_process(&mut self) -> Result<super::ProcInfo, SysError>;
    /// Spawn a supervised scratch child and return the adapter's actual record.
    ///
    /// # Errors
    /// Reports scratch spawn failure.
    fn scratch_child(&mut self) -> Result<super::Child, SysError>;
    /// Actual suite helper binary, for independent vnode identity qualification.
    fn own_executable(&self) -> &std::path::Path;
    /// Disposable, unlinkable scratch binary copy used by `scratch_process`.
    fn scratch_executable(&self) -> &std::path::Path;
    /// Unlink that copy while the supervised process remains alive.
    ///
    /// # Errors
    /// Reports fixture unlink failure.
    fn unlink_scratch_executable(&mut self) -> Result<(), SysError>;
}

fn limit(p: &mut impl Platform) -> Deadline {
    Deadline(p.now().saturating_add(5))
}

/// Run all no-fault contracts against an isolated harness. Assertion failures
/// identify contract violations; the later macOS adapter must run this unchanged.
///
/// # Errors
/// Returns fixture or guarded cleanup failures. Assertion failures panic even
/// outside `#[test]`; the harness must propagate panics as test failures.
///
/// # Panics
/// Asserts each platform contract. Tests must isolate copies and pf accounting.
pub fn run_contracts<P: Platform, H: ContractHarness<P>>(h: &mut H) -> Result<(), SysError> {
    let p = h.platform();
    assert_eq!(p.incarnation().boot, p.boot_id());
    for copy in [Copy::A, Copy::B] {
        let d = limit(p);
        assert_eq!(p.read_copy(copy, d), CopyRead::Missing);
        let d = limit(p);
        assert!(matches!(
            p.write_copy(copy, &[9; COPY_BYTES], d),
            WriteOutcome::Failed(_)
        ));
        let d = limit(p);
        assert_eq!(p.read_copy(copy, d), CopyRead::Missing);
        let d = limit(p);
        assert_eq!(
            p.create_copy(copy, &[1; COPY_BYTES], d),
            WriteOutcome::Synced
        );
        let d = limit(p);
        assert_eq!(
            p.write_copy(copy, &[2; COPY_BYTES], d),
            WriteOutcome::Synced
        );
        let d = limit(p);
        assert_eq!(p.read_copy(copy, d), CopyRead::Bytes(vec![2; COPY_BYTES]));
        let d = limit(p);
        assert!(matches!(
            p.create_copy(copy, &[3; COPY_BYTES], d),
            WriteOutcome::Failed(_)
        ));
        let d = limit(p);
        assert_eq!(p.read_copy(copy, d), CopyRead::Bytes(vec![2; COPY_BYTES]));
    }
    let d = limit(p);
    let before = match p.references(d) {
        Enumeration::Complete(refs) => refs,
        Enumeration::Incomplete(e) => return Err(e),
    };
    let d = limit(p);
    let acquired = p.acquire(d);
    assert_eq!(p.fence(), Fence::Closed);
    assert!(matches!(acquired, ToolOutcome::Ok(_)));
    if let ToolOutcome::Ok((token, pid)) = acquired {
        let d = limit(p);
        let references = p.references(d);
        assert!(
            matches!(references, Enumeration::Complete(ref refs) if refs.iter().any(|r| r.token == token && r.pid == pid))
        );
        let d = limit(p);
        assert_eq!(p.release(token, d), ToolOutcome::Ok(Release::Requested));
        assert_eq!(p.fence(), Fence::Closed);
        let d = limit(p);
        assert!(
            matches!(p.references(d), Enumeration::Complete(ref refs) if !refs.iter().any(|r| r.token == token) && before.iter().all(|foreign| refs.contains(foreign)))
        );
        let d = limit(p);
        // Exclusive pf accounting is required here: a concurrent pf client may
        // acquire the just-freed number, and this second release would release it.
        assert_eq!(p.release(token, d), ToolOutcome::Ok(Release::TokenInvalid));
        assert_eq!(p.fence(), Fence::Closed);
        let d = limit(p);
        assert!(
            matches!(p.references(d), Enumeration::Complete(ref refs) if refs.len() == before.len() && before.iter().all(|foreign| refs.contains(foreign)))
        );
    }
    run_process_contracts(h)
}

fn run_process_contracts<P: Platform, H: ContractHarness<P>>(h: &mut H) -> Result<(), SysError> {
    let own_path = h.own_executable().to_path_buf();
    let p = h.platform();
    let own = p.incarnation();
    let d = limit(p);
    let own_exe = p.executable_id(&own_path, d)?;
    let d = limit(p);
    assert!(
        matches!(p.processes(d), Enumeration::Complete(ref procs) if procs.iter().any(|proc| proc.pid == own.pid && proc.start == own.start && proc.pgid == own.pgid && proc.state == super::ProcState::Running && proc.path.is_some() && proc.exe == Some(own_exe)) && !procs.iter().any(|proc| proc.pid == 0))
    );
    assert_eq!(p.fence(), Fence::Closed);

    let child = h.scratch_child()?;
    let scratch_path = h.scratch_executable().to_path_buf();
    let p = h.platform();
    let d = limit(p);
    let scratch_exe = p.executable_id(&scratch_path, d)?;
    assert_eq!(child.boot, own.boot);
    assert_eq!(child.pgid, own.pgid);
    assert_eq!(child.exe, Some(scratch_exe));
    assert!(p.spawned_children().contains(&child));
    let d = limit(p);
    let proc = match p.processes(d) {
        Enumeration::Complete(procs) => procs
            .into_iter()
            .find(|proc| proc.pid == child.pid)
            .ok_or(SysError::Failed("spawn record missing from process list"))?,
        Enumeration::Incomplete(error) => return Err(error.error),
    };
    assert_eq!(proc.start, child.start_time);
    assert_eq!(proc.pgid, child.pgid);
    assert_eq!(proc.ppid, own.pid);
    assert_eq!(proc.state, super::ProcState::Running);
    assert_eq!(proc.exe, child.exe);
    assert_eq!(proc.path.as_deref(), Some(scratch_path.as_path()));
    h.unlink_scratch_executable()?;
    let p = h.platform();
    let d = limit(p);
    assert!(p.executable_id(&scratch_path, d).is_err());
    let d = limit(p);
    assert!(
        matches!(p.processes(d), Enumeration::Complete(ref procs) if procs.iter().any(|entry| entry.pid == proc.pid && entry.start == proc.start && entry.state == super::ProcState::Running && entry.exe == Some(scratch_exe) && (entry.path.is_none() || entry.path.as_deref() == Some(scratch_path.as_path()))) && procs.iter().any(|entry| entry.pid == own.pid && entry.start == own.start && entry.exe == Some(own_exe)))
    );
    let mut wrong = proc.start;
    wrong.microseconds = (wrong.microseconds + 1) % 1_000_000;
    let d = limit(p);
    assert_eq!(
        p.kill_process(proc.pid, wrong, d)?,
        KillOutcome::StartChanged
    );
    let d = limit(p);
    assert!(
        matches!(p.processes(d), Enumeration::Complete(ref procs) if procs.iter().any(|entry| entry.pid == proc.pid && entry.start == proc.start && entry.exe == proc.exe && entry.state == super::ProcState::Running))
    );
    let d = limit(p);
    p.kill_process(proc.pid, proc.start, d)?;
    // Qualification bound: a supervised killable child must be absent after
    // at most five sleep-counting seconds, including reaping our own zombies.
    let overall = limit(p);
    loop {
        let d = Deadline(p.now().saturating_add(5).min(overall.0));
        p.reap_children(d)?;
        let d = Deadline(p.now().saturating_add(5).min(overall.0));
        let procs = p.processes(d);
        if matches!(procs, Enumeration::Complete(ref entries) if !entries.iter().any(|entry| entry.pid == proc.pid && entry.start == proc.start))
        {
            break;
        }
        assert!(
            p.now() < overall.0,
            "killed scratch process did not disappear within five seconds: {procs:?}"
        );
        p.pause(std::time::Duration::from_millis(50), overall);
    }
    let d = limit(p);
    assert_eq!(p.reap(d), Fence::Closed);
    assert!(p.spawned_children().contains(&child));
    Ok(())
}

#[cfg(test)]
mod fake_contracts {
    use super::*;
    use crate::{
        platform::{
            Collection, Commit, ConfigKey, ExeId, PfInfo, ProcInfo, ProcState, ProcessError,
            Setting, StartFence, Sweep, Timings,
            fake::{CHILD_PATH, Call, CopyState, FakePlatform, Fault, Mutation},
        },
        snapshot::{self, CopyClass, HelperIncarnation, Snapshot, StartDecision, StartTime},
    };
    use scupper_core::mac::{TunnelGeneration, policy, verify};
    use std::{collections::BTreeSet, path::Path, time::Duration};

    #[test]
    fn abandoned_read_worker_never_holds_write_fence_or_supplies_a_later_result() {
        for delay in [Fault::StorageDelay(60), Fault::WriteHang] {
            let mut p = FakePlatform::new().unwrap();
            p.inject(Call::Install, 1, delay);
            let d = Deadline(p.now() + 1);
            assert!(p.poll_install_record(d).is_pending());
            p.abandon_storage_read();
            p.inject(Call::Read(Copy::B), 1, delay);
            let d = Deadline(p.now() + 1);
            assert!(p.poll_copy(Copy::B, d).is_pending());
            p.abandon_storage_read();
            let bytes = snapshot::encode(1, &Snapshot::initial(Some(501), None)).unwrap();
            let d = Deadline(p.now() + 5);
            assert_eq!(p.create_copy(Copy::A, &bytes, d), WriteOutcome::Synced);
            p.calls.clear();
            let d = Deadline(p.now() + 5);
            assert_eq!(
                p.poll_copy(Copy::B, d),
                std::task::Poll::Ready(CopyRead::Unreadable)
            );
            assert!(matches!(
                p.poll_install_record(d),
                std::task::Poll::Ready(Err(SysError::Failed("storage read busy")))
            ));
            assert!(!p.calls.contains(&Call::Read(Copy::B)));
            assert!(!p.calls.contains(&Call::Install));
            let d = Deadline(p.now() + 5);
            p.pause(Duration::from_secs(4), d);
            let d = Deadline(p.now() + 5);
            if delay == Fault::WriteHang {
                assert_eq!(p.read_copy(Copy::A, d), CopyRead::Unreadable);
            } else {
                // The abandoned install result cannot be supplied as copy bytes.
                assert_eq!(p.read_copy(Copy::A, d), CopyRead::Bytes(bytes.to_vec()));
            }
        }
    }

    fn unrelated_previous(p: &FakePlatform) -> HelperIncarnation {
        HelperIncarnation {
            pid: 90_000,
            pgid: 90_000,
            start: StartTime {
                seconds: 1,
                microseconds: 0,
            },
            boot: p.boot.clone(),
        }
    }
    // Generic sweep deliberately has no startup age restriction. A missing pin
    // therefore also exposes the host's newer pathless orphan; resolve that
    // independent uncertainty before testing specific child-record ownership.
    fn resolve_host_pathless_after_missing_pin(p: &mut FakePlatform) {
        p.procs.get_mut(&14).unwrap().path = None;
        assert!(matches!(
            sweep(p, Path::new(CHILD_PATH)),
            Sweep::Incomplete(ProcessError { pid: Some(14), .. })
        ));
        if let Some(proc) = p.procs.get_mut(&14) {
            proc.path = Some("/usr/bin/foreign-path-now-readable".into());
        }
    }
    fn sweep(p: &mut FakePlatform, path: &Path) -> Sweep {
        let overall = limit(p);
        super::super::sweep(p, path, &[], &Timings::default(), overall)
    }
    fn start_fence(
        p: &mut FakePlatform,
        previous: Option<HelperIncarnation>,
        tools: &[&Path],
    ) -> StartFence {
        let overall = limit(p);
        super::super::start_fence(
            p,
            previous.map_or(
                super::super::PreviousHelper::Unknown,
                super::super::PreviousHelper::Known,
            ),
            tools,
            Path::new(CHILD_PATH),
            &[],
            &Timings::default(),
            overall,
        )
    }
    fn commit(p: &mut FakePlatform, bytes: &[u8; COPY_BYTES]) -> Commit {
        let overall = limit(p);
        super::super::commit(p, bytes, &Timings::default(), overall)
    }
    fn read_copy_with_retry(p: &mut FakePlatform, copy: Copy) -> CopyRead {
        let overall = limit(p);
        super::super::read_copy_with_retry(p, copy, &Timings::default(), overall)
    }

    impl ContractHarness<FakePlatform> for FakePlatform {
        fn platform(&mut self) -> &mut Self {
            self
        }
        fn own_executable(&self) -> &Path {
            Path::new("/opt/scupper/helper")
        }
        fn scratch_executable(&self) -> &Path {
            // All fake paths are synthetic fixture files, never host binaries.
            Path::new(CHILD_PATH)
        }
        fn unlink_scratch_executable(&mut self) -> Result<(), SysError> {
            self.executables.remove(Path::new(CHILD_PATH));
            for proc in self.procs.values_mut() {
                if proc.path.as_deref() == Some(Path::new(CHILD_PATH)) {
                    proc.path = None;
                }
            }
            Ok(())
        }
        fn scratch_process(&mut self) -> Result<ProcInfo, SysError> {
            let child = self.scratch_child()?;
            self.procs
                .get(&child.pid)
                .cloned()
                .ok_or(SysError::Failed("fixture process"))
        }
        fn scratch_child(&mut self) -> Result<super::super::Child, SysError> {
            let d = limit(self);
            self.spawn(
                TunnelGeneration::new(1).map_err(|_| SysError::Failed("fixture generation"))?,
                super::super::SpawnAttributes {
                    default_signals: true,
                    empty_signal_mask: true,
                    cloexec_default: true,
                    synchronous: true,
                },
                d,
            )
        }
    }

    fn fake() -> Result<FakePlatform, SysError> {
        FakePlatform::new()
    }
    fn seeded() -> Result<FakePlatform, SysError> {
        let mut p = fake()?;
        for copy in [Copy::A, Copy::B] {
            let d = limit(&mut p);
            assert_eq!(
                p.create_copy(copy, &[1; COPY_BYTES], d),
                WriteOutcome::Synced
            );
        }
        p.calls.clear();
        Ok(p)
    }
    fn bytes(p: &mut FakePlatform, copy: Copy, expected: &[u8]) {
        let d = limit(p);
        assert_eq!(p.read_copy(copy, d), CopyRead::Bytes(expected.to_vec()));
    }
    #[test]
    fn polling_reap_error_returns_without_sleep_or_retry() -> Result<(), SysError> {
        let mut p = fake()?;
        p.inject(Call::ReapChildren, 1, Fault::ReadFail);
        let overall = limit(&mut p);
        assert!(matches!(
            super::super::poll_start_fence(
                &mut p,
                super::super::PreviousHelper::None,
                &[],
                Path::new(CHILD_PATH),
                &[],
                &Timings::default(),
                overall,
            ),
            StartFence::Processes(Sweep::Incomplete(_))
        ));
        assert!(!p.calls.iter().any(|call| matches!(call, Call::Pause(_))));
        Ok(())
    }

    #[test]
    fn polling_signal_gets_immediate_confirmation_inventory() -> Result<(), SysError> {
        let mut p = fake()?;
        let orphan = proc(202, 49, 202, 1, CHILD_PATH);
        p.procs.insert(orphan.pid, orphan);
        p.calls.clear();
        let overall = limit(&mut p);
        super::super::poll_start_fence(
            &mut p,
            super::super::PreviousHelper::None,
            &[],
            Path::new(CHILD_PATH),
            &[],
            &Timings::default(),
            overall,
        );
        assert_eq!(
            p.calls
                .iter()
                .filter(|call| **call == Call::Processes)
                .count(),
            2
        );
        Ok(())
    }

    #[allow(clippy::similar_names)] // Kernel terminology for process/group/parent identifiers.
    fn proc(pid: u32, seconds: u64, pgid: u32, ppid: u32, path: &str) -> ProcInfo {
        ProcInfo {
            pid,
            start: StartTime {
                seconds,
                microseconds: 0,
            },
            pgid,
            ppid,
            state: ProcState::Running,
            name: Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned()),
            path: Some(path.into()),
            exe: None,
            image: None,
        }
    }
    fn acquire(p: &mut FakePlatform) -> u64 {
        let d = limit(p);
        let acquired = p.acquire(d);
        assert!(matches!(acquired, ToolOutcome::Ok(_)));
        match acquired {
            ToolOutcome::Ok((token, _)) => token,
            _ => 0,
        }
    }
    fn previous(p: &FakePlatform) -> HelperIncarnation {
        HelperIncarnation {
            pid: 200,
            start: StartTime {
                seconds: 50,
                microseconds: 0,
            },
            pgid: 200,
            boot: p.boot.clone(),
        }
    }

    #[test]
    fn shared_adapter_contracts() -> Result<(), SysError> {
        let mut p = fake()?;
        p.mutate(Mutation::ForeignEnable);
        run_contracts(&mut p)
    }

    #[test]
    fn torn_write_keeps_durable_prefix_through_crash() -> Result<(), SysError> {
        for (i, copy) in [Copy::A, Copy::B].into_iter().enumerate() {
            let mut p = seeded()?;
            p.inject(Call::Write(copy), 1, Fault::TornWrite(31));
            let d = limit(&mut p);
            assert!(matches!(
                p.write_copy(copy, &[2; COPY_BYTES], d),
                WriteOutcome::Failed(_)
            ));
            let mut expected = vec![1; COPY_BYTES];
            expected[..31].fill(2);
            assert_eq!(
                p.copies[i]
                    .durable
                    .as_deref()
                    .map(<[u8; COPY_BYTES]>::as_slice),
                Some(expected.as_slice())
            );
            assert!(p.copies[i].pending.is_none());
            bytes(&mut p, copy, &expected);
            p.mutate(Mutation::Reboot);
            bytes(&mut p, copy, &expected);
        }
        Ok(())
    }
    fn unchanged_fault(fault: Fault) -> Result<(), SysError> {
        for (i, copy) in [Copy::A, Copy::B].into_iter().enumerate() {
            let mut p = seeded()?;
            p.inject(Call::Write(copy), 1, fault);
            let d = limit(&mut p);
            assert!(matches!(
                p.write_copy(copy, &[2; COPY_BYTES], d),
                WriteOutcome::Failed(_)
            ));
            assert_eq!(p.copies[i].durable.as_deref(), Some(&[1; COPY_BYTES]));
            assert!(p.copies[i].pending.is_none());
            bytes(&mut p, copy, &[1; COPY_BYTES]);
            p.mutate(Mutation::Reboot);
            bytes(&mut p, copy, &[1; COPY_BYTES]);
            let d = limit(&mut p);
            assert_eq!(
                p.write_copy(copy, &[2; COPY_BYTES], d),
                WriteOutcome::Synced
            );
            p.mutate(Mutation::Reboot);
            bytes(&mut p, copy, &[2; COPY_BYTES]);
        }
        Ok(())
    }
    #[test]
    fn lost_before_sync_is_failed_and_lost() -> Result<(), SysError> {
        unchanged_fault(Fault::LostBeforeSync)
    }
    #[test]
    fn write_fail_preserves_old_durable_bytes() -> Result<(), SysError> {
        unchanged_fault(Fault::WriteFail)
    }
    #[test]
    fn no_space_preserves_old_durable_bytes() -> Result<(), SysError> {
        unchanged_fault(Fault::NoSpace)
    }

    #[test]
    fn write_hang_is_global_busy_until_late_completion() -> Result<(), SysError> {
        for copy in [Copy::A, Copy::B] {
            for durable in [false, true] {
                let mut p = seeded()?;
                let i = usize::from(copy == Copy::B);
                p.inject(Call::Write(copy), 1, Fault::WriteHang);
                let d = limit(&mut p);
                assert_eq!(
                    p.write_copy(copy, &[2; COPY_BYTES], d),
                    WriteOutcome::TimedOut
                );
                assert_eq!(p.now(), d.0);
                assert_eq!(p.copies[i].durable.as_deref(), Some(&[1; COPY_BYTES]));
                assert_eq!(p.copies[i].pending.as_deref(), Some(&[2; COPY_BYTES]));
                bytes(&mut p, copy, &[2; COPY_BYTES]);
                for next in [Copy::A, Copy::B] {
                    let d = limit(&mut p);
                    assert_eq!(p.write_copy(next, &[3; COPY_BYTES], d), WriteOutcome::Busy);
                }
                let other = if copy == Copy::A { Copy::B } else { Copy::A };
                p.complete_late(other, true);
                assert_eq!(p.outstanding, Some(copy));
                p.complete_late(copy, durable);
                assert!(p.outstanding.is_none());
                assert!(p.copies[i].pending.is_none());
                let expected = [if durable { 2 } else { 1 }; COPY_BYTES];
                bytes(&mut p, copy, &expected);
                p.mutate(Mutation::Reboot);
                bytes(&mut p, copy, &expected);
                let d = limit(&mut p);
                assert_eq!(
                    p.write_copy(copy, &[3; COPY_BYTES], d),
                    WriteOutcome::Synced
                );
            }
        }
        Ok(())
    }
    #[test]
    fn reboot_discards_outstanding_write_and_late_completion() -> Result<(), SysError> {
        let mut p = seeded()?;
        p.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
        let d = limit(&mut p);
        assert_eq!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::TimedOut
        );
        p.mutate(Mutation::Reboot);
        assert!(p.outstanding.is_none());
        assert!(p.copies[0].pending.is_none());
        p.complete_late(Copy::A, true);
        bytes(&mut p, Copy::A, &[1; COPY_BYTES]);
        Ok(())
    }
    #[test]
    fn deleting_a_copy_keeps_storage_busy_until_worker_finishes() -> Result<(), SysError> {
        let mut p = seeded()?;
        p.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
        let d = limit(&mut p);
        assert_eq!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::TimedOut
        );
        p.mutate(Mutation::MissingCopy(Copy::A));
        assert_eq!(p.outstanding, Some(Copy::A));
        assert_eq!(p.copies[0], CopyState::default());
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::A, d), CopyRead::Missing);
        let d = limit(&mut p);
        assert_eq!(
            p.write_copy(Copy::B, &[3; COPY_BYTES], d),
            WriteOutcome::Busy
        );
        let d = limit(&mut p);
        assert_eq!(
            p.create_copy(Copy::A, &[3; COPY_BYTES], d),
            WriteOutcome::Busy
        );
        p.complete_late(Copy::A, true);
        assert!(p.outstanding.is_none());
        assert_eq!(p.copies[0], CopyState::default());
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::A, d), CopyRead::Missing);
        p.mutate(Mutation::Reboot);
        assert_eq!(p.copies[0], CopyState::default());
        bytes(&mut p, Copy::B, &[1; COPY_BYTES]);
        let d = limit(&mut p);
        assert_eq!(
            p.create_copy(Copy::A, &[3; COPY_BYTES], d),
            WriteOutcome::Synced
        );
        Ok(())
    }
    #[test]
    fn read_failure_does_not_change_storage() -> Result<(), SysError> {
        let mut p = seeded()?;
        p.inject(Call::Read(Copy::A), 1, Fault::ReadFail);
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::A, d), CopyRead::Unreadable);
        assert_eq!(p.copies[0].durable.as_deref(), Some(&[1; COPY_BYTES]));
        assert!(p.copies[0].pending.is_none());
        bytes(&mut p, Copy::A, &[1; COPY_BYTES]);
        p.mutate(Mutation::Reboot);
        bytes(&mut p, Copy::A, &[1; COPY_BYTES]);
        Ok(())
    }
    #[test]
    fn copy_rot_is_durable_and_missing_stays_missing() -> Result<(), SysError> {
        let mut p = seeded()?;
        p.mutate(Mutation::CopyRot(Copy::A));
        let mut expected = vec![1; COPY_BYTES];
        expected[24] ^= 1;
        assert!(p.copies[0].pending.is_none());
        bytes(&mut p, Copy::A, &expected);
        p.mutate(Mutation::Reboot);
        bytes(&mut p, Copy::A, &expected);
        p.mutate(Mutation::MissingCopy(Copy::A));
        assert_eq!(p.copies[0], CopyState::default());
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::A, d), CopyRead::Missing);
        p.mutate(Mutation::Reboot);
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::A, d), CopyRead::Missing);
        Ok(())
    }
    #[test]
    fn exclusive_create_faults_and_missing_write() -> Result<(), SysError> {
        for fault in [Fault::NoSpace, Fault::WriteFail, Fault::LostBeforeSync] {
            let mut p = fake()?;
            p.inject(Call::Create(Copy::A), 1, fault);
            let d = limit(&mut p);
            assert!(matches!(
                p.create_copy(Copy::A, &[2; COPY_BYTES], d),
                WriteOutcome::Failed(_)
            ));
            p.mutate(Mutation::Reboot);
            assert_eq!(p.copies[0], CopyState::default());
            let d = limit(&mut p);
            assert_eq!(p.read_copy(Copy::A, d), CopyRead::Missing);
        }
        let mut p = fake()?;
        let d = limit(&mut p);
        assert!(matches!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::Failed(_)
        ));
        p.inject(Call::Create(Copy::A), 1, Fault::WriteHang);
        let d = limit(&mut p);
        assert_eq!(
            p.create_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::TimedOut
        );
        let d = limit(&mut p);
        assert_eq!(
            p.create_copy(Copy::B, &[2; COPY_BYTES], d),
            WriteOutcome::Busy
        );
        p.mutate(Mutation::Reboot);
        assert_eq!(p.copies[0], CopyState::default());
        Ok(())
    }
    #[test]
    fn copy_rot_selects_valid_b_and_repairs_a() -> Result<(), Box<dyn std::error::Error>> {
        let mut p = seeded()?;
        let encoded = snapshot::encode(1, &Snapshot::initial(Some(501), None))?;
        assert_eq!(commit(&mut p, &encoded), Commit::Committed);
        p.mutate(Mutation::CopyRot(Copy::A));
        let d = limit(&mut p);
        let a = snapshot::classify_copy(p.read_copy(Copy::A, d));
        let d = limit(&mut p);
        let b = snapshot::classify_copy(p.read_copy(Copy::B, d));
        assert_eq!(a, CopyClass::T);
        assert!(matches!(
            snapshot::decide(a, b),
            StartDecision::Trust {
                source: Copy::B,
                repair: Some(Copy::A),
                seq: 1,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn pid_reuse_during_sweep_signals_only_after_reobserving_replacement() -> Result<(), SysError> {
        let mut p = fake()?;
        let target = proc(200, 50, 200, 77, CHILD_PATH);
        p.procs.insert(200, target.clone());
        p.inject(
            Call::KillProcess(200, target.start),
            1,
            Fault::PidReused(200),
        );
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.signals.len(), 1);
        assert_eq!(p.signals[0].0, 200);
        assert_ne!(p.signals[0].1, target.start);
        Ok(())
    }
    #[test]
    fn kill_guard_checks_group_and_missing_pid_too() -> Result<(), SysError> {
        let mut p = fake()?;
        let target = proc(200, 50, 200, 77, CHILD_PATH);
        p.procs.insert(200, target.clone());
        let d = limit(&mut p);
        assert_eq!(
            p.kill_group(201, 200, target.start, d)?,
            KillOutcome::StartChanged
        );
        let d = limit(&mut p);
        assert_eq!(p.kill_group(200, 201, target.start, d)?, KillOutcome::Gone);
        assert_eq!(p.signals, []);
        p.unkillable.insert(200);
        assert!(matches!(
            sweep(&mut p, Path::new(CHILD_PATH)),
            Sweep::Survivors(_) | Sweep::Incomplete(_)
        ));
        p.unkillable.clear();
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        Ok(())
    }
    #[test]
    fn unreaped_tool_blocks_fences_across_sweep() -> Result<(), SysError> {
        let mut p = fake()?;
        p.inject(
            Call::Acquire,
            1,
            Fault::ToolHang {
                reaped: false,
                effect: true,
            },
        );
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        assert_eq!(p.now(), d.0);
        assert_eq!(p.tokens.len(), 1);
        let fence = p.fence();
        assert!(matches!(fence, Fence::Open(ref children) if children.len() == 1));
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.fence(), fence);
        let d = limit(&mut p);
        assert_eq!(p.reap(d), fence);
        assert_eq!(p.now(), d.0);
        assert!(matches!(
            start_fence(&mut p, None, &[Path::new("/sbin/pfctl")]),
            StartFence::Processes(_) | StartFence::Tools(_)
        ));
        p.release_unreaped();
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        Ok(())
    }
    #[test]
    fn incomplete_enumerations_never_confirm_sweep_or_start() -> Result<(), SysError> {
        for startup in [false, true] {
            let mut p = fake()?;
            for _ in 0..100 {
                p.inject(Call::Processes, 1, Fault::Incomplete);
            }
            if startup {
                assert!(matches!(
                    start_fence(&mut p, None, &[]),
                    StartFence::Processes(Sweep::Incomplete(_))
                ));
            } else {
                assert!(matches!(
                    sweep(&mut p, Path::new(CHILD_PATH)),
                    Sweep::Incomplete(_)
                ));
            }
            assert_eq!(p.signals, []);
        }
        let mut p = fake()?;
        let token = acquire(&mut p);
        p.inject(Call::References, 1, Fault::Incomplete);
        let d = limit(&mut p);
        assert!(matches!(p.references(d), Enumeration::Incomplete(_)));
        let d = limit(&mut p);
        assert!(
            matches!(p.references(d), Enumeration::Complete(ref refs) if refs[0].token == token)
        );
        p.inject(Call::PfInfo, 1, Fault::Incomplete);
        let d = limit(&mut p);
        assert!(matches!(p.pf_info(d), PfInfo::Incomplete(_)));
        let d = limit(&mut p);
        assert_eq!(p.pf_info(d), PfInfo::Enabled);
        Ok(())
    }
    #[test]
    fn foreign_mutations_visible_and_pf_disable_invalidates_all_tokens() -> Result<(), SysError> {
        let mut p = fake()?;
        let ours = acquire(&mut p);
        p.mutate(Mutation::ForeignEnable);
        let foreign = p.tokens.values().find(|r| r.pid == 77).map(|r| r.token);
        assert!(foreign.is_some());
        let d = limit(&mut p);
        assert!(matches!(p.references(d), Enumeration::Complete(ref refs) if refs.len() == 2));
        p.mutate(Mutation::ForeignRelease(ours));
        let d = limit(&mut p);
        assert!(
            matches!(p.references(d), Enumeration::Complete(ref refs) if refs.len() == 1 && Some(refs[0].token) == foreign)
        );
        acquire(&mut p);
        p.x_qualified = false;
        p.mutate(Mutation::PfDisable);
        let d = limit(&mut p);
        assert_eq!(p.pf_info(d), PfInfo::Disabled);
        let d = limit(&mut p);
        assert_eq!(p.references(d), Enumeration::Complete(Vec::new()));
        let d = limit(&mut p);
        assert_eq!(p.release(ours, d), ToolOutcome::Ok(Release::TokenInvalid));
        Ok(())
    }
    #[test]
    fn tool_outcomes_distinguish_no_ioctl_failure_and_timeout() -> Result<(), SysError> {
        let mut p = fake()?;
        for (fault, expected) in [
            (
                Fault::NotStarted,
                ToolOutcome::NotStarted(SysError::Failed("exec failed")),
            ),
            (
                Fault::ToolFail { effect: false },
                ToolOutcome::Failed(SysError::Failed("tool failure")),
            ),
            (
                Fault::ToolHang {
                    reaped: true,
                    effect: false,
                },
                ToolOutcome::Unknown { reaped: true },
            ),
        ] {
            p.inject(Call::Acquire, 1, fault);
            let d = limit(&mut p);
            assert_eq!(p.acquire(d), expected);
            assert!(p.tokens.is_empty());
            assert_eq!(p.fence(), Fence::Closed);
        }
        let token = acquire(&mut p);
        p.inject(Call::Release(token), 1, Fault::NotStarted);
        let d = limit(&mut p);
        assert!(matches!(p.release(token, d), ToolOutcome::NotStarted(_)));
        assert!(p.tokens.contains_key(&token));
        p.inject(
            Call::Release(token),
            1,
            Fault::ToolHang {
                reaped: true,
                effect: true,
            },
        );
        let d = limit(&mut p);
        assert_eq!(p.release(token, d), ToolOutcome::Unknown { reaped: true });
        assert!(!p.tokens.contains_key(&token));
        assert!(!p.enabled);
        Ok(())
    }
    #[test]
    fn boot_unavailable_is_none_and_reboot_preserves_only_durable_copies() -> Result<(), SysError> {
        let mut p = seeded()?;
        let old_boot = p.boot_id();
        assert!(old_boot.is_some());
        p.mutate(Mutation::BootIdUnavailable);
        assert_eq!(p.boot_id(), None);
        acquire(&mut p);
        p.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
        let d = limit(&mut p);
        assert_eq!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::TimedOut
        );
        p.mutate(Mutation::Reboot);
        assert!(p.boot_id().is_some());
        assert_ne!(p.boot_id(), old_boot);
        assert!(!p.enabled);
        assert!(p.tokens.is_empty());
        assert_eq!(p.procs.len(), 1);
        assert!(p.procs.contains_key(&p.helper.pid));
        assert_eq!(p.incarnation().boot, p.boot_id());
        assert!(p.outstanding.is_none());
        assert!(p.copies[0].pending.is_none());
        bytes(&mut p, Copy::A, &[1; COPY_BYTES]);
        bytes(&mut p, Copy::B, &[1; COPY_BYTES]);
        Ok(())
    }

    #[test]
    fn commit_orders_a_before_b_and_stops_at_first_failure() -> Result<(), SysError> {
        let mut p = seeded()?;
        assert_eq!(commit(&mut p, &[2; COPY_BYTES]), Commit::Committed);
        assert_eq!(
            p.calls
                .iter()
                .filter(|c| matches!(c, Call::Write(_)))
                .copied()
                .collect::<Vec<_>>(),
            vec![Call::Write(Copy::A), Call::Write(Copy::B)]
        );
        for (copy, after_a) in [(Copy::A, false), (Copy::B, true)] {
            for fault in [Fault::WriteFail, Fault::WriteHang] {
                let mut p = seeded()?;
                p.inject(Call::Write(copy), 1, fault);
                assert_eq!(commit(&mut p, &[2; COPY_BYTES]), Commit::Failed { after_a });
                let writes: Vec<_> = p
                    .calls
                    .iter()
                    .filter(|c| matches!(c, Call::Write(_)))
                    .copied()
                    .collect();
                assert_eq!(
                    writes,
                    if after_a {
                        vec![Call::Write(Copy::A), Call::Write(Copy::B)]
                    } else {
                        vec![Call::Write(Copy::A)]
                    }
                );
                p.mutate(Mutation::Reboot);
                bytes(&mut p, Copy::A, &[if after_a { 2 } else { 1 }; COPY_BYTES]);
                bytes(&mut p, Copy::B, &[1; COPY_BYTES]);
            }
        }
        Ok(())
    }
    #[test]
    fn copy_retry_returns_u_after_three_or_v_on_third_attempt()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoded = snapshot::encode(1, &Snapshot::initial(None, None))?;
        for failures in [2, 3] {
            let mut p = seeded()?;
            assert_eq!(commit(&mut p, &encoded), Commit::Committed);
            p.calls.clear();
            for _ in 0..failures {
                p.inject(Call::Read(Copy::A), 1, Fault::ReadFail);
            }
            let classified = snapshot::classify_copy(read_copy_with_retry(&mut p, Copy::A));
            assert!(if failures == 3 {
                classified == CopyClass::U
            } else {
                matches!(classified, CopyClass::V { seq: 1, .. })
            });
            assert_eq!(
                p.calls
                    .iter()
                    .filter(|c| **c == Call::Read(Copy::A))
                    .count(),
                3
            );
            assert_eq!(
                p.calls
                    .iter()
                    .filter(|c| **c == Call::Pause(Duration::from_millis(100)))
                    .count(),
                2
            );
        }
        let mut p = fake()?;
        assert_eq!(read_copy_with_retry(&mut p, Copy::A), CopyRead::Missing);
        assert!(!p.calls.iter().any(|c| matches!(c, Call::Pause(_))));
        Ok(())
    }
    #[test]
    fn start_fence_targets_previous_group_and_only_old_orphaned_pinned_tools()
    -> Result<(), SysError> {
        let mut p = fake()?;
        let prev = previous(&p);
        let candidates = [
            proc(200, 50, 200, 1, "/old/helper"),
            proc(201, 60, 200, 200, "/sbin/route"),
            proc(202, 49, 202, 1, "/sbin/pfctl"),
            proc(203, 70, 203, 1, CHILD_PATH),
            proc(204, 70, 204, 88, "/sbin/pfctl"), // live parent: keep
            proc(205, 101, 205, 1, "/sbin/pfctl"), // newer: keep
            proc(206, 49, 200, 88, "/foreign"),    // older than previous: keep
            proc(207, 70, 207, 1, "/foreign"),     // unpinned: keep
            proc(208, 100, 208, 1, "/sbin/pfctl"), // equal start: keep
        ];
        for candidate in candidates {
            p.procs.insert(candidate.pid, candidate);
        }
        let paths = [
            Path::new("/sbin/pfctl"),
            Path::new("/sbin/route"),
            Path::new(CHILD_PATH),
        ];
        // The older group member shares a targeted group: signalling the group
        // can kill it too. Test the membership threshold separately below.
        if let Some(proc) = p.procs.get_mut(&206) {
            proc.pgid = 206;
        }
        assert_eq!(start_fence(&mut p, Some(prev), &paths), StartFence::Closed);
        p.tick();
        assert_eq!(
            p.procs.keys().copied().collect::<Vec<_>>(),
            vec![1, 10, 11, 12, 13, 14, 100, 204, 205, 206, 207, 208]
        );
        assert!(
            !p.signals
                .iter()
                .any(|(pid, _)| [100, 204, 205, 206, 207, 208].contains(pid))
        );
        assert_eq!(start_fence(&mut p, None, &paths), StartFence::Closed);
        Ok(())
    }
    #[test]
    fn start_fence_preserves_self_and_older_group_members_and_other_boot() -> Result<(), SysError> {
        let mut p = fake()?;
        let mut prev = previous(&p);
        p.procs.insert(210, proc(210, 49, 200, 88, "/foreign"));
        assert_eq!(
            start_fence(&mut p, Some(prev.clone()), &[]),
            StartFence::Closed
        );
        assert!(p.procs.contains_key(&210));
        assert_eq!(p.signals, []);
        // A corrupt/overlapping recorded identity must never directly target self.
        prev.pgid = p.helper.pgid;
        prev.start = p.helper.start;
        assert_eq!(start_fence(&mut p, Some(prev), &[]), StartFence::Closed);
        assert!(p.procs.contains_key(&p.helper.pid));
        let mut prev = previous(&p);
        prev.boot = None;
        p.procs.insert(211, proc(211, 70, 200, 88, "/foreign"));
        let mut old_boot = previous(&p);
        old_boot.boot = "00000000-0000-0000-0000-000000000099".try_into().ok();
        assert_eq!(start_fence(&mut p, Some(old_boot), &[]), StartFence::Closed);
        assert_eq!(p.procs[&211].state, ProcState::Running);
        assert!(!p.signals.iter().any(|(pid, _)| *pid == 211));
        assert_eq!(start_fence(&mut p, Some(prev), &[]), StartFence::Closed);
        p.tick();
        assert!(
            p.procs
                .get(&211)
                .is_none_or(|proc| proc.state == ProcState::Zombie)
        );
        Ok(())
    }
    #[test]
    fn expired_deadlines_never_claim_completion() -> Result<(), SysError> {
        let mut p = seeded()?;
        let d = Deadline(p.now());
        assert_eq!(p.acquire(d), ToolOutcome::NotStarted(SysError::TimedOut));
        assert_eq!(p.read_copy(Copy::A, d), CopyRead::Unreadable);
        assert_eq!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::NotStarted(SysError::TimedOut)
        );
        assert!(matches!(p.processes(d), Enumeration::Incomplete(_)));
        assert!(matches!(p.references(d), Enumeration::Incomplete(_)));
        assert!(matches!(p.pf_info(d), PfInfo::Incomplete(_)));
        assert_eq!(p.cleanup_dns(d), Err(SysError::TimedOut));
        bytes(&mut p, Copy::A, &[1; COPY_BYTES]);
        Ok(())
    }
    #[test]
    fn start_fence_never_signals_a_group_containing_self() -> Result<(), SysError> {
        let mut p = fake()?;
        p.procs
            .insert(212, proc(212, 70, p.helper.pgid, 1, "/sbin/pfctl"));
        assert_eq!(
            start_fence(&mut p, None, &[Path::new("/sbin/pfctl")]),
            StartFence::Closed
        );
        assert_eq!(p.signals.len(), 1);
        assert!(
            p.calls
                .iter()
                .any(|call| matches!(call, Call::KillProcess(212, _)))
        );
        assert!(p.procs.contains_key(&p.helper.pid));
        p.tick();
        assert!(!p.procs.contains_key(&212));
        Ok(())
    }
    #[test]
    fn carried_mutating_tools_honour_timeout_and_reap_contract() -> Result<(), SysError> {
        for reaped in [false, true] {
            for effect in [false, true] {
                let mut p = fake()?;
                let text = policy::render_pre_tunnel(&p.install.config.inputs);
                p.inject(Call::LoadAnchor, 1, Fault::ToolHang { reaped, effect });
                let d = limit(&mut p);
                assert_eq!(
                    p.load_anchor(&text, d),
                    Err(if reaped {
                        SysError::TimedOut
                    } else {
                        SysError::Unknown
                    })
                );
                assert_eq!(p.now(), d.0);
                assert_eq!(p.anchor.is_some(), effect);
                assert_eq!(p.fence() == Fence::Closed, reaped);
                p.release_unreaped();
                assert_eq!(p.fence() == Fence::Closed, reaped);
                let d = limit(&mut p);
                assert_eq!(p.reap(d), Fence::Closed);
            }
        }
        // Tool-family membership includes all four mutating utility families.
        for (key, setting, family) in [
            (
                ConfigKey::Mtu,
                Setting::Mtu(1400),
                super::super::Tool::Ifconfig,
            ),
            (
                ConfigKey::Dns,
                Setting::Dns(Vec::new()),
                super::super::Tool::Scutil,
            ),
            (
                ConfigKey::SplitRoutes,
                Setting::SplitRoutes(Vec::new()),
                super::super::Tool::Route,
            ),
        ] {
            let mut p = fake()?;
            p.inject(
                Call::Configure(key),
                1,
                Fault::ToolHang {
                    reaped: false,
                    effect: true,
                },
            );
            let d = limit(&mut p);
            assert_eq!(p.configure(key, &setting, d), Err(SysError::Unknown));
            assert!(
                matches!(p.fence(), Fence::Open(ref tools) if tools.len() == 1 && tools[0].tool == family)
            );
            let d = limit(&mut p);
            assert_eq!(p.read_config(key, d)?, Some(setting));
        }
        Ok(())
    }
    #[test]
    fn route_cleanup_uses_explicit_endpoint_and_preserves_other_route()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut p = fake()?;
        let setting = Setting::Route {
            destination: "203.0.113.8".parse()?,
            interface: "en0".into(),
            gateway: None,
        };
        p.settings.insert(ConfigKey::EndpointRoute, setting.clone());
        let d = limit(&mut p);
        p.cleanup_routes("198.51.100.7:51820".parse()?, d)?;
        assert_eq!(p.settings.get(&ConfigKey::EndpointRoute), Some(&setting));
        let d = limit(&mut p);
        p.cleanup_routes("203.0.113.8:51820".parse()?, d)?;
        assert!(!p.settings.contains_key(&ConfigKey::EndpointRoute));
        Ok(())
    }
    #[test]
    fn carried_effects_have_independent_readbacks_and_idempotent_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut p = seeded()?;
        let config = p.install.config.clone();
        let text = policy::render_pre_tunnel(&config.inputs);
        let d = limit(&mut p);
        p.load_anchor(&text, d)?;
        let d = limit(&mut p);
        assert_eq!(p.read_anchor(d)?, Some(text.as_str().into()));
        p.states.push(true);
        p.interface_states.insert("en0".parse()?, vec![true]);
        let d = limit(&mut p);
        p.remove_interface_states(&BTreeSet::from(["en0".parse()?]), d)?;
        assert!(p.interface_states.is_empty());
        assert_eq!(p.states, vec![true]);
        let d = limit(&mut p);
        p.flush_states(d)?;
        assert_eq!(p.states, [] as [bool; 0]);
        let d = limit(&mut p);
        p.check_tools(d)?;
        let d = limit(&mut p);
        let child = p.spawn(
            TunnelGeneration::new(1)?,
            super::super::SpawnAttributes {
                default_signals: true,
                empty_signal_mask: true,
                cloexec_default: true,
                synchronous: true,
            },
            d,
        )?;
        let d = limit(&mut p);
        assert_eq!(p.identity(&child, d)?.generation.value(), 1);
        let settings = [
            (ConfigKey::Uapi, Setting::Uapi(1)),
            (
                ConfigKey::Addresses,
                Setting::Addresses(config.addresses.clone()),
            ),
            (ConfigKey::Mtu, Setting::Mtu(config.mtu)),
            (
                ConfigKey::EndpointRoute,
                Setting::Route {
                    destination: "198.51.100.7".parse()?,
                    interface: "en0".into(),
                    gateway: None,
                },
            ),
            (
                ConfigKey::SplitRoutes,
                Setting::SplitRoutes(vec!["0.0.0.0".parse()?]),
            ),
            (ConfigKey::Dns, Setting::Dns(config.dns.clone())),
        ];
        for (key, value) in settings {
            let d = limit(&mut p);
            p.configure(key, &value, d)?;
            let d = limit(&mut p);
            assert_eq!(p.read_config(key, d)?, Some(value));
        }
        let d = limit(&mut p);
        let cheap = p.cheap_check(Some(&child), d)?;
        assert!(cheap.child_alive && cheap.route_present && cheap.anchor_present);
        let collection = Collection {
            context: verify::Context::default(),
            inputs: config.inputs,
            states: verify::StateEvidence::Unproven,
            child: Some(child),
        };
        let d = limit(&mut p);
        let observed = p.collect(&collection, d)?;
        assert!(observed.anchor.is_ok());
        assert!(matches!(
            observed.identity,
            verify::IdentityEvidence::CurrentGeneration(_)
        ));
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        p.artifacts.insert("socket".into());
        for _ in 0..2 {
            let d = limit(&mut p);
            p.cleanup_routes("198.51.100.7:51820".parse()?, d)?;
            let d = limit(&mut p);
            p.cleanup_dns(d)?;
            let d = limit(&mut p);
            p.cleanup_artifacts(d)?;
            let d = limit(&mut p);
            p.remove_anchor(d)?;
        }
        assert!(!p.settings.contains_key(&ConfigKey::EndpointRoute));
        assert!(!p.settings.contains_key(&ConfigKey::SplitRoutes));
        assert!(!p.settings.contains_key(&ConfigKey::Dns));
        assert!(p.anchor.is_none());
        assert!(p.artifacts.is_empty());
        assert_eq!(p.fence(), Fence::Closed);
        Ok(())
    }
    #[test]
    fn processes_distinguish_esrch_pid_zero_zombies_and_unreadable_foreign_paths()
    -> Result<(), SysError> {
        let mut p = fake()?;
        let mut kernel = proc(0, 1, 0, 0, "/kernel");
        kernel.path = None;
        p.procs.insert(0, kernel);
        let mut zombie = proc(200, 50, 200, 1, "/exited");
        zombie.state = ProcState::Zombie;
        zombie.path = None;
        p.procs.insert(200, zombie.clone());
        let d = limit(&mut p);
        assert!(
            matches!(p.processes(d), Enumeration::Complete(ref entries) if !entries.iter().any(|entry| entry.pid == 0) && entries.contains(&zombie))
        );
        let mut foreign = proc(201, 50, 201, 77, "/foreign");
        foreign.path = None;
        foreign.exe = Some(ExeId { dev: 9, ino: 201 });
        foreign.image = Some(super::super::ImageId {
            uuid: [9; 16],
            uniqueid: 201,
        });
        p.procs.insert(201, foreign);
        assert!(matches!(
            sweep(&mut p, Path::new(CHILD_PATH)),
            Sweep::Incomplete(ProcessError { pid: Some(201), .. })
        ));
        let history =
            snapshot::ImageHistory::empty_for_boot(p.boot.clone().ok_or(SysError::Unknown)?);
        let overall = limit(&mut p);
        assert_eq!(
            super::super::sweep_with_history(
                &mut p,
                Path::new(CHILD_PATH),
                &[],
                &history,
                &[],
                &Timings::default(),
                overall
            ),
            Sweep::Swept
        );
        let d = limit(&mut p);
        assert!(matches!(p.processes(d), Enumeration::Complete(ref entries)
            if entries.iter().any(|entry| entry.pid == 201 && entry.path.is_none() && entry.exe.is_some())));
        if let Some(entry) = p.procs.get_mut(&201) {
            entry.exe = None;
            entry.image = None;
        }
        let d = limit(&mut p);
        assert!(matches!(
            p.processes(d),
            Enumeration::Incomplete(ProcessError { pid: Some(201), .. })
        ));
        assert!(matches!(
            sweep(&mut p, Path::new(CHILD_PATH)),
            Sweep::Incomplete(ProcessError { pid: Some(201), .. })
        ));
        p.inject(Call::Processes, 1, Fault::ExitRace(201));
        let d = limit(&mut p);
        assert!(
            matches!(p.processes(d), Enumeration::Complete(ref entries) if !entries.iter().any(|entry| entry.pid == 201))
        );
        Ok(())
    }

    #[test]
    fn sweep_waits_for_async_kill_and_reaps_own_zombie() -> Result<(), SysError> {
        let mut p = fake()?;
        let target = p.scratch_process()?;
        p.inject(
            Call::KillProcess(target.pid, target.start),
            1,
            Fault::KillDelay(3),
        );
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert!(!p.procs.contains_key(&target.pid));
        assert_eq!(
            p.calls
                .iter()
                .filter(|call| **call == Call::Pause(Duration::from_millis(50)))
                .count(),
            3
        );
        assert!(
            p.calls
                .iter()
                .filter(|call| **call == Call::ReapChildren)
                .count()
                >= 4
        );
        Ok(())
    }

    #[test]
    fn killed_process_is_zombie_until_its_parent_reaps() -> Result<(), SysError> {
        let mut p = fake()?;
        let target = p.scratch_process()?;
        let d = limit(&mut p);
        assert_eq!(
            p.kill_process(target.pid, target.start, d)?,
            KillOutcome::Signalled
        );
        assert_eq!(p.procs[&target.pid].state, ProcState::Running);
        p.tick();
        assert_eq!(p.procs[&target.pid].state, ProcState::Zombie);
        p.tick();
        assert!(p.procs.contains_key(&target.pid));
        let d = limit(&mut p);
        p.reap_children(d)?;
        assert!(!p.procs.contains_key(&target.pid));
        let foreign = proc(200, 50, 200, 77, CHILD_PATH);
        p.procs.insert(200, foreign);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.procs[&200].state, ProcState::Zombie);
        // Only launchd orphans are auto-reaped by a tick.
        if let Some(entry) = p.procs.get_mut(&200) {
            entry.ppid = 1;
        }
        p.crash();
        p.tick();
        assert!(!p.procs.contains_key(&200));
        Ok(())
    }

    #[test]
    fn sweep_survivors_name_process_and_obey_overall_budget() -> Result<(), SysError> {
        let mut p = fake()?;
        let target = p.scratch_process()?;
        p.unkillable.insert(target.pid);
        let overall = Deadline(p.now() + 1);
        let result = super::super::sweep(
            &mut p,
            Path::new(CHILD_PATH),
            &[],
            &Timings::default(),
            overall,
        );
        assert_eq!(result, Sweep::Survivors(vec![target.clone()]));
        assert!(format!("{result:?}").contains(CHILD_PATH));
        assert!(format!("{result:?}").contains(&target.pid.to_string()));
        assert_eq!(p.now(), overall.0);
        Ok(())
    }

    #[test]
    fn helper_death_restart_orphans_children_and_preserves_page_cache() -> Result<(), SysError> {
        let mut p = seeded()?;
        let old = p.incarnation();
        let child = p.scratch_process()?;
        acquire(&mut p);
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: None });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        let tool_pid = p.unreaped[0].pid;
        p.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
        let d = limit(&mut p);
        assert_eq!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::TimedOut
        );
        p.crash();
        assert!(!p.procs.contains_key(&old.pid));
        assert_eq!(p.procs[&child.pid].ppid, 1);
        assert_eq!(p.procs[&tool_pid].ppid, 1);
        assert_eq!(p.fence(), Fence::Closed);
        assert!(p.children.is_empty());
        assert!(p.outstanding.is_none());
        bytes(&mut p, Copy::A, &[2; COPY_BYTES]);
        assert_eq!(p.copies[0].durable.as_deref(), Some(&[1; COPY_BYTES]));
        p.restart();
        let own = p.incarnation();
        assert_ne!(own.pid, old.pid);
        assert_ne!(own.start, old.start);
        assert_ne!(own.pgid, old.pgid);
        assert_eq!(own.boot, old.boot);
        assert_eq!(own.boot, p.boot_id());
        assert!(p.procs.contains_key(&own.pid));
        assert_eq!(p.tokens.len(), 1);
        p.writeback(Copy::A);
        assert_eq!(p.copies[0].durable.as_deref(), Some(&[2; COPY_BYTES]));
        p.orphan_finish(tool_pid, false);
        assert_eq!(
            start_fence(&mut p, Some(old), &[Path::new("/sbin/pfctl")]),
            StartFence::Closed
        );
        p.tick();
        assert!(!p.procs.contains_key(&child.pid));
        assert!(!p.procs.contains_key(&tool_pid));
        assert_eq!(p.tokens.len(), 1); // killed deferred tool cannot act later
        Ok(())
    }

    #[test]
    fn launchd_group_cleanup_is_default_and_reboot_installs_fresh_helper() -> Result<(), SysError> {
        let mut p = seeded()?;
        let old = p.incarnation();
        let child = p.scratch_process()?;
        p.procs
            .insert(200, proc(200, 101, old.pgid, old.pid, "/foreign"));
        p.procs
            .insert(201, proc(201, 101, old.pgid, old.pid, "/stuck"));
        p.unkillable.insert(201);
        p.crash();
        assert_eq!(p.procs[&child.pid].state, ProcState::Zombie);
        assert_eq!(p.procs[&child.pid].pgid, old.pgid);
        assert_eq!(p.procs[&child.pid].ppid, 1);
        assert_eq!(p.procs[&200].state, ProcState::Zombie);
        assert_eq!(p.procs[&201].state, ProcState::Running);
        p.tick();
        assert!(!p.procs.contains_key(&child.pid));
        assert!(!p.procs.contains_key(&200));
        assert_eq!(p.procs[&201].state, ProcState::Running);
        p.restart();
        acquire(&mut p);
        p.inject(Call::Write(Copy::A), 1, Fault::FailedPending);
        let d = limit(&mut p);
        assert!(matches!(
            p.write_copy(Copy::A, &[2; COPY_BYTES], d),
            WriteOutcome::Failed(_)
        ));
        p.mutate(Mutation::Reboot);
        let own = p.incarnation();
        assert_ne!(own.boot, old.boot);
        assert_ne!(own.pid, old.pid);
        assert_ne!(own.start, old.start);
        assert_eq!(own.boot, p.boot_id());
        assert_eq!(p.procs.len(), 1);
        assert_eq!(p.procs[&own.pid].start, own.start);
        assert_eq!(p.fence(), Fence::Closed);
        assert!(p.tokens.is_empty());
        assert!(!p.enabled);
        assert!(p.copies[0].pending.is_none());
        bytes(&mut p, Copy::A, &[1; COPY_BYTES]);
        Ok(())
    }

    #[test]
    fn late_effect_requires_reap_and_never_occurs_after_reap() -> Result<(), SysError> {
        for ticks in [None, Some(2)] {
            let mut p = fake()?;
            p.inject(Call::Acquire, 1, Fault::ToolLate { ticks });
            let d = limit(&mut p);
            assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
            assert!(p.tokens.is_empty());
            let fence = p.fence();
            p.release_unreaped();
            assert_eq!(p.fence(), fence);
            assert!(p.tokens.is_empty());
            let d = limit(&mut p);
            assert_eq!(p.reap(d), Fence::Closed);
            assert_eq!(p.tokens.len(), 1);
            for _ in 0..4 {
                p.tick();
            }
            assert_eq!(p.tokens.len(), 1);
            assert_eq!(p.fence(), Fence::Closed);
        }
        let mut p = fake()?;
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: Some(2) });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        p.tick();
        assert!(p.tokens.is_empty());
        p.tick();
        assert_eq!(p.tokens.len(), 1);
        assert!(matches!(p.fence(), Fence::Open(_)));
        p.release_unreaped();
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert_eq!(p.tokens.len(), 1);
        Ok(())
    }

    #[test]
    fn late_release_and_anchor_effects_apply_only_when_reaped() -> Result<(), SysError> {
        let mut p = fake()?;
        let token = acquire(&mut p);
        p.inject(Call::Release(token), 1, Fault::ToolLate { ticks: None });
        let d = limit(&mut p);
        assert_eq!(p.release(token, d), ToolOutcome::Unknown { reaped: false });
        assert!(p.tokens.contains_key(&token));
        p.release_unreaped();
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert!(!p.tokens.contains_key(&token));
        let text = policy::render_pre_tunnel(&p.install.config.inputs);
        p.inject(Call::LoadAnchor, 1, Fault::ToolLate { ticks: None });
        let d = limit(&mut p);
        assert_eq!(p.load_anchor(&text, d), Err(SysError::Unknown));
        assert!(p.anchor.is_none());
        p.release_unreaped();
        assert!(p.anchor.is_none());
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert_eq!(p.anchor.as_deref(), Some(text.as_str()));
        Ok(())
    }

    #[test]
    fn failed_writes_can_be_durable_or_pending_after_restart() -> Result<(), SysError> {
        for fault in [Fault::FailedDurable, Fault::FailedPending] {
            let mut p = seeded()?;
            p.inject(Call::Write(Copy::A), 1, fault);
            assert_eq!(
                commit(&mut p, &[2; COPY_BYTES]),
                Commit::Failed { after_a: false }
            );
            assert!(p.outstanding.is_none());
            p.crash();
            p.restart();
            bytes(&mut p, Copy::A, &[2; COPY_BYTES]);
            bytes(&mut p, Copy::B, &[1; COPY_BYTES]);
            if fault == Fault::FailedPending {
                assert_eq!(p.copies[0].durable.as_deref(), Some(&[1; COPY_BYTES]));
                p.writeback(Copy::A);
            }
            p.mutate(Mutation::Reboot);
            bytes(&mut p, Copy::A, &[2; COPY_BYTES]);
        }
        Ok(())
    }

    #[test]
    fn failed_tools_can_acquire_and_release_without_touching_foreign_reference()
    -> Result<(), SysError> {
        let mut p = fake()?;
        p.mutate(Mutation::ForeignEnable);
        let foreign = p.tokens.clone();
        p.inject(Call::Acquire, 1, Fault::ToolFail { effect: true });
        let d = limit(&mut p);
        assert!(matches!(p.acquire(d), ToolOutcome::Failed(_)));
        assert_eq!(p.fence(), Fence::Closed);
        assert_eq!(p.tokens.len(), 2);
        let token = p
            .tokens
            .keys()
            .find(|token| !foreign.contains_key(token))
            .copied()
            .ok_or(SysError::Failed("missing applied acquire"))?;
        p.inject(Call::Release(token), 1, Fault::ToolFail { effect: true });
        let d = limit(&mut p);
        assert!(matches!(p.release(token, d), ToolOutcome::Failed(_)));
        assert_eq!(p.tokens, foreign);
        assert_eq!(p.fence(), Fence::Closed);
        Ok(())
    }

    #[test]
    fn spawn_timeout_can_leave_child_and_double_spawn_records_violation() -> Result<(), SysError> {
        for child in [false, true] {
            let mut p = fake()?;
            p.inject(Call::Spawn, 1, Fault::SpawnHang { child });
            let d = limit(&mut p);
            assert_eq!(
                p.spawn(
                    TunnelGeneration::new(1).map_err(|_| SysError::Failed("generation"))?,
                    super::super::SpawnAttributes {
                        default_signals: true,
                        empty_signal_mask: true,
                        cloexec_default: true,
                        synchronous: true
                    },
                    d
                ),
                Err(SysError::TimedOut)
            );
            assert_eq!(p.children.len(), usize::from(child));
            assert_eq!(p.fence(), Fence::Closed);
            assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            assert!(p.children.is_empty());
            assert_eq!(p.violations, [] as [&str; 0]);
        }
        let mut p = fake()?;
        p.scratch_process()?;
        p.scratch_process()?;
        assert_eq!(p.children.len(), 2);
        assert_eq!(p.violations, vec!["spawn before confirmed sweep"]);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        Ok(())
    }

    #[test]
    fn pf_disable_can_retain_tokens_independent_of_x_qualification() -> Result<(), SysError> {
        for invalidates in [false, true] {
            for qualified in [false, true] {
                let mut p = fake()?;
                acquire(&mut p);
                p.mutate(Mutation::ForeignEnable);
                let before = p.tokens.clone();
                p.disable_invalidates_tokens = invalidates;
                p.x_qualified = qualified;
                p.mutate(Mutation::PfDisable);
                let d = limit(&mut p);
                assert_eq!(p.pf_info(d), PfInfo::Disabled);
                if invalidates {
                    assert!(p.tokens.is_empty());
                } else {
                    assert_eq!(p.tokens, before);
                }
            }
        }
        let mut p = fake()?;
        acquire(&mut p);
        p.mutate(Mutation::PfDisableKeepTokens);
        assert!(!p.enabled);
        assert_eq!(p.tokens.len(), 1);
        Ok(())
    }

    #[test]
    fn kill_refuses_special_groups_and_orphan_pid_kill_preserves_group_peers()
    -> Result<(), SysError> {
        let mut p = fake()?;
        let own = p.incarnation();
        for pgid in [0, 1, own.pgid] {
            let target = proc(200, 50, pgid, 1, CHILD_PATH);
            p.procs.insert(200, target.clone());
            let d = limit(&mut p);
            assert!(p.kill_group(pgid, 200, target.start, d).is_err());
            let before = p.signals.len();
            assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            assert_eq!(p.signals[before..], [(target.pid, target.start)]);
        }
        let peer = proc(201, 50, own.pgid, 77, "/foreign");
        p.procs.insert(201, peer.clone());
        assert_eq!(start_fence(&mut p, None, &[]), StartFence::Closed);
        assert_eq!(p.procs[&201], peer);
        assert!(p.procs.contains_key(&own.pid));
        assert!(
            p.calls
                .iter()
                .any(|call| matches!(call, Call::KillProcess(200, _)))
        );
        // The individual start guard also protects a reused orphan PID.
        let target = proc(202, 50, 1, 1, "/sbin/pfctl");
        p.procs.insert(202, target.clone());
        p.inject(
            Call::KillProcess(202, target.start),
            1,
            Fault::PidReused(202),
        );
        assert_eq!(
            start_fence(&mut p, None, &[Path::new("/sbin/pfctl")]),
            StartFence::Closed
        );
        assert!(
            p.signals
                .iter()
                .any(|(pid, start)| *pid == 202 && *start != target.start)
        );
        assert!(!p.signals.contains(&(202, target.start)));
        Ok(())
    }

    #[test]
    fn full_child_start_identity_detects_same_second_pid_reuse() -> Result<(), SysError> {
        let mut p = fake()?;
        let d = limit(&mut p);
        p.pause(Duration::from_millis(50), d);
        let d = limit(&mut p);
        let child = p.spawn(
            TunnelGeneration::new(1).map_err(|_| SysError::Failed("generation"))?,
            super::super::SpawnAttributes {
                default_signals: true,
                empty_signal_mask: true,
                cloexec_default: true,
                synchronous: true,
            },
            d,
        )?;
        assert_eq!(child.start_time.microseconds, 50_000);
        let d = limit(&mut p);
        assert!(p.identity(&child, d).is_ok());
        if let Some(proc) = p.procs.get_mut(&child.pid) {
            proc.start.microseconds += 1;
        }
        let d = limit(&mut p);
        assert!(p.identity(&child, d).is_err());
        Ok(())
    }

    #[test]
    fn helper_deadlines_use_timings_and_cap_total_wait() -> Result<(), SysError> {
        let timings = Timings {
            command_deadline: 2,
            ..Timings::default()
        };
        for budget in [0, 1, 10] {
            let mut p = seeded()?;
            let start = p.now();
            p.inject(Call::Write(Copy::A), 1, Fault::WriteHang);
            assert_eq!(
                super::super::commit(&mut p, &[2; COPY_BYTES], &timings, Deadline(start + budget)),
                Commit::Failed { after_a: false }
            );
            assert_eq!(p.now() - start, budget.min(2));
            assert!(!p.calls.contains(&Call::Write(Copy::B)));
            assert_eq!(p.outstanding.is_some(), budget != 0);
        }
        let mut p = fake()?;
        let start = p.now();
        let budget = Deadline(start);
        assert_eq!(
            super::super::read_copy_with_retry(&mut p, Copy::A, &timings, budget),
            CopyRead::Unreadable
        );
        assert!(!p.calls.iter().any(|call| matches!(call, Call::Pause(_))));
        assert!(matches!(
            super::super::sweep(&mut p, Path::new(CHILD_PATH), &[], &timings, budget),
            Sweep::Incomplete(ProcessError {
                pid: None,
                error: SysError::TimedOut
            })
        ));
        Ok(())
    }

    #[test]
    fn pathless_own_zombies_are_reaped_and_foreign_zombies_need_no_path() -> Result<(), SysError> {
        let mut p = fake()?;
        let mut own = p.scratch_process()?;
        own.state = ProcState::Zombie;
        own.path = None;
        p.procs.insert(own.pid, own.clone());
        let mut foreign = proc(200, 50, 200, 77, CHILD_PATH);
        foreign.state = ProcState::Zombie;
        foreign.path = None;
        p.procs.insert(200, foreign);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert!(!p.procs.contains_key(&own.pid));
        assert_eq!(p.signals, []);
        assert!(p.procs.contains_key(&200));
        Ok(())
    }

    #[test]
    fn orphan_late_effect_survives_helper_death_but_not_reboot() -> Result<(), SysError> {
        let mut p = fake()?;
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: Some(2) });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        let tool = p.unreaped[0].pid;
        p.crash();
        p.restart();
        assert_eq!(p.procs[&tool].ppid, 1);
        assert_eq!(p.fence(), Fence::Closed);
        p.tick();
        p.tick();
        assert_eq!(p.tokens.len(), 1);
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: Some(2) });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        p.mutate(Mutation::Reboot);
        p.tick();
        p.tick();
        assert!(p.tokens.is_empty());
        assert_eq!(p.procs.len(), 1);
        Ok(())
    }

    #[test]
    fn observation_timeouts_and_b_commit_respect_remaining_budget() -> Result<(), SysError> {
        let timings = Timings {
            command_deadline: 2,
            ..Timings::default()
        };
        let mut p = seeded()?;
        let start = p.now();
        for _ in 0..3 {
            p.inject(Call::Read(Copy::A), 1, Fault::WriteHang);
        }
        assert_eq!(
            super::super::read_copy_with_retry(&mut p, Copy::A, &timings, Deadline(start + 3)),
            CopyRead::Unreadable
        );
        assert_eq!(p.now(), start + 3);
        assert_eq!(
            p.calls
                .iter()
                .filter(|call| **call == Call::Read(Copy::A))
                .count(),
            2
        );
        let mut p = seeded()?;
        let start = p.now();
        p.inject(Call::Write(Copy::B), 1, Fault::WriteHang);
        assert_eq!(
            super::super::commit(&mut p, &[2; COPY_BYTES], &timings, Deadline(start + 1)),
            Commit::Failed { after_a: true }
        );
        assert_eq!(p.now(), start + 1);
        assert_eq!(p.outstanding, Some(Copy::B));
        let mut p = fake()?;
        let start = p.now();
        p.inject(Call::Processes, 1, Fault::WriteHang);
        assert_eq!(
            super::super::start_fence(
                &mut p,
                super::super::PreviousHelper::Unknown,
                &[],
                Path::new(CHILD_PATH),
                &[],
                &timings,
                Deadline(start + 1)
            ),
            StartFence::Processes(Sweep::Incomplete(ProcessError {
                pid: None,
                error: SysError::TimedOut
            }))
        );
        assert_eq!(p.now(), start + 1);
        Ok(())
    }

    #[test]
    fn helper_pauses_do_not_overrun_subsecond_budget_remainder() -> Result<(), SysError> {
        let mut p = seeded()?;
        let start = p.now();
        let d = limit(&mut p);
        p.pause(Duration::from_millis(950), d);
        for _ in 0..3 {
            p.inject(Call::Read(Copy::A), 1, Fault::ReadFail);
        }
        assert_eq!(
            super::super::read_copy_with_retry(
                &mut p,
                Copy::A,
                &Timings::default(),
                Deadline(start + 1)
            ),
            CopyRead::Unreadable
        );
        let child = p.scratch_process()?;
        assert_eq!(
            child.start,
            StartTime {
                seconds: start + 1,
                microseconds: 0
            }
        );
        Ok(())
    }

    #[test]
    fn reap_waits_for_killed_tool_and_cancels_its_deferred_effect() -> Result<(), SysError> {
        let mut p = fake()?;
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: None });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        let pid = p.unreaped[0].pid;
        let start = p.procs[&pid].start;
        p.unkillable.remove(&pid);
        let d = limit(&mut p);
        assert_eq!(p.kill_process(pid, start, d)?, KillOutcome::Signalled);
        let before = p.now();
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert!(p.now() < before + 5);
        assert!(!p.procs.contains_key(&pid));
        p.tick();
        assert!(p.tokens.is_empty());
        Ok(())
    }
    #[test]
    fn executable_identity_finds_unlinked_and_renamed_children() -> Result<(), SysError> {
        for path in [None, Some("/replaced/old-wireguard-go".into())] {
            let mut p = fake()?;
            let child = p.scratch_process()?;
            if let Some(entry) = p.procs.get_mut(&child.pid) {
                entry.path = path;
            }
            assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            assert!(!p.procs.contains_key(&child.pid));
            assert!(p.signals.iter().any(|(pid, _)| *pid == child.pid));
        }
        // A pinned path still establishes ownership after binary replacement.
        let mut p = fake()?;
        let mut foreign = proc(200, 50, 200, 77, CHILD_PATH);
        foreign.exe = Some(ExeId { dev: 9, ino: 9 });
        p.procs.insert(200, foreign.clone());
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.procs[&200].state, ProcState::Zombie);
        assert_eq!(p.signals, [(200, foreign.start)]);
        Ok(())
    }

    #[test]
    fn start_fence_matches_pathless_orphan_identity_and_path_fallback() -> Result<(), SysError> {
        for identity_readable in [false, true] {
            let mut p = fake()?;
            let mut orphan = proc(200, 50, 200, 1, "/sbin/pfctl");
            if identity_readable {
                orphan.exe = p.executables.get(Path::new("/sbin/pfctl")).copied();
                orphan.path = None;
                orphan.image = Some(super::super::ImageId {
                    uuid: [9; 16],
                    uniqueid: 200,
                });
            }
            p.procs.insert(200, orphan);
            assert_eq!(
                start_fence(&mut p, None, &[Path::new("/sbin/pfctl")]),
                StartFence::Closed
            );
            assert!(p.signals.iter().any(|(pid, _)| *pid == 200));
        }
        let mut p = fake()?;
        let child = p.scratch_process()?;
        p.executables.remove(Path::new(CHILD_PATH));
        resolve_host_pathless_after_missing_pin(&mut p);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert!(!p.procs.contains_key(&child.pid));
        Ok(())
    }

    #[test]
    fn transient_incomplete_enumeration_retries_within_budget() -> Result<(), SysError> {
        for occurrence in [1, 2] {
            let mut p = fake()?;
            let child = p.scratch_process()?;
            p.inject(Call::Processes, occurrence, Fault::Incomplete);
            let before = p.now();
            assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            assert!(!p.procs.contains_key(&child.pid));
            assert!(p.now() < before + 5);
            assert_eq!(p.signals.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn sweep_signals_identity_first_seen_after_pid_reuse() -> Result<(), SysError> {
        let mut p = fake()?;
        let child = p.scratch_process()?;
        p.inject(
            Call::KillProcess(child.pid, child.start),
            1,
            Fault::PidReused(child.pid),
        );
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.signals.len(), 1);
        assert_ne!(p.signals[0].1, child.start);
        assert!(!p.procs.contains_key(&child.pid));
        Ok(())
    }

    #[test]
    fn own_exit_race_requires_reap_and_never_signals_a_zombie() -> Result<(), SysError> {
        let mut p = fake()?;
        let child = p.scratch_process()?;
        p.inject(Call::Processes, 1, Fault::ExitRace(child.pid));
        let d = limit(&mut p);
        assert!(matches!(p.processes(d), Enumeration::Complete(ref entries)
            if entries.iter().any(|entry| entry.pid == child.pid && entry.state == ProcState::Zombie)));
        assert!(p.procs.contains_key(&child.pid));
        let d = limit(&mut p);
        assert_eq!(
            p.kill_process(child.pid, child.start, d)?,
            KillOutcome::Gone
        );
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.signals, []);
        assert!(!p.procs.contains_key(&child.pid));

        // The race can also create a zombie after sweep's first reap attempt.
        let child = p.scratch_process()?;
        p.inject(Call::Processes, 1, Fault::ExitRace(child.pid));
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.signals, []);
        assert!(!p.procs.contains_key(&child.pid));
        Ok(())
    }

    #[test]
    fn launchd_abandon_process_group_preserves_group_members() -> Result<(), SysError> {
        let mut p = fake()?;
        let own = p.incarnation();
        p.abandon_process_group = true;
        p.procs
            .insert(200, proc(200, 101, own.pgid, own.pid, "/foreign"));
        p.crash();
        p.tick();
        assert_eq!(p.procs[&200].state, ProcState::Running);
        assert_eq!(p.procs[&200].ppid, 1);
        Ok(())
    }

    #[test]
    fn released_token_reissues_as_a_different_reference() -> Result<(), SysError> {
        let mut p = fake()?;
        let token = acquire(&mut p);
        let old = p.tokens[&token].clone();
        let d = limit(&mut p);
        assert_eq!(p.release(token, d), ToolOutcome::Ok(Release::Requested));
        p.mutate(Mutation::ForeignEnable);
        let d = limit(&mut p);
        let Enumeration::Complete(refs) = p.references(d) else {
            return Err(SysError::Failed("references"));
        };
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].token, old.token);
        assert_ne!(refs[0].pid, old.pid);
        assert_ne!(refs[0].timestamp, old.timestamp);
        assert!(!refs.contains(&old)); // Full fingerprint never mistakes it for ours.
        Ok(())
    }

    #[test]
    fn token_reuse_is_lowest_freed_first_and_covers_disable() -> Result<(), SysError> {
        let mut p = fake()?;
        let first = acquire(&mut p);
        let second = acquire(&mut p);
        for token in [second, first] {
            p.mutate(Mutation::ForeignRelease(token));
        }
        assert_eq!(acquire(&mut p), first);
        assert_eq!(acquire(&mut p), second);
        p.mutate(Mutation::PfDisable);
        assert_eq!(acquire(&mut p), first);
        let d = limit(&mut p);
        assert_eq!(p.release(first, d), ToolOutcome::Ok(Release::Requested));
        p.reuse_tokens = false;
        assert!(acquire(&mut p) > second);
        Ok(())
    }

    #[test]
    fn reused_previous_pgid_foreign_shell_survives() -> Result<(), SysError> {
        let mut p = fake()?;
        let prev = previous(&p);
        // Both shell and job predate current helper: the leader proves reuse.
        let shell = proc(prev.pgid, 70, prev.pgid, 77, "/bin/zsh");
        let job = proc(201, 80, prev.pgid, shell.pid, "/foreign/job");
        p.procs.insert(shell.pid, shell.clone());
        p.procs.insert(job.pid, job.clone());
        assert_eq!(start_fence(&mut p, Some(prev), &[]), StartFence::Closed);
        assert_eq!(p.procs[&shell.pid], shell);
        assert_eq!(p.procs[&job.pid], job);
        assert_eq!(p.signals, []);
        Ok(())
    }

    #[test]
    fn previous_group_orphan_is_killed_but_current_or_later_members_survive() -> Result<(), SysError>
    {
        for seconds in [70, 100, 101] {
            let mut p = fake()?;
            let prev = previous(&p);
            let orphan = proc(201, seconds, prev.pgid, 1, "/foreign/old-tool");
            p.procs.insert(orphan.pid, orphan.clone());
            assert_eq!(start_fence(&mut p, Some(prev), &[]), StartFence::Closed);
            assert_eq!(
                p.signals.iter().any(|(pid, _)| *pid == orphan.pid),
                seconds < 100
            );
            if seconds >= 100 {
                assert_eq!(p.procs[&orphan.pid], orphan);
            }
        }
        Ok(())
    }

    #[test]
    fn corrupt_previous_group_names_later_own_group_member_without_signal() -> Result<(), SysError>
    {
        let mut p = fake()?;
        let mut prev = previous(&p);
        prev.pgid = p.helper.pgid;
        let member = proc(201, 101, p.helper.pgid, p.helper.pid, "/foreign/job");
        p.procs.insert(member.pid, member.clone());
        assert_eq!(
            start_fence(&mut p, Some(prev), &[]),
            StartFence::Processes(Sweep::Survivors(vec![member]))
        );
        assert_eq!(p.signals, []);
        Ok(())
    }

    #[test]
    fn reap_children_only_consumes_spawn_children_never_tools_or_harness_children()
    -> Result<(), SysError> {
        let mut p = fake()?;
        let spawned = p.scratch_process()?;
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: None });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        let tool = p.unreaped[0].pid;
        let mut other = proc(200, 101, 200, p.helper.pid, "/harness-child");
        other.state = ProcState::Zombie;
        p.procs.insert(200, other.clone());
        for pid in [spawned.pid, tool] {
            if let Some(entry) = p.procs.get_mut(&pid) {
                entry.state = ProcState::Zombie;
            }
        }
        let d = limit(&mut p);
        p.reap_children(d)?;
        assert!(!p.procs.contains_key(&spawned.pid));
        assert_eq!(p.procs[&200], other);
        assert_eq!(p.procs[&tool].state, ProcState::Zombie);
        assert!(matches!(p.fence(), Fence::Open(_)));
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert!(!p.procs.contains_key(&tool));
        assert!(p.tokens.is_empty());
        // ECHILD is also a completed reap.
        p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: None });
        let d = limit(&mut p);
        assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
        p.procs.remove(&p.unreaped[0].pid);
        let d = limit(&mut p);
        assert_eq!(p.reap(d), Fence::Closed);
        assert!(p.tokens.is_empty());
        Ok(())
    }

    #[test]
    fn orphan_stuck_tool_finishes_late_and_start_fence_then_closes() -> Result<(), SysError> {
        for apply_effect in [false, true] {
            let mut p = fake()?;
            let old = p.incarnation();
            p.inject(Call::Acquire, 1, Fault::ToolLate { ticks: None });
            let d = limit(&mut p);
            assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
            let tool = p.unreaped[0].pid;
            p.crash();
            p.restart();
            assert!(matches!(
                start_fence(&mut p, Some(old.clone()), &[]),
                StartFence::Processes(Sweep::Survivors(_))
            ));
            p.orphan_finish(tool, apply_effect);
            assert_eq!(p.tokens.len(), usize::from(apply_effect));
            assert_eq!(p.procs[&tool].state, ProcState::Zombie);
            assert_eq!(start_fence(&mut p, Some(old), &[]), StartFence::Closed);
            p.tick();
            assert!(!p.procs.contains_key(&tool));
            assert_eq!(p.tokens.len(), usize::from(apply_effect));
        }
        Ok(())
    }

    #[test]
    fn clock_is_monotonic_per_boot_and_resets_on_reboot() -> Result<(), SysError> {
        let mut p = fake()?;
        let before = p.now();
        let boot = p.boot_id();
        p.tick();
        assert!(p.now() >= before);
        p.mutate(Mutation::Reboot);
        assert_ne!(p.boot_id(), boot);
        assert!(p.now() < before);
        assert_eq!(p.now(), 0);
        p.tick();
        assert_eq!(p.now(), 0);
        Ok(())
    }

    #[test]
    fn shared_group_signal_refusal_rule() {
        for pgid in [0, 1, 100, u32::MAX, super::super::OS_PID_MAX + 1] {
            assert!(!super::super::group_kill_allowed(pgid, 100));
        }
        for pgid in [2, 99, 101, super::super::OS_PID_MAX] {
            assert!(super::super::group_kill_allowed(pgid, 100));
        }
    }
    #[test]
    fn initially_empty_sweep_still_requires_a_second_complete_enumeration() -> Result<(), SysError>
    {
        for hang in [false, true] {
            let mut p = fake()?;
            if hang {
                p.inject(Call::Processes, 2, Fault::WriteHang);
            }
            let result = sweep(&mut p, Path::new(CHILD_PATH));
            assert_eq!(
                result,
                if hang {
                    Sweep::Incomplete(SysError::TimedOut.into())
                } else {
                    Sweep::Swept
                }
            );
            assert_eq!(
                p.calls
                    .iter()
                    .filter(|call| **call == Call::Processes)
                    .count(),
                2
            );
            assert_eq!(p.signals, []);
        }
        Ok(())
    }

    #[test]
    fn replacement_and_removal_keep_child_covered() -> Result<(), SysError> {
        for startup in [false, true] {
            for removed in [false, true] {
                for pathless in [false, true] {
                    let mut p = fake()?;
                    let proc = p.scratch_process()?;
                    let recorded = p.spawned_children().to_vec();
                    assert_eq!(recorded[0].exe, proc.exe);
                    assert_eq!(recorded[0].pid, proc.pid);
                    assert_eq!(recorded[0].start_time, proc.start);
                    if removed {
                        p.executables.remove(Path::new(CHILD_PATH));
                    } else {
                        p.executables
                            .insert(CHILD_PATH.into(), ExeId { dev: 1, ino: 999 });
                    }
                    if removed && !startup {
                        resolve_host_pathless_after_missing_pin(&mut p);
                    }
                    if pathless && let Some(entry) = p.procs.get_mut(&proc.pid) {
                        entry.path = None;
                    }
                    if startup {
                        let previous = p.incarnation();
                        p.abandon_process_group = true;
                        p.crash();
                        p.restart();
                        assert_eq!(p.spawned_children(), []);
                        let overall = limit(&mut p);
                        assert_eq!(
                            super::super::start_fence(
                                &mut p,
                                super::super::PreviousHelper::Known(previous),
                                &[],
                                Path::new(CHILD_PATH),
                                &[],
                                &Timings::default(),
                                overall,
                            ),
                            StartFence::Closed
                        );
                    } else {
                        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
                    }
                    // launchd may still owe the orphan zombie its final reap.
                    p.tick();
                    assert!(!p.procs.contains_key(&proc.pid));
                    assert_eq!(p.signals, [(proc.pid, proc.start)]);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn hard_link_elsewhere_is_owned_by_current_identity() -> Result<(), SysError> {
        for startup in [false, true] {
            let mut p = fake()?;
            // This was not spawned by the helper: the inode alone owns it.
            let peer = proc(201, 40, 300, 77, "/foreign/group-peer");
            p.procs.insert(peer.pid, peer.clone());
            let mut linked = proc(200, 50, peer.pgid, 1, "/elsewhere/hard-link");
            linked.exe = p.executables.get(Path::new(CHILD_PATH)).copied();
            p.procs.insert(linked.pid, linked.clone());
            if startup {
                assert_eq!(start_fence(&mut p, None, &[]), StartFence::Closed);
            } else {
                assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            }
            assert_eq!(p.signals, [(linked.pid, linked.start)]);
            assert!(
                p.calls
                    .contains(&Call::KillProcess(linked.pid, linked.start))
            );
            assert!(!p.calls.iter().any(|call| matches!(call, Call::Kill(..))));
            assert_eq!(p.procs[&peer.pid], peer);
            p.tick();
            assert!(!p.procs.contains_key(&linked.pid));
        }
        Ok(())
    }

    #[test]
    fn upgrade_default_launchd_removes_child_without_records() -> Result<(), SysError> {
        for path in [None, Some("/upgraded/unlinked-old-wireguard-go".into())] {
            let mut p = fake()?;
            assert!(!p.abandon_process_group);
            let previous = p.incarnation();
            let child = p.scratch_process()?;
            assert_eq!(child.pgid, previous.pgid);
            let replacement = ExeId { dev: 1, ino: 999 };
            p.executables.insert(CHILD_PATH.into(), replacement);
            if let Some(proc) = p.procs.get_mut(&child.pid) {
                proc.path = path;
            }
            assert_ne!(child.exe, Some(replacement));
            p.crash();
            assert_eq!(p.procs[&child.pid].state, ProcState::Zombie);
            p.restart();
            assert_eq!(p.spawned_children(), []);
            assert_eq!(start_fence(&mut p, Some(previous), &[]), StartFence::Closed);
            // A foreign zombie cannot act; launchd completes its reap next tick.
            p.tick();
            assert!(!p.procs.contains_key(&child.pid));
            assert_eq!(p.signals, []); // launchd, not an in-memory child record
        }
        Ok(())
    }

    #[test]
    fn upgrade_surviving_child_is_killed_by_previous_group_without_records() -> Result<(), SysError>
    {
        for path in [None, Some("/upgraded/unlinked-old-wireguard-go".into())] {
            let mut p = fake()?;
            let previous = p.incarnation();
            let child = p.scratch_process()?;
            p.executables
                .insert(CHILD_PATH.into(), ExeId { dev: 1, ino: 999 });
            if let Some(proc) = p.procs.get_mut(&child.pid) {
                proc.path = path;
            }
            // Opt-out also models the interval before launchd's group kill arrives.
            p.abandon_process_group = true;
            p.crash();
            assert_eq!(p.procs[&child.pid].state, ProcState::Running);
            assert_eq!(p.procs[&child.pid].pgid, previous.pgid);
            p.restart();
            assert_eq!(p.spawned_children(), []);
            assert_eq!(start_fence(&mut p, Some(previous), &[]), StartFence::Closed);
            p.tick();
            assert!(!p.procs.contains_key(&child.pid));
            assert_eq!(p.signals, [(child.pid, child.start)]);
            assert!(p.calls.contains(&Call::Kill(child.pid, child.start)));
            p.scratch_process()?;
            assert_eq!(p.violations, [] as [&str; 0]);
        }
        Ok(())
    }

    #[test]
    fn exact_spawn_pair_matches_without_exe_and_never_owns_identity_peers() -> Result<(), SysError>
    {
        for startup in [false, true] {
            for record_exe in [None, Some(ExeId { dev: 9, ino: 9 })] {
                let mut p = fake()?;
                let child = p.scratch_process()?;
                let mut record = p.spawned_children()[0].clone();
                record.exe = record_exe;
                // Clear the adapter records to isolate the supplied match fixture.
                // This tests the matcher; startup's real upgrade tests pass &[]
                // and use the previous-group rule, never a persisted child record.
                p.abandon_process_group = true;
                p.restart();
                assert_eq!(p.spawned_children(), []);
                if let Some(proc) = p.procs.get_mut(&child.pid) {
                    proc.path = None;
                }
                p.executables
                    .insert(CHILD_PATH.into(), ExeId { dev: 1, ino: 999 });
                let mut peer = proc(200, 50, child.pgid, 1, "/foreign/identity-peer");
                peer.exe = record_exe;
                p.procs.insert(peer.pid, peer.clone());
                let overall = limit(&mut p);
                let previous = unrelated_previous(&p);
                let result = if startup {
                    let result = super::super::start_fence(
                        &mut p,
                        super::super::PreviousHelper::Known(previous),
                        &[],
                        Path::new(CHILD_PATH),
                        &[record],
                        &Timings::default(),
                        overall,
                    );
                    assert_eq!(result, StartFence::Closed);
                    Sweep::Swept
                } else {
                    super::super::sweep(
                        &mut p,
                        Path::new(CHILD_PATH),
                        &[record],
                        &Timings::default(),
                        overall,
                    )
                };
                assert_eq!(result, Sweep::Swept);
                assert_eq!(p.procs[&peer.pid], peer);
                assert_eq!(p.signals, [(child.pid, child.start)]);
                assert!(p.calls.contains(&Call::KillProcess(child.pid, child.start)));
                assert!(!p.calls.iter().any(|call| matches!(call, Call::Kill(..))));
            }
        }
        Ok(())
    }

    #[test]
    fn spawn_records_do_not_match_reused_pid_or_other_boot() -> Result<(), SysError> {
        for mismatch in ["pid", "start", "boot", "unknown-boot"] {
            let mut p = fake()?;
            let child = p.scratch_process()?;
            let mut recorded = p.spawned_children().to_vec();
            p.abandon_process_group = true;
            p.restart(); // The saved vector below is only a negative match fixture.
            if let Some(proc) = p.procs.get_mut(&child.pid) {
                proc.path = None;
                if mismatch == "start" {
                    proc.start.microseconds += 1;
                }
            }
            match mismatch {
                "pid" => recorded[0].pid += 1,
                "boot" => {
                    recorded[0].boot = Some(
                        snapshot::BootId::try_from("00000000-0000-0000-0000-000000000002")
                            .map_err(|_| SysError::Failed("fixture boot"))?,
                    );
                }
                "unknown-boot" => recorded[0].boot = None,
                _ => {}
            }
            p.executables
                .insert(CHILD_PATH.into(), ExeId { dev: 1, ino: 999 });
            let overall = limit(&mut p);
            assert!(matches!(
                super::super::sweep(
                    &mut p,
                    Path::new(CHILD_PATH),
                    &recorded,
                    &Timings::default(),
                    overall,
                ),
                Sweep::Incomplete(ProcessError {pid: Some(pid), ..}) if pid == child.pid
            ));
            assert_eq!(p.procs[&child.pid].state, ProcState::Running);
            assert_eq!(p.signals, []);
        }
        Ok(())
    }

    #[test]
    fn incarnation_local_spawn_pair_works_with_unknown_boot() -> Result<(), SysError> {
        let mut p = fake()?;
        p.boot = None;
        p.helper.boot = None;
        let child = p.scratch_child()?;
        assert_eq!(child.boot, None);
        p.executables
            .insert(CHILD_PATH.into(), ExeId { dev: 1, ino: 999 });
        if let Some(proc) = p.procs.get_mut(&child.pid) {
            proc.path = None;
        }
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert!(!p.procs.contains_key(&child.pid));
        assert_eq!(p.signals, [(child.pid, child.start_time)]);
        Ok(())
    }

    #[test]
    fn missing_pin_with_unrelated_record_still_fails_closed() -> Result<(), SysError> {
        for startup in [false, true] {
            let mut p = fake()?;
            let record = p.scratch_child()?;
            assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            p.unlink_scratch_executable()?;
            resolve_host_pathless_after_missing_pin(&mut p);
            let mut unknown = proc(200, 50, 200, 1, "/removed/other-child");
            unknown.path = None;
            unknown.exe = Some(ExeId { dev: 1, ino: 999 });
            p.procs.insert(unknown.pid, unknown.clone());
            let overall = limit(&mut p);
            let result = if startup {
                let StartFence::Processes(result) = super::super::start_fence(
                    &mut p,
                    super::super::PreviousHelper::Unknown,
                    &[],
                    Path::new(CHILD_PATH),
                    &[record],
                    &Timings::default(),
                    overall,
                ) else {
                    return Err(SysError::Failed("missing pin closed startup"));
                };
                result
            } else {
                super::super::sweep(
                    &mut p,
                    Path::new(CHILD_PATH),
                    &[record],
                    &Timings::default(),
                    overall,
                )
            };
            assert!(matches!(
                result,
                Sweep::Incomplete(ProcessError { pid: Some(200), .. })
            ));
            assert_eq!(p.procs[&unknown.pid], unknown);
        }
        Ok(())
    }

    #[test]
    fn symlink_pin_is_rejected_without_owning_its_target() -> Result<(), SysError> {
        let mut p = fake()?;
        p.executable_symlinks.insert(CHILD_PATH.into());
        resolve_host_pathless_after_missing_pin(&mut p);
        let d = limit(&mut p);
        assert!(p.executable_id(Path::new(CHILD_PATH), d).is_err());
        let d = limit(&mut p);
        assert!(p.check_tools(d).is_err());
        let mut foreign = proc(200, 50, 200, 1, "/opt/homebrew/bin/wireguard-go");
        foreign.exe = p.executables.get(Path::new(CHILD_PATH)).copied();
        p.procs.insert(foreign.pid, foreign.clone());
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.procs[&foreign.pid], foreign);
        assert_eq!(p.signals, []);
        Ok(())
    }

    #[test]
    fn missing_tool_blocks_all_unselected_pathless_startup_candidates() -> Result<(), SysError> {
        for (parent, seconds, blocked) in [(77, 50, true), (1, 101, true), (1, 50, true)] {
            let mut p = fake()?;
            p.executables.remove(Path::new("/sbin/pfctl"));
            let mut foreign = proc(200, seconds, 200, parent, "/foreign/updated-browser");
            foreign.path = None;
            foreign.exe = Some(ExeId { dev: 9, ino: 9 });
            p.procs.insert(foreign.pid, foreign.clone());
            let result = start_fence(&mut p, None, &[Path::new("/sbin/pfctl")]);
            if blocked {
                assert!(matches!(
                    result,
                    StartFence::Processes(Sweep::Incomplete(ProcessError { pid: Some(200), .. }))
                ));
            } else {
                assert_eq!(result, StartFence::Closed);
            }
            assert_eq!(p.procs[&foreign.pid], foreign);
            assert_eq!(p.signals, []);
        }
        Ok(())
    }

    #[test]
    fn kill_errors_are_retried_within_budget() -> Result<(), SysError> {
        for startup in [false, true] {
            for (fault, budget) in [
                (Fault::Incomplete, 5),
                (Fault::WriteHang, 5),
                (Fault::WriteHang, 1),
            ] {
                let mut p = fake()?;
                let target = proc(200, 50, 200, 1, CHILD_PATH);
                p.procs.insert(target.pid, target.clone());
                let call = Call::KillProcess(target.pid, target.start);
                p.inject(call, 1, fault);
                let overall = Deadline(p.now() + budget);
                let timings = Timings {
                    command_deadline: 1,
                    ..Timings::default()
                };
                let result = if startup {
                    match super::super::start_fence(
                        &mut p,
                        super::super::PreviousHelper::Unknown,
                        &[],
                        Path::new(CHILD_PATH),
                        &[],
                        &timings,
                        overall,
                    ) {
                        StartFence::Closed => Sweep::Swept,
                        StartFence::Processes(result) => result,
                        StartFence::Tools(_) | StartFence::Uncommitted => {
                            return Err(SysError::Failed("unexpected open fence"));
                        }
                    }
                } else {
                    super::super::sweep(&mut p, Path::new(CHILD_PATH), &[], &timings, overall)
                };
                if fault == Fault::WriteHang && budget == 1 {
                    assert_eq!(result, Sweep::Incomplete(SysError::TimedOut.into()));
                    assert_eq!(p.now(), overall.0);
                } else {
                    assert_eq!(result, Sweep::Swept);
                    assert_eq!(p.calls.iter().filter(|entry| **entry == call).count(), 2);
                    assert_eq!(p.signals, [(target.pid, target.start)]);
                    assert!(p.now() < overall.0);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn pinned_path_with_different_identity_is_owned_at_start() -> Result<(), SysError> {
        let mut p = fake()?;
        let mut old = proc(200, 50, 200, 1, CHILD_PATH);
        old.exe = Some(ExeId { dev: 1, ino: 999 });
        p.procs.insert(old.pid, old.clone());
        assert_eq!(start_fence(&mut p, None, &[]), StartFence::Closed);
        assert_eq!(p.signals, [(old.pid, old.start)]);
        p.tick();
        assert!(!p.procs.contains_key(&old.pid));
        Ok(())
    }

    #[test]
    fn pinned_identity_is_re_statted_on_every_poll() -> Result<(), SysError> {
        for startup in [false, true] {
            let mut p = fake()?;
            let exe = ExeId { dev: 1, ino: 999 };
            let mut old = proc(200, 50, 200, 1, "/elsewhere/hard-link");
            old.exe = Some(exe);
            p.procs.insert(old.pid, old.clone());
            p.inject(Call::Processes, 1, Fault::ReplaceExecutable(exe));
            if startup {
                assert_eq!(start_fence(&mut p, None, &[]), StartFence::Closed);
            } else {
                assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
            }
            assert_eq!(p.signals, [(old.pid, old.start)]);
            p.tick();
            assert!(!p.procs.contains_key(&old.pid));
            let stats = p
                .calls
                .iter()
                .filter(|call| **call == Call::ExecutableId)
                .count();
            let polls = p
                .calls
                .iter()
                .filter(|call| **call == Call::Processes)
                .count();
            assert_eq!(stats, polls);
        }
        Ok(())
    }

    #[test]
    fn spawn_oracle_uses_real_children_even_when_unidentifiable() -> Result<(), SysError> {
        let mut p = fake()?;
        let child = p.scratch_process()?;
        if let Some(entry) = p.procs.get_mut(&child.pid) {
            entry.path = None;
            entry.exe = None;
        }
        p.abandon_process_group = true;
        p.crash();
        p.restart();
        p.scratch_process()?;
        assert_eq!(p.violations, ["spawn before confirmed sweep"]);
        Ok(())
    }

    #[test]
    fn spawn_records_survive_reap_and_precede_uncertain_wait() -> Result<(), SysError> {
        let mut p = fake()?;
        p.inject(Call::Spawn, 1, Fault::SpawnHang { child: true });
        assert_eq!(p.scratch_process(), Err(SysError::TimedOut));
        let records = p.spawned_children().to_vec();
        assert_eq!(records.len(), 1);
        let proc = &p.procs[&records[0].pid];
        assert_eq!(records[0].exe, proc.exe);
        assert_eq!(records[0].start_time, proc.start);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert!(p.children.is_empty());
        assert_eq!(p.spawned_children(), records);
        Ok(())
    }

    #[test]
    fn launchd_group_kill_applies_pending_by_default_or_drops_on_request() -> Result<(), SysError> {
        for apply in [true, false] {
            for ticks in [None, Some(2)] {
                let mut p = fake()?;
                assert!(p.launchd_kill_applies_pending);
                p.launchd_kill_applies_pending = apply;
                p.inject(Call::Acquire, 1, Fault::ToolLate { ticks });
                let d = limit(&mut p);
                assert_eq!(p.acquire(d), ToolOutcome::Unknown { reaped: false });
                let pid = p.unreaped[0].pid;
                p.unkillable.remove(&pid);
                assert!(p.tokens.is_empty());
                p.crash();
                assert_eq!(p.procs[&pid].state, ProcState::Zombie);
                assert_eq!(p.tokens.len(), usize::from(apply));
                p.restart();
                for _ in 0..4 {
                    p.tick();
                }
                assert_eq!(p.tokens.len(), usize::from(apply));
                assert!(!p.procs.contains_key(&pid));
                assert_eq!(p.fence(), Fence::Closed);
            }
        }
        Ok(())
    }

    #[test]
    fn residual_unknown_boot_reused_previous_group_is_killed() -> Result<(), SysError> {
        let mut p = fake()?;
        p.restart();
        p.mutate(Mutation::BootIdUnavailable);
        let previous = p.incarnation();
        p.mutate(Mutation::Reboot);
        let boot_helper = p.incarnation();
        assert!(boot_helper.pid < previous.pid); // PID allocation restarts low.
        assert!(
            super::super::start_key(boot_helper.start) > super::super::start_key(previous.start)
        );
        p.mutate(Mutation::BootIdUnavailable);
        // Foreign leader has exited. A foreign member reused the old pgid after
        // reboot, before the next helper: this is the documented residual.
        let mut foreign = proc(
            202,
            boot_helper.start.seconds,
            previous.pgid,
            1,
            "/foreign/job",
        );
        foreign.start = boot_helper.start;
        p.procs.insert(foreign.pid, foreign.clone());
        p.restart();
        assert!(super::super::start_key(foreign.start) < super::super::start_key(p.helper.start));
        assert_eq!(start_fence(&mut p, Some(previous), &[]), StartFence::Closed);
        assert_eq!(p.signals, [(foreign.pid, foreign.start)]);
        p.tick();
        assert!(!p.procs.contains_key(&foreign.pid));
        Ok(())
    }

    #[test]
    fn original_older_leader_does_not_suppress_previous_group_cleanup() -> Result<(), SysError> {
        let mut p = fake()?;
        let prev = previous(&p);
        let leader = proc(prev.pgid, 40, prev.pgid, 1, "/original/leader");
        let member = proc(201, 70, prev.pgid, 1, "/original/member");
        p.procs.insert(leader.pid, leader);
        p.procs.insert(member.pid, member.clone());
        assert_eq!(start_fence(&mut p, Some(prev), &[]), StartFence::Closed);
        assert_eq!(p.signals, [(member.pid, member.start)]);
        p.tick();
        assert!(!p.procs.contains_key(&member.pid));
        Ok(())
    }

    #[test]
    fn reused_zombie_leader_proves_previous_group_reuse() -> Result<(), SysError> {
        let mut p = fake()?;
        let prev = previous(&p);
        let mut leader = proc(prev.pgid, 70, prev.pgid, 77, "/foreign/leader");
        leader.state = ProcState::Zombie;
        let member = proc(201, 80, prev.pgid, 77, "/foreign/member");
        p.procs.insert(leader.pid, leader);
        p.procs.insert(member.pid, member.clone());
        assert_eq!(start_fence(&mut p, Some(prev), &[]), StartFence::Closed);
        assert_eq!(p.procs[&member.pid], member);
        assert_eq!(p.signals, []);
        Ok(())
    }

    #[test]
    fn transient_process_guard_race_is_retried() -> Result<(), SysError> {
        let mut p = fake()?;
        let child = p.scratch_process()?;
        let call = Call::KillProcess(child.pid, child.start);
        p.inject(call, 1, Fault::GroupRace);
        assert_eq!(sweep(&mut p, Path::new(CHILD_PATH)), Sweep::Swept);
        assert_eq!(p.calls.iter().filter(|c| **c == call).count(), 2);
        assert_eq!(p.signals, [(child.pid, child.start)]);
        assert!(!p.procs.contains_key(&child.pid));
        Ok(())
    }

    #[test]
    fn reap_errors_are_retried_within_the_overall_budget() -> Result<(), SysError> {
        for fault in [Fault::Incomplete, Fault::WriteHang] {
            let mut p = fake()?;
            let child = p.scratch_process()?;
            p.inject(Call::ReapChildren, 1, fault);
            let overall = limit(&mut p);
            let result = super::super::sweep(
                &mut p,
                Path::new(CHILD_PATH),
                &[],
                &Timings::default(),
                overall,
            );
            if fault == Fault::WriteHang {
                assert_eq!(result, Sweep::Incomplete(SysError::TimedOut.into()));
                assert_eq!(p.now(), overall.0);
                assert!(p.procs.contains_key(&child.pid));
            } else {
                assert_eq!(result, Sweep::Swept);
                assert!(!p.procs.contains_key(&child.pid));
                assert!(p.now() < overall.0);
            }
        }
        Ok(())
    }

    #[test]
    fn sweep_uses_in_memory_spawn_pair_after_unlink() -> Result<(), SysError> {
        let mut p = fake()?;
        let child = p.scratch_process()?;
        let recorded = p.spawned_children().to_vec();
        p.unlink_scratch_executable()?;
        resolve_host_pathless_after_missing_pin(&mut p);
        let overall = limit(&mut p);
        assert_eq!(
            super::super::sweep(
                &mut p,
                Path::new(CHILD_PATH),
                &recorded,
                &Timings::default(),
                overall,
            ),
            Sweep::Swept
        );
        p.tick();
        assert!(!p.procs.contains_key(&child.pid));
        assert_eq!(p.signals, [(child.pid, child.start)]);
        Ok(())
    }

    #[test]
    fn spawn_oracle_does_not_infer_children_from_paths() -> Result<(), SysError> {
        let mut p = fake()?;
        p.procs.insert(200, proc(200, 50, 200, 77, CHILD_PATH));
        p.scratch_process()?;
        assert_eq!(p.violations, [] as [&str; 0]);
        Ok(())
    }

    #[test]
    fn missing_pin_and_spawn_records_fail_closed_for_pathless_process() -> Result<(), SysError> {
        for startup in [false, true] {
            let mut p = fake()?;
            let child = p.scratch_process()?;
            p.unlink_scratch_executable()?;
            resolve_host_pathless_after_missing_pin(&mut p);
            p.abandon_process_group = true;
            p.restart(); // Restart discards all in-memory spawn records.
            let result = if startup {
                let StartFence::Processes(result) =
                    start_fence(&mut p, None, &[Path::new("/sbin/pfctl")])
                else {
                    return Err(SysError::Failed(
                        "unknown pinned identity falsely closed startup",
                    ));
                };
                result
            } else {
                sweep(&mut p, Path::new(CHILD_PATH))
            };
            assert_eq!(
                result,
                Sweep::Incomplete(ProcessError {
                    pid: Some(child.pid),
                    error: SysError::Failed(if startup {
                        "previous helper unknown: process ownership undecidable"
                    } else {
                        "pinned identity unavailable for pathless process"
                    }),
                })
            );
            assert_eq!(p.procs[&child.pid].state, ProcState::Running);
            assert_eq!(p.signals, []);
        }
        Ok(())
    }
    #[test]
    fn volatile_stub_name_needs_repair_not_just_data_writeback() -> Result<(), SysError> {
        for repair in [false, true] {
            let mut p = FakePlatform::new()?;
            let bytes = [7; COPY_BYTES];
            p.inject(
                Call::Create(Copy::B),
                1,
                Fault::CreateStub {
                    len: COPY_BYTES / 2,
                    durable_name: false,
                },
            );
            let d = limit(&mut p);
            assert!(matches!(
                p.create_copy(Copy::B, &bytes, d),
                WriteOutcome::Failed(_)
            ));
            if repair {
                let d = limit(&mut p);
                assert_eq!(p.write_copy(Copy::B, &bytes, d), WriteOutcome::Synced);
            } else {
                p.inject(Call::Write(Copy::B), 1, Fault::FailedPending);
                let d = limit(&mut p);
                assert!(matches!(
                    p.write_copy(Copy::B, &bytes, d),
                    WriteOutcome::Failed(_)
                ));
                p.writeback(Copy::B);
            }
            let d = limit(&mut p);
            assert_eq!(p.read_copy(Copy::B, d), CopyRead::Bytes(bytes.to_vec()));
            p.mutate(Mutation::Reboot);
            let d = limit(&mut p);
            assert_eq!(
                p.read_copy(Copy::B, d),
                if repair {
                    CopyRead::Bytes(bytes.to_vec())
                } else {
                    CopyRead::Missing
                }
            );
        }
        Ok(())
    }

    #[test]
    fn create_stub_provenance_survives_pending_write_loss_and_clears_on_repair()
    -> Result<(), SysError> {
        let mut p = FakePlatform::new()?;
        let bytes = snapshot::encode(1, &Snapshot::initial(Some(501), None))
            .map_err(|_| SysError::Failed("fixture"))?;
        p.inject(
            Call::Create(Copy::B),
            1,
            Fault::CreateStub {
                len: COPY_BYTES / 2,
                durable_name: true,
            },
        );
        let d = limit(&mut p);
        assert!(matches!(
            p.create_copy(Copy::B, &bytes, d),
            WriteOutcome::Failed(_)
        ));
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::B, d), CopyRead::Short(bytes.to_vec()));
        p.inject(Call::Write(Copy::B), 1, Fault::FailedPending);
        let d = limit(&mut p);
        assert!(matches!(
            p.write_copy(Copy::B, &bytes, d),
            WriteOutcome::Failed(_)
        ));
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::B, d), CopyRead::Bytes(bytes.to_vec()));
        p.mutate(Mutation::Reboot);
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::B, d), CopyRead::Short(bytes.to_vec()));
        let d = limit(&mut p);
        assert_eq!(p.write_copy(Copy::B, &bytes, d), WriteOutcome::Synced);
        let d = limit(&mut p);
        assert_eq!(p.read_copy(Copy::B, d), CopyRead::Bytes(bytes.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod run5_contracts {
    use super::*;
    use crate::{
        platform::{self, SpawnAttributes, fake::FakePlatform},
        snapshot::StartTime,
    };
    use scupper_core::mac::TunnelGeneration;

    #[test]
    fn spawn_resets_signals_mask_fds_and_runs_synchronously() -> Result<(), SysError> {
        let mut p = FakePlatform::new()?;
        let d = limit(&mut p);
        p.spawn(
            TunnelGeneration::new(1).map_err(|_| SysError::Failed("fixture"))?,
            super::super::SpawnAttributes {
                default_signals: true,
                empty_signal_mask: true,
                cloexec_default: true,
                synchronous: true,
            },
            d,
        )?;
        assert_eq!(
            p.spawn_attributes,
            [SpawnAttributes {
                default_signals: true,
                empty_signal_mask: true,
                cloexec_default: true,
                synchronous: true
            }]
        );
        Ok(())
    }
    #[test]
    fn shared_pid_guard_and_checked_os_conversion_cover_signed_boundaries() -> Result<(), SysError>
    {
        let mut p = FakePlatform::new()?;
        let start = StartTime {
            seconds: 1,
            microseconds: 0,
        };
        for pid in [0, 1, p.helper.pid, platform::OS_PID_MAX + 1, u32::MAX] {
            assert!(!platform::process_kill_allowed(pid, p.helper.pid));
            assert!(!platform::group_kill_allowed(pid, p.helper.pgid));
            let d = limit(&mut p);
            assert!(p.kill_process(pid, start, d).is_err());
            let d = limit(&mut p);
            assert!(p.kill_group(pid, 222, start, d).is_err());
        }
        for pid in [2, 99, 101, platform::OS_PID_MAX] {
            assert!(platform::process_kill_allowed(pid, p.helper.pid));
            assert!(platform::checked_os_pid(pid).is_some_and(|p| p > 1));
        }
        assert_eq!(platform::checked_os_pid(u32::MAX), None);
        assert_eq!(platform::checked_os_pid(platform::OS_PID_MAX + 1), None);
        assert_eq!(p.signals, []);
        Ok(())
    }
}
