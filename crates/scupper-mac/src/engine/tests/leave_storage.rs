use super::*;
use crate::snapshot::{COPY_BYTES, CopyRead};

#[test]
fn leave_revokes_containment_during_slow_storage() {
    for lose_anchor in [false, true] {
        let mut e = joined();
        e.platform.inject(Call::Write(Copy::A), 1, Fault::WriteFail);
        e.apply(Event::InvalidateObservations { since: 100 });
        assert_eq!(e.mode, Mode::PersistBlocked);
        assert!(!e.emergency_loaded);
        for copy in [Copy::A, Copy::B] {
            e.platform
                .inject(Call::Write(copy), 1, Fault::StorageDelay(120));
        }
        if lose_anchor {
            e.platform.anchor = None;
        }
        let start = e.platform.calls.len();
        leave(&mut e, 2);
        for _ in 0..600 {
            tick(&mut e);
            assert!(!e.platform.calls[start..].iter().any(|call| matches!(
                call,
                Call::LoadAnchor | Call::EnablePf | Call::Flush | Call::Acquire
            )));
            if e.status().text.starts_with("left") {
                assert!(e.platform.anchor.is_none());
            }
        }
        // Finish the timed-out storage worker; Busy does not poll its result.
        if e.platform.outstanding.is_some() {
            let d = Deadline(e.platform.now() + 1);
            assert_eq!(e.platform.wait_write(d), WriteOutcome::Synced);
        }
        e.platform.clear_faults();
        elapse(&mut e, 90);
        assert_left(&mut e, 2);
    }
}

#[test]
fn failed_create_stub_is_repaired_without_manual_action() {
    for length in [0, COPY_BYTES / 2] {
        let mut e = fresh();
        e.platform.mutate(Mutation::MissingCopy(Copy::B));
        e.platform
            .inject(Call::Create(Copy::B), 1, Fault::CreateStub(length));
        e.repair_pending = Some((Copy::B, snapshot::encode(e.seq, &e.snapshot).unwrap()));
        e.storage_blocked = true;
        e.next_storage = e.platform.now();
        e.retry_storage();
        assert!(e.storage_blocked);
        assert_eq!(e.platform.copies[1].stub_len, Some(length));
        let d = Deadline(e.platform.now() + 1);
        assert!(matches!(
            e.platform.read_copy(Copy::B, d),
            CopyRead::Short(_)
        ));
        e.platform.clear_faults();
        let now = e.platform.now();
        e.platform.pause(Duration::from_secs(1), Deadline(now + 1));
        e.retry_storage();
        assert!(!e.storage_blocked);
        assert_eq!(e.platform.copies[1].stub_len, None);
        assert_eq!(read_snapshot(&mut e.platform, Copy::B), e.snapshot);
        assert!(e.platform.calls.contains(&Call::Write(Copy::B)));
    }
}
