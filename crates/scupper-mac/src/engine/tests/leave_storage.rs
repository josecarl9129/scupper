use super::*;

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
