//! Alert mapping, privacy, payload goldens and caller-clock policy boundaries.
#![allow(clippy::unwrap_used)]
use scupper_core::{
    alerts::*,
    config::{AlertSink as Settings, Severity},
};
fn settings(kind: &str) -> Settings {
    if kind == "ntfy" {
        serde_json::from_value(
            serde_json::json!({"kind":"ntfy","url_ref":"fixture-reference","min_severity":"info"}),
        )
        .unwrap()
    } else {
        serde_json::from_value(serde_json::json!({"kind":"webhook","preset":kind,"url_ref":"fixture-reference","min_severity":"warning"})).unwrap()
    }
}
fn firing(seq: u64, at: u64) -> Alert {
    map(OperationalEvent::Failover, seq, at)
}
#[test]
fn mapping_table_and_filter() {
    use AlertKey as K;
    use AlertState::{Firing, Resolved};
    use OperationalEvent as E;
    use Severity::{Critical, Info, Warning};
    for (event, key, severity, state, duration) in [
        (E::FailClosedStarted, K::FailClosed, Critical, Firing, 0),
        (
            E::FailClosedEnded(17),
            K::FailClosed,
            Critical,
            Resolved,
            17,
        ),
        (E::Failover, K::Failover, Warning, Firing, 0),
        (E::Failback, K::Failover, Warning, Resolved, 0),
        (E::Unprotected, K::Unprotected, Critical, Firing, 0),
        (E::ProtectionRestored, K::Unprotected, Critical, Resolved, 0),
        (E::RepairSuppressed, K::RepairSuppressed, Warning, Firing, 0),
        (E::RepairRestored, K::RepairSuppressed, Warning, Resolved, 0),
        (E::QuarantineSet, K::Quarantine, Critical, Firing, 0),
        (E::QuarantineCleared, K::Quarantine, Critical, Resolved, 0),
        (E::PersistenceFailed, K::Persistence, Warning, Firing, 0),
        (
            E::PersistenceRecovered,
            K::Persistence,
            Warning,
            Resolved,
            0,
        ),
        (E::Flapping, K::Flapping, Warning, Firing, 0),
    ] {
        let alert = map(event, 42, 100);
        assert_eq!(
            (alert.key, alert.severity, alert.state, alert.duration),
            (key, severity, state, duration)
        );
        assert_eq!((alert.seq, alert.at), (42, 100));
        assert!(eligible(&alert, Info));
        assert_eq!(eligible(&alert, Critical), severity == Critical);
        assert_eq!(eligible(&alert, Warning), severity != Info);
    }
    let info = Alert::test(100);
    assert!(eligible(&info, Info));
    assert!(!eligible(&info, Warning));
    assert!(!eligible(&info, Critical));
}

#[test]
fn ten_minute_incident_summary_survives_restart() {
    let mut c = Coalescer::default();
    assert_eq!(c.push(firing(1, 100)).len(), 1);
    assert_eq!(c.push(map(OperationalEvent::Failback, 2, 120)).len(), 0);
    assert_eq!(c.push(firing(3, 200)).len(), 0);
    assert_eq!(c.push(map(OperationalEvent::Failback, 4, 230)).len(), 0);
    let mut restored: Coalescer =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(restored.pending_seq(), Some(4));
    assert_eq!(restored.flush(699).len(), 0);
    let resolved = restored.flush(700);
    assert_eq!(resolved.len(), 1);
    assert_eq!(
        (resolved[0].state, resolved[0].duration, resolved[0].count),
        (AlertState::Resolved, 130, 2)
    );
    assert_eq!(restored.flush(701).len(), 0);
    assert_eq!(restored.push(firing(5, 701)).len(), 1);
}
#[test]
fn critical_bypasses_coalescing_only_and_bucket_refills_at_exact_boundary() {
    let mut c = Coalescer::default();
    let mut b = TokenBucket::new(10);
    for seq in 0..6 {
        let a = map(OperationalEvent::FailClosedStarted, seq, 10);
        assert_eq!(c.push(a).len(), usize::from(seq == 0));
        assert_eq!(b.take(10), seq < 5);
    }
    assert!(!b.take(309));
    assert!(b.take(310));
    assert!(!b.take(310));
    assert!(!b.take(5));
    for _ in 0..5 {
        assert!(b.take(1810));
    }
    assert!(!b.take(1810));
}
#[test]
fn retry_and_status_boundaries() {
    assert_eq!(
        (0..10).map(backoff).collect::<Vec<_>>(),
        vec![5, 10, 20, 40, 80, 160, 320, 640, 900, 900]
    );
    assert_eq!(backoff(u32::MAX), 900);
    assert!(!exhausted(100, 86499));
    assert!(exhausted(100, 86500));
    assert!(!exhausted(100, 99));
    for code in 100..600 {
        assert_eq!(
            http_status(code),
            match code {
                200..=299 => Ok(()),
                408 | 429 | 500..=599 => Err(SinkError::Transient),
                _ => Err(SinkError::Permanent),
            }
        );
    }
}
#[test]
fn golden_presets() {
    let a = map(OperationalEvent::FailClosedEnded(17), 42, 100);
    for (kind, golden) in [
        (
            "ntfy",
            include_str!("../../../tests/golden/alerts/ntfy.json"),
        ),
        (
            "generic",
            include_str!("../../../tests/golden/alerts/generic.json"),
        ),
        (
            "telegram",
            include_str!("../../../tests/golden/alerts/telegram.json"),
        ),
        (
            "pushover",
            include_str!("../../../tests/golden/alerts/pushover.json"),
        ),
    ] {
        let actual = serde_json::to_value(render(&settings(kind), &a)).unwrap();
        let expected: serde_json::Value = serde_json::from_str(golden).unwrap();
        assert_eq!(actual, expected, "{kind}");
    }
}
proptest::proptest! {
    #[test]
    fn bucket_never_exceeds_burst_plus_elapsed_refills(times in proptest::collection::vec(0u64..10000,1..200)) {
        let mut b=TokenBucket::new(0);let mut times=times;times.sort_unstable();let mut delivered=0;
        for time in times {if b.take(time) {delivered+=1;}proptest::prop_assert!(delivered<=5+time/300);}
    }
}

#[test]
fn successful_repairs_resolve_only_a_previously_suppressed_incident() {
    let mut c = Coalescer::default();
    assert_eq!(
        c.push(map(OperationalEvent::RepairRestored, 1, 100)).len(),
        0
    );
    assert_eq!(
        c.push(map(OperationalEvent::RepairSuppressed, 2, 110))
            .len(),
        1
    );
    assert_eq!(
        c.push(map(OperationalEvent::RepairRestored, 3, 120)).len(),
        0
    );
    let ready = c.flush(710);
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].key, AlertKey::RepairSuppressed);
    assert_eq!(ready[0].state, AlertState::Resolved);
    assert_eq!(ready[0].duration, 10);
}

#[test]
fn active_incident_can_notify_again_after_ten_minutes_without_losing_duration() {
    let mut c = Coalescer::default();
    assert_eq!(c.push(firing(1, 100)).len(), 1);
    assert_eq!(c.push(firing(2, 699)).len(), 0);
    let repeated = c.push(firing(3, 700));
    assert_eq!(repeated.len(), 1);
    assert_eq!(repeated[0].count, 3);
    assert_eq!(c.push(map(OperationalEvent::Failback, 4, 701)).len(), 0);
    assert_eq!(c.flush(1299).len(), 0);
    let resolved = c.flush(1300);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].duration, 601);
    assert_eq!(resolved[0].count, 3);
}

#[test]
fn critical_incidents_deduplicate_and_recover_with_monotonic_duration() {
    let mut c = Coalescer::default();
    assert_eq!(
        c.push_at(map(OperationalEvent::Unprotected, 1, 9000), 10)
            .len(),
        1
    );
    assert_eq!(c.push_at(map(OperationalEvent::Unprotected, 2, 1), 20), []);
    let resolved = c.push_at(map(OperationalEvent::ProtectionRestored, 3, 0), 130);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].duration, 120);
    assert_eq!(
        c.push_at(map(OperationalEvent::ProtectionRestored, 4, 0), 140),
        []
    );
    assert_eq!(
        c.push_at(map(OperationalEvent::Unprotected, 5, 0), 150)
            .len(),
        1
    );
}

#[test]
#[cfg(feature = "testing")]
fn shortened_lab_hold_is_never_loaded_as_production_policy() {
    let mut c = Coalescer::default();
    c.set_test_hold(2);
    c.push_at(map(OperationalEvent::Failover, 1, 0), 0);
    c.push_at(map(OperationalEvent::Failback, 2, 0), 1);
    let mut restored: Coalescer =
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(c.flush(2).len(), 1);
    assert_eq!(restored.flush(2), []);
    assert_eq!(restored.flush(600).len(), 1);
}
