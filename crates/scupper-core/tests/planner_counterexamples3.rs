//! Counterexamples for the M2-2l second fix round (third review).
//! Each test asserts the behaviour requested by the review (F1-F4).
#![allow(clippy::unwrap_used)]
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    failover::MonoTime,
    planner::*,
    render::{RouteTarget, VersionStamp},
    verdict::v2::Selection,
};
use std::time::Duration;
fn at(seconds: u64) -> MonoTime {
    MonoTime(Duration::from_secs(seconds))
}
fn desired() -> Desired {
    let site = validate(parse_site(include_str!("fixtures/site-m2.toml")).unwrap()).unwrap();
    let gateway = GatewayId("gw1".into());
    let target = RouteTarget::Exit(site.gateway(&gateway).unwrap().exits()[0].ifname().clone());
    Desired::new(
        &site,
        &gateway,
        &VersionStamp {
            version: 43,
            sha256: [3; 32],
        },
        [7; 32],
        &target,
        &Selection::Auto,
    )
    .unwrap()
}
fn run(m: &KernelModel, steps: &[Step]) -> KernelModel {
    steps.iter().fold(m.clone(), |m, s| m.apply(s))
}

/// F1. `closed_by_planner` is cleared only when forwarding is *observed* on. After any one
/// planner closure (boot, a ruleset flake, a reload, link work), an external writer that zeroes
/// `ip_forward` faster than the tick is never observed "on", so every restore is free: the
/// "forwarding" budget is never charged and `RepairSuppressed` never fires, while each cycle
/// flushes conntrack. The identical fighter without a prior planner closure is suppressed
/// after three restores. Ownership of the closure must end at the planner's own reopening.
#[test]
fn f1_external_forwarding_fight_after_a_planner_close_is_never_charged() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    let (mut budgets, mut debounce) = (Budgets::default(), Debounce::default());
    // One ruleset read flake: the planner closes forwarding (correct, uncharged).
    m.ruleset = Known::Unknown;
    let p = plan(&d, &m, &budgets, None, &debounce, at(0));
    m = run(&m, &p.steps);
    (budgets, debounce) = (p.budgets, p.debounce);
    m.ruleset = Known::Value(Ruleset::Verified(d.fingerprint()));
    let mut reopenings = 0;
    let mut suppressed = false;
    for k in 1..=20_u64 {
        let p = plan(&d, &m, &budgets, None, &debounce, at(k * 10));
        reopenings += usize::from(
            p.steps
                .iter()
                .any(|s| matches!(s, Step::ForwardingOn { .. })),
        );
        suppressed |= p.steps.iter().any(|s| {
            matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { object }) if object == "forwarding")
        });
        m = run(&m, &p.steps);
        (budgets, debounce) = (p.budgets, p.debounce);
        // The fighter zeroes the global gate before the next observation.
        m.forwarding_v4 = Known::Value(0);
    }
    assert!(
        suppressed && reopenings <= 4,
        "external forwarding fight restored {reopenings} times in 200 s without suppression; \
         attempts {:?}, closed_by_planner {}",
        budgets.attempts,
        budgets.closed_by_planner
    );
}

/// F2. The A2 root cause remains for the client link: the planner's own ingress quarantine
/// (`LinkDown` wg0 on the second Unknown-inventory tick) is charged to `link:wg0` when the
/// planner brings wg0 back. Four two-tick inventory outages in ten minutes exhaust the budget
/// and wg0 stays down (every client cut) for the rest of the window, with no external drift.
#[test]
fn f2_planner_ingress_quarantine_must_not_exhaust_the_client_link_budget() {
    let d = desired();
    let client = "wg0";
    let mut m = KernelModel::desired(&d);
    let (mut budgets, mut debounce) = (Budgets::default(), Debounce::default());
    let mut t = 0_u64;
    for outage in 0..4 {
        for _ in 0..2 {
            m.links_complete = false;
            let p = plan(&d, &m, &budgets, None, &debounce, at(t));
            m = run(&m, &p.steps);
            (budgets, debounce) = (p.budgets, p.debounce);
            t += 10;
        }
        assert_eq!(
            m.links[client].up,
            Known::Value(false),
            "quarantine expected"
        );
        m.links_complete = true;
        for _ in 0..4 {
            let p = plan(&d, &m, &budgets, None, &debounce, at(t));
            m = run(&m, &p.steps);
            (budgets, debounce) = (p.budgets, p.debounce);
            t += 10;
        }
        assert_eq!(
            m.links[client].up,
            Known::Value(true),
            "outage {outage} (t={t}s): client link left down after inventory recovered; \
             attempts {:?}",
            budgets.attempts
        );
        assert!(budgets.attempts.is_empty(), "{:?}", budgets.attempts);
        assert!(budgets.downed_by_planner.is_empty());
    }
}

/// F3. `StepFailure` has two values but the executor needs three behaviours: a failed
/// containment step (`TcDelete`, `LinkDown`, `ForwardingOff`) must block every later Stop step,
/// a failed Emit/PersistLatch must not. Both report `Continue`, so the policy is not
/// "intrinsic to Step" (the suite's own `failure_state` needs a `matches!` on the variant).
/// An executor written against the enum (`Stop => break, Continue => continue`) runs the
/// same-plan reopen after a failed `TcDelete`: `[ForwardingOff, TcDelete(fails), ..,
/// FlushConntrack, ForwardingOn]` reopens with the hook still on wg0.
#[test]
fn f3_failure_policy_must_distinguish_containment_from_non_fatal_steps() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress/filter/9".into()]);
    let p = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(1),
    );
    let fail = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::TcDelete { .. }))
        .unwrap();
    // Enum-only executor: skip a failed Continue step, stop only on a failed Stop step.
    let end = p
        .steps
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != fail)
        .fold(m.clone(), |m, (_, s)| m.apply(s));
    let reopened_with_hook =
        end.forwarding_v4 == Known::Value(1) && end.links["wg0"].tc_hooks != Known::Value(vec![]);
    let emit = Step::Emit(PlannerEvent::ObservationUnknown);
    assert!(
        !reopened_with_hook || p.steps[fail].failure() != emit.failure(),
        "TcDelete and Emit share {:?}; an enum-driven executor reopens with the hook: {:?}",
        emit.failure(),
        p.steps
    );
}

/// F4. DESIGN §7 and ADR 0031 (as amended 2026-11-09) order a new latch as: hold in memory,
/// forwarding 0, tighten the drift away, *then* persist. The code persists before tightening.
/// `forwarding=0` does not stop a tc `mirred` redirect (the `safe()` doc says so), so on a
/// stalled disk the synchronous fsync in `PersistLatch` keeps a foreign link up and a tc
/// bypass live for as long as the write hangs. Since Tighten steps are now `Continue`, a failed
/// `TcDelete` no longer skips a later `PersistLatch`, so the round-2 reason (A3) for moving it
/// first is gone; the every-plan retry covers the remaining loss case.
#[test]
fn f4_latch_persistence_must_follow_tightening_as_design_specifies() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress/mirred/1".into()]);
    let mut b = Budgets::default();
    b.attempts
        .insert(SafetyClass::TcHook.key().into(), vec![at(0); 3]);
    let p = plan(&d, &m, &b, None, &Debounce::default(), at(1));
    assert!(p.latch.is_some());
    let persist = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::PersistLatch { .. }))
        .unwrap();
    let last_tighten = p
        .steps
        .iter()
        .rposition(|s| matches!(s, Step::TcDelete { .. } | Step::LinkDown { .. }))
        .unwrap();
    assert!(
        persist > last_tighten,
        "PersistLatch (step {persist}) runs before the tc bypass is removed (step {last_tighten}): {:?}",
        &p.steps[..=last_tighten]
    );
}

/// Incomplete inventory cannot establish that the configured ingress is absent.
#[test]
fn omitted_client_is_quarantined_and_retried_unless_positively_contained() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.remove("wg0");
    m.links_complete = false;
    let first = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(0),
    );
    let down = Step::LinkDown { name: "wg0".into() };
    assert!(first.steps.contains(&down));
    m = run(&m, &first.steps);
    let second = plan(&d, &m, &first.budgets, None, &first.debounce, at(10));
    assert!(second.steps.contains(&down));
    assert!(second.budgets.downed_by_planner.contains("wg0"));
    assert!(
        first
            .steps
            .contains(&Step::Emit(PlannerEvent::IngressQuarantined))
    );
    let retry = plan(&d, &m, &second.budgets, None, &second.debounce, at(20));
    assert!(retry.steps.contains(&down));
    assert!(
        !retry
            .steps
            .contains(&Step::Emit(PlannerEvent::IngressQuarantined))
    );

    // A positive down observation stops retries, even with incomplete inventory.
    m.links
        .insert("wg0".into(), KernelModel::desired(&d).links["wg0"].clone());
    m = m.apply(&down);
    let contained = plan(&d, &m, &retry.budgets, None, &retry.debounce, at(30));
    assert!(!contained.steps.contains(&down));

    // A complete link dump establishes absence, despite an unknown tc dump.
    m.links.remove("wg0");
    m.links_complete = true;
    let exit = d.exits().values().next().unwrap();
    m.links.get_mut(exit).unwrap().tc_hooks = Known::Unknown;
    let absent = plan(
        &d,
        &m,
        &contained.budgets,
        None,
        &contained.debounce,
        at(40),
    );
    assert!(absent.debounce.ingress_quarantined);
    assert!(!absent.steps.contains(&down));
}

#[test]
fn quarantine_ownership_does_not_exempt_configuration_drift() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links_complete = false;
    let first = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(0),
    );
    m = run(&m, &first.steps);
    let second = plan(&d, &m, &first.budgets, None, &first.debounce, at(10));
    m = run(&m, &second.steps);
    assert!(second.budgets.downed_by_planner.contains("wg0"));
    m.links_complete = true;
    m.links.get_mut("wg0").unwrap().addresses = Known::Value(vec![]);
    let warm = plan(&d, &m, &second.budgets, None, &second.debounce, at(20));
    let restore = plan(&d, &m, &warm.budgets, None, &warm.debounce, at(30));
    assert_eq!(restore.budgets.attempts["link:wg0"], vec![at(20), at(30)]);
    m = run(&m, &restore.steps);
    assert_eq!(m.links["wg0"].up, Known::Value(true));
    let recovered = plan(&d, &m, &restore.budgets, None, &restore.debounce, at(40));
    assert!(recovered.budgets.downed_by_planner.is_empty());
}

#[test]
fn failed_reopening_rearms_ownership_and_issued_retry_ends_it() {
    let d = desired();
    let m = KernelModel::desired(&d).apply(&Step::ForwardingOff);
    let budgets = Budgets {
        closed_by_planner: true,
        ..Budgets::default()
    };
    let warm = plan(&d, &m, &budgets, None, &Debounce::default(), at(0));
    let reopen = plan(&d, &m, &warm.budgets, None, &warm.debounce, at(10));
    let on = Step::ForwardingOn {
        requires: d.fingerprint(),
    };
    assert!(reopen.steps.contains(&on));
    assert!(!reopen.budgets.closed_by_planner);
    assert!(reopen.budgets.attempts.is_empty());
    // The write failed: the fresh observation still has all gates closed.
    let retry = replan_after_failure(&on, &d, &m, &reopen.budgets, None, &reopen.debounce, at(20));
    assert!(retry.steps.contains(&on));
    assert!(retry.budgets.attempts.is_empty());
    assert!(!retry.budgets.closed_by_planner);
    // An external closure after the issued retry is charged, even if no tick saw UP.
    let fight = plan(&d, &m, &retry.budgets, None, &retry.debounce, at(30));
    assert_eq!(fight.budgets.attempts["forwarding"], vec![at(30)]);
}
