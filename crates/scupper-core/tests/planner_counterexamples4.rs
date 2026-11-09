//! Regression tests for planner budget ownership (G1, G2).
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
fn restores_up(p: &Plan, name: &str) -> bool {
    p.steps
        .iter()
        .any(|s| matches!(s, Step::LinkCreate { link, phase: LinkPhase::Up } if link.name == name))
}

/// G1. F1 ends `closed_by_planner` when a plan *emits* `ForwardingOn`, and
/// `replan_after_failure` re-arms it only when the failed step *is* `ForwardingOn`.
/// Any other failure between the planner's own `ForwardingOff` and its `ForwardingOn`
/// (here a transient `FlushConntrack` failure; equally a failed `Contain` step, which
/// makes the executor skip the `ForwardingOn`) leaves forwarding closed by the planner
/// with ownership already given up. The replanned reopening is then charged to the
/// generic external-fight `forwarding` budget, although no external writer exists.
#[test]
fn g1_failure_before_the_planners_reopen_must_not_charge_the_forwarding_budget() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress/filter/9".into()]);
    let p = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(0),
    );
    assert_eq!(p.steps.first(), Some(&Step::ForwardingOff));
    assert!(
        p.steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert!(!p.budgets.closed_by_planner);
    // Everything up to the flush succeeds; the flush fails (Stop): forwarding stays off.
    let flush = p
        .steps
        .iter()
        .position(|s| *s == Step::FlushConntrack)
        .unwrap();
    let partial = run(&m, &p.steps[..flush]);
    assert!(partial.forwarding_off());
    let rp = replan_after_failure(
        &p.steps[flush],
        &d,
        &partial,
        &p.budgets,
        None,
        &p.debounce,
        at(2),
    );
    assert!(
        rp.steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert!(
        !rp.budgets.attempts.contains_key("forwarding"),
        "the planner's own closure was charged to the external-fight budget: {:?}",
        rp.budgets.attempts
    );
}

/// G2. F2 ends `downed_by_planner` only when the client link is *observed* up: the
/// exact shape F1 had for forwarding. After one ingress quarantine, an external actor
/// that sets wg0 down faster than the tick is never observed up, so every restore of
/// wg0 (link down, reconfigure, forwarding off, hardening, up, conntrack flush,
/// forwarding on) is free: `link:wg0` is never charged and `RepairSuppressed` never
/// fires. The control (same fighter, no prior quarantine) is suppressed after three.
fn link_fight(prior_quarantine: bool) -> (usize, bool, Budgets) {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    let (mut budgets, mut debounce) = (Budgets::default(), Debounce::default());
    let mut t = 0;
    if prior_quarantine {
        for _ in 0..2 {
            m.links_complete = false;
            let p = plan(&d, &m, &budgets, None, &debounce, at(t));
            m = run(&m, &p.steps);
            (budgets, debounce) = (p.budgets, p.debounce);
            t += 10;
        }
        assert_eq!(m.links["wg0"].up, Known::Value(false));
        m.links_complete = true;
    } else {
        m = m.apply(&Step::LinkDown { name: "wg0".into() });
    }
    let (mut restores, mut suppressed) = (0, false);
    for _ in 0..20 {
        let p = plan(&d, &m, &budgets, None, &debounce, at(t));
        restores += usize::from(restores_up(&p, "wg0"));
        suppressed |= p.steps.iter().any(|s| {
            matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { object }) if object == "link:wg0")
        });
        m = run(&m, &p.steps);
        (budgets, debounce) = (p.budgets, p.debounce);
        // The fighter downs the client link before the next observation.
        m = m.apply(&Step::LinkDown { name: "wg0".into() });
        t += 10;
    }
    (restores, suppressed, budgets)
}

#[test]
fn g2_link_fight_after_planner_quarantine_must_be_charged() {
    let (restores, suppressed, budgets) = link_fight(true);
    assert!(
        suppressed && restores <= 4,
        "client-link fight restored wg0 {restores} times in 200 s without suppression; \
         attempts {:?}, downed_by_planner {:?}",
        budgets.attempts,
        budgets.downed_by_planner
    );
}

#[test]
fn g2_control_link_fight_without_quarantine_is_suppressed() {
    let (restores, suppressed, _) = link_fight(false);
    assert!(suppressed && restores <= 4, "control: {restores} restores");
}
