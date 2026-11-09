//! Counterexamples for the M2-2l planner review.
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
fn foreign(d: &Desired) -> KernelLink {
    let mut link = KernelModel::desired(d).links["wg0"].clone();
    link.kind = Known::Value("veth".into());
    link.ours = Known::Value(false);
    link
}
fn run(m: &KernelModel, steps: &[Step]) -> KernelModel {
    steps.iter().fold(m.clone(), |m, s| m.apply(s))
}
fn exhausted(class: SafetyClass) -> Budgets {
    let mut b = Budgets::default();
    b.attempts.insert(class.key().into(), vec![at(0); 3]);
    b
}
/// CE1. A mirred hook acts below the forwarding gate and must still be removed.
#[test]
fn ce1_tc_suppression_must_still_remove_the_hook() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress/mirred-to-veth0".into()]);
    let p = plan(
        &d,
        &m,
        &exhausted(SafetyClass::TcHook),
        None,
        &Debounce::default(),
        at(1),
    );
    let end = run(&m, &p.steps);
    assert!(end.forwarding_off());
    assert!(
        safe(&end, &d),
        "suppression ended with the tc hook still installed: {:?}",
        end.links["wg0"].tc_hooks
    );
}
/// CE2. Recurring foreign links must still be set down after suppression.
#[test]
fn ce2_foreign_link_suppression_must_still_set_it_down() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.insert("veth0".into(), foreign(&d));
    let p = plan(
        &d,
        &m,
        &exhausted(SafetyClass::ForeignLink),
        None,
        &Debounce::default(),
        at(1),
    );
    let end = run(&m, &p.steps);
    assert!(end.forwarding_off());
    assert!(
        safe(&end, &d),
        "foreign link left up: {:?}",
        end.links["veth0"].up
    );
}
/// CE3. A host name collision must not freeze namespace tightening.
#[test]
fn ce3_host_collision_must_not_suppress_netns_tightening() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.insert("veth0".into(), foreign(&d));
    m.host_links.insert("wg0".into(), foreign(&d));
    assert!(!safe(&m, &d));
    let p = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(1),
    );
    assert_eq!(p.escalations, [Escalation::HostLinkCollision("wg0".into())]);
    let end = run(&m, &p.steps);
    assert!(
        end.forwarding_off() || safe(&end, &d),
        "plan left an unsafe namespace open: {:?}",
        p.steps
    );
}
/// CE4. Edge being elsewhere must not freeze namespace tightening.
#[test]
fn ce4_edge_elsewhere_must_not_suppress_netns_tightening() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress".into()]);
    m.namespace = NamespaceState::EdgeElsewhere;
    let p = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(1),
    );
    assert!(
        p.steps.contains(&Step::ForwardingOff),
        "no tightening while edge is elsewhere: {:?}",
        p.steps
    );
}
/// CE5. No executed prefix persists quarantine with forwarding still open.
#[test]
fn ce5_no_prefix_is_latched_and_forwarding() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.insert("veth0".into(), foreign(&d));
    let p = plan(
        &d,
        &m,
        &exhausted(SafetyClass::ForeignLink),
        None,
        &Debounce::default(),
        at(1),
    );
    let mut cur = m.clone();
    for (i, s) in p.steps.iter().enumerate() {
        cur = cur.apply(s);
        let open = [
            &cur.forwarding_v4,
            &cur.forwarding_v6,
            &cur.client_forwarding_v4,
        ]
        .contains(&&Known::Value(1));
        assert!(
            !(open && cur.latch.is_some()),
            "prefix {i} ({s:?}) is latched with forwarding still 1"
        );
    }
}
/// CE6. Fresh tc identities must share a namespace-wide fighting budget.
#[test]
fn ce6_tc_identity_churn_must_eventually_latch() {
    let d = desired();
    let mut budgets = Budgets::default();
    let mut debounce = Debounce::default();
    let mut latched = false;
    for k in 0..12_u64 {
        let mut m = KernelModel::desired(&d);
        m.links.get_mut("wg0").unwrap().tc_hooks =
            Known::Value(vec![format!("ingress/filter/{k}")]);
        let p = plan(&d, &m, &budgets, None, &debounce, at(k * 10));
        latched |= p
            .steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. }));
        budgets = p.budgets;
        debounce = p.debounce;
    }
    assert!(latched, "12 tc re-adds in 2 minutes never latched");
}
/// CE7. Transient Unknown rulesets close forwarding without counting as fighting.
#[test]
fn ce7_transient_unknown_ruleset_must_not_latch() {
    let d = desired();
    let mut budgets = Budgets::default();
    let mut latched = false;
    for k in 0..4_u64 {
        let mut m = KernelModel::desired(&d);
        m.ruleset = Known::Unknown;
        let p = plan(&d, &m, &budgets, None, &Debounce::default(), at(k * 60));
        latched |= p
            .steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. }));
        budgets = p.budgets;
    }
    assert!(!latched, "four collector flakes set the quarantine latch");
}
