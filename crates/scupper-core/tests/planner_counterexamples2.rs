//! Counterexamples for the M2-2l fix round (planner re-review).
#![allow(clippy::unwrap_used)]
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    failover::MonoTime,
    planner::*,
    render::{RouteTarget, VersionStamp},
    verdict::v2::{
        DefaultRouteObs, DefaultRoutes, Forwarding, LinkObs, NetnsIdentity, NetnsObs, RulesetObs,
        Selection, TopologyObs,
    },
};
use std::{collections::BTreeMap, time::Duration};
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
fn exhausted(class: SafetyClass) -> Budgets {
    let mut b = Budgets::default();
    b.attempts.insert(class.key().into(), vec![at(0); 3]);
    b
}

/// N1a. An exhausted stale-exit Restore budget must not cut client flows.
#[test]
fn n1a_stale_exit_budget_must_not_close_a_safe_gateway() {
    let d = desired();
    let exit = d.exits().keys().next().unwrap().clone();
    let mut m = KernelModel::desired(&d);
    let (mut budgets, mut debounce) = (Budgets::default(), Debounce::default());
    for k in 0..8_u64 {
        m.stale_exits.insert(exit.clone());
        assert!(safe(&m, &d));
        let p = plan(&d, &m, &budgets, None, &debounce, at(k * 2));
        assert!(
            !p.steps.contains(&Step::ForwardingOff),
            "tick {k}: a stale exit closed every client flow: {:?}",
            p.steps
        );
        m = run(&m, &p.steps);
        (budgets, debounce) = (p.budgets, p.debounce);
    }
}

/// N1b. Transient Unknown rulesets close forwarding without spending its budget.
#[test]
fn n1b_unknown_ruleset_flakes_must_not_exhaust_the_forwarding_budget() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    let (mut budgets, mut debounce) = (Budgets::default(), Debounce::default());
    for flake in 0..4_u64 {
        let base = flake * 60;
        m.ruleset = Known::Unknown;
        let p = plan(&d, &m, &budgets, None, &debounce, at(base));
        m = run(&m, &p.steps);
        (budgets, debounce) = (p.budgets, p.debounce);
        for t in 1..=4_u64 {
            m.ruleset = Known::Value(Ruleset::Verified(d.fingerprint()));
            let p = plan(&d, &m, &budgets, None, &debounce, at(base + 2 * t));
            m = run(&m, &p.steps);
            (budgets, debounce) = (p.budgets, p.debounce);
        }
        assert_eq!(
            m.forwarding_v4,
            Known::Value(1),
            "flake {flake}: gateway still closed 8 s after recovery; budgets {:?}",
            budgets.attempts
        );
        assert!(!budgets.attempts.contains_key("forwarding"));
    }
}

/// N2. Failed tightening must still allow later latch persistence, and a
/// memory-only latch is retried if that persistence attempt also fails.
#[test]
fn n2_latch_must_still_be_persisted_after_a_failed_tightening_step() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress/filter/9".into()]);
    let p = plan(
        &d,
        &m,
        &exhausted(SafetyClass::TcHook),
        None,
        &Debounce::default(),
        at(1),
    );
    let memory = p.latch.clone().expect("new latch");
    let fail = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::TcDelete { .. }))
        .unwrap();
    let persist = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::PersistLatch { .. }))
        .unwrap();
    assert!(fail < persist);
    assert_eq!(p.steps[fail].failure(), StepFailure::Contain);
    assert_eq!(p.steps[persist].failure(), StepFailure::NonFatal);
    // A containment failure skips Restore, but still reaches persistence.
    let persisted = p
        .steps
        .iter()
        .enumerate()
        .filter(|(i, s)| *i != fail && (*i < fail || s.failure() != StepFailure::Stop))
        .fold(m.clone(), |m, (_, s)| m.apply(s));
    assert_eq!(persisted.latch.as_ref(), Some(&memory));
    assert_eq!(persisted.links["wg0"].tc_hooks, m.links["wg0"].tc_hooks);
    // Both tc deletion and persistence fail; retain and retry the memory latch.
    let partial = p
        .steps
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            *i != fail && *i != persist && (*i < fail || s.failure() != StepFailure::Stop)
        })
        .fold(m.clone(), |m, (_, s)| m.apply(s));
    assert!(partial.latch.is_none());
    let recovery = replan_after_failure(
        &p.steps[fail],
        &d,
        &partial,
        &p.budgets,
        Some(&memory),
        &p.debounce,
        at(2),
    );
    assert!(
        recovery
            .steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. })),
        "memory latch is never persisted: {:?}",
        recovery.steps
    );
}

/// N3. Recreating an exit must restore its IPv4 ingress gate in the same plan.
#[test]
fn n3_recreated_exit_must_forward_replies_when_the_plan_ends() {
    let d = desired();
    let exit = d.exits().values().next().unwrap().clone();
    let mut m = KernelModel::desired(&d);
    m.links.remove(&exit);
    m.default_v4 = Known::Value(DefaultRouteObs::Missing);
    let (mut budgets, mut debounce) = (Budgets::default(), Debounce::default());
    for k in 0..3_u64 {
        let p = plan(&d, &m, &budgets, None, &debounce, at(k * 2));
        let recreated = p.steps.iter().any(
            |s| matches!(s, Step::LinkCreate { phase: LinkPhase::Up, link } if link.name == exit),
        );
        m = run(&m, &p.steps);
        (budgets, debounce) = (p.budgets, p.debounce);
        if recreated {
            assert_eq!(m.forwarding_v4, Known::Value(1));
            assert_eq!(
                m.links[&exit].forwarding_v4,
                Known::Value(1),
                "exit is up and routed but replies to clients are dropped"
            );
            assert!(!budgets.attempts.contains_key("forwarding"));
            return;
        }
    }
    panic!("exit never recreated");
}

/// N4. A replaced name must not stop containment of the live held namespace.
#[test]
fn n4_wrong_name_with_live_held_inode_must_still_tighten() {
    let d = desired();
    let good = KernelModel::desired(&d);
    let topology = TopologyObs {
        host_wireguard_on_client_port: vec![],
        errors: vec![],
        links_complete: true,
        addresses_complete: true,
        netns: NetnsObs::WrongInode,
        links: good
            .links
            .iter()
            .map(|(name, l)| LinkObs {
                name: name.clone(),
                kind: l.kind.value().cloned(),
                up: *l.up.value().unwrap(),
                addresses: l.addresses.value().unwrap().clone(),
            })
            .collect(),
        peers: good
            .links
            .iter()
            .map(|(name, l)| (name.clone(), l.peers.value().unwrap().clone()))
            .collect(),
        ruleset: RulesetObs::Exact,
        extra_rules: vec![],
        tc_hooks: vec![],
    };
    let forwarding = Forwarding {
        client_v4: 1,
        netns_sockets: vec![],
        v4: 1,
        hardening: vec![],
        v6: 1,
        quarantine: None,
        client_public_key: Some([0; 32]),
        listen_port: 51820,
        host_sockets: vec![],
        client_handshakes: BTreeMap::new(),
    };
    let gates = ForwardingGates {
        default_v4: Known::Value(1),
        default_v6: Known::Value(1),
        links: good
            .links
            .keys()
            .map(|name| (name.clone(), [Known::Value(1), Known::Value(1)]))
            .collect(),
    };
    let defaults = DefaultRoutes {
        violations: vec![],
        v4: good.default_v4.value().unwrap().clone(),
        v6: DefaultRouteObs::Unreachable,
        extra: vec![],
    };
    let mut details = ObservationDetails {
        hardening: d
            .hardening()
            .iter()
            .map(|s| (s.key.to_string(), Ok(s.value.clone())))
            .collect(),
        settings: d
            .links()
            .iter()
            .map(|(name, l)| (name.clone(), Ok(l.settings.clone())))
            .collect(),
        owned_links: d.links().keys().cloned().collect(),
        expected_netns: Some(NetnsIdentity {
            device: 1,
            inode: 2,
        }),
        held_inode_alive: true,
        ..ObservationDetails::default()
    };
    details
        .tc_hooks
        .insert("wg0".into(), Ok(vec!["ingress/mirred-to-veth0".into()]));
    let m = KernelModel::from_observations(
        &topology,
        &Ok(forwarding),
        &gates,
        &Ok(defaults),
        &d,
        &details,
    );
    let p = plan(
        &d,
        &m,
        &Budgets::default(),
        None,
        &Debounce::default(),
        at(0),
    );
    assert!(
        p.steps.contains(&Step::ForwardingOff)
            && p.steps.iter().any(|s| matches!(s, Step::TcDelete { .. })),
        "live held namespace left untouched: namespace={:?} steps={:?} escalations={:?}",
        m.namespace,
        p.steps,
        p.escalations
    );
}

/// N5. Clearing a clean namespace must reset pending safety and its reservations.
#[test]
fn n5_repair_clear_on_a_clean_namespace_must_not_relatch() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress/filter/1".into()]);
    let p = plan(
        &d,
        &m,
        &exhausted(SafetyClass::TcHook),
        None,
        &Debounce::default(),
        at(1),
    );
    let latch = p.latch.clone().expect("latched");
    m = run(&m, &p.steps);
    assert!(safe(&m, &d), "hook removed, gateway closed");
    let cleared = clear_latch(&latch, ClearLatch::RepairClear, &p.budgets);
    assert!(cleared.latch.is_none());
    m.latch = None;
    let after = plan(&d, &m, &cleared.budgets, None, &p.debounce, at(60));
    assert!(
        after.latch.is_none(),
        "clean namespace re-latched right after repair clear: pending={:?} steps={:?}",
        cleared.budgets.pending_safety,
        after.steps
    );
}
