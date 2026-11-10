//! DESIGN §7 row tables, failure boundaries, quarantine and generated safety.
#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use scupper_core::{
    config::{ExitId, GatewayId, parse_site, validate},
    failover::MonoTime,
    planner::*,
    render::{Family, RouteTarget, VersionStamp},
    verdict::v2::{
        DefaultRouteObs, DefaultRoutes, Forwarding, LinkObs, NetnsIdentity, NetnsObs, ProbeError,
        RulesetObs, Selection, TopologyObs,
    },
};
use std::{collections::BTreeMap, time::Duration};
fn at(seconds: u64) -> MonoTime {
    MonoTime(Duration::from_secs(seconds))
}
fn desired() -> Desired {
    desired_with("ch1", [7; 32], &Selection::Auto)
}
fn desired_with(exit: &str, fingerprint: Fingerprint, selection: &Selection) -> Desired {
    let site =
        validate(parse_site(&include_str!("fixtures/site-m2.toml").replace("ch1", exit)).unwrap())
            .unwrap();
    let gateway = GatewayId("gw1".into());
    let target = RouteTarget::Exit(site.gateway(&gateway).unwrap().exits()[0].ifname().clone());
    Desired::new(
        &site,
        &gateway,
        &VersionStamp {
            version: 43,
            sha256: [3; 32],
        },
        fingerprint,
        &target,
        selection,
    )
    .unwrap()
}
fn tick(d: &Desired, m: &KernelModel, debounce: &Debounce) -> Plan {
    plan(d, m, &Budgets::default(), None, debounce, at(0))
}
fn settled(d: &Desired, m: &KernelModel) -> Plan {
    let first = tick(d, m, &Debounce::default());
    plan(d, m, &first.budgets, None, &first.debounce, at(2))
}
fn harden(d: &Desired) -> Vec<Step> {
    d.hardening()
        .iter()
        .map(|s| Step::WriteSysctl {
            key: HardeningKey::new(s.key.clone()).unwrap(),
            value: s.value.clone(),
        })
        .chain([Step::ReadBackSysctls])
        .collect()
}
fn on(d: &Desired) -> Vec<Step> {
    [
        Step::FlushConntrack,
        Step::ForwardingOn {
            requires: d.fingerprint(),
        },
    ]
    .into_iter()
    .chain(harden(d))
    .collect()
}
fn load(d: &Desired) -> Vec<Step> {
    vec![
        Step::ForwardingOff,
        Step::LoadRuleset {
            fingerprint: d.fingerprint(),
            rendered: scupper_core::render::render_netns(
                &validate(parse_site(include_str!("fixtures/site-m2.toml")).unwrap()).unwrap(),
                &GatewayId("gw1".into()),
                &VersionStamp {
                    version: 43,
                    sha256: [3; 32],
                },
            )
            .unwrap(),
        },
        Step::VerifyRuleset {
            fingerprint: d.fingerprint(),
        },
    ]
    .into_iter()
    .chain(on(d))
    .collect()
}
fn extra_route() -> RouteKey {
    RouteKey {
        family:Family::V4,
        entry:scupper_core::parse::parse_ip_route(r#"[{"dst":"203.0.113.0/24","dev":"ex-ch1","type":"unicast","metric":100,"gateway":"10.2.0.1"}]"#).unwrap().remove(0),
    }
}
fn foreign(d: &Desired) -> KernelLink {
    let mut link = KernelModel::desired(d).links["wg0"].clone();
    link.kind = Known::Value("veth".into());
    link.ours = Known::Value(false);
    link
}
fn closed_steps(d: &Desired, middle: Vec<Step>) -> Vec<Step> {
    std::iter::once(Step::ForwardingOff)
        .chain(middle)
        .chain(harden(d))
        .collect()
}
fn reopen_steps(d: &Desired, steps: &[Step]) -> Vec<Step> {
    steps[..steps.len() - harden(d).len()]
        .iter()
        .cloned()
        .chain(on(d))
        .collect()
}
fn safety_event(object: &str) -> Step {
    Step::Emit(PlannerEvent::SafetyDrift {
        object: object.into(),
    })
}
fn recreate(d: &Desired, name: &str) -> Vec<Step> {
    let link = d.links()[name].clone();
    [
        LinkPhase::CleanupHost,
        LinkPhase::HostAddDown,
        LinkPhase::Move,
        LinkPhase::Configure,
    ]
    .into_iter()
    .map(|phase| Step::LinkCreate {
        link: link.clone(),
        phase,
    })
    .chain([Step::LinkForwardingOff { name: name.into() }])
    .chain(harden(d))
    .chain([Step::LinkCreate {
        link: link.clone(),
        phase: LinkPhase::Up,
    }])
    .collect()
}

#[test]
#[allow(clippy::too_many_lines)] // Keep all DESIGN rows together as an exact table.
fn repairs_table_exact_steps_and_classes() {
    type Case = (&'static str, KernelModel, Vec<Step>, Vec<Step>, RepairClass);
    let d = desired();
    let good = KernelModel::desired(&d);
    let mut cases: Vec<Case> = Vec::new();
    for rules in [Ruleset::Absent, Ruleset::Unverified([8; 32])] {
        let mut m = good.clone();
        m.ruleset = Known::Value(rules);
        cases.push((
            "ruleset missing/differs",
            m,
            load(&d),
            load(&d),
            RepairClass::Restore,
        ));
    }
    let mut m = good.clone();
    m.forwarding_v4 = Known::Value(0);
    m.forwarding_v6 = Known::Value(0);
    m.client_forwarding_v4 = Known::Value(0);
    cases.push(("forwarding", m, vec![], on(&d), RepairClass::Restore));
    let key = d.hardening()[0].key.clone();
    let mut m = good.clone();
    m.hardening
        .insert(key.to_string(), Known::Value("1".into()));
    cases.push((
        "hardening",
        m,
        vec![],
        vec![
            Step::WriteSysctl {
                key: HardeningKey::new(key).unwrap(),
                value: "0".into(),
            },
            Step::ReadBackSysctls,
        ],
        RepairClass::Restore,
    ));
    for observed in [DefaultRouteObs::Missing, DefaultRouteObs::Unreachable] {
        let mut m = good.clone();
        m.default_v4 = Known::Value(observed);
        cases.push((
            "missing/wrong route",
            m,
            vec![],
            vec![
                Step::RouteReplace {
                    family: Family::V4,
                    target: d.routes()[0].1.clone(),
                },
                Step::FlushConntrack,
            ],
            RepairClass::Restore,
        ));
    }
    let mut m = good.clone();
    m.extra_routes = Known::Value(vec![extra_route()]);
    let steps = vec![Step::RouteDelete {
        route: extra_route(),
    }];
    cases.push(("extra route", m, steps.clone(), steps, RepairClass::Tighten));
    let mut m = good.clone();
    m.links.remove("wg0");
    cases.push((
        "missing client link",
        m,
        vec![],
        recreate(&d, "wg0").into_iter().chain(on(&d)).collect(),
        RepairClass::Restore,
    ));
    let mut m = good.clone();
    m.links.get_mut("wg0").unwrap().addresses = Known::Value(vec![]);
    let mut down = d.links()["wg0"].clone();
    down.up = false;
    let steps = vec![
        Step::LinkDown { name: "wg0".into() },
        Step::LinkReconfigure { link: down },
        Step::LinkForwardingOff { name: "wg0".into() },
    ]
    .into_iter()
    .chain(harden(&d))
    .chain([Step::LinkCreate {
        link: d.links()["wg0"].clone(),
        phase: LinkPhase::Up,
    }])
    .chain(on(&d))
    .collect();
    cases.push(("address config", m, vec![], steps, RepairClass::Restore));
    let mut m = good.clone();
    m.links.get_mut("wg0").unwrap().peers = Known::Value(vec![]);
    let first = closed_steps(&d, vec![Step::LinkDown { name: "wg0".into() }]);
    let mut second = vec![
        Step::ForwardingOff,
        Step::LinkDown { name: "wg0".into() },
        Step::LinkDown { name: "wg0".into() },
    ];
    let mut down = d.links()["wg0"].clone();
    down.up = false;
    second.push(Step::LinkReconfigure { link: down });
    second.push(Step::LinkForwardingOff { name: "wg0".into() });
    second.extend(harden(&d));
    second.push(Step::LinkCreate {
        link: d.links()["wg0"].clone(),
        phase: LinkPhase::Up,
    });
    second.extend(on(&d));
    cases.push(("peer config", m, first, second, RepairClass::Restore));
    let mut m = good.clone();
    m.links.insert("foreign0".into(), foreign(&d));
    let steps = closed_steps(
        &d,
        vec![
            Step::LinkDown {
                name: "foreign0".into(),
            },
            safety_event("foreign-link:foreign0"),
        ],
    );
    cases.push((
        "foreign link",
        m,
        reopen_steps(&d, &steps),
        reopen_steps(&d, &steps),
        RepairClass::Tighten,
    ));
    let mut m = good.clone();
    m.extra_rules = Known::Value(vec!["100: lookup 42".into()]);
    let steps = closed_steps(
        &d,
        vec![Step::RuleDelete {
            rule: "100: lookup 42".into(),
        }],
    );
    cases.push((
        "extra RPDB rule",
        m,
        steps.clone(),
        steps,
        RepairClass::Tighten,
    ));
    let mut m = good.clone();
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress".into()]);
    let steps = closed_steps(
        &d,
        vec![
            Step::TcDelete {
                name: "wg0".into(),
                hook: "ingress".into(),
            },
            safety_event("tc:wg0:ingress"),
        ],
    );
    cases.push((
        "tc on owned link",
        m,
        reopen_steps(&d, &steps),
        reopen_steps(&d, &steps),
        RepairClass::Tighten,
    ));
    let mut m = good.clone();
    let mut link = foreign(&d);
    link.tc_hooks = Known::Value(vec!["ingress".into()]);
    m.links.insert("foreign0".into(), link);
    let steps = closed_steps(
        &d,
        vec![
            Step::LinkDown {
                name: "foreign0".into(),
            },
            safety_event("foreign-link:foreign0"),
            Step::TcDelete {
                name: "foreign0".into(),
                hook: "ingress".into(),
            },
            safety_event("tc:foreign0:ingress"),
        ],
    );
    cases.push((
        "tc on foreign link",
        m,
        reopen_steps(&d, &steps),
        reopen_steps(&d, &steps),
        RepairClass::Tighten,
    ));
    let mut m = good.clone();
    let mut leftover = good.links["wg0"].clone();
    leftover.up = Known::Value(false);
    leftover.addresses = Known::Value(vec![]);
    leftover.peers = Known::Value(vec![]);
    m.host_links.insert("wg0".into(), leftover);
    cases.push((
        "host leftover",
        m,
        vec![],
        vec![Step::LinkCreate {
            link: d.links()["wg0"].clone(),
            phase: LinkPhase::CleanupHost,
        }],
        RepairClass::Restore,
    ));
    let mut m = good.clone();
    m.stale_exits.insert(ExitId("ch1".into()));
    cases.push((
        "stale handshake",
        m,
        vec![],
        vec![Step::ReResolveEndpoint {
            exit: ExitId("ch1".into()),
        }],
        RepairClass::Restore,
    ));
    let mut m = good.clone();
    m.edge_dead = true;
    cases.push((
        "edge dead",
        m,
        vec![Step::Emit(PlannerEvent::EdgeDead)],
        vec![Step::Emit(PlannerEvent::EdgeDead)],
        RepairClass::Tighten,
    ));
    cases.push((
        "host-side state not repaired",
        good.clone(),
        vec![],
        vec![],
        RepairClass::Tighten,
    ));
    for (label, m, first, second, class) in cases {
        let p = tick(&d, &m, &Debounce::default());
        assert_eq!(p.steps, first, "first tick: {label}");
        let p2 = plan(&d, &m, &p.budgets, None, &p.debounce, at(2));
        assert_eq!(p2.steps, second, "second tick: {label}");
        if !p2.repairs.is_empty() {
            assert!(
                p2.repairs.iter().any(|r| r.class() == class),
                "class: {label}"
            );
        }
        assert_plan(&d, &m, &p2, None);
    }
    for (namespace, escalation) in [
        (NamespaceState::NameGone, Escalation::NamespaceNameGone),
        (NamespaceState::InodeGone, Escalation::NamespaceInodeGone),
        (
            NamespaceState::EdgeElsewhere,
            Escalation::EdgeInAnotherNamespace,
        ),
    ] {
        let mut m = good.clone();
        m.namespace = namespace;
        let p = settled(&d, &m);
        assert_eq!(p.steps, []);
        assert_eq!(p.escalations, [escalation]);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Compare both interrupted and fresh boot sequences in one fixture.
fn missing_exit_removed_from_route_before_recreation_and_fresh_build_matches_boot() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.remove("ex-ch1");
    let first = tick(&d, &m, &Debounce::default());
    assert_eq!(
        first.steps,
        closed_steps(
            &d,
            vec![Step::RouteReplace {
                family: Family::V4,
                target: RouteTarget::Unreachable
            }]
        ).into_iter().filter(|step| !matches!(step, Step::WriteSysctl {key, ..} if matches!(&key.sysctl().scope, scupper_core::render::Scope::Link(name) if name.as_str()=="ex-ch1"))).collect::<Vec<_>>()
    );
    let p = settled(&d, &m);
    let mut expected = vec![
        Step::ForwardingOff,
        Step::RouteReplace {
            family: Family::V4,
            target: RouteTarget::Unreachable,
        },
    ];
    expected.extend(recreate(&d, "ex-ch1"));
    expected.extend([
        Step::RouteReplace {
            family: Family::V4,
            target: d.routes()[0].1.clone(),
        },
        Step::FlushConntrack,
    ]);
    expected.push(Step::ForwardingOn {
        requires: d.fingerprint(),
    });
    expected.extend(harden(&d));
    assert_eq!(p.steps, expected);
    assert_plan(&d, &m, &p, None);
    m.links.clear();
    m.ruleset = Known::Value(Ruleset::Absent);
    m.default_v4 = Known::Value(DefaultRouteObs::Missing);
    m.default_v6 = Known::Value(DefaultRouteObs::Missing);
    let p = settled(&d, &m);
    let creation_order = p
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::LinkCreate {
                link,
                phase: LinkPhase::HostAddDown,
            } => Some(link.name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(creation_order, ["wg0", "ex-ch1"]);
    let off = p
        .steps
        .iter()
        .position(|s| *s == Step::ForwardingOff)
        .unwrap();
    let initial_read = p
        .steps
        .iter()
        .position(|s| *s == Step::ReadBackSysctls)
        .unwrap();
    let load = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::LoadRuleset { .. }))
        .unwrap();
    let verify = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::VerifyRuleset { .. }))
        .unwrap();
    let link = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::LinkCreate { .. }))
        .unwrap();
    let route = p
        .steps
        .iter()
        .position(|s| {
            matches!(
                s,
                Step::RouteReplace {
                    target: RouteTarget::Exit(_),
                    ..
                }
            )
        })
        .unwrap();
    let on = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::ForwardingOn { .. }))
        .unwrap();
    assert!(
        off < initial_read
            && initial_read < load
            && load < verify
            && verify < link
            && link < route
            && route < on
    );
    assert_plan(&d, &m, &p, None);
}

#[test]
fn budget_table_slides_and_safety_suppression_latches_first() {
    let d = desired();
    for object in [
        "safety:ruleset",
        "safety:foreign-link",
        "safety:tc-hook",
        "sysctl:net.ipv4.conf.all.rp_filter",
        "route:V4",
        "endpoint:ch1",
    ] {
        let mut m = KernelModel::desired(&d);
        match object {
            "safety:ruleset" => m.ruleset = Known::Value(Ruleset::Absent),
            "safety:foreign-link" => {
                m.links.insert("foreign0".into(), foreign(&d));
            }
            "safety:tc-hook" => {
                m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress".into()]);
            }
            "route:V4" => m.default_v4 = Known::Value(DefaultRouteObs::Missing),
            "endpoint:ch1" => {
                m.stale_exits.insert(ExitId("ch1".into()));
            }
            _ => {
                m.hardening
                    .insert(d.hardening()[0].key.to_string(), Known::Value("1".into()));
            }
        }
        let first = tick(&d, &m, &Debounce::default());
        let mut budgets = Budgets::default();
        for time in 0..3 {
            let p = plan(&d, &m, &budgets, None, &first.debounce, at(time));
            assert!(
                !p.steps
                    .contains(&Step::Emit(PlannerEvent::RepairSuppressed {
                        object: object.into()
                    })),
                "{object}"
            );
            assert_eq!(
                p.budgets.attempts[object].len(),
                usize::try_from(time + 1).unwrap()
            );
            budgets = p.budgets;
        }
        let p = plan(&d, &m, &budgets, None, &first.debounce, at(3));
        assert!(
            p.steps
                .contains(&Step::Emit(PlannerEvent::RepairSuppressed {
                    object: object.into()
                })),
            "{object}"
        );
        if matches!(
            object,
            "safety:ruleset" | "safety:foreign-link" | "safety:tc-hook"
        ) {
            assert!(
                p.steps.first() == Some(&Step::ForwardingOff)
                    && p.latch.as_ref().is_some_and(|l| l.object == object)
            );
        }
        if object.starts_with("safety:") {
            assert!(run(&m, &p.steps).forwarding_off());
        } else {
            assert!(!p.steps.contains(&Step::ForwardingOff));
        }
        assert_plan(&d, &m, &p, None);
        let p = plan(&d, &m, &budgets, None, &first.debounce, at(600));
        assert!(
            !p.steps
                .contains(&Step::Emit(PlannerEvent::RepairSuppressed {
                    object: object.into()
                }))
        );
        assert_eq!(p.budgets.attempts[object].len(), 3); // t=0 expired; t=1,2 remain.
    }
}

fn run(m: &KernelModel, steps: &[Step]) -> KernelModel {
    steps.iter().fold(m.clone(), |m, s| m.apply(s))
}
fn forwarding_invariant(d: &Desired, m: &KernelModel) -> bool {
    ![&m.forwarding_v4, &m.forwarding_v6, &m.client_forwarding_v4].contains(&&Known::Value(1))
        || m.ruleset == Known::Value(Ruleset::Verified(d.fingerprint())) && m.latch.is_none()
}
// Only unknown residue may remain after known bypasses have been removed.
fn closed_or_safe(d: &Desired, m: &KernelModel) -> bool {
    if safe(m, d) {
        return true;
    }
    if !m.forwarding_off() {
        return false;
    }
    let mut known = m.clone();
    let good = KernelModel::desired(d);
    known.namespace = NamespaceState::Ready; // Lifecycle escalation does not affect held-netns containment.
    known.links_complete = true;
    if known.ruleset == Known::Unknown {
        known.ruleset = Known::Value(Ruleset::Absent);
    }
    if known.extra_routes == Known::Unknown {
        known.extra_routes = Known::Value(vec![]);
    }
    if known.extra_rules == Known::Unknown {
        known.extra_rules = Known::Value(vec![]);
    }
    if known.default_v4 == Known::Unknown {
        known.default_v4 = good.default_v4;
    }
    if known.default_v6 == Known::Unknown {
        known.default_v6 = good.default_v6;
    }
    for (name, link) in &mut known.links {
        if link.tc_hooks == Known::Unknown {
            link.tc_hooks = Known::Value(vec![]);
        }
        if link.up == Known::Unknown {
            link.up = Known::Value(false);
        }
        if link.peers == Known::Unknown
            && let Some(want) = d.links().get(name)
        {
            link.peers = Known::Value(want.peers.clone());
        }
    }
    safe(&known, d)
}
fn assert_plan(d: &Desired, m: &KernelModel, p: &Plan, latch: Option<&Latch>) {
    if p.escalations.contains(&Escalation::NamespaceInodeGone) {
        return;
    }
    let latching = p
        .steps
        .iter()
        .any(|s| matches!(s, Step::PersistLatch { .. }));
    let mut current = m.clone();
    if let Some(latch) = latch {
        current.latch = Some(latch.clone());
    }
    let mut was_safe = safe(&current, d);
    let mut was_closed_or_safe = closed_or_safe(d, &current);
    if !was_safe && !current.forwarding_off() {
        assert_eq!(p.steps.first(), Some(&Step::ForwardingOff));
    }
    let mut verified = m.ruleset == Known::Value(Ruleset::Verified(d.fingerprint()));
    let mut invariant_seen = forwarding_invariant(d, &current);
    for (i, s) in p.steps.iter().enumerate() {
        if let Step::ForwardingOn { requires } = s {
            assert!(i > 0 && p.steps[i - 1] == Step::FlushConntrack);
            assert!(!latching && latch.is_none() && m.latch.is_none());
            assert!(verified);
            assert_eq!(*requires, d.fingerprint());
        }
        if let Step::VerifyRuleset { fingerprint } = s {
            verified = *fingerprint == d.fingerprint();
        }
        if let Step::RouteReplace {
            target: RouteTarget::Exit(name),
            ..
        } = s
        {
            assert!(d.exits().values().any(|n| n == name.as_str()));
        }
        if let Step::WriteSysctl { key, .. } = s
            && let scupper_core::render::Scope::Link(name) = &key.sysctl().scope
        {
            assert!(
                current.links.contains_key(name.as_str()),
                "sysctl targets missing link {name}"
            );
        }
        current = current.apply(s);
        if invariant_seen {
            assert!(forwarding_invariant(d, &current), "step {i}: {s:?}");
        }
        invariant_seen |= forwarding_invariant(d, &current);
        if was_safe {
            assert!(safe(&current, d), "unsafe prefix {i}: {s:?}");
        }
        was_safe |= safe(&current, d);
        if was_closed_or_safe {
            assert!(
                closed_or_safe(d, &current),
                "containment regressed at {i}: {s:?}"
            );
        }
        was_closed_or_safe |= closed_or_safe(d, &current);
        assert!(
            current.latch.is_none() || current.forwarding_off(),
            "latched open prefix {i}"
        );
        // Failure at i+1 is exactly this successful prefix (no rollback fantasy).
    }
    assert!(
        closed_or_safe(d, &current),
        "final state is neither safe nor closed: {p:?}"
    );
    if p.steps
        .iter()
        .any(|s| matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { object }) if object.starts_with("safety:")))
    {
        assert!(current.forwarding_off());
    }
}

// A Stop failure is a cut. A Contain failure skips every later Stop step,
// but executes every later Contain/NonFatal step, even after skipped Restores.
fn failure_state(d: &Desired, m: &KernelModel, p: &Plan, failed: usize) -> KernelModel {
    let mut current = m.clone();
    current.latch = p.latch.clone().or(current.latch);
    current = run(&current, &p.steps[..failed]);
    if p.steps[failed].failure() == StepFailure::Stop {
        return current;
    }
    let containment_failed = p.steps[failed].failure() == StepFailure::Contain;
    let mut contained = closed_or_safe(d, &current);
    for step in &p.steps[failed + 1..] {
        if containment_failed && step.failure() == StepFailure::Stop {
            continue;
        }
        current = current.apply(step);
        if contained {
            assert!(
                closed_or_safe(d, &current),
                "failed step {failed}, later {step:?}"
            );
        }
        contained |= closed_or_safe(d, &current);
    }
    current
}

#[test]
fn latch_survives_ticks_restore_repairs_and_failure_replanning() {
    let d = desired();
    let latch = Latch {
        reason: "fighting".into(),
        object: "link:foreign0".into(),
    };
    let mut m = KernelModel::desired(&d);
    m.ruleset = Known::Value(Ruleset::Absent);
    m.latch = Some(latch.clone());
    m.forwarding_v4 = Known::Value(0);
    m.forwarding_v6 = Known::Value(0);
    m.client_forwarding_v4 = Known::Value(0);
    let p = settled(&d, &m);
    assert!(
        !p.steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert!(
        p.steps
            .iter()
            .any(|s| matches!(s, Step::LoadRuleset { .. }))
    );
    m = run(&m, &p.steps);
    assert_eq!(m.latch, Some(latch.clone()));
    assert_eq!(tick(&d, &m, &Debounce::default()).steps, []);
    for action in [ClearLatch::RepairClear, ClearLatch::VerifiedFullApply] {
        let transition = clear_latch(&latch, action, &p.budgets);
        assert_eq!(transition.latch, None);
        assert_eq!(transition.event, PlannerEvent::AdminAction { action });
    }
    let d_candidate = desired_with("other", [99; 32], &Selection::Auto);
    let failed = Step::ForwardingOn {
        requires: d_candidate.fingerprint(),
    };
    for cut in 0..=p.steps.len() {
        let partial = run(&KernelModel::desired(&d), &p.steps[..cut]);
        let rp = replan_after_failure(
            &failed,
            &d,
            &partial,
            &p.budgets,
            partial.latch.as_ref(),
            &p.debounce,
            at(4),
        );
        assert!(
            rp.steps
                .contains(&Step::Emit(PlannerEvent::ReplanAfterFailure {
                    failed: Box::new(failed.clone()),
                    applied_version: d.applied_version()
                }))
        );
        assert_plan(&d, &partial, &rp, partial.latch.as_ref());
    }
}

#[test]
fn debounce_resets_after_an_absent_sighting_and_budgets_are_per_object() {
    let d = desired();
    let good = KernelModel::desired(&d);
    let mut m = good.clone();
    m.stale_exits.insert(ExitId("ch1".into()));
    let first = tick(&d, &m, &Debounce::default());
    assert_eq!(first.steps, []);
    let quiet = tick(&d, &good, &first.debounce);
    assert_eq!(quiet.debounce, Debounce::default());
    assert_eq!(tick(&d, &m, &quiet.debounce).steps, []);
    let mut budgets = Budgets::default();
    budgets.attempts.insert("unrelated".into(), vec![at(0); 3]);
    let p = plan(&d, &m, &budgets, None, &first.debounce, at(1));
    assert_eq!(
        p.steps,
        [Step::ReResolveEndpoint {
            exit: ExitId("ch1".into())
        }]
    );
}

#[test]
fn disconnected_routes_precede_exit_down_and_never_promote_a_foreign_target() {
    let d = desired();
    let m = KernelModel::desired(&d);
    let disconnected = desired_with("ch1", [7; 32], &Selection::Disconnected);
    let p = tick(&disconnected, &m, &Debounce::default());
    assert!(p.debounce.previous.contains("exit-down:ex-ch1"));
    assert!(!p.debounce.previous.contains("link:ex-ch1"));
    assert_eq!(
        p.steps,
        [
            Step::RouteReplace {
                family: Family::V4,
                target: RouteTarget::Unreachable
            },
            Step::LinkDown {
                name: "ex-ch1".into()
            }
        ]
    );
    assert!(safe(&run(&m, &p.steps), &disconnected));
    let site = validate(parse_site(include_str!("fixtures/site-m2.toml")).unwrap()).unwrap();
    let other = validate(
        parse_site(&include_str!("fixtures/site-m2.toml").replace("ch1", "other")).unwrap(),
    )
    .unwrap();
    let gateway = GatewayId("gw1".into());
    let target = RouteTarget::Exit(other.gateway(&gateway).unwrap().exits()[0].ifname().clone());
    let d = Desired::new(
        &site,
        &gateway,
        &VersionStamp {
            version: 1,
            sha256: [0; 32],
        },
        [1; 32],
        &target,
        &Selection::Auto,
    )
    .unwrap();
    assert!(
        d.routes()
            .iter()
            .all(|(_, r)| *r == RouteTarget::Unreachable)
    );
}

fn observations(
    d: &Desired,
) -> (
    TopologyObs,
    Forwarding,
    ForwardingGates,
    DefaultRoutes,
    ObservationDetails,
) {
    let good = KernelModel::desired(d);
    let topology = TopologyObs {
        host_wireguard_on_client_port: vec![],
        errors: vec![],
        links_complete: true,
        addresses_complete: true,
        netns: NetnsObs::Present {
            device: 1,
            inode: 2,
        },
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
    let defaults = DefaultRoutes {
        violations: vec![],
        v4: good.default_v4.value().unwrap().clone(),
        v6: DefaultRouteObs::Unreachable,
        extra: vec![],
    };
    let details = ObservationDetails {
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
    let gates = ForwardingGates {
        default_v4: Known::Value(1),
        default_v6: Known::Value(1),
        links: good
            .links
            .keys()
            .map(|name| (name.clone(), [Known::Value(1), Known::Value(1)]))
            .collect(),
    };
    (topology, forwarding, gates, defaults, details)
}
#[test]
#[allow(clippy::many_single_char_names, clippy::too_many_lines)] // Keep independent projection failures and their assertions together.
fn projection_errors_are_unknown_and_never_invent_verified_state_or_route_keys() {
    let d = desired();
    let (mut t, f, gates, mut routes, mut details) = observations(&d);
    let m = KernelModel::from_observations(
        &t,
        &Ok(f.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert!(safe(&m, &d));
    assert_eq!(tick(&d, &m, &Debounce::default()).steps, []);
    let mut items = vec![
        ObservationItem::ForwardingV4,
        ObservationItem::ForwardingV6,
        ObservationItem::ClientForwardingV4,
        ObservationItem::Ruleset,
        ObservationItem::Links,
        ObservationItem::Rules,
        ObservationItem::DefaultV4,
        ObservationItem::DefaultV6,
        ObservationItem::ExtraRoutes,
    ];
    for name in d.links().keys() {
        items.extend([
            ObservationItem::Addresses(name.clone()),
            ObservationItem::Peers(name.clone()),
            ObservationItem::Tc(name.clone()),
        ]);
    }
    for item in items {
        let mut details = details.clone();
        details.failed.insert(item.clone());
        let m = KernelModel::from_observations(
            &t,
            &Ok(f.clone()),
            &gates,
            &Ok(routes.clone()),
            &d,
            &details,
        );
        match &item {
            ObservationItem::ForwardingV4 => assert_eq!(m.forwarding_v4, Known::Unknown),
            ObservationItem::ForwardingV6 => assert_eq!(m.forwarding_v6, Known::Unknown),
            ObservationItem::ClientForwardingV4 => {
                assert_eq!(m.client_forwarding_v4, Known::Unknown);
            }
            ObservationItem::Ruleset => assert_eq!(m.ruleset, Known::Unknown),
            ObservationItem::Links => assert!(!m.links_complete),
            ObservationItem::Addresses(name) => assert_eq!(m.links[name].addresses, Known::Unknown),
            ObservationItem::Peers(name) => assert_eq!(m.links[name].peers, Known::Unknown),
            ObservationItem::Tc(name) => assert_eq!(m.links[name].tc_hooks, Known::Unknown),
            ObservationItem::Rules => assert_eq!(m.extra_rules, Known::Unknown),
            ObservationItem::DefaultV4 => assert_eq!(m.default_v4, Known::Unknown),
            ObservationItem::DefaultV6 => assert_eq!(m.default_v6, Known::Unknown),
            ObservationItem::ExtraRoutes => assert_eq!(m.extra_routes, Known::Unknown),
        }
        let p = settled(&d, &m);
        assert_plan(&d, &m, &p, None);
        if !matches!(item, ObservationItem::Addresses(_)) {
            assert!(p.steps.iter().any(|s| matches!(s, Step::ForwardingOff)));
        }
    }
    // Real linkinfo omits loopback's kind, and it has no WireGuard peers.
    t.links
        .iter_mut()
        .find(|link| link.name == "lo")
        .unwrap()
        .kind = None;
    t.peers.remove("lo");
    let loopback_model = KernelModel::from_observations(
        &t,
        &Ok(f.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert_eq!(tick(&d, &loopback_model, &Debounce::default()).steps, []);
    // Old collectors retain unscoped errors and may leave the ruleset at Exact.
    // That placeholder must never be promoted to Verified by this projection.
    t.errors.push(ProbeError::Timeout);
    let m = KernelModel::from_observations(
        &t,
        &Ok(f.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert_eq!(m.ruleset, Known::Unknown);
    assert!(!m.links_complete);
    assert!(!safe(&m, &d));
    t.errors.clear();
    routes.extra.push(DefaultRouteObs::Dev("foreign0".into()));
    let m = KernelModel::from_observations(
        &t,
        &Ok(f.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert_eq!(m.extra_routes, Known::Unknown);
    details.extra_routes = Some(Ok(vec![extra_route()]));
    let m = KernelModel::from_observations(
        &t,
        &Ok(f.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert_eq!(m.extra_routes, Known::Value(vec![extra_route()]));
    t.netns = NetnsObs::Missing;
    assert_eq!(
        KernelModel::from_observations(
            &t,
            &Ok(f.clone()),
            &gates,
            &Ok(routes.clone()),
            &d,
            &details
        )
        .namespace,
        NamespaceState::NameGone
    );
    details.held_inode_alive = false;
    assert_eq!(
        KernelModel::from_observations(
            &t,
            &Ok(f.clone()),
            &gates,
            &Ok(routes.clone()),
            &d,
            &details
        )
        .namespace,
        NamespaceState::InodeGone
    );
    t.netns = NetnsObs::Present {
        device: 1,
        inode: 2,
    };
    details.edge_elsewhere = true;
    assert_eq!(
        KernelModel::from_observations(
            &t,
            &Ok(f.clone()),
            &gates,
            &Ok(routes.clone()),
            &d,
            &details
        )
        .namespace,
        NamespaceState::EdgeElsewhere
    );
}

// A new Repair variant makes this helper fail to compile until explicitly
// assigned a coverage slot; the guard requires every slot to be reached.
fn repair_slot(repair: &Repair) -> usize {
    match repair {
        Repair::PeerContainment { .. } => 15,
        Repair::RulesetReload => 0,
        Repair::ForwardingRestore => 1,
        Repair::HardeningSysctl { .. } => 2,
        Repair::RouteReplace { .. } => 3,
        Repair::ExtraRouteDelete { .. } => 4,
        Repair::LinkRecreate { .. } => 5,
        Repair::LinkReconfigure { .. } => 6,
        Repair::ForeignLinkDown { .. } => 7,
        Repair::ExtraRuleDelete { .. } => 8,
        Repair::TcHookDelete { .. } => 9,
        Repair::ExitRehandshake { .. } => 10,
        Repair::PersistLatch { .. } => 11,
        Repair::ForwardingOff => 12,
        Repair::ExitDown { .. } => 13,
        Repair::HostLinkCleanup { .. } => 14,
    }
}
fn escalation_slot(escalation: &Escalation) -> usize {
    match escalation {
        Escalation::NamespaceNameGone => 0,
        Escalation::NamespaceInodeGone => 1,
        Escalation::EdgeInAnotherNamespace => 2,
        Escalation::HostLinkCollision(_) => 3,
        Escalation::NamespaceLinkCollision(_) => 4,
    }
}
fn drift(d: &Desired, mode: u8) -> KernelModel {
    let mut m = KernelModel::desired(d);
    let exit = d.exits().values().next().unwrap().clone();
    match mode {
        0 => m.ruleset = Known::Value(Ruleset::Absent),
        1 => {
            m.forwarding_v4 = Known::Value(0);
            m.forwarding_v6 = Known::Value(0);
            m.client_forwarding_v4 = Known::Value(0);
        }
        2 => {
            m.hardening
                .insert(d.hardening()[0].key.to_string(), Known::Value("1".into()));
        }
        3 => m.default_v4 = Known::Value(DefaultRouteObs::Missing),
        4 => m.extra_routes = Known::Value(vec![extra_route()]),
        5 => {
            m.links.remove("wg0");
        }
        6 => m.links.get_mut("wg0").unwrap().addresses = Known::Value(vec![]),
        7 => {
            m.links.insert("foreign0".into(), foreign(d));
        }
        8 => m.extra_rules = Known::Value(vec!["100: lookup 42".into()]),
        9 => m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["ingress".into()]),
        10 => {
            m.stale_exits.extend(d.exits().keys().cloned());
        }
        11 => m.ruleset = Known::Unknown,
        12 => {
            for name in d.exits().values() {
                m.links.get_mut(name).unwrap().up = Known::Value(true);
            }
        }
        13 => {
            let mut link = m.links["wg0"].clone();
            link.up = Known::Value(false);
            link.peers = Known::Value(vec![]);
            link.addresses = Known::Value(vec![]);
            m.host_links.insert("wg0".into(), link);
        }
        14 => m.namespace = NamespaceState::NameGone,
        15 => m.namespace = NamespaceState::InodeGone,
        16 => m.namespace = NamespaceState::EdgeElsewhere,
        17 => {
            m.host_links.insert("wg0".into(), foreign(d));
        }
        18 => m.forwarding_v4 = Known::Unknown,
        19 => m.forwarding_v6 = Known::Unknown,
        20 => m.extra_routes = Known::Unknown,
        21 => m.extra_rules = Known::Unknown,
        22 => m.links_complete = false,
        23 => m.links.get_mut("wg0").unwrap().tc_hooks = Known::Unknown,
        24 => m.default_v4 = Known::Unknown,
        25 => m.links.get_mut("wg0").unwrap().peers = Known::Unknown,
        26 => m.links.get_mut(&exit).unwrap().up = Known::Unknown,
        27 => m.links.get_mut(&exit).unwrap().ours = Known::Unknown,
        28 => m.links.get_mut(&exit).unwrap().kind = Known::Unknown,
        29 => {
            m.links.remove(&exit);
        }
        30 => {
            m.links.get_mut("wg0").unwrap().peers = Known::Value(vec![]);
        }
        31 => m.edge_dead = true,
        32 => {
            m.links.insert(exit, foreign(d));
        }
        33 => m.default_v6 = Known::Unknown,
        34 => m.client_forwarding_v4 = Known::Unknown,
        35 => m.links.get_mut("wg0").unwrap().addresses = Known::Unknown,
        36 => m.default_forwarding_v4 = Known::Unknown,
        37 => m.default_forwarding_v6 = Known::Unknown,
        38 => m.links.get_mut("wg0").unwrap().forwarding_v4 = Known::Unknown,
        39 => m.links.get_mut(&exit).unwrap().forwarding_v6 = Known::Unknown,
        41 | 42 => {
            let (mut topology, forwarding, gates, routes, mut details) = observations(d);
            if mode == 41 {
                topology.netns = NetnsObs::WrongInode;
            } else {
                details.expected_netns = None;
            }
            m = KernelModel::from_observations(
                &topology,
                &Ok(forwarding),
                &gates,
                &Ok(routes),
                d,
                &details,
            );
        }
        _ => m.links.get_mut(&exit).unwrap().tc_hooks = Known::Value(vec!["egress/mirred".into()]),
    }
    m
}
#[derive(Default, Debug)]
struct Coverage {
    repairs: [usize; 16],
    escalations: [usize; 5],
    latch: usize,
    suppression: usize,
    unknown: [usize; 19],
    latched_unsafe: usize,
    suppressed_safety_open: usize,
    escalation_unsafe: usize,
    namespace_unknown: usize,
    held_name_hijacked: usize,
    non_safety_suppression: usize,
    single_object_suppression: usize,
}
impl Coverage {
    fn record(&mut self, d: &Desired, m: &KernelModel, p: &Plan, modes: &[u8]) {
        let unsafe_input = !safe(m, d);
        self.namespace_unknown += usize::from(m.namespace == NamespaceState::Unknown);
        self.held_name_hijacked +=
            usize::from(modes.contains(&41) && m.namespace == NamespaceState::NameGone);
        let non_safety = p.steps.iter().any(|s| {
            matches!(s,
            Step::Emit(PlannerEvent::RepairSuppressed { object }) if !object.starts_with("safety:"))
        });
        self.non_safety_suppression += usize::from(non_safety);
        self.single_object_suppression += usize::from(
            non_safety && p.budgets.attempts.values().filter(|v| v.len() >= 3).count() == 1,
        );
        self.latched_unsafe += usize::from(m.latch.is_some() && unsafe_input);
        self.escalation_unsafe += usize::from(!p.escalations.is_empty() && unsafe_input);
        self.suppressed_safety_open +=
            usize::from(p.latch.is_some() && m.forwarding_v4 == Known::Value(1));
        let unknowns = [
            m.ruleset == Known::Unknown,
            m.forwarding_v4 == Known::Unknown,
            m.forwarding_v6 == Known::Unknown,
            m.client_forwarding_v4 == Known::Unknown,
            m.extra_routes == Known::Unknown,
            m.extra_rules == Known::Unknown,
            !m.links_complete,
            m.default_v4 == Known::Unknown,
            m.default_v6 == Known::Unknown,
            m.links.values().any(|l| l.tc_hooks == Known::Unknown),
            m.links.values().any(|l| l.peers == Known::Unknown),
            m.links.values().any(|l| l.up == Known::Unknown),
            m.links.values().any(|l| l.ours == Known::Unknown),
            m.links.values().any(|l| l.addresses == Known::Unknown),
            m.links.values().any(|l| l.kind == Known::Unknown),
            m.default_forwarding_v4 == Known::Unknown,
            m.default_forwarding_v6 == Known::Unknown,
            m.links.values().any(|l| l.forwarding_v4 == Known::Unknown),
            m.links.values().any(|l| l.forwarding_v6 == Known::Unknown),
        ];
        for (counter, hit) in self.unknown.iter_mut().zip(unknowns) {
            *counter += usize::from(hit);
        }

        for repair in &p.repairs {
            self.repairs[repair_slot(repair)] += 1;
            assert!(matches!(
                repair.class(),
                RepairClass::Restore | RepairClass::Tighten
            ));
        }
        for e in &p.escalations {
            self.escalations[escalation_slot(e)] += 1;
        }
        self.latch += usize::from(
            p.steps
                .iter()
                .any(|s| matches!(s, Step::PersistLatch { .. })),
        );
        self.suppression += usize::from(
            p.steps
                .iter()
                .any(|s| matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { .. }))),
        );
    }
}

// Compose individual link fields as well as namespace-wide observations.
fn random_model(d: &Desired, modes: &[u8]) -> KernelModel {
    let good = KernelModel::desired(d);
    let mut m = good.clone();
    for mode in modes {
        let changed = drift(d, *mode);
        macro_rules! merge {
            ($($field:ident),+) => {$(if changed.$field != good.$field { m.$field = changed.$field.clone(); })+};
        }
        merge!(
            ruleset,
            forwarding_v4,
            forwarding_v6,
            client_forwarding_v4,
            default_forwarding_v4,
            default_forwarding_v6,
            hardening,
            default_v4,
            default_v6,
            extra_routes,
            links_complete,
            extra_rules,
            namespace,
            host_links,
            stale_exits,
            edge_dead
        );
        for name in good.links.keys() {
            if !changed.links.contains_key(name) {
                m.links.remove(name);
            }
        }
        for (name, link) in changed.links {
            let Some(reference) = good.links.get(&name) else {
                m.links.insert(name, link);
                continue;
            };
            if &link == reference {
                continue;
            }
            let actual = m.links.entry(name).or_insert_with(|| reference.clone());
            macro_rules! field { ($($f:ident),+) => {$(if link.$f != reference.$f {actual.$f = link.$f;})+}; }
            field!(
                up,
                kind,
                ours,
                peers,
                addresses,
                settings,
                tc_hooks,
                forwarding_v4,
                forwarding_v6
            );
        }
    }
    m
}
#[test]
#[allow(clippy::too_many_lines)] // Keep random generation and its coverage assertions together.
fn random_models_prefixes_failures_determinism_and_coverage() {
    use proptest::test_runner::{Config, TestRunner};
    use std::cell::RefCell;
    let coverage = RefCell::new(Coverage::default());
    let strategy = (
        prop_oneof![
            prop::collection::vec(0_u8..43, 2..12),
            prop::collection::vec(0_u8..14, 1..2)
        ],
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(0_usize..5, 1..80),
        0_u64..1201,
        any::<[u8; 32]>(),
    );
    let mut runner = TestRunner::new(Config {
        cases: 1024,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x2_2_1),
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(
            &strategy,
            |(modes, disconnected, seed_debounce, seed_latch, counts, now, fingerprint)| {
                let selection = if disconnected {
                    Selection::Disconnected
                } else {
                    Selection::Auto
                };
                let d = desired_with("ch1", fingerprint, &selection);
                let mut m = random_model(&d, &modes);
                if seed_latch {
                    m.latch = Some(Latch {
                        reason: "generated quarantine".into(),
                        object: SafetyClass::TcHook.key().into(),
                    });
                }
                let warm = tick(&d, &m, &Debounce::default());
                let mut budgets = Budgets::default();
                for (index, key) in warm
                    .debounce
                    .previous
                    .iter()
                    .cloned()
                    .chain([
                        SafetyClass::Ruleset.key().into(),
                        SafetyClass::TcHook.key().into(),
                        SafetyClass::ForeignLink.key().into(),
                    ])
                    .enumerate()
                {
                    let count = counts[index % counts.len()];
                    budgets
                        .attempts
                        .insert(key, vec![at(now.saturating_sub(1)); count]);
                }
                let debounce = if seed_debounce {
                    warm.debounce
                } else {
                    Debounce::default()
                };
                let p = plan(&d, &m, &budgets, m.latch.as_ref(), &debounce, at(now));
                coverage.borrow_mut().record(&d, &m, &p, &modes);
                prop_assert_eq!(
                    &p,
                    &plan(&d, &m, &budgets, m.latch.as_ref(), &debounce, at(now))
                );
                assert_plan(&d, &m, &p, m.latch.as_ref());
                for (i, step) in p.steps.iter().enumerate() {
                    let once = m.apply(step);
                    prop_assert_eq!(once.apply(step), once, "non-idempotent {:?}", step);
                    if i != usize::from(modes[0]) % p.steps.len() {
                        continue;
                    }
                    let partial = failure_state(&d, &m, &p, i);
                    let recovery = replan_after_failure(
                        step,
                        &d,
                        &partial,
                        &p.budgets,
                        p.latch.as_ref().or(m.latch.as_ref()),
                        &p.debounce,
                        at(now + 2),
                    );
                    assert_plan(
                        &d,
                        &partial,
                        &recovery,
                        p.latch.as_ref().or(m.latch.as_ref()),
                    );
                }
                Ok(())
            },
        )
        .unwrap();
    let coverage = coverage.into_inner();
    assert!(
        coverage.repairs.iter().all(|n| *n > 0),
        "random repair coverage: {coverage:?}"
    );
    assert!(
        coverage.escalations.iter().all(|n| *n > 0),
        "random escalation coverage: {coverage:?}"
    );
    assert!(
        coverage.unknown.iter().all(|n| *n > 0),
        "random Unknown coverage: {coverage:?}"
    );
    assert!(
        coverage.latch > 0
            && coverage.suppression > 0
            && coverage.latched_unsafe > 0
            && coverage.suppressed_safety_open > 0
            && coverage.escalation_unsafe > 0
            && coverage.namespace_unknown > 0
            && coverage.held_name_hijacked > 0
            && coverage.non_safety_suppression > 0
            && coverage.single_object_suppression > 0,
        "random coverage: {coverage:?}"
    );
}

#[test]
fn suppression_only_closes_for_safety_and_repeated_safety_suppression_keeps_order() {
    let d = desired();
    for mode in [0, 1, 2, 3, 5, 6, 7, 9, 10, 13] {
        let episode = if mode == 12 {
            desired_with("ch1", [7; 32], &Selection::Disconnected)
        } else {
            d.clone()
        };
        let m = drift(&episode, mode);
        let warm = settled(&episode, &m);
        let mut budgets = warm.budgets.clone();
        for times in budgets.attempts.values_mut() {
            *times = vec![at(0); 3];
        }
        let p = plan(&episode, &m, &budgets, None, &warm.debounce, at(2));
        assert!(
            p.steps
                .iter()
                .any(|s| matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { .. }))),
            "mode {mode}"
        );
        if [0, 7, 9].contains(&mode) {
            assert!(run(&m, &p.steps).forwarding_off());
        } else {
            assert!(
                !p.steps.contains(&Step::ForwardingOff),
                "non-safety mode {mode}"
            );
        }
        assert_plan(&episode, &m, &p, None);
    }
    let mut m = drift(&d, 0);
    m.forwarding_v4 = Known::Value(0);
    m.forwarding_v6 = Known::Value(0);
    m.client_forwarding_v4 = Known::Value(0);
    let mut budgets = Budgets::default();
    budgets
        .attempts
        .insert(SafetyClass::Ruleset.key().into(), vec![at(0); 3]);
    let p = plan(&d, &m, &budgets, None, &Debounce::default(), at(2));
    assert!(matches!(&p.steps[..2], [Step::ForwardingOff, ..]));
    let mut recovered = run(&m, &p.steps);
    recovered.ruleset = Known::Value(Ruleset::Verified(d.fingerprint()));
    let later = plan(&d, &recovered, &p.budgets, None, &p.debounce, at(1000));
    assert_eq!(later.steps, []);
    assert!(recovered.latch.is_some());
}

#[test]
fn roaming_endpoints_are_ignored_keepalive_is_repaired_and_tc_summary_needs_identity() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    for link in m.links.values_mut() {
        if let Known::Value(peers) = &mut link.peers {
            for peer in peers {
                peer.endpoint = Some("198.51.100.99:12345".parse().unwrap());
            }
        }
    }
    assert_eq!(settled(&d, &m).steps, []);
    if let Known::Value(settings) = &mut m.links.get_mut("ex-ch1").unwrap().settings {
        settings.keepalives.clear();
    }
    let p = settled(&d, &m);
    assert!(p.repairs.contains(&Repair::LinkReconfigure {
        name: "ex-ch1".into()
    }));
    assert_plan(&d, &m, &p, None);
    let (mut topology, forwarding, gates, routes, mut details) = observations(&d);
    topology.tc_hooks.push("wg0".into());
    topology.extra_rules.push("V4 RPDB differs".into());
    let m = KernelModel::from_observations(
        &topology,
        &Ok(forwarding.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert_eq!(m.links["wg0"].tc_hooks, Known::Unknown);
    assert_eq!(m.extra_rules, Known::Unknown);
    details
        .tc_hooks
        .insert("wg0".into(), Ok(vec!["ingress/filter/42".into()]));
    details.extra_rules = Some(Ok(vec!["v4 pref 100 lookup 42".into()]));
    let m = KernelModel::from_observations(
        &topology,
        &Ok(forwarding.clone()),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    let p = tick(&d, &m, &Debounce::default());
    assert!(p.steps.contains(&Step::TcDelete {
        name: "wg0".into(),
        hook: "ingress/filter/42".into()
    }));
    assert!(p.steps.contains(&Step::RuleDelete {
        rule: "v4 pref 100 lookup 42".into()
    }));
}

#[test]
fn partial_candidate_ruleset_failure_replans_toward_previous_applied_version() {
    let previous = desired();
    let candidate = desired_with("new", [99; 32], &Selection::Auto);
    let before = KernelModel::desired(&previous);
    let steps = [
        Step::ForwardingOff,
        Step::LoadRuleset {
            fingerprint: candidate.fingerprint(),
            rendered: "candidate source supplied by apply".into(),
        },
        Step::VerifyRuleset {
            fingerprint: candidate.fingerprint(),
        },
        Step::FlushConntrack,
    ];
    for fail_at in 0..steps.len() {
        let partial = run(&before, &steps[..fail_at]);
        let recovery = replan_after_failure(
            &steps[fail_at],
            &previous,
            &partial,
            &Budgets::default(),
            None,
            &Debounce::default(),
            at(1),
        );
        for step in &recovery.steps {
            if let Step::LoadRuleset { fingerprint, .. }
            | Step::VerifyRuleset { fingerprint }
            | Step::ForwardingOn {
                requires: fingerprint,
            } = step
            {
                assert_eq!(*fingerprint, previous.fingerprint());
            }
        }
        assert_plan(&previous, &partial, &recovery, None);
        assert!(
            recovery
                .steps
                .contains(&Step::Emit(PlannerEvent::ReplanAfterFailure {
                    failed: Box::new(steps[fail_at].clone()),
                    applied_version: previous.applied_version()
                }))
        );
    }
}

#[test]
fn unrelated_link_restore_cannot_bypass_route_debounce_and_external_latch_cannot_raise() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.remove("wg0");
    let first = tick(&d, &m, &Debounce::default());
    m.default_v4 = Known::Value(DefaultRouteObs::Unreachable);
    let p = plan(&d, &m, &first.budgets, None, &first.debounce, at(2));
    assert!(p.steps.iter().any(|s| matches!(s, Step::LinkCreate { .. })));
    assert!(!p.steps.iter().any(|s| matches!(
        s,
        Step::RouteReplace {
            target: RouteTarget::Exit(_),
            ..
        }
    )));
    let latch = Latch {
        reason: "external persisted quarantine".into(),
        object: "ruleset".into(),
    };
    let m = KernelModel::desired(&d);
    let p = plan(
        &d,
        &m,
        &Budgets::default(),
        Some(&latch),
        &Debounce::default(),
        at(2),
    );
    assert!(run(&m, &p.steps).forwarding_off());
    assert!(
        !p.steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert_plan(&d, &m, &p, Some(&latch));
}

#[test]
fn ingress_forwarding_drift_is_not_hidden_by_the_global_values() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.client_forwarding_v4 = Known::Value(0);
    assert_eq!(tick(&d, &m, &Debounce::default()).steps, []);
    assert_eq!(settled(&d, &m).steps, on(&d));
    let latch = Latch {
        reason: "quarantine".into(),
        object: "ruleset".into(),
    };
    m.latch = Some(latch);
    m.forwarding_v4 = Known::Value(0);
    m.forwarding_v6 = Known::Value(0);
    m.client_forwarding_v4 = Known::Value(1);
    let p = tick(&d, &m, &Debounce::default());
    assert_eq!(p.steps.first(), Some(&Step::ForwardingOff));
    assert!(run(&m, &p.steps).forwarding_off());
}

#[test]
fn blocked_restores_reserve_nothing_and_unknown_rulesets_only_close() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m = m.apply(&Step::ForwardingOff);
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Unknown;
    let mut budgets = Budgets::default();
    let mut debounce = Debounce::default();
    for second in 0..8 {
        let p = plan(&d, &m, &budgets, None, &debounce, at(second));
        assert!(!p.budgets.attempts.contains_key("forwarding"));
        assert!(
            !p.steps
                .iter()
                .any(|s| matches!(s, Step::ForwardingOn { .. }))
        );
        budgets = p.budgets;
        debounce = p.debounce;
    }
    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec![]);
    let p = plan(&d, &m, &budgets, None, &debounce, at(10));
    assert!(
        p.steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    m.ruleset = Known::Unknown;
    for second in 0..5 {
        let p = plan(&d, &m, &budgets, None, &Debounce::default(), at(second));
        assert!(!p.steps.iter().any(|s| matches!(
            s,
            Step::LoadRuleset { .. } | Step::FlushConntrack | Step::ForwardingOn { .. }
        )));
        assert!(p.latch.is_none());
        assert!(!p.budgets.attempts.contains_key(SafetyClass::Ruleset.key()));
    }
}

#[test]
fn unknown_inventory_closes_ingress_on_second_tick_then_recovers() {
    let d = desired();
    for missing_links in [false, true] {
        let mut m = KernelModel::desired(&d);
        if missing_links {
            m.links_complete = false;
        } else {
            m.links.get_mut("wg0").unwrap().tc_hooks = Known::Unknown;
        }
        let first = tick(&d, &m, &Debounce::default());
        assert_eq!(first.steps.first(), Some(&Step::ForwardingOff));
        assert!(!first.steps.contains(&Step::LinkDown { name: "wg0".into() }));
        m = run(&m, &first.steps);
        let second = plan(&d, &m, &first.budgets, None, &first.debounce, at(2));
        assert!(
            second
                .steps
                .contains(&Step::LinkDown { name: "wg0".into() })
        );
        assert!(
            second
                .steps
                .contains(&Step::Emit(PlannerEvent::IngressQuarantined))
        );
        m = run(&m, &second.steps);
        assert_eq!(m.links["wg0"].up, Known::Value(false));
        let still_unknown = plan(&d, &m, &second.budgets, None, &second.debounce, at(3));
        assert!(
            !still_unknown
                .steps
                .contains(&Step::Emit(PlannerEvent::IngressQuarantined))
        );
        assert!(
            !still_unknown
                .steps
                .contains(&Step::LinkDown { name: "wg0".into() })
        );
        m.links_complete = true;
        m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec![]);
        let third = plan(&d, &m, &second.budgets, None, &second.debounce, at(4));
        m = run(&m, &third.steps);
        let fourth = plan(&d, &m, &third.budgets, None, &third.debounce, at(6));
        m = run(&m, &fourth.steps);
        assert_eq!(m.links["wg0"].up, Known::Value(true));
        assert!(safe(&m, &d));
    }
}

#[test]
fn interrupted_flush_is_repeated_before_reopening_and_failure_alert_precedes_recovery() {
    let d = desired();
    let mut m = drift(&d, 0);
    let p = settled(&d, &m);
    let flush = p
        .steps
        .iter()
        .position(|s| *s == Step::FlushConntrack)
        .unwrap();
    m = run(&m, &p.steps[..flush]);
    assert!(!m.conntrack_flushed);
    let first = replan_after_failure(
        &Step::FlushConntrack,
        &d,
        &m,
        &p.budgets,
        None,
        &p.debounce,
        at(2),
    );
    let second = replan_after_failure(
        &Step::FlushConntrack,
        &d,
        &m,
        &first.budgets,
        None,
        &first.debounce,
        at(4),
    );
    let on = second
        .steps
        .iter()
        .position(|s| matches!(s, Step::ForwardingOn { .. }))
        .unwrap();
    assert_eq!(second.steps[on - 1], Step::FlushConntrack);
    let m = drift(&d, 0);
    for _ in 0..3 {
        let recovery = replan_after_failure(
            &Step::FlushConntrack,
            &d,
            &m,
            &Budgets::default(),
            None,
            &Debounce::default(),
            at(0),
        );
        assert_eq!(recovery.steps.first(), Some(&Step::ForwardingOff));
        assert!(matches!(
            recovery.steps[1],
            Step::Emit(PlannerEvent::ReplanAfterFailure { .. })
        ));
        let load = recovery
            .steps
            .iter()
            .position(|s| matches!(s, Step::LoadRuleset { .. }))
            .unwrap();
        assert!(load > 1);
    }
}

#[test]
fn observation_results_cannot_turn_failed_reads_into_closed_or_empty_placeholders() {
    let d = desired();
    let (topology, forwarding, gates, routes, details) = observations(&d);
    let m = KernelModel::from_observations(
        &topology,
        &Err(ProbeError::Timeout),
        &gates,
        &Ok(routes.clone()),
        &d,
        &details,
    );
    assert_eq!(m.forwarding_v4, Known::Unknown);
    assert_eq!(m.forwarding_v6, Known::Unknown);
    assert_eq!(m.client_forwarding_v4, Known::Unknown);
    assert!(!safe(&m, &d));
    assert_eq!(
        tick(&d, &m, &Debounce::default()).steps.first(),
        Some(&Step::ForwardingOff)
    );
    let m = KernelModel::from_observations(
        &topology,
        &Ok(forwarding),
        &gates,
        &Err(ProbeError::Timeout),
        &d,
        &details,
    );
    assert_eq!(m.default_v4, Known::Unknown);
    assert_eq!(m.default_v6, Known::Unknown);
    assert_eq!(m.extra_routes, Known::Unknown);
}

#[test]
fn latch_is_adopted_without_io_and_tightening_precedes_persistence() {
    let d = desired();
    let mut m = drift(&d, 9);
    m.links.insert("foreign0".into(), foreign(&d));
    let mut budgets = Budgets::default();
    budgets
        .attempts
        .insert(SafetyClass::TcHook.key().into(), vec![at(0); 3]);
    let p = plan(&d, &m, &budgets, None, &Debounce::default(), at(1));
    assert!(p.latch.is_some());
    assert_eq!(p.steps.first(), Some(&Step::ForwardingOff));
    let persist = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::PersistLatch { .. }))
        .unwrap();
    assert!(
        p.steps[..persist]
            .iter()
            .any(|s| matches!(s, Step::TcDelete { .. }))
    );
    // A failed persist is skipped, with the executor retaining its memory latch.
    m = run(
        &m,
        &p.steps
            .iter()
            .filter(|s| !matches!(s, Step::PersistLatch { .. }))
            .cloned()
            .collect::<Vec<_>>(),
    );
    assert!(safe(&m, &d));
    assert!(m.forwarding_off());
    let failed = &p.steps[persist];
    let next = replan_after_failure(
        failed,
        &d,
        &m,
        &p.budgets,
        p.latch.as_ref(),
        &p.debounce,
        at(2),
    );
    assert!(
        next.steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. }))
    );
    assert!(
        next.steps
            .contains(&Step::Emit(PlannerEvent::PersistenceFailed))
    );
    let retry = plan(
        &d,
        &m,
        &next.budgets,
        p.latch.as_ref(),
        &next.debounce,
        at(4),
    );
    assert!(
        retry
            .steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. }))
    );
    assert!(
        retry
            .steps
            .contains(&Step::Emit(PlannerEvent::PersistenceFailed))
    );
    let persisted = run(&m, &retry.steps);
    let done = plan(
        &d,
        &persisted,
        &retry.budgets,
        p.latch.as_ref(),
        &retry.debounce,
        at(6),
    );
    assert!(!done.budgets.persistence_failed);
    assert!(!done.steps.iter().any(|s| matches!(
        s,
        Step::PersistLatch { .. } | Step::Emit(PlannerEvent::PersistenceFailed)
    )));
    assert!(
        !next
            .steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert!(
        !next
            .steps
            .iter()
            .any(|s| matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { .. })))
    );
}

#[test]
fn safety_reopening_budget_follows_tightening_across_ticks() {
    let d = desired();
    let mut m = drift(&d, 9);
    m.extra_rules = Known::Unknown;
    let first = tick(&d, &m, &Debounce::default());
    assert!(
        !first
            .steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert!(
        !first
            .budgets
            .attempts
            .contains_key(SafetyClass::TcHook.key())
    );
    assert!(first.budgets.pending_safety.contains(&SafetyClass::TcHook));
    m = run(&m, &first.steps);
    m.extra_rules = Known::Value(vec![]);
    let second = plan(&d, &m, &first.budgets, None, &first.debounce, at(2));
    assert!(
        second
            .steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert_eq!(second.budgets.attempts[SafetyClass::TcHook.key()].len(), 1);
    assert!(!second.budgets.attempts.contains_key("forwarding"));
    assert!(second.budgets.pending_safety.is_empty());
}

#[test]
fn failure_alert_precedes_new_latch_persistence_and_tightening() {
    let d = desired();
    let mut m = drift(&d, 9);
    m.ruleset = Known::Value(Ruleset::Absent);
    let mut budgets = Budgets::default();
    budgets
        .attempts
        .insert(SafetyClass::TcHook.key().into(), vec![at(0); 3]);
    let failed = Step::FlushConntrack;
    let p = replan_after_failure(&failed, &d, &m, &budgets, None, &Debounce::default(), at(1));
    let persist = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::PersistLatch { .. }))
        .unwrap();
    assert!(matches!(
        p.steps[1],
        Step::Emit(PlannerEvent::ReplanAfterFailure { .. })
    ));
    let load = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::LoadRuleset { .. }))
        .unwrap();
    let tighten = p
        .steps
        .iter()
        .position(|s| matches!(s, Step::TcDelete { .. }))
        .unwrap();
    assert!(1 < tighten && tighten < persist && persist < load);
}

#[test]
fn inheritance_and_model_effects_expose_wrongly_emitted_steps() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    let link = d.links()["wg0"].clone();
    m.links.remove("wg0");
    m.forwarding_v4 = Known::Value(0);
    m.client_forwarding_v4 = Known::Unknown;
    m = m.apply(&Step::LinkCreate {
        link: link.clone(),
        phase: LinkPhase::HostAddDown,
    });
    m = m.apply(&Step::LinkCreate {
        link: link.clone(),
        phase: LinkPhase::Move,
    });
    assert_eq!(m.client_forwarding_v4, Known::Value(1));
    m = m.apply(&Step::ForwardingOff);
    m.latch = Some(Latch {
        reason: "test".into(),
        object: SafetyClass::TcHook.key().into(),
    });
    let wrong = m.apply(&Step::ForwardingOn { requires: [99; 32] });
    assert_eq!(wrong.forwarding_v4, Known::Value(1));
    assert!(!safe(&wrong, &d));
    m.links.get_mut("wg0").unwrap().peers = Known::Value(vec![]);
    let wrong = m.apply(&Step::LinkCreate {
        link,
        phase: LinkPhase::Up,
    });
    assert_eq!(wrong.links["wg0"].up, Known::Value(true));
    for value in scupper_core::render::desired_sysctls(&[], false) {
        if matches!(value.key.name, "forwarding" | "ip_forward") {
            assert!(HardeningKey::new(value.key).is_none());
        } else {
            assert!(HardeningKey::new(value.key).is_some());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
    #[test]
    fn fighting_fresh_safety_identities_reach_latch_and_stay_closed(
        class in 0_u8..3, mixed in any::<bool>(), choices in prop::collection::vec((0_u8..3,any::<bool>()),16..40),
    ) {
        let d=desired();let mut m=KernelModel::desired(&d);let mut budgets=Budgets::default();let mut debounce=Debounce::default();let mut latch=None;
        for (tick,(random_class,choice)) in choices.iter().enumerate() {
            let identity=format!("fresh-{tick}");
            match if mixed {*random_class} else {class} {
                0=>m.ruleset=Known::Value(Ruleset::Unverified([u8::from(*choice);32])),
                1=>{m.links.insert(identity,foreign(&d));},
                _=>{let name=if *choice {"wg0"} else {"ex-ch1"};m.links.get_mut(name).unwrap().tc_hooks=Known::Value(vec![identity]);},
            }
            let p=plan(&d,&m,&budgets,latch.as_ref(),&debounce,at(u64::try_from(tick).unwrap()*10));
            if let Some(new)=&p.latch {latch=Some(new.clone());}
            m.latch=latch.clone();
            for step in &p.steps {
                if latch.is_some() {prop_assert!(!matches!(step,Step::ForwardingOn {..}), "latched plan reopened");}
                m=m.apply(step);
                if latch.is_some() {prop_assert!(m.forwarding_off());}
            }
            prop_assert!(closed_or_safe(&d,&m));
            if !safe(&m,&d) {prop_assert!(m.forwarding_off());}
            if tick>=if mixed {9} else {3} {prop_assert!(latch.is_some(),"four sightings of one class must latch");prop_assert!(m.forwarding_off());}
            budgets=p.budgets;debounce=p.debounce;
        }
    }
}

#[test]
fn namespace_projection_uses_holders_and_unknown_identity_stays_closed() {
    let d = desired();
    let (mut topology, forwarding, gates, routes, mut details) = observations(&d);
    for netns in [
        NetnsObs::WrongInode,
        NetnsObs::Missing,
        NetnsObs::Present {
            device: 3,
            inode: 4,
        },
    ] {
        topology.netns = netns;
        for alive in [false, true] {
            details.held_inode_alive = alive;
            let m = KernelModel::from_observations(
                &topology,
                &Ok(forwarding.clone()),
                &gates,
                &Ok(routes.clone()),
                &d,
                &details,
            );
            assert_eq!(
                m.namespace,
                if alive {
                    NamespaceState::NameGone
                } else {
                    NamespaceState::InodeGone
                }
            );
        }
        details.expected_netns = None;
        let m = KernelModel::from_observations(
            &topology,
            &Ok(forwarding.clone()),
            &gates,
            &Ok(routes.clone()),
            &d,
            &details,
        );
        assert_eq!(m.namespace, NamespaceState::Unknown);
        assert!(!safe(&m, &d));
        let p = settled(&d, &m);
        assert_eq!(p.steps.first(), Some(&Step::ForwardingOff));
        assert!(run(&m, &p.steps).forwarding_off());
        assert!(
            !p.steps
                .iter()
                .any(|s| matches!(s, Step::ForwardingOn { .. }))
        );
        details.expected_netns = Some(NetnsIdentity {
            device: 1,
            inode: 2,
        });
    }
}

#[test]
fn typed_gates_are_independent_of_hardening_reads() {
    let d = desired();
    let (topology, forwarding, mut gates, routes, details) = observations(&d);
    assert!(
        details
            .hardening
            .keys()
            .all(|key| !key.ends_with(".forwarding"))
    );
    gates.default_v4 = Known::Unknown;
    gates.links.get_mut("ex-ch1").unwrap()[1] = Known::Unknown;
    let m = KernelModel::from_observations(
        &topology,
        &Ok(forwarding),
        &gates,
        &Ok(routes),
        &d,
        &details,
    );
    assert_eq!(m.default_forwarding_v4, Known::Unknown);
    assert_eq!(m.links["ex-ch1"].forwarding_v6, Known::Unknown);
    assert!(!safe(&m, &d));
    assert_eq!(
        tick(&d, &m, &Debounce::default()).steps.first(),
        Some(&Step::ForwardingOff)
    );
}

#[test]
fn reconfigured_links_reopen_without_a_forwarding_budget_even_if_it_is_exhausted() {
    let d = desired();
    for name in ["wg0", "ex-ch1"] {
        let mut m = KernelModel::desired(&d);
        m.links.get_mut(name).unwrap().addresses = Known::Value(vec![]);
        let first = tick(&d, &m, &Debounce::default());
        let mut budgets = first.budgets;
        budgets.attempts.insert("forwarding".into(), vec![at(0); 3]);
        let p = plan(&d, &m, &budgets, None, &first.debounce, at(2));
        let end = run(&m, &p.steps);
        assert_eq!(end.links[name].forwarding_v4, Known::Value(1));
        assert_eq!(end.links[name].forwarding_v6, Known::Value(1));
        assert_eq!(
            p.budgets.attempts["forwarding"],
            budgets.attempts["forwarding"]
        );
        assert!(
            !p.steps
                .iter()
                .any(|s| matches!(s, Step::Emit(PlannerEvent::RepairSuppressed { .. })))
        );
        assert_plan(&d, &m, &p, None);
    }
}

#[test]
fn admin_actions_reset_only_safety_and_pending_classes_cannot_create_a_latch() {
    let d = desired();
    let m = KernelModel::desired(&d).apply(&Step::ForwardingOff);
    let mut budgets = Budgets::default();
    for class in [
        SafetyClass::Ruleset,
        SafetyClass::ForeignLink,
        SafetyClass::TcHook,
    ] {
        budgets.pending_safety.insert(class);
        budgets.attempts.insert(class.key().into(), vec![at(0); 3]);
        budgets.suppressed.insert(class.key().into());
    }
    budgets
        .attempts
        .insert("endpoint:ch1".into(), vec![at(0); 3]);
    budgets.suppressed.insert("endpoint:ch1".into());
    budgets.persistence_failed = true;
    let warm = tick(&d, &m, &Debounce::default());
    let pending = plan(&d, &m, &budgets, None, &warm.debounce, at(2));
    assert!(pending.latch.is_none());
    assert!(
        pending
            .steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    let latch = Latch {
        reason: "test".into(),
        object: SafetyClass::TcHook.key().into(),
    };
    for action in [ClearLatch::RepairClear, ClearLatch::VerifiedFullApply] {
        let clear = clear_latch(&latch, action, &budgets);
        assert!(clear.budgets.pending_safety.is_empty());
        assert!(!clear.budgets.persistence_failed);
        assert_eq!(clear.budgets.attempts.len(), 1);
        assert_eq!(clear.budgets.suppressed, ["endpoint:ch1".into()].into());
        assert_eq!(
            clear.budgets.attempts["endpoint:ch1"],
            budgets.attempts["endpoint:ch1"]
        );
    }
}

#[test]
fn failed_close_and_tc_delete_still_allow_remaining_tightening() {
    let d = desired();
    let mut m = drift(&d, 9);
    m.extra_rules = Known::Value(vec!["100: lookup 42".into()]);
    m.links.insert("foreign0".into(), foreign(&d));
    let p = settled(&d, &m);
    for failed in [
        0,
        p.steps
            .iter()
            .position(|s| matches!(s, Step::TcDelete { .. }))
            .unwrap(),
    ] {
        assert_eq!(p.steps[failed].failure(), StepFailure::Contain);
        let end = failure_state(&d, &m, &p, failed);
        assert_eq!(end.extra_rules, Known::Value(vec![]));
        assert_eq!(end.links["foreign0"].up, Known::Value(false));
        if failed == 0 {
            assert_eq!(end.links["wg0"].tc_hooks, Known::Value(vec![]));
        } else {
            assert_eq!(end.links["wg0"].tc_hooks, m.links["wg0"].tc_hooks);
        }
        assert!(
            !p.steps[..failed]
                .iter()
                .any(|s| s.failure() == StepFailure::Stop)
        );
    }
}

#[test]
fn containment_failure_skips_restores_but_reaches_later_containment_and_persistence() {
    let d = desired();
    let mut m = drift(&d, 9);
    m.links.insert("foreign0".into(), foreign(&d));
    let p = Plan {
        steps: vec![
            Step::ForwardingOff,
            Step::TcDelete {
                name: "wg0".into(),
                hook: "ingress".into(),
            },
            Step::ForwardingOn {
                requires: d.fingerprint(),
            },
            Step::LinkDown {
                name: "foreign0".into(),
            },
            Step::Emit(PlannerEvent::ObservationUnknown),
            Step::PersistLatch {
                reason: "test".into(),
                object: SafetyClass::TcHook.key().into(),
            },
            Step::ForwardingOn {
                requires: d.fingerprint(),
            },
        ],
        ..Plan::default()
    };
    let end = failure_state(&d, &m, &p, 1);
    assert!(end.forwarding_off());
    assert_eq!(end.links["foreign0"].up, Known::Value(false));
    assert_eq!(end.links["wg0"].tc_hooks, m.links["wg0"].tc_hooks);
    assert!(end.latch.is_some());

    // A NonFatal event failure by itself still permits a same-plan reopening.
    let p = settled(&d, &drift(&d, 9));
    let event = p
        .steps
        .iter()
        .position(|step| matches!(step, Step::Emit(_)))
        .unwrap();
    assert_eq!(p.steps[event].failure(), StepFailure::NonFatal);
    let end = failure_state(&d, &drift(&d, 9), &p, event);
    assert_eq!(end.forwarding_v4, Known::Value(1));
    assert!(safe(&end, &d));
}

#[test]
fn loopback_exemption_depends_on_kind_in_detection_and_safety() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.links.get_mut("lo").unwrap().kind = Known::Value("veth".into());
    let p = tick(&d, &m, &Debounce::default());
    assert!(p.steps.contains(&Step::LinkDown { name: "lo".into() }));
    assert_eq!(p.budgets.attempts[SafetyClass::ForeignLink.key()].len(), 1);
    assert!(safe(&run(&m, &p.steps), &d));
    let mut m = KernelModel::desired(&d);
    let loopback = m.links.remove("lo").unwrap();
    m.links.insert("renamed-loopback".into(), loopback);
    assert!(safe(&m, &d));
    assert_eq!(tick(&d, &m, &Debounce::default()).steps, []);
}

#[test]
fn memory_latch_persistence_survives_namespace_loss() {
    let d = desired();
    let mut m = KernelModel::desired(&d);
    m.namespace = NamespaceState::InodeGone;
    let latch = Latch {
        reason: "fighting".into(),
        object: SafetyClass::TcHook.key().into(),
    };
    let mut budgets = Budgets {
        persistence_failed: true,
        ..Budgets::default()
    };
    for now in [0, 2, 4] {
        let p = plan(
            &d,
            &m,
            &budgets,
            Some(&latch),
            &Debounce::default(),
            at(now),
        );
        assert_eq!(
            p.steps,
            [
                Step::Emit(PlannerEvent::PersistenceFailed),
                Step::PersistLatch {
                    reason: latch.reason.clone(),
                    object: latch.object.clone()
                },
            ]
        );
        budgets = p.budgets;
    }
}

#[test]
fn external_forwarding_zero_spends_its_budget_and_one_suppressed_object_leaves_other_restores() {
    let d = desired();
    let m = KernelModel::desired(&d).apply(&Step::ForwardingOff);
    let mut budgets = Budgets::default();
    let debounce = tick(&d, &m, &Debounce::default()).debounce;
    for now in 0..3 {
        let p = plan(&d, &m, &budgets, None, &debounce, at(now));
        assert!(
            p.steps
                .iter()
                .any(|s| matches!(s, Step::ForwardingOn { .. }))
        );
        budgets = p.budgets;
    }
    assert_eq!(budgets.attempts["forwarding"].len(), 3);
    let p = plan(&d, &m, &budgets, None, &debounce, at(3));
    assert!(
        p.steps
            .contains(&Step::Emit(PlannerEvent::RepairSuppressed {
                object: "forwarding".into()
            }))
    );
    assert!(!p.steps.contains(&Step::ForwardingOff));
    assert!(p.latch.is_none());

    let mut m = drift(&d, 2);
    m.stale_exits.extend(d.exits().keys().cloned());
    let warm = tick(&d, &m, &Debounce::default());
    let mut budgets = Budgets::default();
    budgets
        .attempts
        .insert("endpoint:ch1".into(), vec![at(0); 3]);
    let p = plan(&d, &m, &budgets, None, &warm.debounce, at(2));
    assert!(
        p.steps
            .contains(&Step::Emit(PlannerEvent::RepairSuppressed {
                object: "endpoint:ch1".into()
            }))
    );
    assert!(
        !p.steps
            .iter()
            .any(|s| matches!(s, Step::ReResolveEndpoint { .. }))
    );
    assert!(
        p.steps
            .iter()
            .any(|s| matches!(s, Step::WriteSysctl { .. }))
    );
    assert!(!p.steps.contains(&Step::ForwardingOff));
    assert!(safe(&run(&m, &p.steps), &d));
}
