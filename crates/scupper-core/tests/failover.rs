//! DESIGN §6 health/global tables, monotonic boundaries, and I1 properties.

#![allow(clippy::unwrap_used)]

use std::{collections::BTreeMap, sync::OnceLock, time::Duration};

use proptest::prelude::*;
use scupper_core::{
    config::{ExitId, Failback, GatewayId, Standby, parse_site, validate},
    failover::*,
    render::RouteTarget,
};

fn at(seconds: u64) -> MonoTime {
    MonoTime(Duration::from_secs(seconds))
}
fn id(index: usize) -> ExitId {
    ExitId(format!("e{index}"))
}

fn config(count: usize) -> FailoverConfig {
    // Each interface still comes from validation. Combining singleton policies
    // exercises N-exit decisions without relaxing the release validation boundary.
    static CONFIGS: OnceLock<Vec<FailoverConfig>> = OnceLock::new();
    let configs = CONFIGS.get_or_init(|| {
        (0..4)
            .map(|index| {
                let text =
                    include_str!("fixtures/site-m2.toml").replace("ch1", &format!("e{index}"));
                let site = validate(parse_site(&text).unwrap()).unwrap();
                FailoverConfig::from_site(&site, &GatewayId("gw1".into())).unwrap()
            })
            .collect()
    });
    let mut cfg = configs[0].clone();
    cfg.exits = configs
        .iter()
        .take(count)
        .flat_map(|cfg| cfg.exits.clone())
        .collect();
    cfg
}

fn target(cfg: &FailoverConfig, index: usize) -> RouteTarget {
    RouteTarget::Exit(cfg.exits[index].1.clone())
}
fn handshakes(cfg: &FailoverConfig, age: Option<u64>) -> FailoverInput {
    FailoverInput::Handshakes(
        cfg.exits
            .iter()
            .map(|(id, _)| (id.clone(), age.map(Duration::from_secs)))
            .collect(),
    )
}
fn probes(values: &[(usize, bool)]) -> FailoverInput {
    FailoverInput::PathProbe(
        values
            .iter()
            .map(|(index, success)| (id(*index), *success))
            .collect(),
    )
}
fn all_probes(cfg: &FailoverConfig, success: bool) -> FailoverInput {
    FailoverInput::PathProbe(
        cfg.exits
            .iter()
            .map(|(id, _)| (id.clone(), success))
            .collect(),
    )
}
fn advance(
    machine: &mut Failover,
    now: u64,
    input: FailoverInput,
    cfg: &FailoverConfig,
) -> Vec<FailoverAction> {
    let (next, actions) = machine.step(at(now), input, cfg);
    *machine = next;
    actions
}
fn fresh(machine: &mut Failover, now: u64, cfg: &FailoverConfig) {
    advance(machine, now, handshakes(cfg, Some(0)), cfg);
}
fn qualified(cfg: &FailoverConfig) -> Failover {
    let mut machine = Failover::new(at(0), Selection::Auto, cfg).0;
    fresh(&mut machine, 0, cfg);
    for now in [0, 2, 4] {
        advance(&mut machine, now, all_probes(cfg, true), cfg);
    }
    machine
}
fn healthy_since(machine: &Failover, index: usize, seconds: u64) {
    assert_eq!(
        machine.health()[&id(index)],
        ExitHealth::Healthy { since: at(seconds) }
    );
}
fn switch_event(from: usize, to: usize, failback: bool) -> FailoverAction {
    FailoverAction::Emit(if failback {
        FailoverEvent::Failback {
            from: id(from),
            to: id(to),
        }
    } else {
        FailoverEvent::Failover {
            from: id(from),
            to: id(to),
        }
    })
}

#[test]
fn config_conversion_and_monotonic_arithmetic() {
    let site = validate(parse_site(include_str!("fixtures/site-m2.toml")).unwrap()).unwrap();
    let cfg = FailoverConfig::from_site(&site, &GatewayId("gw1".into())).unwrap();
    assert_eq!(cfg.exits[0].0, ExitId("ch1".into()));
    assert_eq!(cfg.exits[0].1.as_str(), "ex-ch1");
    assert_eq!(cfg.failback, Failback::Manual);
    assert_eq!(cfg.standby, Standby::Hot);
    assert_eq!(cfg.failback_hold, Duration::from_mins(10));
    assert_eq!(cfg.min_dwell, Duration::from_secs(120));
    assert_eq!(cfg.handshake_stale, Duration::from_secs(180));
    assert_eq!(
        FailoverConfig::from_site(&site, &GatewayId("absent".into())),
        Err(FailoverConfigError::UnknownGateway)
    );
    let mut editable = parse_site(include_str!("fixtures/site-m2.toml")).unwrap();
    editable.policy.failback = Failback::Auto;
    editable.policy.standby = Standby::Cold;
    editable.policy.failback_hold.0 = "7m".into();
    editable.policy.min_dwell.0 = "9s".into();
    editable.health.handshake_stale.0 = "240s".into();
    let site = validate(editable).unwrap();
    let cfg = FailoverConfig::from_site(&site, &GatewayId("gw1".into())).unwrap();
    assert_eq!((cfg.failback, cfg.standby), (Failback::Auto, Standby::Cold));
    assert_eq!(cfg.failback_hold, Duration::from_mins(7));
    assert_eq!(cfg.min_dwell, Duration::from_secs(9));
    assert_eq!(cfg.handshake_stale, Duration::from_secs(240));
    assert_eq!(at(2).elapsed_since(at(1)), Duration::from_secs(1));
    assert_eq!(at(1).elapsed_since(at(2)), Duration::ZERO);
    assert_eq!(
        MonoTime(Duration::MAX).after(Duration::from_secs(1)),
        MonoTime(Duration::MAX)
    );
}

#[test]
fn unknown_requires_fresh_handshake_and_three_consecutive_successes() {
    let cfg = config(1);
    let mut machine = Failover::new(at(0), Selection::Auto, &cfg).0;
    for now in 0..3 {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
    }
    assert_eq!(machine.health()[&id(0)], ExitHealth::Unknown);
    fresh(&mut machine, 3, &cfg);
    advance(&mut machine, 4, probes(&[(0, true)]), &cfg);
    advance(&mut machine, 5, probes(&[(0, true)]), &cfg);
    advance(&mut machine, 6, probes(&[(0, false)]), &cfg);
    for now in [7, 8] {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
        assert_eq!(machine.health()[&id(0)], ExitHealth::Unknown);
    }
    let actions = advance(&mut machine, 9, probes(&[(0, true)]), &cfg);
    healthy_since(&machine, 0, 9);
    assert_eq!(machine.active(), &target(&cfg, 0));
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(target(&cfg, 0)),
            FailoverAction::NotifyEdge(id(0)),
            FailoverAction::Emit(FailoverEvent::FailClosedEnded {
                duration: Duration::from_secs(9)
            })
        ]
    );
    assert_eq!(machine.fail_closed_since(), None);
    assert_eq!(machine.fail_closed_reason(), None);
    advance(&mut machine, 10, probes(&[(0, true)]), &cfg);
    healthy_since(&machine, 0, 9);
}

#[test]
fn counted_failure_diagram_and_detection_at_ten_plus_two_plus_two_seconds() {
    let cfg = config(2);
    let mut machine = qualified(&cfg);
    for (now, failures) in [(14, 1), (16, 2)] {
        assert_eq!(
            advance(&mut machine, now, probes(&[(0, false), (1, true)]), &cfg),
            []
        );
        assert_eq!(
            machine.health()[&id(0)],
            ExitHealth::Suspect {
                failures,
                since: at(14)
            }
        );
    }
    let actions = advance(&mut machine, 18, probes(&[(0, false), (1, true)]), &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Down {
            since: at(18),
            reason: DownReason::PathProbeFailed
        }
    );
    assert_eq!(machine.active(), &target(&cfg, 1));
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(target(&cfg, 1)),
            FailoverAction::FlushConntrack,
            FailoverAction::NotifyEdge(id(1)),
            switch_event(0, 1, false)
        ]
    );
    assert_eq!(
        machine.switches().iter().copied().collect::<Vec<_>>(),
        vec![at(18)]
    );
}

#[test]
fn suspect_success_resets_count_and_healthy_since() {
    let cfg = config(2);
    let mut machine = qualified(&cfg);
    advance(&mut machine, 10, probes(&[(0, false), (1, true)]), &cfg);
    advance(&mut machine, 12, probes(&[(0, true)]), &cfg);
    healthy_since(&machine, 0, 12);
    advance(&mut machine, 14, probes(&[(0, false)]), &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Suspect {
            failures: 1,
            since: at(14)
        }
    );
}

#[test]
fn comparison_window_boundary_and_common_mode() {
    let cfg = config(2);
    let initial = qualified(&cfg); // Last other success at t=4.
    for (now, counted) in [(24, true), (25, false)] {
        let (next, _) = initial.step(at(now), probes(&[(0, false)]), &cfg);
        if counted {
            assert_eq!(
                next.health()[&id(0)],
                ExitHealth::Suspect {
                    failures: 1,
                    since: at(now)
                }
            );
        } else {
            healthy_since(&next, 0, 4);
        }
    }
    let mut machine = initial;
    for now in [5, 7, 9, 20, 60, 120] {
        fresh(&mut machine, now, &cfg);
        assert_eq!(
            advance(&mut machine, now, all_probes(&cfg, false), &cfg),
            []
        );
        healthy_since(&machine, 0, 4);
        healthy_since(&machine, 1, 4);
    }
    // A newer failure invalidates an older comparison success.
    advance(&mut machine, 121, probes(&[(1, true)]), &cfg);
    advance(&mut machine, 122, probes(&[(1, false)]), &cfg);
    advance(&mut machine, 123, probes(&[(0, false)]), &cfg);
    healthy_since(&machine, 0, 4);
    // A failed standby cannot qualify a lone failing active exit.
    advance(
        &mut machine,
        124,
        FailoverInput::LinkState(
            id(1),
            ExitLinkState {
                link_up: false,
                ..ExitLinkState::default()
            },
        ),
        &cfg,
    );
    for now in [125, 127, 129] {
        advance(&mut machine, now, probes(&[(0, false)]), &cfg);
    }
    healthy_since(&machine, 0, 4);
}

fn health_states(cfg: &FailoverConfig) -> Vec<Failover> {
    let unknown = Failover::new(at(0), Selection::Auto, cfg).0;
    let healthy = qualified(cfg);
    let mut suspect = healthy.clone();
    advance(&mut suspect, 5, probes(&[(0, false), (1, true)]), cfg);
    let mut down = healthy.clone();
    advance(
        &mut down,
        5,
        FailoverInput::Handshakes(BTreeMap::from([(id(0), None)])),
        cfg,
    );
    let mut recovering = down.clone();
    fresh(&mut recovering, 6, cfg);
    vec![unknown, healthy, suspect, down, recovering]
}

#[test]
fn hard_down_from_every_health_state_and_fault_precedence() {
    let cfg = config(2);
    let cases = [
        (
            FailoverInput::Handshakes(BTreeMap::from([(id(0), None)])),
            DownReason::HandshakeStale,
        ),
        (
            FailoverInput::Handshakes(BTreeMap::from([(id(0), Some(Duration::from_secs(181)))])),
            DownReason::HandshakeStale,
        ),
        (
            FailoverInput::LinkState(
                id(0),
                ExitLinkState {
                    link_up: false,
                    ..ExitLinkState::default()
                },
            ),
            DownReason::LinkMissing,
        ),
        (
            FailoverInput::LinkState(
                id(0),
                ExitLinkState {
                    peer_present: false,
                    ..ExitLinkState::default()
                },
            ),
            DownReason::PeerMissing,
        ),
        (
            FailoverInput::LinkState(
                id(0),
                ExitLinkState {
                    key_present: false,
                    ..ExitLinkState::default()
                },
            ),
            DownReason::KeyMissing,
        ),
    ];
    for machine in health_states(&cfg) {
        for (input, reason) in &cases {
            let (mut next, _) = machine.step(at(10), input.clone(), &cfg);
            let since = if matches!(machine.health()[&id(0)], ExitHealth::Down { .. }) {
                at(5)
            } else {
                at(10)
            };
            assert_eq!(
                next.health()[&id(0)],
                ExitHealth::Down {
                    since,
                    reason: *reason
                }
            );
            advance(&mut next, 11, probes(&[(0, true)]), &cfg);
            assert!(matches!(next.health()[&id(0)], ExitHealth::Down { .. }));
            if *reason != DownReason::HandshakeStale {
                fresh(&mut next, 12, &cfg);
                assert!(matches!(next.health()[&id(0)], ExitHealth::Down { .. }));
                advance(
                    &mut next,
                    13,
                    FailoverInput::LinkState(id(0), ExitLinkState::default()),
                    &cfg,
                );
                fresh(&mut next, 14, &cfg);
                assert_eq!(
                    next.health()[&id(0)],
                    ExitHealth::Recovering {
                        successes: 0,
                        since: at(14)
                    }
                );
            }
        }
    }
}

#[test]
fn handshake_stale_is_strict_and_ages_on_ticks() {
    let cfg = config(1);
    let mut machine = qualified(&cfg);
    advance(&mut machine, 180, FailoverInput::Tick, &cfg);
    healthy_since(&machine, 0, 4);
    let actions = advance(&mut machine, 181, FailoverInput::Tick, &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Down {
            since: at(181),
            reason: DownReason::HandshakeStale
        }
    );
    assert_eq!(machine.fail_closed_since(), Some(at(181)));
    assert_eq!(
        machine.fail_closed_reason(),
        Some(&FailClosedReason::NoHealthyExit)
    );
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(RouteTarget::Unreachable),
            FailoverAction::FlushConntrack,
            FailoverAction::Emit(FailoverEvent::FailClosedStarted(
                FailClosedReason::NoHealthyExit
            ))
        ]
    );
    advance(&mut machine, 182, FailoverInput::Tick, &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Down {
            since: at(181),
            reason: DownReason::HandshakeStale
        }
    );
}

#[test]
fn l16_single_exit_recovers_and_reopens_by_itself_after_thirty_seconds() {
    let cfg = config(1);
    let mut machine = qualified(&cfg);
    advance(&mut machine, 5, handshakes(&cfg, None), &cfg);
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    fresh(&mut machine, 6, &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Recovering {
            successes: 0,
            since: at(6)
        }
    );
    for (now, successes) in [(10, 1), (20, 2), (39, 3)] {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
        assert_eq!(
            machine.health()[&id(0)],
            ExitHealth::Recovering {
                successes,
                since: at(10)
            }
        );
        assert_eq!(machine.active(), &RouteTarget::Unreachable);
    }
    // Time alone cannot turn fewer than three successes into qualification.
    let actions = advance(&mut machine, 40, probes(&[(0, true)]), &cfg);
    healthy_since(&machine, 0, 40);
    assert_eq!(machine.active(), &target(&cfg, 0));
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(target(&cfg, 0)),
            FailoverAction::NotifyEdge(id(0)),
            FailoverAction::Emit(FailoverEvent::FailClosedEnded {
                duration: Duration::from_secs(35)
            })
        ]
    );
    assert_eq!(machine.fail_closed_since(), None);
}

#[test]
fn recovery_requires_three_successes_and_any_failure_restarts_it() {
    let cfg = config(1);
    let mut machine = qualified(&cfg);
    advance(&mut machine, 5, handshakes(&cfg, None), &cfg);
    fresh(&mut machine, 6, &cfg);
    advance(&mut machine, 7, probes(&[(0, true)]), &cfg);
    advance(&mut machine, 40, probes(&[(0, true)]), &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Recovering {
            successes: 2,
            since: at(7)
        }
    );
    advance(&mut machine, 41, probes(&[(0, false)]), &cfg);
    assert_eq!(
        machine.health()[&id(0)],
        ExitHealth::Down {
            since: at(41),
            reason: DownReason::PathProbeFailed
        }
    );
    advance(&mut machine, 42, probes(&[(0, true)]), &cfg);
    assert!(matches!(machine.health()[&id(0)], ExitHealth::Down { .. }));
    fresh(&mut machine, 43, &cfg);
    for now in [44, 59, 74] {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
    }
    healthy_since(&machine, 0, 74);
}

#[test]
#[allow(clippy::too_many_lines)] // A single administrative transition sequence.
fn admin_candidates_disconnect_pin_and_immediate_re_evaluation() {
    let cfg = config(4);
    let mut machine = qualified(&cfg);
    let actions = advance(
        &mut machine,
        5,
        FailoverInput::SelectionChanged(Selection::Prefer(id(2))),
        &cfg,
    );
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(target(&cfg, 2)),
            FailoverAction::FlushConntrack,
            FailoverAction::NotifyEdge(id(2)),
            switch_event(0, 2, true)
        ]
    );
    // Admin Auto overrides sticky failback without waiting for hold/dwell.
    advance(
        &mut machine,
        6,
        FailoverInput::SelectionChanged(Selection::Auto),
        &cfg,
    );
    assert_eq!(machine.active(), &target(&cfg, 0));
    advance(
        &mut machine,
        7,
        FailoverInput::SelectionChanged(Selection::Pin(id(2))),
        &cfg,
    );
    let actions = advance(
        &mut machine,
        8,
        FailoverInput::Handshakes(BTreeMap::from([(id(2), None)])),
        &cfg,
    );
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    assert_eq!(
        machine.fail_closed_reason(),
        Some(&FailClosedReason::PinnedExitDown(id(2)))
    );
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(RouteTarget::Unreachable),
            FailoverAction::FlushConntrack,
            FailoverAction::Emit(FailoverEvent::FailClosedStarted(
                FailClosedReason::PinnedExitDown(id(2))
            ))
        ]
    );
    let actions = advance(
        &mut machine,
        9,
        FailoverInput::SelectionChanged(Selection::Disconnected),
        &cfg,
    );
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(RouteTarget::Unreachable),
            FailoverAction::FlushConntrack,
            FailoverAction::SetExitsDown
        ]
    );
    assert_eq!(
        machine.fail_closed_reason(),
        Some(&FailClosedReason::AdminDisconnected)
    );
    assert_eq!(machine.fail_closed_since(), Some(at(8)));
    let actions = advance(&mut machine, 10, FailoverInput::Tick, &cfg);
    assert_eq!(actions, []);
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    let actions = advance(
        &mut machine,
        11,
        FailoverInput::SelectionChanged(Selection::Prefer(id(3))),
        &cfg,
    );
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    assert_eq!(actions, []);
    fresh(&mut machine, 11, &cfg);
    for now in [11, 11] {
        advance(&mut machine, now, all_probes(&cfg, true), &cfg);
    }
    let actions = advance(&mut machine, 11, all_probes(&cfg, true), &cfg);
    assert_eq!(machine.active(), &target(&cfg, 3));
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(target(&cfg, 3)),
            FailoverAction::NotifyEdge(id(3)),
            FailoverAction::Emit(FailoverEvent::FailClosedEnded {
                duration: Duration::from_secs(3)
            })
        ]
    );
    advance(
        &mut machine,
        12,
        FailoverInput::SelectionChanged(Selection::Pin(id(9))),
        &cfg,
    );
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    advance(
        &mut machine,
        13,
        FailoverInput::SelectionChanged(Selection::Prefer(id(9))),
        &cfg,
    );
    assert_eq!(machine.active(), &target(&cfg, 0));
}

#[test]
fn prefer_falls_back_in_policy_order_and_pin_recovers_only_itself() {
    let cfg = config(3);
    let mut machine = qualified(&cfg);
    advance(
        &mut machine,
        5,
        FailoverInput::SelectionChanged(Selection::Prefer(id(2))),
        &cfg,
    );
    advance(
        &mut machine,
        6,
        FailoverInput::Handshakes(BTreeMap::from([(id(2), None)])),
        &cfg,
    );
    assert_eq!(machine.active(), &target(&cfg, 0));
    advance(
        &mut machine,
        7,
        FailoverInput::SelectionChanged(Selection::Pin(id(2))),
        &cfg,
    );
    fresh(&mut machine, 8, &cfg);
    for now in [9, 24, 39] {
        advance(&mut machine, now, probes(&[(2, true)]), &cfg);
    }
    assert_eq!(machine.active(), &target(&cfg, 2));
}

#[test]
fn disconnect_resets_every_state_and_ignores_observations_until_reconnect() {
    let cfg = config(2);
    for mut machine in health_states(&cfg) {
        let previous_closure = machine.fail_closed_since();
        let actions = advance(
            &mut machine,
            10,
            FailoverInput::SelectionChanged(Selection::Disconnected),
            &cfg,
        );
        assert_eq!(machine.active(), &RouteTarget::Unreachable);
        assert_eq!(
            machine.fail_closed_since(),
            Some(previous_closure.unwrap_or(at(10)))
        );
        assert_eq!(
            machine.fail_closed_reason(),
            Some(&FailClosedReason::AdminDisconnected)
        );
        assert_eq!(
            actions,
            vec![
                FailoverAction::SetRoute(RouteTarget::Unreachable),
                FailoverAction::FlushConntrack,
                FailoverAction::SetExitsDown
            ]
        );
        fresh(&mut machine, 11, &cfg);
        for now in [12, 27, 42] {
            let actions = advance(&mut machine, now, all_probes(&cfg, true), &cfg);
            assert_eq!(machine.active(), &RouteTarget::Unreachable);
            assert_eq!(actions, []);
            assert!(
                machine
                    .health()
                    .values()
                    .all(|state| *state == ExitHealth::Unknown)
            );
        }
        advance(
            &mut machine,
            43,
            FailoverInput::SelectionChanged(Selection::Auto),
            &cfg,
        );
        assert_eq!(machine.active(), &RouteTarget::Unreachable);
        for now in [43, 44, 45] {
            advance(&mut machine, now, all_probes(&cfg, true), &cfg);
        }
        assert_eq!(machine.active(), &RouteTarget::Unreachable);
        fresh(&mut machine, 46, &cfg);
        for now in [46, 48, 50] {
            advance(&mut machine, now, all_probes(&cfg, true), &cfg);
        }
        assert_eq!(machine.active(), &target(&cfg, 0));
    }
}

#[test]
fn no_healthy_candidate_waits_and_unknown_observations_cannot_inject_routes() {
    let cfg = config(3);
    let mut machine = qualified(&cfg);
    let actions = advance(&mut machine, 10, handshakes(&cfg, None), &cfg);
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    assert_eq!(
        machine.fail_closed_reason(),
        Some(&FailClosedReason::NoHealthyExit)
    );
    assert_eq!(
        actions,
        vec![
            FailoverAction::SetRoute(RouteTarget::Unreachable),
            FailoverAction::FlushConntrack,
            FailoverAction::Emit(FailoverEvent::FailClosedStarted(
                FailClosedReason::NoHealthyExit
            ))
        ]
    );
    assert_eq!(advance(&mut machine, 11, FailoverInput::Tick, &cfg), []);
    let before = machine.clone();
    for input in [
        probes(&[(99, true)]),
        FailoverInput::Handshakes(BTreeMap::from([(id(99), Some(Duration::ZERO))])),
        FailoverInput::LinkState(id(99), ExitLinkState::default()),
    ] {
        assert_eq!(advance(&mut machine, 11, input, &cfg), []);
        assert_eq!(machine, before);
    }
    // Fresh handshakes alone leave all candidates Recovering and the route closed.
    fresh(&mut machine, 12, &cfg);
    assert_eq!(
        advance(
            &mut machine,
            13,
            FailoverInput::SelectionChanged(Selection::Auto),
            &cfg
        ),
        []
    );
    assert_eq!(machine.active(), &RouteTarget::Unreachable);
    for now in [14, 29, 44] {
        advance(&mut machine, now, probes(&[(2, true)]), &cfg);
    }
    assert_eq!(machine.active(), &target(&cfg, 2));
}

#[test]
fn failback_hold_and_min_dwell_boundaries_and_manual_stickiness() {
    for mode in [Failback::Manual, Failback::Auto] {
        let mut cfg = config(2);
        cfg.failback = mode;
        let mut machine = qualified(&cfg);
        advance(
            &mut machine,
            5,
            FailoverInput::SelectionChanged(Selection::Prefer(id(1))),
            &cfg,
        );
        // Change intent back to Auto while preferred e0 is Down, so the current
        // route stays e1. Recover e0 at t=40, starting the ten-minute hold.
        advance(
            &mut machine,
            6,
            FailoverInput::Handshakes(BTreeMap::from([(id(0), None)])),
            &cfg,
        );
        advance(
            &mut machine,
            7,
            FailoverInput::SelectionChanged(Selection::Auto),
            &cfg,
        );
        fresh(&mut machine, 8, &cfg);
        for now in [10, 25, 40] {
            advance(&mut machine, now, probes(&[(0, true)]), &cfg);
        }
        healthy_since(&machine, 0, 40);
        fresh(&mut machine, 639, &cfg);
        advance(&mut machine, 639, all_probes(&cfg, true), &cfg);
        assert_eq!(machine.active(), &target(&cfg, 1));
        let actions = advance(&mut machine, 640, FailoverInput::Tick, &cfg);
        if mode == Failback::Auto {
            assert_eq!(
                actions,
                vec![
                    FailoverAction::SetRoute(target(&cfg, 0)),
                    FailoverAction::FlushConntrack,
                    FailoverAction::NotifyEdge(id(0)),
                    switch_event(1, 0, true)
                ]
            );
        } else {
            assert_eq!(actions, []);
            assert_eq!(machine.active(), &target(&cfg, 1));
        }
    }
    let mut cfg = config(2);
    cfg.failback = Failback::Auto;
    cfg.failback_hold = Duration::from_secs(1);
    let mut machine = qualified(&cfg);
    advance(
        &mut machine,
        5,
        FailoverInput::SelectionChanged(Selection::Prefer(id(1))),
        &cfg,
    );
    advance(
        &mut machine,
        6,
        FailoverInput::Handshakes(BTreeMap::from([(id(0), None)])),
        &cfg,
    );
    advance(
        &mut machine,
        7,
        FailoverInput::SelectionChanged(Selection::Auto),
        &cfg,
    );
    fresh(&mut machine, 8, &cfg);
    for now in [9, 24, 39] {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
    }
    advance(&mut machine, 124, all_probes(&cfg, true), &cfg);
    assert_eq!(advance(&mut machine, 124, FailoverInput::Tick, &cfg), []);
    assert_eq!(machine.active(), &target(&cfg, 1));
    advance(&mut machine, 125, FailoverInput::Tick, &cfg);
    assert_eq!(machine.active(), &target(&cfg, 0));
}

#[test]
fn common_mode_also_blocks_timer_driven_failback_until_a_path_succeeds() {
    let mut cfg = config(2);
    cfg.failback = Failback::Auto;
    cfg.failback_hold = Duration::from_secs(1);
    cfg.min_dwell = Duration::from_secs(1);
    let mut machine = qualified(&cfg);
    advance(
        &mut machine,
        5,
        FailoverInput::SelectionChanged(Selection::Prefer(id(1))),
        &cfg,
    );
    advance(
        &mut machine,
        6,
        FailoverInput::Handshakes(BTreeMap::from([(id(0), None)])),
        &cfg,
    );
    advance(
        &mut machine,
        7,
        FailoverInput::SelectionChanged(Selection::Auto),
        &cfg,
    );
    fresh(&mut machine, 8, &cfg);
    for now in [10, 25, 40] {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
    }
    assert_eq!(machine.active(), &target(&cfg, 1));
    advance(&mut machine, 40, all_probes(&cfg, false), &cfg);
    for now in [41, 100] {
        assert_eq!(advance(&mut machine, now, FailoverInput::Tick, &cfg), []);
        assert_eq!(machine.active(), &target(&cfg, 1));
    }
    advance(&mut machine, 101, probes(&[(0, true)]), &cfg);
    assert_eq!(machine.active(), &target(&cfg, 0));
}

#[test]
fn flapping_window_suppression_expiry_and_admin_override() {
    let mut cfg = config(3);
    cfg.failback = Failback::Auto;
    let mut machine = qualified(&cfg);
    for (now, selected) in [(10, 1), (20, 0), (30, 1), (40, 0), (50, 1)] {
        let actions = advance(
            &mut machine,
            now,
            FailoverInput::SelectionChanged(Selection::Prefer(id(selected))),
            &cfg,
        );
        assert_eq!(
            actions.contains(&FailoverAction::Emit(FailoverEvent::Flapping)),
            now == 50
        );
    }
    assert_eq!(machine.failback_suppressed_until(), Some(at(3650)));
    // Admin can switch while suppressed; suppression doesn't block failure handling.
    let mut admin = machine.clone();
    advance(
        &mut admin,
        51,
        FailoverInput::SelectionChanged(Selection::Auto),
        &cfg,
    );
    assert_eq!(admin.active(), &target(&cfg, 0));
    let mut failed = machine.clone();
    advance(
        &mut failed,
        51,
        FailoverInput::Handshakes(BTreeMap::from([(id(1), None)])),
        &cfg,
    );
    assert_eq!(failed.active(), &target(&cfg, 0));
    // Put e0 first in intent while it is unavailable, then recover it.
    advance(
        &mut machine,
        51,
        FailoverInput::Handshakes(BTreeMap::from([(id(0), None)])),
        &cfg,
    );
    advance(
        &mut machine,
        52,
        FailoverInput::SelectionChanged(Selection::Auto),
        &cfg,
    );
    fresh(&mut machine, 53, &cfg);
    for now in [54, 69, 84] {
        advance(&mut machine, now, probes(&[(0, true)]), &cfg);
    }
    fresh(&mut machine, 3649, &cfg);
    advance(&mut machine, 3649, all_probes(&cfg, true), &cfg);
    assert_eq!(machine.active(), &target(&cfg, 1));
    assert_eq!(machine.failback_suppressed_until(), Some(at(3650)));
    let actions = advance(&mut machine, 3650, FailoverInput::Tick, &cfg);
    assert_eq!(machine.active(), &target(&cfg, 0));
    assert_eq!(machine.failback_suppressed_until(), None);
    assert!(!actions.contains(&FailoverAction::Emit(FailoverEvent::Flapping)));
    assert_eq!(machine.switches().len(), 1);

    // Exact thirty-minute endpoint is included; one second later it is evicted.
    let mut boundary = qualified(&cfg);
    for (now, selected) in [(10, 1), (20, 0), (30, 1), (40, 0)] {
        advance(
            &mut boundary,
            now,
            FailoverInput::SelectionChanged(Selection::Prefer(id(selected))),
            &cfg,
        );
    }
    for (now, flapping) in [(1810, true), (1811, false)] {
        let mut branch = boundary.clone();
        fresh(&mut branch, now, &cfg);
        let actions = advance(
            &mut branch,
            now,
            FailoverInput::SelectionChanged(Selection::Prefer(id(1))),
            &cfg,
        );
        assert_eq!(
            actions.contains(&FailoverAction::Emit(FailoverEvent::Flapping)),
            flapping
        );
    }
}

#[test]
fn standby_modes_are_noops_and_removed_config_targets_fail_closed() {
    let mut hot = config(3);
    let mut cold = hot.clone();
    cold.standby = Standby::Cold;
    let machine = qualified(&hot);
    let input = FailoverInput::Handshakes(BTreeMap::from([(id(0), None)]));
    assert_eq!(
        machine.step(at(10), input.clone(), &hot),
        machine.step(at(10), input, &cold)
    );
    hot.exits.clear();
    let (next, actions) = machine.step(at(10), FailoverInput::Tick, &hot);
    assert_eq!(next.active(), &RouteTarget::Unreachable);
    assert!(next.health().is_empty());
    assert!(actions.contains(&FailoverAction::SetRoute(RouteTarget::Unreachable)));
}

fn selection(kind: u8, selected: usize) -> Selection {
    match kind % 4 {
        0 => Selection::Auto,
        1 => Selection::Prefer(id(selected)),
        2 => Selection::Pin(id(selected)),
        _ => Selection::Disconnected,
    }
}
fn permitted(target: &RouteTarget, cfg: &FailoverConfig) -> bool {
    *target == RouteTarget::Unreachable
        || cfg
            .exits
            .iter()
            .any(|(_, iface)| *target == RouteTarget::Exit(iface.clone()))
}
fn pin_permits(target: &RouteTarget, pinned: &ExitId, cfg: &FailoverConfig) -> bool {
    *target == RouteTarget::Unreachable
        || cfg
            .exits
            .iter()
            .any(|(id, iface)| id == pinned && *target == RouteTarget::Exit(iface.clone()))
}

proptest! {
    #[test]
    fn random_streams_preserve_i1_pins_alphabet_disconnect_and_determinism(
        count in 1_usize..=4, automatic in any::<bool>(), initial in 0_u8..4, bootstrapped in any::<bool>(),
        stream in prop::collection::vec((prop_oneof![9 => 0_u64..12, 1 => 120_u64..700], 0_u8..12, 0_usize..6, any::<bool>(), 0_u16..250), 60..180)
    ) {
        let mut cfg = config(count);
        if automatic { cfg.failback = Failback::Auto; }
        let mut machine = if bootstrapped { qualified(&cfg) } else { Failover::new(at(4), Selection::Auto, &cfg).0 };
        advance(&mut machine, 4, FailoverInput::SelectionChanged(selection(initial, 0)), &cfg);
        let mut now = 4;
        for (delta, kind, selected, success, age) in stream {
            now += delta;
            // Most steps retain fresh handshakes; explicit stale events still exercise hard faults.
            fresh(&mut machine, now, &cfg);
            if kind == 10 && cfg.exits.len() > 1 {
                cfg.exits.remove(selected % cfg.exits.len());
            } else if kind == 11 {
                cfg.exits.reverse();
            }
            let input = match kind {
                0 => FailoverInput::Handshakes(BTreeMap::from([(id(selected), success.then(|| Duration::from_secs(u64::from(age))))])),
                1 | 8 | 9 => FailoverInput::PathProbe(cfg.exits.iter().map(|(exit, _)| (exit.clone(), exit != &id(selected % count) || success)).collect()),
                2 => FailoverInput::LinkState(id(selected), ExitLinkState { link_up: success, ..ExitLinkState::default() }),
                3 => FailoverInput::LinkState(id(selected), ExitLinkState { peer_present: success, ..ExitLinkState::default() }),
                4 => FailoverInput::LinkState(id(selected), ExitLinkState { key_present: success, ..ExitLinkState::default() }),
                5 => FailoverInput::SelectionChanged(selection(age.to_le_bytes()[0], selected)),
                6 => all_probes(&cfg, success),
                7 => handshakes(&cfg, Some(0)),
                _ => FailoverInput::Tick,
            };
            let admin = matches!(input, FailoverInput::SelectionChanged(_));
            let (next, actions) = machine.step(at(now), input.clone(), &cfg);
            prop_assert_eq!(machine.step(at(now), input, &cfg), (next.clone(), actions.clone()));
            prop_assert!(permitted(next.active(), &cfg));
            if let Selection::Pin(pinned) = next.selection() {
                prop_assert!(pin_permits(next.active(), pinned, &cfg));
            }
            if matches!(machine.active(), RouteTarget::Exit(_)) && next.active() != machine.active()
                && matches!(next.active(), RouteTarget::Exit(_)) {
                let route_position = actions.iter().position(|action| matches!(action, FailoverAction::SetRoute(_))).unwrap();
                prop_assert_eq!(actions.get(route_position + 1), Some(&FailoverAction::FlushConntrack));
            }
            prop_assert_eq!(next.desired_route(), next.active());
            // Exhaustive match deliberately fails to compile if the alphabet grows.
            for action in &actions {
                match action {
                    FailoverAction::SetRoute(route) => {
                        prop_assert!(permitted(route, &cfg));
                        if let Selection::Pin(pinned) = next.selection() {
                            prop_assert!(pin_permits(route, pinned, &cfg));
                        }
                    }
                    FailoverAction::FlushConntrack | FailoverAction::SetExitsDown |
                    FailoverAction::NotifyEdge(_) | FailoverAction::Emit(_) => {}
                }
            }
            if *next.selection() == Selection::Disconnected {
                prop_assert_eq!(next.active(), &RouteTarget::Unreachable);
                if *machine.selection() == Selection::Disconnected {
                    prop_assert_eq!(&actions, &[]);
                } else {
                    prop_assert_eq!(&actions, &vec![FailoverAction::SetRoute(RouteTarget::Unreachable), FailoverAction::FlushConntrack, FailoverAction::SetExitsDown]);
                }
            }
            if !automatic && !admin && *next.selection() != Selection::Disconnected {
                let active = cfg.exits.iter().find(|(_, iface)| *machine.active() == RouteTarget::Exit(iface.clone()));
                if let Some((id, _)) = active
                    && matches!(next.health().get(id), Some(ExitHealth::Healthy { .. }))
                    && permitted(machine.active(), &cfg) {
                    prop_assert_eq!(next.active(), machine.active());
                }
            }
            machine = next;
        }
    }

    #[test]
    fn common_mode_with_fresh_handshakes_never_switches(
        count in 1_usize..=4, kind in 0_u8..4, selected in 0_usize..4,
        deltas in prop::collection::vec(0_u64..12, 3..100)
    ) {
        let cfg = config(count);
        let mut machine = qualified(&cfg);
        advance(&mut machine, 5, FailoverInput::SelectionChanged(selection(kind, selected % count)), &cfg);
        let route = machine.active().clone();
        let mut now = 5;
        for delta in deltas {
            now += delta;
            let handshake_actions = advance(&mut machine, now, handshakes(&cfg, Some(0)), &cfg);
            let actions = advance(&mut machine, now, all_probes(&cfg, false), &cfg);
            prop_assert_eq!(machine.active(), &route);
            prop_assert!(handshake_actions.iter().chain(&actions).all(|action| !matches!(action,
                FailoverAction::Emit(FailoverEvent::Failover { .. } | FailoverEvent::Failback { .. }))), "common-mode failure switched exits");
        }
    }
}

#[test]
fn config_removal_and_interface_change_are_switches_with_flush_and_no_false_reopening() {
    let cfg = config(2);
    for rename in [false, true] {
        let mut machine = qualified(&cfg);
        let mut changed = cfg.clone();
        if rename {
            changed.exits[0].1 = cfg.exits[1].1.clone();
        } else {
            changed.exits.remove(0);
        }
        let actions = advance(&mut machine, 10, FailoverInput::Tick, &changed);
        assert_eq!(machine.active(), &target(&cfg, 1));
        assert_eq!(actions[0], FailoverAction::SetRoute(target(&cfg, 1)));
        assert_eq!(actions[1], FailoverAction::FlushConntrack);
        assert!(actions.contains(&switch_event(0, usize::from(!rename), false)));
        assert!(!actions.iter().any(|a| matches!(
            a,
            FailoverAction::Emit(FailoverEvent::FailClosedEnded { .. })
        )));
        assert_eq!(machine.switches().len(), 1);
    }
}

#[test]
fn duplicate_interfaces_preserve_active_identity_without_churning() {
    let mut cfg = config(2);
    cfg.exits[1].1 = cfg.exits[0].1.clone();
    let mut machine = qualified(&cfg);
    advance(
        &mut machine,
        5,
        FailoverInput::SelectionChanged(Selection::Pin(id(1))),
        &cfg,
    );
    assert_eq!(advance(&mut machine, 6, FailoverInput::Tick, &cfg), []);
    assert_eq!(machine.switches().len(), 1);
}

#[test]
fn complete_common_mode_rounds_never_use_a_previous_rounds_success() {
    let cfg = config(2);
    let mut machine = qualified(&cfg);
    advance(&mut machine, 5, probes(&[(1, true)]), &cfg);
    for now in [10, 12, 14] {
        fresh(&mut machine, now, &cfg);
        // The caller collects both same-instant results before delivering the round.
        assert_eq!(
            advance(&mut machine, now, probes(&[(0, false), (1, false)]), &cfg),
            []
        );
        assert_eq!(machine.active(), &target(&cfg, 0));
        healthy_since(&machine, 0, 4);
    }
}

#[test]
fn common_mode_blocks_failback_with_down_and_never_probed_standbys() {
    for count in 2..=4 {
        for down in [false, true] {
            let mut cfg = config(count);
            cfg.failback = Failback::Auto;
            let mut machine = Failover::new(at(0), Selection::Auto, &cfg).0;
            fresh(&mut machine, 0, &cfg);
            for now in [0, 2, 4] {
                advance(&mut machine, now, probes(&[(0, true), (1, true)]), &cfg);
            }
            if down {
                for index in 2..count {
                    advance(
                        &mut machine,
                        5,
                        FailoverInput::LinkState(
                            id(index),
                            ExitLinkState {
                                link_up: false,
                                ..ExitLinkState::default()
                            },
                        ),
                        &cfg,
                    );
                }
            }
            for now in [7, 9, 11] {
                advance(&mut machine, now, probes(&[(0, false), (1, true)]), &cfg);
            }
            assert_eq!(machine.active(), &target(&cfg, 1));
            fresh(&mut machine, 12, &cfg);
            for now in [13, 30, 45] {
                advance(&mut machine, now, probes(&[(0, true), (1, true)]), &cfg);
            }
            healthy_since(&machine, 0, 45);
            // Common mode starts before the healthy hold expires, with fresh handshakes.
            for now in (50..=700).step_by(5) {
                let handshake_actions = advance(&mut machine, now, handshakes(&cfg, Some(0)), &cfg);
                let actions = if now < 600 {
                    advance(&mut machine, now, probes(&[(0, true), (1, true)]), &cfg)
                } else {
                    advance(&mut machine, now, probes(&[(0, false), (1, false)]), &cfg)
                };
                assert_eq!(handshake_actions, []);
                assert_eq!(actions, []);
                assert_eq!(machine.active(), &target(&cfg, 1));
            }
            // Even an operator re-evaluation cannot switch onto the failing path.
            assert_eq!(
                advance(
                    &mut machine,
                    701,
                    FailoverInput::SelectionChanged(Selection::Auto),
                    &cfg
                ),
                []
            );
            assert_eq!(machine.active(), &target(&cfg, 1));
            advance(&mut machine, 702, probes(&[(0, true), (1, true)]), &cfg);
            assert_eq!(machine.active(), &target(&cfg, 0));
        }
    }
}

#[test]
fn startup_restart_and_tick_reconciliation_always_assert_the_desired_route() {
    let cfg = config(2);
    for selection in [
        Selection::Auto,
        Selection::Pin(id(0)),
        Selection::Disconnected,
    ] {
        // Model a restart with a route left behind by a previous process.
        let previous_route = target(&cfg, 1);
        let (mut machine, actions) = Failover::new(at(0), selection.clone(), &cfg);
        let mut applied = previous_route.clone();
        for action in &actions {
            if let FailoverAction::SetRoute(route) = action {
                applied = route.clone();
            }
        }
        assert_eq!(applied, RouteTarget::Unreachable);
        assert_eq!(
            actions[..2],
            [
                FailoverAction::SetRoute(RouteTarget::Unreachable),
                FailoverAction::FlushConntrack
            ]
        );
        assert_eq!(
            actions.contains(&FailoverAction::SetExitsDown),
            selection == Selection::Disconnected
        );
        for now in 1..50 {
            assert_eq!(advance(&mut machine, now, FailoverInput::Tick, &cfg), []);
            // Reconciler contract: overwrite any drift on every tick, without
            // waiting for a transition action from the machine.
            let observed_route = previous_route.clone();
            assert_ne!(&observed_route, machine.desired_route());
            applied = machine.desired_route().clone();
            assert_eq!(applied, RouteTarget::Unreachable);
        }
        if selection == Selection::Pin(id(0)) {
            fresh(&mut machine, 50, &cfg);
            for now in [50, 52, 54] {
                advance(&mut machine, now, probes(&[(1, true)]), &cfg);
                assert_eq!(machine.desired_route(), &RouteTarget::Unreachable);
            }
            for now in [56, 58, 60] {
                advance(&mut machine, now, probes(&[(0, true)]), &cfg);
            }
            assert_eq!(machine.desired_route(), &target(&cfg, 0));
        }
    }
}

#[derive(Default, Debug)]
struct Coverage {
    states: [usize; 5],
    path_failovers: usize,
    failbacks: usize,
    flapping: usize,
}

impl Coverage {
    fn record(&mut self, machine: &Failover, actions: &[FailoverAction]) {
        for state in machine.health().values() {
            let index = match state {
                ExitHealth::Unknown => 0,
                ExitHealth::Healthy { .. } => 1,
                ExitHealth::Suspect { .. } => 2,
                ExitHealth::Down { .. } => 3,
                ExitHealth::Recovering { .. } => 4,
            };
            self.states[index] += 1;
        }
        for action in actions {
            match action {
                FailoverAction::Emit(FailoverEvent::Failover { from, .. })
                    if matches!(
                        machine.health()[from],
                        ExitHealth::Down {
                            reason: DownReason::PathProbeFailed,
                            ..
                        }
                    ) =>
                {
                    self.path_failovers += 1;
                }
                FailoverAction::Emit(FailoverEvent::Failback { .. }) => self.failbacks += 1,
                FailoverAction::Emit(FailoverEvent::Flapping) => self.flapping += 1,
                _ => {}
            }
        }
    }
}

fn covered_round(
    machine: &mut Failover,
    now: u64,
    results: &[(usize, bool)],
    cfg: &FailoverConfig,
    coverage: &mut Coverage,
) {
    let actions = advance(machine, now, handshakes(cfg, Some(0)), cfg);
    coverage.record(machine, &actions);
    let previous = machine.active().clone();
    let actions = advance(machine, now, probes(results), cfg);
    if matches!(previous, RouteTarget::Exit(_)) && machine.active() != &previous {
        assert_eq!(actions.get(1), Some(&FailoverAction::FlushConntrack));
    }
    assert!(permitted(machine.desired_route(), cfg));
    coverage.record(machine, &actions);
}

proptest! {
    #[test]
    fn generated_probe_episodes_cover_health_failover_failback_and_flapping(
        // Each episode biases one exit's path down for three rounds, then lets
        // it recover. Jitter stays inside the comparison window and handshakes
        // remain fresh. No operator switches can satisfy these coverage guards.
        episodes in prop::collection::vec((1_u64..6, 4_u64..9), 6..10)
    ) {
        let mut cfg = config(2);
        cfg.failback = Failback::Auto;
        cfg.failback_hold = Duration::from_secs(8);
        cfg.min_dwell = Duration::ZERO;
        let mut machine = Failover::new(at(0), Selection::Auto, &cfg).0;
        let mut coverage = Coverage::default();
        coverage.record(&machine, &[]);
        let mut now = 0;
        for _ in 0..3 {
            covered_round(&mut machine, now, &[(0, true), (1, true)], &cfg, &mut coverage);
            now += 2;
        }
        for (failure_gap, recovery_gap) in episodes {
            let failing = usize::from(machine.active() == &target(&cfg, 1));
            for _ in 0..3 {
                now += failure_gap;
                covered_round(&mut machine, now, &[(failing, false), (1 - failing, true)], &cfg, &mut coverage);
            }
            for _ in 0..16 {
                now += recovery_gap;
                covered_round(&mut machine, now, &[(0, true), (1, true)], &cfg, &mut coverage);
            }
        }
        prop_assert!(coverage.states.iter().all(|count| *count >= 1), "missing health state: {coverage:?}");
        prop_assert!(coverage.path_failovers >= 6, "too few path failovers: {coverage:?}");
        prop_assert!(coverage.failbacks >= 1, "no automatic failback: {coverage:?}");
        prop_assert!(coverage.flapping >= 1, "no probe-driven flapping: {coverage:?}");
    }
}

#[test]
fn inconclusive_probes_preserve_initial_and_recovery_qualification() {
    let cfg = config(1);
    let inconclusive =
        || FailoverInput::ProbeRound(BTreeMap::from([(id(0), ProbeOutcome::Inconclusive)]));
    let mut initial = Failover::new(at(0), Selection::Auto, &cfg).0;
    fresh(&mut initial, 0, &cfg);
    advance(&mut initial, 0, probes(&[(0, true)]), &cfg);
    advance(&mut initial, 1, inconclusive(), &cfg);
    advance(&mut initial, 2, probes(&[(0, true)]), &cfg);
    advance(&mut initial, 3, probes(&[(0, true)]), &cfg);
    healthy_since(&initial, 0, 3);
    advance(&mut initial, 4, handshakes(&cfg, None), &cfg);
    fresh(&mut initial, 5, &cfg);
    advance(&mut initial, 6, probes(&[(0, true)]), &cfg);
    let health = initial.health().clone();
    let actions = advance(&mut initial, 7, inconclusive(), &cfg);
    assert_eq!(initial.health(), &health);
    assert_eq!(actions, []);
    advance(&mut initial, 20, probes(&[(0, true)]), &cfg);
    advance(&mut initial, 36, probes(&[(0, true)]), &cfg);
    healthy_since(&initial, 0, 36);
}

#[test]
fn inconclusive_probe_neither_counts_as_failure_nor_witnesses_another_failure() {
    let cfg = config(2);
    let mut machine = qualified(&cfg);
    let actions = advance(
        &mut machine,
        5,
        FailoverInput::ProbeRound(BTreeMap::from([
            (id(0), ProbeOutcome::Failure),
            (id(1), ProbeOutcome::Inconclusive),
        ])),
        &cfg,
    );
    assert_eq!(actions, []);
    healthy_since(&machine, 0, 4);
    healthy_since(&machine, 1, 4);
    let actions = advance(
        &mut machine,
        6,
        FailoverInput::ProbeRound(BTreeMap::from([
            (id(0), ProbeOutcome::Inconclusive),
            (id(1), ProbeOutcome::Success),
        ])),
        &cfg,
    );
    assert_eq!(actions, []);
    healthy_since(&machine, 0, 4);
}
