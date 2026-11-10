//! DESIGN §12's M2 verdict table, boundary cases and staging properties.

#![allow(clippy::unwrap_used)] // Invalid fixtures or mutations must fail these tests.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::OnceLock,
    time::Duration,
};

use proptest::prelude::*;
use scupper_core::{
    config::{ExitId, GatewayId, parse_site, validate},
    parse::{Handshake, ParseError, UdpSocket},
    render::RouteTarget,
    rules::IfName,
    verdict::v2::*,
};

const NETNS: NetnsIdentity = NetnsIdentity {
    device: 7,
    inode: 42,
};

const NOW: u64 = 10_000;
const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
const UPLINK: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2));

fn config() -> HealthConfigV2 {
    static CONFIG: OnceLock<HealthConfigV2> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let site =
                validate(parse_site(include_str!("fixtures/site-m2.toml")).unwrap()).unwrap();
            HealthConfigV2::new(&site, &GatewayId("gw1".into()), NETNS, vec![UPLINK], 7).unwrap()
        })
        .clone()
}

fn exit_id() -> ExitId {
    ExitId("ch1".into())
}
fn dev(name: &str) -> RouteAnswer {
    RouteAnswer::Dev(IfName::new(name).unwrap())
}
fn route(v4: RouteAnswer) -> RouteObs {
    RouteObs {
        v4: Ok(v4),
        v6: Ok(RouteAnswer::Unreachable),
    }
}
fn defaults(obs: &mut Observations) -> &mut DefaultRoutes {
    obs.defaults.as_mut().unwrap().as_mut().unwrap()
}
fn current() -> Handshake {
    Handshake::At { unix_secs: NOW }
}

fn passing() -> Observations {
    Observations {
        topology: Some(Ok(TopologyObs {
            host_wireguard_on_client_port: vec![],
            errors: vec![],
            links_complete: true,
            addresses_complete: true,
            netns: NetnsObs::Present {
                device: NETNS.device,
                inode: NETNS.inode,
            },
            links: vec![
                LinkObs {
                    name: "lo".into(),
                    kind: None,
                    up: true,
                    addresses: vec!["127.0.0.1/8".parse().unwrap()],
                },
                LinkObs {
                    name: "wg0".into(),
                    kind: Some("wireguard".into()),
                    up: true,
                    addresses: vec!["10.99.0.1/24".parse().unwrap()],
                },
                LinkObs {
                    name: "ex-ch1".into(),
                    kind: Some("wireguard".into()),
                    up: true,
                    addresses: vec!["10.2.0.2/32".parse().unwrap()],
                },
            ],
            peers: BTreeMap::from([
                (
                    "wg0".into(),
                    vec![PeerObs {
                        public_key: [2; 32],
                        allowed_ips: vec!["10.99.0.2/32".parse().unwrap()],
                        endpoint: Some("192.0.2.3:5555".parse().unwrap()),
                    }],
                ),
                (
                    "ex-ch1".into(),
                    vec![PeerObs {
                        public_key: [1; 32],
                        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                        endpoint: Some("203.0.113.10:51820".parse().unwrap()),
                    }],
                ),
            ]),
            ruleset: RulesetObs::Exact,
            extra_rules: vec![],
            tc_hooks: vec![],
        })),
        defaults: Some(Ok(DefaultRoutes {
            violations: vec![],
            v4: dev("ex-ch1").into(),
            v6: DefaultRouteObs::Unreachable,
            extra: vec![],
        })),
        selection: Selection::Auto,
        active: RouteTarget::Exit(config().exit_iface),
        handshakes: Some(Ok(BTreeMap::from([(exit_id(), current())]))),
        forwarding: Some(Ok(Forwarding {
            client_v4: 1,
            netns_sockets: vec![],
            hardening: vec![],
            v4: 1,
            v6: 0,
            quarantine: None,
            client_public_key: Some([0; 32]),
            listen_port: 51820,
            host_sockets: vec![UdpSocket {
                local: "0.0.0.0:51820".parse().unwrap(),
                inode: 99,
            }],
            client_handshakes: BTreeMap::from([([2; 32], current())]),
        })),
        routes: Some(vec![(CLIENT, route(dev("ex-ch1")))]),
        exit_probe: Some(Ok(PUBLIC)),
        standby_probe: None,
        dns: None,
        supervisor: Some(Supervisor::Alive {
            netns: NETNS,
            iteration_age: Duration::from_secs(1),
        }),
    }
}

fn topology(obs: &mut Observations) -> &mut TopologyObs {
    obs.topology.as_mut().unwrap().as_mut().unwrap()
}
fn forwarding(obs: &mut Observations) -> &mut Forwarding {
    obs.forwarding.as_mut().unwrap().as_mut().unwrap()
}
fn handshakes(obs: &mut Observations) -> &mut BTreeMap<ExitId, Handshake> {
    obs.handshakes.as_mut().unwrap().as_mut().unwrap()
}
fn report_with(obs: &Observations, cfg: &HealthConfigV2) -> Report {
    let result = next(obs, cfg, NOW);
    assert!(matches!(result, Next::Done(Ok(_))), "{result:?}");
    if let Next::Done(Ok(report)) = result {
        report
    } else {
        unreachable!()
    }
}
fn report(obs: &Observations) -> Report {
    report_with(obs, &config())
}
fn code(result: &Next) -> Option<u8> {
    match result {
        Next::Done(Ok(report)) => Some(report.verdict.exit_code()),
        Next::Done(Err(error)) => Some(error.exit_code()),
        _ => None,
    }
}
fn assert_violation(obs: &Observations, want: Violation) {
    let result = report(obs);
    assert_eq!(result.verdict.exit_code(), 2);
    assert_eq!(result.verdict, Verdict::Unprotected(NonEmpty::new(want)));
}
fn assert_degraded(obs: &Observations, want: Degraded) {
    let result = report(obs);
    assert_eq!(result.verdict.exit_code(), 3);
    assert_eq!(result.verdict, Verdict::Degraded(want));
}
fn assert_closed(obs: &Observations, want: FailClosed) {
    let result = report(obs);
    assert_eq!(result.verdict.exit_code(), 4);
    assert_eq!(result.verdict, Verdict::FailClosed(want));
}

#[test]
fn protected_has_time_and_applied_version() {
    let result = report(&passing());
    assert_eq!(
        result.verdict,
        Verdict::Protected {
            exit: exit_id(),
            exit_ip: PUBLIC
        }
    );
    assert_eq!(result.verdict.exit_code(), 0);
    assert_eq!(result.at, NOW);
    assert_eq!(result.config_version, 7);
    assert_eq!(result.warnings, Vec::<Warning>::new());
}

#[test]
fn netns_missing() {
    let mut obs = passing();
    topology(&mut obs).netns = NetnsObs::Missing;
    assert_violation(&obs, Violation::NetnsMissing);
}
#[test]
fn netns_wrong_inode() {
    for state in [
        NetnsObs::WrongInode,
        NetnsObs::Present {
            device: NETNS.device,
            inode: 43,
        },
    ] {
        let mut obs = passing();
        topology(&mut obs).netns = state;
        assert_violation(&obs, Violation::NetnsWrongInode);
    }
}
#[test]
fn foreign_link() {
    let mut obs = passing();
    topology(&mut obs).links.push(LinkObs {
        name: "Foreign@42".into(),
        kind: Some("wireguard".into()),
        up: false,
        addresses: vec![],
    });
    assert_violation(&obs, Violation::ForeignLink("Foreign@42".into()));
}
#[test]
fn link_kind() {
    for kind in [None, Some("veth".into())] {
        let mut obs = passing();
        topology(&mut obs).links[1].kind = kind;
        assert_violation(&obs, Violation::LinkKind("wg0".into()));
    }
}
#[test]
fn peer_differs() {
    let mut obs = passing();
    topology(&mut obs).peers.get_mut("ex-ch1").unwrap()[0].public_key = [9; 32];
    assert_violation(
        &obs,
        Violation::PeerDiffers {
            ifname: "ex-ch1".into(),
        },
    );
    let mut obs = passing();
    topology(&mut obs).peers.get_mut("wg0").unwrap()[0].allowed_ips =
        vec!["0.0.0.0/0".parse().unwrap()];
    assert_violation(
        &obs,
        Violation::PeerDiffers {
            ifname: "wg0".into(),
        },
    );
}
#[test]
fn ruleset_missing() {
    let mut obs = passing();
    topology(&mut obs).ruleset = RulesetObs::Missing;
    assert_violation(&obs, Violation::RulesetMissing);
}
#[test]
fn ruleset_differs() {
    let mut obs = passing();
    topology(&mut obs).ruleset = RulesetObs::Differs {
        live: [1; 32],
        want: [2; 32],
    };
    assert_violation(
        &obs,
        Violation::RulesetDiffers {
            live: [1; 32],
            want: [2; 32],
        },
    );
}

#[test]
fn rulesets_are_canonical_json_observations() {
    use scupper_core::canon::{canonicalize, compare_rulesets};
    let want = canonicalize(r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}},{"rule":{"counter":{"packets":0,"bytes":0}}}]}"#).unwrap();
    let live = canonicalize(r#"{ "nftables": [ {"metainfo":{"version":"different"}}, {"table":{"name":"scupper","family":"inet","handle":99}}, {"rule":{"handle":33,"counter":{"bytes":1234,"packets":56}}} ] }"#).unwrap();
    let mut obs = passing();
    topology(&mut obs).ruleset = compare_rulesets(&want, &live).unwrap().0.into();
    assert_eq!(report(&obs).verdict.exit_code(), 0);
    let different =
        canonicalize(r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#).unwrap();
    topology(&mut obs).ruleset = compare_rulesets(&want, &different).unwrap().0.into();
    assert_eq!(report(&obs).verdict.exit_code(), 2);
}
#[test]
fn extra_policy_rule() {
    let mut obs = passing();
    topology(&mut obs)
        .extra_rules
        .push("1000 lookup 51820".into());
    assert_violation(&obs, Violation::ExtraPolicyRule("1000 lookup 51820".into()));
}
#[test]
fn traffic_control_hook() {
    let mut obs = passing();
    topology(&mut obs).tc_hooks.push("wg0".into());
    assert_violation(&obs, Violation::TrafficControlHook("wg0".into()));
}
#[test]
fn exit_ip_is_uplink_address() {
    for ip in [
        UPLINK,
        IpAddr::V6(Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped()),
    ] {
        let mut obs = passing();
        obs.exit_probe = Some(Ok(ip));
        assert_violation(&obs, Violation::ExitIpIsUplinkAddress(ip));
    }
}
#[test]
fn config_mismatch() {
    let mut obs = passing();
    topology(&mut obs).links[2].addresses = vec!["10.2.0.3/32".parse().unwrap()];
    assert_violation(
        &obs,
        Violation::ConfigMismatch("ex-ch1 addresses differ".into()),
    );
}

#[test]
fn collects_all_violations_before_errors() {
    let mut obs = passing();
    let t = topology(&mut obs);
    t.netns = NetnsObs::Missing;
    t.links[1].kind = None;
    t.peers.get_mut("wg0").unwrap().clear();
    t.ruleset = RulesetObs::Missing;
    t.extra_rules = vec!["extra1".into(), "extra2".into()];
    t.tc_hooks = vec!["wg0".into(), "ex-ch1".into()];
    obs.handshakes = Some(Err(ProbeError::Timeout));
    obs.exit_probe = Some(Ok(UPLINK));
    let result = report(&obs);
    let Verdict::Unprotected(found) = result.verdict else {
        unreachable!()
    };
    assert_eq!(
        found.as_slice(),
        &[
            Violation::NetnsMissing,
            Violation::LinkKind("wg0".into()),
            Violation::PeerDiffers {
                ifname: "wg0".into()
            },
            Violation::RulesetMissing,
            Violation::ExtraPolicyRule("extra1".into()),
            Violation::ExtraPolicyRule("extra2".into()),
            Violation::TrafficControlHook("wg0".into()),
            Violation::TrafficControlHook("ex-ch1".into()),
            Violation::ExitIpIsUplinkAddress(UPLINK),
        ]
    );
    obs.topology = Some(Err(ProbeError::Timeout));
    assert_violation(&obs, Violation::ExitIpIsUplinkAddress(UPLINK));
}

#[test]
fn missing_duplicate_links_and_peers_fail_containment() {
    let mut obs = passing();
    topology(&mut obs).links.remove(2);
    assert_violation(&obs, Violation::ForeignLink("ex-ch1".into()));
    let mut obs = passing();
    let link = topology(&mut obs).links[1].clone();
    topology(&mut obs).links.push(link);
    assert_violation(&obs, Violation::ForeignLink("wg0".into()));
    let mut obs = passing();
    let peer = topology(&mut obs).peers["wg0"][0].clone();
    topology(&mut obs).peers.get_mut("wg0").unwrap().push(peer);
    assert_violation(
        &obs,
        Violation::PeerDiffers {
            ifname: "wg0".into(),
        },
    );
    let mut obs = passing();
    topology(&mut obs).peers.get_mut("ex-ch1").unwrap().clear();
    assert_violation(
        &obs,
        Violation::PeerDiffers {
            ifname: "ex-ch1".into(),
        },
    );
}

fn close_defaults(obs: &mut Observations) {
    defaults(obs).v4 = DefaultRouteObs::Unreachable;
}
#[test]
fn admin_disconnected_requires_observed_closure() {
    let mut obs = passing();
    obs.selection = Selection::Disconnected;
    obs.active = RouteTarget::Unreachable;
    close_defaults(&mut obs);
    topology(&mut obs).links[2].up = false;
    obs.handshakes = None;
    obs.forwarding = None;
    obs.routes = None;
    obs.exit_probe = None;
    obs.supervisor = None;
    assert_closed(&obs, FailClosed::AdminDisconnected);
    topology(&mut obs).links[2].up = true;
    topology(&mut obs).peers.get_mut("ex-ch1").unwrap().clear();
    assert_closed(&obs, FailClosed::AdminDisconnected);
}
#[test]
fn disconnect_not_effective() {
    let mut obs = passing();
    obs.selection = Selection::Disconnected;
    assert_degraded(&obs, Degraded::DisconnectNotEffective);
    close_defaults(&mut obs);
    assert_degraded(&obs, Degraded::DisconnectNotEffective);
    topology(&mut obs).links[2].up = false;
    defaults(&mut obs).v6 = dev("ex-ch1").into();
    assert_degraded(&obs, Degraded::DisconnectNotEffective);
}
#[test]
fn no_healthy_exit_uses_observed_defaults_not_intent() {
    let mut obs = passing();
    close_defaults(&mut obs);
    assert_closed(&obs, FailClosed::NoHealthyExit);
    obs.handshakes = None;
    assert_closed(&obs, FailClosed::NoHealthyExit);
}
#[test]
fn pinned_exit_down() {
    let mut obs = passing();
    obs.selection = Selection::Pin(exit_id());
    close_defaults(&mut obs);
    assert_closed(&obs, FailClosed::PinnedExitDown(exit_id()));
}
#[test]
fn stale_never_and_down_exit_are_no_healthy_exit_in_m2() {
    for handshake in [
        Handshake::Never,
        Handshake::At {
            unix_secs: NOW - 181,
        },
        Handshake::At { unix_secs: NOW + 6 },
    ] {
        let mut obs = passing();
        handshakes(&mut obs).insert(exit_id(), handshake);
        assert_closed(&obs, FailClosed::NoHealthyExit);
    }
    let mut obs = passing();
    topology(&mut obs).links[2].up = false;
    assert_closed(&obs, FailClosed::NoHealthyExit);
}
#[test]
fn route_wrong_for_intent_extra_defaults_and_ipv6() {
    let mut obs = passing();
    obs.active = RouteTarget::Unreachable;
    assert_degraded(
        &obs,
        Degraded::DefaultRouteWrong {
            family: scupper_core::render::Family::V4,
            got: dev("ex-ch1").into(),
            want: RouteTarget::Unreachable,
        },
    );
    let mut obs = passing();
    defaults(&mut obs).extra.push(dev("wg0").into());
    assert_degraded(
        &obs,
        Degraded::RouteWrong {
            client: "10.99.0.1".parse().unwrap(),
            got: dev("wg0").into(),
            want: obs.active.clone(),
        },
    );
    let mut obs = passing();
    defaults(&mut obs).v6 = dev("ex-ch1").into();
    assert_degraded(
        &obs,
        Degraded::DefaultRouteWrong {
            family: scupper_core::render::Family::V6,
            got: dev("ex-ch1").into(),
            want: RouteTarget::Unreachable,
        },
    );
    let mut obs = passing();
    defaults(&mut obs).v4 = dev("wg0").into();
    assert_degraded(
        &obs,
        Degraded::DefaultRouteWrong {
            family: scupper_core::render::Family::V4,
            got: dev("wg0").into(),
            want: obs.active.clone(),
        },
    );
}
#[test]
fn forwarding_disabled() {
    for value in [0, -1, 2] {
        let mut obs = passing();
        forwarding(&mut obs).v4 = value;
        assert_degraded(&obs, Degraded::ForwardingDisabled);
    }
}
#[test]
fn quarantined_requires_latch_and_forwarding_zero() {
    let mut obs = passing();
    forwarding(&mut obs).quarantine = Some(RepairKind::SafetyDrift);
    forwarding(&mut obs).v4 = 0;
    assert_closed(
        &obs,
        FailClosed::Quarantined {
            reason: RepairKind::SafetyDrift,
        },
    );
    forwarding(&mut obs).v4 = 2;
    assert_degraded(&obs, Degraded::QuarantineNotEffective);
}
#[test]
fn client_side_broken() {
    let mut obs = passing();
    topology(&mut obs).links[1].up = false;
    assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::LinkDown));
    let mut obs = passing();
    forwarding(&mut obs).client_public_key = None;
    assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::PublicKey));
    forwarding(&mut obs).client_public_key = Some([9; 32]);
    assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::PublicKey));
    let mut obs = passing();
    forwarding(&mut obs).listen_port = 1;
    assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::ListenPort));
    let mut obs = passing();
    forwarding(&mut obs).host_sockets[0].local.set_port(1);
    assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::HostSocket));
}
#[test]
fn bug4_route_via_configured_non_exit_despite_probe() {
    let mut obs = passing();
    obs.routes = Some(vec![(CLIENT, route(dev("wg0")))]);
    assert_degraded(
        &obs,
        Degraded::RouteWrong {
            client: CLIENT,
            got: dev("wg0").into(),
            want: obs.active.clone(),
        },
    );
}
#[test]
fn ipv6_lookup_must_be_unreachable() {
    let mut obs = passing();
    obs.routes.as_mut().unwrap()[0].1.v6 = Ok(dev("ex-ch1"));
    assert_degraded(
        &obs,
        Degraded::RouteWrong {
            client: CLIENT,
            got: dev("ex-ch1").into(),
            want: RouteTarget::Unreachable,
        },
    );
}
#[test]
fn exit_probe_failed_is_availability_not_a_switch() {
    for source in [
        ProbeError::Timeout,
        ProbeError::io("connection reset"),
        ProbeError::exit_status(Some(1), "path failed"),
    ] {
        let mut obs = passing();
        obs.exit_probe = Some(Err(source.clone()));
        assert_degraded(&obs, Degraded::ExitProbeFailed(source));
    }
}
#[test]
fn exit_probe_implausible() {
    for text in [
        "0.0.0.0",
        "127.0.0.1",
        "10.1.2.3",
        "10.2.0.2",
        "100.64.0.1",
        "172.16.1.1",
        "192.168.1.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
        "2001:db8::1",
    ] {
        let ip = text.parse().unwrap();
        let mut obs = passing();
        obs.exit_probe = Some(Ok(ip));
        assert_degraded(&obs, Degraded::ExitProbeImplausible { ip });
    }
}
#[test]
fn clock_skew_and_exact_freshness_boundaries() {
    for (timestamp, expected_code, skew) in [
        (NOW - 180, 0, false),
        (NOW - 181, 4, false),
        (NOW, 0, false),
        (NOW + 5, 0, true),
        (NOW + 6, 4, true),
        (u64::MAX, 4, true),
    ] {
        let mut obs = passing();
        handshakes(&mut obs).insert(
            exit_id(),
            Handshake::At {
                unix_secs: timestamp,
            },
        );
        let result = report(&obs);
        assert_eq!(result.verdict.exit_code(), expected_code);
        assert_eq!(result.warnings.contains(&Warning::ClockSkew), skew);
    }
}
#[test]
fn established_client_handshakes_stale_is_warning_only() {
    for handshake in [
        Handshake::Never,
        Handshake::At {
            unix_secs: NOW - 181,
        },
        Handshake::At { unix_secs: NOW + 6 },
    ] {
        let mut obs = passing();
        forwarding(&mut obs)
            .client_handshakes
            .insert([2; 32], handshake);
        let result = report(&obs);
        assert_eq!(
            result.verdict.exit_code(),
            if handshake == Handshake::Never { 3 } else { 0 }
        );
        assert!(result.warnings.contains(&Warning::ClientHandshakesStale));
        assert_eq!(
            result.warnings.contains(&Warning::ClockSkew),
            handshake == Handshake::At { unix_secs: NOW + 6 }
        );
    }
}
#[test]
fn daemon_dead_is_optional_warning() {
    let mut cfg = config();
    cfg.require_daemon = false;
    let mut obs = passing();
    obs.supervisor = Some(Supervisor::Dead);
    let result = report_with(&obs, &cfg);
    assert_eq!(result.verdict.exit_code(), 0);
    assert_eq!(result.warnings, vec![Warning::DaemonDead]);
    obs.supervisor = None;
    assert_eq!(report_with(&obs, &cfg).verdict.exit_code(), 0);
    obs.supervisor = Some(Supervisor::NotRequired);
    assert_eq!(report_with(&obs, &cfg).verdict.exit_code(), 0);
}
#[test]
fn unsupervised_only_after_verified_data_path() {
    for (state, why) in [
        (Supervisor::Dead, SupervisorFault::Dead),
        (
            Supervisor::Alive {
                netns: NETNS,
                iteration_age: Duration::from_secs(30),
            },
            SupervisorFault::Stale,
        ),
        (Supervisor::NotRequired, SupervisorFault::NotRequired),
    ] {
        let mut obs = passing();
        obs.supervisor = Some(state);
        let result = report(&obs);
        assert_eq!(result.verdict.exit_code(), 5);
        assert_eq!(
            result.verdict,
            Verdict::Unsupervised {
                exit: exit_id(),
                exit_ip: PUBLIC,
                why
            }
        );
        obs.routes = Some(vec![(CLIENT, route(dev("wg0")))]);
        assert_eq!(report(&obs).verdict.exit_code(), 3);
    }
    let mut obs = passing();
    obs.supervisor = Some(Supervisor::Alive {
        netns: NETNS,
        iteration_age: Duration::from_secs(30) - Duration::from_nanos(1),
    });
    assert_eq!(report(&obs).verdict.exit_code(), 0);
}

#[test]
fn each_observation_error_is_code_one_and_bounded() {
    let source = ProbeError::Io("界".repeat(201));
    for stage in [
        Stage::Topology,
        Stage::Defaults,
        Stage::Handshakes,
        Stage::Forwarding,
        Stage::Routes,
        Stage::ExitProbe,
    ] {
        let mut obs = passing();
        let actual_source = if stage == Stage::ExitProbe {
            ProbeError::Setup("界".repeat(201))
        } else {
            source.clone()
        };
        match stage {
            Stage::Topology => obs.topology = Some(Err(actual_source)),
            Stage::Defaults => obs.defaults = Some(Err(actual_source)),
            Stage::Handshakes => obs.handshakes = Some(Err(actual_source)),
            Stage::Forwarding => obs.forwarding = Some(Err(actual_source)),
            Stage::Routes => obs.routes.as_mut().unwrap()[0].1.v4 = Err(actual_source),
            Stage::ExitProbe => obs.exit_probe = Some(Err(actual_source)),
            _ => unreachable!(),
        }
        let result = next(&obs, &config(), NOW);
        assert_eq!(code(&result), Some(1));
        let Next::Done(Err(error)) = result else {
            unreachable!()
        };
        assert_eq!(error.stage, stage);
        assert_eq!(
            error.source,
            if stage == Stage::ExitProbe {
                ProbeError::Setup("界".repeat(200))
            } else {
                ProbeError::Io("界".repeat(200))
            }
        );
    }
    let mut obs = passing();
    obs.exit_probe = Some(Err(ProbeError::Parse(ParseError::EmptyRoute)));
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(3));
    let mut obs = passing();
    obs.routes.as_mut().unwrap()[0].1.v6 = Err(ProbeError::Timeout);
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
}

#[test]
fn normal_staging_and_reserved_stages() {
    let full = passing();
    let mut obs = Observations {
        active: full.active.clone(),
        ..Observations::default()
    };
    assert_eq!(next(&obs, &config(), NOW), Next::Topology);
    obs.topology = full.topology;
    assert_eq!(next(&obs, &config(), NOW), Next::Defaults);
    obs.defaults = full.defaults;
    assert_eq!(next(&obs, &config(), NOW), Next::Handshakes);
    obs.handshakes = full.handshakes;
    assert_eq!(next(&obs, &config(), NOW), Next::Forwarding);
    obs.forwarding = full.forwarding;
    assert_eq!(next(&obs, &config(), NOW), Next::Routes);
    obs.routes = full.routes;
    assert_eq!(next(&obs, &config(), NOW), Next::ExitProbe);
    obs.exit_probe = full.exit_probe;
    assert_eq!(next(&obs, &config(), NOW), Next::Supervisor);
    obs.supervisor = full.supervisor;
    obs.standby_probe = Some(Err(ProbeError::Timeout));
    obs.dns = Some(Err(ProbeError::Timeout));
    assert_eq!(report(&obs).verdict.exit_code(), 0);
}

#[test]
fn every_client_route_and_handshake_must_be_observed() {
    let mut obs = passing();
    obs.routes = Some(vec![]);
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
    let mut obs = passing();
    obs.routes
        .as_mut()
        .unwrap()
        .push((CLIENT, route(dev("ex-ch1"))));
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
    let mut obs = passing();
    obs.routes.as_mut().unwrap()[0].0 = "10.99.0.3".parse().unwrap();
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
    let mut obs = passing();
    handshakes(&mut obs).clear();
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
    let mut obs = passing();
    forwarding(&mut obs).client_handshakes.clear();
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
}

#[test]
fn constructor_uses_validated_health_and_rejects_unknown_boot_state() {
    let mut raw = parse_site(include_str!("fixtures/site-m2.toml")).unwrap();
    raw.health.handshake_stale.0 = "240s".into();
    raw.health.require_daemon = false;
    let site = validate(raw).unwrap();
    let gateway = GatewayId("gw1".into());
    let cfg = HealthConfigV2::new(&site, &gateway, NETNS, vec![UPLINK], 17).unwrap();
    assert_eq!(cfg.max_handshake_age, Duration::from_secs(240));
    assert!(!cfg.require_daemon);
    assert_eq!(cfg.config_version, 17);
    assert_eq!(cfg.client_public_key, [0; 32]);
    assert_eq!(cfg.peers["wg0"][0].public_key, [2; 32]);
    assert_eq!(cfg.peers["ex-ch1"][0].public_key, [1; 32]);
    assert_eq!(cfg.route_probe_dst4, Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(
        HealthConfigV2::new(&site, &GatewayId("absent".into()), NETNS, vec![UPLINK], 7),
        Err(HealthConfigError::UnknownGateway)
    );
    assert_eq!(
        HealthConfigV2::new(
            &site,
            &gateway,
            NetnsIdentity { inode: 0, ..NETNS },
            vec![UPLINK],
            7
        ),
        Err(HealthConfigError::InvalidNetnsIdentity)
    );
    assert_eq!(
        HealthConfigV2::new(&site, &gateway, NETNS, vec![], 7),
        Err(HealthConfigError::NoUplinkAddresses)
    );
}

// Review regressions: these assertions describe the required behavior.
#[test]
fn regression_zero_devices_still_requires_a_forwarded_route() {
    let mut raw = parse_site(include_str!("fixtures/site-m2.toml")).unwrap();
    raw.devices.clear();
    let cfg = HealthConfigV2::new(
        &validate(raw).unwrap(),
        &GatewayId("gw1".into()),
        NETNS,
        vec![UPLINK],
        7,
    )
    .unwrap();
    let mut obs = passing();
    topology(&mut obs).peers.get_mut("wg0").unwrap().clear();
    forwarding(&mut obs).client_handshakes.clear();
    obs.routes = Some(vec![]);
    assert_eq!(code(&next(&obs, &cfg, NOW)), Some(1));
}
#[test]
fn regression_quarantine_cannot_report_protected() {
    let mut obs = passing();
    forwarding(&mut obs).quarantine = Some(RepairKind::SafetyDrift);
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(3));
}
#[test]
fn regression_unknown_pin_is_a_state_error() {
    let mut obs = passing();
    obs.selection = Selection::Pin(ExitId("nl1".into()));
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
}
#[test]
fn regression_route_via_unknown_device_is_foreign_link() {
    let mut obs = passing();
    obs.routes = Some(vec![(CLIENT, route(dev("eth0")))]);
    assert_violation(&obs, Violation::ForeignLink("eth0".into()));
}
#[test]
fn regression_incomplete_handshake_answer_is_error() {
    let mut obs = passing();
    handshakes(&mut obs).clear();
    handshakes(&mut obs).insert(ExitId("other".into()), current());
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
}
#[test]
fn regression_optional_stale_supervisor_warns() {
    let mut cfg = config();
    cfg.require_daemon = false;
    let mut obs = passing();
    obs.supervisor = Some(Supervisor::Alive {
        netns: NETNS,
        iteration_age: Duration::from_secs(3600),
    });
    assert_eq!(report_with(&obs, &cfg).warnings, vec![Warning::DaemonStale]);
}
#[test]
fn regression_closed_defaults_keep_quarantine_warning() {
    let mut obs = passing();
    close_defaults(&mut obs);
    forwarding(&mut obs).quarantine = Some(RepairKind::SafetyDrift);
    forwarding(&mut obs).v4 = 0;
    assert!(
        report(&obs)
            .warnings
            .contains(&Warning::RepairSuppressed(RepairKind::SafetyDrift))
    );
}
#[test]
fn regression_exit_probe_parse_is_path_failure() {
    let mut obs = passing();
    obs.exit_probe = Some(Err(ProbeError::Parse(ParseError::EmptyRoute)));
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(3));
}
#[test]
fn regression_missing_disconnected_peer_inventory_is_error() {
    let mut obs = passing();
    obs.selection = Selection::Disconnected;
    close_defaults(&mut obs);
    topology(&mut obs).peers.remove("ex-ch1");
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
}
#[test]
fn regression_loopback_socket_cannot_prove_host_listener() {
    let mut obs = passing();
    forwarding(&mut obs).host_sockets[0].local = "127.0.0.1:51820".parse().unwrap();
    assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::HostSocket));
}
#[test]
fn regression_mapped_exit_ip_is_canonical() {
    let mut obs = passing();
    obs.exit_probe = Some(Ok(IpAddr::V6(
        Ipv4Addr::new(203, 0, 113, 77).to_ipv6_mapped(),
    )));
    assert_eq!(
        report(&obs).verdict,
        Verdict::Protected {
            exit: exit_id(),
            exit_ip: PUBLIC
        }
    );
}
#[test]
fn regression_link_local_addresses_are_ignored() {
    let mut obs = passing();
    topology(&mut obs).links[1]
        .addresses
        .push("fe80::1/64".parse().unwrap());
    assert_eq!(report(&obs).verdict.exit_code(), 0);
}

#[test]
fn missing_default_with_exit_link_down_fails_closed() {
    // The kernel drops a down link's routes (CI lab, exit link set down): fail closed (4).
    let mut obs = passing();
    defaults(&mut obs).v4 = DefaultRouteObs::Missing;
    if let Some(Ok(topology)) = &mut obs.topology {
        for link in &mut topology.links {
            if link.name == config().exit_iface.as_str() {
                link.up = false;
            }
        }
    }
    let Next::Done(Ok(report)) = next(&obs, &config(), NOW) else {
        panic!("expected a verdict");
    };
    assert_eq!(
        report.verdict,
        Verdict::FailClosed(FailClosed::NoHealthyExit)
    );
}

#[test]
fn missing_defaults_are_route_failures_for_each_family() {
    for v6 in [false, true] {
        let mut obs = passing();
        let d = defaults(&mut obs);
        if v6 {
            d.v6 = DefaultRouteObs::Missing;
        } else {
            d.v4 = DefaultRouteObs::Missing;
        }
        assert_degraded(
            &obs,
            Degraded::DefaultRouteWrong {
                family: if v6 {
                    scupper_core::render::Family::V6
                } else {
                    scupper_core::render::Family::V4
                },
                got: DefaultRouteObs::Missing,
                want: if v6 {
                    RouteTarget::Unreachable
                } else {
                    obs.active.clone()
                },
            },
        );
    }
}

#[test]
fn defaults_collection_error_preserves_containment_findings() {
    let mut obs = passing();
    topology(&mut obs).links.push(LinkObs {
        name: "eth0".into(),
        kind: Some("wireguard".into()),
        up: true,
        addresses: vec![],
    });
    obs.defaults = Some(Err(ProbeError::Timeout));
    assert_violation(&obs, Violation::ForeignLink("eth0".into()));
}

#[test]
fn default_and_lookup_foreign_devices_win_over_errors_and_availability() {
    for family in 0..5 {
        let mut obs = passing();
        let foreign = DefaultRouteObs::Dev("Foreign@42".into());
        match family {
            0 => defaults(&mut obs).v4 = foreign,
            1 => defaults(&mut obs).v6 = foreign,
            2 => defaults(&mut obs).extra.push(foreign),
            3 => obs.routes.as_mut().unwrap()[0].1.v4 = Ok(dev("eth0")),
            _ => obs.routes.as_mut().unwrap()[0].1.v6 = Ok(dev("eth0")),
        }
        obs.handshakes = Some(Err(ProbeError::Timeout));
        assert_violation(
            &obs,
            Violation::ForeignLink(if family < 3 { "Foreign@42" } else { "eth0" }.into()),
        );
    }
    for lookup in [false, true] {
        let mut obs = passing();
        if lookup {
            obs.routes.as_mut().unwrap()[0].1.v4 = Ok(RouteAnswer::OtherDev);
        } else {
            defaults(&mut obs).v4 = DefaultRouteObs::Other(RouteAnswer::OtherDev);
        }
        assert_violation(&obs, Violation::ForeignLink("<unrecognized device>".into()));
    }
}

#[test]
fn additional_distinct_peer_on_either_link_violates_containment() {
    for name in ["wg0", "ex-ch1"] {
        let mut obs = passing();
        topology(&mut obs)
            .peers
            .get_mut(name)
            .unwrap()
            .push(PeerObs {
                public_key: [9; 32],
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                endpoint: None,
            });
        assert_violation(
            &obs,
            Violation::PeerDiffers {
                ifname: name.into(),
            },
        );
    }
}

#[test]
fn disconnected_does_not_exempt_wrong_exit_peers() {
    for wrong_key in [false, true] {
        let mut obs = passing();
        obs.selection = Selection::Disconnected;
        close_defaults(&mut obs);
        topology(&mut obs).links[2].up = false;
        let peer = &mut topology(&mut obs).peers.get_mut("ex-ch1").unwrap()[0];
        if wrong_key {
            peer.public_key = [9; 32];
        } else {
            peer.allowed_ips.push("::/0".parse().unwrap());
        }
        assert_violation(
            &obs,
            Violation::PeerDiffers {
                ifname: "ex-ch1".into(),
            },
        );
    }
}

#[test]
fn disconnected_with_extra_route_is_not_closed() {
    let mut obs = passing();
    obs.selection = Selection::Disconnected;
    close_defaults(&mut obs);
    topology(&mut obs).links[2].up = false;
    defaults(&mut obs).extra.push(dev("wg0").into());
    assert_degraded(&obs, Degraded::DisconnectNotEffective);
}

#[test]
fn full_namespace_identity_and_daemon_handle_are_compared() {
    let mut obs = passing();
    topology(&mut obs).netns = NetnsObs::Present {
        device: NETNS.device + 1,
        inode: NETNS.inode,
    };
    assert_violation(&obs, Violation::NetnsWrongInode);
    for netns in [
        NetnsIdentity {
            device: NETNS.device + 1,
            ..NETNS
        },
        NetnsIdentity { inode: 43, ..NETNS },
    ] {
        let mut obs = passing();
        obs.supervisor = Some(Supervisor::Alive {
            iteration_age: Duration::ZERO,
            netns,
        });
        obs.forwarding = Some(Err(ProbeError::Timeout));
        assert_violation(&obs, Violation::NetnsWrongInode);
    }
}

#[test]
fn host_socket_must_bind_wildcard_or_uplink_on_the_listen_port() {
    for address in [
        "0.0.0.0:51820",
        "[::]:51820",
        "198.51.100.7:51820",
        "[::ffff:198.51.100.7]:51820",
    ] {
        let mut obs = passing();
        forwarding(&mut obs).host_sockets[0].local = address.parse().unwrap();
        assert_eq!(report(&obs).verdict.exit_code(), 0);
    }
    for address in [
        "127.0.0.1:51820",
        "[::1]:51820",
        "10.99.0.1:51820",
        "198.51.100.8:51820",
        "198.51.100.7:9999",
    ] {
        let mut obs = passing();
        forwarding(&mut obs).host_sockets[0].local = address.parse().unwrap();
        assert_degraded(&obs, Degraded::ClientSideBroken(ClientFault::HostSocket));
    }
}

#[test]
fn pin_is_checked_before_exit_availability() {
    let mut obs = passing();
    obs.selection = Selection::Pin(exit_id());
    handshakes(&mut obs).insert(exit_id(), Handshake::Never);
    obs.routes.as_mut().unwrap()[0].1.v4 = Ok(dev("wg0"));
    assert_degraded(
        &obs,
        Degraded::RouteWrong {
            client: CLIENT,
            got: dev("wg0").into(),
            want: obs.active.clone(),
        },
    );
    for selection in [
        Selection::Pin(ExitId("absent".into())),
        Selection::Prefer(ExitId("absent".into())),
    ] {
        obs.selection = selection;
        close_defaults(&mut obs);
        assert_eq!(code(&next(&obs, &config(), NOW)), Some(1));
    }
}

#[test]
fn quarantined_forwarding_cannot_be_hidden_by_closed_defaults() {
    for value in [-1, 1, 2] {
        let mut obs = passing();
        close_defaults(&mut obs);
        forwarding(&mut obs).quarantine = Some(RepairKind::SafetyDrift);
        forwarding(&mut obs).v4 = value;
        assert_degraded(&obs, Degraded::QuarantineNotEffective);
        assert!(
            report(&obs)
                .warnings
                .contains(&Warning::RepairSuppressed(RepairKind::SafetyDrift))
        );
    }
}

#[test]
fn zero_device_probe_is_the_first_host_other_than_the_gateway() {
    for (prefix, expected) in [("10.99.0.1/24", "10.99.0.2"), ("10.99.0.2/24", "10.99.0.1")] {
        let mut raw = parse_site(include_str!("fixtures/site-m2.toml")).unwrap();
        raw.devices.clear();
        raw.gateways
            .get_mut(&GatewayId("gw1".into()))
            .unwrap()
            .client_tunnel
            .address4 = prefix.into();
        let cfg = HealthConfigV2::new(
            &validate(raw).unwrap(),
            &GatewayId("gw1".into()),
            NETNS,
            vec![UPLINK],
            7,
        )
        .unwrap();
        assert_eq!(cfg.clients, Vec::<IpAddr>::new());
        assert_eq!(cfg.route_sources, vec![expected.parse::<IpAddr>().unwrap()]);
        let mut obs = passing();
        topology(&mut obs).links[1].addresses = vec![prefix.parse().unwrap()];
        topology(&mut obs).peers.get_mut("wg0").unwrap().clear();
        forwarding(&mut obs).client_handshakes.clear();
        obs.routes = None;
        assert_eq!(next(&obs, &cfg, NOW), Next::Routes);
        obs.routes = Some(vec![(cfg.route_sources[0], route(dev("wg0")))]);
        assert_eq!(code(&next(&obs, &cfg, NOW)), Some(3));
        obs.routes = Some(vec![(cfg.route_sources[0], route(dev("ex-ch1")))]);
        assert_eq!(code(&next(&obs, &cfg, NOW)), Some(0));
    }
}

// States are missing/error/pass/failure. Failure kinds vary independently in
// every stage, including collection omissions and multiple containment shapes.
#[allow(clippy::too_many_lines)] // Keep the seven independent stage mutations together.
fn observations(states: [u8; 7], kinds: [u8; 7]) -> Observations {
    let mut obs = passing();
    match states[0] {
        0 => obs.topology = None,
        1 => obs.topology = Some(Err(ProbeError::Timeout)),
        3 => match kinds[0] % 6 {
            0 => topology(&mut obs).ruleset = RulesetObs::Missing,
            1 => topology(&mut obs).links[1].kind = Some("veth".into()),
            2 => topology(&mut obs).peers.get_mut("wg0").unwrap().clear(),
            3 => topology(&mut obs).netns = NetnsObs::Missing,
            4 => topology(&mut obs).extra_rules.push("extra".into()),
            _ => topology(&mut obs).tc_hooks.push("wg0".into()),
        },
        _ => {}
    }
    match states[1] {
        0 => obs.defaults = None,
        1 => obs.defaults = Some(Err(ProbeError::io("default inventory failed"))),
        3 => match kinds[1] % 5 {
            0 => defaults(&mut obs).v4 = DefaultRouteObs::Missing,
            1 => close_defaults(&mut obs),
            2 => defaults(&mut obs).v4 = dev("wg0").into(),
            3 => defaults(&mut obs).v6 = DefaultRouteObs::Missing,
            _ => defaults(&mut obs).extra.push(RouteAnswer::Blackhole.into()),
        },
        _ => {}
    }
    match states[2] {
        0 => obs.handshakes = None,
        1 => obs.handshakes = Some(Err(ProbeError::Timeout)),
        3 => match kinds[2] % 4 {
            0 => {
                handshakes(&mut obs).insert(exit_id(), Handshake::Never);
            }
            1 => {
                handshakes(&mut obs).insert(
                    exit_id(),
                    Handshake::At {
                        unix_secs: NOW - 181,
                    },
                );
            }
            2 => {
                handshakes(&mut obs).insert(exit_id(), Handshake::At { unix_secs: NOW + 6 });
            }
            _ => handshakes(&mut obs).clear(),
        },
        _ => {}
    }
    match states[3] {
        0 => obs.forwarding = None,
        1 => obs.forwarding = Some(Err(ProbeError::io("forwarding collection failed"))),
        3 => match kinds[3] % 6 {
            0 => forwarding(&mut obs).v4 = 0,
            1 => forwarding(&mut obs).client_public_key = None,
            2 => forwarding(&mut obs).host_sockets.clear(),
            3 => forwarding(&mut obs).quarantine = Some(RepairKind::SafetyDrift),
            4 => forwarding(&mut obs).client_handshakes.clear(),
            _ => forwarding(&mut obs).listen_port = 1,
        },
        _ => {}
    }
    match states[4] {
        0 => obs.routes = None,
        1 => obs.routes.as_mut().unwrap()[0].1.v4 = Err(ProbeError::Timeout),
        3 => match kinds[4] % 6 {
            0 => obs.routes.as_mut().unwrap()[0].1.v4 = Ok(dev("wg0")),
            1 => obs.routes.as_mut().unwrap()[0].1.v4 = Ok(RouteAnswer::Unreachable),
            2 => obs.routes.as_mut().unwrap()[0].1.v6 = Ok(RouteAnswer::Local),
            3 => obs.routes.as_mut().unwrap().clear(),
            4 => obs
                .routes
                .as_mut()
                .unwrap()
                .push((CLIENT, route(dev("ex-ch1")))),
            _ => obs.routes.as_mut().unwrap()[0].0 = "10.99.0.99".parse().unwrap(),
        },
        _ => {}
    }
    obs.exit_probe = match states[5] {
        0 => None,
        1 => Some(Err(ProbeError::setup("bind failed"))),
        3 => match kinds[5] % 4 {
            0 => Some(Err(ProbeError::Timeout)),
            1 => Some(Err(ProbeError::Parse(ParseError::EmptyRoute))),
            2 => Some(Ok("127.0.0.1".parse().unwrap())),
            _ => Some(Ok(UPLINK)),
        },
        _ => Some(Ok(PUBLIC)),
    };
    obs.supervisor = match states[6] {
        0 => None,
        1 => Some(Supervisor::Dead),
        3 if kinds[6].is_multiple_of(2) => Some(Supervisor::NotRequired),
        3 => Some(Supervisor::Alive {
            iteration_age: Duration::from_secs(30),
            netns: NETNS,
        }),
        _ => Some(Supervisor::Alive {
            iteration_age: Duration::ZERO,
            netns: NETNS,
        }),
    };
    obs
}

fn assert_request_has_no_answer(obs: &Observations, result: &Next) {
    match result {
        Next::Topology => assert!(obs.topology.is_none()),
        Next::Defaults => assert!(obs.defaults.is_none()),
        Next::Handshakes => assert!(obs.handshakes.is_none()),
        Next::Forwarding => assert!(obs.forwarding.is_none()),
        Next::Routes => assert!(obs.routes.is_none()),
        Next::ExitProbe => assert!(obs.exit_probe.is_none()),
        Next::Supervisor => assert!(obs.supervisor.is_none()),
        Next::StandbyProbe | Next::Dns => unreachable!("reserved stage requested"),
        Next::Done(_) => {}
    }
}

#[test]
fn canned_stage_space_is_exhaustive() {
    let cfg = config();
    for packed in 0_u32..4_u32.pow(7) {
        let states =
            std::array::from_fn(|index| u8::try_from((packed >> (2 * index)) & 3).unwrap());
        let obs = observations(states, [0; 7]);
        let result = next(&obs, &cfg, NOW);
        assert_request_has_no_answer(&obs, &result);
        let has_violation = states[0] == 3;
        let has_error = states[..6].contains(&1);
        if has_violation {
            assert_eq!(code(&result), Some(2), "{states:?}");
        } else if has_error {
            assert_eq!(code(&result), Some(1), "{states:?}");
        }
        assert_eq!(code(&result) == Some(0), states == [2; 7], "{states:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn prop_stage_errors_and_violation_precedence(
        states in prop::array::uniform7(0_u8..4),
        kinds in prop::array::uniform7(any::<u8>()),
    ) {
        let obs = observations(states, kinds);
        let result = next(&obs, &config(), NOW);
        let violation = states[0] == 3 || (states[5] == 3 && kinds[5] % 4 == 3);
        let error = states[..6].contains(&1)
            || (states[2] == 3 && kinds[2] % 4 == 3)
            || (states[3] == 3 && kinds[3] % 6 == 4)
            || (states[4] == 3 && kinds[4] % 6 >= 3);
        if violation { prop_assert_eq!(code(&result), Some(2)); }
        else if error { prop_assert_eq!(code(&result), Some(1)); }
        prop_assert_eq!(code(&result) == Some(0), states == [2; 7]);
        assert_request_has_no_answer(&obs, &result);
        // Requested stages require all preceding observations to have passed.
        let requested = match result {
            Next::Topology => Some(0), Next::Defaults => Some(1), Next::Handshakes => Some(2),
            Next::Forwarding => Some(3), Next::Routes => Some(4), Next::ExitProbe => Some(5),
            Next::Supervisor => Some(6), _ => None,
        };
        if let Some(index) = requested { prop_assert!(states[..index].iter().all(|s| *s == 2)); }
        if code(&result) == Some(5) {
            let mut supervised = obs;
            supervised.supervisor = Some(Supervisor::Alive { iteration_age: Duration::ZERO, netns: NETNS });
            prop_assert_eq!(code(&next(&supervised, &config(), NOW)), Some(0));
        }
    }

    #[test]
    fn prop_freshness_matches_v1_bounds(timestamp in any::<u64>(), now in any::<u64>()) {
        let mut obs = passing();
        handshakes(&mut obs).insert(exit_id(), Handshake::At { unix_secs: timestamp });
        forwarding(&mut obs).client_handshakes.insert([2; 32], Handshake::At { unix_secs: now });
        let result = next(&obs, &config(), now);
        let fresh = if timestamp > now { timestamp - now <= 5 } else { now - timestamp <= 180 };
        prop_assert_eq!(code(&result), Some(if fresh { 0 } else { 4 }));
        if let Next::Done(Ok(report)) = result {
            prop_assert_eq!(report.warnings.contains(&Warning::ClockSkew), timestamp > now);
        }
    }
}

fn config_with_clients(count: u8) -> HealthConfigV2 {
    let mut raw = parse_site(include_str!("fixtures/site-m2.toml")).unwrap();
    let template = raw.devices["mac"].clone();
    raw.devices.clear();
    for index in 0..count {
        let mut device = template.clone();
        device.address4 = format!("10.99.0.{}/32", index + 2);
        device.public_key = raw.identities["edge"].public_key.clone();
        device
            .public_key
            .0
            .replace_range(..1, ["C", "D", "E"][usize::from(index)]);
        raw.devices.insert(format!("client{index}"), device);
    }
    HealthConfigV2::new(
        &validate(raw).unwrap(),
        &GatewayId("gw1".into()),
        NETNS,
        vec![UPLINK],
        7,
    )
    .unwrap()
}

fn passing_with(cfg: &HealthConfigV2) -> Observations {
    let mut obs = passing();
    topology(&mut obs).peers.clone_from(&cfg.peers);
    forwarding(&mut obs).client_handshakes = cfg.peers["wg0"]
        .iter()
        .map(|peer| (peer.public_key, current()))
        .collect();
    obs.routes = Some(
        cfg.route_sources
            .iter()
            .map(|client| (*client, route(dev("ex-ch1"))))
            .collect(),
    );
    obs
}

// Canonical public policy sets form an independent oracle; it does not call the
// engine's matching helpers or derive expectations from a mutation number.
fn peer_policy(peers: &[PeerObs]) -> Vec<([u8; 32], Vec<ipnet::IpNet>)> {
    let mut policy: Vec<_> = peers
        .iter()
        .map(|peer| {
            let mut prefixes: Vec<_> = peer.allowed_ips.iter().map(ipnet::IpNet::trunc).collect();
            prefixes.sort_unstable();
            (peer.public_key, prefixes)
        })
        .collect();
    policy.sort_unstable();
    policy
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn prop_protected_implies_independent_inventory_and_route_policy(
        client_count in 0_u8..4,
        links in prop_oneof![Just(vec![(0_u8, true), (1, true), (2, true)]), prop::collection::vec((0_u8..4, any::<bool>()), 0..6)],
        client_peers in prop_oneof![Just(None), prop::collection::vec((0_u8..5, any::<bool>()), 0..5).prop_map(Some)],
        exit_peers in prop_oneof![Just(None), prop::collection::vec((any::<bool>(), any::<bool>()), 0..3).prop_map(Some)],
        routes in prop_oneof![Just(None), prop::collection::vec((0_u8..5, 0_u8..5, 0_u8..4), 0..6).prop_map(Some)],
        require_daemon in any::<bool>(),
        selection in 0_u8..5,
        quarantine in prop_oneof![4 => Just(false), 1 => Just(true)],
        daemon in 0_u8..3,
    ) {
        let mut cfg = config_with_clients(client_count);
        cfg.require_daemon = require_daemon;
        let mut obs = passing_with(&cfg);
        let original_links = topology(&mut obs).links.clone();
        topology(&mut obs).links = links.iter().map(|(index, wireguard)| {
            let mut link = if *index < 3 { original_links[usize::from(*index)].clone() }
                else { LinkObs { name: "eth0".into(), kind: Some("wireguard".into()), up: true, addresses: vec![] } };
            if *index != 0 && !wireguard { link.kind = Some("veth".into()); }
            link
        }).collect();
        if let Some(peers) = client_peers {
            let actual = peers.iter().map(|(index, exact)| {
                let mut peer = cfg.peers["wg0"].get(usize::from(*index)).cloned().unwrap_or(PeerObs {
                    public_key: [9; 32], allowed_ips: vec![], endpoint: None,
                });
                if !exact { peer.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()]; }
                peer
            }).collect();
            topology(&mut obs).peers.insert("wg0".into(), actual);
        }
        if let Some(peers) = exit_peers {
            let actual = peers.iter().map(|(key, allowed)| {
                let mut peer = cfg.peers["ex-ch1"][0].clone();
                if !key { peer.public_key = [9; 32]; }
                if !allowed { peer.allowed_ips.push("::/0".parse().unwrap()); }
                peer
            }).collect();
            topology(&mut obs).peers.insert("ex-ch1".into(), actual);
        }
        if let Some(routes) = routes {
            obs.routes = Some(routes.iter().map(|(index, v4, v6)| {
                let source = cfg.route_sources.get(usize::from(*index)).copied().unwrap_or("10.99.0.99".parse().unwrap());
                let v4 = match v4 { 0 => dev("ex-ch1"), 1 => dev("wg0"), 2 => RouteAnswer::Unreachable,
                    3 => dev("eth0"), _ => RouteAnswer::OtherDev };
                let v6 = match v6 { 0 => RouteAnswer::Unreachable, 1 => dev("ex-ch1"), 2 => dev("eth0"), _ => RouteAnswer::Blackhole };
                (source, RouteObs { v4: Ok(v4), v6: Ok(v6) })
            }).collect());
        }
        obs.selection = match selection { 0 => Selection::Auto, 1 => Selection::Prefer(exit_id()),
            2 => Selection::Pin(exit_id()), 3 => Selection::Disconnected, _ => Selection::Pin(ExitId("unknown".into())) };
        if quarantine { forwarding(&mut obs).quarantine = Some(RepairKind::SafetyDrift); }
        obs.supervisor = match daemon { 0 => Some(Supervisor::Dead),
            1 => Some(Supervisor::Alive { iteration_age: Duration::from_secs(3600), netns: NETNS }),
            _ => Some(Supervisor::Alive { iteration_age: Duration::ZERO, netns: NETNS }) };
        let result = next(&obs, &cfg, NOW);
        assert_request_has_no_answer(&obs, &result);
        if matches!(code(&result), Some(0 | 5)) {
            let t = topology(&mut obs);
            let mut names: Vec<_> = t.links.iter().filter(|link| link.name != "lo").map(|link| link.name.as_str()).collect();
            names.sort_unstable();
            prop_assert_eq!(names, vec!["ex-ch1", "wg0"]);
            prop_assert!(t.links.iter().filter(|link| link.name != "lo").all(|link| link.kind.as_deref() == Some("wireguard")));
            for name in ["wg0", "ex-ch1"] {
                prop_assert_eq!(peer_policy(&t.peers[name]), peer_policy(&cfg.peers[name]));
            }
            let routes = obs.routes.as_ref().unwrap();
            let mut sources: Vec<_> = routes.iter().map(|(source, _)| *source).collect();
            sources.sort_unstable();
            let mut expected = cfg.route_sources.clone();
            expected.sort_unstable();
            prop_assert_eq!(sources, expected);
            prop_assert!(routes.iter().all(|(_, route)| route.v4 == Ok(dev("ex-ch1")) && route.v6 == Ok(RouteAnswer::Unreachable)));
            prop_assert!(!quarantine);
            prop_assert!(selection < 3);
            if code(&result) == Some(0) && require_daemon { prop_assert_eq!(daemon, 2); }
        }
    }
}

#[test]
fn pin_rejects_different_exit_intent_before_closed_route_availability() {
    let mut raw = parse_site(include_str!("fixtures/site-m2.toml")).unwrap();
    raw.gateways
        .get_mut(&GatewayId("gw1".into()))
        .unwrap()
        .exits[0]
        .ifname = "ex-other".into();
    let other = HealthConfigV2::new(
        &validate(raw).unwrap(),
        &GatewayId("gw1".into()),
        NETNS,
        vec![UPLINK],
        7,
    )
    .unwrap();
    let mut obs = passing();
    obs.selection = Selection::Pin(exit_id());
    obs.active = RouteTarget::Exit(other.exit_iface);
    close_defaults(&mut obs);
    assert_degraded(
        &obs,
        Degraded::DefaultRouteWrong {
            family: scupper_core::render::Family::V4,
            got: DefaultRouteObs::Unreachable,
            want: RouteTarget::Exit(config().exit_iface),
        },
    );
}

#[test]
fn exit_down_does_not_hide_foreign_or_extra_routes() {
    let mut obs = passing();
    topology(&mut obs).links[2].up = false;
    defaults(&mut obs).v4 = DefaultRouteObs::Dev("foreign0".into());
    assert_violation(&obs, Violation::ForeignLink("foreign0".into()));
    defaults(&mut obs).v4 = DefaultRouteObs::Missing;
    defaults(&mut obs)
        .extra
        .push(DefaultRouteObs::Dev("wg0".into()));
    assert_degraded(
        &obs,
        Degraded::RouteWrong {
            client: config().client_addr.into(),
            got: DefaultRouteObs::Dev("wg0".into()),
            want: RouteTarget::Exit(config().exit_iface),
        },
    );
}

#[test]
fn clients_without_established_session_are_not_protected() {
    let cfg = config();
    let mut obs = passing_with(&cfg);
    for handshake in forwarding(&mut obs).client_handshakes.values_mut() {
        *handshake = Handshake::Never;
    }
    assert!(matches!(
        report(&obs).verdict,
        Verdict::Degraded(Degraded::ClientSideBroken(ClientFault::NoHandshake))
    ));
}
