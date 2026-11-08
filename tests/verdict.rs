//! M1 parity, stage ordering, diagnostics, and truthful-health properties.

use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use proptest::prelude::*;
use scupper::{
    parse::{Handshake, ParseError, RouteLookup, RouteType},
    rules::{IfName, V1Config},
    verdict::{
        CheckError, ConfigMismatch, Degraded, FailClosed, HealthConfig, M1Observations, M1Topology,
        Next, Probe, ProbeError, Report, RulesetObs, Stage, Verdict, Violation, Violations,
        Warning, next,
    },
};

const NOW: u64 = 10_000;
const EXIT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
const UPLINK: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

fn config() -> HealthConfig {
    HealthConfig::from(&V1Config::default())
}

fn topology() -> M1Topology {
    M1Topology {
        ruleset: RulesetObs::Exact,
        tc_hooks: vec![],
        config_mismatches: vec![],
        uplink_addrs: vec![UPLINK],
    }
}

fn passing() -> M1Observations {
    M1Observations {
        topology: Some(Ok(topology())),
        handshake: Some(Ok(Handshake::At { unix_secs: NOW })),
        route: Some(Ok(RouteLookup::Dev(config().exit_iface))),
        exit_probe: Some(Ok(EXIT)),
    }
}

fn report(obs: &M1Observations) -> Result<Report, Box<dyn Error>> {
    match next(obs, &config(), NOW) {
        Next::Done(result) => Ok(result?),
        stage => Err(format!("expected completed verdict, got {stage:?}").into()),
    }
}

fn code(result: &Next) -> Option<u8> {
    match result {
        Next::Done(Ok(report)) => Some(report.verdict.exit_code()),
        Next::Done(Err(error)) => Some(error.exit_code()),
        _ => None,
    }
}

#[test]
fn v1_verdict_table() {
    let mut missing = passing();
    missing.topology = Some(Ok(M1Topology {
        ruleset: RulesetObs::Missing,
        ..topology()
    }));
    missing.handshake = Some(Err(ProbeError::Timeout));
    missing.route = Some(Err(ProbeError::Timeout));
    missing.exit_probe = Some(Err(ProbeError::Timeout));
    let mut down = passing();
    down.handshake = Some(Ok(Handshake::Never));
    let mut stale = passing();
    stale.handshake = Some(Ok(Handshake::At {
        unix_secs: NOW - 600,
    }));
    let mut failed_probe = passing();
    failed_probe.exit_probe = Some(Err(ProbeError::Timeout));
    let mut wrong_route = passing();
    wrong_route.route = Some(Ok(RouteLookup::Dev(V1Config::default().uplink_iface)));
    let mut failed_route = passing();
    failed_route.route = Some(Err(ProbeError::exit_status(Some(2), "route failed")));
    for (label, obs, expected) in [
        ("connected", passing(), 0),
        ("missing ruleset outranks everything", missing, 2),
        ("tunnel down", down, 4),
        ("handshake stale, 10 min", stale, 4),
        ("probe failed", failed_probe, 3),
        ("policy rule missing", wrong_route.clone(), 3),
        // v1 returned 3 here; §12 requires failed route observations to use 1.
        ("route lookup failed", failed_route, 1),
    ] {
        assert_eq!(code(&next(&obs, &config(), NOW)), Some(expected), "{label}");
    }
    // Bug 4: a bound probe would succeed, but must never mask the wrong route.
    wrong_route.exit_probe = None;
    assert!(matches!(
        next(&wrong_route, &config(), NOW),
        Next::Done(Ok(Report {
            verdict: Verdict::Degraded(Degraded::RouteWrong { .. }),
            ..
        }))
    ));
}

#[test]
fn clock_skew_cases() -> Result<(), Box<dyn Error>> {
    for (timestamp, expected, warnings) in [
        (NOW + 3, 0, vec![Warning::ClockSkew]),
        (NOW + 5, 0, vec![Warning::ClockSkew]),
        (NOW + 6, 4, vec![Warning::ClockSkew]),
        (u64::MAX, 4, vec![Warning::ClockSkew]),
        (NOW - 180, 0, vec![]),
        (NOW - 181, 4, vec![]),
    ] {
        let mut obs = passing();
        obs.handshake = Some(Ok(Handshake::At {
            unix_secs: timestamp,
        }));
        let actual = report(&obs)?;
        assert_eq!(
            actual.verdict.exit_code(),
            expected,
            "timestamp {timestamp}"
        );
        assert_eq!(actual.warnings, warnings);
    }
    let cfg = config();
    assert_eq!(cfg.max_handshake_age, Duration::from_secs(180));
    assert_eq!(cfg.max_clock_skew, Duration::from_secs(5));
    assert_eq!(cfg.exit_addr, V1Config::default().exit_addr);
    let mut obs = passing();
    obs.handshake = Some(Ok(Handshake::At {
        unix_secs: u64::MAX,
    }));
    assert_eq!(code(&next(&obs, &cfg, u64::MAX)), Some(0));
    obs.handshake = Some(Ok(Handshake::At { unix_secs: 0 }));
    assert_eq!(code(&next(&obs, &cfg, u64::MAX)), Some(4));
    Ok(())
}

#[test]
fn violations_collected() -> Result<(), Box<dyn Error>> {
    let tc = V1Config::default().client_iface;
    let missing = V1Config::default().exit_iface;
    let mismatches = vec![
        ConfigMismatch::UplinkNotDefaultRouteDev,
        ConfigMismatch::InterfaceMissing(missing),
    ];
    let mut obs = passing();
    obs.topology = Some(Ok(M1Topology {
        ruleset: RulesetObs::Differs {
            live_sha256: [1; 32],
            want_sha256: [2; 32],
        },
        tc_hooks: vec![tc.clone()],
        config_mismatches: mismatches.clone(),
        ..topology()
    }));
    let Verdict::Unprotected(violations) = report(&obs)?.verdict else {
        return Err("expected unprotected".into());
    };
    assert_eq!(
        violations.as_slice(),
        &[
            Violation::RulesetDiffers {
                live_sha256: [1; 32],
                want_sha256: [2; 32]
            },
            Violation::TrafficControlHook(tc),
            Violation::ConfigMismatch(mismatches[0].clone()),
            Violation::ConfigMismatch(mismatches[1].clone()),
        ]
    );
    Ok(())
}

#[test]
fn violation_beats_observation_error() -> Result<(), Box<dyn Error>> {
    let mut obs = passing();
    obs.topology = Some(Ok(M1Topology {
        ruleset: RulesetObs::Missing,
        ..topology()
    }));
    obs.handshake = Some(Err(ProbeError::Timeout));
    assert_eq!(
        report(&obs)?.verdict,
        Verdict::Unprotected(Violations::new(Violation::RulesetMissing))
    );
    assert_eq!(report(&obs)?.warnings, Vec::<Warning>::new());
    Ok(())
}

#[test]
fn observation_errors_are_code_1() {
    // Parse failures use code 1 at required-observation stages and code 3 at
    // the final path probe. Its Setup exception is covered separately.
    for stage in [
        Stage::Topology,
        Stage::Handshake,
        Stage::Route,
        Stage::ExitProbe,
    ] {
        let mut obs = passing();
        let source = ProbeError::Parse(ParseError::EmptyRoute);
        match stage {
            Stage::Topology => obs.topology = Some(Err(source.clone())),
            Stage::Handshake => obs.handshake = Some(Err(source.clone())),
            Stage::Route => obs.route = Some(Err(source.clone())),
            Stage::ExitProbe => obs.exit_probe = Some(Err(source.clone())),
        }
        let result = next(&obs, &config(), NOW);
        if stage == Stage::ExitProbe {
            assert_eq!(
                result,
                Next::Done(Ok(Report {
                    verdict: Verdict::Degraded(Degraded::ExitProbeFailed(source)),
                    warnings: vec![],
                }))
            );
            assert_eq!(code(&result), Some(3));
        } else {
            assert_eq!(result, Next::Done(Err(CheckError { stage, source })));
            assert_eq!(code(&result), Some(1));
        }
    }
}

#[test]
fn staging_order() {
    let mut obs = M1Observations::default();
    let cfg = config();
    assert_eq!(next(&obs, &cfg, NOW), Next::Topology);
    obs.topology = Some(Ok(topology()));
    assert_eq!(next(&obs, &cfg, NOW), Next::Handshake);
    obs.handshake = Some(Ok(Handshake::At { unix_secs: NOW }));
    assert_eq!(next(&obs, &cfg, NOW), Next::Route);
    obs.route = Some(Ok(RouteLookup::Dev(cfg.exit_iface.clone())));
    assert_eq!(next(&obs, &cfg, NOW), Next::ExitProbe);
    obs.exit_probe = Some(Ok(EXIT));
    assert_eq!(code(&next(&obs, &cfg, NOW)), Some(0));
    obs.handshake = Some(Ok(Handshake::At {
        unix_secs: NOW - 181,
    }));
    obs.route = Some(Err(ProbeError::Timeout));
    assert_eq!(code(&next(&obs, &cfg, NOW)), Some(4));
    obs.handshake = Some(Ok(Handshake::At { unix_secs: NOW }));
    obs.route = Some(Ok(RouteLookup::OtherDev));
    obs.exit_probe = None;
    assert_eq!(code(&next(&obs, &cfg, NOW)), Some(3));
    // Speculatively supplied later successes never stand in for a missing stage.
    for stage in [
        Stage::Topology,
        Stage::Handshake,
        Stage::Route,
        Stage::ExitProbe,
    ] {
        let mut obs = passing();
        let expected = match stage {
            Stage::Topology => {
                obs.topology = None;
                Next::Topology
            }
            Stage::Handshake => {
                obs.handshake = None;
                Next::Handshake
            }
            Stage::Route => {
                obs.route = None;
                Next::Route
            }
            Stage::ExitProbe => {
                obs.exit_probe = None;
                Next::ExitProbe
            }
        };
        assert_eq!(next(&obs, &cfg, NOW), expected);
    }
}

#[test]
fn exit_ip_is_uplink() -> Result<(), Box<dyn Error>> {
    let mut obs = passing();
    obs.exit_probe = Some(Ok(UPLINK));
    assert_eq!(
        report(&obs)?.verdict,
        Verdict::Unprotected(Violations::new(Violation::ExitIpIsUplinkAddress(UPLINK)))
    );
    Ok(())
}

fn implausible_ips() -> Vec<IpAddr> {
    let v4 = [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 31, 255, 255),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(100, 64, 0, 0),
        Ipv4Addr::new(100, 127, 255, 255),
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(239, 255, 255, 255),
        Ipv4Addr::BROADCAST,
        config().exit_addr,
    ];
    let mut ips: Vec<_> = v4
        .into_iter()
        .flat_map(|ip| [IpAddr::V4(ip), IpAddr::V6(ip.to_ipv6_mapped())])
        .collect();
    ips.extend([
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfebf, 0xffff, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfdff, 0xffff, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
    ]);
    ips
}

#[test]
fn exit_ip_plausibility() -> Result<(), Box<dyn Error>> {
    for ip in implausible_ips() {
        let mut obs = passing();
        obs.exit_probe = Some(Ok(ip));
        let verdict = report(&obs)?.verdict;
        assert_eq!(verdict.exit_code(), 3, "{ip}");
        assert_eq!(
            verdict,
            Verdict::Degraded(Degraded::ExitProbeImplausible { ip })
        );
    }
    // A configured address must be rejected even in an otherwise accepted range.
    let exit_addr = Ipv4Addr::new(203, 0, 113, 77);
    let cfg = HealthConfig {
        exit_addr,
        ..config()
    };
    for ip in [
        IpAddr::V4(exit_addr),
        IpAddr::V6(exit_addr.to_ipv6_mapped()),
    ] {
        let mut obs = passing();
        obs.exit_probe = Some(Ok(ip));
        assert_eq!(
            next(&obs, &cfg, NOW),
            Next::Done(Ok(Report {
                verdict: Verdict::Degraded(Degraded::ExitProbeImplausible { ip }),
                warnings: vec![],
            }))
        );
    }
    for text in [
        "192.0.2.77",
        "198.51.100.77",
        "203.0.113.77",
        "2001:db8::77",
    ] {
        let ip: IpAddr = text.parse()?;
        let mut forms = vec![ip];
        if let IpAddr::V4(ip) = ip {
            forms.push(IpAddr::V6(ip.to_ipv6_mapped()));
        }
        for ip in forms {
            let mut obs = passing();
            obs.exit_probe = Some(Ok(ip));
            assert_eq!(report(&obs)?.verdict, Verdict::Protected { exit_ip: ip });
        }
    }
    Ok(())
}

#[test]
fn uplink_match_is_canonical() -> Result<(), Box<dyn Error>> {
    // Include an implausible address: an uplink leak still wins over degradation.
    for ip in [Ipv4Addr::new(192, 0, 2, 10), config().exit_addr] {
        let forms = [IpAddr::V4(ip), IpAddr::V6(ip.to_ipv6_mapped())];
        for uplink in forms {
            for exit in forms {
                let mut obs = passing();
                obs.topology = Some(Ok(M1Topology {
                    uplink_addrs: vec![uplink],
                    ..topology()
                }));
                obs.exit_probe = Some(Ok(exit));
                let verdict = report(&obs)?.verdict;
                assert_eq!(verdict.exit_code(), 2);
                assert_eq!(
                    verdict,
                    Verdict::Unprotected(Violations::new(Violation::ExitIpIsUplinkAddress(exit)))
                );
            }
        }
    }
    Ok(())
}

#[test]
fn empty_uplinks_is_code_1() {
    let empty = M1Topology {
        uplink_addrs: vec![],
        ..topology()
    };
    for mut obs in [passing(), M1Observations::default()] {
        obs.topology = Some(Ok(empty.clone()));
        let result = next(&obs, &config(), NOW);
        assert_eq!(code(&result), Some(1));
        assert!(matches!(
            result,
            Next::Done(Err(CheckError {
                stage: Stage::Topology,
                ..
            }))
        ));
    }
    // DESIGN §12: a known containment violation wins over an observation error.
    let obs = M1Observations {
        topology: Some(Ok(M1Topology {
            ruleset: RulesetObs::Missing,
            ..empty
        })),
        ..passing()
    };
    assert_eq!(code(&next(&obs, &config(), NOW)), Some(2));
}

fn wrong_routes() -> Vec<RouteLookup> {
    let mut routes = vec![
        RouteLookup::Dev(V1Config::default().uplink_iface),
        RouteLookup::OtherDev,
        RouteLookup::Local,
        RouteLookup::Unreachable,
        RouteLookup::Blackhole,
        RouteLookup::Prohibit,
        RouteLookup::Throw,
    ];
    routes.extend(
        [
            RouteType::Broadcast,
            RouteType::Anycast,
            RouteType::Multicast,
            RouteType::Nat,
            RouteType::Xresolve,
        ]
        .map(RouteLookup::OtherType),
    );
    let exit = config().exit_iface.to_string();
    routes.extend(
        [
            format!("{exit}0"),
            exit.trim_end_matches('0').to_owned(),
            format!("{exit}x"),
            exit.replacen('p', "P", 1),
        ]
        .into_iter()
        .filter_map(|name| IfName::new(&name).ok())
        .map(RouteLookup::Dev),
    );
    routes
}

#[test]
fn route_types_all_degraded() -> Result<(), Box<dyn Error>> {
    for route in wrong_routes() {
        let mut obs = passing();
        obs.route = Some(Ok(route.clone()));
        obs.exit_probe = Some(Err(ProbeError::Timeout));
        assert_eq!(
            report(&obs)?.verdict,
            Verdict::Degraded(Degraded::RouteWrong {
                got: route,
                want: config().exit_iface
            })
        );
        assert_eq!(report(&obs)?.verdict.exit_code(), 3);
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn messages_snapshot() {
    let cases = [
        (
            Verdict::Protected { exit_ip: EXIT },
            "connected through 203.0.113.77, kill switch in place",
        ),
        (
            Verdict::FailClosed(FailClosed::NoHealthyExit),
            "exit tunnel is down, traffic is blocked (fail closed)",
        ),
        (
            Verdict::Degraded(Degraded::RouteWrong {
                got: RouteLookup::Dev(V1Config::default().uplink_iface),
                want: config().exit_iface,
            }),
            "client traffic routes via eth0, not proton0 (policy rule missing?), traffic is blocked",
        ),
        (
            Verdict::Degraded(Degraded::RouteWrong {
                got: RouteLookup::Unreachable,
                want: config().exit_iface,
            }),
            "client route is unreachable, not via proton0, traffic is blocked",
        ),
        (
            Verdict::Degraded(Degraded::RouteWrong {
                got: RouteLookup::OtherDev,
                want: config().exit_iface,
            }),
            "client route is via an unrecognized device, not via proton0, traffic is blocked",
        ),
        (
            Verdict::Degraded(Degraded::ExitProbeFailed(ProbeError::Timeout)),
            "exit probe failed, exit connectivity could not be verified: probe timed out",
        ),
        (
            Verdict::Degraded(Degraded::ExitProbeImplausible {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            }),
            "exit probe returned implausible public exit IP 127.0.0.1, exit connectivity could not be verified",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::RulesetMissing)),
            "unprotected: ruleset missing",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::RulesetDiffers {
                live_sha256: [0; 32],
                want_sha256: [1; 32],
            })),
            "unprotected: ruleset differs from policy",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::TrafficControlHook(
                config().exit_iface,
            ))),
            "unprotected: unexpected traffic-control hook on proton0",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::ExitIpIsUplinkAddress(UPLINK))),
            "unprotected: exit IP 192.0.2.10 is an uplink address",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::ConfigMismatch(
                ConfigMismatch::UplinkNotDefaultRouteDev,
            ))),
            "unprotected: configured uplink is not the default-route device",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::ConfigMismatch(
                ConfigMismatch::ExitAddrNotOnExitIface,
            ))),
            "unprotected: exit address is not on the exit interface",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::ConfigMismatch(
                ConfigMismatch::ClientAddrNotInPeerAllowedIps,
            ))),
            "unprotected: client address is not in peer AllowedIPs",
        ),
        (
            Verdict::Unprotected(Violations::new(Violation::ConfigMismatch(
                ConfigMismatch::InterfaceMissing(config().exit_iface),
            ))),
            "unprotected: configured interface proton0 is missing",
        ),
    ];
    for (verdict, expected) in cases {
        assert_eq!(verdict.to_string(), expected);
    }
    let mut obs = passing();
    obs.topology = Some(Ok(M1Topology {
        ruleset: RulesetObs::Missing,
        tc_hooks: vec![config().exit_iface],
        ..topology()
    }));
    #[allow(clippy::panic)]
    let Next::Done(Ok(report)) = next(&obs, &config(), NOW) else {
        panic!("expected an unprotected report");
    };
    assert_eq!(
        report.verdict.to_string(),
        "unprotected: ruleset missing; unexpected traffic-control hook on proton0"
    );
    for route in wrong_routes() {
        let text = Verdict::Degraded(Degraded::RouteWrong {
            got: route,
            want: config().exit_iface,
        })
        .to_string();
        assert!(text.ends_with(", traffic is blocked"));
        assert!(
            text.contains("not proton0 (policy rule missing?)") || text.contains("not via proton0")
        );
        assert!(!text.contains('\n'));
    }
}

#[test]
fn io_errors_are_bounded() -> Result<(), Box<dyn Error>> {
    let long = "界".repeat(201);
    assert_eq!(ProbeError::io(&long), ProbeError::Io("界".repeat(200)));
    assert_eq!(
        ProbeError::Io(long.clone()).to_string(),
        format!("I/O error: {}", "界".repeat(200))
    );
    let mut obs = passing();
    obs.topology = Some(Err(ProbeError::Io(long.clone())));
    assert_eq!(
        next(&obs, &config(), NOW),
        Next::Done(Err(CheckError {
            stage: Stage::Topology,
            source: ProbeError::io(&long)
        }))
    );
    obs = passing();
    obs.exit_probe = Some(Err(ProbeError::Io(long.clone())));
    assert_eq!(
        report(&obs)?.verdict,
        Verdict::Degraded(Degraded::ExitProbeFailed(ProbeError::io(&long)))
    );
    assert_eq!(
        report(&obs)?.verdict.to_string(),
        format!(
            "exit probe failed, exit connectivity could not be verified: I/O error: {}",
            "界".repeat(200)
        )
    );
    Ok(())
}

fn names() -> impl Strategy<Value = IfName> {
    "[a-z][a-z0-9_.-]{0,14}".prop_filter_map("valid interface", |name| IfName::new(&name).ok())
}

fn ips() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u8>().prop_map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))),
        any::<u8>().prop_map(|last| IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))),
        any::<u8>().prop_map(|last| IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))),
        any::<u8>().prop_map(|last| IpAddr::V6(Ipv4Addr::new(192, 0, 2, last).to_ipv6_mapped())),
        any::<[u16; 6]>().prop_map(|tail| IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, tail[0], tail[1], tail[2], tail[3], tail[4], tail[5]
        ))),
        Just(EXIT),
        Just(UPLINK),
        Just(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped())),
        prop::sample::select(implausible_ips()),
    ]
}

fn errors() -> impl Strategy<Value = ProbeError> {
    prop_oneof![
        Just(ProbeError::Timeout),
        (prop::option::of(any::<i32>()), any::<String>())
            .prop_map(|(code, stderr)| ProbeError::ExitStatus { code, stderr }),
        any::<String>().prop_map(ProbeError::Setup),
        Just(ProbeError::Setup("界".repeat(201))),
        Just(ProbeError::Parse(ParseError::NoPeers)),
        Just(ProbeError::Parse(ParseError::EmptyRoute)),
        any::<String>().prop_map(ProbeError::Io),
        Just(ProbeError::Io("界".repeat(201))),
    ]
}

fn observation<T: Clone + std::fmt::Debug + 'static>(
    value: impl Strategy<Value = T> + 'static,
) -> impl Strategy<Value = Option<Probe<T>>> {
    prop_oneof![1 => Just(None), 1 => errors().prop_map(|error| Some(Err(error))), 6 => value.prop_map(|value| Some(Ok(value)))]
}

fn topologies() -> impl Strategy<Value = M1Topology> {
    let rules = prop_oneof![4 => Just(RulesetObs::Exact), 1 => Just(RulesetObs::Missing),
        1 => (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(live_sha256, want_sha256)| RulesetObs::Differs { live_sha256, want_sha256 })];
    let mismatch = prop_oneof![
        Just(ConfigMismatch::UplinkNotDefaultRouteDev),
        Just(ConfigMismatch::ExitAddrNotOnExitIface),
        Just(ConfigMismatch::ClientAddrNotInPeerAllowedIps),
        names().prop_map(ConfigMismatch::InterfaceMissing)
    ];
    (
        rules,
        prop_oneof![9 => Just(vec![]), 1 => prop::collection::vec(names(), 1..4)],
        prop_oneof![9 => Just(vec![]), 1 => prop::collection::vec(mismatch, 1..4)],
        prop::collection::vec(ips(), 0..4),
    )
        .prop_map(
            |(ruleset, tc_hooks, config_mismatches, uplink_addrs)| M1Topology {
                ruleset,
                tc_hooks,
                config_mismatches,
                uplink_addrs,
            },
        )
}

fn arbitrary_cases() -> impl Strategy<Value = (M1Observations, HealthConfig, u64)> {
    let now = prop_oneof![any::<u64>(), Just(0), Just(NOW), Just(u64::MAX)];
    let exit_iface = prop_oneof![names(), Just(config().exit_iface)];
    let exit_addr = prop_oneof![
        Just(config().exit_addr),
        Just(Ipv4Addr::new(203, 0, 113, 77))
    ];
    (now, 0..600_u64, 0..30_u64, exit_iface, exit_addr).prop_flat_map(|(now, age, skew, exit_iface, exit_addr)| {
        let cfg = HealthConfig { exit_iface: exit_iface.clone(), exit_addr, max_handshake_age: Duration::from_secs(age), max_clock_skew: Duration::from_secs(skew) };
        let handshake = prop_oneof![Just(Handshake::Never), Just(Handshake::At { unix_secs: now }),
            Just(Handshake::At { unix_secs: now.saturating_sub(age) }),
            Just(Handshake::At { unix_secs: now.saturating_sub(age).saturating_sub(1) }),
            Just(Handshake::At { unix_secs: now.saturating_add(skew) }),
            Just(Handshake::At { unix_secs: now.saturating_add(skew).saturating_add(1) }),
            any::<u64>().prop_map(|unix_secs| Handshake::At { unix_secs })];
        let route = prop_oneof![4 => Just(RouteLookup::Dev(exit_iface)), 1 => names().prop_map(RouteLookup::Dev), 1 => prop::sample::select(wrong_routes())];
        (observation(topologies()), observation(handshake), observation(route), observation(ips()))
            .prop_map(move |(topology, handshake, route, exit_probe)| (M1Observations { topology, handshake, route, exit_probe }, cfg.clone(), now))
    })
}

fn topology_passes(value: &M1Topology) -> bool {
    value.ruleset == RulesetObs::Exact
        && value.tc_hooks.is_empty()
        && value.config_mismatches.is_empty()
        && !value.uplink_addrs.is_empty()
}

// Independent freshness oracle: do not use the production age helper here.
fn fresh(handshake: Handshake, cfg: &HealthConfig, now: u64) -> bool {
    match handshake {
        Handshake::Never => false,
        Handshake::At { unix_secs } if unix_secs > now => {
            Duration::from_secs(unix_secs - now) <= cfg.max_clock_skew
        }
        Handshake::At { unix_secs } => {
            Duration::from_secs(now - unix_secs) <= cfg.max_handshake_age
        }
    }
}

// Use mapped-address extraction and explicit ranges rather than the production
// canonicalization and address classification helpers.
fn reference_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    ip
}

fn reference_plausible(ip: IpAddr, cfg: &HealthConfig) -> bool {
    match reference_ip(ip) {
        IpAddr::V4(v4) => {
            let bytes = v4.octets();
            v4 != cfg.exit_addr
                && !matches!(
                    bytes,
                    [0, 0, 0, 0]
                        | [127 | 10 | 224..=239, _, _, _]
                        | [172, 16..=31, _, _]
                        | [192, 168, _, _]
                        | [100, 64..=127, _, _]
                        | [169, 254, _, _]
                        | [255, 255, 255, 255]
                )
        }
        IpAddr::V6(v6) => {
            let number = u128::from(v6);
            number > 1
                && number >> 118 != 0b11_1111_1010 // fe80::/10
                && number >> 121 != 0b111_1110 // fc00::/7
                && number >> 120 != 0xff // ff00::/8
        }
    }
}

fn reference_error(stage: Stage, source: &ProbeError) -> Next {
    let source = match source {
        ProbeError::Io(text) => ProbeError::Io(text.chars().take(200).collect()),
        ProbeError::Setup(text) => ProbeError::Setup(text.chars().take(200).collect()),
        ProbeError::ExitStatus { code, stderr } => ProbeError::ExitStatus {
            code: *code,
            stderr: stderr
                .lines()
                .next()
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect(),
        },
        other => other.clone(),
    };
    Next::Done(Err(CheckError { stage, source }))
}

// Deliberately linear oracle for DESIGN §12's M1 order. It shares only result
// types with the production decision, not its stage or classification helpers.
#[allow(clippy::too_many_lines)]
fn reference_next(obs: &M1Observations, cfg: &HealthConfig, now: u64) -> Next {
    let topology = match &obs.topology {
        None => return Next::Topology,
        Some(Err(error)) => return reference_error(Stage::Topology, error),
        Some(Ok(value)) => value,
    };
    let mut findings = vec![];
    if topology.ruleset == RulesetObs::Missing {
        findings.push(Violation::RulesetMissing);
    }
    if let RulesetObs::Differs {
        live_sha256,
        want_sha256,
    } = topology.ruleset
    {
        findings.push(Violation::RulesetDiffers {
            live_sha256,
            want_sha256,
        });
    }
    for name in &topology.tc_hooks {
        findings.push(Violation::TrafficControlHook(name.clone()));
    }
    for mismatch in &topology.config_mismatches {
        findings.push(Violation::ConfigMismatch(mismatch.clone()));
    }
    let mut findings = findings.into_iter();
    if let Some(first) = findings.next() {
        let mut violations = Violations::new(first);
        for finding in findings {
            violations.push(finding);
        }
        return Next::Done(Ok(Report {
            verdict: Verdict::Unprotected(violations),
            warnings: vec![],
        }));
    }
    if topology.uplink_addrs.is_empty() {
        return reference_error(
            Stage::Topology,
            &ProbeError::Io("topology contains no uplink addresses".into()),
        );
    }
    let handshake = match &obs.handshake {
        None => return Next::Handshake,
        Some(Err(error)) => return reference_error(Stage::Handshake, error),
        Some(Ok(value)) => value,
    };
    let mut warnings = vec![];
    if matches!(handshake, Handshake::At { unix_secs } if *unix_secs > now) {
        warnings.push(Warning::ClockSkew);
    }
    if !fresh(*handshake, cfg, now) {
        return Next::Done(Ok(Report {
            verdict: Verdict::FailClosed(FailClosed::NoHealthyExit),
            warnings,
        }));
    }
    let route = match &obs.route {
        None => return Next::Route,
        Some(Err(error)) => return reference_error(Stage::Route, error),
        Some(Ok(value)) => value,
    };
    if route != &RouteLookup::Dev(cfg.exit_iface.clone()) {
        return Next::Done(Ok(Report {
            verdict: Verdict::Degraded(Degraded::RouteWrong {
                got: route.clone(),
                want: cfg.exit_iface.clone(),
            }),
            warnings,
        }));
    }
    let ip = match &obs.exit_probe {
        None => return Next::ExitProbe,
        Some(Err(error @ ProbeError::Setup(_))) => return reference_error(Stage::ExitProbe, error),
        Some(Err(error)) => {
            let bounded = match error {
                ProbeError::Io(text) => ProbeError::Io(text.chars().take(200).collect()),
                ProbeError::Setup(text) => ProbeError::Setup(text.chars().take(200).collect()),
                ProbeError::ExitStatus { code, stderr } => ProbeError::ExitStatus {
                    code: *code,
                    stderr: stderr
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect(),
                },
                other => other.clone(),
            };
            return Next::Done(Ok(Report {
                verdict: Verdict::Degraded(Degraded::ExitProbeFailed(bounded)),
                warnings,
            }));
        }
        Some(Ok(ip)) => *ip,
    };
    for uplink in &topology.uplink_addrs {
        if reference_ip(ip) == reference_ip(*uplink) {
            return Next::Done(Ok(Report {
                verdict: Verdict::Unprotected(Violations::new(Violation::ExitIpIsUplinkAddress(
                    ip,
                ))),
                warnings,
            }));
        }
    }
    if !reference_plausible(ip, cfg) {
        return Next::Done(Ok(Report {
            verdict: Verdict::Degraded(Degraded::ExitProbeImplausible { ip }),
            warnings,
        }));
    }
    Next::Done(Ok(Report {
        verdict: Verdict::Protected { exit_ip: ip },
        warnings,
    }))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn prop_protected_only_when_all_pass((obs, cfg, now) in arbitrary_cases()) {
        let expected = matches!((&obs.topology, &obs.handshake, &obs.route, &obs.exit_probe),
            (Some(Ok(topology)), Some(Ok(handshake)), Some(Ok(RouteLookup::Dev(device))), Some(Ok(ip)))
                if topology_passes(topology) && fresh(*handshake, &cfg, now) && device == &cfg.exit_iface
                    && !topology.uplink_addrs.iter().any(|uplink| reference_ip(*uplink) == reference_ip(*ip))
                    && reference_plausible(*ip, &cfg));
        let result = next(&obs, &cfg, now);
        let actual = matches!(result, Next::Done(Ok(Report { verdict: Verdict::Protected { .. }, .. })));
        prop_assert_eq!(actual, expected);
        prop_assert_eq!(code(&result) == Some(0), expected);
    }

    #[test]
    fn prop_next_matches_reference((obs, cfg, now) in arbitrary_cases()) {
        let expected = reference_next(&obs, &cfg, now);
        let actual = next(&obs, &cfg, now);
        prop_assert_eq!(code(&actual), code(&expected));
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn prop_never_safe_on_error((obs, cfg, now) in arbitrary_cases()) {
        let reached_error = match &obs.topology {
            Some(Err(_)) => Some(Stage::Topology),
            Some(Ok(topology)) if topology_passes(topology) => match &obs.handshake {
                Some(Err(_)) => Some(Stage::Handshake),
                Some(Ok(handshake)) if fresh(*handshake, &cfg, now) => match &obs.route {
                    Some(Err(_)) => Some(Stage::Route),
                    Some(Ok(RouteLookup::Dev(device))) if device == &cfg.exit_iface && matches!(obs.exit_probe, Some(Err(_))) => Some(Stage::ExitProbe),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        if let Some(stage) = reached_error {
            let result = next(&obs, &cfg, now);
            // Final path failures use 3; local Setup failures and required
            // observations at earlier stages use 1.
            if stage == Stage::ExitProbe && !matches!(obs.exit_probe, Some(Err(ProbeError::Setup(_)))) {
                prop_assert_eq!(code(&result), Some(3));
                prop_assert!(matches!(result, Next::Done(Ok(Report { verdict: Verdict::Degraded(Degraded::ExitProbeFailed(_)), .. }))), "wrong bound-probe classification");
            } else {
                prop_assert_eq!(code(&result), Some(1));
                prop_assert!(matches!(result, Next::Done(Err(CheckError { stage: actual, .. })) if actual == stage), "wrong observation-error stage");
            }
        }
    }
}

#[test]
fn exit_probe_setup_error_is_code_1() {
    let mut obs = passing();
    let source = ProbeError::setup("binding device: permission denied");
    obs.exit_probe = Some(Err(source.clone()));
    let result = next(&obs, &config(), NOW);
    assert_eq!(code(&result), Some(1));
    assert_eq!(
        result,
        Next::Done(Err(CheckError {
            stage: Stage::ExitProbe,
            source
        }))
    );
}

#[test]
fn exit_probe_io_error_is_code_3() -> Result<(), Box<dyn Error>> {
    let mut obs = passing();
    let source = ProbeError::io("connection reset");
    obs.exit_probe = Some(Err(source.clone()));
    let result = report(&obs)?;
    assert_eq!(result.verdict.exit_code(), 3);
    assert_eq!(
        result.verdict,
        Verdict::Degraded(Degraded::ExitProbeFailed(source))
    );
    Ok(())
}

#[test]
fn setup_errors_are_bounded() {
    let long = "界".repeat(201);
    assert_eq!(
        ProbeError::setup(&long),
        ProbeError::Setup("界".repeat(200))
    );
    assert_eq!(
        ProbeError::Setup(long.clone()).to_string(),
        format!("probe setup error: {}", "界".repeat(200))
    );
    let mut obs = passing();
    obs.exit_probe = Some(Err(ProbeError::Setup(long.clone())));
    assert_eq!(
        next(&obs, &config(), NOW),
        Next::Done(Err(CheckError {
            stage: Stage::ExitProbe,
            source: ProbeError::setup(&long),
        }))
    );
}

#[test]
fn exit_status_diagnostics_are_bounded_and_readable() -> Result<(), Box<dyn Error>> {
    for (code, expected) in [(Some(1), "code 1"), (None, "killed by signal")] {
        let stderr = format!("{}\nsecond line must be omitted", "界".repeat(201));
        let error = ProbeError::exit_status(code, &stderr);
        assert_eq!(
            error,
            ProbeError::ExitStatus {
                code,
                stderr: "界".repeat(200)
            }
        );
        assert_eq!(
            error.to_string(),
            format!(
                "probe exited unsuccessfully ({expected}): {}",
                "界".repeat(200)
            )
        );
        let direct = ProbeError::ExitStatus { code, stderr };
        assert_eq!(direct.to_string(), error.to_string());
        let mut obs = passing();
        obs.exit_probe = Some(Err(direct));
        assert_eq!(
            report(&obs)?.verdict,
            Verdict::Degraded(Degraded::ExitProbeFailed(error))
        );
    }
    assert_eq!(
        ProbeError::exit_status(None, "").to_string(),
        "probe exited unsuccessfully (killed by signal)"
    );
    Ok(())
}
