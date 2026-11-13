//! Fixed health fixtures without any system calls or wall-clock reads.
#![allow(clippy::unwrap_used)]
use super::view::*;
use super::*;
use scupper_core::{
    config::{self, ExitId},
    parse::{Handshake, RouteLookup},
    verdict::v2::*,
};
use std::collections::BTreeMap;

fn fixture() -> (AppliedConfig, Report, Observations) {
    let site = config::validate(
        config::parse_site(include_str!(
            "../../../scupper-core/tests/fixtures/site-m2.toml"
        ))
        .unwrap(),
    )
    .unwrap();
    let config = AppliedConfig {
        site,
        gateway: config::GatewayId("gw1".into()),
        stamp: scupper_core::render::VersionStamp {
            version: 2,
            sha256: [0; 32],
        },
    };
    let report = Report {
        verdict: Verdict::Protected {
            exit: ExitId("ch1".into()),
            exit_ip: "37.120.137.232".parse().unwrap(),
        },
        warnings: vec![Warning::ClientHandshakesStale, Warning::ClockSkew],
        at: 1000,
        config_version: 2,
    };
    let obs = Observations {
        topology: Some(Ok(TopologyObs {
            host_wireguard_on_client_port: vec![],
            errors: vec![],
            links_complete: true,
            addresses_complete: true,
            netns: NetnsObs::Present {
                device: 1,
                inode: 2,
            },
            links: vec![],
            peers: BTreeMap::from([
                (
                    "ex-ch1".into(),
                    vec![PeerObs {
                        public_key: [1; 32],
                        allowed_ips: vec![],
                        endpoint: Some("203.0.113.10:51820".parse().unwrap()),
                    }],
                ),
                (
                    "wg0".into(),
                    vec![PeerObs {
                        public_key: [2; 32],
                        allowed_ips: vec![],
                        endpoint: Some("198.51.100.99:45678".parse().unwrap()),
                    }],
                ),
            ]),
            ruleset: RulesetObs::Exact,
            extra_rules: vec![],
            tc_hooks: vec![],
        })),
        handshakes: Some(Ok(BTreeMap::from([(
            ExitId("ch1".into()),
            Handshake::At { unix_secs: 959 },
        )]))),
        forwarding: Some(Ok(Forwarding {
            client_v4: 1,
            netns_sockets: vec![],
            v4: 1,
            hardening: vec![],
            v6: 0,
            quarantine: None,
            client_public_key: Some([0; 32]),
            listen_port: 51820,
            host_sockets: vec![],
            client_handshakes: BTreeMap::from([([2; 32], Handshake::Never)]),
        })),
        routes: Some(vec![(
            "10.99.0.2".parse().unwrap(),
            RouteObs {
                v4: Ok(RouteLookup::Dev(
                    scupper_core::rules::IfName::new("ex-ch1").unwrap(),
                )),
                v6: Ok(RouteLookup::Unreachable),
            },
        )]),
        supervisor: Some(Supervisor::Alive {
            iteration_age: std::time::Duration::from_secs(3),
            netns: NetnsIdentity {
                device: 1,
                inode: 2,
            },
        }),
        ..Observations::default()
    };
    (config, report, obs)
}

#[test]
fn check_and_status_human_goldens_and_structured_status() {
    let (config, report, obs) = fixture();
    let mut output = Vec::new();
    check(&mut output, &serde_json::to_value(&report).unwrap()).unwrap();
    let check_text = String::from_utf8(output).unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&serde_json::to_value(&report).unwrap()).unwrap() + "\n",
        include_str!("../../tests/golden/check.json")
    );
    let value = status_value(&config, &Ok(report), &obs, 1000).unwrap();
    let mut output = Vec::new();
    status(&mut output, &value).unwrap();
    let status_text = String::from_utf8(output).unwrap();
    assert_eq!(check_text, include_str!("../../tests/golden/check.txt"));
    assert_eq!(status_text, include_str!("../../tests/golden/status.txt"));
    assert_eq!(
        serde_json::to_string_pretty(&value).unwrap() + "\n",
        include_str!("../../tests/golden/status.json")
    );
    for text in [check_text, status_text] {
        for debug in [
            "Observations {",
            "Check {",
            "Report {",
            "Some(",
            "Ok(",
            "public_key: [",
            "ClientHandshakesStale",
        ] {
            assert!(!text.contains(debug), "{debug} reached human output");
        }
        assert!(!text.contains("198.51.100.99"));
    }
    // Prevent reintroducing a whole-struct Debug formatter in the human view.
    assert!(!include_str!("view.rs").contains(":?}"));
    assert!(!include_str!("view.rs").contains(":#?}"));
}

#[test]
fn incomplete_observations_never_look_successful() {
    let (config, _, mut obs) = fixture();
    obs.handshakes = Some(Ok(BTreeMap::from([(
        ExitId("ch1".into()),
        Handshake::At { unix_secs: 1010 },
    )])));
    obs.forwarding = Some(Err(ProbeError::io("forwarding unavailable")));
    obs.routes = None;
    obs.supervisor = Some(Supervisor::Dead);
    let value = status_value(
        &config,
        &Err(CheckError {
            stage: Stage::Forwarding,
            source: ProbeError::io("forwarding unavailable"),
        }),
        &obs,
        1000,
    )
    .unwrap();
    let mut output = Vec::new();
    status(&mut output, &value).unwrap();
    let output = String::from_utf8(output).unwrap();
    for expected in [
        "observation failed",
        "10s in future",
        "not observed",
        "forwarding unavailable",
        "scupperd unavailable",
    ] {
        assert!(output.contains(expected), "{output}");
    }
}

#[test]
fn observed_empty_routes_say_no_clients() {
    let (config, report, mut obs) = fixture();
    obs.routes = Some(vec![]);
    let value = status_value(&config, &Ok(report), &obs, 1000).unwrap();
    let mut output = Vec::new();
    status(&mut output, &value).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("Client route\n  no clients\n")
    );
}
