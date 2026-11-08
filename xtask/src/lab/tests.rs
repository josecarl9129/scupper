//! Pure policy/topology tests and unprivileged command/registry checks.
#![allow(clippy::unwrap_used)]
use super::{
    SITE,
    addresses::A,
    command::{Invocation, Runner},
    evidence::{self, Case, Row},
    fixtures::redact_public_keys,
};
use crate::pcap::{Policy, classify};
use ipnet::IpNet;
use std::{
    collections::BTreeSet,
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

#[test]
fn address_table_is_disjoint_and_restricted() {
    let mut networks: Vec<IpNet> = A.segments().map(|s| s.network.parse().unwrap()).to_vec();
    networks.extend(
        [A.client_net, A.exit_net, A.client_v6_net, A.internet_v6_net]
            .map(|s| s.parse::<IpNet>().unwrap()),
    );
    let permitted = [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
        "10.99.0.0/24",
        "10.2.0.0/24",
        "fd00:99::/64",
    ]
    .map(|s| s.parse::<IpNet>().unwrap());
    for (i, network) in networks.iter().enumerate() {
        assert!(
            permitted
                .iter()
                .any(|allowed| allowed.contains(&network.network())
                    && allowed.prefix_len() <= network.prefix_len())
        );
        for other in &networks[i + 1..] {
            assert!(!network.contains(&other.network()) && !other.contains(&network.network()));
        }
    }
    for segment in A.segments() {
        let network: IpNet = segment.network.parse().unwrap();
        let wan: IpAddr = segment.wan.parse().unwrap();
        let peer: IpAddr = segment.peer.parse().unwrap();
        assert!(network.contains(&wan) && network.contains(&peer));
        assert_ne!(wan, peer);
        assert_ne!(wan, network.network());
        assert_ne!(peer, network.broadcast());
    }
    for (network, address) in [
        (A.client_net, A.client_inner),
        (A.client_net, A.gateway_inner),
        (A.exit_net, A.provider_inner),
        (A.exit_net, A.exit_inner),
        (A.client_v6_net, A.client_v6),
        (A.internet_v6_net, A.internet_v6),
        (A.internet_v6_net, A.wan_v6),
    ] {
        assert!(
            network
                .parse::<IpNet>()
                .unwrap()
                .contains(&address.parse::<IpAddr>().unwrap())
        );
    }
}
#[test]
fn lab_site_validates_and_matches_all_tunnel_addresses() {
    let site =
        scupper_core::config::validate(scupper_core::config::parse_site(SITE).unwrap()).unwrap();
    let gateway = site.gateways().values().next().unwrap();
    assert_eq!(gateway.endpoint().ip().to_string(), A.gwhost.peer);
    assert_eq!(
        gateway.client_tunnel().address4().addr().to_string(),
        A.gateway_inner
    );
    assert_eq!(
        gateway.exits()[0].endpoint().ip().to_string(),
        A.provider.peer
    );
    assert_eq!(
        gateway.exits()[0].address4().addr().to_string(),
        A.exit_inner
    );
    assert_eq!(
        site.devices()
            .values()
            .next()
            .unwrap()
            .address4()
            .addr()
            .to_string(),
        A.client_inner
    );
}
#[test]
fn policy_for_every_case_has_exact_endpoints_and_positive_evidence() {
    let markers = vec!["scupper-canary-00112233445566778899aabbccddeeff".into()];
    let mut names = BTreeSet::new();
    for case in Case::ALL {
        assert!(names.insert(case.name()));
        let text = evidence::policy(&markers, false).unwrap();
        Policy::from_toml(&text).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(value["min_packets"].as_integer(), Some(16));
        assert_eq!(value["expect"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["wireguard"][0]["gateway"].as_str(),
            Some("198.51.100.2:51820")
        );
        assert_eq!(
            value["wireguard"][0]["peer"].as_str(),
            Some("192.0.2.2:51820")
        );
        assert_eq!(
            value["wireguard"][1]["gateway"].as_str(),
            Some("198.51.100.2:51821")
        );
        assert_eq!(
            value["wireguard"][1]["peer"].as_str(),
            Some("203.0.113.2:51820")
        );
        assert_eq!(value["forbidden_addrs"].as_array().unwrap().len(), 5);
        assert_eq!(
            value["canary_markers"][0].as_str(),
            Some(markers[0].as_str())
        );
        assert!(value["arp"].as_bool().unwrap() && value["ndp"].as_bool().unwrap());
    }
    assert_eq!(names.len(), 5);
    Policy::from_toml(&evidence::policy(&markers, true).unwrap()).unwrap();
}
fn capture(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut data = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    data.extend([0_u8; 8]);
    data.extend(65535_u32.to_le_bytes());
    data.extend(101_u32.to_le_bytes());
    for packet in packets {
        data.extend([0_u8; 8]);
        data.extend(u32::try_from(packet.len()).unwrap().to_le_bytes());
        data.extend(u32::try_from(packet.len()).unwrap().to_le_bytes());
        data.extend(packet);
    }
    data
}
fn udp(source: [u8; 4], destination: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&u16::try_from(28 + payload.len()).unwrap().to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&source);
    bytes[16..20].copy_from_slice(&destination);
    bytes[20..22].copy_from_slice(&sport.to_be_bytes());
    bytes[22..24].copy_from_slice(&dport.to_be_bytes());
    bytes[24..26].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    bytes.extend(payload);
    bytes
}
#[test]
fn positive_controls_require_packet_evidence_and_silence_is_auxiliary_only() {
    let marker = "scupper-canary-00112233445566778899aabbccddeeff".to_owned();
    let policy =
        Policy::from_toml(&evidence::policy(std::slice::from_ref(&marker), false).unwrap())
            .unwrap();
    let mut wg = vec![0; 32];
    wg[0] = 4;
    let mut packets = Vec::new();
    for _ in 0..8 {
        packets.push(udp([198, 51, 100, 2], [192, 0, 2, 2], 51820, 51820, &wg));
        packets.push(udp([198, 51, 100, 2], [203, 0, 113, 2], 51821, 51820, &wg));
    }
    let healthy = classify(&capture(&packets), &policy, 0).unwrap();
    assert_eq!(healthy.violation_count, 0);
    assert!(!evidence::leak_seen(&healthy));
    packets.push(udp(
        [10, 99, 0, 2],
        [192, 0, 2, 6],
        40001,
        8080,
        marker.as_bytes(),
    ));
    let leaking = classify(&capture(&packets), &policy, 0).unwrap();
    assert!(evidence::leak_seen(&leaking));
    assert_eq!(leaking.capture_failures, []);
    let empty = classify(&capture(&[]), &policy, 0).unwrap();
    assert!(!evidence::leak_seen(&empty));
    assert!(!evidence::contained(&empty));
    let auxiliary = Policy::from_toml(&evidence::policy(&[], true).unwrap()).unwrap();
    let empty = classify(&capture(&[]), &auxiliary, 0).unwrap();
    assert!(evidence::contained(&empty));
    assert!(!evidence::leak_seen(&empty));
    let malformed = classify(&capture(&[vec![0_u8; 30]]), &auxiliary, 0).unwrap();
    assert!(!evidence::contained(&malformed));
    assert!(!evidence::leak_seen(&malformed));
}
#[test]
fn every_external_program_uses_argv_namespace_entry_and_a_timeout() {
    let commands: &[(&str, &[&str])] = &[
        ("ip", &["-j", "route", "show", "table", "all"]),
        ("wg", &["show", "wg0", "public-key"]),
        ("nft", &["-f", "/path with spaces/rules.nft"]),
        ("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]),
        (
            "tcpdump",
            &[
                "-U",
                "-s",
                "0",
                "-i",
                "to-gwhost",
                "-w",
                "/pcap path/case.pcap",
            ],
        ),
        ("dnsmasq", &["--keep-in-foreground", "--no-resolv"]),
        ("tc", &["-j", "filter", "show", "dev", "wg0", "ingress"]),
        ("cat", &["/proc/net/udp"]),
        ("nft", &["--version"]),
        ("uname", &["-r"]),
        (
            "/path with spaces/xtask",
            &["probe", "--target", "literal;$(no-shell)`true`"],
        ),
    ];
    for ns in [
        "",
        "gwhost",
        "scupper",
        "client",
        "provA",
        "internet",
        "wan",
        "scupper-verify",
    ] {
        for (program, args) in commands {
            let invocation = Invocation::new(ns, program, args);
            let expected_prefix: Vec<String> = match ns {
                "" => Vec::new(),
                "gwhost" => vec![
                    "--net=/run/netns/gwhost".into(),
                    "--".into(),
                    (*program).into(),
                ],
                _ => vec!["netns".into(), "exec".into(), ns.into(), (*program).into()],
            };
            let mut expected = expected_prefix;
            expected.extend(args.iter().map(|arg| (*arg).to_owned()));
            assert_eq!(invocation.args, expected);
            assert_eq!(
                invocation.program,
                if ns.is_empty() {
                    program
                } else if ns == "gwhost" {
                    "nsenter"
                } else {
                    "ip"
                }
            );
            for seconds in [15, 1050] {
                let timed = invocation.timed(seconds);
                assert_eq!(
                    timed[0..3],
                    ["--signal=TERM", "--kill-after=2", &seconds.to_string()]
                );
                assert_eq!(timed[3], invocation.program);
                assert_eq!(timed[4..], invocation.args);
            }
        }
    }
}
fn test_dir(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../target/lab-test-{name}-{}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}
#[test]
fn command_deadline_kills_and_reaps_without_root() {
    let dir = test_dir("deadline");
    let mut runner = Runner::new(
        fs::File::create(dir.join("trace")).unwrap(),
        Arc::new(AtomicBool::new(false)),
    );
    runner.phase = Instant::now() + Duration::from_millis(100);
    let start = Instant::now();
    assert!(runner.run(&Invocation::new("", "sleep", &["5"])).is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn results_round_trip_and_tsv_sanitizes_only_display_cells() {
    let dir = test_dir("results");
    let rows = vec![Row {
        name: "baseline".into(),
        wanted: "clean".into(),
        got: "failed".into(),
        detail: "one\ttwo\nthree\r".into(),
    }];
    evidence::save_results(&dir, &rows).unwrap();
    assert_eq!(
        fs::read_to_string(dir.join("results.tsv")).unwrap(),
        "name\twanted\tgot\tdetail\nbaseline\tclean\tfailed\tone two three \n"
    );
    assert_eq!(
        serde_json::from_str::<Vec<Row>>(&fs::read_to_string(dir.join("results.json")).unwrap())
            .unwrap(),
        rows
    );
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn public_key_fixture_redaction_preserves_structure() {
    let keys = vec![
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
    ];
    let text = format!(
        "{{\"peers\":[\"{}\",\"{}\",\"{}\"]}}",
        keys[0], keys[1], keys[0]
    );
    assert_eq!(
        redact_public_keys(&text, &keys),
        "{\"peers\":[\"PUBKEY1\",\"PUBKEY2\",\"PUBKEY1\"]}"
    );
}

#[test]
fn background_processes_shutdown_cleanly_and_early_exit_fails() {
    let dir = test_dir("background");
    let cancel = Arc::new(AtomicBool::new(false));
    let mut runner = Runner::new(
        fs::File::create(dir.join("trace")).unwrap(),
        Arc::clone(&cancel),
    );
    let mut group = runner
        .background(
            &Invocation::new("", "sleep", &["5"]),
            &dir.join("sleep.stdout"),
        )
        .unwrap();
    group.alive().unwrap();
    group.stop(rustix::process::Signal::TERM).unwrap();
    group.stop(rustix::process::Signal::TERM).unwrap();
    let mut group = runner
        .background(
            &Invocation::new("", "false", &[]),
            &dir.join("false.stdout"),
        )
        .unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if group.alive().is_err() {
            break;
        }
        assert!(
            Instant::now() < until,
            "background false command did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(runner.run(&Invocation::new("", "true", &[])).is_err());
    let trace = fs::read_to_string(dir.join("trace")).unwrap();
    for line in trace.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn capture_loss_or_missing_statistics_cannot_establish_silence() {
    assert!(
        evidence::check_capture_stats(
            "0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n"
        )
        .is_ok()
    );
    assert!(evidence::check_capture_stats("1 packets dropped by kernel\n").is_err());
    assert!(
        evidence::check_capture_stats(
            "0 packets dropped by kernel\n2 packets dropped by interface\n"
        )
        .is_err()
    );
    assert!(evidence::check_capture_stats("listening on to-gwhost\n").is_err());
}

#[test]
#[ignore = "subprocess fixture"]
#[allow(clippy::zombie_processes)] // The fixture must exit before its bounded child.
fn inherited_pipe_fixture() {
    // This bounded child inherits the test executable's capture pipes and group.
    // The executable exits first, exercising the runner's pipe-drain deadline.
    let _child = std::process::Command::new("timeout")
        .args(["3", "sleep", "2"])
        .spawn()
        .unwrap();
}

#[test]
fn inherited_pipes_are_bounded_after_the_leader_exits() {
    let dir = test_dir("inherited-pipes");
    let mut runner = Runner::new(
        fs::File::create(dir.join("trace")).unwrap(),
        Arc::new(AtomicBool::new(false)),
    );
    runner.phase = Instant::now() + Duration::from_millis(500);
    let executable = std::env::current_exe().unwrap();
    let invocation = Invocation::new(
        "",
        executable.to_str().unwrap(),
        &[
            "--ignored",
            "--exact",
            "lab::tests::inherited_pipe_fixture",
            "--nocapture",
        ],
    );
    let start = Instant::now();
    assert!(runner.run(&invocation).is_err());
    assert!(start.elapsed() < Duration::from_millis(1500));
    fs::remove_dir_all(dir).unwrap();
}
