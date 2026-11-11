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
fn lab_account_preflight_refuses_users_and_groups_without_claiming_them() {
    let passwd = "root:x:0:0:root:/root:/bin/bash\n";
    let group = "root:x:0:\n";
    super::refuse_lab_accounts(passwd, group).unwrap();
    for account in super::LAB_ACCOUNTS {
        for (users, groups) in [
            (
                format!("{passwd}{account}:x:991:991::/nonexistent:/usr/sbin/nologin\n"),
                group.into(),
            ),
            (passwd.into(), format!("{group}{account}:x:991:\n")),
        ] {
            let error = super::refuse_lab_accounts(&users, &groups).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("refusing occupied {account} lab account/group")
            );
        }
    }
}

#[test]
fn address_table_is_disjoint_and_restricted() {
    let mut networks: Vec<IpNet> = A.segments().map(|s| s.network.parse().unwrap()).to_vec();
    networks.extend(
        [A.client_net, A.exit_net, A.client_v6_net, A.internet_v6_net]
            .map(|s| s.parse::<IpNet>().unwrap()),
    );
    networks.extend(
        ["2001:db8:2::/64", "2001:db8:3::/64", "2001:db8:5::/64"]
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
        ("2001:db8:5::/64", A.bridge_v6),
        ("2001:db8:5::/64", A.bridge_wan_v6),
        ("fe80::/64", A.client_link_local_v6),
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
fn second_client_runtime_configuration_preserves_the_single_peer_capture_template() {
    let mut config = scupper_core::config::parse_site(SITE).unwrap();
    assert_eq!(config.devices.len(), 1);
    super::add_second_client(&mut config, "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=").unwrap();
    let site = scupper_core::config::validate(config).unwrap();
    assert_eq!(site.devices().len(), 2);
    assert_eq!(
        site.devices()["client2"].address4().addr().to_string(),
        "10.99.0.3"
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
        assert_eq!(value["min_packets"].as_integer(), Some(4));
        assert_eq!(value["expect"].as_array().unwrap().len(), 2);
        assert_eq!(value["wireguard"].as_array().unwrap().len(), 2);
        let l11: toml::Value =
            toml::from_str(&evidence::policy_for_case(&markers, false, 51821, true).unwrap())
                .unwrap();
        assert_eq!(l11["wireguard"].as_array().unwrap().len(), 3);
        assert_eq!(
            l11["wireguard"][2]["peer"].as_str(),
            Some("192.0.2.10:51820")
        );
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
    assert_eq!(names.len(), 9);
    assert!(names.contains("L19"));
    assert!(names.contains("daemon"));
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
fn foreign_control_accepts_any_exact_udp_marker_but_rejects_silence_and_substrings() {
    let markers: Vec<String> = ["control-first", "control-second", "control-third"]
        .map(String::from)
        .to_vec();
    let packet = |payload: &[u8]| udp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 8080, payload);
    let check = |packets: &[Vec<u8>]| super::daemon::foreign_control(&capture(packets), &markers);
    assert!(check(&[]).is_err());
    assert!(check(&[packet(b"other")]).is_err());
    assert!(check(&[packet(b"prefix-control-second-suffix")]).is_err());
    for marker in &markers {
        assert_eq!(check(&[packet(marker.as_bytes())]).unwrap(), 1);
    }
    let packets: Vec<_> = markers.iter().map(|m| packet(m.as_bytes())).collect();
    assert_eq!(check(&packets).unwrap(), 3);
    // Repeated packets prove one marker, and TCP cannot satisfy the UDP control.
    assert_eq!(check(&[packets[1].clone(), packets[1].clone()]).unwrap(), 1);
    let mut tcp = packet(markers[1].as_bytes());
    tcp[9] = 6;
    assert!(check(&[tcp]).is_err());
}
#[test]
fn positive_controls_require_packet_evidence_and_reject_silence() {
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
    assert!(!evidence::contained(&empty));
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
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("lab-test-{name}-{}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}
#[test]
fn command_output_waits_for_exit_and_eof_after_large_and_delayed_writes() {
    let dir = test_dir("output-eof");
    let mut runner = Runner::new(
        fs::File::create(dir.join("trace")).unwrap(),
        Arc::new(AtomicBool::new(false)),
    );
    let (status, stdout) = runner.output(&Invocation::new("", "/bin/sh", &[
        "-c",
        r#"printf '{"body":"'; head -c 131072 /dev/zero | tr '\000' x; head -c 131072 /dev/zero >&2; (sleep 0.05; printf '"}') &"#,
    ]), None).unwrap();
    assert!(status.success());
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["body"].as_str().unwrap(), "x".repeat(131_072));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn command_failure_preserves_stderr_in_case_error() {
    let dir = test_dir("stderr");
    let mut runner = Runner::new(
        fs::File::create(dir.join("trace")).unwrap(),
        Arc::new(AtomicBool::new(false)),
    );
    let error = runner
        .input(
            &Invocation::new("", "sh", &["-c", "cat >&2; exit 1"]),
            Some(b"nft: unsupported expression\n"),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("nft: unsupported expression"));
    assert!(error.contains("exit status: 1"));
    fs::remove_dir_all(dir).unwrap();
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
        "name\twanted\tgot\telapsed_ms\tdetail\nbaseline\tclean\tfailed\t0\tone two three \n"
    );
    assert_eq!(
        serde_json::from_str::<Vec<Row>>(&fs::read_to_string(dir.join("results.json")).unwrap())
            .unwrap(),
        rows
    );
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn setup_observations_do_not_masquerade_as_shard_cases_and_measurements_survive() {
    let dir = test_dir("setup-results");
    let row = |name: &str, got: &str, detail: &str| Row {
        name: name.into(),
        wanted: "evidence".into(),
        got: got.into(),
        detail: detail.into(),
    };
    let mut rows = vec![
        row("L18", "verified", "hardening"),
        row("boot-adopt", "adopted", "trace"),
        row("L9-cli-0", "passed", "checkpoint"),
        row(
            "daemon-L7",
            "passed",
            "elapsed_ms=1234; forwarding_zero_ms=42",
        ),
        row("daemon-unknown", "passed", "not catalogued"),
    ];
    evidence::save_setup(&dir, &mut rows).unwrap();
    evidence::save_setup(&dir, &mut rows).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "daemon-L7");
    evidence::save_results(&dir, &rows).unwrap();
    let tsv = fs::read_to_string(dir.join("results.tsv")).unwrap();
    assert!(tsv.contains("passed\t1234\telapsed_ms=1234; forwarding_zero_ms=42"));
    let setup: Vec<Row> =
        serde_json::from_slice(&fs::read(dir.join("setup-results.json")).unwrap()).unwrap();
    assert_eq!(setup.len(), 4);
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
    let checkpoint = runner.background_checkpoint();
    let mut group = runner
        .background(
            &Invocation::new("", "sleep", &["5"]),
            &dir.join("sleep.stdout"),
        )
        .unwrap();
    group.alive().unwrap();
    assert!(runner.assert_background_released(checkpoint).is_err());
    group.stop(rustix::process::Signal::TERM).unwrap();
    runner.assert_background_released(checkpoint).unwrap();
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
    let error = evidence::check_capture_stats(
        "0 packets captured\n218 packets received by filter\n0 packets dropped by kernel\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("capture harness error"));
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

fn healthy_outer_packets() -> Vec<Vec<u8>> {
    let mut wg = vec![0; 32];
    wg[0] = 4;
    (0..8)
        .flat_map(|_| {
            [
                udp([198, 51, 100, 2], [192, 0, 2, 2], 51820, 51820, &wg),
                udp([198, 51, 100, 2], [203, 0, 113, 2], 51821, 51820, &wg),
            ]
        })
        .collect()
}

#[test]
fn uplink_control_requires_exact_injections_reasons_and_no_other_leaks() {
    let marker = "scupper-canary-00112233445566778899aabbccddeeff".to_owned();
    let policy =
        Policy::from_toml(&evidence::policy(std::slice::from_ref(&marker), false).unwrap())
            .unwrap();
    let mut packets = healthy_outer_packets();
    packets.extend(super::helpers::injection_packets(&marker).unwrap());
    let bytes = capture(&packets);
    let report = classify(&bytes, &policy, 0).unwrap();
    assert_eq!(report.violation_count, 3);
    assert_eq!(report.counts["Violation(CanaryMarker)"], 2);
    assert_eq!(report.counts["Violation(ForbiddenAddress)"], 1);
    assert!(evidence::injected_only(&report, &bytes, &marker).is_ok());

    // A real extra leak cannot be laundered as the deliberate positive control.
    packets.push(udp(
        [10, 99, 0, 2],
        [198, 51, 100, 1],
        1234,
        8080,
        b"unrelated",
    ));
    let bytes = capture(&packets);
    assert!(
        evidence::injected_only(&classify(&bytes, &policy, 0).unwrap(), &bytes, &marker).is_err()
    );
    packets.pop();
    // Three violations, but one is not an injected tuple/payload.
    packets.last_mut().unwrap()[20..22].copy_from_slice(&40004_u16.to_be_bytes());
    let bytes = capture(&packets);
    let report = classify(&bytes, &policy, 0).unwrap();
    assert_eq!(report.violation_count, 3);
    assert!(evidence::injected_only(&report, &bytes, &marker).is_err());
    packets.pop();
    let bytes = capture(&packets);
    assert!(
        evidence::injected_only(&classify(&bytes, &policy, 0).unwrap(), &bytes, &marker).is_err()
    );
    let mut wrong = classify(&capture(&healthy_outer_packets()), &policy, 0).unwrap();
    wrong.violation_count = 3;
    assert!(evidence::injected_only(&wrong, &bytes, &marker).is_err());

    // With the marker list broken, both marker-only injections cease to have
    // CanaryMarker as their reason; forbidden-address coverage alone cannot pass.
    let text = evidence::policy(&[], false).unwrap();
    let policy = Policy::from_toml(&text).unwrap();
    let mut packets = healthy_outer_packets();
    packets.extend(super::helpers::injection_packets(&marker).unwrap());
    let bytes = capture(&packets);
    assert!(
        evidence::injected_only(&classify(&bytes, &policy, 0).unwrap(), &bytes, &marker).is_err()
    );
}

fn ipv6(source: &str, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    packet[6] = protocol;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.parse::<std::net::Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(
        &A.internet_v6
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    packet.extend(payload);
    packet
}

#[test]
fn ipv6_exit_leak_fails_and_all_capture_instances_require_liveness() {
    let markers: Vec<String> = (0..5)
        .map(|i| format!("scupper-canary-00112233445566778899aabbccddeef{i}"))
        .collect();
    let mut packets: Vec<_> = (0..4)
        .map(|_| udp([10, 2, 0, 2], [192, 0, 2, 6], 1234, 8080, b"liveness"))
        .collect();
    let check = |packets: &[Vec<u8>], ingress, permissive| {
        evidence::v6_evidence(&capture(packets), &markers, ingress, permissive, "fe80::2")
    };
    assert!(check(&[], false, false).is_err());
    assert!(check(&packets, false, false).is_ok());
    assert!(check(&packets, true, false).is_err());
    assert!(check(&packets, false, true).is_err());
    let mut payload = vec![0, 1, 0x1f, 0x90, 0, 60, 0, 1];
    payload.extend(markers[2].as_bytes());
    packets.push(ipv6(A.client_v6, 17, &payload));
    assert!(check(&packets, false, false).is_err());
    assert!(check(&packets, false, true).is_err());
    payload.truncate(8);
    payload.extend(markers[3].as_bytes());
    packets.push(ipv6(A.client_v6, 17, &payload));
    assert!(check(&packets, false, true).is_ok());
    let mut tcp = vec![0; 20];
    tcp[..4].copy_from_slice(&[0, 1, 0x1f, 0x90]);
    tcp[12] = 0x50;
    packets.push(ipv6(A.client_v6, 6, &tcp));
    tcp[1] = 2;
    packets.push(ipv6(A.client_v6, 6, &tcp));
    assert!(check(&packets, true, false).is_err());
    payload.truncate(8);
    payload.extend(markers[4].as_bytes());
    packets.push(ipv6("fe80::2", 17, &payload));
    assert!(check(&packets, true, false).is_ok());
    // Removing IPv4 traffic makes even a nonempty canary capture fail liveness.
    assert!(check(&packets[4..], true, false).is_err());
}

#[test]
fn antispoof_drop_must_belong_to_the_observed_source_trace() {
    let trace = "trace id ab inet scupper antispoof packet: ip6 saddr fd00:99::2 ip6 daddr 2001:db8:4::6\ntrace id ab inet scupper antispoof rule ... (verdict drop)\n";
    assert!(evidence::antispoof_trace(trace, &[A.client_v6]).is_ok());
    assert!(evidence::antispoof_trace(trace, &["fe80::2"]).is_err());
    assert!(
        evidence::antispoof_trace(
            &trace.replace(
                "id ab inet scupper antispoof rule",
                "id cd inet scupper antispoof rule"
            ),
            &[A.client_v6]
        )
        .is_err()
    );
    assert!(
        evidence::antispoof_trace(
            &trace.replace("antispoof rule", "forward rule"),
            &[A.client_v6]
        )
        .is_err()
    );
}

#[test]
fn bridge_policy_requires_arp_and_both_ping_exchanges() {
    let ethernet = |kind: u16, payload: &[u8]| {
        let mut frame = vec![0; 12];
        frame.extend(kind.to_be_bytes());
        frame.extend(payload);
        frame
    };
    let mut frames = Vec::new();
    for (source, destination, operation) in [
        ([198, 51, 100, 6], [198, 51, 100, 5], 1_u8),
        ([198, 51, 100, 5], [198, 51, 100, 6], 2),
    ] {
        let mut arp = vec![0; 28];
        arp[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, operation]);
        arp[14..18].copy_from_slice(&source);
        arp[24..28].copy_from_slice(&destination);
        frames.push(ethernet(0x0806, &arp));
    }
    for (source, destination, kind) in [
        ([198, 51, 100, 6], [198, 51, 100, 5], 8),
        ([198, 51, 100, 5], [198, 51, 100, 6], 0),
    ] {
        let mut ip = udp(source, destination, 0, 0, &[]);
        ip[9] = 1;
        ip[20] = kind;
        frames.push(ethernet(0x0800, &ip));
    }
    for (source, destination, kind) in [
        (A.bridge_v6, A.bridge_wan_v6, 128),
        (A.bridge_wan_v6, A.bridge_v6, 129),
    ] {
        let mut ip = ipv6(source, 58, &[kind, 0, 0, 0, 0, 1, 0, 1]);
        ip[24..40].copy_from_slice(&destination.parse::<std::net::Ipv6Addr>().unwrap().octets());
        frames.push(ethernet(0x86dd, &ip));
    }
    let policy = Policy::from_toml(&evidence::policy(&[], true).unwrap()).unwrap();
    let classify_frames = |frames: &[Vec<u8>]| {
        let mut bytes = capture(frames);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        classify(&bytes, &policy, 0).unwrap()
    };
    assert!(evidence::contained(&classify_frames(&frames)));
    for omitted in [0..2, 2..4, 4..6] {
        let remaining: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| !omitted.contains(i))
            .map(|(_, frame)| frame.clone())
            .collect();
        assert!(!evidence::contained(&classify_frames(&remaining)));
    }
}

fn bad_inline_nft_braces(source: &str) -> bool {
    let adjacent = |text: &str| {
        text.lines().any(|line| {
            line.match_indices('}').any(|(at, _)| {
                line[at + 1..]
                    .trim_start_matches([' ', '\t', '\r'])
                    .starts_with('}')
            })
        })
    };
    // Ordinary byte strings: preserve escaped quotes and decode line boundaries.
    for start in source.match_indices("b\"").map(|(at, _)| at + 2) {
        let mut literal = String::new();
        let mut chars = source[start..].chars();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => literal.push('\n'),
                    Some('t') => literal.push('\t'),
                    Some('r') => literal.push('\r'),
                    Some(ch) => literal.push(ch),
                    None => break,
                },
                ch => literal.push(ch),
            }
        }
        if adjacent(&literal) {
            return true;
        }
    }
    // Raw byte strings used by the topology fixtures.
    source
        .split("br#\"")
        .skip(1)
        .any(|tail| adjacent(tail.split("\"#").next().unwrap()))
}

#[test]
fn inline_nft_guard_handles_spacing_and_escaped_quotes() {
    for source in [
        r#"Some(b"table { chain { } }")"#,
        r#"Some(b"table { chain { }}")"#,
        r#"Some(b"oifname \"eth0\"; }\t}")"#,
    ] {
        assert!(bad_inline_nft_braces(source), "{source}");
    }
    assert!(!bad_inline_nft_braces(r#"Some(b"table { chain { }\n}")"#));
    assert!(!bad_inline_nft_braces("br#\"table { chain { }\n}\"#"));
}

/// nft rejects `...; } }` on one line (a closing brace after a chain needs a newline);
/// every inline ruleset in the lab must be written with newlines.
#[test]
fn inline_nft_rulesets_have_no_single_line_closing_braces() {
    let mut directories = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lab")];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") || path.ends_with("tests.rs") {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            assert!(
                !bad_inline_nft_braces(&source),
                "{} contains a one-line nft ruleset",
                path.display()
            );
        }
    }
}

#[test]
fn boot_prefix_oracle_rejects_plaintext_and_silence_with_ephemeral_exit_ports() {
    let dir = test_dir("boot-prefix");
    let marker = "scupper-canary-00112233445566778899aabbccddeeff".to_owned();
    let markers = std::slice::from_ref(&marker);
    let mut encrypted = vec![0; 32];
    encrypted[0] = 4;
    let mut packets = vec![
        udp([192, 0, 2, 2], [198, 51, 100, 2], 51820, 51820, &encrypted),
        udp(
            [198, 51, 100, 2],
            [203, 0, 113, 2],
            43210,
            51820,
            &encrypted,
        ),
    ];
    fs::write(dir.join("prefix.pcap"), capture(&packets)).unwrap();
    evidence::boot_prefix(&dir, "prefix", markers, 43210, false).unwrap();
    evidence::boot_prefix(&dir, "prefix", markers, 43210, true).unwrap();
    fs::write(dir.join("prefix.pcap"), capture(&packets[..1])).unwrap();
    assert!(evidence::boot_prefix(&dir, "prefix", markers, 43210, true).is_err());
    let mut initiation = vec![0; 148];
    initiation[0] = 1;
    let handshake_only = vec![
        packets[0].clone(),
        udp(
            [198, 51, 100, 2],
            [203, 0, 113, 2],
            43210,
            51820,
            &initiation,
        ),
    ];
    fs::write(dir.join("prefix.pcap"), capture(&handshake_only)).unwrap();
    evidence::boot_prefix(&dir, "prefix", markers, 43210, false).unwrap();
    assert!(evidence::boot_prefix(&dir, "prefix", markers, 43210, true).is_err());
    fs::write(dir.join("prefix.pcap"), capture(&packets)).unwrap();
    assert!(evidence::boot_prefix(&dir, "prefix", markers, 51821, false).is_err());
    packets.push(udp(
        [10, 99, 0, 2],
        [192, 0, 2, 6],
        40001,
        8080,
        marker.as_bytes(),
    ));
    fs::write(dir.join("prefix.pcap"), capture(&packets)).unwrap();
    assert!(evidence::boot_prefix(&dir, "prefix", markers, 43210, false).is_err());
    fs::write(dir.join("prefix.pcap"), capture(&[])).unwrap();
    assert!(evidence::boot_prefix(&dir, "prefix", markers, 43210, false).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn boot_canary_requires_received_bytes_and_the_actual_ingress_marker() {
    use super::boot::boot_canary_arrival;
    let markers = vec!["marker".to_owned()];
    let packet = udp([10, 99, 0, 2], [192, 0, 2, 6], 40001, 8080, b"marker");
    let pcap = capture(std::slice::from_ref(&packet));
    boot_canary_arrival(10, 11, &pcap, &markers).unwrap();
    assert!(boot_canary_arrival(10, 10, &pcap, &markers).is_err());
    assert!(boot_canary_arrival(10, 11, &capture(&[]), &markers).is_err());
    assert!(boot_canary_arrival(10, 11, &pcap, &["different".into()]).is_err());
}

#[test]
fn longest_daemon_case_has_a_short_control_socket_path() {
    let longest = super::daemon::CASES
        .iter()
        .max_by_key(|case| case.len())
        .unwrap();
    let root = super::daemon::short_boot_root(longest).join("run/scupper");
    assert!(root.join("control.sock").as_os_str().len() < 108);
    scupper_sys::daemon::control::validate_socket_path(&root).unwrap();
}

#[test]
fn fresh_handshake_only_uses_the_expected_client() {
    use super::boot::client_handshake;
    let before = client_handshake("client1 100\nclient2 200\n", "client1");
    assert_eq!(before, 100);
    assert_eq!(
        client_handshake("client2 999\nclient1 100\n", "client1"),
        before
    );
    assert_eq!(client_handshake("client2 999\n", "client1"), 0);
    assert_eq!(
        client_handshake("client1 101\nclient2 999\n", "client1"),
        before + 1
    );
    assert_eq!(client_handshake("client1 0\nclient2 999\n", "client1"), 0);
}
