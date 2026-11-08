//! Golden parity and configuration guards for the fail-closed v1 renderer.

use std::net::Ipv4Addr;

use proptest::prelude::*;
use scupper::rules::{IfName, V1Config, ruleset};

const GOLDEN: &str = include_str!("golden/ruleset.golden");

fn line_diff(expected: &str, actual: &str) -> String {
    let expected: Vec<_> = expected.split_inclusive('\n').collect();
    let actual: Vec<_> = actual.split_inclusive('\n').collect();
    (0..expected.len().max(actual.len()))
        .filter(|&index| expected.get(index) != actual.get(index))
        .map(|index| {
            format!(
                "line {}:\n- {:?}\n+ {:?}",
                index + 1,
                expected.get(index),
                actual.get(index)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn golden_byte_exact() {
    let cfg = V1Config::default();
    assert_eq!(cfg.client_iface.as_str(), "wg0");
    assert_eq!(cfg.exit_iface.as_str(), "proton0");
    assert_eq!(cfg.uplink_iface.as_str(), "eth0");
    assert_eq!(cfg.exit_addr, Ipv4Addr::new(10, 2, 0, 2));
    assert_eq!(cfg.client_addr, Ipv4Addr::new(10, 99, 0, 2));

    let actual = ruleset(&cfg).expect("default configuration must render");
    assert_eq!(actual, GOLDEN, "\n{}", line_diff(GOLDEN, &actual));
}

#[test]
fn config_values_flow_into_output() {
    let cfg = V1Config {
        client_iface: IfName::new("wgX").unwrap(),
        exit_iface: IfName::new("exitY").unwrap(),
        uplink_iface: IfName::new("upZ").unwrap(),
        exit_addr: Ipv4Addr::new(10, 9, 9, 9),
        ..V1Config::default()
    };
    let actual = ruleset(&cfg).unwrap();
    for expected in [
        "iifname \"wgX\" oifname \"exitY\" accept",
        "iifname \"exitY\" oifname \"wgX\" ct state established,related accept",
        "oifname \"exitY\" masquerade",
        "oifname \"upZ\" ip saddr 10.9.9.9 drop",
    ] {
        assert!(actual.contains(expected), "missing rule: {expected}");
    }
    for stale_default in ["wg0", "proton0", "eth0", "10.2.0.2"] {
        assert!(
            !actual.contains(stale_default),
            "stale default: {stale_default}"
        );
    }
}

#[test]
fn ifname_validation_table() {
    for invalid in [
        "",
        "abcdefghijklmnop",
        "\"",
        "\\",
        " ",
        "\t",
        "\n",
        "/",
        ".",
        "..",
        "wg0;",
        "é",
        "wg\"0",
        "wg\\0",
        "wg 0",
        "wg\t0",
        "wg\n0",
        "wg/0",
        "wg\0",
    ] {
        let error = IfName::new(invalid).expect_err("invalid name must be rejected");
        for field in ["client_iface", "exit_iface", "uplink_iface"] {
            assert!(error.to_string().contains(field));
        }
        assert!(invalid.parse::<IfName>().is_err(), "accepted {invalid:?}");
    }
    for valid in [
        "abcdefghijklmno",
        "wg0",
        "ex-ch1",
        "eth0.100",
        "a_b",
        "A0",
        "-",
        "_",
    ] {
        let name = IfName::new(valid).expect("valid name must be accepted");
        assert_eq!(name.as_str(), valid);
        assert_eq!(name.to_string(), valid);
        assert_eq!(valid.parse::<IfName>().unwrap(), name);
    }
}

#[test]
fn interfaces_must_be_distinct() {
    let base = V1Config::default();
    for (cfg, field, other) in [
        (
            V1Config {
                client_iface: base.exit_iface.clone(),
                ..base.clone()
            },
            "client_iface",
            "exit_iface",
        ),
        (
            V1Config {
                exit_iface: base.uplink_iface.clone(),
                ..base.clone()
            },
            "exit_iface",
            "uplink_iface",
        ),
        (
            V1Config {
                client_iface: base.uplink_iface.clone(),
                ..base.clone()
            },
            "client_iface",
            "uplink_iface",
        ),
    ] {
        let error = cfg
            .validate()
            .expect_err("overlapping roles must be rejected");
        assert!(error.to_string().contains(field));
        assert!(error.to_string().contains(other));
        assert_eq!(ruleset(&cfg), Err(error));
    }
}

#[test]
fn address_validation() {
    for field in ["exit_addr", "client_addr"] {
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 0),
            Ipv4Addr::new(239, 255, 255, 255),
        ] {
            let mut cfg = V1Config::default();
            if field == "exit_addr" {
                cfg.exit_addr = address;
            } else {
                cfg.client_addr = address;
            }
            let error = cfg
                .validate()
                .expect_err("invalid endpoint must be rejected");
            assert!(error.to_string().contains(field), "{error}");
            assert_eq!(ruleset(&cfg), Err(error));
        }
    }
    let mut cfg = V1Config::default();
    cfg.client_addr = cfg.exit_addr;
    let error = cfg
        .validate()
        .expect_err("equal endpoints must be rejected");
    assert!(error.to_string().contains("exit_addr"));
    assert!(error.to_string().contains("client_addr"));
    assert_eq!(ruleset(&cfg), Err(error));
}

fn valid_ifname() -> impl Strategy<Value = IfName> {
    "[A-Za-z0-9._-]{1,15}".prop_filter_map("valid interface syntax", |name| IfName::new(&name).ok())
}

fn valid_address() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>()
        .prop_map(Ipv4Addr::from)
        .prop_filter("individual endpoint", |address| {
            !address.is_unspecified() && !address.is_broadcast() && !address.is_multicast()
        })
}

fn valid_config() -> impl Strategy<Value = V1Config> {
    (
        valid_ifname(),
        valid_ifname(),
        valid_ifname(),
        valid_address(),
        valid_address(),
    )
        .prop_filter(
            "distinct interface and endpoint roles",
            |(client, exit, uplink, exit_addr, client_addr)| {
                client != exit && exit != uplink && client != uplink && exit_addr != client_addr
            },
        )
        .prop_map(
            |(client_iface, exit_iface, uplink_iface, exit_addr, client_addr)| V1Config {
                client_iface,
                exit_iface,
                uplink_iface,
                exit_addr,
                client_addr,
            },
        )
}

fn invalid_ifname() -> impl Strategy<Value = String> {
    let forbidden_character = any::<char>()
        .prop_filter("outside interface alphabet", |character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-')
        });
    prop_oneof![
        (
            "[A-Za-z0-9._-]{0,7}",
            forbidden_character,
            "[A-Za-z0-9._-]{0,7}"
        )
            .prop_map(|(prefix, character, suffix)| format!("{prefix}{character}{suffix}")),
        "[A-Za-z0-9._-]{16,128}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_valid_configs_render(cfg in valid_config()) {
        let output = ruleset(&cfg).expect("valid configuration must render");
        prop_assert_eq!(output.lines().count(), GOLDEN.lines().count());
        prop_assert!(output.ends_with('\n'));
        prop_assert!(!output.contains("iif "));
        prop_assert!(!output.contains("oif "));

        // The byte-exact v1 header mentions the uplink without nftables quoting.
        // Quoting and occurrence checks therefore cover executable rules only.
        let lines: Vec<_> = output.lines().filter(|line| !line.starts_with('#')).collect();
        let quoted_uplink = format!("\"{}\"", cfg.uplink_iface);
        let mut interfaces = Vec::new();
        for line in &lines {
            let tokens: Vec<_> = line.split_whitespace().collect();
            for pair in tokens.windows(2) {
                if matches!(pair[0], "iifname" | "oifname") {
                    prop_assert!(pair[1].starts_with('"') && pair[1].ends_with('"'));
                    interfaces.push(pair[1]);
                }
            }
            if line.contains(" accept") || line.contains(" masquerade") {
                prop_assert!(!line.contains(&quoted_uplink));
            }
        }
        for (name, count) in [(&cfg.client_iface, 2), (&cfg.exit_iface, 3), (&cfg.uplink_iface, 1)] {
            let quoted = format!("\"{name}\"");
            prop_assert_eq!(interfaces.iter().filter(|&&token| token == quoted).count(), count);
            prop_assert_eq!(lines.iter().map(|line| line.matches(&quoted).count()).sum::<usize>(), count);
        }
        prop_assert_eq!(interfaces.len(), 6);
        let drop_rule = format!("oifname \"{}\" ip saddr {} drop", cfg.uplink_iface, cfg.exit_addr);
        prop_assert!(lines.iter().any(|line| line.trim() == drop_rule));
    }

    #[test]
    fn prop_invalid_ifnames_rejected(name in invalid_ifname()) {
        prop_assert!(IfName::new(&name).is_err(), "accepted invalid name: {:?}", name);
    }
}
