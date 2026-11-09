//! Exercise every captured namespace observation on both reference runners.
use scupper_core::parse::*;
use std::{error::Error, fs, path::Path};

const FIELDS: [WgField; 8] = [
    WgField::PublicKey,
    WgField::ListenPort,
    WgField::Peers,
    WgField::AllowedIps,
    WgField::Endpoints,
    WgField::PersistentKeepalive,
    WgField::LatestHandshakes,
    WgField::Transfer,
];
fn key(index: usize) -> String {
    format!(
        "{}A=",
        ["A", "E", "I", "M", "Q", "U", "Y", "c"][index % 8].repeat(42)
    )
}
fn substitute(mut text: String) -> String {
    for index in (0..32).rev() {
        text = text.replace(&format!("PUBKEY{index}"), &key(index));
    }
    text
}

#[test]
fn every_namespace_fixture() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/netns");
    for runner in ["ubuntu-22.04", "ubuntu-24.04"] {
        let mut counts = [0; 11];
        for file in fs::read_dir(root.join(runner))? {
            let path = file?.path();
            let name = path
                .file_name()
                .ok_or("missing filename")?
                .to_string_lossy();
            let out = substitute(fs::read_to_string(&path)?);
            if matches!(
                name.as_ref(),
                "rules-v4.json" | "rules-v6.json" | "routes-source-v6.json"
            ) {
                continue;
            }
            let result = if name.ends_with("-link.json") {
                counts[0] += 1;
                fixture_links(&name, &out)
            } else if name.ends_with("-addr.json") {
                counts[1] += 1;
                fixture_addresses(&name, &out)
            } else if name.ends_with("-route.json") || name.ends_with("-routes-all.json") {
                counts[2] += 1;
                fixture_routes(&name, &out)
            } else if name.ends_with("-rule.json") {
                counts[3] += 1;
                fixture_default_rules(&name, &out)
            } else if name.contains("-wg-") {
                counts[4] += 1;
                let field = FIELDS
                    .iter()
                    .find(|f| name.ends_with(&format!("-{}.txt", f.as_str())))
                    .ok_or("unclassified wg fixture")?;
                fixture_wg(&name, *field, &out)
            } else if name.contains("-sysctl-") {
                counts[5] += 1;
                parse_sysctl(&out).map(|value| {
                    assert_eq!(
                        value,
                        i64::from(
                            name.ends_with("ip_forward.txt")
                                || name.ends_with("all.forwarding.txt")
                        )
                    );
                })
            } else if name.ends_with("-qdisc.json") {
                counts[6] += 1;
                parse_tc_qdisc(&out).map(|entries| {
                    assert_ne!(entries, []);
                })
            } else if name.contains("-tc-") {
                counts[7] += 1;
                parse_tc_filter(&out).map(|entries| {
                    assert_eq!(entries, []);
                })
            } else if name.ends_with("-nft-ruleset.json") {
                counts[8] += 1;
                parse_nft_ruleset(&out).map(|_| ())
            } else if name.ends_with("-proc-net-udp.txt") {
                counts[9] += 1;
                parse_proc_net_udp(&out).map(|sockets| {
                    assert!(udp_port_bound(&sockets, 51820));
                    assert!(udp_port_bound(&sockets, 51821));
                })
            } else if name.ends_with("-proc-net-udp6.txt") {
                counts[9] += 1;
                parse_proc_net_udp6(&out).map(|sockets| {
                    assert!(udp_port_bound(&sockets, 51820));
                })
            } else if name.contains("-route-get-") {
                counts[10] += 1;
                parse_route_get(&out).map(|route| {
                    assert!(matches!(route, RouteLookup::Dev(dev) if dev.as_str() == "ex-ch1"));
                })
            } else {
                assert!(
                    matches!(name.as_ref(), "kernel.txt" | "nft-version.txt"),
                    "unclassified fixture {name}"
                );
                continue;
            };
            assert!(result.is_ok(), "{}: {result:?}", path.display());
        }
        assert_eq!(counts, [4, 4, 8, 4, 16, 32, 2, 10, 1, 2, 2]);
    }
    Ok(())
}

#[test]
fn m1_captured_fixtures() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ubuntu-24.04");
    for file in fs::read_dir(root)? {
        let path = file?.path();
        let name = path
            .file_name()
            .ok_or("missing filename")?
            .to_string_lossy();
        let out = substitute(fs::read_to_string(&path)?);
        if name.contains("ip-link") {
            parse_ip_link(&out)?;
        } else if name.contains("ip-addr") {
            parse_ip_addr(&out)?;
        } else if name == "ip-default.json" {
            parse_ip_route(&out)?;
        } else if name.contains("tc-qdisc") {
            parse_tc_qdisc(&out)?;
        } else if name.contains("tc-filter") {
            parse_tc_filter(&out)?;
        } else if name.contains("nft") && name.ends_with(".json") {
            parse_nft_ruleset(&out)?;
        } else if name == "wg-handshakes.txt" {
            parse_wg(WgField::LatestHandshakes, &out)?;
        } else if name == "wg-allowed-ips.txt" {
            parse_wg(WgField::AllowedIps, &out)?;
        }
    }
    Ok(())
}

fn fixture_links(name: &str, out: &str) -> Result<(), ParseError> {
    let links = parse_ip_link(out)?;
    let expected = if name.starts_with("scupper") {
        vec!["lo", "wg0", "ex-ch1"]
    } else {
        vec!["lo", "eth0"]
    };
    assert_eq!(
        links.iter().map(|l| l.ifname.as_str()).collect::<Vec<_>>(),
        expected
    );
    for link in links {
        assert!(link.flags.iter().any(|flag| flag == "UP"));
        assert_eq!(
            link.mtu,
            if matches!(link.ifname.as_str(), "wg0" | "ex-ch1") {
                1420
            } else if link.ifname == "lo" {
                65536
            } else {
                1500
            }
        );
        // Original captures predate -d. Re-captures must retain the actual kind;
        // the synthetic detailed-link regression also exercises both parsers.
        if out.contains("info_kind") && link.ifname != "lo" {
            assert_eq!(
                link.kind.as_deref(),
                Some(if link.ifname == "eth0" {
                    "veth"
                } else {
                    "wireguard"
                })
            );
        } else {
            assert_eq!(link.kind, None);
        }
    }
    Ok(())
}
fn fixture_addresses(name: &str, out: &str) -> Result<(), ParseError> {
    let entries = parse_ip_addr(out)?;
    let actual = entries
        .iter()
        .flat_map(|entry| {
            entry.addresses.iter().map(|addr| {
                (
                    entry.ifname.as_str(),
                    addr.local.to_string(),
                    addr.prefixlen,
                    addr.scope.as_str(),
                )
            })
        })
        .collect::<Vec<_>>();
    let expected = if name.contains("--6-") {
        vec![("lo", "::1".into(), 128, "host")]
    } else if name.starts_with("scupper") {
        vec![
            ("lo", "127.0.0.1".into(), 8, "host"),
            ("wg0", "10.99.0.1".into(), 24, "global"),
            ("ex-ch1", "10.2.0.2".into(), 32, "global"),
        ]
    } else {
        vec![
            ("lo", "127.0.0.1".into(), 8, "host"),
            ("eth0", "198.51.100.2".into(), 30, "global"),
        ]
    };
    assert_eq!(actual, expected);
    Ok(())
}
fn fixture_routes(name: &str, out: &str) -> Result<(), ParseError> {
    let routes = parse_ip_route(out)?;
    let all = name.ends_with("routes-all.json");
    let gateway = name.starts_with("scupper");
    let v6 = name.contains("--6-");
    let expected_len = match (gateway, v6, all) {
        (_, false, false) | (false, true, true) => 2,
        (true, false, true) => 8,
        (false, false, true) => 7,
        (true, true, false) => 1,
        (true, true, true) => 4,
        (false, true, false) => 0,
    };
    assert_eq!(routes.len(), expected_len);
    for route in &routes {
        assert!(route.from.is_none());
    }
    if gateway || !v6 {
        let default = &routes[0];
        assert_eq!(default.dst, RouteDestination::Default);
        assert_eq!(default.table, RoutingTable::Main);
        assert_eq!(
            default.dev.as_deref(),
            Some(if v6 {
                "lo"
            } else if gateway {
                "ex-ch1"
            } else {
                "eth0"
            })
        );
        assert_eq!(
            default.kind,
            if v6 {
                RouteKind::Unreachable
            } else {
                RouteKind::Unicast
            }
        );
        assert_eq!(default.metric, if v6 { Some(1024) } else { None });
        assert_eq!(
            default.gateway.map(|ip| ip.to_string()),
            if gateway {
                None
            } else {
                Some("198.51.100.1".into())
            }
        );
    }
    if all {
        assert!(routes.iter().any(|r| r.table == RoutingTable::Local
            && r.kind == RouteKind::Local
            && r.dev.as_deref() == Some("lo")));
    }
    if !v6 {
        assert_eq!(
            routes[1].dst,
            RouteDestination::Prefix(
                if gateway {
                    "10.99.0.0/24"
                } else {
                    "198.51.100.0/30"
                }
                .parse()
                .map_err(|_| ParseError::Topology("invalid test prefix"))?
            )
        );
        assert_eq!(
            routes[1].dev.as_deref(),
            Some(if gateway { "wg0" } else { "eth0" })
        );
    }
    Ok(())
}
fn fixture_wg(name: &str, field: WgField, out: &str) -> Result<(), ParseError> {
    let exit = name.contains("ex-ch1");
    let result = parse_wg(field, out)?;
    match result {
        WgOutput::PublicKey(public) => assert_eq!(
            public.map(|k| k.to_string()),
            Some(key(if exit { 2 } else { 1 }))
        ),
        WgOutput::ListenPort(port) => assert_eq!(port, if exit { 51821 } else { 51820 }),
        WgOutput::Peers(peers) => {
            assert_eq!(peers.len(), 1);
            let peer = &peers[0];
            assert_eq!(peer.public_key.to_string(), key(if exit { 3 } else { 4 }));
            match field {
                WgField::AllowedIps => assert_eq!(
                    peer.allowed_ips
                        .as_ref()
                        .map(|nets| nets.iter().map(ToString::to_string).collect::<Vec<_>>()),
                    Some(vec![if exit { "0.0.0.0/0" } else { "10.99.0.2/32" }.into()])
                ),
                WgField::Endpoints => assert_eq!(
                    peer.endpoint.map(|endpoint| endpoint.to_string()),
                    Some(
                        if exit {
                            "203.0.113.2:51820"
                        } else {
                            "192.0.2.2:51820"
                        }
                        .into()
                    )
                ),
                WgField::PersistentKeepalive => {
                    assert_eq!(peer.keepalive, Some(if exit { 25 } else { 0 }));
                }
                WgField::LatestHandshakes => assert!(peer.handshake.is_some()),
                WgField::Transfer => assert!(peer.received.is_some() && peer.transmitted.is_some()),
                _ => {}
            }
        }
    }
    Ok(())
}

#[test]
fn captured_rule_selectors_when_available() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/netns");
    for runner in ["ubuntu-22.04", "ubuntu-24.04"] {
        for family in ["v4", "v6"] {
            let path = root.join(runner).join(format!("rules-{family}.json"));
            // Skip until CI commits the captures. Once committed, their presence
            // makes these value assertions mandatory on every test run.
            if !path.exists() {
                continue;
            }
            let rules = parse_ip_rule(&fs::read_to_string(path)?)?;
            let lookup = |table| {
                rules
                    .iter()
                    .find(|rule| rule.table == Some(RoutingTable::Number(table)))
                    .ok_or("missing captured rule")
            };
            assert!(
                rules
                    .iter()
                    .any(|r| r.priority == 0 && r.table == Some(RoutingTable::Local))
            );
            assert!(
                rules
                    .iter()
                    .any(|r| r.priority == 32766 && r.table == Some(RoutingTable::Main))
            );
            if family == "v6" {
                assert_eq!(lookup(106)?.src, Some("fd00:99::/64".parse()?));
                continue;
            }
            assert!(
                rules
                    .iter()
                    .any(|r| r.priority == 32767 && r.table == Some(RoutingTable::Default))
            );
            assert_eq!(lookup(100)?.src, Some("10.99.0.0/24".parse()?));
            assert_eq!(lookup(101)?.dst, Some("192.0.2.0/24".parse()?));
            assert!(lookup(102)?.invert);
            assert_eq!(lookup(102)?.fwmark, Some(1));
            assert_eq!(lookup(103)?.uid, Some((1000, 2000)));
            assert_eq!(lookup(104)?.sport, Some((1000, 2000)));
            assert_eq!(lookup(105)?.dport, Some((53, 53)));
            assert_eq!(lookup(105)?.ipproto.as_deref(), Some("udp"));
            assert!(lookup(107)?.invert);
            assert_eq!(lookup(107)?.iif.as_deref(), Some("wg0"));
            assert_eq!(lookup(108)?.iif.as_deref(), Some("nosuchdev"));
            assert!(lookup(108)?.iif_detached);
            assert_eq!(lookup(109)?.sport, Some((1, 2)));
            assert_eq!(lookup(51820)?.iif.as_deref(), Some("wg0"));
            assert_eq!(lookup(51820)?.priority, 1000);
            assert!(rules.iter().any(|r| r.table == Some(RoutingTable::Main) && r.suppress_prefixlen == Some(0)));
            assert!(
                rules
                    .iter()
                    .any(|r| r.src.is_none() && r.action == RuleAction::Unreachable)
            );
        }
        let path = root.join(runner).join("routes-source-v6.json");
        if path.exists() {
            let routes = parse_ip_route(&fs::read_to_string(path)?)?;
            assert!(routes.iter().any(|r| r.dst == RouteDestination::Default
                && r.from == "2001:db8::/64".parse().ok()
                && r.dev.as_deref() == Some("wg0")));
        }
    }
    Ok(())
}

fn fixture_default_rules(name: &str, out: &str) -> Result<(), ParseError> {
    parse_ip_rule(out).map(|rules| {
        assert_eq!(
            rules.iter().map(|r| r.priority).collect::<Vec<_>>(),
            if name.contains("--4-") {
                vec![0, 32766, 32767]
            } else {
                vec![0, 32766]
            }
        );
        assert_eq!(rules[0].table, Some(RoutingTable::Local));
        assert_eq!(rules[1].table, Some(RoutingTable::Main));
        if rules.len() == 3 {
            assert_eq!(rules[2].table, Some(RoutingTable::Default));
        }
        assert!(rules.iter().all(|r| r.src.is_none()
            && r.dst.is_none()
            && !r.invert
            && r.action == RuleAction::Lookup));
    })
}
