//! Byte-exact and structural checks for the pure M2 namespace renderers.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use scupper_core::{
    config::{
        ExitId, GatewayId, PublicKey, SiteConfig, ValidatedDevice, ValidatedSite, parse_site,
        validate,
    },
    render::{
        Family, RenderError, RouteTarget, Scope, SysctlFamily, SysctlKey, VersionStamp,
        desired_routes, desired_sysctls, render_netns, route_argv,
    },
    rules::IfName,
};

const FIXTURE: &str = include_str!("fixtures/site-m2.toml");
const GOLDEN: &str = include_str!("golden/netns-m2-one-exit.nft");
const STAMP: VersionStamp = VersionStamp {
    version: 43,
    sha256: [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ],
};

#[allow(clippy::unwrap_used)] // A malformed fixture must fail the test.
fn config() -> SiteConfig {
    parse_site(FIXTURE).unwrap()
}

#[allow(clippy::unwrap_used)] // An invalid fixture must fail the test.
fn site() -> ValidatedSite {
    validate(config()).unwrap()
}

fn gateway() -> GatewayId {
    GatewayId("gw1".into())
}

#[allow(clippy::unwrap_used)] // Missing chains or delimiters must fail the test.
fn chain<'a>(output: &'a str, name: &str) -> Vec<&'a str> {
    output
        .split_once(&format!("\tchain {name} {{\n"))
        .unwrap()
        .1
        .split_once("\n\t}")
        .unwrap()
        .0
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect()
}

// Keep the entire final statement, including reject arguments or named counters.
fn rule(line: &str) -> Option<(String, String)> {
    let tokens: Vec<_> = line.split_whitespace().collect();
    let start = tokens.iter().position(|token| {
        matches!(
            *token,
            "accept" | "drop" | "reject" | "masquerade" | "counter"
        )
    })?;
    Some((tokens[..start].join(" "), tokens[start..].join(" ")))
}

#[allow(clippy::unwrap_used)] // Malformed set declarations must fail the test.
fn sets(output: &str) -> BTreeMap<&str, Vec<String>> {
    let mut sets = BTreeMap::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("set "))
    {
        let name = line.split_whitespace().nth(1).unwrap();
        let elements = line
            .split_once("elements = { ")
            .map_or_else(Vec::new, |(_, rest)| {
                rest.split_once(" }")
                    .unwrap()
                    .0
                    .split(", ")
                    .map(str::to_owned)
                    .collect()
            });
        assert!(sets.insert(name, elements).is_none());
    }
    sets
}

#[test]
fn sysctl_keys_preserve_dotted_link_names() {
    for (key, path, notation) in [
        (
            SysctlKey {
                family: SysctlFamily::Ipv4,
                scope: Scope::Link(IfName::new("foo.100").unwrap()),
                name: "rp_filter",
            },
            "/proc/sys/net/ipv4/conf/foo.100/rp_filter",
            "net.ipv4.conf.foo/100.rp_filter",
        ),
        (
            SysctlKey {
                family: SysctlFamily::Ipv4,
                scope: Scope::Global,
                name: "ip_forward",
            },
            "/proc/sys/net/ipv4/ip_forward",
            "net.ipv4.ip_forward",
        ),
        (
            SysctlKey {
                family: SysctlFamily::Ipv6,
                scope: Scope::Default,
                name: "accept_ra",
            },
            "/proc/sys/net/ipv6/conf/default/accept_ra",
            "net.ipv6.conf.default.accept_ra",
        ),
        (
            SysctlKey {
                family: SysctlFamily::Netfilter,
                scope: Scope::Global,
                name: "nf_conntrack_tcp_loose",
            },
            "/proc/sys/net/netfilter/nf_conntrack_tcp_loose",
            "net.netfilter.nf_conntrack_tcp_loose",
        ),
    ] {
        assert_eq!(key.proc_path(), std::path::Path::new(path));
        assert_eq!(key.to_string(), notation);
    }
}

#[test]
fn netns_m2_matches_golden() {
    assert_eq!(render_netns(&site(), &gateway(), &STAMP).unwrap(), GOLDEN);
}

#[test]
fn unknown_gateway_cannot_render() {
    assert_eq!(
        render_netns(&site(), &GatewayId("missing".into()), &STAMP),
        Err(RenderError::UnknownGateway)
    );
}

#[test]
fn empty_sets_fail_closed_and_later_features_are_absent() {
    let mut cfg = config();
    cfg.devices.clear();
    let output = render_netns(&validate(cfg).unwrap(), &gateway(), &STAMP).unwrap();
    for declaration in [
        "set client_nets4 { type ipv4_addr; flags interval; }",
        "set client_nets6 { type ipv6_addr; flags interval; }",
        "set exit_ifaces_v6 { type ifname; }",
    ] {
        assert!(output.contains(declaration));
    }
    assert!(
        chain(&output, "antispoof")
            .contains(&"iifname @client_ifaces ip6 saddr != @client_nets6 drop")
    );
    for later_feature in [
        "dns_redirect",
        "nonglobal",
        "dport 53",
        "dport 853",
        "dport 7380",
    ] {
        assert!(!output.contains(later_feature));
    }
}

#[test]
fn route_arguments_match_design_table() {
    let site = site();
    let exit = site.gateway(&gateway()).unwrap().exits()[0]
        .ifname()
        .clone();
    for (family, target, expected) in [
        (
            Family::V4,
            RouteTarget::Exit(exit.clone()),
            vec!["route", "replace", "default", "dev", "ex-ch1"],
        ),
        (
            Family::V6,
            RouteTarget::Exit(exit),
            vec!["-6", "route", "replace", "default", "dev", "ex-ch1"],
        ),
        (
            Family::V4,
            RouteTarget::Unreachable,
            vec!["route", "replace", "unreachable", "default"],
        ),
        (
            Family::V6,
            RouteTarget::Unreachable,
            vec!["-6", "route", "replace", "unreachable", "default"],
        ),
    ] {
        let argv = route_argv(family, &target);
        assert!(
            !argv.iter().any(|s| s == "rule" || s == "from"),
            "product route plan must use only the main table"
        );
        assert_eq!(argv, expected);
    }
}

#[test]
fn route_selection_is_ipv4_only_and_fails_closed() {
    let site = site();
    let gw = gateway();
    let selected = ExitId("ch1".into());
    let unknown = ExitId("missing".into());
    let exit = site.gateway(&gw).unwrap().exits()[0].ifname().clone();
    for (gateway, selection, v4) in [
        (&gw, None, RouteTarget::Unreachable),
        (&gw, Some(&selected), RouteTarget::Exit(exit)),
        (&gw, Some(&unknown), RouteTarget::Unreachable),
        (
            &GatewayId("missing".into()),
            Some(&selected),
            RouteTarget::Unreachable,
        ),
    ] {
        assert_eq!(
            desired_routes(&site, gateway, selection),
            [(Family::V4, v4), (Family::V6, RouteTarget::Unreachable)]
        );
    }
}

#[test]
fn sysctls_write_forwarding_before_all_hardening_values() {
    // Include a foreign link: the supplied inventory, rather than just config,
    // determines which links need explicit rp_filter settings.
    let links: Vec<_> = ["wg0", "lo", "ex-ch1", "foreign0", "foo.100", "wg0"]
        .map(|name| IfName::new(name).unwrap())
        .into();
    for forwarding in [true, false] {
        let values = desired_sysctls(&links, forwarding);
        assert_eq!(
            values[..4]
                .iter()
                .map(|value| (value.key.to_string(), value.value.clone()))
                .collect::<Vec<_>>(),
            [
                "net.ipv4.ip_forward",
                "net.ipv6.conf.all.forwarding",
                "net.ipv4.conf.default.forwarding",
                "net.ipv6.conf.default.forwarding"
            ]
            .map(|key| (key.into(), u8::from(forwarding).to_string()))
        );
        let expected = [
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            "net.ipv4.conf.ex-ch1.rp_filter",
            "net.ipv4.conf.foo/100.rp_filter",
            "net.ipv4.conf.foreign0.rp_filter",
            "net.ipv4.conf.lo.rp_filter",
            "net.ipv4.conf.wg0.rp_filter",
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv4.conf.default.accept_redirects",
            "net.ipv4.conf.default.send_redirects",
            "net.ipv4.conf.default.accept_source_route",
            "net.ipv4.conf.ex-ch1.accept_redirects",
            "net.ipv4.conf.ex-ch1.send_redirects",
            "net.ipv4.conf.ex-ch1.accept_source_route",
            "net.ipv4.conf.foo/100.accept_redirects",
            "net.ipv4.conf.foo/100.send_redirects",
            "net.ipv4.conf.foo/100.accept_source_route",
            "net.ipv4.conf.foreign0.accept_redirects",
            "net.ipv4.conf.foreign0.send_redirects",
            "net.ipv4.conf.foreign0.accept_source_route",
            "net.ipv4.conf.lo.accept_redirects",
            "net.ipv4.conf.lo.send_redirects",
            "net.ipv4.conf.lo.accept_source_route",
            "net.ipv4.conf.wg0.accept_redirects",
            "net.ipv4.conf.wg0.send_redirects",
            "net.ipv4.conf.wg0.accept_source_route",
            "net.ipv6.conf.all.accept_ra",
            "net.ipv6.conf.all.accept_redirects",
            "net.ipv6.conf.all.autoconf",
            "net.ipv6.conf.default.accept_ra",
            "net.ipv6.conf.default.accept_redirects",
            "net.ipv6.conf.default.autoconf",
            "net.ipv4.conf.all.proxy_arp",
            "net.ipv6.conf.all.proxy_ndp",
            "net.ipv4.conf.all.route_localnet",
            "net.netfilter.nf_conntrack_tcp_loose",
        ];
        assert_eq!(
            values[4..]
                .iter()
                .map(|value| value.key.to_string())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(values[4..].iter().all(|value| value.value == "0"));
        assert_eq!(
            values
                .iter()
                .map(|value| value.key.proc_path())
                .collect::<BTreeSet<_>>()
                .len(),
            values.len()
        );
        let mut reversed = links.clone();
        reversed.reverse();
        assert_eq!(values, desired_sysctls(&reversed, forwarding));
    }
    let empty = desired_sysctls(&[], false);
    assert_eq!(empty.len(), 22);
    assert!(empty.iter().all(|value| value.value == "0"));
}

// Distinct synthetic public keys: 31 zero bytes followed by the seed byte.
fn public_key(seed: u8) -> PublicKey {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    PublicKey(format!(
        "{}{}{}=",
        "A".repeat(41),
        char::from(ALPHABET[usize::from(seed >> 2)]),
        char::from(ALPHABET[usize::from((seed & 3) << 4)])
    ))
}

#[allow(clippy::unwrap_used)] // Every generated config starts from the fixture gateway.
fn configs() -> impl Strategy<Value = SiteConfig> {
    (
        proptest::collection::btree_set(2_u8..254, 1..=8),
        32_u8..=254,
        any::<u8>(),
        "ex-[a-z0-9]{1,12}",
        "wg[a-z0-9]{1,10}",
        "wan[a-z0-9]{1,8}",
    )
        .prop_map(|(addresses, subnet, octet, exit, client, uplink)| {
            let mut cfg = config();
            let gw = cfg.gateways.get_mut(&gateway()).unwrap();
            gw.client_tunnel.ifname = client;
            gw.client_tunnel.address4 = format!("10.{subnet}.{octet}.1/24");
            gw.exits[0].ifname = exit;
            gw.uplinks = vec![uplink];
            let peer = cfg.devices["mac"].clone();
            cfg.devices.clear();
            for host in addresses {
                let mut device = peer.clone();
                device.address4 = format!("10.{subnet}.{octet}.{host}/32");
                device.public_key = public_key(host);
                // ID ordering deliberately differs from address ordering.
                cfg.devices.insert(format!("dev{}", 255 - host), device);
            }
            cfg
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn namespace_rules_preserve_allowed_shapes(cfg in configs()) {
        let site = validate(cfg).unwrap();
        let output = render_netns(&site, &gateway(), &STAMP).unwrap();
        prop_assert_eq!(&output, &render_netns(&site, &gateway(), &STAMP).unwrap());
        let gw = site.gateway(&gateway()).unwrap();
        for uplink in gw.uplinks() {
            prop_assert!(!output.contains(uplink.as_str()));
        }
        prop_assert!(!output.contains(&gw.endpoint().ip().to_string()));
        for line in output.lines().filter(|line| !line.trim().starts_with('#')) {
            let tokens: Vec<_> = line.split_whitespace().collect();
            for pair in tokens.windows(2) {
                if matches!(pair[0], "iif" | "oif") {
                    prop_assert_eq!(pair[1], "\"lo\"");
                }
            }
        }
        for name in ["input", "forward", "output"] {
            let expected = format!("type filter hook {name} priority filter; policy drop;");
            prop_assert!(chain(&output, name).contains(&expected.as_str()));
        }
        let chain_names: Vec<_> = output.lines().map(str::trim)
            .filter_map(|line| line.strip_prefix("chain "))
            .map(|line| line.strip_suffix(" {").unwrap()).collect();
        prop_assert_eq!(&chain_names, &["antispoof", "input", "forward", "postrouting", "output"]);
        for name in chain_names {
            for line in chain(&output, name).into_iter().filter(|line| !line.starts_with("type ")) {
                let tokens: Vec<_> = line.split_whitespace().collect();
                prop_assert!(!tokens.iter().any(|token| matches!(*token, "jump" | "goto" | "return")));
                let (matches, verdict) = rule(line).unwrap();
                prop_assert!(["accept", "drop", "reject with tcp reset", "masquerade", "counter name \"fwd_dropped\" drop"].contains(&verdict.as_str()));
                if verdict == "accept" {
                    let allowed: &[&str] = match name {
                        "input" => &[
                            "iif \"lo\"",
                            "ct state established,related",
                            "iifname @client_ifaces icmp type echo-request limit rate 10/second",
                            "iifname @client_ifaces icmpv6 type echo-request limit rate 10/second",
                            "iifname @client_ifaces icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert }",
                        ],
                        "forward" => &[
                            "iifname @client_ifaces meta nfproto ipv4 oifname @exit_ifaces",
                            "iifname @client_ifaces meta nfproto ipv6 oifname @exit_ifaces_v6",
                            "iifname @exit_ifaces oifname @client_ifaces ct state established,related",
                        ],
                        "output" => &["oif \"lo\"", "oifname @client_ifaces", "oifname @exit_ifaces"],
                        _ => &[],
                    };
                    prop_assert!(allowed.contains(&matches.as_str()));
                }
            }
        }
        let antispoof = chain(&output, "antispoof");
        prop_assert_eq!(antispoof.len(), 5); // Hook declaration and exactly four rules.
        prop_assert_eq!(antispoof, chain(GOLDEN, "antispoof"));
        let forward = chain(&output, "forward");
        let accepts: Vec<_> = forward.iter().copied()
            .filter(|line| rule(line).is_some_and(|(_, verdict)| verdict == "accept")).collect();
        prop_assert_eq!(accepts, [
            "iifname @client_ifaces meta nfproto ipv4 oifname @exit_ifaces accept",
            "iifname @client_ifaces meta nfproto ipv6 oifname @exit_ifaces_v6 accept",
            "iifname @exit_ifaces oifname @client_ifaces ct state established,related accept",
        ]);
        prop_assert_eq!(chain(&output, "forward").last().copied(), Some("counter name \"fwd_dropped\" drop"));
        let masquerades: Vec<_> = output.lines().map(str::trim).filter(|line| line.contains("masquerade")).collect();
        prop_assert_eq!(masquerades, ["oifname @exit_ifaces masquerade"]);

        let mut addresses: Vec<_> = site.devices().values()
            .filter(|device| device.gateways().contains(&gateway()))
            .map(ValidatedDevice::address4).collect();
        addresses.sort_by_key(|net| (net.network(), net.prefix_len()));
        let mut exits: Vec<_> = gw.exits().iter().map(|exit| format!("\"{}\"", exit.ifname())).collect();
        exits.sort();
        let expected = BTreeMap::from([
            ("client_ifaces", vec![format!("\"{}\"", gw.client_tunnel().ifname())]),
            ("exit_ifaces", exits),
            ("exit_ifaces_v6", vec![]),
            ("client_nets4", addresses.iter().map(ToString::to_string).collect()),
            ("client_nets6", vec![]),
        ]);
        prop_assert_eq!(sets(&output), expected);
    }

    #[test]
    fn device_order_in_document_does_not_change_rules(cfg in configs()) {
        // Reorder the actual TOML tables: SiteConfig's BTreeMap already erases
        // insertion order, so merely reversing inserts would not exercise this.
        let mut base = cfg;
        let devices = std::mem::take(&mut base.devices);
        let base_text = toml::to_string(&base).unwrap();
        let mut documents = [base_text.clone(), base_text];
        let device_texts: Vec<_> = devices.into_iter().map(|(id, device)| {
            // Serialize only the devices map to append independent TOML tables.
            toml::to_string(&BTreeMap::from([("devices", BTreeMap::from([(id, device)]))])).unwrap()
        }).collect();
        for text in &device_texts {
            documents[0].push_str(text);
        }
        for text in device_texts.iter().rev() {
            documents[1].push_str(text);
        }
        let outputs = documents.map(|text| {
            let site = validate(parse_site(&text).unwrap()).unwrap();
            render_netns(&site, &gateway(), &STAMP).unwrap()
        });
        prop_assert_eq!(&outputs[0], &outputs[1]);
    }
}
