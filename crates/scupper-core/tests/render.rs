//! Byte-exact and structural checks for the pure M2 namespace renderers.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use scupper_core::{
    config::{ExitId, GatewayId, PublicKey, SiteConfig, ValidatedSite, parse_site, validate},
    render::{
        Family, RenderError, RouteTarget, Sysctl, VersionStamp, desired_routes, desired_sysctls,
        render_netns, route_argv,
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
        assert_eq!(route_argv(family, &target), expected);
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
    let site = site();
    // Include a foreign link: the supplied inventory, rather than just config,
    // determines which links need explicit rp_filter settings.
    let links: Vec<_> = ["wg0", "lo", "ex-ch1", "foreign0", "wg0"]
        .map(|name| IfName::new(name).unwrap())
        .into();
    for forwarding in [true, false] {
        let values = desired_sysctls(&site, &gateway(), &links, forwarding);
        assert_eq!(
            values[..2],
            [
                Sysctl {
                    key: "net.ipv4.ip_forward".into(),
                    value: u8::from(forwarding).to_string(),
                },
                Sysctl {
                    key: "net.ipv6.conf.all.forwarding".into(),
                    value: u8::from(forwarding).to_string(),
                },
            ]
        );
        let expected = [
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            "net.ipv4.conf.ex-ch1.rp_filter",
            "net.ipv4.conf.foreign0.rp_filter",
            "net.ipv4.conf.lo.rp_filter",
            "net.ipv4.conf.wg0.rp_filter",
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv4.conf.default.accept_redirects",
            "net.ipv4.conf.default.send_redirects",
            "net.ipv4.conf.default.accept_source_route",
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
            values[2..]
                .iter()
                .map(|value| value.key.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(values[2..].iter().all(|value| value.value == "0"));
        assert_eq!(
            values
                .iter()
                .map(|value| &value.key)
                .collect::<BTreeSet<_>>()
                .len(),
            values.len()
        );
        let mut reversed = links.clone();
        reversed.reverse();
        assert_eq!(
            values,
            desired_sysctls(&site, &gateway(), &reversed, forwarding)
        );
    }
    let empty = desired_sysctls(&site, &gateway(), &[], false);
    assert_eq!(empty.len(), 20);
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
        let forward = chain(&output, "forward");
        let accepts: Vec<_> = forward.iter().copied().filter(|line| line.ends_with(" accept")).collect();
        prop_assert_eq!(accepts, [
            "iifname @client_ifaces meta nfproto ipv4 oifname @exit_ifaces accept",
            "iifname @client_ifaces meta nfproto ipv6 oifname @exit_ifaces_v6 accept",
            "iifname @exit_ifaces oifname @client_ifaces ct state established,related accept",
        ]);
        prop_assert_eq!(forward.last().copied(), Some("counter name \"fwd_dropped\" drop"));
        let masquerades: Vec<_> = output.lines().map(str::trim).filter(|line| line.contains("masquerade")).collect();
        prop_assert_eq!(masquerades, ["oifname @exit_ifaces masquerade"]);

        let nets = output.lines().find(|line| line.contains("set client_nets4 ")).unwrap();
        let addresses: Vec<_> = nets.split_once("elements = { ").unwrap().1.split_once(" }").unwrap().0.split(", ").collect();
        let sorted: BTreeSet<_> = addresses.iter().copied().collect();
        prop_assert_eq!(&addresses, &sorted.into_iter().collect::<Vec<_>>());
        prop_assert_eq!(addresses.len(), site.devices().len());
        for device in site.devices().values() {
            prop_assert!(addresses.contains(&device.address4().to_string().as_str()));
        }
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
