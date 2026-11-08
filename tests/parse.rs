//! Captured output, validation and arbitrary-input coverage for command-output parsers.
//! Synthetic inputs cover malformed data and shapes absent from the lab captures.

use std::{error::Error, net::Ipv4Addr, time::Duration};

use proptest::prelude::*;
use scupper::{
    parse::{
        Handshake, HandshakeAge, ParseError, PeerHandshake, PeerKey, ROUTE_PROBE_DST, RouteLookup,
        RouteType, parse_latest_handshakes, parse_route_get, route_probe_argv,
        single_peer_handshake,
    },
    rules::{IfName, V1Config},
};

fn key(letter: char) -> String {
    format!("{}{letter}=", "A".repeat(42))
}

#[test]
fn latest_handshakes_ported() -> Result<(), Box<dyn Error>> {
    let key = key('A');
    assert_eq!(
        single_peer_handshake(&format!("{key}\t1757160000"))?,
        Handshake::At {
            unix_secs: 1_757_160_000
        }
    );
    assert_eq!(
        single_peer_handshake(&format!("{key}\t0"))?,
        Handshake::Never
    );
    for out in [
        String::new(),
        "garbage".to_owned(),
        "a\tb\tc".to_owned(),
        format!("{key}\tnotanumber"),
        "AbCd=\t1757160000".to_owned(),
    ] {
        assert!(single_peer_handshake(&out).is_err(), "accepted {out:?}");
    }
    assert!(PeerKey::new("AbCd=").is_err());
    Ok(())
}

#[test]
fn latest_handshakes_multi_peer() -> Result<(), Box<dyn Error>> {
    let first = key('A');
    let second = key('E');
    let expected = vec![
        PeerHandshake {
            peer: PeerKey::new(&first)?,
            handshake: Handshake::At { unix_secs: 123 },
        },
        PeerHandshake {
            peer: PeerKey::new(&second)?,
            handshake: Handshake::Never,
        },
    ];
    for newline in ["\n", "\r\n"] {
        let out = format!("{first}\t123{newline}{second} 0{newline}");
        assert_eq!(parse_latest_handshakes(&out)?, expected);
    }
    assert!(matches!(
        parse_latest_handshakes(&format!("{first}\t1\n{first}\t2\n")),
        Err(ParseError::DuplicatePeer { line: 2 })
    ));
    for seconds in ["-1", "+5", "18446744073709551616", "1.5", "１", "1\u{b}2"] {
        assert!(matches!(
            parse_latest_handshakes(&format!("{first}\t{seconds}")),
            Err(ParseError::InvalidHandshakeTimestamp { line: 1 })
        ));
    }
    assert_eq!(
        single_peer_handshake(&format!("{first} {}", u64::MAX))?,
        Handshake::At {
            unix_secs: u64::MAX
        }
    );
    assert_eq!(
        parse_latest_handshakes(&format!("\n \t{first}\t 000123 \t\r\n\n"))?,
        vec![expected[0].clone()]
    );
    for empty in ["", " \t\r\n\n", "\u{2003}"] {
        assert_eq!(parse_latest_handshakes(empty)?, Vec::<PeerHandshake>::new());
    }
    Ok(())
}

#[test]
fn single_peer_counts() {
    assert_eq!(single_peer_handshake(""), Err(ParseError::NoPeers));
    assert_eq!(
        single_peer_handshake(&format!("{}\t1\n{}\t2", key('A'), key('E'))),
        Err(ParseError::MultiplePeers { count: 2 })
    );
}

#[test]
fn peer_key_validation() -> Result<(), Box<dyn Error>> {
    for invalid in [
        format!("{}=", "A".repeat(42)),
        format!("{}=", "A".repeat(44)),
        "A".repeat(44),
        format!("{}==", "A".repeat(42)),
        key('B'),
        key('_'),
        format!("!{}=", "A".repeat(42)),
        format!("é{}=", "A".repeat(41)),
        format!("{}=\n", "A".repeat(43)),
    ] {
        assert!(matches!(
            PeerKey::new(&invalid),
            Err(ParseError::InvalidPeerKey { .. })
        ));
        assert!(invalid.parse::<PeerKey>().is_err());
    }
    for last in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".chars() {
        assert_eq!(
            PeerKey::new(&key(last)).is_ok(),
            "AEIMQUYcgkosw048".contains(last),
            "incorrect padding-bit validation for {last}"
        );
    }
    for valid in [
        key('A'),
        "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=".to_owned(),
        format!("{}8=", "+/".repeat(21)),
    ] {
        let parsed = PeerKey::new(&valid)?;
        assert_eq!(parsed.as_str(), valid);
        assert_eq!(parsed.to_string(), valid);
        assert_eq!(valid.parse::<PeerKey>()?, parsed);
    }
    Ok(())
}

#[test]
fn handshake_age_cases() {
    assert_eq!(Handshake::Never.age_at(100), HandshakeAge::Never);
    for (timestamp, now, expected) in [
        (70, 100, HandshakeAge::Age(Duration::from_secs(30))),
        (100, 100, HandshakeAge::Age(Duration::ZERO)),
        (105, 100, HandshakeAge::InFuture(Duration::from_secs(5))),
        (
            0,
            u64::MAX,
            HandshakeAge::Age(Duration::from_secs(u64::MAX)),
        ),
        (
            u64::MAX,
            0,
            HandshakeAge::InFuture(Duration::from_secs(u64::MAX)),
        ),
    ] {
        assert_eq!(
            Handshake::At {
                unix_secs: timestamp
            }
            .age_at(now),
            expected
        );
    }
}

#[test]
fn route_get_ported() -> Result<(), Box<dyn Error>> {
    for (out, name) in [
        (
            include_str!("fixtures/ubuntu-24.04/ip-policy-route.txt"),
            "proton0",
        ),
        (
            "1.1.1.1 from 10.99.0.2 via 192.0.2.1 dev eth0 \n    cache iif wg0",
            "eth0",
        ),
        ("\r\n \t\r\n1.1.1.1 dev wg0\r\n cache iif wg1\r\n", "wg0"),
    ] {
        assert_eq!(parse_route_get(out)?, RouteLookup::Dev(IfName::new(name)?));
    }
    for empty in ["", " \t\r\n"] {
        assert_eq!(parse_route_get(empty), Err(ParseError::EmptyRoute));
    }
    assert_eq!(
        parse_route_get("RTNETLINK answers: Network is unreachable"),
        Err(ParseError::InvalidRouteStart { line: 1 })
    );
    assert_eq!(
        parse_route_get("1.1.1.1 dev"),
        Err(ParseError::MissingRouteInterface { line: 1 })
    );
    Ok(())
}

macro_rules! route_type_test {
    ($test:ident, $route_type:literal, $expected:expr) => {
        #[test]
        fn $test() -> Result<(), Box<dyn Error>> {
            assert_eq!(parse_route_get($route_type)?, $expected);
            assert_eq!(
                parse_route_get(concat!(
                    $route_type,
                    " 192.0.2.1 from 198.51.100.2 dev wg0 table 51820 \n    cache iif wg0"
                ))?,
                $expected
            );
            Ok(())
        }
    };
}

route_type_test!(
    route_get_unreachable,
    "unreachable",
    RouteLookup::Unreachable
);
route_type_test!(route_get_blackhole, "blackhole", RouteLookup::Blackhole);
route_type_test!(route_get_prohibit, "prohibit", RouteLookup::Prohibit);
route_type_test!(route_get_throw, "throw", RouteLookup::Throw);
route_type_test!(route_get_local, "local", RouteLookup::Local);
route_type_test!(
    route_get_broadcast,
    "broadcast",
    RouteLookup::OtherType(RouteType::Broadcast)
);
route_type_test!(
    route_get_anycast,
    "anycast",
    RouteLookup::OtherType(RouteType::Anycast)
);
route_type_test!(
    route_get_multicast,
    "multicast",
    RouteLookup::OtherType(RouteType::Multicast)
);
route_type_test!(route_get_nat, "nat", RouteLookup::OtherType(RouteType::Nat));
route_type_test!(
    route_get_xresolve,
    "xresolve",
    RouteLookup::OtherType(RouteType::Xresolve)
);

#[test]
fn route_get_unicast() -> Result<(), Box<dyn Error>> {
    for destination in ["192.0.2.1", "2001:db8::1"] {
        for prefix in ["", "unicast "] {
            assert_eq!(
                parse_route_get(&format!("{prefix}{destination} dev proton0"))?,
                RouteLookup::Dev(IfName::new("proton0")?)
            );
        }
    }
    for out in [
        "unicast",
        "unicast dev proton0",
        "unicast invalid dev proton0",
    ] {
        assert_eq!(
            parse_route_get(out),
            Err(ParseError::InvalidRouteDestination { line: 1 })
        );
    }
    Ok(())
}

#[test]
fn route_get_rejects_unknown_prefixes() {
    for out in [
        "dev wg0",
        "unknown 192.0.2.1 dev wg0",
        "RTNETLINK answers: Network is unreachable dev wg0",
        "192.0.2.999 dev wg0",
        "2001:db8::gg dev wg0",
    ] {
        assert_eq!(
            parse_route_get(&format!("\n{out}")),
            Err(ParseError::InvalidRouteStart { line: 2 })
        );
    }
}

#[test]
fn route_get_rejects_ambiguous_devices() {
    for out in [
        "dev wg0 dev eth0",
        "192.0.2.1 dev wg0 dev eth0",
        "192.0.2.1 dev wg0 dev",
        "192.0.2.1 nexthop via 192.0.2.2 dev proton0 weight 1 nexthop via 192.0.2.3 dev eth0",
        "192.0.2.1 nexthop via 192.0.2.2 dev proton0",
        "local 192.0.2.1 dev lo dev eth0",
        "blackhole 192.0.2.1 nexthop",
    ] {
        assert_eq!(
            parse_route_get(&format!("\n{out}")),
            Err(ParseError::AmbiguousRouteDev { line: 2 })
        );
    }
}

#[test]
fn route_get_synthesized_printing_shapes() -> Result<(), Box<dyn Error>> {
    // These printing shapes were not captured by the lab; retain synthetic
    // inputs for nexthop IDs, explicit unicast, route attributes, and IPv6 gateways.
    for (out, expected) in [
        (
            "192.0.2.1 from 198.51.100.2 nhid 12 dev proton0 table 51820 uid 0 \n    cache iif wg0",
            RouteLookup::Dev(IfName::new("proton0")?),
        ),
        (
            "unicast 192.0.2.1 from 198.51.100.2 dev proton0 table 51820 proto boot scope global \n    cache iif wg0",
            RouteLookup::Dev(IfName::new("proton0")?),
        ),
        (
            "192.0.2.1 from 198.51.100.2 dev proton0 table 51820 src 203.0.113.2 mtu 1420 \n    cache <redirected> iif wg0",
            RouteLookup::Dev(IfName::new("proton0")?),
        ),
        (
            "192.0.2.1 from 198.51.100.2 via inet6 2001:db8::1 dev eth0 table 51820 \n    cache iif wg0",
            RouteLookup::Dev(IfName::new("eth0")?),
        ),
        (
            "local 192.0.2.1 from 198.51.100.2 dev lo table local \n    cache <local> iif wg0",
            RouteLookup::Local,
        ),
    ] {
        assert_eq!(parse_route_get(out)?, expected);
    }
    Ok(())
}

#[test]
fn route_get_route_types() -> Result<(), Box<dyn Error>> {
    for (name, expected) in [
        ("unreachable", RouteLookup::Unreachable),
        ("blackhole", RouteLookup::Blackhole),
        ("prohibit", RouteLookup::Prohibit),
        ("throw", RouteLookup::Throw),
        ("local", RouteLookup::Local),
    ] {
        assert_eq!(
            parse_route_get(&format!(
                "{name} 1.1.1.1 from 10.99.0.2 dev wg0 table 51820 \n    cache iif wg0"
            ))?,
            expected
        );
        assert_eq!(parse_route_get(name)?, expected);
    }
    assert_eq!(
        parse_route_get("local 1.1.1.1 dev lo ...")?,
        RouteLookup::Local
    );
    assert_eq!(
        parse_route_get("1.1.1.1 from 10.99.0.2\n cache dev proton0"),
        Err(ParseError::MissingRouteDev { line: 1 })
    );
    assert_eq!(
        parse_route_get("1.1.1.1 dev\n cache dev proton0"),
        Err(ParseError::MissingRouteInterface { line: 1 })
    );
    for name in ["-x", "wg\"0", "abcdefghijklmnop", "wg/0", "é"] {
        assert_eq!(
            parse_route_get(&format!("1.1.1.1 dev {name}"))?,
            RouteLookup::OtherDev
        );
    }
    Ok(())
}

#[test]
fn route_get_other_device_has_no_config_error() -> Result<(), Box<dyn Error>> {
    // Linux permits these names, while IfName restricts names for nftables quoting.
    for name in ["-x", "wg\"0", "é"] {
        assert!(IfName::new(name).is_err());
        assert_eq!(
            parse_route_get(&format!("192.0.2.1 dev {name}"))?,
            RouteLookup::OtherDev
        );
    }
    let error = ParseError::InvalidRouteInterface {
        line: 1,
        source: IfName::new("-x").err().ok_or("expected invalid name")?,
    };
    assert_eq!(
        error.to_string(),
        "route line 1: invalid device after 'dev'"
    );
    assert!(!error.to_string().contains("config:"));
    let source = error.source().ok_or("expected interface error source")?;
    assert!(source.to_string().starts_with("config:"));
    assert!(source.source().is_none());
    Ok(())
}

#[test]
fn route_probe_argv_shape() -> Result<(), Box<dyn Error>> {
    assert_eq!(ROUTE_PROBE_DST, Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(
        route_probe_argv(&V1Config::default()),
        ["route", "get", "1.1.1.1", "from", "10.99.0.2", "iif", "wg0"]
    );
    let cfg = V1Config {
        client_addr: Ipv4Addr::new(192, 0, 2, 42),
        client_iface: IfName::new("clients9")?,
        ..V1Config::default()
    };
    assert_eq!(
        route_probe_argv(&cfg),
        [
            "route",
            "get",
            "1.1.1.1",
            "from",
            "192.0.2.42",
            "iif",
            "clients9"
        ]
    );
    Ok(())
}

#[test]
fn error_lines_and_bounded_diagnostics() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        parse_latest_handshakes("\n \t\r\ngarbage"),
        Err(ParseError::InvalidHandshakeFields { line: 3 })
    );
    assert!(matches!(
        parse_latest_handshakes("\nAbCd=\t1"),
        Err(ParseError::InvalidHandshakeKey { line: 2, .. })
    ));
    assert_eq!(
        parse_latest_handshakes(&format!("\n{}\tnotanumber", key('A'))),
        Err(ParseError::InvalidHandshakeTimestamp { line: 2 })
    );
    assert_eq!(
        parse_route_get("\n\n1.1.1.1"),
        Err(ParseError::MissingRouteDev { line: 3 })
    );
    let untrusted = "界".repeat(10_000);
    for result in [
        PeerKey::new(&untrusted).map(|_| ()),
        parse_latest_handshakes(&format!("{untrusted}\t1")).map(|_| ()),
        parse_latest_handshakes(&format!("{}\t{untrusted}", key('A'))).map(|_| ()),
        parse_route_get(&format!("{untrusted} dev wg0")).map(|_| ()),
    ] {
        let error = result.err().ok_or("expected malformed-input error")?;
        let message = error.to_string();
        assert!(!message.contains('界'));
        assert!(message.chars().count() < 240);
    }
    assert_eq!(
        parse_route_get(&format!("192.0.2.1 dev {untrusted}"))?,
        RouteLookup::OtherDev
    );
    Ok(())
}

fn parser_token() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "dev",
            "via",
            "nexthop",
            "from",
            "table",
            "cache",
            "iif",
            "unicast",
            "local",
            "broadcast",
            "anycast",
            "multicast",
            "blackhole",
            "unreachable",
            "prohibit",
            "throw",
            "nat",
            "xresolve",
            "wg0",
            "proton0",
            "eth0",
            "-x",
            "wg\"0",
            "abcdefghijklmnop",
            "wg/0",
            "é",
            "192.0.2.1",
            "2001:db8::1",
            "192.0.2.999",
            "2001:db8::gg",
            "AbCd=",
            "0",
            "18446744073709551616",
            "\t",
            "\r",
            "\u{2003}",
            "\u{a0}",
        ])
        .prop_map(str::to_owned),
        "[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=",
        "[A-Za-z0-9+/]{42}[BDFH]=",
        "[0-9]{1,30}",
    ]
}

fn token_line() -> impl Strategy<Value = String> {
    prop::collection::vec(
        (
            parser_token(),
            prop::sample::select(vec![" ", "\t", "\r", "\u{2003}", "\u{a0}"]),
        ),
        0..40,
    )
    .prop_map(|fields| {
        fields
            .into_iter()
            .fold(String::new(), |mut line, (token, separator)| {
                line.push_str(&token);
                line.push_str(separator);
                line
            })
    })
}

fn token_output() -> impl Strategy<Value = String> {
    prop::collection::vec(token_line(), 0..8).prop_map(|lines| lines.join("\n"))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_parsers_never_panic(
        arbitrary in any::<String>(),
        line in token_line(),
        output in token_output(),
    ) {
        for out in [arbitrary, line, output] {
            let _ = parse_latest_handshakes(&out);
            let _ = single_peer_handshake(&out);
            let _ = parse_route_get(&out);
        }
    }

    #[test]
    fn prop_special_types_never_dev(
        route_type in prop::sample::select(vec![
            "local", "broadcast", "anycast", "multicast", "blackhole", "unreachable",
            "prohibit", "throw", "nat", "xresolve",
        ]),
        tail in token_line(),
    ) {
        // Include a valid device in every case so special-type precedence is exercised.
        let out = format!("{route_type} 192.0.2.1 dev proton0 {tail}");
        prop_assert!(!matches!(parse_route_get(&out), Ok(RouteLookup::Dev(_))));
    }

    #[test]
    fn prop_handshake_roundtrip(
        key in "[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=",
        seconds in prop_oneof![Just(0_u64), Just(u64::MAX), any::<u64>()],
    ) {
        let parsed = parse_latest_handshakes(&format!("{key}\t{seconds}\n"))?;
        let expected = if seconds == 0 {
            Handshake::Never
        } else {
            Handshake::At { unix_secs: seconds }
        };
        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(parsed[0].peer.as_str(), key);
        prop_assert_eq!(parsed[0].handshake, expected);
    }
}

#[test]
fn tc_json_baseline_and_hooks() -> Result<(), Box<dyn Error>> {
    use scupper::parse::{filter_has_hooks, qdisc_has_hooks};
    for out in [
        include_str!("fixtures/ubuntu-24.04/tc-qdisc-wg0.json"),
        include_str!("fixtures/ubuntu-24.04/tc-qdisc-proton0.json"),
        include_str!("fixtures/ubuntu-24.04/case-04-tc-qdisc-proton0.json"),
    ] {
        assert!(!qdisc_has_hooks(out)?, "{out}");
    }
    assert!(qdisc_has_hooks(include_str!(
        "fixtures/ubuntu-24.04/case-10-tc-qdisc-wg0.json"
    ))?);
    assert!(!qdisc_has_hooks(r#"[{"kind":"noop","root":true}]"#)?);
    for out in [
        "[]",
        r#"[{"kind":"noop"}]"#,
        r#"[{"kind":"noop","root":false}]"#,
        r#"[{"kind":"noop","root":true},{"kind":"noqueue","root":true}]"#,
        r#"[{"kind":"noqueue"}]"#,
        r#"[{"kind":"noqueue","root":false}]"#,
        r#"[{"kind":"fq_codel","root":true}]"#,
        r#"[{"kind":"ingress","parent":"ffff:fff1"}]"#,
        r#"[{"kind":"clsact","parent":"ffff:fff1"}]"#,
        r#"[{"kind":"noqueue","root":true},{"kind":"noqueue","root":true}]"#,
    ] {
        assert!(qdisc_has_hooks(out)?, "{out}");
    }
    for out in [
        "garbage",
        "{}",
        "[null]",
        "[{}]",
        r#"[{"kind":2}]"#,
        r#"[{"kind":"noqueue","root":1}]"#,
    ] {
        assert!(qdisc_has_hooks(out).is_err(), "{out}");
    }
    for out in [
        include_str!("fixtures/ubuntu-24.04/tc-filter-wg0.json"),
        include_str!("fixtures/ubuntu-24.04/tc-filter-proton0.json"),
    ] {
        assert!(!filter_has_hooks(out)?, "{out}");
    }
    assert!(filter_has_hooks(include_str!(
        "fixtures/ubuntu-24.04/case-10-tc-filter-wg0-ingress.json"
    ))?);
    for out in ["", "{}", "[null]"] {
        assert!(filter_has_hooks(out).is_err());
    }
    Ok(())
}

#[test]
fn topology_ip_json() -> Result<(), Box<dyn Error>> {
    use scupper::parse::{default_routes_use, link_names, local_addresses};
    assert_eq!(
        link_names(include_str!("fixtures/ubuntu-24.04/ip-link.json"))?,
        ["lo", "eth0", "wg0", "proton0"]
    );
    assert!(link_names("[{}]").is_err());
    let uplink = IfName::new("eth0")?;
    assert!(default_routes_use(
        include_str!("fixtures/ubuntu-24.04/ip-default.json"),
        &uplink
    )?);
    for out in ["[]", "[{}]", r#"[{"dev":"eth0"},{"dev":"eth1"}]"#] {
        assert!(!default_routes_use(out, &uplink)?);
    }
    assert!(default_routes_use(r#"[{"dev":false}]"#, &uplink).is_err());
    let addrs = local_addresses(include_str!("fixtures/ubuntu-24.04/ip-addr-eth0.json"))?;
    assert_eq!(
        addrs,
        [
            "172.31.0.2".parse::<std::net::IpAddr>()?,
            "fe80::300d:a6ff:fe5f:c596".parse()?
        ]
    );
    assert_eq!(
        local_addresses(r#"[{"addr_info":[]},{}]"#)?,
        Vec::<std::net::IpAddr>::new()
    );
    for out in [
        r#"[{"addr_info":{}}]"#,
        r#"[{"addr_info":[{}]}]"#,
        r#"[{"addr_info":[{"local":"bad"}]}]"#,
        r#"[{"addr_info":[{"local":2}]}]"#,
    ] {
        assert!(local_addresses(out).is_err());
    }
    for out in ["", "not JSON", "{}", "[42]"] {
        assert!(link_names(out).is_err());
        assert!(default_routes_use(out, &uplink).is_err());
        assert!(local_addresses(out).is_err());
    }
    Ok(())
}

#[test]
fn allowed_ips_ipv4_prefix_containment() -> Result<(), Box<dyn Error>> {
    use scupper::parse::allowed_ips_contain;
    let client = Ipv4Addr::new(10, 99, 0, 2);
    for (cidrs, expected) in [
        ("10.99.0.2/32", true),
        ("10.99.0.3/32", false),
        ("10.99.0.0/24", true),
        ("10.99.1.0/24", false),
        ("0.0.0.0/0", true),
        ("10.99.0.128/25", false),
        ("10.99.0.2/31", true),
        ("::/0", false),
        ("2001:db8::1/128 10.99.0.0/24", true),
        ("(none)", false),
    ] {
        assert_eq!(
            allowed_ips_contain(&format!("{}\t{cidrs}\n", key('A')), client)?,
            expected,
            "{cidrs}"
        );
    }
    assert!(!allowed_ips_contain("", client)?);
    assert!(allowed_ips_contain(
        &format!("{}\t(none)\n{}\t10.99.0.0/24", key('A'), key('E')),
        client
    )?);
    for cidr in [
        "10.0.0.0",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0.0/+1",
        "10.0.0.0/",
        "bad/24",
        "10.0.0.0/1/2",
        "::/129",
        "",
        "10.99.0.0/24 bad",
    ] {
        assert!(
            allowed_ips_contain(&format!("{}\t{cidr}", key('A')), client).is_err(),
            "{cidr}"
        );
    }
    assert!(allowed_ips_contain("invalid-key\t0.0.0.0/0", client).is_err());
    assert!(allowed_ips_contain(&format!("{} 0.0.0.0/0", key('A')), client).is_err());
    Ok(())
}

#[test]
fn link_flags_and_xdp_presence() -> Result<(), Box<dyn Error>> {
    use scupper::parse::links;
    let parsed = links(
        r#"[{"ifname":"wg0","flags":["POINTOPOINT","UP"],"xdp":null},{"ifname":"proton0","flags":["POINTOPOINT"]},{"ifname":"eth0"}]"#,
    )?;
    assert!(parsed[0].up);
    assert!(parsed[0].xdp);
    assert!(!parsed[1].up);
    assert!(!parsed[1].xdp);
    assert!(!parsed[2].up);
    for out in [
        r#"[{"ifname":"wg0","flags":null}]"#,
        r#"[{"ifname":"wg0","flags":[1]}]"#,
    ] {
        assert!(links(out).is_err());
    }
    Ok(())
}

#[test]
fn captured_wireguard_peer_and_allowed_ips() -> Result<(), Box<dyn Error>> {
    let peer_key = key('A');
    let handshakes =
        include_str!("fixtures/ubuntu-24.04/wg-handshakes.txt").replace("PUBKEY3", &peer_key);
    let expected = Handshake::At {
        unix_secs: 1_794_160_057,
    };
    assert_eq!(
        parse_latest_handshakes(&handshakes)?,
        vec![PeerHandshake {
            peer: PeerKey::new(&peer_key)?,
            handshake: expected,
        }]
    );
    assert_eq!(single_peer_handshake(&handshakes)?, expected);
    let allowed_ips =
        include_str!("fixtures/ubuntu-24.04/wg-allowed-ips.txt").replace("PUBKEY4", &peer_key);
    assert!(scupper::parse::allowed_ips_contain(
        &allowed_ips,
        Ipv4Addr::new(10, 99, 0, 2)
    )?);
    Ok(())
}

#[test]
fn captured_exit_link_and_address_states() -> Result<(), Box<dyn Error>> {
    use scupper::parse::{links, local_addresses};

    for (out, expected_up) in [
        (include_str!("fixtures/ubuntu-24.04/ip-link.json"), true),
        (
            include_str!("fixtures/ubuntu-24.04/case-04-ip-link.json"),
            false,
        ),
        (
            include_str!("fixtures/ubuntu-24.04/ip-addr-proton0.json"),
            true,
        ),
        (
            include_str!("fixtures/ubuntu-24.04/case-04-ip-addr-proton0.json"),
            false,
        ),
    ] {
        let parsed = links(out)?;
        let exit = parsed
            .iter()
            .find(|link| link.name == "proton0")
            .ok_or("captured proton0 missing")?;
        assert_eq!(exit.up, expected_up);
        assert!(!exit.xdp);
    }
    for out in [
        include_str!("fixtures/ubuntu-24.04/ip-addr-proton0.json"),
        include_str!("fixtures/ubuntu-24.04/case-04-ip-addr-proton0.json"),
    ] {
        assert_eq!(
            local_addresses(out)?,
            [std::net::IpAddr::from([10, 2, 0, 2])]
        );
    }
    Ok(())
}
