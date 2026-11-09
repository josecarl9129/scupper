//! Captured and adversarial coverage for the M2 observation boundary.

use proptest::prelude::*;
use scupper_core::parse::*;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

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
#[test]
fn routing_shapes_and_defaults() -> Result<(), Box<dyn Error>> {
    let routes = parse_ip_route(
        r#"[{"type":"unreachable","dst":"default","extra":{}},{"type":"blackhole","dst":"2001:db8::/32","table":255,"metric":0},{"type":"local","dst":"127.0.0.1","dev":"lo","table":"local"}]"#,
    )?;
    assert_eq!(routes[0].kind, RouteKind::Unreachable);
    assert_eq!(routes[0].dst, RouteDestination::Default);
    assert_eq!(routes[0].table, RoutingTable::Main);
    assert_eq!(routes[1].kind, RouteKind::Blackhole);
    assert_eq!(routes[1].table, RoutingTable::Local);
    assert_eq!(routes[2].kind, RouteKind::Local);
    let rules = parse_ip_rule(
        r#"[{"priority":10,"src":"2001:db8::","srclen":64,"dst":"::","dstlen":0,"table":123,"iif":"wg0","fwmark":"0x42","fwmask":"0xff","not":null},{"priority":20,"action":"blackhole"}]"#,
    )?;
    assert_eq!(rules[0].fwmark, Some(66));
    assert_eq!(rules[0].fwmask, Some(255));
    assert!(rules[0].invert);
    assert_eq!(rules[0].table, Some(RoutingTable::Number(123)));
    assert_eq!(rules[1].action, RuleAction::Blackhole);
    for out in [
        r#"[{"dst":"default","type":"unknown"}]"#,
        r#"[{"dst":"bad"}]"#,
        r#"[{"dst":"default","nexthops":[]}]"#,
        r#"[{"dst":"default","dev":null}]"#,
        r#"[{"dst":"default","table":{}}]"#,
        r#"[{"dst":"default","metric":-1}]"#,
    ] {
        assert!(parse_ip_route(out).is_err(), "{out}");
    }
    for out in [
        "[{}]",
        r#"[{"priority":0,"table":"main","src":42}]"#,
        r#"[{"priority":0,"table":"main","suppress_prefixlength":0}]"#,
        r#"[{"priority":0,"action":"unknown"}]"#,
    ] {
        assert!(parse_ip_rule(out).is_err(), "{out}");
    }
    for kind in [
        "unicast",
        "unreachable",
        "blackhole",
        "local",
        "broadcast",
        "multicast",
        "anycast",
        "prohibit",
        "throw",
        "nat",
        "xresolve",
    ] {
        parse_ip_route(&format!(r#"[{{"dst":"default","type":"{kind}"}}]"#))?;
    }
    Ok(())
}

#[test]
fn wireguard_empty_none_and_numeric_edges() -> Result<(), Box<dyn Error>> {
    let key = key(0);
    for field in FIELDS
        .into_iter()
        .filter(|f| !matches!(f, WgField::PublicKey | WgField::ListenPort))
    {
        assert_eq!(parse_wg(field, "")?, WgOutput::Peers(vec![]));
        assert!(parse_wg(field, "garbage").is_err());
    }
    assert_eq!(parse_wg_public_key("(none)\n")?, None);
    assert_eq!(parse_wg_listen_port("65535\n")?, 65535);
    for text in ["-1", "+1", "65536", "1 2", "", "1\n2"] {
        assert!(parse_wg_listen_port(text).is_err());
    }
    let WgOutput::Peers(peers) = parse_wg(WgField::AllowedIps, &format!("{key}\t(none)\n"))? else {
        return Err("wrong output".into());
    };
    assert_eq!(peers[0].allowed_ips, Some(vec![]));
    for (field, value) in [
        (WgField::Endpoints, "(none)"),
        (WgField::Endpoints, "[2001:db8::1]:51820"),
        (WgField::PersistentKeepalive, "off"),
        (WgField::PersistentKeepalive, "65535"),
        (WgField::Transfer, "0\t18446744073709551615"),
        (WgField::AllowedIps, "0.0.0.0/0 ::/0"),
    ] {
        parse_wg(field, &format!("{key}\t{value}"))?;
    }
    for (field, value) in [
        (WgField::Endpoints, "host.example:51820"),
        (WgField::PersistentKeepalive, "65536"),
        (WgField::Transfer, "1\t18446744073709551616"),
        (WgField::AllowedIps, "(none) ::/0"),
        (WgField::AllowedIps, "0.0.0.0/33"),
        (WgField::AllowedIps, ""),
    ] {
        assert!(
            parse_wg(field, &format!("{key}\t{value}")).is_err(),
            "{field:?}"
        );
    }
    for field in [
        WgField::Peers,
        WgField::Endpoints,
        WgField::AllowedIps,
        WgField::PersistentKeepalive,
        WgField::Transfer,
        WgField::LatestHandshakes,
    ] {
        let value = match field {
            WgField::Peers => key.clone(),
            WgField::Transfer => format!("{key}\t0\t0"),
            WgField::LatestHandshakes => format!("{key}\t0"),
            _ => format!("{key}\t(none)"),
        };
        assert!(parse_wg(field, &format!("{value}\n{value}")).is_err());
    }
    Ok(())
}

#[test]
fn recognized_field_shapes() -> Result<(), Box<dyn Error>> {
    for out in [
        r#"[{"ifindex":1,"ifname":"lo","mtu":1,"flags":null}]"#,
        r#"[{"ifindex":1,"ifname":"lo","mtu":1,"linkinfo":42}]"#,
    ] {
        assert!(parse_ip_link(out).is_err());
    }
    for out in [
        r#"[{"ifindex":1,"ifname":"lo","addr_info":[{"local":"::1","family":"inet","prefixlen":32,"scope":"host"}]}]"#,
        r#"[{"ifindex":1,"ifname":"lo","addr_info":[{"local":"::1","family":"inet6","prefixlen":129,"scope":"host"}]}]"#,
    ] {
        assert!(parse_ip_addr(out).is_err());
    }
    for out in [
        r#"[{"kind":1}]"#,
        r#"[{"kind":"noqueue","root":1}]"#,
        r#"[{"kind":"bpf","options":[]}]"#,
    ] {
        assert!(parse_tc_qdisc(out).is_err());
        assert!(parse_tc_filter(out).is_err());
    }
    for out in ["", "1\n2", "name = 1", "+1", "9223372036854775808"] {
        assert!(parse_sysctl(out).is_err());
    }
    assert_eq!(parse_sysctl(" -9223372036854775808\n")?, i64::MIN);
    let value = parse_nft_ruleset(r#"{"nftables":[{"table":{"name":"scupper","handle":12}}]}"#)?;
    assert!(value["nftables"][0]["table"].get("handle").is_none());
    Ok(())
}

#[test]
fn udp_addresses_and_validation() -> Result<(), Box<dyn Error>> {
    let header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    let record = |address| {
        format!(
            "{header}0: {address}:CA6C {address}:0000 07 00000000:00000000 00:00000000 00000000 0 0 123 2 0 0\n"
        )
    };
    let v4 = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
    let sockets = parse_proc_net_udp(&record(format!("{v4:08X}")))?;
    assert_eq!(sockets[0].local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(sockets[0].local.port(), 51820);
    assert_eq!(sockets[0].inode, 123);
    for ip in [
        Ipv6Addr::LOCALHOST,
        "2001:db8:102:304:506:708:90a:b0c".parse()?,
    ] {
        use std::fmt::Write;
        let mut text = String::new();
        for bytes in ip.octets().as_chunks::<4>().0 {
            write!(&mut text, "{:08X}", u32::from_ne_bytes(*bytes))?;
        }
        assert_eq!(
            parse_proc_net_udp6(&record(text))?[0].local.ip(),
            IpAddr::V6(ip)
        );
    }
    assert_eq!(parse_proc_net_udp(header)?, []);
    for out in [
        "",
        "garbage",
        &record("界界界界".into()),
        &record("0000000G".into()),
        &format!("{header}0: 00000000:0000"),
    ] {
        assert!(parse_proc_net_udp(out).is_err());
        assert!(parse_proc_net_udp6(out).is_err());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn every_parser_never_panics(out in "[\\s\\S]{0,4096}") {
        let _ = parse_ip_link(&out); let _ = parse_ip_addr(&out); let _ = parse_ip_route(&out); let _ = parse_ip_rule(&out);
        let _ = parse_tc_qdisc(&out); let _ = parse_tc_filter(&out); let _ = parse_sysctl(&out); let _ = parse_nft_ruleset(&out);
        let _ = parse_proc_net_udp(&out); let _ = parse_proc_net_udp6(&out);
        for field in FIELDS { let _ = parse_wg(field, &out); }
        let _ = links(&out); let _ = link_names(&out); let _ = local_addresses(&out);
        let _ = qdisc_has_hooks(&out); let _ = filter_has_hooks(&out); let _ = parse_route_get(&out);
        let _ = parse_latest_handshakes(&out); let _ = single_peer_handshake(&out);
        if let Ok(ifname) = scupper_core::rules::IfName::new("eth0") { let _ = default_routes_use(&out, &ifname); }
        let _ = allowed_ips_contain(&out, Ipv4Addr::LOCALHOST); let _ = PeerKey::new(&out);
    }
}

#[test]
fn real_rule_selectors_are_retained() -> Result<(), Box<dyn Error>> {
    let rules = parse_ip_rule(
        r#"[
        {"priority":100,"src":"10.99.0.0","srclen":24,"table":"100"},
        {"priority":101,"src":"all","dst":"192.0.2.0","dstlen":24,"table":"101"},
        {"priority":102,"src":"all","not":null,"fwmark":"0x1","fwmask":"0xff","table":"102"},
        {"priority":103,"src":"all","uid_start":1000,"uid_end":2000,"table":"103"},
        {"priority":104,"src":"all","sport_start":1000,"sport_end":2000,"table":"104"},
        {"priority":105,"src":"all","dport":53,"ipproto":"udp","table":"105"},
        {"priority":1000,"src":"all","iif":"wg0","table":"51820"},
        {"priority":1100,"src":"all","table":"main","suppress_prefixlen":0},
        {"priority":1101,"src":"all","action":"unreachable"},
        {"priority":1102,"src":"fd00:99::","srclen":64,"table":"106"},
        {"priority":1103,"src":"all","iif":"gone","iif_detached":null,"oif":"gone2","oif_detached":null,"table":"107"},
        {"priority":1104,"src":"all","l3mdev":null},
        {"priority":1105,"src":"all","goto":1200,"unresolved":null},
        {"priority":1106,"src":"all","nop":null},
        {"priority":1107,"src":"all","table":"main","tos":"0x10","protocol":"boot","flow_from":"1","flow_to":"2"}
    ]"#,
    )?;
    assert_eq!(rules.len(), 15);
    assert_eq!(rules[0].src, Some("10.99.0.0/24".parse()?));
    assert_eq!(rules[1].dst, Some("192.0.2.0/24".parse()?));
    assert!(rules[2].invert);
    assert_eq!((rules[2].fwmark, rules[2].fwmask), (Some(1), Some(255)));
    assert_eq!(rules[3].uid, Some((1000, 2000)));
    assert_eq!(rules[4].sport, Some((1000, 2000)));
    assert_eq!(rules[5].dport, Some((53, 53)));
    assert_eq!(rules[5].ipproto.as_deref(), Some("udp"));
    assert_eq!(rules[6].iif.as_deref(), Some("wg0"));
    assert_eq!(rules[6].table, Some(RoutingTable::Number(51820)));
    assert_eq!(rules[7].suppress_prefixlen, Some(0));
    assert_eq!(rules[8].action, RuleAction::Unreachable);
    assert_eq!(rules[9].src, Some("fd00:99::/64".parse()?));
    assert!(rules[10].iif_detached && rules[10].oif_detached);
    assert!(rules[11].l3mdev);
    assert_eq!(rules[12].action, RuleAction::Goto);
    assert_eq!(rules[12].goto.as_deref(), Some("1200"));
    assert!(rules[12].unresolved);
    assert_eq!(rules[13].action, RuleAction::Nop);
    assert_eq!(rules[14].tos.as_deref(), Some("0x10"));
    assert_eq!(rules[14].protocol.as_deref(), Some("boot"));
    assert_eq!(rules[14].flow_from.as_deref(), Some("1"));
    assert_eq!(rules[14].flow_to.as_deref(), Some("2"));
    let rule = parse_ip_rule(
        r#"[{"priority":1,"table":"main","src":"2001:db8::1","dst":"2001:db8:1::","dstlen":64,"sport":80,"dport_start":20,"dport_end":21,"ipproto":"tcp","dsfield":"0x04","flowid":"1:2","realms":"1/2"}]"#,
    )?;
    assert_eq!(rule[0].src, Some("2001:db8::1/128".parse()?));
    assert_eq!(rule[0].dst, Some("2001:db8:1::/64".parse()?));
    assert_eq!(rule[0].sport, Some((80, 80)));
    assert_eq!(rule[0].dport, Some((20, 21)));
    assert_eq!(rule[0].dsfield.as_deref(), Some("0x04"));
    assert_eq!(rule[0].flowid.as_deref(), Some("1:2"));
    assert_eq!(rule[0].realms.as_deref(), Some("1/2"));
    Ok(())
}

#[test]
fn unknown_or_malformed_rule_selectors_fail_closed() {
    for extra in [
        r#""new_selector":null"#,
        r#""suppress_prefixlength":0"#,
        r#""uidrange":"0-0""#,
        r#""tun_id":1"#,
        r#""suppress_ifgroup":"1""#,
        r#""src":"10.99.0.0/24""#,
        r#""src":"10.99.0.0","srclen":33"#,
        r#""src":"fd00::","srclen":129"#,
        r#""srclen":24"#,
        r#""src":"all","srclen":0"#,
        r#""dstlen":0"#,
        r#""uid_start":0"#,
        r#""uid_end":1"#,
        r#""uid_start":2,"uid_end":1"#,
        r#""sport_start":1"#,
        r#""dport_end":1"#,
        r#""sport":65536"#,
        r#""dport_start":53,"dport_end":54,"dport":53"#,
        r#""suppress_prefixlen":129"#,
        r#""iif_detached":null"#,
        r#""oif_detached":null"#,
        r#""l3mdev":false"#,
        r#""unresolved":null"#,
        r#""goto":-1"#,
        r#""goto":"bad""#,
        r#""goto":1,"nop":null"#,
        r#""goto":1,"action":"unreachable""#,
    ] {
        let out = format!(r#"[{{"priority":1,"table":"main",{extra}}}]"#);
        assert!(parse_ip_rule(&out).is_err(), "{out}");
    }
}

#[test]
fn routes_retain_source_constraints_and_links_retain_kind() -> Result<(), Box<dyn Error>> {
    for source in [
        r#""from":"2001:db8::/64""#,
        r#""src":"2001:db8::","srclen":64"#,
    ] {
        let out = format!(r#"[{{"dst":"default","dev":"wg0",{source}}}]"#);
        assert_eq!(
            parse_ip_route(&out)?[0].from,
            Some("2001:db8::/64".parse()?)
        );
    }
    assert!(
        parse_ip_route(
            r#"[{"dst":"default","src":"2001:db8::","srclen":64,"from":"2001:db8::/64"}]"#
        )
        .is_err()
    );
    let out = r#"[{"ifindex":2,"ifname":"wg0","mtu":1420,"linkinfo":{"info_kind":"wireguard"}},{"ifindex":3,"ifname":"eth0","mtu":1500,"linkinfo":{"info_kind":"veth"}}]"#;
    for kinds in [
        parse_ip_link(out)?
            .iter()
            .map(|l| l.kind.clone())
            .collect::<Vec<_>>(),
        links(out)?.iter().map(|l| l.kind.clone()).collect(),
    ] {
        assert_eq!(kinds, [Some("wireguard".into()), Some("veth".into())]);
    }
    assert!(links(r#"[{"ifname":"wg0","linkinfo":{"info_kind":42}}]"#).is_err());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn structured_kernel_json_never_panics(
        entries in proptest::collection::vec(proptest::collection::btree_map(
            prop::sample::select(vec!["priority", "src", "srclen", "dst", "dstlen", "not", "table", "action", "uid_start", "uid_end", "sport_start", "sport_end", "iif_detached", "linkinfo", "ifname", "mtu", "addr_info", "options", "root", "unknown"]),
            prop_oneof![Just(serde_json::Value::Null), any::<bool>().prop_map(serde_json::Value::from), any::<u64>().prop_map(serde_json::Value::from), ".{0,40}".prop_map(serde_json::Value::from), Just(serde_json::json!({})), Just(serde_json::json!([]))], 0..15),0..8)
    ) {
        let out = serde_json::to_string(&entries).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let _ = parse_ip_rule(&out); let _ = parse_ip_route(&out);
        let _ = parse_ip_link(&out); let _ = links(&out); let _ = parse_ip_addr(&out);
        let _ = parse_tc_qdisc(&out); let _ = parse_tc_filter(&out);
    }
}
