//! Synthetic wire fixtures for the uplink oracle. No privileges or network access.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)] // Bounded fixture sizes.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::Command,
};

use proptest::prelude::*;
use xtask::pcap::{Class, FragmentError, Location, Policy, Reason, Report, classify};

const LOCAL: [u8; 4] = [192, 0, 2, 1];
const PEER: [u8; 4] = [198, 51, 100, 2];
const CLIENT: [u8; 4] = [10, 99, 0, 2];
const EXIT: [u8; 4] = [10, 2, 0, 2];
const POLICY: &str = r#"
uplink_addrs = ["192.0.2.1", "2001:db8::1"]
forbidden_addrs = ["10.99.0.0/24", "10.2.0.2/32", "2001:db8:99::/48"]
canary_markers = ["leak.example", "split-marker"]
arp = true
ndp = true

[[wireguard]]
gateway = "192.0.2.1:51820"
peer = "198.51.100.2:51820"

[[wireguard]]
gateway = "[2001:db8::1]:51820"
peer = "[2001:db8:1::2]:51820"

[[host_allow]]
proto = "tcp"
local_port = 22
remote_addr = "198.51.100.0/24"

[[host_allow]]
proto = "udp"
local_port = 40000
remote_addr = "198.51.100.2/32"
remote_port = 53

[[host_allow]]
proto = "icmp"
remote_addr = "198.51.100.2/32"

[[host_allow]]
proto = "icmpv6"
remote_addr = "2001:db8:1::/48"
"#;

fn policy() -> Policy {
    Policy::from_toml(POLICY).unwrap()
}

// Classic pcap helper supports both endiannesses, timestamp resolutions and
// snaplen cuts; original lengths can differ from the captured record's length.
fn pcap(kind: u32, records: &[(Vec<u8>, usize)], big: bool, nano: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let u16s = |n: u16| {
        if big {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        }
    };
    let u32s = |n: u32| {
        if big {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        }
    };
    out.extend_from_slice(&u32s(if nano { 0xa1b2_3c4d } else { 0xa1b2_c3d4 }));
    out.extend_from_slice(&u16s(2));
    out.extend_from_slice(&u16s(4));
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&u32s(65535));
    out.extend_from_slice(&u32s(kind));
    for (i, (data, original)) in records.iter().enumerate() {
        out.extend_from_slice(&u32s(1_700_000_000 + i as u32));
        out.extend_from_slice(&u32s(123));
        out.extend_from_slice(&u32s(data.len() as u32));
        out.extend_from_slice(&u32s(*original as u32));
        out.extend_from_slice(data);
    }
    out
}

fn capture(kind: u32, packets: &[Vec<u8>]) -> Vec<u8> {
    pcap(
        kind,
        &packets
            .iter()
            .map(|p| (p.clone(), p.len()))
            .collect::<Vec<_>>(),
        false,
        false,
    )
}

fn report(packets: &[Vec<u8>]) -> Report {
    classify(&capture(101, packets), &policy(), 20).unwrap()
}

fn classes(packets: &[Vec<u8>]) -> Vec<Class> {
    report(packets)
        .packets
        .into_iter()
        .map(|p| p.class)
        .collect()
}

fn violation(reason: Reason) -> Class {
    Class::Violation(reason)
}
fn allowed(rule: &str) -> Class {
    Class::Allowed(rule.into())
}
fn forbidden(addr: [u8; 4], location: Location) -> Class {
    violation(Reason::ForbiddenAddress {
        addr: Ipv4Addr::from(addr).into(),
        location,
    })
}

fn ip4(src: [u8; 4], dst: [u8; 4], proto: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 20];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    out[8] = 64;
    out[9] = proto;
    out[12..16].copy_from_slice(&src);
    out[16..20].copy_from_slice(&dst);
    out.extend_from_slice(body);
    out
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}
fn ip6(src: &str, dst: &str, proto: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 40];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    out[6] = proto;
    out[7] = 255;
    out[8..24].copy_from_slice(&v6(src).octets());
    out[24..40].copy_from_slice(&v6(dst).octets());
    out.extend_from_slice(body);
    out
}

fn udp(src: u16, dst: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 8];
    out[..2].copy_from_slice(&src.to_be_bytes());
    out[2..4].copy_from_slice(&dst.to_be_bytes());
    out[4..6].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn tcp(src: u16, dst: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 20];
    out[..2].copy_from_slice(&src.to_be_bytes());
    out[2..4].copy_from_slice(&dst.to_be_bytes());
    out[12] = 0x50;
    out.extend_from_slice(body);
    out
}

fn wg(kind: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    out[0] = kind;
    out
}
fn wg_packet(kind: u8, len: usize) -> Vec<u8> {
    ip4(LOCAL, PEER, 17, &udp(51820, 51820, &wg(kind, len)))
}
fn icmp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 8];
    out[0] = kind;
    out.extend_from_slice(body);
    out
}

fn fragment4(body: &[u8], offset: usize, more: bool) -> Vec<u8> {
    let mut out = ip4(LOCAL, PEER, 17, body);
    out[4..6].copy_from_slice(&42_u16.to_be_bytes());
    out[6..8].copy_from_slice(&((offset as u16 / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
    out
}
fn fragment6(src: &str, body: &[u8], offset: usize, more: bool, proto: u8) -> Vec<u8> {
    let mut out = vec![proto, 0];
    out.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
    out.extend_from_slice(&42_u32.to_be_bytes());
    out.extend_from_slice(body);
    ip6(src, "2001:db8:1::2", 44, &out)
}

fn ethernet(packet: &[u8], vlans: usize, proto: u16) -> Vec<u8> {
    let mut out = vec![0; 12];
    for _ in 0..vlans {
        out.extend_from_slice(&0x8100_u16.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
    }
    out.extend_from_slice(&proto.to_be_bytes());
    out.extend_from_slice(packet);
    out
}
fn arp(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut out = vec![0; 28];
    out[0..2].copy_from_slice(&1_u16.to_be_bytes());
    out[2..4].copy_from_slice(&0x0800_u16.to_be_bytes());
    out[4] = 6;
    out[5] = 4;
    out[6..8].copy_from_slice(&1_u16.to_be_bytes());
    out[14..18].copy_from_slice(&src);
    out[24..28].copy_from_slice(&dst);
    ethernet(&out, 0, 0x0806)
}

#[test]
fn wireguard_messages_both_directions_and_families() {
    let mut packets = Vec::new();
    for (kind, len) in [(1, 148), (2, 92), (3, 64), (4, 32), (4, 192)] {
        packets.push(wg_packet(kind, len));
        packets.push(ip4(PEER, LOCAL, 17, &udp(51820, 51820, &wg(kind, len))));
    }
    assert!(
        classes(&packets)
            .iter()
            .all(|c| *c == allowed("wireguard[0]"))
    );
    assert_eq!(
        classes(&[ip6(
            "2001:db8::1",
            "2001:db8:1::2",
            17,
            &udp(51820, 51820, &wg(4, 32))
        )]),
        [allowed("wireguard[1]")]
    );
}

#[test]
fn host_ssh_arp_and_default_deny() {
    assert_eq!(
        classes(&[
            ip4(LOCAL, PEER, 6, &tcp(22, 45000, b"ssh")),
            ip4(PEER, LOCAL, 6, &tcp(45000, 22, b"ssh")),
            ip4(LOCAL, PEER, 6, &tcp(23, 45000, b"ssh")),
            ip4([192, 0, 2, 5], PEER, 6, &tcp(22, 45000, b"ssh")),
            ip4(LOCAL, PEER, 99, b"unknown"),
        ]),
        [
            allowed("host_allow[0]"),
            allowed("host_allow[0]"),
            violation(Reason::NotAllowListed),
            violation(Reason::NotAllowListed),
            violation(Reason::NotAllowListed)
        ]
    );
    let out = classify(
        &capture(
            1,
            &[
                arp(PEER, LOCAL),
                arp(LOCAL, PEER),
                arp(PEER, [192, 0, 2, 5]),
                arp(CLIENT, LOCAL),
            ],
        ),
        &policy(),
        20,
    )
    .unwrap();
    assert_eq!(
        out.packets
            .iter()
            .map(|p| p.class.clone())
            .collect::<Vec<_>>(),
        [
            allowed("arp"),
            allowed("arp"),
            violation(Reason::NotAllowListed),
            forbidden(CLIENT, Location::Outer)
        ]
    );
}

#[test]
fn outer_client_and_post_nat_exit_are_forbidden() {
    assert_eq!(
        classes(&[
            ip4(CLIENT, PEER, 6, &tcp(22, 40000, b"")),
            ip4(
                EXIT,
                PEER,
                1,
                &icmp(3, &ip4(LOCAL, PEER, 17, &udp(3, 4, b"")))
            ),
            ip4(LOCAL, CLIENT, 6, &tcp(22, 40000, b"")),
        ]),
        [
            forbidden(CLIENT, Location::Outer),
            forbidden(EXIT, Location::Outer),
            forbidden(CLIENT, Location::Outer)
        ]
    );
    // Contradictory allow/forbidden policies are rejected at configuration time.
    assert!(Policy::from_toml(&POLICY.replace("10.2.0.2/32", "192.0.2.1/32")).is_err());
}

#[test]
fn every_icmp_error_type_inspects_quoted_addresses() {
    for kind in [3, 4, 5, 11, 12] {
        // Legal short quotation: complete IP header + first eight TCP octets.
        let inner = ip4(CLIENT, PEER, 6, &tcp(22, 40000, b"payload"));
        let out = classes(&[ip4(LOCAL, PEER, 1, &icmp(kind, &inner[..28]))]);
        assert_eq!(out, [forbidden(CLIENT, Location::Quoted)], "type {kind}");
    }
    for kind in 1..=4 {
        let inner = ip6("2001:db8::1", "2001:db8:99::2", 17, &udp(1, 2, b""));
        assert_eq!(
            classes(&[ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(kind, &inner))]),
            [violation(Reason::ForbiddenAddress {
                addr: v6("2001:db8:99::2").into(),
                location: Location::Quoted
            })]
        );
    }
    let inner = ip4(PEER, CLIENT, 17, &udp(1, 2, b""));
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(3, &inner))]),
        [forbidden(CLIENT, Location::Quoted)]
    );
}

#[test]
fn short_legal_quotation_is_allowed_but_cut_quoted_header_fails() {
    let inner = ip4(LOCAL, PEER, 6, &tcp(1, 2, b"content not quoted"));
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(3, &inner[..28]))]),
        [allowed("host_allow[2]")]
    );
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(3, &inner[..19]))]),
        [violation(Reason::Truncated)]
    );
}

#[test]
fn malformed_wireguard_never_falls_back_to_a_host_rule() {
    let mut bad_reserved = wg(4, 32);
    bad_reserved[1] = 1;
    let mut packets = vec![ip4(LOCAL, PEER, 17, &udp(51820, 51820, &bad_reserved))];
    for (kind, len) in [
        (1, 147),
        (1, 149),
        (2, 91),
        (3, 65),
        (4, 31),
        (0, 32),
        (5, 32),
    ] {
        packets.push(wg_packet(kind, len));
    }
    assert!(
        classes(&packets)
            .iter()
            .all(|c| *c == violation(Reason::MalformedWireGuard))
    );
    let p = Policy::from_toml(&format!(
        "{POLICY}\n[[host_allow]]\nproto='udp'\nlocal_port=51820\nremote_addr='198.51.100.0/24'\n"
    ))
    .unwrap();
    assert_eq!(
        classify(&capture(101, &packets), &p, 1)
            .unwrap()
            .violation_count,
        packets.len()
    );
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 17, &udp(51820, 51821, &wg(4, 32)))]),
        [violation(Reason::NotAllowListed)]
    );
}

#[test]
fn split_marker_is_detected_after_ipv4_reassembly_in_any_order() {
    let body = udp(40000, 53, b"aaaaaasplit-marker");
    // The split is inside the marker; each non-terminal fragment is 8-byte aligned.
    let fragments = [
        fragment4(&body[..16], 0, true),
        fragment4(&body[16..], 16, false),
    ];
    for packets in [fragments.to_vec(), fragments.into_iter().rev().collect()] {
        assert_eq!(
            classes(&packets),
            [
                violation(Reason::CanaryMarker),
                violation(Reason::CanaryMarker)
            ]
        );
    }
}

#[test]
fn fragmented_wireguard_is_classified_as_a_datagram_and_ids_can_be_reused() {
    let body = udp(51820, 51820, &wg(1, 148));
    let a = fragment4(&body[..80], 0, true);
    let b = fragment4(&body[80..], 80, false);
    assert_eq!(
        classes(&[b.clone(), a.clone(), a, b]),
        vec![allowed("wireguard[0]"); 4]
    );
}

#[test]
fn fragment_overlap_incomplete_holes_and_invalid_alignment_fail() {
    let body = udp(51820, 51820, &wg(1, 148));
    assert_eq!(
        classes(&[
            fragment4(&body[..80], 0, true),
            fragment4(&body[72..], 72, false)
        ]),
        vec![violation(Reason::Fragment(FragmentError::Overlap)); 2]
    );
    assert_eq!(
        classes(&[fragment4(&body[..80], 0, true)]),
        [violation(Reason::Fragment(FragmentError::Incomplete))]
    );
    assert_eq!(
        classes(&[
            fragment4(&body[..8], 0, true),
            fragment4(&body[16..], 16, false)
        ]),
        vec![violation(Reason::Fragment(FragmentError::Incomplete)); 2]
    );
    assert_eq!(
        classes(&[fragment4(&body[..9], 0, true)]),
        [violation(Reason::Fragment(FragmentError::Invalid))]
    );
    assert_eq!(
        classes(&[
            fragment4(&body[..80], 0, true),
            fragment4(&body[..80], 0, true)
        ]),
        vec![violation(Reason::Fragment(FragmentError::Overlap)); 2]
    );
}

fn compressed_dns() -> Vec<u8> {
    // Question 2 is "leak" + pointer to "example" in question 1. Neither wire
    // question contains the marker "leak.example" as contiguous bytes.
    let mut out = vec![0; 12];
    out[4..6].copy_from_slice(&2_u16.to_be_bytes());
    out.extend_from_slice(b"\x07example\0\0\x01\0\x01");
    out.extend_from_slice(b"\x04leak\xc0\x0c\0\x01\0\x01");
    out
}

#[test]
fn dns_compressed_names_queries_answers_and_tcp_frames() {
    let dns = compressed_dns();
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 17, &udp(40000, 53, &dns))]),
        [violation(Reason::CanaryMarker)]
    );
    let mut framed = (dns.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&dns);
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 6, &tcp(22, 53, &framed))]),
        [violation(Reason::CanaryMarker)]
    );
    // DNS response, compressed owner name, and a CNAME RDATA containing a marker.
    let mut answer = vec![0; 12];
    answer[2] = 0x80;
    answer[4..6].copy_from_slice(&1_u16.to_be_bytes());
    answer[6..8].copy_from_slice(&1_u16.to_be_bytes());
    answer.extend_from_slice(b"\x07example\0\0\x01\0\x01");
    answer.extend_from_slice(b"\xc0\x0c\0\x05\0\x01\0\0\0\x01\0\x07\x04leak\xc0\x0c");
    assert_eq!(
        classes(&[ip4(PEER, LOCAL, 17, &udp(53, 40000, &answer))]),
        [violation(Reason::CanaryMarker)]
    );
    // Complete DNS inside an ICMP quote also expands its names.
    let quoted = ip4(LOCAL, PEER, 17, &udp(40000, 53, &dns));
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(3, &quoted))]),
        [violation(Reason::CanaryMarker)]
    );
}

#[test]
fn dns_pointer_cycles_and_out_of_bounds_names_fail_closed() {
    for suffix in [b"\xc0\x0c".as_slice(), b"\xc0\xff", b"\x3fshort"] {
        let mut dns = vec![0; 12];
        dns[4..6].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(suffix);
        assert!(matches!(
            classes(&[ip4(LOCAL, PEER, 17, &udp(40000, 53, &dns))])[0],
            Class::Violation(_)
        ));
    }
}

#[test]
fn ipv6_extensions_fragments_and_forbidden_sources() {
    let body = udp(51820, 51820, &wg(4, 64));
    let mut ext = vec![
        43, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0,
    ];
    ext.extend_from_slice(&body);
    assert_eq!(
        classes(&[ip6("2001:db8::1", "2001:db8:1::2", 0, &ext)]),
        [allowed("wireguard[1]")]
    );
    assert_eq!(
        classes(&[fragment6("2001:db8:99::2", &body, 0, false, 17)]),
        [violation(Reason::ForbiddenAddress {
            addr: v6("2001:db8:99::2").into(),
            location: Location::Outer
        })]
    );
    // Destination options after a fragment header are walked after reassembly.
    let mut post_ext = vec![17, 0, 0, 0, 0, 0, 0, 0];
    post_ext.extend_from_slice(&body);
    let fragments = [
        fragment6("2001:db8::1", &post_ext[..40], 0, true, 60),
        fragment6("2001:db8::1", &post_ext[40..], 40, false, 60),
    ];
    assert_eq!(classes(&fragments), vec![allowed("wireguard[1]"); 2]);
    assert_eq!(
        classes(&[
            fragment6("2001:db8::1", &body[..40], 0, true, 17),
            fragment6("2001:db8::1", &body[32..], 32, false, 17)
        ]),
        vec![violation(Reason::Fragment(FragmentError::Overlap)); 2]
    );
}

#[test]
fn ipv4_options_and_tcp_options_do_not_hide_payloads() {
    let mut packet = wg_packet(4, 32);
    packet.splice(20..20, [1, 1, 1, 0]);
    packet[0] = 0x46;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    assert_eq!(classes(&[packet]), [allowed("wireguard[0]")]);
    let mut t = tcp(22, 45000, b"split-marker");
    t.splice(20..20, [1, 1, 1, 0]);
    t[12] = 0x60;
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 6, &t)]),
        [violation(Reason::CanaryMarker)]
    );
}

#[test]
fn ndp_allows_uplink_resolution_and_checks_hop_limit() {
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&v6("2001:db8::1").octets());
    let good = ip6("2001:db8:1::2", "ff02::1:ff00:1", 58, &ns);
    assert_eq!(classes(std::slice::from_ref(&good)), [allowed("ndp")]);
    let mut bad_hop = good.clone();
    bad_hop[7] = 64;
    assert_eq!(classes(&[bad_hop]), [violation(Reason::MalformedPacket)]);
    ns[8..24].copy_from_slice(&v6("2001:db8:1::2").octets());
    assert_eq!(
        classes(&[ip6("2001:db8::1", "2001:db8:1::2", 58, &ns)]),
        [allowed("ndp")]
    );
    ns[8..24].copy_from_slice(&v6("2001:db8:99::2").octets());
    assert_eq!(
        classes(&[ip6("2001:db8::1", "2001:db8:1::2", 58, &ns)]),
        [violation(Reason::ForbiddenAddress {
            addr: v6("2001:db8:99::2").into(),
            location: Location::Outer
        })]
    );
    let disabled = Policy::from_toml(&POLICY.replace("ndp = true", "ndp = false")).unwrap();
    assert_eq!(
        classify(&capture(101, &[good]), &disabled, 20)
            .unwrap()
            .packets[0]
            .class,
        violation(Reason::NotAllowListed)
    );
}

#[test]
fn mldv2_report_from_unspecified_source_during_dad_is_link_control() {
    // Seen in the namespace lab: a tentative interface reports from `::` (RFC 3810 §5.2.13).
    let mut report = vec![143, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0];
    report.extend_from_slice(&v6("ff02::1:ff00:1").octets());
    let packet = ip6("::", "ff02::16", 58, &report);
    assert_eq!(classes(std::slice::from_ref(&packet)), [allowed("ndp")]);
    // A unicast destination is still not link control.
    assert_eq!(
        classes(&[ip6("::", "2001:db8:1::2", 58, &report)]),
        [violation(Reason::NotAllowListed)]
    );
}

#[test]
fn vlan_sll_sll2_and_unknown_links_are_classified() {
    let packet = ip4(CLIENT, PEER, 6, &tcp(22, 40000, b""));
    for tags in [0, 1, 2] {
        assert_eq!(
            classify(
                &capture(1, &[ethernet(&packet, tags, 0x0800)]),
                &policy(),
                20
            )
            .unwrap()
            .packets[0]
                .class,
            forbidden(CLIENT, Location::Outer)
        );
    }
    for kind in [113, 276] {
        let mut cooked = vec![0; if kind == 113 { 16 } else { 20 }];
        let at = if kind == 113 { 14 } else { 0 };
        cooked[at..at + 2].copy_from_slice(&0x0800_u16.to_be_bytes());
        cooked.extend_from_slice(&packet);
        assert_eq!(
            classify(&capture(kind, &[cooked]), &policy(), 20)
                .unwrap()
                .packets[0]
                .class,
            forbidden(CLIENT, Location::Outer)
        );
    }
    assert_eq!(
        classify(&capture(999, &[packet]), &policy(), 20)
            .unwrap()
            .packets[0]
            .class,
        violation(Reason::UnparsableLinkLayer)
    );
    assert_eq!(
        classify(
            &capture(1, &[ethernet(b"unknown", 0, 0x88b5)]),
            &policy(),
            20
        )
        .unwrap()
        .packets[0]
            .class,
        violation(Reason::UnparsableLinkLayer)
    );
}

#[test]
fn truncated_headers_and_snaplen_cuts_are_never_allowed() {
    let full = wg_packet(1, 148);
    for len in [0, 1, 19, 20, 24, 27, full.len() - 1] {
        let out = classify(
            &pcap(101, &[(full[..len].to_vec(), full.len())], false, false),
            &policy(),
            20,
        )
        .unwrap();
        assert_eq!(
            out.packets[0].class,
            violation(Reason::Truncated),
            "length {len}"
        );
    }
    for (kind, len) in [(1, 13), (113, 15), (276, 19)] {
        assert_eq!(
            classify(&capture(kind, &[vec![0; len]]), &policy(), 20)
                .unwrap()
                .packets[0]
                .class,
            violation(Reason::Truncated)
        );
    }
    // TCP option and IPv6 extension header cuts, with self-consistent IP lengths.
    let mut t = tcp(22, 3, b"");
    t[12] = 0xf0;
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 6, &t)]),
        [violation(Reason::Truncated)]
    );
    assert_eq!(
        classes(&[ip6("2001:db8::1", "2001:db8:1::2", 0, &[17, 3])]),
        [violation(Reason::Truncated)]
    );
}

#[test]
fn reader_endianness_nanoseconds_and_bad_containers() {
    for big in [false, true] {
        for nano in [false, true] {
            let packet = wg_packet(4, 32);
            let bytes = pcap(101, &[(packet.clone(), packet.len())], big, nano);
            let out = classify(&bytes, &policy(), 20).unwrap();
            assert_eq!(out.packets[0].class, allowed("wireguard[0]"));
            assert_eq!(
                out.packets[0].timestamp.nanoseconds,
                if nano { 123 } else { 123_000 }
            );
            for end in [0, 23, 25, bytes.len() - 1] {
                assert!(classify(&bytes[..end], &policy(), 20).is_err());
            }
        }
    }
    let mut bad = capture(101, &[wg_packet(4, 32)]);
    bad[36..40].copy_from_slice(&1_u32.to_le_bytes()); // original < included
    assert!(classify(&bad, &policy(), 20).is_err());
    assert!(classify(b"\x0a\x0d\x0d\x0a pcapng", &policy(), 20).is_err());
}

#[test]
fn policy_is_strict_and_defaults_deny_everything() {
    for bad in [
        "wiregaurd=[]",
        "canary_markers=['']",
        "[[wireguard]]\ngateway='192.0.2.1:4'\npeer='198.51.100.2:4'",
        "forbidden_addrs=['bogus']",
        "[[host_allow]]\nproto='icmp'\nlocal_port=22\nremote_addr='192.0.2.0/24'",
        "[[host_allow]]\nproto='any'\nremote_addr='192.0.2.0/24'",
    ] {
        assert!(Policy::from_toml(bad).is_err(), "{bad}");
    }
    let p = Policy::from_toml("forbidden_addrs=['10.99.0.0/24']").unwrap();
    assert_eq!(
        classify(&capture(101, &[wg_packet(1, 148)]), &p, 20)
            .unwrap()
            .packets[0]
            .class,
        violation(Reason::NotAllowListed)
    );
}

fn mixed() -> Vec<u8> {
    capture(
        101,
        &[
            wg_packet(4, 32),
            ip4(CLIENT, PEER, 6, &tcp(22, 40000, b"")),
            ip4(
                LOCAL,
                PEER,
                1,
                &icmp(3, &ip4(LOCAL, CLIENT, 17, &udp(1, 2, b""))),
            ),
            wg_packet(4, 31),
        ],
    )
}

#[test]
fn golden_report_and_bounded_violation_samples() {
    let out = classify(&mixed(), &policy(), 2).unwrap();
    assert_eq!(out.packet_count, 4);
    assert_eq!(out.violation_count, 3);
    assert_eq!(out.violations.len(), 2);
    assert_eq!(out.violations[0].packet.index, 2);
    assert!(out.violations.iter().all(|v| v.captured_hex.len() <= 128));
    let json = format!("{}\n", serde_json::to_string_pretty(&out).unwrap());
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/mixed.json"),
            &json,
        )
        .unwrap();
    } else {
        assert_eq!(json, include_str!("golden/mixed.json"));
    }
    assert!(
        classify(&mixed(), &policy(), 0)
            .unwrap()
            .violations
            .is_empty()
    );
}

#[test]
fn cli_json_and_exit_codes() {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("capture.pcap");
    let p = dir.join("policy.toml");
    std::fs::write(&p, POLICY).unwrap();
    for (data, code) in [(mixed(), 1), (capture(101, &[wg_packet(4, 32)]), 0)] {
        std::fs::write(&file, data).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["classify"])
            .arg(&file)
            .arg("--policy")
            .arg(&p)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(json["violation_count"], if code == 1 { 3 } else { 0 });
    }
    std::fs::remove_dir_all(dir).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn arbitrary_pcap_bytes_never_panic(data in prop::collection::vec(any::<u8>(),0..4096)) {
        let _ = classify(&data,&policy(),4);
    }

    #[test]
    fn every_capture_record_gets_one_class(
        kind in prop::sample::select(vec![1_u32,113,276,101,999]),
        frames in prop::collection::vec(prop::collection::vec(any::<u8>(),0..512),0..24),
    ) {
        let out = classify(&capture(kind,&frames),&policy(),3).unwrap();
        prop_assert_eq!(out.packets.len(),frames.len());
        prop_assert_eq!(out.counts.values().sum::<usize>(),frames.len() + out.capture_failures.len());
        prop_assert_eq!(out.violation_count,out.packets.iter().filter(|p| matches!(p.class,Class::Violation(_))).count() + out.capture_failures.len());
        for (i,p) in out.packets.iter().enumerate() { prop_assert_eq!(p.index,i+1); }
    }

    #[test]
    fn arbitrary_transport_and_extension_bytes_never_panic(
        body in prop::collection::vec(any::<u8>(),0..1024),
        proto in prop::sample::select(vec![0_u8,1,6,17,43,44,58,60]),
    ) {
        let out = report(&[ip4(LOCAL,PEER,proto,&body),ip6("2001:db8::1","2001:db8:1::2",proto,&body)]);
        prop_assert_eq!(out.packet_count,2);
    }
}

#[test]
fn binary_markers_single_address_rules_and_wireguard_on_dns_port() {
    let p = Policy::from_toml("uplink_addrs=['192.0.2.1']\nforbidden_addrs=['10.99.0.0/24']\ncanary_markers=[[255,0,254,1,2,3,4,5,6,7,8,9]]\n[[host_allow]]\nproto='tcp'\nlocal_port=22\nremote_addr='198.51.100.2'").unwrap();
    let packets = [
        ip4(
            LOCAL,
            PEER,
            6,
            &tcp(22, 40000, b"\xff\0\xfe\x01\x02\x03\x04\x05\x06\x07\x08\x09"),
        ),
        ip4(LOCAL, PEER, 6, &tcp(22, 40000, b"ssh")),
    ];
    let out = classify(&capture(101, &packets), &p, 20).unwrap();
    assert_eq!(out.packets[0].class, violation(Reason::CanaryMarker));
    assert_eq!(out.packets[1].class, allowed("host_allow[0]"));
    let p = Policy::from_toml(&POLICY.replace(":51820", ":53")).unwrap();
    assert_eq!(
        classify(
            &capture(101, &[ip4(LOCAL, PEER, 17, &udp(53, 53, &wg(1, 148)))]),
            &p,
            20
        )
        .unwrap()
        .packets[0]
            .class,
        allowed("wireguard[0]")
    );
}

#[test]
fn dns_canary_is_found_before_a_quoted_short_tail() {
    let mut dns = compressed_dns();
    dns[6..8].copy_from_slice(&1_u16.to_be_bytes()); // Claim an answer not in the quote.
    let mut u = udp(40000, 53, &dns);
    // Original UDP/IP lengths include an answer's missing tail, like a real quote.
    let u_len = (u.len() + 32) as u16;
    u[4..6].copy_from_slice(&u_len.to_be_bytes());
    let mut inner = ip4(LOCAL, PEER, 17, &u);
    let i_len = (inner.len() + 32) as u16;
    inner[2..4].copy_from_slice(&i_len.to_be_bytes());
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(3, &inner))]),
        [violation(Reason::CanaryMarker)]
    );
    // The identical outer DNS message is structurally incomplete and fails closed.
    assert!(matches!(
        classes(&[ip4(LOCAL, PEER, 17, &udp(40000, 53, &dns))])[0],
        Class::Violation(_)
    ));
}

#[test]
fn ipv6_split_marker_and_raw_icmp_canary_fail() {
    let body = udp(40000, 53, b"aaaaaasplit-marker");
    assert_eq!(
        classes(&[
            fragment6("2001:db8::1", &body[..16], 0, true, 17),
            fragment6("2001:db8::1", &body[16..], 16, false, 17)
        ]),
        vec![violation(Reason::CanaryMarker); 2]
    );
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(8, b"split-marker"))]),
        [violation(Reason::CanaryMarker)]
    );
    // Address evidence wins over a marker and matching host allow rule.
    let inner = ip4(CLIENT, PEER, 17, &udp(1, 2, b"split-marker"));
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &icmp(3, &inner))]),
        [forbidden(CLIENT, Location::Quoted)]
    );
}

#[test]
fn violation_samples_use_capture_order_after_reassembly() {
    let body = udp(40000, 53, b"aaaaaasplit-marker");
    let packets = [
        fragment4(&body[..16], 0, true),
        ip4(CLIENT, PEER, 6, &tcp(22, 3, b"")),
        fragment4(&body[16..], 16, false),
    ];
    let out = classify(&capture(101, &packets), &policy(), 1).unwrap();
    assert_eq!(out.violation_count, 3);
    assert_eq!(out.violations.len(), 1);
    assert_eq!(out.violations[0].packet.index, 1);
    assert_eq!(
        out.violations[0].packet.class,
        violation(Reason::CanaryMarker)
    );
    assert_eq!(out.packets[2].timestamp.seconds, 1_700_000_002);
}

fn with_options(mut packet: Vec<u8>, options: &[u8]) -> Vec<u8> {
    assert!(options.len().is_multiple_of(4));
    packet.splice(20..20, options.iter().copied());
    packet[0] = 0x45 + (options.len() / 4) as u8;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet
}

fn routing(kind: u8, address: &str, body: &[u8]) -> Vec<u8> {
    let mut out = vec![17, 2, kind, 1, 0, 0, 0, 0];
    out.extend_from_slice(&v6(address).octets());
    out.extend_from_slice(body);
    out
}

#[test]
fn positive_evidence_is_required_and_controls_cli_exit() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("positive-evidence-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("capture.pcap");
    let policy_file = dir.join("policy.toml");
    let ssh = ip4(LOCAL, PEER, 6, &tcp(22, 45000, b"ssh"));
    for (settings, packets, reason) in [
        ("", vec![], Some("EmptyCapture")),
        (
            "min_packets=2",
            vec![wg_packet(4, 32)],
            Some("EmptyCapture"),
        ),
        (
            "expect=['wireguard']",
            vec![ssh.clone()],
            Some("ExpectedClassMissing"),
        ),
        (
            "expect=['wireguard[1]']",
            vec![wg_packet(4, 32)],
            Some("ExpectedClassMissing"),
        ),
        (
            "expect=['wireguard','wireguard[0]']",
            vec![wg_packet(4, 1452)],
            None,
        ),
    ] {
        let text = format!("{settings}\n{POLICY}");
        let p = Policy::from_toml(&text).unwrap();
        let data = capture(101, &packets);
        let out = classify(&data, &p, 0).unwrap();
        assert_eq!(out.packet_count, packets.len());
        assert_eq!(out.violation_count, usize::from(reason.is_some()));
        if let Some(reason) = reason {
            assert!(serde_json::to_string(&out).unwrap().contains(reason));
        }
        std::fs::write(&file, data).unwrap();
        std::fs::write(&policy_file, text).unwrap();
        let cli = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("classify")
            .arg(&file)
            .arg("--policy")
            .arg(&policy_file)
            .output()
            .unwrap();
        assert_eq!(cli.status.code(), Some(i32::from(reason.is_some())));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn policy_rejects_missing_contradictory_or_unbounded_rules() {
    for text in [
        "",
        "forbidden_addrs=[]",
        "min_packets=0\nforbidden_addrs=['10.99.0.0/24']",
    ] {
        assert!(Policy::from_toml(text).is_err(), "{text}");
    }
    for text in [
        POLICY.replace("192.0.2.1\",", "10.99.0.2\","),
        POLICY.replace("198.51.100.2:51820", "10.99.0.2:51820"),
        POLICY.replace(
            "remote_addr = \"198.51.100.0/24\"",
            "remote_addr = \"10.99.0.0/24\"",
        ),
        POLICY.replace(
            "remote_addr = \"198.51.100.0/24\"",
            "remote_addr = \"0.0.0.0/0\"\nallow_wide=true",
        ),
        POLICY.replace("local_port = 22", ""),
        POLICY.replace(
            "remote_addr = \"198.51.100.0/24\"",
            "remote_addr = \"198.51.0.0/16\"",
        ),
        format!("expect=['typo']\n{POLICY}"),
    ] {
        assert!(Policy::from_toml(&text).is_err(), "{text}");
    }
    assert!(
        Policy::from_toml(&POLICY.replace(
            "remote_addr = \"198.51.100.0/24\"",
            "remote_addr = \"198.51.0.0/16\"\nallow_wide=true"
        ))
        .is_ok()
    );
}

#[test]
fn canary_markers_require_twelve_bytes() {
    for size in 0..12 {
        for marker in [
            format!("'{}'", "x".repeat(size)),
            format!("{:?}", vec![255; size]),
        ] {
            assert!(
                Policy::from_toml(&format!(
                    "forbidden_addrs=['10.99.0.0/24']\ncanary_markers=[{marker}]"
                ))
                .is_err()
            );
        }
    }
    assert!(
        Policy::from_toml("forbidden_addrs=['10.99.0.0/24']\ncanary_markers=['twelve-bytes']")
            .is_ok()
    );
}

#[test]
fn ipv4_option_address_lists_and_raw_bytes_are_checked() {
    for kind in [7, 131, 137] {
        let option = [kind, 7, 4, CLIENT[0], CLIENT[1], CLIENT[2], CLIENT[3], 0];
        assert_eq!(
            classes(&[with_options(wg_packet(4, 32), &option)]),
            [forbidden(CLIENT, Location::Outer)]
        );
    }
    for flags in [1, 3] {
        let mut option = vec![68, 12, 5, flags];
        option.extend_from_slice(&EXIT);
        option.extend_from_slice(&[0; 4]);
        assert_eq!(
            classes(&[with_options(wg_packet(4, 32), &option)]),
            [forbidden(EXIT, Location::Outer)]
        );
    }
    let mut option = vec![68, 16, 5, 0];
    option.extend_from_slice(b"split-marker");
    assert_eq!(
        classes(&[with_options(wg_packet(4, 32), &option)]),
        [violation(Reason::CanaryMarker)]
    );
    // Timestamp-only values resembling an address are not address fields.
    assert_eq!(
        classes(&[with_options(wg_packet(4, 32), &[68, 8, 5, 0, 10, 99, 0, 2])]),
        [allowed("wireguard[0]")]
    );
}

#[test]
fn ipv6_routing_and_home_addresses_are_checked() {
    let body = udp(51820, 51820, &wg(4, 32));
    for kind in [0, 2, 4] {
        let packet = ip6(
            "2001:db8::1",
            "2001:db8:1::2",
            43,
            &routing(kind, "2001:db8:99::2", &body),
        );
        assert_eq!(
            classes(&[packet]),
            [violation(Reason::ForbiddenAddress {
                addr: v6("2001:db8:99::2").into(),
                location: Location::Outer
            })]
        );
    }
    let mut home = vec![17, 2, 201, 16];
    home.extend_from_slice(&v6("2001:db8:99::2").octets());
    home.resize(24, 0);
    home.extend_from_slice(&body);
    assert!(matches!(
        classes(&[ip6("2001:db8::1", "2001:db8:1::2", 60, &home)])[0],
        Class::Violation(Reason::ForbiddenAddress { .. })
    ));
}

#[test]
fn extension_markers_survive_decoding_and_fragment_reassembly() {
    let body = udp(51820, 51820, &wg(1, 148));
    for proto in [0, 43, 60, 51] {
        let mut ext = match proto {
            43 => vec![17, 2, 4, 0, 0, 0, 0, 0],
            51 => vec![17, 2, 0, 0], // AH length (2+2)*4 = 16
            _ => vec![17, 1, 1, 12],
        };
        ext.extend_from_slice(b"leak.example");
        if proto == 43 {
            ext.resize(24, 0);
        }
        ext.extend_from_slice(&body);
        assert_eq!(
            classes(&[ip6("2001:db8::1", "2001:db8:1::2", proto, &ext)]),
            [violation(Reason::CanaryMarker)]
        );
    }
    let first = fragment6("2001:db8::1", &body[..80], 0, true, 17);
    let last = fragment6("2001:db8::1", &body[80..], 80, false, 17);
    let mut prefixed = vec![44, 1, 1, 12];
    prefixed.extend_from_slice(b"leak.example");
    prefixed.extend_from_slice(&first[40..]);
    for packets in [
        vec![
            ip6("2001:db8::1", "2001:db8:1::2", 60, &prefixed),
            last.clone(),
        ],
        vec![last, ip6("2001:db8::1", "2001:db8:1::2", 60, &prefixed)],
    ] {
        assert_eq!(classes(&packets), vec![violation(Reason::CanaryMarker); 2]);
    }
    let mut post = vec![17, 1, 1, 12];
    post.extend_from_slice(b"leak.example");
    post.extend_from_slice(&body);
    assert_eq!(
        classes(&[
            fragment6("2001:db8::1", &post[..8], 0, true, 60),
            fragment6("2001:db8::1", &post[8..], 8, false, 60)
        ]),
        vec![violation(Reason::CanaryMarker); 2]
    );
}

#[test]
fn trailers_are_checked_on_every_link_and_only_minimum_ethernet_padding_is_allowed() {
    for ipv6 in [false, true] {
        let packet = if ipv6 {
            ip6(
                "2001:db8::1",
                "2001:db8:1::2",
                17,
                &udp(51820, 51820, &wg(4, 32)),
            )
        } else {
            wg_packet(4, 32)
        };
        for kind in [1, 101, 113, 276] {
            for tail in [
                b"leak.example".to_vec(),
                ip4(CLIENT, PEER, 17, &udp(1, 2, b"")),
                vec![0; 8],
            ] {
                let mut p = packet.clone();
                p.extend_from_slice(&tail);
                let frame = match kind {
                    1 => ethernet(&p, 0, if ipv6 { 0x86dd } else { 0x0800 }),
                    113 | 276 => {
                        let mut h = vec![0; if kind == 113 { 16 } else { 20 }];
                        let at = if kind == 113 { 14 } else { 0 };
                        h[at..at + 2].copy_from_slice(
                            &(if ipv6 { 0x86dd_u16 } else { 0x0800 }).to_be_bytes(),
                        );
                        h.extend_from_slice(&p);
                        h
                    }
                    _ => p,
                };
                let r = classify(&capture(kind, &[frame]), &policy(), 1).unwrap();
                let expected = if tail == b"leak.example" {
                    "CanaryMarker"
                } else {
                    "TrailingData"
                };
                assert!(format!("{:?}", r.packets[0].class).contains(expected));
            }
        }
    }
    let short = ip4(LOCAL, PEER, 1, &icmp(8, b""));
    for fill in [0, 0x7e] {
        let mut frame = ethernet(&short, 0, 0x0800);
        frame.resize(60, fill);
        assert_eq!(
            classify(&capture(1, &[frame.clone()]), &policy(), 1)
                .unwrap()
                .violation_count,
            0
        );
        frame.extend_from_slice(&[0; 4]); // Declared Ethernet FCS, not an IP trailer.
        assert_eq!(
            classify(&capture(1 | (1 << 26) | (2 << 28), &[frame]), &policy(), 1)
                .unwrap()
                .violation_count,
            0
        );
    }
    let mut with_fcs = ethernet(&ip4(LOCAL, PEER, 1, &icmp(8, b"leak.exa")), 0, 0x0800);
    with_fcs.extend_from_slice(b"mple");
    assert_eq!(
        classify(
            &capture(1 | (1 << 26) | (2 << 28), &[with_fcs]),
            &policy(),
            1
        )
        .unwrap()
        .packets[0]
            .class,
        violation(Reason::CanaryMarker)
    );
    let mut frame = ethernet(&short, 0, 0x0800);
    frame.extend_from_slice(b"leak.example");
    frame.resize(60, 0);
    assert_eq!(
        classify(&capture(1, &[frame]), &policy(), 1)
            .unwrap()
            .packets[0]
            .class,
        violation(Reason::CanaryMarker)
    );
}

#[test]
fn dns_names_are_case_insensitive_and_scanned_before_wireguard() {
    let mut dns = compressed_dns();
    for b in &mut dns[12..] {
        b.make_ascii_uppercase();
    }
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 17, &udp(40000, 53, &dns))]),
        [violation(Reason::CanaryMarker)]
    );
    let p = Policy::from_toml(&POLICY.replace(":51820", ":53")).unwrap();
    dns[..4].copy_from_slice(&[1, 0, 0, 0]);
    dns.resize(148, 0);
    let r = classify(
        &capture(101, &[ip4(LOCAL, PEER, 17, &udp(53, 53, &dns))]),
        &p,
        1,
    )
    .unwrap();
    assert_eq!(r.packets[0].class, violation(Reason::CanaryMarker));
    // Binary markers retain case-sensitive matching even in decoded names.
    let bytes = b"leak.example".to_vec();
    let p = Policy::from_toml(&POLICY.replace("\"leak.example\"", &format!("{bytes:?}"))).unwrap();
    let r = classify(
        &capture(101, &[ip4(LOCAL, PEER, 17, &udp(40000, 53, &dns))]),
        &p,
        1,
    )
    .unwrap();
    assert_eq!(r.violation_count, 0);
}

#[test]
fn nested_quotes_and_redirect_address_fields_are_checked() {
    for depth in 1..=3 {
        let mut packet = ip4(CLIENT, PEER, 17, &udp(1, 2, b""));
        let mut packet6 = ip6("2001:db8:99::2", "2001:db8:1::2", 59, b"");
        for _ in 0..depth {
            packet = ip4(LOCAL, PEER, 1, &icmp(3, &packet));
            packet6 = ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(2, &packet6));
        }
        assert_eq!(classes(&[packet]), [forbidden(CLIENT, Location::Quoted)]);
        assert!(matches!(
            classes(&[packet6])[0],
            Class::Violation(Reason::ForbiddenAddress {
                location: Location::Quoted,
                ..
            })
        ));
    }
    let mut redirect = icmp(5, &wg_packet(4, 32));
    redirect[4..8].copy_from_slice(&CLIENT);
    assert_eq!(
        classes(&[ip4(LOCAL, PEER, 1, &redirect)]),
        [forbidden(CLIENT, Location::Outer)]
    );
    for at in [8, 24] {
        let mut redirect = vec![0; 40];
        redirect[0] = 137;
        redirect[at..at + 16].copy_from_slice(&v6("2001:db8:99::2").octets());
        assert!(matches!(
            classes(&[ip6("2001:db8::1", "2001:db8:1::2", 58, &redirect)])[0],
            Class::Violation(Reason::ForbiddenAddress { .. })
        ));
    }
    for kind in [42, 43] {
        assert_eq!(
            classes(&[ip4(LOCAL, PEER, 1, &icmp(kind, b""))]),
            [violation(Reason::NotAllowListed)]
        );
    }
    let p = Policy::from_toml(&POLICY.replace("proto = \"icmp\"", "proto = \"icmp\"\ntypes=[8]"))
        .unwrap();
    let r = classify(
        &capture(
            101,
            &[
                ip4(LOCAL, PEER, 1, &icmp(0, b"")),
                ip4(LOCAL, PEER, 1, &icmp(8, b"")),
            ],
        ),
        &p,
        1,
    )
    .unwrap();
    assert_eq!(r.packets[0].class, violation(Reason::NotAllowListed));
    assert_eq!(r.packets[1].class, allowed("host_allow[2]"));
}

#[test]
fn embedded_ipv4_forbidden_addresses_are_checked() {
    for (addr, prefix) in [
        ("::ffff:10.99.0.2", "::ffff:0:0/96"),
        ("::10.99.0.2", "::/96"),
        ("64:ff9b::a63:2", "64:ff9b::/96"),
        ("2002:a63:2::1", "2002::/16"),
    ] {
        // The remote prefix would allow this flow without embedded-v4 checks.
        let wide = if prefix == "2002::/16" {
            "\nallow_wide=true"
        } else {
            ""
        };
        let p = Policy::from_toml(&format!(
            "{POLICY}\n[[host_allow]]\nproto='icmpv6'\nremote_addr='{prefix}'{wide}"
        ))
        .unwrap();
        let r = classify(
            &capture(101, &[ip6("2001:db8::1", addr, 58, &icmp(128, b""))]),
            &p,
            1,
        )
        .unwrap();
        assert_eq!(
            r.packets[0].class,
            violation(Reason::ForbiddenAddress {
                addr: v6(addr).into(),
                location: Location::Outer
            })
        );
    }
}

#[test]
fn link_local_control_traffic_is_allowed_only_when_enabled_and_safe() {
    for source in ["fe80::1", "2001:db8::1"] {
        for kind in [131, 133, 134, 135, 136, 143] {
            let len = match kind {
                131 | 135 | 136 => 24,
                134 => 16,
                _ => 8,
            };
            let mut body = vec![0; len];
            body[0] = kind;
            if matches!(kind, 135 | 136) {
                body[8..24].copy_from_slice(&v6("fe80::fe").octets());
            }
            let good = ip6(source, "ff02::2", 58, &body);
            assert_eq!(
                classes(std::slice::from_ref(&good)),
                [allowed("ndp")],
                "type {kind}, source {source}"
            );
            let disabled = Policy::from_toml(&POLICY.replace("ndp = true", "ndp = false")).unwrap();
            assert_eq!(
                classify(&capture(101, std::slice::from_ref(&good)), &disabled, 1)
                    .unwrap()
                    .violation_count,
                1
            );
            if matches!(kind, 133..=136) {
                let mut bad = good;
                bad[7] = 64;
                assert_eq!(classes(&[bad]), [violation(Reason::MalformedPacket)]);
            }
            if matches!(kind, 131 | 135 | 136) {
                body[8..24].copy_from_slice(&v6("2001:db8:99::2").octets());
                assert!(matches!(
                    classes(&[ip6(source, "ff02::2", 58, &body)])[0],
                    Class::Violation(Reason::ForbiddenAddress { .. })
                ));
            }
        }
    }
    let mut ra = vec![
        134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    ra.extend_from_slice(&v6("2001:db8:99::").octets());
    assert!(matches!(
        classes(&[ip6("fe80::1", "ff02::1", 58, &ra)])[0],
        Class::Violation(Reason::ForbiddenAddress { .. })
    ));
    let mut report = vec![143, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1];
    report.extend_from_slice(&v6("ff02::1").octets());
    report.extend_from_slice(&v6("2001:db8:99::2").octets());
    assert!(matches!(
        classes(&[ip6("fe80::1", "ff02::16", 58, &report)])[0],
        Class::Violation(Reason::ForbiddenAddress { .. })
    ));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn generated_valid_wireguard_is_always_allowed(
        kind in 1u8..=4, len in 32usize..1500, reverse in any::<bool>(), ipv6 in any::<bool>(),
        bytes in prop::collection::vec(any::<u8>(), 1500), split in 1usize..20,
    ) {
        let size = match kind { 1 => 148, 2 => 92, 3 => 64, _ => len };
        let mut message = bytes[..size].to_vec();
        message[..4].copy_from_slice(&[kind, 0, 0, 0]);
        let body = udp(51820, 51820, &message);
        let packet = if ipv6 {
            let (s,d) = if reverse { ("2001:db8:1::2", "2001:db8::1") } else { ("2001:db8::1", "2001:db8:1::2") };
            // A valid generated hop-by-hop / destination option chain.
            let mut extensions = vec![60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0];
            extensions.extend_from_slice(&body);
            ip6(s,d,0,&extensions)
        } else {
            let (s,d) = if reverse { (PEER,LOCAL) } else { (LOCAL,PEER) };
            with_options(ip4(s,d,17,&body), &[1,1,1,0])
        };
        prop_assert_eq!(&classes(&[packet])[0], &allowed(if ipv6 { "wireguard[1]" } else { "wireguard[0]" }));
        // Random valid fragment splits (including an eight-byte first fragment).
        let at = (split * 8).min((body.len()-1)/8*8);
        if !reverse {
            let packets = if ipv6 { vec![fragment6("2001:db8::1", &body[at..], at, false, 17), fragment6("2001:db8::1", &body[..at], 0, true, 17)] }
                else { vec![fragment4(&body[at..],at,false),fragment4(&body[..at],0,true)] };
            for class in classes(&packets) { prop_assert_eq!(class, allowed(if ipv6 { "wireguard[1]" } else { "wireguard[0]" })); }
        }
    }

    #[test]
    fn generated_forbidden_fields_always_violate(last in 1u8..255, len in 32usize..1500) {
        let client = [10,99,0,last];
        let body = udp(51820,51820,&wg(4,len));
        let base = wg_packet(4,len);
        let mut packets = vec![ip4(client,PEER,17,&body),ip4(LOCAL,client,17,&body)];
        let mut quoted = ip4(client,PEER,17,&body);
        for _ in 0..3 { quoted = ip4(LOCAL,PEER,1,&icmp(3,&quoted)); packets.push(quoted.clone()); }
        for kind in [7,131,137] { packets.push(with_options(base.clone(), &[kind,7,4,10,99,0,last,0])); }
        for flag in [1,3] { packets.push(with_options(base.clone(), &[68,12,5,flag,10,99,0,last,0,0,0,0])); }
        for embedded in [format!("::ffff:10.99.0.{last}"),format!("::10.99.0.{last}"),format!("64:ff9b::a63:{last:x}"),format!("2002:a63:{last:x}::1")] {
            packets.push(ip6("2001:db8::1",&embedded,17,&body));
            for kind in [0,2,4] { packets.push(ip6("2001:db8::1","2001:db8:1::2",43,&routing(kind,&embedded,&body))); }
        }
        for class in classes(&packets) { prop_assert!(matches!(class,Class::Violation(Reason::ForbiddenAddress { .. })), "{class:?}"); }
    }
}

#[test]
fn wireguard_destination_option_canary_is_rejected() {
    let mut ext = vec![17, 1, 1, 12];
    ext.extend_from_slice(b"leak.example");
    ext.extend_from_slice(&udp(51820, 51820, &wg(4, 1452)));
    assert_eq!(
        classes(&[ip6("2001:db8::1", "2001:db8:1::2", 60, &ext)]),
        [violation(Reason::CanaryMarker)]
    );
}

#[test]
fn compressed_dns_canary_precedes_wireguard_on_port_53() {
    let p = Policy::from_toml(&POLICY.replace(":51820", ":53")).unwrap();
    let mut dns = compressed_dns();
    dns[..4].copy_from_slice(&[1, 0, 0, 0]);
    dns.resize(148, 0);
    let r = classify(
        &capture(101, &[ip4(LOCAL, PEER, 17, &udp(53, 53, &dns))]),
        &p,
        1,
    )
    .unwrap();
    assert_eq!(r.packets[0].class, violation(Reason::CanaryMarker));
}

fn wireguard_only_policy() -> Policy {
    Policy::from_toml(POLICY.split("[[host_allow]]").next().unwrap()).unwrap()
}

#[test]
fn wireguard_icmp_errors_require_the_exact_reverse_listed_tuple() {
    let policy = wireguard_only_policy();
    let quote = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &wg(4, 32)));
    let mut error = icmp(3, &quote); // Complete quotation.
    error[1] = 3;
    let allowed_error = ip4(LOCAL, PEER, 1, &error);
    let report = classify(&capture(101, &[allowed_error]), &policy, 10).unwrap();
    assert_eq!(report.packets[0].class, allowed("wireguard_error[0]"));
    // Echo, reversed outer direction, unknown gateway port, and a quotation
    // going gateway -> peer must not be accepted by this exception.
    let invalid = [
        ip4(LOCAL, PEER, 1, &icmp(8, &quote)),
        ip4(PEER, LOCAL, 1, &error),
        ip4(
            LOCAL,
            PEER,
            1,
            &icmp(3, &ip4(PEER, LOCAL, 17, &udp(51820, 57794, &[]))),
        ),
        ip4(
            LOCAL,
            PEER,
            1,
            &icmp(3, &ip4(LOCAL, PEER, 17, &udp(51820, 51820, &[]))),
        ),
    ];
    let report = classify(&capture(101, &invalid), &policy, 10).unwrap();
    assert!(
        report
            .packets
            .iter()
            .all(|p| p.class == violation(Reason::NotAllowListed))
    );

    let policy = Policy::from_toml(&format!(
        "{}\n[[wireguard]]\ngateway='192.0.2.1:57794'\npeer='198.51.100.2:51820'\n",
        POLICY.split("[[host_allow]]").next().unwrap()
    ))
    .unwrap();
    let old_port = ip4(
        LOCAL,
        PEER,
        1,
        &icmp(3, &ip4(PEER, LOCAL, 17, &udp(51820, 57794, &[]))),
    );
    let report = classify(&capture(101, &[old_port]), &policy, 10).unwrap();
    assert_eq!(report.packets[0].class, allowed("wireguard_error[2]"));
}

#[test]
fn wireguard_icmp_error_with_forbidden_inner_address_still_violates() {
    let option = [7, 7, 4, CLIENT[0], CLIENT[1], CLIENT[2], CLIENT[3], 0];
    let quotations = [
        ip4(PEER, CLIENT, 17, &udp(51820, 51820, &[])),
        // Even an exact allowed tuple cannot hide a forbidden option address.
        with_options(ip4(PEER, LOCAL, 17, &udp(51820, 51820, &[])), &option),
    ];
    for quotation in quotations {
        let error = ip4(LOCAL, PEER, 1, &icmp(3, &quotation));
        let report = classify(&capture(101, &[error]), &wireguard_only_policy(), 10).unwrap();
        assert_eq!(
            report.packets[0].class,
            violation(Reason::ForbiddenAddress {
                addr: Ipv4Addr::from(CLIENT).into(),
                location: Location::Quoted,
            })
        );
    }
}

#[test]
fn wireguard_icmp_error_to_non_peer_still_violates() {
    let quote = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &[]));
    let error = ip4(LOCAL, [198, 51, 100, 3], 1, &icmp(3, &quote));
    let report = classify(&capture(101, &[error]), &wireguard_only_policy(), 10).unwrap();
    assert_eq!(report.packets[0].class, violation(Reason::NotAllowListed));
}

#[test]
fn wireguard_icmpv6_errors_require_the_exact_reverse_listed_tuple() {
    let local = "2001:db8::1";
    let peer = "2001:db8:1::2";
    let quote = ip6(peer, local, 17, &udp(51820, 51820, &wg(4, 32)));
    let allowed_error = ip6(local, peer, 58, &icmp(1, &quote));
    let forbidden = ip6(
        local,
        peer,
        58,
        &icmp(1, &ip6(peer, "2001:db8:99::2", 17, &udp(51820, 51820, &[]))),
    );
    let non_peer = ip6(local, "2001:db8:1::3", 58, &icmp(1, &quote));
    let report = classify(
        &capture(101, &[allowed_error, forbidden, non_peer]),
        &wireguard_only_policy(),
        10,
    )
    .unwrap();
    assert_eq!(report.packets[0].class, allowed("wireguard_error[1]"));
    assert_eq!(
        report.packets[1].class,
        violation(Reason::ForbiddenAddress {
            addr: v6("2001:db8:99::2").into(),
            location: Location::Quoted,
        })
    );
    assert_eq!(report.packets[2].class, violation(Reason::NotAllowListed));
}

#[test]
fn heartbeat_allowance_is_only_one_host_https_tuple() {
    let policy = Policy::from_toml(&format!("heartbeat = \"198.51.100.2:443\"\n{POLICY}")).unwrap();
    let hello = b"\x16\x03\x01\x00\x01\x01";
    let packets = [
        ip4(LOCAL, PEER, 6, &tcp(40123, 443, hello)),
        ip4(PEER, LOCAL, 6, &tcp(443, 40123, b"")),
        ip4([192, 0, 2, 20], PEER, 6, &tcp(40123, 443, hello)),
        ip4(LOCAL, [198, 51, 100, 3], 6, &tcp(40123, 443, hello)),
        ip4(LOCAL, PEER, 6, &tcp(40123, 444, hello)),
        ip4(CLIENT, PEER, 6, &tcp(40123, 443, hello)),
    ];
    let report = classify(&capture(101, &packets), &policy, 20).unwrap();
    assert_eq!(report.packets[0].class, allowed("heartbeat"));
    assert_eq!(report.packets[1].class, allowed("heartbeat"));
    assert!(
        report.packets[2..]
            .iter()
            .all(|p| matches!(p.class, Class::Violation(_)))
    );
    let endpoint = "198.51.100.2:443".parse().unwrap();
    let host = Ipv4Addr::from(LOCAL).into();
    assert_eq!(
        xtask::pcap::heartbeat_hellos(&capture(101, &packets[..2]), host, endpoint)
            .unwrap()
            .len(),
        1
    );
    assert!(xtask::pcap::heartbeat_hellos(&capture(101, &packets[2..3]), host, endpoint).is_err());
    for endpoint in ["198.51.100.2:444", "10.99.0.2:443"] {
        assert!(Policy::from_toml(&format!("heartbeat = {endpoint:?}\n{POLICY}")).is_err());
    }
}

#[test]
fn heartbeat_deadline_oracle_detects_application_data_without_client_hello() {
    let application = b"\x17\x03\x03\x00\x06opaque";
    let packets = [
        ip4(LOCAL, PEER, 6, &tcp(40123, 443, application)),
        ip4(LOCAL, PEER, 6, &tcp(40123, 443, b"")),
        ip4(PEER, LOCAL, 6, &tcp(443, 40123, application)),
    ];
    let bytes = capture(101, &packets);
    let host = Ipv4Addr::from(LOCAL).into();
    let endpoint = "198.51.100.2:443".parse().unwrap();
    assert!(
        xtask::pcap::heartbeat_hellos(&bytes, host, endpoint)
            .unwrap()
            .is_empty()
    );
    let payloads = xtask::pcap::heartbeat_payloads(&bytes, host, endpoint).unwrap();
    assert_eq!(payloads.len(), 1);
    let late_deadline = &payloads[0];
    assert!(payloads.iter().any(|time| (time.seconds, time.nanoseconds)
        >= (late_deadline.seconds, late_deadline.nanoseconds)));
    let wrong_source = capture(101, &[ip4(CLIENT, PEER, 6, &tcp(40123, 443, application))]);
    assert!(xtask::pcap::heartbeat_payloads(&wrong_source, host, endpoint).is_err());
}

#[test]
fn alert_identity_mark_rejects_client_syn_even_after_uplink_source_translation() {
    let policy = Policy::from_toml(&format!(
        "heartbeat = \"198.51.100.2:443\"\nheartbeat_dscp = 56\n{POLICY}"
    ))
    .unwrap();
    let client_syn = ip4(LOCAL, PEER, 6, &tcp(40123, 443, b""));
    let mut delivery_syn = client_syn.clone();
    delivery_syn[1] = 56 << 2;
    let report = classify(&capture(101, &[client_syn, delivery_syn]), &policy, 20).unwrap();
    assert_eq!(report.packets[0].class, violation(Reason::NotAllowListed));
    assert_eq!(report.packets[1].class, allowed("heartbeat"));
}
