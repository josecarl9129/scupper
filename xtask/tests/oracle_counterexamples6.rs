//! Sixth-round review counterexamples for the `WireGuard` ICMP-error exception.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
use std::net::Ipv6Addr;
use xtask::pcap::{Class, Policy, classify};

const LOCAL: [u8; 4] = [192, 0, 2, 1];
const PEER: [u8; 4] = [198, 51, 100, 2];
const RESOLVER: [u8; 4] = [192, 0, 2, 53];
const CLIENT: [u8; 4] = [10, 99, 0, 2];
const INTERNET: [u8; 4] = [203, 0, 113, 99];
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
proto = "icmp"
remote_addr = "192.0.2.53/32"
types = [3]
"#;

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
fn ip6(src: &str, dst: &str, proto: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 40];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    out[6] = proto;
    out[7] = 255;
    out[8..24].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
    out[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
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
fn icmp(kind: u8, code: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, code, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(body);
    out
}
fn capture(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(&4_u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535_u32.to_le_bytes());
    out.extend_from_slice(&101_u32.to_le_bytes());
    for p in packets {
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}
fn class(packet: Vec<u8>) -> Class {
    classify(&capture(&[packet]), &Policy::from_toml(POLICY).unwrap(), 10)
        .unwrap()
        .packets[0]
        .class
        .clone()
}
/// Linux wg pads plaintext to min(ALIGN(len, 16), mtu) (send.c,
/// `calculate_skb_padding`). A full 1420-byte packet on an MTU-1420 peer
/// becomes a 16 + 1420 + 16 = 1452-byte data message: not 16-aligned.
fn mtu_clamped_data() -> Vec<u8> {
    let mut body = vec![0xa5; 1452];
    body[..4].copy_from_slice(&[4, 0, 0, 0]);
    body
}

#[test]
fn control_aligned_data_message_at_v4_quotation_limit_is_admitted() {
    let mut body = vec![0xa5; 1440];
    body[..4].copy_from_slice(&[4, 0, 0, 0]);
    let mut q = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &body));
    q.truncate(548); // 576 - 20 - 8: icmp_send's quotation limit
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert_eq!(class(error), Class::Allowed("wireguard_error[0]".into()));
}

/// F6-2: legitimate kernel port-unreachable quoting an MTU-clamped data
/// message (the L4 remote-sender scenario with retransmit coalescing).
#[test]
fn f6_2_v4_mtu_clamped_data_message_quotation_is_admitted() {
    let mut q = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &mtu_clamped_data()));
    q.truncate(548);
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert_eq!(class(error), Class::Allowed("wireguard_error[0]".into()));
}
#[test]
fn f6_2_v6_mtu_clamped_data_message_quotation_is_admitted() {
    let mut q = ip6(
        "2001:db8:1::2",
        "2001:db8::1",
        17,
        &udp(51820, 51820, &mtu_clamped_data()),
    );
    q.truncate(1232); // 1280 - 40 - 8
    let error = ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(1, 4, &q));
    assert_eq!(class(error), Class::Allowed("wireguard_error[1]".into()));
}

/// F6-3: ordinary UDP quotations must still reach `host_allow`.
#[test]
fn f6_3_non_wireguard_icmp_error_still_reaches_host_allow() {
    // Gateway port-unreachable for a late DNS reply from the resolver.
    let late_reply = ip4(RESOLVER, LOCAL, 17, &udp(53, 40000, &[0x12; 40]));
    let error = ip4(LOCAL, RESOLVER, 1, &icmp(3, 3, &late_reply));
    assert_eq!(class(error), Class::Allowed("host_allow[0]".into()));
}

/// F6-4: an unknown option carries a full client->internet IPv4 header.
#[test]
fn f6_4_quoted_ipv4_unknown_option_hides_client_header() {
    let hidden = ip4(CLIENT, INTERNET, 6, &[]);
    assert_eq!(hidden.len(), 20);
    let mut option = vec![0x9e, 24, 0, 0]; // unknown kind, len 24
    option.extend_from_slice(&hidden);
    assert_eq!(option.len(), 24);
    let datagram = udp(51820, 51820, &[]);
    let mut q = vec![0; 20];
    q[0] = 0x40 | ((20 + option.len()) / 4) as u8;
    q[2..4].copy_from_slice(&((20 + option.len() + datagram.len()) as u16).to_be_bytes());
    q[8] = 64;
    q[9] = 17;
    q[12..16].copy_from_slice(&PEER);
    q[16..20].copy_from_slice(&LOCAL);
    q.extend_from_slice(&option);
    q.extend_from_slice(&datagram);
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert!(
        matches!(class(error.clone()), Class::Violation(_)),
        "client header in quoted IPv4 option admitted: {:?}",
        class(error)
    );
}

/// F6-5: a 148-byte initiation quoted to 100 bytes (not 548) must violate.
#[test]
fn f6_5_truncation_away_from_quotation_limit_violates() {
    let mut body = vec![0; 148];
    body[0] = 1;
    let mut q = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &body));
    q.truncate(28 + 100);
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert!(
        matches!(class(error.clone()), Class::Violation(_)),
        "mid-message truncation admitted: {:?}",
        class(error)
    );
}

/// F6-6: header-only quotations must not bypass length validation.
#[test]
fn f6_6_header_only_quotation_with_impossible_length_violates() {
    let mut q = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &[0; 37]));
    q.truncate(28);
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert!(
        matches!(class(error.clone()), Class::Violation(_)),
        "impossible claimed length admitted: {:?}",
        class(error)
    );
}

#[test]
fn ipv6_opaque_options_cannot_enter_the_wireguard_exception() {
    for proto in [0, 60] {
        for option in [1, 0x1e] {
            // PadN and unknown options can both carry an opaque client header.
            let mut extension = vec![17, 3, option, 28];
            extension.extend_from_slice(&ip4(CLIENT, INTERNET, 6, &[]));
            extension.resize(32, 0);
            extension.extend_from_slice(&udp(51820, 51820, &[]));
            let q = ip6("2001:db8:1::2", "2001:db8::1", proto, &extension);
            let error = ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(1, 4, &q));
            assert!(matches!(class(error), Class::Violation(_)));
        }
    }
}

#[test]
fn partial_quotations_require_the_exact_family_limit() {
    for v6 in [false, true] {
        let limit = if v6 { 1232 } else { 548 };
        for cut in [limit - 1, limit, limit + 1] {
            let datagram = udp(51820, 51820, &mtu_clamped_data());
            let mut q = if v6 {
                ip6("2001:db8:1::2", "2001:db8::1", 17, &datagram)
            } else {
                ip4(PEER, LOCAL, 17, &datagram)
            };
            q.truncate(cut);
            let error = if v6 {
                ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(1, 4, &q))
            } else {
                ip4(LOCAL, PEER, 1, &icmp(3, 3, &q))
            };
            assert_eq!(matches!(class(error), Class::Allowed(_)), cut == limit);
        }
    }
}

#[test]
fn non_wireguard_length_disagreement_still_reaches_host_allow() {
    let mut q = ip4(RESOLVER, LOCAL, 17, &udp(53, 40000, &[0x12; 40]));
    q[24..26].copy_from_slice(&8_u16.to_be_bytes());
    let error = ip4(LOCAL, RESOLVER, 1, &icmp(3, 3, &q));
    assert_eq!(class(error), Class::Allowed("host_allow[0]".into()));
}
