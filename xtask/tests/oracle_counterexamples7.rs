//! Seventh-round review regressions for the `WireGuard` ICMP-error exception.
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
fn at_limit(v6: bool, body: &[u8]) -> Vec<u8> {
    let datagram = udp(51820, 51820, body);
    if v6 {
        let mut q = ip6("2001:db8:1::2", "2001:db8::1", 17, &datagram);
        q.truncate(1232);
        assert_eq!(q.len(), 1232);
        ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(1, 4, &q))
    } else {
        let mut q = ip4(PEER, LOCAL, 17, &datagram);
        q.truncate(548);
        assert_eq!(q.len(), 548);
        ip4(LOCAL, PEER, 1, &icmp(3, 3, &q))
    }
}

/// Exact-limit quotations reach framing validation rather than the truncation guard.
#[test]
fn f7_framing_is_enforced_at_the_quotation_limit() {
    for v6 in [false, true] {
        let mut plaintext = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
        plaintext.resize(1452, b'a');
        let mut unknown = vec![0xa5; 1452];
        unknown[..4].copy_from_slice(&[5, 0, 0, 0]);
        let mut reserved = vec![0xa5; 1452];
        reserved[..4].copy_from_slice(&[4, 0, 1, 0]);
        let mut long_init = vec![0xa5; 1452];
        long_init[..4].copy_from_slice(&[1, 0, 0, 0]);
        for body in [plaintext, unknown, reserved, long_init] {
            assert_eq!(
                class(at_limit(v6, &body)),
                Class::Violation(xtask::pcap::Reason::MalformedWireGuard),
                "v6={v6} first={:?}",
                &body[..4]
            );
        }
        let mut good = vec![0xa5; 1452];
        good[..4].copy_from_slice(&[4, 0, 0, 0]);
        assert_eq!(
            class(at_limit(v6, &good)),
            Class::Allowed(format!("wireguard_error[{}]", usize::from(v6)))
        );
    }
}

#[test]
fn f7_trailer_padded_to_limit_is_not_admitted() {
    let mut body = vec![0; 32];
    body[0] = 4;
    let mut q = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &body));
    q.extend_from_slice(&ip4(CLIENT, INTERNET, 6, &[]));
    q.resize(548, 0);
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert!(matches!(class(error), Class::Violation(_)));
}

#[test]
fn f7_header_only_prefix_of_long_datagram_violates() {
    for len in [32, 1452] {
        let mut body = vec![0; len];
        body[0] = 4;
        let mut q = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &body));
        q.truncate(28);
        let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
        assert!(matches!(class(error), Class::Violation(_)));
    }
}

#[test]
fn short_udp_quotations_require_explicit_host_allow() {
    for len in 0..4 {
        for (peer, allowed) in [(RESOLVER, true), (PEER, false)] {
            let mut q = ip4(peer, LOCAL, 17, &udp(51820, 51820, &[0; 32]));
            q.truncate(20 + len);
            let error = ip4(LOCAL, peer, 1, &icmp(3, 3, &q));
            let expected = if allowed {
                Class::Allowed("host_allow[0]".into())
            } else {
                Class::Violation(xtask::pcap::Reason::NotAllowListed)
            };
            assert_eq!(class(error), expected, "len={len}, allowed={allowed}");
        }
    }
}
