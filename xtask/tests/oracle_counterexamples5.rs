//! Fifth-round review counterexamples for the `WireGuard` ICMP-error exception.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
use std::net::Ipv6Addr;
use xtask::pcap::{Class, Policy, Reason, classify};
const LOCAL: [u8; 4] = [192, 0, 2, 1];
const PEER: [u8; 4] = [198, 51, 100, 2];
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
fn icmp(kind: u8, code: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, code, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(body);
    out
}
fn class(packet: Vec<u8>) -> Class {
    classify(&capture(&[packet]), &Policy::from_toml(POLICY).unwrap(), 10)
        .unwrap()
        .packets[0]
        .class
        .clone()
}
fn quote() -> Vec<u8> {
    // Quote four bytes of a valid 32-byte data message, at the quotation limit.
    // A complete four-byte type-4 datagram is invalid under the framing rule.
    let mut body = vec![0; 32];
    body[0] = 4;
    let mut packet = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &body));
    packet.truncate(32);
    packet
}
#[test]
fn control_port_unreachable_is_admitted() {
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &quote()));
    assert_eq!(class(error), Class::Allowed("wireguard_error[0]".into()));
}
#[test]
fn control_truncated_udp_quotation_violates() {
    let q = quote();
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q[..24]));
    assert!(matches!(class(error), Class::Violation(_)));
}
#[test]
fn f5_1_trailing_bytes_after_quoted_datagram_hide_a_client_header() {
    let mut body = ip4(PEER, LOCAL, 17, &udp(51820, 51820, &[]));
    assert_eq!(body.len(), 28);
    body.extend_from_slice(&ip4(CLIENT, INTERNET, 6, &[0; 20]));
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &body));
    assert!(
        matches!(class(error.clone()), Class::Violation(_)),
        "client header in quotation trailer admitted: {:?}",
        class(error)
    );
}
#[test]
fn f5_2_icmp_redirect_is_not_a_wireguard_error() {
    let mut redirect = icmp(5, 1, &quote());
    redirect[4..8].copy_from_slice(&[192, 0, 2, 254]);
    let packet = ip4(LOCAL, PEER, 1, &redirect);
    assert!(
        matches!(class(packet.clone()), Class::Violation(_)),
        "redirect admitted: {:?}",
        class(packet)
    );
}
#[test]
fn f5_3_quoted_payload_must_be_wireguard_shaped() {
    let q = ip4(
        PEER,
        LOCAL,
        17,
        &udp(51820, 51820, b"GET / HTTP/1.1\r\nHost: x\r\n"),
    );
    let error = ip4(LOCAL, PEER, 1, &icmp(3, 3, &q));
    assert!(
        matches!(
            class(error.clone()),
            Class::Violation(Reason::MalformedWireGuard | Reason::NotAllowListed)
        ),
        "plaintext quotation admitted: {:?}",
        class(error)
    );
}
#[test]
fn f5_1_v6_trailing_bytes_after_quoted_datagram_hide_a_client_header() {
    let mut body = ip6("2001:db8:1::2", "2001:db8::1", 17, &udp(51820, 51820, &[]));
    body.extend_from_slice(&ip6("2001:db8:99::2", "2001:db8:5::1", 6, &[0; 20]));
    let error = ip6("2001:db8::1", "2001:db8:1::2", 58, &icmp(1, 4, &body));
    assert!(
        matches!(class(error.clone()), Class::Violation(_)),
        "client v6 header in quotation trailer admitted: {:?}",
        class(error)
    );
}
fn wrapped(v6: bool, kind: u8, body: &[u8], cut: Option<usize>) -> Vec<u8> {
    let datagram = udp(51820, 51820, body);
    let mut inner = if v6 {
        ip6("2001:db8:1::2", "2001:db8::1", 17, &datagram)
    } else {
        ip4(PEER, LOCAL, 17, &datagram)
    };
    if let Some(len) = cut {
        inner.truncate(if v6 { 48 + len } else { 28 + len });
    }
    let error = icmp(kind, 0, &inner);
    if v6 {
        ip6("2001:db8::1", "2001:db8:1::2", 58, &error)
    } else {
        ip4(LOCAL, PEER, 1, &error)
    }
}
#[test]
fn ipv4_and_ipv6_quoted_framing_and_truncation_limits() {
    for v6 in [false, true] {
        let kind = if v6 { 1 } else { 3 };
        for (message, len) in [(1, 148), (2, 92), (3, 64), (4, 32), (4, 48)] {
            let mut body = vec![0; len];
            body[0] = message;
            for cut in [None, Some(0), Some(4), Some(len - 1)] {
                assert!(
                    matches!(class(wrapped(v6, kind, &body, cut)), Class::Allowed(_)),
                    "v6={v6} message={message} len={len} cut={cut:?}"
                );
            }
            for cut in [Some(1), Some(2), Some(3)] {
                assert!(matches!(
                    class(wrapped(v6, kind, &body, cut)),
                    Class::Violation(_)
                ));
            }
            for bad_len in [len - 1, len + 1] {
                let mut bad = vec![0; bad_len];
                bad[0] = message;
                for cut in [None, Some(4)] {
                    assert!(matches!(
                        class(wrapped(v6, kind, &bad, cut)),
                        Class::Violation(_)
                    ));
                }
            }
            body[1] = 1;
            assert!(matches!(
                class(wrapped(v6, kind, &body, Some(4))),
                Class::Violation(_)
            ));
        }
        for body in [
            b"GET / HTTP/1.1\r\nHost: x\r\n".as_slice(),
            &[0, 0, 0, 0],
            &[5, 0, 0, 0],
        ] {
            assert!(matches!(
                class(wrapped(v6, kind, body, None)),
                Class::Violation(_)
            ));
        }
    }
}
#[test]
fn exception_accepts_only_error_types() {
    for v6 in [false, true] {
        for kind in 0..=255 {
            let expected = if v6 {
                matches!(kind, 1..=4)
            } else {
                matches!(kind, 3 | 11 | 12)
            };
            assert_eq!(
                matches!(class(wrapped(v6, kind, &[], None)), Class::Allowed(_)),
                expected,
                "v6={v6} type={kind}"
            );
        }
    }
}
