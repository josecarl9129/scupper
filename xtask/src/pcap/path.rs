//! Directional evidence on decrypted tunnel captures. These predicates never
//! relax the uplink policy: client addresses and ICMP quotations stay forbidden there.
use super::{Error, Observed, decode, observe};
use std::net::IpAddr;

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct Flow {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub ports: Option<(u16, u16)>,
}
impl Flow {
    fn matches(&self, packet: &Observed) -> bool {
        packet.source == self.source
            && packet.destination == self.destination
            && packet.protocol == self.protocol
            && self.ports.is_none_or(|(a, b)| {
                packet.payload.get(..4)
                    == Some([a.to_be_bytes(), b.to_be_bytes()].concat().as_slice())
            })
    }
}
fn error(message: &str) -> Error {
    Error::Capture(message.into())
}
pub(crate) fn attempted(bytes: &[u8], flows: &[Flow]) -> Result<(), Error> {
    let packets = observe(bytes)?;
    if flows
        .iter()
        .any(|flow| !packets.iter().any(|packet| flow.matches(packet)))
    {
        return Err(error("probe missing at protected ingress"));
    }
    Ok(())
}
/// Require attempted packets at the sending interface and none at the protected
/// destination. Independent service controls make both captures non-blind.
pub(crate) fn dropped(ingress: &[u8], destination: &[u8], flows: &[Flow]) -> Result<(), Error> {
    let ingress = observe(ingress)?;
    let destination = observe(destination)?;
    for flow in flows {
        if !ingress.iter().any(|p| flow.matches(p)) {
            return Err(error("drop trial lacks ingress attempt"));
        }
        if destination.iter().any(|p| flow.matches(p)) {
            return Err(error("forbidden delivery at destination"));
        }
    }
    Ok(())
}
/// M2 permits echo replies from the gateway; DNS/API listeners are M4. Require
/// the request and reply at wg0 and reject gateway-local traffic on the exit.
pub(crate) fn gateway(
    wg: &[u8],
    exit: &[u8],
    gateway: IpAddr,
    client: IpAddr,
) -> Result<(), Error> {
    let wg = observe(wg)?;
    let exit = observe(exit)?;
    let echo = |p: &Observed, source, destination, kind| {
        p.source == source
            && p.destination == destination
            && p.protocol == 1
            && p.payload.get(..2) == Some(&[kind, 0])
    };
    if !wg.iter().any(|p| echo(p, client, gateway, 8))
        || !wg.iter().any(|p| echo(p, gateway, client, 0))
    {
        return Err(error("gateway echo request/reply missing at wg0"));
    }
    if wg
        .iter()
        .any(|p| p.source == gateway && !echo(p, gateway, client, 0))
    {
        return Err(error("unexpected gateway service reply"));
    }
    if exit
        .iter()
        .any(|p| p.source == gateway || p.destination == gateway || p.destination == client)
    {
        return Err(error("gateway-local traffic reached exit"));
    }
    Ok(())
}
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct Pmtu {
    pub router: IpAddr,
    pub flow: Flow,
    pub mtu: u32,
}
fn pmtu(packet: &Observed, expected: &Pmtu) -> bool {
    let v6 = expected.flow.source.is_ipv6();
    let data = &packet.payload;
    if packet.source != expected.router
        || packet.destination != expected.flow.source
        || packet.protocol != if v6 { 58 } else { 1 }
        || data.get(..2) != Some(if v6 { &[2, 0] } else { &[3, 4] })
    {
        return false;
    }
    let Some(header) = data.get(..8) else {
        return false;
    };
    let mtu = if v6 {
        u32::from_be_bytes([header[4], header[5], header[6], header[7]])
    } else {
        u32::from(u16::from_be_bytes([header[6], header[7]]))
    };
    if mtu != expected.mtu {
        return false;
    }
    let Ok(quoted) = decode::ip(&data[8..], true) else {
        return false;
    };
    quoted.fragment.is_none()
        && quoted.src == expected.flow.source
        && quoted.dst == expected.flow.destination
        && quoted.proto == expected.flow.protocol
        && quoted.payload.len() >= 8
        && expected.flow.ports.is_some_and(|(a, b)| {
            quoted.payload[..4] == [a.to_be_bytes(), b.to_be_bytes()].concat()
        })
}
/// Require the oversized datagram at its sender and permit only PMTU ICMP
/// addressed back to that sender, quoting the exact measured flow.
pub(crate) fn pmtu_sender(bytes: &[u8], expected: &Pmtu) -> Result<(), Error> {
    let packets = observe(bytes)?;
    if !packets.iter().any(|packet| {
        expected.flow.matches(packet)
            && packet.payload.len() + if packet.source.is_ipv4() { 20 } else { 40 }
                > usize::try_from(expected.mtu).unwrap_or(usize::MAX)
    }) {
        return Err(error("oversized datagram missing at sender"));
    }
    let mut seen = false;
    for packet in &packets {
        if matches!(packet.protocol, 1 | 58) {
            if !pmtu(packet, expected) {
                return Err(error("ICMP took an unapproved path or quoted another flow"));
            }
            seen = true;
        }
    }
    if !seen {
        return Err(error("sender did not receive PMTU error"));
    }
    Ok(())
}

/// Reject PMTU ICMP and delivery of the oversized measured flow, after NAT.
pub(crate) fn pmtu_receiver(bytes: &[u8], flow: &Flow) -> Result<(), Error> {
    for packet in observe(bytes)? {
        if matches!(packet.protocol, 1 | 58) {
            return Err(error("PMTU ICMP reached receiver"));
        }
        // Capture begins after the small control has been received. Any packet
        // on this tuple is measured-flow delivery, including its first fragment.
        if flow.matches(&packet) {
            return Err(error("oversized PMTU datagram reached receiver"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    fn ip(src: &str, dst: &str, proto: u8, body: &[u8]) -> Vec<u8> {
        let src: IpAddr = src.parse().unwrap();
        let dst: IpAddr = dst.parse().unwrap();
        let mut out = match (src, dst) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mut p = vec![0; 20];
                p[0] = 0x45;
                p[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
                p[8] = 64;
                p[9] = proto;
                p[12..16].copy_from_slice(&a.octets());
                p[16..20].copy_from_slice(&b.octets());
                p
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mut p = vec![0; 40];
                p[0] = 0x60;
                p[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
                p[6] = proto;
                p[7] = 64;
                p[8..24].copy_from_slice(&a.octets());
                p[24..40].copy_from_slice(&b.octets());
                p
            }
            _ => unreachable!(),
        };
        out.extend(body);
        out
    }
    fn capture(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        out.extend([0; 8]);
        out.extend(65535_u32.to_le_bytes());
        out.extend(101_u32.to_le_bytes());
        for packet in packets {
            out.extend([0; 8]);
            for _ in 0..2 {
                out.extend((packet.len() as u32).to_le_bytes());
            }
            out.extend(packet);
        }
        out
    }
    #[test]
    fn gateway_replies_only_on_client_path_and_service_replies_rejected() {
        let request = ip("10.99.0.2", "10.99.0.1", 1, &[8, 0, 0, 0, 1, 2, 0, 1]);
        let reply = ip("10.99.0.1", "10.99.0.2", 1, &[0, 0, 0, 0, 1, 2, 0, 1]);
        let g = "10.99.0.1".parse().unwrap();
        let c = "10.99.0.2".parse().unwrap();
        assert!(
            gateway(
                &capture(&[request.clone(), reply.clone()]),
                &capture(&[]),
                g,
                c
            )
            .is_ok()
        );
        assert!(
            gateway(
                &capture(std::slice::from_ref(&request)),
                &capture(&[]),
                g,
                c
            )
            .is_err()
        );
        assert!(
            gateway(
                &capture(&[request.clone(), reply.clone()]),
                &capture(std::slice::from_ref(&reply)),
                g,
                c
            )
            .is_err()
        );
        let service = ip("10.99.0.1", "10.99.0.2", 17, &[0, 53, 0, 1, 0, 8, 0, 0]);
        assert!(gateway(&capture(&[request, reply, service]), &capture(&[]), g, c).is_err());
    }
    #[test]
    fn isolation_requires_attempt_and_detects_any_delivery() {
        let flow = Flow {
            source: "10.99.0.3".parse().unwrap(),
            destination: "10.99.0.2".parse().unwrap(),
            protocol: 1,
            ports: None,
        };
        let request = ip("10.99.0.3", "10.99.0.2", 1, &[8, 0, 0, 0, 0, 0, 0, 1]);
        assert!(
            dropped(
                &capture(std::slice::from_ref(&request)),
                &capture(&[]),
                std::slice::from_ref(&flow)
            )
            .is_ok()
        );
        assert!(dropped(&capture(&[]), &capture(&[]), std::slice::from_ref(&flow)).is_err());
        assert!(
            dropped(
                &capture(std::slice::from_ref(&request)),
                &capture(&[request]),
                &[flow]
            )
            .is_err()
        );
    }
    #[test]
    fn pmtu_v4_v6_only_toward_sender_and_for_exact_flow() {
        for (router, sender, destination, proto, kind, code) in [
            ("10.99.0.1", "10.99.0.2", "192.0.2.6", 1, 3, 4),
            ("fd00:99::1", "fd00:99::2", "2001:db8:2::1", 58, 2, 0),
        ] {
            let expected = Pmtu {
                router: router.parse().unwrap(),
                flow: Flow {
                    source: sender.parse().unwrap(),
                    destination: destination.parse().unwrap(),
                    protocol: 17,
                    ports: Some((40020, 8080)),
                },
                mtu: 1280,
            };
            let mut udp = vec![0; 1400 - if proto == 1 { 20 } else { 40 }];
            udp[..4].copy_from_slice(&[0x9c, 0x54, 0x1f, 0x90]);
            let len = udp.len() as u16;
            udp[4..6].copy_from_slice(&len.to_be_bytes());
            let original = ip(sender, destination, 17, &udp);
            let mut quote = original.clone();
            quote.truncate(if proto == 1 { 28 } else { 48 });
            let mut body = vec![kind, code, 0, 0, 0, 0, 5, 0];
            body.extend(&quote);
            let valid = ip(router, sender, proto, &body);
            assert!(pmtu_sender(&capture(&[original.clone(), valid.clone()]), &expected).is_ok());
            // A correct sender error cannot excuse oversized delivery, including
            // the NATed receiver tuple in either address family.
            let received = Flow {
                source: if proto == 1 {
                    "10.2.0.2".parse().unwrap()
                } else {
                    "2001:db8:2::2".parse().unwrap()
                },
                ..expected.flow.clone()
            };
            let delivered = ip(&received.source.to_string(), destination, 17, &udp);
            assert!(pmtu_receiver(&capture(&[]), &received).is_ok());
            assert!(pmtu_receiver(&capture(&[delivered]), &received).is_err());
            if proto == 1 {
                let mut fragment = ip(&received.source.to_string(), destination, 17, &udp[..1024]);
                fragment[6] = 0x20; // First IPv4 fragment, smaller than the path MTU.
                assert!(pmtu_receiver(&capture(&[fragment]), &received).is_err());
            }
            assert!(pmtu_receiver(&capture(std::slice::from_ref(&valid)), &received).is_err());
            assert!(pmtu_sender(&capture(std::slice::from_ref(&valid)), &expected).is_err());
            let echo = ip(
                router,
                sender,
                proto,
                &[if proto == 1 { 0 } else { 129 }, 0, 0, 0, 0, 0, 0, 0],
            );
            assert!(
                pmtu_sender(
                    &capture(&[original.clone(), valid.clone(), echo]),
                    &expected
                )
                .is_err()
            );
            for bad in [
                ip(router, destination, proto, &body),
                ip(destination, sender, proto, &body),
            ] {
                assert!(
                    pmtu_sender(&capture(&[original.clone(), valid.clone(), bad]), &expected)
                        .is_err()
                );
            }
            for at in [0, 1, 7, 8 + if proto == 1 { 12 } else { 8 }, body.len() - 8] {
                let mut bad = body.clone();
                bad[at] ^= 1;
                assert!(
                    pmtu_sender(
                        &capture(&[original.clone(), ip(router, sender, proto, &bad)]),
                        &expected
                    )
                    .is_err()
                );
            }
            assert!(pmtu_sender(&capture(&[]), &expected).is_err());
            let policy = super::super::Policy::from_toml(
                "uplink_addrs=['198.51.100.2']\nforbidden_addrs=['10.99.0.0/24','fd00:99::/64']\n",
            )
            .unwrap();
            assert!(
                super::super::classify(&capture(&[valid]), &policy, 10)
                    .unwrap()
                    .violation_count
                    > 0
            );
        }
    }
}
