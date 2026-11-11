//! Pure, default-deny classic-pcap oracle. See `xtask/README.md` for the policy.

mod control;
mod decode;
mod dns;
pub(crate) mod path;
mod policy;
mod reader;

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use serde::Serialize;

use decode::{Fragment, Ip, Key, Link};
pub use policy::Policy;

/// Invalid policy or capture container. Packet decoding failures instead enter the report.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A policy could not be parsed or validated.
    #[error("policy: {0}")]
    Policy(String),
    /// A classic-pcap container is invalid or incomplete.
    #[error("pcap: {0}")]
    Capture(String),
}

/// The address's position in an IP packet or ICMP error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Location {
    /// An outer IP or ARP address (also an ND target).
    Outer,
    /// An address in the IP packet quoted by ICMP.
    Quoted,
}

/// Fragment sets that cannot safely be classified as a datagram.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum FragmentError {
    /// A set is missing a first, last, or intermediate fragment at EOF.
    Incomplete,
    /// Two fragment ranges overlap, including exact duplicates.
    Overlap,
    /// A fragment's size, alignment or terminal length is inconsistent.
    Invalid,
}

/// A single, fail-closed packet classification reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Reason {
    /// No explicit rule matched.
    NotAllowListed,
    /// Fewer records than the policy's positive-evidence minimum.
    EmptyCapture,
    /// An expected allowed class or rule was not observed.
    ExpectedClassMissing(String),
    /// Bytes beyond the IP length exceeded permitted link-layer padding.
    TrailingData,
    /// A client or exit address appeared, regardless of matching allow rules.
    ForbiddenAddress {
        /// The disallowed address.
        addr: IpAddr,
        /// Whether this was the outer or quoted packet.
        #[serde(rename = "where")]
        location: Location,
    },
    /// A marker appeared in packet bytes or an expanded DNS name.
    CanaryMarker,
    /// Configured `WireGuard` endpoints carried a malformed message.
    MalformedWireGuard,
    /// Fragment reassembly failed.
    Fragment(FragmentError),
    /// A required packet header or declared packet body was cut short.
    Truncated,
    /// An unsupported or invalid link layer was encountered.
    UnparsableLinkLayer,
    /// A recognized packet's structure was invalid.
    MalformedPacket,
}

/// Exactly one classification for each capture record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Class {
    /// The explicit rule that permitted this packet.
    Allowed(String),
    /// The reason the packet fails the leak test.
    Violation(Reason),
}

/// An exact pcap timestamp, normalized to nanoseconds without floating point.
#[derive(Clone, Debug, Serialize)]
pub struct Timestamp {
    /// Unix seconds from the capture.
    pub seconds: u32,
    /// Fractional nanoseconds.
    pub nanoseconds: u32,
}

/// One capture record's verdict, in capture order.
#[derive(Clone, Debug, Serialize)]
pub struct Packet {
    /// One-based capture record number.
    pub index: usize,
    /// Timestamp of this fragment/packet, rather than the reassembly time.
    pub timestamp: Timestamp,
    /// Its sole final classification.
    pub class: Class,
    /// One line of protocol/address information; no raw payload.
    pub summary: String,
}

/// A bounded sample of a violation.
#[derive(Debug, Serialize)]
pub struct Violation {
    /// The capture record and its classification.
    #[serde(flatten)]
    pub packet: Packet,
    /// At most 64 captured bytes, hexadecimal, for diagnosis.
    pub captured_hex: String,
}

/// Deterministic JSON-serializable classification of a complete capture.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Number of capture records (fragments count individually).
    pub packet_count: usize,
    /// Number of failed records plus capture-wide failures.
    pub violation_count: usize,
    /// Capture-wide failures, independent of individual record verdicts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture_failures: Vec<Reason>,
    /// Counts per allowed rule or violation kind.
    pub counts: BTreeMap<String, usize>,
    /// Exactly one verdict per input record.
    pub packets: Vec<Packet>,
    /// First N failures in capture order, independent of fragment arrival order.
    pub violations: Vec<Violation>,
}

fn forbidden(policy: &Policy, src: IpAddr, dst: IpAddr, location: Location) -> Option<Reason> {
    [src, dst]
        .into_iter()
        .find(|&addr| policy.forbidden(addr))
        .map(|addr| Reason::ForbiddenAddress { addr, location })
}

fn quoted_reason(policy: &Policy, data: &[u8], depth: usize) -> Result<Option<Reason>, Reason> {
    let ip = decode::ip(data, true)?;
    if let Some(reason) = forbidden(policy, ip.src, ip.dst, Location::Quoted) {
        return Ok(Some(reason));
    }
    if let Some(reason) = field_reason(policy, &ip.addresses, Location::Quoted) {
        return Ok(Some(reason));
    }
    // ICMP errors commonly quote only IP + eight transport bytes. Do not mistake
    // that legal quotation for a snaplen cut. Follow nested errors to depth three.
    if ip.fragment.as_ref().is_none_or(|f| f.offset == 0) {
        let (proto, payload, addresses) = if ip.src.is_ipv6() {
            decode::extensions(ip.proto, ip.payload)?
        } else {
            (ip.proto, ip.payload, Vec::new())
        };
        if let Some(reason) = field_reason(policy, &addresses, Location::Quoted) {
            return Ok(Some(reason));
        }
        if matches!(proto, 1 | 58) {
            control::fields(policy, proto, payload, &Location::Quoted)?;
            if let Some(quote) = decode::transport(proto, payload, ip.src.is_ipv6())?.quotation {
                if depth >= 3 {
                    return Err(Reason::MalformedPacket);
                }
                if let Some(reason) = quoted_reason(policy, quote, depth + 1)? {
                    return Ok(Some(reason));
                }
            }
        }
        let header_len = match proto {
            17 => Some(8),
            6 => payload
                .get(12)
                .map(|b| usize::from(b >> 4) * 4)
                .filter(|&len| len >= 20),
            _ => None,
        };
        if let Some(len) = header_len
            && payload.len() >= len
            && [decode::word(payload, 0)?, decode::word(payload, 2)?].contains(&53)
            && dns::scan(&payload[len..], proto == 6)
                .0
                .iter()
                .any(|n| policy.name_marker(n))
        {
            return Ok(Some(Reason::CanaryMarker));
        }
    }
    if policy.marker(data) {
        return Ok(Some(Reason::CanaryMarker));
    }
    Ok(None)
}

fn field_reason(policy: &Policy, addresses: &[IpAddr], location: Location) -> Option<Reason> {
    addresses
        .iter()
        .copied()
        .find(|&a| policy.forbidden(a))
        .map(|addr| Reason::ForbiddenAddress { addr, location })
}

fn wg_shaped(data: &[u8]) -> bool {
    if data.len() < 4 || data[1..4] != [0, 0, 0] {
        return false;
    }
    match data[0] {
        1 => data.len() == 148,
        2 => data.len() == 92,
        3 => data.len() == 64,
        4 => data.len() >= 32,
        _ => false,
    }
}

fn datagram(policy: &Policy, ip: &Ip<'_>) -> Class {
    match decide(policy, ip) {
        Ok(rule) => Class::Allowed(rule),
        Err(reason) => Class::Violation(reason),
    }
}

fn decide(policy: &Policy, ip: &Ip<'_>) -> Result<String, Reason> {
    if let Some(reason) = forbidden(policy, ip.src, ip.dst, Location::Outer) {
        return Err(reason);
    }
    if ip.truncated {
        return Err(Reason::Truncated);
    }
    if let Some(reason) = field_reason(policy, &ip.addresses, Location::Outer) {
        return Err(reason);
    }
    let (proto, payload, addresses) = if ip.src.is_ipv6() {
        decode::extensions(ip.proto, ip.payload)?
    } else {
        (ip.proto, ip.payload, Vec::new())
    };
    if let Some(reason) = field_reason(policy, &addresses, Location::Outer) {
        return Err(reason);
    }
    if matches!(proto, 1 | 58) {
        control::fields(policy, proto, payload, &Location::Outer)?;
    }
    let t = decode::transport(proto, payload, ip.src.is_ipv6())?;
    if let Some(quotation) = t.quotation
        && let Some(reason) = quoted_reason(policy, quotation, 1)?
    {
        return Err(reason);
    }
    if policy.marker(ip.raw) {
        return Err(Reason::CanaryMarker);
    }
    if let Some(quotation) = t.quotation
        && let Some(rule) = wireguard_error(policy, ip, proto, payload[0], quotation)?
    {
        return Ok(rule);
    }
    if proto == 58 && matches!(payload.first(), Some(131..=137 | 143)) {
        return if control::ndp(policy, ip, payload)? {
            Ok("ndp".into())
        } else {
            Err(Reason::NotAllowListed)
        };
    }
    if t.ports.is_some_and(|(s, d)| s == 53 || d == 53)
        && matches!(proto, 6 | 17)
        && dns::scan(t.payload, proto == 6)
            .0
            .iter()
            .any(|n| policy.name_marker(n))
    {
        return Err(Reason::CanaryMarker);
    }
    if proto == 17
        && let Some((src, dst)) = t.ports
    {
        let src = SocketAddr::new(ip.src, src);
        let dst = SocketAddr::new(ip.dst, dst);
        for (i, rule) in policy.wireguard.iter().enumerate() {
            if (src == rule.gateway && dst == rule.peer)
                || (src == rule.peer && dst == rule.gateway)
            {
                return if wg_shaped(t.payload) {
                    Ok(format!("wireguard[{i}]"))
                } else {
                    Err(Reason::MalformedWireGuard)
                };
            }
        }
    }
    if t.ports.is_some_and(|(s, d)| s == 53 || d == 53)
        && matches!(proto, 6 | 17)
        && dns::names(t.payload, proto == 6)?
            .iter()
            .any(|n| policy.name_marker(n))
    {
        return Err(Reason::CanaryMarker);
    }
    host_allowed(policy, ip, proto, payload, t.ports).ok_or(Reason::NotAllowListed)
}

// A complete quotation may contain just IP + UDP headers. Its tuple must be the
// incoming direction of an explicitly listed WireGuard pair, including the
// gateway's old listen port after recreation. All quotation safety checks run
// before this exception, and errors never count as positive WireGuard traffic.
fn wireguard_error(
    policy: &Policy,
    outer: &Ip<'_>,
    protocol: u8,
    kind: u8,
    quotation: &[u8],
) -> Result<Option<String>, Reason> {
    if !matches!((protocol, kind), (1, 3 | 11 | 12) | (58, 1..=4)) {
        return Ok(None);
    }
    let inner = decode::ip(quotation, true)?;
    if inner.proto != 17 || inner.fragment.is_some() || !inner.trailer.is_empty() {
        return Ok(None);
    }
    // Without both ports no WireGuard tuple can match; host_allow still applies.
    if inner.payload.len() < 4 {
        return Ok(None);
    }
    let src = SocketAddr::new(inner.src, decode::word(inner.payload, 0)?);
    let dst = SocketAddr::new(inner.dst, decode::word(inner.payload, 2)?);
    let Some((i, _)) = policy.wireguard.iter().enumerate().find(|(_, rule)| {
        outer.src == rule.gateway.ip()
            && outer.dst == rule.peer.ip()
            && policy.uplink_addrs.contains(&outer.src)
            && src == rule.peer
            && dst == rule.gateway
    }) else {
        return Ok(None);
    };
    let header_len = inner.raw.len() - inner.payload.len();
    let (base_header_len, quotation_limit) = if inner.src.is_ipv4() {
        (20, 548)
    } else {
        (40, 1232)
    };
    // Peer WireGuard datagrams have no IP options or extension headers.
    if header_len != base_header_len {
        return Err(Reason::MalformedPacket);
    }
    let udp_len = usize::from(decode::word(inner.payload, 4)?);
    // The IP and UDP lengths must agree, even when ICMP quotes only a prefix.
    let ip_len = if inner.src.is_ipv4() {
        usize::from(decode::word(quotation, 2)?)
    } else {
        40 + usize::from(decode::word(quotation, 4)?)
    };
    if udp_len < 8 || ip_len - header_len != udp_len {
        return Err(Reason::MalformedPacket);
    }
    if inner.raw.len() != ip_len && quotation.len() != quotation_limit {
        return Err(Reason::Truncated);
    }
    decode::bytes(inner.payload, 0, 8)?;
    let body = &inner.payload[8..];
    let full_len = udp_len - 8;
    let valid_length = match body.first() {
        Some(1) => full_len == 148,
        Some(2) => full_len == 92,
        Some(3) => full_len == 64,
        Some(4) => full_len >= 32,
        None => full_len == 0,
        _ => false,
    };
    if !valid_length || (!body.is_empty() && (body.len() < 4 || body[1..4] != [0, 0, 0])) {
        return Err(Reason::MalformedWireGuard);
    }
    Ok(Some(format!("wireguard_error[{i}]")))
}

fn host_allowed(
    policy: &Policy,
    ip: &Ip<'_>,
    proto: u8,
    payload: &[u8],
    ports: Option<(u16, u16)>,
) -> Option<String> {
    if proto == 6
        && let (Some(endpoint), Some((source, destination))) = (policy.heartbeat, ports)
    {
        for (local, remote) in [
            (
                SocketAddr::new(ip.src, source),
                SocketAddr::new(ip.dst, destination),
            ),
            (
                SocketAddr::new(ip.dst, destination),
                SocketAddr::new(ip.src, source),
            ),
        ] {
            if policy.uplink_addrs.contains(&local.ip()) && remote == endpoint {
                return Some("heartbeat".into());
            }
        }
    }
    for (i, rule) in policy.host_allow.iter().enumerate() {
        if matches!(proto, 1 | 58)
            && !rule.types.as_ref().map_or_else(
                || {
                    if proto == 1 {
                        matches!(payload[0], 0 | 3 | 4 | 5 | 8 | 11 | 12)
                    } else {
                        matches!(payload[0], 1..=4 | 128 | 129)
                    }
                },
                |types| types.contains(&payload[0]),
            )
        {
            continue;
        }
        if proto != rule.proto.number() {
            continue;
        }
        for (local, remote, ports) in [
            (ip.src, ip.dst, ports),
            (ip.dst, ip.src, ports.map(|(s, d)| (d, s))),
        ] {
            if policy.uplink_addrs.contains(&local)
                && rule.remote_addr.contains(&remote)
                && rule
                    .local_port
                    .is_none_or(|p| ports.is_some_and(|(s, _)| s == p))
                && rule
                    .remote_port
                    .is_none_or(|p| ports.is_some_and(|(_, d)| d == p))
            {
                return Some(format!("host_allow[{i}]"));
            }
        }
    }
    None
}

#[derive(Default)]
struct Assembly {
    indices: Vec<usize>,
    pieces: Vec<(usize, Vec<u8>)>,
    end: Option<usize>,
    error: Option<Reason>,
    hop_limit: u8,
    evidence: Option<Reason>,
}

impl Assembly {
    fn add(&mut self, index: usize, fragment: &Fragment, payload: &[u8], hop_limit: u8) {
        self.indices.push(index);
        self.hop_limit = hop_limit;
        if self.error.is_some() {
            return;
        }
        let end = fragment.offset + payload.len();
        if self
            .pieces
            .iter()
            .any(|(offset, data)| fragment.offset < offset + data.len() && *offset < end)
        {
            self.error = Some(Reason::Fragment(FragmentError::Overlap));
        } else if end > 65_535
            || payload.is_empty()
            || (fragment.more && !payload.len().is_multiple_of(8))
            || self
                .end
                .is_some_and(|last| end > last || (!fragment.more && last != end))
            || (!fragment.more && self.pieces.iter().any(|(o, p)| o + p.len() > end))
        {
            self.error = Some(Reason::Fragment(FragmentError::Invalid));
        }
        if !fragment.more {
            self.end = Some(end);
        }
        // Invalid groups retain indices but need not retain more untrusted bytes.
        if self.error.is_none() {
            self.pieces.push((fragment.offset, payload.to_vec()));
        }
    }

    fn complete(&self) -> bool {
        self.error.is_none()
            && self.end.is_some_and(|end| {
                self.pieces
                    .iter()
                    .map(|(_, bytes)| bytes.len())
                    .sum::<usize>()
                    == end
            })
    }

    fn reassemble(&self) -> Result<Vec<u8>, Reason> {
        if let Some(reason) = &self.error {
            return Err(reason.clone());
        }
        let end = self
            .end
            .ok_or(Reason::Fragment(FragmentError::Incomplete))?;
        let mut pieces: Vec<_> = self.pieces.iter().collect();
        pieces.sort_by_key(|(offset, _)| *offset);
        let mut out = Vec::new();
        for (offset, data) in pieces {
            if *offset != out.len() {
                return Err(Reason::Fragment(FragmentError::Incomplete));
            }
            out.extend_from_slice(data);
        }
        if out.len() != end {
            return Err(Reason::Fragment(FragmentError::Incomplete));
        }
        Ok(out)
    }
}

fn finish(policy: &Policy, key: &Key, assembly: &Assembly, packets: &mut [Packet]) {
    let class = match assembly
        .evidence
        .clone()
        .map_or_else(|| assembly.reassemble(), Err)
    {
        Ok(payload) => datagram(
            policy,
            &Ip {
                src: key.src,
                dst: key.dst,
                proto: key.proto,
                payload: &payload,
                raw: &payload,
                trailer: &[],
                addresses: Vec::new(),
                fragment: None,
                truncated: false,
                hop_limit: assembly.hop_limit,
            },
        ),
        Err(reason) => Class::Violation(reason),
    };
    for &index in &assembly.indices {
        if !matches!(
            packets[index].class,
            Class::Violation(Reason::ForbiddenAddress { .. })
        ) {
            packets[index].class = class.clone();
        }
    }
}

/// Classify a classic-pcap byte slice without I/O or mutable external state.
///
/// Fragment verdicts are assigned to every contributing record. Incomplete sets
/// fail at EOF. Completed fragment IDs can be reused by later datagrams.
///
/// # Errors
/// Rejects invalid pcap headers/record framing; packet errors are reported as violations.
#[allow(clippy::too_many_lines)] // Capture-order bookkeeping stays alongside fragment completion.
pub fn classify(capture: &[u8], policy: &Policy, limit: usize) -> Result<Report, Error> {
    let capture = reader::read(capture)?;
    let mut packets = Vec::new();
    let mut pending: BTreeMap<Key, Assembly> = BTreeMap::new();
    for (index, record) in capture.records.iter().enumerate() {
        let mut touched = None;
        let mut packet = Packet {
            index: index + 1,
            timestamp: record.timestamp.clone(),
            class: Class::Violation(Reason::NotAllowListed),
            summary: format!("linktype {}", capture.linktype),
        };
        let frame = record
            .data
            .get(..record.data.len().saturating_sub(capture.fcs_len));
        let linked = if record.data.len() < capture.fcs_len {
            Err(Reason::Truncated)
        } else {
            decode::link(frame.unwrap_or_default(), capture.linktype)
        };
        match linked {
            Ok(Link::Other) => {
                packet.class = Class::Violation(Reason::UnparsableLinkLayer);
            }
            Ok(Link::Arp(data)) => {
                let wire_data = &record.data[record.data.len() - capture.fcs_len - data.len()..];
                packet.class = match decode::arp(data) {
                    Ok((src, dst)) => {
                        packet.summary = format!("ARP {src} -> {dst}");
                        if let Some(reason) = forbidden(policy, src, dst, Location::Outer) {
                            Class::Violation(reason)
                        } else if policy.marker(wire_data) {
                            Class::Violation(Reason::CanaryMarker)
                        } else if record.truncated {
                            Class::Violation(Reason::Truncated)
                        } else if policy.arp
                            && (policy.uplink_addrs.contains(&src)
                                || policy.uplink_addrs.contains(&dst))
                        {
                            Class::Allowed("arp".into())
                        } else {
                            Class::Violation(Reason::NotAllowListed)
                        }
                    }
                    Err(reason) => Class::Violation(reason),
                };
            }
            Ok(Link::Ip(data)) => match decode::ip(data, false) {
                Ok(mut ip) => {
                    ip.truncated |= record.truncated;
                    packet.summary = format!("{} -> {} proto {}", ip.src, ip.dst, ip.proto);
                    // Include any declared FCS in raw scanning, but exclude it
                    // from IP length/padding validation.
                    let wire_data =
                        &record.data[record.data.len() - capture.fcs_len - data.len()..];
                    let evidence = forbidden(policy, ip.src, ip.dst, Location::Outer)
                        .or_else(|| field_reason(policy, &ip.addresses, Location::Outer))
                        .or_else(|| policy.marker(wire_data).then_some(Reason::CanaryMarker))
                        .or_else(|| {
                            // Ethernet padding may extend only to the 60-byte minimum.
                            // Raw and cooked captures have no link-layer padding.
                            let padded_ethernet = capture.linktype == 1
                                && record.data.len().saturating_sub(capture.fcs_len) <= 60;
                            (!ip.trailer.is_empty() && !padded_ethernet)
                                .then_some(Reason::TrailingData)
                        });
                    let forbidden = evidence.clone();
                    if let Some(reason) = forbidden {
                        packet.class = Class::Violation(reason);
                    }
                    if let Some(fragment) = &ip.fragment {
                        if ip.truncated {
                            if !matches!(
                                packet.class,
                                Class::Violation(Reason::ForbiddenAddress { .. })
                            ) {
                                packet.class = Class::Violation(Reason::Truncated);
                            }
                        } else {
                            touched = Some(fragment.key.clone());
                            let assembly = pending.entry(fragment.key.clone()).or_default();
                            if assembly.evidence.is_none() {
                                assembly.evidence = evidence;
                            }
                            assembly.add(index, fragment, ip.payload, ip.hop_limit);
                        }
                    } else {
                        packet.class = datagram(policy, &ip);
                        if matches!(packet.class, Class::Allowed(_))
                            && let Some(reason) = evidence
                        {
                            packet.class = Class::Violation(reason);
                        }
                    }
                }
                Err(reason) => packet.class = Class::Violation(reason),
            },
            Err(reason) => packet.class = Class::Violation(reason),
        }
        packets.push(packet);
        // Complete groups immediately so identification reuse is not an overlap.
        // Only the group touched by this record can have become complete.
        if let Some(key) = touched
            && pending.get(&key).is_some_and(Assembly::complete)
            && let Some(a) = pending.remove(&key)
        {
            finish(policy, &key, &a, &mut packets);
        }
    }
    for (key, assembly) in pending {
        finish(policy, &key, &assembly, &mut packets);
    }
    let mut counts = BTreeMap::new();
    let mut violations = Vec::new();
    let mut violation_count = 0;
    for (packet, record) in packets.iter().zip(&capture.records) {
        let key = match &packet.class {
            Class::Allowed(rule) => format!("Allowed({rule})"),
            Class::Violation(reason) => {
                violation_count += 1;
                if violations.len() < limit {
                    use std::fmt::Write;
                    let mut hex = String::new();
                    for b in record.data.iter().take(64) {
                        let _ = write!(hex, "{b:02x}");
                    }
                    violations.push(Violation {
                        packet: packet.clone(),
                        captured_hex: hex,
                    });
                }
                match reason {
                    Reason::ForbiddenAddress { .. } => "Violation(ForbiddenAddress)".into(),
                    other => format!("Violation({other:?})"),
                }
            }
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    let mut capture_failures = Vec::new();
    if packets.len() < policy.min_packets {
        capture_failures.push(Reason::EmptyCapture);
    }
    for expected in &policy.expect {
        if !packets.iter().any(|packet| matches!(&packet.class, Class::Allowed(rule) if rule == expected || rule.strip_prefix(expected).is_some_and(|s| s.starts_with('[')))) {
            capture_failures.push(Reason::ExpectedClassMissing(expected.clone()));
        }
    }
    for reason in &capture_failures {
        violation_count += 1;
        *counts.entry(format!("Violation({reason:?})")).or_insert(0) += 1;
    }
    Ok(Report {
        packet_count: packets.len(),
        violation_count,
        capture_failures,
        counts,
        packets,
        violations,
    })
}

// Decoded evidence for namespace-case preconditions and exact injected controls.
// Reuse the oracle's framing/length validation; never search arbitrary pcap bytes.
pub(crate) struct Observed {
    pub timestamp: Timestamp,
    pub index: usize,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub payload: Vec<u8>,
}
pub(crate) fn observe(bytes: &[u8]) -> Result<Vec<Observed>, Error> {
    let capture = reader::read(bytes)?;
    let mut observed = Vec::new();
    let mut pending = BTreeMap::<Key, Assembly>::new();
    for (index, record) in capture.records.iter().enumerate() {
        if record.truncated {
            return Err(Error::Capture("truncated case evidence".into()));
        }
        let data = record
            .data
            .get(..record.data.len().saturating_sub(capture.fcs_len))
            .ok_or_else(|| Error::Capture("short FCS".into()))?;
        let linked = decode::link(data, capture.linktype)
            .map_err(|e| Error::Capture(format!("case link: {e:?}")))?;
        if let Link::Ip(data) = linked {
            let ip =
                decode::ip(data, false).map_err(|e| Error::Capture(format!("case IP: {e:?}")))?;
            if ip.truncated {
                return Err(Error::Capture("incomplete case datagram".into()));
            }
            if let Some(fragment) = &ip.fragment {
                let assembly = pending.entry(fragment.key.clone()).or_default();
                assembly.add(index, fragment, ip.payload, ip.hop_limit);
                if let Some(reason) = &assembly.error {
                    return Err(Error::Capture(format!("case fragments: {reason:?}")));
                }
                if assembly.complete() {
                    let first = assembly.indices[0];
                    let payload = assembly
                        .reassemble()
                        .map_err(|reason| Error::Capture(format!("case fragments: {reason:?}")))?;
                    observed.push(Observed {
                        timestamp: capture.records[first].timestamp.clone(),
                        index: first + 1,
                        source: ip.src,
                        destination: ip.dst,
                        protocol: ip.proto,
                        payload,
                    });
                    pending.remove(&fragment.key);
                }
                continue;
            }
            observed.push(Observed {
                timestamp: record.timestamp.clone(),
                index: index + 1,
                source: ip.src,
                destination: ip.dst,
                protocol: ip.proto,
                payload: ip.payload.to_vec(),
            });
        }
    }
    if !pending.is_empty() {
        return Err(Error::Capture("incomplete case datagram".into()));
    }
    observed.sort_by_key(|packet| packet.index);
    Ok(observed)
}

/// Extract every outbound TCP payload timestamp for the heartbeat endpoint.
/// # Errors
/// Rejects malformed captures or endpoint traffic from a non-host source.
pub fn heartbeat_payloads(
    bytes: &[u8],
    host: IpAddr,
    endpoint: SocketAddr,
) -> Result<Vec<Timestamp>, Error> {
    let mut times = Vec::new();
    for packet in observe(bytes)? {
        if packet.protocol != 6 || packet.destination != endpoint.ip() || packet.payload.len() < 20
        {
            continue;
        }
        if u16::from_be_bytes([packet.payload[2], packet.payload[3]]) != endpoint.port() {
            continue;
        }
        let offset = usize::from(packet.payload[12] >> 4) * 4;
        let payload = packet
            .payload
            .get(offset..)
            .ok_or_else(|| Error::Capture("heartbeat TCP header".into()))?;
        if !payload.is_empty() {
            if packet.source != host {
                return Err(Error::Capture(
                    "heartbeat payload from non-host source".into(),
                ));
            }
            times.push(packet.timestamp);
        }
    }
    Ok(times)
}

/// Extract outbound heartbeat `ClientHello` timestamps for one configured endpoint.
/// The host uplink source must match exactly; namespace/client sources fail.
///
/// # Errors
/// Rejects malformed captures and `ClientHello` traffic from a different source.
pub fn heartbeat_hellos(
    bytes: &[u8],
    host: IpAddr,
    endpoint: SocketAddr,
) -> Result<Vec<Timestamp>, Error> {
    let mut timestamps = Vec::new();
    for packet in observe(bytes)? {
        if packet.protocol != 6 || packet.destination != endpoint.ip() || packet.payload.len() < 20
        {
            continue;
        }
        let port = u16::from_be_bytes([packet.payload[2], packet.payload[3]]);
        if port != endpoint.port() {
            continue;
        }
        let offset = usize::from(packet.payload[12] >> 4) * 4;
        let payload = packet
            .payload
            .get(offset..)
            .ok_or_else(|| Error::Capture("heartbeat TCP header".into()))?;
        if payload.len() >= 6 && payload[0] == 22 && payload[1] == 3 && payload[5] == 1 {
            if packet.source != host {
                return Err(Error::Capture(
                    "heartbeat ClientHello from non-host source".into(),
                ));
            }
            timestamps.push(packet.timestamp);
        }
    }
    Ok(timestamps)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod observation_tests {
    use super::*;
    #[test]
    fn case_fragment_reassembly_requires_complete_nonoverlapping_records() {
        let valid = include_bytes!("../../tests/fixtures/run5-l11-tls-fragments.pcap");
        let packets = observe(valid).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload.len(), 1460);
        let first_length = u32::from_le_bytes(valid[32..36].try_into().unwrap()) as usize;
        let end = 24 + 16 + first_length;
        assert!(observe(&valid[..end]).is_err());
        let mut duplicate = valid[..end].to_vec();
        duplicate.extend_from_slice(&valid[24..end]);
        duplicate.extend_from_slice(&valid[end..]);
        assert!(observe(&duplicate).is_err());
        let mut truncated = valid.to_vec();
        // The first IP header now claims more bytes than the captured record.
        truncated[42..44].copy_from_slice(&1500_u16.to_be_bytes());
        assert!(observe(&truncated).is_err());
    }
    fn capture(kind: u32, frame: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        bytes.extend([0; 8]);
        bytes.extend(65535_u32.to_le_bytes());
        bytes.extend(kind.to_le_bytes());
        bytes.extend(7_u32.to_le_bytes());
        bytes.extend(123_u32.to_le_bytes());
        let len = u32::try_from(frame.len()).unwrap();
        bytes.extend(len.to_le_bytes());
        bytes.extend(len.to_le_bytes());
        bytes.extend(frame);
        bytes
    }
    #[test]
    fn raw_ethernet_and_stacked_vlan_observations_have_identical_packets() {
        let mut ip = vec![
            0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        ];
        ip.extend([0, 1, 0, 2, 0, 12, 0, 0]);
        ip.extend(b"test");
        for tags in [vec![], vec![0x8100_u16], vec![0x88a8, 0x8100]] {
            let mut frame = vec![0; 12];
            for tag in tags {
                frame.extend(tag.to_be_bytes());
                frame.extend([0, 1]);
            }
            frame.extend(0x0800_u16.to_be_bytes());
            frame.extend(&ip);
            let raw = observe(&capture(101, &ip)).unwrap();
            let ethernet = observe(&capture(1, &frame)).unwrap();
            assert_eq!(ethernet.len(), 1);
            assert_eq!(ethernet[0].source, raw[0].source);
            assert_eq!(ethernet[0].destination, raw[0].destination);
            assert_eq!(ethernet[0].payload, raw[0].payload);
            assert_eq!(ethernet[0].timestamp.seconds, raw[0].timestamp.seconds);
            assert_eq!(
                ethernet[0].timestamp.nanoseconds,
                raw[0].timestamp.nanoseconds
            );
        }
    }
    #[test]
    fn ethernet_control_frames_are_not_ip_and_truncated_headers_fail() {
        let mut lldp = vec![0; 12];
        lldp.extend(0x88cc_u16.to_be_bytes());
        assert!(observe(&capture(1, &lldp)).unwrap().is_empty());
        assert!(observe(&capture(1, &[0; 13])).is_err());
        lldp[12..].copy_from_slice(&0x8100_u16.to_be_bytes());
        assert!(observe(&capture(1, &lldp)).is_err());
    }
}
