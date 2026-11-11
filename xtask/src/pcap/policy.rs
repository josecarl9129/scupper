use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnet::IpNet;
use serde::Deserialize;

/// A validated, default-deny uplink policy. Construct with [`Self::from_toml`].
#[derive(Debug)]
pub struct Policy {
    pub(super) uplink_addrs: Vec<IpAddr>,
    pub(super) heartbeat: Option<SocketAddr>,
    pub(super) wireguard: Vec<WireGuard>,
    pub(super) host_allow: Vec<HostRule>,
    pub(super) arp: bool,
    pub(super) ndp: bool,
    pub(super) forbidden_addrs: Vec<IpNet>,
    canary_markers: Vec<Marker>,
    pub(super) min_packets: usize,
    pub(super) expect: Vec<String>,
}

#[derive(Debug)]
struct Marker {
    bytes: Vec<u8>,
    name: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireGuard {
    pub gateway: SocketAddr,
    pub peer: SocketAddr,
}

#[derive(Debug)]
pub(super) struct HostRule {
    pub proto: Protocol,
    pub local_port: Option<u16>,
    pub remote_addr: IpNet,
    pub remote_port: Option<u16>,
    pub types: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Protocol {
    Udp,
    Tcp,
    Icmp,
    Icmpv6,
}

impl Protocol {
    pub fn number(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp => 6,
            Self::Icmp => 1,
            Self::Icmpv6 => 58,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    uplink_addrs: Vec<IpAddr>,
    #[serde(default)]
    wireguard: Vec<WireGuard>,
    #[serde(default)]
    heartbeat: Option<SocketAddr>,
    #[serde(default)]
    host_allow: Vec<RawHost>,
    #[serde(default)]
    arp: bool,
    #[serde(default)]
    ndp: bool,
    forbidden_addrs: Vec<String>,
    #[serde(default)]
    canary_markers: Vec<RawMarker>,
    #[serde(default = "one")]
    min_packets: usize,
    #[serde(default)]
    expect: Vec<String>,
}

fn one() -> usize {
    1
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawMarker {
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    proto: Protocol,
    local_port: Option<u16>,
    remote_addr: String,
    remote_port: Option<u16>,
    types: Option<Vec<u8>>,
    #[serde(default)]
    allow_wide: bool,
}

impl Policy {
    /// Parse strict TOML, rejecting missing forbidden prefixes and contradictory rules.
    ///
    /// # Errors
    /// Returns a configuration diagnostic if TOML or a rule is invalid.
    #[allow(clippy::too_many_lines)] // Validate all policy constraints in one place.
    pub fn from_toml(input: &str) -> Result<Self, super::Error> {
        let raw: RawPolicy =
            toml::from_str(input).map_err(|e| super::Error::Policy(e.to_string()))?;
        let invalid = |message: &str| super::Error::Policy(message.to_owned());
        let prefix = |s: &str| {
            s.parse::<IpNet>().or_else(|e| {
                s.parse::<IpAddr>()
                    .map(IpNet::from)
                    .map_err(|_| super::Error::Policy(e.to_string()))
            })
        };
        let canary_markers: Vec<Marker> = raw
            .canary_markers
            .into_iter()
            .map(|marker| match marker {
                RawMarker::Text(text) => Marker {
                    bytes: text.into_bytes(),
                    name: true,
                },
                RawMarker::Bytes(bytes) => Marker { bytes, name: false },
            })
            .collect();
        if canary_markers.iter().any(|m| m.bytes.len() < 12) {
            return Err(invalid(
                "canary_markers must each contain at least 12 bytes",
            ));
        }
        if raw.forbidden_addrs.is_empty() {
            return Err(invalid("forbidden_addrs is required and must be non-empty"));
        }
        if raw.min_packets == 0 {
            return Err(invalid("min_packets must be at least 1"));
        }
        let forbidden_addrs: Vec<_> = raw
            .forbidden_addrs
            .iter()
            .map(|s| prefix(s))
            .collect::<Result<_, _>>()?;
        let mut policy = Self {
            uplink_addrs: raw.uplink_addrs,
            wireguard: raw.wireguard,
            heartbeat: raw.heartbeat,
            host_allow: Vec::new(),
            arp: raw.arp,
            ndp: raw.ndp,
            forbidden_addrs,
            canary_markers,
            min_packets: raw.min_packets,
            expect: raw.expect,
        };
        if policy.uplink_addrs.iter().any(|&a| policy.forbidden(a)) {
            return Err(invalid("uplink_addrs overlaps forbidden_addrs"));
        }
        if policy
            .heartbeat
            .is_some_and(|endpoint| endpoint.port() != 443 || policy.forbidden(endpoint.ip()))
        {
            return Err(invalid(
                "heartbeat requires one non-forbidden HTTPS endpoint on port 443",
            ));
        }
        for pair in &policy.wireguard {
            if !policy.uplink_addrs.contains(&pair.gateway.ip())
                || pair.gateway.is_ipv4() != pair.peer.is_ipv4()
                || pair.gateway.port() == 0
                || pair.peer.port() == 0
                || policy.forbidden(pair.gateway.ip())
                || policy.forbidden(pair.peer.ip())
            {
                return Err(invalid(
                    "wireguard requires non-forbidden endpoints, an uplink gateway, matching address families and nonzero ports",
                ));
            }
        }
        for rule in raw.host_allow {
            let icmp = matches!(rule.proto, Protocol::Icmp | Protocol::Icmpv6);
            if icmp && (rule.local_port.is_some() || rule.remote_port.is_some()) {
                return Err(invalid("ICMP rules cannot specify ports"));
            }
            if !icmp && (rule.local_port.is_none() && rule.remote_port.is_none()) {
                return Err(invalid("TCP/UDP rules require at least one port"));
            }
            if !icmp && rule.types.is_some() {
                return Err(invalid("only ICMP rules can specify types"));
            }
            let remote_addr = prefix(&rule.remote_addr)?;
            if !rule.allow_wide
                && remote_addr.prefix_len() < if remote_addr.addr().is_ipv4() { 24 } else { 48 }
            {
                return Err(invalid("wide host prefixes require allow_wide = true"));
            }
            if policy.forbidden_addrs.iter().any(|net| {
                net.contains(&remote_addr.network()) || remote_addr.contains(&net.network())
            }) || policy.forbidden(remote_addr.network())
            {
                return Err(invalid("host_allow.remote_addr overlaps forbidden_addrs"));
            }
            policy.host_allow.push(HostRule {
                proto: rule.proto,
                local_port: rule.local_port,
                remote_port: rule.remote_port,
                remote_addr,
                types: rule.types,
            });
        }
        for expected in &policy.expect {
            let valid = matches!(
                expected.as_str(),
                "wireguard" | "host_allow" | "heartbeat" | "arp" | "ndp"
            ) || (0..policy.wireguard.len())
                .any(|i| *expected == format!("wireguard[{i}]"))
                || (0..policy.host_allow.len()).any(|i| *expected == format!("host_allow[{i}]"));
            if !valid {
                return Err(invalid(
                    "expect must name an allowed class or configured rule",
                ));
            }
        }
        Ok(policy)
    }

    pub(super) fn forbidden(&self, addr: IpAddr) -> bool {
        let embedded = match addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => {
                let b = v6.octets();
                if b[..12] == [0; 12]
                    || b[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255]
                    || b[..12] == [0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0]
                {
                    Some(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
                } else if b[..2] == [0x20, 0x02] {
                    Some(Ipv4Addr::new(b[2], b[3], b[4], b[5]))
                } else {
                    None
                }
            }
        };
        self.forbidden_addrs.iter().any(|net| {
            net.contains(&addr) || embedded.is_some_and(|v4| net.contains(&IpAddr::V4(v4)))
        })
    }

    pub(super) fn marker(&self, bytes: &[u8]) -> bool {
        self.canary_markers
            .iter()
            .any(|m| bytes.windows(m.bytes.len()).any(|w| w == m.bytes))
    }

    pub(super) fn name_marker(&self, bytes: &[u8]) -> bool {
        self.canary_markers.iter().any(|m| {
            bytes.windows(m.bytes.len()).any(|w| {
                if m.name {
                    w.eq_ignore_ascii_case(&m.bytes)
                } else {
                    w == m.bytes
                }
            })
        })
    }
}
