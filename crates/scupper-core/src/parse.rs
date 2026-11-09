//! Pure parsers for kernel topology, `WireGuard` and the client route lookup.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};

use thiserror::Error;

use crate::rules::{ConfigError, IfName, V1Config};

/// Invalid command output or an unexpected exit-tunnel peer count.
///
/// Diagnostics describe the failure without echoing untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Error, serde::Serialize)]
pub enum ParseError {
    /// Malformed topology output, without retaining untrusted input.
    #[error("invalid topology output: {0}")]
    Topology(&'static str),
    /// A standalone public key has invalid base64 syntax or padding bits.
    #[error("peer key {reason}")]
    InvalidPeerKey {
        /// The public-key validation rule that failed.
        reason: &'static str,
    },
    /// A handshake line does not contain exactly a key and timestamp.
    #[error(
        "handshake line {line}: expected exactly two space- or tab-separated fields (public key and seconds)"
    )]
    InvalidHandshakeFields {
        /// The one-based line number in the original output.
        line: usize,
    },
    /// A handshake line contains an invalid public key.
    #[error("handshake line {line}: peer key {reason}")]
    InvalidHandshakeKey {
        /// The one-based line number in the original output.
        line: usize,
        /// The public-key validation rule that failed.
        reason: &'static str,
    },
    /// A timestamp is not an unsigned decimal integer fitting in `u64`.
    #[error(
        "handshake line {line}: seconds must be decimal digits in the range 0..=18446744073709551615, without a sign"
    )]
    InvalidHandshakeTimestamp {
        /// The one-based line number in the original output.
        line: usize,
    },
    /// The same peer was reported more than once.
    #[error("handshake line {line}: duplicate public key; expected one record per peer")]
    DuplicatePeer {
        /// The one-based line number of the repeated peer.
        line: usize,
    },
    /// An exit tunnel has no peer records.
    #[error(
        "expected exactly one exit peer, but found none; check the tunnel's peer configuration"
    )]
    NoPeers,
    /// An exit tunnel has more than one peer record.
    #[error(
        "expected exactly one exit peer, but found {count}; check the tunnel's peer configuration"
    )]
    MultiplePeers {
        /// The number of distinct peers in the output.
        count: usize,
    },
    /// The route lookup contains no nonempty line.
    #[error("route lookup is empty; expected a route type or a route containing 'dev <interface>'")]
    EmptyRoute,
    /// The significant line starts with neither an IP address nor a known route type.
    #[error("route line {line}: expected an IP destination or a known route type")]
    InvalidRouteStart {
        /// The one-based line number of the first nonempty line.
        line: usize,
    },
    /// An explicit unicast route has no valid IP destination.
    #[error("route line {line}: 'unicast' must be followed by an IP destination")]
    InvalidRouteDestination {
        /// The one-based line number of the first nonempty line.
        line: usize,
    },
    /// Multiple device fields or a nexthop field make device selection ambiguous.
    #[error("route line {line}: multiple 'dev' fields or 'nexthop' make the route ambiguous")]
    AmbiguousRouteDev {
        /// The one-based line number of the first nonempty line.
        line: usize,
    },
    /// The significant route line contains no device field.
    #[error("route line {line}: missing 'dev <interface>'; check that route lookup succeeded")]
    MissingRouteDev {
        /// The one-based line number of the first nonempty line.
        line: usize,
    },
    /// The device field has no following interface name.
    #[error("route line {line}: 'dev' must be followed by an interface name")]
    MissingRouteInterface {
        /// The one-based line number of the first nonempty line.
        line: usize,
    },
    /// The reported route device fails interface-name validation.
    #[error("route line {line}: invalid device after 'dev'")]
    InvalidRouteInterface {
        /// The one-based line number of the first nonempty line.
        line: usize,
        /// The interface validation failure, without the untrusted name.
        source: ConfigError,
    },
}

/// A canonical standard-base64 `WireGuard` public key encoding exactly 32 bytes.
///
/// The private representation enforces validation through [`Self::new`] or parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKey(String);

impl PeerKey {
    /// Validates the 44-byte encoding, single `=` padding and zero padding bits.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidPeerKey`] for a noncanonical encoding.
    pub fn new(key: &str) -> Result<Self, ParseError> {
        Self::validated(key).map_err(|reason| ParseError::InvalidPeerKey { reason })
    }

    fn validated(key: &str) -> Result<Self, &'static str> {
        if key.len() != 44 {
            return Err("must contain exactly 44 ASCII characters");
        }
        if !key.ends_with('=')
            || !key
                .bytes()
                .take(43)
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        {
            return Err("must contain 43 standard-base64 characters followed by one '='");
        }
        if !key
            .as_bytes()
            .get(42)
            .is_some_and(|byte| b"AEIMQUYcgkosw048".contains(byte))
        {
            return Err("must have zero padding bits (last data character: AEIMQUYcgkosw048)");
        }
        Ok(Self(key.to_owned()))
    }

    /// Borrows the validated base64 encoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PeerKey {
    type Err = ParseError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        Self::new(key)
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether and when a peer last completed a `WireGuard` handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake {
    /// No handshake has completed (`WireGuard` reports zero).
    Never,
    /// The most recent completed handshake's Unix timestamp.
    At {
        /// Whole seconds since the Unix epoch.
        unix_secs: u64,
    },
}

/// One validated peer and its reported handshake state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHandshake {
    /// The peer's canonical public key.
    pub peer: PeerKey,
    /// Whether and when the peer last completed a handshake.
    pub handshake: Handshake,
}

/// A handshake's age relative to a caller-supplied Unix timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeAge {
    /// No handshake has completed.
    Never,
    /// Time elapsed since the handshake, including zero for the current second.
    Age(Duration),
    /// Time until the reported handshake; indicates clock skew.
    InFuture(Duration),
}

impl Handshake {
    /// Computes age without reading a clock or hiding a future timestamp.
    #[must_use]
    pub fn age_at(&self, now_unix_secs: u64) -> HandshakeAge {
        match *self {
            Self::Never => HandshakeAge::Never,
            Self::At { unix_secs } if unix_secs > now_unix_secs => {
                HandshakeAge::InFuture(Duration::from_secs(unix_secs - now_unix_secs))
            }
            Self::At { unix_secs } => {
                HandshakeAge::Age(Duration::from_secs(now_unix_secs - unix_secs))
            }
        }
    }
}

/// Parses `wg show IFACE latest-handshakes`, preserving peer order.
///
/// Blank lines are ignored, and CRLF and a trailing newline are accepted.
/// Empty output represents an interface with no peers.
///
/// # Errors
///
/// Returns a one-based line-numbered error for invalid fields, keys, timestamps
/// or duplicate peers. Diagnostics never echo the input.
pub fn parse_latest_handshakes(out: &str) -> Result<Vec<PeerHandshake>, ParseError> {
    let mut peers = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, text) in out.lines().enumerate() {
        if text.trim().is_empty() {
            continue;
        }
        let line = index + 1;
        let mut fields = text.split([' ', '\t']).filter(|field| !field.is_empty());
        let (Some(key), Some(seconds), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(ParseError::InvalidHandshakeFields { line });
        };
        let peer = PeerKey::validated(key)
            .map_err(|reason| ParseError::InvalidHandshakeKey { line, reason })?;
        if !seconds.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ParseError::InvalidHandshakeTimestamp { line });
        }
        let unix_secs = seconds
            .parse::<u64>()
            .map_err(|_| ParseError::InvalidHandshakeTimestamp { line })?;
        if !seen.insert(key) {
            return Err(ParseError::DuplicatePeer { line });
        }
        peers.push(PeerHandshake {
            peer,
            handshake: if unix_secs == 0 {
                Handshake::Never
            } else {
                Handshake::At { unix_secs }
            },
        });
    }
    Ok(peers)
}

/// Parses the handshake of an exit tunnel configured with exactly one peer.
///
/// # Errors
///
/// Propagates malformed-output errors and distinguishes [`ParseError::NoPeers`]
/// from [`ParseError::MultiplePeers`].
pub fn single_peer_handshake(out: &str) -> Result<Handshake, ParseError> {
    let peers = parse_latest_handshakes(out)?;
    match peers.as_slice() {
        [] => Err(ParseError::NoPeers),
        [peer] => Ok(peer.handshake),
        _ => Err(ParseError::MultiplePeers { count: peers.len() }),
    }
}

/// Additional iproute2 route types that cannot identify a unicast output device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RouteType {
    /// A route for link-layer broadcast destinations.
    Broadcast,
    /// A route for anycast destinations.
    Anycast,
    /// A route for multicast destinations.
    Multicast,
    /// A legacy network address translation route.
    Nat,
    /// A route requiring an external resolver.
    Xresolve,
}

/// The route selected for a forwarded client packet, including special types.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum RouteLookup {
    /// A route through the validated output interface.
    Dev(IfName),
    /// A device token is present but falls outside [`IfName`]'s accepted syntax.
    OtherDev,
    /// A recognized route type that does not select a unicast output device.
    OtherType(RouteType),
    /// An explicit unreachable route.
    Unreachable,
    /// A route that silently discards packets.
    Blackhole,
    /// A route that rejects packets as administratively prohibited.
    Prohibit,
    /// A route that ends lookup in its table and continues policy processing.
    Throw,
    /// A route that delivers packets to the local host.
    Local,
}

/// Parses only the first nonempty line of textual `ip route get` output.
///
/// The line must start with an IP destination or a known iproute2 route type;
/// explicit `unicast` must be followed by an IP destination. Special route types
/// take precedence over a single device field. Following lines,
/// including `cache` metadata, cannot supply a device. The exec layer must
/// classify nonzero command exits before calling this parser.
///
/// # Errors
///
/// Returns [`ParseError`] for empty output, an invalid route prefix, a missing
/// device field or name, multiple device fields, or any `nexthop` field.
/// A device outside [`IfName`]'s syntax yields [`RouteLookup::OtherDev`].
/// Error text from `ip` is not a route.
pub fn parse_route_get(out: &str) -> Result<RouteLookup, ParseError> {
    let (index, text) = out
        .lines()
        .enumerate()
        .find(|(_, text)| !text.trim().is_empty())
        .ok_or(ParseError::EmptyRoute)?;
    let line = index + 1;
    let mut tokens = text.split_whitespace();
    if tokens.clone().any(|token| token == "nexthop")
        || tokens.clone().filter(|token| *token == "dev").count() > 1
    {
        return Err(ParseError::AmbiguousRouteDev { line });
    }
    match tokens.next() {
        Some("unreachable") => return Ok(RouteLookup::Unreachable),
        Some("blackhole") => return Ok(RouteLookup::Blackhole),
        Some("prohibit") => return Ok(RouteLookup::Prohibit),
        Some("throw") => return Ok(RouteLookup::Throw),
        Some("local") => return Ok(RouteLookup::Local),
        Some("broadcast") => return Ok(RouteLookup::OtherType(RouteType::Broadcast)),
        Some("anycast") => return Ok(RouteLookup::OtherType(RouteType::Anycast)),
        Some("multicast") => return Ok(RouteLookup::OtherType(RouteType::Multicast)),
        Some("nat") => return Ok(RouteLookup::OtherType(RouteType::Nat)),
        Some("xresolve") => return Ok(RouteLookup::OtherType(RouteType::Xresolve)),
        Some("unicast") => {
            if tokens
                .next()
                .is_none_or(|token| token.parse::<IpAddr>().is_err())
            {
                return Err(ParseError::InvalidRouteDestination { line });
            }
        }
        Some(destination) if destination.parse::<IpAddr>().is_ok() => {}
        _ => return Err(ParseError::InvalidRouteStart { line }),
    }
    if !tokens.any(|token| token == "dev") {
        return Err(ParseError::MissingRouteDev { line });
    }
    let name = tokens
        .next()
        .ok_or(ParseError::MissingRouteInterface { line })?;
    Ok(IfName::new(name).map_or(RouteLookup::OtherDev, RouteLookup::Dev))
}

/// Destination used by the v1 forwarded-client route probe.
pub const ROUTE_PROBE_DST: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// Builds the `ip` arguments that check routing for a forwarded client packet.
///
/// A socket bound to the exit interface bypasses route selection and can
/// succeed despite a missing policy rule. Looking up the client's source and
/// ingress interface reveals that failure. The exec layer adds the program path.
#[must_use]
pub fn route_probe_argv(cfg: &V1Config) -> Vec<String> {
    vec![
        "route".to_owned(),
        "get".to_owned(),
        ROUTE_PROBE_DST.to_string(),
        "from".to_owned(),
        cfg.client_addr.to_string(),
        "iif".to_owned(),
        cfg.client_iface.to_string(),
    ]
}

pub(crate) fn json_array(out: &str) -> Result<Vec<serde_json::Value>, ParseError> {
    let value: serde_json::Value =
        serde_json::from_str(out).map_err(|_| ParseError::Topology("malformed JSON"))?;
    let serde_json::Value::Array(entries) = value else {
        return Err(ParseError::Topology("expected a JSON array"));
    };
    if entries.iter().any(|entry| !entry.is_object()) {
        return Err(ParseError::Topology("expected JSON object entries"));
    }
    Ok(entries)
}

/// Whether `tc -j qdisc show` contains anything beyond one root `noqueue` or `noop`.
/// Unknown fields are retained only by the JSON reader and otherwise ignored.
///
/// # Errors
/// Returns an error for malformed JSON, missing kinds or invalid root flags.
pub fn qdisc_has_hooks(out: &str) -> Result<bool, ParseError> {
    let entries = json_array(out)?;
    let mut baseline = entries.len() == 1;
    for entry in entries {
        let kind = entry["kind"]
            .as_str()
            .ok_or(ParseError::Topology("qdisc is missing a string kind"))?;
        let root = match entry.get("root") {
            None => false,
            Some(value) => value
                .as_bool()
                .ok_or(ParseError::Topology("qdisc root must be boolean"))?,
        };
        baseline &= matches!(kind, "noqueue" | "noop") && root;
    }
    Ok(!baseline)
}

/// Whether `tc -j filter show` contains any filter.
///
/// # Errors
/// Returns an error for malformed JSON or non-object entries.
pub fn filter_has_hooks(out: &str) -> Result<bool, ParseError> {
    Ok(!json_array(out)?.is_empty())
}

/// Link details needed to distinguish fail-closed exits and netfilter bypasses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Detailed kernel link kind, such as wireguard or veth.
    pub kind: Option<String>,
    /// Kernel interface name.
    pub name: String,
    /// Whether the flags include the administrative `UP` flag.
    pub up: bool,
    /// Whether an XDP key is present, regardless of its value.
    pub xdp: bool,
}

/// Collects names, administrative state and XDP presence from `ip -j link show`.
/// Missing flags mean the link is not up; unknown fields are ignored.
///
/// # Errors
/// Returns an error for malformed JSON, names or flags.
pub fn links(out: &str) -> Result<Vec<Link>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            let name = entry["ifname"]
                .as_str()
                .ok_or(ParseError::Topology("link is missing a string ifname"))?
                .to_owned();
            let mut up = false;
            if let Some(flags) = entry.get("flags") {
                for flag in flags
                    .as_array()
                    .ok_or(ParseError::Topology("link flags must be an array"))?
                {
                    up |= flag
                        .as_str()
                        .ok_or(ParseError::Topology("link flag must be a string"))?
                        == "UP";
                }
            }
            let kind = entry
                .get("linkinfo")
                .map(|info| {
                    let info = info
                        .as_object()
                        .ok_or(ParseError::Topology("invalid linkinfo"))?;
                    info.get("info_kind")
                        .map(|kind| {
                            kind.as_str()
                                .map(str::to_owned)
                                .ok_or(ParseError::Topology("invalid link kind"))
                        })
                        .transpose()
                })
                .transpose()?
                .flatten();
            Ok(Link {
                kind,
                name,
                up,
                xdp: entry.get("xdp").is_some(),
            })
        })
        .collect()
}

/// Collects interface names from `ip -j link show`, ignoring unknown fields.
///
/// # Errors
/// Returns an error for malformed JSON or missing/non-string interface names.
pub fn link_names(out: &str) -> Result<Vec<String>, ParseError> {
    json_array(out)?
        .iter()
        .map(|entry| {
            entry["ifname"]
                .as_str()
                .map(str::to_owned)
                .ok_or(ParseError::Topology("link is missing a string ifname"))
        })
        .collect()
}

/// Checks that every default route selects the uplink and at least one exists.
/// A route without a device (including a multipath route) cannot agree.
///
/// # Errors
/// Returns an error for malformed JSON or a non-string device.
pub fn default_routes_use(out: &str, uplink: &IfName) -> Result<bool, ParseError> {
    let entries = json_array(out)?;
    let mut agrees = !entries.is_empty();
    for entry in entries {
        let dev = entry
            .get("dev")
            .map(|value| {
                value
                    .as_str()
                    .ok_or(ParseError::Topology("route dev must be a string"))
            })
            .transpose()?;
        agrees &= dev == Some(uplink.as_str());
    }
    Ok(agrees)
}

/// Collects all IPv4 and IPv6 `local` addresses from `ip -j addr show`.
/// An interface with no `addr_info` has no addresses.
///
/// # Errors
/// Returns an error for malformed JSON, address entries or IP addresses.
pub fn local_addresses(out: &str) -> Result<Vec<IpAddr>, ParseError> {
    let mut addresses = Vec::new();
    for entry in json_array(out)? {
        let Some(info) = entry.get("addr_info") else {
            continue;
        };
        let info = info
            .as_array()
            .ok_or(ParseError::Topology("addr_info must be an array"))?;
        for address in info {
            let local = address["local"]
                .as_str()
                .ok_or(ParseError::Topology("address is missing a string local"))?;
            addresses.push(
                local
                    .parse()
                    .map_err(|_| ParseError::Topology("invalid local IP address"))?,
            );
        }
    }
    Ok(addresses)
}

/// Checks client containment in `wg show IFACE allowed-ips` output.
/// IPv6 CIDRs are validated but cannot contain an IPv4 client. All lines are
/// parsed even after a match so malformed later records remain errors.
///
/// # Errors
/// Returns an error for invalid peer records or CIDRs.
pub fn allowed_ips_contain(out: &str, client: Ipv4Addr) -> Result<bool, ParseError> {
    let mut contains = false;
    for line in out.lines().filter(|line| !line.trim().is_empty()) {
        let (key, ips) = line.split_once('\t').ok_or(ParseError::Topology(
            "allowed-ips record must contain a tab",
        ))?;
        PeerKey::new(key)?;
        if ips.trim() == "(none)" {
            continue;
        }
        if ips.trim().is_empty() {
            return Err(ParseError::Topology("empty allowed-ips record"));
        }
        for cidr in ips.split_whitespace() {
            let (network, prefix) = cidr
                .split_once('/')
                .ok_or(ParseError::Topology("allowed IP must be a CIDR"))?;
            let network: IpAddr = network
                .parse()
                .map_err(|_| ParseError::Topology("invalid CIDR address"))?;
            if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ParseError::Topology("invalid CIDR prefix"));
            }
            let prefix: u32 = prefix
                .parse()
                .map_err(|_| ParseError::Topology("invalid CIDR prefix"))?;
            match network {
                IpAddr::V4(network) if prefix <= 32 => {
                    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                    contains |= u32::from(network) & mask == u32::from(client) & mask;
                }
                IpAddr::V6(_) if prefix <= 128 => {}
                _ => return Err(ParseError::Topology("CIDR prefix out of range")),
            }
        }
    }
    Ok(contains)
}

mod kernel;
mod udp;
mod wireguard;

pub use kernel::*;
pub use udp::*;
pub use wireguard::*;
