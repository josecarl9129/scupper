//! Public-only `WireGuard` output parsers.

use super::{Handshake, ParseError, PeerKey, parse_latest_handshakes};
use ipnet::IpNet;
use std::{collections::BTreeSet, net::SocketAddr};

/// Every field whose output is safe to observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgField {
    /// Interface public key.
    PublicKey,
    /// UDP listen port.
    ListenPort,
    /// Peer public keys.
    Peers,
    /// Peer allowed prefixes.
    AllowedIps,
    /// Learned numeric endpoints.
    Endpoints,
    /// Keepalive intervals.
    PersistentKeepalive,
    /// Last handshake timestamps.
    LatestHandshakes,
    /// Received and transmitted bytes.
    Transfer,
}
impl WgField {
    /// The literal safe `wg show` field token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicKey => "public-key",
            Self::ListenPort => "listen-port",
            Self::Peers => "peers",
            Self::AllowedIps => "allowed-ips",
            Self::Endpoints => "endpoints",
            Self::PersistentKeepalive => "persistent-keepalive",
            Self::LatestHandshakes => "latest-handshakes",
            Self::Transfer => "transfer",
        }
    }
}

/// One public peer observation. Only the selected field is populated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeer {
    /// Validated public key.
    pub public_key: PeerKey,
    /// Numeric endpoint, or None if absent or not observed.
    pub endpoint: Option<SocketAddr>,
    /// Allowed prefixes; Some(empty) means the observed value was `(none)`.
    pub allowed_ips: Option<Vec<IpNet>>,
    /// Keepalive seconds; zero means `off`.
    pub keepalive: Option<u16>,
    /// Last handshake, including the explicit never state.
    pub handshake: Option<Handshake>,
    /// Received bytes.
    pub received: Option<u64>,
    /// Transmitted bytes.
    pub transmitted: Option<u64>,
}
impl WgPeer {
    fn new(public_key: PeerKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            allowed_ips: None,
            keepalive: None,
            handshake: None,
            received: None,
            transmitted: None,
        }
    }
}

/// A field-specific `WireGuard` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgOutput {
    /// None means the interface has no private/public key configured.
    PublicKey(Option<PeerKey>),
    /// Zero means no fixed port is configured.
    ListenPort(u16),
    /// Public peer records; empty output means no peers.
    Peers(Vec<WgPeer>),
}
fn invalid() -> ParseError {
    ParseError::Topology("invalid public WireGuard output")
}
fn decimal<T: std::str::FromStr>(text: &str) -> Result<T, ParseError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}

/// Parses `wg show IFACE public-key`, accepting `(none)` for an unset key.
///
/// # Errors
/// Rejects noncanonical keys and extra records.
pub fn parse_wg_public_key(out: &str) -> Result<Option<PeerKey>, ParseError> {
    match out.trim() {
        "(none)" => Ok(None),
        text => PeerKey::new(text).map(Some),
    }
}

/// Parses `wg show IFACE listen-port` as an unsigned UDP port.
///
/// # Errors
/// Rejects signs, overflow, missing values and extra records.
pub fn parse_wg_listen_port(out: &str) -> Result<u16, ParseError> {
    decimal(out.trim())
}

/// Parses one field in the public `WireGuard` allow-list.
///
/// # Errors
/// Rejects malformed fields, duplicate peers, invalid keys or overflowing numbers.
/// Diagnostics never retain the input.
pub fn parse_wg(field: WgField, out: &str) -> Result<WgOutput, ParseError> {
    match field {
        WgField::PublicKey => return parse_wg_public_key(out).map(WgOutput::PublicKey),
        WgField::ListenPort => return parse_wg_listen_port(out).map(WgOutput::ListenPort),
        WgField::LatestHandshakes => {
            return Ok(WgOutput::Peers(
                parse_latest_handshakes(out)?
                    .into_iter()
                    .map(|value| {
                        let mut peer = WgPeer::new(value.peer);
                        peer.handshake = Some(value.handshake);
                        peer
                    })
                    .collect(),
            ));
        }
        _ => {}
    }
    let mut peers = Vec::new();
    let mut seen = BTreeSet::new();
    for line in out.lines().filter(|line| !line.trim().is_empty()) {
        let columns: Vec<_> = line.trim().split('\t').collect();
        let count = match field {
            WgField::Peers => 1,
            WgField::Transfer => 3,
            _ => 2,
        };
        if columns.len() != count {
            return Err(invalid());
        }
        let key = columns[0];
        let mut peer = WgPeer::new(PeerKey::new(key)?);
        if !seen.insert(key) {
            return Err(invalid());
        }
        match field {
            WgField::Peers => {}
            WgField::Endpoints => {
                peer.endpoint = match columns[1] {
                    "(none)" => None,
                    endpoint => Some(endpoint.parse().map_err(|_| invalid())?),
                };
            }
            WgField::AllowedIps => {
                let text = columns[1];
                peer.allowed_ips = Some(if text == "(none)" {
                    Vec::new()
                } else {
                    let prefixes = text
                        .split_ascii_whitespace()
                        .map(|prefix| prefix.parse().map_err(|_| invalid()))
                        .collect::<Result<Vec<IpNet>, _>>()?;
                    if prefixes.is_empty() {
                        return Err(invalid());
                    }
                    prefixes
                });
            }
            WgField::PersistentKeepalive => {
                peer.keepalive = Some(if columns[1] == "off" {
                    0
                } else {
                    decimal(columns[1])?
                });
            }
            WgField::Transfer => {
                peer.received = Some(decimal(columns[1])?);
                peer.transmitted = Some(decimal(columns[2])?);
            }
            _ => return Err(invalid()),
        }
        peers.push(peer);
    }
    Ok(WgOutput::Peers(peers))
}
