//! Validated policy inputs; constructors cannot introduce pf source syntax.

use std::{collections::BTreeMap, fmt, net::Ipv4Addr, str::FromStr};

/// Invalid typed input or captured command output. Does not echo supplied text.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid Mac observation/input: {0}")]
pub struct Error(pub &'static str);

/// Validated kernel interface token (including interfaces not eligible for DHCP).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interface(String);
impl FromStr for Interface {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty()
            || s.len() > 15
            || !s.bytes().all(|b| b.is_ascii_alphanumeric())
            || !s.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(Error("interface name"));
        }
        Ok(Self(s.into()))
    }
}
impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl Interface {
    /// Only the kernel loopback family may have pf skip enabled.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        numbered(&self.0, "lo")
    }
}
fn numbered(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Physical-interface name. Eligibility still requires an explicit OS record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalInterface(Interface);
impl FromStr for PhysicalInterface {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let name: Interface = s.parse()?;
        let split = s
            .find(|c: char| c.is_ascii_digit())
            .ok_or(Error("physical unit number"))?;
        if !s[..split].bytes().all(|b| b.is_ascii_lowercase())
            || !s[split..].bytes().all(|b| b.is_ascii_digit())
            || name.is_loopback()
            || s.starts_with("utun")
            || ["awdl", "llw", "ap", "bridge", "anpi"]
                .iter()
                .any(|prefix| s.starts_with(prefix))
        {
            return Err(Error("excluded physical interface family"));
        }
        Ok(Self(name))
    }
}
impl PhysicalInterface {
    /// Borrow the validated kernel name.
    #[must_use]
    pub fn interface(&self) -> &Interface {
        &self.0
    }
}
impl fmt::Display for PhysicalInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Kernel-assigned utun name; never sufficient proof of child identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utun(Interface);
impl FromStr for Utun {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let name = s.parse()?;
        if !numbered(s, "utun") {
            return Err(Error("utun name"));
        }
        Ok(Self(name))
    }
}
impl Utun {
    /// Borrow the validated kernel name.
    #[must_use]
    pub fn interface(&self) -> &Interface {
        &self.0
    }
}
impl fmt::Display for Utun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() && !ip.is_loopback()
}
/// Numeric IPv4 address and nonzero UDP port, fixed at setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    address: Ipv4Addr,
    port: u16,
}
impl Endpoint {
    /// Destination address.
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
    /// `WireGuard` UDP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}
impl FromStr for Endpoint {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let (address, port) = s.split_once(':').ok_or(Error("IPv4 endpoint"))?;
        let address = address.parse().map_err(|_| Error("IPv4 endpoint"))?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error("UDP port"));
        }
        let port = port.parse().map_err(|_| Error("UDP port"))?;
        if !unicast(address) || port == 0 {
            return Err(Error("IPv4 endpoint"));
        }
        Ok(Self { address, port })
    }
}
/// Validated `DHCPv4` lease server; timer derivation belongs to 5a2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseServer(Ipv4Addr);
impl FromStr for LeaseServer {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let ip = s.parse().map_err(|_| Error("lease server"))?;
        if !unicast(ip) {
            return Err(Error("lease server"));
        }
        Ok(Self(ip))
    }
}
impl fmt::Display for LeaseServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
/// Independently observed DHCP phase for each eligible physical interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DhcpPhase {
    /// No lease, expired lease, network change, or T2 reached.
    AcquiringRebinding,
    /// Validated current lease, before T2.
    Bound {
        /// Validated server identifier.
        server: LeaseServer,
    },
}
/// Opaque, nonzero child incarnation identifier; supplied by the supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TunnelGeneration(u64);
impl TunnelGeneration {
    /// Numeric incarnation, for monotonic generation allocation by the caller.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
    /// Reject zero (uninitialized) generations.
    ///
    /// # Errors
    /// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
    pub fn new(value: u64) -> Result<Self, Error> {
        if value == 0 {
            Err(Error("zero tunnel generation"))
        } else {
            Ok(Self(value))
        }
    }
}
impl FromStr for TunnelGeneration {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error("tunnel generation"));
        }
        Self::new(s.parse().map_err(|_| Error("tunnel generation"))?)
    }
}
/// Qualification must choose the ND hop-limit mechanism or record its limitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HopLimitPolicy {
    /// Qualified OS enforces 255 externally; evidence is checked by the verifier.
    External255,
    /// Qualified limitation: these pf rules do not enforce the hop limit.
    QualifiedLimitation,
}
/// Name and generation together; the verifier additionally requires identity proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tunnel {
    /// Kernel interface name.
    pub name: Utun,
    /// Supervisor incarnation.
    pub generation: TunnelGeneration,
}
/// Renderer inputs. No implicit discovery, lease timing, or uplink selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    selected: PhysicalInterface,
    endpoint: Endpoint,
    physical: BTreeMap<PhysicalInterface, DhcpPhase>,
    tunnel: Tunnel,
    hop_limit: HopLimitPolicy,
}
impl Inputs {
    /// The physical set must already be qualified DHCP-enabled services; selected
    /// must be in it. Empty/duplicate sets cannot silently produce wider policy.
    ///
    /// # Errors
    /// Rejects invalid, incomplete, out-of-order or unsupported supplied evidence.
    pub fn new(
        selected: PhysicalInterface,
        endpoint: Endpoint,
        physical: BTreeMap<PhysicalInterface, DhcpPhase>,
        tunnel: Tunnel,
        hop_limit: HopLimitPolicy,
    ) -> Result<Self, Error> {
        if !physical.contains_key(&selected) {
            return Err(Error("selected interface not DHCP eligible"));
        }
        Ok(Self {
            selected,
            endpoint,
            physical,
            tunnel,
            hop_limit,
        })
    }
    /// Explicit selected path (selection algorithm is deferred to 5a2).
    #[must_use]
    pub fn selected(&self) -> &PhysicalInterface {
        &self.selected
    }
    /// Numeric setup endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// Every qualified DHCP-enabled service, including inactive ones.
    #[must_use]
    pub fn physical(&self) -> &BTreeMap<PhysicalInterface, DhcpPhase> {
        &self.physical
    }
    /// Intended supervised child.
    #[must_use]
    pub fn tunnel(&self) -> &Tunnel {
        &self.tunnel
    }
    /// Explicit qualification decision.
    #[must_use]
    pub fn hop_limit(&self) -> &HopLimitPolicy {
        &self.hop_limit
    }
}
