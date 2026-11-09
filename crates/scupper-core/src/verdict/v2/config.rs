//! Pure conversion from applied, validated site configuration.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use ipnet::{IpNet, Ipv4Net};

use crate::config::{ExitId, ExitIfname, GatewayId, ValidatedSite};

use super::{NetnsIdentity, PeerObs};

/// Expected namespace state and health policy, without host or clock access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthConfigV2 {
    /// Full namespace identity from the boot record, never inferred from live state.
    pub expected_netns: NetnsIdentity,
    /// Host uplink addresses that must never be accepted as exit addresses.
    pub uplink_addrs: Vec<IpAddr>,
    /// Applied configuration version for reports.
    pub config_version: u64,
    /// Sole configured M2 exit.
    pub exit: ExitId,
    /// Exit-only validated interface used by route intent.
    pub exit_iface: ExitIfname,
    /// Assigned exit address, excluded by the plausibility check.
    pub exit_addr: Ipv4Addr,
    /// Expected non-loopback link names and assigned prefixes.
    pub links: BTreeMap<String, Vec<IpNet>>,
    /// Expected peers; learned client endpoints are not policy.
    pub peers: BTreeMap<String, Vec<PeerObs>>,
    /// Client-facing interface name.
    pub client_iface: String,
    /// Gateway's client-facing IPv4 address, used to diagnose default routes.
    pub client_addr: Ipv4Addr,
    /// Every configured client source whose forwarded route must be verified.
    pub clients: Vec<IpAddr>,
    /// Device addresses, or the first client-prefix host other than the gateway.
    /// Always nonempty, even before any devices have been configured.
    pub route_sources: Vec<IpAddr>,
    /// Expected client-facing public identity.
    pub client_public_key: [u8; 32],
    /// Expected client listen port and host UDP bind.
    pub listen_port: u16,
    /// Inclusive exit/client handshake age bound.
    pub max_handshake_age: Duration,
    /// Inclusive future-handshake tolerance, as in v1.
    pub max_clock_skew: Duration,
    /// IPv4 forwarded route probe destination.
    pub route_probe_dst4: Ipv4Addr,
    /// IPv6 rejecting route probe destination.
    pub route_probe_dst6: Ipv6Addr,
    /// Whether the supervisor must pass for code 0.
    pub require_daemon: bool,
}

/// A caller supplied inputs outside the supported single-exit M2 scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HealthConfigError {
    /// Gateway ID is absent from the validated site.
    #[error("unknown health-check gateway")]
    UnknownGateway,
    /// Exactly one enabled exit is required in M2.
    #[error("M2 health checks require exactly one exit")]
    ExitCount,
    /// Expected namespace identity must come from a nonzero boot-record inode.
    #[error("expected namespace inode is zero")]
    InvalidNetnsIdentity,
    /// Uplink comparison cannot be skipped silently.
    #[error("no uplink addresses supplied")]
    NoUplinkAddresses,
    /// The client prefix contains no host address other than the gateway.
    #[error("client prefix has no forwarded route probe address")]
    NoRouteProbeAddress,
    /// The resolved identity must retain its validated public key and port.
    #[error("invalid validated client public identity")]
    InvalidIdentity,
}

impl HealthConfigV2 {
    /// Builds expectations solely from a validated site and supplied boot state.
    ///
    /// No secret references are copied or opened. The config version identifies
    /// the applied version, not an uncommitted candidate configuration.
    ///
    /// # Errors
    /// Rejects unknown gateways, unsupported exit counts, zero namespace identity,
    /// missing uplink addresses, a prefix without a probe host, or an invalid public identity.
    pub fn new(
        site: &ValidatedSite,
        gateway: &GatewayId,
        expected_netns: NetnsIdentity,
        uplink_addrs: Vec<IpAddr>,
        config_version: u64,
    ) -> Result<Self, HealthConfigError> {
        let gw = site
            .gateway(gateway)
            .ok_or(HealthConfigError::UnknownGateway)?;
        let [exit] = gw.exits() else {
            return Err(HealthConfigError::ExitCount);
        };
        if expected_netns.inode == 0 {
            return Err(HealthConfigError::InvalidNetnsIdentity);
        }
        if uplink_addrs.is_empty() {
            return Err(HealthConfigError::NoUplinkAddresses);
        }
        let client = gw.client_tunnel();
        let client_iface = client.ifname().as_str().to_owned();
        let exit_name = exit.ifname().as_str().to_owned();
        let devices: Vec<_> = site
            .devices()
            .values()
            .filter(|device| device.gateways().contains(gateway))
            .collect();
        let peers = BTreeMap::from([
            (
                client_iface.clone(),
                devices
                    .iter()
                    .map(|device| PeerObs {
                        public_key: device.public_key(),
                        allowed_ips: vec![device.address4().into()],
                        endpoint: None,
                    })
                    .collect(),
            ),
            (
                exit_name.clone(),
                vec![PeerObs {
                    public_key: exit.peer_public_key(),
                    allowed_ips: vec![Ipv4Net::default().into()],
                    endpoint: Some(exit.endpoint()),
                }],
            ),
        ]);
        let clients: Vec<_> = devices
            .iter()
            .map(|device| IpAddr::V4(device.address4().addr()))
            .collect();
        let route_sources = if clients.is_empty() {
            vec![IpAddr::V4(
                client
                    .address4()
                    .hosts()
                    .find(|addr| *addr != client.address4().addr())
                    .ok_or(HealthConfigError::NoRouteProbeAddress)?,
            )]
        } else {
            clients.clone()
        };
        Ok(Self {
            expected_netns,
            uplink_addrs,
            config_version,
            exit: exit.id().clone(),
            exit_iface: exit.ifname().clone(),
            exit_addr: exit.address4().addr(),
            links: BTreeMap::from([
                (client_iface.clone(), vec![client.address4().into()]),
                (exit_name, vec![exit.address4().into()]),
            ]),
            peers,
            client_iface,
            client_addr: client.address4().addr(),
            clients,
            route_sources,
            client_public_key: client
                .identity()
                .public_key
                .bytes()
                .map_err(|_| HealthConfigError::InvalidIdentity)?,
            listen_port: u16::try_from(client.identity().listen_port)
                .map_err(|_| HealthConfigError::InvalidIdentity)?,
            max_handshake_age: site.health().handshake_stale(),
            max_clock_skew: Duration::from_secs(5),
            route_probe_dst4: site.health().route_probe_dst4(),
            route_probe_dst6: site.health().route_probe_dst6(),
            require_daemon: site.health().require_daemon(),
        })
    }
}
