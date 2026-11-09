//! Immutable renderer inputs, constructed only after exhaustive validation.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use ipnet::Ipv4Net;

use super::{
    model::{
        AlertSink, ApiSettings, Device, DnsSettings, Exit, Gateway, HealthSettings,
        HeartbeatSettings, Identity, Policy, Site, SiteConfig, User,
    },
    network::https_host,
    types::{ExitId, ExitIfname, ExitName, GatewayId, SecretName, Tag},
};
use crate::rules::IfName;

/// A site that has passed every safety and release check. Only produced by [`super::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedSite {
    config: SiteConfig,
    gateways: BTreeMap<GatewayId, ValidatedGateway>,
    devices: BTreeMap<String, ValidatedDevice>,
    health: ValidatedHealth,
}
impl ValidatedSite {
    /// Selects a gateway by stable ID without reading a local gateway-id file.
    #[must_use]
    pub fn gateway(&self, id: &GatewayId) -> Option<&ValidatedGateway> {
        self.gateways.get(id)
    }
    /// Returns the site's immutable metadata.
    #[must_use]
    pub fn site(&self) -> &Site {
        &self.config.site
    }
    /// Returns all validated gateways.
    #[must_use]
    pub fn gateways(&self) -> &BTreeMap<GatewayId, ValidatedGateway> {
        &self.gateways
    }
    /// Returns validated host peers, indexed by device ID.
    #[must_use]
    pub fn devices(&self) -> &BTreeMap<String, ValidatedDevice> {
        &self.devices
    }
    /// Returns immutable health settings with typed durations, addresses and URLs.
    #[must_use]
    pub fn health(&self) -> &ValidatedHealth {
        &self.health
    }
    /// Returns the validated global failover policy.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.config.policy
    }
    /// Returns optional external dead-man settings.
    #[must_use]
    pub fn heartbeat(&self) -> Option<&HeartbeatSettings> {
        self.config.heartbeat.as_ref()
    }
    /// Returns the supported alert sinks.
    #[must_use]
    pub fn sinks(&self) -> &BTreeMap<String, AlertSink> {
        &self.config.alerts.sinks
    }
    /// Returns the validated user roles.
    #[must_use]
    pub fn users(&self) -> &BTreeMap<String, User> {
        &self.config.users
    }
}

/// A strictly parsed HTTPS URL, constructed only after site validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    text: String,
    host: String,
}
impl ValidatedUrl {
    fn build(text: &str) -> Option<Self> {
        Some(Self {
            text: text.into(),
            host: https_host(text)?.into(),
        })
    }
    /// Borrows the validated URL text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
    /// Returns the DNS name or literal IP, without IPv6 brackets or a port.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    /// Returns a literal host address, or `None` for DNS names.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

/// Typed health inputs, constructed only after site validation.
#[derive(Debug, Clone)]
pub struct ValidatedHealth {
    handshake_stale: Duration,
    failover_grace: Duration,
    probe_targets: Vec<ValidatedUrl>,
    route_probe_dst4: Ipv4Addr,
    route_probe_dst6: Ipv6Addr,
    speed_test_url: ValidatedUrl,
    require_daemon: bool,
}
impl ValidatedHealth {
    fn build(health: &HealthSettings) -> Option<Self> {
        Some(Self {
            handshake_stale: health.handshake_stale.duration().ok()?,
            failover_grace: health.failover_grace.duration().ok()?,
            probe_targets: health
                .probe_targets
                .iter()
                .map(|url| ValidatedUrl::build(url))
                .collect::<Option<_>>()?,
            route_probe_dst4: health.route_probe_dst4.parse().ok()?,
            route_probe_dst6: health.route_probe_dst6.parse().ok()?,
            speed_test_url: ValidatedUrl::build(&health.speed_test_url)?,
            require_daemon: health.require_daemon,
        })
    }
    /// Returns the maximum fresh handshake age.
    #[must_use]
    pub fn handshake_stale(&self) -> Duration {
        self.handshake_stale
    }
    /// Returns the failover pending grace.
    #[must_use]
    pub fn failover_grace(&self) -> Duration {
        self.failover_grace
    }
    /// Returns the validated exit-IP HTTPS targets.
    #[must_use]
    pub fn probe_targets(&self) -> &[ValidatedUrl] {
        &self.probe_targets
    }
    /// Returns the IPv4 forwarding probe destination.
    #[must_use]
    pub fn route_probe_dst4(&self) -> Ipv4Addr {
        self.route_probe_dst4
    }
    /// Returns the IPv6 forwarding probe destination.
    #[must_use]
    pub fn route_probe_dst6(&self) -> Ipv6Addr {
        self.route_probe_dst6
    }
    /// Returns the validated speed-test target.
    #[must_use]
    pub fn speed_test_url(&self) -> &ValidatedUrl {
        &self.speed_test_url
    }
    /// Returns whether absence of the supervisor yields verdict 5.
    #[must_use]
    pub fn require_daemon(&self) -> bool {
        self.require_daemon
    }
}

/// A gateway's typed renderer inputs. Obtain it from `ValidatedSite::gateway`. Only produced by [`super::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedGateway {
    /// Original settings, already validated and immutable through the site accessor.
    settings: Gateway,
    /// Parsed host uplink interfaces.
    uplinks: Vec<IfName>,
    /// Parsed client-facing literal endpoint.
    endpoint: SocketAddr,
    /// Typed client tunnel, with its resolved identity.
    client_tunnel: ValidatedClientTunnel,
    /// Enabled exits in policy order.
    exits: Vec<ValidatedExit>,
}

/// Client interface, subnet and resolved identity. Only produced by [`super::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedClientTunnel {
    /// Validated Linux interface name.
    ifname: IfName,
    /// IPv4 interface address with the client subnet prefix.
    address4: Ipv4Net,
    /// Resolved client-facing public identity and local private-key reference.
    identity: Identity,
    identity_id: String,
    /// `WireGuard` MTU.
    mtu: u32,
}

/// An enabled exit in policy order, with typed network inputs. Only produced by [`super::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedExit {
    /// Original validated exit metadata and references.
    settings: Exit,
    /// Exit-only interface type, sharing the rules renderer's interface representation.
    ifname: ExitIfname,
    /// Literal provider endpoint.
    endpoint: SocketAddr,
    /// Assigned provider address and prefix.
    address4: Ipv4Net,
    /// Literal provider DNS servers.
    dns: Vec<IpAddr>,
    /// Decoded provider public key.
    peer_public_key: [u8; 32],
    /// Positive persistent keepalive.
    keepalive: Duration,
}

/// Client peer whose `AllowedIPs` are guaranteed to contain only a host prefix. Only produced by [`super::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedDevice {
    /// Original validated user, gateway and token-hash references.
    settings: Device,
    /// Unique IPv4 host prefix inside the selected client subnet.
    address4: Ipv4Net,
    /// Decoded public peer key.
    public_key: [u8; 32],
}

impl ValidatedGateway {
    /// Returns the owned network namespace.
    #[must_use]
    pub fn netns(&self) -> &str {
        &self.settings.netns
    }
    /// Returns host uplink interfaces.
    #[must_use]
    pub fn uplinks(&self) -> &[IfName] {
        &self.uplinks
    }
    /// Returns the client-facing endpoint.
    #[must_use]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
    /// Returns the client tunnel and resolved identity.
    #[must_use]
    pub fn client_tunnel(&self) -> &ValidatedClientTunnel {
        &self.client_tunnel
    }
    /// Returns enabled exits in policy order.
    #[must_use]
    pub fn exits(&self) -> &[ValidatedExit] {
        &self.exits
    }
    /// Returns optional API settings.
    #[must_use]
    pub fn api(&self) -> Option<&ApiSettings> {
        self.settings.api.as_ref()
    }
    /// Returns optional DNS settings.
    #[must_use]
    pub fn dns(&self) -> Option<&DnsSettings> {
        self.settings.dns.as_ref()
    }
}

impl ValidatedClientTunnel {
    /// Returns the client interface name.
    #[must_use]
    pub fn ifname(&self) -> &IfName {
        &self.ifname
    }
    /// Returns the gateway address and client prefix.
    #[must_use]
    pub fn address4(&self) -> Ipv4Net {
        self.address4
    }
    /// Returns the resolved public identity and secret reference.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Returns the identity reference name.
    #[must_use]
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }
    /// Returns the tunnel MTU.
    #[must_use]
    pub fn mtu(&self) -> u32 {
        self.mtu
    }
}

impl ValidatedExit {
    /// Returns the stable exit ID.
    #[must_use]
    pub fn id(&self) -> &ExitId {
        &self.settings.id
    }
    /// Returns the display name.
    #[must_use]
    pub fn name(&self) -> &ExitName {
        &self.settings.name
    }
    /// Returns configured labels.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        &self.settings.tags
    }
    /// Returns the supported provider.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.settings.provider
    }
    /// Returns the local private-key reference.
    #[must_use]
    pub fn private_key_ref(&self) -> &SecretName {
        &self.settings.private_key_ref
    }
    /// Returns the tunnel MTU.
    #[must_use]
    pub fn mtu(&self) -> u32 {
        self.settings.mtu
    }
    /// Returns whether the exit is enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.settings.enabled
    }
    /// Returns the exit interface name.
    #[must_use]
    pub fn ifname(&self) -> &ExitIfname {
        &self.ifname
    }
    /// Returns the provider endpoint.
    #[must_use]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
    /// Returns the assigned IPv4 host prefix.
    #[must_use]
    pub fn address4(&self) -> Ipv4Net {
        self.address4
    }
    /// Returns provider DNS servers.
    #[must_use]
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }
    /// Returns the validated public provider key encoding.
    #[must_use]
    pub fn peer_public_key_text(&self) -> &super::PublicKey {
        &self.settings.peer_public_key
    }
    /// Returns the decoded provider peer key.
    #[must_use]
    pub fn peer_public_key(&self) -> [u8; 32] {
        self.peer_public_key
    }
    /// Returns persistent keepalive.
    #[must_use]
    pub fn keepalive(&self) -> Duration {
        self.keepalive
    }
}

impl ValidatedDevice {
    /// Returns the owning user ID.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.settings.user
    }
    /// Returns selected gateway IDs.
    #[must_use]
    pub fn gateways(&self) -> &[GatewayId] {
        &self.settings.gateways
    }
    /// Returns the optional API token digest.
    #[must_use]
    pub fn api_token_sha256(&self) -> Option<&str> {
        self.settings.api_token_sha256.as_deref()
    }
    /// Returns the unique IPv4 host prefix.
    #[must_use]
    pub fn address4(&self) -> Ipv4Net {
        self.address4
    }
    /// Returns the validated public device key encoding.
    #[must_use]
    pub fn public_key_text(&self) -> &super::PublicKey {
        &self.settings.public_key
    }
    /// Returns the decoded peer key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

pub(super) fn build(cfg: SiteConfig) -> Option<ValidatedSite> {
    let mut gateways = BTreeMap::new();
    for (id, gw) in &cfg.gateways {
        let client = &gw.client_tunnel;
        let mut exits = Vec::new();
        for id in &cfg.policy.exits {
            let exit = gw.exits.iter().find(|e| &e.id == id)?;
            exits.push(ValidatedExit {
                settings: exit.clone(),
                ifname: ExitIfname::validated(&exit.ifname)?,
                endpoint: exit.endpoint.parse().ok()?,
                address4: exit.address4.parse().ok()?,
                dns: exit
                    .dns
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<_, _>>()
                    .ok()?,
                peer_public_key: exit.peer_public_key.bytes().ok()?,
                keepalive: exit.keepalive.duration().ok()?,
            });
        }
        gateways.insert(
            id.clone(),
            ValidatedGateway {
                settings: gw.clone(),
                uplinks: gw
                    .uplinks
                    .iter()
                    .map(|s| IfName::site_name(s))
                    .collect::<Result<_, _>>()
                    .ok()?,
                endpoint: gw.endpoint.parse().ok()?,
                client_tunnel: ValidatedClientTunnel {
                    ifname: IfName::site_name(&client.ifname).ok()?,
                    address4: client.address4.parse().ok()?,
                    identity: cfg.identities.get(&client.identity)?.clone(),
                    identity_id: client.identity.clone(),
                    mtu: client.mtu,
                },
                exits,
            },
        );
    }
    let devices = cfg
        .devices
        .iter()
        .map(|(id, device)| {
            Some((
                id.clone(),
                ValidatedDevice {
                    settings: device.clone(),
                    address4: device.address4.parse().ok()?,
                    public_key: device.public_key.bytes().ok()?,
                },
            ))
        })
        .collect::<Option<_>>()?;
    Some(ValidatedSite {
        health: ValidatedHealth::build(&cfg.health)?,
        config: cfg,
        gateways,
        devices,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Invalid internal fixtures must fail these tests.
mod render_tests {
    use super::*;
    use crate::{
        config::parse_site,
        render::{Family, RouteTarget, VersionStamp, desired_routes, render_netns},
    };

    // Release validation requires one enabled exit. Build internal fixtures here
    // to exercise fail-closed renderer behavior without relaxing that contract.
    fn no_exit_site(disabled: bool) -> ValidatedSite {
        let mut cfg = parse_site(include_str!("../../tests/fixtures/site-m2.toml")).unwrap();
        if disabled {
            cfg.gateways
                .get_mut(&GatewayId("gw1".into()))
                .unwrap()
                .exits[0]
                .enabled = false;
        } else {
            cfg.policy.exits.clear();
        }
        build(cfg).unwrap()
    }

    #[test]
    fn empty_enabled_exit_list_matches_golden() {
        let stamp = VersionStamp {
            version: 43,
            sha256: std::array::from_fn(|i| u8::try_from(i).unwrap()),
        };
        for disabled in [false, true] {
            assert_eq!(
                render_netns(&no_exit_site(disabled), &GatewayId("gw1".into()), &stamp).unwrap(),
                include_str!("../../tests/golden/netns-m2-no-exit.nft")
            );
        }
    }

    #[test]
    fn desired_routes_ignores_disabled_exits() {
        let site = no_exit_site(true);
        assert!(!site.gateway(&GatewayId("gw1".into())).unwrap().exits()[0].enabled());
        assert_eq!(
            desired_routes(&site, &GatewayId("gw1".into()), Some(&ExitId("ch1".into()))),
            [
                (Family::V4, RouteTarget::Unreachable),
                (Family::V6, RouteTarget::Unreachable)
            ]
        );
    }
}
