use super::{Fingerprint, LinkSettings, LinkSpec};
use crate::{
    config::{ExitId, GatewayId, ValidatedSite},
    render::{
        Family, RenderError, RouteTarget, Sysctl, VersionStamp, desired_routes, desired_sysctls,
        render_netns,
    },
    rules::IfName,
    verdict::v2::{PeerObs, Selection},
};
use std::collections::BTreeMap;

/// Immutable intent derived from a validated applied version, never a candidate apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    pub(super) version: u64,
    pub(super) fingerprint: Fingerprint,
    pub(super) rendered: String,
    pub(super) links: BTreeMap<String, LinkSpec>,
    pub(super) link_order: Vec<String>,
    pub(super) exits: BTreeMap<ExitId, String>,
    pub(super) routes: [(Family, RouteTarget); 2],
    pub(super) hardening: Vec<Sysctl>,
    pub(super) disconnected: bool,
}
impl Desired {
    /// Whether operator intent requires exits and forwarding to remain closed.
    #[must_use]
    pub const fn disconnected(&self) -> bool {
        self.disconnected
    }
    /// Uses the canonical fingerprint of `render_netns` supplied by the caller's
    /// renderer/canonicalizer. Pure Rust cannot ask nft to produce canonical JSON.
    /// Invalid or disconnected route intent becomes unreachable in both families.
    ///
    /// # Errors
    /// Returns `UnknownGateway` when the applied gateway is not in the site.
    pub fn new(
        site: &ValidatedSite,
        gateway: &GatewayId,
        stamp: &VersionStamp,
        fingerprint: Fingerprint,
        target: &RouteTarget,
        selection: &Selection,
    ) -> Result<Self, RenderError> {
        let gw = site.gateway(gateway).ok_or(RenderError::UnknownGateway)?;
        let client = gw.client_tunnel();
        let disconnected = *selection == Selection::Disconnected;
        let mut links = BTreeMap::new();
        let name = client.ifname().as_str().to_owned();
        let mut link_order = vec![name.clone()];
        links.insert(
            name.clone(),
            LinkSpec {
                name,
                addresses: vec![client.address4().into()],
                peers: site
                    .devices()
                    .values()
                    .filter(|d| d.gateways().contains(gateway))
                    .map(|d| PeerObs {
                        public_key: d.public_key(),
                        allowed_ips: vec![d.address4().into()],
                        endpoint: None,
                    })
                    .collect(),
                settings: LinkSettings {
                    mtu: client.mtu(),
                    public_key: client.identity().public_key.bytes().ok(),
                    listen_port: client.identity().listen_port,
                    keepalives: BTreeMap::new(),
                },
                up: true,
            },
        );
        let mut exits = BTreeMap::new();
        for exit in gw.exits().iter().filter(|e| e.enabled()) {
            let name = exit.ifname().as_str().to_owned();
            link_order.push(name.clone());
            exits.insert(exit.id().clone(), name.clone());
            links.insert(
                name.clone(),
                LinkSpec {
                    name,
                    addresses: vec![exit.address4().into()],
                    peers: vec![PeerObs {
                        public_key: exit.peer_public_key(),
                        allowed_ips: vec![ipnet::IpNet::V4(ipnet::Ipv4Net::default())],
                        endpoint: Some(exit.endpoint()),
                    }],
                    settings: LinkSettings {
                        mtu: exit.mtu(),
                        public_key: None,
                        listen_port: 0,
                        keepalives: BTreeMap::from([(exit.peer_public_key(), exit.keepalive())]),
                    },
                    up: !disconnected,
                },
            );
        }
        let selected = if disconnected {
            None
        } else {
            gw.exits()
                .iter()
                .find(|e| {
                    *target == RouteTarget::Exit(e.ifname().clone())
                        && match selection {
                            Selection::Pin(id) => e.id() == id,
                            Selection::Auto | Selection::Prefer(_) => true,
                            Selection::Disconnected => false,
                        }
                })
                .map(crate::config::ValidatedExit::id)
        };
        let names = std::iter::once(IfName::new("lo").map_err(|_| RenderError::UnknownGateway)?)
            .chain(std::iter::once(client.ifname().clone()))
            .chain(gw.exits().iter().map(|e| e.ifname().ifname().clone()))
            .collect::<Vec<_>>();
        Ok(Self {
            version: stamp.version,
            fingerprint,
            rendered: render_netns(site, gateway, stamp)?,
            links,
            link_order,
            exits,
            routes: desired_routes(site, gateway, selected),
            hardening: desired_sysctls(&names, false)
                .into_iter()
                .filter(|s| !matches!(s.key.name, "forwarding" | "ip_forward"))
                .collect(),
            disconnected,
        })
    }
    /// Published convergence target; planning never advances it.
    #[must_use]
    pub const fn applied_version(&self) -> u64 {
        self.version
    }
    /// Canonical expected whole-namespace ruleset identity.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
    /// Applied rendered nft source for the system executor's transaction checks.
    #[must_use]
    pub fn rendered(&self) -> &str {
        &self.rendered
    }
    /// Configured public tunnel settings, keyed by namespace name.
    #[must_use]
    pub fn links(&self) -> &BTreeMap<String, LinkSpec> {
        &self.links
    }
    /// Enabled exit IDs and interface names.
    #[must_use]
    pub fn exits(&self) -> &BTreeMap<ExitId, String> {
        &self.exits
    }
    /// Desired family defaults in renderer order.
    #[must_use]
    pub const fn routes(&self) -> &[(Family, RouteTarget); 2] {
        &self.routes
    }
    /// All hardening writes in renderer order, excluding the guarded forwarding keys.
    #[must_use]
    pub fn hardening(&self) -> &[Sysctl] {
        &self.hardening
    }
}
