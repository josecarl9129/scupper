use super::{
    Desired, Known, Latch, LinkPhase, LinkSettings, LinkSpec, NamespaceState, RouteKey, Ruleset,
    Step,
};
use crate::{
    config::ExitId,
    render::{Family, RouteTarget},
    verdict::v2::{
        DefaultRouteObs, DefaultRoutes, Forwarding, NetnsIdentity, NetnsObs, PeerObs, Probe,
        RulesetObs, TopologyObs,
    },
};
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet};

/// A link in the abstract kernel. Unknown fields never establish containment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelLink {
    /// Kernel kind, including `loopback`.
    pub kind: Known<String>,
    /// Positive applied ownership, not just a matching name.
    pub ours: Known<bool>,
    /// Administrative UP state.
    pub up: Known<bool>,
    /// Assigned addresses.
    pub addresses: Known<Vec<IpNet>>,
    /// Public peer keys, prefixes and informational learned endpoints.
    pub peers: Known<Vec<PeerObs>>,
    /// Public settings absent from the existing topology observation.
    pub settings: Known<LinkSettings>,
    /// Unexpected tc/XDP hooks, retaining exact deletion identities.
    pub tc_hooks: Known<Vec<String>>,
    /// IPv4 forwarding inherited on namespace entry, independently writable.
    pub forwarding_v4: Known<i64>,
    /// IPv6 forwarding inherited on namespace entry, independently writable.
    pub forwarding_v6: Known<i64>,
}
impl KernelLink {
    pub(super) fn configured(link: &LinkSpec) -> Self {
        Self {
            kind: Known::Value("wireguard".into()),
            ours: Known::Value(true),
            up: Known::Value(link.up),
            addresses: Known::Value(link.addresses.clone()),
            peers: Known::Value(link.peers.clone()),
            settings: Known::Value(link.settings.clone()),
            tc_hooks: Known::Value(vec![]),
            forwarding_v4: Known::Value(1),
            forwarding_v6: Known::Value(1),
        }
    }
    pub(super) fn owned(&self) -> bool {
        self.ours == Known::Value(true) && self.kind == Known::Value("wireguard".into())
    }
    /// Whether the observed owned tunnel is up/down as intended and exactly configured.
    #[must_use]
    pub fn ready(&self, desired: &LinkSpec) -> bool {
        self.owned() && self.up == Known::Value(desired.up) && self.matches_config(desired)
    }
    pub(super) fn matches_config(&self, desired: &LinkSpec) -> bool {
        self.addresses
            .value()
            .is_some_and(|a| same_addresses(a, &desired.addresses))
            && self
                .peers
                .value()
                .is_some_and(|p| same_peers(p, &desired.peers))
            && self.settings == Known::Value(desired.settings.clone())
    }
}
fn same_addresses(a: &[IpNet], b: &[IpNet]) -> bool {
    a.iter().collect::<BTreeSet<_>>() == b.iter().collect::<BTreeSet<_>>()
}
pub(super) fn same_peers(a: &[PeerObs], b: &[PeerObs]) -> bool {
    let normalize = |peers: &[PeerObs]| {
        peers
            .iter()
            .map(|p| {
                (
                    p.public_key,
                    p.allowed_ips.iter().copied().collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    // Duplicate peer entries are not a trustworthy configuration match.
    a.len() == b.len() && normalize(a) == normalize(b)
}

/// Collection items that can independently fail. Extra failures invalidate only
/// that item; the older unscoped `TopologyObs.errors` conservatively invalidate
/// all topology safety inventories, since their provenance is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationItem {
    /// IPv4 forwarding value.
    ForwardingV4,
    /// IPv6 forwarding value.
    ForwardingV6,
    /// IPv4 forwarding on client ingress, independently writable in Linux.
    ClientForwardingV4,
    /// Whole ruleset fingerprint.
    Ruleset,
    /// Complete link set.
    Links,
    /// A link's addresses.
    Addresses(String),
    /// A link's public peers.
    Peers(String),
    /// Per-interface hooks.
    Tc(String),
    /// RPDB inventory.
    Rules,
    /// IPv4 default.
    DefaultV4,
    /// IPv6 default.
    DefaultV6,
    /// Exact extra-route inventory.
    ExtraRoutes,
}

/// Typed forwarding reads supplementing the global/client [`Forwarding`] probe.
/// Missing or failed reads stay Unknown; these are never hardening keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForwardingGates {
    /// IPv4 forwarding inherited by newly created or moved devices.
    pub default_v4: Known<i64>,
    /// IPv6 forwarding inherited by newly created or moved devices.
    pub default_v6: Known<i64>,
    /// Per-interface IPv4 and IPv6 forwarding, in that order.
    pub links: BTreeMap<String, [Known<i64>; 2]>,
}

/// Additional public observations required for safe planning. Existing health
/// summaries lack route deletion identities, host leftovers and keepalives.
/// If the namespace name is removed or hijacked, collectors and executors must
/// access the original namespace through its held fd, never by reopening the
/// name under `/run/netns`. Link, route, ruleset and forwarding observations
/// must describe that inode; the mount name's identity is checked separately.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservationDetails {
    /// Independently failed items.
    pub failed: BTreeSet<ObservationItem>,
    /// Successful exact sysctl reads; missing values become Unknown.
    pub hardening: BTreeMap<String, Probe<String>>,
    /// Link settings including persistent keepalive, never secret keys.
    pub settings: BTreeMap<String, Probe<LinkSettings>>,
    /// Exact extra routes. None is acceptable only when the summary is empty.
    pub extra_routes: Option<Probe<Vec<RouteKey>>>,
    /// Exact extra RPDB deletion identities. Summary differences may instead
    /// mean missing baseline rules and cannot be used as deletion commands.
    pub extra_rules: Option<Probe<Vec<String>>>,
    /// Exact tc/XDP hook identities, including foreign links.
    pub tc_hooks: BTreeMap<String, Probe<Vec<String>>>,
    /// Ownership established by the collector, not inferred from link names.
    pub owned_links: BTreeSet<String>,
    /// Held boot identity, compared with `TopologyObs.netns`.
    pub expected_netns: Option<NetnsIdentity>,
    /// Whether the held namespace inode is alive when its name is gone or
    /// hijacked. Set true while the held fd remains live, including when a
    /// liveness probe is inconclusive. False asserts that the held inode is
    /// positively gone and makes namespace planning inert; the default false
    /// is not an unknown observation and must not substitute for a failed read.
    pub held_inode_alive: bool,
    /// Edge's namespace differs from the held inode.
    pub edge_elsewhere: bool,
    /// Public host inventory for configured names only; no host forwarding state.
    pub host_links: BTreeMap<String, KernelLink>,
    /// Independently detected stale exit handshakes.
    pub stale_exits: BTreeSet<ExitId>,
    /// Systemd owns restarting edge; false produces an alert only.
    pub edge_dead: bool,
}

/// Abstract kernel and persisted latch state. All fields are public so collectors
/// and property generators can represent partial, inconsistent observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelModel {
    /// Configured client ingress name.
    pub client_link: String,
    /// Global IPv4 forwarding.
    pub forwarding_v4: Known<i64>,
    /// Global IPv6 forwarding.
    pub forwarding_v6: Known<i64>,
    /// IPv4 client ingress gate; global forwarding can disagree after drift.
    pub client_forwarding_v4: Known<i64>,
    /// Forwarding inherited by links created or moved into the namespace.
    pub default_forwarding_v4: Known<i64>,
    /// IPv6 forwarding inherited by new links.
    pub default_forwarding_v6: Known<i64>,
    /// Entire namespace ruleset.
    pub ruleset: Known<Ruleset>,
    /// Per-key hardening values.
    pub hardening: BTreeMap<String, Known<String>>,
    /// Namespace interface inventory.
    pub links: BTreeMap<String, KernelLink>,
    /// Whether absence from `links` is authoritative.
    pub links_complete: bool,
    /// IPv4 default, retaining foreign/missing route observations.
    pub default_v4: Known<DefaultRouteObs>,
    /// IPv6 default.
    pub default_v6: Known<DefaultRouteObs>,
    /// Extra main-table or non-main routes with exact deletion keys.
    pub extra_routes: Known<Vec<RouteKey>>,
    /// Extra or missing-baseline policy rules, as collector deletion identities.
    pub extra_rules: Known<Vec<String>>,
    /// Flows were flushed after the last ruleset load.
    pub conntrack_flushed: bool,
    /// Latched administrative quarantine.
    pub latch: Option<Latch>,
    /// Identity faults are returned to the lifecycle reconciler.
    pub namespace: NamespaceState,
    /// Configured host-side leftovers; absent inventory entries mean no leftover.
    pub host_links: BTreeMap<String, KernelLink>,
    /// Exit endpoints that need to be re-set.
    pub stale_exits: BTreeSet<ExitId>,
    /// Edge needs an alert; systemd handles restart.
    pub edge_dead: bool,
}
impl KernelModel {
    /// A complete reference model of applied intent, useful to collectors/tests.
    #[must_use]
    pub fn desired(desired: &Desired) -> Self {
        let forwarding = i64::from(!desired.disconnected);
        let mut links = desired
            .links
            .iter()
            .map(|(name, link)| {
                let mut configured = KernelLink::configured(link);
                configured.forwarding_v4 = Known::Value(forwarding);
                configured.forwarding_v6 = Known::Value(forwarding);
                (name.clone(), configured)
            })
            .collect::<BTreeMap<_, _>>();
        links.insert(
            "lo".into(),
            KernelLink {
                kind: Known::Value("loopback".into()),
                ours: Known::Value(false),
                up: Known::Value(true),
                addresses: Known::Value(vec![]),
                peers: Known::Value(vec![]),
                settings: Known::Unknown,
                tc_hooks: Known::Value(vec![]),
                forwarding_v4: Known::Value(forwarding),
                forwarding_v6: Known::Value(forwarding),
            },
        );
        Self {
            client_link: desired.link_order[0].clone(),
            forwarding_v4: Known::Value(forwarding),
            forwarding_v6: Known::Value(forwarding),
            client_forwarding_v4: Known::Value(forwarding),
            default_forwarding_v4: Known::Value(forwarding),
            default_forwarding_v6: Known::Value(forwarding),
            ruleset: Known::Value(Ruleset::Verified(desired.fingerprint)),
            hardening: desired
                .hardening
                .iter()
                .map(|s| (s.key.to_string(), Known::Value(s.value.clone())))
                .collect(),
            links,
            links_complete: true,
            default_v4: Known::Value(route_obs(&desired.routes[0].1)),
            default_v6: Known::Value(route_obs(&desired.routes[1].1)),
            extra_routes: Known::Value(vec![]),
            extra_rules: Known::Value(vec![]),
            conntrack_flushed: true,
            latch: None,
            namespace: NamespaceState::Ready,
            host_links: BTreeMap::new(),
            stale_exits: BTreeSet::new(),
            edge_dead: false,
        }
    }
    /// Projects existing observations without promoting missing/failed items to
    /// success. Exact ruleset comparisons refer to `desired` on this same tick.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Explicit field-by-field projection of partial observations.
    pub fn from_observations(
        topology: &TopologyObs,
        forwarding: &Probe<Forwarding>,
        gates: &ForwardingGates,
        defaults: &Probe<DefaultRoutes>,
        desired: &Desired,
        details: &ObservationDetails,
    ) -> Self {
        let failed = |item| details.failed.contains(&item);
        let topology_ok = topology.errors.is_empty();
        let known = |ok, value| {
            if ok {
                Known::Value(value)
            } else {
                Known::Unknown
            }
        };
        let mut m = Self::desired(desired);
        let forwarding = forwarding.as_ref().ok();
        let defaults = defaults.as_ref().ok();
        m.forwarding_v4 = forwarding.map_or(Known::Unknown, |f| {
            known(!failed(ObservationItem::ForwardingV4), f.v4)
        });
        m.forwarding_v6 = forwarding.map_or(Known::Unknown, |f| {
            known(!failed(ObservationItem::ForwardingV6), f.v6)
        });
        m.client_forwarding_v4 = forwarding.map_or(Known::Unknown, |f| {
            known(!failed(ObservationItem::ClientForwardingV4), f.client_v4)
        });
        m.default_forwarding_v4 = gates.default_v4.clone();
        m.default_forwarding_v6 = gates.default_v6.clone();
        m.ruleset = if topology_ok && !failed(ObservationItem::Ruleset) {
            Known::Value(match topology.ruleset {
                RulesetObs::Exact => Ruleset::Verified(desired.fingerprint),
                RulesetObs::Missing => Ruleset::Absent,
                RulesetObs::Differs { live, .. } => Ruleset::Unverified(live),
            })
        } else {
            Known::Unknown
        };
        m.hardening = desired
            .hardening
            .iter()
            .map(|s| {
                let key = s.key.to_string();
                let value = details
                    .hardening
                    .get(&key)
                    .and_then(|v| v.as_ref().ok())
                    .cloned()
                    .map_or(Known::Unknown, Known::Value);
                (key, value)
            })
            .collect();
        m.links_complete =
            topology_ok && topology.links_complete && !failed(ObservationItem::Links);
        m.links = topology
            .links
            .iter()
            .map(|link| {
                let name = &link.name;
                (
                    name.clone(),
                    KernelLink {
                        forwarding_v4: if name == &desired.link_order[0] {
                            m.client_forwarding_v4.clone()
                        } else {
                            gates
                                .links
                                .get(name)
                                .map_or(Known::Unknown, |g| g[0].clone())
                        },
                        forwarding_v6: gates
                            .links
                            .get(name)
                            .map_or(Known::Unknown, |g| g[1].clone()),
                        // Existing topology observations identify the loopback exception
                        // by name; ip link's linkinfo omits a kind for it.
                        kind: if name == "lo" && link.kind.is_none() {
                            Known::Value("loopback".into())
                        } else {
                            link.kind.clone().map_or(Known::Unknown, Known::Value)
                        },
                        ours: Known::Value(details.owned_links.contains(name)),
                        up: Known::Value(link.up),
                        addresses: if topology.addresses_complete
                            && !failed(ObservationItem::Addresses(name.clone()))
                        {
                            Known::Value(link.addresses.clone())
                        } else {
                            Known::Unknown
                        },
                        peers: if name == "lo" {
                            Known::Value(vec![])
                        } else if failed(ObservationItem::Peers(name.clone())) {
                            Known::Unknown
                        } else {
                            topology
                                .peers
                                .get(name)
                                .cloned()
                                .map_or(Known::Unknown, Known::Value)
                        },
                        settings: details
                            .settings
                            .get(name)
                            .and_then(|s| s.as_ref().ok())
                            .cloned()
                            .map_or(Known::Unknown, Known::Value),
                        tc_hooks: if topology_ok && !failed(ObservationItem::Tc(name.clone())) {
                            match details.tc_hooks.get(name) {
                                Some(Ok(hooks)) => Known::Value(hooks.clone()),
                                None if !topology.tc_hooks.contains(name)
                                    && (desired.links.contains_key(name) || name == "lo") =>
                                {
                                    Known::Value(vec![])
                                }
                                Some(Err(_)) | None => Known::Unknown,
                            }
                        } else {
                            Known::Unknown
                        },
                    },
                )
            })
            .collect();
        // Duplicate names make absence/ownership claims untrustworthy.
        m.links_complete &= m.links.len() == topology.links.len();
        m.default_v4 = if defaults.is_none() || failed(ObservationItem::DefaultV4) {
            Known::Unknown
        } else {
            defaults.map_or(Known::Unknown, |d| Known::Value(d.v4.clone()))
        };
        m.default_v6 = if defaults.is_none() || failed(ObservationItem::DefaultV6) {
            Known::Unknown
        } else {
            defaults.map_or(Known::Unknown, |d| Known::Value(d.v6.clone()))
        };
        m.extra_routes = if defaults.is_none() || failed(ObservationItem::ExtraRoutes) {
            Known::Unknown
        } else {
            match &details.extra_routes {
                Some(Ok(routes)) => Known::Value(routes.clone()),
                None if defaults.is_some_and(|d| d.extra.is_empty() && d.violations.is_empty()) => {
                    Known::Value(vec![])
                }
                Some(Err(_)) | None => Known::Unknown, // Summaries lack complete deletion identities.
            }
        };
        m.extra_rules = if topology_ok && !failed(ObservationItem::Rules) {
            match &details.extra_rules {
                Some(Ok(rules)) => Known::Value(rules.clone()),
                None if topology.extra_rules.is_empty() => Known::Value(vec![]),
                Some(Err(_)) | None => Known::Unknown,
            }
        } else {
            Known::Unknown
        };
        m.namespace = match (details.expected_netns, topology.netns) {
            (None, _) => NamespaceState::Unknown,
            (Some(expected), NetnsObs::Present { device, inode })
                if expected.device == device && expected.inode == inode =>
            {
                if details.edge_elsewhere {
                    NamespaceState::EdgeElsewhere
                } else {
                    NamespaceState::Ready
                }
            }
            (Some(_), _) if details.held_inode_alive => NamespaceState::NameGone,
            (Some(_), _) => NamespaceState::InodeGone,
        };
        m.latch = forwarding
            .and_then(|f| f.quarantine.as_ref())
            .map(|_| Latch {
                reason: "persisted safety drift".into(),
                object: "persisted".into(),
            });
        m.conntrack_flushed = false; // Existing observations do not prove this history.
        m.host_links.clone_from(&details.host_links);
        m.stale_exits.clone_from(&details.stale_exits);
        m.edge_dead = details.edge_dead;
        m
    }
    /// Successful abstract execution. Real failures skip the failing step and follow
    /// [`Step::failure`], re-observing before further Restore after containment failure.
    /// Effects are unguarded so unsafe planner output remains visible to tests.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Keep each modeled kernel effect in one exhaustive match.
    pub fn apply(&self, step: &Step) -> Self {
        let mut m = self.clone();
        // ip_forward writes reset per-device redirect settings. The explicit
        // hardening writes/read-back after each gate transition restore them.
        if matches!(step, Step::ForwardingOff) || matches!(step, Step::ForwardingOn { .. }) {
            for (key, value) in &mut m.hardening {
                if key.starts_with("net.ipv4.") && key.ends_with(".accept_redirects") {
                    *value = Known::Unknown;
                }
            }
        }
        match step {
            Step::ForwardingOff => {
                m.forwarding_v4 = Known::Value(0);
                m.forwarding_v6 = Known::Value(0);
                m.client_forwarding_v4 = Known::Value(0);
                m.default_forwarding_v4 = Known::Value(0);
                m.default_forwarding_v6 = Known::Value(0);
                for link in m.links.values_mut() {
                    link.forwarding_v4 = Known::Value(0);
                    link.forwarding_v6 = Known::Value(0);
                }
            }
            Step::ForwardingOn { .. } => {
                m.forwarding_v4 = Known::Value(1);
                m.forwarding_v6 = Known::Value(1);
                m.client_forwarding_v4 = Known::Value(1);
                m.default_forwarding_v4 = Known::Value(1);
                m.default_forwarding_v6 = Known::Value(1);
                for link in m.links.values_mut() {
                    link.forwarding_v4 = Known::Value(1);
                    link.forwarding_v6 = Known::Value(1);
                }
            }
            Step::LoadRuleset { fingerprint, .. } => {
                m.ruleset = Known::Value(Ruleset::Unverified(*fingerprint));
                m.conntrack_flushed = false;
            }
            Step::VerifyRuleset { fingerprint } => {
                if matches!(m.ruleset, Known::Value(Ruleset::Unverified(f) | Ruleset::Verified(f)) if f == *fingerprint)
                {
                    m.ruleset = Known::Value(Ruleset::Verified(*fingerprint));
                }
            }
            Step::FlushConntrack => m.conntrack_flushed = true,
            Step::WriteSysctl { key, value } => {
                m.hardening
                    .insert(key.to_string(), Known::Value(value.clone()));
            }
            Step::ReadBackSysctls | Step::Emit(_) => {}
            Step::RouteReplace { family, target } => {
                *m.default_mut(*family) = Known::Value(route_obs(target));
            }
            Step::RouteDelete { route } => {
                if let Known::Value(routes) = &mut m.extra_routes {
                    routes.retain(|r| r != route);
                }
            }
            Step::LinkDown { name } => {
                if let Some(link) = m.links.get_mut(name) {
                    link.up = Known::Value(false);
                }
            }
            Step::LinkForwardingOff { name } => {
                if let Some(link) = m.links.get_mut(name) {
                    link.forwarding_v4 = Known::Value(0);
                    link.forwarding_v6 = Known::Value(0);
                }
                if name == &m.client_link {
                    m.client_forwarding_v4 = Known::Value(0);
                }
            }
            Step::LinkCreate { link, phase } => m.create_link(link, *phase),
            Step::LinkReconfigure { link } => {
                if let Some(actual) = m.links.get_mut(&link.name)
                    && actual.owned()
                {
                    let hooks = actual.tc_hooks.clone();
                    let gates = (actual.forwarding_v4.clone(), actual.forwarding_v6.clone());
                    *actual = KernelLink::configured(link);
                    actual.tc_hooks = hooks;
                    (actual.forwarding_v4, actual.forwarding_v6) = gates;
                }
            }
            Step::RuleDelete { rule } => {
                if let Known::Value(rules) = &mut m.extra_rules {
                    rules.retain(|r| r != rule);
                }
            }
            Step::TcDelete { name, hook } => {
                if let Some(link) = m.links.get_mut(name)
                    && let Known::Value(hooks) = &mut link.tc_hooks
                {
                    hooks.retain(|h| h != hook);
                }
            }
            Step::ReResolveEndpoint { exit } => {
                m.stale_exits.remove(exit);
            }
            Step::PersistLatch { reason, object } => {
                m.latch = Some(Latch {
                    reason: reason.clone(),
                    object: object.clone(),
                });
            }
        }
        m
    }
    fn create_link(&mut self, spec: &LinkSpec, phase: LinkPhase) {
        match phase {
            LinkPhase::CleanupHost => {
                if self.host_links.get(&spec.name).is_some_and(host_leftover) {
                    self.host_links.remove(&spec.name);
                }
            }
            LinkPhase::HostAddDown => {
                if !self.links.contains_key(&spec.name) && !self.host_links.contains_key(&spec.name)
                {
                    let mut link = KernelLink::configured(spec);
                    link.up = Known::Value(false);
                    link.addresses = Known::Value(vec![]);
                    link.peers = Known::Value(vec![]);
                    link.settings = Known::Unknown;
                    self.host_links.insert(spec.name.clone(), link);
                }
            }
            LinkPhase::Move => {
                if !self.links.contains_key(&spec.name)
                    && let Some(link) = self.host_links.remove(&spec.name)
                {
                    let mut link = link;
                    link.forwarding_v4 = self.default_forwarding_v4.clone();
                    link.forwarding_v6 = self.default_forwarding_v6.clone();
                    if spec.name == self.client_link {
                        self.client_forwarding_v4 = link.forwarding_v4.clone();
                    }
                    self.links.insert(spec.name.clone(), link);
                }
            }
            LinkPhase::Configure => {
                if let Some(link) = self.links.get_mut(&spec.name)
                    && link.owned()
                {
                    let hooks = link.tc_hooks.clone();
                    let gates = (link.forwarding_v4.clone(), link.forwarding_v6.clone());
                    *link = KernelLink::configured(spec);
                    link.up = Known::Value(false);
                    link.tc_hooks = hooks;
                    (link.forwarding_v4, link.forwarding_v6) = gates;
                }
            }
            LinkPhase::Up => {
                if let Some(link) = self.links.get_mut(&spec.name) {
                    link.up = Known::Value(spec.up);
                }
            }
        }
    }
    pub(super) fn default_mut(&mut self, family: Family) -> &mut Known<DefaultRouteObs> {
        match family {
            Family::V4 => &mut self.default_v4,
            Family::V6 => &mut self.default_v6,
        }
    }
    pub(super) fn default(&self, family: Family) -> &Known<DefaultRouteObs> {
        match family {
            Family::V4 => &self.default_v4,
            Family::V6 => &self.default_v6,
        }
    }
    /// An exit route requires verified policy and a configured, wanted UP link.
    #[must_use]
    pub fn route_ready(&self, desired: &Desired, target: &RouteTarget) -> bool {
        match target {
            RouteTarget::Unreachable => true,
            RouteTarget::Exit(name) => {
                self.ruleset == Known::Value(Ruleset::Verified(desired.fingerprint()))
                    && desired.links().get(name.as_str()).is_some_and(|want| {
                        want.up
                            && self
                                .links
                                .get(name.as_str())
                                .is_some_and(|link| link.ready(want))
                    })
            }
        }
    }
    /// Both forwarding gates are positively observed closed.
    #[must_use]
    pub fn forwarding_off(&self) -> bool {
        self.forwarding_v4 == Known::Value(0)
            && self.forwarding_v6 == Known::Value(0)
            && self.client_forwarding_v4 == Known::Value(0)
            && self.default_forwarding_v4 == Known::Value(0)
            && self.default_forwarding_v6 == Known::Value(0)
            && self
                .links
                .values()
                .filter(|link| link.up != Known::Value(false))
                .all(|link| {
                    link.forwarding_v4 == Known::Value(0) && link.forwarding_v6 == Known::Value(0)
                })
    }
}
pub(super) fn host_leftover(link: &KernelLink) -> bool {
    link.owned()
        && link.up == Known::Value(false)
        && link.addresses == Known::Value(vec![])
        && link.peers == Known::Value(vec![])
        && link.tc_hooks == Known::Value(vec![])
}
pub(super) fn route_obs(target: &RouteTarget) -> DefaultRouteObs {
    match target {
        RouteTarget::Exit(name) => DefaultRouteObs::Dev(name.as_str().into()),
        RouteTarget::Unreachable => DefaultRouteObs::Unreachable,
    }
}
// An extra prefix through a configured, ready exit cannot bypass the kill switch.
// It remains routing drift to delete, without closing or flushing established flows.
fn exit_prefix_routes_safe(model: &KernelModel, desired: &Desired) -> bool {
    use crate::parse::{RouteDestination, RouteKind, RoutingTable};
    model.extra_routes.value().is_some_and(|routes| {
        routes.iter().all(|route| {
            route.entry.kind == RouteKind::Unicast
                && route.entry.table == RoutingTable::Main
                && matches!(route.entry.dst, RouteDestination::Prefix(_))
                && route.entry.dev.as_ref().is_some_and(|name| {
                    desired.routes.iter().any(|(family, target)| {
                        *family == route.family
                            && matches!(target, RouteTarget::Exit(exit) if exit.as_str() == name)
                    }) && model.links.get(name).is_some_and(|link| {
                        desired.links.get(name).is_some_and(|want| link.ready(want))
                    })
                })
        })
    })
}
/// Containment, independent of availability. Unknown safety items are unsafe,
/// including while forwarding is closed (tc can bypass the forwarding gate).
#[must_use]
pub fn safe(m: &KernelModel, desired: &Desired) -> bool {
    let forwarding_ok = [
        &m.forwarding_v4,
        &m.forwarding_v6,
        &m.client_forwarding_v4,
        &m.default_forwarding_v4,
        &m.default_forwarding_v6,
    ]
    .iter()
    .all(|value| match value {
        Known::Value(0) => true,
        Known::Value(1) => {
            m.latch.is_none() && m.ruleset == Known::Value(Ruleset::Verified(desired.fingerprint))
        }
        Known::Unknown | Known::Value(_) => false,
    });
    let link_gates_ok = m
        .links
        .values()
        .filter(|l| l.up == Known::Value(true))
        .all(|l| {
            [&l.forwarding_v4, &l.forwarding_v6]
                .iter()
                .all(|gate| match gate {
                    Known::Value(0) => true,
                    Known::Value(1) => {
                        m.latch.is_none()
                            && m.ruleset == Known::Value(Ruleset::Verified(desired.fingerprint))
                    }
                    _ => false,
                })
        });
    let routes_ok = [&m.default_v4, &m.default_v6]
        .iter()
        .all(|route| match route {
            Known::Value(DefaultRouteObs::Unreachable | DefaultRouteObs::Missing) => true,
            Known::Value(DefaultRouteObs::Dev(name)) => {
                desired.exits.values().any(|n| n == name)
                    && m.links.get(name).is_some_and(KernelLink::owned)
            }
            Known::Unknown | Known::Value(DefaultRouteObs::Other(_)) => false,
        });
    (!desired.disconnected || m.forwarding_off())
        && forwarding_ok
        && m.ruleset != Known::Unknown
        && link_gates_ok
        && routes_ok
        && !matches!(
            m.namespace,
            NamespaceState::InodeGone | NamespaceState::Unknown
        )
        && m.links_complete
        && exit_prefix_routes_safe(m, desired)
        && m.extra_rules == Known::Value(vec![])
        && m.links.iter().all(|(name, link)| {
            let loopback = link.kind == Known::Value("loopback".into());
            link.tc_hooks == Known::Value(vec![])
                && matches!(link.up, Known::Value(_))
                && (loopback
                    || if let Some(want) = desired.links.get(name) {
                        (link.owned()
                            && link
                                .peers
                                .value()
                                .is_some_and(|p| same_peers(p, &want.peers)))
                            || link.up == Known::Value(false)
                    } else {
                        link.up == Known::Value(false)
                    })
        })
}
