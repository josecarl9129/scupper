//! Complete repair inventories. The health summaries deliberately discard identities.
use super::{key_bytes, peer_field, topology::peers, wg};
use crate::{
    canon::{canonicalize, command_result, fingerprint},
    cmd::{IpCmd, KernelCmd, NftCmd, RouteTable, SysctlCmd, TcCmd, TcParent, run_cmd},
    netns::NetnsHandle,
    reconcile::Observation,
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, ExecTarget, Program, System},
};
use scupper_core::{
    failover::ExitLinkState,
    parse::{
        Handshake, WgField, WgOutput, parse_ip_addr, parse_ip_link, parse_ip_route, parse_ip_rule,
        parse_sysctl, parse_tc_filter, parse_tc_qdisc,
    },
    planner::{
        Desired, KernelLink, KernelModel, Known, LinkSettings, NamespaceState, RouteKey, Ruleset,
    },
    render::{Family, Scope, SysctlFamily, SysctlKey},
    rules::IfName,
    verdict::v2::{DefaultRouteObs, HealthConfigV2, Probe, ProbeError},
};
use std::{
    cell::Cell,
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Applies a shared safety deadline in addition to the per-exec bound.
struct SafetySystem<'a> {
    system: &'a dyn System,
    deadline: Instant,
    failed: Cell<bool>,
}
impl System for SafetySystem<'_> {
    fn canon_cache(&self) -> Option<(&std::cell::RefCell<crate::canon::CanonCache>, &Path)> {
        self.system.canon_cache()
    }

    fn run(&self, p: Program, args: &[String], timeout: Duration) -> Result<ExecOutput, ExecError> {
        self.run_in(ExecTarget::Host, p, args, timeout)
    }
    fn run_in(
        &self,
        target: ExecTarget<'_>,
        p: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let result = if remaining.is_zero() {
            Err(ExecError::Timeout {
                after: Duration::from_secs(6),
            })
        } else {
            self.system
                .run_in(target, p, args, timeout.min(EXEC_TIMEOUT).min(remaining))
        };
        if !result.as_ref().is_ok_and(|out| out.status == Some(0)) {
            self.failed.set(true);
        }
        result
    }
    fn now_unix_secs(&self) -> u64 {
        self.system.now_unix_secs()
    }
    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        self.system.wireguard_socket_dirs()
    }
}
fn read(sys: &dyn System, held: &NetnsHandle, cmd: &KernelCmd) -> Probe<String> {
    command_result(run_cmd(sys, ExecTarget::Netns(held), cmd, EXEC_TIMEOUT))
}
fn known<T>(value: Probe<T>) -> Known<T> {
    value.map_or(Known::Unknown, Known::Value)
}
fn gate(
    sys: &dyn System,
    held: &NetnsHandle,
    family: SysctlFamily,
    scope: Scope,
    name: &'static str,
) -> Known<i64> {
    known(
        read(
            sys,
            held,
            &KernelCmd::Sysctl(SysctlCmd::Read(SysctlKey {
                family,
                scope,
                name,
            })),
        )
        .and_then(|s| Ok(parse_sysctl(&s)?)),
    )
}

pub(crate) fn hooks(
    sys: &dyn System,
    held: &NetnsHandle,
    name: &str,
    xdp: bool,
) -> Probe<Vec<String>> {
    hooks_in(sys, ExecTarget::Netns(held), name, xdp)
}
fn read_in(sys: &dyn System, target: ExecTarget<'_>, cmd: &KernelCmd) -> Probe<String> {
    command_result(run_cmd(sys, target, cmd, EXEC_TIMEOUT))
}
fn hooks_in(sys: &dyn System, target: ExecTarget<'_>, name: &str, xdp: bool) -> Probe<Vec<String>> {
    let dev = IfName::new(name).map_err(|_| ProbeError::io("unrepresentable tc link"))?;
    let qdiscs = parse_tc_qdisc(&read_in(
        sys,
        target,
        &KernelCmd::Tc(TcCmd::QdiscShowJson { dev: dev.clone() }),
    )?)?;
    let mut hooks = Vec::new();
    if xdp {
        hooks.push("xdp".into());
    }
    for q in qdiscs {
        if q.kind == "noqueue"
            && q.root
            && q.handle.as_deref() == Some("0:")
            && q.parent.is_none()
            && q.dev.as_deref().is_none_or(|d| d == name)
            && q.options
                .as_ref()
                .is_none_or(|o| o.as_object().is_some_and(serde_json::Map::is_empty))
        {
            continue;
        }
        hooks.push(if matches!(q.kind.as_str(), "ingress" | "clsact") {
            q.kind
        } else {
            "root".into()
        });
    }
    for parent in [TcParent::Root, TcParent::Ingress, TcParent::Egress] {
        let filters = parse_tc_filter(&read_in(
            sys,
            target,
            &KernelCmd::Tc(TcCmd::FilterShowJson {
                dev: dev.clone(),
                parent,
            }),
        )?)?;
        if !filters.is_empty() {
            hooks.push(
                match parent {
                    TcParent::Root => "root",
                    TcParent::Ingress => "ingress-filters",
                    TcParent::Egress => "egress-filters",
                }
                .into(),
            );
        }
    }
    hooks.sort();
    hooks.dedup();
    Ok(hooks)
}

fn settings(
    sys: &dyn System,
    held: &NetnsHandle,
    name: &str,
    mtu: u32,
    client: bool,
) -> Probe<LinkSettings> {
    let public_key = if client {
        match wg(sys, held, name, WgField::PublicKey)? {
            WgOutput::PublicKey(key) => key.as_ref().map(key_bytes).transpose()?,
            _ => return Err(ProbeError::io("invalid public key field")),
        }
    } else {
        None
    };
    let WgOutput::ListenPort(port) = wg(sys, held, name, WgField::ListenPort)? else {
        return Err(ProbeError::io("invalid listen port field"));
    };
    let keepalives = if client {
        BTreeMap::new()
    } else {
        peer_field(sys, held, name, WgField::PersistentKeepalive)?
            .into_iter()
            .map(|p| {
                Ok((
                    key_bytes(&p.public_key)?,
                    Duration::from_secs(u64::from(
                        p.keepalive
                            .ok_or_else(|| ProbeError::io("missing keepalive"))?,
                    )),
                ))
            })
            .collect::<Probe<_>>()?
    };
    Ok(LinkSettings {
        mtu,
        public_key,
        listen_port: if client { u32::from(port) } else { 0 },
        keepalives,
    })
}

pub(crate) fn rules(sys: &dyn System, held: &NetnsHandle) -> Probe<Vec<String>> {
    let mut extra = Vec::new();
    for family in [Family::V4, Family::V6] {
        let raw = read(sys, held, &KernelCmd::Ip(IpCmd::RuleShowJson { family }))?;
        let mut parsed = parse_ip_rule(&raw)?;
        let json: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| ProbeError::io("invalid rules"))?;
        let baseline = if family == Family::V4 {
            r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]"#
        } else {
            r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]"#
        };
        let want = parse_ip_rule(baseline)?;
        for rule in &mut parsed {
            if matches!(rule.protocol.as_deref(), Some("kernel" | "2")) {
                rule.protocol = None;
            }
        }
        if !want.iter().all(|r| parsed.contains(r)) {
            return Err(ProbeError::io("baseline policy rule missing"));
        }
        for (index, rule) in parsed.iter().enumerate().filter(|(_, r)| !want.contains(r)) {
            if parsed
                .iter()
                .filter(|r| r.priority == rule.priority)
                .count()
                != 1
            {
                return Err(ProbeError::io("ambiguous rule priority"));
            }
            extra.push(
                serde_json::json!({"v6": family == Family::V6, "rule": json[index]}).to_string(),
            );
        }
    }
    Ok(extra)
}

fn routes(sys: &dyn System, held: &NetnsHandle, cfg: &HealthConfigV2, model: &mut KernelModel) {
    let mut extra = Vec::new();
    let mut complete = true;
    for family in [Family::V4, Family::V6] {
        let result = read(
            sys,
            held,
            &KernelCmd::Ip(IpCmd::RouteShowJson {
                family,
                table: RouteTable::All,
            }),
        )
        .and_then(|s| Ok(parse_ip_route(&s)?));
        let target = if family == Family::V4 {
            &mut model.default_v4
        } else {
            &mut model.default_v6
        };
        *target = Known::Unknown;
        match result {
            Ok(routes) => {
                let mut default_seen = false;
                *target = Known::Value(DefaultRouteObs::Missing);
                for route in routes {
                    use scupper_core::parse::{RouteDestination, RoutingTable};
                    if route.table == RoutingTable::Main
                        && route.dst == RouteDestination::Default
                        && !default_seen
                    {
                        *target = Known::Value(super::routes::answer(&route));
                        default_seen = true;
                    } else if !(route.table == RoutingTable::Main
                        && super::routes::kernel_route(&route, cfg)
                        || route.table == RoutingTable::Local
                            && super::routes::kernel_local(&route, cfg, family))
                    {
                        extra.push(RouteKey {
                            family,
                            entry: route,
                        });
                    }
                }
            }
            Err(_) => complete = false,
        }
    }
    model.extra_routes = if complete {
        Known::Value(extra)
    } else {
        Known::Unknown
    };
}

// Safety first: inode, links, ruleset, all forwarding gates and hooks. Only then
// collect public configuration, routes, host leftovers, hardening and handshakes.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) fn observe(
    sys: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    _cfg: &HealthConfigV2,
    namespace: &Path,
    edge: Option<&Path>,
    owned: &BTreeMap<String, u32>,
) -> Observation {
    let start = Instant::now();
    let safety = SafetySystem {
        system: sys,
        deadline: start + Duration::from_secs(6),
        failed: Cell::new(false),
    };
    let mut model = KernelModel::desired(desired);
    model.conntrack_flushed = false;
    model.latch = None;
    model.namespace = match std::fs::metadata(namespace) {
        Ok(metadata) if (metadata.dev(), metadata.ino()) == held.identity() => {
            NamespaceState::Ready
        }
        Ok(_) => NamespaceState::NameGone,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => NamespaceState::NameGone,
        Err(_) => {
            safety.failed.set(true);
            NamespaceState::Unknown
        }
    };
    if let Some(path) = edge {
        match std::fs::metadata(path) {
            Ok(metadata) if (metadata.dev(), metadata.ino()) != held.identity() => {
                if model.namespace == NamespaceState::Ready {
                    model.namespace = NamespaceState::EdgeElsewhere;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => model.edge_dead = true,
            Err(_) => safety.failed.set(true),
        }
    }
    let raw = read(&safety, held, &KernelCmd::Ip(IpCmd::LinkShowJson))
        .and_then(|s| Ok(parse_ip_link(&s)?));
    model.links_complete = raw.is_ok();
    let raw = raw.unwrap_or_else(|_| {
        safety.failed.set(true);
        vec![]
    });
    model.links.clear();
    model.ruleset = if safety.canon_cache().is_some() {
        known(
            crate::canon::netns_rulesets(&safety, held, desired.rendered()).and_then(
                |(want, live)| {
                    Ok(if live == want {
                        Ruleset::Verified(desired.fingerprint())
                    } else if live
                        .get("nftables")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(Vec::is_empty)
                    {
                        Ruleset::Absent
                    } else {
                        Ruleset::Unverified(fingerprint(&live)?)
                    })
                },
            ),
        )
    } else {
        known(
            read(&safety, held, &KernelCmd::Nft(NftCmd::ListRulesetJson)).and_then(|s| {
                let canon = canonicalize(&s)?;
                let live = fingerprint(&canon)?;
                Ok(if live == desired.fingerprint() {
                    Ruleset::Verified(live)
                } else if canon
                    .get("nftables")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                {
                    Ruleset::Absent
                } else {
                    Ruleset::Unverified(live)
                })
            }),
        )
    };
    model.forwarding_v4 = gate(
        &safety,
        held,
        SysctlFamily::Ipv4,
        Scope::Global,
        "ip_forward",
    );
    model.forwarding_v6 = gate(&safety, held, SysctlFamily::Ipv6, Scope::All, "forwarding");
    model.default_forwarding_v4 = gate(
        &safety,
        held,
        SysctlFamily::Ipv4,
        Scope::Default,
        "forwarding",
    );
    model.default_forwarding_v6 = gate(
        &safety,
        held,
        SysctlFamily::Ipv6,
        Scope::Default,
        "forwarding",
    );
    for link in &raw {
        let name = &link.ifname;
        let ifname = IfName::new(name);
        let (gates, tc) = match ifname {
            Ok(dev) => (
                [
                    gate(
                        &safety,
                        held,
                        SysctlFamily::Ipv4,
                        Scope::Link(dev.clone()),
                        "forwarding",
                    ),
                    gate(
                        &safety,
                        held,
                        SysctlFamily::Ipv6,
                        Scope::Link(dev),
                        "forwarding",
                    ),
                ],
                known(hooks(&safety, held, name, link.xdp)),
            ),
            Err(_) => ([Known::Unknown, Known::Unknown], Known::Unknown),
        };
        model.links.insert(
            name.clone(),
            KernelLink {
                kind: Known::Value(if name == "lo" {
                    "loopback".into()
                } else {
                    link.kind.clone().unwrap_or_default()
                }),
                ours: Known::Value(
                    owned.get(name) == Some(&link.ifindex)
                        && link.kind.as_deref() == Some("wireguard"),
                ),
                up: Known::Value(link.flags.iter().any(|f| f == "UP")),
                addresses: Known::Unknown,
                peers: if link.kind.as_deref() == Some("wireguard") {
                    Known::Unknown
                } else {
                    Known::Value(vec![])
                },
                settings: Known::Unknown,
                tc_hooks: tc,
                forwarding_v4: gates[0].clone(),
                forwarding_v6: gates[1].clone(),
            },
        );
    }
    model.client_forwarding_v4 = model
        .links
        .get(&model.client_link)
        .map_or(Known::Value(0), |l| l.forwarding_v4.clone());
    let safety_complete = !safety.failed.get()
        && start.elapsed() <= Duration::from_secs(6)
        && model.ruleset != Known::Unknown
        && [
            &model.forwarding_v4,
            &model.forwarding_v6,
            &model.default_forwarding_v4,
            &model.default_forwarding_v6,
        ]
        .iter()
        .all(|v| **v != Known::Unknown)
        && model.links.values().all(|l| {
            l.tc_hooks != Known::Unknown
                && l.forwarding_v4 != Known::Unknown
                && l.forwarding_v6 != Known::Unknown
        });
    let safety_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    super::super::reconcile::unknown_nonsafety(&mut model);
    Observation {
        model,
        safety_complete,
        safety_ms,
        complete: safety_complete,
        handshakes: BTreeMap::new(),
        exit_links: BTreeMap::new(),
    }
}

/// Complete availability observations only after the emergency prefix.
#[allow(clippy::too_many_lines)]
pub(crate) fn observe_rest(
    system: &dyn System,
    held: &NetnsHandle,
    desired: &Desired,
    cfg: &HealthConfigV2,
    observed: Observation,
    deadline: Instant,
) -> Observation {
    let bounded = SafetySystem {
        system,
        deadline,
        failed: Cell::new(false),
    };
    let sys: &dyn System = &bounded;
    let Observation {
        mut model,
        safety_complete,
        safety_ms,
        ..
    } = observed;
    let raw = read(sys, held, &KernelCmd::Ip(IpCmd::LinkShowJson))
        .and_then(|s| Ok(parse_ip_link(&s)?))
        .unwrap_or_default();
    let addresses = read(sys, held, &KernelCmd::Ip(IpCmd::AddrShowJson))
        .and_then(|s| Ok(parse_ip_addr(&s)?))
        .ok();
    for link in &raw {
        let Some(actual) = model.links.get_mut(&link.ifname) else {
            continue;
        };
        actual.addresses = addresses
            .as_ref()
            .and_then(|a| {
                a.iter()
                    .find(|a| a.ifindex == link.ifindex && a.ifname == link.ifname)
            })
            .map_or(Known::Unknown, |a| {
                known(
                    a.addresses
                        .iter()
                        .map(|a| {
                            ipnet::IpNet::new(a.local, a.prefixlen)
                                .map_err(|_| ProbeError::io("invalid prefix"))
                        })
                        .collect(),
                )
            });
        if link.kind.as_deref() == Some("wireguard") && desired.links().contains_key(&link.ifname) {
            actual.peers = known(peers(sys, held, &link.ifname));
            actual.settings = known(settings(
                sys,
                held,
                &link.ifname,
                link.mtu,
                link.ifname == model.client_link,
            ));
        }
    }
    for setting in desired.hardening() {
        model.hardening.insert(
            setting.key.to_string(),
            known(
                read(
                    sys,
                    held,
                    &KernelCmd::Sysctl(SysctlCmd::Read(setting.key.clone())),
                )
                .and_then(|s| Ok(parse_sysctl(&s)?.to_string())),
            ),
        );
    }
    model.extra_rules = known(rules(sys, held));
    routes(sys, held, cfg, &mut model);
    // A failed host inventory must not look like an empty, positively owned host.
    model.host_links.clear();
    let host = command_result(run_cmd(
        sys,
        ExecTarget::Host,
        &KernelCmd::Ip(IpCmd::LinkShowJson),
        EXEC_TIMEOUT,
    ))
    .and_then(|s| Ok(parse_ip_link(&s)?));
    let host_addresses = command_result(run_cmd(
        sys,
        ExecTarget::Host,
        &KernelCmd::Ip(IpCmd::AddrShowJson),
        EXEC_TIMEOUT,
    ))
    .and_then(|s| Ok(parse_ip_addr(&s)?))
    .ok();
    if let Ok(host) = host {
        for link in host
            .into_iter()
            .filter(|l| desired.links().contains_key(&l.ifname))
        {
            let peers = command_result(run_cmd(
                sys,
                ExecTarget::Host,
                &KernelCmd::Wg(crate::cmd::WgCmd::Show {
                    ifname: match IfName::new(&link.ifname) {
                        Ok(n) => n,
                        Err(_) => continue,
                    },
                    field: WgField::Peers,
                }),
                EXEC_TIMEOUT,
            ));
            let Some(mut record) = KernelModel::desired(desired).links.remove(&link.ifname) else {
                continue;
            };
            record.kind = Known::Value(link.kind.unwrap_or_default());
            record.up = Known::Value(link.flags.iter().any(|f| f == "UP"));
            record.peers = if peers.is_ok_and(|p| p.trim().is_empty()) {
                Known::Value(vec![])
            } else {
                Known::Unknown
            };
            record.addresses = host_addresses
                .as_ref()
                .and_then(|a| {
                    a.iter()
                        .find(|a| a.ifname == link.ifname && a.ifindex == link.ifindex)
                })
                .map_or(Known::Unknown, |a| {
                    known(
                        a.addresses
                            .iter()
                            .map(|a| {
                                ipnet::IpNet::new(a.local, a.prefixlen)
                                    .map_err(|_| ProbeError::io("invalid host prefix"))
                            })
                            .collect(),
                    )
                });
            record.tc_hooks = known(hooks_in(sys, ExecTarget::Host, &link.ifname, link.xdp));
            record.ours = Known::Value(false); // Replaced below only on positive leftover verification.
            if record.kind == Known::Value("wireguard".into())
                && record.up == Known::Value(false)
                && record.peers == Known::Value(vec![])
                && record.addresses == Known::Value(vec![])
                && record.tc_hooks == Known::Value(vec![])
            {
                record.ours = Known::Value(true);
            }
            model.host_links.insert(link.ifname, record);
        }
    } else {
        // Prevent speculative host creation; the executor also rechecks on every add.
        model.links_complete = false;
    }
    let mut handshakes = BTreeMap::new();
    let mut exit_links = BTreeMap::new();
    for (id, name) in desired.exits() {
        if let Ok(map) = super::handshake_map(sys, held, name)
            && let Some(peer) = desired.links().get(name).and_then(|l| l.peers.first())
            && let Some(h) = map.get(&peer.public_key)
        {
            let age = match h {
                Handshake::At { unix_secs: at } if *at <= sys.now_unix_secs() => {
                    Some(Duration::from_secs(sys.now_unix_secs() - *at))
                }
                Handshake::Never | Handshake::At { .. } => None,
            };
            if age.is_none_or(|a| a > cfg.max_handshake_age) {
                model.stale_exits.insert(id.clone());
            }
            handshakes.insert(id.clone(), age);
        }
        let link = model.links.get(name);
        exit_links.insert(
            id.clone(),
            ExitLinkState {
                link_up: link.is_some_and(|l| l.up == Known::Value(true)),
                peer_present: link.is_some_and(|l| l.peers.value().is_some_and(|p| !p.is_empty())),
                key_present: true,
            },
        );
    }
    Observation {
        model,
        safety_complete,
        safety_ms,
        complete: Instant::now() < deadline,
        handshakes,
        exit_links,
    }
}
