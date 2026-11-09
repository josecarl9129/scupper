use super::{key_bytes, observe, peer_field};
use crate::{
    canon,
    cmd::{IpCmd, KernelCmd, TcCmd, TcParent},
    netns::NetnsHandle,
    system::System,
};
use scupper_core::{
    config::{GatewayId, ValidatedSite},
    parse::{
        WgField, parse_ip_addr, parse_ip_link, parse_ip_rule, parse_tc_filter, parse_tc_qdisc,
    },
    render::{Family, VersionStamp, render_netns},
    rules::IfName,
    verdict::v2::{LinkObs, NetnsObs, PeerObs, Probe, ProbeError, TopologyObs},
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn peers(sys: &dyn System, handle: &NetnsHandle, name: &str) -> Probe<Vec<PeerObs>> {
    let keys = peer_field(sys, handle, name, WgField::Peers)?;
    let allowed = peer_field(sys, handle, name, WgField::AllowedIps)?;
    let endpoints = peer_field(sys, handle, name, WgField::Endpoints)?;
    let want: BTreeSet<_> = keys.iter().map(|peer| peer.public_key.as_str()).collect();
    for field in [&allowed, &endpoints] {
        if want != field.iter().map(|peer| peer.public_key.as_str()).collect() {
            return Err(ProbeError::io("WireGuard field peer inventories disagree"));
        }
    }
    keys.iter()
        .map(|peer| {
            let allowed_ips = allowed
                .iter()
                .find(|p| p.public_key == peer.public_key)
                .and_then(|p| p.allowed_ips.clone())
                .ok_or_else(|| ProbeError::io("AllowedIPs missing"))?;
            let endpoint = endpoints
                .iter()
                .find(|p| p.public_key == peer.public_key)
                .ok_or_else(|| ProbeError::io("endpoint observation missing"))?
                .endpoint;
            Ok(PeerObs {
                public_key: key_bytes(&peer.public_key)?,
                allowed_ips,
                endpoint,
            })
        })
        .collect()
}

fn policy_rules(
    sys: &dyn System,
    handle: &NetnsHandle,
    errors: &mut Vec<ProbeError>,
) -> Vec<String> {
    let mut differences = Vec::new();
    for family in [Family::V4, Family::V6] {
        let Some(mut got) = retain(
            observe(sys, handle, KernelCmd::Ip(IpCmd::RuleShowJson { family }))
                .and_then(|text| Ok(parse_ip_rule(&text)?)),
            errors,
        ) else {
            continue;
        };
        // Newer kernels emit the origin protocol for their built-in rules.
        for rule in &mut got {
            if matches!(rule.protocol.as_deref(), Some("kernel" | "2")) {
                rule.protocol = None;
            }
        }
        let v4 = r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]"#;
        let v6 = r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]"#;
        let Some(want) = retain(
            parse_ip_rule(if family == Family::V4 { v4 } else { v6 }).map_err(Into::into),
            errors,
        ) else {
            continue;
        };
        if got != want {
            differences.push(format!("{family:?} RPDB differs: {got:?}"));
        }
    }
    differences
}

// Keep independent observations even when another item cannot be read. A foreign
// link is already a violation by name and needs no per-link commands.
fn retain<T>(result: Probe<T>, errors: &mut Vec<ProbeError>) -> Option<T> {
    result.map_err(|error| errors.push(error)).ok()
}

fn tc_hook(
    sys: &dyn System,
    handle: &NetnsHandle,
    name: &str,
    xdp: bool,
    errors: &mut Vec<ProbeError>,
) -> bool {
    let Ok(dev) = IfName::new(name) else {
        errors.push(ProbeError::io("unrepresentable tc interface"));
        return xdp;
    };
    let qdiscs = retain(
        observe(
            sys,
            handle,
            KernelCmd::Tc(TcCmd::QdiscShowJson { dev: dev.clone() }),
        )
        .and_then(|text| Ok(parse_tc_qdisc(&text)?)),
        errors,
    )
    .unwrap_or_default();
    let mut hooked = xdp
        || qdiscs.iter().any(|q| {
            q.kind != "noqueue"
                || !q.root
                || q.handle.as_deref() != Some("0:")
                || q.parent.is_some()
                || q.dev.as_deref().is_some_and(|dev| dev != name)
                || q.options
                    .as_ref()
                    .is_some_and(|v| v.as_object().is_none_or(|o| !o.is_empty()))
        });
    for parent in [TcParent::Root, TcParent::Ingress, TcParent::Egress] {
        hooked |= retain(
            observe(
                sys,
                handle,
                KernelCmd::Tc(TcCmd::FilterShowJson {
                    dev: dev.clone(),
                    parent,
                }),
            )
            .and_then(|text| Ok(parse_tc_filter(&text)?)),
            errors,
        )
        .is_some_and(|filters| !filters.is_empty());
    }
    hooked
}

/// Collects containment per item. Foreign links need no tc or peer inspection.
/// Errors are retained alongside successful observations, so known violations win.
/// `tcx/bpf_link` attachments are not yet inventoried; tc and XDP are observed.
///
/// # Errors
/// Per-item command, parse and canon failures are retained in `TopologyObs.errors`.
#[allow(clippy::too_many_lines)] // Preserve independent observations in one auditable inventory pass.
pub fn topology(
    sys: &dyn System,
    handle: &NetnsHandle,
    site: &ValidatedSite,
    gateway: &GatewayId,
    stamp: &VersionStamp,
) -> Probe<TopologyObs> {
    topology_recorded(sys, handle, site, gateway, stamp, &mut BTreeMap::new())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn topology_recorded(
    sys: &dyn System,
    handle: &NetnsHandle,
    site: &ValidatedSite,
    gateway_id: &GatewayId,
    stamp: &VersionStamp,
    identities: &mut BTreeMap<String, u32>,
) -> Probe<TopologyObs> {
    let mut errors = Vec::new();
    let raw = retain(
        observe(sys, handle, KernelCmd::Ip(IpCmd::LinkShowJson))
            .and_then(|text| Ok(parse_ip_link(&text)?)),
        &mut errors,
    );
    let links_complete = raw.is_some();
    let addresses = retain(
        observe(sys, handle, KernelCmd::Ip(IpCmd::AddrShowJson))
            .and_then(|text| Ok(parse_ip_addr(&text)?)),
        &mut errors,
    );
    let raw = raw.unwrap_or_default();
    let addresses_complete = links_complete
        && addresses.as_ref().is_some_and(|addresses| {
            raw.len() == addresses.len()
                && raw.iter().all(|link| {
                    addresses
                        .iter()
                        .filter(|addr| link.ifindex == addr.ifindex && link.ifname == addr.ifname)
                        .count()
                        == 1
                })
        });
    if links_complete && addresses.is_some() && !addresses_complete {
        errors.push(ProbeError::io("link/address inventories disagree"));
    }
    let gateway = site
        .gateway(gateway_id)
        .ok_or_else(|| ProbeError::setup("unknown gateway"))?;
    let configured = |name: &str| {
        name == "lo"
            || name == gateway.client_tunnel().ifname().as_str()
            || gateway
                .exits()
                .iter()
                .any(|exit| exit.ifname().as_str() == name)
    };
    identities.clear();
    identities.extend(
        raw.iter()
            .filter(|link| configured(&link.ifname) && link.kind.as_deref() == Some("wireguard"))
            .map(|link| (link.ifname.clone(), link.ifindex)),
    );
    let mut links = Vec::new();
    let mut peer_inventory = BTreeMap::new();
    let mut tc_hooks = Vec::new();
    for link in raw {
        let assigned = addresses.as_ref().and_then(|addresses| {
            addresses
                .iter()
                .find(|addr| addr.ifindex == link.ifindex && addr.ifname == link.ifname)
        });
        let addresses = assigned
            .map(|addr| {
                addr.addresses
                    .iter()
                    .map(|addr| {
                        ipnet::IpNet::new(addr.local, addr.prefixlen)
                            .map_err(|_| ProbeError::io("invalid assigned prefix"))
                    })
                    .collect::<Probe<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        if configured(&link.ifname) {
            if link.kind.as_deref() == Some("wireguard")
                && let Some(peers) = retain(peers(sys, handle, &link.ifname), &mut errors)
            {
                peer_inventory.insert(link.ifname.clone(), peers);
            }
            if tc_hook(sys, handle, &link.ifname, link.xdp, &mut errors) {
                tc_hooks.push(link.ifname.clone());
            }
        }
        links.push(LinkObs {
            name: link.ifname,
            kind: link.kind,
            up: link.flags.iter().any(|f| f == "UP"),
            addresses,
        });
    }
    let host_wireguard_on_client_port =
        u16::try_from(gateway.client_tunnel().identity().listen_port)
            .map_err(|_| ProbeError::setup("invalid client listen port"))
            .and_then(|port| super::forwarding::host_wireguard_ports(sys, port, &mut errors));
    let host_wireguard_on_client_port =
        retain(host_wireguard_on_client_port, &mut errors).unwrap_or_default();
    let extra_rules = policy_rules(sys, handle, &mut errors);
    let ruleset = retain(
        render_netns(site, gateway_id, stamp)
            .map_err(|error| ProbeError::setup(&error.to_string()))
            .and_then(|rendered| canon::observe_netns_ruleset(sys, handle, &rendered)),
        &mut errors,
    )
    .unwrap_or(scupper_core::verdict::v2::RulesetObs::Exact);
    let (device, inode) = handle.identity();
    Ok(TopologyObs {
        host_wireguard_on_client_port,
        errors,
        links_complete,
        addresses_complete,
        netns: NetnsObs::Present { device, inode },
        links,
        peers: peer_inventory,
        ruleset,
        extra_rules,
        tc_hooks,
    })
}
