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

fn peers(sys: &dyn System, handle: &NetnsHandle, name: &str) -> Probe<Vec<PeerObs>> {
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

fn policy_rules(sys: &dyn System, handle: &NetnsHandle) -> Probe<Vec<String>> {
    let mut differences = Vec::new();
    for family in [Family::V4, Family::V6] {
        let text = observe(sys, handle, KernelCmd::Ip(IpCmd::RuleShowJson { family }))?;
        let mut got = parse_ip_rule(&text)?;
        // Newer kernels emit the origin protocol for their built-in rules.
        for rule in &mut got {
            if matches!(rule.protocol.as_deref(), Some("kernel" | "2")) {
                rule.protocol = None;
            }
        }
        let v4 = r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]"#;
        let v6 = r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]"#;
        let want = parse_ip_rule(if family == Family::V4 { v4 } else { v6 })?;
        if got != want {
            differences.push(format!("{family:?} RPDB differs: {got:?}"));
        }
    }
    Ok(differences)
}

/// Collects the complete namespace containment inventory, including peers,
/// addresses, canonical rules, both RPDB families and tc on every observed link.
///
/// # Errors
/// Any command, parse, incomplete address/peer inventory or canon failure is an
/// error observation. Foreign names outside command syntax fail closed too.
pub fn topology(
    sys: &dyn System,
    handle: &NetnsHandle,
    site: &ValidatedSite,
    gateway: &GatewayId,
    stamp: &VersionStamp,
) -> Probe<TopologyObs> {
    let raw = parse_ip_link(&observe(sys, handle, KernelCmd::Ip(IpCmd::LinkShowJson))?)?;
    let addresses = parse_ip_addr(&observe(sys, handle, KernelCmd::Ip(IpCmd::AddrShowJson))?)?;
    if raw.len() != addresses.len()
        || addresses.iter().any(|addr| {
            raw.iter()
                .filter(|link| link.ifindex == addr.ifindex && link.ifname == addr.ifname)
                .count()
                != 1
        })
    {
        return Err(ProbeError::io("link/address inventories disagree"));
    }
    let mut links = Vec::new();
    let mut peer_inventory = BTreeMap::new();
    let mut tc_hooks = Vec::new();
    for link in raw {
        let addr = addresses
            .iter()
            .find(|addr| addr.ifindex == link.ifindex && addr.ifname == link.ifname)
            .ok_or_else(|| ProbeError::io("link addresses missing"))?;
        let addresses = addr
            .addresses
            .iter()
            .map(|addr| {
                ipnet::IpNet::new(addr.local, addr.prefixlen)
                    .map_err(|_| ProbeError::io("invalid assigned prefix"))
            })
            .collect::<Probe<_>>()?;
        if link.kind.as_deref() == Some("wireguard") {
            peer_inventory.insert(link.ifname.clone(), peers(sys, handle, &link.ifname)?);
        }
        let dev = IfName::new(&link.ifname)
            .map_err(|_| ProbeError::io("unrepresentable tc interface"))?;
        let qdiscs = parse_tc_qdisc(&observe(
            sys,
            handle,
            KernelCmd::Tc(TcCmd::QdiscShowJson { dev: dev.clone() }),
        )?)?;
        let mut hooked = link.xdp
            || qdiscs.iter().any(|q| {
                q.kind != "noqueue"
                    || !q.root
                    || q.handle.as_deref() != Some("0:")
                    || q.parent.is_some()
                    || q.dev.as_deref().is_some_and(|name| name != link.ifname)
                    || q.options
                        .as_ref()
                        .is_some_and(|v| v.as_object().is_none_or(|o| !o.is_empty()))
            });
        for parent in [TcParent::Root, TcParent::Ingress, TcParent::Egress] {
            hooked |= !parse_tc_filter(&observe(
                sys,
                handle,
                KernelCmd::Tc(TcCmd::FilterShowJson {
                    dev: dev.clone(),
                    parent,
                }),
            )?)?
            .is_empty();
        }
        if hooked {
            tc_hooks.push(link.ifname.clone());
        }
        links.push(LinkObs {
            name: link.ifname,
            kind: link.kind,
            up: link.flags.iter().any(|f| f == "UP"),
            addresses,
        });
    }
    let extra_rules = policy_rules(sys, handle)?;
    let rendered = render_netns(site, gateway, stamp)
        .map_err(|error| ProbeError::setup(&error.to_string()))?;
    let ruleset = canon::observe_netns_ruleset(sys, handle, &rendered)?;
    let (device, inode) = handle.identity();
    Ok(TopologyObs {
        netns: NetnsObs::Present { device, inode },
        links,
        peers: peer_inventory,
        ruleset,
        extra_rules,
        tc_hooks,
    })
}
