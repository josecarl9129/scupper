//! Pure staged health checks for the single-exit, IPv4-only M2 namespace.
//!
//! Stages follow DESIGN §12: containment → administrative closure → observed
//! defaults/handshakes → forwarding/client listener → forwarded routes → exit
//! probe → required supervisor. Standby probing is reserved for multi-exit M2k;
//! DNS self-tests begin with the M4 forwarder. Neither is requested in M2.
//!
//! Known violations in any supplied observation win over observation errors.
//! Supplied required-observation errors win over availability results, even if
//! a caller collected them out of order. Missing stages still gate requests:
//! the engine never requests a costly probe before all earlier stages pass.
//! Exit-probe path failures are typed availability results; local setup and
//! malformed collection responses are errors. The engine performs no I/O or
//! text ruleset comparison; collectors supply a canonical-JSON [`RulesetObs`].
//!
//! Compared with the design sketch, handshakes use `Option<Probe<...>>` so a
//! failed collection cannot look like Never or an unobserved map. Cheap default
//! inventory is independent of topology, and each client route response includes
//! both families to prove M2's IPv6 rejection without requesting a stage twice.
//! Interface names in inventories are raw strings so foreign kernel
//! names outside config syntax remain representable. Missing/duplicate links
//! use `ForeignLink`, except absent client ingress (degraded link down). Disconnected exits may have no peers (the documented
//! administrative closure), but any peers still present must match policy.
//! FailoverPending/Stuck and other future variants are retained as vocabulary,
//! without multi-exit logic. The constructor requires exactly one exit. Assigned
//! addresses must match config, ignoring kernel IPv6 link-local addresses.
//! Selection describes runtime operator state; it is not a site config policy.

mod config;
mod types;

pub use config::*;
pub use types::*;

use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use crate::{
    parse::{Handshake, HandshakeAge, RouteLookup},
    render::{Family, RouteTarget},
};

use super::v1::exit_ip_plausible;

fn error(stage: Stage, source: &ProbeError) -> Next {
    Next::Done(Err(CheckError {
        stage,
        source: source.bounded(),
    }))
}

fn report(verdict: Verdict, warnings: Vec<Warning>, cfg: &HealthConfigV2, now: u64) -> Next {
    Next::Done(Ok(Report {
        verdict,
        warnings,
        at: now,
        config_version: cfg.config_version,
    }))
}

fn same_prefixes(a: &[ipnet::IpNet], b: &[ipnet::IpNet]) -> bool {
    // Assigned addresses retain host bits; peer AllowedIPs are truncated below.
    let left: BTreeSet<_> = a.iter().collect();
    let right: BTreeSet<_> = b.iter().collect();
    a.len() == left.len() && b.len() == right.len() && left == right
}

fn peers_match(got: &[PeerObs], want: &[PeerObs]) -> bool {
    let keys: BTreeSet<_> = got.iter().map(|peer| peer.public_key).collect();
    got.len() == want.len()
        && keys.len() == got.len()
        && want.iter().all(|peer| {
            got.iter().any(|other| {
                other.public_key == peer.public_key && {
                    let a: Vec<_> = other.allowed_ips.iter().map(ipnet::IpNet::trunc).collect();
                    let b: Vec<_> = peer.allowed_ips.iter().map(ipnet::IpNet::trunc).collect();
                    same_prefixes(&a, &b)
                }
            })
        })
}

/// Collects every known violation, including an already supplied uplink probe.
/// Endpoint roaming is informational; policy covers public keys and `AllowedIPs`.
#[must_use]
pub fn violations(obs: &Observations, cfg: &HealthConfigV2) -> Option<NonEmpty<Violation>> {
    let mut found = Vec::new();
    if let Some(Ok(topology)) = &obs.topology {
        topology_violations(topology, &obs.selection, cfg, &mut found);
    }
    if let Some(Ok(defaults)) = &obs.defaults {
        found.extend(defaults.violations.clone());
        for answer in [&defaults.v4, &defaults.v6]
            .into_iter()
            .chain(&defaults.extra)
        {
            route_violations(answer, cfg, &mut found);
        }
    }
    if let Some(routes) = &obs.routes {
        for (_, route) in routes {
            for answer in [&route.v4, &route.v6]
                .into_iter()
                .filter_map(|r| r.as_ref().ok())
            {
                route_violations(&answer.clone().into(), cfg, &mut found);
            }
        }
    }
    if let Some(Supervisor::Alive { netns, .. }) = obs.supervisor
        && netns != cfg.expected_netns
        && !found.contains(&Violation::NetnsWrongInode)
    {
        found.push(Violation::NetnsWrongInode);
    }
    if let Some(Ok(ip)) = obs.exit_probe
        && cfg
            .uplink_addrs
            .iter()
            .any(|uplink| uplink.to_canonical() == ip.to_canonical())
    {
        found.push(Violation::ExitIpIsUplinkAddress(ip));
    }
    NonEmpty::from_vec(found)
}

fn topology_violations(
    t: &TopologyObs,
    selection: &Selection,
    cfg: &HealthConfigV2,
    found: &mut Vec<Violation>,
) {
    found.extend(
        t.host_wireguard_on_client_port
            .iter()
            .cloned()
            .map(Violation::HostWireguardOnClientPort),
    );
    match t.netns {
        NetnsObs::Missing => found.push(Violation::NetnsMissing),
        NetnsObs::WrongInode => found.push(Violation::NetnsWrongInode),
        NetnsObs::Present { device, inode }
            if NetnsIdentity { device, inode } != cfg.expected_netns =>
        {
            found.push(Violation::NetnsWrongInode);
        }
        NetnsObs::Present { .. } => {}
    }
    let mut seen = BTreeSet::new();
    for link in &t.links {
        let unique = seen.insert(link.name.as_str());
        if !unique || (link.name != "lo" && !cfg.links.contains_key(&link.name)) {
            found.push(Violation::ForeignLink(link.name.clone()));
        }
        if link.name == "lo" {
            continue;
        }
        if link.kind.as_deref() != Some("wireguard") {
            found.push(Violation::LinkKind(link.name.clone()));
        }
        // Kernel-generated IPv6 link-local addresses are not assigned policy.
        let addresses: Vec<_> = link
            .addresses
            .iter()
            .copied()
            .filter(|net| !matches!(net, ipnet::IpNet::V6(v6) if v6.addr().is_unicast_link_local()))
            .collect();
        if t.addresses_complete
            && let Some(expected) = cfg.links.get(&link.name)
            && !same_prefixes(&addresses, expected)
        {
            found.push(Violation::ConfigMismatch(format!(
                "{} addresses differ",
                link.name
            )));
        }
    }
    for name in cfg.links.keys().filter(|name| {
        t.links_complete && *name != &cfg.client_iface && !seen.contains(name.as_str())
    }) {
        found.push(Violation::ForeignLink(name.clone()));
    }
    let names: BTreeSet<_> = cfg.peers.keys().chain(t.peers.keys()).collect();
    for name in names {
        // Missing collection entries are errors, not an observed empty peer set.
        let Some(got) = t.peers.get(name).map(Vec::as_slice) else {
            continue;
        };
        let want = cfg.peers.get(name).map(Vec::as_slice).unwrap_or_default();
        let disconnected_exit = *selection == Selection::Disconnected
            && name == cfg.exit_iface.as_str()
            && got.is_empty();
        if !disconnected_exit && (!cfg.peers.contains_key(name) || !peers_match(got, want)) {
            found.push(Violation::PeerDiffers {
                ifname: name.clone(),
            });
        }
    }
    match t.ruleset {
        RulesetObs::Exact => {}
        RulesetObs::Missing => found.push(Violation::RulesetMissing),
        RulesetObs::Differs { live, want } => found.push(Violation::RulesetDiffers { live, want }),
    }
    found.extend(
        t.extra_rules
            .iter()
            .cloned()
            .map(Violation::ExtraPolicyRule),
    );
    found.extend(
        t.tc_hooks
            .iter()
            .cloned()
            .map(Violation::TrafficControlHook),
    );
}

// Route answers can expose links added after the topology snapshot.
fn route_violations(answer: &DefaultRouteObs, cfg: &HealthConfigV2, found: &mut Vec<Violation>) {
    let name = match answer {
        DefaultRouteObs::Dev(name) => Some(name.as_str()),
        DefaultRouteObs::Other(RouteAnswer::Dev(name)) => Some(name.as_str()),
        // The lookup parser could not retain a device outside IfName syntax.
        DefaultRouteObs::Other(RouteAnswer::OtherDev) => Some("<unrecognized device>"),
        _ => None,
    };
    if let Some(name) = name
        && name != "lo"
        && !cfg.links.contains_key(name)
    {
        let violation = Violation::ForeignLink(name.to_owned());
        if !found.contains(&violation) {
            found.push(violation);
        }
    }
}

fn observation_error(obs: &Observations, cfg: &HealthConfigV2) -> Option<(Stage, ProbeError)> {
    // Supplied errors and incomplete answers outrank availability, even out of order.
    if let Some(Err(source)) = &obs.topology {
        return Some((Stage::Topology, source.clone()));
    }
    if let Some(Ok(t)) = &obs.topology
        && let Some(source) = t.errors.first()
    {
        return Some((Stage::Topology, source.clone()));
    }
    if let Some(Ok(t)) = &obs.topology
        && t.links.iter().any(|link| {
            link.kind.as_deref() == Some("wireguard") && !t.peers.contains_key(&link.name)
        })
    {
        return Some((
            Stage::Topology,
            ProbeError::io("peer inventory entry missing"),
        ));
    }
    if let Selection::Pin(exit) | Selection::Prefer(exit) = &obs.selection
        && *exit != cfg.exit
    {
        return Some((
            Stage::Defaults,
            ProbeError::io("selection names an unconfigured exit"),
        ));
    }
    if let Some(Err(source)) = &obs.defaults {
        return Some((Stage::Defaults, source.clone()));
    }
    match &obs.handshakes {
        Some(Err(source)) => return Some((Stage::Handshakes, source.clone())),
        Some(Ok(map)) if !map.contains_key(&cfg.exit) => {
            return Some((
                Stage::Handshakes,
                ProbeError::io("exit handshake observation missing"),
            ));
        }
        _ => {}
    }
    if let Some(Err(source)) = &obs.forwarding {
        return Some((Stage::Forwarding, source.clone()));
    }
    if let Some(Ok(f)) = &obs.forwarding
        && cfg.peers.get(&cfg.client_iface).is_some_and(|peers| {
            peers
                .iter()
                .any(|p| !f.client_handshakes.contains_key(&p.public_key))
        })
    {
        return Some((
            Stage::Forwarding,
            ProbeError::io("client handshake observation missing"),
        ));
    }
    if let Some(routes) = &obs.routes {
        for (_, route) in routes {
            for answer in [&route.v4, &route.v6] {
                if let Err(source) = answer {
                    return Some((Stage::Routes, source.clone()));
                }
            }
        }
        let sources: BTreeSet<_> = routes.iter().map(|(client, _)| *client).collect();
        let expected: BTreeSet<_> = cfg.route_sources.iter().copied().collect();
        if sources.len() != routes.len() || sources != expected || expected.is_empty() {
            return Some((
                Stage::Routes,
                ProbeError::io("missing, unexpected or duplicate client route source"),
            ));
        }
    }
    if let Some(Err(source @ ProbeError::Setup(_))) = &obs.exit_probe {
        return Some((Stage::ExitProbe, source.clone()));
    }
    None
}

fn fresh(
    handshake: Handshake,
    cfg: &HealthConfigV2,
    now: u64,
    warnings: &mut Vec<Warning>,
) -> bool {
    match handshake.age_at(now) {
        HandshakeAge::Never => false,
        HandshakeAge::Age(age) => age <= cfg.max_handshake_age,
        HandshakeAge::InFuture(skew) => {
            if !warnings.contains(&Warning::ClockSkew) {
                warnings.push(Warning::ClockSkew);
            }
            skew <= cfg.max_clock_skew
        }
    }
}

fn route_wrong(client: IpAddr, got: &DefaultRouteObs, want: RouteTarget) -> Verdict {
    Verdict::Degraded(Degraded::RouteWrong {
        client,
        got: got.clone(),
        want,
    })
}

fn default_wrong(family: Family, got: &DefaultRouteObs, want: RouteTarget) -> Verdict {
    Verdict::Degraded(Degraded::DefaultRouteWrong {
        family,
        got: got.clone(),
        want,
    })
}

fn defaults_failure(
    t: &TopologyObs,
    defaults: &DefaultRoutes,
    obs: &Observations,
    cfg: &HealthConfigV2,
) -> Option<Verdict> {
    let both_closed =
        defaults.v4 == DefaultRouteObs::Unreachable && defaults.v6 == DefaultRouteObs::Unreachable;
    if obs.selection == Selection::Disconnected {
        let exits_closed = t
            .links
            .iter()
            .filter(|link| link.name == cfg.exit_iface.as_str())
            .all(|link| !link.up || t.peers.get(&link.name).is_some_and(Vec::is_empty));
        return Some(
            if both_closed && defaults.extra.is_empty() && exits_closed {
                Verdict::FailClosed(FailClosed::AdminDisconnected)
            } else {
                Verdict::Degraded(Degraded::DisconnectNotEffective)
            },
        );
    }
    let client = IpAddr::V4(cfg.client_addr);
    if let Some(extra) = defaults.extra.first() {
        return Some(route_wrong(client, extra, obs.active.clone()));
    }
    if defaults.v6 != DefaultRouteObs::Unreachable {
        return Some(default_wrong(
            Family::V6,
            &defaults.v6,
            RouteTarget::Unreachable,
        ));
    }
    // A pin cannot authorize an intent through a different configured exit.
    if matches!(obs.selection, Selection::Pin(_))
        && matches!(&obs.active, RouteTarget::Exit(iface) if iface != &cfg.exit_iface)
    {
        return Some(default_wrong(
            Family::V4,
            &defaults.v4,
            RouteTarget::Exit(cfg.exit_iface.clone()),
        ));
    }
    if matches!(obs.selection, Selection::Pin(_))
        && let Some(routes) = &obs.routes
    {
        for (client, route) in routes {
            if let Ok(got @ RouteAnswer::Dev(name)) = &route.v4
                && name != cfg.exit_iface.ifname()
            {
                return Some(route_wrong(
                    *client,
                    &got.clone().into(),
                    RouteTarget::Exit(cfg.exit_iface.clone()),
                ));
            }
        }
    }
    if both_closed {
        return Some(Verdict::FailClosed(match &obs.selection {
            Selection::Pin(exit) => FailClosed::PinnedExitDown(exit.clone()),
            _ => FailClosed::NoHealthyExit,
        }));
    }
    // The kernel removes a down link's routes, so a down (or absent) exit link leaves
    // the v4 default missing: nothing can leave, the exit is simply down (fail closed).
    // A missing default while the exit link is up stays degraded (route wrong).
    let exit_up = t
        .links
        .iter()
        .any(|link| link.name == cfg.exit_iface.as_str() && link.up);
    if defaults.v4 == DefaultRouteObs::Missing && !exit_up {
        return Some(Verdict::FailClosed(match &obs.selection {
            Selection::Pin(exit) => FailClosed::PinnedExitDown(exit.clone()),
            _ => FailClosed::NoHealthyExit,
        }));
    }
    let expected = RouteTarget::Exit(cfg.exit_iface.clone());
    if obs.active != expected
        || defaults.v4 != DefaultRouteObs::Dev(cfg.exit_iface.as_str().to_owned())
    {
        return Some(default_wrong(Family::V4, &defaults.v4, obs.active.clone()));
    }
    None
}

fn client_fault(f: &Forwarding, cfg: &HealthConfigV2) -> Option<ClientFault> {
    if f.client_public_key != Some(cfg.client_public_key) {
        Some(ClientFault::PublicKey)
    } else if f.listen_port != cfg.listen_port {
        Some(ClientFault::ListenPort)
    } else if f
        .netns_sockets
        .iter()
        .any(|socket| socket.local.port() == cfg.listen_port)
        || !f.host_sockets.iter().any(|socket| {
            socket.local.port() == cfg.listen_port
                && (socket.local.ip().is_unspecified()
                    || cfg
                        .uplink_addrs
                        .iter()
                        .any(|ip| ip.to_canonical() == socket.local.ip().to_canonical()))
        })
    {
        Some(ClientFault::HostSocket)
    } else {
        None
    }
}

/// Advances the M2 stages using only supplied observations and Unix time.
///
/// Missing observations request the earliest required stage. Supplied known
/// violations outrank all errors; supplied required observation errors outrank
/// availability verdicts. Exit path failures use 3 and never cause a single-exit
/// failover. Code 0 proves every applicable stage; 5 differs only in supervision.
#[must_use]
#[allow(clippy::too_many_lines)] // Linear stage order makes the safety gates auditable.
pub fn next(obs: &Observations, cfg: &HealthConfigV2, now: u64) -> Next {
    #[cfg(feature = "lab-mutation")]
    let adjusted = if crate::lab_mutation::active() == Some(crate::lab_mutation::Mutation::Probe) {
        let mut adjusted = obs.clone();
        crate::lab_mutation::trust_bound_probe(&mut adjusted, cfg);
        Some(adjusted)
    } else {
        None
    };
    #[cfg(feature = "lab-mutation")]
    let obs = adjusted.as_ref().unwrap_or(obs);
    let mut warnings = Vec::new();
    if let Some(Ok(f)) = &obs.forwarding {
        warnings.extend(f.hardening.iter().cloned().map(Warning::HardeningSysctl));
    }
    if let Some(Ok(f)) = &obs.forwarding
        && let Some(reason) = &f.quarantine
    {
        warnings.push(Warning::RepairSuppressed(reason.clone()));
    }
    if let Some(found) = violations(obs, cfg) {
        return report(Verdict::Unprotected(found), warnings, cfg, now);
    }
    if let Some((stage, source)) = observation_error(obs, cfg) {
        return error(stage, &source);
    }
    let Some(Ok(topology)) = &obs.topology else {
        return Next::Topology;
    };
    if let Some(Ok(f)) = &obs.forwarding
        && f.quarantine.is_some()
        && f.v4 != 0
    {
        return report(
            Verdict::Degraded(Degraded::QuarantineNotEffective),
            warnings,
            cfg,
            now,
        );
    }
    let Some(Ok(defaults)) = &obs.defaults else {
        return Next::Defaults;
    };
    // Client ingress being cut off is an availability failure even if the exit
    // is also down. Administrative closure and effective quarantine outrank it.
    if obs.selection != Selection::Disconnected
        && !topology
            .links
            .iter()
            .any(|link| link.name == cfg.client_iface && link.up)
    {
        let Some(Ok(forwarding)) = &obs.forwarding else {
            return Next::Forwarding;
        };
        if forwarding.v4 == 0
            && let Some(reason) = &forwarding.quarantine
        {
            return report(
                Verdict::FailClosed(FailClosed::Quarantined {
                    reason: reason.clone(),
                }),
                warnings,
                cfg,
                now,
            );
        }
        return report(
            Verdict::Degraded(Degraded::ClientSideBroken(ClientFault::LinkDown)),
            warnings,
            cfg,
            now,
        );
    }
    if let Some(verdict) = defaults_failure(topology, defaults, obs, cfg) {
        return report(verdict, warnings, cfg, now);
    }
    let Some(Ok(handshakes)) = &obs.handshakes else {
        return Next::Handshakes;
    };
    let Some(handshake) = handshakes.get(&cfg.exit) else {
        return error(
            Stage::Handshakes,
            &ProbeError::io("exit handshake observation missing"),
        );
    };
    let handshake_fresh = fresh(*handshake, cfg, now, &mut warnings);
    let exit_up = topology
        .links
        .iter()
        .any(|link| link.name == cfg.exit_iface.as_str() && link.up);
    if !handshake_fresh || !exit_up {
        return report(
            Verdict::FailClosed(FailClosed::NoHealthyExit),
            warnings,
            cfg,
            now,
        );
    }
    let Some(Ok(forwarding)) = &obs.forwarding else {
        return Next::Forwarding;
    };
    if forwarding.v4 == 0
        && let Some(reason) = &forwarding.quarantine
    {
        return report(
            Verdict::FailClosed(FailClosed::Quarantined {
                reason: reason.clone(),
            }),
            warnings,
            cfg,
            now,
        );
    }
    if forwarding.v4 != 1 || forwarding.client_v4 != 1 {
        return report(
            Verdict::Degraded(Degraded::ForwardingDisabled),
            warnings,
            cfg,
            now,
        );
    }
    if let Some(fault) = client_fault(forwarding, cfg) {
        return report(
            Verdict::Degraded(Degraded::ClientSideBroken(fault)),
            warnings,
            cfg,
            now,
        );
    }
    if let Some(peers) = cfg.peers.get(&cfg.client_iface) {
        let mut stale = false;
        for peer in peers {
            let Some(handshake) = forwarding.client_handshakes.get(&peer.public_key) else {
                return error(
                    Stage::Forwarding,
                    &ProbeError::io("client handshake observation missing"),
                );
            };
            stale |= !fresh(*handshake, cfg, now, &mut warnings);
        }
        if stale {
            warnings.push(Warning::ClientHandshakesStale);
        }
    }
    let Some(routes) = &obs.routes else {
        return Next::Routes;
    };
    let want = RouteTarget::Exit(cfg.exit_iface.clone());
    for (client, route) in routes {
        if let Ok(got) = &route.v4
            && *got != RouteLookup::Dev(cfg.exit_iface.ifname().clone())
        {
            return report(
                route_wrong(*client, &got.clone().into(), want),
                warnings,
                cfg,
                now,
            );
        }
        if let Ok(got) = &route.v6
            && *got != RouteAnswer::Unreachable
        {
            return report(
                route_wrong(*client, &got.clone().into(), RouteTarget::Unreachable),
                warnings,
                cfg,
                now,
            );
        }
    }
    let ip = match &obs.exit_probe {
        None => return Next::ExitProbe,
        Some(Err(source)) => {
            return report(
                Verdict::Degraded(Degraded::ExitProbeFailed(source.bounded())),
                warnings,
                cfg,
                now,
            );
        }
        Some(Ok(ip)) => ip.to_canonical(),
    };
    if !ip.to_canonical().is_ipv4() || !exit_ip_plausible(ip, cfg.exit_addr) {
        return report(
            Verdict::Degraded(Degraded::ExitProbeImplausible { ip }),
            warnings,
            cfg,
            now,
        );
    }
    let exit = cfg.exit.clone();
    if cfg.require_daemon {
        let why = match obs.supervisor {
            None => return Next::Supervisor,
            Some(Supervisor::Alive { iteration_age, .. })
                if iteration_age < Duration::from_secs(30) =>
            {
                None
            }
            Some(Supervisor::Alive { .. }) => Some(SupervisorFault::Stale),
            Some(Supervisor::Dead) => Some(SupervisorFault::Dead),
            Some(Supervisor::NotRequired) => Some(SupervisorFault::NotRequired),
        };
        if let Some(why) = why {
            return report(
                Verdict::Unsupervised {
                    exit,
                    exit_ip: ip,
                    why,
                },
                warnings,
                cfg,
                now,
            );
        }
    } else {
        match obs.supervisor {
            Some(Supervisor::Dead) => warnings.push(Warning::DaemonDead),
            Some(Supervisor::Alive { iteration_age, .. })
                if iteration_age >= Duration::from_secs(30) =>
            {
                warnings.push(Warning::DaemonStale);
            }
            _ => {}
        }
    }
    report(Verdict::Protected { exit, exit_ip: ip }, warnings, cfg, now)
}
