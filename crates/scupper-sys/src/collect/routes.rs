use super::observe;
use crate::{
    canon::command_result,
    cmd::{IpCmd, KernelCmd, RouteTable, run_cmd},
    netns::NetnsHandle,
    system::{EXEC_TIMEOUT, ExecTarget, System},
};
use scupper_core::{
    parse::{
        RouteDestination, RouteEntry, RouteKind, RoutingTable, parse_ip_route, parse_route_get,
    },
    render::Family,
    rules::IfName,
    verdict::v2::{
        ClientAddr, DefaultRouteObs, DefaultRoutes, HealthConfigV2, Probe, ProbeError, RouteAnswer,
        RouteObs, Violation,
    },
};
use std::net::IpAddr;

pub(crate) fn answer(route: &RouteEntry) -> DefaultRouteObs {
    match route.kind {
        RouteKind::Unreachable => DefaultRouteObs::Unreachable,
        RouteKind::Unicast => route
            .dev
            .as_ref()
            .map_or(DefaultRouteObs::Other(RouteAnswer::OtherDev), |dev| {
                DefaultRouteObs::Dev(dev.clone())
            }),
        RouteKind::Blackhole => DefaultRouteObs::Other(RouteAnswer::Blackhole),
        RouteKind::Prohibit => DefaultRouteObs::Other(RouteAnswer::Prohibit),
        RouteKind::Throw => DefaultRouteObs::Other(RouteAnswer::Throw),
        RouteKind::Local => DefaultRouteObs::Other(RouteAnswer::Local),
        _ => DefaultRouteObs::Other(RouteAnswer::OtherDev),
    }
}

pub(crate) fn kernel_route(route: &RouteEntry, cfg: &HealthConfigV2) -> bool {
    let RouteDestination::Prefix(prefix) = route.dst else {
        return false;
    };
    if route.table != RoutingTable::Main
        || route.kind != RouteKind::Unicast
        || !matches!(route.protocol.as_deref(), Some("kernel" | "2"))
        || route.gateway.is_some()
        || route.from.is_some()
    {
        return false;
    }
    let Some(addresses) = route.dev.as_ref().and_then(|dev| cfg.links.get(dev)) else {
        return false;
    };
    addresses.iter().any(|address| {
        prefix == address.trunc() && route.prefsrc.is_none_or(|source| source == address.addr())
    }) || matches!(prefix, ipnet::IpNet::V6(v6) if v6.addr().is_unicast_link_local() && v6.prefix_len() == 64)
}

fn family_defaults(
    sys: &dyn System,
    handle: &NetnsHandle,
    cfg: &HealthConfigV2,
    family: Family,
) -> Probe<(DefaultRouteObs, Vec<DefaultRouteObs>)> {
    let defaults = parse_ip_route(&observe(
        sys,
        handle,
        KernelCmd::Ip(IpCmd::DefaultShowJson(family)),
    )?)?;
    if defaults
        .iter()
        .any(|route| route.dst != RouteDestination::Default)
    {
        return Err(ProbeError::io(
            "default inventory contains a non-default route",
        ));
    }
    let main = parse_ip_route(&observe(
        sys,
        handle,
        KernelCmd::Ip(IpCmd::RouteShowJson {
            family,
            table: RouteTable::Main,
        }),
    )?)?;
    let main_defaults: Vec<_> = main
        .iter()
        .filter(|route| route.dst == RouteDestination::Default)
        .collect();
    if main_defaults != defaults.iter().collect::<Vec<_>>() {
        return Err(ProbeError::io("default route changed during collection"));
    }
    let first = defaults.first().map_or(DefaultRouteObs::Missing, answer);
    let extra =
        defaults
            .iter()
            .skip(1)
            .chain(main.iter().filter(|route| {
                route.dst != RouteDestination::Default && !kernel_route(route, cfg)
            }))
            .map(answer)
            .collect();
    Ok((first, extra))
}

pub(crate) fn kernel_local(route: &RouteEntry, cfg: &HealthConfigV2, family: Family) -> bool {
    if !matches!(route.protocol.as_deref(), Some("kernel" | "2"))
        || route.gateway.is_some()
        || route.from.is_some()
    {
        return false;
    }
    let Some(dev) = &route.dev else {
        return false;
    };
    let Ok(lo4) = "127.0.0.1/8".parse::<ipnet::IpNet>() else {
        return false;
    };
    let Ok(lo6) = "::1/128".parse::<ipnet::IpNet>() else {
        return false;
    };
    let lo = [lo4, lo6];
    let addresses = if dev == "lo" {
        &lo[..]
    } else {
        let Some(addresses) = cfg.links.get(dev) else {
            return false;
        };
        addresses.as_slice()
    };
    let RouteDestination::Prefix(dst) = route.dst else {
        return false;
    };
    if family == Family::V6 && route.kind == RouteKind::Multicast {
        return "ff00::/8"
            .parse::<ipnet::IpNet>()
            .is_ok_and(|multicast| dst == multicast);
    }
    addresses.iter().any(|address| {
        if address.addr().is_ipv4() != (family == Family::V4)
            || route.prefsrc.is_some_and(|source| source != address.addr())
        {
            return false;
        }
        match (route.kind, address) {
            (RouteKind::Local, _) => {
                dst.addr() == address.addr()
                    && dst.prefix_len() == if family == Family::V4 { 32 } else { 128 }
                    || dev == "lo" && family == Family::V4 && dst == address.trunc()
            }
            (RouteKind::Broadcast, ipnet::IpNet::V4(address)) => {
                address.prefix_len() < 31
                    && dst.prefix_len() == 32
                    && (dst.addr() == IpAddr::V4(address.network())
                        || dst.addr() == IpAddr::V4(address.broadcast()))
            }
            (RouteKind::Anycast, ipnet::IpNet::V6(address)) => {
                dst.prefix_len() == 128
                    && address.prefix_len() < 128
                    && dst.addr() == IpAddr::V6(address.network())
            }
            _ => false,
        }
    })
}

fn extra_route(route: &RouteEntry) -> Violation {
    let table = match &route.table {
        RoutingTable::Main => "main".into(),
        RoutingTable::Local => "local".into(),
        RoutingTable::Default => "default".into(),
        RoutingTable::Number(n) => n.to_string(),
        RoutingTable::Named(name) => name.clone(),
    };
    let dst = match &route.dst {
        RouteDestination::Default => "default".into(),
        RouteDestination::Prefix(prefix) => prefix.to_string(),
    };
    Violation::ExtraRoute {
        table,
        dst,
        dev: route.dev.clone(),
    }
}

fn non_main_routes(
    sys: &dyn System,
    handle: &NetnsHandle,
    cfg: &HealthConfigV2,
    family: Family,
) -> Probe<Vec<Violation>> {
    let mut local = parse_ip_route(&observe(
        sys,
        handle,
        KernelCmd::Ip(IpCmd::RouteShowJson {
            family,
            table: RouteTable::Local,
        }),
    )?)?;
    // iproute2 may omit the table when the dump selected it explicitly. The
    // generic parser defaults that absent field to main; here it means local.
    for route in &mut local {
        if route.table == RoutingTable::Main {
            route.table = RoutingTable::Local;
        }
    }
    let all = parse_ip_route(&observe(
        sys,
        handle,
        KernelCmd::Ip(IpCmd::RouteShowJson {
            family,
            table: RouteTable::All,
        }),
    )?)?;
    let mut found = Vec::new();
    for route in &local {
        if route.table != RoutingTable::Local || !kernel_local(route, cfg, family) {
            found.push(extra_route(route));
        }
    }
    for route in &all {
        if !matches!(route.table, RoutingTable::Main | RoutingTable::Local)
            || route.table == RoutingTable::Local && !kernel_local(route, cfg, family)
        {
            let violation = extra_route(route);
            if !found.contains(&violation) {
                found.push(violation);
            }
        }
    }
    Ok(found)
}

/// Observes default routes for both families and rejects extra main-table routes,
/// permitting only connected kernel routes for configured tunnel prefixes.
/// Local routes must match kernel entries for configured addresses and loopback;
/// routes in every other table are containment violations.
///
/// # Errors
/// Returns command, malformed route and inconsistent snapshot errors.
pub fn defaults(
    sys: &dyn System,
    handle: &NetnsHandle,
    cfg: &HealthConfigV2,
) -> Probe<DefaultRoutes> {
    let (v4, mut extra) = family_defaults(sys, handle, cfg, Family::V4)?;
    let (v6, extra6) = family_defaults(sys, handle, cfg, Family::V6)?;
    extra.extend(extra6);
    let mut violations = non_main_routes(sys, handle, cfg, Family::V4)?;
    violations.extend(non_main_routes(sys, handle, cfg, Family::V6)?);
    Ok(DefaultRoutes {
        v4,
        v6,
        extra,
        violations,
    })
}

fn lookup(
    sys: &dyn System,
    handle: &NetnsHandle,
    dst: IpAddr,
    from: Option<IpAddr>,
    iif: &IfName,
) -> Probe<RouteAnswer> {
    let output = run_cmd(
        sys,
        ExecTarget::Netns(handle),
        &KernelCmd::Ip(IpCmd::RouteGet {
            dst,
            from,
            iif: Some(iif.clone()),
        }),
        EXEC_TIMEOUT,
    );
    // iproute2 reports a negative kernel lookup as exit 2, rather than printing
    // a route. Accept only its exact unreachable diagnostic, never arbitrary
    // command/permission failures, timeout or missing executables.
    // An `unreachable` route answers EHOSTUNREACH ("No route to host"; seen for the IPv6
    // default in the CI lab on Ubuntu 22.04 and 24.04), a missing route ENETUNREACH.
    if output.as_ref().is_ok_and(|out| {
        out.status == Some(2)
            && out.stdout.is_empty()
            && matches!(
                out.stderr.trim(),
                "RTNETLINK answers: Network is unreachable" | "RTNETLINK answers: No route to host"
            )
    }) {
        return Ok(RouteAnswer::Unreachable);
    }
    Ok(parse_route_get(&command_result(output)?)?)
}

/// Collects both families for every configured client or the no-device source.
/// M2 has no IPv6 client sources: the IPv6 probe uses wg0 ingress without a source.
/// Each failed lookup remains an error inside its own family observation.
///
/// # Errors
/// Returns invalid ingress names; lookup errors are retained in each `RouteObs`.
pub fn routes(
    sys: &dyn System,
    handle: &NetnsHandle,
    cfg: &HealthConfigV2,
) -> Probe<Vec<(ClientAddr, RouteObs)>> {
    let iif =
        IfName::new(&cfg.client_iface).map_err(|_| ProbeError::io("invalid route ingress"))?;
    Ok(cfg
        .route_sources
        .iter()
        .map(|source| {
            (
                *source,
                RouteObs {
                    v4: lookup(
                        sys,
                        handle,
                        cfg.route_probe_dst4.into(),
                        Some(*source),
                        &iif,
                    ),
                    v6: lookup(
                        sys,
                        handle,
                        cfg.route_probe_dst6.into(),
                        source.is_ipv6().then_some(*source),
                        &iif,
                    ),
                },
            )
        })
        .collect())
}
