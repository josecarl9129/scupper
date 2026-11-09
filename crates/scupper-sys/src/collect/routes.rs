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
        RouteObs,
    },
};
use std::net::IpAddr;

fn answer(route: &RouteEntry) -> DefaultRouteObs {
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

fn kernel_route(route: &RouteEntry, cfg: &HealthConfigV2) -> bool {
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

/// Observes default routes for both families and rejects extra main-table routes,
/// permitting only connected kernel routes for configured tunnel prefixes.
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
    Ok(DefaultRoutes { v4, v6, extra })
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
