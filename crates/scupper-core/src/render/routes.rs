//! Default routes: an exit tunnel or an immediate unreachable error.

use crate::config::{ExitId, ExitIfname, GatewayId, ValidatedSite};

/// Address family of a namespace default route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4 (the default family for `ip route`).
    V4,
    /// IPv6 (`ip -6 route`).
    V6,
}

/// The only permitted non-kernel route targets inside the namespace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum RouteTarget {
    /// A validated exit interface; an uplink cannot inhabit this type.
    Exit(ExitIfname),
    /// Reject immediately so applications can reconnect or fall back.
    Unreachable,
}

/// Renders arguments following `ip -n scupper`, without executing anything.
#[must_use]
pub fn route_argv(family: Family, target: &RouteTarget) -> Vec<String> {
    let mut args = Vec::new();
    if family == Family::V6 {
        args.push("-6".into());
    }
    args.extend(["route".into(), "replace".into()]);
    match target {
        RouteTarget::Exit(ifname) => {
            args.extend(["default".into(), "dev".into(), ifname.as_str().into()]);
        }
        RouteTarget::Unreachable => args.extend(["unreachable".into(), "default".into()]),
    }
    args
}

/// Selects defaults in IPv4, IPv6 order. M2 always makes IPv6 unreachable.
///
/// No selection, an unknown gateway, or an exit outside that gateway's enabled
/// policy all fail closed to unreachable routes.
#[must_use]
pub fn desired_routes(
    site: &ValidatedSite,
    gateway: &GatewayId,
    selection: Option<&ExitId>,
) -> [(Family, RouteTarget); 2] {
    let v4 = site
        .gateway(gateway)
        .and_then(|gw| {
            gw.exits()
                .iter()
                .find(|exit| exit.enabled() && Some(exit.id()) == selection)
        })
        .map_or(RouteTarget::Unreachable, |exit| {
            RouteTarget::Exit(exit.ifname().clone())
        });
    [(Family::V4, v4), (Family::V6, RouteTarget::Unreachable)]
}
