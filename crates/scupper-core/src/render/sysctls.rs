//! Namespace sysctl write order from DESIGN §5.4.

use std::collections::BTreeSet;

use crate::{
    config::{GatewayId, ValidatedSite},
    rules::IfName,
};

/// One desired kernel value, also suitable for read-back comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sysctl {
    /// Dotted `/proc/sys` key, for example `net.ipv4.ip_forward`.
    pub key: String,
    /// Decimal kernel value.
    pub value: String,
}

/// Returns forwarding first, then every hardening value, for ordered writes.
///
/// The hardening policy is identical for all validated M2 gateways. `links`
/// supplies the complete namespace link inventory (including loopback); its
/// names are sorted and deduplicated alongside `all` and `default`. No host
/// uplink is inferred from the site. Reapply this entire list after changing
/// forwarding, since IPv4 forwarding writes reset some device settings.
#[must_use]
pub fn desired_sysctls(
    _site: &ValidatedSite,
    _gateway: &GatewayId,
    links: &[IfName],
    forwarding: bool,
) -> Vec<Sysctl> {
    let mut values = Vec::new();
    for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
        values.push(Sysctl {
            key: key.into(),
            value: u8::from(forwarding).to_string(),
        });
    }
    let mut harden = |key: String| {
        values.push(Sysctl {
            key,
            value: "0".into(),
        });
    };
    let names: BTreeSet<_> = ["all", "default"]
        .into_iter()
        .chain(links.iter().map(IfName::as_str))
        .collect();
    for name in names {
        harden(format!("net.ipv4.conf.{name}.rp_filter"));
    }
    for name in ["all", "default"] {
        for setting in ["accept_redirects", "send_redirects", "accept_source_route"] {
            harden(format!("net.ipv4.conf.{name}.{setting}"));
        }
    }
    for name in ["all", "default"] {
        for setting in ["accept_ra", "accept_redirects", "autoconf"] {
            harden(format!("net.ipv6.conf.{name}.{setting}"));
        }
    }
    for key in [
        "net.ipv4.conf.all.proxy_arp",
        "net.ipv6.conf.all.proxy_ndp",
        "net.ipv4.conf.all.route_localnet",
        "net.netfilter.nf_conntrack_tcp_loose",
    ] {
        harden(key.into());
    }
    values
}
