//! Namespace sysctl write order from DESIGN §5.4.

use std::{collections::BTreeMap, fmt, path::PathBuf};

use crate::rules::IfName;

/// Network subtree containing a sysctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysctlFamily {
    /// IPv4 settings.
    Ipv4,
    /// IPv6 settings.
    Ipv6,
    /// Connection tracking settings.
    Netfilter,
}

impl fmt::Display for SysctlFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Netfilter => "netfilter",
        })
    }
}

/// Global or interface configuration scope of a sysctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Aggregate interface settings.
    All,
    /// Settings inherited by newly created interfaces.
    Default,
    /// Settings for one existing interface.
    Link(IfName),
    /// A setting directly in the family subtree.
    Global,
}

impl Scope {
    fn link_name(&self) -> Option<&str> {
        match self {
            Self::All => Some("all"),
            Self::Default => Some("default"),
            Self::Link(link) => Some(link.as_str()),
            Self::Global => None,
        }
    }
}

/// Structured key that preserves dots within interface names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlKey {
    /// Network subtree.
    pub family: SysctlFamily,
    /// Interface configuration or global scope.
    pub scope: Scope,
    /// Kernel setting name.
    pub name: &'static str,
}

impl SysctlKey {
    /// Returns the kernel file path without interpreting interface-name dots.
    #[must_use]
    pub fn proc_path(&self) -> PathBuf {
        let mut path = PathBuf::from("/proc/sys/net");
        path.push(self.family.to_string());
        if let Some(link) = self.scope.link_name() {
            path.push("conf");
            path.push(link);
        }
        path.push(self.name);
        path
    }
}

impl fmt::Display for SysctlKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "net.{}.", self.family)?;
        if let Some(link) = self.scope.link_name() {
            // sysctl(8) interchanges dots and slashes after the first separator.
            write!(f, "conf.{}.", link.replace('.', "/"))?;
        }
        f.write_str(self.name)
    }
}

/// One desired kernel value, also suitable for read-back comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sysctl {
    /// Structured `/proc/sys` key.
    pub key: SysctlKey,
    /// Decimal kernel value.
    pub value: String,
}

/// Returns forwarding first, then every hardening value, for ordered writes.
///
/// `links` supplies the complete namespace link inventory (including loopback).
/// Names are sorted and deduplicated; aggregate and default scopes come first.
/// Reapply this entire list after changing forwarding, since IPv4 forwarding
/// writes reset some device settings.
#[must_use]
pub fn desired_sysctls(links: &[IfName], forwarding: bool) -> Vec<Sysctl> {
    use SysctlFamily::{Ipv4, Ipv6, Netfilter};

    let mut values = Vec::new();
    for (family, scope, name) in [
        (Ipv4, Scope::Global, "ip_forward"),
        (Ipv6, Scope::All, "forwarding"),
    ] {
        values.push(Sysctl {
            key: SysctlKey {
                family,
                scope,
                name,
            },
            value: u8::from(forwarding).to_string(),
        });
    }
    let mut harden = |family, scope, name| {
        values.push(Sysctl {
            key: SysctlKey {
                family,
                scope,
                name,
            },
            value: "0".into(),
        });
    };
    let links: BTreeMap<_, _> = links
        .iter()
        .filter(|link| !matches!(link.as_str(), "all" | "default"))
        .map(|link| (link.as_str(), link))
        .collect();
    let scopes: Vec<_> = [Scope::All, Scope::Default]
        .into_iter()
        .chain(links.into_values().map(|link| Scope::Link(link.clone())))
        .collect();
    for scope in &scopes {
        harden(Ipv4, scope.clone(), "rp_filter");
    }
    for scope in scopes {
        for setting in ["accept_redirects", "send_redirects", "accept_source_route"] {
            harden(Ipv4, scope.clone(), setting);
        }
    }
    for scope in [Scope::All, Scope::Default] {
        for setting in ["accept_ra", "accept_redirects", "autoconf"] {
            harden(Ipv6, scope.clone(), setting);
        }
    }
    for (family, scope, name) in [
        (Ipv4, Scope::All, "proxy_arp"),
        (Ipv6, Scope::All, "proxy_ndp"),
        (Ipv4, Scope::All, "route_localnet"),
        (Netfilter, Scope::Global, "nf_conntrack_tcp_loose"),
    ] {
        harden(family, scope, name);
    }
    values
}
