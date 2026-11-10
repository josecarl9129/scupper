//! Historical fault selectors for disposable lab builds. Selection is inert
//! unless the explicitly opt-in `lab-mutation` feature is compiled.
use std::str::FromStr;

/// A lab control or historical product fault, with stable artifact names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    /// Bug-1 symptom oracle control in the lab-only policy layout.
    Src,
    /// Accept established flows in every direction.
    Ct,
    /// Omit local output containment.
    Out,
    /// Trust the bound exit probe without checking client routing.
    Probe,
}
impl Mutation {
    /// All lab controls and historical product faults.
    pub const ALL: [Self; 4] = [Self::Src, Self::Ct, Self::Out, Self::Probe];
    /// Stable command-line and report identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Src => "M-src",
            Self::Ct => "M-ct",
            Self::Out => "M-out",
            Self::Probe => "M-probe",
        }
    }
}
impl FromStr for Mutation {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|m| m.name() == value)
            .ok_or_else(|| format!("unknown mutation {value}; use M-src, M-ct, M-out or M-probe"))
    }
}
/// Runtime selector. The environment name and its reader are absent from
/// default-feature binaries. Invalid selections are rejected by the lab CLI.
#[must_use]
#[allow(clippy::disallowed_methods)] // The opt-in lab hook is the sole environment boundary.
pub fn active() -> Option<Mutation> {
    #[cfg(feature = "lab-mutation")]
    {
        std::env::var("SCUPPER_LAB_MUTATION")
            .ok()
            .and_then(|s| s.parse().ok())
    }
    #[cfg(not(feature = "lab-mutation"))]
    {
        None
    }
}

#[cfg(feature = "lab-mutation")]
pub(crate) fn rules(rules: String, mutation: Option<Mutation>) -> Result<String, &'static str> {
    match mutation {
        Some(Mutation::Ct) => {
            if rules.matches("iifname @exit_ifaces oifname @client_ifaces ct state established,related accept").count() != 1 {
                return Err("M-ct selector must match exactly once");
            }
            Ok(rules.replace(
                "iifname @exit_ifaces oifname @client_ifaces ct state established,related accept",
                "ct state established,related accept",
            ))
        }
        Some(Mutation::Out) => {
            let (before, tail) = rules
                .split_once("\tchain output {")
                .ok_or("M-out output chain missing")?;
            if tail.contains("chain ") || !tail.ends_with("\t}\n}\n") {
                return Err("M-out output must be the last chain");
            }
            Ok(format!("{before}}}\n"))
        }
        _ => Ok(rules),
    }
}

/// Binding used by the faulty check's real HTTPS probe.
#[cfg(feature = "lab-mutation")]
#[must_use]
pub fn probe_binding(
    mutation: Option<Mutation>,
    iface: &crate::rules::IfName,
) -> Option<crate::rules::IfName> {
    (mutation == Some(Mutation::Probe)).then(|| iface.clone())
}

/// Substitute route intent for observation, recreating the bound-probe-only
/// check. Used only by the feature-gated staged-check entry point.
/// # Panics
/// Panics if the lab supplies IPv6 client sources; the fixture is IPv4-only.
#[cfg(feature = "lab-mutation")]
pub fn trust_bound_probe(
    obs: &mut crate::verdict::v2::Observations,
    cfg: &crate::verdict::v2::HealthConfigV2,
) {
    use crate::verdict::v2::{RouteAnswer, RouteObs};
    assert!(
        cfg.route_sources.iter().all(std::net::IpAddr::is_ipv4),
        "M-probe requires IPv4-only sources"
    );
    obs.routes = Some(
        cfg.route_sources
            .iter()
            .map(|source| {
                (
                    *source,
                    RouteObs {
                        v4: Ok(RouteAnswer::Dev(cfg.exit_iface.ifname().clone())),
                        v6: Ok(RouteAnswer::Unreachable),
                    },
                )
            })
            .collect(),
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn default_build_cannot_select_mutations() {
        if !cfg!(feature = "lab-mutation") {
            assert_eq!(active(), None);
        }
        assert!("unknown".parse::<Mutation>().is_err());
    }
    #[test]
    #[cfg(feature = "lab-mutation")]
    fn historical_render_diffs_are_golden() {
        let original = include_str!("../tests/golden/netns-m2-one-exit.nft");
        for (mutation, golden) in [
            (
                Mutation::Ct,
                include_str!("../../../tests/golden/M-ct.diff"),
            ),
            (
                Mutation::Out,
                include_str!("../../../tests/golden/M-out.diff"),
            ),
        ] {
            let changed = rules(original.into(), Some(mutation)).unwrap();
            let before: Vec<_> = original.lines().collect();
            let after: Vec<_> = changed.lines().collect();
            let prefix = before
                .iter()
                .zip(&after)
                .take_while(|(a, b)| a == b)
                .count();
            let suffix = before[prefix..]
                .iter()
                .rev()
                .zip(after[prefix..].iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            let removed = before[prefix..before.len() - suffix]
                .iter()
                .map(|s| format!("-{s}\n"))
                .collect::<Vec<_>>()
                .concat();
            let added = after[prefix..after.len() - suffix]
                .iter()
                .map(|s| format!("+{s}\n"))
                .collect::<Vec<_>>()
                .concat();
            assert_eq!(format!("{removed}{added}"), golden);
        }
    }
}
