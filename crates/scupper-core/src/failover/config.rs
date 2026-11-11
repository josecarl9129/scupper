//! Pure extraction of applied failover policy.

use std::time::Duration;

use crate::config::{ExitId, ExitIfname, Failback, GatewayId, Rule, Standby, ValidatedSite};

/// Policy and configured route targets. The vector order is the policy order.
/// Public fields also permit pure multi-exit modelling independently of M2 validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverConfig {
    /// Enabled exit IDs and their validated interfaces, in preference order.
    pub exits: Vec<(ExitId, ExitIfname)>,
    /// Manual (sticky) or automatic failback.
    pub failback: Failback,
    /// Continuous healthy time required for automatic failback.
    pub failback_hold: Duration,
    /// Minimum time since the last route activation for automatic failback.
    pub min_dwell: Duration,
    /// Handshake ages strictly greater than this are hard Down.
    pub handshake_stale: Duration,
    /// Initial qualification allowance before a fail-closed page.
    pub fail_closed_grace: Duration,
    /// Reserved standby policy. Hot/cold bring-up and the 60 s qualifier are
    /// no-ops in M2, which validates one exit; M3 will supply those mechanics.
    /// Candidate selection remains correct for any number of observed exits.
    pub standby: Standby,
}

/// A gateway could not be resolved or validated durations could not be converted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FailoverConfigError {
    /// Requested gateway is absent.
    #[error("unknown failover gateway")]
    UnknownGateway,
    /// Defensive check for future validation/conversion drift.
    #[error("invalid failover interval")]
    InvalidInterval,
}

impl FailoverConfig {
    /// Copies only exit identities, interfaces, intervals and policy; no I/O.
    ///
    /// # Errors
    /// Rejects an unknown gateway or an invalid validated policy interval.
    pub fn from_site(
        site: &ValidatedSite,
        gateway: &GatewayId,
    ) -> Result<Self, FailoverConfigError> {
        let gw = site
            .gateway(gateway)
            .ok_or(FailoverConfigError::UnknownGateway)?;
        let interval = |result: Result<Duration, Rule>| {
            result.map_err(|_| FailoverConfigError::InvalidInterval)
        };
        Ok(Self {
            exits: gw
                .exits()
                .iter()
                .map(|exit| (exit.id().clone(), exit.ifname().clone()))
                .collect(),
            failback: site.policy().failback,
            failback_hold: interval(site.policy().failback_hold.duration())?,
            min_dwell: interval(site.policy().min_dwell.duration())?,
            handshake_stale: site.health().handshake_stale(),
            standby: site.policy().standby,
            fail_closed_grace: site.fail_closed_grace(),
        })
    }
}
