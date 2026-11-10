//! Time, observations and the closed action alphabet.

use std::{collections::BTreeMap, time::Duration};

pub use crate::verdict::v2::Selection;
use crate::{config::ExitId, render::RouteTarget};

/// Time since an arbitrary monotonic origin, supplied by the caller (no clock access).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonoTime(pub Duration);

impl MonoTime {
    /// Elapsed time, saturating defensively for a reversed input timestamp.
    #[must_use]
    pub fn elapsed_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// A deadline, saturating at the representable time limit.
    #[must_use]
    pub fn after(self, interval: Duration) -> Self {
        Self(self.0.saturating_add(interval))
    }
}

/// Independently observed health; only Healthy exits can become new targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitHealth {
    /// Startup qualification is incomplete.
    Unknown,
    /// Fresh handshake; a resumed path awaits its first successful probe.
    Healthy {
        /// Start of uninterrupted healthy time.
        since: MonoTime,
        /// A successful path probe has confirmed this process's handoff.
        confirmed: bool,
    },
    /// One or two consecutive counted path failures.
    Suspect {
        /// Count including the failure that entered Suspect.
        failures: u8,
        /// Time of the first counted failure.
        since: MonoTime,
    },
    /// A hard fault or three counted path failures.
    Down {
        /// Time this down episode began.
        since: MonoTime,
        /// Most recently observed cause.
        reason: DownReason,
    },
    /// A fresh handshake returned; path qualification is in progress.
    Recovering {
        /// Consecutive successful probes, saturating at three.
        successes: u8,
        /// First success, or entry time before the first success.
        since: MonoTime,
    },
}

/// Causes that prevent an exit from carrying traffic reliably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownReason {
    /// Handshake age strictly exceeds the configured bound, or has never handshaken.
    HandshakeStale,
    /// Tunnel link is absent or down.
    LinkMissing,
    /// Configured provider peer is absent.
    PeerMissing,
    /// Local key is absent; only its presence is an input here.
    KeyMissing,
    /// Three counted failures, or a failed recovery probe.
    PathProbeFailed,
}

/// Public presence flags, supplied without reading any key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitLinkState {
    /// Tunnel exists and is administratively up.
    pub link_up: bool,
    /// Configured peer exists.
    pub peer_present: bool,
    /// Required local key exists.
    pub key_present: bool,
}

impl Default for ExitLinkState {
    fn default() -> Self {
        Self {
            link_up: true,
            peer_present: true,
            key_present: true,
        }
    }
}

/// Result of a path observation, distinguished from our-side setup failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The path answered successfully.
    Success,
    /// The observation completed and the path failed.
    Failure,
    /// Our-side setup failed; supplies no path-health evidence.
    Inconclusive,
}
impl From<bool> for ProbeOutcome {
    fn from(success: bool) -> Self {
        if success {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

/// One observation batch or administrative request; unknown exit IDs are ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverInput {
    /// Ages at `now`; None means explicitly never handshaken. Omitted exits are unchanged.
    Handshakes(BTreeMap<ExitId, Option<Duration>>),
    /// One complete probe round, batched by the caller even when results arrive
    /// separately at the same instant; include the immediate standby comparison
    /// probe started on Suspect. Never deliver one round as separate inputs.
    /// Path results collected together. A failed result invalidates that exit as a
    /// comparison witness, including for other failures in this batch. This makes
    /// simultaneous common-mode failure independent of map iteration order.
    PathProbe(BTreeMap<ExitId, bool>),
    /// Completed observations, including our-side failures which preserve qualification.
    ProbeRound(BTreeMap<ExitId, ProbeOutcome>),
    /// Link, peer and key presence for one exit.
    LinkState(ExitId, ExitLinkState),
    /// Operator action only: re-evaluate even when intent is unchanged.
    /// Restart with `Failover::new`; do not replay persisted intent here.
    SelectionChanged(Selection),
    /// Re-evaluate handshake expiry, holds, dwell and suppression.
    Tick,
}

/// Why the global route is unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailClosedReason {
    /// Operator requested disconnection.
    AdminDisconnected,
    /// No eligible exit is healthy.
    NoHealthyExit,
    /// Only the pinned exit is eligible, and it is not healthy.
    PinnedExitDown(ExitId),
}

/// Operational events contain only exit identities and monotonic intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverEvent {
    /// The active exit failed and a healthy candidate replaced it.
    Failover {
        /// Previous exit.
        from: ExitId,
        /// Replacement exit.
        to: ExitId,
    },
    /// Automatic or administrative return to a preferred candidate.
    Failback {
        /// Previous exit.
        from: ExitId,
        /// Replacement exit.
        to: ExitId,
    },
    /// Automatic closure began.
    FailClosedStarted(FailClosedReason),
    /// A healthy candidate restored service.
    FailClosedEnded {
        /// Time spent closed, including startup or administrative disconnection.
        duration: Duration,
    },
    /// More than four exit switches within thirty minutes suppressed failback.
    Flapping,
}

/// The complete output alphabet. Execution and per-family route expansion are external.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverAction {
    /// Replace the defaults with an exit or unreachable (I1).
    SetRoute(RouteTarget),
    /// Flush flows after replacing the route.
    FlushConntrack,
    /// Administratively bring all exits down.
    SetExitsDown,
    /// Select the new exit's DNS upstream.
    NotifyEdge(ExitId),
    /// Publish an operational event.
    Emit(FailoverEvent),
}
