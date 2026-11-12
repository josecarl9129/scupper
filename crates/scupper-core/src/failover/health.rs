//! Observation memory and the per-exit diagram from DESIGN §6.

use std::time::Duration;

use super::{DownReason, ExitHealth, ExitLinkState, MonoTime};

pub(super) const COMPARISON_WINDOW: Duration = Duration::from_secs(20);
const RECOVERY_SPAN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Signals {
    // No observation differs from an explicit never-handshaken observation.
    pub handshake: Option<(MonoTime, Option<Duration>)>,
    pub link: ExitLinkState,
    pub probe: Option<(MonoTime, bool)>,
    pub initial_successes: u8,
    pub unconfirmed: bool,
    pub initial_link_pending: bool,
    // Only an unexplained hard fault may bypass the initial paging window.
    pub non_qualification_fault: bool,
}

impl Signals {
    pub fn fresh(&self, now: MonoTime, stale: Duration) -> bool {
        self.handshake.is_some_and(|(at, age)| {
            age.is_some_and(|age| age.saturating_add(now.elapsed_since(at)) <= stale)
        })
    }

    pub fn hard_fault(&self, now: MonoTime, stale: Duration) -> Option<DownReason> {
        if !self.link.link_up {
            Some(DownReason::LinkMissing)
        } else if !self.link.peer_present {
            Some(DownReason::PeerMissing)
        } else if !self.link.key_present {
            Some(DownReason::KeyMissing)
        } else if self.handshake.is_some() && !self.fresh(now, stale) {
            Some(DownReason::HandshakeStale)
        } else {
            None
        }
    }

    pub fn qualification_fault(
        &self,
        now: MonoTime,
        reason: DownReason,
        qualification_age: Option<Duration>,
    ) -> bool {
        match reason {
            // A retained handshake at/before the window start is equivalent
            // to no handshake in this qualification. Account for Tick aging too.
            DownReason::HandshakeStale => self.handshake.is_some_and(|(at, age)| {
                age.is_none_or(|age| {
                    qualification_age
                        .is_some_and(|elapsed| age.saturating_add(now.elapsed_since(at)) >= elapsed)
                })
            }),
            DownReason::LinkMissing | DownReason::PeerMissing => self.initial_link_pending,
            DownReason::KeyMissing | DownReason::PathProbeFailed => false,
        }
    }

    pub fn comparison_success(&self, now: MonoTime) -> bool {
        self.probe.is_some_and(|(at, success)| {
            success && now >= at && now.elapsed_since(at) <= COMPARISON_WINDOW
        })
    }
}

pub(super) fn down(health: &mut ExitHealth, now: MonoTime, reason: DownReason) {
    let since = match health {
        ExitHealth::Down { since, .. } => *since,
        _ => now,
    };
    *health = ExitHealth::Down { since, reason };
}

pub(super) fn probe(
    health: &mut ExitHealth,
    signals: &mut Signals,
    now: MonoTime,
    success: bool,
    counted: bool,
    fresh: bool,
) {
    let counted = counted || signals.unconfirmed;
    if success {
        signals.unconfirmed = false;
    }
    if !success {
        signals.initial_successes = 0;
    }
    *health = match *health {
        ExitHealth::Unknown if success && fresh => {
            signals.initial_successes = signals.initial_successes.saturating_add(1).min(3);
            if signals.initial_successes == 3 {
                ExitHealth::Healthy {
                    since: now,
                    confirmed: true,
                }
            } else {
                ExitHealth::Unknown
            }
        }
        ExitHealth::Healthy { since, .. } if success => ExitHealth::Healthy {
            since,
            confirmed: true,
        },
        ExitHealth::Healthy { .. } if !success && counted => ExitHealth::Suspect {
            failures: 1,
            since: now,
        },
        ExitHealth::Suspect { .. } if success => ExitHealth::Healthy {
            since: now,
            confirmed: true,
        },
        ExitHealth::Suspect { failures, since } if counted => {
            if failures >= 2 {
                ExitHealth::Down {
                    since: now,
                    reason: DownReason::PathProbeFailed,
                }
            } else {
                ExitHealth::Suspect {
                    failures: failures + 1,
                    since,
                }
            }
        }
        // The recovery diagram requires consecutive successes: even a common-mode
        // failure interrupts qualification, without switching a healthy active exit.
        ExitHealth::Recovering { .. } if !success => ExitHealth::Down {
            since: now,
            reason: DownReason::PathProbeFailed,
        },
        ExitHealth::Recovering { successes, since } if fresh => {
            let since = if successes == 0 { now } else { since };
            let successes = successes.saturating_add(1).min(3);
            if successes >= 3 && now.elapsed_since(since) >= RECOVERY_SPAN {
                ExitHealth::Healthy {
                    since: now,
                    confirmed: true,
                }
            } else {
                ExitHealth::Recovering { successes, since }
            }
        }
        ref unchanged => unchanged.clone(),
    };
}
