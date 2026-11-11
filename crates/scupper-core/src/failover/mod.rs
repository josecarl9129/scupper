//! Pure exit health and sticky failover (DESIGN §6; ADRs 0010, 0011, 0016).
//!
//! The caller supplies nondecreasing monotonic times and public observations.
//! No clocks, probes, route writes, key reads or other I/O occur here. Start closed
//! with [`Failover::new`], or resume a verified live handoff with
//! [`Failover::resume_verified`]. Otherwise execute the initial actions in order. The executor
//! must also reapply [`Failover::desired_route`] on every reconciliation
//! tick, including after route drift while closed. Every route
//! target comes from the supplied configuration or is unreachable (I1).
//!
//! M2 standby qualification/bring-up is a no-op for either standby mode: validation
//! admits one exit. The same observation and action API supports N-exit decisions;
//! M3 supplies hot/cold session management and the 60-second cold qualifier.

mod config;
mod health;
mod types;

use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

use crate::{
    config::{ExitId, Failback},
    render::RouteTarget,
};

pub use config::{FailoverConfig, FailoverConfigError};
pub use types::*;

const FLAP_WINDOW: Duration = Duration::from_mins(30);
const FLAP_SUPPRESSION: Duration = Duration::from_hours(1);

/// Route intent and per-exit health, with bounded observation and switch history.
/// Fields are read-only through accessors so callers cannot inject a foreign route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failover {
    selection: Selection,
    active: RouteTarget,
    active_exit: Option<ExitId>,
    health: BTreeMap<ExitId, ExitHealth>,
    switches: VecDeque<MonoTime>,
    failback_suppressed_until: Option<MonoTime>,
    fail_closed_since: Option<MonoTime>,
    closed_reason: Option<FailClosedReason>,
    closure_reported: bool,
    qualifying: bool,
    signals: BTreeMap<ExitId, health::Signals>,
    last_activation: Option<MonoTime>,
}

impl Failover {
    /// Starts unreachable with Unknown health and a closure interval beginning at `now`.
    /// Execute the initial route/flush actions unless the caller verifies the live
    /// handoff and calls `resume_verified` before the first step.
    #[must_use]
    pub fn new(
        now: MonoTime,
        selection: Selection,
        cfg: &FailoverConfig,
    ) -> (Self, Vec<FailoverAction>) {
        let mut machine = Self {
            selection,
            active: RouteTarget::Unreachable,
            active_exit: None,
            health: BTreeMap::new(),
            switches: VecDeque::new(),
            failback_suppressed_until: None,
            fail_closed_since: Some(now),
            closed_reason: None,
            closure_reported: false,
            qualifying: true,
            signals: BTreeMap::new(),
            last_activation: None,
        };
        machine.sync_config(cfg);
        machine.closed_reason = Some(machine.unavailable_reason());
        let mut actions = vec![
            FailoverAction::SetRoute(RouteTarget::Unreachable),
            FailoverAction::FlushConntrack,
        ];
        if machine.selection == Selection::Disconnected {
            actions.push(FailoverAction::SetExitsDown);
        }
        (machine, actions)
    }

    /// Resume a verified live route without generating route or conntrack actions.
    /// The caller must verify the namespace, policy, live defaults and exit readiness.
    /// Returns false when the route conflicts with administrative selection.
    pub fn resume_verified(&mut self, now: MonoTime, exit: &ExitId, cfg: &FailoverConfig) -> bool {
        if !self.candidates(cfg).contains(&exit) {
            return false;
        }
        let Some((_, iface)) = cfg.exits.iter().find(|(id, _)| id == exit) else {
            return false;
        };
        self.active = RouteTarget::Exit(iface.clone());
        self.active_exit = Some(exit.clone());
        self.health.insert(
            exit.clone(),
            ExitHealth::Healthy {
                since: now,
                confirmed: false,
            },
        );
        if let Some(signals) = self.signals.get_mut(exit) {
            signals.unconfirmed = true;
        }
        self.fail_closed_since = None;
        self.closed_reason = None;
        self.closure_reported = false;
        self.qualifying = false;
        self.last_activation = Some(now);
        true
    }

    /// Desired route to apply at startup and on every reconciliation tick, even
    /// when `step` returns no actions. This repairs executor/kernel route drift.
    #[must_use]
    pub fn desired_route(&self) -> &RouteTarget {
        &self.active
    }

    /// Current persisted administrative intent.
    #[must_use]
    pub fn selection(&self) -> &Selection {
        &self.selection
    }
    /// Current route intent, independently of any live kernel observation.
    #[must_use]
    pub fn active(&self) -> &RouteTarget {
        &self.active
    }
    /// The active handoff has not yet had a successful path probe.
    #[must_use]
    pub fn unconfirmed(&self) -> bool {
        self.active_exit
            .as_ref()
            .and_then(|id| self.signals.get(id))
            .is_some_and(|signals| signals.unconfirmed)
    }
    /// Per-exit health, in stable exit-ID order.
    #[must_use]
    pub fn health(&self) -> &BTreeMap<ExitId, ExitHealth> {
        &self.health
    }
    /// Exit-to-exit switches still inside the thirty-minute flap window.
    #[must_use]
    pub fn switches(&self) -> &VecDeque<MonoTime> {
        &self.switches
    }
    /// Deadline until which only automatic failback is suppressed.
    #[must_use]
    pub fn failback_suppressed_until(&self) -> Option<MonoTime> {
        self.failback_suppressed_until
    }
    /// Beginning of the current uninterrupted closure interval.
    #[must_use]
    pub fn fail_closed_since(&self) -> Option<MonoTime> {
        self.fail_closed_since
    }
    /// Reason for current closure; None while active.
    #[must_use]
    pub fn fail_closed_reason(&self) -> Option<&FailClosedReason> {
        self.closed_reason.as_ref()
    }

    /// Current alert state; qualification has no definitive incident state yet.
    #[must_use]
    pub fn fail_closed_alert_state(&self) -> Option<bool> {
        if self.qualifying && !self.closure_reported && self.selection != Selection::Disconnected {
            None
        } else {
            Some(self.closure_reported)
        }
    }

    /// Advances the health diagrams and global transition table without side effects.
    ///
    /// `now` must use the same monotonic origin as prior calls. Handshake ages keep
    /// advancing on Tick. Batch probe failures cannot witness one another's health;
    /// otherwise a successful latest probe is a witness for at most twenty seconds.
    /// Deliver each complete probe round as one `PathProbe` map (including the
    /// immediate standby probe when the active exit becomes Suspect). Separate
    /// same-instant inputs are not buffered and violate this batching contract.
    /// An administrative request bypasses failback hold, dwell and suppression.
    /// All exit switches, including operator moves, count toward flap suppression.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // Owned input is the specified public step API.
    pub fn step(
        &self,
        now: MonoTime,
        input: FailoverInput,
        cfg: &FailoverConfig,
    ) -> (Self, Vec<FailoverAction>) {
        let mut next = self.clone();
        next.sync_config(cfg);
        let input = if let FailoverInput::ProbeRound(results) = input {
            let mut paths = BTreeMap::new();
            for (id, outcome) in results {
                match outcome {
                    ProbeOutcome::Inconclusive => {
                        if let Some(signals) = next.signals.get_mut(&id) {
                            signals.probe = None;
                        }
                    }
                    ProbeOutcome::Success => {
                        paths.insert(id, true);
                    }
                    ProbeOutcome::Failure => {
                        paths.insert(id, false);
                    }
                }
            }
            FailoverInput::PathProbe(paths)
        } else {
            input
        };
        next.switches
            .retain(|at| now.elapsed_since(*at) <= FLAP_WINDOW);
        if next
            .failback_suppressed_until
            .is_some_and(|until| now >= until)
        {
            next.failback_suppressed_until = None;
        }
        let admin = matches!(input, FailoverInput::SelectionChanged(_));
        if next.selection != Selection::Disconnected || admin {
            next.observe(now, &input, cfg);
        }
        let mut actions = Vec::new();
        next.decide(now, admin, cfg, &mut actions);
        (next, actions)
    }

    fn sync_config(&mut self, cfg: &FailoverConfig) {
        self.health
            .retain(|id, _| cfg.exits.iter().any(|(exit, _)| id == exit));
        self.signals.retain(|id, _| self.health.contains_key(id));
        for (id, _) in &cfg.exits {
            self.health.entry(id.clone()).or_insert(ExitHealth::Unknown);
            self.signals.entry(id.clone()).or_default();
        }
    }

    fn observe(&mut self, now: MonoTime, input: &FailoverInput, cfg: &FailoverConfig) {
        match input {
            FailoverInput::SelectionChanged(selection) => {
                if self.selection == Selection::Disconnected
                    && *selection != Selection::Disconnected
                {
                    self.qualifying = true;
                    self.fail_closed_since = Some(now);
                }
                self.selection = selection.clone();
            }
            FailoverInput::Handshakes(ages) => {
                for (id, age) in ages {
                    if let Some(signals) = self.signals.get_mut(id) {
                        signals.handshake = Some((now, *age));
                    }
                }
            }
            FailoverInput::LinkState(id, link) => {
                if let Some(signals) = self.signals.get_mut(id) {
                    signals.link = *link;
                }
            }
            FailoverInput::PathProbe(_) | FailoverInput::ProbeRound(_) | FailoverInput::Tick => {}
        }
        let initial_window = self.qualifying
            && self
                .fail_closed_since
                .is_some_and(|since| now.elapsed_since(since) <= cfg.fail_closed_grace);
        for (id, signals) in &mut self.signals {
            let Some(state) = self.health.get_mut(id) else {
                continue;
            };
            if let Some(reason) = signals.hard_fault(now, cfg.handshake_stale) {
                // No handshake yet is normal during initial bring-up. Stay closed
                // and Unknown so a fresh handshake can qualify without recovery delay.
                if initial_window
                    && matches!(state, ExitHealth::Unknown)
                    && reason == DownReason::HandshakeStale
                    && signals.handshake.is_some_and(|(_, age)| age.is_none())
                {
                    signals.initial_successes = 0;
                    signals.probe = None;
                    continue;
                }
                health::down(state, now, reason);
                signals.initial_successes = 0;
                signals.probe = None;
            } else if matches!(input, FailoverInput::Handshakes(ages) if ages.contains_key(id))
                && signals.fresh(now, cfg.handshake_stale)
                && matches!(state, ExitHealth::Down { .. })
            {
                *state = ExitHealth::Recovering {
                    successes: 0,
                    since: now,
                };
            }
        }
        if let FailoverInput::PathProbe(results) = input {
            // Install all outcomes before evaluating any comparisons.
            for (id, success) in results {
                if let Some(signals) = self.signals.get_mut(id) {
                    signals.probe = Some((
                        now,
                        *success
                            && signals.fresh(now, cfg.handshake_stale)
                            && signals.hard_fault(now, cfg.handshake_stale).is_none(),
                    ));
                }
            }
            for (id, success) in results {
                let counted = self.signals.iter().any(|(other, signals)| {
                    other != id
                        && !matches!(self.health.get(other), Some(ExitHealth::Down { .. }))
                        && signals.comparison_success(now)
                });
                let Some(signals) = self.signals.get_mut(id) else {
                    continue;
                };
                let Some(state) = self.health.get_mut(id) else {
                    continue;
                };
                if signals.hard_fault(now, cfg.handshake_stale).is_none() {
                    let fresh = signals.fresh(now, cfg.handshake_stale);
                    health::probe(state, signals, now, *success, counted, fresh);
                }
            }
        }
    }

    fn candidates<'a>(&self, cfg: &'a FailoverConfig) -> Vec<&'a ExitId> {
        let policy = cfg.exits.iter().map(|(id, _)| id);
        match &self.selection {
            Selection::Auto => policy.collect(),
            Selection::Prefer(preferred) => policy
                .clone()
                .filter(|id| *id == preferred)
                .chain(policy.filter(|id| *id != preferred))
                .collect(),
            Selection::Pin(pinned) => policy.filter(|id| *id == pinned).collect(),
            Selection::Disconnected => Vec::new(),
        }
    }

    fn unavailable_reason(&self) -> FailClosedReason {
        match &self.selection {
            Selection::Disconnected => FailClosedReason::AdminDisconnected,
            Selection::Pin(id) => FailClosedReason::PinnedExitDown(id.clone()),
            Selection::Auto | Selection::Prefer(_) => FailClosedReason::NoHealthyExit,
        }
    }

    #[allow(clippy::too_many_lines)] // Keep common-mode, selection and failback ordering together.
    fn decide(
        &mut self,
        now: MonoTime,
        admin: bool,
        cfg: &FailoverConfig,
        actions: &mut Vec<FailoverAction>,
    ) {
        if self.selection == Selection::Disconnected {
            if self.closed_reason != Some(FailClosedReason::AdminDisconnected) {
                self.health
                    .values_mut()
                    .for_each(|state| *state = ExitHealth::Unknown);
                self.signals
                    .values_mut()
                    .for_each(|signals| *signals = health::Signals::default());
                actions.extend([
                    FailoverAction::SetRoute(RouteTarget::Unreachable),
                    FailoverAction::FlushConntrack,
                    FailoverAction::SetExitsDown,
                ]);
            }
            self.active = RouteTarget::Unreachable;
            self.active_exit = None;
            self.fail_closed_since.get_or_insert(now);
            self.closed_reason = Some(FailClosedReason::AdminDisconnected);
            self.closure_reported = false;
            return;
        }
        let previous = self.active_exit.clone();
        let current = previous.as_ref();
        let common_mode = self.common_mode(now);
        let candidates = self.candidates(cfg);
        if common_mode
            && current.is_some_and(|id| {
                candidates.contains(&id)
                    && cfg.exits.iter().any(|(exit, iface)| {
                        exit == id && self.active == RouteTarget::Exit(iface.clone())
                    })
                    && matches!(
                        self.health.get(id),
                        Some(ExitHealth::Healthy { .. } | ExitHealth::Suspect { .. })
                    )
            })
        {
            return;
        }
        let first_healthy = candidates.iter().copied().find(|id| {
            !common_mode
                && matches!(
                    self.health.get(*id),
                    Some(ExitHealth::Healthy {
                        confirmed: true,
                        ..
                    })
                )
        });
        let must_choose = admin
            || current.is_none()
            || current.is_some_and(|id| {
                !candidates.contains(&id)
                    || !cfg.exits.iter().any(|(exit, iface)| {
                        exit == id && self.active == RouteTarget::Exit(iface.clone())
                    })
                    || matches!(self.health.get(id), Some(ExitHealth::Down { .. }))
            });
        if must_choose {
            if let Some(to) = first_healthy {
                if current != Some(to)
                    || cfg.exits.iter().any(|(id, iface)| {
                        id == to && self.active != RouteTarget::Exit(iface.clone())
                    })
                {
                    self.activate(now, current, to, admin, cfg, actions);
                }
            } else {
                let reason = self.unavailable_reason();
                if self.active != RouteTarget::Unreachable {
                    actions.extend([
                        FailoverAction::SetRoute(RouteTarget::Unreachable),
                        FailoverAction::FlushConntrack,
                    ]);
                }
                let alertable = !self.qualifying
                    || cfg.exits.is_empty()
                    || self
                        .fail_closed_since
                        .is_some_and(|since| now.elapsed_since(since) > cfg.fail_closed_grace);
                if !self.closure_reported && alertable {
                    actions.push(FailoverAction::Emit(FailoverEvent::FailClosedStarted(
                        reason.clone(),
                    )));
                    self.closure_reported = true;
                }
                self.active = RouteTarget::Unreachable;
                self.active_exit = None;
                self.fail_closed_since.get_or_insert(now);
                self.closed_reason = Some(reason);
            }
            return;
        }
        if cfg.failback != Failback::Auto
            // Common-mode failure must not trigger a timer-driven failback either.
            // Hard failures and explicit admin requests were handled above.
            || common_mode
            || self
                .failback_suppressed_until
                .is_some_and(|until| now < until)
            || self
                .last_activation
                .is_some_and(|at| now.elapsed_since(at) < cfg.min_dwell)
        {
            return;
        }
        for candidate in candidates {
            if Some(candidate) == current {
                break;
            }
            if self
                .signals
                .get(candidate)
                .is_some_and(|signals| signals.comparison_success(now))
                && matches!(self.health.get(candidate), Some(ExitHealth::Healthy { since, confirmed: true }) if now.elapsed_since(*since) >= cfg.failback_hold)
            {
                self.activate(now, current, candidate, true, cfg, actions);
                break;
            }
        }
    }

    fn common_mode(&self, now: MonoTime) -> bool {
        let mut observed = self
            .signals
            .iter()
            .filter(|(id, _)| !matches!(self.health.get(*id), Some(ExitHealth::Down { .. })))
            .filter_map(|(_, signals)| {
                signals.probe.filter(|(at, _)| {
                    now >= *at && now.elapsed_since(*at) <= health::COMPARISON_WINDOW
                })
            })
            .peekable();
        observed.peek().is_some() && observed.all(|(_, success)| !success)
    }

    fn activate(
        &mut self,
        now: MonoTime,
        from: Option<&ExitId>,
        to: &ExitId,
        failback: bool,
        cfg: &FailoverConfig,
        actions: &mut Vec<FailoverAction>,
    ) {
        let Some((_, iface)) = cfg.exits.iter().find(|(id, _)| id == to) else {
            return;
        };
        self.active = RouteTarget::Exit(iface.clone());
        self.active_exit = Some(to.clone());
        self.last_activation = Some(now);
        self.closed_reason = None;
        let was_reported = self.closure_reported;
        self.closure_reported = false;
        self.qualifying = false;
        actions.push(FailoverAction::SetRoute(self.active.clone()));
        if let Some(from) = from {
            actions.push(FailoverAction::FlushConntrack);
            actions.push(FailoverAction::NotifyEdge(to.clone()));
            actions.push(FailoverAction::Emit(if failback {
                FailoverEvent::Failback {
                    from: from.clone(),
                    to: to.clone(),
                }
            } else {
                FailoverEvent::Failover {
                    from: from.clone(),
                    to: to.clone(),
                }
            }));
            self.switches.push_back(now);
            if self.switches.len() > 4 {
                self.failback_suppressed_until = Some(now.after(FLAP_SUPPRESSION));
                actions.push(FailoverAction::Emit(FailoverEvent::Flapping));
            }
        } else {
            actions.push(FailoverAction::NotifyEdge(to.clone()));
            if let Some(since) = self.fail_closed_since.filter(|_| was_reported) {
                actions.push(FailoverAction::Emit(FailoverEvent::FailClosedEnded {
                    duration: now.elapsed_since(since),
                }));
            }
        }
        self.fail_closed_since = None;
    }
}
