//! Sender deadlines provide best-effort bounded staleness, not a network delivery guarantee.
//! Pure external heartbeat eligibility; all times come from the caller.
use crate::{
    config::{HeartbeatReport, HeartbeatSettings},
    failover::MonoTime,
    verdict::v2::Report,
};
use std::time::Duration;

/// Maximum age at which a delivery may put bytes on the wire.
pub const DELIVERY_WINDOW: Duration = Duration::from_secs(30);

/// Heartbeat classification derived from a verdict report.
/// Only report classification can authorize a neutral session-reset log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome(OutcomeKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeKind {
    Code(u8),
    SessionReset,
}

impl Outcome {
    /// An ordinary code, including observation errors and testing overrides.
    /// This constructor never authorizes a neutral log.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        Self(OutcomeKind::Code(code))
    }

    /// Health exit code for the observation.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self.0 {
            OutcomeKind::Code(code) => code,
            OutcomeKind::SessionReset => 3,
        }
    }
}

impl From<&Report> for Outcome {
    fn from(report: &Report) -> Self {
        if report.session_only_reset() {
            Self(OutcomeKind::SessionReset)
        } else {
            Self::from_code(report.verdict.exit_code())
        }
    }
}

/// A completed scheduler iteration with its independent fresh check result.
#[derive(Debug, Clone, Copy)]
pub struct CompleteIteration {
    /// Monotonic check start: the oldest observation used by the verdict.
    pub at: MonoTime,
    /// A fresh staged check ran for this iteration, without cached stages.
    pub full_fresh_check: bool,
    /// Classification from the complete report, or an ordinary error code.
    pub outcome: Outcome,
}

/// Closed skip reasons; no endpoint or secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// No complete iteration exists.
    NoIteration,
    /// The iteration did not run a fresh check.
    NotFresh,
    /// No sender may report the supervisor as absent, or an unknown code.
    InvalidCode,
    /// Healthy-only reporting suppresses failures.
    NotHealthy,
    /// The interval since the previous attempt has not elapsed.
    Interval,
    /// The verdict is in the future, too old, or its delivery window has ended.
    Stale,
}

/// Work authorized by a complete iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Send a neutral `/log` POST with [`SESSION_RESET_LOG_BODY`]; never a status ping.
    Log {
        /// Absolute monotonic sender deadline.
        deadline: MonoTime,
    },
    /// Append the suffix and attempt sending before the sender deadline; arrival is not guaranteed.
    Send {
        /// Empty for healthy-only; `/0` through `/4` for status reporting.
        url_suffix: String,
        /// Absolute monotonic sender deadline; best-effort staleness bound, not network delivery.
        deadline: MonoTime,
    },
    /// Do not spawn a delivery child.
    Skip(SkipReason),
}

/// Value-free body for a neutral client-session reset ping.
pub const SESSION_RESET_LOG_BODY: &str = "code=3 reason=ClientSessionsReset\n";

/// Decide without clock access or I/O. Last send means last attempt, including
/// failures: retries belong to that attempt and cannot reset this interval.
#[must_use]
pub fn decide(
    settings: &HeartbeatSettings,
    now: MonoTime,
    iteration: Option<CompleteIteration>,
    last_send: Option<MonoTime>,
) -> Decision {
    let Some(iteration) = iteration else {
        return Decision::Skip(SkipReason::NoIteration);
    };
    if !iteration.full_fresh_check {
        return Decision::Skip(SkipReason::NotFresh);
    }
    if iteration.outcome.code() > 4 {
        return Decision::Skip(SkipReason::InvalidCode);
    }
    if settings.report == HeartbeatReport::OkOnly && iteration.outcome.code() != 0 {
        return Decision::Skip(SkipReason::NotHealthy);
    }
    let interval = settings.interval.duration().unwrap_or(Duration::MAX);
    let deadline = iteration.at.after(DELIVERY_WINDOW.min(interval));
    if now < iteration.at || now >= deadline {
        return Decision::Skip(SkipReason::Stale);
    }
    if last_send.is_some_and(|last| now < last || now.elapsed_since(last) < interval) {
        return Decision::Skip(SkipReason::Interval);
    }
    if iteration.outcome.0 == OutcomeKind::SessionReset {
        return Decision::Log { deadline };
    }
    Decision::Send {
        url_suffix: match settings.report {
            HeartbeatReport::OkOnly => String::new(),
            HeartbeatReport::StatusCode => format!("/{}", iteration.outcome.code()),
        },
        deadline,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn settings(report: HeartbeatReport, interval: u64) -> HeartbeatSettings {
        serde_json::from_value(serde_json::json!({"kind":"healthchecks", "url_ref":"check", "interval":format!("{interval}s"), "report":report})).unwrap()
    }
    fn at(seconds: u64) -> MonoTime {
        MonoTime(Duration::from_secs(seconds))
    }
    fn reset_report() -> Report {
        Report {
            verdict: crate::verdict::v2::Verdict::Degraded(
                crate::verdict::v2::Degraded::ClientSessionsReset,
            ),
            warnings: vec![],
            at: 100,
            config_version: 1,
        }
    }
    #[test]
    fn table() {
        for report in [HeartbeatReport::OkOnly, HeartbeatReport::StatusCode] {
            for code in 0..=6 {
                let cfg = settings(report, 60);
                let iteration = Some(CompleteIteration {
                    at: at(100),
                    full_fresh_check: true,
                    outcome: Outcome::from_code(code),
                });
                let actual = decide(&cfg, at(100), iteration, None);
                let expected = if code > 4 {
                    Decision::Skip(SkipReason::InvalidCode)
                } else if report == HeartbeatReport::OkOnly && code != 0 {
                    Decision::Skip(SkipReason::NotHealthy)
                } else {
                    Decision::Send {
                        url_suffix: if report == HeartbeatReport::StatusCode {
                            format!("/{code}")
                        } else {
                            String::new()
                        },
                        deadline: at(130),
                    }
                };
                assert_eq!(actual, expected);
            }
        }
        let cfg = settings(HeartbeatReport::StatusCode, 60);
        let iteration = Some(CompleteIteration {
            at: at(100),
            full_fresh_check: true,
            outcome: Outcome::from_code(0),
        });
        for (now, last, expected) in [
            (100, None, None),
            (129, None, None),
            (99, None, Some(SkipReason::Stale)),
            (130, None, Some(SkipReason::Stale)),
            (100, Some(41), Some(SkipReason::Interval)),
            (100, Some(40), None),
            (100, Some(101), Some(SkipReason::Interval)),
        ] {
            let result = decide(&cfg, at(now), iteration, last.map(at));
            assert_eq!(matches!(result, Decision::Send { .. }), expected.is_none());
            if let Some(reason) = expected {
                assert_eq!(result, Decision::Skip(reason));
            }
        }
        assert_eq!(
            decide(&cfg, at(100), None, None),
            Decision::Skip(SkipReason::NoIteration)
        );
        assert_eq!(
            decide(
                &cfg,
                at(100),
                Some(CompleteIteration {
                    full_fresh_check: false,
                    at: at(100),
                    outcome: Outcome::from_code(0),
                }),
                None
            ),
            Decision::Skip(SkipReason::NotFresh)
        );
        assert_eq!(
            decide(
                &settings(HeartbeatReport::OkOnly, 5),
                at(106),
                iteration,
                None
            ),
            Decision::Skip(SkipReason::Stale)
        );
    }
    #[test]
    fn session_reset_decision_table() {
        use crate::{
            config::ExitId,
            verdict::v2::{Degraded, FailClosed, NonEmpty, Report, Verdict, Violation, Warning},
        };
        let cases = [
            Verdict::Protected {
                exit: ExitId("exit".into()),
                exit_ip: "203.0.113.1".parse().unwrap(),
            },
            Verdict::Degraded(Degraded::ClientSessionsReset),
            Verdict::Degraded(Degraded::ClientSessionsUnknown),
            Verdict::Degraded(Degraded::ClientSessionTelemetryUnknown),
            Verdict::Degraded(Degraded::ForwardingDisabled),
            Verdict::Unprotected(NonEmpty::new(Violation::RulesetMissing)),
            Verdict::FailClosed(FailClosed::NoHealthyExit),
        ];
        for mode in [HeartbeatReport::OkOnly, HeartbeatReport::StatusCode] {
            for verdict in &cases {
                for warnings in [
                    vec![],
                    vec![Warning::ClientHandshakesStale],
                    vec![Warning::DaemonDead],
                    vec![Warning::DaemonStale],
                    vec![Warning::HardeningSysctl(
                        "net.ipv4.conf.all.accept_redirects".into(),
                    )],
                    vec![Warning::RepairSuppressed(
                        crate::verdict::v2::RepairKind::SafetyDrift,
                    )],
                    vec![Warning::ClientHandshakesStale, Warning::DaemonDead],
                ] {
                    let report = Report {
                        verdict: verdict.clone(),
                        warnings,
                        at: 100,
                        config_version: 1,
                    };
                    let code = verdict.exit_code();
                    let actual = decide(
                        &settings(mode, 60),
                        at(100),
                        Some(CompleteIteration {
                            at: at(100),
                            full_fresh_check: true,
                            outcome: Outcome::from(&report),
                        }),
                        None,
                    );
                    let reset = matches!(verdict, Verdict::Degraded(Degraded::ClientSessionsReset))
                        && report
                            .warnings
                            .iter()
                            .all(|warning| matches!(warning, Warning::ClientHandshakesStale));
                    let expected = if mode == HeartbeatReport::OkOnly && code != 0 {
                        Decision::Skip(SkipReason::NotHealthy)
                    } else if reset {
                        Decision::Log { deadline: at(130) }
                    } else {
                        Decision::Send {
                            url_suffix: if mode == HeartbeatReport::StatusCode {
                                format!("/{code}")
                            } else {
                                String::new()
                            },
                            deadline: at(130),
                        }
                    };
                    assert_eq!(actual, expected, "{mode:?} {report:?}");
                }
            }
            // Ordinary codes (including observation errors and overrides)
            // never authorize a log, even for code 3.
            for code in 0..=6 {
                let iteration = Some(CompleteIteration {
                    at: at(100),
                    full_fresh_check: true,
                    outcome: Outcome::from_code(code),
                });
                assert!(!matches!(
                    decide(&settings(mode, 60), at(100), iteration, None),
                    Decision::Log { .. }
                ));
            }
        }
    }

    #[test]
    fn session_reset_retains_freshness_and_interval_gates() {
        let cfg = settings(HeartbeatReport::StatusCode, 60);
        let iteration = CompleteIteration {
            at: at(100),
            full_fresh_check: true,
            outcome: Outcome::from(&reset_report()),
        };
        assert_eq!(
            decide(&cfg, at(100), Some(iteration), Some(at(41))),
            Decision::Skip(SkipReason::Interval)
        );
        assert_eq!(
            decide(&cfg, at(130), Some(iteration), None),
            Decision::Skip(SkipReason::Stale)
        );
        assert_eq!(
            decide(
                &cfg,
                at(100),
                Some(CompleteIteration {
                    full_fresh_check: false,
                    ..iteration
                }),
                None
            ),
            Decision::Skip(SkipReason::NotFresh)
        );
        // Log decisions carry no success/failure suffix at all.
        assert!(matches!(
            decide(&cfg, at(100), Some(iteration), None),
            Decision::Log { .. }
        ));
    }

    #[test]
    fn interval_bounds_deadline_without_an_extra_age_gate() {
        let iteration = Some(CompleteIteration {
            at: at(100),
            full_fresh_check: true,
            outcome: Outcome::from_code(0),
        });
        let cfg = settings(HeartbeatReport::OkOnly, 10);
        assert_eq!(
            decide(&cfg, at(106), iteration, None),
            Decision::Send {
                url_suffix: String::new(),
                deadline: at(110)
            }
        );
        assert_eq!(
            decide(&cfg, at(110), iteration, None),
            Decision::Skip(SkipReason::Stale)
        );
    }
    proptest::proptest! {
        #[test]
        fn never_five_or_late(code in 0u8..=255, age in 0u64..120, elapsed in 0u64..120) {
            let cfg = settings(HeartbeatReport::StatusCode, 60);
            let result = decide(&cfg, at(200 + age), Some(CompleteIteration { at: at(200), full_fresh_check: true, outcome: Outcome::from_code(code) }), Some(at(200 + age - elapsed)));
            if let Decision::Send { url_suffix, deadline } = result {
                proptest::prop_assert!(code <= 4);
                proptest::prop_assert_ne!(url_suffix, "/5");
                proptest::prop_assert!(at(200 + age) < deadline);
                proptest::prop_assert!(elapsed >= 60);
            }
        }
    }
}
