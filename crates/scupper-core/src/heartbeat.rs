//! Pure external heartbeat eligibility; all times come from the caller.
use crate::{
    config::{HeartbeatReport, HeartbeatSettings},
    failover::MonoTime,
};
use std::time::Duration;

/// Maximum age at which a delivery may put bytes on the wire.
pub const DELIVERY_WINDOW: Duration = Duration::from_secs(30);

/// A completed scheduler iteration with its independent fresh check result.
#[derive(Debug, Clone, Copy)]
pub struct CompleteIteration {
    /// Monotonic verdict time, not the time the delivery was queued.
    pub at: MonoTime,
    /// A fresh staged check ran for this iteration, without cached stages.
    pub full_fresh_check: bool,
    /// Health exit code, including observation errors.
    pub code: u8,
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
    /// Append the suffix to the secret URL and deliver before the deadline.
    Send {
        /// Empty for healthy-only; `/0` through `/4` for status reporting.
        url_suffix: String,
        /// Absolute monotonic deadline derived from the verdict.
        deadline: MonoTime,
    },
    /// Do not spawn a delivery child.
    Skip(SkipReason),
}

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
    if iteration.code > 4 {
        return Decision::Skip(SkipReason::InvalidCode);
    }
    if settings.report == HeartbeatReport::OkOnly && iteration.code != 0 {
        return Decision::Skip(SkipReason::NotHealthy);
    }
    let interval = settings.interval.duration().unwrap_or(Duration::MAX);
    let deadline = iteration.at.after(DELIVERY_WINDOW);
    if now < iteration.at || now >= deadline || now.elapsed_since(iteration.at) > interval {
        return Decision::Skip(SkipReason::Stale);
    }
    if last_send.is_some_and(|last| now < last || now.elapsed_since(last) < interval) {
        return Decision::Skip(SkipReason::Interval);
    }
    Decision::Send {
        url_suffix: match settings.report {
            HeartbeatReport::OkOnly => String::new(),
            HeartbeatReport::StatusCode => format!("/{}", iteration.code),
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
    #[test]
    fn table() {
        for report in [HeartbeatReport::OkOnly, HeartbeatReport::StatusCode] {
            for code in 0..=6 {
                let cfg = settings(report, 60);
                let iteration = Some(CompleteIteration {
                    at: at(100),
                    full_fresh_check: true,
                    code,
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
            code: 0,
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
                    code: 0,
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
    proptest::proptest! {
        #[test]
        fn never_five_or_late(code in 0u8..=255, age in 0u64..120, elapsed in 0u64..120) {
            let cfg = settings(HeartbeatReport::StatusCode, 60);
            let result = decide(&cfg, at(200 + age), Some(CompleteIteration { at: at(200), full_fresh_check: true, code }), Some(at(200 + age - elapsed)));
            if let Decision::Send { url_suffix, deadline } = result {
                proptest::prop_assert!(code <= 4);
                proptest::prop_assert_ne!(url_suffix, "/5");
                proptest::prop_assert!(at(200 + age) < deadline);
                proptest::prop_assert!(elapsed >= 60);
            }
        }
    }
}
