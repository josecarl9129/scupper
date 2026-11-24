//! Clock-independent image detach retry policy. Every attempt is journaled by IO.
use std::time::Duration;

#[derive(Clone, Copy)]
pub(super) struct Outcome {
    pub success: bool,
    pub busy: bool,
}
pub(super) trait Io {
    fn elapsed(&self) -> Duration;
    fn pause(&mut self, delay: Duration);
    fn attempt(&mut self, force: bool, budget: Duration) -> Outcome;
}
/// Plain detach retries busy failures for 30 seconds. Force is allowed only
/// afterward (or after a non-busy terminal error), with an initial try plus at
/// most three retries in a separate five-second budget, bounded by restore.
pub(super) fn run(io: &mut impl Io, available: Duration) -> bool {
    let start = io.elapsed();
    let plain_end = start + available.min(Duration::from_secs(30));
    let mut delay = Duration::from_millis(250);
    loop {
        let remaining = plain_end.saturating_sub(io.elapsed());
        if remaining.is_zero() {
            break;
        }
        let result = io.attempt(false, remaining);
        if result.success {
            return true;
        }
        if !result.busy {
            break;
        }
        io.pause(delay.min(plain_end.saturating_sub(io.elapsed())));
        delay = (delay * 2).min(Duration::from_secs(4));
    }
    let force_end = (io.elapsed() + Duration::from_secs(5)).min(start + available);
    for retry in 0..=3 {
        if retry != 0 {
            io.pause(
                Duration::from_millis(250 * (1 << (retry - 1)))
                    .min(force_end.saturating_sub(io.elapsed())),
            );
        }
        let remaining = force_end.saturating_sub(io.elapsed());
        if remaining.is_zero() {
            break;
        }
        if io.attempt(true, remaining).success {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        now: Duration,
        calls: Vec<(bool, Duration)>,
        success_at: Option<Duration>,
        busy: bool,
    }
    impl Io for Fake {
        fn elapsed(&self) -> Duration {
            self.now
        }
        fn pause(&mut self, d: Duration) {
            self.now += d;
        }
        fn attempt(&mut self, force: bool, _: Duration) -> Outcome {
            self.calls.push((force, self.now));
            Outcome {
                success: self.success_at.is_some_and(|t| self.now >= t),
                busy: self.busy,
            }
        }
    }
    #[test]
    fn busy_gets_full_thirty_seconds_before_force_and_all_attempts_are_recorded() {
        let mut f = Fake {
            now: Duration::ZERO,
            calls: vec![],
            success_at: None,
            busy: true,
        };
        assert!(!run(&mut f, Duration::from_secs(40)));
        let force: Vec<_> = f.calls.iter().filter(|(force, _)| *force).collect();
        assert_eq!(force.len(), 4);
        assert_eq!(force[0].1, Duration::from_secs(30));
        assert!(force.iter().all(|(_, t)| *t <= Duration::from_secs(35)));
        let times: Vec<_> = f
            .calls
            .iter()
            .filter(|(force, _)| !force)
            .map(|(_, t)| t.as_millis())
            .collect();
        assert_eq!(
            times,
            [
                0, 250, 750, 1750, 3750, 7750, 11750, 15750, 19750, 23750, 27750
            ]
        );
    }
    #[test]
    fn late_plain_success_avoids_force() {
        let mut f = Fake {
            now: Duration::ZERO,
            calls: vec![],
            success_at: Some(Duration::from_secs(26)),
            busy: true,
        };
        assert!(run(&mut f, Duration::from_secs(40)));
        assert!(f.calls.iter().all(|(force, _)| !force));
        assert!(f.now >= Duration::from_secs(26));
    }
    #[test]
    fn exhausted_restore_budget_stops_without_unbounded_retry() {
        let mut f = Fake {
            now: Duration::ZERO,
            calls: vec![],
            success_at: None,
            busy: true,
        };
        assert!(!run(&mut f, Duration::from_secs(2)));
        assert_eq!(f.now, Duration::from_secs(2));
        assert!(f.calls.iter().all(|(force, _)| !force));
    }
}
