//! Monotonic watchdog accounting across live daemon intervals.
use super::{Duration, Instant, Result, fail};

#[derive(Default)]
pub(super) struct Watchdog {
    last: Option<Instant>,
    paused: bool,
    pub max_gap: Duration,
    failed: bool,
    boundaries: Vec<(&'static str, bool)>,
}
impl Watchdog {
    pub fn ready(&mut self, now: Instant) {
        if !self.paused && self.last.is_none() {
            self.last = Some(now);
        }
    }
    pub fn observe(&mut self, now: Instant, notification: bool) {
        if !self.paused {
            if let Some(last) = self.last {
                let gap = now.saturating_duration_since(last);
                self.max_gap = self.max_gap.max(gap);
                self.failed |= gap >= Duration::from_secs(30);
            }
            if notification {
                self.last = Some(now);
            }
        }
    }
    pub fn boundary(&mut self, now: Instant, paused: bool, reason: &'static str) {
        self.observe(now, false);
        self.paused = paused;
        self.last = None;
        self.boundaries.push((reason, paused));
    }
    pub fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"max_gap_ms":self.max_gap.as_millis(), "failed":self.failed,
            "boundaries":self.boundaries})
    }
    pub fn check(&self) -> Result<()> {
        if self.failed {
            return fail(format!(
                "daemon WATCHDOG=1 gap >= 30 s (observed {} ms)",
                self.max_gap.as_millis()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn exact_threshold_and_trailing_silence_fail_even_after_recovery() {
        for notification in [false, true] {
            let now = Instant::now();
            let mut clock = Watchdog::default();
            clock.observe(now, true);
            clock.observe(now + Duration::from_millis(29_999), false);
            clock.check().unwrap();
            clock.observe(now + Duration::from_secs(30), notification);
            assert!(clock.check().is_err());
            clock.observe(now + Duration::from_secs(31), true);
            assert!(clock.check().is_err());
        }
    }
    #[test]
    fn ready_arms_silence_detection_without_masking_missing_watchdogs() {
        let now = Instant::now();
        let mut clock = Watchdog::default();
        clock.ready(now);
        clock.ready(now + Duration::from_secs(29));
        clock.observe(now + Duration::from_secs(30), false);
        assert!(clock.check().is_err());
    }

    #[test]
    fn deliberate_process_stop_is_a_boundary_but_cannot_hide_an_existing_gap() {
        let now = Instant::now();
        let mut clock = Watchdog::default();
        clock.observe(now, true);
        clock.boundary(now + Duration::from_secs(1), true, "SIGKILL");
        clock.observe(now + Duration::from_secs(90), false);
        clock.boundary(now + Duration::from_secs(91), false, "restart");
        clock.observe(now + Duration::from_secs(92), true);
        clock.check().unwrap();
        clock.boundary(now + Duration::from_secs(122), true, "stop");
        assert!(clock.check().is_err());
    }
}
