//! Shared production/test loop. Only the tick owner performs work or notifies.
use crate::reconcile::{Escalation, TickReport};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Work completed by one process iteration, independent of gateway health.
pub struct Iteration {
    /// All bounded work and retry decisions finished before their deadline.
    pub complete: bool,
    /// Value-free status for the service manager.
    pub status: &'static str,
}
/// Dependencies of the actual daemon scheduler, injectable without real namespaces.
pub trait DaemonDeps {
    /// Monotonic cadence clock.
    fn now(&self) -> Instant;
    /// Wait for at most the requested duration.
    fn sleep(&mut self, duration: Duration);
    /// Announce that the main loop is running.
    fn started(&mut self);
    /// Initialize the reconciler factory; refusal leaves the process degraded.
    fn initialize(&mut self);
    /// Finish a current tick; None means no reconciler is available.
    fn tick(&mut self, stop: &AtomicBool) -> Option<TickReport>;
    /// Tighten gates without adopting an invalid handoff.
    fn close_only(&mut self);
    /// Forget child observations from the old namespace generation.
    fn abandon_probes(&mut self);
    /// Execute one already charged boot/rebuild attempt.
    fn rebuild(&mut self);
    /// Per-boot budget root (the production value is /run/scupper).
    fn run_root(&self) -> &std::path::Path;
    /// `CLOCK_BOOTTIME`, including suspend time, injectable for tests.
    fn boot_time(&self) -> Duration;
    /// Log a failed budget publication while keeping the process alive.
    fn budget_error(&mut self, error: &io::Error);
    /// Maintenance outside the safety observation group.
    fn maintenance(&mut self);
    /// Send status and a watchdog only for completed bounded work.
    fn notify(&mut self, iteration: &Iteration);
    /// Release the reconciler and flush audit data; no kernel work is permitted.
    fn shutdown(&mut self);
}
/// Run the same cadence and signal handling with real or fake dependencies.
pub fn run_with(deps: &mut impl DaemonDeps, stop: &AtomicBool) {
    deps.initialize();
    let mut next = deps.now();
    while !stop.load(Ordering::Relaxed) {
        let now = deps.now();
        if now < next {
            deps.sleep((next - now).min(Duration::from_millis(50)));
            continue;
        }
        deps.started();
        let started = deps.now();
        let report = deps.tick(stop);
        let rebuild = report
            .as_ref()
            .is_none_or(|r| r.escalations.contains(&Escalation::RebuildRequired));
        if report
            .as_ref()
            .is_some_and(|r| r.escalations.contains(&Escalation::ReinitializeRequired))
            && !stop.load(Ordering::Relaxed)
        {
            deps.abandon_probes();
            deps.initialize();
        }
        if rebuild && !stop.load(Ordering::Relaxed) {
            deps.abandon_probes();
            if report.is_none() {
                deps.close_only();
            }
            match reserve_boot(deps.run_root(), deps.boot_time()) {
                Ok(true) => deps.rebuild(),
                Ok(false) => {}
                Err(error) => deps.budget_error(&error),
            }
        }
        deps.maintenance();
        let iteration = Iteration {
            complete: (rebuild || report.as_ref().is_some_and(|r| r.complete))
                && deps.now().saturating_duration_since(started) < Duration::from_secs(20),
            status: if rebuild {
                "closed; boot retry pending"
            } else {
                "reconciling"
            },
        };
        deps.notify(&iteration);
        next = (next + Duration::from_secs(2)).max(deps.now());
    }
    deps.shutdown();
}

/// Charge boot attempts before execution using boot-relative monotonic times.
/// The file lives on /run and survives process restarts within a boot.
///
/// # Errors
/// Any unreadable/corrupt budget or failed publication refuses the attempt.
pub fn reserve_boot(root: &std::path::Path, now: Duration) -> io::Result<bool> {
    use crate::{
        fs::{Fs, RealFs},
        lock::WriterLock,
    };
    use std::io::Write;
    let _guard = WriterLock::acquire_timeout(root, Duration::from_millis(100))?;
    let path = root.join("boot-attempts");
    let mut times: Vec<Duration> = match RealFs.read(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(io::Error::other)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    if times.iter().any(|at| *at > now) {
        return Err(io::Error::other("boot budget clock moved backwards"));
    }
    times.retain(|at| now.saturating_sub(*at) < Duration::from_secs(600));
    if times.len() >= 3
        || times
            .last()
            .is_some_and(|at| now.saturating_sub(*at) < Duration::from_secs(60))
    {
        return Ok(false);
    }
    times.push(now);
    let (temp, mut file) = RealFs.create_temp(root)?;
    let result = (|| {
        file.write_all(&serde_json::to_vec(&times).map_err(io::Error::other)?)?;
        file.sync_all()?;
        RealFs.rename(&temp, &path)?;
        RealFs.sync_dir(root)
    })();
    let _ = RealFs.remove(&temp);
    result.map(|()| true)
}
