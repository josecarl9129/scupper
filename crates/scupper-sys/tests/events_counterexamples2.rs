//! Re-review counterexamples for the 2m fix round. Requires `--features testing`.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
use scupper_proto::{Actor, EventKind, GatewayId, UnixSeconds};
use scupper_sys::events::{EventIoStep, EventLog, LogHandle, OpenedLog};
use std::{
    fs, io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("event-fix-counterexamples")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(path.join("events")).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn gateway() -> GatewayId {
    GatewayId("home".into())
}
fn emit(handle: &LogHandle) -> u64 {
    handle
        .emit(EventKind::Flapping {}, Actor::Daemon, None)
        .unwrap()
}
fn wait_for(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < Duration::from_secs(5), "timed out");
        thread::sleep(Duration::from_millis(1));
    }
}

/// One process lifetime in which no append ever succeeds (ENOSPC, EROFS, EIO),
/// ending in a restart. Returns the greatest seq that `emit` handed out.
fn outage_run(dir: &TempDir) -> u64 {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |step| {
            if step == EventIoStep::Write {
                observed.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("ENOSPC"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    let mut greatest = emit(&handle); // a clean start has no gap record to write
    wait_for(|| calls.load(Ordering::SeqCst) > 0);
    greatest = greatest.max((0..5).map(|_| emit(&handle)).max().unwrap());
    drop(log); // Ordinary restart during the outage: no clean marker is written.
    greatest
}

// N1: the unclean jump is relative to durable state only. If the run that
// started unclean never made anything durable (the outage the jump exists for),
// the next open recomputes the same base and hands out the same seqs again.
// Open-without-marker is the norm after any unclean stop, so two consecutive
// restarts during one outage are enough; no crash is needed.
#[test]
fn n1_seqs_from_an_unclean_started_outage_run_are_reused() {
    let dir = TempDir::new(); // no clean marker: previous stop was unclean
    let first = outage_run(&dir);
    let second = outage_run(&dir);
    assert!(
        second > first,
        "seq reuse across restarts: run 1 handed out up to {first}, run 2 up to {second}"
    );
}

// N1, crash variant: a clean previous stop, then two crashes during one outage.
#[test]
fn n1_reuse_after_clean_then_two_outage_restarts() {
    let dir = TempDir::new();
    fs::write(dir.0.join("events/clean"), b"clean\n").unwrap();
    let _first = outage_run(&dir); // clean start: 1..; jump protects these
    let second = outage_run(&dir); // unclean start: 2^24..
    let third = outage_run(&dir); // unclean start again: 2^24.. again
    assert!(third > second, "run 2 up to {second}, run 3 up to {third}");
}
