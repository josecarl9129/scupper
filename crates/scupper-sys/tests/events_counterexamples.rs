//! Review A counterexamples for the event log. Fault hooks require `testing`.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
use scupper_proto::{Actor, Event, EventKind, GatewayId, Reason, UnixSeconds};
use scupper_sys::events::{EventIoStep, EventLog, LogHandle, OpenedLog, read_since};
use std::{
    fs, io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
            .join("event-counterexamples")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(path.join("events")).unwrap();
        // These counterexamples start from an empty, previously clean log.
        fs::write(path.join("events/clean"), b"clean\n").unwrap();
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
fn open(dir: &TempDir, at: u64) -> (EventLog, LogHandle) {
    let OpenedLog { log, handle, .. } =
        EventLog::open(&dir.0, gateway(), move || UnixSeconds(at)).unwrap();
    (log, handle)
}
fn flush(handle: &LogHandle) {
    handle.flush_blocking(Duration::from_secs(5)).unwrap();
}
fn wait_for(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "condition timed out"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

// F1: failed fsync must not expose a line to cursor consumers, and losing that
// line in a subsequent power loss must not reuse its assigned sequence.
#[test]
fn f1_unsynced_line_reaches_reader_then_seq_is_reused() {
    let dir = TempDir::new();
    let fail = Arc::new(AtomicBool::new(true));
    let hook_fail = fail.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(1_735_689_600),
        16,
        move |step| {
            if hook_fail.load(Ordering::SeqCst)
                && matches!(step, EventIoStep::FileSync | EventIoStep::Checkpoint)
            {
                Err(io::Error::other("injected EIO"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    let first = handle
        .emit(
            EventKind::FailClosedStarted {
                reason: Reason::NoHealthyExit,
                exit: None,
            },
            Actor::Daemon,
            Some(1),
        )
        .unwrap();
    assert_eq!(first, 1);
    wait_for(|| read_since(&dir.0, 0, None).any(|e| e.is_ok_and(|e| e.seq == 1)));
    assert_eq!(handle.committed_seq(), 0);
    assert_eq!(
        read_since(&dir.0, 0, Some(handle.committed_seq())).count(),
        0
    );
    let sink_cursor = first;
    drop(log);
    fs::write(dir.0.join("events/2025-01.jsonl"), b"").unwrap();
    let (_log, handle) = open(&dir, 1_735_689_600);
    let assigned = handle
        .emit(EventKind::Flapping {}, Actor::Daemon, Some(1))
        .unwrap();
    flush(&handle);
    assert!(assigned > first);
    assert!(
        read_since(&dir.0, sink_cursor, Some(handle.committed_seq())).count() > 0,
        "seq {assigned} reused; cursor at {sink_cursor} skips it"
    );
}

// F2: high-water must not be rewritten every second while idle.
#[test]
fn f2_idle_writer_does_not_checkpoint_every_second() {
    let dir = TempDir::new();
    let checkpoints = Arc::new(AtomicUsize::new(0));
    let counter = checkpoints.clone();
    let OpenedLog {
        log: _log, handle, ..
    } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(1_735_689_600),
        16,
        move |step| {
            if step == EventIoStep::Checkpoint {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        },
    )
    .unwrap();
    let _ = handle
        .emit(EventKind::Flapping {}, Actor::Daemon, None)
        .unwrap();
    flush(&handle);
    let before = checkpoints.load(Ordering::SeqCst);
    thread::sleep(Duration::from_millis(3_500));
    let idle = checkpoints.load(Ordering::SeqCst) - before;
    assert_eq!(
        idle, 0,
        "{idle} durable checkpoints in 3.5 s with nothing emitted"
    );
}

// F3: rollback to a binary unaware of a newer event kind must still open.
#[test]
fn f3_open_tolerates_unknown_kind_from_newer_release() {
    let dir = TempDir::new();
    fs::write(
        dir.0.join("events/2025-01.jsonl"),
        b"{\"seq\":7,\"at\":1735689600,\"kind\":\"AlertDelivered\",\"data\":{},\
\"actor\":\"Daemon\",\"gateway\":\"home\",\"config_version\":null}\n",
    )
    .unwrap();
    let OpenedLog {
        log: _log,
        handle,
        warnings,
    } = EventLog::open(&dir.0, gateway(), || UnixSeconds(1_735_689_600)).unwrap();
    assert_eq!(warnings, []);
    assert_eq!(
        handle
            .emit(EventKind::Flapping {}, Actor::Daemon, None)
            .unwrap(),
        8
    );
}

// F4: append-directory sync is required only for creation (including retry).
#[test]
fn f4_directory_sync_only_on_create_or_retry() {
    let dir = TempDir::new();
    let syncs = Arc::new(AtomicUsize::new(0));
    let counter = syncs.clone();
    let OpenedLog {
        log: _log, handle, ..
    } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(1_735_689_600),
        16,
        move |step| {
            if step == EventIoStep::DirectorySync {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        },
    )
    .unwrap();
    for _ in 0..5 {
        let _ = handle
            .emit(EventKind::Flapping {}, Actor::Daemon, None)
            .unwrap();
    }
    flush(&handle);
    assert_eq!(syncs.load(Ordering::SeqCst), 1);
}

// F5: trigger retention through the public writer: emit in October, but let
// the retention clock see November. The newest written month must survive even
// when it alone exceeds the cap. Sparse data keeps the fixture small.
#[test]
fn f5_retention_keeps_newest_written_month() {
    let dir = TempDir::new();
    let calls = AtomicUsize::new(0);
    let OpenedLog {
        log: _log, handle, ..
    } = EventLog::open(&dir.0, gateway(), move || {
        UnixSeconds(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            1_793_491_199
        } else {
            1_793_491_200
        })
    })
    .unwrap();
    let events = dir.0.join("events");
    fs::write(events.join("2026-09.jsonl"), vec![b'x'; 10]).unwrap();
    fs::File::create(events.join("2026-10.jsonl"))
        .unwrap()
        .set_len(100_000_001)
        .unwrap();
    let _ = handle
        .emit(EventKind::Flapping {}, Actor::Daemon, None)
        .unwrap();
    flush(&handle);
    assert!(
        events.join("2026-10.jsonl").exists(),
        "newest month deleted"
    );
    assert!(!events.join("2026-09.jsonl").exists());
}

// F6: a destination domain/IP must not deserialize as an operational ID.
#[test]
fn f6_event_exit_ids_are_validated() {
    let line = r#"{"seq":1,"at":1,"kind":"Failback","data":{"from":"tracker.example.com","to":"203.0.113.9"},"actor":"Daemon","gateway":"home","config_version":null}"#;
    assert!(serde_json::from_str::<Event>(line).is_err());
}
