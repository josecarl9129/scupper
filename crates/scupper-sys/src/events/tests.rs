#![allow(clippy::unwrap_used)]
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("event-tests");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("events")).unwrap();
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
fn emit(handle: &LogHandle) -> u64 {
    handle
        .emit(EventKind::Flapping {}, Actor::Daemon, Some(1))
        .unwrap()
}
fn flush(handle: &LogHandle) {
    handle.flush_blocking(Duration::from_secs(5)).unwrap();
}
fn records(dir: &TempDir) -> Vec<Event> {
    read_since(&dir.0, 0, None)
        .collect::<io::Result<Vec<_>>>()
        .unwrap()
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
#[test]
fn restart_with_and_without_highwater_and_torn_line() {
    for highwater in [false, true] {
        let dir = TempDir::new();
        let (log, handle) = open(&dir, 1_735_689_600); // 2025-01-01
        for n in 1..=103 {
            assert_eq!(emit(&handle), n);
        }
        flush(&handle);
        assert_eq!(
            fs::read_to_string(dir.0.join("events/seq")).unwrap(),
            "103\n"
        );
        drop(log);
        if !highwater {
            fs::remove_file(dir.0.join("events/seq")).unwrap();
        }
        let path = dir.0.join("events/2025-01.jsonl");
        let original = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"seq\":104")
            .unwrap();
        assert_eq!(records(&dir).len(), 103);
        let (log, handle) = open(&dir, 1_735_689_600);
        assert_eq!(emit(&handle), 105); // recovery note is 104
        flush(&handle);
        let events = records(&dir);
        assert_eq!(events.len(), 105);
        assert!(matches!(
            events[103].kind,
            EventKind::Boot {
                result: Outcome::Recovered,
                step: StepKind::EventLog
            }
        ));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
        );
        assert!(fs::metadata(path).unwrap().len() > original);
        drop(log);
    }
}
#[test]
fn highwater_is_maximum_and_checkpoint_every_hundred() {
    let dir = TempDir::new();
    let (log, handle) = open(&dir, 0);
    for _ in 0..100 {
        emit(&handle);
    }
    wait_for(|| {
        fs::read_to_string(dir.0.join("events/seq"))
            .is_ok_and(|text| text.trim().parse::<u64>().is_ok_and(|n| n >= 100))
    });
    drop(log);
    fs::write(dir.0.join("events/seq"), b"500\n").unwrap();
    let (log, handle) = open(&dir, 0);
    assert_eq!(emit(&handle), 502);
    flush(&handle);
    assert!(records(&dir).iter().any(|event| matches!(
        event.kind,
        EventKind::EventGap {
            dropped: 400,
            first_seq: 101,
            last_seq: 500,
            ..
        }
    )));
    drop(log);
}
#[test]
fn month_rollover_reader_cursor_and_permissions() {
    let dir = TempDir::new();
    let at = Arc::new(AtomicU64::new(1_738_367_999)); // Jan 31 2025 23:59:59
    let clock = at.clone();
    let OpenedLog { log, handle, .. } = EventLog::open(&dir.0, gateway(), move || {
        UnixSeconds(clock.load(Ordering::Relaxed))
    })
    .unwrap();
    assert_eq!(emit(&handle), 1);
    flush(&handle);
    at.store(1_738_368_000, Ordering::Relaxed);
    assert_eq!(emit(&handle), 2);
    flush(&handle);
    for month in ["2025-01", "2025-02"] {
        assert_eq!(
            fs::metadata(dir.0.join(format!("events/{month}.jsonl")))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }
    assert_eq!(
        read_since(&dir.0, 1, Some(handle.committed_seq()))
            .map(|r| r.unwrap().seq)
            .collect::<Vec<_>>(),
        [2]
    );
    assert_eq!(month_name(UnixSeconds(0)), "1970-01.jsonl");
    assert_eq!(month_name(UnixSeconds(951_782_400)), "2000-02.jsonl");
    assert_eq!(month_name(UnixSeconds(4_107_542_400)), "2100-03.jsonl");
    drop(log);
}
#[test]
fn retention_count_size_and_never_current_month() {
    let dir = TempDir::new();
    let events = dir.0.join("events");
    fs::create_dir_all(&events).unwrap();
    for year in 2023..=2024 {
        for month in 1..=12 {
            fs::write(events.join(format!("{year}-{month:02}.jsonl")), b"\n").unwrap();
        }
    }
    retain(&events, "2024-01.jsonl", MAX_MONTHS, MAX_SIZE).unwrap();
    let files = monthly_files(&events).unwrap();
    assert_eq!(files.len(), 13);
    assert!(events.join("2024-01.jsonl").exists());
    // Sparse historical files exercise the real 100 MB cap without large fixtures.
    OpenOptions::new()
        .write(true)
        .open(events.join("2024-02.jsonl"))
        .unwrap()
        .set_len(MAX_SIZE)
        .unwrap();
    retain(&events, "2024-01.jsonl", MAX_MONTHS, MAX_SIZE).unwrap();
    assert!(!events.join("2024-02.jsonl").exists());
    assert!(events.join("2024-01.jsonl").exists());
    OpenOptions::new()
        .write(true)
        .open(events.join("2024-01.jsonl"))
        .unwrap()
        .set_len(MAX_SIZE + 1)
        .unwrap();
    retain(&events, "2024-01.jsonl", MAX_MONTHS, MAX_SIZE).unwrap();
    assert_eq!(monthly_files(&events).unwrap().len(), 2);
    assert!(events.join("2024-12.jsonl").exists());
}
#[test]
fn write_and_sync_failures_retry_without_duplicates() {
    for step in [
        EventIoStep::Write,
        EventIoStep::FileSync,
        EventIoStep::DirectorySync,
        EventIoStep::Checkpoint,
    ] {
        let dir = TempDir::new();
        let failed = Arc::new(AtomicBool::new(true));
        let observed = Arc::new(AtomicUsize::new(0));
        let fault = failed.clone();
        let calls = observed.clone();
        let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
            &dir.0,
            gateway(),
            || UnixSeconds(0),
            100,
            move |at| {
                if at == step && fault.load(Ordering::Relaxed) {
                    calls.fetch_add(1, Ordering::Relaxed);
                    return Err(io::Error::from_raw_os_error(28)); // ENOSPC
                }
                Ok(())
            },
        )
        .unwrap();
        let start = Instant::now();
        emit(&handle);
        let _ = handle.flush_blocking(Duration::from_millis(20));
        wait_for(|| observed.load(Ordering::Relaxed) != 0);
        for _ in 0..30 {
            emit(&handle);
        }
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(
            handle
                .flush_blocking(Duration::from_millis(20))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        failed.store(false, Ordering::Relaxed);
        flush(&handle);
        let events = records(&dir);
        assert_eq!(events.len(), 32);
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
                .count(),
            1
        );
        assert!(events.windows(2).all(|pair| pair[0].seq + 1 == pair[1].seq));
        drop(log);
    }
}
#[test]
fn overflow_has_one_failure_and_recorded_gap() {
    let dir = TempDir::new();
    let failed = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(AtomicUsize::new(0));
    let fault = failed.clone();
    let observed = calls.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        8,
        move |step| {
            if step == EventIoStep::Write && fault.load(Ordering::Relaxed) {
                observed.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::from_raw_os_error(30)); // EROFS
            }
            Ok(())
        },
    )
    .unwrap();
    emit(&handle);
    wait_for(|| calls.load(Ordering::Relaxed) != 0);
    for _ in 0..100 {
        emit(&handle);
    }
    assert!(handle.dropped() > 0);
    failed.store(false, Ordering::Relaxed);
    flush(&handle);
    let events = records(&dir);
    assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
            .count(),
        1
    );
    let noted: u64 = events
        .iter()
        .filter_map(|event| {
            if let EventKind::EventGap { dropped, .. } = event.kind {
                Some(dropped)
            } else {
                None
            }
        })
        .sum();
    assert_eq!(noted, handle.dropped());
    assert_eq!(events.len() as u64 + noted, events.last().unwrap().seq);
    drop(log);
}
#[test]
fn concurrent_emit_preserves_unique_sequence_and_file_order() {
    let dir = TempDir::new();
    let (log, handle) = open(&dir, 0);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let handle = handle.clone();
            thread::spawn(move || (0..100).map(|_| emit(&handle)).collect::<Vec<_>>())
        })
        .collect();
    let mut assigned: Vec<_> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    assigned.sort_unstable();
    assert_eq!(assigned, (1..=800).collect::<Vec<_>>());
    // 800 fsyncs can exceed the usual small-test deadline on a shared CI disk.
    handle.flush_blocking(Duration::from_secs(30)).unwrap();
    let text = fs::read_to_string(dir.0.join("events/1970-01.jsonl")).unwrap();
    let persisted: Vec<u64> = text
        .lines()
        .map(|line| serde_json::from_str::<Event>(line).unwrap().seq)
        .collect();
    assert_eq!(persisted, assigned);
    drop(log);
}
#[test]
fn exclusive_writer_corruption_and_foreign_gateway_refused() {
    let dir = TempDir::new();
    let (log, handle) = open(&dir, 0);
    assert!(
        matches!(EventLog::open(&dir.0, gateway(), || UnixSeconds(0)),
        Err(OpenError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    emit(&handle);
    flush(&handle);
    drop(log);
    assert!(EventLog::open(&dir.0, GatewayId("other".into()), || UnixSeconds(0)).is_err());
    OpenOptions::new()
        .append(true)
        .open(dir.0.join("events/1970-01.jsonl"))
        .unwrap()
        .write_all(b"invalid\n")
        .unwrap();
    assert!(read_since(&dir.0, 0, None).any(|r| r.is_err()));
    let recovered = EventLog::open(&dir.0, gateway(), || UnixSeconds(0)).unwrap();
    assert_eq!(recovered.warnings.len(), 1);
}

#[test]
fn slow_disk_does_not_hold_the_emit_lock() {
    let dir = TempDir::new();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let seen = entered.clone();
    let resume = release.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        1000,
        move |step| {
            if step == EventIoStep::FileSync && !seen.swap(true, Ordering::Relaxed) {
                while !resume.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(())
        },
    )
    .unwrap();
    emit(&handle);
    wait_for(|| entered.load(Ordering::Relaxed));
    let producer = handle.clone();
    let (done, result) = mpsc::sync_channel(1);
    let producer = thread::spawn(move || {
        for _ in 0..100 {
            emit(&producer);
        }
        done.send(()).unwrap();
    });
    let quick = result.recv_timeout(Duration::from_secs(1)).is_ok();
    // Always release the disk before an assertion can unwind the log owner.
    release.store(true, Ordering::Relaxed);
    producer.join().unwrap();
    assert!(quick);
    flush(&handle);
    assert_eq!(records(&dir).len(), 101);
    drop(log);
}

#[test]
fn evicted_gap_summaries_preserve_the_original_drop_count() {
    let dir = TempDir::new();
    let (log, handle) = open(&dir, 0);
    // Exercise the channel's overflow bookkeeping deterministically, independent
    // of worker scheduling. This queue is never published to the worker.
    let mut queue = Queue {
        seq: 0,
        events: VecDeque::new(),
        gap: Gap::default(),
        dropped: 0,
        failure: false,
        failure_seq: None,
        state: WriterState::Running,
        flushed: None,
        ..Queue::default()
    };
    let shared = Shared {
        queue: Mutex::new(Queue {
            seq: 0,
            events: VecDeque::new(),
            gap: Gap::default(),
            dropped: 0,
            failure: false,
            failure_seq: None,
            state: WriterState::Running,
            flushed: None,
            ..Queue::default()
        }),
        complete: Condvar::new(),
        wake: mpsc::sync_channel(1).0,
        gateway: Identifier::try_from("home".to_owned()).unwrap(),
        committed: AtomicU64::new(0),
        clock: Arc::new(|| UnixSeconds(0)),
        capacity: 2,
        persistent: true,
    };
    for _ in 0..8 {
        let event = shared
            .event(&mut queue, EventKind::Flapping {}, Actor::Daemon, None)
            .unwrap();
        shared.enqueue(&mut queue, event);
        shared.gap_note(&mut queue);
    }
    let noted: u64 = queue
        .events
        .iter()
        .filter_map(|event| {
            if let EventKind::EventGap { dropped, .. } = event.kind {
                Some(dropped)
            } else {
                None
            }
        })
        .sum();
    assert_eq!(noted + queue.gap.count, queue.dropped);
    assert_eq!(queue.events.len() as u64 + queue.dropped, queue.seq);
    flush(&handle);
    drop(log);
}

#[test]
fn unclean_restart_skips_outage_assignments_and_starts_with_gap() {
    let dir = TempDir::new();
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
                Err(io::Error::other("outage"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    assert!(!dir.0.join("events/clean").exists());
    emit(&handle);
    wait_for(|| calls.load(Ordering::SeqCst) > 0);
    let greatest = (0..100).map(|_| emit(&handle)).max().unwrap();
    drop(log);
    assert!(!dir.0.join("events/clean").exists());
    assert!(matches!(
        handle.emit(EventKind::Flapping {}, Actor::Daemon, None),
        Err(EmitError::Stopped)
    ));
    let (log, handle) = open(&dir, 0);
    assert!(emit(&handle) > greatest);
    flush(&handle);
    let events = records(&dir);
    assert_eq!(events[0].seq, UNCLEAN_SEQ_JUMP);
    assert!(matches!(
        events[0].kind,
        EventKind::EventGap {
            reason: Reason::UncleanStop,
            ..
        }
    ));
    drop(log);
    assert!(dir.0.join("events/clean").exists());
    let last = handle.committed_seq();
    let (log, handle) = open(&dir, 0);
    assert!(!dir.0.join("events/clean").exists());
    assert_eq!(emit(&handle), last + 1);
    drop(log);
}

#[test]
fn new_directory_without_clean_marker_starts_without_a_gap() {
    for existing_directory in [false, true] {
        let dir = TempDir::new();
        fs::remove_dir_all(dir.0.join("events")).unwrap();
        if existing_directory {
            fs::create_dir(dir.0.join("events")).unwrap();
        }
        let (log, handle) = open(&dir, 0);
        assert_eq!(fs::read_to_string(dir.0.join("events/seq")).unwrap(), "0\n");
        assert_eq!(emit(&handle), 1);
        flush(&handle);
        assert_eq!(handle.committed_seq(), 1);
        assert_eq!(records(&dir).len(), 1);
        assert!(matches!(records(&dir)[0].kind, EventKind::Flapping {}));
        drop(log);
    }
}

#[test]
fn committed_watermark_waits_for_file_and_created_directory_sync() {
    for step in [EventIoStep::FileSync, EventIoStep::DirectorySync] {
        let dir = TempDir::new();
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let seen = entered.clone();
        let resume = release.clone();
        let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
            &dir.0,
            gateway(),
            || UnixSeconds(0),
            16,
            move |at| {
                if at == step && !seen.swap(true, Ordering::SeqCst) {
                    while !resume.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        let seq = emit(&handle);
        wait_for(|| entered.load(Ordering::SeqCst));
        let committed = handle.committed_seq();
        let bounded = read_since(&dir.0, 0, Some(committed)).count();
        let best_effort = read_since(&dir.0, 0, None).count();
        release.store(true, Ordering::SeqCst);
        assert_eq!(committed, 0);
        assert_eq!(bounded, 0);
        assert_eq!(best_effort, 1);
        flush(&handle);
        assert_eq!(handle.committed_seq(), seq);
        assert_eq!(read_since(&dir.0, 0, Some(seq)).count(), 1);
        drop(log);
    }
}

#[test]
fn recovery_reports_bad_heads_and_accepts_newer_payloads() {
    let dir = TempDir::new();
    let path = dir.0.join("events/1970-01.jsonl");
    fs::write(&path, b"garbage\n{\"seq\":4,\"gateway\":\"home\",\"kind\":\"NewKind\",\"new_field\":true}\n{\"seq\":\"bad\",\"gateway\":\"home\"}\n{\"seq\":5,\"gateway\":\"invalid.domain\"}\n").unwrap();
    let OpenedLog {
        log,
        handle,
        warnings,
    } = EventLog::open(&dir.0, gateway(), || UnixSeconds(0)).unwrap();
    assert_eq!(
        warnings,
        vec![
            RecoveryWarning {
                path: path.clone(),
                line: 1
            },
            RecoveryWarning {
                path: path.clone(),
                line: 3
            },
            RecoveryWarning { path, line: 4 },
        ]
    );
    assert_eq!(emit(&handle), 6); // Boot/Recovered is 5.
    flush(&handle);
    let new: Vec<_> = read_since(&dir.0, 4, Some(handle.committed_seq()))
        .filter_map(Result::ok)
        .collect();
    assert!(matches!(
        new[0].kind,
        EventKind::Boot {
            result: Outcome::Recovered,
            step: StepKind::EventLog
        }
    ));
    drop(log);
}

#[test]
fn sequence_exhaustion_is_a_typed_open_error() {
    for clean in [false, true] {
        for highwater in [u64::MAX, u64::MAX - 1, u64::MAX - UNCLEAN_SEQ_JUMP + 1] {
            if clean && highwater < u64::MAX - 1 {
                continue;
            }
            let dir = TempDir::new();
            fs::write(dir.0.join("events/seq"), format!("{highwater}\n")).unwrap();
            if !clean {
                fs::remove_file(dir.0.join("events/clean")).unwrap();
            }
            assert!(matches!(
                EventLog::open(&dir.0, gateway(), || UnixSeconds(0)),
                Err(OpenError::SequenceExhausted(_))
            ));
        }
    }
    let dir = TempDir::new();
    fs::write(
        dir.0.join("events/1970-01.jsonl"),
        format!("{{\"seq\":{},\"gateway\":\"home\"}}\n", u64::MAX),
    )
    .unwrap();
    assert!(matches!(
        EventLog::open(&dir.0, gateway(), || UnixSeconds(0)),
        Err(OpenError::SequenceExhausted(_))
    ));
}

#[test]
fn directory_sync_retry_keeps_create_obligation() {
    let dir = TempDir::new();
    let syncs = Arc::new(AtomicUsize::new(0));
    let counter = syncs.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |step| {
            if step == EventIoStep::DirectorySync && counter.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(io::Error::other("first directory sync failed"));
            }
            Ok(())
        },
    )
    .unwrap();
    emit(&handle);
    flush(&handle);
    assert_eq!(syncs.load(Ordering::SeqCst), 2);
    assert_eq!(records(&dir).len(), 2); // Event and persistence-failure note.
    drop(log);
}

#[test]
fn idle_and_unchanged_flush_do_no_io_and_stale_temps_are_removed() {
    let dir = TempDir::new();
    let stale = dir.0.join("events/.scupper-123-456.tmp");
    fs::write(&stale, b"stale").unwrap();
    let io_calls = Arc::new(AtomicUsize::new(0));
    let counter = io_calls.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap();
    assert!(!stale.exists());
    emit(&handle);
    flush(&handle);
    let before = io_calls.load(Ordering::SeqCst);
    thread::sleep(Duration::from_millis(1_100));
    flush(&handle);
    assert_eq!(io_calls.load(Ordering::SeqCst), before);
    drop(log);
}

#[test]
fn drop_detaches_a_hung_writer_and_leaves_no_clean_marker() {
    let dir = TempDir::new();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let seen = entered.clone();
    let resume = release.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |step| {
            if step == EventIoStep::FileSync {
                seen.store(true, Ordering::SeqCst);
                while !resume.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(())
        },
    )
    .unwrap();
    emit(&handle);
    wait_for(|| entered.load(Ordering::SeqCst));
    let start = Instant::now();
    drop(log);
    let elapsed = start.elapsed();
    let clean = dir.0.join("events/clean").exists();
    release.store(true, Ordering::SeqCst);
    wait_for(|| handle.shared.lock().state == WriterState::Finished);
    assert!(elapsed < Duration::from_secs(2));
    assert!(!clean);
    assert!(!dir.0.join("events/clean").exists());
    let (log, handle) = open(&dir, 0);
    flush(&handle);
    assert!(records(&dir).iter().any(|e| matches!(
        e.kind,
        EventKind::EventGap {
            reason: Reason::UncleanStop,
            ..
        }
    )));
    drop(log);
}

#[test]
fn reader_continues_after_file_errors_and_seeks_old_months() {
    let dir = TempDir::new();
    let (log, handle) = open(&dir, 1_738_368_000); // February
    emit(&handle);
    flush(&handle);
    let events = dir.0.join("events");
    // A matching directory is a per-file error; newer months remain readable.
    fs::create_dir(events.join("2025-01.jsonl")).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        events.join("2025-03.jsonl"),
        rustix::fs::Mode::RUSR,
    )
    .unwrap();
    // An invalid earlier line would error if the old month were fully scanned.
    fs::write(
        events.join("2024-12.jsonl"),
        b"bad\n{\"seq\":0,\"gateway\":\"home\"}\ntorn",
    )
    .unwrap();
    let read: Vec<_> = read_since(&dir.0, 0, Some(handle.committed_seq())).collect();
    assert_eq!(read.iter().filter(|e| e.is_ok()).count(), 1);
    let errors: Vec<_> = read.into_iter().filter_map(Result::err).collect();
    assert_eq!(errors.len(), 2);
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("2025-01.jsonl:open"))
    );
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("2025-03.jsonl:open"))
    );
    // A corrupt tail disables seeking, reporting precise line numbers.
    fs::write(events.join("2024-12.jsonl"), b"bad\nbad tail\n").unwrap();
    let errors: Vec<_> = read_since(&dir.0, 0, None)
        .filter_map(Result::err)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.iter().any(|e| e.contains("2024-12.jsonl:1:")));
    assert!(errors.iter().any(|e| e.contains("2024-12.jsonl:2:")));
    drop(log);
}

#[test]
fn checkpoints_wait_for_a_hundred_records_unless_explicitly_flushed() {
    let dir = TempDir::new();
    let (log, handle) = open(&dir, 0);
    for _ in 0..99 {
        emit(&handle);
    }
    wait_for(|| handle.committed_seq() == 99);
    assert_eq!(fs::read_to_string(dir.0.join("events/seq")).unwrap(), "0\n");
    emit(&handle);
    wait_for(|| fs::read_to_string(dir.0.join("events/seq")).is_ok_and(|text| text == "100\n"));
    drop(log);
}

#[test]
fn unclean_jump_uses_maximum_of_highwater_and_recovered_heads() {
    for (highwater, recovered) in [(50_u64, 30_u64), (30, 50)] {
        let dir = TempDir::new();
        fs::remove_file(dir.0.join("events/clean")).unwrap();
        fs::write(dir.0.join("events/seq"), format!("{highwater}\n")).unwrap();
        fs::write(
            dir.0.join("events/1970-01.jsonl"),
            format!("{{\"seq\":{recovered},\"gateway\":\"home\",\"kind\":\"Future\"}}\n"),
        )
        .unwrap();
        let (log, handle) = open(&dir, 0);
        flush(&handle);
        let events: Vec<_> = read_since(&dir.0, 50, Some(handle.committed_seq()))
            .collect::<io::Result<_>>()
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 50 + UNCLEAN_SEQ_JUMP);
        assert!(matches!(
            events[0].kind,
            EventKind::EventGap {
                reason: Reason::UncleanStop,
                ..
            }
        ));
        drop(log);
    }
}

#[test]
fn unclean_gap_survives_buffer_overflow_before_first_append() {
    let dir = TempDir::new();
    fs::remove_file(dir.0.join("events/clean")).unwrap();
    fs::write(dir.0.join("events/seq"), b"0\n").unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let seen = entered.clone();
    let resume = release.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        2,
        move |step| {
            if step == EventIoStep::Write && !seen.swap(true, Ordering::SeqCst) {
                while !resume.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(())
        },
    )
    .unwrap();
    wait_for(|| entered.load(Ordering::SeqCst));
    for _ in 0..100 {
        emit(&handle);
    }
    release.store(true, Ordering::SeqCst);
    flush(&handle);
    assert!(matches!(
        records(&dir)[0].kind,
        EventKind::EventGap {
            reason: Reason::UncleanStop,
            ..
        }
    ));
    drop(log);
}

#[test]
fn invalid_gateway_is_refused_before_creating_log_files() {
    let dir = TempDir::new();
    assert!(matches!(
        EventLog::open(&dir.0, GatewayId("tracker.example.com".into()), || {
            UnixSeconds(0)
        }),
        Err(OpenError::InvalidGateway)
    ));
    assert_eq!(monthly_files(&dir.0.join("events")).unwrap().len(), 0);
}

#[test]
fn timed_out_drop_cleans_a_late_marker_before_releasing_writer_lock() {
    let dir = TempDir::new();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let seen = entered.clone();
    let resume = release.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |step| {
            if step == EventIoStep::CleanMarkerSync {
                seen.store(true, Ordering::SeqCst);
                while !resume.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(())
        },
    )
    .unwrap();
    emit(&handle);
    let (done, result) = mpsc::sync_channel(1);
    let shutdown = thread::spawn(move || {
        drop(log);
        done.send(()).unwrap();
    });
    wait_for(|| entered.load(Ordering::SeqCst));
    let bounded = result.recv_timeout(Duration::from_secs(2)).is_ok();
    let locked = matches!(WriterLock::try_acquire(dir.0.join("events")), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
    let highwater = fs::read_to_string(dir.0.join("events/seq")).unwrap();
    release.store(true, Ordering::SeqCst);
    shutdown.join().unwrap();
    wait_for(|| handle.shared.lock().state == WriterState::Finished);
    assert!(bounded);
    assert!(locked);
    assert_eq!(highwater, "1\n");
    assert_eq!(handle.committed_seq(), 1);
    assert!(!dir.0.join("events/clean").exists());
    let (log, handle) = open(&dir, 0);
    flush(&handle);
    assert_eq!(handle.committed_seq(), 1 + UNCLEAN_SEQ_JUMP);
    drop(log);
}

#[test]
fn tail_seeking_handles_multiple_chunks_and_large_torn_suffixes() {
    let dir = TempDir::new();
    let path = dir.0.join("events/1970-01.jsonl");
    let text = format!(
        "bad earlier line\n{{\"seq\":7,\"gateway\":\"home\",\"future\":\"{}\"}}\n{}",
        "x".repeat(9500),
        "torn".repeat(2500)
    );
    fs::write(path, text).unwrap();
    assert_eq!(read_since(&dir.0, 7, None).count(), 0);
}

#[test]
fn unclean_open_reserves_highwater_before_returning_or_assigning_sequences() {
    let dir = TempDir::new();
    fs::remove_file(dir.0.join("events/clean")).unwrap();
    fs::write(dir.0.join("events/seq"), b"100\n").unwrap();
    let assigned = Arc::new(AtomicUsize::new(0));
    let clock_calls = assigned.clone();
    let entered = Arc::new(AtomicBool::new(false));
    let seen = entered.clone();
    let release = Arc::new(AtomicBool::new(false));
    let resume = release.clone();
    let root = dir.0.clone();
    let (done, result) = mpsc::sync_channel(1);
    let opener = thread::spawn(move || {
        done.send(EventLog::open_with_hook(
            &root,
            gateway(),
            move || {
                clock_calls.fetch_add(1, Ordering::SeqCst);
                UnixSeconds(0)
            },
            16,
            move |step| {
                if step == EventIoStep::OpenCheckpointSync {
                    seen.store(true, Ordering::SeqCst);
                    while !resume.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
                if step == EventIoStep::Write {
                    return Err(io::Error::other("append outage"));
                }
                Ok(())
            },
        ))
        .unwrap();
    });
    wait_for(|| entered.load(Ordering::SeqCst));
    let not_returned = matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty));
    let before_sync = assigned.load(Ordering::SeqCst);
    let reserved = fs::read_to_string(dir.0.join("events/seq")).unwrap();
    release.store(true, Ordering::SeqCst);
    let OpenedLog { log, handle, .. } = result
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    opener.join().unwrap();
    assert!(not_returned);
    assert_eq!(before_sync, 0);
    assert_eq!(reserved, format!("{}\n", 100 + UNCLEAN_SEQ_JUMP - 1));
    assert_eq!(handle.committed_seq(), 0);
    assert!(emit(&handle) > 100 + UNCLEAN_SEQ_JUMP);
    drop(log);
}

#[test]
fn open_reservation_errors_are_typed_and_no_sequence_is_assigned() {
    for corrupt in [false, true] {
        for step in [EventIoStep::OpenCheckpoint, EventIoStep::OpenCheckpointSync] {
            let dir = TempDir::new();
            fs::remove_file(dir.0.join("events/clean")).unwrap();
            fs::write(
                dir.0.join("events/seq"),
                if corrupt { b"bad\n" } else { b"100\n" },
            )
            .unwrap();
            let assigned = Arc::new(AtomicUsize::new(0));
            let clock_calls = assigned.clone();
            let opened = EventLog::open_with_hook(
                &dir.0,
                gateway(),
                move || {
                    clock_calls.fetch_add(1, Ordering::SeqCst);
                    UnixSeconds(0)
                },
                16,
                move |at| {
                    if at == step {
                        Err(io::Error::from_raw_os_error(30)) // EROFS, including a read-only seq filesystem.
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(matches!(opened, Err(OpenError::Reservation(_))));
            assert_eq!(assigned.load(Ordering::SeqCst), 0);
            let (log, handle) = open(&dir, 0); // Failed open released its writer lock.
            flush(&handle);
            drop(log);
        }
    }
}

#[test]
fn real_reservation_replace_failure_is_typed() {
    let dir = TempDir::new();
    fs::remove_file(dir.0.join("events/clean")).unwrap();
    let seq = dir.0.join("events/seq");
    fs::write(&seq, b"100\n").unwrap();
    let opened = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |step| {
            if step == EventIoStep::OpenCheckpoint {
                fs::remove_file(&seq)?;
                fs::create_dir(&seq)?;
            }
            Ok(())
        },
    );
    assert!(matches!(opened, Err(OpenError::Reservation(_))));
}

#[test]
fn corrupt_highwater_recovers_heads_warns_and_forces_unclean_reservation() {
    for text in [
        b"not-a-sequence\n".as_slice(),
        b"\xff\n",
        b"18446744073709551616\n",
    ] {
        let dir = TempDir::new();
        fs::write(dir.0.join("events/seq"), text).unwrap();
        fs::write(
            dir.0.join("events/1970-01.jsonl"),
            b"{\"seq\":73,\"gateway\":\"home\",\"kind\":\"Future\"}\n",
        )
        .unwrap();
        let OpenedLog {
            log,
            handle,
            warnings,
        } = EventLog::open_with_hook(
            &dir.0,
            gateway(),
            || UnixSeconds(0),
            16,
            |step| {
                if step == EventIoStep::Write {
                    Err(io::Error::other("outage"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(
            warnings,
            vec![RecoveryWarning {
                path: dir.0.join("events/seq"),
                line: 1
            }]
        );
        assert_eq!(
            fs::read_to_string(dir.0.join("events/seq")).unwrap(),
            format!("{}\n", 73 + UNCLEAN_SEQ_JUMP - 1)
        );
        assert_eq!(handle.committed_seq(), 73);
        drop(log);
        let (log, handle) = open(&dir, 0);
        flush(&handle);
        assert!(
            read_since(&dir.0, 73, Some(handle.committed_seq()))
                .filter_map(Result::ok)
                .any(|e| matches!(
                    e.kind,
                    EventKind::EventGap {
                        reason: Reason::UncleanStop,
                        ..
                    }
                ))
        );
        drop(log);
    }
}

#[test]
fn retention_errors_warn_once_continue_appending_and_retry_while_idle() {
    let dir = TempDir::new();
    let failing = Arc::new(AtomicBool::new(true));
    let retry = failing.clone();
    let opened = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        100,
        move |step| {
            if step == EventIoStep::Retention && retry.load(Ordering::Relaxed) {
                Err(io::Error::other("retention EIO"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    emit(&opened.handle);
    flush(&opened.handle);
    emit(&opened.handle);
    flush(&opened.handle);
    let events = records(&dir);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e.kind,
                EventKind::Repair {
                    object: None,
                    kind: StepKind::EventLog,
                    result: Outcome::Failed,
                    ..
                }
            ))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
    );
    failing.store(false, Ordering::Relaxed);
    flush(&opened.handle);
    drop(opened);
    assert!(dir.0.join("events/clean").exists());
}

#[test]
fn nonregular_months_warn_and_do_not_prevent_open() {
    let dir = TempDir::new();
    fs::create_dir(dir.0.join("events/1969-01.jsonl")).unwrap();
    std::os::unix::fs::symlink("missing", dir.0.join("events/1969-02.jsonl")).unwrap();
    let opened = EventLog::open(&dir.0, gateway(), || UnixSeconds(0)).unwrap();
    assert_eq!(opened.warnings.len(), 2);
    assert!(opened.warnings.iter().all(|w| w.line == 0));
    emit(&opened.handle);
    flush(&opened.handle);
    drop(opened);
}

#[test]
fn failure_immediately_after_month_create_keeps_directory_sync_obligation() {
    let dir = TempDir::new();
    let syncs = Arc::new(AtomicUsize::new(0));
    let calls = syncs.clone();
    let release = Arc::new(AtomicBool::new(false));
    let resume = release.clone();
    let OpenedLog { log, handle, .. } = EventLog::open_with_hook(
        &dir.0,
        gateway(),
        || UnixSeconds(0),
        16,
        move |step| {
            if step == EventIoStep::MonthCreated {
                return Err(io::Error::other("failure before permissions and metadata"));
            }
            if step == EventIoStep::DirectorySync {
                calls.fetch_add(1, Ordering::SeqCst);
                if !resume.load(Ordering::SeqCst) {
                    return Err(io::Error::other("directory sync blocked"));
                }
            }
            Ok(())
        },
    )
    .unwrap();
    emit(&handle);
    wait_for(|| syncs.load(Ordering::SeqCst) > 0);
    assert_eq!(handle.committed_seq(), 0);
    assert_eq!(
        read_since(&dir.0, 0, Some(handle.committed_seq())).count(),
        0
    );
    release.store(true, Ordering::SeqCst);
    flush(&handle);
    assert!(syncs.load(Ordering::SeqCst) >= 2);
    assert_eq!(records(&dir).len(), 2);
    drop(log);
}

#[test]
fn memory_only_keeps_bounded_history_and_failure_without_committing() {
    let OpenedLog {
        log,
        handle,
        warnings,
    } = EventLog::memory_only(gateway(), || UnixSeconds(42)).unwrap();
    assert_eq!(warnings, []);
    let cloned = handle.clone();
    let mut greatest = 0;
    for _ in 0..CAPACITY + 10 {
        let seq = emit(&cloned);
        assert!(seq > greatest);
        greatest = seq;
    }
    let queue = handle.shared.lock();
    assert_eq!(queue.events.len(), CAPACITY);
    assert_eq!(queue.events.back().unwrap().seq, greatest);
    assert!(queue.events.iter().all(|e| e.at == UnixSeconds(42)));
    assert_eq!(
        queue
            .events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
            .count(),
        1
    );
    drop(queue);
    assert!(handle.dropped() > 0);
    assert_eq!(handle.committed_seq(), 0);
    assert_eq!(
        handle
            .flush_blocking(Duration::from_secs(5))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    drop(log);
    assert!(matches!(
        cloned.emit(EventKind::Flapping {}, Actor::Daemon, None),
        Err(EmitError::Stopped)
    ));
    assert_eq!(cloned.committed_seq(), 0);
    assert!(matches!(
        EventLog::memory_only(GatewayId("invalid.domain".into()), || UnixSeconds(0)),
        Err(OpenError::InvalidGateway)
    ));
}

#[test]
fn replay_uses_disk_sequence_space_even_when_local_ids_are_far_ahead() {
    let dir = TempDir::new();
    let memory = EventLog::memory_only(gateway(), || UnixSeconds(0)).unwrap();
    let base = UNCLEAN_SEQ_JUMP * 3;
    memory.handle.shared.lock().seq = base;
    emit(&memory.handle);
    let opened = EventLog::open(&dir.0, gateway(), || UnixSeconds(0)).unwrap();
    memory.handle.replay_into(&opened.handle).unwrap();
    flush(&opened.handle);
    let high = opened.handle.committed_seq();
    assert!(high < base);
    let events: Vec<_> = read_since(&dir.0, 0, None).map(Result::unwrap).collect();
    assert_eq!(
        events.iter().map(|event| event.seq).collect::<Vec<_>>(),
        (1..=high).collect::<Vec<_>>()
    );
    assert!(
        matches!(events[0].kind, EventKind::MemoryReplay { local_last, .. } if local_last == base + 1)
    );
    drop(opened);
    fs::remove_file(dir.0.join("events/clean")).unwrap();
    let reopened = EventLog::open(&dir.0, gateway(), || UnixSeconds(0)).unwrap();
    assert!(emit(&reopened.handle) > high);
    flush(&reopened.handle);
}

#[test]
fn failed_checkpoint_audit_is_best_effort_and_raises_persistence_alert() {
    let opened = EventLog::memory_buffer(GatewayId("gw1".into()), || UnixSeconds(1000)).unwrap();
    let handle = opened.handle;
    drop(opened.log);
    assert!(!handle.shared.lock().failure);
    handle.repair_checkpoint_created(Actor::Daemon, Some(1));
    let queue = handle.shared.lock();
    assert!(queue.failure);
    let event = queue
        .events
        .iter()
        .find(|event| {
            matches!(
                event.kind,
                EventKind::PersistenceFailed {
                    reason: Reason::EventWrite
                }
            )
        })
        .unwrap();
    assert_eq!(event.alert().unwrap().key, AlertKey::Persistence);
}
