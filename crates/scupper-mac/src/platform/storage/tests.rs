use super::*;
use proptest::prelude::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
fn meta() -> Metadata {
    Metadata {
        regular: true,
        uid: 0,
        mode: 0o100_600,
        nlink: 1,
        size: COPY_BYTES as u64,
    }
}
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent injected faults and file lifecycle observations.
struct Model {
    events: Vec<&'static str>,
    short: bool,
    zero_size: bool,
    fail: Option<&'static str>,
    exists: bool,
    created: bool,
    cleaned: bool,
    initial_short: bool,
}
impl Model {
    fn event(&mut self, name: &'static str) -> Result<(), SysError> {
        self.events.push(name);
        if self.fail == Some(name) {
            Err(FAILED)
        } else {
            Ok(())
        }
    }
}
impl Io for Model {
    fn open(&mut self, create: bool) -> Result<(), SysError> {
        self.event("open")?;
        if create && self.exists {
            return Err(FAILED);
        }
        if create {
            self.created = true;
            self.exists = true;
        }
        Ok(())
    }
    fn cleanup_failed_create(&mut self) {
        if self.created {
            self.exists = false;
            self.cleaned = true;
        }
    }
    fn stat(&mut self) -> Result<Metadata, SysError> {
        self.event("stat")?;
        let mut m = meta();
        if self.zero_size || (self.initial_short && !self.events.contains(&"pwrite")) {
            m.size = 0;
        }
        Ok(m)
    }
    fn preallocate(&mut self) -> Result<(), SysError> {
        self.event("preallocate")
    }
    fn pwrite(&mut self, bytes: &[u8]) -> Result<usize, SysError> {
        self.event("pwrite")?;
        Ok(if self.short {
            bytes.len() / 2
        } else {
            bytes.len()
        })
    }
    fn full_sync(&mut self, directory: bool) -> Result<(), SysError> {
        self.event(if directory {
            "directory-sync"
        } else {
            "file-sync"
        })
    }
}
#[test]
fn create_requires_both_checked_syncs_in_order() {
    let mut io = Model::default();
    assert_eq!(
        write(&mut io, true, &[7; COPY_BYTES], Fault::None),
        WriteOutcome::Synced
    );
    assert_eq!(
        io.events,
        [
            "open",
            "stat",
            "preallocate",
            "pwrite",
            "stat",
            "file-sync",
            "directory-sync"
        ]
    );
    for failure in [
        "open",
        "stat",
        "preallocate",
        "pwrite",
        "file-sync",
        "directory-sync",
    ] {
        let mut io = Model {
            fail: Some(failure),
            ..Model::default()
        };
        assert!(matches!(
            write(&mut io, true, &[7; COPY_BYTES], Fault::None),
            WriteOutcome::Failed(_)
        ));
        assert_eq!(io.events.last(), Some(&failure)); // No fallback or subsequent effects.
    }
}
#[test]
fn full_sync_failure_never_falls_back_or_returns_synced() {
    let mut io = Model {
        fail: Some("file-sync"),
        ..Model::default()
    };
    assert!(matches!(
        write(&mut io, false, &[7; COPY_BYTES], Fault::None),
        WriteOutcome::Failed(_)
    ));
    assert_eq!(io.events.last(), Some(&"file-sync"));
    assert!(!io.events.contains(&"directory-sync"));
}
#[test]
fn preallocation_is_not_length_and_short_pwrite_is_failed_without_sync() {
    for (short, zero_size) in [(true, false), (false, true)] {
        let mut io = Model {
            short,
            zero_size,
            ..Model::default()
        };
        assert!(matches!(
            write(&mut io, true, &[7; COPY_BYTES], Fault::None),
            WriteOutcome::Failed(_)
        ));
        assert!(!io.events.contains(&"file-sync"));
    }
    let mut io = Model {
        exists: true,
        ..Model::default()
    };
    assert!(matches!(
        write(&mut io, true, &[7; COPY_BYTES], Fault::None),
        WriteOutcome::Failed(_)
    ));
    assert_eq!(io.events, ["open"]);
}
#[test]
fn hard_linked_copy_returns_no_bytes_and_starts_no_pread() {
    let mut m = meta();
    m.nlink = 2;
    let mut called = false;
    assert_eq!(
        read_bytes(Ok(m), |_| {
            called = true;
            Ok(COPY_BYTES)
        }),
        CopyRead::Unreadable
    );
    assert!(!called);
}
proptest! {
    #[test]
    fn metadata_and_short_reads_fail_closed(uid in any::<u32>(), permissions in 0u32..0o10000, nlink in 0u64..5, size in 0u64..32768, regular in any::<bool>()) {
        let m = Metadata { uid, mode: permissions, nlink, size, regular };
        prop_assert_eq!(valid_copy(m), regular && uid == 0 && permissions == 0o600 && nlink == 1 && size <= COPY_BYTES as u64);
    }
    #[test]
    fn exactly_one_complete_read_is_required(length in 0usize..=COPY_BYTES) {
        let mut calls = 0;
        let result = read_bytes(Ok(meta()), |bytes| { calls += 1; bytes.fill(9); Ok(length) });
        prop_assert_eq!(calls, 1);
        if length == COPY_BYTES { prop_assert_eq!(result, CopyRead::Bytes(vec![9; COPY_BYTES])); }
        else { prop_assert_eq!(result, CopyRead::Unreadable); }
    }
}
fn budget(duration: Duration) -> impl Fn() -> Duration {
    let end = Instant::now() + duration;
    move || end.saturating_duration_since(Instant::now())
}
fn short() -> impl Fn() -> Duration {
    budget(Duration::from_millis(10))
}
fn long() -> impl Fn() -> Duration {
    budget(Duration::from_secs(2))
}
#[test]
fn write_timeout_busy_and_wait_share_the_same_job_and_storage_thread()
-> Result<(), Box<dyn std::error::Error>> {
    let mut workers = Workers::default();
    let (tx, rx) = mpsc::channel();
    let (id_tx, id_rx) = mpsc::channel();
    assert_eq!(
        workers.start_write(short(), move || {
            let _ = rx.recv();
            let _ = id_tx.send(thread::current().id());
            WriteOutcome::Synced
        }),
        WriteOutcome::TimedOut
    );
    let busy_calls = Arc::new(AtomicUsize::new(0));
    let busy_job = busy_calls.clone();
    assert_eq!(
        workers.start_write(
            || Duration::ZERO,
            move || {
                busy_job.fetch_add(1, Ordering::SeqCst);
                WriteOutcome::Failed(FAILED)
            }
        ),
        WriteOutcome::Busy
    );
    assert_eq!(workers.wait_write(short()), WriteOutcome::TimedOut);
    // Reads do not share the write fence.
    assert_eq!(
        workers.poll_copy(Copy::A, long(), || CopyRead::Missing),
        Poll::Ready(CopyRead::Missing)
    );
    tx.send(())?;
    assert_eq!(workers.wait_write(long()), WriteOutcome::Synced);
    let first_id = id_rx.recv()?;
    let (id_tx, id_rx) = mpsc::channel();
    assert_eq!(
        workers.start_write(long(), move || {
            let _ = id_tx.send(thread::current().id());
            WriteOutcome::Synced
        }),
        WriteOutcome::Synced
    );
    assert_eq!(first_id, id_rx.recv()?);
    assert_eq!(busy_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        workers.wait_write(long()),
        WriteOutcome::Failed(_)
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let copy = calls.clone();
    assert_eq!(
        workers.start_write(
            || Duration::ZERO,
            move || {
                copy.fetch_add(1, Ordering::SeqCst);
                WriteOutcome::Synced
            }
        ),
        WriteOutcome::NotStarted(SysError::TimedOut)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn two_live_readers_third_busy_and_abandoned_result_cannot_be_reused()
-> Result<(), Box<dyn std::error::Error>> {
    let mut workers = Workers::default();
    let (first_tx, first_rx) = mpsc::channel();
    let (second_tx, second_rx) = mpsc::channel();
    assert_eq!(
        workers.poll_copy(Copy::A, short(), move || {
            let _ = first_rx.recv();
            CopyRead::Bytes(vec![1; COPY_BYTES])
        }),
        Poll::Pending
    );
    workers.abandon();
    assert_eq!(
        workers.poll_copy(Copy::B, short(), move || {
            let _ = second_rx.recv();
            CopyRead::Bytes(vec![2; COPY_BYTES])
        }),
        Poll::Pending
    );
    // Polling retains B; it must not execute the replacement closure.
    assert_eq!(
        workers.poll_copy(Copy::B, short(), || CopyRead::Missing),
        Poll::Pending
    );
    assert_eq!(
        workers.poll_copy(Copy::A, short(), || CopyRead::Missing),
        Poll::Ready(CopyRead::Unreadable)
    );
    workers.abandon();
    let called = Arc::new(AtomicUsize::new(0));
    let count = called.clone();
    assert_eq!(
        workers.poll_copy(Copy::A, long(), move || {
            count.fetch_add(1, Ordering::SeqCst);
            CopyRead::Missing
        }),
        Poll::Ready(CopyRead::Unreadable)
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
    assert_eq!(
        workers.start_write(long(), || WriteOutcome::Synced),
        WriteOutcome::Synced
    );
    first_tx.send(())?;
    second_tx.send(())?;
    for handle in workers.readers.drain(..) {
        assert!(handle.join().is_ok());
    }
    assert_eq!(
        workers.poll_copy(Copy::A, long(), || CopyRead::Bytes(vec![3; COPY_BYTES])),
        Poll::Ready(CopyRead::Bytes(vec![3; COPY_BYTES]))
    );
    Ok(())
}
#[cfg(feature = "qualification")]
#[test]
fn every_hook_fails_after_its_selected_stage() {
    for (fault, last) in [
        (Fault::Open, "open"),
        (Fault::Preallocate, "preallocate"),
        (Fault::HalfWrite, "pwrite"),
        (Fault::FileSync, "file-sync"),
        (Fault::DirectorySync, "directory-sync"),
    ] {
        let mut io = Model::default();
        assert!(matches!(
            write(&mut io, true, &[7; COPY_BYTES], fault),
            WriteOutcome::Failed(_)
        ));
        assert_eq!(io.events.last(), Some(&last));
        assert!(fault.reached(&write(&mut Model::default(), true, &[7; COPY_BYTES], fault)));
        assert!(io.cleaned);
    }
}
#[cfg(not(feature = "qualification"))]
#[test]
fn production_fault_selection_has_only_none() {
    // This exhaustive match stops compiling if a fault variant escapes its cfg.
    match Fault::default() {
        Fault::None => {}
    }
    assert_eq!(std::mem::size_of::<Fault>(), 0);
}

#[test]
fn only_checked_root_and_enoent_prove_missing() {
    let mut called = false;
    assert_eq!(
        open_read::<(), ()>(Err(FAILED), |()| {
            called = true;
            Err(OpenError::Missing)
        }),
        Err(CopyRead::Unreadable)
    );
    assert!(!called);
    assert_eq!(
        open_read::<(), ()>(Ok(()), |()| Err(OpenError::Missing)),
        Err(CopyRead::Missing)
    );
    assert_eq!(
        open_read::<(), ()>(Ok(()), |()| Err(OpenError::Unreadable)),
        Err(CopyRead::Unreadable)
    );
    assert_eq!(
        read_bytes(Err(FAILED), |_| Ok(COPY_BYTES)),
        CopyRead::Unreadable
    );
    assert_eq!(
        read_bytes(Ok(meta()), |_| Err(FAILED)),
        CopyRead::Unreadable
    );
}

#[test]
fn abandoned_same_copy_result_is_never_consumed_by_the_next_read()
-> Result<(), Box<dyn std::error::Error>> {
    let mut workers = Workers::default();
    let (tx, rx) = mpsc::channel();
    assert_eq!(
        workers.poll_copy(Copy::A, short(), move || {
            let _ = rx.recv();
            CopyRead::Bytes(vec![1; COPY_BYTES])
        }),
        Poll::Pending
    );
    workers.abandon();
    tx.send(())?;
    for handle in workers.readers.drain(..) {
        assert!(handle.join().is_ok());
    }
    assert_eq!(
        workers.poll_copy(Copy::A, long(), || CopyRead::Bytes(vec![3; COPY_BYTES])),
        Poll::Ready(CopyRead::Bytes(vec![3; COPY_BYTES]))
    );
    Ok(())
}

#[cfg(feature = "qualification")]
#[test]
fn fault_selection_is_consumed_per_call() {
    for fault in [
        Fault::Open,
        Fault::Preallocate,
        Fault::HalfWrite,
        Fault::FileSync,
        Fault::DirectorySync,
    ] {
        let mut selection = fault;
        assert_eq!(selection.take(), fault);
        assert_eq!(selection.take(), Fault::None);
    }
}
proptest! {
    #[test]
    fn synced_requires_full_length_and_every_applicable_sync(create in any::<bool>(), short in any::<bool>(), zero_size in any::<bool>(), file_error in any::<bool>(), directory_error in any::<bool>()) {
        let mut io = Model { short, zero_size, fail: if file_error {Some("file-sync")} else if directory_error {Some("directory-sync")} else {None}, ..Model::default() };
        prop_assert_eq!(write(&mut io, create, &[7; COPY_BYTES], Fault::None) == WriteOutcome::Synced, !short && !zero_size && !file_error && (!create || !directory_error));
    }
}

#[test]
fn failed_create_cleans_its_stub_but_never_an_existing_file() {
    for failure in [
        "stat",
        "preallocate",
        "pwrite",
        "file-sync",
        "directory-sync",
    ] {
        let mut io = Model {
            fail: Some(failure),
            ..Model::default()
        };
        assert!(matches!(
            write(&mut io, true, &[7; COPY_BYTES], Fault::None),
            WriteOutcome::Failed(_)
        ));
        assert!(io.cleaned);
        assert!(!io.exists);
    }
    let mut io = Model {
        exists: true,
        ..Model::default()
    };
    assert!(matches!(
        write(&mut io, true, &[7; COPY_BYTES], Fault::None),
        WriteOutcome::Failed(_)
    ));
    assert!(io.exists);
    assert!(!io.cleaned);
}

#[test]
fn short_stub_is_zero_padded_and_repairable_but_long_files_are_unreadable() {
    for size in [0, 1, COPY_BYTES / 2, COPY_BYTES - 1] {
        let mut m = meta();
        m.size = size as u64;
        let read = read_bytes(Ok(m), |bytes| {
            bytes.fill(7);
            Ok(bytes.len())
        });
        let mut padded = vec![0; COPY_BYTES];
        padded[..size].fill(7);
        assert_eq!(read, CopyRead::Short(padded));
        assert!(!matches!(
            crate::snapshot::classify_copy(read),
            crate::snapshot::CopyClass::V { .. }
        ));
    }
    let mut io = Model {
        initial_short: true,
        ..Model::default()
    };
    assert_eq!(
        write(&mut io, false, &[7; COPY_BYTES], Fault::None),
        WriteOutcome::Synced
    );
    assert!(io.events.contains(&"file-sync"));
    let mut m = meta();
    m.size += 1;
    assert_eq!(read_bytes(Ok(m), |_| unreachable!()), CopyRead::Unreadable);
}

#[test]
#[allow(clippy::panic)] // Deliberate worker failure, not a production panic path.
fn panicking_writer_is_replaced_on_the_next_call() {
    let mut workers = Workers::default();
    assert!(matches!(
        workers.start_write(long(), || panic!("injected worker panic")),
        WriteOutcome::Failed(_)
    ));
    assert_eq!(
        workers.start_write(long(), || WriteOutcome::Synced),
        WriteOutcome::Synced
    );
    // Also cover an already-dead sender whose result was consumed previously.
    let (tx, rx) = mpsc::channel();
    drop(rx);
    workers.writer = Some(tx);
    assert!(matches!(
        workers.start_write(long(), || WriteOutcome::Synced),
        WriteOutcome::Failed(_)
    ));
    assert!(workers.writer.is_none());
    assert_eq!(
        workers.start_write(long(), || WriteOutcome::Synced),
        WriteOutcome::Synced
    );
}

#[cfg(feature = "qualification")]
#[test]
fn unreached_hook_iterations_earn_no_credit() {
    let faults = [
        Fault::Open,
        Fault::Preallocate,
        Fault::HalfWrite,
        Fault::FileSync,
        Fault::DirectorySync,
    ];
    let mut credited = 0;
    for fault in faults {
        for outcome in [
            WriteOutcome::Failed(FAILED),
            WriteOutcome::TimedOut,
            WriteOutcome::Synced,
            WriteOutcome::Failed(Fault::None.injected_error()),
        ] {
            assert!(!fault.credit(&outcome, &mut credited));
        }
        for other in faults {
            assert_eq!(
                fault.reached(&WriteOutcome::Failed(other.injected_error())),
                fault == other
            );
        }
    }
    assert_eq!(credited, 0);
    assert!(Fault::Open.credit(
        &WriteOutcome::Failed(Fault::Open.injected_error()),
        &mut credited
    ));
    assert_eq!(credited, 1);
    let mut io = Model {
        short: true,
        ..Model::default()
    };
    let outcome = write(&mut io, true, &[7; COPY_BYTES], Fault::HalfWrite);
    assert!(!Fault::HalfWrite.reached(&outcome));
}

#[test]
fn truncated_zero_padding_never_classifies_as_a_complete_snapshot() {
    let encoded = crate::snapshot::encode(1, &crate::snapshot::Snapshot::initial(Some(0), None))
        .unwrap_or_else(|e| unreachable!("{e:?}"));
    let mut m = meta();
    m.size = (COPY_BYTES / 2) as u64;
    let result = read_bytes(Ok(m), |bytes| {
        bytes.copy_from_slice(&encoded[..COPY_BYTES / 2]);
        Ok(bytes.len())
    });
    // The actual bytes equal a valid full record: provenance must still reject it.
    assert_eq!(result, CopyRead::Short(encoded.to_vec()));
    assert!(matches!(
        crate::snapshot::classify_copy(result),
        crate::snapshot::CopyClass::T
    ));
}
