//! Process-wide writer serialization using advisory `flock` locks.

use rustix::fs::{FlockOperation, OFlags, flock};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

/// Entry point for the lock rooted at a configurable run directory.
pub struct WriterLock;

/// An exclusive writer lock, released when its file descriptor is dropped.
///
/// Acquire the global lock before the store lock. Never acquire the same path
/// twice: independent file descriptions can deadlock even within one process.
#[derive(Debug)]
pub struct WriterGuard {
    file: std::sync::Arc<LockedFile>,
    // A capability may move between threads but cannot authorize concurrent writes.
    _not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

#[derive(Debug)]
struct LockedFile(File);
impl WriterGuard {
    // A bounded storage worker retains the same lock after a caller timeout.
    // Only storage may use this capability; the caller then does kernel-only
    // containment and cannot hand a new writer the lock over a late write.
    pub(crate) fn retain_for_storage(&self) -> Self {
        Self {
            file: self.file.clone(),
            _not_sync: std::marker::PhantomData,
        }
    }
}
impl Drop for LockedFile {
    fn drop(&mut self) {
        // A concurrent fork can briefly inherit this open file description
        // before exec closes CLOEXEC descriptors. Explicit unlock ends ownership
        // at the guard boundary instead of waiting for that unrelated exec.
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

impl WriterLock {
    /// Acquires `root/writer.lock`, waiting up to five seconds for the previous writer.
    /// Production callers use `/run/scupper` for `root`.
    ///
    /// # Errors
    /// Returns directory, file-open, or lock errors.
    pub fn acquire(root: impl AsRef<Path>) -> io::Result<WriterGuard> {
        Self::acquire_timeout(root, Duration::from_secs(5))
    }

    /// Attempts an exclusive lock without waiting.
    ///
    /// # Errors
    /// Returns `WouldBlock` when another descriptor holds the lock, or an I/O error.
    pub fn try_acquire(root: impl AsRef<Path>) -> io::Result<WriterGuard> {
        Self::open(
            root.as_ref(),
            "writer.lock",
            FlockOperation::NonBlockingLockExclusive,
        )
    }

    /// Acquires the lock with a bounded wait, polling at most every ten milliseconds.
    /// A zero timeout still attempts the lock once.
    ///
    /// # Errors
    /// Returns `TimedOut` if the deadline expires, or an open/lock error.
    pub fn acquire_timeout(root: impl AsRef<Path>, timeout: Duration) -> io::Result<WriterGuard> {
        let start = Instant::now();
        loop {
            match Self::try_acquire(root.as_ref()) {
                Ok(guard) => return Ok(guard),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = timeout.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("writer lock timeout: {error}"),
                        ));
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn open(root: &Path, name: &str, operation: FlockOperation) -> io::Result<WriterGuard> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
            .open(root.join(name))?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("writer lock is not a regular file"));
        }
        if let Err(error) = flock(&file, operation) {
            if io::Error::from(error).kind() != io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            let mut holder = String::new();
            let _ = (&file).take(32).read_to_string(&mut holder);
            let message = holder.trim().parse::<u32>().map_or_else(
                |_| format!("{name} held by another writer"),
                |pid| format!("{name} held by pid {pid}"),
            );
            return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
        }
        file.set_len(0)?;
        writeln!(file, "{}", std::process::id())?;
        Ok(WriterGuard {
            file: std::sync::Arc::new(LockedFile(file)),
            _not_sync: std::marker::PhantomData,
        })
    }
}

/// Lifetime supervisor exclusion, acquired before publishing a control socket.
pub struct SupervisorLease {
    _guard: WriterGuard,
}
impl SupervisorLease {
    /// Wait for a local writer with a bounded retry and status callback.
    /// # Errors
    /// Returns a timeout or filesystem error.
    pub fn acquire_timeout(
        root: &Path,
        timeout: Duration,
        mut waiting: impl FnMut(),
    ) -> io::Result<Self> {
        let deadline = Instant::now() + timeout;
        let mut next_notice = Instant::now();
        loop {
            match Self::try_acquire(root) {
                Ok(lease) => return Ok(lease),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("supervisor lease timeout: {error}"),
                        ));
                    }
                    if Instant::now() >= next_notice {
                        waiting();
                        next_notice = Instant::now() + Duration::from_secs(5);
                    }
                    std::thread::sleep(
                        Duration::from_millis(100)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
    /// Acquire without waiting; local mutations must refuse a live supervisor.
    /// # Errors
    /// Returns contention or filesystem errors.
    pub fn try_acquire(root: impl AsRef<Path>) -> io::Result<Self> {
        WriterLock::open(
            root.as_ref(),
            "scupperd.lock",
            FlockOperation::NonBlockingLockExclusive,
        )
        .map(|guard| Self { _guard: guard })
    }
}

#[cfg(test)]
#[test]
#[allow(clippy::unwrap_used)]
fn bounded_storage_timeout_retains_writer_until_late_completion() {
    let root = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp"))
        .join(format!("late-latch-writer-{}", std::process::id()));
    let guard = WriterLock::acquire(&root).unwrap();
    let retained = guard.retain_for_storage();
    let (release, wait) = std::sync::mpsc::channel();
    let (done, completed) = std::sync::mpsc::channel();
    let result = crate::system::storage_until(Instant::now(), move || {
        let _ = wait.recv();
        drop(retained);
        let _ = done.send(());
        Ok(())
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    drop(guard);
    assert_eq!(
        WriterLock::try_acquire(&root).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    release.send(()).unwrap();
    completed.recv_timeout(Duration::from_secs(1)).unwrap();
    drop(WriterLock::try_acquire(&root).unwrap());
    std::fs::remove_dir_all(root).unwrap();
}
