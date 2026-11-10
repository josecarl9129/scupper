//! Process-wide writer serialization using advisory `flock` locks.

use rustix::fs::{FlockOperation, OFlags, flock};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
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
    file: File,
    // A capability may move between threads but cannot authorize concurrent writes.
    _not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        // A concurrent fork can briefly inherit this open file description
        // before exec closes CLOEXEC descriptors. Explicit unlock ends ownership
        // at the guard boundary instead of waiting for that unrelated exec.
        let _ = flock(&self.file, FlockOperation::Unlock);
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
        fs::create_dir_all(root)?;
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
                |_| "writer lock held by another writer".to_owned(),
                |pid| format!("writer lock held by pid {pid}"),
            );
            return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
        }
        file.set_len(0)?;
        writeln!(file, "{}", std::process::id())?;
        Ok(WriterGuard {
            file,
            _not_sync: std::marker::PhantomData,
        })
    }
}

/// Lifetime supervisor exclusion, acquired before publishing a control socket.
pub struct SupervisorLease {
    _guard: WriterGuard,
}
impl SupervisorLease {
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
