//! Snapshot I/O protocol and bounded workers, independent of the OS adapter.
use super::{SysError, WriteOutcome};
use crate::snapshot::{COPY_BYTES, Copy, CopyRead};
use std::{sync::mpsc, task::Poll, thread, time::Duration};

#[cfg(target_os = "macos")]
pub(crate) mod darwin;

/// Provisional copy A filename (installer layout is deferred to 5a3).
pub const COPY_A_NAME: &str = "snapshot-a";
/// Provisional copy B filename.
pub const COPY_B_NAME: &str = "snapshot-b";
/// Fixed filename for a copy; never accepts caller-supplied path components.
#[must_use]
pub fn filename(copy: Copy) -> &'static str {
    match copy {
        Copy::A => COPY_A_NAME,
        Copy::B => COPY_B_NAME,
    }
}

/// Metadata used by the portable copy predicate.
#[derive(Clone, Copy, Debug)]
pub struct Metadata {
    /// Regular file, without following symlinks.
    pub regular: bool,
    /// Owner uid.
    pub uid: u32,
    /// POSIX mode, including special bits.
    pub mode: u32,
    /// Link count.
    pub nlink: u64,
    /// Logical byte length.
    pub size: u64,
}
/// Require a single root-owned private regular snapshot, possibly a short stub.
#[must_use]
pub fn valid_copy(m: Metadata) -> bool {
    valid_created(m) && m.size <= COPY_BYTES as u64
}
fn valid_created(m: Metadata) -> bool {
    m.regular && m.uid == 0 && m.mode & 0o7777 == 0o600 && m.nlink == 1
}

/// Return bytes after metadata passes and one pread matches its length.
/// Short stubs are zero-padded; snapshot classification rejects their contents.
/// The closure is never invoked for invalid metadata.
pub fn read_bytes(
    meta: Result<Metadata, SysError>,
    pread: impl FnOnce(&mut [u8]) -> Result<usize, SysError>,
) -> CopyRead {
    let Some(meta) = meta.ok() else {
        return CopyRead::Unreadable;
    };
    if !valid_copy(meta) {
        return CopyRead::Unreadable;
    }
    let mut bytes = vec![0; COPY_BYTES];
    let Ok(length) = usize::try_from(meta.size) else {
        return CopyRead::Unreadable;
    };
    match pread(&mut bytes[..length]) {
        Ok(length) if length as u64 == meta.size => {
            if length < COPY_BYTES {
                CopyRead::Short(bytes)
            } else {
                CopyRead::Bytes(bytes)
            }
        }
        _ => CopyRead::Unreadable,
    }
}

/// Copy open error, distinguished only after the root has passed its checks.
#[derive(Clone, Copy, Debug)]
pub enum OpenError {
    /// ENOENT from the fd-relative copy open.
    Missing,
    /// Every other open error.
    Unreadable,
}
/// Root failures can never certify absence. The open closure runs only after a
/// checked root is available.
///
/// # Errors
/// Returns Missing only for a missing copy under a checked root.
pub fn open_read<R, F>(
    root: Result<R, SysError>,
    open: impl FnOnce(R) -> Result<F, OpenError>,
) -> Result<F, CopyRead> {
    let root = root.map_err(|_| CopyRead::Unreadable)?;
    open(root).map_err(|error| match error {
        OpenError::Missing => CopyRead::Missing,
        OpenError::Unreadable => CopyRead::Unreadable,
    })
}

/// Per-call fault selection. Fault variants and gates do not exist in production.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Fault {
    /// Ordinary I/O.
    #[default]
    None,
    /// Fail immediately after opening or creating the copy.
    #[cfg(feature = "qualification")]
    Open,
    /// Fail after successful preallocation.
    #[cfg(feature = "qualification")]
    Preallocate,
    /// Write half of the bytes, then report failure.
    #[cfg(feature = "qualification")]
    HalfWrite,
    /// Force the file full-sync operation to fail.
    #[cfg(feature = "qualification")]
    FileSync,
    /// Force the directory full-sync operation to fail.
    #[cfg(feature = "qualification")]
    DirectorySync,
}

impl Fault {
    /// Consume one call's selection; later calls default to ordinary I/O.
    #[must_use]
    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

#[cfg(feature = "qualification")]
impl Fault {
    /// Unique evidence that this hook fired after its real stage completed.
    #[must_use]
    pub fn injected_error(self) -> SysError {
        SysError::Failed(match self {
            Self::None => "storage: no injection",
            Self::Open => "storage: injected Open; partial bytes may remain",
            Self::Preallocate => "storage: injected Preallocate; partial bytes may remain",
            Self::HalfWrite => "storage: injected HalfWrite; partial bytes may remain",
            Self::FileSync => "storage: injected FileSync; partial bytes may remain",
            Self::DirectorySync => "storage: injected DirectorySync; partial bytes may remain",
        })
    }
    /// Credit exactly one iteration only when this hook actually fired.
    pub fn credit(self, outcome: &WriteOutcome, iterations: &mut u32) -> bool {
        let reached = self.reached(outcome);
        *iterations += u32::from(reached);
        reached
    }
    /// Only a matching injected marker earns a hook iteration.
    #[must_use]
    pub fn reached(self, outcome: &WriteOutcome) -> bool {
        self != Self::None && *outcome == WriteOutcome::Failed(self.injected_error())
    }
}

/// Opened and owned descriptors. The implementation must check the root and all
/// ancestors before opening a copy relative to that root. Only ENOENT after that
/// check may become Missing. All methods are single attempts, without retries.
#[allow(clippy::missing_errors_doc)] // Every operation propagates failure without rollback.
pub trait Io {
    /// Open existing or exclusively create; creation establishes root:0600.
    fn open(&mut self, create: bool) -> Result<(), SysError>;
    /// Best-effort unlink of only the inode created by this call, then directory sync.
    fn cleanup_failed_create(&mut self);
    /// fstat the opened copy.
    fn stat(&mut self) -> Result<Metadata, SysError>;
    /// `F_PREALLOCATE`, `F_ALLOCATEALL`, `F_PEOFPOSMODE`, `COPY_BYTES` (not ftruncate).
    fn preallocate(&mut self) -> Result<(), SysError>;
    /// One pwrite at offset zero. A short success remains a failure.
    fn pwrite(&mut self, bytes: &[u8]) -> Result<usize, SysError>;
    /// Checked `F_FULLFSYNC`; never substitute fsync.
    fn full_sync(&mut self, directory: bool) -> Result<(), SysError>;
}
const FAILED: SysError = SysError::Failed("storage: partial bytes may remain");

/// Execute the write protocol. No successful sync can redeem a failed write.
pub fn write(
    io: &mut impl Io,
    create: bool,
    bytes: &[u8; COPY_BYTES],
    fault: Fault,
) -> WriteOutcome {
    match write_inner(io, create, bytes, fault) {
        Ok(()) => WriteOutcome::Synced,
        Err(error) => {
            if create {
                io.cleanup_failed_create();
            }
            WriteOutcome::Failed(error)
        }
    }
}
fn write_inner(
    io: &mut impl Io,
    create: bool,
    bytes: &[u8; COPY_BYTES],
    fault: Fault,
) -> Result<(), SysError> {
    io.open(create)?;
    #[cfg(feature = "qualification")]
    if fault == Fault::Open {
        return Err(fault.injected_error());
    }
    let meta = io.stat()?;
    if !(if create {
        valid_created(meta)
    } else {
        valid_copy(meta)
    }) {
        return Err(FAILED);
    }
    if create {
        io.preallocate()?;
        #[cfg(feature = "qualification")]
        if fault == Fault::Preallocate {
            return Err(fault.injected_error());
        }
    }
    #[cfg(feature = "qualification")]
    if fault == Fault::HalfWrite {
        if io.pwrite(&bytes[..COPY_BYTES / 2])? != COPY_BYTES / 2 {
            return Err(FAILED);
        }
        return Err(fault.injected_error());
    }
    if io.pwrite(bytes)? != COPY_BYTES {
        return Err(FAILED);
    }
    // Preallocation reserves blocks, not length. Verify actual pwrite length.
    let final_meta = io.stat()?;
    if !valid_copy(final_meta) || final_meta.size != COPY_BYTES as u64 {
        return Err(FAILED);
    }
    io.full_sync(false)?;
    #[cfg(feature = "qualification")]
    if fault == Fault::FileSync {
        return Err(fault.injected_error());
    }
    if create {
        io.full_sync(true)?;
        #[cfg(feature = "qualification")]
        if fault == Fault::DirectorySync {
            return Err(fault.injected_error());
        }
    }
    let _ = fault;
    Ok(())
}

type WriteJob = Box<dyn FnOnce() -> WriteOutcome + Send>;
struct ReadJob {
    copy: Copy,
    result: mpsc::Receiver<CopyRead>,
}
/// A persistent single write thread and at most two live read workers.
#[derive(Default)]
pub struct Workers {
    read: Option<ReadJob>,
    readers: Vec<thread::JoinHandle<()>>,
    writer: Option<mpsc::Sender<(WriteJob, mpsc::Sender<WriteOutcome>)>>,
    outstanding: Option<mpsc::Receiver<WriteOutcome>>,
}
fn receive<T>(
    rx: &mpsc::Receiver<T>,
    remaining: impl Fn() -> Duration,
) -> Result<T, mpsc::RecvTimeoutError> {
    // Recheck the OS deadline on wakeup (Darwin's deadline clock counts sleep).
    loop {
        match rx.try_recv() {
            Ok(value) => return Ok(value),
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(mpsc::RecvTimeoutError::Disconnected);
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let left = remaining();
        if left.is_zero() {
            return Err(mpsc::RecvTimeoutError::Timeout);
        }
        match rx.recv_timeout(left.min(Duration::from_millis(10))) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            result => return result,
        }
    }
}
impl Workers {
    /// All read workers, including abandoned workers, have exited.
    #[cfg(all(target_os = "macos", feature = "qualification"))]
    pub(crate) fn readers_idle(&self) -> bool {
        self.readers.iter().all(thread::JoinHandle::is_finished)
    }
    /// Whether the next poll can start a worker (and consume a qualification gate).
    #[cfg(all(target_os = "macos", feature = "qualification"))]
    pub(crate) fn can_start_read(&mut self) -> bool {
        self.readers.retain(|worker| !worker.is_finished());
        self.read.is_none() && self.readers.len() < 2
    }
    /// Poll the same copy read until completion or the slice deadline. A different
    /// pending copy fails closed. Capacity/expired calls start no worker.
    pub fn poll_copy(
        &mut self,
        copy: Copy,
        remaining: impl Fn() -> Duration,
        job: impl FnOnce() -> CopyRead + Send + 'static,
    ) -> Poll<CopyRead> {
        self.readers.retain(|worker| !worker.is_finished());
        if self.read.as_ref().is_some_and(|r| r.copy != copy) {
            return Poll::Ready(CopyRead::Unreadable);
        }
        if self.read.is_none() {
            if self.readers.len() >= 2 || remaining().is_zero() {
                return Poll::Ready(CopyRead::Unreadable);
            }
            let (tx, rx) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("scupper-read".into())
                .spawn(move || {
                    let _ = tx.send(job());
                });
            let Ok(worker) = worker else {
                return Poll::Ready(CopyRead::Unreadable);
            };
            self.readers.push(worker);
            self.read = Some(ReadJob { copy, result: rx });
        }
        let Some(active) = &self.read else {
            return Poll::Ready(CopyRead::Unreadable);
        };
        match receive(&active.result, remaining) {
            Err(mpsc::RecvTimeoutError::Timeout) => Poll::Pending,
            result => {
                self.read = None;
                Poll::Ready(result.unwrap_or(CopyRead::Unreadable))
            }
        }
    }
    /// Drop only the active receiver; its worker retains a capacity slot until exit.
    pub fn abandon(&mut self) {
        self.read = None;
    }
    /// Start a write only when the prior result has been consumed. Busy wins over
    /// an expired deadline, as in the fake. The job owns all bytes and descriptors.
    pub fn start_write(
        &mut self,
        remaining: impl Fn() -> Duration,
        job: impl FnOnce() -> WriteOutcome + Send + 'static,
    ) -> WriteOutcome {
        if self.outstanding.is_some() {
            return WriteOutcome::Busy;
        }
        if remaining().is_zero() {
            return WriteOutcome::NotStarted(SysError::TimedOut);
        }
        if self.writer.is_none() {
            let (tx, rx) = mpsc::channel::<(WriteJob, mpsc::Sender<WriteOutcome>)>();
            if thread::Builder::new()
                .name("scupper-storage".into())
                .spawn(move || {
                    while let Ok((job, result)) = rx.recv() {
                        let _ = result.send(job());
                    }
                })
                .is_err()
            {
                return WriteOutcome::Failed(FAILED);
            }
            self.writer = Some(tx);
        }
        let (tx, rx) = mpsc::channel();
        let Some(writer) = &self.writer else {
            return WriteOutcome::Failed(FAILED);
        };
        if writer.send((Box::new(job), tx)).is_err() {
            self.writer = None;
            return WriteOutcome::Failed(FAILED);
        }
        self.outstanding = Some(rx);
        self.wait_write(remaining)
    }
    /// Consume only the outstanding write's result. Timeouts retain the fence.
    pub fn wait_write(&mut self, remaining: impl Fn() -> Duration) -> WriteOutcome {
        let Some(rx) = &self.outstanding else {
            return WriteOutcome::Failed(SysError::Failed("no outstanding write"));
        };
        match receive(rx, remaining) {
            Err(mpsc::RecvTimeoutError::Timeout) => WriteOutcome::TimedOut,
            result => {
                self.outstanding = None;
                if let Ok(outcome) = result {
                    outcome
                } else {
                    self.writer = None;
                    WriteOutcome::Failed(FAILED)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
