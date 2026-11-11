//! Bounded asynchronous audit persistence. Emit performs no disk I/O.
//!
//! New files use mode 0640; installation assigns root:scupper-admin ownership.
//! Keep the `EventLog` alive while using its handles. Drop waits at most one
//! second, then detaches a stalled worker holding the writer lock. Shutdown is
//! best effort; the owner must call `LogHandle::flush_blocking` before drop for
//! a clean marker. The daemon shutdown path calls this before dropping the owner.
use crate::{
    fs::{DurableStep, Fs, RealFs, durable_directory, durable_replace},
    lock::{WriterGuard, WriterLock},
};
use scupper_proto::{
    Actor, Event, EventKind, GatewayId, Identifier, Outcome, Reason, StepKind, UnixSeconds,
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Sequence space skipped after an unclean stop.
pub const UNCLEAN_SEQ_JUMP: u64 = 1 << 24;

const CAPACITY: usize = 10_000;
const MAX_MONTHS: usize = 13;
const MAX_SIZE: u64 = 100_000_000;
type Clock = Arc<dyn Fn() -> UnixSeconds + Send + Sync>;
type Hook = Arc<dyn Fn(EventIoStep) -> io::Result<()> + Send + Sync>;

/// Fault injection boundaries for event append and high-water persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIoStep {
    /// Before retention maintenance, independent of append durability.
    Retention,
    /// Before reserving sequence state during open.
    OpenCheckpoint,
    /// After the open reservation rename, before synchronizing its directory.
    OpenCheckpointSync,
    /// Immediately after recording a new month's directory-sync obligation.
    MonthCreated,
    /// Before appending a serialized line.
    Write,
    /// After the line write, before synchronizing it.
    FileSync,
    /// Before synchronizing the monthly directory entry.
    DirectorySync,
    /// Before the durable high-water replacement.
    Checkpoint,
    /// After renaming the clean marker, before synchronizing its directory.
    CleanMarkerSync,
}

/// Sequence space is exhausted; a new audit identity cannot be assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("event sequence exhausted")]
pub struct SequenceExhausted;

/// A sender cannot assign another event identity.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// No more sequence values remain.
    #[error(transparent)]
    SequenceExhausted(#[from] SequenceExhausted),
    /// Shutdown has begun.
    #[error("event log is stopped")]
    Stopped,
}

/// Failures while opening an event log.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The initial sequence reservation could not be made durable.
    #[error("event sequence reservation failed: {0}")]
    Reservation(#[source] io::Error),
    /// Filesystem, locking or writer startup failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The recovered identity cannot advance safely.
    #[error(transparent)]
    SequenceExhausted(#[from] SequenceExhausted),
    /// The supplied gateway is not a core operational identifier.
    #[error("invalid event gateway")]
    InvalidGateway,
    /// A valid record belongs to another gateway.
    #[error("event gateway mismatch")]
    GatewayMismatch,
}

/// A record head or high-water file that could not be recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryWarning {
    /// Monthly file containing the record, or the corrupt `seq` file.
    pub path: PathBuf,
    /// One-based line number (one for the high-water file). Zero denotes a
    /// skipped non-regular monthly entry.
    pub line: u64,
}

/// Open writer, sender and nonfatal recovery diagnostics.
pub struct OpenedLog {
    /// Owns the worker and writer lock.
    pub log: EventLog,
    /// Sender for the opened writer.
    pub handle: LogHandle,
    /// Malformed records, corrupt high-water state and skipped non-regular months.
    pub warnings: Vec<RecoveryWarning>,
}

#[derive(Default)]
struct Gap {
    count: u64,
    first: u64,
    last: u64,
}
#[derive(Default, PartialEq, Eq)]
enum WriterState {
    #[default]
    Running,
    Stopping,
    Abandoned,
    Finished,
}
#[derive(Default)]
struct Queue {
    seq: u64,
    events: VecDeque<Event>,
    gap: Gap,
    dropped: u64,
    failure: bool,
    failure_seq: Option<u64>,
    state: WriterState,
    flushed: Option<u64>,
    flush_requested: bool,
}
struct Shared {
    queue: Mutex<Queue>,
    complete: Condvar,
    wake: SyncSender<()>,
    gateway: Identifier,
    committed: AtomicU64,
    clock: Clock,
    capacity: usize,
    persistent: bool,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn event(
        &self,
        queue: &mut Queue,
        kind: EventKind,
        actor: Actor,
        config_version: Option<u64>,
    ) -> Result<Event, SequenceExhausted> {
        queue.seq = queue.seq.checked_add(1).ok_or(SequenceExhausted)?;
        Ok(Event {
            seq: queue.seq,
            at: (self.clock)(),
            kind,
            actor,
            gateway: self.gateway.clone(),
            config_version,
        })
    }
    fn reserve(&self, queue: &mut Queue) {
        if queue.events.len() >= self.capacity {
            // Keep the one outage marker even when newer events displace history.
            let index = queue
                .events
                .iter()
                .position(|e| Some(e.seq) != queue.failure_seq)
                .unwrap_or(0);
            if let Some(event) = queue.events.remove(index) {
                queue.dropped += 1;
                let (count, first, last) = match event.kind {
                    EventKind::EventGap {
                        dropped,
                        first_seq,
                        last_seq,
                        ..
                    } => (dropped + 1, first_seq, last_seq.max(event.seq)),
                    _ => (1, event.seq, event.seq),
                };
                queue.gap.first = if queue.gap.count == 0 {
                    first
                } else {
                    queue.gap.first.min(first)
                };
                queue.gap.last = queue.gap.last.max(last);
                queue.gap.count += count;
            }
        }
    }
    fn enqueue(&self, queue: &mut Queue, event: Event) {
        self.reserve(queue);
        queue.events.push_back(event);
        let _ = self.wake.try_send(());
    }
    fn failed(&self) {
        let mut queue = self.lock();
        if !queue.failure {
            queue.failure = true;
            let event = self.event(
                &mut queue,
                EventKind::PersistenceFailed {
                    reason: Reason::EventWrite,
                },
                Actor::Daemon,
                None,
            );
            if let Ok(event) = event {
                queue.failure_seq = Some(event.seq);
                self.enqueue(&mut queue, event);
            }
        }
        self.complete.notify_all();
    }
    fn gap_note(&self, queue: &mut Queue) {
        if queue.gap.count != 0 {
            self.reserve(queue);
            let gap = std::mem::take(&mut queue.gap);
            let event = self.event(
                queue,
                EventKind::EventGap {
                    reason: Reason::QueueOverflow,
                    dropped: gap.count,
                    first_seq: gap.first,
                    last_seq: gap.last,
                },
                Actor::Daemon,
                None,
            );
            if let Ok(event) = event {
                self.enqueue(queue, event);
            }
        }
    }
}

/// Owns the audit writer thread and its exclusive per-root writer lock.
///
/// The owner must call [`LogHandle::flush_blocking`] before drop for a clean
/// marker; the daemon does this on normal shutdown. Drop has a one-second budget.
/// Unclean opens durably advance the high-water before assigning identities.
/// Across disk-backed runs, uniqueness holds while one run assigns fewer than
/// 2^24 sequences without a durable checkpoint. Memory-only identities are
/// local to that fallback instance and have no cross-restart uniqueness promise.
pub struct EventLog {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
/// Cloneable bounded memory sender. No method except `flush_blocking` waits on I/O.
///
/// The owner must call [`Self::flush_blocking`] before dropping [`EventLog`] for
/// a clean marker. See [`EventLog`] for the sequence uniqueness bound.
#[derive(Clone)]
pub struct LogHandle {
    shared: Arc<Shared>,
}
impl EventLog {
    /// Recovers sequence state, truncates torn tails, and starts the writer.
    /// The supplied root is normally `/var/lib/scupper`.
    /// Waits up to five seconds for the previous instance's writer lock.
    ///
    /// # Errors
    /// Returns lock, recovery or thread-start errors. An unreadable audit history
    /// is refused because assigning a fresh sequence would risk reusing identities.
    /// Malformed record heads are returned as warnings, and unknown kinds are
    /// accepted during recovery. A corrupt high-water file is a warning and
    /// forces an unclean jump. Failure to persist the open-time high-water
    /// reservation returns [`OpenError::Reservation`] before any assignment.
    /// Sequence exhaustion returns a typed error.
    pub fn open(
        root: &Path,
        gateway: GatewayId,
        clock: impl Fn() -> UnixSeconds + Send + Sync + 'static,
    ) -> Result<OpenedLog, OpenError> {
        Self::start(
            root,
            gateway,
            Arc::new(clock),
            CAPACITY,
            Arc::new(|_| Ok(())),
        )
    }

    /// Keeps events in the bounded memory ring without accessing the filesystem.
    /// A `PersistenceFailed` event is queued and the committed watermark stays
    /// zero. Flush returns `NotConnected`; no clean marker can be written.
    /// 2o uses this on [`Self::open`] failure to keep the safety loop running,
    /// and retries `open` later. Fallback identities are local to this instance;
    /// callers must use only committed disk-backed sequences as durable cursors.
    ///
    /// # Errors
    /// Returns [`OpenError::InvalidGateway`] for an invalid gateway identifier.
    pub fn memory_only(
        gateway: GatewayId,
        clock: impl Fn() -> UnixSeconds + Send + Sync + 'static,
    ) -> Result<OpenedLog, OpenError> {
        let opened = Self::memory_buffer(gateway, clock)?;
        opened.handle.shared.failed();
        Ok(opened)
    }

    /// Planned memory-first startup: no persistence failure has occurred yet.
    pub(crate) fn memory_buffer(
        gateway: GatewayId,
        clock: impl Fn() -> UnixSeconds + Send + Sync + 'static,
    ) -> Result<OpenedLog, OpenError> {
        let gateway = Identifier::try_from(gateway.0).map_err(|_| OpenError::InvalidGateway)?;
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                events: VecDeque::with_capacity(CAPACITY),
                ..Queue::default()
            }),
            complete: Condvar::new(),
            wake: mpsc::sync_channel(1).0,
            gateway,
            committed: AtomicU64::new(0),
            clock: Arc::new(clock),
            capacity: CAPACITY,
            persistent: false,
        });
        Ok(OpenedLog {
            log: Self {
                shared: shared.clone(),
                thread: None,
            },
            handle: LogHandle { shared },
            warnings: Vec::new(),
        })
    }

    /// Opens with an append/checkpoint fault hook for integration testing.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::open`].
    #[cfg(any(test, feature = "testing"))]
    pub fn open_with_hook(
        root: &Path,
        gateway: GatewayId,
        clock: impl Fn() -> UnixSeconds + Send + Sync + 'static,
        capacity: usize,
        hook: impl Fn(EventIoStep) -> io::Result<()> + Send + Sync + 'static,
    ) -> Result<OpenedLog, OpenError> {
        Self::start(
            root,
            gateway,
            Arc::new(clock),
            capacity.max(2),
            Arc::new(hook),
        )
    }

    fn start(
        root: &Path,
        gateway: GatewayId,
        clock: Clock,
        capacity: usize,
        hook: Hook,
    ) -> Result<OpenedLog, OpenError> {
        let gateway = Identifier::try_from(gateway.0).map_err(|_| OpenError::InvalidGateway)?;
        let directory = root.join("events");
        durable_directory(&directory)?;
        // Separate from the safety writer lock: audit I/O cannot hold that lock.
        let guard = WriterLock::acquire_timeout(&directory, Duration::from_secs(5))?;
        RealFs.cleanup_stale(&directory)?;
        let recovery = recover(&directory, &gateway)?;
        let clean = directory.join("clean");
        RealFs.check_target(&clean)?;
        let marker_present = match fs::remove_file(&clean) {
            Ok(()) => {
                RealFs.sync_dir(&directory)?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let was_clean = (marker_present || recovery.fresh) && !recovery.corrupt_highwater;
        let base = recovery.seq;
        let (seq, checkpointed) = recovery.reserve_sequence(&directory, was_clean, &hook)?;
        let (wake, receiver) = mpsc::sync_channel(1);
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                seq,
                events: VecDeque::with_capacity(capacity),
                ..Queue::default()
            }),
            complete: Condvar::new(),
            wake,
            gateway,
            committed: AtomicU64::new(recovery.last_logged),
            clock,
            capacity,
            persistent: true,
        });
        let handle = LogHandle {
            shared: shared.clone(),
        };
        if !was_clean || base > recovery.last_logged {
            let _ = handle.emit(
                EventKind::EventGap {
                    reason: if was_clean {
                        Reason::Recovery
                    } else {
                        Reason::UncleanStop
                    },
                    dropped: seq - recovery.last_logged,
                    first_seq: recovery.last_logged + 1,
                    last_seq: seq,
                },
                Actor::Boot,
                None,
            );
        }
        if recovery.torn || !recovery.warnings.is_empty() {
            let _ = handle.emit(
                EventKind::Boot {
                    result: Outcome::Recovered,
                    step: StepKind::EventLog,
                },
                Actor::Boot,
                None,
            );
        }
        // Keep the first recovery record outside the evictable queue so a
        // producer burst cannot displace the required UncleanStop gap.
        let first_event = shared.lock().events.pop_front();
        let worker = shared.clone();
        let thread = thread::Builder::new()
            .name("scupper-events".into())
            .spawn(move || {
                run(
                    &worker,
                    &receiver,
                    Disk {
                        directory,
                        hook,
                        pending: None,
                        unsynced_create: false,
                        retention_failed: false,
                        last_written: recovery.last_logged,
                        since_checkpoint: 0,
                        checkpointed,
                        _guard: guard,
                    },
                    first_event,
                );
            })?;
        Ok(OpenedLog {
            log: Self {
                shared,
                thread: Some(thread),
            },
            handle,
            warnings: recovery.warnings,
        })
    }
}
impl Drop for EventLog {
    fn drop(&mut self) {
        if self.thread.is_none() {
            self.shared.lock().state = WriterState::Finished;
            self.shared.complete.notify_all();
            return;
        }
        // A hung filesystem must not hold up shutdown. The detached worker keeps
        // the writer lock and removes any late clean marker before releasing it.
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut queue = self.shared.lock();
        queue.state = WriterState::Stopping;
        queue.flush_requested = true;
        let _ = self.shared.wake.try_send(());
        while queue.state != WriterState::Finished {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                queue.state = WriterState::Abandoned;
                break;
            }
            (queue, _) = self
                .shared
                .complete
                .wait_timeout(queue, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(queue);
        if let Some(thread) = self.thread.take().filter(JoinHandle::is_finished) {
            let _ = thread.join();
        }
    }
}

impl LogHandle {
    pub(crate) fn persistence_failed(&self) {
        self.shared.failed();
    }

    /// Assigns a unique sequence and enqueues without disk I/O or a capacity wait.
    /// Overflow discards the oldest buffered event and records a bounded gap note.
    ///
    /// # Errors
    /// Returns an error after shutdown or instead of wrapping an audit identity.
    pub fn emit(
        &self,
        kind: EventKind,
        actor: Actor,
        config_version: Option<u64>,
    ) -> Result<u64, EmitError> {
        let mut queue = self.shared.lock();
        if queue.state != WriterState::Running {
            queue.dropped = queue.dropped.saturating_add(1);
            return Err(EmitError::Stopped);
        }
        let event = self.shared.event(&mut queue, kind, actor, config_version)?;
        let seq = event.seq;
        self.shared.enqueue(&mut queue, event);
        Ok(seq)
    }
    /// Whether this sender has a disk worker.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        self.shared.persistent
    }

    /// Replay a memory-only ring into a newly opened disk log with fresh IDs.
    /// The leading `MemoryReplay` note identifies only the memory-local interval.
    /// Records retain their original timestamps, order, kind, actor and version.
    ///
    /// # Errors
    /// Returns stopped/sequence exhaustion errors. Call only from the tick owner
    /// after all producers have been quiesced, then replace their handles.
    pub fn replay_into(&self, disk: &Self) -> Result<(), EmitError> {
        let queue = self.shared.lock();
        if self.shared.persistent || !disk.shared.persistent {
            return Err(EmitError::Stopped);
        }
        let mut target = disk.shared.lock();
        // Local IDs have their own space and never describe a gap on disk.
        let replayed = queue
            .events
            .iter()
            .filter(|e| !matches!(e.kind, EventKind::EventGap { .. }))
            .count() as u64;
        let note = disk.shared.event(
            &mut target,
            EventKind::MemoryReplay {
                dropped: queue.dropped,
                local_first: u64::from(queue.seq > 0),
                local_last: queue.seq,
                replayed,
            },
            Actor::Daemon,
            None,
        )?;
        disk.shared.enqueue(&mut target, note);
        for event in &queue.events {
            if matches!(event.kind, EventKind::EventGap { .. }) {
                continue;
            }
            let mut replay = disk.shared.event(
                &mut target,
                event.kind.clone(),
                event.actor.clone(),
                event.config_version,
            )?;
            replay.at = event.at;
            disk.shared.enqueue(&mut target, replay);
        }
        Ok(())
    }

    /// Highest committed event sequence. Advances only after the line and any
    /// newly created directory entry have been synchronized successfully.
    /// Pass this bound to [`read_since`] for alert and other cursor consumers.
    #[must_use]
    pub fn committed_seq(&self) -> u64 {
        self.shared.committed.load(Ordering::Acquire)
    }

    /// Total events discarded from the buffer or refused after shutdown since open.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.lock().dropped
    }

    /// Waits until preceding events (and any gap note) and high-water are durable.
    /// Intended only for clean shutdown and tests; never use on a safety path.
    ///
    /// # Errors
    /// Returns `TimedOut` if persistence cannot complete within the deadline,
    /// or `NotConnected` for a memory-only log.
    pub fn flush_blocking(&self, timeout: Duration) -> io::Result<()> {
        if !self.shared.persistent {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "event log has no persistence worker",
            ));
        }
        let start = Instant::now();
        let mut queue = self.shared.lock();
        let target = queue.seq;
        queue.flush_requested = true;
        let _ = self.shared.wake.try_send(());
        loop {
            if queue.flushed.is_some_and(|seq| seq >= target)
                && queue.gap.count == 0
                && !queue.failure
            {
                return Ok(());
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "event log flush timed out",
                ));
            }
            let (next, _) = self
                .shared
                .complete
                .wait_timeout(queue, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queue = next;
        }
    }
}

struct Pending {
    seq: u64,
    start: u64,
}
struct Disk {
    directory: PathBuf,
    hook: Hook,
    pending: Option<Pending>,
    unsynced_create: bool,
    retention_failed: bool,
    last_written: u64,
    since_checkpoint: u64,
    checkpointed: u64,
    _guard: WriterGuard,
}
impl Disk {
    fn append(&mut self, event: &Event) -> io::Result<()> {
        // Replay can jump over a long outage's local sequence space. Reserve
        // that jump before appending, preserving the unclean-restart guarantee.
        if event.seq.saturating_sub(self.checkpointed) >= UNCLEAN_SEQ_JUMP {
            self.checkpoint(event.seq)?;
        }
        if self.last_written >= event.seq {
            return Ok(());
        }
        let path = self.directory.join(month_name(event.at));
        RealFs.check_target(&path)?;
        let created = !path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o640)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
            .open(&path)?;
        // Record this before permissions, metadata, or even the fault hook can
        // fail. Retrying an existing file must still sync its directory entry.
        self.unsynced_create |= created;
        if created {
            (self.hook)(EventIoStep::MonthCreated)?;
        }
        file.set_permissions(fs::Permissions::from_mode(0o640))?;
        let start = file.metadata()?.len();
        let pending = self.pending.get_or_insert(Pending {
            seq: event.seq,
            start,
        });
        if pending.seq != event.seq {
            return Err(io::Error::other("event append identity changed"));
        }
        // Roll back even a complete but unacknowledged write before retrying.
        // This avoids duplicate lines after partial writes or fsync failures.
        file.set_len(pending.start)?;
        file.seek(SeekFrom::Start(pending.start))?;
        let mut bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
        bytes.push(b'\n');
        (self.hook)(EventIoStep::Write)?;
        file.write_all(&bytes)?;
        (self.hook)(EventIoStep::FileSync)?;
        file.sync_all()?;
        // Preserve the create obligation across a failed directory sync.
        if self.unsynced_create {
            (self.hook)(EventIoStep::DirectorySync)?;
            RealFs.sync_dir(&self.directory)?;
            self.unsynced_create = false;
        }
        self.pending = None;
        self.last_written = event.seq;
        self.since_checkpoint += 1;
        Ok(())
    }
    fn checkpoint(&mut self, seq: u64) -> io::Result<()> {
        if seq == self.checkpointed {
            self.since_checkpoint = 0;
            return Ok(());
        }
        (self.hook)(EventIoStep::Checkpoint)?;
        durable_replace(
            &RealFs,
            &self.directory.join("seq"),
            format!("{seq}\n").as_bytes(),
            0o640,
            &|_| Ok(()),
            &|_| Ok(()),
        )?;
        self.since_checkpoint = 0;
        self.checkpointed = seq;
        Ok(())
    }
}
fn run(shared: &Shared, receiver: &Receiver<()>, mut disk: Disk, first_event: Option<Event>) {
    run_writer(shared, receiver, &mut disk, first_event);
    let mut queue = shared.lock();
    if queue.state == WriterState::Abandoned {
        drop(queue);
        // A timed-out Drop may race an in-flight clean-marker fsync. Keep the
        // lock until cleanup finishes, so the next successful open is unclean.
        let _ = fs::remove_file(disk.directory.join("clean"));
        let _ = RealFs.sync_dir(&disk.directory);
        queue = shared.lock();
    }
    drop(disk);
    queue.state = WriterState::Finished;
    shared.complete.notify_all();
}

fn run_writer(
    shared: &Shared,
    receiver: &Receiver<()>,
    disk: &mut Disk,
    first_event: Option<Event>,
) {
    let mut current = first_event;
    let mut delay = Duration::from_millis(10);
    loop {
        if shared.lock().state == WriterState::Abandoned {
            return;
        }
        if current.is_none() {
            let mut queue = shared.lock();
            shared.gap_note(&mut queue);
            current = queue.events.pop_front();
        }
        let result = if let Some(event) = &current {
            disk.append(event).and_then(|()| {
                shared.committed.fetch_max(event.seq, Ordering::Release);
                if disk.since_checkpoint >= 100 {
                    let seq = shared.lock().seq;
                    disk.checkpoint(seq)?;
                    maintain_retention(shared, disk);
                }
                Ok(())
            })
        } else {
            let (seq, flush, stop) = {
                let queue = shared.lock();
                (
                    queue.seq,
                    queue.flush_requested || queue.failure,
                    queue.state != WriterState::Running,
                )
            };
            let result = if flush {
                disk.checkpoint(seq)
                    .map(|()| maintain_retention(shared, disk))
            } else {
                if disk.retention_failed {
                    maintain_retention(shared, disk);
                }
                Ok(())
            };
            if result.is_ok() {
                let mut queue = shared.lock();
                if queue.seq == seq
                    && queue.events.is_empty()
                    && queue.gap.count == 0
                    && disk.checkpointed >= seq
                {
                    queue.flushed = Some(seq);
                    queue.flush_requested = false;
                    queue.failure = false;
                    queue.failure_seq = None;
                    shared.complete.notify_all();
                    if stop {
                        drop(queue);
                        // Final flush and high-water precede the durable marker.
                        let clean = disk.directory.join("clean");
                        if durable_replace(
                            &RealFs,
                            &clean,
                            b"clean\n",
                            0o640,
                            &|_| Ok(()),
                            &|step| {
                                if step == DurableStep::Renamed {
                                    (disk.hook)(EventIoStep::CleanMarkerSync)?;
                                }
                                Ok(())
                            },
                        )
                        .is_err()
                        {
                            let _ = fs::remove_file(&clean);
                            let _ = RealFs.sync_dir(&disk.directory);
                        }
                        return;
                    }
                }
            }
            result
        };
        if result.is_ok() {
            delay = Duration::from_millis(10);
            if current.take().is_none() {
                let _ = receiver.recv_timeout(Duration::from_secs(1));
            }
        } else {
            if shared.lock().state != WriterState::Running {
                return;
            }
            shared.failed();
            let start = Instant::now();
            while start.elapsed() < delay && shared.lock().state == WriterState::Running {
                let _ = receiver.recv_timeout(delay.saturating_sub(start.elapsed()));
            }
            delay = (delay * 2).min(Duration::from_secs(1));
        }
    }
}

// Retention follows checkpoints (every 100 records or an explicit flush),
// rather than forcing a high-water rewrite for every append to a large month.
fn maintain_retention(shared: &Shared, disk: &mut Disk) {
    let failed = try_retention(shared, disk).is_err();
    if failed && !disk.retention_failed {
        eprintln!("event log: retention maintenance failed");
        // Maintenance diagnostics must not hold the current append or mark the
        // persistence queue failed. Retry on later checkpoints or idle ticks.
        let mut queue = shared.lock();
        if let Ok(event) = shared.event(
            &mut queue,
            EventKind::Repair {
                kind: StepKind::EventLog,
                class: scupper_proto::RepairClass::Tighten,
                result: Outcome::Failed,
            },
            Actor::Daemon,
            None,
        ) {
            shared.enqueue(&mut queue, event);
        }
    }
    disk.retention_failed = failed;
}

fn try_retention(shared: &Shared, disk: &Disk) -> io::Result<()> {
    (disk.hook)(EventIoStep::Retention)?;
    if retention_needed(&disk.directory, MAX_MONTHS, MAX_SIZE)? {
        retain(
            &disk.directory,
            &month_name((shared.clock)()),
            MAX_MONTHS,
            MAX_SIZE,
        )?;
    }
    Ok(())
}

// Civil date conversion from days since 1970-01-01, Gregorian UTC, no clock or
// timezone dependency. All intermediates fit i64 even for u64 Unix seconds.
fn month_name(at: UnixSeconds) -> String {
    let days = i64::try_from(at.0 / 86_400).unwrap_or(i64::MAX) + 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    format!("{year:04}-{month:02}.jsonl")
}
fn month_key(name: &str) -> Option<(u64, u8)> {
    let (year, month) = name.strip_suffix(".jsonl")?.split_once('-')?;
    if year.len() < 4
        || month.len() != 2
        || !year.bytes().all(|c| c.is_ascii_digit())
        || !month.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let month: u8 = month.parse().ok()?;
    (1..=12)
        .contains(&month)
        .then_some((year.parse().ok()?, month))
}
fn monthly_files(directory: &Path) -> io::Result<Vec<PathBuf>> {
    monthly_files_warn(directory, &mut Vec::new())
}
fn monthly_files_warn(
    directory: &Path,
    warnings: &mut Vec<RecoveryWarning>,
) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(files),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_str().and_then(month_key).is_some() {
            if !entry.file_type()?.is_file() {
                eprintln!(
                    "event log: skipping non-regular month {}",
                    entry.path().display()
                );
                warnings.push(RecoveryWarning {
                    path: entry.path(),
                    line: 0,
                });
                continue;
            }
            RealFs.check_target(&entry.path())?;
            files.push(entry.path());
        }
    }
    files.sort_by_key(|path| {
        path.file_name()
            .and_then(|n| n.to_str())
            .and_then(month_key)
    });
    Ok(files)
}
#[derive(Deserialize)]
struct Head {
    seq: u64,
    gateway: Identifier,
}
struct Recovery {
    seq: u64,
    last_logged: u64,
    highwater: u64,
    fresh: bool,
    corrupt_highwater: bool,
    torn: bool,
    warnings: Vec<RecoveryWarning>,
}
impl Recovery {
    // Reserve before constructing Shared or assigning even the recovery events.
    fn reserve_sequence(
        &self,
        directory: &Path,
        was_clean: bool,
        hook: &Hook,
    ) -> Result<(u64, u64), OpenError> {
        // Leave room for the gap and at least one following event.
        let next = if was_clean {
            self.seq.checked_add(1)
        } else {
            self.seq.checked_add(UNCLEAN_SEQ_JUMP)
        }
        .filter(|next| *next < u64::MAX)
        .ok_or(SequenceExhausted)?;
        let seq = next - 1;
        let mut checkpointed = self.highwater;
        // Even a fresh open must leave durable evidence of this run: otherwise
        // a crash before the first month creation would look fresh again.
        if !was_clean || self.fresh {
            let reserve = || {
                (hook)(EventIoStep::OpenCheckpoint)?;
                durable_replace(
                    &RealFs,
                    &directory.join("seq"),
                    format!("{seq}\n").as_bytes(),
                    0o640,
                    &|_| Ok(()),
                    &|step| {
                        if step == DurableStep::Renamed {
                            (hook)(EventIoStep::OpenCheckpointSync)?;
                        }
                        Ok(())
                    },
                )
            };
            reserve().map_err(OpenError::Reservation)?;
            checkpointed = seq;
        }
        Ok((seq, checkpointed))
    }
}
fn recover(directory: &Path, gateway: &Identifier) -> Result<Recovery, OpenError> {
    let seq_path = directory.join("seq");
    let (highwater, missing, corrupt_highwater) = match RealFs.read(&seq_path) {
        Ok(text) => match text.trim_end_matches('\n').parse() {
            Ok(seq) => (seq, false, false),
            Err(_) => (0, false, true),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => (0, true, false),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => (0, false, true),
        Err(error) => return Err(error.into()),
    };
    let mut skipped = Vec::new();
    let files = monthly_files_warn(directory, &mut skipped)?;
    let mut recovery = Recovery {
        seq: highwater,
        highwater,
        fresh: missing && files.is_empty(),
        corrupt_highwater,
        last_logged: 0,
        torn: false,
        warnings: if corrupt_highwater {
            vec![RecoveryWarning {
                path: seq_path,
                line: 1,
            }]
        } else {
            Vec::new()
        },
    };
    recovery.warnings.extend(skipped);
    for path in files {
        let mut reader = BufReader::new(File::open(&path)?);
        let mut offset = 0;
        let mut number = 0;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            number += 1;
            if !line.ends_with(b"\n") {
                let file = OpenOptions::new().write(true).open(&path)?;
                file.set_len(offset)?;
                file.sync_all()?;
                recovery.torn = true;
                break;
            }
            match serde_json::from_slice::<Head>(&line) {
                Ok(head) => {
                    if &head.gateway != gateway {
                        return Err(OpenError::GatewayMismatch);
                    }
                    recovery.seq = recovery.seq.max(head.seq);
                    recovery.last_logged = recovery.last_logged.max(head.seq);
                }
                Err(_) => recovery.warnings.push(RecoveryWarning {
                    path: path.clone(),
                    line: number,
                }),
            }
            offset += line.len() as u64;
        }
        // A preceding process may have stopped after write but before fsync.
        // Publish recovered records only after making them durable here.
        reader.get_ref().sync_all()?;
    }
    RealFs.sync_dir(directory)?;
    Ok(recovery)
}
fn retention_needed(directory: &Path, max_months: usize, max_size: u64) -> io::Result<bool> {
    let files = monthly_files(directory)?;
    let total = files.iter().try_fold(0u64, |sum, file| {
        fs::metadata(file).map(|m| sum.saturating_add(m.len()))
    })?;
    Ok(files.len() > max_months || total > max_size)
}
fn retain(directory: &Path, current: &str, max_months: usize, max_size: u64) -> io::Result<()> {
    let files = monthly_files(directory)?;
    let mut count = files.len();
    let mut total = files.iter().try_fold(0u64, |sum, file| {
        fs::metadata(file).map(|m| sum.saturating_add(m.len()))
    })?;
    let newest = files
        .iter()
        .rev()
        .find(|file| fs::metadata(file).is_ok_and(|m| m.len() > 0))
        .cloned();
    let mut removed = false;
    for file in files {
        if count <= max_months && total <= max_size {
            break;
        }
        if newest.as_ref() == Some(&file) || file.file_name().is_some_and(|name| name == current) {
            continue;
        }
        let size = fs::metadata(&file)?.len();
        fs::remove_file(file)?;
        removed = true;
        count -= 1;
        total = total.saturating_sub(size);
    }
    if removed {
        RealFs.sync_dir(directory)?;
    }
    Ok(())
}

/// Reads complete records in `(after, up_to]` across retained months.
/// In-process consumers must pass `Some(handle.committed_seq())`: complete lines
/// on disk above that watermark may be lost even when a read succeeds. `None`
/// permits best-effort inspection of uncommitted data.
/// A torn tail is ignored. Errors name the file and one-based line (or byte
/// offset for tail I/O), and do not prevent scanning subsequent files. Records
/// are sorted by sequence, even after a clock change; errors follow the records.
/// Old months are skipped using their last complete record, read from the tail.
/// The selected records are materialized; missing directories yield no records.
pub fn read_since(
    root: &Path,
    after: u64,
    up_to: Option<u64>,
) -> impl Iterator<Item = io::Result<Event>> {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    match monthly_files_for_read(&root.join("events")) {
        Ok(files) => {
            for entry in files {
                let path = match entry {
                    Ok(path) => path,
                    Err(error) => {
                        errors.push(Err(error));
                        continue;
                    }
                };
                if let Err(error) = read_month(&path, after, up_to, &mut records, &mut errors) {
                    errors.push(Err(error));
                }
            }
        }
        Err(error) => errors.push(Err(error)),
    }
    records.sort_by_key(|event| event.seq);
    records.into_iter().map(Ok).chain(errors)
}

/// One incremental audit record, with undecodable complete lines represented explicitly.
pub enum TailRecord {
    /// Decoded event.
    Event(Event),
    /// Undecodable record's sequence, or zero if its header was also malformed.
    Skipped(u64),
}
/// Per-worker file offsets. Reads only newly appended, committed lines.
#[derive(Default)]
pub struct Tail {
    offsets: std::collections::BTreeMap<PathBuf, u64>,
}
impl Tail {
    /// Read committed records and advance offsets, retaining uncommitted/torn tails.
    /// # Errors
    /// Returns local event-log I/O failures, never decoding failures.
    pub fn read(&mut self, root: &Path, after: u64, upper: u64) -> io::Result<Vec<TailRecord>> {
        let mut records = Vec::new();
        let files = monthly_files_for_read(&root.join("events"))?;
        let mut retained = std::collections::BTreeSet::new();
        for path in files {
            let path = path?;
            retained.insert(path.clone());
            RealFs.check_target(&path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                        .bits()
                        .cast_signed(),
                )
                .open(&path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::other("event month is not a regular file"));
            }
            let offset = self.offsets.entry(path).or_default();
            if *offset > file.metadata()?.len() {
                *offset = 0;
            }
            file.seek(SeekFrom::Start(*offset))?;
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            loop {
                line.clear();
                let len = reader.read_until(b'\n', &mut line)?;
                if len == 0 || !line.ends_with(b"\n") {
                    break;
                }
                let head = serde_json::from_slice::<Head>(&line).ok();
                if head.as_ref().is_some_and(|h| h.seq > upper) {
                    break;
                }
                *offset += len as u64;
                if head.as_ref().is_some_and(|h| h.seq <= after) {
                    continue;
                }
                records.push(match serde_json::from_slice::<Event>(&line) {
                    Ok(event) => TailRecord::Event(event),
                    Err(_) => TailRecord::Skipped(head.map_or(0, |h| h.seq)),
                });
            }
        }
        self.offsets.retain(|p, _| retained.contains(p));
        records.sort_by_key(|r| match r {
            TailRecord::Event(e) => e.seq,
            TailRecord::Skipped(seq) => *seq,
        });
        Ok(records)
    }
}

fn located(path: &Path, position: impl std::fmt::Display, error: &io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{}:{position}: {error}", path.display()),
    )
}

fn monthly_files_for_read(directory: &Path) -> io::Result<Vec<io::Result<PathBuf>>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(located(directory, "directory", &error)),
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) if entry.file_name().to_str().and_then(month_key).is_some() => {
                paths.push(Ok(entry.path()));
            }
            Ok(_) => {}
            Err(error) => paths.push(Err(located(directory, "directory entry", &error))),
        }
    }
    Ok(paths)
}

fn read_month(
    path: &Path,
    after: u64,
    up_to: Option<u64>,
    records: &mut Vec<Event>,
    errors: &mut Vec<io::Result<Event>>,
) -> io::Result<()> {
    let mut file = (|| {
        RealFs.check_target(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                    .bits()
                    .cast_signed(),
            )
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("event month is not a regular file"));
        }
        Ok(file)
    })()
    .map_err(|error| located(path, "open", &error))?;
    if last_head(&mut file)
        .map_err(|e| located(path, "tail", &e))?
        .is_some_and(|head| head.seq <= after)
    {
        return Ok(());
    }
    file.rewind().map_err(|e| located(path, "rewind", &e))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut number = 0;
    loop {
        line.clear();
        let len = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| located(path, number + 1, &e))?;
        if len == 0 || !line.ends_with(b"\n") {
            break;
        }
        number += 1;
        // Unknown future kinds outside the requested range need not be decoded.
        if serde_json::from_slice::<Head>(&line)
            .is_ok_and(|h| h.seq <= after || up_to.is_some_and(|upper| h.seq > upper))
        {
            continue;
        }
        match serde_json::from_slice::<Event>(&line) {
            Ok(event) if event.seq > after && up_to.is_none_or(|upper| event.seq <= upper) => {
                records.push(event);
            }
            Ok(_) => {}
            Err(error) => errors.push(Err(located(path, number, &io::Error::other(error)))),
        }
    }
    Ok(())
}

// Read backwards in chunks. Only the last complete line is parsed; torn bytes
// after its newline do not affect cursor seeking. A malformed tail disables the
// optimization so the full scan can report it with its precise line number.
fn last_head(file: &mut File) -> io::Result<Option<Head>> {
    let mut offset = file.metadata()?.len();
    let mut record_end = None;
    let mut chunk = [0; 4096];
    while offset > 0 {
        let start = offset.saturating_sub(chunk.len() as u64);
        let len = usize::try_from(offset - start).map_err(io::Error::other)?;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk[..len])?;
        for index in (0..len).rev().filter(|&i| chunk[i] == b'\n') {
            let position = start + index as u64;
            if let Some(end) = record_end {
                return head_between(file, position + 1, end);
            }
            record_end = Some(position);
        }
        offset = start;
    }
    record_end.map_or(Ok(None), |end| head_between(file, 0, end))
}

fn head_between(file: &mut File, start: u64, end: u64) -> io::Result<Option<Head>> {
    file.seek(SeekFrom::Start(start))?;
    let mut line = Vec::new();
    file.take(end - start).read_to_end(&mut line)?;
    Ok(serde_json::from_slice(&line).ok())
}

#[cfg(test)]
mod tests;
