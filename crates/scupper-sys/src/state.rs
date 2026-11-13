//! Strict, crash-safe persistence of operator selection and quarantine.

pub use crate::fs::DurableStep;
use crate::{
    fs::{Fs, RealFs, durable_directory, durable_replace},
    lock::WriterGuard,
};
pub use scupper_core::verdict::v2::Selection;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Persisted safety latch; consumers must honor it before enabling forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// Why the repair budget was exhausted.
    pub reason: String,
    /// The object whose recurring drift triggered quarantine.
    pub object: String,
    /// Unix seconds when the latch was set.
    pub since_unix: u64,
    /// Failed persistence or unreadable latch evidence; connect may clear this.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub uncertain: bool,
}

/// Write-ahead repair history, independent of the main state replacement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepairState {
    /// Unix seconds per attempt; legacy count-only checkpoints carry no live history.
    #[serde(default)]
    pub attempts_unix: std::collections::BTreeMap<String, Vec<u64>>,
    /// A restore is in flight; this never constitutes a quarantine latch.
    pub armed: bool,
    /// A quarantine whose main state replacement may have failed.
    pub quarantine: Option<Quarantine>,
}
impl RepairState {
    /// Only a recorded latch survives startup; counts and in-flight restores do not latch.
    #[must_use]
    pub fn startup_latch(&self) -> Option<Quarantine> {
        self.latch()
    }
    /// A checkpointed latch may precede a failed main-state replacement.
    #[must_use]
    pub fn latch(&self) -> Option<Quarantine> {
        self.quarantine.clone().map(|mut q| {
            q.uncertain = true;
            q
        })
    }
}

/// Missing legacy checkpoints carry no latch evidence; unreadable ones fail closed.
#[derive(Debug, Clone)]
pub enum RepairStateRead {
    /// No repair record exists.
    Missing,
    /// A readable checkpoint.
    Present(RepairState),
    /// I/O or decoding failed.
    Unreadable,
}
fn uncertain_quarantine() -> Quarantine {
    Quarantine {
        reason: "latch persistence or clearance uncertain; run scupper connect".into(),
        object: "repair-history".into(),
        since_unix: 0,
        uncertain: true,
    }
}

/// On-disk state schema. Missing optional fields are refused, as are unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// The supported state schema, currently 1.
    pub schema: u32,
    /// Convergence target published under closed gates before target boot.
    #[serde(deserialize_with = "required_option")]
    pub applied_version: Option<u64>,
    /// Durable operator selection, including deliberate disconnection.
    pub selection: Selection,
    /// Persistent quarantine latch, cleared only by explicit administrative action.
    #[serde(
        deserialize_with = "required_option",
        serialize_with = "legacy_quarantine"
    )]
    pub quarantine: Option<Quarantine>,
}
// Keep state.json readable by the previous release, whose latch rejects unknown
// fields. Typed uncertainty lives only in repair-state.json.
#[allow(clippy::ref_option)] // Serde serialize_with borrows the complete field.
fn legacy_quarantine<S: serde::Serializer>(
    quarantine: &Option<Quarantine>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct LegacyQuarantine<'a> {
        reason: &'a str,
        object: &'a str,
        since_unix: u64,
    }
    quarantine
        .as_ref()
        .map(|q| LegacyQuarantine {
            reason: &q.reason,
            object: &q.object,
            since_unix: q.since_unix,
        })
        .serialize(serializer)
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: 1,
            applied_version: None,
            selection: Selection::Auto,
            quarantine: None,
        }
    }
}

/// Explicit result of reading the safety state. Absence is never an implicit reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRead {
    /// A complete, validated persisted state.
    Present(State),
    /// No state file exists.
    Missing,
}

/// Boot's fail-closed decision, including the alert required for lost state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootState {
    /// Selection and quarantine to honor before enabling forwarding.
    pub state: State,
    /// Emit an alert: a configured system has lost its durable safety state.
    pub missing_state_alert: bool,
}

impl StateRead {
    /// Resolves absence for boot. With a config head, stay `Disconnected` and
    /// alert; do not persist a replacement that would hide the lost latch.
    /// Only a fresh install (no config head) creates the initial default state,
    /// explicitly using [`StateFile::write`] while holding the global lock.
    #[must_use]
    pub fn for_boot(self, has_config_head: bool) -> BootState {
        match self {
            Self::Present(state) => BootState {
                state,
                missing_state_alert: false,
            },
            Self::Missing => BootState {
                state: State {
                    selection: if has_config_head {
                        Selection::Disconnected
                    } else {
                        Selection::Auto
                    },
                    ..State::default()
                },
                missing_state_alert: has_config_head,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileGeneration {
    device: u64,
    inode: u64,
    modified: (i64, i64),
    size: u64,
}
fn file_generation(path: &Path) -> io::Result<Option<FileGeneration>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(FileGeneration {
            device: m.dev(),
            inode: m.ino(),
            modified: (m.mtime(), m.mtime_nsec()),
            size: m.size(),
        })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
type Snapshot = (StateRead, Option<FileGeneration>);
type PendingJob<T> = (Option<u64>, std::sync::mpsc::Receiver<io::Result<T>>);

// Separate adapters may open the same state file. A path-scoped permit also
// bounds jobs across those handles, including when a handle is dropped mid-read.
#[derive(Debug, Default)]
struct ReadCapacity {
    busy: AtomicBool,
    // Writes invalidate other handles of this file, never unrelated state roots.
    // The writer-lock boundary and metadata check handle other processes.
    generation: AtomicU64,
}
#[derive(Debug)]
struct ReadPermit(Arc<ReadCapacity>);
impl Drop for ReadPermit {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::SeqCst);
    }
}
fn read_capacity(path: &Path) -> Arc<ReadCapacity> {
    static CAPACITIES: OnceLock<Mutex<std::collections::BTreeMap<PathBuf, Weak<ReadCapacity>>>> =
        OnceLock::new();
    let mut capacities = CAPACITIES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    capacities.retain(|_, capacity| capacity.strong_count() > 0);
    if let Some(capacity) = capacities.get(path).and_then(Weak::upgrade) {
        return capacity;
    }
    let capacity = Arc::new(ReadCapacity::default());
    capacities.insert(path.to_path_buf(), Arc::downgrade(&capacity));
    capacity
}

// Resolve existing ancestors as well, so initially absent roots have the same
// process-wide capacity through symlink and dot-component aliases.
fn canonical_root(root: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(root)?;
    match std::fs::canonicalize(&absolute) {
        Ok(path) => Ok(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = absolute.parent().ok_or(e)?;
            Ok(canonical_root(parent)?.join(
                absolute
                    .file_name()
                    .ok_or_else(|| io::Error::other("invalid state root"))?,
            ))
        }
        Err(e) => Err(e),
    }
}

/// State access rooted at `/var/lib/scupper` in production.
#[derive(Debug)]
pub struct StateFile {
    path: PathBuf,
    capacity: Arc<ReadCapacity>,
    pending_read: std::cell::RefCell<Option<PendingJob<Snapshot>>>,
    pending_metadata: std::cell::RefCell<Option<PendingJob<Option<StateRead>>>>,
}
impl StateFile {
    /// Chooses `root/state.json`. A writer guard enables stale-temp cleanup.
    /// No state file is created until an explicit write.
    ///
    /// # Errors
    /// Returns directory or stale-temp cleanup errors when a guard is supplied.
    pub fn open(root: impl AsRef<Path>, writer: Option<&WriterGuard>) -> io::Result<Self> {
        if writer.is_some() {
            durable_directory(root.as_ref())?;
            RealFs.cleanup_stale(root.as_ref())?;
        }
        let path = root.as_ref().join("state.json");
        let capacity = read_capacity(&canonical_root(root.as_ref())?.join("state.json"));
        Ok(Self {
            path,
            capacity,
            pending_read: std::cell::RefCell::new(None),
            pending_metadata: std::cell::RefCell::new(None),
        })
    }

    /// Reads strict schema 1, distinguishing absence from a persisted state.
    ///
    /// # Errors
    /// Returns corrupt JSON, unsupported schema, unsafe target, or I/O errors.
    pub fn read(&self) -> io::Result<StateRead> {
        match RealFs.read(&self.path) {
            Ok(text) => {
                let mut state: State = serde_json::from_str(&text)
                    .map_err(|_| io::Error::other("invalid state.json"))?;
                check_schema(&state)?;
                // Reattach only typed metadata to an existing latch; raw reads
                // never synthesize a quarantine from missing or unreadable state.
                if let Some(main) = &mut state.quarantine
                    && let Some(checkpoint) = self.repair_state().quarantine
                    && checkpoint.uncertain
                    && main.reason == checkpoint.reason
                    && main.object == checkpoint.object
                    && main.since_unix == checkpoint.since_unix
                {
                    main.uncertain = true;
                }
                Ok(StateRead::Present(state))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(StateRead::Missing),
            Err(error) => Err(error),
        }
    }

    /// Read safety state at a process/boot boundary, honoring uncertainty records.
    /// # Errors
    /// Returns main-state read failures. Corrupt or unreadable repair history is latched.
    pub fn startup_read(&self, run_root: &Path) -> io::Result<StateRead> {
        self.safety_read(run_root)
    }

    /// Read current latch uncertainty without interpreting completed budgets as a restart.
    /// # Errors
    /// Returns main-state read errors.
    pub fn safety_read(&self, run_root: &Path) -> io::Result<StateRead> {
        let mut saved = self.read()?;
        if let StateRead::Present(state) = &mut saved {
            let marker = std::fs::symlink_metadata(run_root.join("latch-uncertain"));
            if state.applied_version.is_some() {
                let repair = self.repair_state();
                state.quarantine = state.quarantine.take().or_else(|| {
                    repair.latch().map(|mut q| {
                        q.reason = format!(
                            "latch persistence or clearance uncertain: {}; run scupper connect",
                            q.reason
                        );
                        q
                    })
                });
                if !matches!(marker, Err(ref e) if e.kind() == io::ErrorKind::NotFound) {
                    state
                        .quarantine
                        .get_or_insert_with(uncertain_quarantine)
                        .uncertain = true;
                }
            }
        }
        Ok(saved)
    }

    /// Read the checkpoint without conflating absence and failed observation.
    #[must_use]
    pub fn repair_state_read(&self) -> RepairStateRead {
        match RealFs.read(&self.path.with_file_name("repair-state.json")) {
            Ok(text) => serde_json::from_str(&text)
                .map_or(RepairStateRead::Unreadable, RepairStateRead::Present),
            Err(e) if e.kind() == io::ErrorKind::NotFound => RepairStateRead::Missing,
            Err(_) => RepairStateRead::Unreadable,
        }
    }

    /// Effective repair history: no record is empty, unreadable evidence latches.
    #[must_use]
    pub fn repair_state(&self) -> RepairState {
        match self.repair_state_read() {
            RepairStateRead::Missing => RepairState::default(),
            RepairStateRead::Present(repair) => repair,
            RepairStateRead::Unreadable => RepairState {
                quarantine: Some(uncertain_quarantine()),
                ..RepairState::default()
            },
        }
    }

    /// Establish a legacy checkpoint under the writer lock without changing state.
    /// Returns true exactly when a checkpoint was created, for the migration audit.
    /// # Errors
    /// Returns main-state or durable checkpoint write errors.
    pub fn migrate_repair_state(&self, writer: &WriterGuard, run_root: &Path) -> io::Result<bool> {
        if !matches!(self.repair_state_read(), RepairStateRead::Missing)
            || !matches!(
                self.read()?,
                StateRead::Present(State {
                    applied_version: Some(_),
                    ..
                })
            )
            || !matches!(std::fs::symlink_metadata(run_root.join("latch-uncertain")), Err(e) if e.kind() == io::ErrorKind::NotFound)
        {
            return Ok(false);
        }
        self.write_repair_state(writer, &RepairState::default())?;
        Ok(true)
    }

    /// Persist a repair checkpoint before allowing an automatic restore.
    /// # Errors
    /// Returns serialization, write or durability failures.
    pub fn write_repair_state(
        &self,
        _writer: &WriterGuard,
        repair: &RepairState,
    ) -> io::Result<()> {
        let bytes = serde_json::to_vec(repair).map_err(io::Error::other)?;
        durable_replace(
            &RealFs,
            &self.path.with_file_name("repair-state.json"),
            &bytes,
            0o600,
            &|_| Ok(()),
            &|_| Ok(()),
        )
    }

    /// Record explicit administrative clearance after the main state is durable.
    /// # Errors
    /// Returns checkpoint or runtime-marker removal/durability failures.
    pub fn clear_repair_state(&self, writer: &WriterGuard, run_root: &Path) -> io::Result<()> {
        self.write_repair_state(writer, &RepairState::default())?;
        match std::fs::remove_file(run_root.join("latch-uncertain")) {
            Ok(()) => RealFs.sync_dir(run_root),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Invalidate snapshots at a writer-lock boundary or intent write, retaining
    /// worker ownership until completion so stalled I/O cannot accumulate jobs.
    pub fn invalidate_reads(&self) {
        if let Some((generation, _)) = self.pending_read.borrow_mut().as_mut() {
            *generation = None;
        }
        if let Some((generation, _)) = self.pending_metadata.borrow_mut().as_mut() {
            *generation = None;
        }
    }

    /// Bound a background read by the tick deadline. A pending read survives
    /// timeouts; administrative writes invalidate its potentially stale result.
    /// Calls in the same generation wait on the worker until their own deadline;
    /// calls for an invalidated generation only poll and discard its completion.
    ///
    /// # Errors
    /// Returns read errors or `TimedOut` without waiting for blocked disk I/O.
    pub fn read_until(&self, deadline: std::time::Instant) -> io::Result<StateRead> {
        loop {
            if let Some(state) = self.read_attempt(deadline)? {
                return Ok(state);
            }
        }
    }

    fn snapshot(&self) -> io::Result<Snapshot> {
        let before = file_generation(&self.path)?;
        let state = self.read()?;
        if file_generation(&self.path)? != before {
            return Err(io::Error::other("state changed during read"));
        }
        Ok((state, before))
    }

    fn reserve_worker(&self) -> io::Result<ReadPermit> {
        self.capacity
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "state worker busy"))?;
        Ok(ReadPermit(self.capacity.clone()))
    }

    #[allow(clippy::too_many_lines)] // Keep worker ownership and generation checks together.
    fn read_attempt(&self, deadline: std::time::Instant) -> io::Result<Option<StateRead>> {
        use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
        let timeout = || io::Error::new(io::ErrorKind::TimedOut, "state read deadline");
        if std::time::Instant::now() >= deadline {
            return Err(timeout());
        }
        // A snapshot and phase B share the current generation's worker. Phase B
        // waits to its own deadline; only obsolete generations are polled.
        let mut metadata = self.pending_metadata.borrow_mut();
        if let Some((started, receive)) = metadata.as_ref() {
            let started = *started;
            let result = if started == Some(self.capacity.generation.load(Ordering::SeqCst)) {
                receive.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            } else {
                receive.try_recv().map_err(|error| match error {
                    TryRecvError::Empty => RecvTimeoutError::Timeout,
                    TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
                })
            };
            match result {
                Err(RecvTimeoutError::Timeout) => return Err(timeout()),
                Ok(result) => {
                    *metadata = None;
                    if started == Some(self.capacity.generation.load(Ordering::SeqCst)) {
                        return result;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    *metadata = None;
                    return Err(io::Error::other("state metadata worker stopped"));
                }
            }
        }
        drop(metadata);
        let mut pending = self.pending_read.borrow_mut();
        let generation = self
            .capacity
            .generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let new_worker = pending.is_none();
        if new_worker {
            let permit = self.reserve_worker()?;
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let path = self.path.clone();
            std::thread::Builder::new()
                .name("state-read".into())
                .spawn(move || {
                    let file = Self {
                        path,
                        capacity: permit.0.clone(),
                        pending_read: std::cell::RefCell::new(None),
                        pending_metadata: std::cell::RefCell::new(None),
                    };
                    let result = file.snapshot();
                    drop(permit);
                    let _ = send.send(result);
                })?;
            *pending = Some((Some(generation), receive));
        }
        let (started, receive) = pending
            .as_ref()
            .ok_or_else(|| io::Error::other("missing read worker"))?;
        let started = *started;
        let result = if started == Some(generation) {
            receive.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        } else {
            receive.try_recv().map_err(|error| match error {
                TryRecvError::Empty => RecvTimeoutError::Timeout,
                TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
            })
        };
        match result {
            Ok(result) => {
                *pending = None;
                if started
                    != Some(
                        self.capacity
                            .generation
                            .load(std::sync::atomic::Ordering::SeqCst),
                    )
                {
                    return Ok(None);
                }
                drop(pending);
                let (state, identity) = result?;
                // Metadata verification is itself bounded and its receiver is
                // retained on timeout, just like the state reader's receiver.
                let permit = self.reserve_worker()?;
                let (send, receive) = std::sync::mpsc::sync_channel(1);
                let path = self.path.clone();
                std::thread::Builder::new()
                    .name("state-generation".into())
                    .spawn(move || {
                        let result = file_generation(&path).map(|current| {
                            if current == identity {
                                Some(state)
                            } else {
                                None
                            }
                        });
                        drop(permit);
                        let _ = send.send(result);
                    })?;
                *self.pending_metadata.borrow_mut() = Some((Some(generation), receive));
                // Keep the snapshot with its verification worker so a later
                // phase can reuse it rather than opening the file a second time.
                Ok(None)
            }
            Err(RecvTimeoutError::Timeout) => Err(timeout()),
            Err(RecvTimeoutError::Disconnected) => {
                *pending = None;
                Err(io::Error::other("state read worker stopped"))
            }
        }
    }

    /// Durably replaces the entire state, using mode 0600.
    /// The guard proves the global writer lock is held for this transaction.
    ///
    /// ```compile_fail
    /// # use scupper_sys::state::{StateFile, State};
    /// fn unlocked(file: &StateFile) {
    ///     file.write(&State::default());
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns unsupported schema, serialization, or durability errors. An error
    /// after rename may leave the complete new state visible.
    pub fn write(&self, writer: &WriterGuard, state: &State) -> io::Result<()> {
        self.write_with_hook(writer, state, &|_| Ok(()))
    }

    /// Reads, modifies, and durably writes state under one global writer guard.
    /// Missing state requires an explicit boot/install decision, never a reset.
    ///
    /// # Errors
    /// Returns `NotFound` for missing state, or read/write/schema errors.
    pub fn update(
        &self,
        writer: &WriterGuard,
        change: impl FnOnce(&mut State),
    ) -> io::Result<State> {
        let StateRead::Present(mut state) = self.read()? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "state.json is missing",
            ));
        };
        change(&mut state);
        self.write(writer, &state)?;
        Ok(state)
    }

    /// Writes state with a callback after each completed durability step.
    ///
    /// # Errors
    /// Returns write errors or the injected failure. Before rename the old file
    /// remains; after rename the new file remains.
    pub fn write_with_hook(
        &self,
        writer: &WriterGuard,
        state: &State,
        hook: &dyn Fn(DurableStep) -> io::Result<()>,
    ) -> io::Result<()> {
        self.invalidate_reads();
        self.capacity
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        check_schema(state)?;
        let bytes = serde_json::to_vec(state).map_err(io::Error::other)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("missing state directory"))?;
        durable_directory(parent)?;
        if state.quarantine.is_some() {
            let mut repair = self.repair_state();
            repair.quarantine.clone_from(&state.quarantine);
            self.write_repair_state(writer, &repair)?;
        } else if !self.path.try_exists()? {
            // Only first creation establishes a clean history automatically.
            self.write_repair_state(writer, &RepairState::default())?;
        }
        durable_replace(&RealFs, &self.path, &bytes, 0o600, &|_| Ok(()), hook)
    }
}
fn check_schema(state: &State) -> io::Result<()> {
    if state.schema == 1 {
        Ok(())
    } else {
        Err(io::Error::other("unsupported state.json schema"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::lock::WriterLock;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn worker_capacity_is_shared_across_handles_and_survives_handle_drop() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("state-worker-capacity")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let guard = WriterLock::acquire(&root).unwrap();
        let reader = StateFile::open(&root, Some(&guard)).unwrap();
        reader.write(&guard, &State::default()).unwrap();
        let permit = reader.reserve_worker().unwrap();
        // The worker owns the permit while its I/O is blocked, even after the
        // originating adapter is gone. Another handle must not start a job.
        drop(reader);
        let reader = StateFile::open(&root, None).unwrap();
        reader.invalidate_reads();
        let start = Instant::now();
        assert_eq!(
            reader
                .read_until(start + Duration::from_secs(60))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(reader.pending_read.borrow().is_none());
        assert!(reader.pending_metadata.borrow().is_none());
        drop(permit);
        assert_eq!(
            reader
                .read_until(Instant::now() + Duration::from_secs(3))
                .unwrap(),
            StateRead::Present(State::default())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_capacity_uses_canonical_roots() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("state-aliases")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
        let a = StateFile::open(root.join("real"), None).unwrap();
        let b = StateFile::open(root.join("alias/../alias/."), None).unwrap();
        assert!(Arc::ptr_eq(&a.capacity, &b.capacity));
        let permit = a.reserve_worker().unwrap();
        assert!(b.reserve_worker().is_err());
        drop(permit);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stalled_workers_survive_invalidation_without_spawning_replacements() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("state-workers")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let guard = WriterLock::acquire(&root).unwrap();
        let reader = StateFile::open(&root, Some(&guard)).unwrap();
        reader.write(&guard, &State::default()).unwrap();
        let old_snapshot = reader.snapshot().unwrap();
        let generation = reader.capacity.generation.load(Ordering::SeqCst);
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        *reader.pending_read.borrow_mut() = Some((Some(generation), receive));
        for _ in 0..32 {
            reader.invalidate_reads();
            let start = Instant::now();
            assert_eq!(
                reader
                    .read_until(start + Duration::from_secs(60))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            assert!(start.elapsed() < Duration::from_secs(1));
            assert_eq!(reader.pending_read.borrow().as_ref().unwrap().0, None);
            assert!(reader.pending_metadata.borrow().is_none());
        }
        let state = State {
            selection: Selection::Disconnected,
            ..State::default()
        };
        reader.write(&guard, &state).unwrap();
        send.send(Ok(old_snapshot)).unwrap();
        assert_eq!(
            reader
                .read_until(Instant::now() + Duration::from_secs(3))
                .unwrap(),
            StateRead::Present(state.clone())
        );

        let (send, receive) = std::sync::mpsc::sync_channel(1);
        *reader.pending_metadata.borrow_mut() = Some((Some(generation), receive));
        for _ in 0..32 {
            reader.invalidate_reads();
            let start = Instant::now();
            assert_eq!(
                reader
                    .read_until(start + Duration::from_secs(60))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(reader.pending_read.borrow().is_none());
            assert_eq!(reader.pending_metadata.borrow().as_ref().unwrap().0, None);
        }
        send.send(Ok(None)).unwrap(); // Stale metadata must be discarded too.
        assert_eq!(
            reader
                .read_until(Instant::now() + Duration::from_secs(3))
                .unwrap(),
            StateRead::Present(state)
        );
        assert!(reader.pending_read.borrow().is_none());
        assert!(reader.pending_metadata.borrow().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delayed_snapshots_are_discarded_after_other_writers_and_lock_boundaries() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("state-generation")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let guard = WriterLock::acquire(&root).unwrap();
        let reader = StateFile::open(&root, Some(&guard)).unwrap();
        let writer = StateFile::open(&root, None).unwrap();
        writer.write(&guard, &State::default()).unwrap();
        for mode in 0..3 {
            let old = reader.snapshot().unwrap();
            let epoch = reader.capacity.generation.load(Ordering::SeqCst);
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            *reader.pending_read.borrow_mut() = Some((Some(epoch), receive));
            // Deterministically hold a worker's captured old intent beyond its timeout.
            assert!(
                reader
                    .read_until(Instant::now() + Duration::from_millis(1))
                    .is_err()
            );
            let state = State {
                selection: Selection::Disconnected,
                ..State::default()
            };
            if mode == 0 {
                writer.write(&guard, &state).unwrap();
            } else if mode == 1 {
                // A replacement outside this process's generation counter.
                let replacement = root.join("replacement.json");
                std::fs::write(&replacement, serde_json::to_vec(&state).unwrap()).unwrap();
                std::fs::rename(replacement, root.join("state.json")).unwrap();
            } else {
                reader.invalidate_reads(); // A new locked tick must start a new read.
                writer.write(&guard, &state).unwrap();
            }
            let _ = send.send(Ok(old));
            assert_eq!(
                reader
                    .read_until(Instant::now() + Duration::from_secs(3))
                    .unwrap(),
                StateRead::Present(state)
            );
            writer.write(&guard, &State::default()).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unrelated_state_writes_preserve_ready_snapshots_when_another_reader_is_busy() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("state-independent-roots")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let reader_guard = WriterLock::acquire(root.join("reader")).unwrap();
        let other_guard = WriterLock::acquire(root.join("other")).unwrap();
        let reader = StateFile::open(root.join("reader"), Some(&reader_guard)).unwrap();
        let other = StateFile::open(root.join("other"), Some(&other_guard)).unwrap();
        reader.write(&reader_guard, &State::default()).unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        *reader.pending_metadata.borrow_mut() = Some((
            Some(reader.capacity.generation.load(Ordering::SeqCst)),
            receive,
        ));
        // A second handle may start another read after metadata verification
        // releases its permit, before the first handle consumes its ready reply.
        let busy = reader.reserve_worker().unwrap();
        other
            .write(
                &other_guard,
                &State {
                    selection: Selection::Disconnected,
                    ..State::default()
                },
            )
            .unwrap();
        send.send(Ok(Some(StateRead::Present(State::default()))))
            .unwrap();
        assert_eq!(
            reader
                .read_until(Instant::now() + Duration::from_secs(3))
                .unwrap(),
            StateRead::Present(State::default())
        );
        drop(busy);
        drop(reader_guard);
        drop(other_guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}
