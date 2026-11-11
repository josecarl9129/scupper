//! Durable, ordered per-sink queues. All I/O belongs to independent workers.
use crate::{
    events::{self, LogHandle},
    fs::{Fs, RealFs, durable_directory, durable_replace},
    heartbeat::{self, Failure, Request},
    lock::WriterLock,
};
use scupper_core::{
    alerts::{self, Alert, AlertSink, Coalescer, SinkError, TokenBucket},
    config::{AlertSink as Settings, ExitId},
};
use scupper_proto::{Actor, EventKind, Identifier, Reason};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn monotonic() -> u64 {
    heartbeat::monotonic_ns() / 1_000_000_000
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// Configured host-namespace sender. Debug output contains no secret URL.
pub struct Sink {
    /// Validated configured name.
    pub name: String,
    /// Configured public settings.
    pub settings: Settings,
    /// Local secret root.
    pub config_root: PathBuf,
    /// Hardened executable.
    pub binary: PathBuf,
    /// Expected secret owner (zero in production).
    pub owner: u32,
}
impl AlertSink for Sink {
    fn name(&self) -> &str {
        &self.name
    }
    fn deliver(&self, alert: &Alert) -> Result<(), SinkError> {
        let attempt = || -> Result<(), Failure> {
            // Deadline covers secret resolution and account lookup as well as exec.
            let deadline = heartbeat::monotonic_ns().saturating_add(30_000_000_000);
            let url =
                heartbeat::resolve(&self.config_root, self.settings.url_ref(), "", self.owner)?;
            let passwd = std::fs::read_to_string("/etc/passwd").map_err(|_| Failure::Account)?;
            let group = std::fs::read_to_string("/etc/group").map_err(|_| Failure::Account)?;
            let identity = heartbeat::account(&passwd, &group)?;
            let request = Request::alert(
                url.expose(),
                deadline,
                alerts::render(&self.settings, alert),
            )?;
            let request = if matches!(
                self.settings,
                Settings::Webhook {
                    preset: scupper_core::config::WebhookPreset::Pushover,
                    ..
                }
            ) {
                request.pushover()
            } else {
                request
            };
            heartbeat::attempt(&self.binary, &request, identity)
        };
        attempt().map_err(classify)
    }
}
fn classify(error: Failure) -> SinkError {
    match error {
        Failure::Permanent => SinkError::Permanent,
        Failure::Secret => SinkError::Secret,
        Failure::Account => SinkError::Account,
        Failure::Exec => SinkError::Exec,
        Failure::Internal => SinkError::Internal,
        _ => SinkError::Transient,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    alert: Alert,
    admitted: bool,
    test: Option<String>,
    first: Option<u64>,
    attempt: u32,
    retry: u64,
}
impl Pending {
    fn new(alert: Alert) -> Self {
        Self {
            alert,
            admitted: false,
            test: None,
            first: None,
            attempt: 0,
            retry: 0,
        }
    }
}
/// Public cursor/status contains only operational numbers and failure classes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    /// Highest settled sequence (pending incidents remain in the journal).
    pub cursor: u64,
    /// Last successful delivery wall timestamp.
    pub last_success: Option<u64>,
    /// Last failure wall timestamp and value-free classification.
    pub last_failure: Option<(u64, String)>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Journal {
    version: u32,
    clock: u64,
    failing_since: Option<u64>,
    failed: bool,
    retry: u64,
    status: Status,
    scanned: u64,
    coalescer: Coalescer,
    bucket: TokenBucket,
    suppressed: u64,
    queue: Vec<Pending>,
}
impl Journal {
    fn new(at: u64) -> Self {
        Self {
            version: 1,
            clock: at,
            failing_since: None,
            failed: false,
            retry: 0,
            status: Status::default(),
            scanned: 0,
            coalescer: Coalescer::default(),
            bucket: TokenBucket::new(at),
            suppressed: 0,
            queue: Vec::new(),
        }
    }
    fn enqueue(&mut self, alerts: Vec<Alert>) {
        for alert in alerts {
            if self.queue.len() == 64 {
                // Prefer Critical across keys, preserving the oldest item within a key.
                if alert.severity == alerts::Severity::Critical {
                    if let Some(index) = self.queue.iter().rposition(|p| {
                        p.test.is_none() && p.alert.severity != alerts::Severity::Critical
                    }) {
                        self.queue.remove(index);
                    } else {
                        self.suppressed = self.suppressed.saturating_add(1);
                        continue;
                    }
                } else {
                    self.suppressed = self.suppressed.saturating_add(1);
                    continue;
                }
                self.suppressed = self.suppressed.saturating_add(1);
            }
            self.queue.push(Pending::new(alert));
        }
    }
    fn advance_clock(&mut self, at: u64) {
        if at < self.clock {
            self.bucket.rebase(self.clock, at);
            self.coalescer.rebase(self.clock, at);
            self.failing_since = self
                .failing_since
                .map(|t| at.saturating_sub(self.clock.saturating_sub(t)));
            self.retry = at.saturating_add(self.retry.saturating_sub(self.clock));
            for p in &mut self.queue {
                p.first = p
                    .first
                    .map(|t| at.saturating_sub(self.clock.saturating_sub(t)));
                p.retry = at.saturating_add(p.retry.saturating_sub(self.clock));
            }
        }
        self.clock = at;
    }
    fn update_cursor(&mut self) {
        let pending = self
            .queue
            .iter()
            .filter(|p| p.alert.seq != 0)
            .map(|p| p.alert.seq)
            .chain(self.coalescer.pending_seq())
            .min();
        self.status.cursor =
            pending.map_or(self.scanned, |seq| self.scanned.min(seq.saturating_sub(1)));
    }
    fn save(&mut self, path: &Path) -> io::Result<()> {
        self.update_cursor();
        durable_replace(
            &RealFs,
            path,
            &serde_json::to_vec(self)?,
            0o640,
            &|_| Ok(()),
            &|_| Ok(()),
        )
    }
    fn load(path: &Path, at: u64) -> io::Result<Self> {
        match RealFs.read(path) {
            Ok(text) => {
                if text.len() > 131_072 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized alert journal",
                    ));
                }
                let mut journal: Self = serde_json::from_str(&text)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if journal.version != 1
                    || journal.queue.len() > 64
                    || journal
                        .queue
                        .iter()
                        .any(|p| p.test.as_ref().is_some_and(|id| !valid_request_id(id)))
                    || journal
                        .status
                        .last_failure
                        .as_ref()
                        .is_some_and(|(_, class)| {
                            ![
                                "transient",
                                "permanent",
                                "secret",
                                "account",
                                "exec",
                                "internal",
                            ]
                            .contains(&class.as_str())
                        })
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported alert journal",
                    ));
                }
                journal.advance_clock(at);
                Ok(journal)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::new(at)),
            Err(e) => Err(e),
        }
    }
}
fn cursor_path(root: &Path, name: &str) -> io::Result<PathBuf> {
    if !ExitId(name.into()).is_valid() {
        return Err(io::Error::other("invalid sink identity"));
    }
    Ok(root.join("sinks").join(format!("{name}.cursor")))
}
/// Read a sink's durable status without exposing its secret reference.
/// # Errors
/// Refuses invalid identities, malformed journals and filesystem failures.
pub fn status(root: &Path, name: &str) -> io::Result<Status> {
    Ok(Journal::load(&cursor_path(root, name)?, monotonic())?.status)
}

fn failure(log: &LogHandle, name: &str, reason: Reason) -> io::Result<()> {
    let sink = Identifier::try_from(name.to_owned()).map_err(io::Error::other)?;
    log.emit(EventKind::SinkFailed { sink, reason }, Actor::Daemon, None)
        .map_err(io::Error::other)?;
    // Failure is durable before skipping its notification. Never on the tick thread.
    log.flush_blocking(Duration::from_secs(5))
}
#[cfg(test)]
fn step(
    journal: &mut Journal,
    path: &Path,
    sink: &dyn AlertSink,
    log: &LogHandle,
    at: u64,
) -> io::Result<()> {
    let started = Instant::now();
    step_with_ack(
        journal,
        path,
        sink,
        log,
        at,
        &|| at.saturating_add(started.elapsed().as_secs()),
        &|| Ok(()),
    )
}
#[allow(clippy::too_many_lines)] // Keep admission, durable outbox and acknowledgement together.
fn step_with_ack(
    journal: &mut Journal,
    path: &Path,
    sink: &dyn AlertSink,
    log: &LogHandle,
    at: u64,
    completed_at: &dyn Fn() -> u64,
    before_ack: &dyn Fn() -> io::Result<()>,
) -> io::Result<()> {
    journal.advance_clock(at);
    let ready = journal.coalescer.flush(at);
    if !ready.is_empty() {
        journal.enqueue(ready);
        journal.save(path)?;
    }
    // A retained resolution is local to its key. Skip delayed retries, and
    // prioritize Critical among the first outstanding notification of each key.
    let index = journal
        .queue
        .iter()
        .enumerate()
        .filter(|(i, p)| {
            !journal.queue[..*i]
                .iter()
                .any(|earlier| earlier.alert.key == p.alert.key)
        })
        .filter(|(_, p)| at >= p.retry)
        .max_by_key(|(i, p)| {
            (
                p.alert.severity == alerts::Severity::Critical,
                std::cmp::Reverse(*i),
            )
        })
        .map(|(i, _)| i);
    let expired = journal
        .failing_since
        .is_some_and(|first| alerts::exhausted(first, at));
    if expired && !journal.failed {
        failure(log, sink.name(), Reason::AlertGiveUp)?;
        journal.failed = true;
        journal.retry = at.saturating_add(900);
        for pending in &journal.queue {
            acknowledge(path, pending, "give_up")?;
        }
        journal.suppressed = journal
            .suppressed
            .saturating_add(journal.queue.len() as u64);
        journal.queue.clear();
        return journal.save(path);
    }
    if at < journal.retry {
        return Ok(());
    }
    let Some(index) = index else {
        return Ok(());
    };
    if !journal.queue[index].admitted {
        if !journal.bucket.take(at) {
            let pending = journal.queue.remove(index);
            acknowledge(path, &pending, "rate_limited")?;
            journal.suppressed = journal.suppressed.saturating_add(1);
            return journal.save(path);
        }
        journal.queue[index].admitted = true;
        journal.queue[index].alert.suppressed = journal.suppressed;
    }
    journal.queue[index].first.get_or_insert(at);
    journal.save(path)?; // durable admission before the first attempt
    journal.queue[index].alert.suppressed = journal.suppressed;
    let result = sink.deliver(&journal.queue[index].alert);
    let completed = completed_at();
    before_ack()?;
    match result {
        Ok(()) => {
            journal.suppressed = journal
                .suppressed
                .saturating_sub(journal.queue[index].alert.suppressed);
            journal.status.last_success = Some(now());
            journal.failing_since = None;
            journal.failed = false;
            journal.retry = 0;
            acknowledge(path, &journal.queue[index], "delivered")?;
            journal.queue.remove(index);
        }
        Err(error) => {
            let class = match error {
                SinkError::Transient => "transient",
                SinkError::Permanent => "permanent",
                SinkError::Secret => "secret",
                SinkError::Account => "account",
                SinkError::Exec => "exec",
                SinkError::Internal => "internal",
            };
            journal.status.last_failure = Some((now(), class.into()));
            journal.failing_since.get_or_insert(completed);
            acknowledge(path, &journal.queue[index], class)?;
            // A test is settled by its first real outcome, individually.
            if error != SinkError::Transient {
                if !journal.failed {
                    let reason = match error {
                        SinkError::Secret => Reason::AlertSecret,
                        SinkError::Account => Reason::AlertAccount,
                        SinkError::Exec => Reason::AlertExec,
                        SinkError::Internal => Reason::AlertInternal,
                        _ => Reason::AlertPermanent,
                    };
                    failure(log, sink.name(), reason)?;
                }
                journal.failed = true;
                journal.retry = completed.saturating_add(900);
                journal.queue.remove(index);
                for pending in &journal.queue {
                    if pending.test.is_some() {
                        acknowledge(path, pending, class)?;
                    }
                }
                journal.queue.retain(|pending| pending.test.is_none());
            } else if journal.queue[index].test.is_some() {
                journal.queue.remove(index);
            } else {
                let pending = &mut journal.queue[index];
                pending.retry = completed.saturating_add(alerts::backoff(pending.attempt));
                pending.attempt = pending.attempt.saturating_add(1);
                if journal.failed {
                    journal.retry = completed.saturating_add(900);
                }
            }
        }
    }
    journal.clock = completed;
    journal.save(path)
}

fn test_directory(path: &Path) -> PathBuf {
    path.with_extension("tests")
}
fn acknowledge(path: &Path, pending: &Pending, outcome: &str) -> io::Result<()> {
    if let Some(id) = &pending.test {
        durable_replace(
            &RealFs,
            &test_directory(path).join(format!("{id}.outcome")),
            outcome.as_bytes(),
            0o600,
            &|_| Ok(()),
            &|_| Ok(()),
        )?;
    }
    Ok(())
}
fn ingest_tests(journal: &mut Journal, path: &Path) -> io::Result<()> {
    let directory = test_directory(path);
    durable_directory(&directory)?;
    let mut entries = std::fs::read_dir(&directory)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if entry.path().extension().is_none_or(|e| e != "request") {
            continue;
        }
        let Some(id) = entry
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        if !valid_request_id(&id) {
            continue;
        }
        if !directory.join(format!("{id}.outcome")).exists()
            && !journal.queue.iter().any(|p| p.test.as_ref() == Some(&id))
        {
            let mut pending = Pending::new(Alert::test(now()));
            pending.test = Some(id);
            if journal.failed && monotonic() < journal.retry {
                acknowledge(
                    path,
                    &pending,
                    journal
                        .status
                        .last_failure
                        .as_ref()
                        .map_or("unavailable", |(_, class)| class.as_str()),
                )?;
            } else if journal.queue.len() == 64 {
                acknowledge(path, &pending, "queue_full")?;
            } else {
                journal.queue.push(pending);
                journal.save(path)?;
            }
        }
        std::fs::remove_file(entry.path())?;
        RealFs.sync_dir(&directory)?;
    }
    Ok(())
}

fn scan_events(
    journal: &mut Journal,
    tail: &mut events::Tail,
    root: &Path,
    path: &Path,
    log: &LogHandle,
    settings: &Settings,
) -> io::Result<()> {
    if !log.is_persistent() || log.committed_seq() <= journal.scanned {
        return Ok(());
    }
    let upper = log.committed_seq();
    for record in tail.read(root, journal.scanned, upper)? {
        match record {
            events::TailRecord::Event(event) => {
                if let Some(alert) = event
                    .alert()
                    .filter(|a| alerts::eligible(a, settings.min_severity()))
                {
                    let ready = journal.coalescer.push_at(alert, monotonic());
                    journal.enqueue(ready);
                }
            }
            events::TailRecord::Skipped(seq) => {
                log.emit(EventKind::EventSkipped { seq }, Actor::Daemon, None)
                    .map_err(io::Error::other)?;
            }
        }
    }
    journal.scanned = upper;
    journal.save(path)
}

fn run_worker(
    root: &Path,
    sink: &Sink,
    log: &mut LogHandle,
    receive: &mpsc::Receiver<LogHandle>,
    stopping: &AtomicBool,
) -> io::Result<()> {
    // Recovery may replace a memory-only log while the worker is backing off.
    while let Ok(updated) = receive.try_recv() {
        *log = updated;
    }
    durable_directory(&root.join("sinks"))?;
    let path = cursor_path(root, &sink.name)?;
    // Serializes replacement workers across reconfiguration and restart.
    let _guard =
        WriterLock::acquire_timeout(root.join("sinks").join(&sink.name), Duration::from_secs(40))?;
    let mut journal = open_journal(root, &path, log)?;
    #[cfg(feature = "testing")]
    if let Some(hold) = std::env::var("SCUPPER_TEST_ALERT_WINDOW_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        journal.coalescer.set_test_hold(hold);
    }
    let mut tail = events::Tail::default();
    while !stopping.load(Ordering::Acquire) {
        while let Ok(updated) = receive.try_recv() {
            *log = updated;
        }
        scan_events(&mut journal, &mut tail, root, &path, log, &sink.settings)?;
        ingest_tests(&mut journal, &path)?;
        step_with_ack(
            &mut journal,
            &path,
            sink,
            log,
            monotonic(),
            &monotonic,
            &|| Ok(()),
        )?;
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

fn report_spawn_failure(log: &LogHandle, name: &str) {
    if let Ok(sink) = Identifier::try_from(name.to_owned()) {
        let _ = log.emit(
            EventKind::SinkFailed {
                sink,
                reason: Reason::AlertInternal,
            },
            Actor::Daemon,
            None,
        );
    }
}

struct Worker {
    settings: Settings,
    log: SyncSender<LogHandle>,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
/// Nonblocking worker ownership; creation and channels only on the tick thread.
#[derive(Default)]
pub struct Workers {
    workers: BTreeMap<String, Worker>,
    spawn_retry: BTreeMap<String, (Instant, u32)>,
}
impl Workers {
    /// Synchronize applied settings and the fsync watermark source.
    #[allow(clippy::too_many_lines)] // Worker replacement shares channel and stop ownership.
    pub fn sync(
        &mut self,
        settings: &BTreeMap<String, Settings>,
        state_root: &Path,
        config_root: &Path,
        binary: &Path,
        log: &LogHandle,
        owner: u32,
    ) {
        self.spawn_retry
            .retain(|name, _| settings.contains_key(name));
        for (name, worker) in &self.workers {
            if worker.thread.is_finished() && !self.spawn_retry.contains_key(name) {
                self.spawn_retry
                    .insert(name.clone(), (Instant::now() + Duration::from_secs(5), 0));
                report_spawn_failure(log, name);
            }
        }
        self.workers.retain(|name, worker| {
            !worker.thread.is_finished()
                && settings.get(name).is_some_and(|s| s == &worker.settings)
        });
        for (name, settings) in settings {
            if let Some(worker) = self.workers.get(name) {
                let _ = worker.log.try_send(log.clone());
                continue;
            }
            if self
                .spawn_retry
                .get(name)
                .is_some_and(|(retry, _)| Instant::now() < *retry)
            {
                continue;
            }
            let retry_attempt = self
                .spawn_retry
                .get(name)
                .map_or(0, |(_, attempt)| *attempt);
            let sink = Sink {
                name: name.clone(),
                settings: settings.clone(),
                config_root: config_root.into(),
                binary: binary.into(),
                owner,
            };
            let root = state_root.to_path_buf();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let (send, receive) = mpsc::sync_channel(1);
            let failure_log = log.clone();
            let mut log = log.clone();
            let result = std::thread::Builder::new()
                .name(format!("scupper-alert-{name}"))
                .spawn(move || {
                    let mut delay = 5;
                    let mut reported = false;
                    while !stopping.load(Ordering::Acquire) {
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            run_worker(&root, &sink, &mut log, &receive, &stopping)
                        }))
                        .is_ok_and(|r| r.is_ok())
                        {
                            break;
                        }
                        if !reported {
                            reported = failure(&log, &sink.name, Reason::AlertPersistence).is_ok();
                        }
                        // Keep ownership while backing off; ticks cannot respawn a failed worker.
                        for _ in 0..delay * 5 {
                            if stopping.load(Ordering::Acquire) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                        delay = (delay * 2).min(900);
                    }
                });
            if let Ok(thread) = result {
                self.spawn_retry.remove(name);
                self.workers.insert(
                    name.clone(),
                    Worker {
                        settings: settings.clone(),
                        log: send,
                        stop,
                        thread,
                    },
                );
            } else {
                if retry_attempt == 0 {
                    report_spawn_failure(&failure_log, name);
                }
                self.spawn_retry.insert(
                    name.clone(),
                    (
                        Instant::now() + Duration::from_secs(alerts::backoff(retry_attempt)),
                        retry_attempt.saturating_add(1),
                    ),
                );
            }
        }
    }
    /// Signal workers without joining potentially blocked I/O.
    pub fn stop(&mut self) {
        self.workers.clear();
        self.spawn_retry.clear();
    }
}
/// Queue an explicit test through the daemon's real per-sink worker.
/// # Errors
/// Rejects invalid identities or non-durable filesystem writes.
pub fn request_test(root: &Path, name: &str) -> io::Result<String> {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = cursor_path(root, name)?;
    durable_directory(&root.join("sinks"))?;
    let directory = test_directory(&path);
    durable_directory(&directory)?;
    let _guard = WriterLock::acquire_timeout(directory.join("writer"), Duration::from_secs(2))?;
    if std::fs::read_dir(&directory)?
        .filter_map(Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|s| s == "request" || s == "outcome")
        })
        .count()
        >= 64
    {
        return Err(io::Error::other("test request limit"));
    }
    let id = format!(
        "{}-{}-{}",
        std::process::id(),
        heartbeat::monotonic_ns(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    durable_replace(
        &RealFs,
        &directory.join(format!("{id}.request")),
        b"test\n",
        0o600,
        &|_| Ok(()),
        &|_| Ok(()),
    )?;
    Ok(id)
}
fn valid_request_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}
/// Read an individual test's durable, value-free outcome.
/// # Errors
/// Invalid identities or local filesystem failure.
pub fn test_outcome(root: &Path, name: &str, id: &str) -> io::Result<Option<String>> {
    if !valid_request_id(id) {
        return Err(io::Error::other("invalid test identity"));
    }
    let directory = test_directory(&cursor_path(root, name)?);
    let path = directory.join(format!("{id}.outcome"));
    match std::fs::read_to_string(&path) {
        Ok(outcome) => Ok(Some(
            if [
                "delivered",
                "transient",
                "permanent",
                "secret",
                "account",
                "exec",
                "internal",
                "rate_limited",
                "queue_full",
                "give_up",
                "unavailable",
            ]
            .contains(&outcome.as_str())
            {
                outcome
            } else {
                "internal".into()
            },
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
/// Remove a consumed test receipt.
/// # Errors
/// Invalid identities or filesystem failure.
pub fn finish_test(root: &Path, name: &str, id: &str) -> io::Result<()> {
    if !valid_request_id(id) {
        return Err(io::Error::other("invalid test identity"));
    }
    let path = test_directory(&cursor_path(root, name)?).join(format!("{id}.outcome"));
    std::fs::remove_file(path)
}

fn open_journal(root: &Path, path: &Path, log: &LogHandle) -> io::Result<Journal> {
    if !log.is_persistent() {
        return Err(io::Error::other("event log not persistent"));
    }
    if path.exists() {
        match Journal::load(path, monotonic()) {
            Ok(journal) => return Ok(journal),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {}
            Err(e) => return Err(e),
        }
        // Keep corrupt bytes for local inspection, bounded to one quarantined file.
        std::fs::rename(path, path.with_extension("corrupt"))?;
        RealFs.sync_dir(&root.join("sinks"))?;
    }
    let mut journal = Journal::new(monotonic());
    journal.scanned = log.committed_seq();
    // No historical deliveries. Reconstruct only currently active Critical state.
    let mut active = BTreeMap::new();
    let mut tail = events::Tail::default();
    for record in tail.read(root, 0, journal.scanned)? {
        if let events::TailRecord::Event(event) = record
            && let Some(alert) = event
                .alert()
                .filter(|a| a.severity == alerts::Severity::Critical)
        {
            if alert.state == alerts::AlertState::Firing {
                active.insert(alert.key, alert);
            } else {
                active.remove(&alert.key);
            }
        }
    }
    for mut alert in active.into_values() {
        alert.seq = journal.scanned;
        alert.at = now();
        let ready = journal.coalescer.push_at(alert, monotonic());
        journal.enqueue(ready);
    }
    journal.save(path)?;
    Ok(journal)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::events::{EventIoStep, EventLog};
    use scupper_core::alerts::{OperationalEvent, map};
    use scupper_proto::{GatewayId, UnixSeconds};
    use std::sync::{Mutex, atomic::AtomicU64};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
                "alerts-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(root.join("sinks")).unwrap();
            Self(root)
        }
        fn log(&self) -> crate::events::OpenedLog {
            EventLog::open(&self.0, GatewayId("gw1".into()), || UnixSeconds(100)).unwrap()
        }
        fn path(&self) -> PathBuf {
            self.0.join("sinks/fixture.cursor")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Fake {
        sent: Mutex<Vec<u64>>,
        suppressed: AtomicU64,
        result: Mutex<Result<(), SinkError>>,
    }
    impl Fake {
        fn new(result: Result<(), SinkError>) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                suppressed: AtomicU64::new(0),
                result: Mutex::new(result),
            }
        }
    }
    impl AlertSink for Fake {
        fn name(&self) -> &'static str {
            "fixture"
        }
        fn deliver(&self, a: &Alert) -> Result<(), SinkError> {
            self.sent.lock().unwrap().push(a.seq);
            self.suppressed.store(a.suppressed, Ordering::Release);
            *self.result.lock().unwrap()
        }
    }
    fn queue() -> Journal {
        let mut j = Journal::new(100);
        j.scanned = 2;
        j.enqueue(vec![
            map(OperationalEvent::FailClosedStarted, 1, 100),
            map(OperationalEvent::FailClosedEnded(3), 2, 103),
        ]);
        j
    }
    #[test]
    fn crash_after_delivery_before_cursor_ack_duplicates_head_never_skips() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = queue();
        assert!(
            step_with_ack(
                &mut j,
                &t.path(),
                &sink,
                &log.handle,
                100,
                &|| 100,
                &|| Err(io::Error::other("simulated crash"))
            )
            .is_err()
        );
        let mut j = Journal::load(&t.path(), 101).unwrap();
        assert_eq!(j.status.cursor, 0);
        step(&mut j, &t.path(), &sink, &log.handle, 101).unwrap();
        let mut j = Journal::load(&t.path(), 102).unwrap();
        assert_eq!(j.status.cursor, 1);
        step(&mut j, &t.path(), &sink, &log.handle, 102).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 1, 2]);
        assert_eq!(Journal::load(&t.path(), 103).unwrap().status.cursor, 2);
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
    }
    #[test]
    fn sink_outage_backlog_and_retry_deadline_survive_restart_in_order() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Err(SinkError::Transient));
        let mut j = queue();
        for (at, retry) in [(100, 105), (105, 115), (115, 135)] {
            step(&mut j, &t.path(), &sink, &log.handle, at).unwrap();
            j = Journal::load(&t.path(), at).unwrap();
            assert_eq!(j.queue[0].retry, retry);
            assert_eq!(j.status.cursor, 0);
        }
        step(&mut j, &t.path(), &sink, &log.handle, 134).unwrap();
        assert_eq!(sink.sent.lock().unwrap().len(), 3);
        *sink.result.lock().unwrap() = Ok(());
        step(&mut j, &t.path(), &sink, &log.handle, 135).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 136).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 1, 1, 1, 2]);
        assert_eq!(j.status.cursor, 2);
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
    }
    #[test]
    fn permanent_failure_and_twenty_four_hour_giveup_emit_durable_sink_failed() {
        for expired in [false, true] {
            let t = Temp::new();
            let log = t.log();
            let sink = Fake::new(if expired {
                Err(SinkError::Transient)
            } else {
                Err(SinkError::Permanent)
            });
            let mut j = queue();
            if expired {
                step(&mut j, &t.path(), &sink, &log.handle, 100).unwrap();
                assert_eq!(j.status.cursor, 0);
                j.queue[0].retry = 90_000; // Give up even before the next retry is due.
            }
            step(
                &mut j,
                &t.path(),
                &sink,
                &log.handle,
                if expired { 86500 } else { 100 },
            )
            .unwrap();
            assert_eq!(j.status.cursor, if expired { 2 } else { 1 });
            assert_eq!(sink.sent.lock().unwrap().len(), 1);
            let events: Vec<_> = events::read_since(&t.0, 0, Some(log.handle.committed_seq()))
                .collect::<io::Result<_>>()
                .unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e.kind, EventKind::SinkFailed { .. }))
                    .count(),
                1
            );
        }
    }
    #[test]
    fn rate_limited_critical_is_suppressed_and_next_delivery_summarizes() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(100);
        j.scanned = 6;
        j.enqueue(
            (1..=6)
                .map(|seq| map(OperationalEvent::FailClosedStarted, seq, 100))
                .collect(),
        );
        for _ in 0..6 {
            step(&mut j, &t.path(), &sink, &log.handle, 100).unwrap();
        }
        assert_eq!(sink.sent.lock().unwrap().len(), 5);
        assert_eq!(j.status.cursor, 6);
        let mut j = Journal::load(&t.path(), 399).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 399).unwrap();
        assert_eq!(j.status.cursor, 6);
        step(&mut j, &t.path(), &sink, &log.handle, 400).unwrap();
        assert_eq!(j.status.cursor, 6);
        assert_eq!(sink.sent.lock().unwrap().len(), 5);
        j.enqueue(vec![map(OperationalEvent::FailClosedEnded(300), 7, 400)]);
        step(&mut j, &t.path(), &sink, &log.handle, 400).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 2, 3, 4, 5, 7]);
        assert_eq!(sink.suppressed.load(Ordering::Acquire), 1);
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
    }
    #[test]
    fn complete_but_unfsynced_record_is_never_read_for_alerts() {
        let t = Temp::new();
        let paused = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let (held, go) = (paused.clone(), release.clone());
        let log = EventLog::open_with_hook(
            &t.0,
            GatewayId("gw1".into()),
            || UnixSeconds(100),
            100,
            move |step| {
                if step == EventIoStep::FileSync {
                    held.store(true, Ordering::Release);
                    while !go.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        log.handle
            .emit(
                EventKind::FailClosedStarted {
                    reason: Reason::NoHealthyExit,
                    exit: None,
                },
                Actor::Daemon,
                None,
            )
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !paused.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let records: Vec<_> =
            events::read_since(&t.0, 0, Some(log.handle.committed_seq())).collect();
        release.store(true, Ordering::Release);
        assert!(paused.load(Ordering::Acquire));
        assert_eq!(records.len(), 0);
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        assert_eq!(
            events::read_since(&t.0, 0, Some(log.handle.committed_seq())).count(),
            1
        );
    }
    #[test]
    fn held_failback_never_blocks_failclosed_and_same_key_order_is_preserved() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(0);
        let ready = j
            .coalescer
            .push_at(map(OperationalEvent::Failover, 1, 9999), 0);
        j.enqueue(ready);
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        assert_eq!(
            j.coalescer
                .push_at(map(OperationalEvent::Failback, 2, 1), 30),
            []
        );
        let ready = j
            .coalescer
            .push_at(map(OperationalEvent::FailClosedStarted, 3, 0), 60);
        j.enqueue(ready);
        step(&mut j, &t.path(), &sink, &log.handle, 60).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 3]);
        step(&mut j, &t.path(), &sink, &log.handle, 600).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 3, 2]);
    }
    #[test]
    fn retry_uses_one_token_and_severity_priority_does_not_reorder_a_key() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Err(SinkError::Transient));
        let mut j = queue();
        for at in [100, 105, 115, 135, 175] {
            step(&mut j, &t.path(), &sink, &log.handle, at).unwrap();
        }
        *sink.result.lock().unwrap() = Ok(());
        step(&mut j, &t.path(), &sink, &log.handle, 255).unwrap();
        j.enqueue(vec![
            map(OperationalEvent::Failover, 3, 256),
            map(OperationalEvent::Unprotected, 4, 256),
        ]);
        for at in 256..259 {
            step(&mut j, &t.path(), &sink, &log.handle, at).unwrap();
        }
        assert!(j.queue.is_empty());
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 1, 1, 1, 1, 1, 2, 4, 3]);
    }
    #[test]
    fn two_hour_storm_is_bounded_and_suppression_is_never_delayed() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(0);
        for seq in 1..=240 {
            let at = (seq - 1) * 30;
            j.scanned = seq;
            j.enqueue(vec![map(
                if seq % 2 == 1 {
                    OperationalEvent::FailClosedStarted
                } else {
                    OperationalEvent::FailClosedEnded(30)
                },
                seq,
                at,
            )]);
            step(&mut j, &t.path(), &sink, &log.handle, at).unwrap();
            assert!(j.queue.is_empty());
            assert_eq!(j.status.cursor, seq);
        }
        assert_eq!(sink.sent.lock().unwrap().len(), 28);
        assert!(std::fs::metadata(t.path()).unwrap().len() < 4096);
        j.enqueue(
            (241..500)
                .map(|seq| map(OperationalEvent::FailClosedStarted, seq, 7200))
                .collect(),
        );
        assert_eq!(j.queue.len(), 64);
    }
    #[test]
    fn new_renamed_and_corrupt_journals_start_at_watermark_with_active_state_only() {
        let t = Temp::new();
        let log = t.log();
        for _ in 0..50 {
            log.handle
                .emit(
                    EventKind::FailClosedStarted {
                        reason: Reason::NoHealthyExit,
                        exit: None,
                    },
                    Actor::Daemon,
                    None,
                )
                .unwrap();
            log.handle
                .emit(
                    EventKind::FailClosedEnded {
                        duration: Duration::from_secs(1),
                    },
                    Actor::Daemon,
                    None,
                )
                .unwrap();
        }
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        for name in ["fixture", "renamed", "corrupt"] {
            let path = cursor_path(&t.0, name).unwrap();
            if name == "corrupt" {
                std::fs::write(&path, b"broken").unwrap();
            }
            let j = open_journal(&t.0, &path, &log.handle).unwrap();
            assert_eq!(j.scanned, log.handle.committed_seq());
            assert!(j.queue.is_empty());
        }
        assert!(
            cursor_path(&t.0, "corrupt")
                .unwrap()
                .with_extension("corrupt")
                .exists()
        );
        log.handle
            .emit(
                EventKind::FailClosedStarted {
                    reason: Reason::NoHealthyExit,
                    exit: None,
                },
                Actor::Daemon,
                None,
            )
            .unwrap();
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let j = open_journal(&t.0, &cursor_path(&t.0, "active").unwrap(), &log.handle).unwrap();
        assert_eq!(j.queue.len(), 1);
        assert_eq!(j.queue[0].alert.seq, log.handle.committed_seq());
        let mut j = Journal::load(&t.path(), monotonic()).unwrap();
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"kind":"ntfy","url_ref":"fixture","min_severity":"critical"}),
        )
        .unwrap();
        scan_events(
            &mut j,
            &mut events::Tail::default(),
            &t.0,
            &t.path(),
            &log.handle,
            &settings,
        )
        .unwrap();
        let sink = Fake::new(Ok(()));
        step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![log.handle.committed_seq()]);
    }
    #[test]
    fn future_monotonic_origin_is_rebased_without_using_wall_time() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(86400);
        j.enqueue(vec![Alert::test(u64::MAX)]);
        j.save(&t.path()).unwrap();
        let mut j = Journal::load(&t.path(), 1).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 1).unwrap();
        assert_eq!(sink.sent.lock().unwrap().len(), 1);
    }
    #[test]
    fn concurrent_test_requests_have_individual_durable_outcomes_across_restart() {
        let t = Temp::new();
        let log = t.log();
        let first = request_test(&t.0, "fixture").unwrap();
        let second = request_test(&t.0, "fixture").unwrap();
        assert_ne!(first, second);
        let mut j = Journal::new(100);
        ingest_tests(&mut j, &t.path()).unwrap();
        let third = request_test(&t.0, "fixture").unwrap();
        let mut j = Journal::load(&t.path(), 100).unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        assert_eq!(j.queue.len(), 3);
        let sink = Fake::new(Ok(()));
        for at in 100..103 {
            step(&mut j, &t.path(), &sink, &log.handle, at).unwrap();
        }
        for id in [first, second, third] {
            assert_eq!(
                test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
                Some("delivered")
            );
        }
    }
    #[test]
    fn every_local_configuration_fault_fails_immediately_once_per_sink() {
        for (source, error, reason) in [
            (Failure::Secret, SinkError::Secret, Reason::AlertSecret),
            (Failure::Account, SinkError::Account, Reason::AlertAccount),
            (Failure::Exec, SinkError::Exec, Reason::AlertExec),
            (
                Failure::Internal,
                SinkError::Internal,
                Reason::AlertInternal,
            ),
            (
                Failure::Permanent,
                SinkError::Permanent,
                Reason::AlertPermanent,
            ),
        ] {
            assert_eq!(classify(source), error);
            let t = Temp::new();
            let log = t.log();
            let sink = Fake::new(Err(error));
            let mut j = queue();
            step(&mut j, &t.path(), &sink, &log.handle, 100).unwrap();
            step(&mut j, &t.path(), &sink, &log.handle, 1000).unwrap();
            let rows: Vec<_> = events::read_since(&t.0, 0, Some(log.handle.committed_seq()))
                .collect::<io::Result<_>>()
                .unwrap();
            assert_eq!(rows.iter().filter(|e| matches!(&e.kind, EventKind::SinkFailed { reason: r, .. } if *r == reason)).count(), 1);
        }
    }
    #[test]
    fn test_first_outcome_reports_permanent_transient_and_rate_limit() {
        for (result, expected) in [
            (Err(SinkError::Permanent), "permanent"),
            (Err(SinkError::Transient), "transient"),
            (Ok(()), "rate_limited"),
        ] {
            let t = Temp::new();
            let log = t.log();
            let sink = Fake::new(result);
            let mut j = Journal::new(100);
            if expected == "rate_limited" {
                for _ in 0..5 {
                    assert!(j.bucket.take(100));
                }
            }
            let id = request_test(&t.0, "fixture").unwrap();
            ingest_tests(&mut j, &t.path()).unwrap();
            step(&mut j, &t.path(), &sink, &log.handle, 100).unwrap();
            assert_eq!(
                test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
                Some(expected)
            );
            assert!(j.queue.is_empty());
        }
    }

    #[test]
    fn undecodable_event_is_reported_once_and_worker_scan_continues_incrementally() {
        let t = Temp::new();
        let log = t.log();
        log.handle
            .emit(EventKind::Flapping {}, Actor::Daemon, None)
            .unwrap();
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let month = std::fs::read_dir(t.0.join("events"))
            .unwrap()
            .map(Result::unwrap)
            .find(|e| e.path().extension().is_some_and(|s| s == "jsonl"))
            .unwrap()
            .path();
        let original = std::fs::read_to_string(&month).unwrap();
        std::fs::write(&month, original.replace("Flapping", "FutureKind")).unwrap();
        log.handle
            .emit(
                EventKind::FailClosedStarted {
                    reason: Reason::NoHealthyExit,
                    exit: None,
                },
                Actor::Daemon,
                None,
            )
            .unwrap();
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"kind":"ntfy","url_ref":"fixture","min_severity":"info"}),
        )
        .unwrap();
        let mut j = Journal::new(monotonic());
        let mut tail = events::Tail::default();
        scan_events(&mut j, &mut tail, &t.0, &t.path(), &log.handle, &settings).unwrap();
        assert_eq!(j.queue.len(), 1);
        assert_eq!(j.queue[0].alert.seq, 2);
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        scan_events(&mut j, &mut tail, &t.0, &t.path(), &log.handle, &settings).unwrap();
        scan_events(&mut j, &mut tail, &t.0, &t.path(), &log.handle, &settings).unwrap();
        assert_eq!(j.queue.len(), 1);
        assert_eq!(
            events::read_since(&t.0, 2, Some(log.handle.committed_seq()))
                .filter_map(Result::ok)
                .filter(|e| matches!(e.kind, EventKind::EventSkipped { seq: 1 }))
                .count(),
            1
        );
    }
    #[test]
    fn hour_of_failed_probes_produces_exactly_one_firing_and_resolution() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(0);
        for seq in 1..=62 {
            let kind = match seq {
                1 => EventKind::FailClosedStarted {
                    reason: Reason::NoHealthyExit,
                    exit: None,
                },
                62 => EventKind::FailClosedEnded {
                    duration: Duration::from_secs(3600),
                },
                _ => EventKind::DriftDetected {
                    object: scupper_proto::ObjectKind::Unknown,
                    reason: Reason::HealthFailure,
                },
            };
            let event = scupper_proto::Event {
                seq,
                at: UnixSeconds(seq * 60),
                kind,
                actor: Actor::Daemon,
                gateway: Identifier::try_from("fixture".to_owned()).unwrap(),
                config_version: None,
            };
            if let Some(alert) = event.alert() {
                let ready = j.coalescer.push_at(alert, seq * 60);
                j.enqueue(ready);
            }
            step(&mut j, &t.path(), &sink, &log.handle, seq * 60).unwrap();
        }
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 62]);
    }
    #[test]
    fn retry_delay_begins_after_blocking_failure_completes() {
        struct Slow;
        impl AlertSink for Slow {
            fn name(&self) -> &'static str {
                "fixture"
            }
            fn deliver(&self, _: &Alert) -> Result<(), SinkError> {
                std::thread::sleep(Duration::from_millis(1100));
                Err(SinkError::Transient)
            }
        }
        let t = Temp::new();
        let log = t.log();
        let mut j = queue();
        step(&mut j, &t.path(), &Slow, &log.handle, 100).unwrap();
        assert!(j.queue[0].retry >= 106);
    }

    proptest::proptest! {
        #[test]
        fn durable_journal_and_public_status_discard_external_event_fields(suffix in "[a-z]{16,24}", octets in proptest::prelude::any::<[u8; 4]>()) {
            let t = Temp::new();
            let secret = format!("secret-{suffix}");
            let client = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
            let destination = format!("{suffix}.invalid");
            let url = format!("https://fixture.invalid/{secret}");
            let mut event = scupper_proto::Event { seq: 1, at: UnixSeconds(100), kind: EventKind::FailClosedStarted { reason: Reason::NoHealthyExit, exit: Some(Identifier::try_from(secret.clone()).unwrap()) }, actor: Actor::Daemon, gateway: Identifier::try_from(secret.clone()).unwrap(), config_version: None };
            let mut j = Journal::new(100); j.enqueue(vec![event.alert().unwrap()]);
            event.kind = EventKind::AdminAction { command: scupper_proto::Command::Disconnect, reason: Some(format!("{client} {destination} {url} {secret}")) };
            proptest::prop_assert!(event.alert().is_none());
            j.save(&t.path()).unwrap();
            let output = format!("{}{}", std::fs::read_to_string(t.path()).unwrap(), serde_json::json!({"sink":"fixture","status":status(&t.0,"fixture").unwrap()}));
            for forbidden in [&client, &destination, &url, &secret] { proptest::prop_assert!(!output.contains(forbidden)); }
        }
    }

    #[test]
    fn worker_reports_local_persistence_failure_and_recovers_without_a_tick() {
        let t = Temp::new();
        let log = t.log();
        std::fs::remove_dir(t.0.join("sinks")).unwrap();
        std::fs::write(t.0.join("sinks"), b"blocked").unwrap();
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"kind":"ntfy","url_ref":"fixture","min_severity":"critical"}),
        )
        .unwrap();
        let settings = BTreeMap::from([("fixture".to_owned(), settings)]);
        let mut workers = Workers::default();
        workers.sync(&settings, &t.0, &t.0, &t.0.join("unused"), &log.handle, 0);
        let deadline = Instant::now() + Duration::from_secs(8);
        while log.handle.committed_seq() == 0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let rows: Vec<_> = events::read_since(&t.0, 0, Some(log.handle.committed_seq()))
            .collect::<io::Result<_>>()
            .unwrap();
        assert_eq!(
            rows.iter()
                .filter(|e| matches!(
                    e.kind,
                    EventKind::SinkFailed {
                        reason: Reason::AlertPersistence,
                        ..
                    }
                ))
                .count(),
            1
        );
        assert_eq!(workers.workers.len(), 1);
        std::fs::remove_file(t.0.join("sinks")).unwrap();
        std::fs::create_dir(t.0.join("sinks")).unwrap();
        while !t.path().exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        workers.stop();
    }
}
