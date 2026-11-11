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
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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
    // Historical snapshots wait briefly for a fresh observation; real outbox work never does.
    #[serde(default)]
    observe_until: Option<u64>,
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
            observe_until: None,
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
    #[serde(default)]
    critical_scanned: u64,
    #[serde(skip)]
    live_keys: Option<std::collections::BTreeSet<alerts::AlertKey>>,
    coalescer: Coalescer,
    bucket: TokenBucket,
    suppressed: u64,
    #[serde(default)]
    delivered: BTreeMap<alerts::AlertKey, alerts::AlertState>,
    #[serde(default = "new_test_bucket")]
    critical_bucket: TokenBucket,
    #[serde(default = "new_test_bucket")]
    test_bucket: TokenBucket,
    queue: Vec<Pending>,
}
fn new_test_bucket() -> TokenBucket {
    TokenBucket::new(monotonic())
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
            critical_scanned: 0,
            live_keys: None,
            coalescer: Coalescer::default(),
            bucket: TokenBucket::new(at),
            suppressed: 0,
            delivered: BTreeMap::new(),
            critical_bucket: TokenBucket::new(at),
            test_bucket: TokenBucket::new(at),
            queue: Vec::new(),
        }
    }
    fn owes_recovery(&self, key: alerts::AlertKey) -> bool {
        self.delivered.get(&key) == Some(&alerts::AlertState::Firing)
            || self
                .queue
                .iter()
                .any(|p| p.alert.key == key && p.observe_until.is_none())
    }
    fn observe(&mut self, alert: Alert, at: u64) {
        if alert.severity == alerts::Severity::Critical
            && alert.state == alerts::AlertState::Firing
            && let Some(pending) = self.queue.iter_mut().find(|p| p.alert.key == alert.key)
        {
            pending.observe_until = None;
        }
        let recovery = alert.severity == alerts::Severity::Critical
            && alert.state == alerts::AlertState::Resolved
            && self.owes_recovery(alert.key);
        let mut ready = self.coalescer.push_at(alert.clone(), at);
        if recovery && !ready.iter().any(|ready| ready.key == alert.key) {
            ready.push(alert);
        }
        self.enqueue(ready);
    }
    fn enqueue(&mut self, alerts: Vec<Alert>) {
        for mut alert in alerts {
            if alert.severity == alerts::Severity::Critical {
                if let Some(index) = self.queue.iter().position(|p| p.alert.key == alert.key) {
                    let pending = self.queue.remove(index);
                    if pending.alert.seq != alert.seq || pending.alert.state != alert.state {
                        self.suppressed = self.suppressed.saturating_add(1);
                    } else {
                        alert.count = alert.count.max(pending.alert.count);
                        alert.duration = alert.duration.max(pending.alert.duration);
                    }
                    if (pending.observe_until.is_none()
                        || alert.state == alerts::AlertState::Firing
                        || self.delivered.get(&alert.key) == Some(&alerts::AlertState::Firing))
                        && self.delivered.get(&alert.key) != Some(&alert.state)
                    {
                        // Collapsing changes state, not the sink's retry schedule
                        // or the admission already paid for this owed key.
                        let mut replacement = pending;
                        replacement.alert = alert;
                        self.queue.push(replacement);
                    }
                    continue;
                }
                if self
                    .delivered
                    .get(&alert.key)
                    .copied()
                    .unwrap_or(alerts::AlertState::Resolved)
                    == alert.state
                {
                    continue;
                }
            }
            if self.queue.len() == 64 {
                if let Some(index) = self
                    .queue
                    .iter()
                    .position(|p| p.alert.severity != alerts::Severity::Critical)
                {
                    self.queue.remove(index);
                } else if alert.severity != alerts::Severity::Critical {
                    self.suppressed = self.suppressed.saturating_add(1);
                    continue;
                } else {
                    // Three Critical keys always fit; explicit tests are expendable.
                    if let Some(index) = self.queue.iter().position(|p| p.test.is_some()) {
                        self.queue.remove(index);
                    }
                }
                self.suppressed = self.suppressed.saturating_add(1);
            }
            self.queue.push(Pending::new(alert));
        }
    }
    fn advance_clock(&mut self, at: u64) {
        if at < self.clock {
            self.bucket.rebase(self.clock, at);
            self.test_bucket.rebase(self.clock, at);
            self.critical_bucket.rebase(self.clock, at);
            self.coalescer.rebase(self.clock, at);
            self.failing_since = self
                .failing_since
                .map(|t| at.saturating_sub(self.clock.saturating_sub(t)));
            self.retry = at.saturating_add(self.retry.saturating_sub(self.clock));
            for p in &mut self.queue {
                p.observe_until = p
                    .observe_until
                    .map(|until| at.saturating_add(until.saturating_sub(self.clock)));
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
                // Upgrade old FIFO journals to one latest slot per Critical key.
                let mut keys = std::collections::BTreeSet::new();
                journal.queue.reverse();
                journal.queue.retain(|pending| {
                    pending.alert.severity != alerts::Severity::Critical
                        || keys.insert(pending.alert.key)
                });
                journal.queue.reverse();
                if !journal.queue.iter().any(|p| p.test.is_none()) {
                    journal.failing_since = None;
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
    if !journal.queue.iter().any(|p| p.test.is_none()) {
        journal.failing_since = None;
    }
    for pending in &mut journal.queue {
        if journal
            .live_keys
            .as_ref()
            .is_some_and(|keys| keys.contains(&pending.alert.key))
        {
            pending.observe_until = None;
        }
    }
    // A retained resolution is local to its key. Skip delayed retries, and
    // prioritize Critical among the first outstanding notification of each key.
    let alert_token_available = journal.critical_bucket.clone().take(at);
    let index = journal
        .queue
        .iter()
        .enumerate()
        .filter(|(i, p)| {
            !journal.queue[..*i]
                .iter()
                .any(|earlier| earlier.alert.key == p.alert.key)
        })
        .filter(|(_, p)| at >= p.retry && (p.test.is_some() || at >= journal.retry))
        .filter(|(_, p)| {
            p.alert.severity != alerts::Severity::Critical || p.admitted || alert_token_available
        })
        .filter(|(_, p)| {
            p.observe_until.is_none_or(|until| at >= until)
                || journal
                    .live_keys
                    .as_ref()
                    .is_some_and(|keys| keys.contains(&p.alert.key))
        })
        .max_by_key(|(i, p)| {
            (
                p.test.is_some() && (journal.failed || at < journal.retry),
                p.alert.severity == alerts::Severity::Critical,
                std::cmp::Reverse(*i),
            )
        })
        .map(|(i, _)| i);
    let expired = journal
        .failing_since
        .is_some_and(|first| alerts::exhausted(first, at));
    if expired && !journal.failed && index.is_none_or(|i| journal.queue[i].test.is_none()) {
        failure(log, sink.name(), Reason::AlertGiveUp)?;
        journal.failed = true;
        journal.retry = at.saturating_add(900);
        for pending in &journal.queue {
            if pending.test.is_none() {
                acknowledge(path, pending, "give_up")?;
            }
        }
        journal.suppressed = journal
            .suppressed
            .saturating_add(journal.queue.len() as u64);
        journal
            .queue
            .retain(|p| p.test.is_some() || p.alert.severity == alerts::Severity::Critical);
        return journal.save(path);
    }
    let Some(index) = index else {
        return Ok(());
    };
    if !journal.queue[index].admitted {
        let allowed = if journal.queue[index].test.is_some() {
            journal.test_bucket.take(at)
        } else if journal.queue[index].alert.severity == alerts::Severity::Critical {
            journal.critical_bucket.take(at)
        } else {
            journal.bucket.take(at)
        };
        if !allowed {
            if journal.queue[index].alert.severity == alerts::Severity::Critical {
                return journal.save(path);
            }
            let pending = journal.queue.remove(index);
            acknowledge(path, &pending, "rate_limited")?;
            journal.suppressed = journal.suppressed.saturating_add(1);
            return journal.save(path);
        }
        journal.queue[index].admitted = true;
        journal.queue[index].alert.suppressed = if journal.queue[index].test.is_none() {
            journal.suppressed
        } else {
            0
        };
    }
    journal.queue[index].first.get_or_insert(at);
    journal.save(path)?; // durable admission before the first attempt
    journal.queue[index].alert.suppressed = if journal.queue[index].test.is_none() {
        journal.suppressed
    } else {
        0
    };
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
            if journal.queue[index].test.is_some() {
                for pending in &mut journal.queue {
                    pending.retry = 0;
                }
            }
            acknowledge(path, &journal.queue[index], "delivered")?;
            let pending = journal.queue.remove(index);
            if pending.alert.severity == alerts::Severity::Critical {
                journal
                    .delivered
                    .insert(pending.alert.key, pending.alert.state);
            }
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
            if journal.queue[index].test.is_none() {
                journal.failing_since.get_or_insert(completed);
            }
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
                if journal.queue[index].alert.severity != alerts::Severity::Critical {
                    journal.queue.remove(index);
                }
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
    if !journal.queue.iter().any(|p| p.test.is_none()) {
        journal.failing_since = None;
    }
    journal.clock = completed;
    journal.save(path)
}

fn test_directory(path: &Path) -> PathBuf {
    path.with_extension("tests")
}
fn acknowledge(path: &Path, pending: &Pending, outcome: &str) -> io::Result<()> {
    if let Some(id) = &pending.test {
        if test_directory(path).join(format!("{id}.cancel")).exists() {
            return Ok(());
        }
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
fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}
fn clean_tests(journal: &mut Journal, path: &Path) -> io::Result<()> {
    let directory = test_directory(path);
    let before = journal.queue.len();
    journal
        .queue
        .retain(|p| p.test.is_none() || now().saturating_sub(p.alert.at) < 600);
    if before != journal.queue.len() {
        journal.save(path)?;
    }
    for entry in std::fs::read_dir(&directory)? {
        let entry = entry?;
        let file = entry.path();
        let Some(id) = file
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| valid_request_id(s))
        else {
            continue;
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let expired =
            metadata.modified()?.elapsed().unwrap_or_default() >= Duration::from_secs(600);
        if file.extension().is_some_and(|s| s == "cancel") || expired {
            journal.queue.retain(|p| p.test.as_deref() != Some(id));
            journal.save(path)?;
            for extension in ["request", "outcome", "cancel"] {
                remove_if_present(&directory.join(format!("{id}.{extension}")))?;
            }
        }
    }
    Ok(())
}
fn ingest_tests(journal: &mut Journal, path: &Path) -> io::Result<()> {
    let directory = test_directory(path);
    durable_directory(&directory)?;
    clean_tests(journal, path)?;
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
            if journal.queue.len() == 64 {
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
                    .filter(|a| {
                        a.severity != alerts::Severity::Critical
                            || event.seq > journal.critical_scanned
                    })
                {
                    journal.observe(alert, monotonic());
                }
            }
            events::TailRecord::Skipped(seq) => {
                log.emit(EventKind::EventSkipped { seq }, Actor::Daemon, None)
                    .map_err(io::Error::other)?;
            }
        }
    }
    journal.scanned = upper;
    journal.critical_scanned = upper;
    journal.save(path)
}

fn run_worker(
    root: &Path,
    sink: &Sink,
    log: &mut LogHandle,
    receive: &Mutex<Option<LogHandle>>,
    stopping: &AtomicBool,
    healthy: &mut bool,
) -> io::Result<()> {
    // Recovery may replace a memory-only log while the worker is backing off.
    loop {
        if let Some(updated) = receive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            *log = updated;
        }
        if log.is_persistent() {
            break;
        }
        if stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
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
        if let Some(updated) = receive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            *log = updated;
        }
        if !log.is_persistent() {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }
        scan_events(&mut journal, &mut tail, root, &path, log, &sink.settings)?;
        ingest_tests(&mut journal, &path)?;
        journal.live_keys = Some(log.current_critical_keys(journal.scanned));
        step_with_ack(
            &mut journal,
            &path,
            sink,
            log,
            monotonic(),
            &monotonic,
            &|| Ok(()),
        )?;
        *healthy = true;
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
    log: Arc<Mutex<Option<LogHandle>>>,
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
                *worker
                    .log
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(log.clone());
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
            let send = Arc::new(Mutex::new(None));
            let receive = send.clone();
            let failure_log = log.clone();
            let mut log = log.clone();
            let result = std::thread::Builder::new()
                .name(format!("scupper-alert-{name}"))
                .spawn(move || {
                    let mut delay = 5;
                    let mut reported = false;
                    while !stopping.load(Ordering::Acquire) {
                        let mut healthy = false;
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            run_worker(&root, &sink, &mut log, &receive, &stopping, &mut healthy)
                        }))
                        .is_ok_and(|r| r.is_ok())
                        {
                            break;
                        }
                        if healthy {
                            delay = 5;
                            reported = false;
                        }
                        if !reported {
                            eprintln!("scupperd: alert persistence unavailable");
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
    for entry in std::fs::read_dir(&directory)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|s| s == "outcome")
            && entry.metadata()?.modified()?.elapsed().unwrap_or_default()
                >= Duration::from_secs(600)
        {
            remove_if_present(&entry.path())?;
        }
    }
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
/// Cancel a timed-out request and remove its receipt, including late acknowledgements.
/// # Errors
/// Invalid identities or local filesystem failure.
pub fn cancel_test(root: &Path, name: &str, id: &str) -> io::Result<()> {
    if !valid_request_id(id) {
        return Err(io::Error::other("invalid test identity"));
    }
    let directory = test_directory(&cursor_path(root, name)?);
    durable_replace(
        &RealFs,
        &directory.join(format!("{id}.cancel")),
        b"cancel",
        0o600,
        &|_| Ok(()),
        &|_| Ok(()),
    )?;
    remove_if_present(&directory.join(format!("{id}.request")))?;
    remove_if_present(&directory.join(format!("{id}.outcome")))
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
    let mut existing = false;
    let mut journal = if path.exists() {
        match Journal::load(path, monotonic()) {
            Ok(journal) => {
                existing = true;
                journal
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                std::fs::rename(path, path.with_extension("corrupt"))?;
                RealFs.sync_dir(&root.join("sinks"))?;
                Journal::new(monotonic())
            }
            Err(e) => return Err(e),
        }
    } else {
        Journal::new(monotonic())
    };
    // Recompute incident truth independently of stale worker-local dedup state.
    // Preserve queued non-Critical work; new sinks never replay old transitions.
    let upper = log.committed_seq();
    let mut latest = BTreeMap::new();
    let mut current = Coalescer::default();
    let mut tail = events::Tail::default();
    for record in tail.read(root, 0, upper)? {
        if let events::TailRecord::Event(event) = record
            && let Some(alert) = event
                .alert()
                .filter(|a| a.severity == alerts::Severity::Critical)
        {
            // An orphan recovery is meaningful only to a sink that already owes it.
            if alert.state == alerts::AlertState::Resolved && journal.owes_recovery(alert.key) {
                latest.insert(alert.key, alert.clone());
            }
            for ready in current.push_at(alert, monotonic()) {
                latest.insert(ready.key, ready);
            }
        }
    }
    for alert in latest.values_mut() {
        if alert.state == alerts::AlertState::Firing
            && let Some((since, count)) = current.incident_stats(alert.key)
        {
            alert.at = since;
            alert.count = count;
        }
    }
    journal.coalescer.restore_critical(&current);
    journal.critical_scanned = upper;
    if !existing {
        journal.scanned = upper;
    }
    for alert in latest.into_values() {
        if existing || alert.state == alerts::AlertState::Firing {
            let key = alert.key;
            let snapshot = alert.state == alerts::AlertState::Firing
                && !journal.queue.iter().any(|p| p.alert.key == key);
            journal.enqueue(vec![alert]);
            if snapshot && let Some(pending) = journal.queue.iter_mut().find(|p| p.alert.key == key)
            {
                pending.observe_until = Some(monotonic().saturating_add(120));
            }
        }
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
            map(OperationalEvent::Failover, 1, 100),
            map(OperationalEvent::Failback, 2, 103),
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
    fn critical_flaps_converge_through_scan_and_survive_restart() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "kind":"ntfy", "url_ref":"fixture", "min_severity":"critical"
        }))
        .unwrap();
        let mut j = Journal::new(0);
        let mut tail = events::Tail::default();
        for seq in 1..=7 {
            log.handle
                .emit(
                    if seq % 2 == 1 {
                        EventKind::FailClosedStarted {
                            reason: Reason::NoHealthyExit,
                            exit: None,
                        }
                    } else {
                        EventKind::FailClosedEnded {
                            duration: Duration::from_secs(1),
                        }
                    },
                    Actor::Daemon,
                    None,
                )
                .unwrap();
            log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
            scan_events(&mut j, &mut tail, &t.0, &t.path(), &log.handle, &settings).unwrap();
            step(
                &mut j,
                &t.path(),
                &sink,
                &log.handle,
                ((seq - 1) * 60).min(301),
            )
            .unwrap();
        }
        j.save(&t.path()).unwrap();
        let mut j = Journal::load(&t.path(), 600).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 600).unwrap();
        assert_eq!(sink.sent.lock().unwrap().last(), Some(&7));
        assert_eq!(
            j.delivered.get(&alerts::AlertKey::FailClosed),
            Some(&alerts::AlertState::Firing)
        );
    }
    #[test]
    fn tests_have_their_own_allowance_before_outage() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(0);
        for _ in 0..5 {
            let id = request_test(&t.0, "fixture").unwrap();
            ingest_tests(&mut j, &t.path()).unwrap();
            step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
            assert_eq!(
                test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
                Some("delivered")
            );
        }
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 0)]);
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        assert_eq!(sink.sent.lock().unwrap().last(), Some(&1));
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
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 1, 1, 1, 1, 1, 4, 2, 3]);
    }
    #[test]
    fn outage_storm_collapses_to_latest_critical_with_bounded_queue() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Err(SinkError::Transient));
        let mut j = Journal::new(0);
        for seq in 1..=71 {
            let ready = j.coalescer.push_at(
                map(
                    if seq % 2 == 1 {
                        OperationalEvent::FailClosedStarted
                    } else {
                        OperationalEvent::FailClosedEnded(1)
                    },
                    seq,
                    seq,
                ),
                0,
            );
            j.enqueue(ready);
            step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
            assert!(j.queue.len() <= 1);
        }
        assert_eq!(
            sink.sent.lock().unwrap().len(),
            1,
            "flaps must not reset retry backoff"
        );
        *sink.result.lock().unwrap() = Ok(());
        step(&mut j, &t.path(), &sink, &log.handle, 300).unwrap();
        assert_eq!(sink.sent.lock().unwrap().last(), Some(&71));
        assert!(j.queue.is_empty());
        assert!(std::fs::metadata(t.path()).unwrap().len() < 4096);
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
                    assert!(j.test_bucket.take(100));
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
    fn deferred_critical_does_not_block_independent_test_allowance() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(0);
        for _ in 0..5 {
            assert!(j.critical_bucket.take(0));
        }
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 0)]);
        let id = request_test(&t.0, "fixture").unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        assert_eq!(
            test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
            Some("delivered")
        );
        assert_eq!(*sink.sent.lock().unwrap(), vec![0]);
        step(&mut j, &t.path(), &sink, &log.handle, 300).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![0, 1]);
    }
    #[test]
    fn overflow_evicts_oldest_noncritical_and_keeps_latest_critical() {
        let mut j = Journal::new(0);
        j.enqueue(
            (1..=65)
                .map(|seq| map(OperationalEvent::Failover, seq, 0))
                .collect(),
        );
        assert_eq!(j.queue.len(), 64);
        assert_eq!(j.queue[0].alert.seq, 2);
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 66, 0)]);
        assert_eq!(j.queue[0].alert.seq, 3);
        for seq in 67..=136 {
            j.enqueue(vec![map(
                if seq % 2 == 1 {
                    OperationalEvent::FailClosedEnded(1)
                } else {
                    OperationalEvent::FailClosedStarted
                },
                seq,
                0,
            )]);
            assert_eq!(j.queue.len(), 64);
        }
        assert_eq!(j.queue.last().unwrap().alert.seq, 136);
        assert_eq!(
            j.queue.last().unwrap().alert.state,
            alerts::AlertState::Firing
        );
    }

    #[test]
    fn failed_test_does_not_age_a_later_real_alert() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Err(SinkError::Transient));
        let mut j = Journal::new(0);
        let id = request_test(&t.0, "fixture").unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        assert_eq!(
            test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
            Some("transient")
        );
        assert_eq!(j.failing_since, None);
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 172_800)]);
        step(&mut j, &t.path(), &sink, &log.handle, 172_800).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![0, 1]);
        assert!(!j.failed);
    }
    #[test]
    fn successful_test_bypasses_slow_retry_and_releases_critical() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Err(SinkError::Permanent));
        let mut j = Journal::new(0);
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 0)]);
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        assert!(j.failed);
        let id = request_test(&t.0, "fixture").unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        *sink.result.lock().unwrap() = Ok(());
        step(&mut j, &t.path(), &sink, &log.handle, 1).unwrap();
        assert_eq!(
            test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
            Some("delivered")
        );
        assert!(!j.failed);
        assert_eq!(j.failing_since, None);
        step(&mut j, &t.path(), &sink, &log.handle, 1).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 0, 1]);
        assert!(j.queue.is_empty());
    }
    #[test]
    fn timeouts_and_expired_receipts_never_lock_out_tests_or_deliver_late() {
        let t = Temp::new();
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let mut j = Journal::new(0);
        for _ in 0..70 {
            let id = request_test(&t.0, "fixture").unwrap();
            ingest_tests(&mut j, &t.path()).unwrap();
            let pending = j.queue[0].clone();
            cancel_test(&t.0, "fixture", &id).unwrap();
            acknowledge(&t.path(), &pending, "delivered").unwrap();
            assert_eq!(test_outcome(&t.0, "fixture", &id).unwrap(), None);
            ingest_tests(&mut j, &t.path()).unwrap();
            step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        }
        assert!(sink.sent.lock().unwrap().is_empty());
        let id = request_test(&t.0, "fixture").unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        let outcome = test_directory(&t.path()).join(format!("{id}.outcome"));
        std::fs::File::open(outcome)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH))
            .unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        assert_eq!(test_outcome(&t.0, "fixture", &id).unwrap(), None);
    }
    #[test]
    fn historical_snapshot_waits_for_observation_without_unmatched_recovery() {
        let t = Temp::new();
        let old = t.log();
        old.handle
            .emit(
                EventKind::FailClosedStarted {
                    reason: Reason::NoHealthyExit,
                    exit: None,
                },
                Actor::Daemon,
                None,
            )
            .unwrap();
        old.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        drop(old);
        let log = t.log();
        let sink = Fake::new(Ok(()));
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"kind":"ntfy", "url_ref":"fixture", "min_severity":"critical"}),
        )
        .unwrap();
        for _ in 0..2 {
            let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
            j.live_keys = Some(log.handle.current_critical_keys(j.scanned));
            step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
            assert!(sink.sent.lock().unwrap().is_empty());
        }
        log.handle
            .emit(
                EventKind::FailClosedState { closed: false },
                Actor::Daemon,
                None,
            )
            .unwrap();
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
        let mut tail = events::Tail::default();
        scan_events(&mut j, &mut tail, &t.0, &t.path(), &log.handle, &settings).unwrap();
        j.live_keys = Some(log.handle.current_critical_keys(j.scanned));
        step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
        let started = log
            .handle
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
        scan_events(&mut j, &mut tail, &t.0, &t.path(), &log.handle, &settings).unwrap();
        j.live_keys = Some(log.handle.current_critical_keys(j.scanned));
        step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![started]);
    }
    #[test]
    fn critical_retry_and_incident_stats_survive_worker_reconstruction() {
        let t = Temp::new();
        let log = t.log();
        for _ in 0..2 {
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
        }
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
        assert_eq!(j.queue[0].alert.count, 2);
        j.live_keys = Some(log.handle.current_critical_keys(j.critical_scanned));
        let at = monotonic();
        let sink = Fake::new(Err(SinkError::Transient));
        step(&mut j, &t.path(), &sink, &log.handle, at).unwrap();
        let retry = j.queue[0].retry;
        let first = j.queue[0].first;
        let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
        assert_eq!(j.queue[0].retry, retry);
        assert_eq!(j.queue[0].first, first);
        assert_eq!(j.queue[0].alert.count, 2);
        step(&mut j, &t.path(), &sink, &log.handle, at + 1).unwrap();
        assert_eq!(sink.sent.lock().unwrap().len(), 1);
    }
    #[test]
    fn empty_old_journal_cannot_carry_a_test_failure_clock_into_real_alerts() {
        let t = Temp::new();
        let log = t.log();
        let mut j = Journal::new(0);
        j.failing_since = Some(0);
        j.save(&t.path()).unwrap();
        let mut j = Journal::load(&t.path(), 172_800).unwrap();
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 172_800)]);
        let sink = Fake::new(Ok(()));
        step(&mut j, &t.path(), &sink, &log.handle, 172_800).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1]);
        assert!(!j.failed);
    }
    #[test]
    fn exhausted_bucket_rebases_and_refills_after_three_hundred_seconds() {
        let t = Temp::new();
        let log = t.log();
        let mut j = Journal::new(86400);
        for _ in 0..5 {
            assert!(j.critical_bucket.take(86400));
        }
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 100)]);
        j.save(&t.path()).unwrap();
        let mut j = Journal::load(&t.path(), 1).unwrap();
        let sink = Fake::new(Ok(()));
        step(&mut j, &t.path(), &sink, &log.handle, 300).unwrap();
        assert!(sink.sent.lock().unwrap().is_empty());
        step(&mut j, &t.path(), &sink, &log.handle, 301).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1]);
    }
    #[test]
    fn restart_recomputes_stale_open_incident_from_current_durable_state() {
        let t = Temp::new();
        let log = t.log();
        log.handle
            .emit(
                EventKind::FailClosedEnded {
                    duration: Duration::from_secs(90),
                },
                Actor::Daemon,
                None,
            )
            .unwrap();
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let mut j = Journal::new(monotonic());
        j.scanned = log.handle.committed_seq();
        j.coalescer
            .push_at(map(OperationalEvent::FailClosedStarted, 0, 0), monotonic());
        j.delivered
            .insert(alerts::AlertKey::FailClosed, alerts::AlertState::Firing);
        j.save(&t.path()).unwrap();
        let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
        let sink = Fake::new(Ok(()));
        step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
        let ready = j.coalescer.push_at(
            map(OperationalEvent::FailClosedStarted, 2, 100),
            monotonic(),
        );
        j.enqueue(ready);
        step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1, 2]);
    }
    #[test]
    fn owed_recovery_is_not_lost_when_another_key_flushes() {
        let mut j = Journal::new(0);
        let _ = j
            .coalescer
            .push_at(map(OperationalEvent::Failover, 1, 0), 0);
        let _ = j
            .coalescer
            .push_at(map(OperationalEvent::Failback, 2, 1), 1);
        j.delivered
            .insert(alerts::AlertKey::FailClosed, alerts::AlertState::Firing);
        j.observe(map(OperationalEvent::FailClosedEnded(600), 3, 600), 600);
        assert_eq!(j.queue.len(), 2);
        assert!(
            j.queue
                .iter()
                .any(|p| p.alert.key == alerts::AlertKey::FailClosed
                    && p.alert.state == alerts::AlertState::Resolved)
        );
        assert!(
            j.queue
                .iter()
                .any(|p| p.alert.key == alerts::AlertKey::Failover
                    && p.alert.state == alerts::AlertState::Resolved)
        );
    }
    #[test]
    fn clean_restart_state_reports_and_orphan_recoveries_deliver_nothing() {
        let t = Temp::new();
        let log = t.log();
        Journal::new(monotonic()).save(&t.path()).unwrap();
        for kind in [
            EventKind::FailClosedEnded {
                duration: Duration::ZERO,
            },
            EventKind::QuarantineChanged { active: false },
            EventKind::FailClosedState { closed: false },
            EventKind::QuarantineState { active: false },
        ] {
            log.handle.emit(kind, Actor::Daemon, None).unwrap();
        }
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let sink = Fake::new(Ok(()));
        for _ in 0..3 {
            let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
            step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
            assert!(j.queue.is_empty());
        }
        assert!(sink.sent.lock().unwrap().is_empty());
    }
    #[test]
    fn durable_owed_state_delivers_without_reobserving_its_key() {
        for resolved in [false, true] {
            let t = Temp::new();
            let log = t.log();
            let mut j = Journal::new(monotonic());
            j.enqueue(vec![map(OperationalEvent::Unprotected, 1, 100)]);
            if resolved {
                j.enqueue(vec![map(OperationalEvent::ProtectionRestored, 2, 101)]);
            }
            j.save(&t.path()).unwrap();
            let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
            j.live_keys = Some(std::collections::BTreeSet::new());
            let sink = Fake::new(Ok(()));
            step(&mut j, &t.path(), &sink, &log.handle, monotonic()).unwrap();
            assert_eq!(
                *sink.sent.lock().unwrap(),
                vec![if resolved { 2 } else { 1 }]
            );
            assert!(j.queue.is_empty());
        }
    }
    #[test]
    fn historical_snapshot_observation_wait_is_bounded() {
        let t = Temp::new();
        let log = t.log();
        log.handle
            .emit(
                EventKind::QuarantineState { active: true },
                Actor::Daemon,
                None,
            )
            .unwrap();
        log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
        let mut j = open_journal(&t.0, &t.path(), &log.handle).unwrap();
        j.live_keys = Some(std::collections::BTreeSet::new());
        let until = j.queue[0].observe_until.unwrap();
        let sink = Fake::new(Ok(()));
        step(&mut j, &t.path(), &sink, &log.handle, until - 1).unwrap();
        assert!(sink.sent.lock().unwrap().is_empty());
        step(&mut j, &t.path(), &sink, &log.handle, until).unwrap();
        assert_eq!(sink.sent.lock().unwrap().len(), 1);
    }
    #[test]
    fn warning_storm_cannot_spend_critical_allowance_and_tests_keep_suppression() {
        let t = Temp::new();
        let log = t.log();
        let mut j = Journal::new(0);
        for _ in 0..5 {
            assert!(j.bucket.take(0));
        }
        let sink = Fake::new(Ok(()));
        j.enqueue(vec![map(OperationalEvent::FailClosedStarted, 1, 100)]);
        step(&mut j, &t.path(), &sink, &log.handle, 0).unwrap();
        assert_eq!(*sink.sent.lock().unwrap(), vec![1]);
        j.suppressed = 7;
        let id = request_test(&t.0, "fixture").unwrap();
        ingest_tests(&mut j, &t.path()).unwrap();
        step(&mut j, &t.path(), &sink, &log.handle, 1).unwrap();
        assert_eq!(
            test_outcome(&t.0, "fixture", &id).unwrap().as_deref(),
            Some("delivered")
        );
        assert_eq!(j.suppressed, 7);
        assert_eq!(sink.suppressed.load(Ordering::Acquire), 0);
        j.enqueue(vec![map(OperationalEvent::QuarantineSet, 3, 101)]);
        step(&mut j, &t.path(), &sink, &log.handle, 2).unwrap();
        assert_eq!(sink.suppressed.load(Ordering::Acquire), 7);
        assert_eq!(j.suppressed, 0);
    }
    #[test]
    fn memory_log_at_start_waits_without_false_sink_failure() {
        let t = Temp::new();
        let memory = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"kind":"ntfy", "url_ref":"fixture", "min_severity":"critical"}),
        )
        .unwrap();
        let mut workers = Workers::default();
        let settings = BTreeMap::from([("fixture".into(), settings)]);
        workers.sync(
            &settings,
            &t.0,
            &t.0,
            &t.0.join("unused"),
            &memory.handle,
            0,
        );
        std::thread::sleep(Duration::from_millis(250));
        let persistent = t.log();
        workers.sync(
            &settings,
            &t.0,
            &t.0,
            &t.0.join("unused"),
            &persistent.handle,
            0,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !t.path().exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        memory.handle.replay_into(&persistent.handle).unwrap();
        persistent
            .handle
            .flush_blocking(Duration::from_secs(5))
            .unwrap();
        assert!(
            !events::read_since(&t.0, 0, None)
                .map(Result::unwrap)
                .any(|e| matches!(e.kind, EventKind::SinkFailed { .. }))
        );
        workers.stop();
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
        // A second independent local failure reports again and restarts at five
        // seconds after the intervening healthy step, rather than doubling forever.
        std::thread::sleep(Duration::from_millis(250));
        let previous = log.handle.committed_seq();
        std::fs::remove_dir_all(t.0.join("sinks")).unwrap();
        std::fs::write(t.0.join("sinks"), b"blocked again").unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while log.handle.committed_seq() == previous {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::remove_file(t.0.join("sinks")).unwrap();
        std::fs::create_dir(t.0.join("sinks")).unwrap();
        while !t.path().exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        let failures = events::read_since(&t.0, 0, None)
            .map(Result::unwrap)
            .filter(|e| {
                matches!(
                    e.kind,
                    EventKind::SinkFailed {
                        reason: Reason::AlertPersistence,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(failures, 2);
        workers.stop();
    }
}
