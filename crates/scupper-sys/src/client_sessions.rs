//! Per-peer session reset generations and constrained gateway recovery probes.
#[cfg(feature = "testing")]
pub mod confirmation_testing;
mod netlink;
mod sampler;
use crate::{
    fs::{RealFs, durable_replace},
    lock::WriterGuard,
    netns::{NetnsHandle, NetnsId},
    system::{EXEC_TIMEOUT, System},
};
pub use sampler::Sampler;
use scupper_core::{
    config::{GatewayId, ValidatedSite},
    verdict::v2::ClientSessions,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsFd,
    path::Path,
    time::{Duration, Instant},
};

/// Public, full-resolution peer telemetry from generic netlink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// Peer public key.
    pub key: [u8; 32],
    /// Native netlink timespec: seconds and nanoseconds, zero for Never.
    pub handshake: (u64, u32),
    /// Kernel receive byte counter (includes handshake traffic).
    pub rx: u64,
    /// Kernel transmit byte counter.
    pub tx: u64,
}
/// One bounded child operation. Probe port and payload cannot be supplied.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Held namespace identity, passed separately on stdin.
    pub namespace: NetnsId,
    /// Validated configured client interface.
    pub iface: String,
    /// None reads telemetry; Some sends one fixed datagram to each host.
    pub probe: Option<(Ipv4Addr, Vec<Ipv4Addr>)>,
}
/// Live device incarnation, independently verified by the telemetry child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceId {
    /// Host boot identity; a reused namespace inode cannot mask a reboot.
    pub boot: String,
    /// Kernel device index within the held namespace.
    pub ifindex: u32,
}
#[derive(Clone)]
struct Snapshot {
    peers: Vec<Sample>,
    device: Option<DeviceId>,
    up: bool,
}
/// Child output contains public observations only.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Full-resolution peer telemetry.
    Samples(Vec<Sample>),
    /// Production telemetry binds every complete peer dump to the live device.
    Telemetry {
        /// Device identity associated with the dump.
        device: DeviceId,
        /// Administrative link state from route netlink.
        up: bool,
        /// Complete peer dump.
        peers: Vec<Sample>,
    },
    /// Per-destination send success, in request order.
    Probes(Vec<bool>),
}
const VERSION: u32 = 3;
const LEASE: u64 = 180;
/// Sampling starts every five seconds, independently of reconciler work.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
// Five-second cadence plus 10 s of collection/commit/scheduling slack.
// The netlink child is bounded to 3 s; missed cadence slots are gaps.
const SAMPLE_FRESHNESS: u64 = 15;
const CONFIRMATION_BUDGET: Duration = Duration::from_millis(500);
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// A timeout excludes a dormant peer from the required cohort; it is not recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum SessionState {
    RequiredPending,
    Recovered,
    ExpiredUnconfirmed,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reset {
    generation: u64,
    baseline: Sample,
    observed: Sample,
    last_authenticated: Option<u64>,
    lease_until: Option<u64>,
    state: SessionState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum History {
    Available,
    Unavailable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gap {
    start: u64,
    end: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanStop {
    namespace: NetnsId,
    device: Option<DeviceId>,
    sequence: u64,
    at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent lifecycle, link and probe facts.
struct Record {
    version: u32,
    gateway: String,
    incarnation: String,
    sequence: u64,
    never_served: bool,
    resumed_at: Option<u64>,
    clean_stop: Option<CleanStop>,
    invalidation: String,
    written_at: u64,
    history: History,
    renewed_at: Option<u64>,
    sample_failed_at: Option<u64>,
    gaps: Vec<Gap>,
    namespace: NetnsId,
    device: Option<DeviceId>,
    down: bool,
    down_since: Option<u64>,
    unknown_until: Option<u64>,
    probe_pending: bool,
    #[serde(default)]
    baseline_pending: bool,
    peers: Vec<Reset>,
}
impl Record {
    fn unknown(gateway: &str, now: u64) -> Self {
        Self {
            version: VERSION,
            gateway: gateway.into(),
            incarnation: String::new(),
            sequence: 0,
            never_served: false,
            resumed_at: None,
            clean_stop: None,
            invalidation: String::new(),
            written_at: now,
            history: History::Unavailable,
            renewed_at: None,
            sample_failed_at: None,
            gaps: vec![Gap {
                start: now,
                end: None,
            }],
            namespace: (0, 0),
            device: None,
            down: false,
            down_since: None,
            unknown_until: Some(now.saturating_add(LEASE)),
            probe_pending: false,
            baseline_pending: false,
            peers: Vec::new(),
        }
    }
}
impl Record {
    fn observation_anchor(&self) -> u64 {
        self.resumed_at
            .or(self.renewed_at)
            .or_else(|| self.unknown_until.map(|end| end.saturating_sub(LEASE)))
            .unwrap_or(self.written_at)
    }
    fn stale(&self, now: u64) -> bool {
        !self.never_served
            && (now < self.written_at
                || now.saturating_sub(self.observation_anchor()) > SAMPLE_FRESHNESS)
    }
    fn open_gap(&mut self, start: u64) {
        if self.gaps.last().is_none_or(|g| g.end.is_some()) {
            self.gaps.push(Gap { start, end: None });
        }
    }
    fn note_stall(&mut self, now: u64) {
        if self.stale(now) {
            self.open_gap(self.observation_anchor().saturating_add(SAMPLE_FRESHNESS));
        }
    }
    fn gap_unknown(&self, now: u64) -> bool {
        self.gaps
            .iter()
            .any(|g| g.end.is_none_or(|end| end.saturating_add(LEASE) > now))
            || self.stale(now)
    }
    fn validate_rebuild(&mut self, now: u64) {
        self.note_stall(now);
        if self.gap_unknown(now) {
            self.history = History::Unavailable;
        }
    }
    fn complete_sample(&mut self, now: u64) {
        self.note_stall(now);
        if let Some(gap) = self.gaps.last_mut()
            && gap.end.is_none()
        {
            gap.end = Some(now);
        }
        self.gaps
            .retain(|g| g.end.is_none_or(|end| end.saturating_add(LEASE) > now));
        self.renewed_at = Some(now);
        self.resumed_at = None;
        self.sample_failed_at = None;
        if self.gaps.is_empty() {
            self.history = History::Available;
        }
        if self.unknown_until.is_some_and(|end| now >= end) {
            self.unknown_until = None;
        }
    }
}

fn path(root: &Path) -> std::path::PathBuf {
    root.join("client-sessions.json")
}
fn valid(record: &Record, gateway: &str, now: u64) -> bool {
    let mut keys = std::collections::BTreeSet::new();
    record.version == VERSION
        && record.gateway == gateway
        && (!record.never_served
            || (record.peers.is_empty()
                && record.renewed_at.is_none()
                && record.resumed_at.is_none()
                && record.gaps.is_empty()
                && record.history == History::Available
                && record.clean_stop.is_none()))
        && record.resumed_at.is_none_or(|at| at <= record.written_at)
        && record.clean_stop.as_ref().is_none_or(|stop| {
            stop.namespace == record.namespace
                && stop.device == record.device
                && stop.sequence == record.sequence
                && Some(stop.at) == record.renewed_at
                && stop.at == record.written_at
                && record.sample_failed_at.is_none()
                && record.down_since.is_none()
                && record.down
        })
        && (record.never_served
            || record.resumed_at.is_some()
            || record.renewed_at.is_some()
            || record.history == History::Unavailable
                && (record.unknown_until.is_some()
                    || record.gaps.last().is_some_and(|g| g.end.is_none())))
        && record.written_at <= now
        && record.renewed_at.is_none_or(|t| t <= record.written_at)
        && record
            .sample_failed_at
            .is_none_or(|t| t <= record.written_at)
        && record.gaps.len() <= 1024
        && record.gaps.iter().enumerate().all(|(i, g)| {
            g.start <= record.written_at
                && g.end
                    .is_none_or(|end| g.start <= end && end <= record.written_at)
                && (g.end.is_some() || i + 1 == record.gaps.len())
                && (i == 0 || record.gaps[i - 1].end.is_some_and(|end| end <= g.start))
        })
        && record.down_since.is_none_or(|t| t <= record.written_at)
        && record
            .unknown_until
            .is_none_or(|t| t <= record.written_at.saturating_add(LEASE))
        && record.peers.len() <= 1024
        && record.peers.iter().all(|p| {
            keys.insert(p.baseline.key)
                && p.baseline.key == p.observed.key
                && p.baseline.handshake.1 < 1_000_000_000
                && p.observed.handshake.1 < 1_000_000_000
                && p.last_authenticated.is_none_or(|t| t <= record.written_at)
                && p.lease_until == p.last_authenticated.map(|t| t.saturating_add(LEASE))
        })
}
fn read_record(file: &Path, gateway: &str, now: u64) -> io::Result<Record> {
    read_bound_record(file, Some(gateway), now)
}
fn read_raw_record(file: &Path) -> io::Result<Record> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(file)?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversize history",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
fn read_bound_record(file: &Path, gateway: Option<&str>, now: u64) -> io::Result<Record> {
    let record = read_raw_record(file)?;
    let incarnation = std::fs::read_to_string(
        file.parent()
            .unwrap_or(Path::new("."))
            .join("gateway-incarnation"),
    )
    .or_else(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Ok(String::new())
        } else {
            Err(error)
        }
    })?;
    if !valid(&record, gateway.unwrap_or(&record.gateway), now)
        || (file
            .file_name()
            .is_some_and(|name| name == "client-sessions.json")
            && record.incarnation != incarnation)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unavailable history",
        ));
    }
    Ok(record)
}
#[cfg(all(test, feature = "testing"))]
fn load(root: &Path, gateway: &str, now: u64) -> Record {
    read_record(&path(root), gateway, now).unwrap_or_else(|_| Record::unknown(gateway, now))
}
fn current_path(root: &Path, run: &Path) -> std::path::PathBuf {
    let fallback = run.join("client-sessions-fallback");
    if fallback.exists() {
        fallback
    } else {
        path(root)
    }
}
fn sealed_record(root: &Path, gateway: &str, now: u64) -> Option<Record> {
    sealed_checkpoint(root, gateway, now).ok().flatten()
}
fn sealed_checkpoint(root: &Path, gateway: &str, now: u64) -> io::Result<Option<Record>> {
    read_record(&path(root), gateway, now)
        .map(|record| record.clean_stop.is_some().then_some(record))
}
fn is_sealed(root: &Path, gateway: &str, now: u64) -> bool {
    // Precondition: the supervisor lease, sampler-owner lock and session lock
    // exclude every writer during and after clean_stop, until a new opening.
    // In particular, no writer carrying a pre-seal `now` may run after sealing.
    // A fresh live-UP observation quarantines an unconsumed seal before the
    // sampler or an opening hook evaluates this predicate.
    // Readers, lifecycle hooks and writer fences share this exact validation.
    sealed_record(root, gateway, now).is_some()
}
fn load_current(root: &Path, run: &Path, gateway: &str, now: u64) -> Record {
    if run.join("client-session-seal-obsolete").exists()
        && read_raw_record(&path(root)).is_ok_and(|record| record.clean_stop.is_some())
    {
        return Record::unknown(gateway, now);
    }
    if let Some(record) = sealed_record(root, gateway, now) {
        return record;
    }
    if read_raw_record(&path(root)).is_ok_and(|record| record.clean_stop.is_some()) {
        // A rejected marker is damaged history even if an old runtime fallback
        // is still readable. Only a writer can quarantine it and reconstruct.
        return Record::unknown(gateway, now);
    }
    read_record(&current_path(root, run), gateway, now)
        .and_then(|mut record| {
            if run.join("client-session-opening").exists() {
                record.history = History::Unavailable;
                record.renewed_at = None;
            }
            if record.invalidation == invalidation(run)
                && record.incarnation
                    == std::fs::read_to_string(root.join("gateway-incarnation")).unwrap_or_default()
            {
                if run.join("client-session-commit").exists() {
                    // Withhold uncommitted freshness without discarding the
                    // fallback's original recovery horizon and peer obligations.
                    record.history = History::Unavailable;
                    record.renewed_at = None;
                }
                Ok(record)
            } else {
                Err(io::Error::other("invalidated history"))
            }
        })
        .unwrap_or_else(|_| Record::unknown(gateway, now))
}
fn history_alert(run: &Path) {
    let _ = durable_replace(
        &RealFs,
        &run.join("client-session-history-alert"),
        b"unavailable\n",
        0o600,
        &|_| Ok(()),
        &|_| Ok(()),
    );
}
/// Consume a value-free unavailable-history alert under the writer lock.
#[must_use]
pub fn take_history_alert(run: &Path, _guard: &WriterGuard) -> bool {
    std::fs::remove_file(run.join("client-session-history-alert")).is_ok()
}
fn load_writer(root: &Path, run: &Path, gateway: &str, now: u64) -> Record {
    load_writer_with_token(root, run, gateway, now, invalidation(run))
}
fn load_writer_with_token(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
    token: String,
) -> Record {
    if let Some(record) = sealed_record(root, gateway, now) {
        return record;
    }
    let durable = read_record(&path(root), gateway, now);
    let file = if durable
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
    {
        path(root)
    } else {
        current_path(root, run)
    };
    let incarnation = match std::fs::read_to_string(root.join("gateway-incarnation")) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(_) => {
            history_alert(run);
            let mut unavailable = Record::unknown(gateway, now);
            unavailable.invalidation = token;
            return unavailable;
        }
    };
    let loaded = if file == path(root) {
        durable
    } else {
        read_record(&file, gateway, now)
    };
    if let Ok(record) = &loaded
        && record.incarnation == incarnation
    {
        let mut record = record.clone();
        if record.invalidation != token {
            // Preserve sequence, obligations and the old observation while
            // recording a reset race or missed sampler slot conservatively.
            let start = token
                .split(':')
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|start| *start <= now)
                .unwrap_or(now);
            let start = record
                .gaps
                .last()
                .and_then(|gap| gap.end)
                .map_or(start, |end| start.max(end));
            record.open_gap(start);
            record.history = History::Unavailable;
            record.clean_stop = None;
            record.resumed_at = None;
            record.invalidation = token;
            record.written_at = now;
        }
        record
    } else {
        let invalid = match &loaded {
            Ok(record) => record.incarnation != incarnation,
            Err(error) => error.kind() == io::ErrorKind::InvalidData,
        };
        if invalid && file.exists() {
            let diagnostic = file.with_extension("unavailable.json");
            let _ = std::fs::rename(&file, diagnostic);
        }
        history_alert(run);
        eprintln!("client session history unavailable; reconstructing from complete samples");
        let mut record = Record::unknown(gateway, now);
        record.incarnation = incarnation;
        record.invalidation = token;
        record
    }
}

fn save(root: &Path, record: &Record, guard: &WriterGuard) -> io::Result<()> {
    save_checked(root, record, guard, &|| Ok(()))
}
fn save_checked(
    root: &Path,
    record: &Record,
    guard: &WriterGuard,
    commit_check: &dyn Fn() -> io::Result<()>,
) -> io::Result<()> {
    save_checkpoint(root, record, guard, commit_check, false)
}
#[cfg(all(test, feature = "testing"))]
type FsyncHook = std::sync::Arc<dyn Fn() + Send + Sync>;
#[cfg(all(test, feature = "testing"))]
fn fsync_hooks() -> &'static std::sync::Mutex<BTreeMap<std::path::PathBuf, FsyncHook>> {
    static HOOKS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<std::path::PathBuf, FsyncHook>>> =
        std::sync::OnceLock::new();
    HOOKS.get_or_init(std::sync::Mutex::default)
}
fn save_checkpoint(
    root: &Path,
    record: &Record,
    _guard: &WriterGuard,
    commit_check: &dyn Fn() -> io::Result<()>,
    consume_stop: bool,
) -> io::Result<()> {
    let fence = || {
        match sealed_checkpoint(root, &record.gateway, record.written_at) {
            Ok(Some(old))
                if !(consume_stop
                    && record.clean_stop.is_none()
                    && record.sequence == old.sequence.saturating_add(1)) =>
            {
                return Err(io::Error::other("sealed client session checkpoint"));
            }
            Err(error)
                if !matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::InvalidData
                ) =>
            {
                return Err(error);
            }
            _ => {}
        }
        Ok(())
    };
    fence()?;
    durable_replace(
        &RealFs,
        &path(root),
        &serde_json::to_vec(record).map_err(io::Error::other)?,
        0o600,
        &|_| Ok(()),
        &|step| {
            #[cfg(all(test, feature = "testing"))]
            if step == crate::fs::DurableStep::FileSynced {
                let hook = fsync_hooks()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(root)
                    .cloned();
                if let Some(hook) = hook {
                    hook();
                }
            }
            if step == crate::fs::DurableStep::FileSynced {
                fence()?;
            }
            if step == crate::fs::DurableStep::FileSynced
                && read_record(&path(root), &record.gateway, u64::MAX)
                    .is_ok_and(|old| old.sequence > record.sequence)
            {
                return Err(io::Error::other("superseded session write"));
            }
            if matches!(
                step,
                crate::fs::DurableStep::FileSynced | crate::fs::DurableStep::DirectorySynced
            ) {
                commit_check()?;
            }
            Ok(())
        },
    )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Readiness {
    at: u64,
    invalidation: String,
    reason: Option<scupper_proto::SessionReason>,
}
fn publish_readiness(run: &Path, record: &Record, committed: bool) {
    use scupper_proto::SessionReason as R;
    let now = record.written_at;
    let reason = if !committed
        || record.clean_stop.is_some()
        || record.down_since.is_some()
        || record.down
            && record
                .peers
                .iter()
                .any(|peer| peer.lease_until.is_some_and(|until| now < until))
        || record.history == History::Unavailable
        || record.gap_unknown(now)
    {
        Some(R::ClientSessionsUnknown)
    } else if record.sample_failed_at == Some(now) {
        Some(R::ClientSessionTelemetryUnknown)
    } else if record.peers.iter().any(|peer| {
        peer.state == SessionState::RequiredPending
            && peer.lease_until.is_some_and(|until| now < until)
    }) {
        Some(R::ClientSessionsReset)
    } else {
        None
    };
    if let Ok(bytes) = serde_json::to_vec(&Readiness {
        at: now,
        invalidation: record.invalidation.clone(),
        reason,
    }) {
        let _ = durable_replace(
            &RealFs,
            &run.join("client-session-readiness"),
            &bytes,
            0o600,
            &|_| Ok(()),
            &|_| Ok(()),
        );
    }
}
/// Lightweight cached status from the sampler. Tick freshness cannot hide a stall.
#[must_use]
pub fn cached_reason(run: &Path, now: u64) -> Option<scupper_proto::SessionReason> {
    if run.join("client-session-commit").exists() || run.join("client-session-opening").exists() {
        return Some(scupper_proto::SessionReason::ClientSessionsUnknown);
    }
    let cached = std::fs::read(run.join("client-session-readiness"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Readiness>(&bytes).ok());
    match cached {
        Some(cached)
            if cached.invalidation == invalidation(run)
                && now >= cached.at
                && now - cached.at <= SAMPLE_FRESHNESS =>
        {
            cached.reason
        }
        _ => Some(scupper_proto::SessionReason::ClientSessionsUnknown),
    }
}
#[cfg(all(test, feature = "testing"))]
fn persist(root: &Path, run: &Path, record: &Record, guard: &WriterGuard) -> bool {
    persist_checked(root, run, record, guard, &|| Ok(()))
}
fn persist_checked(
    root: &Path,
    run: &Path,
    record: &Record,
    guard: &WriterGuard,
    commit_check: &dyn Fn() -> io::Result<()>,
) -> bool {
    if is_sealed(root, &record.gateway, record.written_at) {
        return false;
    }
    let mut record = record.clone();
    record.sequence = read_record(&path(root), &record.gateway, record.written_at)
        .map_or(record.sequence, |old| old.sequence.max(record.sequence))
        .saturating_add(1);
    let record = &record;
    let fallback = run.join("client-sessions-fallback");
    // Read-only check must not treat an atomic rename as a durable sample while
    // the directory fsync is still blocked. Old committed sequences remain usable.
    let pending = run.join("client-session-commit");
    let barrier_written = std::fs::write(&pending, record.sequence.to_string()).is_ok();
    // A full /run must not prevent a durable write or retire peer obligations.
    // Without a runtime barrier, the renamed file itself must withhold Ready
    // even while its directory sync is stalled. EMPTY already withholds Ready.
    let mut durable = record.clone();
    if !barrier_written && !durable.never_served {
        durable.history = History::Unavailable;
        durable.renewed_at = None;
        durable.open_gap(record.written_at);
        durable.unknown_until = record
            .unknown_until
            .or(Some(record.written_at.saturating_add(LEASE)));
    }
    let saved = save_checked(root, &durable, guard, commit_check).is_ok();
    // An abandoned generation must not publish a stale runtime fallback either.
    // Leave the pending barrier in place until a current writer replaces it.
    if !saved && commit_check().is_err() {
        return false;
    }
    if barrier_written && saved {
        let _ = std::fs::remove_file(pending);
        let _ = std::fs::remove_file(fallback);
        publish_readiness(run, record, true);
        true
    } else {
        if is_sealed(root, &record.gateway, record.written_at) {
            return false;
        }
        history_alert(run);
        eprintln!("client session history write failed; readiness history unavailable");
        // /run is a best-effort communication channel to read-only check when
        // durable storage is unavailable. It never substitutes for reboot history.
        let mut unavailable = record.clone();
        unavailable.history = History::Unavailable;
        unavailable.renewed_at = None;
        unavailable.open_gap(record.written_at);
        unavailable.unknown_until = Some(record.written_at.saturating_add(LEASE));
        unavailable.unknown_until = record.unknown_until.or(unavailable.unknown_until);
        let fallback_written = serde_json::to_vec(&unavailable).is_ok_and(|bytes| {
            durable_replace(&RealFs, &fallback, &bytes, 0o600, &|_| Ok(()), &|step| {
                if matches!(
                    step,
                    crate::fs::DurableStep::FileSynced | crate::fs::DurableStep::DirectorySynced
                ) {
                    commit_check()?;
                }
                Ok(())
            })
            .is_ok()
        });
        if commit_check().is_err() {
            return false;
        }
        if !saved
            && !fallback_written
            && !pending.exists()
            && invalidate_for_reopening(root, run, &record.gateway, record.written_at).is_err()
        {
            // No runtime barrier or invalidation reached readers. Retire both
            // readable copies of old Ready evidence before containment returns.
            // LinkUp still fails closed if its own notification cannot succeed.
            for file in [fallback, path(root)] {
                if let Err(error) = std::fs::rename(&file, file.with_extension("unavailable.json"))
                    && error.kind() != io::ErrorKind::NotFound
                {
                    eprintln!("client session history revocation failed: {error}");
                }
            }
            let _ = std::fs::File::open(root).and_then(|file| file.sync_all());
        }
        publish_readiness(run, record, false);
        false
    }
}
// Confirmation is not a sampler sample. Require a runtime barrier, retain it
// on failure (rename may already have happened), and leave all history recovery
// and readiness publication to the next sampler commit.
fn persist_confirmation(
    root: &Path,
    run: &Path,
    record: &Record,
    guard: &WriterGuard,
    commit_check: &dyn Fn() -> io::Result<()>,
) -> io::Result<()> {
    let pending = run.join("client-session-commit");
    if pending.exists() || run.join("client-sessions-fallback").exists() {
        return Err(io::Error::other("uncommitted client session history"));
    }
    commit_check()?;
    std::fs::write(&pending, record.sequence.to_string())?;
    save_checked(root, record, guard, commit_check)?;
    commit_check()?;
    std::fs::remove_file(pending)
}

fn invalidation(run: &Path) -> String {
    std::fs::read_to_string(run.join("client-session-invalidation")).unwrap_or_default()
}
pub(crate) fn invalidate_at(root: &Path, run: &Path, gateway: &str, now: u64, start: u64) {
    if is_sealed(root, gateway, now) {
        return;
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let _ = std::fs::write(
        run.join("client-session-invalidation"),
        format!("{start}:{nonce}"),
    );
}
pub(crate) fn session_lock(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
) -> io::Result<WriterGuard> {
    crate::lock::WriterLock::try_acquire(run.join("client-session-writer")).inspect_err(|_| {
        // Immediately invalidate an in-flight checkpoint without waiting for it.
        invalidate_at(root, run, gateway, now, now);
    })
}
/// Configured client keys, without unrelated full-check prerequisites.
pub(crate) fn configured_keys(site: &ValidatedSite, gateway: &GatewayId) -> Vec<[u8; 32]> {
    site.devices()
        .values()
        .filter(|device| device.gateways().contains(gateway))
        .map(scupper_core::config::ValidatedDevice::public_key)
        .collect()
}
fn new_incarnation() -> io::Result<String> {
    use std::fmt::Write;
    let mut random = [0_u8; 32];
    let mut offset = 0;
    while offset < random.len() {
        let count =
            rustix::rand::getrandom(&mut random[offset..], rustix::rand::GetRandomFlags::empty())?;
        if count == 0 {
            return Err(io::Error::other("incarnation RNG stalled"));
        }
        offset += count;
    }
    let mut incarnation = String::with_capacity(64);
    for byte in random {
        write!(&mut incarnation, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(incarnation)
}
/// Provision once, as part of a NEW installation, before any client can serve.
/// Upgrade and repair must never call this function.
/// # Errors
/// Refuses an existing incarnation; propagates durable storage errors.
pub fn provision(root: &Path, gateway: &str, now: u64, guard: &WriterGuard) -> io::Result<()> {
    if root.join("gateway-incarnation").exists() || path(root).exists() {
        return Err(io::Error::other("gateway incarnation already provisioned"));
    }
    let incarnation = new_incarnation()?;
    durable_replace(
        &RealFs,
        &root.join("gateway-incarnation"),
        incarnation.as_bytes(),
        0o600,
        &|_| Ok(()),
        &|_| Ok(()),
    )?;
    let mut record = Record::unknown(gateway, now);
    record.incarnation = incarnation;
    record.never_served = true;
    record.history = History::Available;
    record.gaps.clear();
    record.unknown_until = None;
    save(root, &record, guard)
}
/// Read-only serving gate: EMPTY must first be durably retired or activated.
#[must_use]
pub fn may_serve(root: &Path, gateway: &str, now: u64) -> bool {
    if !path(root).exists() {
        return true;
    }
    read_record(&path(root), gateway, now)
        .is_ok_and(|record| !record.never_served && record.clean_stop.is_none())
}
/// First sampler/daemon startup durably consumes EMPTY before opening clients.
/// # Errors
/// A failed consumption prevents service startup.
pub fn activate(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
    guard: &WriterGuard,
) -> io::Result<()> {
    if is_sealed(root, gateway, now) {
        return Ok(());
    }
    // A restart with a live device has no EMPTY token to consume. A stalled
    // old sampler must not prevent the new reconciler from repairing protection.
    if !path(root).try_exists()?
        || read_record(&path(root), gateway, now)
            .is_ok_and(|record| !record.never_served && record.clean_stop.is_none())
    {
        return Ok(());
    }
    let _session_guard = session_lock(root, run, gateway, now)?;
    match read_record(&path(root), gateway, now) {
        Ok(mut record) if record.never_served => {
            record.never_served = false;
            record.resumed_at = Some(now);
            record.written_at = now;
            record.sequence += 1;
            save(root, &record, guard)?;
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            // Never leave a damaged/future EMPTY token on disk while serving.
            quarantine_history(root, run)?;
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    Ok(())
}
fn quarantine_history(root: &Path, run: &Path) -> io::Result<()> {
    // A rejected durable record dominates any older runtime fallback. Fallbacks
    // always contain Unavailable history and an open gap; discard the old one
    // before starting reconstruction from the quarantined durable record.
    match std::fs::remove_file(run.join("client-sessions-fallback")) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(path(root), root.join("client-sessions.unavailable.json"))?;
    std::fs::File::open(root)?.sync_all()?;
    history_alert(run);
    Ok(())
}
// A seal promises that its client device was destroyed. Any fresh production
// observation of an UP client proves reopening without consuming that seal,
// including recreation with the same device ID. Never let a later clock step
// resurrect it and fence the sampler.
fn quarantine_live_seal(root: &Path, run: &Path, sampled: &io::Result<Snapshot>) -> io::Result<()> {
    if (run.join("client-session-seal-obsolete").exists()
        || sampled
            .as_ref()
            .is_ok_and(|sample| sample.up && sample.device.is_some()))
        && read_raw_record(&path(root)).is_ok_and(|record| record.clean_stop.is_some())
    {
        quarantine_history(root, run)?;
    }
    Ok(())
}
/// Daemonless boot retires EMPTY durably before opening clients. No readiness
/// credit is granted: only a subsequent sampler can rebuild available history.
/// # Errors
/// Storage or lock failure keeps the client device closed.
pub fn retire_empty(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
    _guard: &WriterGuard,
) -> io::Result<()> {
    // All disk reads and writes run off the boot caller. The worker's fast
    // path avoids lock contention for ordinary non-EMPTY history.
    let identity = gateway.to_owned();
    bounded_hook(
        root,
        run,
        gateway,
        now,
        Instant::now() + SAMPLE_INTERVAL,
        HookMode::Retirement,
        move |root, run, guard, deadline| {
            let pending = run.join("client-session-retiring");
            std::fs::write(&pending, b"retiring\n")?;
            match read_record(&path(root), &identity, now) {
                Ok(mut record) if record.never_served => {
                    record.never_served = false;
                    record.history = History::Unavailable;
                    record.open_gap(now);
                    record.unknown_until = Some(now.saturating_add(LEASE));
                    record.written_at = now;
                    record.sequence += 1;
                    save_checked(root, &record, guard, &|| hook_deadline(deadline))?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    quarantine_history(root, run)?;
                }
                Err(error) => return Err(error),
            }
            // A retry may find the renamed unavailable record after the first
            // worker exceeded its deadline. Confirm the directory durability
            // before removing the retirement barrier or permitting service.
            std::fs::File::open(root)?.sync_all()?;
            std::fs::remove_file(pending)?;
            Ok(())
        },
    )
}

fn retirement_needed(root: &Path, run: &Path, gateway: &str, now: u64) -> io::Result<bool> {
    if run.join("client-session-retiring").exists() {
        return Ok(true);
    }
    match read_record(&path(root), gateway, now) {
        Ok(record) => Ok(record.never_served),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(true),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HookMode {
    Opening,
    OpeningLive,
    Containment,
    Retirement,
    Tracking,
    Probe,
    Confirmation,
}

#[cfg(all(test, feature = "testing"))]
#[derive(Clone)]
struct ContainmentTestHooks {
    before_lock: Option<FsyncHook>,
    finished: std::sync::mpsc::Sender<io::Result<()>>,
}
#[cfg(all(test, feature = "testing"))]
fn containment_test_hooks()
-> &'static std::sync::Mutex<BTreeMap<std::path::PathBuf, ContainmentTestHooks>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<std::path::PathBuf, ContainmentTestHooks>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(std::sync::Mutex::default)
}

// Storage workers own their lock until all I/O exits. A timed-out caller never
// joins one; checkpoint commits are fenced by the worker deadline and, for
// live history, its invalidation token. Retirement never publishes Ready.
// Keep worker ownership and the caller's separate timeout in one place.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn bounded_hook(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
    deadline: Instant,
    mode: HookMode,
    action: impl FnOnce(&Path, &Path, &WriterGuard, Instant) -> io::Result<()> + Send + 'static,
) -> io::Result<()> {
    let reopening = matches!(mode, HookMode::Opening | HookMode::OpeningLive);
    // Containment has already synchronously invalidated readers. Its durable
    // intent may finish after the caller returns, using the normal work budget.
    let caller_deadline = if mode == HookMode::Containment {
        deadline
            .checked_sub(SAMPLE_INTERVAL.saturating_sub(Duration::from_millis(150)))
            .unwrap_or(deadline)
    } else {
        deadline
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let notify_budget = Duration::from_millis(500).min(remaining / 2);
    let work_deadline = if mode == HookMode::Confirmation {
        deadline // Confirmation has no notification phase; its budget is 500 ms.
    } else {
        deadline.checked_sub(notify_budget).unwrap_or(deadline)
    };
    let worker_root = root.to_owned();
    let worker_run = run.to_owned();
    let worker_gateway = gateway.to_owned();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scupper-session-hook".into())
        .spawn(move || {
            #[cfg(all(test, feature = "testing"))]
            let test_hooks = if mode == HookMode::Containment {
                containment_test_hooks()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&worker_root)
                    .cloned()
            } else {
                None
            };
            let result: io::Result<()> = (|| {
                hook_deadline(work_deadline)?;
                if mode == HookMode::Retirement
                    && !retirement_needed(&worker_root, &worker_run, &worker_gateway, now)?
                {
                    return Ok(());
                }
                if reopening {
                    std::fs::write(
                        worker_run.join("client-session-opening"),
                        format!("{now}:{}", new_incarnation()?),
                    )?;
                }
                #[cfg(all(test, feature = "testing"))]
                if let Some(hook) = test_hooks
                    .as_ref()
                    .and_then(|hooks| hooks.before_lock.as_ref())
                {
                    hook();
                }
                let guard = crate::lock::WriterLock::acquire_timeout(
                    worker_run.join("client-session-writer"),
                    work_deadline.saturating_duration_since(Instant::now()),
                )?;
                hook_deadline(work_deadline)?;
                action(&worker_root, &worker_run, &guard, work_deadline)?;
                hook_deadline(work_deadline)?;
                if reopening {
                    std::fs::remove_file(worker_run.join("client-session-opening"))?;
                }
                Ok(())
            })();
            if mode == HookMode::Containment
                && let Err(error) = &result
            {
                eprintln!("client session containment save failed: {error}");
            }
            #[cfg(all(test, feature = "testing"))]
            if let Some(hooks) = test_hooks {
                let outcome = result
                    .as_ref()
                    .copied()
                    .map_err(|error| io::Error::new(error.kind(), error.to_string()));
                let _ = hooks.finished.send(outcome);
            }
            #[cfg(feature = "testing")]
            let result =
                if mode == HookMode::Confirmation && confirmation_testing::ack_lost(&worker_root) {
                    Err(io::Error::other(
                        "injected confirmation acknowledgement loss",
                    ))
                } else {
                    result
                };
            let _ = send.send(result);
        })?;
    let wait_deadline = caller_deadline.min(work_deadline);
    #[cfg(feature = "testing")]
    let outcome = if mode == HookMode::Confirmation {
        confirmation_testing::receive(root, &receive, wait_deadline)
    } else {
        receive.recv_timeout(wait_deadline.saturating_duration_since(Instant::now()))
    };
    #[cfg(not(feature = "testing"))]
    let outcome = receive.recv_timeout(wait_deadline.saturating_duration_since(Instant::now()));
    let error = match outcome {
        Ok(Ok(())) => {
            if mode == HookMode::Confirmation {
                hook_deadline(wait_deadline)?;
                #[cfg(feature = "testing")]
                confirmation_testing::check(root)?;
            }
            return Ok(());
        }
        Ok(Err(error)) => error,
        // The non-ready token is already visible. Acceptance does not depend
        // on whether normal disk latency happens to fit the caller budget.
        Err(_) if mode == HookMode::Containment => return Ok(()),
        Err(_) => io::Error::new(io::ErrorKind::TimedOut, "client lifecycle hook deadline"),
    };
    if matches!(
        mode,
        HookMode::Probe | HookMode::Containment | HookMode::Confirmation
    ) {
        // Probe accounting belongs to the owner of the committed pending bit.
        // A rejected confirmation does not invalidate healthy sampling history.
        return Err(error);
    }
    let notification_gateway = gateway.to_owned();
    let notification_root = root.to_owned();
    let notification_run = run.to_owned();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scupper-session-invalidate".into())
        .spawn(move || {
            let result = if mode == HookMode::OpeningLive {
                // Remember this live proof even if wg0 goes down before the
                // sampler or another opening hook can quarantine the seal.
                let notified = invalidate_runtime(&notification_run, now);
                let obsolete = std::fs::write(
                    notification_run.join("client-session-seal-obsolete"),
                    b"obsolete\n",
                );
                notified.and(obsolete)
            } else {
                invalidate_for_reopening(
                    &notification_root,
                    &notification_run,
                    &notification_gateway,
                    now,
                )
            }
            .and_then(|()| {
                match std::fs::remove_file(notification_run.join("client-session-opening")) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            });
            let _ = send.send(result);
        })?;
    let notified = receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "readiness notification deadline",
            ))
        });
    if reopening && error.kind() != io::ErrorKind::NotConnected {
        notified
    } else {
        Err(error)
    }
}

// 0: waiting, 1: committed, 2: caller abandoned. The side that observes
// the other side's transition accounts for a consumed but unsent opportunity.
fn probe_committed(state: &std::sync::atomic::AtomicU8) {
    if state.swap(1, std::sync::atomic::Ordering::AcqRel) == 2 {
        count_missed_probe();
    }
}
fn probe_persistence_result(
    result: io::Result<()>,
    state: &std::sync::atomic::AtomicU8,
) -> io::Result<bool> {
    if let Err(error) = result {
        if state.swap(2, std::sync::atomic::Ordering::AcqRel) == 1 {
            // The bit was committed before the caller timed out. The reserved
            // child budget can still send it, regardless of the worker result.
            return Ok(true);
        }
        return Err(error);
    }
    Ok(state.load(std::sync::atomic::Ordering::Acquire) == 1)
}
static MISSED_PROBES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn count_missed_probe() {
    let count = MISSED_PROBES
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    eprintln!("client session probe opportunity missed; count={count}; awaiting client retry");
}
fn hook_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "client lifecycle hook deadline",
        ))
    } else {
        Ok(())
    }
}
fn invalidate_for_reopening(root: &Path, run: &Path, gateway: &str, now: u64) -> io::Result<()> {
    // Ignore the wall-clock bound here: an otherwise valid future seal can
    // become valid later. Only a live-UP proof permits the timeout fallback to
    // open over it; key-mismatched or internally damaged markers cannot revive.
    match sealed_checkpoint(root, gateway, u64::MAX) {
        Ok(Some(_)) => {
            return Err(io::Error::other(
                "sealed checkpoint must be durably consumed before LinkUp",
            ));
        }
        Err(error)
            if !matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ) =>
        {
            return Err(error);
        }
        _ => {}
    }
    invalidate_runtime(run, now)
}
fn invalidate_runtime(run: &Path, now: u64) -> io::Result<()> {
    invalidate_runtime_token(run, now).map(|_| ())
}
fn invalidate_runtime_token(run: &Path, now: u64) -> io::Result<String> {
    let token = format!("{now}:{}", new_incarnation()?);
    let file = run.join("client-session-invalidation");
    std::fs::write(&file, &token)?;
    if std::fs::read_to_string(file)? != token {
        return Err(io::Error::other("readiness invalidation was superseded"));
    }
    Ok(token)
}
fn samples(sys: &dyn System, held: &NetnsHandle, iface: &str) -> io::Result<Snapshot> {
    match sys.client_session_io(
        crate::system::HelperPurpose::Observation,
        held,
        &Request {
            namespace: held.identity(),
            iface: iface.into(),
            probe: None,
        },
    )? {
        Response::Samples(peers) => Ok(Snapshot {
            peers,
            device: None,
            up: true,
        }),
        Response::Telemetry { device, peers, up } => Ok(Snapshot {
            peers,
            device: Some(device),
            up,
        }),
        Response::Probes(_) => Err(io::Error::other("invalid client telemetry response")),
    }
}
// WireGuard counts accepted initiations (148), responses (92), and transport.
// Preserve round 5's stronger rule: a newer handshake plus receive growth that
// cannot be gateway responses alone. Repeated/ambiguous multiples of 92 remain
// unconfirmed. Client initiation is accepted evidence under the round 5 contract.
// Residual N3 window: response (92) + client initiation (148) = 240 can satisfy
// this rule even if confirmation and the response to the initiation were lost;
// the client may still wait up to its next 5 s retry. Counters cannot distinguish
// that mixture from transport. This is not an end-to-end forwarding canary.
fn transport(baseline: &Sample, current: &Sample) -> bool {
    if current.handshake < baseline.handshake
        || current.handshake.0 == 0
        || current.rx < baseline.rx
        || current.tx < baseline.tx
    {
        return false;
    }
    let rx = current.rx - baseline.rx;
    rx > 92 && !rx.is_multiple_of(92)
}
fn recovered(reset: &Reset, current: &Sample) -> bool {
    current.handshake > reset.baseline.handshake && transport(&reset.baseline, current)
}
fn expire(peer: &mut Reset, now: u64) {
    if peer.state == SessionState::RequiredPending && peer.lease_until.is_none_or(|t| now >= t) {
        peer.state = SessionState::ExpiredUnconfirmed;
    }
}
fn reset(
    record: &mut Record,
    namespace: NetnsId,
    current: Snapshot,
    now: u64,
    capture_activity: bool,
) {
    if record.unknown_until.is_some_and(|end| now >= end) {
        record.unknown_until = None;
    }
    let same_down = record.down && record.namespace == namespace && record.device == current.device;
    record.device = current.device;
    let current = current.peers;
    let old: BTreeMap<_, _> = record.peers.iter().map(|p| (p.baseline.key, p)).collect();
    let present: std::collections::BTreeSet<_> = current.iter().map(|s| s.key).collect();
    let mut missing: Vec<_> = record
        .peers
        .iter()
        .filter(|p| !present.contains(&p.baseline.key))
        .cloned()
        .collect();
    for peer in &mut missing {
        peer.generation = peer.generation.saturating_add(1);
        peer.state = if peer.lease_until.is_some_and(|t| now < t) {
            SessionState::RequiredPending
        } else {
            SessionState::ExpiredUnconfirmed
        };
    }
    record.peers = current
        .into_iter()
        .map(|sample| {
            let previous = old.get(&sample.key).copied();
            let mut peer = previous.cloned().unwrap_or_else(|| Reset {
                generation: 0,
                baseline: sample.clone(),
                observed: sample.clone(),
                last_authenticated: None,
                lease_until: None,
                state: SessionState::Unknown,
            });
            if !same_down || previous.is_none() {
                // Snapshot current authenticated activity before planned destruction.
                if record.namespace == namespace
                    && !record.down
                    && capture_activity
                    && previous.is_some_and(|p| {
                        (p.state == SessionState::Recovered || recovered(p, &sample))
                            && transport(&p.observed, &sample)
                    })
                {
                    peer.last_authenticated = Some(now);
                    peer.lease_until = Some(now.saturating_add(LEASE));
                }
                peer.generation = peer.generation.saturating_add(1);
                peer.state = if peer.lease_until.is_some_and(|t| now < t) {
                    SessionState::RequiredPending
                } else if peer.last_authenticated.is_some() {
                    SessionState::ExpiredUnconfirmed
                } else {
                    SessionState::Unknown
                };
            }
            if previous.is_none()
                && record
                    .resumed_at
                    .is_some_and(|start| sample.handshake.0 >= start)
                && sample.rx > 92
                && !sample.rx.is_multiple_of(92)
            {
                // EMPTY was consumed before service: this first complete dump
                // already contains authentication from the new device.
                peer.last_authenticated = Some(now);
                peer.lease_until = Some(now.saturating_add(LEASE));
                peer.state = SessionState::Recovered;
            }
            peer.baseline = sample.clone();
            peer.observed = sample;
            expire(&mut peer, now);
            peer
        })
        .collect();
    record.peers.extend(missing);
    record.namespace = namespace;
    record.baseline_pending = false;
    record.down = true;
    record.written_at = now;
}
/// Invalidate readers before containment, without waiting for telemetry.
/// Accepted intent may finish saving within 4.5 seconds after this hook returns.
/// # Errors
/// History failures are exposed as unavailable evidence and do not block containment.
pub fn before_down(
    sys: &dyn System,
    root: &Path,
    run: &Path,
    gateway: &str,
    _guard: &WriterGuard,
) -> io::Result<()> {
    let deadline = Instant::now() + SAMPLE_INTERVAL;
    let now = sys.now_unix_secs();
    // Publish non-ready before queuing disk work or allowing LinkDown. Loading
    // against the prior token preserves healthy history across our own intent;
    // later invalidations fence commits against the new token. Under the lock,
    // also check for lifecycle commits that kept this token.
    let previous_token = invalidation(run);
    // A containment request also makes any unconsumed seal obsolete, even
    // when no sampler ever observed an externally raised device before DOWN.
    let notified = invalidate_runtime_token(run, now);
    // Marker failure must not suppress the synchronous non-ready token.
    let obsolete = std::fs::write(run.join("client-session-seal-obsolete"), b"obsolete\n");
    let token = notified.as_ref().unwrap_or(&previous_token).clone();
    let token_published = notified.is_ok();
    let hook_gateway = gateway.to_owned();
    let gateway = gateway.to_owned();
    let result = bounded_hook(
        root,
        run,
        &hook_gateway,
        now,
        deadline,
        HookMode::Containment,
        move |root, run, guard, deadline| {
            let gateway = gateway.as_str();
            if invalidation(run) != token {
                return Err(io::Error::other("superseded containment intent"));
            }
            // This unique token did not exist when containment was requested.
            // A durable or fallback record carrying it was committed by a later
            // writer: link_down saved the intent, before_up superseded it, or a
            // sampler accounted for the transition. Do not replay the old intent.
            // Read raw state because a newer record may postdate this hook's now.
            // A failed notification kept the old token, so equality proves nothing.
            if token_published
                && [path(root), current_path(root, run)].iter().any(|file| {
                    read_raw_record(file).is_ok_and(|record| record.invalidation == token)
                })
            {
                return Ok(());
            }
            if !path(root).exists() {
                return Ok(());
            }
            if sealed_record(root, gateway, now).is_none()
                && read_record(&current_path(root, run), gateway, now).is_err()
            {
                history_alert(run);
                // load_writer quarantines invalid history and starts reconstruction.
            }
            let mut record = load_writer_with_token(root, run, gateway, now, previous_token);
            record.invalidation = token;
            let now = now.max(record.written_at);
            if record.clean_stop.is_some() {
                return Ok(());
            }
            record.down_since.get_or_insert(now);
            record.written_at = now;
            if !persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            }) {
                return Err(io::Error::other("lifecycle persistence failed"));
            }
            Ok(())
        },
    );
    result.and(notified.map(|_| ())).and(obsolete)
}
/// Capture preserved counters after `LinkDown`, including a command timeout.
/// # Errors
/// Telemetry failure is reported after saving the original reset time.
#[allow(clippy::too_many_arguments)]
pub fn link_down(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    link_is_down: bool,
) -> io::Result<()> {
    link_down_until(
        sys,
        held,
        iface,
        root,
        run,
        gateway,
        guard,
        link_is_down,
        Instant::now() + SAMPLE_INTERVAL,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn link_down_until(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    _guard: &WriterGuard,
    link_is_down: bool,
    deadline: Instant,
) -> io::Result<()> {
    let now = sys.now_unix_secs();
    let namespace = held.identity();
    let sampled = if deadline.saturating_duration_since(Instant::now()) >= EXEC_TIMEOUT {
        samples(sys, held, iface)
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no remaining client telemetry budget",
        ))
    };
    let hook_gateway = gateway.to_owned();
    let gateway = gateway.to_owned();
    bounded_hook(
        root,
        run,
        &hook_gateway,
        now,
        deadline,
        HookMode::Tracking,
        move |root, run, guard, deadline| {
            let gateway = gateway.as_str();

            if !path(root).exists() {
                return Ok(());
            }
            if sealed_record(root, gateway, now).is_none()
                && read_record(&current_path(root, run), gateway, now).is_err()
            {
                history_alert(run);
                // load_writer quarantines invalid history and starts reconstruction.
            }
            let mut record = load_writer(root, run, gateway, now);
            let now = now.max(record.written_at);
            if record.clean_stop.is_some() {
                return Ok(());
            }
            if record.down_since.is_none() {
                record.down_since = Some(now);
            }
            record.written_at = now;
            if !persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            }) {
                return Err(io::Error::other("lifecycle persistence failed"));
            }
            if !link_is_down {
                // The command failed before taking effect. Preserve the live generation
                // and let the first sample of the next tick account for its activity.
                record.down_since = None;
                if !persist_checked(root, run, &record, guard, &|| {
                    sample_commit_check(root, run, &record, deadline)
                }) {
                    return Err(io::Error::other("lifecycle persistence failed"));
                }
                return Ok(());
            }
            reset(&mut record, namespace, sampled?, now, true);
            if !persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            }) {
                return Err(io::Error::other("lifecycle persistence failed"));
            }
            Ok(())
        },
    )
}
/// Establish a new generation without restoring endpoints, within five seconds.
/// History failure permits reopening only after verified reader invalidation.
/// # Errors
/// Fails closed when invalidation or durable sealed-marker consumption fails.
#[allow(clippy::too_many_arguments)]
pub fn before_up(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    was_down: bool,
    guard: &WriterGuard,
) -> io::Result<()> {
    before_up_until(
        sys,
        held,
        iface,
        root,
        run,
        gateway,
        was_down,
        guard,
        Instant::now() + SAMPLE_INTERVAL,
        false,
    )
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keep marker consumption and baseline commit in one bounded transaction.
pub(crate) fn before_up_until(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    was_down: bool,
    _guard: &WriterGuard,
    deadline: Instant,
    reject_empty: bool,
) -> io::Result<()> {
    hook_deadline(deadline)?;
    let now = sys.now_unix_secs();
    let namespace = held.identity();
    let sampled = if deadline.saturating_duration_since(Instant::now()) >= EXEC_TIMEOUT {
        samples(sys, held, iface)
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no remaining client telemetry budget",
        ))
    };
    let hook_gateway = gateway.to_owned();
    let gateway = gateway.to_owned();
    bounded_hook(
        root,
        run,
        &hook_gateway,
        now,
        deadline,
        if sampled
            .as_ref()
            .is_ok_and(|sample| sample.up && sample.device.is_some())
        {
            HookMode::OpeningLive
        } else {
            HookMode::Opening
        },
        move |root, run, guard, deadline| {
            let gateway = gateway.as_str();
            quarantine_live_seal(root, run, &sampled)?;

            if !path(root).exists() {
                return Ok(());
            }
            if sealed_record(root, gateway, now).is_none()
                && let Err(error) = read_record(&current_path(root, run), gateway, now)
            {
                history_alert(run);
                if !matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::NotFound
                ) {
                    return Err(error);
                }
                // Quarantine all damaged history, including daemonless sites
                // without a sampler. A damaged marker must never resurrect
                // after a clock/key change and fence sampling after LinkUp.
            }
            let mut record = load_writer(root, run, gateway, now);
            if record.never_served {
                return if reject_empty {
                    Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "client sampler has not activated EMPTY",
                    ))
                } else {
                    Ok(())
                };
            }
            let consuming_stop = record.clean_stop.is_some();
            if let Some(stop) = record.clean_stop.take() {
                // sealed_checkpoint already validated the marker's internal binding.
                // reset below always binds consumption to the new live observation.
                record.validate_rebuild(stop.at);
                record.resumed_at = Some(now);
                record.down = false;
            }
            let now = now.max(record.written_at);
            if consuming_stop
                || was_down
                || record.down
                || record.down_since.is_some()
                || record.namespace != namespace
            {
                record.validate_rebuild(now);
                if let Ok(current) = sampled {
                    let capture_activity = !consuming_stop && record.down_since.is_none();
                    reset(&mut record, namespace, current, now, capture_activity);
                } else {
                    if !record.baseline_pending {
                        record.unknown_until = Some(now.saturating_add(LEASE));
                        for peer in &mut record.peers {
                            peer.generation = peer.generation.saturating_add(1);
                            peer.state = if peer.lease_until.is_some_and(|t| now < t) {
                                SessionState::RequiredPending
                            } else if peer.last_authenticated.is_some() {
                                SessionState::ExpiredUnconfirmed
                            } else {
                                SessionState::Unknown
                            };
                        }
                    }
                    record.baseline_pending = true;
                    record.history = History::Unavailable;
                    record.open_gap(now);
                    eprintln!("client session baseline unavailable; awaiting client retry");
                }
            }
            record.down_since = None;
            record.namespace = namespace;
            record.down = false;
            record.probe_pending = true;
            record.written_at = now;
            if consuming_stop {
                record.sequence += 1;
                record.invalidation = invalidation(run);
                std::fs::write(
                    run.join("client-session-commit"),
                    record.sequence.to_string(),
                )?;
                save_checkpoint(
                    root,
                    &record,
                    guard,
                    &|| sample_commit_check(root, run, &record, deadline),
                    true,
                )?;
                let _ = std::fs::remove_file(run.join("client-session-commit"));
                let _ = std::fs::remove_file(run.join("client-sessions-fallback"));
            } else if !persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            }) {
                return Err(io::Error::other("lifecycle persistence failed"));
            }
            Ok(())
        },
    )
}
/// Readiness with explicit unknown and expired-unconfirmed warnings.
/// A pending peer with a live lease needs acknowledged durable confirmation
/// before it can pass. Idle peers and persisted, continuous confirmations need
/// no write; a failed commit cannot create an obligation for an idle peer.
/// # Errors
/// Returns current netlink observation failures.
#[allow(clippy::too_many_lines)] // Observation, acknowledged merge and classification share one readiness path.
pub fn status(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    keys: &[[u8; 32]],
) -> io::Result<ClientSessions> {
    let now = sys.now_unix_secs();
    let opening = std::fs::read_to_string(run.join("client-session-opening")).ok();
    let mut record = load_current(root, run, gateway, now);
    let mut sampled = None;
    let (current, device, telemetry_failed): (BTreeMap<_, _>, Option<DeviceId>, bool) =
        match samples(sys, held, iface) {
            Ok(current) => {
                sampled = Some(current.clone());
                if record.clean_stop.is_some() && current.up && current.device.is_some() {
                    record = Record::unknown(gateway, now);
                }
                (
                    current.peers.into_iter().map(|s| (s.key, s)).collect(),
                    current.device,
                    false,
                )
            }
            Err(_) => (BTreeMap::new(), None, true),
        };
    // The record and opening barrier above capture the epoch before telemetry.
    // Only an acknowledged merge can turn live-only evidence into a pass.
    let needs_commit = record.namespace == held.identity()
        && record.device == device
        && !record.down
        && record.down_since.is_none()
        && !record.baseline_pending
        && record.peers.iter().any(|p| {
            keys.contains(&p.baseline.key)
                && p.state == SessionState::RequiredPending
                && p.lease_until.is_some_and(|until| now < until)
                && current
                    .get(&p.baseline.key)
                    .is_some_and(|s| recovered(p, s))
        });
    let mut committed = !needs_commit;
    if needs_commit
        && let Some(sample) = sampled
        && let Ok(merged) = confirm_live(root, run, gateway, &record, opening, sample, keys, now)
    {
        // Use the CURRENT record merged by the worker, including newer sampler
        // accounting and gaps. Avoid another record read after its bounded ack.
        record = merged;
        committed = true;
    }
    let continuous = |p: &Reset| {
        current.get(&p.baseline.key).is_some_and(|s| {
            s.handshake >= p.observed.handshake && s.rx >= p.observed.rx && s.tx >= p.observed.tx
        })
    };
    let same = record.namespace == held.identity()
        && record.device == device
        && !record.down
        && record.down_since.is_none();
    let mut status = ClientSessions {
        history_unavailable: run.join("client-sessions-fallback").exists()
            || record.history == History::Unavailable
            || record.gap_unknown(now),
        telemetry_unavailable: telemetry_failed && !keys.is_empty(),
        peer_missing: !telemetry_failed && keys.iter().any(|key| !current.contains_key(key)),
        unknown: record.never_served
            || record.down_since.is_some()
            || record.gap_unknown(now)
            || record.history == History::Unavailable,
        active_reset: needs_commit && !committed,
        ..ClientSessions::default()
    };
    for peer in record
        .peers
        .iter()
        .filter(|p| keys.contains(&p.baseline.key))
    {
        if telemetry_failed {
            status.active_reset |= peer.state == SessionState::RequiredPending
                && peer.lease_until.is_some_and(|t| now < t);
            status.expired_unconfirmed |=
                peer.lease_until.is_some_and(|t| now >= t) && peer.state != SessionState::Recovered;
            continue;
        }
        if same
            && !record.baseline_pending
            && continuous(peer)
            && peer.state == SessionState::Recovered
        {
            continue;
        }
        if (peer.state == SessionState::RequiredPending || !same || !continuous(peer))
            && peer.lease_until.is_some_and(|t| now < t)
        {
            status.active_reset = true;
        } else {
            status.idle_reset = true;
            status.expired_unconfirmed |= peer.last_authenticated.is_some();
        }
    }
    Ok(status)
}
// A check may acknowledge only the exact observation it used. Sequence changes
// from ordinary sampling are allowed; a recovery epoch change is not. Validation
// precedes the confirmation merge; only the sampler may reconstruct history.
// Failed persistence may leave a commit barrier, but never rotates history or
// publishes a sampler tick, readiness cache, or unavailable-history fallback.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Validate, merge and acknowledge under one writer lock.
fn confirm_live(
    root: &Path,
    run: &Path,
    gateway: &str,
    expected: &Record,
    opening: Option<String>,
    sampled: Snapshot,
    keys: &[[u8; 32]],
    now: u64,
) -> io::Result<Record> {
    let expected = expected.clone();
    let keys = keys.to_vec();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    #[cfg(feature = "testing")]
    let budget = confirmation_testing::budget(root);
    #[cfg(not(feature = "testing"))]
    let budget = CONFIRMATION_BUDGET;
    bounded_hook(
        root,
        run,
        gateway,
        now,
        Instant::now() + budget,
        HookMode::Confirmation,
        move |root, run, guard, deadline| {
            // Telemetry can cross a wall-clock second while the sampler commits.
            // Validate against lock-time wall clock, but stamp leases with the
            // check's original observation time.
            let read_now = now.max(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            if read_record(&path(root), &expected.gateway, read_now)
                .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
            {
                // Leave forensic quarantine and its alert to the sampler loader.
                return Err(io::Error::other("corrupt durable client session history"));
            }
            let current = read_record(&current_path(root, run), &expected.gateway, read_now)?;
            if opening.is_some()
                || std::fs::read_to_string(run.join("client-session-opening")).ok() != opening
                || current.sequence < expected.sequence
                || current.incarnation.is_empty()
                || current.incarnation != expected.incarnation
                || current.invalidation != expected.invalidation
                || invalidation(run) != expected.invalidation
                || current.namespace != expected.namespace
                || current.device != expected.device
                || current.namespace == (0, 0)
                || current.device != sampled.device
                || !sampled.up
                || sampled
                    .peers
                    .iter()
                    .map(|s| s.key)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != sampled.peers.len()
                || current.never_served
                || current.clean_stop != expected.clean_stop
                || current.clean_stop.is_some()
                || current.down != expected.down
                || current.down
                || current.down_since != expected.down_since
                || current.down_since.is_some()
                || current.baseline_pending != expected.baseline_pending
                || current.baseline_pending
                || current.peers.len() != expected.peers.len()
                || current
                    .peers
                    .iter()
                    .map(|p| p.baseline.key)
                    .collect::<std::collections::BTreeSet<_>>()
                    != keys
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>()
                || current.peers.iter().any(|peer| {
                    !expected.peers.iter().any(|old| {
                        old.baseline == peer.baseline && old.generation == peer.generation
                    }) || !sampled.peers.iter().any(|s| {
                        s.key == peer.baseline.key
                            && s.handshake >= peer.observed.handshake
                            && s.rx >= peer.observed.rx
                            && s.tx >= peer.observed.tx
                    })
                })
                || keys.iter().any(|key| {
                    !current.peers.iter().any(|peer| peer.baseline.key == *key)
                        || !sampled.peers.iter().any(|s| s.key == *key)
                })
            {
                return Err(io::Error::other("live confirmation recovery epoch changed"));
            }
            let commit_check = |_: &Record| {
                // Unlike a missed sampler cadence, a failed check commit
                // must not introduce an observation gap or rotate history.
                hook_deadline(deadline)?;
                #[cfg(feature = "testing")]
                confirmation_testing::check(root)?;
                if invalidation(run) != expected.invalidation
                    || std::fs::read_to_string(run.join("client-session-opening")).ok() != opening
                    || std::fs::read_to_string(root.join("gateway-incarnation")).unwrap_or_default()
                        != expected.incarnation
                {
                    return Err(io::Error::other(
                        "live confirmation invalidated during commit",
                    ));
                }
                Ok(())
            };
            let merged = merge_current_activity(
                expected.namespace,
                root,
                run,
                guard,
                &keys,
                current,
                Ok(sampled),
                now,
                MergeMode::Confirmation,
                &commit_check,
            )?;
            commit_check(&merged)?;
            if run.join("client-session-commit").exists()
                || run.join("client-sessions-fallback").exists()
            {
                return Err(io::Error::other(
                    "confirmation persistence barrier not cleared",
                ));
            }
            send.send(merged)
                .map_err(|_| io::Error::other("confirmation receiver closed"))
        },
    )?;
    // The data is queued before the acknowledged completion; never wait again.
    receive
        .try_recv()
        .map_err(|_| io::Error::other("confirmation acknowledgement missing"))
}
/// Durably commit a complete activity sample from the independent sampler.
/// # Errors
/// Returns incomplete telemetry or failed durable commits; check retains unavailable evidence.
#[allow(clippy::too_many_arguments)]
pub fn checkpoint_recovered(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
) -> io::Result<()> {
    checkpoint_activity(sys, held, iface, root, run, gateway, guard, keys)
}

/// Snapshot the last partial interval on daemon stop, without sealing history.
/// System shutdown also uses the quiesced final sample in `boot::clean_stop`.
/// # Errors
/// Returns current telemetry failure. Storage failures are exposed through runtime history.
#[allow(clippy::too_many_arguments)]
pub fn before_shutdown(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
) -> io::Result<()> {
    checkpoint_stop_until(
        sys,
        held,
        iface,
        root,
        run,
        gateway,
        guard,
        keys,
        Instant::now() + SAMPLE_INTERVAL,
    )
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_stop_until(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
    deadline: Instant,
) -> io::Result<()> {
    // Queueing, collection, lock contention and any recollection share one stop budget.
    for attempt in 0..2 {
        hook_deadline(deadline)?;
        let now = sys.now_unix_secs();
        let fence = observation_fence(root, run);
        let sampled = samples(sys, held, iface);
        let session_guard = crate::lock::WriterLock::acquire_timeout(
            run.join("client-session-writer"),
            deadline.saturating_duration_since(Instant::now()),
        )?;
        hook_deadline(deadline)?;
        if observation_fence(root, run) != fence {
            drop(session_guard);
            if attempt == 0 {
                continue;
            }
            return Err(io::Error::other(
                "final client telemetry superseded by lifecycle change",
            ));
        }
        quarantine_live_seal(root, run, &sampled)?;
        return merge_activity(
            held.identity(),
            root,
            run,
            gateway,
            guard,
            keys,
            sampled,
            now,
            deadline,
            Some(&fence.1),
        );
    }
    Err(io::Error::other("final client telemetry superseded"))
}

#[allow(clippy::too_many_arguments)] // Periodic sampling discards lifecycle collisions.
fn checkpoint_activity(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
) -> io::Result<()> {
    let deadline = Instant::now() + SAMPLE_INTERVAL;
    let now = sys.now_unix_secs();
    let fence = observation_fence(root, run);
    let sampled = samples(sys, held, iface);
    // A normal collision with a newer lifecycle writer is not an observation
    // gap. Discard this observation and let the next cadence collect again.
    let _session_guard = crate::lock::WriterLock::try_acquire(run.join("client-session-writer"))?;
    if observation_fence(root, run) != fence {
        return Err(io::Error::other(
            "client telemetry superseded by lifecycle change",
        ));
    }
    quarantine_live_seal(root, run, &sampled)?;
    if is_sealed(root, gateway, now) {
        return Err(io::Error::other(
            "client sampling fenced by sealed clean-stop checkpoint",
        ));
    }
    merge_activity(
        held.identity(),
        root,
        run,
        gateway,
        guard,
        keys,
        sampled,
        now,
        deadline,
        Some(&fence.1),
    )
}
fn observation_fence(root: &Path, run: &Path) -> (Option<u64>, String, Option<String>) {
    (
        read_bound_record(&current_path(root, run), None, u64::MAX)
            .ok()
            .map(|record| record.sequence),
        invalidation(run),
        std::fs::read_to_string(run.join("client-session-opening")).ok(),
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn checkpoint_activity_locked(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
) -> io::Result<()> {
    checkpoint_final_activity_until(
        sys,
        held,
        iface,
        root,
        run,
        gateway,
        guard,
        keys,
        Instant::now() + SAMPLE_INTERVAL,
    )
}
#[allow(clippy::too_many_arguments)]
fn checkpoint_final_activity_until(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
    deadline: Instant,
) -> io::Result<()> {
    loop {
        hook_deadline(deadline)?;
        if deadline.saturating_duration_since(Instant::now()) < EXEC_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no remaining final client telemetry budget",
            ));
        }
        let token = invalidation(run);
        let now = sys.now_unix_secs();
        let sampled = samples(sys, held, iface);
        let result = merge_activity(
            held.identity(),
            root,
            run,
            gateway,
            guard,
            keys,
            sampled,
            now,
            deadline,
            None,
        )
        .and_then(|()| {
            // Run the same seal-time precondition while recollection is
            // still possible, before the caller destroys the device.
            final_stop_record(root, run, gateway, now, held.identity()).map(|_| ())
        });
        if invalidation(run) == token {
            return result;
        }
        // The device is quiesced and the session lock remains held. Recollect
        // final evidence under the new token; never extend the stop's deadline.
        hook_deadline(deadline)?;
        std::thread::sleep(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn merge_activity(
    namespace: NetnsId,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
    sampled: io::Result<Snapshot>,
    now: u64,
    deadline: Instant,
    observed_token: Option<&str>,
) -> io::Result<()> {
    if is_sealed(root, gateway, now) {
        return Err(io::Error::other(
            "client sampling fenced by sealed clean-stop checkpoint",
        ));
    }
    // SIGKILL bypasses the temporary-file guard in a detached CLI writer.
    if let Err(error) = crate::fs::cleanup_orphaned_temps(root) {
        eprintln!("client session temporary file cleanup failed: {error}");
    }
    let record = load_writer(root, run, gateway, now);
    // Invalidation can race even after the initial under-lock fence check.
    // Never adopt a newer token and merge telemetry collected before it.
    if observed_token
        .is_some_and(|token| token != record.invalidation || token != invalidation(run))
    {
        return Err(io::Error::other(
            "client telemetry invalidated while loading history",
        ));
    }
    merge_current_activity(
        namespace,
        root,
        run,
        guard,
        keys,
        record,
        sampled,
        now,
        MergeMode::Sampler,
        &|record| sample_commit_check(root, run, record, deadline),
    )
    .map(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MergeMode {
    Sampler,
    Confirmation,
}

// The caller owns the session lock and supplies the commit fence. Confirmation
// updates peer evidence only; it cannot advance the sampler cadence or history.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn merge_current_activity(
    namespace: NetnsId,
    root: &Path,
    run: &Path,
    guard: &WriterGuard,
    keys: &[[u8; 32]],
    mut record: Record,
    sampled: io::Result<Snapshot>,
    now: u64,
    mode: MergeMode,
    commit_check: &dyn Fn(&Record) -> io::Result<()>,
) -> io::Result<Record> {
    if is_sealed(root, &record.gateway, now) {
        return Err(io::Error::other("sealed client session checkpoint"));
    }
    if record.clean_stop.is_some() {
        return Err(io::Error::other(
            "client sampling fenced by sealed clean-stop checkpoint",
        ));
    }
    if record.never_served {
        return Err(io::Error::other(
            "history must be activated before sampling",
        ));
    }
    if mode == MergeMode::Confirmation {
        let current = sampled?;
        // confirm_live validated the complete key set, epoch and continuity
        // under this lock. Do not prune peers, expire leases, or complete a tick.
        for peer in &mut record.peers {
            if let Some(sample) = current.peers.iter().find(|s| s.key == peer.baseline.key)
                && peer.state != SessionState::Recovered
                && recovered(peer, sample)
            {
                peer.state = SessionState::Recovered;
                if transport(&peer.observed, sample) {
                    peer.last_authenticated = Some(now);
                    peer.lease_until = Some(now.saturating_add(LEASE));
                }
                peer.observed = sample.clone();
            }
        }
        record.written_at = now.max(record.written_at);
        record.sequence = record.sequence.saturating_add(1);
        persist_confirmation(root, run, &record, guard, &|| commit_check(&record))?;
        return Ok(record);
    }
    // A process can die after publishing its temporary opening barrier. Once
    // its five-second deadline has passed, reconstruct conservatively rather
    // than leaving an immortal runtime-only Unknown latch.
    let abandoned_opening = std::fs::read_to_string(run.join("client-session-opening"))
        .ok()
        .filter(|opening| {
            opening
                .split(':')
                .next()
                .and_then(|at| at.parse::<u64>().ok())
                .is_none_or(|at| now < at || now >= at.saturating_add(SAMPLE_INTERVAL.as_secs()))
        });
    if let Some(opening) = &abandoned_opening {
        let start = opening
            .split(':')
            .next()
            .and_then(|at| at.parse::<u64>().ok())
            .unwrap_or(now)
            .min(now);
        let start = record
            .gaps
            .last()
            .and_then(|gap| gap.end)
            .map_or(start, |end| start.max(end));
        record.open_gap(start);
        record.history = History::Unavailable;
    }
    let now = now.max(record.written_at);
    record.note_stall(now);
    record.peers.retain(|p| keys.contains(&p.baseline.key));
    let current = match sampled {
        Ok(current)
            if keys
                .iter()
                .all(|key| current.peers.iter().any(|s| s.key == *key))
                && current
                    .peers
                    .iter()
                    .map(|s| s.key)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == current.peers.len() =>
        {
            current
        }
        _ => {
            record.sample_failed_at = Some(now);
            record.written_at = now;
            persist_checked(root, run, &record, guard, &|| commit_check(&record));
            return Err(io::Error::other("incomplete client activity sample"));
        }
    };
    let discontinuity = record.namespace != namespace
        || record.device != current.device
        || current.peers.iter().any(|s| {
            record.peers.iter().any(|p| {
                p.baseline.key == s.key
                    && (s.handshake < p.observed.handshake
                        || s.rx < p.observed.rx
                        || s.tx < p.observed.tx)
            })
        });
    let abandoned = current.up && (record.down_since.is_some() || record.down);
    if abandoned || discontinuity || record.baseline_pending || record.namespace == (0, 0) {
        // Validate the OLD committed history before recording this fresh sample.
        record.validate_rebuild(now);
        record.down = false;
        reset(&mut record, namespace, current.clone(), now, !abandoned);
        record.down = false;
        if current.up {
            // Identity and counters survive a down/up. Commit the new baseline
            // and clearing of the intent together; no pre-baseline recovery.
            record.down_since = None;
        }
    }
    for sample in &current.peers {
        if keys.contains(&sample.key) && !record.peers.iter().any(|p| p.baseline.key == sample.key)
        {
            record.peers.push(Reset {
                generation: 0,
                baseline: sample.clone(),
                observed: sample.clone(),
                last_authenticated: None,
                lease_until: None,
                state: SessionState::Unknown,
            });
        }
    }
    for peer in &mut record.peers {
        if let Some(sample) = current.peers.iter().find(|s| s.key == peer.baseline.key) {
            if sample.handshake < peer.observed.handshake
                || sample.rx < peer.observed.rx
                || sample.tx < peer.observed.tx
            {
                // An externally recreated device can retain the namespace inode.
                // Never carry a latched recovery over a counter discontinuity.
                peer.generation = peer.generation.saturating_add(1);
                peer.baseline = sample.clone();
                peer.observed = sample.clone();
                peer.state = if peer.lease_until.is_some_and(|t| now < t) {
                    SessionState::RequiredPending
                } else if peer.last_authenticated.is_some() {
                    SessionState::ExpiredUnconfirmed
                } else {
                    SessionState::Unknown
                };
                continue;
            }
            let ready = recovered(peer, sample)
                || peer.state == SessionState::Unknown
                    && sample.handshake.0 > 0
                    && sample.handshake == peer.observed.handshake
                    && sample.rx > peer.observed.rx
                    && sample.tx >= peer.observed.tx
                    && !(sample.rx - peer.observed.rx).is_multiple_of(92);
            if ready && peer.state != SessionState::Recovered {
                peer.state = SessionState::Recovered;
            }
            if (ready || peer.state == SessionState::Recovered)
                && (transport(&peer.observed, sample)
                    || peer.state == SessionState::Recovered
                        && sample.handshake == peer.observed.handshake
                        && sample.rx > peer.observed.rx
                        && sample.tx >= peer.observed.tx)
            {
                peer.last_authenticated = Some(now);
                peer.lease_until = Some(now.saturating_add(LEASE));
            }
            peer.observed = sample.clone();
        }
        expire(peer, now);
    }
    if !current.up {
        record.down_since.get_or_insert(now);
    }
    record.complete_sample(now);
    record.written_at = now;
    if record.history == History::Available && record.incarnation.is_empty() {
        let incarnation = new_incarnation()?;
        durable_replace(
            &RealFs,
            &root.join("gateway-incarnation"),
            incarnation.as_bytes(),
            0o600,
            &|_| Ok(()),
            &|_| Ok(()),
        )?;
        record.incarnation = incarnation;
    }
    if !persist_checked(root, run, &record, guard, &|| commit_check(&record)) {
        return Err(io::Error::other(
            "complete client sample was not durably committed",
        ));
    }
    if abandoned_opening.is_some_and(|opening| {
        std::fs::read_to_string(run.join("client-session-opening"))
            .is_ok_and(|current| current == opening)
    }) {
        let _ = std::fs::remove_file(run.join("client-session-opening"));
    }
    // Persistence owns the on-disk sequence increment. This merged view is
    // returned only for readiness classification, never for another save.
    Ok(record)
}
fn sample_commit_check(
    root: &Path,
    run: &Path,
    record: &Record,
    deadline: Instant,
) -> io::Result<()> {
    if Instant::now() >= deadline {
        invalidate_at(
            root,
            run,
            &record.gateway,
            record.written_at.saturating_add(SAMPLE_INTERVAL.as_secs()),
            record.written_at.saturating_add(SAMPLE_INTERVAL.as_secs()),
        );
        return Err(io::Error::other(
            "client sample missed its next cadence slot",
        ));
    }
    if invalidation(run) != record.invalidation {
        return Err(io::Error::other("client sample invalidated during commit"));
    }
    Ok(())
}
fn final_stop_record(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
    namespace: NetnsId,
) -> io::Result<Record> {
    let record = read_record(&path(root), gateway, now)?;
    if record.namespace != namespace
        || record.renewed_at != Some(record.written_at)
        || record.never_served
        || record.sample_failed_at.is_some()
        || record.invalidation != invalidation(run)
        || record.clean_stop.is_some()
    {
        return Err(io::Error::other("clean stop lacks final complete sample"));
    }
    Ok(record)
}
/// Seal only after the caller confirmed destruction of the quiesced device.
/// Must hold the session lock continuously from final sample through teardown.
pub(crate) fn seal_clean_stop(
    root: &Path,
    run: &Path,
    gateway: &str,
    now: u64,
    namespace: NetnsId,
    guard: &WriterGuard,
) -> io::Result<()> {
    let mut record = final_stop_record(root, run, gateway, now, namespace)?;
    record.sequence += 1;
    record.clean_stop = Some(CleanStop {
        namespace,
        device: record.device.clone(),
        sequence: record.sequence,
        at: record.written_at,
    });
    record.down = true;
    record.down_since = None;
    // This durable checkpoint is independent of this boot's /run token.
    record.invalidation.clear();
    // final_stop_record refused an existing seal, so clearing this boot-local
    // marker cannot expose an obsolete seal. Abort before saving if it fails.
    match std::fs::remove_file(run.join("client-session-seal-obsolete")) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    save(root, &record, guard)?;
    publish_readiness(run, &record, true);
    Ok(())
}
/// Consume a pending `LinkUp` probe after a fresh planner output proof.
/// # Errors
/// Returns child/protocol failure, never opens a gate.
pub fn probe_pending(
    sys: &dyn System,
    held: &NetnsHandle,
    site: &ValidatedSite,
    gateway: &GatewayId,
    root: &Path,
    run: &Path,
    _guard: &WriterGuard,
) -> io::Result<()> {
    let deadline = Instant::now() + SAMPLE_INTERVAL;
    let persistence_deadline = deadline.checked_sub(EXEC_TIMEOUT).unwrap_or(deadline);
    let gw = site
        .gateway(gateway)
        .ok_or_else(|| io::Error::other("unknown gateway"))?;
    let identity = gw.client_tunnel().identity().public_key.as_str().to_owned();
    let namespace = held.identity();
    let now = sys.now_unix_secs();
    if run.join("client-sessions-fallback").exists()
        || run.join("client-session-commit").exists()
        || !read_record(&path(root), &identity, now).is_ok_and(|record| {
            record.clean_stop.is_none() && record.probe_pending && record.namespace == namespace
        })
    {
        return Ok(());
    }
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let worker_ready = ready.clone();
    let hook_gateway = identity.clone();
    let persisted = bounded_hook(
        root,
        run,
        &hook_gateway,
        now,
        persistence_deadline,
        HookMode::Probe,
        move |root, run, guard, deadline| {
            if !path(root).exists()
                || run.join("client-sessions-fallback").exists()
                || run.join("client-session-commit").exists()
            {
                return Ok(());
            }
            let mut record = load_writer(root, run, &identity, now);
            if record.clean_stop.is_some() || !record.probe_pending || record.namespace != namespace
            {
                return Ok(());
            }
            record.probe_pending = false;
            if persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            }) {
                probe_committed(&worker_ready);
            }
            Ok(())
        },
    );
    if !probe_persistence_result(persisted, &ready)? {
        return Ok(());
    }
    // Persistence has its own deadline so the reserved child budget remains
    // available. Crossing that deadline after commit does not cancel the send.
    if Instant::now() >= deadline {
        count_missed_probe();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "client probe send deadline",
        ));
    }
    let destinations = site
        .devices()
        .values()
        .filter(|d| d.gateways().contains(gateway))
        .map(|d| d.address4().addr())
        .collect::<Vec<_>>();
    let response = sys.client_session_io(
        crate::system::HelperPurpose::Observation,
        held,
        &Request {
            namespace: held.identity(),
            iface: gw.client_tunnel().ifname().as_str().into(),
            probe: Some((gw.client_tunnel().address4().addr(), destinations.clone())),
        },
    )?;
    let Response::Probes(results) = response else {
        return Err(io::Error::other("invalid client probe response"));
    };
    if results.len() != destinations.len() {
        return Err(io::Error::other("incomplete client probe response"));
    }
    for (host, ok) in destinations.into_iter().zip(results) {
        if !ok {
            eprintln!("client session probe to {host} failed; awaiting client retry");
        }
    }
    Ok(())
}
/// Parent execution with the held namespace fd; no mutable namespace names.
/// # Errors
/// Returns bounded child/protocol errors, never raw netlink contents.
pub fn execute(
    sys: &dyn System,
    purpose: crate::system::HelperPurpose,
    held: &NetnsHandle,
    request: &Request,
) -> io::Result<Response> {
    held.verify(request.namespace)
        .map_err(|_| io::Error::other("client namespace changed"))?;
    let mut command = std::process::Command::new(sys.canon_executable());
    command
        .arg("client-sessions")
        .arg(serde_json::to_string(request).map_err(io::Error::other)?);
    let output =
        crate::system::execute_file_command(purpose, command, held.try_clone_file()?, EXEC_TIMEOUT)
            .map_err(|_| io::Error::other("client session child failed"))?;
    if output.status != Some(0) {
        return Err(io::Error::other("client session child failed"));
    }
    serde_json::from_str(&output.stdout)
        .map_err(|_| io::Error::other("invalid client session child response"))
}
/// Single-threaded helper, called before any namespace-dependent sockets exist.
/// # Errors
/// Returns bounded setup/operation errors; output contains public telemetry only.
pub fn child(json: &str) -> io::Result<Response> {
    if json.len() > 16384 {
        return Err(io::Error::other("client request too large"));
    }
    let request: Request =
        serde_json::from_str(json).map_err(|_| io::Error::other("invalid client request"))?;
    scupper_core::rules::IfName::new(&request.iface).map_err(io::Error::other)?;
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(io::Error::other("client helper must be single threaded"));
    }
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    let held = NetnsHandle::from_file(rustix::io::dup(std::io::stdin())?.into(), request.namespace)
        .map_err(|_| io::Error::other("invalid client namespace"))?;
    let namespace_file = held.try_clone_file()?;
    rustix::thread::move_into_link_name_space(
        namespace_file.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Network),
    )?;
    rustix::stdio::dup2_stdin(std::fs::File::open("/dev/null")?)?;
    if let Some((source, destinations)) = request.probe {
        if destinations.len() > 1024 || source.is_unspecified() {
            return Err(io::Error::other("invalid client probe"));
        }
        let results = destinations
            .into_iter()
            .map(|host| {
                let send = || -> io::Result<()> {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )?;
                    socket.bind_device(Some(request.iface.as_bytes()))?;
                    socket.bind(&SocketAddrV4::new(source, 0).into())?;
                    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
                    if socket.send_to(b"scupper-session", &SocketAddrV4::new(host, 9).into())?
                        != b"scupper-session".len()
                    {
                        return Err(io::Error::other("short client probe"));
                    }
                    Ok(())
                };
                send().is_ok()
            })
            .collect();
        Ok(Response::Probes(results))
    } else {
        let (ifindex, peers) = netlink::read(&request.iface)?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        Ok(Response::Telemetry {
            device: DeviceId {
                boot: boot.trim().to_owned(),
                ifindex,
            },
            up: netlink::link_up(ifindex)?,
            peers,
        })
    }
}

#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        lock::WriterLock,
        netns::testing,
        system::{ExecError, ExecOutput, Program},
    };
    use std::{
        cell::{Cell, RefCell},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    const ID: &str = "gateway-public-identity";
    struct Fake {
        sample: RefCell<Sample>,
        now: Cell<u64>,
        fail_read: Cell<bool>,
        fail_probe: Cell<bool>,
        missing: Cell<bool>,
        extra: RefCell<Vec<Sample>>,
        device: RefCell<Option<DeviceId>>,
        up: Cell<bool>,
        sends: Cell<usize>,
        reads: Cell<usize>,
        during_sample: RefCell<Option<Box<dyn FnOnce()>>>,
    }
    impl System for Fake {
        fn run(
            &self,
            _purpose: crate::system::HelperPurpose,
            _: Program,
            _: &[String],
            _: Duration,
        ) -> Result<ExecOutput, ExecError> {
            panic!("no commands expected")
        }
        fn now_unix_secs(&self) -> u64 {
            self.now.get()
        }
        fn client_session_io(
            &self,
            _purpose: crate::system::HelperPurpose,
            _: &NetnsHandle,
            r: &Request,
        ) -> io::Result<Response> {
            if self.fail_read.get() {
                return Err(io::Error::other("telemetry timeout"));
            }
            Ok(if let Some((source, hosts)) = &r.probe {
                assert_eq!(r.iface, "wg0");
                assert_eq!(*source, Ipv4Addr::new(10, 99, 0, 1));
                assert!(hosts.iter().all(|h| *h == Ipv4Addr::new(10, 99, 0, 2)));
                self.sends.set(self.sends.get() + hosts.len());
                if self.fail_probe.get() {
                    return Err(io::Error::other("probe failed"));
                }
                Response::Probes(vec![true; hosts.len()])
            } else {
                self.reads.set(self.reads.get() + 1);
                if let Some(action) = self.during_sample.borrow_mut().take() {
                    action();
                }
                let mut peers = if self.missing.get() {
                    vec![]
                } else {
                    vec![self.sample.borrow().clone()]
                };
                peers.extend(self.extra.borrow().iter().cloned());
                if let Some(device) = self.device.borrow().clone() {
                    Response::Telemetry {
                        device,
                        up: self.up.get(),
                        peers,
                    }
                } else {
                    Response::Samples(peers)
                }
            })
        }
    }
    struct Rig {
        confirmation: Option<std::sync::Arc<confirmation_testing::Control>>,
        root: PathBuf,
        guard: WriterGuard,
        held: NetnsHandle,
        sys: Fake,
    }
    impl Rig {
        fn new() -> Self {
            let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp"))
                .join(format!(
                    "session-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            let guard = WriterLock::acquire(&root).unwrap();
            provision(&root, ID, 1000, &guard).unwrap();
            activate(&root, &root, ID, 1000, &guard).unwrap();
            Self {
                confirmation: None,
                root,
                guard,
                held: testing::handle().unwrap(),
                sys: Fake {
                    sample: RefCell::new(Sample {
                        key: [3; 32],
                        handshake: (0, 0),
                        rx: 0,
                        tx: 0,
                    }),
                    now: Cell::new(1000),
                    fail_read: Cell::new(false),
                    fail_probe: Cell::new(false),
                    missing: Cell::new(false),
                    extra: RefCell::default(),
                    device: RefCell::new(None),
                    up: Cell::new(true),
                    sends: Cell::new(0),
                    reads: Cell::new(0),
                    during_sample: RefCell::new(None),
                },
            }
        }
        fn up(&self) {
            self.up_until(Instant::now() + SAMPLE_INTERVAL);
        }
        fn up_until(&self, deadline: Instant) {
            before_up_until(
                &self.sys,
                &self.held,
                "wg0",
                &self.root,
                &self.root,
                ID,
                true,
                &self.guard,
                deadline,
                false,
            )
            .unwrap();
        }
        fn before_down_committed(&self, run: &Path) {
            before_down(&self.sys, &self.root, run, ID, &self.guard).unwrap();
            let deadline = Instant::now() + SAMPLE_INTERVAL;
            loop {
                let worker =
                    WriterLock::acquire_timeout(run.join("client-session-writer"), SAMPLE_INTERVAL)
                        .unwrap();
                let record = self.state();
                if record.down_since.is_some() || record.clean_stop.is_some() {
                    break;
                }
                drop(worker);
                assert!(Instant::now() < deadline, "down intent did not commit");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        fn watch_containment(
            &self,
            before_lock: Option<FsyncHook>,
        ) -> std::sync::mpsc::Receiver<io::Result<()>> {
            let (finished, completion) = std::sync::mpsc::channel();
            containment_test_hooks().lock().unwrap().insert(
                self.root.clone(),
                ContainmentTestHooks {
                    before_lock,
                    finished,
                },
            );
            completion
        }
        fn wait_for_containment(
            &self,
            completion: &std::sync::mpsc::Receiver<io::Result<()>>,
        ) -> io::Result<()> {
            let outcome = completion.recv_timeout(SAMPLE_INTERVAL).unwrap();
            containment_test_hooks().lock().unwrap().remove(&self.root);
            outcome
        }
        fn down(&self) {
            link_down(
                &self.sys,
                &self.held,
                "wg0",
                &self.root,
                &self.root,
                ID,
                &self.guard,
                true,
            )
            .unwrap();
        }
        fn state(&self) -> Record {
            load(&self.root, ID, self.sys.now.get())
        }
        fn status(&self) -> ClientSessions {
            status(
                &self.sys,
                &self.held,
                "wg0",
                &self.root,
                &self.root,
                ID,
                &[[3; 32]],
            )
            .unwrap()
        }
        fn checkpoint(&self) {
            checkpoint_recovered(
                &self.sys,
                &self.held,
                "wg0",
                &self.root,
                &self.root,
                ID,
                &self.guard,
                &[[3; 32]],
            )
            .unwrap();
        }
        fn authenticate(&self) {
            self.sys.now.set(self.sys.now.get() + 1);
            let mut sample = self.sys.sample.borrow_mut();
            sample.handshake = (self.sys.now.get(), 1);
            sample.rx += 124;
            sample.tx += 148;
            drop(sample);
            self.checkpoint();
        }
    }
    impl Drop for Rig {
        fn drop(&mut self) {
            // Bounded hooks may return while their fenced worker is unwinding.
            // Keep the fixture alive until ordinary local I/O has released it.
            if let Ok(_worker) = WriterLock::acquire_timeout(
                self.root.join("client-session-writer"),
                Duration::from_secs(2),
            ) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
    }
    // A real reset with a live lease, followed by evidence seen only by check.
    fn pending_live_confirmation() -> Rig {
        let mut rig = Rig::new();
        rig.confirmation = Some(std::sync::Arc::new(confirmation_testing::Control::new(
            &rig.root,
        )));
        *rig.sys.device.borrow_mut() = Some(DeviceId {
            boot: "boot-confirmation".into(),
            ifindex: 7,
        });
        rig.up();
        rig.authenticate();
        rig.down();
        {
            let mut sample = rig.sys.sample.borrow_mut();
            sample.handshake = (0, 0);
            sample.rx = 0;
            sample.tx = 0;
        }
        rig.up();
        assert_eq!(rig.state().peers[0].state, SessionState::RequiredPending);
        assert_eq!(rig.state().peers[0].baseline.rx, 0);
        rig.sys.now.set(1002);
        {
            let mut sample = rig.sys.sample.borrow_mut();
            sample.handshake = (1002, 1);
            sample.rx = 180 + 112 * 13;
            sample.tx = 2000;
        }
        rig
    }

    #[test]
    fn live_confirmation_persists_exact_sample_before_readiness_and_survives_ambiguous_rx() {
        let rig = pending_live_confirmation();
        let before = rig.state();
        let reads = rig.sys.reads.get();
        assert_eq!(rig.status(), ClientSessions::default());
        assert_eq!(
            rig.sys.reads.get(),
            reads + 1,
            "commit must not re-read telemetry"
        );
        let committed = rig.state();
        assert_eq!(committed.peers[0].state, SessionState::Recovered);
        assert_eq!(committed.peers[0].observed, *rig.sys.sample.borrow());
        assert_eq!(committed.peers[0].generation, before.peers[0].generation);
        assert_eq!(committed.peers[0].baseline, before.peers[0].baseline);
        assert_eq!(committed.peers[0].last_authenticated, Some(1002));
        assert_eq!(committed.peers[0].lease_until, Some(1182));
        assert!(committed.sequence > before.sequence);
        rig.sys.sample.borrow_mut().rx = 1748; // 180 + 112*14 == 92*19
        assert_eq!(rig.status(), ClientSessions::default());
        assert_eq!(
            rig.state().sequence,
            committed.sequence,
            "no sampler or second write"
        );
    }

    #[test]
    fn live_confirmations_never_extend_sampler_freshness_or_publish_readiness() {
        let rig = pending_live_confirmation();
        let mut before = rig.state();
        for key in [[4; 32], [5; 32]] {
            let mut peer = before.peers[0].clone();
            peer.baseline.key = key;
            peer.observed.key = key;
            rig.sys.extra.borrow_mut().push(peer.observed.clone());
            before.peers.push(peer);
        }
        save(&rig.root, &before, &rig.guard).unwrap();
        let cache = std::fs::read(rig.root.join("client-session-readiness")).unwrap();
        let anchor = before.observation_anchor();
        let keys = [[3; 32], [4; 32], [5; 32]];
        // Three clients confirm at separate times, while the sampler never ticks.
        for (index, elapsed) in [1, 7, 14].into_iter().enumerate() {
            rig.sys.now.set(anchor + elapsed);
            if index > 0 {
                rig.sys.extra.borrow_mut()[index - 1] = Sample {
                    key: keys[index],
                    ..rig.sys.sample.borrow().clone()
                };
            }
            let status =
                status(&rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &keys).unwrap();
            assert!(!status.unknown);
            assert_eq!(status.active_reset, index < 2);
            let after = rig.state();
            assert_eq!(after.peers[index].state, SessionState::Recovered);
            assert_eq!(after.renewed_at, before.renewed_at);
            assert_eq!(after.history, before.history);
            assert_eq!(after.resumed_at, before.resumed_at);
            assert_eq!(after.sample_failed_at, before.sample_failed_at);
            assert_eq!(after.unknown_until, before.unknown_until);
            assert_eq!(
                serde_json::to_value(&after.gaps).unwrap(),
                serde_json::to_value(&before.gaps).unwrap()
            );
            assert_eq!(
                std::fs::read(rig.root.join("client-session-readiness")).unwrap(),
                cache
            );
        }
        for elapsed in [16, 28] {
            rig.sys.now.set(anchor + elapsed);
            assert!(
                status(&rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &keys)
                    .unwrap()
                    .unknown
            );
            assert_eq!(
                cached_reason(&rig.root, anchor + elapsed),
                Some(scupper_proto::SessionReason::ClientSessionsUnknown)
            );
        }
    }

    #[test]
    fn live_confirmation_rejects_extra_or_missing_configured_clients_without_writes() {
        for extra_record_peer in [false, true] {
            let rig = pending_live_confirmation();
            let mut record = rig.state();
            let mut keys = vec![[3; 32]];
            if extra_record_peer {
                let mut pending = record.peers[0].clone();
                pending.baseline.key = [4; 32];
                pending.observed.key = [4; 32];
                rig.sys.extra.borrow_mut().push(Sample {
                    key: [4; 32],
                    ..rig.sys.sample.borrow().clone()
                });
                record.peers.push(pending);
                save(&rig.root, &record, &rig.guard).unwrap();
            } else {
                keys.push([4; 32]);
                rig.sys.extra.borrow_mut().push(Sample {
                    key: [4; 32],
                    ..rig.sys.sample.borrow().clone()
                });
            }
            let before = std::fs::read(path(&rig.root)).unwrap();
            let status =
                status(&rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &keys).unwrap();
            assert!(status.active_reset);
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
            assert!(!rig.root.join("client-session-commit").exists());
            assert!(
                rig.state()
                    .peers
                    .iter()
                    .all(|p| p.state == SessionState::RequiredPending)
            );
        }
    }

    #[test]
    fn idle_clients_need_no_commit_even_with_read_only_or_locked_storage() {
        use std::os::unix::fs::PermissionsExt;
        for state in [SessionState::ExpiredUnconfirmed, SessionState::Unknown] {
            let rig = pending_live_confirmation();
            let mut idle = rig.state();
            idle.peers[0].state = state;
            idle.peers[0].last_authenticated =
                (state == SessionState::ExpiredUnconfirmed).then_some(821);
            idle.peers[0].lease_until = idle.peers[0].last_authenticated.map(|at| at + LEASE);
            save(&rig.root, &idle, &rig.guard).unwrap();
            let before = std::fs::read(path(&rig.root)).unwrap();
            let _lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
            let permissions = std::fs::metadata(&rig.root).unwrap().permissions();
            for read_only in [false, true] {
                if read_only {
                    std::fs::set_permissions(&rig.root, std::fs::Permissions::from_mode(0o500))
                        .unwrap();
                }
                let status = rig.status();
                std::fs::set_permissions(&rig.root, permissions.clone()).unwrap();
                assert!(!status.active_reset);
                assert!(!status.unknown);
                assert!(status.idle_reset);
                assert_eq!(
                    status.expired_unconfirmed,
                    state == SessionState::ExpiredUnconfirmed
                );
            }
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        }
    }

    #[test]
    fn live_confirmation_preserves_open_gaps_and_failed_sampling_history() {
        let rig = pending_live_confirmation();
        let mut before = rig.state();
        before.history = History::Unavailable;
        before.resumed_at = Some(1001);
        before.sample_failed_at = Some(1001);
        before.gaps = vec![Gap {
            start: 1001,
            end: None,
        }];
        before.unknown_until = Some(1002);
        save(&rig.root, &before, &rig.guard).unwrap();
        assert!(rig.status().unknown);
        let after = rig.state();
        assert_eq!(after.peers[0].state, SessionState::Recovered);
        assert_eq!(after.history, before.history);
        assert_eq!(after.resumed_at, before.resumed_at);
        assert_eq!(after.sample_failed_at, before.sample_failed_at);
        assert_eq!(after.unknown_until, before.unknown_until);
        assert_eq!(
            serde_json::to_value(after.gaps).unwrap(),
            serde_json::to_value(before.gaps).unwrap()
        );
    }

    #[test]
    fn live_confirmation_keeps_a_continuous_recovered_peer_while_confirming_another() {
        let rig = pending_live_confirmation();
        let mut before = rig.state();
        let mut recovered_peer = before.peers[0].clone();
        recovered_peer.baseline.key = [4; 32];
        recovered_peer.observed = Sample {
            key: [4; 32],
            ..rig.sys.sample.borrow().clone()
        };
        recovered_peer.state = SessionState::Recovered;
        before.peers.push(recovered_peer.clone());
        save(&rig.root, &before, &rig.guard).unwrap();
        rig.sys.extra.borrow_mut().push(Sample {
            rx: 1748,
            ..recovered_peer.observed.clone()
        });
        assert_eq!(
            status(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &[[3; 32], [4; 32]]
            )
            .unwrap(),
            ClientSessions::default()
        );
        let after = rig.state();
        assert!(
            after
                .peers
                .iter()
                .all(|p| p.state == SessionState::Recovered)
        );
        assert_eq!(
            serde_json::to_value(&after.peers[1]).unwrap(),
            serde_json::to_value(recovered_peer).unwrap()
        );
    }

    #[test]
    fn live_confirmation_leaves_corrupt_durable_evidence_for_sampler_alert_and_quarantine() {
        let rig = pending_live_confirmation();
        let fallback = std::fs::read(path(&rig.root)).unwrap();
        std::fs::write(rig.root.join("client-sessions-fallback"), &fallback).unwrap();
        std::fs::write(path(&rig.root), b"corrupt durable history").unwrap();
        assert!(rig.status().active_reset);
        assert_eq!(
            std::fs::read(path(&rig.root)).unwrap(),
            b"corrupt durable history"
        );
        assert_eq!(
            std::fs::read(rig.root.join("client-sessions-fallback")).unwrap(),
            fallback
        );
        assert!(!rig.root.join("client-session-commit").exists());
        rig.checkpoint();
        assert_eq!(
            std::fs::read(path(&rig.root).with_extension("unavailable.json")).unwrap(),
            b"corrupt durable history"
        );
        assert!(take_history_alert(&rig.root, &rig.guard));
    }

    #[test]
    fn sampler_reaps_dead_cli_temps_but_preserves_live_files_and_symlinks() {
        let rig = pending_live_confirmation();
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let orphan = rig.root.join(format!(".scupper-{pid}-0.tmp"));
        let live = rig
            .root
            .join(format!(".scupper-{}-999.tmp", std::process::id()));
        let symlink = rig.root.join(format!(".scupper-{pid}-1.tmp"));
        std::fs::write(&orphan, b"orphan").unwrap();
        std::fs::write(&live, b"live").unwrap();
        std::os::unix::fs::symlink(&live, &symlink).unwrap();
        rig.checkpoint();
        assert!(!orphan.exists());
        assert!(symlink.symlink_metadata().unwrap().is_symlink());
        assert_eq!(std::fs::read(live).unwrap(), b"live");
    }

    #[test]
    fn live_confirmation_accepts_newer_sampler_timestamp_without_restamping_lease() {
        let rig = pending_live_confirmation();
        let mut advanced = rig.state();
        advanced.written_at = 1003;
        advanced.renewed_at = Some(1003);
        let root = rig.root.clone();
        *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
            std::fs::write(path(&root), serde_json::to_vec(&advanced).unwrap()).unwrap();
        }));
        assert!(!rig.status().active_reset);
        // Status's fake observation clock predates this on-disk write.
        let after = read_record(&path(&rig.root), ID, 1003).unwrap();
        assert_eq!(after.written_at, 1003);
        assert_eq!(after.renewed_at, Some(1003));
        assert_eq!(after.peers[0].last_authenticated, Some(1002));
    }

    #[test]
    fn live_confirmation_leaves_unbound_history_for_the_sampler_to_reconstruct() {
        let rig = pending_live_confirmation();
        let mut record = rig.state();
        record.incarnation.clear();
        std::fs::remove_file(rig.root.join("gateway-incarnation")).unwrap();
        save(&rig.root, &record, &rig.guard).unwrap();
        let before = std::fs::read(path(&rig.root)).unwrap();
        assert!(rig.status().active_reset);
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        assert!(!rig.root.join("gateway-incarnation").exists());
        rig.checkpoint();
        assert_eq!(rig.status(), ClientSessions::default());
    }

    #[test]
    fn live_confirmation_rejects_epoch_changes_during_collection_without_writing() {
        for change in 0..9 {
            let rig = pending_live_confirmation();
            let mut changed = rig.state();
            match change {
                0 => changed.namespace = (99, 99),
                1 => changed.device.as_mut().unwrap().ifindex += 1,
                2 => changed.peers[0].generation += 1,
                3 => changed.peers[0].baseline.rx += 1,
                4 => changed.peers[0].baseline.key = [4; 32],
                5 => changed.down = true,
                6 => changed.down_since = Some(1001),
                7 => changed.baseline_pending = true,
                _ => changed.invalidation = "1002:changed".into(),
            }
            if change == 4 {
                changed.peers[0].observed.key = [4; 32];
            }
            changed.sequence += 1;
            let bytes = serde_json::to_vec(&changed).unwrap();
            let root = rig.root.clone();
            let replacement = bytes.clone();
            *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
                let guard = WriterLock::try_acquire(root.join("client-session-writer")).unwrap();
                std::fs::write(path(&root), replacement).unwrap();
                drop(guard);
            }));
            assert!(rig.status().active_reset, "fence {change}");
            assert_eq!(
                std::fs::read(path(&rig.root)).unwrap(),
                bytes,
                "fence {change}"
            );
            assert!(!rig.root.join("client-session-commit").exists());
            assert!(!rig.root.join("client-session-invalidation").exists());
        }
    }

    #[test]
    fn live_confirmation_rejects_sampler_advance_past_exact_sample_without_writing() {
        for counter in 0..3 {
            let rig = pending_live_confirmation();
            let mut advanced = rig.state();
            advanced.peers[0].observed = rig.sys.sample.borrow().clone();
            match counter {
                0 => advanced.peers[0].observed.rx += 1,
                1 => advanced.peers[0].observed.tx += 1,
                _ => advanced.peers[0].observed.handshake.1 += 1,
            }
            advanced.sequence += 1;
            let bytes = serde_json::to_vec(&advanced).unwrap();
            let root = rig.root.clone();
            let replacement = bytes.clone();
            *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
                std::fs::write(path(&root), replacement).unwrap();
            }));
            assert!(rig.status().active_reset, "counter {counter}");
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), bytes);
            assert!(!rig.root.join("client-session-commit").exists());
        }
    }

    #[test]
    fn live_confirmation_merges_current_sampler_record_and_never_rereads_telemetry() {
        let rig = pending_live_confirmation();
        let mut advanced = rig.state();
        advanced.sequence += 1;
        advanced.probe_pending = false;
        // A sampler can advance while remaining in the same recovery epoch.
        advanced.peers[0].observed.rx = 92;
        advanced.peers[0].observed.tx = 148;
        let root = rig.root.clone();
        *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
            std::fs::write(path(&root), serde_json::to_vec(&advanced).unwrap()).unwrap();
        }));
        assert_eq!(rig.status(), ClientSessions::default());
        assert!(
            !rig.state().probe_pending,
            "merge must preserve current accounting"
        );
        assert_eq!(rig.state().peers[0].observed, *rig.sys.sample.borrow());
    }

    #[test]
    fn live_confirmation_lock_timeout_is_bounded_and_does_not_write() {
        let mut rig = pending_live_confirmation();
        rig.confirmation.take(); // Exercise the production 500 ms lock budget.
        let before = std::fs::read(path(&rig.root)).unwrap();
        let lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
        let started = Instant::now();
        assert!(rig.status().active_reset);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(lock);
        let _worker = WriterLock::acquire_timeout(
            rig.root.join("client-session-writer"),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        assert!(!rig.root.join("client-session-invalidation").exists());
    }

    #[test]
    fn read_only_check_requires_persisted_confirmation() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return; // CAP_DAC_OVERRIDE bypasses mode-based write rejection.
        }
        let rig = pending_live_confirmation();
        let before = std::fs::read(path(&rig.root)).unwrap();
        let permissions = std::fs::metadata(&rig.root).unwrap().permissions();
        std::fs::set_permissions(&rig.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let pending = rig.status();
        std::fs::set_permissions(&rig.root, permissions.clone()).unwrap();
        assert!(pending.active_reset);
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        assert_eq!(rig.status(), ClientSessions::default());
        rig.sys.sample.borrow_mut().rx = 1748;
        std::fs::set_permissions(&rig.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let confirmed = rig.status();
        std::fs::set_permissions(&rig.root, permissions).unwrap();
        assert_eq!(confirmed, ClientSessions::default());
    }

    #[test]
    fn live_confirmation_reset_during_commit_rejects_before_rename() {
        let rig = pending_live_confirmation();
        let before = std::fs::read(path(&rig.root)).unwrap();
        let root = rig.root.clone();
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                // Containment invalidates before waiting for the session lock.
                invalidate_at(&root, &root, ID, 1002, 1002);
            }),
        );
        assert!(rig.status().active_reset);
        fsync_hooks().lock().unwrap().remove(&rig.root);
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        assert!(rig.root.join("client-session-commit").exists());
        assert_eq!(
            cached_reason(&rig.root, 1002),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
        rig.checkpoint();
        assert!(!rig.root.join("client-session-commit").exists());
    }

    #[test]
    fn live_confirmation_opening_or_incarnation_change_during_commit_is_fenced() {
        for opening in [false, true] {
            let rig = pending_live_confirmation();
            let before = std::fs::read(path(&rig.root)).unwrap();
            let root = rig.root.clone();
            fsync_hooks().lock().unwrap().insert(
                rig.root.clone(),
                std::sync::Arc::new(move || {
                    if opening {
                        std::fs::write(root.join("client-session-opening"), b"1002:new-opening")
                            .unwrap();
                    } else {
                        std::fs::write(root.join("gateway-incarnation"), b"replacement").unwrap();
                    }
                }),
            );
            assert!(rig.status().active_reset);
            fsync_hooks().lock().unwrap().remove(&rig.root);
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
            assert!(rig.root.join("client-session-commit").exists());
            assert!(!rig.root.join("client-sessions-fallback").exists());
            assert!(!rig.root.join("client-session-history-alert").exists());
        }
    }

    #[test]
    fn live_confirmation_rejects_opening_start_completion_or_clean_seal_during_collection() {
        for change in 0..3 {
            let rig = pending_live_confirmation();
            let root = rig.root.clone();
            let mut changed = rig.state();
            let before = std::fs::read(path(&rig.root)).unwrap();
            let replacement = if change == 0 {
                before
            } else {
                if change == 1 {
                    changed.peers[0].generation += 1;
                } else {
                    changed.down = true;
                    changed.clean_stop = Some(CleanStop {
                        namespace: changed.namespace,
                        device: changed.device.clone(),
                        sequence: changed.sequence,
                        at: changed.written_at,
                    });
                }
                serde_json::to_vec(&changed).unwrap()
            };
            let expected = replacement.clone();
            *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
                if change < 2 {
                    std::fs::write(root.join("client-session-opening"), b"1002:new-opening")
                        .unwrap();
                }
                std::fs::write(path(&root), replacement).unwrap();
                if change == 1 {
                    std::fs::remove_file(root.join("client-session-opening")).unwrap();
                }
            }));
            assert!(rig.status().active_reset, "epoch change {change}");
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), expected);
            assert!(!rig.root.join("client-session-commit").exists());
        }
    }

    #[test]
    fn live_confirmation_ack_loss_returns_reset_even_after_durable_commit() {
        let rig = pending_live_confirmation();
        rig.confirmation.as_ref().unwrap().lose_ack();
        assert!(
            rig.status().active_reset,
            "persistence without ack cannot pass this check"
        );
        assert_eq!(rig.state().peers[0].state, SessionState::Recovered);
        rig.sys.sample.borrow_mut().rx = 1748;
        assert_eq!(
            rig.status(),
            ClientSessions::default(),
            "later checks can use committed evidence"
        );
    }

    #[test]
    fn live_confirmation_does_not_acknowledge_blocked_storage_or_late_commit() {
        let rig = pending_live_confirmation();
        let before = std::fs::read(path(&rig.root)).unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let (entered, entry) = std::sync::mpsc::channel();
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                entered.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap();
            }),
        );
        let control = rig.confirmation.as_ref().unwrap().clone();
        let controller = std::thread::spawn(move || {
            entry.recv_timeout(Duration::from_secs(30)).unwrap();
            control.expire();
        });
        let pending = rig.status();
        controller.join().unwrap();
        assert!(
            pending.active_reset,
            "no acknowledgement while file fsync is blocked"
        );
        release.send(()).unwrap();
        let _worker = WriterLock::acquire_timeout(
            rig.root.join("client-session-writer"),
            Duration::from_secs(2),
        )
        .unwrap();
        fsync_hooks().lock().unwrap().remove(&rig.root);
        assert_eq!(
            std::fs::read(path(&rig.root)).unwrap(),
            before,
            "late pre-rename write rejected"
        );
    }

    #[test]
    fn gateway_responses_are_not_confirmation_and_client_initiation_ambiguity_is_explicit() {
        let rig = Rig::new();
        rig.up();
        let reset = rig.state().peers.remove(0);
        for rx in [92, 184, 276, 736] {
            let sample = Sample {
                handshake: (1001, 1),
                rx,
                tx: 2000,
                ..rig.sys.sample.borrow().clone()
            };
            assert!(!recovered(&reset, &sample), "handshake-only rx={rx}");
        }
        for rx in [124, 148, 180, 220, 240] {
            let sample = Sample {
                handshake: (1001, 1),
                rx,
                tx: 2000,
                ..rig.sys.sample.borrow().clone()
            };
            assert!(recovered(&reset, &sample), "transport rx={rx}");
        }
        assert!(!recovered(&reset, &rig.sys.sample.borrow()));
    }
    #[test]
    fn reboot_and_repeated_rebuilds_keep_original_lease_and_expire_without_recovery() {
        let rig = Rig::new();
        rig.up();
        assert!(
            !rig.status().unknown,
            "explicitly provisioned empty history"
        );
        rig.authenticate();
        assert!(!rig.status().unknown);
        let expiry = rig.state().peers[0].lease_until.unwrap();
        rig.down();
        rig.up();
        assert!(rig.status().active_reset);
        let generation = rig.state().peers[0].generation;
        // /run is irrelevant: the only input is this durable record. A new
        // namespace and completely fresh counters must retain the old expiry.
        let mut record = rig.state();
        record.namespace = (99, 99);
        save(&rig.root, &record, &rig.guard).unwrap();
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (0, 0),
            rx: 0,
            tx: 0,
        };
        rig.up();
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].generation, generation + 1);
        assert_eq!(rig.state().peers[0].lease_until, Some(expiry));
        for now in (1002..expiry).step_by(2) {
            rig.sys.now.set(now);
            rig.checkpoint();
        }
        rig.sys.now.set(expiry - 1);
        rig.down();
        rig.up();
        assert_eq!(rig.state().peers[0].lease_until, Some(expiry));
        rig.sys.now.set(expiry);
        rig.checkpoint();
        assert!(!rig.status().active_reset);
        assert!(rig.status().expired_unconfirmed);
        assert_eq!(rig.state().peers[0].state, SessionState::ExpiredUnconfirmed);
        rig.authenticate();
        assert_eq!(rig.state().peers[0].state, SessionState::Recovered);
    }
    #[test]
    fn unavailable_history_is_bounded_survives_restart_and_does_not_block_reopening() {
        for bytes in [b"torn".as_slice(), br#"{"version":999}"#] {
            let rig = Rig::new();
            std::fs::write(path(&rig.root), bytes).unwrap();
            rig.up();
            assert!(rig.status().unknown);
            assert!(take_history_alert(&rig.root, &rig.guard));
            assert!(!take_history_alert(&rig.root, &rig.guard));
            assert_eq!(
                std::fs::read(rig.root.join("client-sessions.unavailable.json")).unwrap(),
                bytes,
                "opening quarantines damaged history without readiness credit"
            );
            rig.checkpoint();
            assert!(rig.root.join("client-sessions.unavailable.json").exists());
            let expiry = rig.state().unknown_until.unwrap();
            for now in (1002..1100).step_by(2) {
                rig.sys.now.set(now);
                rig.checkpoint();
            }
            rig.sys.now.set(1100);
            rig.up();
            assert_eq!(rig.state().unknown_until, Some(expiry));
            for now in (1100..expiry).step_by(2) {
                rig.sys.now.set(now);
                rig.checkpoint();
            }
            rig.sys.now.set(expiry);
            assert!(
                rig.status().unknown,
                "only a complete checkpoint closes reconstruction"
            );
            assert!(rig.status().history_unavailable);
            rig.checkpoint();
            assert!(!rig.status().unknown);
            assert!(!rig.status().history_unavailable);
            assert_ne!(rig.state().peers[0].state, SessionState::Recovered);
        }
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(900); // rollback invalidates history, rather than extending an old lease forever
        rig.up();
        assert!(rig.status().unknown);
        assert_eq!(rig.state().unknown_until, Some(1080));
    }

    fn session_verdict_config() -> &'static scupper_core::verdict::v2::HealthConfigV2 {
        use scupper_core::{
            config::{parse_site, validate},
            verdict::v2::{HealthConfigV2, NetnsIdentity},
        };
        static CONFIG: std::sync::OnceLock<HealthConfigV2> = std::sync::OnceLock::new();
        CONFIG.get_or_init(|| {
            let site = validate(
                parse_site(include_str!(
                    "../../scupper-core/tests/fixtures/site-m2.toml"
                ))
                .unwrap(),
            )
            .unwrap();
            HealthConfigV2::new(
                &site,
                &GatewayId("gw1".into()),
                NetnsIdentity {
                    device: 7,
                    inode: 42,
                },
                vec!["198.51.100.7".parse().unwrap()],
                7,
            )
            .unwrap()
        })
    }

    // Supply verified gateway stages so these assertions exercise the real exit
    // policy as well as the sampler's independently published readiness cache.
    fn session_verdict(sessions: ClientSessions, now: u64) -> scupper_core::verdict::v2::Verdict {
        use scupper_core::{
            parse::{Handshake, UdpSocket},
            render::RouteTarget,
            verdict::v2::*,
        };
        let cfg = session_verdict_config();
        let route = RouteAnswer::Dev(cfg.exit_iface.ifname().clone());
        let obs = Observations {
            topology: Some(Ok(TopologyObs {
                host_wireguard_on_client_port: vec![],
                errors: vec![],
                links_complete: true,
                addresses_complete: true,
                netns: NetnsObs::Present {
                    device: 7,
                    inode: 42,
                },
                links: cfg
                    .links
                    .iter()
                    .map(|(name, addresses)| LinkObs {
                        name: name.clone(),
                        kind: Some("wireguard".into()),
                        up: true,
                        addresses: addresses.clone(),
                    })
                    .collect(),
                peers: cfg.peers.clone(),
                ruleset: RulesetObs::Exact,
                extra_rules: vec![],
                tc_hooks: vec![],
            })),
            defaults: Some(Ok(DefaultRoutes {
                violations: vec![],
                v4: route.clone().into(),
                v6: DefaultRouteObs::Unreachable,
                extra: vec![],
            })),
            active: RouteTarget::Exit(cfg.exit_iface.clone()),
            handshakes: Some(Ok(BTreeMap::from([(
                cfg.exit.clone(),
                Handshake::At { unix_secs: now },
            )]))),
            forwarding: Some(Ok(Forwarding {
                client_sessions: sessions,
                client_v4: 1,
                v4: 1,
                v6: 0,
                netns_sockets: vec![],
                hardening: vec![],
                quarantine: None,
                client_public_key: Some(cfg.client_public_key),
                listen_port: cfg.listen_port,
                host_sockets: vec![UdpSocket {
                    local: (Ipv4Addr::UNSPECIFIED, cfg.listen_port).into(),
                    inode: 99,
                }],
                client_handshakes: cfg.peers[&cfg.client_iface]
                    .iter()
                    .map(|peer| (peer.public_key, Handshake::Never))
                    .collect(),
            })),
            routes: Some(
                cfg.route_sources
                    .iter()
                    .map(|source| {
                        (
                            *source,
                            RouteObs {
                                v4: Ok(route.clone()),
                                v6: Ok(RouteAnswer::Unreachable),
                            },
                        )
                    })
                    .collect(),
            ),
            exit_probe: Some(Ok("203.0.113.77".parse().unwrap())),
            supervisor: Some(Supervisor::Alive {
                netns: cfg.expected_netns,
                iteration_age: Duration::from_secs(1),
            }),
            ..Observations::default()
        };
        let Next::Done(Ok(report)) = next(&obs, cfg, now) else {
            panic!("incomplete gateway fixture");
        };
        report.verdict
    }

    fn checkpoint_keys(rig: &Rig, keys: &[[u8; 32]]) {
        checkpoint_recovered(
            &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &rig.guard, keys,
        )
        .unwrap();
    }

    fn assert_session_outcome(rig: &Rig, keys: &[[u8; 32]], expected: ClientSessions) -> u8 {
        use scupper_core::verdict::v2::{Degraded, Verdict};
        use scupper_proto::SessionReason;
        let now = rig.sys.now.get();
        let actual = status(&rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, keys).unwrap();
        assert_eq!(actual, expected, "status at {now}");
        let (reason, verdict) = if expected.unknown {
            (
                Some(SessionReason::ClientSessionsUnknown),
                Verdict::Degraded(Degraded::ClientSessionsUnknown),
            )
        } else if expected.active_reset {
            (
                Some(SessionReason::ClientSessionsReset),
                Verdict::Degraded(Degraded::ClientSessionsReset),
            )
        } else {
            (
                None,
                Verdict::Protected {
                    exit: scupper_core::config::ExitId("ch1".into()),
                    exit_ip: "203.0.113.77".parse().unwrap(),
                },
            )
        };
        assert_eq!(cached_reason(&rig.root, now), reason, "cache at {now}");
        let actual_verdict = session_verdict(actual, now);
        assert_eq!(actual_verdict, verdict, "verdict at {now}");
        let exit = actual_verdict.exit_code();
        assert_eq!(
            exit,
            if expected.unknown || expected.active_reset {
                3
            } else {
                0
            },
            "exit at {now}"
        );
        exit
    }

    #[derive(Clone, Copy)]
    enum RestartHistory {
        Corrupt,
        Missing,
        NamespaceChange,
    }
    impl RestartHistory {
        fn apply(self, rig: &Rig) {
            match self {
                Self::Corrupt => {
                    std::fs::write(path(&rig.root), b"torn").unwrap();
                }
                Self::Missing => {
                    std::fs::remove_file(path(&rig.root)).unwrap();
                }
                Self::NamespaceChange => {
                    let mut record = rig.state();
                    record.namespace = (99, 99);
                    save(&rig.root, &record, &rig.guard).unwrap();
                    assert!(valid(&record, ID, rig.sys.now.get()));
                }
            }
        }
    }

    fn authenticated_then_reset(keys: &[[u8; 32]]) -> Rig {
        let rig = Rig::new();
        for key in &keys[1..] {
            rig.sys.extra.borrow_mut().push(Sample {
                key: *key,
                ..rig.sys.sample.borrow().clone()
            });
        }
        rig.up();
        rig.sys.now.set(1001);
        {
            let mut sample = rig.sys.sample.borrow_mut();
            sample.handshake = (1001, 1);
            sample.rx = 124;
            sample.tx = 148;
            for extra in rig.sys.extra.borrow_mut().iter_mut() {
                *extra = Sample {
                    key: extra.key,
                    ..sample.clone()
                };
            }
        }
        checkpoint_keys(&rig, keys);
        assert_eq!(rig.state().peers.len(), keys.len());
        assert!(
            rig.state()
                .peers
                .iter()
                .all(|peer| peer.state == SessionState::Recovered)
        );
        rig.down();
        rig.up();
        assert_eq!(rig.state().peers.len(), keys.len());
        assert!(rig.state().peers.iter().all(|peer| {
            peer.state == SessionState::RequiredPending && peer.lease_until == Some(1181)
        }));
        rig
    }

    fn reconstruction_vs_intact(history: RestartHistory, two_peers: bool) {
        let keys = if two_peers {
            vec![[3; 32], [4; 32]]
        } else {
            vec![[3; 32]]
        };
        let intact = authenticated_then_reset(&keys);
        let restarted = authenticated_then_reset(&keys);
        let lease_until = 1181;
        let restart = 1016;
        let reconstruction_end = restart + 180;
        let reconstructing = !matches!(history, RestartHistory::NamespaceChange);
        // Five-second samples span both sides of the restart. Add exact boundary
        // samples at lease_until - 1 / lease_until and reconstruction 179 / 180.
        let mut times: std::collections::BTreeSet<_> = (1001..=1206).step_by(5).collect();
        times.extend([
            lease_until - 1,
            lease_until,
            reconstruction_end - 1,
            reconstruction_end,
        ]);
        for now in times {
            for rig in [&intact, &restarted] {
                rig.sys.now.set(now);
                if two_peers && now == restart + 5 {
                    // Only the first peer confirms with a newer handshake and
                    // transport receipt. The second retains its reset obligation.
                    let mut sample = rig.sys.sample.borrow_mut();
                    sample.handshake = (now, 1);
                    sample.rx += 124;
                    sample.tx += 148;
                }
            }
            if now == restart {
                history.apply(&restarted);
            }
            for rig in [&intact, &restarted] {
                checkpoint_keys(rig, &keys);
            }
            if reconstructing && now == restart {
                let record = restarted.state();
                assert_eq!(record.unknown_until, Some(reconstruction_end));
                assert_eq!(record.gaps[0].end, Some(restart));
            }
            let intact_expected = ClientSessions {
                active_reset: now < lease_until,
                idle_reset: now >= lease_until,
                expired_unconfirmed: now >= lease_until,
                ..ClientSessions::default()
            };
            let restarted_expected = if reconstructing && now >= restart {
                ClientSessions {
                    unknown: now < reconstruction_end,
                    history_unavailable: now < reconstruction_end,
                    idle_reset: true,
                    ..ClientSessions::default()
                }
            } else {
                intact_expected
            };
            let intact_exit = assert_session_outcome(&intact, &keys, intact_expected);
            let restarted_exit = assert_session_outcome(&restarted, &keys, restarted_expected);
            assert!(
                intact_exit != 3 || restarted_exit == 3,
                "one-way readiness at {now}"
            );
            for (rig, lost) in [
                (&intact, false),
                (&restarted, reconstructing && now >= restart),
            ] {
                let record = rig.state();
                assert_eq!(record.peers.len(), keys.len());
                for peer in &record.peers {
                    let recovered = two_peers && peer.baseline.key == [3; 32] && now >= restart + 5;
                    let expected_state = if recovered {
                        SessionState::Recovered
                    } else if lost {
                        SessionState::Unknown
                    } else if now < lease_until {
                        SessionState::RequiredPending
                    } else {
                        SessionState::ExpiredUnconfirmed
                    };
                    assert_eq!(
                        peer.state, expected_state,
                        "peer {:?} at {now}",
                        peer.baseline.key
                    );
                    assert_eq!(
                        peer.lease_until,
                        if recovered {
                            Some(restart + 5 + 180)
                        } else if lost {
                            None
                        } else {
                            Some(lease_until)
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn reconstruction_from_corrupt_history_never_returns_zero_before_intact() {
        reconstruction_vs_intact(RestartHistory::Corrupt, false);
    }

    #[test]
    fn reconstruction_from_missing_history_never_returns_zero_before_intact() {
        reconstruction_vs_intact(RestartHistory::Missing, false);
    }

    #[test]
    fn valid_history_across_namespace_change_keeps_original_deadline() {
        reconstruction_vs_intact(RestartHistory::NamespaceChange, false);
    }

    #[test]
    fn reconstruction_one_recovered_peer_cannot_mask_another_peer() {
        for history in [
            RestartHistory::Corrupt,
            RestartHistory::Missing,
            RestartHistory::NamespaceChange,
        ] {
            reconstruction_vs_intact(history, true);
        }
    }

    #[test]
    fn reconstruction_same_handshake_client_initiations_grant_a_lease() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        std::fs::write(path(&rig.root), b"torn").unwrap();
        rig.checkpoint();
        let baseline = rig.state().peers[0].clone();
        assert_eq!(baseline.state, SessionState::Unknown);
        assert_eq!(baseline.lease_until, None);
        // L1 is the documented residual in the same family as N3 (DESIGN §12).
        // Changing it must be deliberate: modulus rules cannot classify
        // aggregated counter deltas, and removing the shortcut removes leases.
        for now in (1006..=1181).step_by(5) {
            rig.sys.now.set(now);
            rig.sys.sample.borrow_mut().rx += 148;
            rig.checkpoint();
            let peer = rig.state().peers.remove(0);
            assert_eq!(peer.observed.handshake, baseline.observed.handshake);
            assert_eq!(peer.state, SessionState::Recovered);
            assert_eq!(peer.last_authenticated, Some(now));
            assert_eq!(peer.lease_until, Some(now + 180));
            // The idle warning stays absent even when reconstruction completes.
            assert_session_outcome(
                &rig,
                &[[3; 32]],
                ClientSessions {
                    unknown: now < 1181,
                    history_unavailable: now < 1181,
                    ..ClientSessions::default()
                },
            );
        }
        rig.down();
        rig.up();
        assert_session_outcome(
            &rig,
            &[[3; 32]],
            ClientSessions {
                active_reset: true,
                ..ClientSessions::default()
            },
        );
    }
    #[test]
    fn reset_time_is_saved_before_a_timeout_and_offline_peers_expire() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let expiry = rig.state().peers[0].lease_until;
        rig.sys.fail_read.set(true);
        assert!(
            link_down(
                &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &rig.guard, true
            )
            .is_err()
        );
        assert_eq!(rig.state().down_since, Some(1001));
        rig.sys.fail_read.set(false);
        rig.sys.now.set(9000);
        rig.up();
        assert_eq!(rig.state().peers[0].lease_until, expiry);
        assert!(!rig.status().active_reset);
        assert_eq!(rig.state().peers[0].state, SessionState::ExpiredUnconfirmed);
    }
    #[test]
    fn identity_size_duplicates_and_future_history_are_unavailable() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        assert_eq!(load(&rig.root, "other-gateway", 1001).namespace, (0, 0));
        let mut record = rig.state();
        record.peers.push(record.peers[0].clone());
        save(&rig.root, &record, &rig.guard).unwrap();
        assert_eq!(rig.state().namespace, (0, 0));
        std::fs::write(
            path(&rig.root),
            vec![b' '; usize::try_from(MAX_RECORD_BYTES).unwrap() + 1],
        )
        .unwrap();
        rig.up();
        assert!(rig.status().unknown);
    }
    #[test]
    fn untracked_recreation_in_same_namespace_invalidates_latched_recovery() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let expiry = rig.state().peers[0].lease_until;
        let generation = rig.state().peers[0].generation;
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (0, 0),
            rx: 0,
            tx: 0,
        };
        assert!(rig.status().active_reset);
        rig.checkpoint();
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].generation, generation + 1);
        assert_eq!(rig.state().peers[0].lease_until, expiry);
        rig.authenticate();
        assert!(!rig.status().active_reset);
    }
    #[test]
    fn telemetry_failure_during_reopening_cannot_reuse_old_recovery() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.fail_read.set(true);
        rig.up();
        assert!(rig.state().baseline_pending);
        rig.sys.fail_read.set(false);
        assert!(rig.status().unknown);
        rig.checkpoint();
        assert!(!rig.state().baseline_pending);
        assert!(rig.status().unknown, "old counters are only a new baseline");
        rig.authenticate();
        assert!(rig.status().unknown);
        for now in (1002..=1182).step_by(5) {
            rig.sys.now.set(now);
            rig.checkpoint();
        }
        assert!(!rig.status().unknown);
    }
    #[test]
    fn unavailable_durable_storage_uses_runtime_unknown_lease_and_can_recover() {
        let rig = Rig::new();
        let broken = rig.root.join("not-a-directory");
        std::fs::write(&broken, b"x").unwrap();
        before_up(
            &rig.sys, &rig.held, "wg0", &broken, &rig.root, ID, true, &rig.guard,
        )
        .unwrap();
        let check = || {
            status(
                &rig.sys,
                &rig.held,
                "wg0",
                &broken,
                &rig.root,
                ID,
                &[[3; 32]],
            )
            .unwrap()
        };
        assert!(check().unknown);
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &broken,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]]
            )
            .is_err()
        );
        let expiry = load_current(&broken, &rig.root, ID, 1000).unknown_until;
        rig.sys.now.set(1010);
        before_up(
            &rig.sys, &rig.held, "wg0", &broken, &rig.root, ID, true, &rig.guard,
        )
        .unwrap();
        assert_eq!(
            load_current(&broken, &rig.root, ID, 1010).unknown_until,
            expiry
        );
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (1010, 1),
            rx: 124,
            tx: 148,
        };
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &broken,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]],
            )
            .is_err()
        );
        assert!(check().unknown);
        assert!(check().history_unavailable);
        std::fs::remove_file(&broken).unwrap();
        std::fs::create_dir(&broken).unwrap();
        for now in (1012..=1192).step_by(2) {
            rig.sys.now.set(now);
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &broken,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]],
            )
            .unwrap();
            if now < 1192 {
                assert!(check().unknown);
            }
        }
        assert!(!check().unknown);
        assert!(!check().history_unavailable);
    }
    #[test]
    fn failed_bound_probe_is_consumed_once_and_cannot_renew_an_activity_lease() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let site = scupper_core::config::validate(
            scupper_core::config::parse_site(include_str!(
                "../../scupper-core/tests/fixtures/site-m2.toml"
            ))
            .unwrap(),
        )
        .unwrap();
        let gateway = GatewayId("gw1".into());
        let identity = site
            .gateway(&gateway)
            .unwrap()
            .client_tunnel()
            .identity()
            .public_key
            .as_str();
        let mut record = rig.state();
        record.gateway = identity.into();
        let expiry = record.peers[0].lease_until;
        save(&rig.root, &record, &rig.guard).unwrap();
        rig.sys.fail_probe.set(true);
        assert!(
            probe_pending(
                &rig.sys, &rig.held, &site, &gateway, &rig.root, &rig.root, &rig.guard
            )
            .is_err()
        );
        assert_eq!(rig.sys.sends.get(), 1);
        probe_pending(
            &rig.sys, &rig.held, &site, &gateway, &rig.root, &rig.root, &rig.guard,
        )
        .unwrap();
        assert_eq!(
            rig.sys.sends.get(),
            1,
            "a failed send is left to client retry"
        );
        assert_eq!(
            load(&rig.root, identity, rig.sys.now.get()).peers[0].lease_until,
            expiry
        );
    }
    #[test]
    fn unavailable_readiness_telemetry_is_distinct_and_never_silently_bounded() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.fail_read.set(true);
        for now in [1001, 1181, 9000] {
            rig.sys.now.set(now);
            assert!(rig.status().telemetry_unavailable);
            assert!(
                !rig.status().active_reset,
                "read failure is not session reset"
            );
        }
    }
    #[derive(Clone)]
    struct SamplerDevice {
        data: std::sync::Arc<std::sync::Mutex<(u64, Sample)>>,
        sampled: std::sync::Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>>,
    }
    impl System for SamplerDevice {
        fn run(
            &self,
            _purpose: crate::system::HelperPurpose,
            _: Program,
            _: &[String],
            _: Duration,
        ) -> Result<ExecOutput, ExecError> {
            panic!("no commands expected")
        }
        fn now_unix_secs(&self) -> u64 {
            self.data.lock().unwrap().0
        }
        fn client_session_io(
            &self,
            _purpose: crate::system::HelperPurpose,
            _: &NetnsHandle,
            _: &Request,
        ) -> io::Result<Response> {
            let sample = self.data.lock().unwrap().1.clone();
            if let Some(sampled) = self.sampled.lock().unwrap().take() {
                let _ = sampled.send(());
            }
            Ok(Response::Samples(vec![sample]))
        }
    }
    fn start_sampler(rig: &Rig) -> (Sampler, SamplerDevice) {
        let device = SamplerDevice {
            data: std::sync::Arc::new(std::sync::Mutex::new((
                1000,
                rig.sys.sample.borrow().clone(),
            ))),
            sampled: std::sync::Arc::default(),
        };
        let before = rig.state().sequence;
        let sampler =
            sampler::Sampler::start_test(rig.root.clone(), ID.into(), device.clone()).unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        while rig.state().sequence == before {
            assert!(Instant::now() < until, "first sampler slot did not commit");
            std::thread::sleep(Duration::from_millis(5));
        }
        (sampler, device)
    }

    #[test]
    fn runtime_shutdown_samples_last_interval_and_waits_for_session_lock() {
        let rig = Rig::new();
        rig.up();
        let (sampler, device) = start_sampler(&rig);
        assert_eq!(rig.state().peers[0].lease_until, None);
        {
            let mut data = device.data.lock().unwrap();
            data.0 = 1003;
            data.1.handshake = (1003, 1);
            data.1.rx = 124;
            data.1.tx = 148;
        }
        rig.sys.now.set(1003);
        // A lifecycle writer occupies the session lock at TERM. The stop sample
        // must wait for it instead of dropping the last partial interval.
        // First let any in-flight periodic sampler slot release its own lock.
        let lock =
            WriterLock::acquire_timeout(rig.root.join("client-session-writer"), SAMPLE_INTERVAL)
                .unwrap();
        let (collected, observed) = std::sync::mpsc::channel();
        *device.sampled.lock().unwrap() = Some(collected);
        let release = std::thread::spawn(move || {
            let _ = observed.recv_timeout(SAMPLE_INTERVAL);
            std::thread::sleep(Duration::from_millis(100));
            drop(lock);
        });
        let (result, elapsed) =
            crate::daemon::testing::shutdown_sampler(&rig.root, sampler).unwrap();
        release.join().unwrap();
        result.unwrap();
        assert!(elapsed < SAMPLE_INTERVAL, "stop crossed next slot");
        assert_eq!(rig.state().peers[0].lease_until, Some(1003 + LEASE));
    }

    #[test]
    fn runtime_shutdown_times_out_behind_stalled_sample_and_fences_late_commit() {
        let rig = Rig::new();
        rig.up();
        let (sampler, device) = start_sampler(&rig);
        let before = std::fs::read(path(&rig.root)).unwrap();
        let readiness = std::fs::read(rig.root.join("client-session-readiness")).unwrap();
        device.data.lock().unwrap().0 = 1005;
        let (entered, entry) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                entered.send(()).unwrap();
                released.lock().unwrap().recv().unwrap();
            }),
        );
        // Stall the next periodic slot while it owns the session lock. Finish
        // must queue behind this in-flight write, with the same five-second bound.
        entry
            .recv_timeout(SAMPLE_INTERVAL + Duration::from_secs(1))
            .unwrap();
        // The fixture measures only Sampler::stop, excluding audit fsyncs.
        let (result, elapsed) =
            crate::daemon::testing::shutdown_sampler(&rig.root, sampler).unwrap();
        invalidate_runtime_token(&rig.root, 1006).unwrap();
        fsync_hooks().lock().unwrap().remove(&rig.root);
        release.send(()).unwrap();
        // Wait for the worker (including the expired Finish) before fixture cleanup.
        let owner =
            WriterLock::acquire_timeout(rig.root.join("client-sampler-owner"), SAMPLE_INTERVAL)
                .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(elapsed >= SAMPLE_INTERVAL);
        assert!(elapsed < SAMPLE_INTERVAL + Duration::from_secs(1));
        assert_eq!(
            std::fs::read(path(&rig.root)).unwrap(),
            before,
            "late old-token commit"
        );
        assert!(!rig.root.join("client-sessions-fallback").exists());
        assert_eq!(
            std::fs::read(rig.root.join("client-session-readiness")).unwrap(),
            readiness
        );
        drop(owner);
    }

    #[test]
    fn traffic_in_last_interval_before_daemon_stop_survives_namespace_rebuild() {
        let rig = Rig::new();
        rig.up();
        rig.checkpoint(); // peer has no lease at the last periodic sample
        assert_eq!(rig.state().peers[0].lease_until, None);
        rig.sys.now.set(1003); // traffic arrives before the next five-second slot
        {
            let mut sample = rig.sys.sample.borrow_mut();
            sample.handshake = (1003, 1);
            sample.rx = 124;
            sample.tx = 148;
        }
        before_shutdown(
            &rig.sys,
            &rig.held,
            "wg0",
            &rig.root,
            &rig.root,
            ID,
            &rig.guard,
            &[[3; 32]],
        )
        .unwrap();
        assert_eq!(rig.state().peers[0].lease_until, Some(1183));
        // The stop snapshot is already durable; replace the device before a
        // further periodic observation, just as deleting the namespace does.
        rig.sys.now.set(1004);
        let mut record = rig.state();
        record.namespace = (99, 99); // persisted identity of the destroyed namespace
        save(&rig.root, &record, &rig.guard).unwrap();
        {
            let mut sample = rig.sys.sample.borrow_mut();
            sample.handshake = (0, 0);
            sample.rx = 0;
            sample.tx = 0;
        }
        rig.up();
        assert_eq!(rig.state().peers[0].state, SessionState::RequiredPending);
        assert!(rig.status().active_reset); // check maps this to ClientSessionsReset (3)
        assert!(!rig.status().idle_reset);
        assert_eq!(
            cached_reason(&rig.root, 1004),
            Some(scupper_proto::SessionReason::ClientSessionsReset)
        );
        rig.authenticate();
        assert!(!rig.status().active_reset);
    }

    #[test]
    fn planned_shutdown_snapshots_activity_without_resetting_sessions_or_sending_probes() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1010);
        rig.sys.sample.borrow_mut().rx += 32;
        before_shutdown(
            &rig.sys,
            &rig.held,
            "wg0",
            &rig.root,
            &rig.root,
            ID,
            &rig.guard,
            &[[3; 32]],
        )
        .unwrap();
        assert_eq!(rig.state().peers[0].last_authenticated, Some(1010));
        assert_eq!(rig.state().peers[0].state, SessionState::Recovered);
        assert!(!rig.state().down);
        assert_eq!(rig.sys.sends.get(), 0);
    }
    #[test]
    fn periodic_activity_commits_renewed_at_and_activity_on_every_tick() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let previous = std::fs::read(path(&rig.root)).unwrap();
        rig.sys.now.set(1010);
        rig.sys.sample.borrow_mut().rx += 32;
        rig.checkpoint();
        assert_ne!(std::fs::read(path(&rig.root)).unwrap(), previous);
        assert_eq!(rig.state().renewed_at, Some(1010));
        rig.sys.now.set(1031);
        rig.sys.sample.borrow_mut().rx += 32;
        rig.checkpoint();
        assert_eq!(rig.state().peers[0].last_authenticated, Some(1031));
        assert_eq!(rig.state().peers[0].lease_until, Some(1211));
        assert!(
            !std::fs::read_to_string(path(&rig.root))
                .unwrap()
                .contains("endpoint")
        );
    }
    #[test]
    fn stale_rebuild_and_repeated_rebuilds_cannot_be_cleared_by_first_sample() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1300); // old leases have expired and tracking stalled
        rig.up();
        assert!(rig.status().unknown);
        let gap = rig.state().gaps[0].start;
        rig.checkpoint();
        assert_eq!(rig.state().renewed_at, Some(1300));
        assert!(rig.status().unknown);
        for now in (1302..1480).step_by(2) {
            rig.sys.now.set(now);
            rig.checkpoint();
            assert!(rig.status().unknown);
        }
        rig.up(); // cannot erase the closed gap inside the preceding lease
        assert_eq!(rig.state().gaps[0].start, gap);
        assert!(rig.status().unknown);
        rig.sys.now.set(1480);
        rig.checkpoint();
        assert!(!rig.status().unknown);
        assert!(rig.state().gaps.is_empty());
        assert_eq!(rig.state().unknown_until, None);
        assert!(!rig.status().history_unavailable);
    }

    #[test]
    fn gap_is_durable_even_when_sampling_resumes_before_rebuild() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1020);
        rig.sys.fail_read.set(true);
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]]
            )
            .is_err()
        );
        assert_eq!(rig.state().sample_failed_at, Some(1020));
        assert_eq!(rig.state().renewed_at, Some(1001));
        assert_eq!(rig.state().gaps[0].start, 1016);
        assert_eq!(rig.state().gaps[0].end, None);
        rig.sys.fail_read.set(false);
        rig.sys.now.set(1022);
        rig.checkpoint();
        assert_eq!(rig.state().gaps[0].end, Some(1022));
        assert!(rig.status().unknown);
        rig.up();
        assert!(rig.status().unknown);
    }

    #[test]
    fn missing_peer_keeps_live_lease_and_does_not_renew_complete_sample_time() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let expiry = rig.state().peers[0].lease_until;
        rig.sys.missing.set(true);
        rig.sys.now.set(1002);
        rig.up();
        assert_eq!(rig.state().peers.len(), 1);
        assert_eq!(rig.state().peers[0].lease_until, expiry);
        assert!(rig.status().active_reset);
        assert!(rig.status().peer_missing);
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]]
            )
            .is_err()
        );
        assert_eq!(rig.state().renewed_at, Some(1001));
        rig.sys.now.set(expiry.unwrap());
        assert!(!rig.status().active_reset);
        assert!(rig.status().expired_unconfirmed);
    }

    #[test]
    fn expired_to_active_lease_is_immediately_durable() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let expiry = rig.state().peers[0].lease_until.unwrap();
        for now in (1002..=expiry).step_by(2) {
            rig.sys.now.set(now);
            rig.checkpoint();
        }
        rig.sys.now.set(expiry + 1);
        rig.sys.sample.borrow_mut().rx += 32;
        rig.checkpoint();
        assert_eq!(rig.state().peers[0].last_authenticated, Some(expiry + 1));
        assert_eq!(rig.state().peers[0].lease_until, Some(expiry + 1 + LEASE));
    }

    #[test]
    fn unavailable_marker_and_corrupt_fallback_do_not_quarantine_valid_history() {
        let rig = Rig::new();
        rig.up();
        let good = std::fs::read(path(&rig.root)).unwrap();
        std::fs::write(rig.root.join("client-sessions-fallback"), b"torn").unwrap();
        let _ = load_writer(&rig.root, &rig.root, ID, 1000);
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), good);
        assert!(
            rig.root
                .join("client-sessions-fallback.unavailable.json")
                .exists()
        );
    }

    #[test]
    fn any_backward_clock_step_invalidates_history_until_complete_reconstruction() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(999);
        rig.down();
        rig.up();
        assert!(rig.status().unknown);
        rig.checkpoint();
        assert!(rig.status().unknown);
        for now in (1004..=1179).step_by(5) {
            rig.sys.now.set(now);
            rig.checkpoint();
        }
        assert!(!rig.status().unknown);
    }

    #[test]
    fn containment_lock_contention_is_bounded_and_invalidates_readiness() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        assert!(!rig.status().unknown);
        let lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
        let completion = rig.watch_containment(None);
        let started = Instant::now();
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "elapsed: {:?}",
            started.elapsed()
        );
        assert_ne!(invalidation(&rig.root), "");
        assert!(rig.status().unknown);
        assert_eq!(
            cached_reason(&rig.root, 1001),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
        drop(lock);
        rig.wait_for_containment(&completion).unwrap();
    }

    #[test]
    fn obsolete_marker_failure_still_invalidates_readiness_synchronously() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        std::fs::create_dir(rig.root.join("client-session-seal-obsolete")).unwrap();
        let lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
        let completion = rig.watch_containment(None);
        let previous = invalidation(&rig.root);
        assert!(before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).is_err());
        assert_ne!(invalidation(&rig.root), previous);
        assert!(rig.status().unknown);
        drop(lock);
        rig.wait_for_containment(&completion).unwrap();
        assert!(rig.state().down_since.is_some());
    }

    #[test]
    fn late_containment_cannot_replay_down_intent_after_before_up() {
        // Cover both hooks in the same clock second and a later durable timestamp.
        for reopened_at in [1001, 1002] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            let third_writer =
                WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
            let (entered, entry) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let released = std::sync::Mutex::new(released);
            let completion = rig.watch_containment(Some(std::sync::Arc::new(move || {
                entered.send(()).unwrap();
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(SAMPLE_INTERVAL)
                    .unwrap();
            })));
            before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
            entry.recv_timeout(SAMPLE_INTERVAL).unwrap();
            let token = invalidation(&rig.root);
            // The third writer releases while containment is still waiting. Let the
            // later lifecycle hooks win both lock races before releasing containment.
            drop(third_writer);
            rig.down();
            assert!(rig.state().down_since.is_some());
            rig.sys.now.set(reopened_at);
            rig.up();
            assert_eq!(invalidation(&rig.root), token);
            assert_eq!(rig.state().invalidation, token);
            assert_eq!(rig.state().down_since, None);
            let reopened = std::fs::read(path(&rig.root)).unwrap();
            release.send(()).unwrap();
            // A loaded runner may exhaust the worker's deadline during DOWN/UP.
            // Either outcome must leave the newer committed record unchanged.
            let _outcome = rig.wait_for_containment(&completion);
            assert_eq!(rig.state().down_since, None);
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), reopened);
            // Lock contention opened a reconstruction gap. Recover on its original
            // schedule without a stale down intent forcing another reset/handshake.
            rig.authenticate();
            let recovery_at = reopened_at + 1 + LEASE;
            for now in (reopened_at + 6..=recovery_at).step_by(5) {
                rig.sys.now.set(now);
                rig.checkpoint();
            }
            assert_eq!(rig.status(), ClientSessions::default());
            assert_eq!(cached_reason(&rig.root, recovery_at), None);
        }
    }

    #[test]
    fn slow_containment_commits_after_caller_budget_and_recovers_without_a_gap() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let (entered, entry) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                entered.send(()).unwrap();
                released.lock().unwrap().recv().unwrap();
            }),
        );
        let started = Instant::now();
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
        assert!(started.elapsed() < Duration::from_millis(300));
        entry.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(rig.status().unknown);
        assert_ne!(invalidation(&rig.root), "");
        fsync_hooks().lock().unwrap().remove(&rig.root);
        release.send(()).unwrap();
        // The accepted worker must finish its durable intent after caller return.
        let worker = WriterLock::acquire_timeout(
            rig.root.join("client-session-writer"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(rig.state().down_since, Some(1001));
        assert_eq!(rig.state().history, History::Available);
        assert!(rig.state().gaps.is_empty());
        drop(worker);
        rig.up();
        assert!(rig.status().active_reset);
        assert!(!rig.status().unknown);
        rig.authenticate();
        assert_eq!(rig.status(), ClientSessions::default());
    }

    #[test]
    fn stalled_containment_stays_nonready_and_cannot_commit_after_supersession() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let original = std::fs::read(path(&rig.root)).unwrap();
        let (entered, entry) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                let _ = entered.send(());
                let _ = released.lock().unwrap().recv();
            }),
        );
        let started = Instant::now();
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
        assert!(started.elapsed() < Duration::from_millis(300));
        entry.recv_timeout(Duration::from_secs(1)).unwrap();
        for now in [1001, 1300, 5000] {
            rig.sys.now.set(now);
            let started = Instant::now();
            assert!(rig.status().unknown);
            assert_eq!(
                cached_reason(&rig.root, now),
                Some(scupper_proto::SessionReason::ClientSessionsUnknown)
            );
            assert!(started.elapsed() < Duration::from_millis(300));
        }
        // A later generation wins even if the old disk operation eventually exits.
        invalidate_runtime(&rig.root, 5000).unwrap();
        fsync_hooks().lock().unwrap().remove(&rig.root);
        release.send(()).unwrap();
        let _worker = WriterLock::acquire_timeout(
            rig.root.join("client-session-writer"),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), original);
        assert!(!rig.root.join("client-sessions-fallback").exists());
        assert!(rig.status().unknown);
    }

    #[test]
    fn full_runtime_storage_alone_preserves_healthy_durable_history() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let run = rig.root.join("full-run");
        std::fs::create_dir(&run).unwrap();
        // Every runtime write fails, but the durable directory remains healthy.
        for name in [
            "client-session-commit",
            "client-session-invalidation",
            "client-sessions-fallback",
        ] {
            std::os::unix::fs::symlink(run.join("absent/write"), run.join(name)).unwrap();
        }
        let record = rig.state();
        assert!(!persist(&rig.root, &run, &record, &rig.guard));
        let saved = read_record(&path(&rig.root), ID, 1001).unwrap();
        assert!(saved.sequence > record.sequence);
        assert_eq!(saved.history, History::Unavailable);
        assert_eq!(saved.renewed_at, None);
        assert_eq!(saved.peers[0].lease_until, record.peers[0].lease_until);
        assert_eq!(saved.peers[0].generation, record.peers[0].generation);
        assert_eq!(saved.peers[0].state, record.peers[0].state);
        assert!(load_current(&rig.root, &run, ID, 1001).gap_unknown(1001));
        assert!(!rig.root.join("client-sessions.unavailable.json").exists());
        let empty = Rig::new();
        std::fs::remove_file(path(&empty.root)).unwrap();
        std::fs::remove_file(empty.root.join("gateway-incarnation")).unwrap();
        provision(&empty.root, ID, 1000, &empty.guard).unwrap();
        assert!(!persist(&empty.root, &run, &empty.state(), &empty.guard));
        assert!(
            read_record(&path(&empty.root), ID, 1001)
                .unwrap()
                .never_served
        );
        assert!(!may_serve(&empty.root, ID, 1001));
        assert!(!empty.root.join("client-sessions.unavailable.json").exists());
    }

    #[test]
    fn retirement_of_non_empty_history_does_not_contend_or_invalidate() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let before = std::fs::read(path(&rig.root)).unwrap();
        let _lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
        retire_empty(&rig.root, &rig.root, ID, 1001, &rig.guard).unwrap();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        assert_eq!(invalidation(&rig.root), "");
        assert!(!rig.status().unknown);
    }

    #[test]
    fn probe_timeout_after_pending_bit_commit_preserves_send_opportunity() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let state = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let worker_state = state.clone();
        let (release, released) = std::sync::mpsc::channel();
        let result = bounded_hook(
            &rig.root,
            &rig.root,
            ID,
            1001,
            Instant::now() + EXEC_TIMEOUT + Duration::from_millis(200),
            HookMode::Probe,
            move |root, run, guard, deadline| {
                let mut record = load_writer(root, run, ID, 1001);
                record.probe_pending = false;
                assert!(persist_checked(root, run, &record, guard, &|| {
                    sample_commit_check(root, run, &record, deadline)
                }));
                probe_committed(&worker_state);
                // The commit won the race but its result has not reached the
                // caller before timeout; its ready flag must preserve the send.
                released.recv().unwrap();
                Ok(())
            },
        );
        let result = probe_persistence_result(result, &state);
        assert!(
            result.unwrap(),
            "committed work can use the reserved send budget"
        );
        assert!(!rig.state().probe_pending);
        assert_eq!(rig.sys.sends.get(), 0);
        release.send(()).unwrap();
    }

    #[test]
    fn abandoned_probe_counts_only_a_later_consumed_pending_bit() {
        let count = MISSED_PROBES.load(Ordering::Relaxed);
        let state = std::sync::atomic::AtomicU8::new(0);
        assert!(probe_persistence_result(Err(io::ErrorKind::TimedOut.into()), &state).is_err());
        assert_eq!(
            MISSED_PROBES.load(Ordering::Relaxed),
            count,
            "retained pending work is retried, not missed"
        );
        probe_committed(&state);
        assert!(MISSED_PROBES.load(Ordering::Relaxed) > count);
    }

    #[test]
    fn pending_probe_timeout_does_not_invalidate_or_consume_pending_work() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let site = scupper_core::config::validate(
            scupper_core::config::parse_site(include_str!(
                "../../scupper-core/tests/fixtures/site-m2.toml"
            ))
            .unwrap(),
        )
        .unwrap();
        let gateway = GatewayId("gw1".into());
        let identity = site
            .gateway(&gateway)
            .unwrap()
            .client_tunnel()
            .identity()
            .public_key
            .as_str();
        let mut record = rig.state();
        record.gateway = identity.into();
        for pending in [false, true] {
            record.probe_pending = pending;
            save(&rig.root, &record, &rig.guard).unwrap();
            let before = std::fs::read(path(&rig.root)).unwrap();
            let lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
            let started = Instant::now();
            let result = probe_pending(
                &rig.sys, &rig.held, &site, &gateway, &rig.root, &rig.root, &rig.guard,
            );
            if pending {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            } else {
                result.unwrap();
            }
            if !pending {
                assert!(started.elapsed() < Duration::from_millis(200));
            }
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
            assert_eq!(invalidation(&rig.root), "");
            assert_eq!(rig.sys.sends.get(), 0);
            drop(lock);
        }
    }

    #[test]
    fn failed_link_down_with_continuous_counters_does_not_freeze_tracking() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.before_down_committed(&rig.root);
        link_down(
            &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &rig.guard, false,
        )
        .unwrap();
        assert!(!rig.state().down);
        rig.sys.now.set(1002);
        rig.sys.sample.borrow_mut().rx += 32;
        rig.checkpoint();
        assert!(!rig.state().down);
        assert_eq!(rig.state().renewed_at, Some(1002));
        assert_eq!(rig.state().peers[0].lease_until, Some(1182));
    }
    #[test]
    fn stalled_tracking_never_ages_into_ready_even_with_recovered_counters() {
        let rig = Rig::new();
        // This test advances the sample clock, not the lifecycle I/O deadline.
        rig.up_until(Instant::now() + Duration::from_secs(30));
        rig.authenticate();
        rig.sys.now.set(1016);
        assert!(!rig.status().unknown, "15 seconds is within cadence slack");
        for now in [1017, 1300, 5000] {
            rig.sys.now.set(now);
            assert!(rig.status().unknown);
            rig.up_until(Instant::now() + Duration::from_secs(30));
            assert!(rig.status().unknown);
        }
        rig.checkpoint();
        assert!(
            rig.status().unknown,
            "one resumed sample cannot erase the stall"
        );
    }

    #[test]
    fn first_sample_after_external_recreation_validates_old_history_before_renewing() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1300);
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (0, 0),
            rx: 0,
            tx: 0,
        };
        rig.checkpoint(); // no before_up hook: discover recreation from counter rollback
        assert_eq!(rig.state().renewed_at, Some(1300));
        assert_eq!(rig.state().gaps[0].start, 1016);
        assert_eq!(rig.state().gaps[0].end, Some(1300));
        assert!(rig.status().unknown);
        assert_ne!(rig.state().peers[0].state, SessionState::Recovered);
    }

    #[test]
    fn incomplete_configured_cohort_does_not_renew_even_present_active_peers() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let old = rig.state().peers[0].lease_until;
        rig.sys.now.set(1002);
        rig.sys.sample.borrow_mut().rx += 128;
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32], [4; 32]]
            )
            .is_err()
        );
        assert_eq!(rig.state().renewed_at, Some(1001));
        assert_eq!(rig.state().sample_failed_at, Some(1002));
        assert_eq!(rig.state().peers[0].lease_until, old);
    }

    #[test]
    fn runtime_fallback_is_never_promoted_to_durable_history_by_a_probe() {
        let rig = Rig::new();
        rig.up();
        let site = scupper_core::config::validate(
            scupper_core::config::parse_site(include_str!(
                "../../scupper-core/tests/fixtures/site-m2.toml"
            ))
            .unwrap(),
        )
        .unwrap();
        let gateway = GatewayId("gw1".into());
        let identity = site
            .gateway(&gateway)
            .unwrap()
            .client_tunnel()
            .identity()
            .public_key
            .as_str();
        let mut record = rig.state();
        record.gateway = identity.into();
        record.history = History::Unavailable;
        let fallback = rig.root.join("client-sessions-fallback");
        std::fs::write(&fallback, serde_json::to_vec(&record).unwrap()).unwrap();
        let broken = rig.root.join("broken");
        std::fs::create_dir(&broken).unwrap();
        std::fs::copy(
            rig.root.join("gateway-incarnation"),
            broken.join("gateway-incarnation"),
        )
        .unwrap();
        std::fs::create_dir(path(&broken)).unwrap();
        probe_pending(
            &rig.sys, &rig.held, &site, &gateway, &broken, &rig.root, &rig.guard,
        )
        .unwrap();
        assert_eq!(rig.sys.sends.get(), 0);
        assert!(load_current(&broken, &rig.root, identity, 1000).probe_pending);
        assert!(path(&broken).is_dir());
        probe_pending(
            &rig.sys, &rig.held, &site, &gateway, &broken, &rig.root, &rig.guard,
        )
        .unwrap();
        assert_eq!(rig.sys.sends.get(), 0);
    }
    #[test]
    fn failed_renewer_without_any_successful_sample_is_not_bounded_into_ready() {
        let rig = Rig::new();
        std::fs::remove_file(path(&rig.root)).unwrap();
        rig.up();
        rig.sys.fail_read.set(true);
        for now in [1002, 1020, 1300, 5000] {
            rig.sys.now.set(now);
            assert!(
                checkpoint_recovered(
                    &rig.sys,
                    &rig.held,
                    "wg0",
                    &rig.root,
                    &rig.root,
                    ID,
                    &rig.guard,
                    &[[3; 32]]
                )
                .is_err()
            );
            assert_eq!(rig.state().renewed_at, None);
            assert!(rig.status().unknown);
        }
        assert_eq!(rig.state().gaps[0].start, 1002);
        assert_eq!(rig.state().gaps[0].end, None);
        rig.sys.fail_read.set(false);
        rig.checkpoint();
        assert!(rig.status().unknown);
        assert_eq!(rig.state().gaps[0].end, Some(5000));
    }
    #[test]
    fn available_history_without_committed_sample_time_is_invalid() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let mut record = rig.state();
        record.renewed_at = None;
        assert!(!valid(&record, ID, 1001));
        save(&rig.root, &record, &rig.guard).unwrap();
        assert!(rig.status().unknown);
        assert!(rig.status().history_unavailable);
    }
    #[test]
    fn provisioned_empty_survives_delay_and_boot_cannot_consume_it() {
        let rig = Rig::new();
        std::fs::remove_file(path(&rig.root)).unwrap();
        std::fs::remove_file(rig.root.join("gateway-incarnation")).unwrap();
        provision(&rig.root, ID, 1000, &rig.guard).unwrap();
        let empty = std::fs::read(path(&rig.root)).unwrap();
        rig.sys.now.set(90_000);
        rig.up();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), empty);
        assert!(!may_serve(&rig.root, ID, 90_000));
        assert!(rig.status().unknown);
        activate(&rig.root, &rig.root, ID, 90_000, &rig.guard).unwrap();
        assert!(!rig.state().never_served);
        rig.up();
        rig.checkpoint();
        assert!(!rig.status().unknown);
        assert!(rig.state().gaps.is_empty());
        assert!(provision(&rig.root, ID, 90_000, &rig.guard).is_err());
    }

    #[test]
    fn missing_history_boot_and_check_are_read_only_and_only_sampling_reconstructs() {
        let rig = Rig::new();
        std::fs::remove_file(path(&rig.root)).unwrap();
        for now in [1000, 1500, 9000] {
            rig.sys.now.set(now);
            rig.up();
            assert!(rig.status().unknown);
            assert!(!path(&rig.root).exists());
        }
        for now in (9000..=9180).step_by(5) {
            rig.sys.now.set(now);
            rig.sys.sample.borrow_mut().handshake = (now, 1);
            rig.sys.sample.borrow_mut().rx += 128;
            rig.checkpoint();
            assert_eq!(rig.status().unknown, now < 9180);
        }
        assert!(!rig.status().history_unavailable);
    }

    #[test]
    fn lifecycle_hooks_never_create_durable_history_from_a_runtime_fallback() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let old = std::fs::read(path(&rig.root)).unwrap();
        std::fs::write(rig.root.join("client-sessions-fallback"), &old).unwrap();
        std::fs::remove_file(path(&rig.root)).unwrap();
        rig.up();
        rig.down();
        assert!(!path(&rig.root).exists());
        assert_eq!(
            std::fs::read(rig.root.join("client-sessions-fallback")).unwrap(),
            old
        );
    }

    #[test]
    fn missing_history_stays_unknown_even_without_configured_peers_or_a_sampler() {
        let rig = Rig::new();
        std::fs::remove_file(path(&rig.root)).unwrap();
        for now in [1000, 1180, 9000] {
            rig.sys.now.set(now);
            let sessions =
                status(&rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &[]).unwrap();
            assert!(sessions.unknown);
            assert!(sessions.history_unavailable);
            assert!(!path(&rig.root).exists());
        }
    }

    #[test]
    fn clean_stop_sixty_second_reboot_uses_stop_freshness_and_consumes_once() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1010);
        rig.sys.sample.borrow_mut().rx += 32;
        rig.checkpoint(); // final complete sample after quiescing in the caller
        let expiry = rig.state().peers[0].lease_until;
        seal_clean_stop(
            &rig.root,
            &rig.root,
            ID,
            1010,
            rig.held.identity(),
            &rig.guard,
        )
        .unwrap();
        rig.sys.now.set(1070); // much longer than 15 s, less than original lease
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (0, 0),
            rx: 0,
            tx: 0,
        };
        rig.up();
        assert!(rig.state().clean_stop.is_none());
        assert!(!rig.status().unknown);
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].lease_until, expiry);
        rig.sys.now.set(1090); // no new marker: normal freshness applies
        rig.up();
        assert!(rig.status().unknown);
    }

    #[test]
    fn abandoned_down_intent_resets_until_post_baseline_handshake() {
        let rig = Rig::new();
        *rig.sys.device.borrow_mut() = Some(DeviceId {
            boot: "boot-a".into(),
            ifindex: 7,
        });
        rig.up();
        rig.authenticate();
        let old = rig.state().peers[0].clone();
        rig.before_down_committed(&rig.root);
        assert!(
            rig.status().unknown,
            "intent immediately withholds readiness"
        );
        rig.sys.up.set(false);
        rig.checkpoint();
        assert!(rig.state().down_since.is_some());
        rig.sys.up.set(true); // external raise: deliberately skip before_up
        assert!(rig.status().active_reset);
        rig.sys.now.set(1002);
        rig.sys.sample.borrow_mut().handshake = (1002, 0);
        rig.sys.sample.borrow_mut().rx += 124; // pre-baseline activity cannot recover
        rig.checkpoint();
        let reset = rig.state();
        assert!(reset.down_since.is_none());
        assert!(!reset.down);
        assert!(reset.peers[0].generation > old.generation);
        assert_eq!(reset.peers[0].state, SessionState::RequiredPending);
        assert_eq!(reset.peers[0].lease_until, old.lease_until);
        assert!(rig.status().active_reset);
        assert!(!rig.status().unknown);
        rig.authenticate(); // evidence after the reset baseline
        assert!(!rig.status().active_reset);
        assert!(!rig.status().unknown);
        assert_eq!(rig.state().peers[0].state, SessionState::Recovered);
    }

    #[test]
    fn skipped_before_up_reset_expires_on_original_lease_despite_ordinary_activity() {
        for recorded_down in [false, true] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            let lease = rig.state().peers[0].lease_until.unwrap();
            if recorded_down {
                rig.down();
            } else {
                rig.before_down_committed(&rig.root);
            }
            // A down/up preserves the old handshake and counters. No before_up.
            rig.sys.up.set(true);
            assert!(rig.status().active_reset);
            for now in (1002..lease + 5).step_by(5) {
                rig.sys.now.set(now);
                rig.sys.sample.borrow_mut().rx += 124;
                rig.checkpoint();
                assert_eq!(rig.state().peers[0].lease_until, Some(lease));
                assert_eq!(rig.status().active_reset, now < lease);
                assert!(!rig.state().down);
                assert!(rig.state().down_since.is_none());
            }
            assert!(rig.status().expired_unconfirmed);
            assert!(!rig.status().unknown);
        }
    }

    #[test]
    fn outstanding_down_intent_is_nonready_without_any_leased_peers() {
        let rig = Rig::new();
        rig.up();
        rig.before_down_committed(&rig.root);
        let state = status(&rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &[]).unwrap();
        assert!(state.unknown);
    }

    #[test]
    fn clean_stop_survives_runtime_loss_and_fences_all_writers() {
        let rig = Rig::new();
        let run = rig.root.join("run");
        std::fs::create_dir(&run).unwrap();
        rig.up();
        rig.authenticate();
        invalidate_at(&rig.root, &run, ID, 1001, 1001);
        let checkpoint = || {
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &run,
                ID,
                &rig.guard,
                &[[3; 32]],
            )
            .unwrap();
        };
        // A prior invalidation is fully reconstructed, but its /run token remains.
        for now in (1001..=1191).step_by(5) {
            rig.sys.now.set(now);
            rig.sys.sample.borrow_mut().rx += 32;
            checkpoint();
        }
        let before_seal = rig.state();
        assert_eq!(before_seal.history, History::Available);
        assert_ne!(before_seal.invalidation, "");
        seal_clean_stop(&rig.root, &run, ID, 1191, rig.held.identity(), &rig.guard).unwrap();
        let sealed = std::fs::read(path(&rig.root)).unwrap();
        assert_eq!(rig.state().invalidation, "");
        // Neither same-sequence saves, newer saves nor runtime invalidation may
        // change a seal. Failed telemetry and lifecycle hooks also leave it alone.
        let mut stale = before_seal;
        stale.sequence = rig.state().sequence;
        assert!(save(&rig.root, &stale, &rig.guard).is_err());
        stale.sequence += 1;
        assert!(save(&rig.root, &stale, &rig.guard).is_err());
        assert!(!persist(&rig.root, &run, &stale, &rig.guard));
        let token = invalidation(&run);
        invalidate_at(&rig.root, &run, ID, 1192, 1192);
        // The gap start can predate the seal; the fence uses the writer's now.
        invalidate_at(&rig.root, &run, ID, 1192, 1180);
        assert_eq!(invalidation(&run), token);
        rig.sys.fail_read.set(true);
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &run,
                ID,
                &rig.guard,
                &[[3; 32]]
            )
            .is_err()
        );
        rig.before_down_committed(&run);
        link_down(
            &rig.sys, &rig.held, "wg0", &rig.root, &run, ID, &rig.guard, true,
        )
        .unwrap();
        activate(&rig.root, &run, ID, 1191, &rig.guard).unwrap();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), sealed);
        assert!(!run.join("client-sessions-fallback").exists());
        // A real reboot wipes tmpfs and recreates the kernel device.
        std::fs::remove_dir_all(&run).unwrap();
        std::fs::create_dir(&run).unwrap();
        rig.sys.fail_read.set(false);
        rig.sys.now.set(1251);
        *rig.sys.device.borrow_mut() = Some(DeviceId {
            boot: "new-boot".into(),
            ifindex: 9,
        });
        rig.sys.up.set(false); // freshly recreated device has not been opened
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (0, 0),
            rx: 0,
            tx: 0,
        };
        before_up(
            &rig.sys, &rig.held, "wg0", &rig.root, &run, ID, true, &rig.guard,
        )
        .unwrap();
        rig.sys.up.set(true); // opening consumed the seal before raising wg0
        let sessions = status(&rig.sys, &rig.held, "wg0", &rig.root, &run, ID, &[[3; 32]]).unwrap();
        assert!(!sessions.unknown);
        assert!(!sessions.history_unavailable);
        assert!(sessions.active_reset);
        assert_eq!(rig.state().peers[0].lease_until, stale.peers[0].lease_until);
        assert!(rig.state().clean_stop.is_none());
    }

    #[test]
    fn twenty_second_global_writer_hold_does_not_block_sampler_or_create_gaps() {
        let rig = Rig::new(); // holds the global writer for the entire test
        rig.up();
        let sampler_capability = WriterLock::try_acquire(rig.root.join("sampler")).unwrap();
        for now in (1000..=1020).step_by(5) {
            rig.sys.now.set(now);
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &sampler_capability,
                &[[3; 32]],
            )
            .unwrap();
            assert!(rig.state().gaps.is_empty());
            assert!(!rig.status().unknown);
        }
    }

    #[test]
    fn twenty_second_session_lock_does_not_block_link_up_or_report_ready() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let blocked = session_lock(&rig.root, &rig.root, ID, rig.sys.now.get()).unwrap();
        let root = rig.root.clone();
        let holder = std::thread::spawn(move || {
            let _blocked = blocked;
            let until = Instant::now() + Duration::from_secs(20);
            while Instant::now() < until {
                if root.join("client-session-opening").exists() {
                    assert_eq!(
                        load_current(&root, &root, ID, 1001).history,
                        History::Unavailable
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = Instant::now();
        before_up(
            &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, true, &rig.guard,
        )
        .unwrap();
        assert!(start.elapsed() < Duration::from_millis(5500));
        assert!(rig.status().unknown);
        holder.join().unwrap();
    }

    #[test]
    fn stuck_fsync_cannot_block_before_up_past_five_seconds_or_commit_later() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let original = std::fs::read(path(&rig.root)).unwrap();
        let blocked = std::sync::Arc::new(std::sync::Barrier::new(2));
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_blocked = blocked.clone();
        let worker_entered = entered.clone();
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                // Model a file fsync that has not returned to its pre-rename fence.
                worker_entered.store(true, Ordering::Release);
                worker_blocked.wait();
            }),
        );
        let start = Instant::now();
        before_up(
            &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, true, &rig.guard,
        )
        .unwrap();
        assert!(start.elapsed() < Duration::from_millis(5500));
        assert!(entered.load(Ordering::Acquire));
        assert!(rig.status().unknown);
        blocked.wait();
        let _finished = WriterLock::acquire_timeout(
            rig.root.join("client-session-writer"),
            Duration::from_secs(2),
        )
        .unwrap();
        fsync_hooks().lock().unwrap().remove(&rig.root);
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), original);
        assert!(rig.status().unknown);
    }

    #[test]
    fn outside_lock_telemetry_cannot_recover_an_intervening_reset() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let root = rig.root.clone();
        let mut reset_record = rig.state();
        let namespace = rig.held.identity();
        let baseline = Sample {
            key: [3; 32],
            handshake: (0, 0),
            rx: 0,
            tx: 0,
        };
        reset(
            &mut reset_record,
            namespace,
            Snapshot {
                peers: vec![baseline],
                device: None,
                up: false,
            },
            1001,
            false,
        );
        reset_record.down = false;
        *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
            // Acquiring this lock from inside telemetry proves the child runs
            // outside it. Publish a post-bounce generation during collection.
            let guard = session_lock(&root, &root, ID, 1001).unwrap();
            assert!(persist(&root, &root, &reset_record, &guard));
        }));
        assert!(
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]]
            )
            .is_err()
        );
        assert_eq!(rig.state().peers[0].state, SessionState::RequiredPending);
        assert_eq!(rig.state().peers[0].baseline.handshake, (0, 0));
    }
    #[test]
    fn outside_lock_telemetry_is_discarded_after_invalidation_or_sealing() {
        for seal in [false, true] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            let root = rig.root.clone();
            let namespace = rig.held.identity();
            let before = rig.state().sequence;
            *rig.sys.during_sample.borrow_mut() = Some(Box::new(move || {
                let guard = session_lock(&root, &root, ID, 1001).unwrap();
                if seal {
                    seal_clean_stop(&root, &root, ID, 1001, namespace, &guard).unwrap();
                } else {
                    invalidate_at(&root, &root, ID, 1001, 1001);
                }
            }));
            let sampled = checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]],
            );
            if seal {
                assert!(sampled.is_err());
                assert!(rig.state().clean_stop.is_some());
            } else {
                assert!(sampled.is_err());
                assert!(rig.status().unknown);
            }
            assert_eq!(rig.state().sequence, before + u64::from(seal));
        }
    }
    #[test]
    fn activate_preserves_history_when_incarnation_is_unreadable() {
        let rig = Rig::new();
        let before = std::fs::read(path(&rig.root)).unwrap();
        let incarnation = rig.root.join("gateway-incarnation");
        std::fs::remove_file(&incarnation).unwrap();
        std::fs::create_dir(&incarnation).unwrap();
        assert!(activate(&rig.root, &rig.root, ID, 1000, &rig.guard).is_err());
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        let _ = load_writer(&rig.root, &rig.root, ID, 1000);
        assert!(!rig.root.join("client-sessions.unavailable.json").exists());
        let mut unavailable = Record::unknown(ID, 1000);
        unavailable.sequence = 100;
        assert!(save(&rig.root, &unavailable, &rig.guard).is_err());
        assert!(invalidate_for_reopening(&rig.root, &rig.root, ID, 1000).is_err());
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
    }
    #[test]
    fn inability_to_notify_readers_fails_link_up_closed() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        std::fs::create_dir(rig.root.join("client-session-invalidation")).unwrap();
        let result = bounded_hook(
            &rig.root,
            &rig.root,
            ID,
            1001,
            Instant::now() + Duration::from_millis(20),
            HookMode::Opening,
            |_, _, _, _| Err(io::Error::other("injected write failure")),
        );
        assert!(result.is_err());
        assert!(rig.status().unknown); // retained opening marker withholds readiness
    }

    #[test]
    fn abandoned_opening_barrier_reconstructs_instead_of_latching_unknown_forever() {
        for opening in ["1001:abandoned", "9000:future", "torn"] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            std::fs::write(rig.root.join("client-session-opening"), opening).unwrap();
            assert!(rig.status().unknown);
            for now in (1006..=1186).step_by(5) {
                rig.sys.now.set(now);
                rig.checkpoint();
            }
            assert!(!rig.root.join("client-session-opening").exists());
            assert!(!rig.status().unknown);
        }
    }

    #[test]
    fn final_stop_sample_retries_invalidation_within_original_deadline() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.up.set(false);
        let root = rig.root.clone();
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        fsync_hooks().lock().unwrap().insert(
            root.clone(),
            std::sync::Arc::new(move || {
                if hook_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    invalidate_at(&root, &root, ID, 1001, 1001);
                }
            }),
        );
        let session = session_lock(&rig.root, &rig.root, ID, 1001).unwrap();
        checkpoint_activity_locked(
            &rig.sys,
            &rig.held,
            "wg0",
            &rig.root,
            &rig.root,
            ID,
            &session,
            &[[3; 32]],
        )
        .unwrap();
        fsync_hooks().lock().unwrap().remove(&rig.root);
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "final evidence must be recollected"
        );
        seal_clean_stop(
            &rig.root,
            &rig.root,
            ID,
            1001,
            rig.held.identity(),
            &session,
        )
        .unwrap();
        assert!(rig.state().clean_stop.is_some());
        assert!(rig.status().unknown, "the invalidation gap is retained");
    }

    #[test]
    fn persistently_contended_final_stop_sample_refuses_seal_within_bound() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.up.set(false);
        let root = rig.root.clone();
        fsync_hooks().lock().unwrap().insert(
            root.clone(),
            std::sync::Arc::new(move || {
                invalidate_at(&root, &root, ID, 1001, 1001);
            }),
        );
        let session = session_lock(&rig.root, &rig.root, ID, 1001).unwrap();
        let started = Instant::now();
        let result = checkpoint_final_activity_until(
            &rig.sys,
            &rig.held,
            "wg0",
            &rig.root,
            &rig.root,
            ID,
            &session,
            &[[3; 32]],
            started + EXEC_TIMEOUT + Duration::from_millis(50),
        );
        fsync_hooks().lock().unwrap().remove(&rig.root);
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            seal_clean_stop(
                &rig.root,
                &rig.root,
                ID,
                1001,
                rig.held.identity(),
                &session
            )
            .is_err()
        );
        assert!(rig.state().clean_stop.is_none());
        assert!(rig.status().unknown);
    }

    #[test]
    fn production_fallback_always_has_unavailable_history_and_an_open_gap() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        assert_eq!(rig.status(), ClientSessions::default());
        let record = rig.state();
        let backup = rig.root.join("old-ready.json");
        std::fs::rename(path(&rig.root), &backup).unwrap();
        std::os::unix::fs::symlink(&backup, path(&rig.root)).unwrap();
        assert!(!persist(&rig.root, &rig.root, &record, &rig.guard));
        let fallback = read_record(&rig.root.join("client-sessions-fallback"), ID, 1001).unwrap();
        assert_eq!(fallback.history, History::Unavailable);
        assert!(fallback.gaps.last().is_some_and(|gap| gap.end.is_none()));
        assert!(rig.status().unknown);
        std::fs::remove_file(path(&rig.root)).unwrap();
        assert!(
            rig.status().unknown,
            "removing durable history cannot expose Ready"
        );
    }

    #[test]
    fn clean_stop_clears_obsolete_marker_before_saving_or_aborts_without_a_seal() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let obsolete = rig.root.join("client-session-seal-obsolete");
        let original = std::fs::read(path(&rig.root)).unwrap();
        std::fs::create_dir(&obsolete).unwrap();
        assert!(
            seal_clean_stop(
                &rig.root,
                &rig.root,
                ID,
                1001,
                rig.held.identity(),
                &rig.guard
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), original);
        assert!(rig.state().clean_stop.is_none());
        std::fs::remove_dir(&obsolete).unwrap();
        std::fs::write(&obsolete, b"obsolete\n").unwrap();
        let marker = obsolete.clone();
        fsync_hooks().lock().unwrap().insert(
            rig.root.clone(),
            std::sync::Arc::new(move || {
                assert!(
                    !marker.exists(),
                    "obsolete marker must be cleared before save"
                );
            }),
        );
        seal_clean_stop(
            &rig.root,
            &rig.root,
            ID,
            1001,
            rig.held.identity(),
            &rig.guard,
        )
        .unwrap();
        fsync_hooks().lock().unwrap().remove(&rig.root);
        assert!(rig.state().clean_stop.is_some());
        assert!(!obsolete.exists());
    }

    #[test]
    fn obsolete_live_seal_is_not_consumed_after_link_down_without_a_sample() {
        for fallback_open in [false, true] {
            let rig = Rig::new();
            *rig.sys.device.borrow_mut() = Some(DeviceId {
                boot: "boot-a".into(),
                ifindex: 7,
            });
            rig.up();
            rig.authenticate();
            seal_clean_stop(
                &rig.root,
                &rig.root,
                ID,
                1001,
                rig.held.identity(),
                &rig.guard,
            )
            .unwrap();
            let sealed = std::fs::read(path(&rig.root)).unwrap();
            if fallback_open {
                let lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
                before_up_until(
                    &rig.sys,
                    &rig.held,
                    "wg0",
                    &rig.root,
                    &rig.root,
                    ID,
                    false,
                    &rig.guard,
                    Instant::now() + EXEC_TIMEOUT + Duration::from_millis(40),
                    false,
                )
                .unwrap();
                assert!(rig.root.join("client-session-seal-obsolete").exists());
                drop(lock);
            }
            // No sampler sees this external UP window before the planner lowers wg0.
            rig.sys.up.set(false);
            rig.before_down_committed(&rig.root);
            rig.down();
            rig.sys.now.set(1002);
            rig.up();
            assert_eq!(
                std::fs::read(rig.root.join("client-sessions.unavailable.json")).unwrap(),
                sealed
            );
            assert!(rig.state().clean_stop.is_none());
            assert_eq!(rig.state().history, History::Unavailable);
            assert!(rig.status().unknown);
        }
    }

    #[test]
    fn future_seal_after_fallback_open_is_quarantined_and_readiness_recovers() {
        for same_device in [false, true] {
            let rig = Rig::new();
            let old_device = DeviceId {
                boot: "boot-a".into(),
                ifindex: 7,
            };
            *rig.sys.device.borrow_mut() = Some(old_device.clone());
            rig.up();
            rig.authenticate();
            seal_clean_stop(
                &rig.root,
                &rig.root,
                ID,
                1001,
                rig.held.identity(),
                &rig.guard,
            )
            .unwrap();
            let sealed = std::fs::read(path(&rig.root)).unwrap();
            rig.sys.now.set(999);
            // With no evidence of reopening, a future seal could revive.
            assert!(invalidate_for_reopening(&rig.root, &rig.root, ID, 999).is_err());
            *rig.sys.device.borrow_mut() = Some(if same_device {
                old_device
            } else {
                DeviceId {
                    boot: "boot-b".into(),
                    ifindex: 8,
                }
            });
            rig.sys.up.set(true);
            let lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
            before_up_until(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &rig.root,
                ID,
                false,
                &rig.guard,
                Instant::now() + EXEC_TIMEOUT + Duration::from_millis(40),
                false,
            )
            .unwrap();
            // Opening fallback succeeds on the fresh live-UP proof while disk
            // work cannot take the lock; it has not consumed the raw seal.
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), sealed);
            drop(lock);
            rig.sys.now.set(1002);
            rig.checkpoint();
            assert_eq!(
                std::fs::read(rig.root.join("client-sessions.unavailable.json")).unwrap(),
                sealed
            );
            assert!(rig.status().unknown);
            assert!(rig.state().clean_stop.is_none());
            for now in (1007..=1182).step_by(5) {
                rig.sys.now.set(now);
                rig.sys.sample.borrow_mut().handshake = (now, 1);
                rig.sys.sample.borrow_mut().rx += 124;
                rig.checkpoint();
                assert_eq!(rig.status().unknown, now < 1182);
            }
            assert_eq!(rig.status(), ClientSessions::default());
            assert_eq!(rig.state().peers[0].state, SessionState::Recovered);
        }
    }

    fn damaged_clean_stop_reconstructs(gateway: &str, resume_at: u64) {
        let rig = Rig::new();
        let run = rig.root.join("reboot-run");
        std::fs::create_dir(&run).unwrap();
        rig.up();
        rig.authenticate();
        seal_clean_stop(&rig.root, &run, ID, 1001, rig.held.identity(), &rig.guard).unwrap();
        let sealed = std::fs::read(path(&rig.root)).unwrap();
        std::fs::remove_dir_all(&run).unwrap();
        std::fs::create_dir(&run).unwrap();
        rig.sys.now.set(resume_at);
        assert!(
            status(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &run,
                gateway,
                &[[3; 32]]
            )
            .unwrap()
            .unknown
        );
        // Refuse a future seal that could still become valid; key-mismatched
        // history cannot revive and does not block the timeout fallback.
        assert_eq!(
            invalidate_for_reopening(&rig.root, &run, gateway, resume_at).is_err(),
            gateway == ID
        );
        before_up(
            &rig.sys, &rig.held, "wg0", &rig.root, &run, gateway, true, &rig.guard,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(rig.root.join("client-sessions.unavailable.json")).unwrap(),
            sealed
        );
        assert!(may_serve(&rig.root, gateway, resume_at));
        assert!(sealed_record(&rig.root, gateway, resume_at).is_none());
        // Ordinary activity may establish peer evidence but cannot shorten the gap.
        for now in (resume_at..=resume_at + LEASE).step_by(5) {
            rig.sys.now.set(now);
            if now == resume_at {
                assert!(
                    status(
                        &rig.sys,
                        &rig.held,
                        "wg0",
                        &rig.root,
                        &run,
                        gateway,
                        &[[3; 32]]
                    )
                    .unwrap()
                    .unknown
                );
                assert!(
                    load_current(&rig.root, &run, gateway, now)
                        .peers
                        .iter()
                        .all(|peer| peer.state != SessionState::Recovered)
                );
            }
            rig.sys.sample.borrow_mut().rx += 32;
            checkpoint_recovered(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &run,
                gateway,
                &rig.guard,
                &[[3; 32]],
            )
            .unwrap();
            let sessions = status(
                &rig.sys,
                &rig.held,
                "wg0",
                &rig.root,
                &run,
                gateway,
                &[[3; 32]],
            )
            .unwrap();
            assert_eq!(
                sessions.unknown,
                now < resume_at + LEASE,
                "at {now}: {sessions:?}"
            );
            assert_eq!(sessions.history_unavailable, now < resume_at + LEASE);
            if now == resume_at + LEASE {
                assert!(!sessions.active_reset);
                assert_eq!(cached_reason(&run, now), None);
            }
        }
    }

    #[test]
    fn backward_clock_across_clean_stop_recovers_after_complete_history() {
        damaged_clean_stop_reconstructs(ID, 991);
    }

    #[test]
    fn client_key_change_across_clean_stop_recovers_after_complete_history() {
        damaged_clean_stop_reconstructs("new-gateway-public-identity", 1010);
    }

    #[test]
    fn malformed_seal_bindings_are_damaged_history_for_readers_and_sampler() {
        for damage in [
            "namespace",
            "device",
            "sequence",
            "final-sample",
            "incarnation",
        ] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            let ready = std::fs::read(path(&rig.root)).unwrap();
            seal_clean_stop(
                &rig.root,
                &rig.root,
                ID,
                1001,
                rig.held.identity(),
                &rig.guard,
            )
            .unwrap();
            // A damaged durable seal must dominate a still-readable Ready fallback.
            std::fs::write(rig.root.join("client-sessions-fallback"), ready).unwrap();
            let mut record = rig.state();
            match damage {
                "namespace" => record.clean_stop.as_mut().unwrap().namespace = (0, 0),
                "device" => {
                    record.clean_stop.as_mut().unwrap().device = Some(DeviceId {
                        boot: "other".into(),
                        ifindex: 7,
                    });
                }
                "sequence" => record.clean_stop.as_mut().unwrap().sequence += 1,
                "final-sample" => record.sample_failed_at = Some(1001),
                "incarnation" => record.incarnation = "other".into(),
                _ => unreachable!(),
            }
            std::fs::write(path(&rig.root), serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(!is_sealed(&rig.root, ID, 1001), "{damage}");
            assert!(rig.status().unknown);
            rig.checkpoint();
            assert!(
                rig.root.join("client-sessions.unavailable.json").exists(),
                "{damage}"
            );
            assert!(rig.state().clean_stop.is_none());
            assert!(rig.status().unknown);
        }
    }

    #[test]
    fn sampled_admin_down_up_requires_post_baseline_recovery() {
        let rig = Rig::new();
        *rig.sys.device.borrow_mut() = Some(DeviceId {
            boot: "boot-a".into(),
            ifindex: 7,
        });
        rig.up();
        rig.authenticate();
        let original = rig.state().peers[0].clone();
        rig.sys.up.set(false); // admin DOWN; no lifecycle hooks or planner tick
        rig.checkpoint();
        assert!(rig.state().down_since.is_some());
        assert!(rig.status().unknown);
        assert_eq!(
            cached_reason(&rig.root, 1001),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
        rig.sys.up.set(true); // same device and continuous counters
        assert!(rig.status().active_reset);
        rig.sys.now.set(1002);
        rig.sys.sample.borrow_mut().handshake = (1002, 0);
        rig.sys.sample.borrow_mut().rx += 124;
        rig.checkpoint(); // even this handshake precedes the new baseline
        assert!(rig.status().active_reset);
        assert!(!rig.status().unknown);
        assert!(rig.state().peers[0].generation > original.generation);
        assert_eq!(rig.state().peers[0].lease_until, original.lease_until);
        rig.sys.now.set(1003);
        rig.sys.sample.borrow_mut().rx += 124;
        rig.checkpoint(); // continuous traffic alone cannot confirm the reset
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].lease_until, original.lease_until);
        rig.authenticate();
        assert!(!rig.status().active_reset);
        assert!(!rig.status().unknown);
        assert_eq!(cached_reason(&rig.root, 1004), None);
    }

    #[test]
    fn cached_status_honours_intent_down_and_clean_stop_immediately() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        assert_eq!(cached_reason(&rig.root, 1001), None);
        rig.before_down_committed(&rig.root);
        assert_eq!(
            cached_reason(&rig.root, 1001),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
        rig.down();
        // Pin the independent `down` case without an outstanding intent.
        let mut record = rig.state();
        record.down_since = None;
        publish_readiness(&rig.root, &record, true);
        assert_eq!(
            cached_reason(&rig.root, 1001),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
        rig.up();
        rig.authenticate();
        assert_eq!(cached_reason(&rig.root, 1002), None);
        seal_clean_stop(
            &rig.root,
            &rig.root,
            ID,
            1002,
            rig.held.identity(),
            &rig.guard,
        )
        .unwrap();
        assert_eq!(
            cached_reason(&rig.root, 1002),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
    }

    #[test]
    fn failed_durable_and_fallback_writes_never_expose_old_ready_record() {
        for reopening in [false, true] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            let old = std::fs::read(path(&rig.root)).unwrap();
            // Reads still see the old Ready record; durable_replace refuses symlinks.
            let backup = rig.root.join("old-ready.json");
            std::fs::rename(path(&rig.root), &backup).unwrap();
            std::os::unix::fs::symlink(&backup, path(&rig.root)).unwrap();
            std::os::unix::fs::symlink(&backup, rig.root.join("client-sessions-fallback")).unwrap();
            assert!(!rig.status().unknown, "both old Ready copies are readable");
            if reopening {
                rig.up(); // notification permits UP only with non-ready readers
            } else {
                let completion = rig.watch_containment(None);
                let _ = before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard);
                assert!(rig.wait_for_containment(&completion).is_err());
            }
            assert_eq!(std::fs::read(path(&rig.root)).unwrap(), old);
            assert!(rig.status().unknown);
            assert_eq!(
                cached_reason(&rig.root, 1001),
                Some(scupper_proto::SessionReason::ClientSessionsUnknown)
            );
        }
    }

    #[test]
    fn failed_writes_and_notification_retire_readable_ready_history() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let old = std::fs::read(path(&rig.root)).unwrap();
        let backup = rig.root.join("old-ready.json");
        std::fs::rename(path(&rig.root), &backup).unwrap();
        for file in [path(&rig.root), rig.root.join("client-sessions-fallback")] {
            std::os::unix::fs::symlink(&backup, file).unwrap();
        }
        // Neither write can notify check: a dangling barrier remains invisible
        // to exists(), and token writes fail too. Both old records still read.
        let absent = rig.root.join("absent/notification");
        for file in ["client-session-commit", "client-session-invalidation"] {
            std::os::unix::fs::symlink(&absent, rig.root.join(file)).unwrap();
        }
        assert!(!rig.status().unknown);
        let completion = rig.watch_containment(None);
        assert!(before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).is_err());
        assert!(rig.wait_for_containment(&completion).is_err());
        assert!(!path(&rig.root).exists());
        assert!(!rig.root.join("client-sessions-fallback").exists());
        assert_eq!(
            std::fs::read(rig.root.join("client-sessions.unavailable.json")).unwrap(),
            old
        );
        assert_eq!(
            std::fs::read(rig.root.join("client-sessions-fallback.unavailable.json")).unwrap(),
            old
        );
        assert!(rig.status().unknown);
        assert_eq!(
            cached_reason(&rig.root, 1001),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
    }

    #[test]
    fn sampler_between_down_intent_and_link_down_never_restamps_lease() {
        let rig = Rig::new();
        *rig.sys.device.borrow_mut() = Some(DeviceId {
            boot: "boot-a".into(),
            ifindex: 7,
        });
        rig.up();
        rig.authenticate();
        let original = rig.state().peers[0].clone();
        rig.before_down_committed(&rig.root);
        rig.sys.now.set(1002);
        rig.sys.sample.borrow_mut().rx += 124;
        rig.checkpoint(); // still UP, between hook and command: abandoned reset
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].lease_until, original.lease_until);
        rig.sys.up.set(false);
        rig.sys.now.set(1003);
        rig.sys.sample.borrow_mut().rx += 124;
        rig.down();
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].lease_until, original.lease_until);
        rig.checkpoint();
        rig.up();
        rig.sys.up.set(true);
        assert!(rig.status().active_reset);
        assert_eq!(rig.state().peers[0].lease_until, original.lease_until);
        rig.authenticate();
        assert!(!rig.status().active_reset);
        assert!(!rig.status().unknown);
    }

    #[test]
    fn invalidation_during_history_load_cannot_be_adopted_by_an_old_sample() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let original = std::fs::read(path(&rig.root)).unwrap();
        let token = invalidation(&rig.root);
        let sampled = samples(&rig.sys, &rig.held, "wg0");
        invalidate_at(&rig.root, &rig.root, ID, 1001, 1001);
        let _session = session_lock(&rig.root, &rig.root, ID, rig.sys.now.get()).unwrap();
        assert!(
            merge_activity(
                rig.held.identity(),
                &rig.root,
                &rig.root,
                ID,
                &rig.guard,
                &[[3; 32]],
                sampled,
                1001,
                Instant::now() + SAMPLE_INTERVAL,
                Some(&token)
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), original);
    }

    #[test]
    fn superseded_sequence_cannot_replace_newer_committed_evidence() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let old = rig.state();
        rig.sys.now.set(1002);
        rig.checkpoint();
        let newer = std::fs::read(path(&rig.root)).unwrap();
        assert!(save(&rig.root, &old, &rig.guard).is_err());
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), newer);
    }

    #[test]
    fn empty_history_still_reads_required_telemetry() {
        let rig = Rig::new();
        rig.sys.fail_read.set(true);
        assert!(rig.status().telemetry_unavailable);
        rig.sys.fail_read.set(false);
        rig.sys.missing.set(true);
        assert!(rig.status().peer_missing);
    }
    #[test]
    fn first_sample_after_empty_accounts_for_already_active_client_and_cached_reason() {
        let rig = Rig::new();
        *rig.sys.sample.borrow_mut() = Sample {
            key: [3; 32],
            handshake: (1000, 1),
            rx: 124,
            tx: 148,
        };
        rig.checkpoint();
        assert_eq!(rig.state().peers[0].lease_until, Some(1180));
        assert_eq!(cached_reason(&rig.root, 1000), None);
        rig.sys.now.set(1005);
        rig.sys.sample.borrow_mut().rx += 32; // accepted encrypted keepalive
        rig.checkpoint();
        assert_eq!(rig.state().peers[0].lease_until, Some(1185));
        assert_eq!(
            cached_reason(&rig.root, 1021),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
    }
    #[test]
    fn missed_sampler_slot_is_a_gap_even_inside_freshness_slack() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let sequence = rig.state().sequence;
        let lease = rig.state().peers[0].lease_until;
        invalidate_at(&rig.root, &rig.root, ID, 1006, 1006); // five-second slot after observation at 1001
        rig.sys.now.set(1008);
        assert!(rig.status().unknown);
        rig.checkpoint();
        assert!(rig.state().sequence > sequence);
        assert_eq!(rig.state().peers[0].lease_until, lease);
        assert_eq!(rig.state().gaps[0].start, 1006);
        assert_eq!(rig.state().gaps[0].end, Some(1008));
        assert!(rig.status().unknown);
    }
    #[test]
    fn renamed_sample_is_unavailable_until_directory_sync_and_commit_checks_complete() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let mut record = rig.state();
        record.written_at += 1;
        record.complete_sample(record.written_at);
        rig.sys.now.set(record.written_at);
        let checks = std::cell::Cell::new(0);
        assert!(persist_checked(
            &rig.root,
            &rig.root,
            &record,
            &rig.guard,
            &|| {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    assert!(rig.status().unknown, "renamed sample is not committed yet");
                }
                Ok(())
            }
        ));
        assert_eq!(checks.get(), 2);
        assert!(!rig.status().unknown);
    }

    #[test]
    fn late_or_invalidated_sample_commit_never_publishes_fresh_evidence() {
        for fail_at in [1, 2] {
            let rig = Rig::new();
            rig.up();
            rig.authenticate();
            let old = rig.state();
            let mut record = old.clone();
            record.written_at += 5;
            record.complete_sample(record.written_at);
            rig.sys.now.set(record.written_at);
            let checks = std::cell::Cell::new(0);
            assert!(!persist_checked(
                &rig.root,
                &rig.root,
                &record,
                &rig.guard,
                &|| {
                    checks.set(checks.get() + 1);
                    if checks.get() == fail_at {
                        if fail_at == 1 {
                            return sample_commit_check(
                                &rig.root,
                                &rig.root,
                                &record,
                                Instant::now(),
                            );
                        }
                        invalidate_at(
                            &rig.root,
                            &rig.root,
                            ID,
                            record.written_at,
                            record.written_at,
                        );
                        return sample_commit_check(
                            &rig.root,
                            &rig.root,
                            &record,
                            Instant::now() + SAMPLE_INTERVAL,
                        );
                    }
                    Ok(())
                }
            ));
            assert!(rig.status().unknown);
            assert!(rig.status().history_unavailable);
            assert!(
                load_current(&rig.root, &rig.root, ID, record.written_at)
                    .renewed_at
                    .is_none()
            );
            assert_eq!(
                cached_reason(&rig.root, record.written_at),
                Some(scupper_proto::SessionReason::ClientSessionsUnknown)
            );
            if fail_at == 1 {
                assert_eq!(rig.state().renewed_at, old.renewed_at);
            }
        }
    }

    #[test]
    fn normal_restart_does_not_wait_for_a_blocked_sampler_commit() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let _blocked_commit = session_lock(&rig.root, &rig.root, ID, rig.sys.now.get()).unwrap();
        let before = std::fs::read(path(&rig.root)).unwrap();
        activate(&rig.root, &rig.root, ID, 1001, &rig.guard).unwrap();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), before);
        assert!(!rig.status().unknown);
    }
}
