//! Per-peer session reset generations and constrained gateway recovery probes.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    // A fresh live-UP observation quarantines an unconsumed seal before writers
    // evaluate this predicate; a destroyed client device cannot still be UP.
    // Readers, lifecycle hooks and writer fences share this exact validation.
    sealed_record(root, gateway, now).is_some()
}
fn load_current(root: &Path, run: &Path, gateway: &str, now: u64) -> Record {
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
    let token = invalidation(run);
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
            durable_replace(&RealFs, &fallback, &bytes, 0o600, &|_| Ok(()), &|_| Ok(())).is_ok()
        });
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
    // A rejected durable record dominates any older runtime fallback. Revoke
    // that fallback first, while readers can still see the damaged record, so
    // its rename cannot expose pre-seal Ready evidence during reconstruction.
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
    if sampled
        .as_ref()
        .is_ok_and(|sample| sample.up && sample.device.is_some())
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
    guard: &WriterGuard,
) -> io::Result<()> {
    // Daemonless sites have no sampler to quarantine damage later. Retire it
    // here, before the bounded opening hook and its timeout fallback.
    match read_record(&path(root), gateway, now) {
        Ok(record) if !record.never_served => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let _session = crate::lock::WriterLock::acquire_timeout(
        run.join("client-session-writer"),
        SAMPLE_INTERVAL,
    )?;
    match read_record(&path(root), gateway, now) {
        Ok(mut record) if record.never_served => {
            record.never_served = false;
            record.history = History::Unavailable;
            record.open_gap(now);
            record.unknown_until = Some(now.saturating_add(LEASE));
            record.written_at = now;
            record.sequence += 1;
            save(root, &record, guard)?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            quarantine_history(root, run)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HookMode {
    Opening,
    OpeningLive,
    Containment,
    Tracking,
    Probe,
}

// Storage workers own their lock until all I/O exits. A timed-out caller never
// joins one; every rename and commit is fenced by the original hook deadline.
#[allow(clippy::too_many_arguments)]
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
    let deadline = if mode == HookMode::Containment {
        deadline.min(Instant::now() + Duration::from_millis(150))
    } else {
        deadline
    };
    // Reserve a small part of the original deadline for reader notification.
    // Even notification reads/writes happen off the caller, so a stalled file
    // operation can never extend the hook's total bound.
    let remaining = deadline.saturating_duration_since(Instant::now());
    // Containment's runtime-only token needs no fsync. Reserve a small slice
    // for it rather than halving the already short durable-work allowance.
    let notify_budget = Duration::from_millis(if mode == HookMode::Containment {
        25
    } else {
        500
    })
    .min(remaining / 2);
    let work_deadline = deadline.checked_sub(notify_budget).unwrap_or(deadline);
    let worker_root = root.to_owned();
    let worker_run = run.to_owned();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scupper-session-hook".into())
        .spawn(move || {
            let result = (|| {
                hook_deadline(work_deadline)?;
                if reopening {
                    std::fs::write(
                        worker_run.join("client-session-opening"),
                        format!("{now}:{}", new_incarnation()?),
                    )?;
                }
                let guard = crate::lock::WriterLock::acquire_timeout(
                    worker_run.join("client-session-writer"),
                    if mode == HookMode::Containment {
                        // Containment must never queue behind a sampler or an
                        // abandoned storage writer, even for a single poll.
                        Duration::ZERO
                    } else {
                        work_deadline.saturating_duration_since(Instant::now())
                    },
                )?;
                hook_deadline(work_deadline)?;
                action(&worker_root, &worker_run, &guard, work_deadline)?;
                hook_deadline(work_deadline)?;
                if reopening {
                    std::fs::remove_file(worker_run.join("client-session-opening"))?;
                }
                Ok(())
            })();
            let _ = send.send(result);
        })?;
    let error = match receive.recv_timeout(work_deadline.saturating_duration_since(Instant::now()))
    {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(error)) => error,
        Err(_) => io::Error::new(io::ErrorKind::TimedOut, "client lifecycle hook deadline"),
    };
    if mode == HookMode::Probe {
        // Surface timeout to the caller: an abandoned worker may have consumed
        // the pending bit just before its deadline. This must be counted/logged
        // as a missed probe, never silently reported as success.
        count_missed_probe();
        return Err(error);
    }
    let notification_deadline = if mode == HookMode::Containment {
        deadline.min(Instant::now() + Duration::from_millis(100))
    } else {
        deadline
    };
    let notification_gateway = gateway.to_owned();
    let notification_root = root.to_owned();
    let notification_run = run.to_owned();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scupper-session-invalidate".into())
        .spawn(move || {
            let result = if matches!(mode, HookMode::Containment | HookMode::OpeningLive) {
                // Containment never reads durable history on its failure path.
                // For OpeningLive, fresh UP proves the seal obsolete; the
                // sampler quarantines it before evaluating any writer fence.
                invalidate_runtime(&notification_run, now)
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
        .recv_timeout(notification_deadline.saturating_duration_since(Instant::now()))
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
    let token = format!("{now}:{}", new_incarnation()?);
    let file = run.join("client-session-invalidation");
    std::fs::write(&file, &token)?;
    if std::fs::read_to_string(file)? != token {
        return Err(io::Error::other("readiness invalidation was superseded"));
    }
    Ok(())
}
fn samples(sys: &dyn System, held: &NetnsHandle, iface: &str) -> io::Result<Snapshot> {
    match sys.client_session_io(
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
/// Save reset intent before containment, without waiting for telemetry.
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
    let hook_gateway = gateway.to_owned();
    let gateway = gateway.to_owned();
    bounded_hook(
        root,
        run,
        &hook_gateway,
        now,
        deadline,
        HookMode::Containment,
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
            record.down_since.get_or_insert(now);
            record.written_at = now;
            if !persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            }) {
                return Err(io::Error::other("lifecycle persistence failed"));
            }
            Ok(())
        },
    )
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
/// Read-only readiness, with explicit unknown and expired-unconfirmed warnings.
/// # Errors
/// Returns current netlink observation failures.
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
    let mut record = load_current(root, run, gateway, now);
    let (current, device, telemetry_failed): (BTreeMap<_, _>, Option<DeviceId>, bool) =
        match samples(sys, held, iface) {
            Ok(current) => {
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
    let continuous = |p: &Reset| {
        current.get(&p.baseline.key).is_some_and(|s| {
            s.handshake >= p.observed.handshake && s.rx >= p.observed.rx && s.tx >= p.observed.tx
        })
    };
    let same = record.namespace == held.identity()
        && record.device == device
        && !record.down
        && record.down_since.is_none();
    let confirmed = |p: &Reset| {
        same && !record.baseline_pending
            && current
                .get(&p.baseline.key)
                .is_some_and(|s| recovered(p, s))
    };
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
        if confirmed(peer)
            || same
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

/// Explicit diagnostic snapshot for embedders/tests; no production shutdown caller.
/// System shutdown uses the quiesced final sample in `boot::clean_stop`.
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
    checkpoint_activity(sys, held, iface, root, run, gateway, guard, keys)
}

#[allow(clippy::too_many_arguments)] // Shared periodic and forced snapshot implementation.
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
    let mut record = load_writer(root, run, gateway, now);
    // Invalidation can race even after the initial under-lock fence check.
    // Never adopt a newer token and merge telemetry collected before it.
    if observed_token
        .is_some_and(|token| token != record.invalidation || token != invalidation(run))
    {
        return Err(io::Error::other(
            "client telemetry invalidated while loading history",
        ));
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
            persist_checked(root, run, &record, guard, &|| {
                sample_commit_check(root, run, &record, deadline)
            });
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
    if !persist_checked(root, run, &record, guard, &|| {
        sample_commit_check(root, run, &record, deadline)
    }) {
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
    Ok(())
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
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_ready = ready.clone();
    let hook_gateway = identity.clone();
    bounded_hook(
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
                worker_ready.store(true, std::sync::atomic::Ordering::Release);
            }
            Ok(())
        },
    )?;
    if Instant::now() >= persistence_deadline {
        count_missed_probe();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "client probe persistence deadline",
        ));
    }
    if !ready.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let destinations = site
        .devices()
        .values()
        .filter(|d| d.gateways().contains(gateway))
        .map(|d| d.address4().addr())
        .collect::<Vec<_>>();
    let response = sys.client_session_io(
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
pub fn execute(sys: &dyn System, held: &NetnsHandle, request: &Request) -> io::Result<Response> {
    held.verify(request.namespace)
        .map_err(|_| io::Error::other("client namespace changed"))?;
    let mut command = std::process::Command::new(sys.canon_executable());
    command
        .arg("client-sessions")
        .arg(serde_json::to_string(request).map_err(io::Error::other)?);
    let output = crate::system::execute_file_command(command, held.try_clone_file()?, EXEC_TIMEOUT)
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
        device: RefCell<Option<DeviceId>>,
        up: Cell<bool>,
        sends: Cell<usize>,
        during_sample: RefCell<Option<Box<dyn FnOnce()>>>,
    }
    impl System for Fake {
        fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
            panic!("no commands expected")
        }
        fn now_unix_secs(&self) -> u64 {
            self.now.get()
        }
        fn client_session_io(&self, _: &NetnsHandle, r: &Request) -> io::Result<Response> {
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
                if let Some(action) = self.during_sample.borrow_mut().take() {
                    action();
                }
                let peers = if self.missing.get() {
                    vec![]
                } else {
                    vec![self.sample.borrow().clone()]
                };
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
                    device: RefCell::new(None),
                    up: Cell::new(true),
                    sends: Cell::new(0),
                    during_sample: RefCell::new(None),
                },
            }
        }
        fn up(&self) {
            before_up(
                &self.sys,
                &self.held,
                "wg0",
                &self.root,
                &self.root,
                ID,
                true,
                &self.guard,
            )
            .unwrap();
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
            let _worker = WriterLock::acquire_timeout(
                self.root.join("client-session-writer"),
                Duration::from_secs(2),
            )
            .unwrap();
            std::fs::remove_dir_all(&self.root).unwrap();
        }
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
        let _lock = WriterLock::try_acquire(rig.root.join("client-session-writer")).unwrap();
        let started = Instant::now();
        assert!(before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).is_err());
        assert!(started.elapsed() < Duration::from_millis(200));
        assert_ne!(invalidation(&rig.root), "");
        assert!(rig.status().unknown);
        assert_eq!(
            cached_reason(&rig.root, 1001),
            Some(scupper_proto::SessionReason::ClientSessionsUnknown)
        );
    }

    #[test]
    fn containment_disk_stall_is_bounded_and_invalidates_before_link_down() {
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
        assert!(before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).is_err());
        assert!(started.elapsed() < Duration::from_millis(300));
        entry.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(rig.status().unknown);
        assert_ne!(invalidation(&rig.root), "");
        fsync_hooks().lock().unwrap().remove(&rig.root);
        release.send(()).unwrap();
        // Wait for the abandoned storage worker before deleting its fixture.
        let _worker = WriterLock::acquire_timeout(
            rig.root.join("client-session-writer"),
            Duration::from_secs(1),
        )
        .unwrap();
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
    fn probe_timeout_after_pending_bit_commit_counts_the_missed_probe() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let count = MISSED_PROBES.load(Ordering::Relaxed);
        let (release, released) = std::sync::mpsc::channel();
        let result = bounded_hook(
            &rig.root,
            &rig.root,
            ID,
            1001,
            Instant::now() + Duration::from_millis(200),
            HookMode::Probe,
            move |root, run, guard, deadline| {
                let mut record = load_writer(root, run, ID, 1001);
                record.probe_pending = false;
                assert!(persist_checked(root, run, &record, guard, &|| {
                    sample_commit_check(root, run, &record, deadline)
                }));
                // The commit won the race but its result has not reached the
                // caller before timeout, so no datagram will be sent.
                released.recv().unwrap();
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(!rig.state().probe_pending);
        assert_eq!(rig.sys.sends.get(), 0);
        assert!(MISSED_PROBES.load(Ordering::Relaxed) > count);
        release.send(()).unwrap();
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
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
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
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1016);
        assert!(!rig.status().unknown, "15 seconds is within cadence slack");
        for now in [1017, 1300, 5000] {
            rig.sys.now.set(now);
            assert!(rig.status().unknown);
            rig.up();
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
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
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
                before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
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
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
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
        before_down(&rig.sys, &rig.root, &run, ID, &rig.guard).unwrap();
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
    fn quarantine_never_exposes_older_ready_runtime_fallback() {
        for damage in ["live-seal", "future-seal", "corrupt"] {
            let rig = Rig::new();
            *rig.sys.device.borrow_mut() = Some(DeviceId {
                boot: "boot-a".into(),
                ifindex: 7,
            });
            rig.up();
            rig.authenticate();
            assert_eq!(rig.status(), ClientSessions::default());
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
            let fallback = rig.root.join("client-sessions-fallback");
            std::fs::write(&fallback, ready).unwrap();
            match damage {
                "future-seal" => rig.sys.now.set(999),
                "corrupt" => std::fs::write(path(&rig.root), b"broken history").unwrap(),
                "live-seal" => {}
                _ => unreachable!(),
            }
            if damage != "corrupt" {
                assert!(rig.status().unknown);
            }
            if damage != "live-seal" {
                // Daemonless retirement must also revoke an older fallback
                // before its missing durable file permits the opening fallback.
                retire_empty(&rig.root, &rig.root, ID, rig.sys.now.get(), &rig.guard).unwrap();
                assert!(rig.status().unknown);
                assert!(!fallback.exists());
            }
            rig.sys.now.set(1002);
            rig.checkpoint();
            assert!(!fallback.exists());
            assert!(rig.root.join("client-sessions.unavailable.json").exists());
            assert!(rig.state().clean_stop.is_none());
            assert!(rig.status().unknown, "{damage}");
            assert_eq!(rig.state().peers[0].state, SessionState::Unknown);
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
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
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
                assert!(before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).is_err());
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
        assert!(before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).is_err());
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
        before_down(&rig.sys, &rig.root, &rig.root, ID, &rig.guard).unwrap();
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
