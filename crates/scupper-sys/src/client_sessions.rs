//! Per-peer session reset generations and constrained gateway recovery probes.
mod netlink;
use crate::{
    fs::{RealFs, durable_replace},
    lock::WriterGuard,
    netns::{NetnsHandle, NetnsId},
    system::{EXEC_TIMEOUT, System},
};
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
    time::Duration,
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
/// Child output contains public observations only.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Full-resolution peer telemetry.
    Samples(Vec<Sample>),
    /// Per-destination send success, in request order.
    Probes(Vec<bool>),
}
const VERSION: u32 = 1;
const LEASE: u64 = 180;
const SNAPSHOT_INTERVAL: u64 = 30;
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    gateway: String,
    written_at: u64,
    namespace: NetnsId,
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
            written_at: now,
            namespace: (0, 0),
            down: false,
            down_since: None,
            unknown_until: Some(now.saturating_add(LEASE)),
            probe_pending: false,
            baseline_pending: false,
            peers: Vec::new(),
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
        && record.written_at <= now
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
fn load(root: &Path, gateway: &str, now: u64) -> Record {
    // Bound allocation before parsing; never print state contents.
    let read = || -> io::Result<Record> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path(root))?
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(io::Error::other("oversize history"));
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if !valid(&record, gateway, now) {
            return Err(io::Error::other("unavailable history"));
        }
        Ok(record)
    };
    read().unwrap_or_else(|_| Record::unknown(gateway, now))
}
fn load_current(root: &Path, run: &Path, gateway: &str, now: u64) -> Record {
    let fallback = run.join("client-sessions-fallback");
    if fallback.exists() {
        let read = || -> io::Result<Record> {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(fallback)?
                .take(MAX_RECORD_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_RECORD_BYTES {
                return Err(io::Error::other("oversize fallback"));
            }
            let record: Record = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if !valid(&record, gateway, now) {
                return Err(io::Error::other("invalid fallback"));
            }
            Ok(record)
        };
        return read().unwrap_or_else(|_| Record::unknown(gateway, now));
    }
    load(root, gateway, now)
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
    let record = load_current(root, run, gateway, now);
    if record.namespace == (0, 0) {
        // Keep one bounded diagnostic artifact, under the same private directory.
        if path(root).exists() {
            let _ = std::fs::rename(path(root), root.join("client-sessions.unavailable.json"));
        }
        history_alert(run);
        eprintln!("client session history unavailable; using one bounded unknown lease");
    }
    record
}
fn save(root: &Path, record: &Record, _guard: &WriterGuard) -> io::Result<()> {
    durable_replace(
        &RealFs,
        &path(root),
        &serde_json::to_vec(record).map_err(io::Error::other)?,
        0o600,
        &|_| Ok(()),
        &|_| Ok(()),
    )
}
fn persist(root: &Path, run: &Path, record: &Record, guard: &WriterGuard) {
    let fallback = run.join("client-sessions-fallback");
    if save(root, record, guard).is_ok() {
        let _ = std::fs::remove_file(fallback);
    } else {
        history_alert(run);
        eprintln!("client session history write failed; readiness history unavailable");
        // /run is a best-effort communication channel to read-only check when
        // durable storage is unavailable. It never substitutes for reboot history.
        let mut unavailable = Record::unknown(&record.gateway, record.written_at);
        unavailable.namespace = record.namespace;
        unavailable.unknown_until = record.unknown_until.or(unavailable.unknown_until);
        unavailable.peers.clone_from(&record.peers);
        unavailable.baseline_pending = record.baseline_pending;
        unavailable.down = record.down;
        unavailable.down_since = record.down_since;
        if let Ok(bytes) = serde_json::to_vec(&unavailable) {
            let _ = durable_replace(&RealFs, &fallback, &bytes, 0o600, &|_| Ok(()), &|_| Ok(()));
        }
    }
}
fn samples(sys: &dyn System, held: &NetnsHandle, iface: &str) -> io::Result<Vec<Sample>> {
    match sys.client_session_io(
        held,
        &Request {
            namespace: held.identity(),
            iface: iface.into(),
            probe: None,
        },
    )? {
        Response::Samples(samples) => Ok(samples),
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
fn reset(record: &mut Record, namespace: NetnsId, current: Vec<Sample>, now: u64) {
    let same_down = record.down && record.namespace == namespace;
    let old: BTreeMap<_, _> = record.peers.iter().map(|p| (p.baseline.key, p)).collect();
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
            peer.baseline = sample.clone();
            peer.observed = sample;
            expire(&mut peer, now);
            peer
        })
        .collect();
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
    guard: &WriterGuard,
) -> io::Result<()> {
    let now = sys.now_unix_secs();
    let mut record = load_writer(root, run, gateway, now);
    record.down_since.get_or_insert(now);
    record.written_at = now;
    persist(root, run, &record, guard);
    Ok(())
}
/// Capture preserved counters after `LinkDown`, including a command timeout.
/// # Errors
/// Telemetry failure is reported after saving the original reset time.
pub fn link_down(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
) -> io::Result<()> {
    let now = sys.now_unix_secs();
    let mut record = load_writer(root, run, gateway, now);
    if record.down_since.is_none() {
        record.down_since = Some(now);
    }
    record.written_at = now;
    persist(root, run, &record, guard);
    reset(
        &mut record,
        held.identity(),
        samples(sys, held, iface)?,
        now,
    );
    persist(root, run, &record, guard);
    Ok(())
}
/// Establish a new generation without restoring endpoints. Availability history
/// failures never prevent boot or reopening the independently protected path.
/// # Errors
/// Reserved for interface observation errors; history failures are logged.
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
    let now = sys.now_unix_secs();
    let mut record = load_writer(root, run, gateway, now);
    if was_down || record.namespace != held.identity() {
        if let Ok(current) = samples(sys, held, iface) {
            reset(&mut record, held.identity(), current, now);
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
            eprintln!("client session baseline unavailable; awaiting client retry");
        }
    }
    record.down_since = None;
    record.namespace = held.identity();
    record.down = false;
    record.probe_pending = true;
    record.written_at = now;
    persist(root, run, &record, guard);
    Ok(())
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
    let record = load_current(root, run, gateway, now);
    let current: BTreeMap<_, _> = if record.peers.is_empty() {
        BTreeMap::new()
    } else {
        let Ok(samples) = samples(sys, held, iface) else {
            // Availability telemetry must never become a forwarding-stage error
            // that prevents later route/exit-IP/supervisor safety observations.
            // Anchor uncertainty to the last checkpoint, never this read/retry.
            let deadline = record
                .unknown_until
                .unwrap_or_else(|| record.written_at.saturating_add(LEASE));
            return Ok(ClientSessions {
                unknown: !keys.is_empty() && now < deadline,
                history_unavailable: true,
                active_reset: record.peers.iter().any(|p| {
                    keys.contains(&p.baseline.key) && p.lease_until.is_some_and(|t| now < t)
                }),
                idle_reset: !keys.is_empty(),
                expired_unconfirmed: record.peers.iter().any(|p| {
                    keys.contains(&p.baseline.key) && p.lease_until.is_some_and(|t| now >= t)
                }),
            });
        };
        samples.into_iter().map(|s| (s.key, s)).collect()
    };
    let continuous = |p: &Reset| {
        current.get(&p.baseline.key).is_some_and(|s| {
            s.handshake >= p.observed.handshake && s.rx >= p.observed.rx && s.tx >= p.observed.tx
        })
    };
    let same = record.namespace == held.identity() && !record.down && record.down_since.is_none();
    let confirmed = |p: &Reset| {
        same && !record.baseline_pending
            && current
                .get(&p.baseline.key)
                .is_some_and(|s| recovered(p, s))
    };
    let all_ready = keys.iter().all(|key| {
        record.peers.iter().any(|p| {
            p.baseline.key == *key
                && (p.state == SessionState::Recovered
                    && same
                    && !record.baseline_pending
                    && continuous(p)
                    || confirmed(p))
        })
    });
    let mut status = ClientSessions {
        history_unavailable: run.join("client-sessions-fallback").exists(),
        ..ClientSessions::default()
    };
    if !keys.is_empty() && !all_ready && record.unknown_until.is_some() {
        status.unknown = record.unknown_until.is_some_and(|t| now < t);
        status.history_unavailable |= !status.unknown;
    }
    for peer in record
        .peers
        .iter()
        .filter(|p| keys.contains(&p.baseline.key))
    {
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
/// Update current authenticated activity continuously, at a bounded disk cadence.
/// # Errors
/// Returns current telemetry failures; persistence failures remain availability warnings.
pub fn checkpoint_recovered(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
) -> io::Result<()> {
    checkpoint_activity(sys, held, iface, root, run, gateway, guard, false)
}

/// Best-effort activity snapshot before planned daemon shutdown; no probe or gate changes.
/// # Errors
/// Returns current telemetry failure. Storage failures are exposed through runtime history.
pub fn before_shutdown(
    sys: &dyn System,
    held: &NetnsHandle,
    iface: &str,
    root: &Path,
    run: &Path,
    gateway: &str,
    guard: &WriterGuard,
) -> io::Result<()> {
    checkpoint_activity(sys, held, iface, root, run, gateway, guard, true)
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
    force: bool,
) -> io::Result<()> {
    let now = sys.now_unix_secs();
    let mut record = load_writer(root, run, gateway, now);
    let current = samples(sys, held, iface)?;
    if record.namespace == (0, 0) || record.baseline_pending {
        record.down = true;
        reset(&mut record, held.identity(), current, now);
        record.down = false;
        persist(root, run, &record, guard);
        return Ok(());
    }
    if record.namespace != held.identity() || record.down {
        return Ok(());
    }
    let mut transition = false;
    for peer in &mut record.peers {
        if let Some(sample) = current.iter().find(|s| s.key == peer.baseline.key) {
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
                transition = true;
                continue;
            }
            let ready = recovered(peer, sample);
            if ready && peer.state != SessionState::Recovered {
                peer.state = SessionState::Recovered;
                transition = true;
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
        let before = peer.state;
        expire(peer, now);
        transition |= before != peer.state;
    }
    if force || transition || now.saturating_sub(record.written_at) >= SNAPSHOT_INTERVAL {
        record.written_at = now;
        persist(root, run, &record, guard);
    }
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
    guard: &WriterGuard,
) -> io::Result<()> {
    let gw = site
        .gateway(gateway)
        .ok_or_else(|| io::Error::other("unknown gateway"))?;
    let mut record = load(
        root,
        gw.client_tunnel().identity().public_key.as_str(),
        sys.now_unix_secs(),
    );
    if !record.probe_pending || record.namespace != held.identity() {
        return Ok(());
    }
    let destinations = site
        .devices()
        .values()
        .filter(|d| d.gateways().contains(gateway))
        .map(|d| d.address4().addr())
        .collect::<Vec<_>>();
    record.probe_pending = false;
    // A failed persistence attempt must not trigger output repeatedly.
    if save(root, &record, guard).is_err() {
        return Ok(());
    }
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
        netlink::read(&request.iface).map(Response::Samples)
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
        sends: Cell<usize>,
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
            Ok(match &r.probe {
                Some((source, hosts)) => {
                    assert_eq!(r.iface, "wg0");
                    assert_eq!(*source, Ipv4Addr::new(10, 99, 0, 1));
                    assert!(hosts.iter().all(|h| *h == Ipv4Addr::new(10, 99, 0, 2)));
                    self.sends.set(self.sends.get() + hosts.len());
                    if self.fail_probe.get() {
                        return Err(io::Error::other("probe failed"));
                    }
                    Response::Probes(vec![true; hosts.len()])
                }
                None => Response::Samples(vec![self.sample.borrow().clone()]),
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
                    sends: Cell::new(0),
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
        assert!(rig.status().unknown);
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
            assert!(rig.root.join("client-sessions.unavailable.json").exists());
            let expiry = rig.state().unknown_until.unwrap();
            rig.sys.now.set(1100);
            rig.up();
            assert_eq!(rig.state().unknown_until, Some(expiry));
            rig.sys.now.set(expiry);
            assert!(!rig.status().unknown);
            assert!(rig.status().history_unavailable);
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
                &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &rig.guard
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
        checkpoint_recovered(
            &rig.sys, &rig.held, "wg0", &broken, &rig.root, ID, &rig.guard,
        )
        .unwrap();
        assert!(!check().unknown);
        assert!(check().history_unavailable);
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
            probe_pending(&rig.sys, &rig.held, &site, &gateway, &rig.root, &rig.guard).is_err()
        );
        assert_eq!(rig.sys.sends.get(), 1);
        probe_pending(&rig.sys, &rig.held, &site, &gateway, &rig.root, &rig.guard).unwrap();
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
    fn unavailable_readiness_telemetry_is_bounded_availability_evidence_not_a_safety_error() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.fail_read.set(true);
        assert!(rig.status().unknown);
        assert!(rig.status().active_reset);
        rig.sys.now.set(1181);
        assert!(!rig.status().unknown);
        assert!(!rig.status().active_reset);
        assert!(rig.status().history_unavailable);
        assert!(rig.status().expired_unconfirmed);
    }
    #[test]
    fn planned_shutdown_snapshots_activity_without_resetting_sessions_or_sending_probes() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        rig.sys.now.set(1010);
        rig.sys.sample.borrow_mut().rx += 32;
        before_shutdown(
            &rig.sys, &rig.held, "wg0", &rig.root, &rig.root, ID, &rig.guard,
        )
        .unwrap();
        assert_eq!(rig.state().peers[0].last_authenticated, Some(1010));
        assert_eq!(rig.state().peers[0].state, SessionState::Recovered);
        assert!(!rig.state().down);
        assert_eq!(rig.sys.sends.get(), 0);
    }
    #[test]
    fn periodic_activity_is_durable_without_shutdown_and_does_not_write_each_tick() {
        let rig = Rig::new();
        rig.up();
        rig.authenticate();
        let previous = std::fs::read(path(&rig.root)).unwrap();
        rig.sys.now.set(1010);
        rig.sys.sample.borrow_mut().rx += 32;
        rig.checkpoint();
        assert_eq!(std::fs::read(path(&rig.root)).unwrap(), previous);
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
}
