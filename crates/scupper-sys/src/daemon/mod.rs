//! Synchronous daemon lifecycle. One thread owns the reconciler and all mutable
//! scheduler state. Child-wait and audit-open workers return values over channels;
//! neither can submit failover inputs or execute a kernel repair.
pub mod notify;
pub mod probes;

use crate::{
    boot::{self, BootDeps, BootReport, GatewayNamespace},
    canon,
    events::{EventLog, OpenedLog},
    fs::{Fs, RealFs},
    netns::NetnsHandle,
    reconcile::{Config, Escalation, RealKernel, Reconciler},
    state::{StateFile, StateRead},
    store::VersionStore,
    system::RealSystem,
};
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    failover::{ExitHealth, MonoTime},
    render::{RouteTarget, VersionStamp, render_netns},
    verdict::v2::{HealthConfigV2, NetnsIdentity},
};
use scupper_proto::{Actor, EventKind, Release, UnixSeconds};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Production roots, with explicit overrides only for isolated lab execution.
pub struct Options {
    /// Immutable versions and safety state.
    pub state_root: PathBuf,
    /// Gateway identity and boot inputs.
    pub config_root: PathBuf,
    /// Writer lock and per-boot handoff.
    pub run_root: PathBuf,
    /// Existing single-threaded CLI child executable.
    pub probe_binary: PathBuf,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            state_root: "/var/lib/scupper".into(),
            config_root: "/etc/scupper".into(),
            run_root: "/run/scupper".into(),
            probe_binary: "/usr/local/bin/scupper".into(),
        }
    }
}
fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
type Machine<'a> = Reconciler<RealKernel<'a>, StateFile, Box<dyn Fn() -> (MonoTime, u64)>>;

fn initialize(
    deps: BootDeps<'_>,
    gateway: GatewayId,
    log: crate::events::LogHandle,
    origin: Instant,
) -> io::Result<(Machine<'_>, Arc<NetnsHandle>, Config)> {
    let state = StateFile::open(deps.state_root, None)?;
    let StateRead::Present(saved) = state.read()? else {
        return Err(io::Error::other("missing safety state"));
    };
    let version = saved
        .applied_version
        .ok_or_else(|| io::Error::other("no applied version"))?;
    let store = VersionStore::read_only(deps.state_root, deps.config_root);
    let (text, _) = store.read(version).map_err(io::Error::other)?;
    let site = validate(parse_site(&text).map_err(io::Error::other)?)
        .map_err(|_| io::Error::other("invalid applied configuration"))?;
    let stamp = VersionStamp {
        version,
        sha256: Sha256::digest(text.as_bytes()).into(),
    };
    let report: BootReport = serde_json::from_str(&RealFs.read(&deps.run_root.join("boot.json"))?)
        .map_err(io::Error::other)?;
    let expected = report
        .netns
        .ok_or_else(|| io::Error::other("missing boot namespace identity"))?;
    let held = Arc::new(
        NetnsHandle::open_expected("/run/netns/scupper", Some((expected.dev, expected.ino)))
            .map_err(io::Error::other)?,
    );
    let rendered = render_netns(&site, &gateway, &stamp).map_err(io::Error::other)?;
    let (want, _) =
        canon::netns_rulesets(deps.system, &held, &rendered).map_err(io::Error::other)?;
    let fingerprint = canon::fingerprint(&want).map_err(io::Error::other)?;
    let config = Config {
        site,
        gateway,
        stamp,
        fingerprint,
        run_root: deps.run_root.into(),
        lock_wait: Duration::from_millis(100),
    };
    let health = HealthConfigV2::new(
        &config.site,
        &config.gateway,
        NetnsIdentity {
            device: expected.dev,
            inode: expected.ino,
        },
        vec![std::net::Ipv4Addr::UNSPECIFIED.into()],
        version,
    )
    .map_err(io::Error::other)?;
    let kernel = RealKernel::from_boot_file(
        deps,
        held.clone(),
        &config,
        health,
        "/run/netns/scupper".into(),
        None,
    )?;
    let machine_config = Config {
        site: config.site.clone(),
        gateway: config.gateway.clone(),
        stamp,
        fingerprint,
        run_root: config.run_root.clone(),
        lock_wait: config.lock_wait,
    };
    let machine = Reconciler::new(
        kernel,
        state,
        log,
        machine_config,
        held.clone(),
        Box::new(move || (MonoTime(origin.elapsed()), unix())) as Box<dyn Fn() -> (MonoTime, u64)>,
    )?;
    Ok((machine, held, config))
}

/// Audit ownership and asynchronous memory-only recovery. Disk opens can stall
/// without delaying a tick. The old ring remains live until its replay completes.
pub struct Audit {
    opened: OpenedLog,
    root: PathBuf,
    gateway: GatewayId,
    retry_at: Instant,
    pending: Option<Receiver<Result<OpenedLog, crate::events::OpenError>>>,
}
impl Audit {
    /// Open once, falling back to a bounded in-memory log.
    ///
    /// # Errors
    /// Returns invalid gateway errors from the fallback constructor.
    pub fn open(
        root: &Path,
        gateway: GatewayId,
        now: Instant,
    ) -> Result<Self, crate::events::OpenError> {
        let opened = EventLog::open(root, gateway.clone(), || UnixSeconds(unix()))
            .or_else(|_| EventLog::memory_only(gateway.clone(), || UnixSeconds(unix())))?;
        Ok(Self {
            opened,
            root: root.into(),
            gateway,
            retry_at: now + Duration::from_secs(60),
            pending: None,
        })
    }
    /// Current nonblocking sender.
    #[must_use]
    pub fn handle(&self) -> crate::events::LogHandle {
        self.opened.handle.clone()
    }
    /// Check/start a recovery open without waiting on filesystem I/O.
    /// Returns true when the caller must replace its sender.
    pub fn poll(&mut self, now: Instant) -> bool {
        if let Some(pending) = &self.pending {
            match pending.try_recv() {
                Ok(Ok(opened)) => {
                    self.pending = None;
                    if self.opened.handle.replay_into(&opened.handle).is_ok() {
                        self.opened = opened;
                        return true;
                    }
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.retry_at = now + Duration::from_secs(60);
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if !self.opened.handle.is_persistent() && self.pending.is_none() && now >= self.retry_at {
            let root = self.root.clone();
            let gateway = self.gateway.clone();
            let (send, receive) = mpsc::sync_channel(1);
            if std::thread::Builder::new()
                .name("scupper-log-open".into())
                .spawn(move || {
                    let _ = send.send(EventLog::open(&root, gateway, || UnixSeconds(unix())));
                })
                .is_ok()
            {
                self.pending = Some(receive);
            }
            self.retry_at = now + Duration::from_secs(60);
        }
        false
    }
    /// Flush events and let the writer publish its clean marker. No kernel calls.
    ///
    /// # Errors
    /// Returns memory-only or bounded flush errors.
    pub fn shutdown(&self) -> io::Result<()> {
        self.opened.handle.flush_blocking(Duration::from_secs(5))
    }
}

/// Run until SIGTERM/SIGINT sets `stop`, finishing any current tick first.
/// Notification, probes and audit maintenance occur outside the writer lock.
/// Shutdown never executes kernel operations, even if flushing fails.
///
/// # Errors
/// Returns invalid identity/configuration roots or notify socket setup errors.
#[allow(clippy::too_many_lines)]
pub fn run(options: &Options, stop: &AtomicBool) -> io::Result<()> {
    let origin = Instant::now();
    let gateway = GatewayId(
        RealFs
            .read(&options.config_root.join("gateway-id"))?
            .trim()
            .into(),
    );
    let system = RealSystem::default();
    let namespace = GatewayNamespace;
    let deps = || BootDeps {
        system: &system,
        namespace: &namespace,
        state_root: &options.state_root,
        config_root: &options.config_root,
        run_root: &options.run_root,
        #[cfg(feature = "testing")]
        hook: None,
        #[cfg(feature = "testing")]
        secret_owner: 0,
    };
    let mut audit =
        Audit::open(&options.state_root, gateway.clone(), origin).map_err(io::Error::other)?;
    let _ = audit.handle().emit(
        EventKind::DaemonStarted {
            version: Release {
                major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
                minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
                patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
            },
        },
        Actor::Daemon,
        None,
    );
    let mut notify = notify::Notify::new(std::env::var_os("NOTIFY_SOCKET").as_deref())?;
    let mut running = match initialize(deps(), gateway.clone(), audit.handle(), origin) {
        Ok(machine) => Some(machine),
        Err(error) => {
            eprintln!("scupperd: reconciler startup refused: {error}");
            let _ = audit.handle().emit(
                EventKind::DriftDetected {
                    object: scupper_proto::ObjectKind::Unknown,
                    reason: scupper_proto::Reason::ObservationUnknown,
                },
                Actor::Daemon,
                None,
            );
            None
        }
    };
    let mut probes = probes::Probes::new(options.probe_binary.clone(), origin);
    let mut rebuilds = std::collections::VecDeque::new();
    let mut retry_at = origin;
    let mut next_tick = origin;
    let mut edge_logged = false;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now < next_tick {
            std::thread::sleep((next_tick - now).min(Duration::from_millis(50)));
            continue;
        }
        if audit.poll(now)
            && let Some((machine, _, _)) = &mut running
        {
            machine.set_log(audit.handle());
        }
        let mut rebuild = running.is_none();
        if let Some((machine, held, config)) = &mut running {
            for round in probes.collect() {
                if !round.paths.is_empty() {
                    machine.submit_probe_round(round.paths);
                }
                if round.exit_ok == Some(false) {
                    let _ = audit.handle().emit(
                        EventKind::DriftDetected {
                            object: scupper_proto::ObjectKind::Route,
                            reason: scupper_proto::Reason::HealthFailure,
                        },
                        Actor::Daemon,
                        Some(config.stamp.version),
                    );
                }
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let report = machine.tick();
            rebuild = report.escalations.contains(&Escalation::RebuildRequired);
            if report.escalations.contains(&Escalation::RestartEdge) && !edge_logged {
                eprintln!("scupperd: RestartEdge deferred until M4");
                edge_logged = true;
            }
            if !stop.load(Ordering::Relaxed) && !rebuild {
                let probe_exit = machine.probe_exit();
                if let Some(exit) = config.site.gateway(&config.gateway).and_then(|gw| {
                    gw.exits()
                        .iter()
                        .find(|exit| Some(exit.id()) == probe_exit.as_ref())
                }) {
                    let suspect = matches!(
                        machine.health().get(exit.id()),
                        Some(ExitHealth::Suspect { .. })
                    );
                    if let Some(dns) = exit.dns().iter().find_map(|ip| {
                        if let std::net::IpAddr::V4(ip) = ip {
                            Some(*ip)
                        } else {
                            None
                        }
                    }) {
                        let targets = config
                            .site
                            .health()
                            .probe_targets()
                            .iter()
                            .map(|url| crate::probe_child::Url::new(url.as_str()))
                            .collect::<Result<Vec<_>, _>>();
                        if let Ok(targets) = targets {
                            let closed = machine.desired().is_ok_and(|d| {
                                d.routes()
                                    .iter()
                                    .all(|(_, r)| *r == RouteTarget::Unreachable)
                            });
                            let request = crate::probe_child::ProbeRequest {
                                kind: crate::probe_child::ProbeKind::Path,
                                bind: closed
                                    .then(|| {
                                        scupper_core::rules::IfName::new(exit.ifname().as_str())
                                    })
                                    .transpose()
                                    .map_err(io::Error::other)?,
                                expected_netns: held.identity(),
                                dns,
                                targets,
                                deadline_ms: 0,
                                #[cfg(feature = "testing")]
                                identity: None,
                            };
                            if let Err(error) =
                                probes.schedule(now, suspect, exit.id(), request, held)
                            {
                                eprintln!("scupperd: probe worker: {error}");
                            }
                        }
                    }
                }
                // Last operation of an entire successful iteration.
                if let Err(error) = notify.completed(&report) {
                    eprintln!("scupperd: notify: {error}");
                }
            }
        }
        if rebuild && !stop.load(Ordering::Relaxed) {
            // Never adopt a mismatched boot identity. The fallback only tightens
            // the named foreign namespace; ordered boot is retried under its lock.
            if running.is_none() {
                close_only(&deps(), options);
            }
            rebuilds.retain(|at| now.duration_since(*at) < Duration::from_secs(600));
            if now >= retry_at && rebuilds.len() < 3 {
                rebuilds.push_back(now);
                let report = if let Some((machine, _, _)) = &mut running {
                    machine.rebuild(&deps()).ok()
                } else {
                    Some(boot::boot(&deps()))
                };
                retry_at = now + Duration::from_secs(60);
                if report.is_some_and(|report| report.succeeded()) {
                    running = initialize(deps(), gateway.clone(), audit.handle(), origin).ok();
                    probes = probes::Probes::new(options.probe_binary.clone(), now);
                }
            }
        }
        next_tick += Duration::from_secs(2);
        // Coalesce overdue wakeups without adding another interval after a slow tick.
        next_tick = next_tick.max(Instant::now());
    }
    if let Err(error) = audit.shutdown() {
        eprintln!("scupperd: event flush: {error}");
    }
    Ok(())
}
// An invalid handoff cannot authorize restoration. Close gates only, using the
// same bounded kernel executor and writer lock as reconciliation.
fn close_only(deps: &BootDeps<'_>, options: &Options) {
    let Ok(_guard) =
        crate::lock::WriterLock::acquire_timeout(&options.run_root, Duration::from_millis(100))
    else {
        return;
    };
    let Ok(held) = NetnsHandle::open("/run/netns/scupper") else {
        return;
    };
    let _ = crate::reconcile::forwarding_gates(deps, &held, false, None);
}
