//! Synchronous daemon lifecycle. One thread owns the reconciler and all mutable
//! scheduler state. Child-wait and audit-open workers return values over channels;
//! neither can submit failover inputs or execute a kernel repair.
pub mod notify;
pub mod probes;
pub mod scheduler;
pub use scheduler::{DaemonDeps, Iteration, run_with};

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
fn uplink_addresses(system: &dyn crate::system::System) -> io::Result<Vec<std::net::IpAddr>> {
    use crate::{
        cmd::{IpCmd, KernelCmd, run_cmd},
        system::{EXEC_TIMEOUT, ExecTarget},
    };
    let text = canon::command_result(run_cmd(
        system,
        ExecTarget::Host,
        &KernelCmd::Ip(IpCmd::AddrShowJson),
        EXEC_TIMEOUT,
    ))
    .map_err(io::Error::other)?;
    let interfaces = scupper_core::parse::parse_ip_addr(&text).map_err(io::Error::other)?;
    let addresses: Vec<_> = interfaces
        .into_iter()
        .flat_map(|i| i.addresses)
        .map(|a| a.local)
        .filter(|a| !a.is_loopback() && !a.is_unspecified())
        .collect();
    if addresses.is_empty() {
        return Err(io::Error::other("no uplink addresses observed"));
    }
    Ok(addresses)
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
        uplink_addresses(deps.system)?,
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
    /// Start in memory; the first disk open runs on the recovery worker.
    ///
    /// # Errors
    /// Returns invalid gateway errors from the fallback constructor.
    pub fn open(
        root: &Path,
        gateway: GatewayId,
        now: Instant,
    ) -> Result<Self, crate::events::OpenError> {
        let opened = EventLog::memory_only(gateway.clone(), || UnixSeconds(unix()))?;
        Ok(Self {
            opened,
            root: root.into(),
            gateway,
            retry_at: now,
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

impl Drop for Audit {
    fn drop(&mut self) {
        let _ = self.shutdown();
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
    let system = RealSystem::default()
        .with_canon_paths(options.probe_binary.clone(), options.run_root.clone());
    let namespace = GatewayNamespace;
    let mut audit =
        Audit::open(&options.state_root, gateway.clone(), origin).map_err(io::Error::other)?;
    audit.poll(origin);
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
    let notify =
        notify::Notify::new(std::env::var_os("NOTIFY_SOCKET").as_deref()).unwrap_or_else(|error| {
            eprintln!("scupperd: notify setup: {error}");
            notify::Notify::disabled()
        });
    let mut runtime = Runtime {
        options,
        system: &system,
        namespace: &namespace,
        gateway,
        origin,
        audit,
        notify,
        running: None,
        probes: probes::Probes::new(options.probe_binary.clone(), origin)
            .with_uplink(uplink_addresses(&system).unwrap_or_default()),
        setup_at: None,
        setup_rounds: 0,
        edge_logged: false,
    };
    run_with(&mut runtime, stop);
    Ok(())
}
struct Runtime<'a> {
    options: &'a Options,
    system: &'a RealSystem,
    namespace: &'a GatewayNamespace,
    gateway: GatewayId,
    origin: Instant,
    audit: Audit,
    notify: notify::Notify,
    running: Option<(Machine<'a>, Arc<NetnsHandle>, Config)>,
    probes: probes::Probes,
    edge_logged: bool,
    setup_at: Option<Instant>,
    setup_rounds: u64,
}
impl<'a> Runtime<'a> {
    fn deps(&self) -> BootDeps<'a> {
        BootDeps {
            system: self.system,
            namespace: self.namespace,
            state_root: &self.options.state_root,
            config_root: &self.options.config_root,
            run_root: &self.options.run_root,
            #[cfg(feature = "testing")]
            hook: None,
            #[cfg(feature = "testing")]
            secret_owner: 0,
        }
    }
}
impl DaemonDeps for Runtime<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn started(&mut self) {
        if let Err(error) = self.notify.started() {
            eprintln!("scupperd: notify: {error}");
        }
    }
    fn notify(&mut self, iteration: &Iteration) {
        if let Err(error) = self.notify.iteration(iteration.complete, iteration.status) {
            eprintln!("scupperd: notify: {error}");
        }
    }
    fn shutdown(&mut self) {
        self.running.take();
        if let Err(error) = self.audit.shutdown() {
            eprintln!("scupperd: event flush: {error}");
        }
    }
    fn initialize(&mut self) {
        self.running = match initialize(
            self.deps(),
            self.gateway.clone(),
            self.audit.handle(),
            self.origin,
        ) {
            Ok(machine) => Some(machine),
            Err(error) => {
                eprintln!("scupperd: reconciler startup refused: {error}");
                let _ = self.audit.handle().emit(
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
    }
    fn run_root(&self) -> &Path {
        &self.options.run_root
    }
    fn boot_time(&self) -> Duration {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        Duration::new(
            time.tv_sec.unsigned_abs(),
            u32::try_from(time.tv_nsec).unwrap_or(0),
        )
    }
    fn budget_error(&mut self, error: &io::Error) {
        eprintln!("scupperd: boot budget: {error}");
        let _ = self.audit.handle().emit(
            EventKind::PersistenceFailed {
                reason: scupper_proto::Reason::BootWrite,
            },
            Actor::Daemon,
            None,
        );
    }
    fn close_only(&mut self) {
        close_only(&self.deps(), self.options);
    }
    fn abandon_probes(&mut self) {
        self.probes = probes::Probes::new(self.options.probe_binary.clone(), Instant::now())
            .with_uplink(uplink_addresses(self.system).unwrap_or_default());
    }
    fn rebuild(&mut self) {
        let deps = self.deps();
        let report = if let Some((machine, _, _)) = &mut self.running {
            machine.rebuild(&deps).ok()
        } else {
            Some(boot::boot(&deps))
        };
        if report.is_some_and(|report| report.succeeded()) {
            self.initialize();
        }
    }
    fn maintenance(&mut self) {
        if let Err(error) = canon::refresh_tool_facts(self.system, Instant::now()) {
            eprintln!("scupperd: canonical tool identity: {error}");
        }
    }
    #[allow(clippy::too_many_lines)]
    fn tick(&mut self, stop: &AtomicBool) -> Option<crate::reconcile::TickReport> {
        let now = Instant::now();
        #[cfg(feature = "testing")]
        while self.options.run_root.join("stall-tick").exists() && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(25));
        }
        let Self {
            audit,
            running,
            probes,
            edge_logged,
            setup_at,
            setup_rounds,
            ..
        } = self;
        if audit.poll(now)
            && let Some((machine, _, _)) = running
        {
            machine.set_log(audit.handle());
        }
        if let Some((machine, held, config)) = running {
            for round in probes.collect() {
                if round.setup_failures > 0 {
                    *setup_rounds = setup_rounds.saturating_add(1);
                    if setup_at.is_none_or(|at| {
                        now.saturating_duration_since(at) >= Duration::from_secs(60)
                    }) {
                        eprintln!(
                            "scupperd: probe setup failed; consecutive rounds={setup_rounds}"
                        );
                        let _ = audit.handle().emit(
                            EventKind::DriftDetected {
                                object: scupper_proto::ObjectKind::Unknown,
                                reason: scupper_proto::Reason::ObservationUnknown,
                            },
                            Actor::Daemon,
                            Some(config.stamp.version),
                        );
                        *setup_at = Some(now);
                    }
                } else {
                    *setup_rounds = 0;
                }

                if !round.paths.is_empty() {
                    machine.submit_probe_round(round.paths);
                }
                if round.exit_ok == Some(false) && round.setup_failures == 0 {
                    let _ = audit.handle().emit(
                        EventKind::DriftDetected {
                            object: scupper_proto::ObjectKind::Unknown,
                            reason: scupper_proto::Reason::HealthFailure,
                        },
                        Actor::Daemon,
                        Some(config.stamp.version),
                    );
                }
            }
            if stop.load(Ordering::Relaxed) {
                return Some(crate::reconcile::TickReport::default());
            }
            let report = machine.tick();
            let rebuild = report.escalations.contains(&Escalation::RebuildRequired)
                || report
                    .escalations
                    .contains(&Escalation::ReinitializeRequired);
            if report.escalations.contains(&Escalation::RestartEdge) && !*edge_logged {
                eprintln!("scupperd: RestartEdge deferred until M4");
                *edge_logged = true;
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
                            let bind = match closed
                                .then(|| scupper_core::rules::IfName::new(exit.ifname().as_str()))
                                .transpose()
                            {
                                Ok(bind) => bind,
                                Err(error) => {
                                    eprintln!("scupperd: probe interface: {error}");
                                    let _ = audit.handle().emit(
                                        EventKind::DriftDetected {
                                            object: scupper_proto::ObjectKind::Unknown,
                                            reason: scupper_proto::Reason::ObservationUnknown,
                                        },
                                        Actor::Daemon,
                                        Some(config.stamp.version),
                                    );
                                    return Some(report);
                                }
                            };
                            let request = crate::probe_child::ProbeRequest {
                                kind: crate::probe_child::ProbeKind::Path,
                                bind,
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
            }
            Some(report)
        } else {
            None
        }
    }
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
