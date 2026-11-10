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

// One owned read job survives startup timeouts. Retained inputs make canon retries
// channel-only; no configuration, state, boot report or namespace is reopened.
struct StartupInputs {
    state: StateFile,
    kernel_state: StateFile,
    saved: crate::state::State,
    text: String,
    report: BootReport,
    held: Arc<NetnsHandle>,
}
#[derive(Default)]
struct StartupRead {
    pending: Option<Receiver<io::Result<StartupInputs>>>,
    ready: Option<StartupInputs>,
}
impl StartupRead {
    fn load(&mut self, deps: &BootDeps<'_>, deadline: Instant) -> io::Result<&StartupInputs> {
        if self.ready.is_none() {
            if self.pending.is_none() {
                let state_root = deps.state_root.to_path_buf();
                let config_root = deps.config_root.to_path_buf();
                let run_root = deps.run_root.to_path_buf();
                let (send, receive) = mpsc::sync_channel(1);
                std::thread::Builder::new()
                    .name("scupper-startup-read".into())
                    .spawn(move || {
                        let result = (|| {
                            let state = StateFile::open(&state_root, None)?;
                            let StateRead::Present(saved) = state.read()? else {
                                return Err(io::Error::other("missing safety state"));
                            };
                            let version = saved
                                .applied_version
                                .ok_or_else(|| io::Error::other("no applied version"))?;
                            let (text, _) = VersionStore::read_only(&state_root, &config_root)
                                .read(version)
                                .map_err(io::Error::other)?;
                            let report: BootReport =
                                serde_json::from_str(&RealFs.read(&run_root.join("boot.json"))?)
                                    .map_err(io::Error::other)?;
                            let expected = report.netns.ok_or_else(|| {
                                io::Error::other("missing boot namespace identity")
                            })?;
                            let held = Arc::new(
                                NetnsHandle::open_expected(
                                    "/run/netns/scupper",
                                    Some((expected.dev, expected.ino)),
                                )
                                .map_err(io::Error::other)?,
                            );
                            let kernel_state = StateFile::open(&state_root, None)?;
                            Ok(StartupInputs {
                                state,
                                kernel_state,
                                saved,
                                text,
                                report,
                                held,
                            })
                        })();
                        let _ = send.send(result);
                    })?;
                self.pending = Some(receive);
            }
            let result = self
                .pending
                .as_ref()
                .ok_or_else(|| io::Error::other("missing startup worker"))?
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|e| match e {
                    mpsc::RecvTimeoutError::Timeout => {
                        io::Error::new(io::ErrorKind::TimedOut, "startup reads pending")
                    }
                    mpsc::RecvTimeoutError::Disconnected => {
                        io::Error::other("startup read worker stopped")
                    }
                })?;
            self.pending = None;
            self.ready = Some(result?);
        }
        self.ready
            .as_ref()
            .ok_or_else(|| io::Error::other("missing startup inputs"))
    }
}
fn initialize<'a>(
    deps: BootDeps<'a>,
    gateway: GatewayId,
    log: crate::events::LogHandle,
    origin: Instant,
    canon_deadline: Instant,
    inputs: &mut StartupRead,
) -> io::Result<(Machine<'a>, Arc<NetnsHandle>, Config)> {
    let loaded = inputs.load(&deps, canon_deadline)?;
    let site = validate(parse_site(&loaded.text).map_err(io::Error::other)?)
        .map_err(|_| io::Error::other("invalid applied configuration"))?;
    let version = loaded
        .saved
        .applied_version
        .ok_or_else(|| io::Error::other("no applied version"))?;
    let stamp = VersionStamp {
        version,
        sha256: Sha256::digest(loaded.text.as_bytes()).into(),
    };
    let held = loaded.held.clone();
    let expected = loaded
        .report
        .netns
        .ok_or_else(|| io::Error::other("missing boot namespace identity"))?;
    let rendered = render_netns(&site, &gateway, &stamp).map_err(io::Error::other)?;
    let want = canon::prepare_netns_ruleset(deps.system, &held, &rendered, canon_deadline)
        .map_err(|error| match error {
            crate::verdict::ProbeError::Timeout => io::Error::new(io::ErrorKind::TimedOut, error),
            _ => io::Error::other(error),
        })?;
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
    let loaded = inputs
        .ready
        .take()
        .ok_or_else(|| io::Error::other("missing startup inputs"))?;
    let kernel = RealKernel::from_boot_report(
        deps,
        held.clone(),
        &config,
        health,
        loaded.report,
        loaded.kernel_state,
    )?;
    let machine_config = Config {
        site: config.site.clone(),
        gateway: config.gateway.clone(),
        stamp,
        fingerprint,
        run_root: config.run_root.clone(),
        lock_wait: config.lock_wait,
    };
    let mut machine = Reconciler::with_state(
        kernel,
        loaded.state,
        log,
        machine_config,
        held.clone(),
        Box::new(move || (MonoTime(origin.elapsed()), unix())) as Box<dyn Fn() -> (MonoTime, u64)>,
        loaded.saved,
    )?;
    machine.recover_route_switch()?;
    machine.resume_existing();
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
    pending_deadline: Option<Instant>,
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
        let opened = EventLog::memory_buffer(gateway.clone(), || UnixSeconds(unix()))?;
        Ok(Self {
            opened,
            root: root.into(),
            gateway,
            retry_at: now,
            pending: None,
            pending_deadline: None,
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
                    self.pending_deadline = None;
                    if self.opened.handle.replay_into(&opened.handle).is_ok() {
                        self.opened = opened;
                        return true;
                    }
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.pending_deadline = None;
                    self.opened.handle.persistence_failed();
                    self.retry_at = now + Duration::from_secs(60);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if self
                        .pending_deadline
                        .is_some_and(|deadline| now >= deadline)
                    {
                        // Keep the receiver: a slow open may still recover, and
                        // abandoning it would spawn unbounded blocked workers.
                        self.pending_deadline = None;
                        eprintln!("scupperd: event log open exceeded 10 seconds");
                        self.opened.handle.persistence_failed();
                    }
                }
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
                self.pending_deadline = Some(now + Duration::from_secs(10));
            } else {
                self.opened.handle.persistence_failed();
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
        pending_canon: false,
        startup_read: StartupRead::default(),
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
    pending_canon: bool,
    startup_read: StartupRead,
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
impl Runtime<'_> {
    fn initialize_until(&mut self, deadline: Instant) {
        self.running = match initialize(
            self.deps(),
            self.gateway.clone(),
            self.audit.handle(),
            self.origin,
            deadline,
            &mut self.startup_read,
        ) {
            Ok(machine) => {
                self.pending_canon = false;
                Some(machine)
            }
            Err(error) => {
                self.pending_canon = error.kind() == io::ErrorKind::TimedOut;
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
}
impl DaemonDeps for Runtime<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn started(&mut self) {
        if self.running.is_none() {
            return;
        }
        if let Err(error) = self.notify.started() {
            eprintln!("scupperd: notify: {error}");
        }
    }
    fn notify(&mut self, iteration: &Iteration) {
        let Some((machine, _, _)) = &self.running else {
            return;
        };
        let status = if machine.unconfirmed() {
            "unconfirmed; reconciling"
        } else {
            iteration.status
        };
        if let Err(error) = self.notify.iteration(iteration.complete, status) {
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
        self.startup_read.ready = None;
        self.initialize_until(Instant::now() + canon::CANON_TIMEOUT + crate::system::EXEC_TIMEOUT);
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
        // A cold canonicalization timeout is Unknown, not an invalid boot
        // handoff. Poll its existing worker and contain without consuming a boot.
        if self.pending_canon && !stop.load(Ordering::Relaxed) {
            close_only(&self.deps(), self.options);
            self.initialize_until(now + Duration::from_millis(100));
            if self.pending_canon {
                return Some(crate::reconcile::TickReport::default());
            }
        }
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
                    machine.submit_probe_outcomes(round.paths);
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hung_audit_open_reports_after_bound_and_can_still_recover() {
        let now = Instant::now();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/audit-open-bound")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&root);
        let mut audit = Audit::open(&root, GatewayId("gw1".into()), now).unwrap();
        let (send, receive) = mpsc::sync_channel(1);
        audit.pending = Some(receive);
        audit.pending_deadline = Some(now + Duration::from_secs(10));
        assert!(!audit.poll(now + Duration::from_secs(9)));
        assert_eq!(
            audit
                .handle()
                .emit(EventKind::Flapping {}, Actor::Daemon, None)
                .unwrap(),
            1
        );
        assert!(!audit.poll(now + Duration::from_secs(10)));
        assert!(!audit.poll(now + Duration::from_secs(120)));
        assert!(audit.pending.is_some());
        assert_eq!(
            audit
                .handle()
                .emit(EventKind::Flapping {}, Actor::Daemon, None)
                .unwrap(),
            3
        );
        send.send(EventLog::open(&root, GatewayId("gw1".into()), || {
            UnixSeconds(100)
        }))
        .unwrap();
        assert!(audit.poll(now + Duration::from_secs(121)));
        assert!(audit.handle().is_persistent());
        audit.shutdown().unwrap();
        drop(audit);
        let events = crate::events::read_since(&root, 0, None)
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
                .count(),
            1
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "testing")]
    #[test]
    #[allow(clippy::too_many_lines)] // Exercise production timeout, retry and handoff ordering together.
    fn production_initialize_retries_only_canon_then_recovers_before_handoff() {
        use crate::{
            canon::CanonCache,
            system::{ExecError, ExecOutput, ExecTarget, Program, System},
        };
        use std::{cell::RefCell, sync::atomic::AtomicUsize};
        const RULES: &str = r#"{"nftables":[]}"#;
        struct StartupSystem {
            cache: RefCell<CanonCache>,
            root: PathBuf,
            reads: Arc<AtomicUsize>,
            flushes: Arc<AtomicUsize>,
        }
        impl System for StartupSystem {
            fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
                Some((&self.cache, &self.root))
            }
            fn canon_run_root(&self) -> &Path {
                &self.root
            }
            fn canon_worker(&self) -> Option<Box<dyn System + Send>> {
                Some(Box::new(Self {
                    cache: RefCell::default(),
                    root: self.root.clone(),
                    reads: self.reads.clone(),
                    flushes: self.flushes.clone(),
                }))
            }
            fn run(&self, p: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
                if p == Program::Unshare {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(ExecOutput {
                    status: Some(0),
                    stdout: if p == Program::Unshare {
                        RULES.into()
                    } else {
                        "nft v1".into()
                    },
                    stderr: String::new(),
                })
            }
            fn run_in(
                &self,
                _: ExecTarget<'_>,
                p: Program,
                args: &[String],
                _: Duration,
            ) -> Result<ExecOutput, ExecError> {
                if p == Program::Conntrack {
                    self.flushes.fetch_add(1, Ordering::Relaxed);
                }
                if p == Program::Nft {
                    self.reads.fetch_add(1, Ordering::Relaxed);
                }
                let stdout = if p == Program::Nft {
                    RULES.into()
                } else if p == Program::Ip && args.iter().any(|arg| arg == "addr") {
                    r#"[{"ifindex":1,"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.1","prefixlen":24,"scope":"global"}]}]"#.into()
                } else {
                    "[]".into()
                };
                Ok(ExecOutput {
                    status: Some(0),
                    stdout,
                    stderr: String::new(),
                })
            }
            fn now_unix_secs(&self) -> u64 {
                100
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/production-initialize")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../scupper-core/tests/fixtures/site-m2.toml"
        ))
        .to_owned();
        let held = Arc::new(crate::netns::testing::handle().unwrap());
        let (dev, ino) = held.identity();
        let report = BootReport {
            steps: vec![
                boot::StepResult {
                    step: boot::BootStep::Lock,
                    error: None,
                    adopted: true
                };
                8
            ],
            applied_version: Some(1),
            netns: Some(boot::NamespaceIdentity { dev, ino }),
            owned_links: std::collections::BTreeMap::from([
                ("wg0".into(), 1),
                ("ex-ch1".into(), 2),
            ]),
            ..BootReport::default()
        };
        let mut inputs = StartupRead {
            pending: None,
            ready: Some(StartupInputs {
                state: StateFile::open(&root, None).unwrap(),
                kernel_state: StateFile::open(&root, None).unwrap(),
                saved: crate::state::State {
                    applied_version: Some(1),
                    ..crate::state::State::default()
                },
                text,
                report,
                held,
            }),
        };
        let system = StartupSystem {
            cache: RefCell::default(),
            root: root.clone(),
            reads: Arc::default(),
            flushes: Arc::default(),
        };
        let deps = || BootDeps {
            system: &system,
            namespace: &GatewayNamespace,
            state_root: &root,
            config_root: &root,
            run_root: &root,
            hook: None,
            secret_owner: 0,
        };
        let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
        let attempt = |inputs: &mut StartupRead, wait| {
            initialize(
                deps(),
                GatewayId("gw1".into()),
                log.handle.clone(),
                Instant::now(),
                Instant::now() + wait,
                inputs,
            )
        };
        let error = attempt(&mut inputs, Duration::from_millis(5))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(inputs.ready.is_some());
        assert_eq!(
            system.reads.load(Ordering::Relaxed),
            0,
            "handoff observed before canon completed"
        );
        // No state/version/boot files exist: retry must use the retained inputs.
        std::fs::write(root.join("route-switch"), b"target=exit\ntime=100\n").unwrap();
        let (_machine, _, _) = attempt(&mut inputs, Duration::from_secs(3)).unwrap();
        assert!(inputs.ready.is_none());
        assert_eq!(system.flushes.load(Ordering::Relaxed), 1);
        assert!(!root.join("route-switch").exists());
        assert!(
            system.reads.load(Ordering::Relaxed) > 0,
            "production initialization skipped handoff observation"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_retry_waits_are_bounded_while_the_same_input_read_is_stalled() {
        use std::io::Write;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/startup-read-bound")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let fifo = root.join("state.json");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let system = RealSystem::new(crate::system::Programs::default());
        let deps = BootDeps {
            system: &system,
            namespace: &GatewayNamespace,
            state_root: &root,
            config_root: &root,
            run_root: &root,
            #[cfg(feature = "testing")]
            hook: None,
            #[cfg(feature = "testing")]
            secret_owner: 0,
        };
        let mut reader = StartupRead::default();
        for _ in 0..3 {
            let started = Instant::now();
            let error = reader
                .load(&deps, started + Duration::from_millis(25))
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() < Duration::from_millis(250));
            assert!(reader.pending.is_some());
        }
        let writer = std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new().write(true).open(fifo).unwrap();
            file.write_all(&serde_json::to_vec(&crate::state::State::default()).unwrap())
                .unwrap();
        });
        let error = reader
            .load(&deps, Instant::now() + Duration::from_secs(2))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "no applied version");
        writer.join().unwrap();
        assert!(reader.pending.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}
