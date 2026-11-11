//! Synchronous daemon lifecycle. One thread owns the reconciler and all mutable
//! scheduler state. Child-wait and audit-open workers return values over channels;
//! neither can submit failover inputs or execute a kernel repair.
pub mod admin;
pub mod control;
mod heartbeat;
pub mod notify;
mod pending;
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
                #[cfg(not(feature = "testing"))]
                let namespace_path = deps.namespace.path().to_path_buf();
                #[cfg(feature = "testing")]
                let test_held = deps.namespace.open().map_err(io::Error::other)?;
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
                            #[cfg(feature = "testing")]
                            let held = if let Some(held) = test_held {
                                if held.identity() != (expected.dev, expected.ino) {
                                    return Err(io::Error::other("namespace identity mismatch"));
                                }
                                Arc::new(held)
                            } else {
                                return Err(io::Error::other("missing test namespace"));
                            };
                            #[cfg(not(feature = "testing"))]
                            let held = Arc::new(
                                NetnsHandle::open_expected(
                                    &namespace_path,
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
    guard: Option<(&crate::lock::WriterGuard, bool)>,
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
    let want = if deps.system.canon_cache().is_some() {
        canon::prepare_netns_ruleset(deps.system, &held, &rendered, canon_deadline)
    } else {
        canon::netns_rulesets(deps.system, &held, &rendered).map(|(want, _)| want)
    }
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
    if let Some((guard, recover)) = guard {
        if recover {
            machine.recover_route_switch_locked(guard)?;
        }
        machine.resume_existing_locked(guard);
    } else {
        machine.recover_route_switch()?;
        machine.resume_existing();
    }
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
    let lease_notify = notify::Notify::new(std::env::var_os("NOTIFY_SOCKET").as_deref())
        .unwrap_or_else(|_| notify::Notify::disabled());
    run_notified(options, stop, lease_notify)
}

fn run_notified(
    options: &Options,
    stop: &AtomicBool,
    lease_notify: notify::Notify,
) -> io::Result<()> {
    let _lease = crate::lock::SupervisorLease::acquire_timeout(
        &options.run_root,
        Duration::from_secs(60),
        || {
            let _ = lease_notify.status("waiting for supervisor lease; local writer active");
        },
    )?;
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
    let mut runtime = Runtime {
        options,
        system: &system,
        namespace: &namespace,
        #[cfg(feature = "testing")]
        secret_owner: 0,
        gateway,
        origin,
        audit,
        notify: lease_notify,
        started_event: false,
        running: None,
        pending_canon: false,
        startup_read: StartupRead::default(),
        probes: probes::Probes::new(options.probe_binary.clone(), origin)
            .with_uplink(uplink_addresses(&system).unwrap_or_default()),
        setup_at: None,
        setup_rounds: 0,
        edge_logged: false,
        control: None,
        binding: None,
        bind_retry: Instant::now(),
        control_errors: control::FailureSummary::default(),
        dispatcher: pending::Dispatcher::default(),
        last_complete: None,
        heartbeat: crate::daemon::heartbeat::Heartbeat::default(),
        snapshot: control::SharedSnapshot::default(),
        cached: None,
    };
    run_with(&mut runtime, stop);
    Ok(())
}
struct Runtime<'a> {
    options: &'a Options,
    system: &'a dyn crate::system::System,
    namespace: &'a dyn crate::boot::BootNamespace,
    #[cfg(feature = "testing")]
    secret_owner: u32,
    gateway: GatewayId,
    origin: Instant,
    audit: Audit,
    notify: notify::Notify,
    started_event: bool,
    running: Option<(Machine<'a>, Arc<NetnsHandle>, Config)>,
    pending_canon: bool,
    startup_read: StartupRead,
    probes: probes::Probes,
    edge_logged: bool,
    control: Option<control::Server>,
    binding: Option<Receiver<io::Result<control::Server>>>,
    bind_retry: Instant,
    control_errors: control::FailureSummary,
    dispatcher: pending::Dispatcher,
    last_complete: Option<Instant>,
    heartbeat: heartbeat::Heartbeat,
    snapshot: control::SharedSnapshot,
    cached: Option<(
        Instant,
        scupper_proto::HealthSummary,
        scupper_proto::TickObservation,
    )>,
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
            hook: Some(&testing_boot_hook),
            #[cfg(feature = "testing")]
            secret_owner: self.secret_owner,
        }
    }
}
impl Runtime<'_> {
    fn publish_snapshot(&self) {
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.last_complete = self.last_complete;
        snapshot.ping =
            self.running
                .as_ref()
                .map(|(machine, _, _)| scupper_proto::OpResult::Ping {
                    last_complete_iteration_age: None,
                    current_iteration_age: None,
                    operation: None,
                    netns: machine.netns_identity(),
                    version: machine.version(),
                    quarantined: machine.latch().is_some(),
                    selection: machine.selection(),
                });
    }
    fn begin_operation(&self, kind: scupper_proto::OperationKind, target: Option<u64>) {
        let from = self
            .running
            .as_ref()
            .map_or(0, |(machine, _, _)| machine.version());
        self.snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .operation = Some((
            scupper_proto::OperationProgress {
                kind,
                from,
                to: target.unwrap_or(from),
                age: 0,
            },
            Instant::now(),
        ));
    }
    fn end_operation(&self) {
        self.publish_snapshot();
        self.snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .operation = None;
    }
    fn control_failure(&mut self, error: &str) {
        let Some(count) = self.control_errors.record(Instant::now()) else {
            return;
        };
        eprintln!("scupperd: control listener: {count} errors since last notice: {error}");
        let _ =
            self.audit
                .handle()
                .emit(EventKind::ControlUnavailable { count }, Actor::Daemon, None);
    }
    fn maintain_control(&mut self) {
        if let Some(server) = &self.control {
            let errors: Vec<_> = server.errors.try_iter().collect();
            let alive = server.alive();
            for error in errors {
                self.control_failure(&error);
            }
            if !alive {
                self.control_failure("listener exited; rebinding");
                self.control = None;
            }
        }
        if let Some(binding) = &self.binding {
            match binding.try_recv() {
                Ok(Ok(server)) => {
                    self.control = Some(server);
                    self.binding = None;
                }
                Ok(Err(error)) => {
                    self.control_failure(&error.to_string());
                    self.binding = None;
                    self.bind_retry = Instant::now() + Duration::from_secs(1);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.binding = None;
                    self.bind_retry = Instant::now() + Duration::from_secs(1);
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.control.is_none() && self.binding.is_none() && Instant::now() >= self.bind_retry {
            let root = self.options.run_root.clone();
            let snapshot = self.snapshot.clone();
            let (send, receive) = mpsc::sync_channel(1);
            self.binding = Some(receive);
            let _ = std::thread::Builder::new()
                .name("scupper-control-bind".into())
                .spawn(move || {
                    let _ = send.send(control::Server::bind_snapshot(&root, snapshot));
                });
        }
    }
    fn control_requests(&mut self) {
        self.maintain_control();
        let mut dispatcher = std::mem::take(&mut self.dispatcher);
        dispatcher.poll_admin(self, Instant::now());
        for _ in 0..4 {
            let Some(server) = &self.control else { break };
            let Ok(pending) = server.receive.try_recv() else {
                break;
            };
            dispatcher.dispatch(pending, self, Instant::now());
        }
        self.dispatcher = dispatcher;
    }
    #[allow(clippy::too_many_lines)] // Keep the apply writer lifetime and reattachment boundary visible.
    fn operation(
        &mut self,
        op: scupper_proto::Op,
        uid: u32,
    ) -> Result<scupper_proto::OpResult, scupper_proto::ApiError> {
        use scupper_proto::{ApiErrorCode, Op, OpResult};
        if !control::authorized(uid) {
            return Err(control::api(ApiErrorCode::Unauthorized));
        }
        let deps = self.deps();
        if let Op::Commit {
            parent,
            toml,
            reason,
        } = op
        {
            return admin::commit(&deps, &self.audit.handle(), parent, &toml, reason, uid);
        }
        if let Op::Apply { version, dry_run } = op {
            let _keepalive = notify::ApplyKeepalive::start();
            let guard =
                crate::lock::WriterLock::acquire_timeout(deps.run_root, Duration::from_secs(2))
                    .map_err(|_| control::api(ApiErrorCode::Conflict))?;
            // Resolve request errors before persisting latch or resetting runtime state.
            if let Some(target) = version {
                VersionStore::read_only(deps.state_root, deps.config_root)
                    .read(target)
                    .map_err(admin::store_error)?;
            }
            if !dry_run && let Some((machine, _, _)) = &mut self.running {
                machine
                    .preserve_latch_locked(&guard)
                    .map_err(|_| control::api(ApiErrorCode::PersistenceUnavailable))?;
            }
            let target = match version {
                Some(version) => Some(version),
                None => VersionStore::read_only(deps.state_root, deps.config_root)
                    .head()
                    .map_err(|_| control::api(ApiErrorCode::Internal))?,
            };
            let prefix = if dry_run {
                admin::preview_locked(&deps, &guard, target)?
            } else {
                Vec::new()
            };
            if !dry_run
                && !self
                    .heartbeat
                    .drain_checks(Instant::now() + Duration::from_secs(20))
            {
                return Err(control::api(ApiErrorCode::Timeout));
            }
            if !dry_run {
                self.begin_operation(scupper_proto::OperationKind::Apply, target);
            }
            let (mut result, touched) =
                admin::apply_tracked(&deps, &self.audit.handle(), &guard, version, dry_run, uid);
            if touched {
                self.abandon_probes();
                self.startup_read = StartupRead::default();
                self.running = if result
                    .as_ref()
                    .is_err_and(|error| error.code == ApiErrorCode::RollbackFailed)
                {
                    None
                } else {
                    initialize(
                        deps,
                        self.gateway.clone(),
                        self.audit.handle(),
                        self.origin,
                        Instant::now() + canon::CANON_TIMEOUT + crate::system::EXEC_TIMEOUT,
                        &mut self.startup_read,
                        Some((&guard, true)),
                    )
                    .ok()
                };
                if self.running.is_none() {
                    close_only(&deps, self.options);
                }
                self.cached = None;
                self.last_complete = None;
                self.publish_snapshot();
            }
            if let Ok(OpResult::Apply { repair_plan, .. }) = &mut result {
                *repair_plan = prefix;
            }
            self.end_operation();
            return result;
        }
        if matches!(op, Op::RepairClear { .. }) && self.running.is_none() {
            admin::durable_intent(&deps, &op, uid)?;
            let _ = self.audit.handle().emit(
                EventKind::AdminAction {
                    reason: if let Op::RepairClear { reason } = &op {
                        reason.clone()
                    } else {
                        None
                    },
                    command: scupper_proto::Command::RepairClear,
                },
                Actor::Local { uid },
                None,
            );
            return Ok(OpResult::RepairClear {});
        }
        if matches!(op, Op::RepairStatus {}) && self.running.is_none() {
            return admin::repair_status(deps.state_root);
        }
        if matches!(op, Op::Status {}) {
            let (at, health, observations) = self
                .cached
                .as_ref()
                .ok_or_else(|| control::api(ApiErrorCode::SupervisorUnavailable))?;
            return Ok(OpResult::Status {
                health: health.clone(),
                age: at.elapsed().as_secs(),
                observations: observations.clone(),
                heartbeat_last_success_age: self
                    .heartbeat
                    .last_success
                    .map(|at| at.elapsed().as_secs()),
            });
        }
        let Some((machine, held, config)) = &mut self.running else {
            return Err(control::api(ApiErrorCode::SupervisorUnavailable));
        };
        let age = self.last_complete.map(|at| at.elapsed().as_secs());
        admin::execute(
            machine,
            op,
            uid,
            self.last_complete.map(|at| at.elapsed().as_secs()),
            |deadline| {
                admin::check(
                    &deps,
                    &probes::ProbeCommand(self.options.probe_binary.clone()),
                    held,
                    config,
                    deadline,
                    age,
                )
            },
        )
    }
    fn initialize_until(&mut self, deadline: Instant) {
        self.dispatcher.invalidate_admin_workers(Instant::now());
        self.last_complete = None;
        self.cached = None;
        self.running = match initialize(
            self.deps(),
            self.gateway.clone(),
            self.audit.handle(),
            self.origin,
            deadline,
            &mut self.startup_read,
            None,
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
        self.publish_snapshot();
    }
}
impl DaemonDeps for Runtime<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn control_requests(&mut self) {
        Runtime::control_requests(self);
    }
    fn started(&mut self) {
        if self.running.is_none() {
            return;
        }
        if let Err(error) = self.notify.started() {
            eprintln!("scupperd: notify: {error}");
        }
        if !self.started_event {
            self.started_event = true;
            let _ = self.audit.handle().emit(
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
        }
    }
    fn notify(&mut self, iteration: &Iteration) {
        self.snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current_iteration = None;
        if iteration.complete && self.running.is_some() {
            self.last_complete = Some(Instant::now());
        }
        self.publish_snapshot();
        self.heartbeat_iteration(false);
        let Some((machine, _, _)) = &self.running else {
            return;
        };
        let status = if machine.unconfirmed() {
            "unconfirmed; reconciling"
        } else {
            iteration.status
        };
        if let Err(error) = self.notify.iteration(iteration.bounded, status) {
            eprintln!("scupperd: notify: {error}");
        }
    }
    fn heartbeat(&mut self) {
        self.heartbeat_iteration(true);
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
        self.heartbeat.abandon_check();
        self.probes = probes::Probes::new(self.options.probe_binary.clone(), Instant::now())
            .with_uplink(uplink_addresses(self.system).unwrap_or_default());
    }
    fn rebuild(&mut self) {
        if !self
            .heartbeat
            .drain_checks(Instant::now() + Duration::from_secs(20))
        {
            self.heartbeat_failed_deadline();
            return;
        }
        self.begin_operation(scupper_proto::OperationKind::Rebuild, None);
        let deps = self.deps();
        let report = if let Some((machine, _, _)) = &mut self.running {
            machine.rebuild(&deps).ok()
        } else {
            Some(boot::boot(&deps))
        };
        if report.is_some_and(|report| report.succeeded()) {
            self.initialize();
        }
        self.end_operation();
    }
    fn maintenance(&mut self) {
        if let Err(error) = canon::refresh_tool_facts(self.system, Instant::now()) {
            eprintln!("scupperd: canonical tool identity: {error}");
        }
    }
    #[allow(clippy::too_many_lines)]
    fn tick(&mut self, stop: &AtomicBool) -> Option<crate::reconcile::TickReport> {
        let now = Instant::now();
        self.snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current_iteration = Some(now);
        #[cfg(feature = "testing")]
        if self.options.run_root.join("incomplete-tick").exists() {
            return Some(crate::reconcile::TickReport::default());
        }
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
            if let Some(verdict) = machine.verdict() {
                let (at, kernel) = machine.cached_observation().map_or_else(
                    || (Instant::now(), None),
                    |(at, observation)| (at, Some(observation)),
                );
                self.cached = Some((
                    at,
                    scupper_proto::HealthSummary {
                        verdict,
                        at: UnixSeconds(unix()),
                        config_version: config.stamp.version,
                        warnings: 0,
                    },
                    scupper_proto::TickObservation {
                        complete: report.complete,
                        safety_ms: report.safety_ms,
                        steps: report
                            .steps
                            .iter()
                            .map(scupper_proto::StepKind::from)
                            .collect(),
                        kernel,
                        failed_steps: report
                            .failures
                            .iter()
                            .map(|(step, _)| scupper_proto::StepKind::from(step))
                            .collect(),
                    },
                ));
            }
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

// Fault injection is confined to testing builds and still executes real boot.
#[cfg(feature = "testing")]
#[allow(clippy::needless_pass_by_value)] // Boot hook signature owns its checkpoint.
fn testing_boot_hook(point: boot::BootPoint) -> Result<(), String> {
    let label = match &point {
        boot::BootPoint::After(step) => (*step as u8).to_string(),
        boot::BootPoint::LinkAdded(name) => format!("link-add-{name}"),
    };
    if std::env::var("SCUPPER_TEST_BOOT_POINT").ok().as_deref() == Some(&label) {
        let marker =
            std::env::var_os("SCUPPER_TEST_BOOT_MARKER").ok_or("missing boot marker path")?;
        boot::testing_checkpoint(Path::new(&marker), &point)?;
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL)
            .map_err(|e| e.to_string())?;
        return Err("injected daemon boot crash".into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn daemon_run_waits_for_lease_and_sends_status_before_reading_config() {
        use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
                PathBuf::from,
            )
            .join(format!("run-lease-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        // Directory fd keeps sockaddr_un within its platform limit.
        let dir = std::fs::File::open(&root).unwrap();
        let path = PathBuf::from(format!("/proc/self/fd/{}/notify", dir.as_raw_fd()));
        let socket = UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let lease = crate::lock::SupervisorLease::try_acquire(&root).unwrap();
        let options = Options {
            run_root: PathBuf::from(format!("/proc/self/fd/{}/.", dir.as_raw_fd())),
            config_root: root.join("missing"),
            state_root: root.join("state"),
            probe_binary: root.join("unused"),
        };
        let notify = notify::Notify::new(Some(path.as_os_str())).unwrap();
        let (send, receive) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _ = send.send(run_notified(&options, &AtomicBool::new(false), notify));
        });
        let mut buf = [0; 256];
        let count = socket.recv(&mut buf).unwrap();
        assert!(
            std::str::from_utf8(&buf[..count])
                .unwrap()
                .starts_with("STATUS=waiting for supervisor lease")
        );
        assert!(
            receive.try_recv().is_err(),
            "run exited while its lease was held"
        );
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        assert!(
            socket.recv(&mut buf).is_err(),
            "lease notices flooded the socket"
        );
        drop(lease);
        // The first post-lease operation now reaches the deliberately missing config.
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        worker.join().unwrap();
        assert!(!root.join("state").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hung_audit_open_reports_after_bound_and_can_still_recover() {
        let now = Instant::now();
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
            .join("audit-open-bound")
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
            .join("production-initialize")
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
                None,
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
            .join("startup-read-bound")
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

/// Integration boundary for exercising the production dispatcher and runtime.
#[cfg(feature = "testing")]
pub mod testing {
    use super::{
        Audit, BootDeps, DaemonDeps, Duration, EventKind, EventLog, GatewayId, Instant, Options,
        Runtime, StartupRead, UnixSeconds, control, io, mpsc, notify, pending, probes, unix,
    };
    /// Drives one apply through the real runtime using injected kernel I/O.
    /// Returns the response, Ping before/after, retained completion age, and next tick.
    /// # Errors
    /// Returns fixture initialization or channel failures.
    #[allow(clippy::too_many_lines, clippy::type_complexity)]
    pub fn dispatch_apply(
        deps: BootDeps<'_>,
        version: u64,
    ) -> io::Result<(
        scupper_proto::Response,
        scupper_proto::OpResult,
        scupper_proto::OpResult,
        bool,
        crate::reconcile::TickReport,
    )> {
        let options = Options {
            state_root: deps.state_root.into(),
            config_root: deps.config_root.into(),
            run_root: deps.run_root.into(),
            probe_binary: deps.run_root.join("unused-probe"),
        };
        let mut runtime = runtime(deps, &options)?;
        let origin = runtime.origin;
        runtime.last_complete = Some(origin);
        runtime.publish_snapshot();
        let before = runtime
            .snapshot
            .read()
            .map_err(|_| io::Error::other("snapshot poisoned"))?
            .ping
            .clone()
            .ok_or_else(|| io::Error::other("no Ping"))?;
        let (reply, receive) = mpsc::sync_channel(1);
        let mut dispatcher = pending::Dispatcher::default();
        dispatcher.dispatch(
            control::Pending {
                request: control::request(scupper_proto::Op::Apply {
                    version: Some(version),
                    dry_run: false,
                }),
                uid: 0,
                until: origin + Duration::from_secs(10),
                reply,
                peer: None,
            },
            &mut runtime,
            origin,
        );
        let response = receive
            .recv_timeout(Duration::from_secs(10))
            .map_err(io::Error::other)?;
        let after = runtime
            .snapshot
            .read()
            .map_err(|_| io::Error::other("snapshot poisoned"))?
            .ping
            .clone()
            .ok_or_else(|| io::Error::other("runtime lost attachment"))?;
        let retained_completion = runtime.last_complete == Some(origin);
        let tick = runtime
            .running
            .as_mut()
            .ok_or_else(|| io::Error::other("no machine"))?
            .0
            .tick();
        Ok((response, before, after, retained_completion, tick))
    }
    fn runtime<'a>(deps: BootDeps<'a>, options: &'a Options) -> io::Result<Runtime<'a>> {
        let origin = Instant::now();
        let gateway = GatewayId("gw1".into());
        let audit =
            Audit::open(deps.state_root, gateway.clone(), origin).map_err(io::Error::other)?;
        let mut runtime = Runtime {
            options,
            system: deps.system,
            namespace: deps.namespace,
            secret_owner: deps.secret_owner,
            gateway,
            origin,
            audit,
            notify: notify::Notify::disabled(),
            started_event: false,
            running: None,
            pending_canon: false,
            startup_read: StartupRead::default(),
            probes: probes::Probes::new(options.probe_binary.clone(), origin),
            setup_at: None,
            setup_rounds: 0,
            edge_logged: false,
            control: None,
            binding: None,
            bind_retry: origin,
            control_errors: control::FailureSummary::default(),
            dispatcher: pending::Dispatcher::default(),
            last_complete: None,
            heartbeat: crate::daemon::heartbeat::Heartbeat::default(),
            snapshot: control::SharedSnapshot::default(),
            cached: None,
        };
        runtime.initialize_until(origin + Duration::from_secs(5));
        if runtime.running.is_none() {
            return Err(io::Error::other("fixture runtime did not initialize"));
        }
        Ok(runtime)
    }

    /// Counts startup audit events after two READY writes to a missing socket.
    /// # Errors
    /// Returns fixture initialization or audit persistence failures.
    pub fn started_with_broken_notify(deps: BootDeps<'_>) -> io::Result<usize> {
        let options = Options {
            state_root: deps.state_root.into(),
            config_root: deps.config_root.into(),
            run_root: deps.run_root.into(),
            probe_binary: deps.run_root.join("unused-probe"),
        };
        let mut runtime = runtime(deps, &options)?;
        // Short and never created: the fixture root may exceed the 108-byte `sun_path` limit.
        let missing = std::path::PathBuf::from(format!(
            "/tmp/scupper-missing-notify-{}.sock",
            std::process::id()
        ));
        runtime.notify = notify::Notify::new(Some(missing.as_os_str()))?;
        runtime.started();
        runtime.started();
        let root = deps.state_root.join("started-audit");
        let disk = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(unix()))
            .map_err(io::Error::other)?;
        runtime
            .audit
            .handle()
            .replay_into(&disk.handle)
            .map_err(io::Error::other)?;
        disk.handle.flush_blocking(Duration::from_secs(5))?;
        let events = crate::events::read_since(&root, 0, None).collect::<io::Result<Vec<_>>>()?;
        Ok(events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::DaemonStarted { .. }))
            .count())
    }
}
