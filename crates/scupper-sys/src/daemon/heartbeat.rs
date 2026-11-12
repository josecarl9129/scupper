//! Fresh heartbeat checks and bounded delivery run outside the watchdog loop.
use super::{Runtime, admin, probes};
use crate::{
    boot::{BootDeps, GatewayNamespace},
    heartbeat::{self, Failure, Request},
    system::RealSystem,
};
use scupper_core::{
    failover::MonoTime,
    heartbeat::{CompleteIteration, Decision, SkipReason, decide},
};
use scupper_proto::{Actor, EventKind, Reason};
use std::{
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

// Detached checks retain only a completion handle; at most this many may live.
const MAX_DETACHED_CHECKS: usize = 4;

struct Checked {
    at: Instant,
    version: u64,
    code: u8,
    reason: scupper_proto::ObjectKind,
    full_fresh_check: bool,
    namespace: (u64, u64),
}

#[derive(Default)]
pub(super) struct Heartbeat {
    check_at: Option<Instant>,
    verdict: Option<scupper_proto::VerdictCode>,
    pub(super) verdict_events: Vec<EventKind>,
    check: Option<Receiver<Checked>>,
    sending: Option<Receiver<Result<Instant, Failure>>>,
    sending_deadline: Option<Instant>,
    last_send: Option<Instant>,
    workers: Vec<std::thread::JoinHandle<()>>,
    detached: Vec<std::thread::JoinHandle<()>>,
    pending_detached: usize,
    last_stale: Option<Instant>,
    pub(super) last_success: Option<Instant>,
}
impl Heartbeat {
    pub(super) fn record_verdict(&mut self, code: u8, reason: scupper_proto::ObjectKind) {
        use scupper_proto::VerdictCode as V;
        let to = match code {
            0 => V::Protected,
            2 => V::Unprotected,
            _ => return,
        };
        let from = self.verdict.unwrap_or(V::ObservationError);
        if from != to {
            self.verdict_events
                .push(EventKind::CheckVerdictChanged { from, to, reason });
        }
        self.verdict = Some(to);
    }
    pub(super) fn abandon_check(&mut self) {
        self.check = None;
        self.check_at = None;
    }
    // Shared by the real runtime and fake-clock tests. All eligibility and
    // cadence decisions live here; only starting work is delegated to Runtime.
    #[allow(clippy::too_many_lines)] // Coordinate fresh protection checks and the independent delivery cadence.
    fn iteration(
        &mut self,
        now: Instant,
        origin: Instant,
        complete: bool,
        context: Option<Context<'_>>,
    ) -> Option<Work> {
        if !complete {
            return None;
        }
        let Some(context) = context else {
            self.abandon_check();
            self.detach_workers();
            return None;
        };
        if let Some(checked) = self.checked() {
            if checked.version != context.version || checked.namespace != context.namespace {
                // Replaced observations do not consume a new configuration's
                // cadence slot. Schedule its check from the last attempt.
                self.check_at = None;
            }
            if checked.version == context.version
                && checked.namespace == context.namespace
                && self.sending.is_none()
            {
                if checked.full_fresh_check
                    && now.saturating_duration_since(checked.at) < Duration::from_secs(30)
                {
                    self.record_verdict(checked.code, checked.reason);
                }
                let mono = |at: Instant| MonoTime(at.saturating_duration_since(origin));
                let decision =
                    context
                        .settings
                        .map_or(Decision::Skip(SkipReason::NotHealthy), |settings| {
                            decide(
                                settings,
                                mono(now),
                                Some(CompleteIteration {
                                    at: mono(checked.at),
                                    full_fresh_check: checked.full_fresh_check,
                                    code: checked.code,
                                }),
                                self.last_send.map(mono),
                            )
                        });
                if checked.code == 0
                    && matches!(decision, Decision::Skip(SkipReason::Stale))
                    && self.last_stale.is_none_or(|at| {
                        now.saturating_duration_since(at) >= Duration::from_secs(60)
                    })
                {
                    self.last_stale = Some(now);
                    return Some(Work::Stale);
                }
                if let Decision::Send {
                    url_suffix,
                    deadline,
                } = decision
                {
                    self.last_send = Some(now);
                    self.sending_deadline = Some(origin + deadline.0);
                    return Some(Work::Send {
                        suffix: url_suffix,
                        deadline: origin + deadline.0,
                    });
                }
            }
        }
        let interval = context
            .settings
            .map_or(Duration::from_secs(60), |settings| {
                settings.interval.duration().unwrap_or(Duration::MAX)
            })
            .min(if context.alerts {
                Duration::from_secs(60)
            } else {
                Duration::MAX
            });
        // One cadence source: checks become due from the last attempt. check_at
        // only throttles suppressed/failed checks, never an eligible next beat.
        let due = self.last_send.map_or_else(
            || {
                self.check_at
                    .is_none_or(|last| now.saturating_duration_since(last) >= interval)
            },
            |last| {
                now.saturating_duration_since(last) >= interval
                    && self.check_at.is_none_or(|at| {
                        at <= last || now.saturating_duration_since(at) >= interval
                    })
            },
        );
        if self.check.is_none() && self.sending.is_none() && due {
            self.check_at = Some(now);
            self.detached.retain(|worker| !worker.is_finished());
            if self.detached.len() >= MAX_DETACHED_CHECKS {
                return Some(Work::WorkerLimit);
            }
            return Some(Work::Check);
        }
        None
    }
    fn expire(&mut self, now: Instant) -> Option<Failure> {
        let check_stuck = self.check.is_some()
            && self
                .check_at
                .is_some_and(|at| now >= at + Duration::from_secs(40));
        let send_stuck = self.sending.is_some()
            && self
                .sending_deadline
                .is_some_and(|at| now >= at + Duration::from_secs(10));
        if check_stuck {
            self.abandon_check();
            self.detach_workers();
        }
        if send_stuck {
            self.sending = None;
            self.sending_deadline = None;
        }
        (check_stuck || send_stuck).then_some(Failure::Deadline)
    }
    // Only read-only workers are detached. Their receiver is closed first, so
    // late results cannot authorize delivery or block replacement of a namespace.
    // This runs before charging a boot, with a small independent drain budget.
    pub(super) fn drain_checks(&mut self) {
        self.abandon_check();
        let deadline = Instant::now() + Duration::from_millis(50);
        loop {
            self.workers.retain(|worker| !worker.is_finished());
            if self.workers.is_empty() || Instant::now() >= deadline {
                self.detach_workers();
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn detach_workers(&mut self) {
        self.workers.retain(|worker| !worker.is_finished());
        self.detached.retain(|worker| !worker.is_finished());
        self.pending_detached += self.workers.len();
        self.detached.append(&mut self.workers);
    }
    pub(super) fn report_events(&mut self, log: &crate::events::LogHandle, version: Option<u64>) {
        for event in self.verdict_events.drain(..) {
            let _ = log.emit(event, Actor::Daemon, version);
        }
        for _ in 0..std::mem::take(&mut self.pending_detached) {
            let _ = log.emit(EventKind::HeartbeatCheckDetached {}, Actor::Daemon, version);
        }
    }
    fn checked(&mut self) -> Option<Checked> {
        let receive = self.check.as_ref()?;
        match receive.try_recv() {
            Ok(checked) => {
                self.check = None;
                Some(checked)
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.check = None;
                None
            }
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }
    fn collect(&mut self) -> Option<Failure> {
        let receive = self.sending.as_ref()?;
        match receive.try_recv() {
            Ok(result) => {
                self.sending = None;
                match result {
                    Ok(at) => {
                        self.last_success = Some(at);
                        None
                    }
                    Err(reason) => Some(reason),
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.sending = None;
                Some(Failure::Internal)
            }
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }
}
struct Context<'a> {
    settings: Option<&'a scupper_core::config::HeartbeatSettings>,
    alerts: bool,
    version: u64,
    namespace: (u64, u64),
}
enum Work {
    Check,
    WorkerLimit,
    Stale,
    Send { suffix: String, deadline: Instant },
}
pub(super) fn protection_reason(
    verdict: &scupper_core::verdict::v2::Verdict,
) -> scupper_proto::ObjectKind {
    use scupper_core::verdict::v2::{Verdict, Violation};
    use scupper_proto::ObjectKind as O;
    let Verdict::Unprotected(violations) = verdict else {
        return O::Unknown;
    };
    match &violations.as_slice()[0] {
        Violation::RulesetMissing | Violation::RulesetDiffers { .. } => O::Ruleset,
        Violation::ForeignLink(_) | Violation::LinkKind(_) => O::ForeignLink,
        Violation::TrafficControlHook(_) => O::TcHook,
        Violation::PeerDiffers { .. } => O::Peer,
        Violation::ExitIpIsUplinkAddress(_) => O::ExitIp,
        _ => O::Unknown,
    }
}
fn failure_event(failure: Failure) -> EventKind {
    let reason = match failure {
        Failure::Secret => Reason::HeartbeatSecret,
        Failure::Account => Reason::HeartbeatAccount,
        Failure::Http | Failure::Permanent => Reason::HeartbeatHttp,
        Failure::Deadline => Reason::HeartbeatDeadline,
        Failure::Internal => Reason::ExecutionFailed,
        Failure::Exec => Reason::HeartbeatExec,
        Failure::Tls => Reason::HeartbeatTls,
        Failure::Transport => Reason::HeartbeatTransport,
        Failure::RtoRead => Reason::HeartbeatRtoRead,
        Failure::WriteRefused => Reason::HeartbeatWriteRefused,
        Failure::Reset => Reason::HeartbeatReset,
        Failure::Certificate => Reason::HeartbeatCertificate,
    };
    EventKind::HeartbeatFailed { reason }
}
impl Runtime<'_> {
    fn heartbeat_failed(&self, failure: Failure) {
        eprintln!("scupperd: warning: {failure}");
        let _ = self.audit.handle().emit(
            failure_event(failure),
            Actor::Daemon,
            self.running.as_ref().map(|(_, _, cfg)| cfg.stamp.version),
        );
    }
    pub(super) fn heartbeat_iteration(&mut self, complete: bool) {
        if let Some(failure) = self.heartbeat.collect() {
            self.heartbeat_failed(failure);
        }
        let now = Instant::now();
        if let Some(failure) = self.heartbeat.expire(now) {
            self.heartbeat_failed(failure);
        }
        // Alert protection checks run even without an external heartbeat.
        let context = self.running.as_ref().and_then(|(_, held, config)| {
            let settings = config.site.heartbeat();
            let alerts = !config.site.sinks().is_empty();
            (settings.is_some() || alerts).then_some(Context {
                settings,
                alerts,
                version: config.stamp.version,
                namespace: held.identity(),
            })
        });
        let work = self
            .heartbeat
            .iteration(now, self.origin, complete, context);
        self.heartbeat.report_events(
            &self.audit.handle(),
            self.running.as_ref().map(|(_, _, cfg)| cfg.stamp.version),
        );
        match work {
            Some(Work::WorkerLimit) => {
                let _ = self.audit.handle().emit(
                    EventKind::HeartbeatSkipped {
                        reason: Reason::HeartbeatWorkerLimit,
                    },
                    Actor::Daemon,
                    self.running.as_ref().map(|(_, _, cfg)| cfg.stamp.version),
                );
            }
            Some(Work::Stale) => {
                eprintln!("scupperd: info: heartbeat skipped: stale verdict");
                let _ = self.audit.handle().emit(
                    EventKind::HeartbeatSkipped {
                        reason: Reason::Stale,
                    },
                    Actor::Daemon,
                    self.running.as_ref().map(|(_, _, cfg)| cfg.stamp.version),
                );
            }
            Some(Work::Send { suffix, deadline }) => {
                if let Some((_, _, config)) = &self.running
                    && let Some(settings) = config.site.heartbeat()
                {
                    self.launch_heartbeat(settings.url_ref.clone(), suffix, deadline);
                }
            }
            Some(Work::Check) => {
                if let Some((_, held, config)) = &self.running {
                    self.start_heartbeat_check(now, held.clone(), config.clone());
                }
            }
            None => {}
        }
    }
    fn start_heartbeat_check(
        &mut self,
        now: Instant,
        held: std::sync::Arc<crate::netns::NetnsHandle>,
        config: crate::reconcile::Config,
    ) {
        self.heartbeat.check_at = Some(now);
        let (send, receive) = mpsc::sync_channel(1);
        self.heartbeat.check = Some(receive);
        let binary = self.options.probe_binary.clone();
        let run_root = self.options.run_root.clone();
        let state_root = self.options.state_root.clone();
        let config_root = self.options.config_root.clone();
        let snapshot = self.snapshot.clone();
        let result = std::thread::Builder::new()
            .name("scupper-heartbeat-check".into())
            .spawn(move || {
                let system =
                    RealSystem::default().with_canon_paths(binary.clone(), run_root.clone());
                let deps = BootDeps {
                    system: &system,
                    namespace: &GatewayNamespace,
                    run_root: &run_root,
                    state_root: &state_root,
                    config_root: &config_root,
                    #[cfg(feature = "testing")]
                    hook: None,
                    #[cfg(feature = "testing")]
                    secret_owner: 0,
                };
                let deadline = now + Duration::from_secs(20);
                let result = admin::check_live(
                    &deps,
                    &probes::ProbeCommand(binary),
                    &held,
                    &config,
                    Some(deadline),
                    &|| {
                        snapshot
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .last_complete
                    },
                );
                let reason = result
                    .as_ref()
                    .map_or(scupper_proto::ObjectKind::Unknown, |report| {
                        protection_reason(&report.verdict)
                    });
                let code = result.map_or(1, |report| report.verdict.exit_code());
                #[cfg(feature = "testing")]
                let code = std::fs::read_to_string(run_root.join("heartbeat-test-code"))
                    .ok()
                    .and_then(|value| value.parse::<u8>().ok())
                    .unwrap_or(code);
                let _ = send.send(Checked {
                    at: now,
                    version: config.stamp.version,
                    code,
                    reason,
                    full_fresh_check: Instant::now() < deadline,
                    namespace: held.identity(),
                });
            });
        if let Ok(worker) = result {
            self.heartbeat
                .workers
                .retain(|worker| !worker.is_finished());
            self.heartbeat.workers.push(worker);
        } else {
            self.heartbeat.check = None;
            self.heartbeat_failed(Failure::Internal);
        }
    }
    fn launch_heartbeat(
        &mut self,
        reference: scupper_core::config::SecretName,
        suffix: String,
        deadline: Instant,
    ) {
        let config_root = self.options.config_root.clone();
        let binary = self.options.probe_binary.clone();
        #[cfg(feature = "testing")]
        let run_root = self.options.run_root.clone();
        #[cfg(feature = "testing")]
        let owner = self.secret_owner;
        #[cfg(not(feature = "testing"))]
        let owner = 0;
        // Absolute monotonic timestamp is captured BEFORE any spawn or secret I/O.
        let monotonic = heartbeat::monotonic_ns();
        let deadline_ns = monotonic.saturating_add(
            u64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_nanos(),
            )
            .unwrap_or(0),
        );
        let (send, receive) = mpsc::sync_channel(1);
        self.heartbeat.sending = Some(receive);
        let result = std::thread::Builder::new()
            .name("scupper-heartbeat-wait".into())
            .spawn(move || {
                let result = heartbeat::retry_deadline(deadline_ns, || {
                    let url = heartbeat::resolve(&config_root, &reference, &suffix, owner)?;
                    let passwd =
                        std::fs::read_to_string("/etc/passwd").map_err(|_| Failure::Account)?;
                    let group =
                        std::fs::read_to_string("/etc/group").map_err(|_| Failure::Account)?;
                    let identity = heartbeat::account(&passwd, &group)?;
                    let request = Request::new(url.expose(), deadline_ns)?;
                    #[cfg(feature = "testing")]
                    let request = {
                        let mut request = request;
                        let hold = run_root
                            .parent()
                            .and_then(std::path::Path::parent)
                            .unwrap_or(&run_root)
                            .join("heartbeat-request-pause");
                        if hold.exists() {
                            request.test_hold = Some(hold);
                        }
                        request
                    };
                    #[cfg(feature = "testing")]
                    {
                        use std::io::Write;
                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(run_root.join("heartbeat-trace.jsonl"))
                        {
                            let _ = writeln!(
                                file,
                                "{}",
                                serde_json::json!({"suffix":suffix,"deadline_ns":deadline_ns})
                            );
                        }
                        while run_root.join("heartbeat-pause").exists()
                            && heartbeat::monotonic_ns() < deadline_ns
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    heartbeat::attempt(&binary, &request, identity)
                })
                .map(|()| Instant::now());
                let _ = send.send(result);
            });
        if result.is_err() {
            self.heartbeat.sending = None;
            self.heartbeat_failed(Failure::Internal);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings(report: &str, interval: u64) -> scupper_core::config::HeartbeatSettings {
        serde_json::from_value(serde_json::json!({"kind":"healthchecks", "url_ref":"test", "interval":format!("{interval}s"), "report":report})).unwrap()
    }
    fn context(settings: &scupper_core::config::HeartbeatSettings) -> Context<'_> {
        Context {
            settings: Some(settings),
            alerts: false,
            version: 1,
            namespace: (2, 3),
        }
    }
    fn queue(state: &mut Heartbeat, at: Instant, code: u8, fresh: bool) {
        let (send, receive) = mpsc::sync_channel(1);
        state.check_at = Some(at);
        state.check = Some(receive);
        send.send(Checked {
            at,
            code,
            reason: scupper_proto::ObjectKind::Unknown,
            full_fresh_check: fresh,
            version: 1,
            namespace: (2, 3),
        })
        .unwrap();
    }
    #[test]
    fn alert_only_configuration_runs_fresh_checks_and_reports_protection() {
        let now = Instant::now();
        let mut state = Heartbeat::default();
        let context = || Context {
            settings: None,
            alerts: true,
            version: 1,
            namespace: (2, 3),
        };
        assert!(matches!(
            state.iteration(now, now, true, Some(context())),
            Some(Work::Check)
        ));
        queue(&mut state, now, 2, true);
        state.iteration(now, now, true, Some(context()));
        assert!(matches!(
            state.verdict_events.as_slice(),
            [EventKind::CheckVerdictChanged {
                to: scupper_proto::VerdictCode::Unprotected,
                ..
            }]
        ));
        assert_eq!(state.last_send, None);
        assert!(matches!(
            state.iteration(now + Duration::from_secs(60), now, true, Some(context())),
            Some(Work::Check)
        ));
    }
    #[test]
    fn stuck_read_only_worker_does_not_veto_or_delay_repair() {
        let (started, ready) = mpsc::sync_channel(1);
        let mut state = Heartbeat::default();
        state.workers.push(std::thread::spawn(move || {
            started.send(()).unwrap();
            loop {
                std::thread::park();
            }
        }));
        ready.recv().unwrap();
        let before = Instant::now();
        state.drain_checks();
        assert!(before.elapsed() < Duration::from_millis(500));
        assert!(state.workers.is_empty());
        assert!(state.check.is_none());
    }
    #[test]
    fn detached_checks_are_bounded_audited_and_capacity_recovers() {
        use crate::events::{EventLog, read_since};
        use scupper_core::config::GatewayId;
        use scupper_proto::UnixSeconds;
        let root =
            std::env::temp_dir().join(format!("heartbeat-worker-cap-{}", std::process::id()));
        let log = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
        let origin = Instant::now();
        let mut state = Heartbeat::default();
        let cfg = settings("ok_only", 10);
        let mut release = Vec::new();
        for i in 0..MAX_DETACHED_CHECKS {
            let now = origin + Duration::from_secs(u64::try_from(i).unwrap() * 60);
            assert!(matches!(
                state.iteration(now, origin, true, Some(context(&cfg))),
                Some(Work::Check)
            ));
            let (send, recv) = mpsc::channel();
            state.workers.push(std::thread::spawn(move || {
                let _ = recv.recv();
            }));
            release.push(send);
            let (_send, recv) = mpsc::sync_channel(1);
            state.check = Some(recv);
            if i % 2 == 0 {
                assert_eq!(
                    state.expire(now + Duration::from_secs(40)),
                    Some(Failure::Deadline)
                );
            } else {
                state.drain_checks();
            }
            assert_eq!(state.detached.len(), i + 1);
            state.report_events(&log.handle, Some(1));
        }
        let now = origin + Duration::from_secs(300);
        assert!(matches!(
            state.iteration(now, origin, true, Some(context(&cfg))),
            Some(Work::WorkerLimit)
        ));
        assert!(state.check.is_none());
        assert!(
            state
                .iteration(
                    now + Duration::from_secs(1),
                    origin,
                    true,
                    Some(context(&cfg))
                )
                .is_none()
        );
        // Re-reporting never duplicates detach events.
        state.report_events(&log.handle, Some(1));
        log.handle.flush_blocking(Duration::from_secs(2)).unwrap();
        let events: Vec<_> = read_since(&root, 0, None).map(Result::unwrap).collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.kind, EventKind::HeartbeatCheckDetached {}))
                .count(),
            MAX_DETACHED_CHECKS
        );
        release.remove(0).send(()).unwrap();
        let finished_by = Instant::now() + Duration::from_secs(2);
        while !state.detached[0].is_finished() {
            assert!(Instant::now() < finished_by);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            state.iteration(
                now + Duration::from_secs(10),
                origin,
                true,
                Some(context(&cfg))
            ),
            Some(Work::Check)
        ));
        assert_eq!(state.detached.len(), MAX_DETACHED_CHECKS - 1);
        drop(release);
        for worker in state.detached {
            worker.join().unwrap();
        }
        drop(log);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[cfg(feature = "testing")]
    #[allow(clippy::too_many_lines)] // Complete scheduler and worker fault fixture.
    fn fake_kernel_stuck_worker_drains_before_charge_and_rebuild_continues() {
        use crate::{
            daemon::{DaemonDeps, Iteration, run_with},
            reconcile::{Escalation, Kernel, TickReport, fake::FakeKernel},
        };
        use scupper_core::{
            config::{GatewayId, parse_site, validate},
            planner::{Desired, Step},
            render::{RouteTarget, VersionStamp},
            verdict::v2::Selection,
        };
        use std::{
            path::{Path, PathBuf},
            sync::atomic::{AtomicBool, Ordering},
        };
        struct Rig<'a> {
            heartbeat: Heartbeat,
            kernel: FakeKernel,
            root: PathBuf,
            stop: &'a AtomicBool,
            began: Instant,
            drained: bool,
            rebuilt: bool,
        }
        impl DaemonDeps for Rig<'_> {
            fn now(&self) -> Instant {
                Instant::now()
            }
            fn sleep(&mut self, _: Duration) {}
            fn started(&mut self) {}
            fn initialize(&mut self) {}
            fn tick(&mut self, _: &AtomicBool) -> Option<TickReport> {
                Some(TickReport {
                    escalations: vec![Escalation::RebuildRequired],
                    ..TickReport::default()
                })
            }
            fn close_only(&mut self) {}
            fn abandon_probes(&mut self) {
                assert!(!self.root.join("boot-attempts").exists());
                self.heartbeat.drain_checks();
                self.drained = true;
            }
            fn rebuild(&mut self) {
                assert!(self.drained);
                assert!(self.root.join("boot-attempts").exists());
                assert!(self.began.elapsed() < Duration::from_millis(500));
                self.kernel.execute(&Step::ForwardingOff).unwrap();
                self.rebuilt = true;
            }
            fn run_root(&self) -> &Path {
                &self.root
            }
            fn boot_time(&self) -> Duration {
                Duration::from_secs(1)
            }
            fn budget_error(&mut self, error: &std::io::Error) {
                assert_eq!(error.to_string(), "unexpected budget error");
            }
            fn maintenance(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
            }
            fn notify(&mut self, _: &Iteration) {}
            fn shutdown(&mut self) {}
        }
        let site = validate(
            parse_site(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../scupper-core/tests/fixtures/site-m2.toml"
            )))
            .unwrap(),
        )
        .unwrap();
        let desired = Desired::new(
            &site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version: 1,
                sha256: [0; 32],
            },
            [7; 32],
            &RouteTarget::Unreachable,
            &Selection::Auto,
        )
        .unwrap();
        let worker_desired = desired.clone();
        let mut heartbeat = Heartbeat::default();
        let (started, ready) = mpsc::sync_channel(1);
        heartbeat.workers.push(std::thread::spawn(move || {
            // The fake check worker observes and then stalls forever.
            let _kernel = FakeKernel::new(worker_desired);
            started.send(()).unwrap();
            loop {
                std::thread::park();
            }
        }));
        ready.recv().unwrap();
        let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp"))
            .join(format!("stuck-check-rebuild-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let stop = AtomicBool::new(false);
        let mut rig = Rig {
            heartbeat,
            kernel: FakeKernel::new(desired),
            root,
            stop: &stop,
            began: Instant::now(),
            drained: false,
            rebuilt: false,
        };
        run_with(&mut rig, &stop);
        assert!(rig.rebuilt);
        assert_eq!(rig.kernel.history().len(), 1);
        std::fs::remove_dir_all(&rig.root).unwrap();
    }
    #[test]
    fn healthy_stale_verdict_emits_rate_limited_skip() {
        let origin = Instant::now();
        let cfg = settings("ok_only", 10);
        let mut state = Heartbeat::default();
        for (second, emit) in [(10, true), (11, false), (70, true)] {
            queue(&mut state, origin, 0, true);
            let work = state.iteration(
                origin + Duration::from_secs(second),
                origin,
                true,
                Some(context(&cfg)),
            );
            assert_eq!(matches!(work, Some(Work::Stale)), emit);
        }
    }
    #[test]
    fn delivery_exclusivity_consumes_no_second_authorization() {
        let origin = Instant::now();
        let cfg = settings("status_code", 60);
        let mut state = Heartbeat::default();
        queue(&mut state, origin, 0, true);
        let (_send, receive) = mpsc::sync_channel(1);
        state.sending = Some(receive);
        assert!(
            state
                .iteration(origin, origin, true, Some(context(&cfg)))
                .is_none()
        );
        assert!(state.last_send.is_none());
    }
    #[test]
    fn healthy_cadence_with_alternating_check_durations() {
        let origin = Instant::now();
        let cfg = settings("ok_only", 60);
        let mut state = Heartbeat::default();
        let mut pending: Option<(Instant, Instant, mpsc::SyncSender<Checked>)> = None;
        let mut starts = 0;
        let mut sends = Vec::new();
        for second in (0..600).step_by(2) {
            let now = origin + Duration::from_secs(second);
            if let Some((ready, at, send)) = pending.take() {
                if now >= ready {
                    send.send(Checked {
                        at,
                        version: 1,
                        reason: scupper_proto::ObjectKind::Unknown,
                        code: 0,
                        full_fresh_check: true,
                        namespace: (2, 3),
                    })
                    .unwrap();
                } else {
                    pending = Some((ready, at, send));
                }
            }
            match state.iteration(now, origin, true, Some(context(&cfg))) {
                Some(Work::Check) => {
                    let (send, receive) = mpsc::sync_channel(1);
                    state.check = Some(receive);
                    let duration = if starts % 2 == 0 { 4 } else { 1 };
                    starts += 1;
                    pending = Some((now + Duration::from_secs(duration), now, send));
                }
                Some(Work::Send { deadline, .. }) => {
                    assert!(now < deadline);
                    sends.push(second);
                    let (send, receive) = mpsc::sync_channel(1);
                    state.sending = Some(receive);
                    send.send(Ok(now)).unwrap();
                    assert_eq!(state.collect(), None);
                }
                Some(Work::Stale | Work::WorkerLimit) | None => {}
            }
        }
        assert!(sends.len() >= 9);
        assert!(
            sends
                .windows(2)
                .all(|pair| (60..=66).contains(&(pair[1] - pair[0])))
        );
    }
    #[test]
    fn queued_results_obey_scheduler_and_generation_gates() {
        let origin = Instant::now();
        let cfg = settings("status_code", 60);
        for code in 0..=5 {
            let mut state = Heartbeat::default();
            queue(&mut state, origin, code, true);
            assert!(
                state
                    .iteration(origin, origin, false, Some(context(&cfg)))
                    .is_none()
            );
            assert!(state.check.is_some());
            let work = state.iteration(origin, origin, true, Some(context(&cfg)));
            if code <= 4 {
                assert!(
                    matches!(work, Some(Work::Send { suffix, .. }) if suffix == format!("/{code}"))
                );
            } else {
                assert!(work.is_none());
            }
        }
        let ok = settings("ok_only", 60);
        for code in 1..=5 {
            let mut state = Heartbeat::default();
            queue(&mut state, origin, code, true);
            assert!(
                state
                    .iteration(origin, origin, true, Some(context(&ok)))
                    .is_none()
            );
        }
        for (age, fresh, version, namespace) in [
            (20, false, 1, (2, 3)),
            (30, true, 1, (2, 3)),
            (0, true, 2, (2, 3)),
            (0, true, 1, (2, 4)),
        ] {
            let mut state = Heartbeat::default();
            queue(&mut state, origin, 0, fresh);
            let work = state.iteration(
                origin + Duration::from_secs(age),
                origin,
                true,
                Some(Context {
                    settings: Some(&cfg),
                    alerts: false,
                    version,
                    namespace,
                }),
            );
            assert!(!matches!(work, Some(Work::Send { .. })));
        }
        let mut state = Heartbeat::default();
        queue(&mut state, origin, 0, true);
        state.abandon_check();
        assert!(matches!(
            state.iteration(origin, origin, true, Some(context(&cfg))),
            Some(Work::Check)
        ));
        let short = settings("ok_only", 10);
        queue(&mut state, origin, 0, true);
        assert!(!matches!(
            state.iteration(
                origin + Duration::from_secs(10),
                origin,
                true,
                Some(context(&short))
            ),
            Some(Work::Send { .. })
        ));
    }
    #[test]
    fn stuck_workers_emit_deadline_once_and_allow_recovery() {
        let origin = Instant::now();
        let mut state = Heartbeat::default();
        let (_send, receive) = mpsc::sync_channel(1);
        state.check = Some(receive);
        state.check_at = Some(origin);
        assert_eq!(state.expire(origin + Duration::from_secs(39)), None);
        assert_eq!(
            state.expire(origin + Duration::from_secs(40)),
            Some(Failure::Deadline)
        );
        assert_eq!(state.expire(origin + Duration::from_secs(41)), None);
        let cfg = settings("ok_only", 60);
        assert!(matches!(
            state.iteration(
                origin + Duration::from_secs(40),
                origin,
                true,
                Some(context(&cfg))
            ),
            Some(Work::Check)
        ));
        let (_send, receive) = mpsc::sync_channel(1);
        state.sending = Some(receive);
        state.sending_deadline = Some(origin + Duration::from_secs(30));
        assert_eq!(
            state.expire(origin + Duration::from_secs(40)),
            Some(Failure::Deadline)
        );
        assert!(state.sending.is_none());
    }
    #[test]
    fn failure_events_distinguish_exec_identity_tls_http_and_transport() {
        for (failure, reason) in [
            (Failure::Exec, Reason::HeartbeatExec),
            (Failure::Account, Reason::HeartbeatAccount),
            (Failure::Tls, Reason::HeartbeatTls),
            (Failure::Http, Reason::HeartbeatHttp),
            (Failure::Transport, Reason::HeartbeatTransport),
            (Failure::Internal, Reason::ExecutionFailed),
            (Failure::RtoRead, Reason::HeartbeatRtoRead),
            (Failure::WriteRefused, Reason::HeartbeatWriteRefused),
            (Failure::Reset, Reason::HeartbeatReset),
            (Failure::Certificate, Reason::HeartbeatCertificate),
        ] {
            assert_eq!(
                failure_event(failure),
                EventKind::HeartbeatFailed { reason }
            );
        }
    }
    #[test]
    fn two_failed_attempts_produce_one_failure_then_no_repeat() {
        let mut heartbeat = Heartbeat::default();
        let (send, receive) = mpsc::sync_channel(1);
        heartbeat.sending = Some(receive);
        let mut attempts = 0;
        let result = heartbeat::retry_deadline(heartbeat::monotonic_ns() + 1_000_000_000, || {
            attempts += 1;
            Err(Failure::Http)
        });
        assert_eq!(attempts, 2);
        send.send(result.map(|()| Instant::now())).unwrap();
        let reason = heartbeat.collect().unwrap();
        assert_eq!(
            failure_event(reason),
            EventKind::HeartbeatFailed {
                reason: Reason::HeartbeatHttp
            }
        );
        assert_eq!(heartbeat.collect(), None);
        assert!(heartbeat.last_success.is_none());
    }
    #[test]
    fn success_updates_status_and_never_produces_failure() {
        let mut heartbeat = Heartbeat::default();
        let (send, receive) = mpsc::sync_channel(1);
        heartbeat.sending = Some(receive);
        let now = Instant::now();
        send.send(Ok(now)).unwrap();
        assert_eq!(heartbeat.collect(), None);
        assert_eq!(heartbeat.last_success, Some(now));
    }
}
