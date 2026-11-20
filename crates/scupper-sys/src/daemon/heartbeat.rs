//! Fresh heartbeat checks and bounded delivery run outside the watchdog loop.
use super::{Runtime, admin, probes};
use crate::{
    boot::{BootDeps, GatewayNamespace},
    heartbeat::{self, Failure, Request},
    system::RealSystem,
};
use scupper_core::{
    failover::MonoTime,
    heartbeat::{CompleteIteration, Decision, Outcome, SkipReason, decide},
};
use scupper_proto::{Actor, EventKind, HeartbeatAction, HeartbeatVerdictReason, Reason};
use std::{
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

// Detached checks retain only a completion handle; at most this many may live.
const MAX_DETACHED_CHECKS: usize = 4;

fn discard_legacy_grace(root: &std::path::Path) {
    // Obsolete, even when corrupt or unreadable. Cleanup runs in the check
    // worker, outside the watchdog; failure never gates a heartbeat.
    let _ = std::fs::remove_file(root.join("heartbeat-session-grace.json"));
    let _ = std::fs::remove_file(root.join("heartbeat-grace-writer"));
}

struct Checked {
    at: Instant,
    version: u64,
    outcome: Outcome,
    reason: scupper_proto::ObjectKind,
    full_fresh_check: bool,
    check_reason: HeartbeatVerdictReason,
    namespace: (u64, u64),
}

const CHECK_DEBOUNCE: Duration = Duration::from_secs(600);
// Count comes from the closed vocabulary; new reasons grow this fixed table
// at compile time. Invalid codes never allocate new entries.
const CHECK_REASON_SLOTS: usize = HeartbeatVerdictReason::COUNT;

#[derive(Clone, Copy, Default)]
struct CheckCounter {
    last_event: Option<Instant>,
    // Cumulative process-local observations, including suppressed observations.
    count: u64,
}
impl CheckCounter {
    fn observe(&mut self, now: Instant) -> Option<u64> {
        self.count = self.count.saturating_add(1);
        self.emit_due(now)
    }
    fn emit_due(&mut self, now: Instant) -> Option<u64> {
        if self
            .last_event
            .is_some_and(|last| now.saturating_duration_since(last) < CHECK_DEBOUNCE)
        {
            return None;
        }
        self.last_event = Some(now);
        Some(self.count)
    }
}
struct CheckHistory {
    keys: [[CheckCounter; CHECK_REASON_SLOTS]; 7],
    recovery: CheckCounter,
    failing: bool,
    recovery_pending: bool,
}
impl Default for CheckHistory {
    fn default() -> Self {
        Self {
            keys: [[CheckCounter::default(); CHECK_REASON_SLOTS]; 7],
            recovery: CheckCounter::default(),
            failing: false,
            recovery_pending: false,
        }
    }
}

#[derive(Default)]
pub(super) struct Heartbeat {
    legacy_grace_cleanup_started: bool,
    check_history: CheckHistory,
    check_at: Option<Instant>,
    verdict: Option<scupper_proto::VerdictCode>,
    pub(super) verdict_events: Vec<EventKind>,
    check: Option<Receiver<Checked>>,
    sending: Option<Receiver<Result<Delivered, Failure>>>,
    // Hold a log-class event until the worker resolves the actual request class.
    pending_log_action: Option<Receiver<HeartbeatAction>>,
    #[cfg(all(test, feature = "testing"))]
    worker_identity: Option<crate::probe_child::ProbeIdentity>,
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
    fn record_check(&mut self, now: Instant, checked: &Checked, action: HeartbeatAction) {
        if !checked.full_fresh_check {
            return;
        }
        let code = checked.outcome.code();
        if code == 0 {
            let count = if std::mem::take(&mut self.check_history.failing) {
                self.check_history.recovery_pending = true;
                self.check_history.recovery.observe(now)
            } else if self.check_history.recovery_pending {
                self.check_history.recovery.emit_due(now)
            } else {
                None
            };
            if let Some(count) = count {
                self.check_history.recovery_pending = false;
                self.verdict_events
                    .push(EventKind::HeartbeatCheckRecovered {
                        code: 0,
                        reason: HeartbeatVerdictReason::Protected,
                        action,
                        count,
                    });
            }
            return;
        }
        self.check_history.failing = true;
        let Some(counter) = self
            .check_history
            .keys
            .get_mut(usize::from(code))
            .and_then(|reasons| reasons.get_mut(checked.check_reason as usize))
        else {
            return;
        };
        if let Some(count) = counter.observe(now) {
            self.check_history.recovery_pending = false;
            self.verdict_events.push(EventKind::HeartbeatCheckVerdict {
                code,
                reason: checked.check_reason,
                action,
                count,
            });
        }
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
            if checked.version == context.version && checked.namespace == context.namespace {
                if checked.full_fresh_check
                    && now.saturating_duration_since(checked.at) < Duration::from_secs(30)
                {
                    self.record_verdict(checked.outcome.code(), checked.reason);
                }
                let mono = |at: Instant| MonoTime(at.saturating_duration_since(origin));
                let decision = context.settings.filter(|_| self.sending.is_none()).map_or(
                    Decision::Skip(SkipReason::NotHealthy),
                    |settings| {
                        decide(
                            settings,
                            mono(now),
                            Some(CompleteIteration {
                                at: mono(checked.at),
                                full_fresh_check: checked.full_fresh_check,
                                outcome: checked.outcome,
                            }),
                            self.last_send.map(mono),
                        )
                    },
                );
                let action = match &decision {
                    Decision::Log { .. } => HeartbeatAction::Log,
                    Decision::Send { .. } if checked.outcome.code() == 0 => {
                        HeartbeatAction::Success
                    }
                    Decision::Send { .. } => HeartbeatAction::Status,
                    Decision::Skip(_) => HeartbeatAction::Withheld,
                };
                self.record_check(now, &checked, action);
                if checked.outcome.code() == 0
                    && matches!(decision, Decision::Skip(SkipReason::Stale))
                    && self.last_stale.is_none_or(|at| {
                        now.saturating_duration_since(at) >= Duration::from_secs(60)
                    })
                {
                    self.last_stale = Some(now);
                    return Some(Work::Stale);
                }
                let delivery = match decision {
                    Decision::Send {
                        url_suffix,
                        deadline,
                    } => Some((url_suffix, deadline)),
                    Decision::Log { deadline } => Some(("/log".into(), deadline)),
                    Decision::Skip(_) => None,
                };
                if let Some((suffix, deadline)) = delivery {
                    self.last_send = Some(now);
                    self.sending_deadline = Some(origin + deadline.0);
                    return Some(Work::Send {
                        suffix,
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
            self.collect_log_action(true);
            self.sending = None;
            self.sending_deadline = None;
        }
        (check_stuck || send_stuck).then_some(Failure::Deadline)
    }
    // Check workers may commit session confirmations under a separate lock.
    // Their receiver is closed first, so late verdicts cannot authorize delivery.
    // Blocked storage may retain that lock, but commits carry deadline/epoch fences
    // and namespace replacement does not wait for the worker to exit.
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
        // Preserve heartbeat check ordering while resolving a possible /3
        // fallback. Protection alerts must not wait for delivery preparation.
        if self.pending_log_action.is_some() {
            let mut held = false;
            self.verdict_events.retain(|event| {
                held |= matches!(
                    event,
                    EventKind::HeartbeatCheckVerdict {
                        action: HeartbeatAction::Log,
                        ..
                    }
                );
                if held
                    && matches!(
                        event,
                        EventKind::HeartbeatCheckVerdict { .. }
                            | EventKind::HeartbeatCheckRecovered { .. }
                    )
                {
                    true
                } else {
                    let _ = log.emit(event.clone(), Actor::Daemon, version);
                    false
                }
            });
        } else {
            for event in self.verdict_events.drain(..) {
                let _ = log.emit(event, Actor::Daemon, version);
            }
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
        self.collect_log_action(false);
        let receive = self.sending.as_ref()?;
        match receive.try_recv() {
            Ok(result) => {
                // The action is sent before the result; check again in case
                // it arrived between the two nonblocking receives.
                self.collect_log_action(true);
                self.sending = None;
                match result {
                    Ok(delivered) => {
                        if delivered.success {
                            self.last_success = Some(delivered.at);
                        }
                        None
                    }
                    Err(reason) => Some(reason),
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.collect_log_action(true);
                self.sending = None;
                Some(Failure::Internal)
            }
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }
    pub(super) fn collect_log_action(&mut self, finished: bool) {
        let Some(receive) = &self.pending_log_action else {
            return;
        };
        let action = match receive.try_recv() {
            Ok(action) => action,
            Err(mpsc::TryRecvError::Empty) if !finished => return,
            Err(_) => HeartbeatAction::Withheld,
        };
        self.finish_log_action(action);
    }
    fn finish_log_action(&mut self, resolved: HeartbeatAction) {
        if self.pending_log_action.take().is_some()
            && let Some(EventKind::HeartbeatCheckVerdict { action, .. }) =
                self.verdict_events.iter_mut().find(|event| {
                    matches!(
                        event,
                        EventKind::HeartbeatCheckVerdict {
                            action: HeartbeatAction::Log,
                            ..
                        }
                    )
                })
        {
            *action = resolved;
        }
    }
    fn track_log_action(&mut self, suffix: &str) -> Option<mpsc::SyncSender<HeartbeatAction>> {
        if suffix != "/log"
            || !self.verdict_events.iter().any(|event| {
                matches!(
                    event,
                    EventKind::HeartbeatCheckVerdict {
                        action: HeartbeatAction::Log,
                        ..
                    }
                )
            })
        {
            return None;
        }
        let (send, receive) = mpsc::sync_channel(1);
        self.pending_log_action = Some(receive);
        Some(send)
    }
}

fn resolved_request(
    url: &heartbeat::SecretUrl,
    deadline_ns: u64,
) -> Result<(Request, HeartbeatAction), Failure> {
    if url.is_log() {
        Request::log(url.expose(), deadline_ns).map(|request| (request, HeartbeatAction::Log))
    } else {
        Request::new(url.expose(), deadline_ns).map(|request| (request, HeartbeatAction::Status))
    }
}
struct Delivered {
    at: Instant,
    success: bool,
}
impl Delivered {
    fn new(at: Instant, suffix: &str) -> Self {
        Self {
            at,
            success: matches!(suffix, "" | "/0"),
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
        self.heartbeat.report_events(
            &self.audit.handle(),
            self.running.as_ref().map(|(_, _, cfg)| cfg.stamp.version),
        );
    }
    fn start_heartbeat_check(
        &mut self,
        now: Instant,
        held: std::sync::Arc<crate::netns::NetnsHandle>,
        config: crate::reconcile::Config,
    ) {
        let cleanup_grace =
            !std::mem::replace(&mut self.heartbeat.legacy_grace_cleanup_started, true);
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
                if cleanup_grace {
                    discard_legacy_grace(&state_root);
                }
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
                let outcome = result.as_ref().map_or(Outcome::from_code(1), Outcome::from);
                let check_reason = result
                    .as_ref()
                    .map_or(HeartbeatVerdictReason::ObservationError, |report| {
                        HeartbeatVerdictReason::from(&report.verdict)
                    });
                #[cfg(feature = "testing")]
                let outcome = std::fs::read_to_string(run_root.join("heartbeat-test-code"))
                    .ok()
                    .and_then(|value| value.parse::<u8>().ok())
                    .map_or(outcome, Outcome::from_code);
                let _ = send.send(Checked {
                    at: now,
                    version: config.stamp.version,
                    outcome,
                    check_reason,
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
        let mut action_send = self.heartbeat.track_log_action(&suffix);
        #[cfg(all(test, feature = "testing"))]
        let worker_identity = self.heartbeat.worker_identity;
        let result = std::thread::Builder::new()
            .name("scupper-heartbeat-wait".into())
            .spawn(move || {
                let result = heartbeat::retry_deadline(deadline_ns, || {
                    let url = heartbeat::resolve(&config_root, &reference, &suffix, owner)?;
                    let identity = || {
                        let passwd =
                            std::fs::read_to_string("/etc/passwd").map_err(|_| Failure::Account)?;
                        let group =
                            std::fs::read_to_string("/etc/group").map_err(|_| Failure::Account)?;
                        heartbeat::account(&passwd, &group)
                    };
                    #[cfg(all(test, feature = "testing"))]
                    let identity = worker_identity.map_or_else(identity, Ok)?;
                    #[cfg(not(all(test, feature = "testing")))]
                    let identity = identity()?;
                    let (request, action) = resolved_request(&url, deadline_ns)?;
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
                                serde_json::json!({"suffix":suffix,"deadline_ns":deadline_ns,"log_body":request.payload_body()})
                            );
                        }
                        while run_root.join("heartbeat-pause").exists()
                            && heartbeat::monotonic_ns() < deadline_ns
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    // Record the first attempted request class, including /log
                    // falling back to /3. No URL leaves the delivery worker.
                    if let Some(send) = action_send.take() {
                        let _ = send.send(action);
                    }
                    heartbeat::attempt(&binary, &request, identity)
                })
                .map(|()| Delivered::new(Instant::now(), &suffix));
                let _ = send.send(result);
            });
        if result.is_err() {
            self.heartbeat.finish_log_action(HeartbeatAction::Withheld);
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
            outcome: Outcome::from_code(code),
            reason: scupper_proto::ObjectKind::Unknown,
            full_fresh_check: fresh,
            check_reason: HeartbeatVerdictReason::ObservationError,
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
            [
                EventKind::CheckVerdictChanged {
                    to: scupper_proto::VerdictCode::Unprotected,
                    ..
                },
                EventKind::HeartbeatCheckVerdict {
                    code: 2,
                    action: HeartbeatAction::Withheld,
                    ..
                }
            ]
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
                        outcome: Outcome::from_code(0),
                        full_fresh_check: true,
                        check_reason: HeartbeatVerdictReason::ObservationError,
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
                    send.send(Ok(Delivered::new(now, "/0"))).unwrap();
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
        send.send(result.map(|()| Delivered::new(Instant::now(), "/0")))
            .unwrap();
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
        send.send(Ok(Delivered::new(now, "/0"))).unwrap();
        assert_eq!(heartbeat.collect(), None);
        assert_eq!(heartbeat.last_success, Some(now));
    }
    #[test]
    fn degraded_without_grace_uses_the_configured_report_mode() {
        let now = Instant::now();
        for mode in ["ok_only", "status_code"] {
            let cfg = settings(mode, 60);
            let mut state = Heartbeat::default();
            queue(&mut state, now, 3, true);
            let work = state.iteration(now, now, true, Some(context(&cfg)));
            if mode == "status_code" {
                assert!(matches!(work, Some(Work::Send { suffix, .. }) if suffix == "/3"));
            } else {
                assert!(!matches!(work, Some(Work::Send { .. })));
                assert_eq!(state.last_send, None);
            }
        }
    }

    fn reset_report() -> scupper_core::verdict::v2::Report {
        scupper_core::verdict::v2::Report {
            verdict: scupper_core::verdict::v2::Verdict::Degraded(
                scupper_core::verdict::v2::Degraded::ClientSessionsReset,
            ),
            warnings: vec![],
            at: 0,
            config_version: 1,
        }
    }

    fn queue_report(
        state: &mut Heartbeat,
        at: Instant,
        report: &scupper_core::verdict::v2::Report,
    ) {
        queue(state, at, report.verdict.exit_code(), true);
        let mut checked = state.checked().unwrap();
        checked.outcome = Outcome::from(report);
        checked.check_reason = match report.verdict {
            scupper_core::verdict::v2::Verdict::Protected { .. } => {
                HeartbeatVerdictReason::Protected
            }
            scupper_core::verdict::v2::Verdict::Degraded(
                scupper_core::verdict::v2::Degraded::ClientSessionsUnknown,
            ) => HeartbeatVerdictReason::ClientSessionsUnknown,
            _ => HeartbeatVerdictReason::ClientSessionsReset,
        };
        let (send, receive) = mpsc::sync_channel(1);
        state.check = Some(receive);
        send.send(checked).unwrap();
    }

    fn queue_reset(state: &mut Heartbeat, at: Instant) {
        queue_report(state, at, &reset_report());
    }

    fn history_report() -> scupper_core::verdict::v2::Report {
        use scupper_core::verdict::v2::{Degraded, Verdict, Warning};
        let mut report = reset_report();
        report.verdict = Verdict::Degraded(Degraded::ClientSessionsUnknown);
        report.warnings = vec![
            Warning::ClientSessionHistoryUnavailable,
            Warning::ClientSessionsPending,
            Warning::ClientHandshakesStale,
        ];
        report
    }

    fn deliver_work(state: &mut Heartbeat, work: Option<Work>, now: Instant) -> Option<String> {
        let Some(Work::Send { suffix, .. }) = work else {
            return None;
        };
        let (send, receive) = mpsc::sync_channel(1);
        state.sending = Some(receive);
        send.send(Ok(Delivered::new(now, &suffix))).unwrap();
        assert_eq!(state.collect(), None);
        Some(suffix)
    }

    fn assert_history_delivery(
        state: &mut Heartbeat,
        now: Instant,
        origin: Instant,
        cfg: &scupper_core::config::HeartbeatSettings,
    ) {
        let work = state.iteration(now, origin, true, Some(context(cfg)));
        let suffix = deliver_work(state, work, now);
        if cfg.report == scupper_core::config::HeartbeatReport::StatusCode {
            assert_eq!(suffix.as_deref(), Some("/log"));
            assert_eq!(state.last_send, Some(now));
        } else {
            assert_eq!(suffix, None);
        }
    }

    #[test]
    fn session_reset_logs_indefinitely_and_recovery_sends_zero_across_restarts() {
        let origin = Instant::now();
        let cfg = settings("status_code", 60);
        let mut state = Heartbeat::default();
        for second in [0, 60, 600, 1200, 3600] {
            let now = origin + Duration::from_secs(second);
            queue_reset(&mut state, now);
            assert!(
                matches!(state.iteration(now, origin, true, Some(context(&cfg))),
                Some(Work::Send { suffix, .. }) if suffix == "/log")
            );
            assert_eq!(state.last_send, Some(now));
            // Sending /log consumes the ordinary cadence slot.
            queue_reset(&mut state, now + Duration::from_secs(1));
            assert!(!matches!(
                state.iteration(
                    now + Duration::from_secs(1),
                    origin,
                    true,
                    Some(context(&cfg))
                ),
                Some(Work::Send { .. })
            ));
            // A restart carries no grace epoch and does not change the decision.
            let mut restarted = Heartbeat::default();
            queue_reset(&mut restarted, now);
            assert!(
                matches!(restarted.iteration(now, origin, true, Some(context(&cfg))), Some(Work::Send { suffix, .. }) if suffix == "/log")
            );
        }
        let recovered = origin + Duration::from_mins(61);
        queue(&mut state, recovered, 0, true);
        assert!(
            matches!(state.iteration(recovered, origin, true, Some(context(&cfg))), Some(Work::Send { suffix, .. }) if suffix == "/0")
        );
        let ok = settings("ok_only", 60);
        let mut state = Heartbeat::default();
        queue_reset(&mut state, origin);
        assert!(!matches!(
            state.iteration(origin, origin, true, Some(context(&ok))),
            Some(Work::Send { .. })
        ));
        assert!(state.last_send.is_none());
        assert!(matches!(
            state.verdict_events.last(),
            Some(EventKind::HeartbeatCheckVerdict {
                action: HeartbeatAction::Withheld,
                ..
            })
        ));
    }

    #[test]
    fn history_reconstruction_restart_loop_never_sends_success_or_moves_last_success() {
        let origin = Instant::now();
        for mode in ["ok_only", "status_code"] {
            let cfg = settings(mode, 60);
            for last_success in [None, Some(origin)] {
                for restart_second in [60, 180, 7200, 86400] {
                    let mut state = Heartbeat {
                        last_success,
                        ..Heartbeat::default()
                    };
                    // Restart before 180 s of complete history, indefinitely.
                    for elapsed in [0, 60, 120] {
                        let now = origin + Duration::from_secs(restart_second + elapsed);
                        queue_report(&mut state, now, &history_report());
                        assert_history_delivery(&mut state, now, origin, &cfg);
                        assert_eq!(state.last_success, last_success);
                        if mode == "ok_only" {
                            assert_eq!(state.last_send, None);
                        }
                    }
                }
            }
        }
    }

    struct HistoryTelemetry(u64);
    impl crate::system::System for HistoryTelemetry {
        fn now_unix_secs(&self) -> u64 {
            self.0
        }
        fn run(
            &self,
            _: crate::system::HelperPurpose,
            _: crate::system::Program,
            _: &[String],
            _: Duration,
        ) -> Result<crate::system::ExecOutput, crate::system::ExecError> {
            panic!("no commands expected");
        }
        fn client_session_io(
            &self,
            _: crate::system::HelperPurpose,
            _: &crate::netns::NetnsHandle,
            _: &crate::client_sessions::Request,
        ) -> std::io::Result<crate::client_sessions::Response> {
            Ok(crate::client_sessions::Response::Samples(vec![
                crate::client_sessions::Sample {
                    key: [3; 32],
                    handshake: (0, 0),
                    rx: 0,
                    tx: 0,
                },
            ]))
        }
    }

    #[test]
    fn persistent_history_fallback_never_sends_success_or_moves_last_success() {
        use crate::{client_sessions, lock::WriterLock, netns::testing};
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("heartbeat-history-fallback-{}", std::process::id()));
        let guard = WriterLock::acquire(&root).unwrap();
        client_sessions::provision(&root, "gateway", 1000, &guard).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("client-sessions.json")).unwrap())
                .unwrap();
        // Model the unavailable record written on a failed durable save. Keep
        // that fallback on disk throughout the fake-clock run, beyond timeout.
        record["never_served"] = false.into();
        record["history"] = "Unavailable".into();
        record["unknown_until"] = 1180.into();
        record["gaps"] = serde_json::json!([{ "start":1000, "end":null }]);
        let fallback = root.join("client-sessions-fallback");
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&fallback, &bytes).unwrap();
        let held = testing::handle().unwrap();
        let origin = Instant::now();
        for mode in ["ok_only", "status_code"] {
            let cfg = settings(mode, 60);
            for last_success in [None, Some(origin)] {
                let mut state = Heartbeat {
                    last_success,
                    ..Heartbeat::default()
                };
                for second in [60, 120, 180, 600, 3600, 86400] {
                    let sessions = client_sessions::status(
                        &HistoryTelemetry(1000 + second),
                        &held,
                        "wg0",
                        &root,
                        &root,
                        "gateway",
                        &[[3; 32]],
                    )
                    .unwrap();
                    assert!(sessions.unknown && sessions.history_unavailable);
                    assert!(!sessions.telemetry_unavailable && !sessions.peer_missing);
                    let now = origin + Duration::from_secs(second);
                    queue_report(&mut state, now, &history_report());
                    assert_history_delivery(&mut state, now, origin, &cfg);
                    assert_eq!(state.last_success, last_success);
                    assert_eq!(std::fs::read(&fallback).unwrap(), bytes);
                }
            }
        }
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_history_gap_logs_or_withholds_without_advancing_last_success() {
        let origin = Instant::now();
        for mode in ["ok_only", "status_code"] {
            let cfg = settings(mode, 60);
            let mut state = Heartbeat::default();
            queue(&mut state, origin, 0, true);
            let work = state.iteration(origin, origin, true, Some(context(&cfg)));
            assert_eq!(
                deliver_work(&mut state, work, origin).as_deref(),
                Some(if mode == "ok_only" { "" } else { "/0" })
            );
            for second in [60, 120, 600, 3600] {
                let now = origin + Duration::from_secs(second);
                queue_report(&mut state, now, &history_report());
                // M1(a): runtime gaps share the start exemption, with no provenance.
                assert_history_delivery(&mut state, now, origin, &cfg);
                assert_eq!(state.last_success, Some(origin));
            }
        }
    }

    #[test]
    fn recovery_to_zero_with_a_stale_peer_sends_success_under_existing_policy() {
        use scupper_core::{
            config::ExitId,
            verdict::v2::{Verdict, Warning},
        };
        let origin = Instant::now();
        for mode in ["ok_only", "status_code"] {
            let cfg = settings(mode, 60);
            let mut state = Heartbeat::default();
            queue_report(&mut state, origin, &history_report());
            assert_history_delivery(&mut state, origin, origin, &cfg);
            assert_eq!(state.last_success, None);
            let now = origin + Duration::from_secs(180);
            let mut recovered = history_report();
            recovered.verdict = Verdict::Protected {
                exit: ExitId("exit".into()),
                exit_ip: "203.0.113.1".parse().unwrap(),
            };
            recovered.warnings = vec![Warning::ClientHandshakesStale];
            // Known limitation: stale handshakes alone stay Protected after
            // reconstruction. Even brief recovery sends success and resets the
            // monitor's timeout; this cannot detect every serving failure.
            queue_report(&mut state, now, &recovered);
            let work = state.iteration(now, origin, true, Some(context(&cfg)));
            assert_eq!(
                deliver_work(&mut state, work, now).as_deref(),
                Some(if mode == "ok_only" { "" } else { "/0" })
            );
            assert_eq!(state.last_success, Some(now));
        }
    }

    #[test]
    fn obsolete_grace_is_deleted_without_parsing_or_gating() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("obsolete-grace-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("heartbeat-session-grace.json");
        let lock = root.join("heartbeat-grace-writer");
        for bytes in ["not JSON", r#"{"last":9999999999,"first_session":0}"#] {
            std::fs::write(&path, bytes).unwrap();
            std::fs::write(&lock, "obsolete").unwrap();
            let mut state = Heartbeat::default();
            discard_legacy_grace(&root);
            assert!(!path.exists());
            assert!(!lock.exists());
            let now = Instant::now();
            queue_reset(&mut state, now);
            assert!(
                matches!(state.iteration(now, now, true, Some(context(&settings("status_code", 60)))), Some(Work::Send { suffix, .. }) if suffix == "/log")
            );
        }
        // Even a cleanup error is harmless.
        std::fs::create_dir(&path).unwrap();
        discard_legacy_grace(&root);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fresh_verdict_events_record_changes_repeats_and_recovery() {
        let origin = Instant::now();
        let cfg = settings("status_code", 10);
        let mut state = Heartbeat::default();
        for (second, code, reason, expected_len) in [
            (0, 0, HeartbeatVerdictReason::Protected, 0),
            (10, 0, HeartbeatVerdictReason::Protected, 0),
            (20, 3, HeartbeatVerdictReason::ClientSessionsReset, 1),
            (30, 3, HeartbeatVerdictReason::ClientSessionsReset, 1),
            (619, 3, HeartbeatVerdictReason::ClientSessionsReset, 1),
            (620, 3, HeartbeatVerdictReason::ClientSessionsReset, 2),
            (621, 3, HeartbeatVerdictReason::ClientSessionsUnknown, 3),
            (
                622,
                3,
                HeartbeatVerdictReason::ClientSessionTelemetryUnknown,
                4,
            ),
            (623, 1, HeartbeatVerdictReason::ObservationError, 5),
            (624, 2, HeartbeatVerdictReason::RulesetDiffers, 6),
            (625, 4, HeartbeatVerdictReason::NoHealthyExit, 7),
            (626, 0, HeartbeatVerdictReason::Protected, 8),
            (627, 0, HeartbeatVerdictReason::Protected, 8),
        ] {
            let now = origin + Duration::from_secs(second);
            queue(&mut state, now, code, true);
            let mut checked = state.checked().unwrap();
            checked.check_reason = reason;
            if reason == HeartbeatVerdictReason::ClientSessionsReset {
                checked.outcome = Outcome::from(&reset_report());
            }
            let (send, receive) = mpsc::sync_channel(1);
            state.check = Some(receive);
            send.send(checked).unwrap();
            let _ = state.iteration(now, origin, true, Some(context(&cfg)));
            let events: Vec<_> = state
                .verdict_events
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        EventKind::HeartbeatCheckVerdict { .. }
                            | EventKind::HeartbeatCheckRecovered { .. }
                    )
                })
                .collect();
            assert_eq!(events.len(), expected_len, "at {second}");
        }
        let events: Vec<_> = state
            .verdict_events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    EventKind::HeartbeatCheckVerdict { .. }
                        | EventKind::HeartbeatCheckRecovered { .. }
                )
            })
            .collect();
        assert!(matches!(
            events[0],
            EventKind::HeartbeatCheckVerdict {
                code: 3,
                count: 1,
                action: HeartbeatAction::Log,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            EventKind::HeartbeatCheckVerdict {
                code: 3,
                count: 4,
                action: HeartbeatAction::Withheld,
                ..
            }
        ));
        assert!(matches!(
            events[2],
            EventKind::HeartbeatCheckVerdict {
                reason: HeartbeatVerdictReason::ClientSessionsUnknown,
                action: HeartbeatAction::Withheld,
                count: 1,
                ..
            }
        ));
        assert!(matches!(
            events[7],
            EventKind::HeartbeatCheckRecovered {
                code: 0,
                action: HeartbeatAction::Withheld,
                ..
            }
        ));
    }
    #[test]
    fn minimum_interval_flapping_debounces_each_key_and_recoveries() {
        for reasons in [
            [
                HeartbeatVerdictReason::ClientSessionsReset,
                HeartbeatVerdictReason::Protected,
            ],
            [
                HeartbeatVerdictReason::ClientSessionsReset,
                HeartbeatVerdictReason::ClientSessionsUnknown,
            ],
        ] {
            let origin = Instant::now();
            let cfg = settings("status_code", 10);
            let mut state = Heartbeat::default();
            for step in 0..360 {
                let now = origin + Duration::from_secs(step * 10);
                let reason = reasons[usize::try_from(step % 2).unwrap()];
                queue(
                    &mut state,
                    now,
                    if reason == HeartbeatVerdictReason::Protected {
                        0
                    } else {
                        3
                    },
                    true,
                );
                let mut checked = state.checked().unwrap();
                checked.check_reason = reason;
                if reason == HeartbeatVerdictReason::ClientSessionsReset {
                    checked.outcome = Outcome::from(&reset_report());
                }
                let (send, receive) = mpsc::sync_channel(1);
                state.check = Some(receive);
                send.send(checked).unwrap();
                state.iteration(now, origin, true, Some(context(&cfg)));
            }
            let events: Vec<_> = state
                .verdict_events
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        EventKind::HeartbeatCheckVerdict { .. }
                            | EventKind::HeartbeatCheckRecovered { .. }
                    )
                })
                .collect();
            // Two keys, six windows each, rather than 360 events/hour.
            assert_eq!(events.len(), 12);
            for (index, event) in events.iter().enumerate() {
                let count = match event {
                    EventKind::HeartbeatCheckVerdict { count, .. }
                    | EventKind::HeartbeatCheckRecovered { count, .. } => *count,
                    _ => unreachable!(),
                };
                // Each key recurs every 20 seconds. Suppressed observations,
                // including recoveries, are folded into its next cumulative count.
                assert_eq!(count, 1 + 30 * u64::try_from(index / 2).unwrap());
            }
        }
    }

    fn record_at(state: &mut Heartbeat, origin: Instant, second: u64, code: u8) {
        let now = origin + Duration::from_secs(second);
        queue(state, now, code, true);
        let checked = state.checked().unwrap();
        state.record_check(now, &checked, HeartbeatAction::Withheld);
    }

    #[test]
    fn healthy_tail_always_leaves_a_recovery_after_random_check_sequences() {
        let origin = Instant::now();
        let mut seed = 0x6a09_e667_f3bc_c909_u64;
        for sequence in 0..1024 {
            let mut state = Heartbeat::default();
            // Include a failure in every sequence so the property is non-vacuous.
            record_at(&mut state, origin, 0, 3);
            for step in 1..=360 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                record_at(
                    &mut state,
                    origin,
                    step * 10,
                    [0, 3, 4][(seed % 3) as usize],
                );
            }
            for step in 361..=423 {
                record_at(&mut state, origin, step * 10, 0);
            }
            assert!(
                matches!(
                    state.verdict_events.last(),
                    Some(EventKind::HeartbeatCheckRecovered { .. })
                ),
                "sequence {sequence} ended on a failure after 620 seconds of health"
            );
        }
    }

    #[cfg(feature = "testing")]
    fn audit_options(label: &str) -> super::super::Options {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("heartbeat-{label}-{}", std::process::id()));
        for child in ["state", "config", "run"] {
            std::fs::create_dir_all(root.join(child)).unwrap();
        }
        super::super::Options {
            state_root: root.join("state"),
            config_root: root.join("config"),
            run_root: root.join("run"),
            probe_binary: root.join("missing-probe"),
        }
    }

    #[cfg(feature = "testing")]
    fn audit_runtime<'a>(
        options: &'a super::super::Options,
        system: &'a RealSystem,
    ) -> Runtime<'a> {
        use super::super::{Config, EventLog, Reconciler, StateFile, testing};
        use scupper_core::{
            config::{GatewayId, parse_site, validate},
            render::VersionStamp,
            verdict::v2::{HealthConfigV2, NetnsIdentity},
        };
        let deps = BootDeps {
            system,
            namespace: &GatewayNamespace,
            state_root: &options.state_root,
            config_root: &options.config_root,
            run_root: &options.run_root,
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        };
        let mut runtime = testing::runtime_shell(deps, options).unwrap();
        runtime.audit.opened = EventLog::open(&options.state_root, GatewayId("gw1".into()), || {
            scupper_proto::UnixSeconds(1)
        })
        .unwrap();
        let config = || Config {
            site: validate(
                parse_site(include_str!(
                    "../../../scupper-core/tests/fixtures/site-m2.toml"
                ))
                .unwrap(),
            )
            .unwrap(),
            gateway: GatewayId("gw1".into()),
            stamp: VersionStamp {
                version: 7,
                sha256: [0; 32],
            },
            fingerprint: [7; 32],
            run_root: options.run_root.clone(),
            lock_wait: Duration::ZERO,
        };
        let cfg = config();
        let held = std::sync::Arc::new(crate::netns::testing::handle().unwrap());
        let (device, inode) = held.identity();
        let health = HealthConfigV2::new(
            &cfg.site,
            &cfg.gateway,
            NetnsIdentity { device, inode },
            vec!["203.0.113.1".parse().unwrap()],
            7,
        )
        .unwrap();
        let kernel = crate::reconcile::RealKernel::new(
            deps,
            held.clone(),
            &cfg,
            health,
            options.run_root.join("netns"),
            None,
        )
        .unwrap();
        let clock: Box<dyn Fn() -> (MonoTime, u64)> = Box::new(|| (MonoTime(Duration::ZERO), 1));
        let machine = Reconciler::with_state(
            kernel,
            StateFile::open(&options.state_root, None).unwrap(),
            runtime.audit.handle(),
            config(),
            held.clone(),
            clock,
            crate::state::State {
                applied_version: Some(7),
                ..crate::state::State::default()
            },
        )
        .unwrap();
        runtime.running = Some((machine, held, cfg));
        runtime
    }

    #[cfg(feature = "testing")]
    fn assert_shutdown_pending_log_action(reported: bool) {
        use super::super::DaemonDeps;
        let options = audit_options(if reported {
            "shutdown-status"
        } else {
            "shutdown-withheld"
        });
        let system = RealSystem::default();
        let mut runtime = audit_runtime(&options, &system);
        let now = Instant::now();
        queue_reset(&mut runtime.heartbeat, now);
        runtime
            .heartbeat
            .iteration(now, now, true, Some(context(&settings("status_code", 10))));
        let sender = runtime.heartbeat.track_log_action("/log").unwrap();
        record_at(&mut runtime.heartbeat, now, 10, 0);
        record_at(&mut runtime.heartbeat, now, 20, 4);
        runtime
            .heartbeat
            .record_verdict(2, scupper_proto::ObjectKind::Ruleset);
        runtime
            .heartbeat
            .report_events(&runtime.audit.handle(), Some(7));
        runtime
            .audit
            .handle()
            .flush_blocking(Duration::from_secs(30))
            .unwrap();
        let persisted = || {
            crate::events::read_since(&options.state_root, 0, None)
                .map(Result::unwrap)
                .collect::<Vec<_>>()
        };
        let before = persisted();
        assert!(
            before
                .iter()
                .any(|event| matches!(event.kind, EventKind::CheckVerdictChanged { .. }))
        );
        assert!(!before.iter().any(|event| matches!(
            event.kind,
            EventKind::HeartbeatCheckVerdict { .. } | EventKind::HeartbeatCheckRecovered { .. }
        )));
        if reported {
            sender.send(HeartbeatAction::Status).unwrap();
        }
        // Keep the sender alive: shutdown must resolve even an unreported action.
        runtime.shutdown();
        assert!(runtime.heartbeat.pending_log_action.is_none());
        let events: Vec<_> = persisted()
            .into_iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    EventKind::HeartbeatCheckVerdict { .. }
                        | EventKind::HeartbeatCheckRecovered { .. }
                )
            })
            .collect();
        assert_eq!(events.len(), 3);
        let expected = if reported {
            HeartbeatAction::Status
        } else {
            HeartbeatAction::Withheld
        };
        assert!(
            matches!(events[0].kind, EventKind::HeartbeatCheckVerdict { code: 3, action, .. } if action == expected)
        );
        assert!(matches!(
            events[1].kind,
            EventKind::HeartbeatCheckRecovered { .. }
        ));
        assert!(matches!(
            events[2].kind,
            EventKind::HeartbeatCheckVerdict { code: 4, .. }
        ));
        assert!(events.iter().all(|event| event.config_version == Some(7)));
        drop(sender);
        drop(runtime);
        std::fs::remove_dir_all(options.state_root.parent().unwrap()).unwrap();
    }

    #[test]
    #[cfg(feature = "testing")]
    fn shutdown_flushes_unreported_log_action_as_withheld_in_check_order() {
        assert_shutdown_pending_log_action(false);
    }

    #[test]
    #[cfg(feature = "testing")]
    fn shutdown_flushes_reported_log_action_as_status_in_check_order() {
        assert_shutdown_pending_log_action(true);
    }

    #[test]
    #[cfg(feature = "testing")]
    fn launch_heartbeat_worker_reports_log_and_status_fallback_to_audit() {
        use super::super::DaemonDeps;
        use scupper_core::config::{SecretKind, SecretName};
        use std::os::unix::fs::PermissionsExt;
        let options = audit_options("worker-action");
        std::fs::create_dir_all(options.config_root.join("secrets/url")).unwrap();
        for path in ["", "secrets", "secrets/url"] {
            std::fs::set_permissions(
                options.config_root.join(path),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let system = RealSystem::default();
        for target_len in [2044, 2045, 2046] {
            let path = options.config_root.join("secrets/url/test");
            let target = format!("/{}?q=x", "x".repeat(target_len - 5));
            std::fs::write(&path, format!("https://fixture.invalid{target}")).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let mut runtime = audit_runtime(&options, &system);
            // Only account lookup is injected; request resolution and the action
            // channel run in the real worker. The absent binary prevents network I/O.
            runtime.heartbeat.worker_identity = Some(crate::probe_child::ProbeIdentity {
                uid: 65534,
                gid: 65534,
            });
            let now = Instant::now();
            queue_reset(&mut runtime.heartbeat, now);
            runtime.heartbeat.iteration(
                now,
                now,
                true,
                Some(context(&settings("status_code", 10))),
            );
            runtime.launch_heartbeat(
                SecretName::new(SecretKind::Url, "test").unwrap(),
                "/log".into(),
                now + Duration::from_secs(30),
            );
            assert!(matches!(
                runtime
                    .heartbeat
                    .sending
                    .take()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap(),
                Err(Failure::Exec)
            ));
            // Receive the completion before shutdown so this checks the worker's
            // report even when its send attempt fails.
            runtime.heartbeat.collect_log_action(true);
            runtime
                .heartbeat
                .report_events(&runtime.audit.handle(), Some(7));
            runtime.shutdown();
            let events: Vec<_> = crate::events::read_since(&options.state_root, 0, None)
                .map(Result::unwrap)
                .filter(|event| matches!(event.kind, EventKind::HeartbeatCheckVerdict { .. }))
                .collect();
            let expected = if target_len == 2044 {
                HeartbeatAction::Log
            } else {
                HeartbeatAction::Status
            };
            assert!(
                matches!(events.last().unwrap().kind, EventKind::HeartbeatCheckVerdict { action, .. } if action == expected),
                "target length {target_len}"
            );
            drop(runtime);
        }
        std::fs::remove_dir_all(options.state_root.parent().unwrap()).unwrap();
    }

    #[test]
    fn suppressed_recovery_flushes_once_on_first_healthy_check_after_window() {
        let origin = Instant::now();
        let mut state = Heartbeat::default();
        for (second, code) in [(0, 3), (10, 0), (100, 4), (110, 0)] {
            record_at(&mut state, origin, second, code);
        }
        assert!(state.check_history.recovery_pending);
        assert_eq!(state.verdict_events.len(), 3);
        // Stay healthy for eleven minutes after the suppressed recovery.
        for second in (120..=770).step_by(10) {
            record_at(&mut state, origin, second, 0);
            assert_eq!(state.verdict_events.len(), if second < 610 { 3 } else { 4 });
        }
        assert!(!state.check_history.recovery_pending);
        assert_eq!(state.check_history.recovery.count, 2);
        assert_eq!(
            state.check_history.recovery.last_event,
            Some(origin + Duration::from_secs(610))
        );
        assert!(matches!(
            state.verdict_events.last(),
            Some(EventKind::HeartbeatCheckRecovered { count: 2, .. })
        ));
    }

    #[test]
    fn logged_failure_cancels_pending_recovery_and_incomplete_zero_cannot_flush() {
        let origin = Instant::now();
        let mut state = Heartbeat::default();
        for (second, code) in [(0, 3), (10, 0), (100, 4), (110, 0), (200, 1)] {
            record_at(&mut state, origin, second, code);
        }
        assert!(!state.check_history.recovery_pending);
        assert_eq!(state.verdict_events.len(), 4);
        let now = origin + Duration::from_secs(610);
        queue(&mut state, now, 0, false);
        let checked = state.checked().unwrap();
        state.record_check(now, &checked, HeartbeatAction::Withheld);
        assert_eq!(state.verdict_events.len(), 4);
        assert!(state.check_history.failing);
        record_at(&mut state, origin, 620, 1);
        assert!(matches!(
            state.verdict_events.last(),
            Some(EventKind::HeartbeatCheckVerdict { code: 1, .. })
        ));
        record_at(&mut state, origin, 630, 0);
        assert!(matches!(
            state.verdict_events.last(),
            Some(EventKind::HeartbeatCheckRecovered { count: 3, .. })
        ));
    }

    #[test]
    fn suppressed_failure_preserves_pending_recovery_and_transition_count() {
        let origin = Instant::now();
        let mut state = Heartbeat::default();
        for (second, code) in [(0, 3), (10, 0), (100, 4), (110, 0), (120, 4)] {
            record_at(&mut state, origin, second, code);
        }
        assert!(state.check_history.recovery_pending);
        assert_eq!(state.verdict_events.len(), 3);
        record_at(&mut state, origin, 130, 0);
        record_at(&mut state, origin, 609, 0);
        assert_eq!(state.verdict_events.len(), 3);
        record_at(&mut state, origin, 610, 0);
        assert_eq!(state.verdict_events.len(), 4);
        assert!(matches!(
            state.verdict_events.last(),
            Some(EventKind::HeartbeatCheckRecovered { count: 3, .. })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Cover resolution boundaries and persisted audit ordering together.
    fn resolved_log_fallback_records_status_and_preserves_check_order() {
        use crate::events::{EventLog, read_since};
        use scupper_core::config::{GatewayId, SecretKind, SecretName};
        use scupper_proto::UnixSeconds;
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("heartbeat-action-{}", std::process::id()));
        std::fs::create_dir_all(root.join("secrets/url")).unwrap();
        for path in ["", "secrets", "secrets/url"] {
            std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let reference = SecretName::new(SecretKind::Url, "test").unwrap();
        let owner = rustix::process::geteuid().as_raw();
        for target_len in [2044, 2045, 2046] {
            let path = root.join("secrets/url/test");
            let target = format!("/{}?q=x", "x".repeat(target_len - 5));
            std::fs::write(&path, format!("https://fixture.invalid{target}")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let url = heartbeat::resolve(&root, &reference, "/log", owner).unwrap();
            let (request, action) =
                resolved_request(&url, heartbeat::monotonic_ns() + 5_000_000_000).unwrap();
            let expected = if target_len == 2044 {
                HeartbeatAction::Log
            } else {
                HeartbeatAction::Status
            };
            let encoded: serde_json::Value =
                serde_json::from_slice(&request.encode().unwrap()).unwrap();
            assert_eq!(action, expected);
            assert_eq!(
                encoded
                    .get("log")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                target_len == 2044
            );
            assert!(
                encoded["url"]
                    .as_str()
                    .unwrap()
                    .ends_with(if target_len == 2044 {
                        "/log?q=x"
                    } else {
                        "/3?q=x"
                    })
            );
            let log_root = root.join(format!("events-{target_len}"));
            let log =
                EventLog::open(&log_root, GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
            let now = Instant::now();
            let mut state = Heartbeat::default();
            queue_reset(&mut state, now);
            let Some(Work::Send { suffix, .. }) =
                state.iteration(now, now, true, Some(context(&settings("status_code", 10))))
            else {
                panic!("expected log delivery")
            };
            let action_send = state.track_log_action(&suffix).unwrap();
            // Even if a later check is queued, the failure must precede recovery.
            record_at(&mut state, now, 10, 0);
            state.record_verdict(2, scupper_proto::ObjectKind::Ruleset);
            state.report_events(&log.handle, Some(1));
            log.handle.flush_blocking(Duration::from_secs(2)).unwrap();
            let before: Vec<_> = read_since(&log_root, 0, None).map(Result::unwrap).collect();
            assert!(!before.iter().any(|event| matches!(
                event.kind,
                EventKind::HeartbeatCheckVerdict { .. } | EventKind::HeartbeatCheckRecovered { .. }
            )));
            assert!(
                before
                    .iter()
                    .any(|event| matches!(event.kind, EventKind::CheckVerdictChanged { .. }))
            );
            action_send.send(action).unwrap();
            assert_eq!(state.collect(), None);
            state.report_events(&log.handle, Some(1));
            log.handle.flush_blocking(Duration::from_secs(2)).unwrap();
            let events: Vec<_> = read_since(&log_root, 0, None)
                .map(Result::unwrap)
                .filter(|event| {
                    matches!(
                        event.kind,
                        EventKind::HeartbeatCheckVerdict { .. }
                            | EventKind::HeartbeatCheckRecovered { .. }
                    )
                })
                .collect();
            assert_eq!(events.len(), 2);
            assert!(
                matches!(events[0].kind, EventKind::HeartbeatCheckVerdict { action, count: 1, .. } if action == expected)
            );
            assert!(matches!(
                events[1].kind,
                EventKind::HeartbeatCheckRecovered { .. }
            ));
            assert!(state.last_success.is_none());
            drop(log);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unresolved_log_action_is_withheld_on_worker_failure_or_timeout() {
        let now = Instant::now();
        for timeout in [false, true] {
            let mut state = Heartbeat::default();
            queue_reset(&mut state, now);
            state.iteration(now, now, true, Some(context(&settings("status_code", 10))));
            let action_send = state.track_log_action("/log").unwrap();
            let (send, receive) = mpsc::sync_channel(1);
            state.sending = Some(receive);
            state.sending_deadline = Some(now);
            if timeout {
                assert_eq!(
                    state.expire(now + Duration::from_secs(10)),
                    Some(Failure::Deadline)
                );
            } else {
                drop(action_send);
                send.send(Err(Failure::Secret)).unwrap();
                assert_eq!(state.collect(), Some(Failure::Secret));
            }
            assert!(state.pending_log_action.is_none());
            assert!(matches!(
                state.verdict_events.last(),
                Some(EventKind::HeartbeatCheckVerdict {
                    action: HeartbeatAction::Withheld,
                    ..
                })
            ));
        }
    }

    #[test]
    fn delivered_log_and_failure_status_do_not_advance_last_success() {
        let origin = Instant::now();
        let cfg = settings("status_code", 10);
        let mut state = Heartbeat {
            last_success: Some(origin),
            ..Heartbeat::default()
        };
        for (step, reset, code) in [(1, true, 3), (2, false, 3), (3, false, 0)] {
            let now = origin + Duration::from_secs(step * 10);
            if reset {
                queue_reset(&mut state, now);
            } else {
                queue(&mut state, now, code, true);
            }
            let Some(Work::Send { suffix, .. }) =
                state.iteration(now, origin, true, Some(context(&cfg)))
            else {
                panic!("expected delivery");
            };
            assert_eq!(
                suffix,
                if reset {
                    "/log"
                } else if code == 0 {
                    "/0"
                } else {
                    "/3"
                }
            );
            let (send, receive) = mpsc::sync_channel(1);
            state.sending = Some(receive);
            send.send(Ok(Delivered::new(now, &suffix))).unwrap();
            assert_eq!(state.collect(), None);
            assert_eq!(
                state.last_success,
                Some(if code == 0 { now } else { origin })
            );
        }
    }

    #[test]
    fn check_events_use_the_bounded_log_even_when_delivery_is_unavailable() {
        use crate::events::{EventLog, read_since};
        use scupper_core::config::GatewayId;
        use scupper_proto::UnixSeconds;
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("heartbeat-verdict-log-{}", std::process::id()));
        let log = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
        let origin = Instant::now();
        let cfg = settings("status_code", 60);
        let mut state = Heartbeat::default();
        // A delivery already in progress withholds this fresh failure but must
        // not discard its audit event.
        let (_send, receive) = mpsc::sync_channel(1);
        state.sending = Some(receive);
        queue_reset(&mut state, origin);
        let _ = state.iteration(origin, origin, true, Some(context(&cfg)));
        state.report_events(&log.handle, Some(1));
        // An incomplete check does not recover the failure or emit an event.
        queue(&mut state, origin, 0, false);
        let _ = state.iteration(origin, origin, true, Some(context(&cfg)));
        state.report_events(&log.handle, Some(1));
        state.sending = None;
        // Even a full fresh verdict that aged out of its delivery window is
        // useful evidence; recovery is recorded as withheld.
        queue(&mut state, origin, 0, true);
        let _ = state.iteration(
            origin + Duration::from_secs(30),
            origin,
            true,
            Some(context(&cfg)),
        );
        state.report_events(&log.handle, Some(1));
        log.handle.flush_blocking(Duration::from_secs(2)).unwrap();
        let events: Vec<_> = read_since(&root, 0, None)
            .map(Result::unwrap)
            .filter(|event| {
                matches!(
                    event.kind,
                    EventKind::HeartbeatCheckVerdict { .. }
                        | EventKind::HeartbeatCheckRecovered { .. }
                )
            })
            .collect();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0].kind,
            EventKind::HeartbeatCheckVerdict {
                code: 3,
                action: HeartbeatAction::Withheld,
                count: 1,
                ..
            }
        ));
        assert!(matches!(
            events[1].kind,
            EventKind::HeartbeatCheckRecovered {
                code: 0,
                action: HeartbeatAction::Withheld,
                ..
            }
        ));
        drop(log);
        std::fs::remove_dir_all(root).unwrap();
    }
}
