//! Fresh heartbeat checks and bounded delivery run outside the watchdog loop.
use super::{Runtime, admin, probes};
use crate::{
    boot::{BootDeps, GatewayNamespace},
    heartbeat::{self, Failure, Request},
    system::RealSystem,
};
use scupper_core::{
    failover::MonoTime,
    heartbeat::{CompleteIteration, Decision, decide},
};
use scupper_proto::{Actor, EventKind, Reason};
use std::{
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

struct Checked {
    at: Instant,
    version: u64,
    code: u8,
    full_fresh_check: bool,
    namespace: (u64, u64),
}

#[derive(Default)]
pub(super) struct Heartbeat {
    check_at: Option<Instant>,
    check: Option<Receiver<Checked>>,
    sending: Option<Receiver<Result<Instant, Failure>>>,
    sending_deadline: Option<Instant>,
    last_send: Option<Instant>,
    workers: Vec<std::thread::JoinHandle<()>>,
    pub(super) last_success: Option<Instant>,
}
impl Heartbeat {
    pub(super) fn abandon_check(&mut self) {
        self.check = None;
        self.check_at = None;
    }
    // Shared by the real runtime and fake-clock tests. All eligibility and
    // cadence decisions live here; only starting work is delegated to Runtime.
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
                let mono = |at: Instant| MonoTime(at.saturating_duration_since(origin));
                if let Decision::Send {
                    url_suffix,
                    deadline,
                } = decide(
                    context.settings,
                    mono(now),
                    Some(CompleteIteration {
                        at: mono(checked.at),
                        full_fresh_check: checked.full_fresh_check,
                        code: checked.code,
                    }),
                    self.last_send.map(mono),
                ) {
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
            .interval
            .duration()
            .unwrap_or(Duration::MAX);
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
        }
        if send_stuck {
            self.sending = None;
            self.sending_deadline = None;
        }
        (check_stuck || send_stuck).then_some(Failure::Deadline)
    }
    // Rebuild/apply may close the old namespace only after its read-only check
    // workers release their handles. This bounded wait occurs during closed
    // administrative/rebuild work, never on the normal heartbeat iteration.
    pub(super) fn drain_checks(&mut self, deadline: Instant) -> bool {
        self.abandon_check();
        loop {
            self.workers.retain(|worker| !worker.is_finished());
            if self.workers.is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
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
    settings: &'a scupper_core::config::HeartbeatSettings,
    version: u64,
    namespace: (u64, u64),
}
enum Work {
    Check,
    Send { suffix: String, deadline: Instant },
}
fn failure_event(failure: Failure) -> EventKind {
    let reason = match failure {
        Failure::Secret => Reason::HeartbeatSecret,
        Failure::Account => Reason::HeartbeatAccount,
        Failure::Http => Reason::HeartbeatHttp,
        Failure::Deadline => Reason::HeartbeatDeadline,
        Failure::Internal => Reason::ExecutionFailed,
    };
    EventKind::HeartbeatFailed { reason }
}
impl Runtime<'_> {
    pub(super) fn heartbeat_failed_deadline(&self) {
        self.heartbeat_failed(Failure::Deadline);
    }
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
        let context = self.running.as_ref().and_then(|(_, held, config)| {
            config.site.heartbeat().map(|settings| Context {
                settings,
                version: config.stamp.version,
                namespace: held.identity(),
            })
        });
        let work = self
            .heartbeat
            .iteration(now, self.origin, complete, context);
        match work {
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
            settings,
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
            full_fresh_check: fresh,
            version: 1,
            namespace: (2, 3),
        })
        .unwrap();
    }
    #[test]
    fn namespace_worker_is_drained_before_rebuild_and_stuck_worker_refuses() {
        let lease = std::sync::Arc::new(());
        let weak = std::sync::Arc::downgrade(&lease);
        let (release, wait) = mpsc::sync_channel(1);
        let mut state = Heartbeat::default();
        state.workers.push(std::thread::spawn(move || {
            let _ = wait.recv();
            drop(lease);
        }));
        state.abandon_check();
        assert!(weak.upgrade().is_some());
        assert!(!state.drain_checks(Instant::now()));
        release.send(()).unwrap();
        assert!(state.drain_checks(Instant::now() + Duration::from_secs(1)));
        assert!(weak.upgrade().is_none());
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
                None => {}
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
                    settings: &cfg,
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
