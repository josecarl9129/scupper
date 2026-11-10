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
    last_send: Option<Instant>,
    pub(super) last_success: Option<Instant>,
}
impl Heartbeat {
    pub(super) fn abandon_check(&mut self) {
        self.check = None;
        self.check_at = None;
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
        if !complete {
            return;
        }
        let Some((_, held, config)) = &self.running else {
            return;
        };
        let Some(settings) = config.site.heartbeat().cloned() else {
            self.heartbeat.check = None;
            return;
        };
        let checked = self.heartbeat.checked();
        let now = Instant::now();
        if let Some(checked) = checked {
            // A check from a replaced configuration cannot authorize a delivery.
            if checked.version == config.stamp.version
                && checked.namespace == held.identity()
                && self.heartbeat.sending.is_none()
            {
                let mono = |at: Instant| MonoTime(at.saturating_duration_since(self.origin));
                if let Decision::Send {
                    url_suffix,
                    deadline,
                } = decide(
                    &settings,
                    mono(now),
                    Some(CompleteIteration {
                        at: mono(checked.at),
                        full_fresh_check: checked.full_fresh_check,
                        code: checked.code,
                    }),
                    self.heartbeat.last_send.map(mono),
                ) {
                    self.heartbeat.last_send = Some(now);
                    let deadline = self.origin + deadline.0;
                    self.launch_heartbeat(settings.url_ref, url_suffix, deadline);
                }
            }
        }
        let Some((_, held, config)) = &self.running else {
            return;
        };
        if self.heartbeat.check.is_some()
            || self.heartbeat.sending.is_some()
            || self.heartbeat.check_at.is_some_and(|last| {
                now.saturating_duration_since(last)
                    < settings.interval.duration().unwrap_or(Duration::MAX)
            })
        {
            return;
        }
        self.start_heartbeat_check(now, held.clone(), config.clone());
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
                let deadline = Instant::now() + Duration::from_secs(20);
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
                let at = Instant::now();
                let _ = send.send(Checked {
                    at,
                    version: config.stamp.version,
                    code,
                    full_fresh_check: at < deadline,
                    namespace: held.identity(),
                });
            });
        if result.is_err() {
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
