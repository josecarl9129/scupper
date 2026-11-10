//! Read-only verification workers; only the scheduler persists administrative intent.
use super::{Runtime, control, probes};
use crate::{
    boot::{BootDeps, GatewayNamespace},
    reconcile::Config,
    system::RealSystem,
};
use scupper_core::verdict::v2::{FailClosed, Report, Selection, Verdict};
use scupper_proto::{ApiError, ApiErrorCode, Op, OpResult, Request, Response};
use std::{
    sync::mpsc::{self, Receiver, SyncSender},
    time::{Duration, Instant},
};

pub(super) struct Operation {
    pub request: Request,
    pub replies: Vec<(Request, SyncSender<Response>)>,
    deadline: Instant,
    receive: Option<Receiver<Result<Report, ApiError>>>,
    retry_at: Instant,
    observed_at: Option<scupper_proto::UnixSeconds>,
    last_verified: Option<ApiError>,
}

impl Operation {
    fn poll(&mut self, now: Instant) -> Option<Result<OpResult, ApiError>> {
        let result = self
            .receive
            .as_ref()
            .and_then(|receive| match receive.try_recv() {
                Ok(report) => {
                    if let Ok(report) = &report {
                        self.observed_at = Some(scupper_proto::UnixSeconds(report.at));
                    }
                    Some(report.and_then(|report| {
                        let result = verified(&self.request.op, report);
                        if let Err(error) = &result {
                            self.last_verified = Some(error.clone());
                        }
                        result
                    }))
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err(control::api(ApiErrorCode::Internal)))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(result) = result {
            self.receive = None;
            if result.is_ok() || matches!(self.request.op, Op::Check {}) {
                return Some(result);
            }
            self.retry_at = now + Duration::from_millis(100);
        }
        if now >= self.deadline {
            return Some(Err(self
                .last_verified
                .clone()
                .unwrap_or_else(|| control::api(ApiErrorCode::Timeout))));
        }
        None
    }
}

/// Interpret a fresh observation without making a present-tense cached claim.
pub(super) fn verified(op: &Op, report: Report) -> Result<OpResult, ApiError> {
    match op {
        Op::Check {} => Ok(OpResult::Check {
            health: (&report).into(),
            report: serde_json::to_value(report)
                .map_err(|_| control::api(ApiErrorCode::Internal))?,
        }),
        Op::Connect { .. } => match report.verdict {
            Verdict::Protected { exit, .. } | Verdict::Unsupervised { exit, .. } => {
                Ok(OpResult::Connect {
                    exit: (&exit).into(),
                })
            }
            _ => Err(control::api(ApiErrorCode::NotReady)),
        },
        Op::Disconnect {}
            if report.verdict == Verdict::FailClosed(FailClosed::AdminDisconnected) =>
        {
            Ok(OpResult::Disconnect {})
        }
        Op::Disconnect {} => Err(ApiError {
            code: ApiErrorCode::DisconnectNotEffective,
            observation: serde_json::to_value(report).ok(),
        }),
        _ => Err(control::api(ApiErrorCode::InvalidRequest)),
    }
}
type Worker = Receiver<Result<Report, ApiError>>;
pub(super) trait Backend {
    fn now(&self) -> Instant;
    fn intent(&mut self, op: &Op, uid: u32) -> Result<(), ApiError>;
    fn execute(&mut self, op: Op, uid: u32) -> Result<OpResult, ApiError>;
    fn check(&self, deadline: Instant) -> Option<Worker>;
}
impl Backend for Runtime<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn intent(&mut self, op: &Op, uid: u32) -> Result<(), ApiError> {
        self.intent(op, uid)
    }
    fn execute(&mut self, op: Op, uid: u32) -> Result<OpResult, ApiError> {
        self.operation(op, uid)
    }
    fn check(&self, deadline: Instant) -> Option<Worker> {
        self.running
            .as_ref()
            .map(|(_, held, config)| self.check_worker(held.clone(), config.clone(), deadline))
    }
}
#[derive(Default)]
pub(super) struct Dispatcher {
    dedupe: control::Dedupe,
    pending_admin: Vec<Operation>,
}
impl Dispatcher {
    pub(super) fn dispatch(
        &mut self,
        pending: control::Pending,
        backend: &mut impl Backend,
        now: Instant,
    ) {
        if !matches!(pending.request.op, Op::Disconnect {})
            && pending
                .peer
                .as_ref()
                .is_some_and(|peer| !control::peer_connected(peer))
        {
            return;
        }
        if !control::authorized(pending.uid) {
            let _ = pending.reply.send(control::response(
                pending.request.request_id,
                Err(control::api(ApiErrorCode::Unauthorized)),
            ));
            return;
        }
        if now > pending.until {
            let _ = pending.reply.send(control::response(
                pending.request.request_id,
                Err(control::api(ApiErrorCode::Timeout)),
            ));
            return;
        }
        if let Some(response) = self.dedupe.lookup(&pending.request, now) {
            let _ = pending.reply.send(response);
            return;
        }
        if let Some(inflight) = self.pending_admin.iter_mut().find(|operation| {
            operation
                .replies
                .iter()
                .any(|(request, _)| request.request_id == pending.request.request_id)
        }) {
            if inflight.request.op == pending.request.op {
                inflight.replies.push((pending.request, pending.reply));
            } else {
                let _ = pending.reply.send(control::response(
                    pending.request.request_id,
                    Err(control::api(ApiErrorCode::Conflict)),
                ));
            }
            return;
        }
        if matches!(
            pending.request.op,
            Op::Check {} | Op::Connect { .. } | Op::Disconnect {}
        ) {
            self.begin_admin(pending, backend, now);
        } else {
            if matches!(pending.request.op, Op::Apply { dry_run: false, .. }) {
                self.invalidate_admin_workers(now);
            }
            let applying = matches!(pending.request.op, Op::Apply { dry_run: false, .. });
            let response = self
                .dedupe
                .execute(pending.request, now, |op| backend.execute(op, pending.uid));
            if applying {
                self.invalidate_admin_workers(backend.now());
            }
            let _ = pending.reply.send(response);
        }
    }
    pub(super) fn begin_admin(
        &mut self,
        pending: control::Pending,
        backend: &mut impl Backend,
        now: Instant,
    ) {
        if !control::authorized(pending.uid) {
            let _ = pending.reply.send(control::response(
                pending.request.request_id,
                Err(control::api(ApiErrorCode::Unauthorized)),
            ));
            return;
        }
        if matches!(pending.request.op, Op::Connect { .. } | Op::Disconnect {})
            && let Some(operation) = self
                .pending_admin
                .iter_mut()
                .find(|operation| operation.request.op == pending.request.op)
        {
            operation.replies.push((pending.request, pending.reply));
            return;
        }
        if let Err(error) = backend.intent(&pending.request.op, pending.uid) {
            let response = control::response(pending.request.request_id.clone(), Err(error));
            let _ = pending.reply.send(response);
            return;
        }
        if matches!(pending.request.op, Op::Connect { .. } | Op::Disconnect {}) {
            let previous = std::mem::take(&mut self.pending_admin);
            for operation in previous {
                if matches!(operation.request.op, Op::Connect { .. } | Op::Disconnect {}) {
                    self.finish_admin(operation, Err(control::api(ApiErrorCode::Conflict)), now);
                } else {
                    self.pending_admin.push(operation);
                }
            }
        }
        let duration = if matches!(pending.request.op, Op::Connect { .. }) {
            10
        } else {
            45
        };
        self.pending_admin.push(Operation {
            request: pending.request.clone(),
            replies: vec![(pending.request, pending.reply)],
            deadline: now + Duration::from_secs(duration),
            receive: None,
            retry_at: now,
            observed_at: None,
            last_verified: None,
        });
    }
    pub(super) fn poll_admin(&mut self, backend: &mut impl Backend, now: Instant) {
        let mut active = std::mem::take(&mut self.pending_admin);
        for mut operation in active.drain(..) {
            if let Some(result) = operation.poll(now) {
                self.finish_admin(operation, result, now);
                continue;
            }
            if operation.receive.is_none() && now >= operation.retry_at {
                operation.receive = backend.check(operation.deadline);
                if operation.receive.is_none() && matches!(operation.request.op, Op::Check {}) {
                    self.finish_admin(
                        operation,
                        Err(control::api(ApiErrorCode::SupervisorUnavailable)),
                        now,
                    );
                    continue;
                }
            }
            self.pending_admin.push(operation);
        }
    }
    fn finish_admin(
        &mut self,
        operation: Operation,
        result: Result<OpResult, ApiError>,
        now: Instant,
    ) {
        let mut response = control::response(operation.request.request_id.clone(), result);
        response.observed_at = operation.observed_at.or(response.observed_at);
        self.dedupe
            .remember(operation.request, response.clone(), now);
        for (request, reply) in operation.replies {
            response.request_id = request.request_id.clone();
            self.dedupe.remember(request, response.clone(), now);
            let _ = reply.send(response.clone());
        }
    }
    pub(super) fn invalidate_admin_workers(&mut self, now: Instant) {
        for mut operation in std::mem::take(&mut self.pending_admin) {
            if matches!(operation.request.op, Op::Check {}) {
                self.finish_admin(
                    operation,
                    Err(control::api(ApiErrorCode::SupervisorUnavailable)),
                    now,
                );
            } else {
                operation.receive = None;
                operation.last_verified = None;
                operation.retry_at = now;
                operation.deadline = now
                    + Duration::from_secs(if matches!(operation.request.op, Op::Connect { .. }) {
                        10
                    } else {
                        45
                    });
                self.pending_admin.push(operation);
            }
        }
    }
}

impl Runtime<'_> {
    fn intent(&mut self, op: &Op, uid: u32) -> Result<(), ApiError> {
        let selection = match op {
            Op::Connect { exit } => exit.as_ref().map_or(Selection::Auto, |id| {
                Selection::Prefer(scupper_core::config::ExitId(String::from(id.clone())))
            }),
            Op::Disconnect {} => Selection::Disconnected,
            _ => return Ok(()),
        };
        let Some((machine, _, _)) = &mut self.running else {
            return super::admin::durable_intent(&self.deps(), op, uid);
        };
        if matches!(op, Op::Connect { .. }) && machine.latch().is_some() {
            return Err(control::api(ApiErrorCode::Quarantined));
        }
        let guard = machine
            .writer_guard()
            .map_err(|_| control::api(ApiErrorCode::Conflict))?;
        machine.set_intent_locked(&guard, selection).map_err(|e| {
            control::api(if e.to_string() == "unconfigured exit" {
                ApiErrorCode::InvalidRequest
            } else {
                ApiErrorCode::PersistenceUnavailable
            })
        })?;
        let command = if matches!(op, Op::Disconnect {}) {
            scupper_proto::Command::Disconnect
        } else {
            scupper_proto::Command::Connect
        };
        let _ = self.audit.handle().emit(
            scupper_proto::EventKind::AdminAction {
                reason: None,
                command,
            },
            scupper_proto::Actor::Local { uid },
            Some(machine.version()),
        );
        Ok(())
    }
    fn check_worker(
        &self,
        held: std::sync::Arc<crate::netns::NetnsHandle>,
        config: Config,
        deadline: Instant,
    ) -> Receiver<Result<Report, ApiError>> {
        let (send, receive) = mpsc::sync_channel(1);
        let binary = self.options.probe_binary.clone();
        let run_root = self.options.run_root.clone();
        let state_root = self.options.state_root.clone();
        let config_root = self.options.config_root.clone();
        let snapshot = self.snapshot.clone();
        let _ = std::thread::Builder::new()
            .name("scupper-check".into())
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
                #[cfg(feature = "testing")]
                let trace = verification_trace::Trace::start(
                    &system,
                    &held,
                    &config,
                    deadline,
                    &run_root.join("connect-verification.jsonl"),
                );
                let result = super::admin::check_live(
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
                #[cfg(feature = "testing")]
                if let Some(trace) = trace {
                    trace.finish(&result);
                }
                let _ = send.send(result);
            });
        receive
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn pending_verification_does_not_wait_for_probe_worker() {
        let (held_sender, receive) = mpsc::sync_channel(1);
        let start = Instant::now();
        let mut operation = Operation {
            request: control::request(Op::Check {}),
            replies: Vec::new(),
            deadline: start + Duration::from_secs(45),
            receive: Some(receive),
            retry_at: start,
            observed_at: None,
            last_verified: None,
        };
        assert!(operation.poll(start).is_none());
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(
            operation
                .poll(start + Duration::from_secs(45))
                .unwrap()
                .unwrap_err()
                .code,
            ApiErrorCode::Timeout
        );
        drop(held_sender);
    }
    #[test]
    fn pending_disconnect_requires_real_stage_two_closure() {
        let report = |verdict| Report {
            verdict,
            warnings: Vec::new(),
            at: 1000,
            config_version: 1,
        };
        assert_eq!(
            verified(
                &Op::Disconnect {},
                report(Verdict::Degraded(
                    scupper_core::verdict::v2::Degraded::DisconnectNotEffective
                ))
            )
            .unwrap_err()
            .code,
            ApiErrorCode::DisconnectNotEffective
        );
        assert!(
            verified(
                &Op::Disconnect {},
                report(Verdict::FailClosed(FailClosed::AdminDisconnected))
            )
            .is_ok()
        );
    }
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod dispatcher_tests;

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    #[allow(clippy::unwrap_used)]
    fn disconnect_worker_failure_at_deadline_is_not_internal() {
        let start = Instant::now();
        for (failed_worker, observed) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let (send, receive) = mpsc::sync_channel(1);
            if failed_worker {
                drop(send);
            } else {
                send.send(Err(control::api(ApiErrorCode::Internal)))
                    .unwrap();
            }
            let mut operation = Operation {
                request: control::request(Op::Disconnect {}),
                replies: Vec::new(),
                deadline: start + Duration::from_secs(1),
                receive: None,
                retry_at: start,
                observed_at: None,
                last_verified: None,
            };
            if observed {
                let (first, observed_receive) = mpsc::sync_channel(1);
                first
                    .send(Ok(Report {
                        verdict: Verdict::Degraded(
                            scupper_core::verdict::v2::Degraded::DisconnectNotEffective,
                        ),
                        warnings: Vec::new(),
                        at: 1000,
                        config_version: 1,
                    }))
                    .unwrap();
                operation.receive = Some(observed_receive);
                assert!(operation.poll(start).is_none());
            }
            operation.receive = Some(receive);
            let error = operation
                .poll(start + Duration::from_secs(1))
                .unwrap()
                .unwrap_err();
            assert_eq!(
                error.code,
                if observed {
                    ApiErrorCode::DisconnectNotEffective
                } else {
                    ApiErrorCode::Timeout
                }
            );
            assert_eq!(error.observation.is_some(), observed);
        }
    }
}

#[cfg(feature = "testing")]
#[path = "verification_trace.rs"]
mod verification_trace;
