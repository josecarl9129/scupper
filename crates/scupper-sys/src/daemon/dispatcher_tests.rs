//! Exercises the production dispatcher with independent intent and worker boundaries.
#![allow(clippy::unwrap_used)]
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Rig {
    clock: Option<Instant>,
    intents: Vec<Op>,
    failure: Option<ApiErrorCode>,
    workers: RefCell<Vec<SyncSender<Result<Report, ApiError>>>>,
    applies: usize,
}
impl Backend for Rig {
    fn now(&self) -> Instant {
        self.clock.unwrap_or_else(Instant::now)
    }
    fn intent(&mut self, op: &Op, _: u32) -> Result<(), ApiError> {
        if let Some(error) = self.failure.take() {
            return Err(control::api(error));
        }
        if matches!(op, Op::Connect { .. } | Op::Disconnect {}) {
            self.intents.push(op.clone());
        }
        Ok(())
    }
    fn execute(&mut self, op: Op, _: u32) -> Result<OpResult, ApiError> {
        assert!(matches!(op, Op::Apply { .. }));
        self.applies += 1;
        Ok(OpResult::Apply {
            version: 1,
            dry_run: false,
            repair_plan: Vec::new(),
            plan: Vec::new(),
        })
    }
    fn check(&self, _: Instant) -> Option<Worker> {
        let (send, receive) = mpsc::sync_channel(1);
        self.workers.borrow_mut().push(send);
        Some(receive)
    }
}
fn enqueue(
    dispatcher: &mut Dispatcher,
    rig: &mut Rig,
    request: Request,
    now: Instant,
    until: Instant,
) -> Receiver<Response> {
    rig.clock = Some(now);
    let (reply, receive) = mpsc::sync_channel(1);
    dispatcher.dispatch(
        control::Pending {
            peer: None,
            request,
            uid: 0,
            until,
            reply,
        },
        rig,
        now,
    );
    receive
}
fn report(op: &Op) -> Report {
    Report {
        verdict: if matches!(op, Op::Disconnect {}) {
            Verdict::FailClosed(FailClosed::AdminDisconnected)
        } else {
            Verdict::Protected {
                exit: scupper_core::config::ExitId("ch1".into()),
                exit_ip: "203.0.113.7".parse().unwrap(),
            }
        },
        warnings: Vec::new(),
        at: 1000,
        config_version: 1,
    }
}
#[test]
fn dispatcher_same_intent_and_supersession() {
    let now = Instant::now();
    for (first, second) in [
        (Op::Connect { exit: None }, Op::Disconnect {}),
        (Op::Disconnect {}, Op::Connect { exit: None }),
    ] {
        let mut dispatcher = Dispatcher::default();
        let mut rig = Rig::default();
        let request = control::request(first.clone());
        let original = enqueue(
            &mut dispatcher,
            &mut rig,
            request.clone(),
            now,
            now + control::QUEUE_TIMEOUT,
        );
        let repeated = enqueue(
            &mut dispatcher,
            &mut rig,
            request.clone(),
            now,
            now + control::QUEUE_TIMEOUT,
        );
        let same_intent_request = control::request(first.clone());
        let same_intent_id = same_intent_request.request_id.clone();
        let same_intent = enqueue(
            &mut dispatcher,
            &mut rig,
            same_intent_request,
            now,
            now + control::QUEUE_TIMEOUT,
        );
        assert_eq!(rig.intents, vec![first.clone()]);
        let mut collision = request.clone();
        collision.op = second.clone();
        let conflict = enqueue(
            &mut dispatcher,
            &mut rig,
            collision,
            now,
            now + control::QUEUE_TIMEOUT,
        );
        assert_eq!(
            conflict.recv().unwrap().result.unwrap_err().code,
            ApiErrorCode::Conflict
        );
        dispatcher.poll_admin(&mut rig, now);
        let old_worker = rig.workers.borrow_mut().remove(0);
        let next = enqueue(
            &mut dispatcher,
            &mut rig,
            control::request(second.clone()),
            now,
            now + control::QUEUE_TIMEOUT,
        );
        for receiver in [&original, &repeated, &same_intent] {
            assert_eq!(
                receiver.recv().unwrap().result.unwrap_err().code,
                ApiErrorCode::Conflict
            );
        }
        assert!(old_worker.send(Ok(report(&first))).is_err());
        assert!(next.try_recv().is_err());
        dispatcher.poll_admin(&mut rig, now);
        rig.workers
            .borrow_mut()
            .remove(0)
            .send(Ok(report(&second)))
            .unwrap();
        dispatcher.poll_admin(&mut rig, now);
        assert!(next.recv().unwrap().result.is_ok());
        assert_eq!(rig.intents, vec![first, second]);
        // The attached id is also retained as the correlated superseded outcome.
        let replay = enqueue(
            &mut dispatcher,
            &mut rig,
            Request {
                request_id: same_intent_id,
                op: request.op,
            },
            now,
            now + control::QUEUE_TIMEOUT,
        );
        assert!(replay.recv().unwrap().replayed);
    }
}
#[test]
fn dispatcher_same_intent_success_correlates_every_id() {
    let now = Instant::now();
    let mut dispatcher = Dispatcher::default();
    let mut rig = Rig::default();
    let first = control::request(Op::Disconnect {});
    let second = control::request(Op::Disconnect {});
    let a = enqueue(
        &mut dispatcher,
        &mut rig,
        first.clone(),
        now,
        now + control::QUEUE_TIMEOUT,
    );
    let b = enqueue(
        &mut dispatcher,
        &mut rig,
        second.clone(),
        now,
        now + control::QUEUE_TIMEOUT,
    );
    dispatcher.poll_admin(&mut rig, now);
    rig.workers
        .borrow_mut()
        .remove(0)
        .send(Ok(report(&first.op)))
        .unwrap();
    dispatcher.poll_admin(&mut rig, now);
    for (receiver, request) in [(a, first), (b, second)] {
        let response = receiver.recv().unwrap();
        assert_eq!(response.request_id, request.request_id);
        assert!(response.result.is_ok());
        let replay = enqueue(
            &mut dispatcher,
            &mut rig,
            request,
            now,
            now + control::QUEUE_TIMEOUT,
        );
        assert!(replay.recv().unwrap().replayed);
    }
    assert_eq!(rig.intents.len(), 1);
}
#[test]
fn dispatcher_expiry_and_unexecuted_retry() {
    let now = Instant::now();
    for error in [ApiErrorCode::Conflict, ApiErrorCode::Quarantined] {
        let mut dispatcher = Dispatcher::default();
        let mut rig = Rig::default();
        let request = control::request(Op::Disconnect {});
        let expired = enqueue(
            &mut dispatcher,
            &mut rig,
            request.clone(),
            now,
            now.checked_sub(Duration::from_secs(1)).unwrap(),
        );
        assert_eq!(
            expired.recv().unwrap().result.unwrap_err().code,
            ApiErrorCode::Timeout
        );
        assert_eq!(rig.intents.len(), 0);
        rig.failure = Some(error);
        let refused = enqueue(
            &mut dispatcher,
            &mut rig,
            request.clone(),
            now,
            now + control::QUEUE_TIMEOUT,
        );
        assert_eq!(refused.recv().unwrap().result.unwrap_err().code, error);
        let retry = enqueue(
            &mut dispatcher,
            &mut rig,
            request,
            now,
            now + control::QUEUE_TIMEOUT,
        );
        // A three-second tick fits the queue budget and does not block polling.
        dispatcher.poll_admin(&mut rig, now + Duration::from_secs(3));
        assert!(retry.try_recv().is_err());
        rig.workers
            .borrow_mut()
            .remove(0)
            .send(Ok(report(&Op::Disconnect {})))
            .unwrap();
        dispatcher.poll_admin(&mut rig, now + Duration::from_secs(3));
        assert!(retry.recv().unwrap().result.is_ok());
        assert_eq!(rig.intents.len(), 1);
    }
}
#[test]
fn dispatcher_pending_across_apply() {
    let now = Instant::now();
    let mut dispatcher = Dispatcher::default();
    let mut rig = Rig::default();
    let connect = enqueue(
        &mut dispatcher,
        &mut rig,
        control::request(Op::Connect { exit: None }),
        now,
        now + control::QUEUE_TIMEOUT,
    );
    let request = control::request(Op::Check {});
    let check = enqueue(
        &mut dispatcher,
        &mut rig,
        request.clone(),
        now,
        now + control::QUEUE_TIMEOUT,
    );
    dispatcher.poll_admin(&mut rig, now);
    let old_workers = std::mem::take(&mut *rig.workers.borrow_mut());
    let applied = enqueue(
        &mut dispatcher,
        &mut rig,
        control::request(Op::Apply {
            version: None,
            dry_run: false,
        }),
        now,
        now + control::QUEUE_TIMEOUT,
    );
    assert!(applied.recv().unwrap().result.is_ok());
    assert_eq!(
        check.recv().unwrap().result.unwrap_err().code,
        ApiErrorCode::SupervisorUnavailable
    );
    for old in old_workers {
        assert!(old.send(Ok(report(&Op::Check {}))).is_err());
    }
    assert!(connect.try_recv().is_err());
    let retry = enqueue(
        &mut dispatcher,
        &mut rig,
        request,
        now,
        now + control::QUEUE_TIMEOUT,
    );
    dispatcher.poll_admin(&mut rig, now);
    for sender in rig.workers.borrow_mut().drain(..) {
        sender
            .send(Ok(report(&Op::Connect { exit: None })))
            .unwrap();
    }
    dispatcher.poll_admin(&mut rig, now);
    assert!(connect.recv().unwrap().result.is_ok());
    assert!(retry.recv().unwrap().result.is_ok());
    assert_eq!(rig.applies, 1);
}

#[test]
fn dispatcher_three_second_tick_does_not_expire_requests() {
    let now = Instant::now();
    let mut dispatcher = Dispatcher::default();
    let mut rig = Rig::default();
    let response = enqueue(
        &mut dispatcher,
        &mut rig,
        control::request(Op::Disconnect {}),
        now + Duration::from_secs(3),
        now + control::QUEUE_TIMEOUT,
    );
    assert!(response.try_recv().is_err());
    assert_eq!(rig.intents, vec![Op::Disconnect {}]);
    dispatcher.poll_admin(&mut rig, now + Duration::from_secs(3));
    rig.workers
        .borrow_mut()
        .remove(0)
        .send(Ok(report(&Op::Disconnect {})))
        .unwrap();
    dispatcher.poll_admin(&mut rig, now + Duration::from_secs(3));
    assert!(response.recv().unwrap().result.is_ok());
}

#[test]
fn dispatcher_drops_mutation_after_peer_hangup() {
    let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(client);
    let mut dispatcher = Dispatcher::default();
    let mut rig = Rig::default();
    let (reply, receive) = mpsc::sync_channel(1);
    let now = Instant::now();
    dispatcher.dispatch(
        control::Pending {
            peer: Some(server),
            request: control::request(Op::Disconnect {}),
            uid: 0,
            until: now + Duration::from_secs(30),
            reply,
        },
        &mut rig,
        now,
    );
    assert_eq!(rig.intents, [] as [Op; 0]);
    assert!(receive.recv().is_err());
}
