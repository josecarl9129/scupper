//! Third-round counterexamples CE-13..CE-16 for the 2n reconciler (fix2).
//! Drop-in for `crates/scupper-sys/tests/`; run with
//! `cargo test -p scupper-sys --all-features --test reconcile_counterexamples3`.
//! Measured on 533c75c (fix2): all four fail. On e72300b (fix1): CE-13, CE-15 and
//! CE-16 pass (regressions of this round); CE-14 fails there too (pre-existing).
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::panic, dead_code)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    failover::MonoTime,
    planner::{Desired, KernelModel, Known, Step},
    render::{RouteTarget, VersionStamp},
    verdict::v2::{DefaultRouteObs, Selection},
};
use scupper_proto::{StepKind, UnixSeconds};
use scupper_sys::{
    events::{EventLog, LogHandle},
    netns::testing,
    reconcile::{
        Config, Reconciler, TickReport,
        fake::{FakeKernel, Fault, MemoryStore},
    },
    state::State,
};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
type Machine = Reconciler<FakeKernel, MemoryStore, Box<dyn Fn() -> (MonoTime, u64)>>;
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn stamp() -> VersionStamp {
    VersionStamp {
        version: 1,
        sha256: [0; 32],
    }
}
fn desired() -> Desired {
    desired_for(&support::site("ubuntu-24.04"))
}
fn desired_for(site: &scupper_core::config::ValidatedSite) -> Desired {
    Desired::new(
        site,
        &GatewayId("gw1".into()),
        &stamp(),
        [7; 32],
        &RouteTarget::Unreachable,
        &Selection::Auto,
    )
    .unwrap()
}
fn root() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/reconcile-fix2-ce")
        .join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&root).unwrap();
    root
}
fn config(root: &Path, site: &scupper_core::config::ValidatedSite) -> Config {
    Config {
        site: site.clone(),
        gateway: GatewayId("gw1".into()),
        stamp: stamp(),
        fingerprint: [7; 32],
        run_root: root.into(),
        lock_wait: Duration::ZERO,
    }
}
struct Rig {
    root: PathBuf,
    kernel: FakeKernel,
    time: Rc<Cell<u64>>,
    machine: Machine,
    two: bool,
}
impl Rig {
    fn new(log: LogHandle) -> Self {
        Self::with_site(log, support::site("ubuntu-24.04"), false)
    }
    #[allow(clippy::needless_pass_by_value)] // Preserve the supplied fixture signature.
    fn with_site(log: LogHandle, site: scupper_core::config::ValidatedSite, two: bool) -> Self {
        let root = root();
        let kernel = FakeKernel::new(desired_for(&site));
        let store = MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        });
        let time = Rc::new(Cell::new(0_u64));
        let t = time.clone();
        let machine = Reconciler::new(
            kernel.clone(),
            store,
            log,
            config(&root, &site),
            Arc::new(testing::handle().unwrap()),
            Box::new(move || (MonoTime(Duration::from_secs(t.get())), 1000 + t.get()))
                as Box<dyn Fn() -> (MonoTime, u64)>,
        )
        .unwrap();
        let mut rig = Self {
            root,
            kernel,
            time,
            machine,
            two,
        };
        rig.settle();
        assert!(rig.healthy(), "rig did not reach the healthy baseline");
        rig.kernel.clear_history();
        rig
    }
    fn tick(&mut self) -> TickReport {
        let mut round = BTreeMap::from([(scupper_core::config::ExitId("ch1".into()), true)]);
        if self.two {
            self.kernel.handshake(
                scupper_core::config::ExitId("ch2".into()),
                Some(Duration::from_secs(1)),
            );
            round.insert(scupper_core::config::ExitId("ch2".into()), true);
        }
        self.machine.submit_probe_round(round);
        self.time.set(self.time.get() + 2);
        self.machine.tick()
    }
    fn settle(&mut self) {
        for _ in 0..6 {
            self.tick();
        }
    }
    fn healthy(&self) -> bool {
        let m = self.kernel.model();
        m.default_v4 == Known::Value(DefaultRouteObs::Dev("ex-ch1".into()))
            && m.forwarding_v4 == Known::Value(1)
    }
    fn blackholed(&self) -> bool {
        self.kernel.history().iter().any(|(step, _)| {
            matches!(
                step,
                Step::RouteReplace {
                    target: RouteTarget::Unreachable,
                    ..
                }
            )
        })
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn log() -> scupper_sys::events::OpenedLog {
    EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap()
}
fn foreign(model: &mut KernelModel) {
    let mut link = KernelModel::desired(&desired()).links["wg0"].clone();
    link.kind = Known::Value("veth".into());
    link.ours = Known::Value(false);
    link.peers = Known::Value(vec![]);
    model.links.insert("foreign0".into(), link);
}
fn tc_hook(model: &mut KernelModel) {
    model.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
}

fn multi_exit_site() -> scupper_core::config::ValidatedSite {
    use scupper_core::config::{ExitId, parse_site, testing_build};
    let mut cfg = parse_site(include_str!(
        "../../scupper-core/tests/fixtures/site-m2.toml"
    ))
    .unwrap();
    let gateway = GatewayId("gw1".into());
    let mut second = cfg.gateways[&gateway].exits[0].clone();
    second.id = ExitId("ch2".into());
    second.ifname = "ex-ch2".into();
    cfg.gateways.get_mut(&gateway).unwrap().exits.push(second);
    cfg.policy.exits.push(ExitId("ch2".into()));
    testing_build(cfg).unwrap()
}
fn closes(rig: &Rig) -> usize {
    rig.kernel
        .history()
        .iter()
        .filter(|(s, _)| *s == Step::ForwardingOff)
        .count()
}

/// CE-13 (blocking: client outage on a harmless event). An *unselected* exit link
/// is set administratively down. No packet can leak and the full-model planner keeps
/// serving through ex-ch1 (`safe()` accepts a down desired link). The fix2 predicate
/// compares link UP with intent, so phase A treats it as safety drift; the phase-A
/// prefix plan has `safe() == false` and executes `ForwardingOff`; the reopen is a
/// debounced Restore, so clients are cut for about two ticks and conntrack is flushed.
#[test]
fn ce13_unselected_exit_down_does_not_close_forwarding() {
    let log = log();
    let mut rig = Rig::with_site(log.handle.clone(), multi_exit_site(), true);
    rig.kernel
        .mutate(|m| m.links.get_mut("ex-ch2").unwrap().up = Known::Value(false));
    rig.tick();
    let after_first = rig.kernel.model().forwarding_v4.clone();
    rig.settle();
    assert_eq!(
        closes(&rig),
        0,
        "unselected exit down closed forwarding (after drift tick: {after_first:?})"
    );
}

/// CE-14 (blocking: permanent flapping on a non-safety event). An unselected exit's
/// namespace link is gone and a same-name host link blocks recreation (a
/// `LinkCollision` escalation for the operator). The full plan keeps serving, but
/// `safety_drift` treats every missing desired link as drift: each tick's phase A
/// closes forwarding and phase B reopens it with a conntrack flush.
#[test]
fn ce14_missing_unselected_exit_does_not_flap_forwarding() {
    let log = log();
    let mut rig = Rig::with_site(log.handle.clone(), multi_exit_site(), true);
    rig.kernel.mutate(|m| {
        let mut link = m.links.remove("ex-ch2").unwrap();
        link.ours = Known::Value(false);
        m.host_links.insert("ex-ch2".into(), link);
    });
    for _ in 0..8 {
        rig.tick();
    }
    let flushes = rig
        .kernel
        .history()
        .iter()
        .filter(|(s, _)| *s == Step::FlushConntrack)
        .count();
    assert_eq!(
        closes(&rig),
        0,
        "missing unselected exit: {} closes and {flushes} conntrack flushes in 8 ticks",
        closes(&rig)
    );
}

/// CE-15 (blocking: spec divergence, ADR 0031). One transient `LinkDown` failure
/// during an operator disconnect creates a durable quarantine
/// ("containment execution failed"). After a successful retry and `connect`, the
/// gateway never serves again until `repair clear`. ADR 0031: only an exhausted
/// safety budget sets the latch; "only safety suppression closes the gateway".
#[test]
fn ce15_transient_containment_failure_does_not_quarantine() {
    let log = log();
    let mut rig = Rig::new(log.handle.clone());
    rig.kernel.inject(Fault {
        step: StepKind::LinkDown,
        remaining: Some(1),
        partial: false,
    });
    let _ = rig.machine.set_selection(
        Selection::Disconnected,
        scupper_proto::Actor::Local { uid: 0 },
    );
    rig.machine
        .set_selection(
            Selection::Disconnected,
            scupper_proto::Actor::Local { uid: 0 },
        )
        .unwrap();
    rig.machine
        .set_selection(Selection::Auto, scupper_proto::Actor::Local { uid: 0 })
        .unwrap();
    for _ in 0..4 {
        rig.settle();
    }
    assert!(
        rig.machine.latch().is_none(),
        "transient LinkDown failure latched: {:?}",
        rig.machine.latch()
    );
    assert!(rig.healthy(), "clients not restored after connect");
}

/// CE-16 (follow-up). A dropped audit event (full or stopped log) is `NonFatal`, but it
/// arms `refresh_before_restore`; the refresh `observe()` resets the conntrack-flush
/// guard after `FlushConntrack` already ran, so the following `ForwardingOn` is
/// refused and the tick ends closed. Event-log health changes kernel outcome.
#[test]
fn ce16_dropped_event_does_not_refuse_same_tick_reopen() {
    let outcome = |dead: bool| {
        let ok = log();
        let handle = ok.handle.clone();
        let mut rig = Rig::new(handle);
        let _keep = if dead {
            drop(ok.log);
            None
        } else {
            Some(ok)
        };
        // Forwarding off with a verified ruleset; reopen is planned after debounce.
        rig.kernel.mutate(tc_hook);
        rig.tick();
        rig.kernel.inject(Fault {
            step: StepKind::ForwardingOn,
            remaining: Some(1),
            partial: false,
        });
        let report = rig.tick();
        (
            report
                .failures
                .iter()
                .filter(|(s, _)| matches!(s, Step::ForwardingOn { .. }))
                .count(),
            rig.kernel.model().forwarding_v4,
        )
    };
    let healthy = outcome(false);
    let dead = outcome(true);
    assert_eq!(healthy, dead, "dropped events changed the reopen outcome");
}
