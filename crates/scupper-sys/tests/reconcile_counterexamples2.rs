//! Re-review counterexamples CE-8..CE-12 for the second reconciler fix round.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::panic)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    failover::MonoTime,
    planner::{Desired, KernelModel, Known, NamespaceState, Step},
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
    Desired::new(
        &support::site("ubuntu-24.04"),
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
        .join("../../target/reconcile-fix-ce")
        .join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&root).unwrap();
    root
}
fn config(root: &Path) -> Config {
    Config {
        site: support::site("ubuntu-24.04"),
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
}
impl Rig {
    fn new(log: LogHandle) -> Self {
        let root = root();
        let kernel = FakeKernel::new(desired());
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
            config(&root),
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
        };
        rig.settle();
        assert!(rig.healthy(), "rig did not reach the healthy baseline");
        rig.kernel.clear_history();
        rig
    }
    fn tick(&mut self) -> TickReport {
        self.machine.submit_probe_round(BTreeMap::from([(
            scupper_core::config::ExitId("ch1".into()),
            true,
        )]));
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

/// CE-8: removal of the name alone is a rebind, not a forwarding hazard.
#[test]
fn ce8_name_removal_alone_does_not_cut_clients() {
    let log = log();
    let mut rig = Rig::new(log.handle.clone());
    rig.kernel
        .mutate(|m| m.namespace = NamespaceState::NameGone);
    let report = rig.tick();
    assert!(
        !report.steps.contains(&Step::ForwardingOff),
        "name removal closed forwarding: {:?}",
        report.steps
    );
    assert!(
        !rig.blackholed(),
        "name removal blackholed the default routes"
    );
}

/// CE-9: an edge restart escalation must not repeatedly close forwarding.
#[test]
fn ce9_edge_elsewhere_does_not_flap_forwarding() {
    let log = log();
    let mut rig = Rig::new(log.handle.clone());
    rig.kernel
        .mutate(|m| m.namespace = NamespaceState::EdgeElsewhere);
    let mut closes = 0;
    for _ in 0..8 {
        closes += rig
            .tick()
            .steps
            .iter()
            .filter(|s| **s == Step::ForwardingOff)
            .count();
    }
    assert_eq!(
        closes, 0,
        "EdgeElsewhere closed forwarding {closes} times in 8 ticks"
    );
}

/// CE-10: hook containment must leave correct default routes alone.
#[test]
fn ce10_tc_hook_prefix_does_not_blackhole_a_correct_route() {
    let log = log();
    let mut rig = Rig::new(log.handle.clone());
    rig.kernel.mutate(tc_hook);
    rig.tick();
    assert!(
        !rig.blackholed(),
        "tc-hook containment replaced correct routes: {:?}",
        rig.kernel
            .history()
            .iter()
            .map(|(s, _)| s.clone())
            .collect::<Vec<_>>()
    );
}

/// CE-11: mixed safety classes in one window must not consume route repairs.
#[test]
fn ce11_unrelated_safety_drifts_do_not_exhaust_the_route_budget() {
    let log = log();
    let mut rig = Rig::new(log.handle.clone());
    for i in 0..4 {
        if i % 2 == 0 {
            rig.kernel.mutate(tc_hook);
        } else {
            rig.kernel.mutate(foreign);
        }
        rig.tick();
        rig.settle();
    }
    rig.settle();
    assert!(rig.machine.latch().is_none(), "unexpected latch");
    assert!(
        rig.healthy(),
        "no latch, no drift, but clients are still cut: {:?} forwarding {:?}",
        rig.kernel.model().default_v4,
        rig.kernel.model().forwarding_v4
    );
}

/// CE-12: a transient hardening write failure must re-observe routes fully.
#[test]
fn ce12_failed_restore_recovery_keeps_a_correct_route() {
    let log = log();
    let mut rig = Rig::new(log.handle.clone());
    let key = desired().hardening()[0].key.to_string();
    rig.kernel.mutate(|m| {
        m.hardening.insert(key.clone(), Known::Value("999".into()));
    });
    rig.kernel.inject(Fault {
        step: StepKind::WriteSysctl,
        remaining: Some(1),
        partial: false,
    });
    let mut failed = false;
    for _ in 0..3 {
        failed |= rig
            .tick()
            .failures
            .iter()
            .any(|(s, _)| matches!(s, Step::WriteSysctl { .. }));
    }
    assert!(failed, "fault was not exercised");
    assert!(
        !rig.blackholed(),
        "recovery after a hardening write failure blackholed the routes"
    );
}
