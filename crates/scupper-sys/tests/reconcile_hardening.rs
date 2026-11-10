//! Reconciler hardening: transient containment failures, fights with failing containment,
//! and unselected exit events while collection stalls.
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
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(
            || std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
            std::path::PathBuf::from,
        )
        .join("reconcile-hardening")
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

fn fwd(rig: &Rig) -> Known<i64> {
    rig.kernel.model().forwarding_v4
}
fn attempts(rig: &Rig, kind: StepKind) -> usize {
    rig.kernel
        .history()
        .iter()
        .filter(|(s, _)| StepKind::from(s) == kind)
        .count()
}

/// CE-17 (spec divergence, pre-existing, fail-closed). One foreign link appears and
/// `ip link set foreign0 down` fails 9 times in a row (for example, nine 3 s exec
/// timeouts under load). No reopen window is ever granted: forwarding stays 0 and
/// no `ForwardingOn` executes. Yet each failure replan that *plans* the reopen
/// reserves `safety:foreign-link`, so the class budget is exhausted inside a single
/// tick and the gateway is quarantined until `repair clear`, after the drift is gone.
/// DESIGN §7: "At most 3 Restore repairs per object ... Tighten repairs are never
/// budgeted"; ADR 0031 budgets count reopen windows.
#[test]
fn h1_transient_emergency_failure_leaves_closed_and_retried() {
    for kind in [
        StepKind::ForwardingOff,
        StepKind::LinkDown,
        StepKind::TcDelete,
    ] {
        let lg = log();
        let mut rig = Rig::new(lg.handle.clone());
        rig.kernel.mutate(foreign);
        rig.kernel.mutate(tc_hook);
        rig.kernel.inject(Fault {
            step: kind,
            remaining: Some(1),
            partial: false,
        });
        rig.kernel
            .observation_latency(Duration::ZERO, Duration::from_secs(20));
        let report = rig.tick();
        assert!(!report.complete, "{kind:?}");
        assert_eq!(
            fwd(&rig),
            Known::Value(0),
            "{kind:?}: not closed after failing tick"
        );
        assert!(
            attempts(&rig, kind) >= 2,
            "{kind:?}: failed containment not retried"
        );
        assert_eq!(
            rig.kernel.model().links["foreign0"].up,
            Known::Value(false),
            "{kind:?}"
        );
        assert_eq!(
            rig.kernel.model().links["wg0"].tc_hooks,
            Known::Value(vec![]),
            "{kind:?}"
        );
        assert!(rig.machine.latch().is_none(), "{kind:?}");
    }
}

/// H-2: repeated fights still exhaust the safety budget and latch with the budget
/// reason, even when each fight's first containment attempt fails.
#[test]
fn h2_fights_with_failing_containment_still_exhaust_safety_budget() {
    let lg = log();
    let mut rig = Rig::new(lg.handle.clone());
    for fight in 0..6 {
        rig.kernel.mutate(foreign);
        rig.kernel.inject(Fault {
            step: StepKind::LinkDown,
            remaining: Some(1),
            partial: false,
        });
        rig.settle();
        if let Some(latch) = rig.machine.latch() {
            assert!(latch.reason.contains("budget"), "fight {fight}: {latch:?}");
            assert_eq!(fwd(&rig), Known::Value(0));
            return;
        }
    }
    panic!("six foreign-link fights never exhausted the safety budget");
}

/// H-3: an unselected exit that is down or missing, with phase B stalled, causes no
/// closure (B1/B3 in the emergency path, not only through the full plan).
#[test]
fn h3_unselected_exit_events_with_stalled_phase_b_do_not_close() {
    for missing in [false, true] {
        let lg = log();
        let mut rig = Rig::with_site(lg.handle.clone(), multi_exit_site(), true);
        rig.kernel.mutate(|m| {
            if missing {
                m.links.remove("ex-ch2");
            } else {
                m.links.get_mut("ex-ch2").unwrap().up = Known::Value(false);
            }
        });
        rig.kernel
            .observation_latency(Duration::ZERO, Duration::from_secs(20));
        rig.tick();
        assert_eq!(closes(&rig), 0, "missing={missing}");
        assert_eq!(fwd(&rig), Known::Value(1), "missing={missing}");
    }
}
