//! Review regressions CE-1 through CE-7, asserting the required behavior.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::panic)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    failover::MonoTime,
    planner::{Desired, KernelModel, Known, NamespaceState, Ruleset, Step},
    render::{RouteTarget, VersionStamp},
    verdict::v2::{DefaultRouteObs, Selection},
};
use scupper_proto::{Actor, EventKind, UnixSeconds, VerdictCode};
use scupper_sys::{
    events::{EventLog, LogHandle},
    netns::{NetnsHandle, testing},
    reconcile::{
        Config, Escalation, Reconciler, TickReport,
        fake::{FakeKernel, MemoryStore},
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
    time::{Duration, Instant},
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
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(
            || std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
            std::path::PathBuf::from,
        )
        .join("reconcile-ce")
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
    store: MemoryStore,
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
            store.clone(),
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
            store,
            time,
            machine,
        };
        for _ in 0..3 {
            rig.round();
            rig.tick();
        }
        rig.tick();
        rig.kernel.clear_history();
        rig
    }
    fn round(&mut self) {
        self.machine.submit_probe_round(BTreeMap::from([(
            scupper_core::config::ExitId("ch1".into()),
            true,
        )]));
    }
    fn tick(&mut self) -> TickReport {
        self.time.set(self.time.get() + 2);
        self.machine.tick()
    }
    fn ruleset_and_tc_drift(&self) {
        self.kernel.mutate(|m| {
            m.ruleset = Known::Value(Ruleset::Absent);
            m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
        });
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn ce1_failed_emit_must_not_double_charge_safety_budget() {
    let ok = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
    let mut control = Rig::new(ok.handle.clone());
    for _ in 0..2 {
        control.ruleset_and_tc_drift();
        control.tick();
    }
    assert!(control.machine.latch().is_none());
    let stopped = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
    let handle = stopped.handle.clone();
    drop(stopped.log);
    let mut rig = Rig::new(handle.clone());
    for _ in 0..2 {
        rig.ruleset_and_tc_drift();
        let report = rig.tick();
        assert!(report.dropped_events > 0);
    }
    assert!(
        rig.machine.latch().is_none(),
        "event failure quarantined gateway"
    );
    assert!(handle.dropped() > 0);
    assert_eq!(rig.store.state().quarantine, None);
    assert!(
        rig.machine
            .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
            .is_ok()
    );
}
#[test]
fn ce2_healthy_steady_state_is_not_reported_degraded() {
    let ok = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
    let mut rig = Rig::new(ok.handle.clone());
    let mut events = rig
        .machine
        .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
        .unwrap()
        .events;
    events.extend(
        rig.machine
            .set_selection(Selection::Auto, Actor::Local { uid: 0 })
            .unwrap()
            .events,
    );
    for _ in 0..25 {
        rig.round();
        events.extend(rig.tick().events);
    }
    assert_eq!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Dev("ex-ch1".into()))
    );
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
    assert!(!events.iter().any(|e| matches!(
        e,
        EventKind::VerdictChanged {
            to: VerdictCode::Degraded,
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        EventKind::VerdictChanged {
            to: VerdictCode::Protected,
            ..
        }
    )));
}
#[test]
fn ce3_random_property_mostly_runs_unlatched() {
    // Use the revised generator's time windows and explicit administrative clears.
    let ok = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
    let (mut latched, mut total, mut late_raises) = (0, 0, 0);
    for seed in 1..=32_u64 {
        let mut rng = seed;
        let mut rig = Rig::new(ok.handle.clone());
        for tick in 0..80 {
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            if tick % 8 == 0 {
                rig.time.set(rig.time.get() + 601);
                rig.machine.clear_latch(Actor::Local { uid: 0 }).unwrap();
            }
            match (rng >> 32) % 16 {
                0 => rig
                    .kernel
                    .mutate(|m| m.ruleset = Known::Value(Ruleset::Absent)),
                3 => rig.kernel.mutate(|model| {
                    let mut link = KernelModel::desired(&desired()).links["wg0"].clone();
                    link.kind = Known::Value("veth".into());
                    link.ours = Known::Value(false);
                    link.peers = Known::Value(vec![]);
                    model.links.insert("foreign0".into(), link);
                }),
                4 => rig.kernel.mutate(|m| {
                    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
                }),
                _ => {}
            }
            rig.round();
            let report = rig.tick();
            total += 1;
            latched += usize::from(rig.machine.latch().is_some());
            if tick >= 40
                && report
                    .steps
                    .iter()
                    .any(|s| matches!(s, Step::ForwardingOn { .. }))
            {
                late_raises += 1;
            }
        }
    }
    eprintln!("latched {latched}/{total}; late raises {late_raises}");
    assert!(latched * 2 < total);
    assert!(late_raises > 0);
}

type CollectorCall = (bool, scupper_sys::system::Program, Vec<String>, Duration);
#[derive(Default)]
struct Sys {
    calls: std::cell::RefCell<Vec<CollectorCall>>,
    fail_ruleset: Cell<bool>,
    stall_wg: Cell<bool>,
    down_fallback_tunnel: Cell<bool>,
    stall: Cell<bool>,
}
impl scupper_sys::system::System for Sys {
    fn run(
        &self,
        program: scupper_sys::system::Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<scupper_sys::system::ExecOutput, scupper_sys::system::ExecError> {
        self.run_in(
            scupper_sys::system::ExecTarget::Host,
            program,
            args,
            timeout,
        )
    }
    fn run_in(
        &self,
        target: scupper_sys::system::ExecTarget<'_>,
        program: scupper_sys::system::Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<scupper_sys::system::ExecOutput, scupper_sys::system::ExecError> {
        use scupper_sys::system::{ExecError, ExecOutput, ExecTarget, Program};
        assert!(timeout <= Duration::from_secs(3));
        let ns = matches!(target, ExecTarget::Netns(_));
        self.calls
            .borrow_mut()
            .push((ns, program, args.to_vec(), timeout));
        if self.stall.get() && self.calls.borrow().len() <= 2 {
            std::thread::sleep(timeout);
            return Err(ExecError::Timeout { after: timeout });
        }
        if self.fail_ruleset.get() && program == Program::Nft {
            return Err(ExecError::Timeout { after: timeout });
        }
        if self.stall_wg.get() && program == Program::Wg {
            std::thread::sleep(timeout);
            return Err(ExecError::Timeout { after: timeout });
        }
        if self.down_fallback_tunnel.get() && ns {
            if program == Program::Ip
                && args.iter().any(|a| a == "link")
                && args.iter().any(|a| a == "show")
            {
                let script = support::Script::new("ubuntu-24.04");
                let mut links: serde_json::Value =
                    serde_json::from_str(&script.text("scupper--4-link.json")).unwrap();
                links.as_array_mut().unwrap().push(serde_json::json!({"ifindex":40,"ifname":"sit0","flags":["NOARP"],"mtu":1480,"qdisc":"noop","operstate":"DOWN","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"sit","address":"0.0.0.0","broadcast":"0.0.0.0","linkinfo":{"info_kind":"sit"}}));
                return Ok(ExecOutput {
                    status: Some(0),
                    stdout: links.to_string(),
                    stderr: String::new(),
                });
            }
            if program == Program::Tc && args.iter().any(|a| a == "sit0") {
                return Ok(ExecOutput {
                    status: Some(0),
                    stdout: "[]".into(),
                    stderr: String::new(),
                });
            }
        }
        let text = if !ns && program == Program::Ip {
            "[]".into()
        } else if program == Program::Sysctl {
            let key = args.get(1).unwrap();
            if key.ends_with(".forwarding") || key.ends_with(".ip_forward") {
                "1".into()
            } else {
                desired()
                    .hardening()
                    .iter()
                    .find(|s| &s.key.to_string() == key)
                    .unwrap()
                    .value
                    .clone()
            }
        } else if program == Program::Wg
            && args.get(2).is_some_and(|s| s == "listen-port")
            && args.get(1).is_some_and(|s| s != "wg0")
        {
            "0".into()
        } else {
            return support::Script::new("ubuntu-24.04").run_in(target, program, args, timeout);
        };
        Ok(ExecOutput {
            status: Some(0),
            stdout: text,
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        1_000
    }
    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
}
fn observe_real(
    root: &Path,
    held: &Arc<NetnsHandle>,
    sys: &Sys,
    namespace: PathBuf,
    edge: Option<PathBuf>,
    complete: bool,
) -> scupper_sys::reconcile::Observation {
    use scupper_sys::{
        boot::{BootDeps, GatewayNamespace},
        reconcile::{Kernel, RealKernel},
    };
    let deps = BootDeps {
        system: sys,
        namespace: &GatewayNamespace,
        state_root: root,
        config_root: root,
        run_root: root,
        hook: None,
        secret_owner: rustix::process::getuid().as_raw(),
    };
    let health = scupper_core::verdict::v2::HealthConfigV2::new(
        &support::site("ubuntu-24.04"),
        &GatewayId("gw1".into()),
        scupper_core::verdict::v2::NetnsIdentity {
            device: held.identity().0,
            inode: held.identity().1,
        },
        vec!["203.0.113.1".parse().unwrap()],
        1,
    )
    .unwrap();
    let mut cfg = config(root);
    cfg.fingerprint = fingerprint();
    let kernel = RealKernel::new(deps, held.clone(), &cfg, health, namespace, edge).unwrap();
    kernel.set_owned_links(BTreeMap::from([("wg0".into(), 2), ("ex-ch1".into(), 3)]));
    let safety = kernel.observe(held);
    if complete {
        kernel.observe_rest(held, safety, Instant::now() + Duration::from_secs(20))
    } else {
        safety
    }
}
fn fingerprint() -> [u8; 32] {
    scupper_sys::canon::fingerprint(
        &scupper_sys::canon::canonicalize(&support::fixture(
            "ubuntu-24.04",
            "scupper-nft-ruleset.json",
        ))
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn ce4_hijacked_name_is_not_masked_by_edge_elsewhere() {
    let root = root();
    let held = Arc::new(testing::handle().unwrap());
    let hijack = root.join("hijacked-name");
    let edge = root.join("edge-ns");
    fs::write(&hijack, b"").unwrap();
    fs::write(&edge, b"").unwrap();
    let observed = observe_real(&root, &held, &Sys::default(), hijack, Some(edge), false);
    fs::remove_dir_all(root).unwrap();
    assert_eq!(observed.model.namespace, NamespaceState::NameGone);
}
#[test]
fn ce5_stalled_nonsafety_tool_must_not_delay_emergency_closure_beyond_bound() {
    // Kernel::observe is now phase A only; the tick executes containment before observe_rest.
    let root = root();
    let held = Arc::new(testing::handle().unwrap());
    let sys = Sys::default();
    sys.stall_wg.set(true);
    let start = Instant::now();
    let observed = observe_real(&root, &held, &sys, held.fd_path(), None, false);
    fs::remove_dir_all(root).unwrap();
    assert!(observed.safety_complete);
    assert!(start.elapsed() <= Duration::from_secs(8));
    assert!(
        !sys.calls
            .borrow()
            .iter()
            .any(|c| c.1 == scupper_sys::system::Program::Wg)
    );
    for (safety, rest) in [
        (Duration::ZERO, Duration::from_secs(30)),
        (Duration::from_secs(150), Duration::from_secs(150)),
    ] {
        let ok = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
        let mut rig = Rig::new(ok.handle.clone());
        rig.kernel
            .mutate(|m| m.ruleset = Known::Value(Ruleset::Absent));
        rig.kernel.observation_latency(safety, rest);
        let report = rig.tick();
        assert!(!report.complete, "incomplete tick must not feed watchdog");
        assert_eq!(report.steps.first(), Some(&Step::ForwardingOff));
        assert!(rig.kernel.step_times()[0] <= Duration::from_secs(8));
        assert!(rig.kernel.model().forwarding_off());
        assert!(
            !report
                .steps
                .iter()
                .any(|s| matches!(s, Step::ForwardingOn { .. }))
        );
    }
}
#[test]
fn ce6_link_collision_must_not_mask_lifecycle_escalations() {
    let ok = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
    for namespace in [NamespaceState::EdgeElsewhere, NamespaceState::InodeGone] {
        let mut rig = Rig::new(ok.handle.clone());
        rig.kernel.mutate(|m| {
            m.namespace = namespace;
            let mut host = KernelModel::desired(&desired()).links["wg0"].clone();
            host.up = Known::Value(true);
            m.host_links.insert("wg0".into(), host);
        });
        let report = rig.tick();
        assert!(report.escalations.contains(&Escalation::LinkCollision));
        if namespace == NamespaceState::InodeGone {
            assert!(!report.complete);
            assert!(report.escalations.contains(&Escalation::RebuildRequired));
            assert!(
                report
                    .steps
                    .iter()
                    .all(|s| matches!(s, Step::Emit(_) | Step::PersistLatch { .. }))
            );
        } else {
            assert!(report.escalations.contains(&Escalation::RestartEdge));
        }
    }
}
#[test]
fn ce7_down_foreign_link_is_not_an_unknown_observation() {
    let root = root();
    let held = Arc::new(testing::handle().unwrap());
    let sys = Sys::default();
    sys.down_fallback_tunnel.set(true);
    let observed = observe_real(&root, &held, &sys, held.fd_path(), None, true);
    fs::remove_dir_all(root).unwrap();
    assert!(observed.safety_complete);
    let want = Desired::new(
        &support::site("ubuntu-24.04"),
        &GatewayId("gw1".into()),
        &stamp(),
        fingerprint(),
        &RouteTarget::Unreachable,
        &Selection::Auto,
    )
    .unwrap();
    assert_eq!(observed.model.links["sit0"].up, Known::Value(false));
    let plan = scupper_core::planner::plan(
        &want,
        &observed.model,
        &scupper_core::planner::Budgets::default(),
        None,
        &scupper_core::planner::Debounce::default(),
        MonoTime(Duration::from_secs(10)),
    );
    assert!(!plan.steps.contains(&Step::Emit(
        scupper_core::planner::PlannerEvent::ObservationUnknown
    )));
}
