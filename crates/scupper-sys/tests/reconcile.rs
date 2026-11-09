//! Stateful reconciliation scenarios FS-1 through FS-13 and adversarial prefixes.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::panic)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    failover::MonoTime,
    planner::{Desired, KernelModel, Known, NamespaceState, ObservationItem, Ruleset, Step, safe},
    render::{RouteTarget, VersionStamp},
    verdict::v2::{DefaultRouteObs, Selection},
};
use scupper_proto::{Actor, EventKind, StepKind, UnixSeconds};
use scupper_sys::{
    events::{EventLog, OpenedLog},
    lock::WriterLock,
    netns::{NetnsHandle, testing},
    reconcile::{
        Config, Escalation, Reconciler, TickReport,
        fake::{Crash, FakeKernel, Fault, MemoryStore},
    },
    state::{State, StateFile},
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

type Machine = Reconciler<FakeKernel, MemoryStore, Box<dyn Fn() -> (MonoTime, u64)>>;
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Rig {
    root: PathBuf,
    site: scupper_core::config::ValidatedSite,
    held: Arc<NetnsHandle>,
    kernel: FakeKernel,
    store: MemoryStore,
    log: OpenedLog,
    time: Rc<Cell<u64>>,
    machine: Option<Machine>,
}
impl Rig {
    fn new() -> Self {
        Self::with_site(support::site("ubuntu-24.04"))
    }
    fn with_site(site: scupper_core::config::ValidatedSite) -> Self {
        let desired = Desired::new(
            &site,
            &GatewayId("gw1".into()),
            &stamp(),
            [7; 32],
            &RouteTarget::Unreachable,
            &Selection::Auto,
        )
        .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/reconcile-fs")
            .join(format!(
                "scupper-reconcile-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        let store = MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        });
        let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(1_000)).unwrap();
        let mut rig = Self {
            root,
            site,
            held: Arc::new(testing::handle().unwrap()),
            kernel: FakeKernel::new(desired),
            store,
            log,
            time: Rc::new(Cell::new(0)),
            machine: None,
        };
        rig.restart();
        // Finish startup's forced unreachable route and qualification.
        for _ in 0..3 {
            rig.round(true);
            rig.tick();
        }
        rig.tick();
        rig.kernel.clear_history();
        rig
    }
    fn config(&self) -> Config {
        Config {
            site: self.site.clone(),
            gateway: GatewayId("gw1".into()),
            stamp: stamp(),
            fingerprint: [7; 32],
            run_root: self.root.clone(),
            lock_wait: Duration::from_millis(100),
        }
    }
    fn restart(&mut self) {
        self.machine.take();
        let time = self.time.clone();
        self.machine = Some(
            Reconciler::new(
                self.kernel.clone(),
                self.store.clone(),
                self.log.handle.clone(),
                self.config(),
                self.held.clone(),
                Box::new(move || {
                    (
                        MonoTime(Duration::from_secs(time.get())),
                        1_000 + time.get(),
                    )
                }) as Box<dyn Fn() -> (MonoTime, u64)>,
            )
            .unwrap(),
        );
    }
    fn machine(&mut self) -> &mut Machine {
        self.machine.as_mut().unwrap()
    }
    fn tick(&mut self) -> TickReport {
        self.time.set(self.time.get() + 2);
        self.machine().tick()
    }
    fn round(&mut self, success: bool) {
        self.machine().submit_probe_round(BTreeMap::from([(
            scupper_core::config::ExitId("ch1".into()),
            success,
        )]));
    }
    fn settle(&mut self) {
        for _ in 0..6 {
            self.round(true);
            self.tick();
        }
    }
    fn flush_rules(&self) {
        self.kernel
            .mutate(|m| m.ruleset = Known::Value(Ruleset::Absent));
    }
    fn safe_history(&self) {
        let desired = self.machine.as_ref().unwrap().desired().unwrap();
        let mut certified = false;
        for ((step, model), memory_guard) in self
            .kernel
            .history()
            .into_iter()
            .zip(self.kernel.guard_history())
        {
            if let Step::RouteReplace {
                target: RouteTarget::Exit(_),
                ..
            } = &step
            {
                let Step::RouteReplace { target, .. } = &step else {
                    unreachable!()
                };
                assert!(
                    model.route_ready(&desired, target),
                    "route promoted without verified policy and a ready exit"
                );
            }
            let is_safe = safe(&model, &desired);
            if certified {
                assert!(is_safe, "unsafe prefix after {step:?}: {model:?}");
            }
            certified |= is_safe;
            for gate in [
                &model.forwarding_v4,
                &model.forwarding_v6,
                &model.client_forwarding_v4,
            ] {
                if gate == &Known::Value(1)
                    && (certified || matches!(step, Step::ForwardingOn { .. }))
                {
                    assert_eq!(
                        model.ruleset,
                        Known::Value(Ruleset::Verified(desired.fingerprint())),
                        "{step:?}"
                    );
                    assert!(model.latch.is_none(), "persisted latch held at {step:?}");
                    if matches!(step, Step::ForwardingOn { .. }) {
                        assert!(!memory_guard, "executor memory guard held");
                    }
                }
            }
        }
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.machine.take();
        fs::remove_dir_all(&self.root).unwrap();
    }
}
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
fn raises(report: &TickReport) -> bool {
    report
        .steps
        .iter()
        .any(|s| matches!(s, Step::ForwardingOn { .. }))
}

#[test]
fn fs1_route_deleted_restored_after_two_ticks() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|m| m.default_v4 = Known::Value(DefaultRouteObs::Missing));
    assert!(!rig.tick().steps.iter().any(|s| matches!(
        s,
        Step::RouteReplace {
            family: scupper_core::render::Family::V4,
            ..
        }
    )));
    assert!(rig.tick().steps.iter().any(|s| matches!(
        s,
        Step::RouteReplace {
            family: scupper_core::render::Family::V4,
            ..
        }
    )));
    assert_ne!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Missing)
    );
}
#[test]
fn fs2_ruleset_flush_closes_and_repairs_in_order() {
    let mut rig = Rig::new();
    rig.flush_rules();
    let report = rig.tick();
    assert_eq!(report.steps.first(), Some(&Step::ForwardingOff));
    let relevant: Vec<_> = report
        .steps
        .iter()
        .filter_map(|s| match s {
            Step::ForwardingOff => Some("off"),
            Step::LoadRuleset { .. } => Some("load"),
            Step::VerifyRuleset { .. } => Some("verify"),
            Step::FlushConntrack => Some("flush"),
            Step::ForwardingOn { .. } => Some("on"),
            _ => None,
        })
        .collect();
    assert_eq!(relevant, ["off", "load", "verify", "flush", "on"]);
    assert!(report.complete);
    rig.safe_history();
}
#[test]
fn fs3_safety_budget_exhaustion_closes_tightens_persists() {
    let mut rig = Rig::new();
    for _ in 0..3 {
        rig.flush_rules();
        assert!(raises(&rig.tick()));
    }
    rig.flush_rules();
    let report = rig.tick();
    assert_eq!(report.steps.first(), Some(&Step::ForwardingOff));
    assert!(
        report
            .steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. }))
    );
    assert!(rig.store.state().quarantine.is_some());
    for _ in 0..3 {
        assert!(!raises(&rig.tick()));
    }
    assert!(rig.kernel.model().forwarding_off());
}
#[test]
fn fs4_safety_timeouts_never_complete() {
    for item in [
        ObservationItem::Links,
        ObservationItem::Ruleset,
        ObservationItem::ForwardingV4,
        ObservationItem::ForwardingV6,
        ObservationItem::Tc("wg0".into()),
    ] {
        let mut rig = Rig::new();
        rig.kernel.timeouts(BTreeSet::from([item]));
        let report = rig.tick();
        assert!(!report.complete);
        assert!(report.safety_ms >= 3_000);
    }
}
#[test]
fn fs5_crash_at_every_ruleset_and_link_repair_boundary_converges() {
    for missing_link in [false, true] {
        let mut baseline = Rig::new();
        if missing_link {
            baseline.kernel.mutate(|m| {
                m.links.remove("wg0");
            });
            baseline.tick();
        } else {
            baseline.flush_rules();
        }
        let count = baseline.tick().steps.len();
        assert!(count > 4);
        for boundary in 1..=count {
            let mut rig = Rig::new();
            if missing_link {
                rig.kernel.mutate(|m| {
                    m.links.remove("wg0");
                });
                rig.tick();
            } else {
                rig.flush_rules();
            }
            rig.kernel.clear_history();
            rig.kernel.crash_after(boundary);
            let crash = catch_unwind(AssertUnwindSafe(|| rig.tick())).unwrap_err();
            assert!(crash.is::<Crash>());
            rig.safe_history();
            rig.restart();
            rig.settle();
            rig.safe_history();
            assert!(safe(&rig.kernel.model(), &desired()));
            assert!(rig.kernel.model().links.contains_key("wg0"));
            assert_eq!(
                rig.kernel.model().ruleset,
                Known::Value(Ruleset::Verified([7; 32]))
            );
        }
    }
}
#[test]
fn fs6_removed_or_hijacked_name_remounts_held_inode() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|m| m.namespace = NamespaceState::NameGone);
    let report = rig.tick();
    assert_eq!(report.escalations, vec![Escalation::RebindNamespace]);
    assert_eq!(rig.kernel.remounts(), 1);
    assert_eq!(rig.kernel.model().namespace, NamespaceState::Ready);
}
#[test]
fn fs7_persisted_and_memory_latches_hold_across_ticks() {
    for persist in [true, false] {
        let mut rig = Rig::new();
        for _ in 0..3 {
            rig.flush_rules();
            rig.tick();
        }
        rig.store.fail_writes(!persist);
        rig.flush_rules();
        let report = rig.tick();
        assert!(rig.machine().latch().is_some());
        assert_eq!(rig.store.state().quarantine.is_some(), persist);
        if !persist {
            assert!(
                report.complete,
                "disk failure alone must not trigger a watchdog restart"
            );
            assert!(
                report
                    .events
                    .iter()
                    .any(|e| matches!(e, EventKind::PersistenceFailed { .. }))
            );
        }
        assert!(!raises(&rig.tick()));
        rig.restart();
        if persist {
            assert!(rig.machine().latch().is_some());
        } else {
            assert!(rig.machine().latch().is_none());
            // Budgets are process-local. Persistent fighting is detected afresh.
            for _ in 0..4 {
                rig.flush_rules();
                rig.tick();
            }
            assert!(rig.machine().latch().is_some());
        }
        assert!(!raises(&rig.tick()));
    }
}
#[test]
fn fs8_disconnect_durable_and_closed_before_ack() {
    let mut rig = Rig::new();
    let report = rig
        .machine()
        .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
        .unwrap();
    assert!(report.complete);
    assert_eq!(rig.store.state().selection, Selection::Disconnected);
    let model = rig.kernel.model();
    assert_eq!(model.default_v4, Known::Value(DefaultRouteObs::Unreachable));
    assert_eq!(model.default_v6, Known::Value(DefaultRouteObs::Unreachable));
    assert_eq!(model.links["ex-ch1"].up, Known::Value(false));
    rig.restart();
    assert_eq!(rig.store.state().selection, Selection::Disconnected);
}
fn foreign(model: &mut KernelModel) {
    let mut link = KernelModel::desired(&desired()).links["wg0"].clone();
    link.kind = Known::Value("veth".into());
    link.ours = Known::Value(false);
    link.peers = Known::Value(vec![]);
    model.links.insert("foreign0".into(), link);
}
#[test]
fn fs9_foreign_link_down_first_tick() {
    let mut rig = Rig::new();
    rig.kernel.mutate(foreign);
    assert!(rig.tick().steps.contains(&Step::LinkDown {
        name: "foreign0".into()
    }));
    assert_eq!(rig.kernel.model().links["foreign0"].up, Known::Value(false));
}
#[test]
fn fs10_tc_hook_removed_first_tick() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|m| m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]));
    assert!(rig.tick().steps.contains(&Step::TcDelete {
        name: "wg0".into(),
        hook: "root".into()
    }));
    assert_eq!(
        rig.kernel.model().links["wg0"].tc_hooks,
        Known::Value(vec![])
    );
}
#[test]
fn fs11_failed_apply_replans_previous_version_same_tick() {
    let mut rig = Rig::new();
    rig.flush_rules();
    rig.kernel.inject(Fault {
        step: StepKind::LoadRuleset,
        remaining: Some(1),
        partial: false,
    });
    let report = rig.tick();
    let first = report
        .steps
        .iter()
        .position(|s| matches!(s, Step::LoadRuleset { .. }))
        .unwrap();
    assert_eq!(report.steps[first + 1], Step::ForwardingOff);
    assert!(
        report.steps[first + 2..]
            .iter()
            .any(|s| matches!(s, Step::LoadRuleset { .. }))
    );
    assert!(report.events.iter().any(|e| matches!(
        e,
        EventKind::ApplyFailed {
            version: Some(1),
            ..
        }
    )));
    assert_eq!(rig.store.state().applied_version, Some(1));
    rig.safe_history();
}
#[test]
fn fs12_inode_gone_requires_rebuild() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|m| m.namespace = NamespaceState::InodeGone);
    let report = rig.tick();
    assert_eq!(report.escalations, vec![Escalation::RebuildRequired]);
    assert_eq!(report.steps, vec![]);
    assert!(!report.complete);
}
#[test]
fn fs13_writer_lock_contention_executes_nothing() {
    let mut rig = Rig::new();
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let report = rig.tick();
    assert!(!report.complete);
    assert_eq!(report.steps, vec![]);
    assert_ne!(report.events, vec![]);
    drop(guard);
    assert!(rig.tick().complete);
}
#[test]
fn partial_forwarding_failure_is_closed_by_replan() {
    for times in [Some(1), None] {
        let mut rig = Rig::new();
        rig.flush_rules();
        rig.kernel.inject(Fault {
            step: StepKind::ForwardingOn,
            remaining: times,
            partial: true,
        });
        let report = rig.tick();
        for (i, step) in report.steps.iter().enumerate() {
            if matches!(step, Step::ForwardingOn { .. }) {
                assert_eq!(report.steps.get(i + 1), Some(&Step::ForwardingOff));
            }
        }
        if times.is_none() {
            assert!(rig.kernel.model().forwarding_off());
        }
        rig.safe_history();
    }
}
#[test]
fn containment_failure_still_executes_later_tightening() {
    let mut rig = Rig::new();
    rig.kernel.mutate(foreign);
    rig.kernel
        .mutate(|m| m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]));
    rig.kernel.inject(Fault {
        step: StepKind::ForwardingOff,
        remaining: None,
        partial: false,
    });
    let report = rig.tick();
    assert!(report.steps.contains(&Step::LinkDown {
        name: "foreign0".into()
    }));
    assert!(report.steps.contains(&Step::TcDelete {
        name: "wg0".into(),
        hook: "root".into()
    }));
    assert!(!raises(&report));
}
#[test]
fn admin_clear_is_durable_and_audited() {
    let mut rig = Rig::new();
    for _ in 0..4 {
        rig.flush_rules();
        rig.tick();
    }
    rig.store.fail_writes(true);
    assert!(rig.machine().clear_latch(Actor::Local { uid: 0 }).is_err());
    assert!(rig.machine().latch().is_some());
    rig.store.fail_writes(false);
    rig.machine().clear_latch(Actor::Local { uid: 0 }).unwrap();
    assert!(rig.machine().latch().is_none());
    assert!(rig.store.state().quarantine.is_none());
    rig.tick();
    rig.flush_rules();
    assert!(raises(&rig.tick()));
}
#[test]
fn real_state_file_disconnect_survives_reopen() {
    let rig = Rig::new();
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let file = StateFile::open(&rig.root, Some(&guard)).unwrap();
    file.write(&guard, &rig.store.state()).unwrap();
    drop(guard);
    let mut machine = Reconciler::new(
        rig.kernel.clone(),
        file,
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1_100),
    )
    .unwrap();
    machine
        .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
        .unwrap();
    assert!(matches!(
        StateFile::open(&rig.root, None).unwrap().read().unwrap(),
        scupper_sys::state::StateRead::Present(State {
            selection: Selection::Disconnected,
            ..
        })
    ));
}
#[test]
fn edge_namespace_mismatch_requests_restart() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|m| m.namespace = NamespaceState::EdgeElsewhere);
    assert_eq!(rig.tick().escalations, vec![Escalation::RestartEdge]);
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
#[test]
#[allow(clippy::too_many_lines)]
fn randomized_adversary_failures_and_crashes_preserve_safe_prefixes() {
    use scupper_core::{
        config::ExitId,
        planner::{RouteKey, StepFailure},
        render::Family,
    };
    let mut failures = BTreeSet::new();
    let mut prefix_failures = BTreeSet::new();
    let mut phase_b_failures = BTreeSet::new();
    let (
        mut unknowns,
        mut switches,
        mut raises_after_recovery,
        mut crashes,
        mut latched,
        mut total,
    ) = (0, 0, 0, 0, 0, 0);
    for seed in 1..=32_u64 {
        let mut rng = seed;
        let mut rig = Rig::with_site(multi_exit_site());
        let mut last_exit = Some("ex-ch1".to_owned());
        for case in 0..80 {
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            // Independent fighting windows keep the property active throughout every seed.
            rig.time.set(rig.time.get() + 601);
            rig.machine().clear_latch(Actor::Local { uid: 0 }).unwrap();
            rig.kernel.timeouts(BTreeSet::new());
            rig.kernel
                .handshake(ExitId("ch1".into()), Some(Duration::from_secs(1)));
            rig.kernel
                .handshake(ExitId("ch2".into()), Some(Duration::from_secs(1)));
            let choice = (rng >> 32) % 13;
            let fault = match choice {
                0 => {
                    rig.flush_rules();
                    Some(StepKind::ForwardingOff)
                }
                1 => {
                    rig.kernel.mutate(foreign);
                    Some(StepKind::LinkDown)
                }
                2 => {
                    rig.kernel.mutate(|m| {
                        m.links.get_mut("wg0").unwrap().tc_hooks =
                            Known::Value(vec!["root".into()]);
                    });
                    Some(StepKind::TcDelete)
                }
                3 => {
                    rig.kernel
                        .mutate(|m| m.extra_rules = Known::Value(vec!["extra-rule".into()]));
                    Some(StepKind::RuleDelete)
                }
                4 => {
                    let route = RouteKey {
                        family: Family::V4,
                        entry: scupper_core::parse::parse_ip_route(
                            r#"[{"dst":"198.18.0.0/16","dev":"wg0"}]"#,
                        )
                        .unwrap()
                        .remove(0),
                    };
                    rig.kernel
                        .mutate(|m| m.extra_routes = Known::Value(vec![route]));
                    Some(StepKind::RouteDelete)
                }
                5 => {
                    rig.kernel.mutate(|m| {
                        m.default_v4 = Known::Value(DefaultRouteObs::Dev("eth0".into()));
                    });
                    Some(StepKind::RouteReplace)
                }
                6 => {
                    rig.kernel.mutate(|m| {
                        m.links.remove("wg0");
                    });
                    Some(StepKind::LinkForwardingOff)
                }
                7 => {
                    let items = [
                        ObservationItem::Ruleset,
                        ObservationItem::ForwardingV4,
                        ObservationItem::ForwardingV6,
                        ObservationItem::ClientForwardingV4,
                        ObservationItem::Links,
                        ObservationItem::Tc("wg0".into()),
                        ObservationItem::Peers("wg0".into()),
                        ObservationItem::Addresses("wg0".into()),
                        ObservationItem::Rules,
                        ObservationItem::ExtraRoutes,
                        ObservationItem::DefaultV4,
                        ObservationItem::DefaultV6,
                    ];
                    rig.kernel.timeouts(BTreeSet::from([items
                        [usize::try_from((rng >> 20) % 12).unwrap()]
                    .clone()]));
                    unknowns += 1;
                    None
                }
                8 => {
                    rig.flush_rules();
                    Some(StepKind::ForwardingOn)
                }
                9 => {
                    rig.kernel
                        .mutate(|m| m.links.get_mut("wg0").unwrap().peers = Known::Value(vec![]));
                    None
                }
                10 => {
                    rig.kernel
                        .mutate(|m| m.namespace = NamespaceState::NameGone);
                    None
                }
                11 => {
                    rig.flush_rules();
                    rig.kernel
                        .crash_after(usize::try_from((rng >> 8) % 6 + 1).unwrap());
                    None
                }
                _ => {
                    rig.kernel
                        .handshake(ExitId("ch1".into()), Some(Duration::from_secs(400)));
                    None
                }
            };
            if let Some(step) = fault.filter(|_| (rng >> 17) % 4 == 0) {
                rig.kernel.inject(Fault {
                    step,
                    remaining: Some(1),
                    partial: true,
                });
            }
            // Let stale handshakes and failed rounds drive actual multi-exit switches.
            let fight = (rng >> 12) % 64 == 0;
            for recovery in 0..8 {
                if fight && recovery < 5 {
                    rig.flush_rules();
                }
                rig.kernel.clear_history();
                if recovery > 0 {
                    rig.kernel.timeouts(BTreeSet::new());
                }
                rig.machine().submit_probe_round(BTreeMap::from([
                    (ExitId("ch1".into()), choice != 12),
                    (ExitId("ch2".into()), true),
                ]));
                if choice == 12 {
                    rig.time.set(rig.time.get() + 35);
                }
                let reads_before = rig.kernel.rest_reads();
                let result = catch_unwind(AssertUnwindSafe(|| rig.tick()));
                match result {
                    Ok(report) => {
                        for (step, _) in &report.failures {
                            if step.failure() == StepFailure::Contain {
                                failures.insert(format!("{:?}", StepKind::from(step)));
                                let first_attempt = rig
                                    .kernel
                                    .history()
                                    .iter()
                                    .position(|(s, _)| s == step)
                                    .unwrap();
                                let target = if rig.kernel.step_rest_reads()[first_attempt]
                                    == reads_before
                                {
                                    &mut prefix_failures
                                } else {
                                    &mut phase_b_failures
                                };
                                target.insert(format!("{:?}", StepKind::from(step)));
                            }
                        }
                        for (step, model) in rig.kernel.history() {
                            if let Step::RouteReplace {
                                family: Family::V4,
                                target: RouteTarget::Exit(name),
                            } = step
                                && model.default_v4
                                    == Known::Value(DefaultRouteObs::Dev(name.as_str().into()))
                            {
                                if last_exit
                                    .as_deref()
                                    .is_some_and(|last| last != name.as_str())
                                {
                                    switches += 1;
                                }
                                last_exit = Some(name.as_str().to_owned());
                            }
                        }
                        raises_after_recovery +=
                            usize::from(recovery > 0 && report.complete && raises(&report));
                    }
                    Err(crash) => {
                        assert!(crash.is::<Crash>());
                        crashes += 1;
                        rig.restart();
                    }
                }
                total += 1;
                latched += usize::from(rig.machine().latch().is_some());
                rig.safe_history();
            }
            if case % 17 == 0 {
                rig.time.set(rig.time.get() + 601);
            }
            // Recovery is bounded after faults/Unknown stop; no safety latch may silently
            // turn the remaining random cases into checks of a permanently closed kernel.
            rig.kernel
                .handshake(ExitId("ch1".into()), Some(Duration::from_secs(1)));
            rig.kernel.timeouts(BTreeSet::new());
            if rig.machine().latch().is_none() {
                rig.settle();
                assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
            }
        }
    }
    eprintln!(
        "random coverage: {switches} switches, {unknowns} Unknown cases, {raises_after_recovery} recovery raises, {crashes} crashes, {latched}/{total} latched ticks; containment failures {failures:?}"
    );
    eprintln!(
        "prefix containment failures {prefix_failures:?}; phase-B containment failures {phase_b_failures:?}"
    );
    assert!(!prefix_failures.is_empty() && !phase_b_failures.is_empty());
    assert!(latched > 0 && latched * 2 < total);
    assert!(switches > 0 && unknowns > 0 && raises_after_recovery > 0 && crashes > 0);
    assert_eq!(
        failures,
        BTreeSet::from(
            [
                "ForwardingOff",
                "LinkDown",
                "LinkForwardingOff",
                "TcDelete",
                "RuleDelete",
                "RouteDelete",
                "RouteReplace"
            ]
            .map(str::to_owned)
        )
    );
}

// A separate process owns the lock; independent descriptors in the parent are
// already covered by the basic contention test above.
#[test]
fn writer_lock_child() {
    let Some(root) = std::env::var_os("SCUPPER_RECONCILE_LOCK_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let _guard = WriterLock::acquire(&root).unwrap();
    fs::write(root.join("ready"), b"ready").unwrap();
    let mut byte = [0];
    std::io::Read::read_exact(&mut std::io::stdin(), &mut byte).unwrap();
}
#[test]
fn fs13_other_process_holds_writer_lock() {
    use std::process::{Command, Stdio};
    let mut rig = Rig::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "writer_lock_child", "--nocapture"])
        .env("SCUPPER_RECONCILE_LOCK_CHILD", &rig.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while !rig.root.join("ready").exists() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    let report = rig.tick();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"x").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(!report.complete);
    assert_eq!(report.steps, vec![]);
}

type CollectorCall = (bool, scupper_sys::system::Program, Vec<String>, Duration);
#[derive(Default)]
struct CollectorSystem {
    calls: std::cell::RefCell<Vec<CollectorCall>>,
    fail_ruleset: Cell<bool>,
    stall: Cell<bool>,
}
impl scupper_sys::system::System for CollectorSystem {
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
fn observe_real(rig: &Rig, sys: &CollectorSystem) -> scupper_sys::reconcile::Observation {
    use scupper_sys::{
        boot::{BootDeps, GatewayNamespace},
        reconcile::{Kernel, RealKernel},
    };
    let deps = BootDeps {
        system: sys,
        namespace: &GatewayNamespace,
        state_root: &rig.root,
        config_root: &rig.root,
        run_root: &rig.root,
        hook: None,
        secret_owner: rustix::process::getuid().as_raw(),
    };
    let health = scupper_core::verdict::v2::HealthConfigV2::new(
        &support::site("ubuntu-24.04"),
        &GatewayId("gw1".into()),
        scupper_core::verdict::v2::NetnsIdentity {
            device: rig.held.identity().0,
            inode: rig.held.identity().1,
        },
        vec!["203.0.113.1".parse().unwrap()],
        1,
    )
    .unwrap();
    let mut config = rig.config();
    config.fingerprint = scupper_sys::canon::fingerprint(
        &scupper_sys::canon::canonicalize(&support::fixture(
            "ubuntu-24.04",
            "scupper-nft-ruleset.json",
        ))
        .unwrap(),
    )
    .unwrap();
    let kernel = RealKernel::new(
        deps,
        rig.held.clone(),
        &config,
        health,
        rig.held.fd_path(),
        None,
    )
    .unwrap();
    kernel.set_owned_links(BTreeMap::from([("wg0".into(), 2), ("ex-ch1".into(), 3)]));
    let safety = kernel.observe(&rig.held);
    kernel.observe_rest(
        &rig.held,
        safety,
        std::time::Instant::now() + Duration::from_secs(20),
    )
}
#[test]
fn real_collector_safety_first_held_inode_and_failed_items() {
    use scupper_sys::system::Program;
    let rig = Rig::new();
    let sys = CollectorSystem::default();
    let observed = observe_real(&rig, &sys);
    assert!(observed.safety_complete);
    assert_eq!(observed.model.namespace, NamespaceState::Ready);
    assert!(matches!(
        observed.model.ruleset,
        Known::Value(Ruleset::Verified(_))
    ));
    assert_ne!(observed.model.links["wg0"].settings, Known::Unknown);
    assert_ne!(observed.model.links["ex-ch1"].settings, Known::Unknown);
    assert_eq!(observed.model.extra_routes, Known::Value(vec![]));
    // Captured handshake timestamps are later than this executor's Unix clock.
    let exit = scupper_core::config::ExitId("ch1".into());
    assert!(observed.exit_links[&exit].link_up);
    assert!(observed.exit_links[&exit].peer_present);
    assert_eq!(observed.handshakes[&exit], None);
    let calls = sys.calls.borrow();
    let availability = calls
        .iter()
        .position(|(_, p, a, _)| *p == Program::Ip && a.iter().any(|s| s == "addr"))
        .unwrap();
    let last_tc = calls
        .iter()
        .rposition(|(_, p, _, _)| *p == Program::Tc)
        .unwrap();
    assert!(last_tc < availability);
    assert!(calls[..availability].iter().all(|(ns, _, _, _)| *ns));
    drop(calls);
    sys.fail_ruleset.set(true);
    let failed = observe_real(&rig, &sys);
    assert!(!failed.safety_complete);
    assert_eq!(failed.model.ruleset, Known::Unknown);
    assert!(failed.model.links_complete);
}
#[test]
fn real_safety_group_stops_at_six_seconds() {
    let rig = Rig::new();
    let sys = CollectorSystem::default();
    sys.stall.set(true);
    let start = std::time::Instant::now();
    let observed = observe_real(&rig, &sys);
    assert!(!observed.safety_complete);
    assert!(observed.safety_ms <= 6_200);
    assert!(start.elapsed() < Duration::from_secs(7));
    // Only two commands actually reach the underlying executor before the
    // shared deadline; subsequent safety reads immediately become Unknown.
    let calls = sys.calls.borrow();
    assert_eq!(calls[0].3, Duration::from_secs(3));
    assert!(calls[1].3 < Duration::from_secs(3));
}

#[test]
fn skipped_link_restore_group_still_runs_containment_substeps() {
    let mut rig = Rig::new();
    rig.kernel.mutate(|m| {
        m.links.remove("wg0");
    });
    rig.tick();
    rig.kernel.mutate(foreign);
    rig.kernel.inject(Fault {
        step: StepKind::LinkDown,
        remaining: None,
        partial: false,
    });
    let report = rig.tick();
    assert!(
        report
            .steps
            .contains(&Step::LinkForwardingOff { name: "wg0".into() })
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| matches!(s, Step::LinkCreate { .. }))
    );
    assert!(!raises(&report));
}

#[test]
fn event_log_open_failure_falls_back_to_memory() {
    let rig = Rig::new();
    let blocker = rig.root.join("not-a-directory");
    fs::write(&blocker, b"x").unwrap();
    let opened = scupper_sys::reconcile::open_event_log(&blocker, GatewayId("gw1".into()), || {
        UnixSeconds(1_000)
    })
    .unwrap();
    assert_eq!(opened.handle.committed_seq(), 0);
    opened
        .handle
        .emit(EventKind::Flapping {}, Actor::Daemon, Some(1))
        .unwrap();
}

#[test]
fn latch_persists_through_state_file_and_reconciler_restart() {
    let rig = Rig::new();
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let file = StateFile::open(&rig.root, Some(&guard)).unwrap();
    file.write(&guard, &rig.store.state()).unwrap();
    drop(guard);
    let mut machine = Reconciler::new(
        rig.kernel.clone(),
        file,
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1_100),
    )
    .unwrap();
    for _ in 0..4 {
        rig.flush_rules();
        machine.tick();
    }
    assert!(machine.latch().is_some());
    drop(machine);
    let file = StateFile::open(&rig.root, None).unwrap();
    let scupper_sys::state::StateRead::Present(state) = file.read().unwrap() else {
        panic!("state missing");
    };
    assert_eq!(state.quarantine.as_ref().unwrap().since_unix, 1_100);
    let mut restarted = Reconciler::new(
        rig.kernel.clone(),
        file,
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::ZERO), 1_200),
    )
    .unwrap();
    assert!(restarted.latch().is_some());
    assert!(!raises(&restarted.tick()));
    assert!(rig.kernel.model().forwarding_off());
}
#[test]
fn disconnect_is_durable_before_first_action_and_failed_persistence_does_nothing() {
    let mut rig = Rig::new();
    rig.store.fail_writes(true);
    assert!(
        rig.machine()
            .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
            .is_err()
    );
    assert_eq!(rig.store.state().selection, Selection::Auto);
    assert_eq!(rig.kernel.history().len(), 0);
    rig.store.fail_writes(false);
    rig.kernel.crash_after(1);
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        rig.machine()
            .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
    }))
    .unwrap_err();
    assert!(crashed.is::<Crash>());
    assert_eq!(rig.store.state().selection, Selection::Disconnected);
    rig.restart();
    rig.settle();
    assert_eq!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Unreachable)
    );
    assert_eq!(rig.kernel.model().links["ex-ch1"].up, Known::Value(false));
}

#[test]
fn name_hijack_rebinds_before_next_tick_requests_edge_restart() {
    let mut rig = Rig::new();
    rig.kernel.hijack_name_with_edge();
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::from_secs(30));
    let first = rig.tick();
    assert!(!first.complete);
    assert!(first.escalations.contains(&Escalation::RebindNamespace));
    assert!(!first.escalations.contains(&Escalation::RestartEdge));
    assert_eq!(rig.kernel.remounts(), 1);
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::ZERO);
    assert!(rig.tick().escalations.contains(&Escalation::RestartEdge));
}

#[test]
fn fake_forwarding_faults_obey_guards_and_flush_is_per_tick() {
    use scupper_core::planner::Latch;
    use scupper_sys::reconcile::Kernel;
    let rig = Rig::new();
    let on = Step::ForwardingOn {
        requires: desired().fingerprint(),
    };
    rig.kernel.execute(&Step::ForwardingOff).unwrap();
    rig.kernel.execute(&Step::FlushConntrack).unwrap();
    rig.kernel.observe(&rig.held);
    rig.kernel.inject(Fault {
        step: StepKind::ForwardingOn,
        remaining: Some(1),
        partial: true,
    });
    assert!(rig.kernel.execute(&on).is_err());
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(0));
    rig.kernel.execute(&Step::FlushConntrack).unwrap();
    let latch = Latch {
        reason: "memory".into(),
        object: "test".into(),
    };
    rig.kernel.hold_latch(Some(&latch));
    assert!(rig.kernel.model().latch.is_none());
    assert!(rig.kernel.execute(&on).is_err());
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(0));
    rig.kernel.hold_latch(None);
    assert!(rig.kernel.execute(&on).is_err()); // The pending partial fault now passes guards.
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
}

#[test]
fn expired_storage_collection_runs_after_closure_and_never_restores() {
    use scupper_sys::{lock::WriterGuard, reconcile::StateStore};
    struct ExpiredStore {
        inner: MemoryStore,
        kernel: FakeKernel,
    }
    impl StateStore for ExpiredStore {
        fn read(&self) -> std::io::Result<State> {
            self.inner.read()
        }
        fn write(&self, guard: &WriterGuard, state: &State) -> std::io::Result<()> {
            self.inner.write(guard, state)
        }
        fn read_until(&self, _deadline: std::time::Instant) -> std::io::Result<State> {
            assert_eq!(
                self.kernel.history().first().map(|(step, _)| step),
                Some(&Step::ForwardingOff)
            );
            assert!(self.kernel.model().forwarding_off());
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "storage deadline",
            ))
        }
    }
    let rig = Rig::new();
    let mut machine = Reconciler::new(
        rig.kernel.clone(),
        ExpiredStore {
            inner: rig.store.clone(),
            kernel: rig.kernel.clone(),
        },
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1100),
    )
    .unwrap();
    rig.flush_rules();
    let report = machine.tick();
    assert!(!report.complete);
    assert!(
        !report
            .steps
            .iter()
            .any(|step| matches!(step, Step::LoadRuleset { .. } | Step::ForwardingOn { .. }))
    );
}

#[test]
fn fake_inventory_failure_clears_links_and_downing_an_exit_removes_its_routes() {
    use scupper_core::render::Family;
    use scupper_sys::reconcile::Kernel;
    let rig = Rig::new();
    rig.kernel
        .execute(&Step::LinkDown {
            name: "ex-ch1".into(),
        })
        .unwrap();
    assert_eq!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Missing)
    );
    assert!(
        rig.kernel
            .execute(&Step::RouteReplace {
                family: Family::V4,
                target: RouteTarget::Exit(
                    support::site("ubuntu-24.04")
                        .gateway(&GatewayId("gw1".into()))
                        .unwrap()
                        .exits()[0]
                        .ifname()
                        .clone()
                )
            })
            .is_err()
    );
    rig.kernel
        .timeouts(BTreeSet::from([ObservationItem::Links]));
    let snapshot = rig.kernel.observe(&rig.held);
    assert!(!snapshot.model.links_complete);
    assert!(snapshot.model.links.is_empty());
}

#[test]
fn required_gates_and_disconnected_exits_are_contained_before_stalled_phase_b() {
    for gate in 0..7 {
        let mut rig = Rig::new();
        rig.kernel.mutate(|m| match gate {
            0 => m.forwarding_v4 = Known::Value(0),
            1 => m.forwarding_v6 = Known::Value(0),
            2 => m.default_forwarding_v4 = Known::Value(0),
            3 => m.default_forwarding_v6 = Known::Value(0),
            4 => m.client_forwarding_v4 = Known::Value(0),
            5 => m.links.get_mut("wg0").unwrap().forwarding_v4 = Known::Value(0),
            _ => m.links.get_mut("wg0").unwrap().forwarding_v6 = Known::Unknown,
        });
        rig.kernel
            .observation_latency(Duration::from_secs(1), Duration::from_secs(20));
        let report = rig.tick();
        assert!(!report.complete);
        assert_eq!(
            report.steps.first(),
            Some(&Step::ForwardingOff),
            "gate {gate}"
        );
        assert!(rig.kernel.step_times()[0] <= Duration::from_secs(6));
        assert!(!raises(&report));
    }
    let mut rig = Rig::new();
    rig.machine()
        .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
        .unwrap();
    rig.kernel.clear_history();
    rig.kernel.mutate(|m| {
        m.forwarding_v4 = Known::Value(1);
        m.forwarding_v6 = Known::Value(1);
        m.links.get_mut("ex-ch1").unwrap().up = Known::Value(true);
    });
    rig.kernel
        .observation_latency(Duration::from_secs(1), Duration::from_secs(20));
    let report = rig.tick();
    assert!(!report.complete);
    assert_eq!(report.steps.first(), Some(&Step::ForwardingOff));
    assert!(report.steps.contains(&Step::LinkDown {
        name: "ex-ch1".into()
    }));
    assert!(rig.kernel.model().forwarding_off());
    assert_eq!(rig.kernel.model().links["ex-ch1"].up, Known::Value(false));
    assert!(
        rig.kernel
            .history()
            .iter()
            .all(|(s, _)| !matches!(s, Step::RouteReplace { .. }))
    );
}

#[test]
fn emergency_failures_contain_without_quarantine_before_incomplete_phase_b() {
    for kind in [
        StepKind::ForwardingOff,
        StepKind::LinkDown,
        StepKind::TcDelete,
    ] {
        for fail_persistence in [false, true] {
            let mut rig = Rig::new();
            rig.kernel.mutate(foreign);
            rig.kernel.mutate(|m| {
                m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
            });
            rig.kernel.inject(Fault {
                step: kind,
                remaining: Some(1),
                partial: false,
            });
            rig.store.fail_writes(fail_persistence);
            rig.kernel
                .observation_latency(Duration::ZERO, Duration::from_secs(20));
            let report = rig.tick();
            assert!(!report.complete);
            assert!(rig.machine().latch().is_none(), "{kind:?}");
            assert!(
                report
                    .steps
                    .iter()
                    .all(|s| !matches!(s, Step::PersistLatch { .. }))
            );
            assert!(rig.store.state().quarantine.is_none());
            assert!(
                report
                    .events
                    .iter()
                    .any(|e| matches!(e, EventKind::ApplyFailed { .. }))
            );
            assert!(
                !report
                    .events
                    .iter()
                    .any(|e| matches!(e, EventKind::PersistenceFailed { .. }))
            );
            assert!(!raises(&report));
            assert!(report.steps.iter().all(|s| matches!(
                s,
                Step::ForwardingOff
                    | Step::LinkForwardingOff { .. }
                    | Step::LinkDown { .. }
                    | Step::TcDelete { .. }
                    | Step::Emit(_)
                    | Step::PersistLatch { .. }
            )));
            rig.store.fail_writes(false);
            rig.kernel
                .observation_latency(Duration::ZERO, Duration::ZERO);
            rig.settle();
            assert!(rig.machine().latch().is_none());
            assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
        }
    }
}

#[test]
fn recovery_restores_only_after_both_phases_and_stops_at_execution_deadline() {
    for expire in [false, true] {
        let mut rig = Rig::new();
        let key = rig.machine().desired().unwrap().hardening()[0]
            .key
            .to_string();
        rig.kernel.mutate(|m| {
            m.hardening.insert(key, Known::Value("999".into()));
        });
        rig.tick(); // Debounce.
        rig.kernel.clear_history();
        rig.kernel.inject(Fault {
            step: StepKind::WriteSysctl,
            remaining: Some(1),
            partial: false,
        });
        if expire {
            rig.kernel.expire_after(StepKind::WriteSysctl);
        }
        let report = rig.tick();
        assert!(
            report
                .failures
                .iter()
                .any(|(s, _)| matches!(s, Step::WriteSysctl { .. }))
        );
        let history = rig.kernel.history();
        let reads = rig.kernel.step_rest_reads();
        let failed = history
            .iter()
            .position(|(s, _)| matches!(s, Step::WriteSysctl { .. }))
            .unwrap();
        let subsequent_restores: Vec<_> = history
            .iter()
            .enumerate()
            .skip(failed + 1)
            .filter(|(_, (s, _))| matches!(s, Step::WriteSysctl { .. } | Step::ForwardingOn { .. }))
            .collect();
        if expire {
            assert!(!report.complete);
            assert_eq!(subsequent_restores.len(), 0);
            assert!(
                !history
                    .iter()
                    .any(|(s, _)| matches!(s, Step::RouteReplace { .. }))
            );
        } else {
            assert_ne!(subsequent_restores.len(), 0);
            assert!(
                subsequent_restores
                    .iter()
                    .all(|(i, _)| reads[*i] > reads[failed])
            );
        }
    }
    let mut rig = Rig::new();
    rig.flush_rules();
    rig.kernel.expire_after(StepKind::LoadRuleset);
    let report = rig.tick();
    assert!(!report.complete);
    assert!(
        report
            .steps
            .iter()
            .any(|s| matches!(s, Step::LoadRuleset { .. }))
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| matches!(s, Step::VerifyRuleset { .. } | Step::ForwardingOn { .. }))
    );
}

#[test]
fn randomized_multi_window_episodes_preserve_mixed_drift_liveness() {
    let mut tc_drifts = 0;
    let mut foreign_drifts = 0;
    for seed in 1..=16_u64 {
        let mut rig = Rig::new();
        let mut rng = seed;
        // Each episode spans several windows, retaining one reconciler and all budgets.
        for _window in 0..4 {
            // CE-11 shape in randomized order: two drifts of each unrelated class.
            let mut drifts = [false, false, true, true];
            for i in (1..drifts.len()).rev() {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                drifts.swap(
                    i,
                    usize::try_from((rng >> 32) % u64::try_from(i + 1).unwrap()).unwrap(),
                );
            }
            for tc in drifts {
                rig.kernel.clear_history();
                if tc {
                    tc_drifts += 1;
                    rig.kernel.mutate(|m| {
                        m.links.get_mut("wg0").unwrap().tc_hooks =
                            Known::Value(vec!["root".into()]);
                    });
                } else {
                    foreign_drifts += 1;
                    rig.kernel.mutate(foreign);
                }
                rig.tick();
                rig.settle();
                rig.safe_history();
                assert!(rig.machine().latch().is_none());
                assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
                assert_eq!(
                    rig.kernel.model().default_v4,
                    Known::Value(DefaultRouteObs::Dev("ex-ch1".into()))
                );
            }
            // Drift has stopped: liveness holds throughout the rest of this window.
            for _ in 0..10 {
                rig.time.set(rig.time.get() + 60);
                rig.round(true);
                rig.tick();
                assert!(rig.machine().latch().is_none());
                assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
                assert_eq!(
                    rig.kernel.model().default_v4,
                    Known::Value(DefaultRouteObs::Dev("ex-ch1".into()))
                );
            }
        }
    }
    assert!(tc_drifts >= 128 && foreign_drifts >= 128);
}

#[test]
fn emergency_only_ticks_defer_accounting_and_budget_latches_are_persisted() {
    let mut rig = Rig::new();
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::from_secs(20));
    for _ in 0..6 {
        rig.kernel.mutate(|m| {
            m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
        });
        assert!(!rig.tick().complete);
        assert!(rig.machine().latch().is_none());
    }
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::ZERO);
    rig.settle();
    assert!(rig.machine().latch().is_none());
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
    // The deferred reopening counted once. Two more reopenings reach the limit.
    for _ in 0..2 {
        rig.kernel.mutate(|m| {
            m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
        });
        rig.tick();
        rig.settle();
        assert!(rig.machine().latch().is_none());
    }
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::from_secs(20));
    rig.kernel.mutate(|m| {
        m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
    });
    let report = rig.tick();
    assert!(!report.complete);
    assert!(rig.machine().latch().is_some());
    assert!(rig.store.state().quarantine.is_some());
    assert!(
        report
            .steps
            .iter()
            .any(|s| matches!(s, Step::PersistLatch { .. }))
    );
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, EventKind::RepairSuppressed { .. }))
    );
}

#[test]
fn phase_b_receives_reobserved_safety_after_emergency_execution() {
    use scupper_core::planner::Latch;
    use scupper_sys::{
        lock::WriterGuard,
        reconcile::{Kernel, Observation, StepError},
    };
    use std::time::Instant;
    struct DuringContainment {
        inner: FakeKernel,
        mutated: Cell<bool>,
        observations: Rc<Cell<usize>>,
    }
    impl Kernel for DuringContainment {
        fn observe(&self, held: &NetnsHandle) -> Observation {
            self.observations.set(self.observations.get() + 1);
            self.inner.observe(held)
        }
        fn observe_rest(
            &self,
            held: &NetnsHandle,
            safety: Observation,
            deadline: Instant,
        ) -> Observation {
            if self.mutated.get() {
                assert!(self.observations.get() >= 2);
                assert_eq!(
                    safety.model.links["wg0"].tc_hooks,
                    Known::Value(vec!["root".into()])
                );
            }
            self.inner.observe_rest(held, safety, deadline)
        }
        fn execute(&self, step: &Step) -> Result<(), StepError> {
            self.inner.execute(step)?;
            if *step == Step::ForwardingOff && !self.mutated.replace(true) {
                self.inner.mutate(|m| {
                    m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
                });
            }
            Ok(())
        }
        fn hold_latch(&self, latch: Option<&Latch>) {
            self.inner.hold_latch(latch);
        }
        fn persisted_latch(&self, latch: Option<&Latch>) {
            self.inner.persisted_latch(latch);
        }
        fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError> {
            self.inner.restore_name(held, guard)
        }
    }
    let rig = Rig::new();
    let observations = Rc::new(Cell::new(0));
    let mut machine = Reconciler::new(
        DuringContainment {
            inner: rig.kernel.clone(),
            mutated: Cell::new(false),
            observations: observations.clone(),
        },
        rig.store.clone(),
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1100),
    )
    .unwrap();
    rig.flush_rules();
    let report = machine.tick();
    assert!(observations.get() >= 2);
    assert!(report.steps.contains(&Step::TcDelete {
        name: "wg0".into(),
        hook: "root".into()
    }));
    assert_eq!(
        rig.kernel.model().links["wg0"].tc_hooks,
        Known::Value(vec![])
    );
}

#[test]
fn full_observation_of_unknown_inventory_advances_ingress_quarantine() {
    let mut rig = Rig::new();
    rig.kernel
        .timeouts(BTreeSet::from([ObservationItem::Tc("wg0".into())]));
    assert!(!rig.tick().complete);
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(true));
    let report = rig.tick();
    assert!(!report.complete);
    assert!(
        report
            .steps
            .contains(&Step::LinkDown { name: "wg0".into() })
    );
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(false));
}

#[test]
fn emergency_client_down_is_reserved_for_ingress_quarantine() {
    let mut rig = Rig::new();
    rig.kernel.mutate(|m| {
        let link = m.links.get_mut("wg0").unwrap();
        let Known::Value(mut settings) = link.settings.clone() else {
            panic!("missing settings")
        };
        settings.mtu += 1;
        link.settings = Known::Value(settings);
    });
    rig.tick(); // The full plan debounces client configuration repair.
    rig.kernel.mutate(|m| {
        m.links.get_mut("ex-ch1").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
    });
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::from_secs(20));
    let report = rig.tick();
    assert!(!report.complete);
    assert!(report.steps.contains(&Step::ForwardingOff));
    assert!(
        !report
            .steps
            .contains(&Step::LinkDown { name: "wg0".into() })
    );
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(true));
}

#[test]
fn emergency_unknown_alert_uses_only_phase_a_observations() {
    for unknown in [false, true] {
        let mut rig = Rig::new();
        rig.kernel.mutate(|m| {
            m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
        });
        if unknown {
            rig.kernel
                .timeouts(BTreeSet::from([ObservationItem::Tc("wg0".into())]));
        }
        rig.kernel
            .observation_latency(Duration::ZERO, Duration::from_secs(20));
        let report = rig.tick();
        assert!(!report.complete);
        assert_eq!(
            report.steps.iter().any(|s| matches!(
                s,
                Step::Emit(scupper_core::planner::PlannerEvent::ObservationUnknown)
            )),
            unknown
        );
    }
}

#[test]
fn emergency_failure_replans_do_not_reserve_hardening_repairs() {
    let mut rig = Rig::new();
    let key = rig.machine().desired().unwrap().hardening()[0]
        .key
        .to_string();
    let expected = rig.kernel.model().hardening[&key].clone();
    rig.kernel.mutate(|m| {
        m.hardening.insert(key.clone(), Known::Value("999".into()));
    });
    rig.tick(); // Admit the hardening object through debounce.
    for _ in 0..2 {
        rig.kernel.mutate(foreign);
        rig.kernel.inject(Fault {
            step: StepKind::LinkDown,
            remaining: Some(1),
            partial: false,
        });
        let report = rig.tick();
        assert!(
            report
                .failures
                .iter()
                .any(|(s, _)| matches!(s, Step::LinkDown { .. }))
        );
        assert_ne!(rig.kernel.model().hardening[&key], expected);
    }
    let report = rig.tick();
    assert!(report.steps.iter().any(
        |s| matches!(s, Step::WriteSysctl { key: written, .. } if written.to_string() == key)
    ));
    assert_eq!(rig.kernel.model().hardening[&key], expected);
    assert!(rig.machine().latch().is_none());
}
