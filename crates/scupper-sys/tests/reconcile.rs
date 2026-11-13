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
    fs, io,
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
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("reconcile-fs")
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
        assert!(rig.machine().latch().is_some());
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
    // A disconnected restart must keep completing ticks without attempting a
    // forbidden reopen; complete ticks authorize status-code heartbeats.
    for _ in 0..4 {
        let report = rig.tick();
        assert!(report.complete, "{report:?}");
        assert_eq!(report.failures.len(), 0, "{:?}", report.failures);
        assert!(
            !report
                .steps
                .iter()
                .any(|step| matches!(step, Step::ForwardingOn { .. }))
        );
        let model = rig.kernel.model();
        assert_eq!(model.forwarding_v4, Known::Value(0));
        assert_eq!(model.forwarding_v6, Known::Value(0));
    }
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
#[allow(clippy::struct_excessive_bools)] // Independent injected collector faults.
struct CollectorSystem {
    calls: std::cell::RefCell<Vec<CollectorCall>>,
    fail_ruleset: Cell<bool>,
    fail_host_links: Cell<bool>,
    fail_netns_links: Cell<bool>,
    stall: Cell<bool>,
    per_link_race: Cell<u8>,
    link_dumps: Cell<usize>,
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
        if program == Program::Ip
            && args.iter().any(|a| a == "link")
            && (if ns {
                self.fail_netns_links.get()
            } else {
                self.fail_host_links.get()
            })
        {
            return Err(ExecError::Timeout { after: timeout });
        }
        let race = self.per_link_race.get();
        if ns && race != 0 {
            if program == Program::Ip && args.iter().any(|a| a == "link") {
                let dump = self.link_dumps.get() + 1;
                self.link_dumps.set(dump);
                if race == 4 && dump > 1 {
                    return Err(ExecError::Timeout { after: timeout });
                }
                let script = support::Script::new("ubuntu-24.04");
                let output = script.run_in(target, program, args, timeout)?;
                let mut links: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                if dump == 1 || matches!(race, 2 | 3) {
                    links.as_array_mut().unwrap().push(serde_json::json!({
                        "ifindex": if race == 3 && dump > 1 { 11 } else { 10 },
                        "ifname":"foreign0", "flags":["BROADCAST"], "mtu":1500,
                        "linkinfo":{"info_kind":"dummy"}
                    }));
                }
                return Ok(ExecOutput {
                    stdout: links.to_string(),
                    ..output
                });
            }
            let failed = program == Program::Tc && args.iter().any(|a| a == "foreign0")
                || race == 5
                    && program == Program::Sysctl
                    && args.iter().any(|a| a.contains(".foreign0."));
            if failed {
                return Ok(ExecOutput {
                    status: Some(1),
                    stdout: String::new(),
                    stderr: "Cannot find device foreign0".into(),
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
        uncertain: false,
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
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(false));
    let report = rig.tick();
    assert!(!report.complete);
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

// Drive the production scheduler with a real Reconciler<FakeKernel>, fake clock,
// fake signal source and local notify socket. A shutdown kernel mutation fails
// the final history comparison, even when it leaves final kernel state unchanged.
#[allow(clippy::struct_excessive_bools)] // Independent injected scheduler faults.
struct DaemonRig<'a> {
    rig: &'a mut Rig,
    now: std::time::Instant,
    origin: std::time::Instant,
    offset: Duration,
    limit: usize,
    iterations: usize,
    tick_duration: Duration,
    control_calls: usize,
    fail_control_bind: bool,
    complete_iterations: usize,
    heartbeat_calls: usize,
    degraded: bool,
    rebuild_pending: bool,
    probes: Option<scupper_sys::daemon::probes::Probes>,
    probe_received: bool,
    longest_tick: Duration,
    boots: usize,
    closed: usize,
    abandoned: usize,
    initialized: usize,
    notify: scupper_sys::daemon::notify::Notify,
    notifications: Option<std::os::unix::net::UnixDatagram>,
    messages: Vec<String>,
    before_shutdown: Option<Vec<(Step, KernelModel)>>,
    stop: &'a std::sync::atomic::AtomicBool,
}
impl scupper_sys::daemon::DaemonDeps for DaemonRig<'_> {
    fn now(&self) -> std::time::Instant {
        self.now
    }
    fn control_requests(&mut self) {
        self.control_calls += 1;
        if self.fail_control_bind {
            assert!(
                scupper_sys::daemon::control::Server::bind(&self.rig.root.join("unsafe-control"))
                    .is_err()
            );
        }
    }
    fn sleep(&mut self, duration: Duration) {
        if self.probes.is_some() {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.now += duration;
    }
    fn started(&mut self) {
        self.notify.started().unwrap();
    }
    fn initialize(&mut self) {
        self.initialized += 1;
    }
    fn tick(&mut self, _: &std::sync::atomic::AtomicBool) -> Option<TickReport> {
        self.iterations += 1;
        self.now += self.tick_duration;
        if self.degraded {
            return None;
        }
        self.rig.kernel.timeouts(if self.iterations == 1 {
            BTreeSet::from([ObservationItem::Ruleset])
        } else {
            BTreeSet::new()
        });
        let started = std::time::Instant::now();
        if let Some(probes) = &mut self.probes {
            for round in probes.collect() {
                if !round.paths.is_empty() {
                    assert!(
                        round.paths.values().all(
                            |outcome| *outcome != scupper_core::failover::ProbeOutcome::Success
                        )
                    );
                    self.rig.machine().submit_probe_outcomes(round.paths);
                    self.probe_received = true;
                }
            }
        }
        let mut report = self.rig.tick();
        self.longest_tick = self.longest_tick.max(started.elapsed());
        if self.rebuild_pending {
            report.complete = false;
            report.escalations.push(Escalation::RebuildRequired);
        }
        if self.iterations == self.limit {
            // SIGTERM arrives during this tick: it must finish, then no kernel work.
            self.stop.store(true, Ordering::Relaxed);
            self.before_shutdown = Some(self.rig.kernel.history());
        }
        Some(report)
    }
    fn close_only(&mut self) {
        use scupper_sys::reconcile::Kernel;
        self.closed += 1;
        self.rig.kernel.execute(&Step::ForwardingOff).unwrap();
    }
    fn abandon_probes(&mut self) {
        self.abandoned += 1;
    }
    fn rebuild(&mut self) {
        self.boots += 1;
    }
    fn run_root(&self) -> &std::path::Path {
        &self.rig.root
    }
    fn boot_time(&self) -> Duration {
        self.offset + self.now.duration_since(self.origin)
    }
    fn budget_error(&mut self, error: &std::io::Error) {
        panic!("budget: {error}");
    }
    fn maintenance(&mut self) {
        if self.iterations == self.limit {
            self.stop.store(true, Ordering::Relaxed);
        }
    }
    fn notify(&mut self, iteration: &scupper_sys::daemon::Iteration) {
        self.complete_iterations += usize::from(iteration.complete);
        self.notify
            .iteration(iteration.bounded, iteration.status)
            .unwrap();
        if let Some(socket) = &self.notifications {
            self.messages.extend(drain_notify(socket));
        }
    }
    fn heartbeat(&mut self) {
        use scupper_core::heartbeat::{CompleteIteration, Decision, SkipReason, decide};
        self.heartbeat_calls += 1;
        assert!(self.complete_iterations > 0);
        let settings: scupper_core::config::HeartbeatSettings = serde_json::from_value(serde_json::json!({
            "kind": "healthchecks", "url_ref": "check", "interval": "60s", "report": "status_code"
        })).unwrap();
        let now = MonoTime(self.now.duration_since(self.origin));
        assert_eq!(
            decide(&settings, now, None, None),
            Decision::Skip(SkipReason::NoIteration)
        );
        assert_eq!(
            decide(
                &settings,
                now,
                Some(CompleteIteration {
                    at: now,
                    full_fresh_check: true,
                    code: 5
                }),
                None
            ),
            Decision::Skip(SkipReason::InvalidCode)
        );
        assert!(matches!(
            decide(
                &settings,
                now,
                Some(CompleteIteration {
                    at: now,
                    full_fresh_check: true,
                    code: 0
                }),
                None
            ),
            Decision::Send { .. }
        ));
    }
    fn shutdown(&mut self) {
        self.rig.machine.take();
    }
}
fn daemon_notify_socket() -> (PathBuf, std::os::unix::net::UnixDatagram) {
    use std::os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    };
    let name = format!(
        "scupper-daemon-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let socket = UnixDatagram::bind_addr(&address).unwrap();
    (PathBuf::from(format!("@{name}")), socket)
}
fn drain_notify(socket: &std::os::unix::net::UnixDatagram) -> Vec<String> {
    let mut messages = Vec::new();
    let mut bytes = [0; 128];
    while let Ok(len) = socket.recv(&mut bytes) {
        messages.push(String::from_utf8(bytes[..len].to_vec()).unwrap());
    }
    messages
}
#[test]
fn daemon_scheduler_notifies_and_sigterm_shutdown_has_no_kernel_steps() {
    use scupper_sys::daemon::{notify::Notify, run_with};
    use std::{sync::atomic::AtomicBool, time::Instant};
    let mut rig = Rig::new();
    rig.flush_rules();
    let (socket_path, socket) = daemon_notify_socket();
    socket.set_nonblocking(true).unwrap();
    let stop = AtomicBool::new(false);
    let now = Instant::now();
    let mut deps = DaemonRig {
        rig: &mut rig,
        now,
        origin: now,
        offset: Duration::ZERO,
        limit: 3,
        iterations: 0,
        tick_duration: Duration::ZERO,
        control_calls: 0,
        fail_control_bind: false,
        complete_iterations: 0,
        heartbeat_calls: 0,
        degraded: false,
        rebuild_pending: false,
        probes: None,
        probe_received: false,
        longest_tick: Duration::ZERO,
        boots: 0,
        closed: 0,
        abandoned: 0,
        initialized: 0,
        notify: Notify::new(Some(socket_path.as_os_str())).unwrap(),
        notifications: Some(socket.try_clone().unwrap()),
        messages: Vec::new(),
        before_shutdown: None,
        stop: &stop,
    };
    run_with(&mut deps, &stop);
    assert_eq!(deps.iterations, 3);
    assert_eq!(
        deps.heartbeat_calls, 1,
        "only completed work before shutdown authorizes a heartbeat check"
    );
    assert_eq!(deps.now.duration_since(now), Duration::from_secs(4));
    assert!(deps.rig.machine.is_none());
    let before = deps.before_shutdown.take().unwrap();
    assert!(
        !before.is_empty(),
        "control: kernel work actually ran before SIGTERM"
    );
    assert_eq!(
        deps.rig.kernel.history(),
        before,
        "kernel operation after SIGTERM tick finished"
    );
    let messages = std::mem::take(&mut deps.messages);
    assert_eq!(messages.iter().filter(|s| *s == "READY=1").count(), 1);
    assert_eq!(messages.iter().filter(|s| *s == "WATCHDOG=1").count(), 2);
}
#[test]
fn degraded_scheduler_feeds_watchdog_and_boot_budget_survives_restarts() {
    use scupper_sys::daemon::{notify::Notify, run_with};
    use std::{sync::atomic::AtomicBool, time::Instant};
    let mut rig = Rig::new();
    let (socket_path, socket) = daemon_notify_socket();
    socket.set_nonblocking(true).unwrap();
    let mut boots = 0;
    for (offset, limit) in [
        (0, 16),
        (32, 16),
        (64, 16),
        (96, 16),
        (128, 16),
        (160, 16),
        (598, 1),
        (600, 1),
    ] {
        let stop = AtomicBool::new(false);
        let now = Instant::now();
        let mut deps = DaemonRig {
            rig: &mut rig,
            now,
            origin: now,
            offset: Duration::from_secs(offset),
            limit,
            iterations: 0,
            tick_duration: Duration::ZERO,
            control_calls: 0,
            fail_control_bind: false,
            complete_iterations: 0,
            heartbeat_calls: 0,
            degraded: true,
            rebuild_pending: false,
            probes: None,
            probe_received: false,
            longest_tick: Duration::ZERO,
            boots: 0,
            closed: 0,
            abandoned: 0,
            initialized: 0,
            notify: Notify::new(Some(socket_path.as_os_str())).unwrap(),
            notifications: Some(socket.try_clone().unwrap()),
            messages: Vec::new(),
            before_shutdown: None,
            stop: &stop,
        };
        run_with(&mut deps, &stop);
        boots += deps.boots;
        assert_eq!(deps.closed, limit);
        assert_eq!(deps.abandoned, limit);
        assert_eq!(deps.initialized, 1);
        assert!(boots <= if offset < 600 { 3 } else { 4 });
        let messages = std::mem::take(&mut deps.messages);
        assert_eq!(messages.iter().filter(|s| *s == "READY=1").count(), 1);
        assert_eq!(
            messages.iter().filter(|s| *s == "WATCHDOG=1").count(),
            limit
        );
    }
    assert_eq!(
        boots, 4,
        "three boots in first ten minutes; one when oldest expires"
    );
}

#[test]
fn rebuild_pending_scheduler_feeds_watchdog_while_retry_is_spaced() {
    use scupper_sys::daemon::{notify::Notify, run_with};
    use std::{sync::atomic::AtomicBool, time::Instant};
    let mut rig = Rig::new();
    let (socket_path, socket) = daemon_notify_socket();
    socket.set_nonblocking(true).unwrap();
    let stop = AtomicBool::new(false);
    let now = Instant::now();
    let mut deps = DaemonRig {
        rig: &mut rig,
        now,
        origin: now,
        offset: Duration::ZERO,
        limit: 4,
        iterations: 0,
        tick_duration: Duration::ZERO,
        control_calls: 0,
        fail_control_bind: false,
        complete_iterations: 0,
        heartbeat_calls: 0,
        degraded: false,
        rebuild_pending: true,
        probes: None,
        probe_received: false,
        longest_tick: Duration::ZERO,
        boots: 0,
        closed: 0,
        abandoned: 0,
        initialized: 0,
        notify: Notify::new(Some(socket_path.as_os_str())).unwrap(),
        notifications: Some(socket.try_clone().unwrap()),
        messages: Vec::new(),
        before_shutdown: None,
        stop: &stop,
    };
    run_with(&mut deps, &stop);
    assert_eq!(deps.boots, 1);
    assert_eq!(deps.complete_iterations, 0);
    assert_eq!(deps.heartbeat_calls, 0);
    assert_eq!(deps.abandoned, 3); // SIGTERM skips recovery after the last tick.
    let messages = std::mem::take(&mut deps.messages);
    assert_eq!(messages.iter().filter(|s| *s == "READY=1").count(), 1);
    assert_eq!(messages.iter().filter(|s| *s == "WATCHDOG=1").count(), 4);
}

#[test]
fn persistent_tighten_failure_never_consumes_a_reopen_budget() {
    for kind in [
        StepKind::ForwardingOff,
        StepKind::LinkDown,
        StepKind::TcDelete,
    ] {
        let mut rig = Rig::new();
        if kind == StepKind::ForwardingOff {
            rig.flush_rules();
        } else if kind == StepKind::LinkDown {
            rig.kernel.mutate(foreign);
        } else {
            rig.kernel.mutate(|m| {
                m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
            });
        }
        rig.kernel.inject(Fault {
            step: kind,
            remaining: None,
            partial: false,
        });
        for _ in 0..20 {
            let report = rig.tick();
            assert!(
                !report
                    .steps
                    .iter()
                    .any(|s| matches!(s, Step::ForwardingOn { .. }))
            );
            assert!(
                rig.machine().latch().is_none(),
                "Tighten was budgeted: {kind:?}; latch={:?}; report={report:?}",
                rig.machine().latch()
            );
        }
    }
}

#[test]
fn incomplete_failure_recovery_retains_route_and_rule_unknown_alerts() {
    use scupper_sys::reconcile::{Kernel, Observation, StepError};
    for rules in [false, true] {
        struct Incomplete {
            inner: FakeKernel,
            reads: Cell<usize>,
            rules: bool,
        }
        impl Kernel for Incomplete {
            fn observe(&self, held: &NetnsHandle) -> Observation {
                self.inner.observe(held)
            }
            fn observe_rest(
                &self,
                held: &NetnsHandle,
                safety: Observation,
                deadline: std::time::Instant,
            ) -> Observation {
                let mut observation = self.inner.observe_rest(held, safety, deadline);
                self.reads.set(self.reads.get() + 1);
                if self.reads.get() > 1 {
                    observation.complete = false;
                    if self.rules {
                        observation.model.extra_rules = Known::Unknown;
                    } else {
                        observation.model.extra_routes = Known::Unknown;
                    }
                }
                observation
            }
            fn restore_name(
                &self,
                held: &NetnsHandle,
                guard: &scupper_sys::lock::WriterGuard,
            ) -> Result<(), StepError> {
                self.inner.restore_name(held, guard)
            }
            fn execute(&self, step: &Step) -> Result<(), StepError> {
                self.inner.execute(step)
            }
            fn hold_latch(&self, latch: Option<&scupper_core::planner::Latch>) {
                self.inner.hold_latch(latch);
            }
        }
        let rig = Rig::new();
        rig.kernel.inject(Fault {
            step: StepKind::RouteReplace,
            remaining: Some(1),
            partial: false,
        });
        let mut machine = Reconciler::new(
            Incomplete {
                inner: rig.kernel.clone(),
                reads: Cell::new(0),
                rules,
            },
            rig.store.clone(),
            rig.log.handle.clone(),
            rig.config(),
            rig.held.clone(),
            || (MonoTime(Duration::from_secs(100)), 1000),
        )
        .unwrap();
        let report = machine.tick();
        assert!(!report.complete);
        assert!(
            report.events.iter().any(|event| matches!(
                event,
                EventKind::DriftDetected {
                    reason: scupper_proto::Reason::ObservationUnknown,
                    ..
                }
            )),
            "lost routes/rules unknown alert: {report:?}"
        );
    }
}

#[test]
fn successful_reopen_consumes_emergency_evidence_across_ticks() {
    let mut rig = Rig::new();
    for _ in 0..3 {
        rig.kernel.mutate(|m| {
            m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]);
        });
        rig.kernel.inject(Fault {
            step: StepKind::TcDelete,
            remaining: Some(1),
            partial: false,
        });
        rig.settle();
        assert!(rig.machine().latch().is_none());
        // Quiet ticks after the recovery must not charge its evidence again.
        rig.settle();
        assert!(rig.machine().latch().is_none());
    }
    rig.kernel
        .mutate(|m| m.links.get_mut("wg0").unwrap().tc_hooks = Known::Value(vec!["root".into()]));
    rig.tick();
    assert!(rig.machine().latch().is_some());
}

#[test]
fn probe_child_timeout_does_not_delay_fake_kernel_ticks() {
    use scupper_sys::{
        daemon::probes::Probes,
        probe_child::{ProbeKind, ProbeRequest, Url},
    };
    use std::{os::unix::fs::PermissionsExt, time::Instant};
    let mut rig = Rig::new();
    let script = rig.root.join("hung-probe");
    fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let start = Instant::now();
    let mut probes = Probes::new(script, start);
    probes
        .schedule(
            start,
            false,
            &scupper_core::config::ExitId("ch1".into()),
            ProbeRequest {
                kind: ProbeKind::Path,
                bind: None,
                expected_netns: rig.held.identity(),
                dns: "10.2.0.1".parse().unwrap(),
                targets: vec![Url::new("https://example.com/").unwrap()],
                deadline_ms: 10,
                identity: None,
            },
            &rig.held,
        )
        .unwrap();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut deps = DaemonRig {
        rig: &mut rig,
        now: start,
        origin: start,
        offset: Duration::ZERO,
        limit: 12,
        iterations: 0,
        tick_duration: Duration::ZERO,
        control_calls: 0,
        fail_control_bind: false,
        complete_iterations: 0,
        heartbeat_calls: 0,
        degraded: false,
        rebuild_pending: false,
        probes: Some(probes),
        probe_received: false,
        longest_tick: Duration::ZERO,
        boots: 0,
        closed: 0,
        abandoned: 0,
        initialized: 0,
        notify: scupper_sys::daemon::notify::Notify::disabled(),
        notifications: None,
        messages: Vec::new(),
        before_shutdown: None,
        stop: &stop,
    };
    scupper_sys::daemon::run_with(&mut deps, &stop);
    assert_eq!(deps.iterations, 12);
    assert_eq!(deps.now.duration_since(start), Duration::from_secs(22));
    assert!(
        deps.probe_received,
        "hung child result never reached the tick owner"
    );
    assert!(
        deps.longest_tick < Duration::from_millis(500),
        "tick waited on a child"
    );
    assert!(start.elapsed() < Duration::from_secs(6));
}

#[test]
fn scheduler_probes_selected_recovery_candidate_and_stops_when_disconnected() {
    let mut rig = Rig::with_site(multi_exit_site());
    let second = scupper_core::config::ExitId("ch2".into());
    rig.machine()
        .set_selection(Selection::Pin(second.clone()), Actor::Local { uid: 0 })
        .unwrap();
    assert_eq!(rig.machine().probe_exit(), Some(second));
    rig.machine()
        .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
        .unwrap();
    assert_eq!(rig.machine().probe_exit(), None);
}

#[test]
fn changed_applied_version_never_reloads_the_old_render() {
    use scupper_sys::reconcile::StateStore;
    let mut rig = Rig::new();
    let mut state = rig.store.state();
    state.applied_version = Some(2);
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    rig.kernel.mutate(|model| {
        model.ruleset = Known::Value(Ruleset::Verified([9; 32]));
    });
    rig.kernel.clear_history();
    let report = rig.tick();
    assert_eq!(report.escalations, vec![Escalation::ReinitializeRequired]);
    assert_eq!(report.steps, vec![Step::ForwardingOff]);
    assert_eq!(
        rig.kernel.model().ruleset,
        Known::Value(Ruleset::Verified([9; 32]))
    );
    assert!(
        rig.kernel
            .history()
            .iter()
            .all(|(step, _)| matches!(step, Step::ForwardingOff))
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the operation table and independent closure oracle together.
fn control_ops_use_fake_kernel_and_verify_disconnect_independently() {
    use scupper_core::verdict::v2::{Degraded, FailClosed, Report, Verdict};
    use scupper_proto::{ApiErrorCode, Op, OpResult};
    use scupper_sys::daemon::admin::execute;
    let mut rig = Rig::new();
    let healthy = |_| {
        Ok(Report {
            verdict: Verdict::Protected {
                exit: scupper_core::config::ExitId("ch1".into()),
                exit_ip: "192.0.2.1".parse().unwrap(),
            },
            warnings: vec![],
            at: 1000,
            config_version: 1,
        })
    };
    assert!(matches!(
        execute(rig.machine(), Op::Ping {}, 0, Some(2), healthy).unwrap(),
        OpResult::Ping {
            last_complete_iteration_age: Some(2),
            version: 1,
            ..
        }
    ));
    assert!(matches!(
        execute(rig.machine(), Op::Check {}, 0, None, healthy).unwrap(),
        OpResult::Check { .. }
    ));
    assert!(matches!(
        execute(rig.machine(), Op::Connect { exit: None }, 0, None, healthy).unwrap(),
        OpResult::Connect { .. }
    ));
    assert!(matches!(
        execute(rig.machine(), Op::RepairStatus {}, 0, None, healthy).unwrap(),
        OpResult::RepairStatus {
            quarantined: false,
            ..
        }
    ));
    assert!(
        execute(
            rig.machine(),
            Op::RepairClear { reason: None },
            0,
            None,
            healthy
        )
        .is_ok()
    );
    assert_eq!(
        execute(rig.machine(), Op::Disconnect {}, 1000, None, healthy)
            .unwrap_err()
            .code,
        ApiErrorCode::Unauthorized
    );
    let kernel = rig.kernel.clone();
    let closed = |_| {
        let model = kernel.model();
        let effective = model.default_v4 == Known::Value(DefaultRouteObs::Unreachable)
            && model.default_v6 == Known::Value(DefaultRouteObs::Unreachable)
            && model.links["ex-ch1"].up == Known::Value(false);
        Ok(Report {
            verdict: if effective {
                Verdict::FailClosed(FailClosed::AdminDisconnected)
            } else {
                Verdict::Degraded(Degraded::DisconnectNotEffective)
            },
            warnings: vec![],
            at: 1000,
            config_version: 1,
        })
    };
    rig.kernel.inject(Fault {
        step: StepKind::RouteReplace,
        remaining: None,
        partial: false,
    });
    let error = execute(rig.machine(), Op::Disconnect {}, 0, None, closed).unwrap_err();
    assert_eq!(error.code, ApiErrorCode::DisconnectNotEffective);
    assert!(error.observation.is_some());
    assert_eq!(rig.store.state().selection, Selection::Disconnected);
    assert_ne!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Unreachable)
    );
    let mut rig = Rig::new();
    assert!(
        execute(rig.machine(), Op::Disconnect {}, 0, None, |_| Ok(Report {
            verdict: Verdict::FailClosed(FailClosed::AdminDisconnected),
            warnings: vec![],
            at: 1000,
            config_version: 1
        }))
        .is_ok()
    );
    assert_eq!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Unreachable)
    );
    rig.store.fail_writes(true);
    assert!(execute(rig.machine(), Op::Connect { exit: None }, 0, None, healthy).is_err());
    assert_eq!(rig.store.state().selection, Selection::Disconnected);
    assert!(
        execute(rig.machine(), Op::Check {}, 0, None, |_| Err(
            scupper_proto::ApiError {
                code: ApiErrorCode::Internal,
                observation: None
            }
        ))
        .is_err()
    );
}

#[test]
fn control_apply_planner_previews_without_writes_then_repairs_without_auto_debounce() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|model| *model.hardening.values_mut().next().unwrap() = Known::Value("-1".into()));
    let before = rig.kernel.history().len();
    let preview = rig
        .machine()
        .apply_plan(true, Actor::Local { uid: 0 })
        .unwrap();
    assert!(preview.contains(&StepKind::WriteSysctl));
    assert_eq!(rig.kernel.history().len(), before);
    let executed = rig
        .machine()
        .apply_plan(false, Actor::Local { uid: 0 })
        .unwrap();
    assert!(executed.contains(&StepKind::WriteSysctl));
    assert!(rig.kernel.history().len() > before);
}

#[test]
fn control_repair_clear_preserves_another_writers_selection() {
    use scupper_sys::reconcile::StateStore;
    let mut rig = Rig::new();
    let mut state = rig.store.state();
    state.selection = Selection::Disconnected;
    state.quarantine = Some(scupper_sys::state::Quarantine {
        reason: "repair-budget".into(),
        object: "safety:ruleset".into(),
        since_unix: 1000,
        uncertain: false,
    });
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    rig.machine().clear_latch(Actor::Local { uid: 0 }).unwrap();
    assert_eq!(rig.store.state().selection, Selection::Disconnected);
    assert!(rig.store.state().quarantine.is_none());
    rig.tick();
    assert_eq!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Unreachable)
    );
}

#[test]
fn verified_apply_clear_is_not_undone_by_a_stale_daemon_version_handoff() {
    use scupper_sys::reconcile::StateStore;
    let mut rig = Rig::new();
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let mut state = rig.store.state();
    state.quarantine = Some(scupper_sys::state::Quarantine {
        reason: "repair-budget".into(),
        object: "safety:ruleset".into(),
        since_unix: 1000,
        uncertain: false,
    });
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    rig.restart();
    assert!(rig.machine().latch().is_some());
    let guard = WriterLock::acquire(&rig.root).unwrap();
    state.applied_version = Some(2);
    state.quarantine = None;
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    assert!(
        rig.tick()
            .escalations
            .contains(&Escalation::ReinitializeRequired)
    );
    assert!(rig.store.state().quarantine.is_none());
    assert!(rig.machine().latch().is_none());
    assert!(rig.kernel.model().forwarding_off());
}

#[test]
fn control_requests_are_serviced_without_scheduler_sleep() {
    use scupper_sys::daemon::{notify::Notify, run_with};
    use std::{sync::atomic::AtomicBool, time::Instant};
    let mut rig = Rig::new();
    let (socket_path, socket) = daemon_notify_socket();
    socket.set_nonblocking(true).unwrap();
    let stop = AtomicBool::new(false);
    let now = Instant::now();
    let mut deps = DaemonRig {
        rig: &mut rig,
        now,
        origin: now,
        offset: Duration::ZERO,
        limit: 7,
        iterations: 0,
        tick_duration: Duration::from_secs(3),
        control_calls: 0,
        fail_control_bind: false,
        complete_iterations: 0,
        heartbeat_calls: 0,
        degraded: false,
        rebuild_pending: false,
        probes: None,
        probe_received: false,
        longest_tick: Duration::ZERO,
        boots: 0,
        closed: 0,
        abandoned: 0,
        initialized: 0,
        notify: Notify::new(Some(socket_path.as_os_str())).unwrap(),
        notifications: Some(socket.try_clone().unwrap()),
        messages: Vec::new(),
        before_shutdown: None,
        stop: &stop,
    };
    run_with(&mut deps, &stop);
    assert_eq!(deps.iterations, 7);
    assert_eq!(deps.control_calls, 7);
    assert_eq!(deps.now.duration_since(now), Duration::from_secs(21));
}

#[test]
fn connect_supersedes_frozen_ineffective_disconnect_within_ten_seconds() {
    for selection in [
        Selection::Auto,
        Selection::Prefer(scupper_core::config::ExitId("ch1".into())),
        Selection::Pin(scupper_core::config::ExitId("ch1".into())),
    ] {
        let mut rig = Rig::new();
        let guard = WriterLock::acquire(&rig.root).unwrap();
        // The daemon's incomplete-tick hook skips reconciliation entirely.
        // Persist intent through the same scheduler API, without draining actions.
        rig.machine()
            .set_intent_locked(&guard, Selection::Disconnected)
            .unwrap();
        rig.kernel.mutate(|model| {
            model.links.get_mut("ex-ch1").unwrap().up = Known::Value(true);
            model.default_v4 = Known::Value(DefaultRouteObs::Dev("ex-ch1".into()));
        });
        rig.time.set(rig.time.get() + 45);
        assert_eq!(rig.store.state().selection, Selection::Disconnected);
        assert_eq!(rig.kernel.history(), Vec::new());
        assert_ne!(
            rig.kernel.model().default_v4,
            Known::Value(DefaultRouteObs::Unreachable),
            "disconnect is still ineffective while ticks are frozen"
        );
        rig.machine().set_intent_locked(&guard, selection).unwrap();
        drop(guard);
        let start = rig.time.get();
        for _ in 0..4 {
            let report = rig.tick();
            assert!(report.complete, "{report:?}");
            assert!(report.failures.is_empty(), "{report:?}");
            assert!(!report.steps.contains(&Step::LinkDown {
                name: "ex-ch1".into()
            }));
            assert!(!matches!(
                rig.machine().health()[&scupper_core::config::ExitId("ch1".into())],
                scupper_core::failover::ExitHealth::Down { .. }
            ));
            let model = rig.kernel.model();
            let desired = rig.machine().desired().unwrap();
            if model.default_v4 == Known::Value(DefaultRouteObs::Dev("ex-ch1".into()))
                && model.forwarding_v4 == Known::Value(1)
                && safe(&model, &desired)
            {
                assert!(rig.time.get() - start < 10);
                rig.safe_history();
                assert_eq!(rig.tick().failures, Vec::new());
                assert!(!matches!(
                    rig.machine().health()[&scupper_core::config::ExitId("ch1".into())],
                    scupper_core::failover::ExitHealth::Down { .. }
                ));
                break;
            }
            assert!(rig.time.get() - start < 8, "connect did not become ready");
        }
    }
}

#[test]
fn frozen_disconnect_still_removes_injected_route_before_availability_reads() {
    let mut rig = Rig::new();
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.machine()
        .set_intent_locked(&guard, Selection::Disconnected)
        .unwrap();
    drop(guard);
    rig.kernel.mutate(|model| {
        model.links.get_mut("ex-ch1").unwrap().up = Known::Value(true);
        model.default_v4 = Known::Value(DefaultRouteObs::Dev("ex-ch1".into()));
    });
    let reads = rig.kernel.rest_reads();
    rig.kernel
        .observation_latency(Duration::ZERO, Duration::from_secs(20));
    let report = rig.tick();
    assert!(!report.complete);
    assert_eq!(report.failures, Vec::new());
    let model = rig.kernel.model();
    assert_eq!(model.default_v4, Known::Value(DefaultRouteObs::Missing));
    assert_eq!(model.links["ex-ch1"].up, Known::Value(false));
    assert!(model.forwarding_off());
    assert!(
        rig.kernel
            .step_rest_reads()
            .iter()
            .all(|count| *count == reads)
    );
    assert!(!raises(&report));
}

#[test]
fn pending_connect_allows_ticks_to_qualify() {
    let mut rig = Rig::new();
    rig.machine()
        .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
        .unwrap();
    for _ in 0..20 {
        rig.tick();
    }
    let exit = scupper_core::config::ExitId("ch1".into());
    rig.kernel.handshake(exit.clone(), None);
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.machine()
        .set_intent_locked(&guard, Selection::Auto)
        .unwrap();
    drop(guard);
    assert_eq!(rig.store.state().selection, Selection::Auto);
    assert!(rig.machine().probe_exit().is_some());
    for _ in 0..2 {
        rig.round(true);
        rig.tick();
    }
    assert_eq!(
        rig.kernel.model().default_v4,
        Known::Value(DefaultRouteObs::Unreachable)
    );
    rig.kernel.handshake(exit, Some(Duration::from_secs(1)));
    for _ in 0..6 {
        rig.round(true);
        rig.tick();
    }
    assert_eq!(
        rig.machine().verdict(),
        Some(scupper_proto::VerdictCode::Protected)
    );
}
#[test]
fn connect_rejects_unconfigured_exit_and_quarantine() {
    use scupper_proto::{ApiErrorCode, Op};
    use scupper_sys::{daemon::admin::execute, reconcile::StateStore};
    let mut rig = Rig::new();
    assert_eq!(
        execute(
            rig.machine(),
            Op::Connect {
                exit: Some(scupper_proto::Identifier::try_from("missing".to_owned()).unwrap())
            },
            0,
            None,
            |_| unreachable!()
        )
        .unwrap_err()
        .code,
        ApiErrorCode::InvalidRequest
    );
    let mut state = rig.store.state();
    state.quarantine = Some(scupper_sys::state::Quarantine {
        reason: "state write failed".into(),
        object: "state".into(),
        since_unix: 1000,
        uncertain: false,
    });
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    rig.restart();
    assert_eq!(
        execute(
            rig.machine(),
            Op::Connect { exit: None },
            0,
            None,
            |_| unreachable!()
        )
        .unwrap_err()
        .code,
        ApiErrorCode::Quarantined
    );
}

#[test]
fn repair_clear_retains_operator_context_and_actual_latch_reason() {
    use scupper_proto::{Op, OpResult};
    use scupper_sys::{daemon::admin::execute, reconcile::StateStore};
    let mut rig = Rig::new();
    let mut state = rig.store.state();
    state.quarantine = Some(scupper_sys::state::Quarantine {
        reason: "state write failed".into(),
        object: "state".into(),
        since_unix: 1000,
        uncertain: false,
    });
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    rig.restart();
    assert!(
        matches!(execute(rig.machine(), Op::RepairStatus {}, 0, None, |_| unreachable!()).unwrap(), OpResult::RepairStatus { reason: Some(reason), .. } if reason == "state write failed")
    );
    execute(
        rig.machine(),
        Op::RepairClear {
            reason: Some("operator inspected gateway".into()),
        },
        0,
        None,
        |_| unreachable!(),
    )
    .unwrap();
    assert!(
        !serde_json::to_string(&rig.store.state())
            .unwrap()
            .contains("last_repair_reason")
    );
    let disk = EventLog::open(&rig.root, GatewayId("gw1".into()), || UnixSeconds(1000)).unwrap();
    rig.log.handle.replay_into(&disk.handle).unwrap();
    disk.handle.flush_blocking(Duration::from_secs(2)).unwrap();
    assert!(scupper_sys::events::read_since(&rig.root, 0, None).map(Result::unwrap).any(|event| matches!(&event.kind,
        scupper_proto::EventKind::AdminAction { reason: Some(reason), .. } if reason == "operator inspected gateway")));
}

#[test]
fn bind_failure_does_not_prevent_scheduler_ticks() {
    use scupper_sys::daemon::{notify::Notify, run_with};
    use std::os::unix::fs::PermissionsExt;
    use std::{sync::atomic::AtomicBool, time::Instant};
    let mut rig = Rig::new();
    fs::create_dir_all(rig.root.join("unsafe-control")).unwrap();
    fs::set_permissions(
        rig.root.join("unsafe-control"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let (socket_path, socket) = daemon_notify_socket();
    socket.set_nonblocking(true).unwrap();
    let stop = AtomicBool::new(false);
    let now = Instant::now();
    let mut deps = DaemonRig {
        rig: &mut rig,
        now,
        origin: now,
        offset: Duration::ZERO,
        limit: 3,
        iterations: 0,
        tick_duration: Duration::ZERO,
        control_calls: 0,
        fail_control_bind: true,
        complete_iterations: 0,
        heartbeat_calls: 0,
        degraded: false,
        rebuild_pending: false,
        probes: None,
        probe_received: false,
        longest_tick: Duration::ZERO,
        boots: 0,
        closed: 0,
        abandoned: 0,
        initialized: 0,
        notify: Notify::new(Some(socket_path.as_os_str())).unwrap(),
        notifications: Some(socket.try_clone().unwrap()),
        messages: Vec::new(),
        before_shutdown: None,
        stop: &stop,
    };
    run_with(&mut deps, &stop);
    assert_eq!(deps.iterations, 3);
    assert!(deps.control_calls >= 3);
    assert!(deps.complete_iterations > 0);
}

#[test]
fn read_only_admin_ignores_writer_contention() {
    use scupper_proto::{Op, OpResult};
    let mut rig = Rig::new();
    let guard = WriterLock::acquire(&rig.root).unwrap();
    assert!(matches!(
        scupper_sys::daemon::admin::execute(
            rig.machine(),
            Op::Ping {},
            0,
            Some(0),
            |_| unreachable!()
        )
        .unwrap(),
        OpResult::Ping { .. }
    ));
    assert!(matches!(
        scupper_sys::daemon::admin::execute(
            rig.machine(),
            Op::RepairStatus {},
            0,
            None,
            |_| unreachable!()
        )
        .unwrap(),
        OpResult::RepairStatus { .. }
    ));
    drop(guard);
}

#[test]
fn repair_clear_reopens_forwarding_after_quarantined_restart() {
    let mut rig = Rig::new();
    let mut state = rig.store.state();
    state.quarantine = Some(scupper_sys::state::Quarantine {
        reason: "repair budget".into(),
        object: "safety:ruleset".into(),
        since_unix: 1000,
        uncertain: false,
    });
    let guard = WriterLock::acquire(&rig.root).unwrap();
    scupper_sys::reconcile::StateStore::write(&rig.store, &guard, &state).unwrap();
    drop(guard);
    rig.kernel.mutate(|model| {
        model.forwarding_v4 = Known::Value(0);
        model.forwarding_v6 = Known::Value(0);
        model.default_forwarding_v4 = Known::Value(0);
        model.default_forwarding_v6 = Known::Value(0);
        model.client_forwarding_v4 = Known::Value(0);
        for link in model.links.values_mut() {
            link.forwarding_v4 = Known::Value(0);
            link.forwarding_v6 = Known::Value(0);
        }
    });
    rig.restart();
    let mut recovered = false;
    for _ in 0..4 {
        rig.round(true);
        recovered |= rig.tick().events.iter().any(|event| {
            matches!(
                event,
                EventKind::FailClosedEnded { .. } | EventKind::FailClosedState { closed: false }
            )
        });
    }
    assert!(recovered, "exit recovery must be reported while latched");
    assert!(rig.kernel.model().forwarding_off());
    rig.machine().clear_latch(Actor::Local { uid: 0 }).unwrap();
    for _ in 0..4 {
        rig.round(true);
        rig.tick();
    }
    let model = rig.kernel.model();
    for gate in [
        &model.forwarding_v4,
        &model.forwarding_v6,
        &model.default_forwarding_v4,
        &model.default_forwarding_v6,
        &model.client_forwarding_v4,
    ] {
        assert_eq!(*gate, Known::Value(1));
    }
    assert!(rig.store.state().quarantine.is_none());
    assert!(rig.machine().latch().is_none());
}

#[test]
fn outage_latch_recovery_clear_and_second_outage_emit_two_firings() {
    use scupper_sys::reconcile::StateStore;
    let mut rig = Rig::new();
    let mut events = Vec::new();
    rig.kernel
        .handshake(scupper_core::config::ExitId("ch1".into()), None);
    events.extend(rig.tick().events);
    let mut state = rig.store.state();
    state.quarantine = Some(scupper_sys::state::Quarantine {
        reason: "repair budget".into(),
        object: "safety:ruleset".into(),
        since_unix: 1000,
        uncertain: false,
    });
    let guard = WriterLock::acquire(&rig.root).unwrap();
    rig.store.write(&guard, &state).unwrap();
    drop(guard);
    events.extend(rig.tick().events);
    rig.kernel.handshake(
        scupper_core::config::ExitId("ch1".into()),
        Some(Duration::ZERO),
    );
    for _ in 0..6 {
        rig.time.set(rig.time.get() + 30);
        rig.round(true);
        events.extend(rig.tick().events);
    }
    assert!(rig.machine().latch().is_some());
    assert!(
        events
            .iter()
            .any(|e| matches!(e, EventKind::FailClosedEnded { .. }))
    );
    rig.machine().clear_latch(Actor::Local { uid: 0 }).unwrap();
    rig.tick();
    rig.kernel
        .handshake(scupper_core::config::ExitId("ch1".into()), None);
    events.extend(rig.tick().events);
    let mut coalescer = scupper_core::alerts::Coalescer::default();
    let mut queued = Vec::new();
    for (seq, kind) in events.into_iter().enumerate() {
        let event = scupper_proto::Event {
            seq: seq as u64 + 1,
            at: UnixSeconds(seq as u64),
            kind,
            actor: Actor::Daemon,
            gateway: scupper_proto::Identifier::try_from("gw1".to_owned()).unwrap(),
            config_version: None,
        };
        if let Some(alert) = event.alert() {
            queued.extend(coalescer.push(alert));
        }
    }
    assert_eq!(
        queued
            .iter()
            .filter(|a| a.key == scupper_core::alerts::AlertKey::FailClosed
                && a.state == scupper_core::alerts::AlertState::Firing)
            .count(),
        2
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep FakeKernel drift, the real check, and the alert lifecycle in one fixture.
fn fake_kernel_ruleset_drift_reaches_daemon_full_check_alert_and_recovers() {
    use scupper_core::alerts::{AlertKey, AlertState, Coalescer};
    use scupper_sys::boot::{BootDeps, GatewayNamespace};
    let mut rig = Rig::new();
    rig.flush_rules();
    let sys = support::Script::new("ubuntu-24.04");
    support::fresh(&sys);
    let root = support::Root::new("ubuntu-24.04", &rig.held);
    let site = support::site("ubuntu-24.04");
    let config = Config {
        site,
        gateway: GatewayId("gw1".into()),
        stamp: root.stamp,
        fingerprint: [7; 32],
        run_root: root.path.clone(),
        lock_wait: Duration::ZERO,
    };
    let deps = BootDeps {
        system: &sys,
        namespace: &GatewayNamespace,
        run_root: &root.path,
        state_root: &root.path,
        config_root: &root.path,
        hook: None,
        secret_owner: 0,
    };
    assert_eq!(rig.kernel.model().ruleset, Known::Value(Ruleset::Absent));
    sys.replace("scupper-nft-ruleset.json", r#"{"nftables":[]}"#);
    let (report, firing) =
        scupper_sys::daemon::testing::protection_alerts(&deps, &sys, &rig.held, &config).unwrap();
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(matches!(
        firing.as_slice(),
        [EventKind::CheckVerdictChanged {
            to: scupper_proto::VerdictCode::Unprotected,
            reason: scupper_proto::ObjectKind::Ruleset,
            ..
        }]
    ));
    rig.tick();
    assert!(matches!(
        rig.kernel.model().ruleset,
        Known::Value(Ruleset::Verified(_))
    ));
    sys.replacements
        .borrow_mut()
        .remove("scupper-nft-ruleset.json");
    let (report, recovered) =
        scupper_sys::daemon::testing::protection_alerts(&deps, &sys, &rig.held, &config).unwrap();
    assert_eq!(report.verdict.exit_code(), 0, "{report:?}");
    let mut queue = Vec::new();
    let mut coalescer = Coalescer::default();
    for (seq, kind) in firing.into_iter().chain(recovered).enumerate() {
        let event = scupper_proto::Event {
            seq: seq as u64 + 1,
            at: UnixSeconds(seq as u64 * 60),
            kind,
            actor: Actor::Daemon,
            gateway: scupper_proto::Identifier::try_from("gw1".to_owned()).unwrap(),
            config_version: None,
        };
        queue.extend(coalescer.push(event.alert().unwrap()));
    }
    assert_eq!(
        queue.iter().map(|a| (a.key, a.state)).collect::<Vec<_>>(),
        vec![
            (AlertKey::Unprotected, AlertState::Firing),
            (AlertKey::Unprotected, AlertState::Resolved)
        ]
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Exercise the real full-check emitter for each protection reason in one fixture.
fn daemon_full_check_uplink_exit_ip_is_critical_and_probe_failure_is_not() {
    use scupper_sys::boot::{BootDeps, GatewayNamespace};
    let held = testing::handle().unwrap();
    let sys = support::Script::new("ubuntu-24.04");
    support::fresh(&sys);
    let root = support::Root::new("ubuntu-24.04", &held);
    let config = Config {
        site: support::site("ubuntu-24.04"),
        gateway: GatewayId("gw1".into()),
        stamp: root.stamp,
        fingerprint: [7; 32],
        run_root: root.path.clone(),
        lock_wait: Duration::ZERO,
    };
    let deps = BootDeps {
        system: &sys,
        namespace: &GatewayNamespace,
        run_root: &root.path,
        state_root: &root.path,
        config_root: &root.path,
        hook: None,
        secret_owner: 0,
    };
    let links = sys.text("scupper--4-link.json");
    let mut foreign: serde_json::Value = serde_json::from_str(&links).unwrap();
    foreign
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|l| l["ifname"] == "wg0")
        .unwrap()["linkinfo"]["info_kind"] = serde_json::json!("veth");
    let peer = support::fixture("ubuntu-24.04", "scupper-wg-ex-ch1-peers.txt");
    for (file, value, reason) in [
        (
            "scupper--4-link.json",
            foreign.to_string(),
            scupper_proto::ObjectKind::ForeignLink,
        ),
        (
            "scupper-tc-lo-ingress.json",
            r#"[{"kind":"bpf"}]"#.into(),
            scupper_proto::ObjectKind::TcHook,
        ),
        (
            "scupper-wg-ex-ch1-allowed-ips.txt",
            format!("{}\t192.0.2.0/24\n", peer.trim()),
            scupper_proto::ObjectKind::Peer,
        ),
    ] {
        let original = sys.text(file);
        sys.replace(file, &value);
        let (report, events) =
            scupper_sys::daemon::testing::protection_alerts(&deps, &sys, &held, &config).unwrap();
        assert_eq!(report.verdict.exit_code(), 2, "{report:?}");
        assert!(
            matches!(events.as_slice(), [EventKind::CheckVerdictChanged { to: scupper_proto::VerdictCode::Unprotected, reason: r, .. }] if *r == reason),
            "{events:?}"
        );
        sys.replace(file, &original);
    }
    let original = sys.probe.borrow().clone();
    let mut probe: serde_json::Value = serde_json::from_str(&original).unwrap();
    // The real check reads the uplink address from the host address fixture.
    let addresses: serde_json::Value =
        serde_json::from_str(&sys.text("gwhost--4-addr.json")).unwrap();
    let uplink = addresses
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["ifname"] == "eth0")
        .unwrap()["addr_info"][0]["local"]
        .clone();
    probe["result"]["ip"] = uplink;
    *sys.probe.borrow_mut() = probe.to_string();
    let (report, events) =
        scupper_sys::daemon::testing::protection_alerts(&deps, &sys, &held, &config).unwrap();
    assert_eq!(report.verdict.exit_code(), 2, "{report:?}");
    assert!(matches!(
        events.as_slice(),
        [EventKind::CheckVerdictChanged {
            to: scupper_proto::VerdictCode::Unprotected,
            reason: scupper_proto::ObjectKind::ExitIp,
            ..
        }]
    ));
    probe["result"] = serde_json::json!({"class":"timeout"});
    *sys.probe.borrow_mut() = probe.to_string();
    let (_, events) =
        scupper_sys::daemon::testing::protection_alerts(&deps, &sys, &held, &config).unwrap();
    assert_eq!(events, []);
}

#[test]
fn healthy_restart_and_connect_state_observations_do_not_create_incidents() {
    let mut rig = Rig::new();
    for connect in [false, true] {
        rig.restart();
        let mut events = Vec::new();
        if connect {
            events.extend(
                rig.machine()
                    .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
                    .unwrap()
                    .events,
            );
            events.extend(
                rig.machine()
                    .set_selection(Selection::Auto, Actor::Local { uid: 0 })
                    .unwrap()
                    .events,
            );
        }
        for _ in 0..6 {
            rig.round(true);
            events.extend(rig.tick().events);
        }
        let mut coalescer = scupper_core::alerts::Coalescer::default();
        for (seq, kind) in events.into_iter().enumerate() {
            assert!(
                !matches!(kind, EventKind::FailClosedEnded { .. }),
                "healthy qualification is not a recovery"
            );
            let event = scupper_proto::Event {
                seq: seq as u64 + 1,
                at: UnixSeconds(seq as u64),
                kind,
                actor: Actor::Daemon,
                gateway: scupper_proto::Identifier::try_from("gw1".to_owned()).unwrap(),
                config_version: None,
            };
            if let Some(alert) = event.alert() {
                assert_eq!(coalescer.push(alert), []);
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the healthy reset, real cadence, and containment assertions together.
fn reconnect_with_retained_stale_handshake_qualifies_from_unknown_without_incident() {
    use scupper_core::{config::ExitId, failover::ExitHealth};
    for retained in [false, true] {
        let mut rig = Rig::new();
        let exit = ExitId("ch1".into());
        assert!(matches!(
            rig.machine().health()[&exit],
            ExitHealth::Healthy {
                confirmed: true,
                ..
            }
        ));
        rig.kernel.handshake(exit.clone(), Some(Duration::ZERO));
        let mut events = rig
            .machine()
            .set_selection(Selection::Disconnected, Actor::Local { uid: 0 })
            .unwrap()
            .events;
        assert_eq!(rig.machine().health()[&exit], ExitHealth::Unknown);
        assert_eq!(rig.kernel.model().links["ex-ch1"].up, Known::Value(false));
        rig.time.set(rig.time.get() + 600);
        let base = rig.time.get();
        rig.kernel
            .handshake(exit.clone(), retained.then_some(Duration::from_secs(600)));
        events.extend(
            rig.machine()
                .set_selection(Selection::Auto, Actor::Local { uid: 0 })
                .unwrap()
                .events,
        );
        assert_eq!(rig.machine().health()[&exit], ExitHealth::Unknown);
        for offset in (2..=42).step_by(2) {
            let age = if offset < 14 {
                retained.then_some(Duration::from_secs(600 + offset))
            } else {
                Some(Duration::from_secs(offset - 14))
            };
            rig.kernel.handshake(exit.clone(), age);
            if offset % 10 == 2 {
                rig.round(true);
            }
            events.extend(rig.tick().events);
            assert_eq!(rig.time.get(), base + offset);
            if offset == 14 {
                assert_eq!(rig.kernel.model().links["ex-ch1"].up, Known::Value(true));
            }
            if offset < 42 {
                assert_eq!(rig.machine().health()[&exit], ExitHealth::Unknown);
                assert_eq!(
                    rig.machine().desired().unwrap().routes()[0].1,
                    RouteTarget::Unreachable
                );
            }
        }
        assert!(matches!(
            rig.machine().health()[&exit],
            ExitHealth::Healthy {
                confirmed: true,
                ..
            }
        ));
        assert!(!events.iter().any(|e| matches!(
            e,
            EventKind::FailClosedStarted { .. } | EventKind::FailClosedEnded { .. }
        )));
        rig.safe_history();
    }
}

#[test]
fn cold_start_without_resume_qualifies_at_real_cadence_without_incident() {
    for inherited_down in [false, true] {
        let mut rig = Rig::new();
        if inherited_down {
            rig.kernel
                .mutate(|model| model.links.get_mut("ex-ch1").unwrap().up = Known::Value(false));
        }
        let exit = scupper_core::config::ExitId("ch1".into());
        rig.kernel.handshake(exit.clone(), None);
        rig.restart();
        let base = rig.time.get();
        // Explicitly attempt resume: a cold boot has no fresh handshake to authorize it.
        rig.machine().resume_existing();
        assert_eq!(
            rig.machine().health()[&exit],
            scupper_core::failover::ExitHealth::Unknown
        );
        let mut events = Vec::new();
        for offset in (2..=32).step_by(2) {
            rig.kernel
                .handshake(exit.clone(), (offset >= 4).then_some(Duration::ZERO));
            if offset % 10 == 2 {
                rig.round(true);
            }
            events.extend(rig.tick().events);
            assert_eq!(rig.time.get(), base + offset);
            if offset < 32 {
                assert_eq!(
                    rig.machine().health()[&exit],
                    scupper_core::failover::ExitHealth::Unknown
                );
                assert_eq!(
                    &rig.machine().desired().unwrap().routes()[0].1,
                    &RouteTarget::Unreachable
                );
            }
        }
        assert!(matches!(
            rig.machine().health()[&exit],
            scupper_core::failover::ExitHealth::Healthy {
                confirmed: true,
                ..
            }
        ));
        assert!(!events.iter().any(|event| matches!(
            event,
            EventKind::FailClosedStarted { .. } | EventKind::FailClosedEnded { .. }
        )));
        rig.safe_history();
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep injected persistence failure, restart/reboot and explicit clearance in one lifecycle.
fn failed_latch_persist_restart_and_reboot_keep_closed_with_durable_budgets() {
    use scupper_sys::{
        reconcile::StateStore,
        state::{RepairState, StateRead},
    };
    use std::time::Instant;
    struct FailingLatch(StateFile);
    impl StateStore for FailingLatch {
        fn read(&self) -> io::Result<State> {
            StateStore::read(&self.0)
        }
        fn read_until(&self, deadline: Instant) -> io::Result<State> {
            StateStore::read_until(&self.0, deadline)
        }
        fn write(&self, guard: &scupper_sys::lock::WriterGuard, state: &State) -> io::Result<()> {
            self.0.write_with_hook(guard, state, &|step| {
                if state.quarantine.is_some() && step == scupper_sys::fs::DurableStep::ContentSynced
                {
                    Err(io::Error::other("injected main latch persistence failure"))
                } else {
                    Ok(())
                }
            })
        }
        fn repair_state(&self) -> Option<RepairState> {
            Some(self.0.repair_state())
        }
        fn write_repair_state(
            &self,
            guard: &scupper_sys::lock::WriterGuard,
            repair: &RepairState,
        ) -> io::Result<()> {
            self.0.write_repair_state(guard, repair)
        }
    }
    for reboot in [false, true] {
        let rig = Rig::new();
        let state_root = rig.root.join("durable");
        let run_root = rig.root.join("runtime");
        let guard = WriterLock::acquire(&run_root).unwrap();
        let file = StateFile::open(&state_root, Some(&guard)).unwrap();
        file.write(&guard, &rig.store.state()).unwrap();
        drop(guard);
        let config = || {
            let mut c = rig.config();
            c.run_root = run_root.clone();
            c
        };
        let mut machine = Reconciler::new(
            rig.kernel.clone(),
            FailingLatch(file),
            rig.log.handle.clone(),
            config(),
            rig.held.clone(),
            || (MonoTime(Duration::from_secs(100)), 1100),
        )
        .unwrap();
        for _ in 0..4 {
            rig.flush_rules();
            machine.tick();
        }
        assert!(machine.latch().is_some());
        assert!(run_root.join("latch-uncertain").is_file());
        drop(machine);
        let file = StateFile::open(&state_root, None).unwrap();
        let StateRead::Present(raw) = file.read().unwrap() else {
            panic!("missing state")
        };
        assert!(
            raw.quarantine.is_none(),
            "main state write must have failed"
        );
        assert_eq!(
            file.repair_state().attempts_unix["safety:ruleset"],
            vec![1100; 3]
        );
        if reboot {
            fs::remove_dir_all(&run_root).unwrap();
        }
        let StateRead::Present(startup) = file.startup_read(&run_root).unwrap() else {
            panic!("missing state")
        };
        assert!(startup.quarantine.is_some());
        let mut restarted = Reconciler::new(
            rig.kernel.clone(),
            file,
            rig.log.handle.clone(),
            config(),
            rig.held.clone(),
            || (MonoTime(Duration::ZERO), 1200),
        )
        .unwrap();
        assert!(restarted.latch().is_some());
        let report = restarted.tick();
        assert!(!raises(&report));
        assert!(rig.kernel.model().forwarding_off());
        let kind = report
            .events
            .iter()
            .find(|event| {
                matches!(
                    event,
                    EventKind::QuarantineChanged { active: true }
                        | EventKind::QuarantineState { active: true }
                )
            })
            .unwrap()
            .clone();
        let alert = scupper_proto::Event {
            seq: 1,
            at: UnixSeconds(1200),
            kind,
            actor: Actor::Daemon,
            gateway: scupper_proto::Identifier::try_from("gw1".to_owned()).unwrap(),
            config_version: Some(1),
        }
        .alert()
        .unwrap();
        assert_eq!(alert.severity, scupper_core::alerts::Severity::Critical);
        scupper_sys::daemon::admin::execute(
            &mut restarted,
            scupper_proto::Op::Connect { exit: None },
            0,
            None,
            |_| {
                Ok(scupper_core::verdict::v2::Report {
                    verdict: scupper_core::verdict::v2::Verdict::Protected {
                        exit: scupper_core::config::ExitId("ch1".into()),
                        exit_ip: "192.0.2.1".parse().unwrap(),
                    },
                    warnings: vec![],
                    at: 1200,
                    config_version: 1,
                })
            },
        )
        .unwrap();
        assert!(restarted.latch().is_none());
        let file = StateFile::open(&state_root, None).unwrap();
        assert!(
            file.repair_state()
                .attempts_unix
                .get("safety:ruleset")
                .map_or(0, Vec::len)
                <= 1,
            "explicit connect resets the exhausted budget before repairing"
        );
        assert!(file.repair_state().latch().is_none());
        assert!(!run_root.join("latch-uncertain").exists());
    }
}

#[test]
fn exhausted_durable_budget_without_latch_record_does_not_latch_after_reboot() {
    let rig = Rig::new();
    let run = rig.root.join("runtime");
    let state_root = rig.root.join("durable");
    let guard = WriterLock::acquire(&run).unwrap();
    let file = StateFile::open(&state_root, Some(&guard)).unwrap();
    file.write(&guard, &rig.store.state()).unwrap();
    file.write_repair_state(
        &guard,
        &scupper_sys::state::RepairState {
            attempts_unix: BTreeMap::from([("safety:ruleset".into(), vec![1100; 3])]),
            ..Default::default()
        },
    )
    .unwrap();
    drop(guard);
    fs::remove_dir_all(&run).unwrap();
    let scupper_sys::state::StateRead::Present(saved) = file.startup_read(&run).unwrap() else {
        panic!("missing state")
    };
    assert!(saved.quarantine.is_none());
    assert_eq!(
        file.repair_state().attempts_unix["safety:ruleset"],
        vec![1100; 3]
    );
}

#[test]
fn three_successful_repairs_survive_restart_and_reboot_without_latch() {
    for (reboot, gap) in [false, true]
        .into_iter()
        .flat_map(|reboot| [120, 600, 660].map(|gap| (reboot, gap)))
    {
        let rig = Rig::new();
        let state_root = rig.root.join("durable");
        let run_root = rig.root.join("runtime");
        let guard = WriterLock::acquire(&run_root).unwrap();
        let file = StateFile::open(&state_root, Some(&guard)).unwrap();
        file.write(&guard, &rig.store.state()).unwrap();
        drop(guard);
        let config = || {
            let mut c = rig.config();
            c.run_root = run_root.clone();
            c
        };
        let mut machine = Reconciler::new(
            rig.kernel.clone(),
            file,
            rig.log.handle.clone(),
            config(),
            rig.held.clone(),
            || (MonoTime(Duration::from_secs(100)), 1100),
        )
        .unwrap();
        for _ in 0..3 {
            rig.flush_rules();
            let tick = machine.tick();
            assert!(tick.failures.is_empty(), "{tick:?}");
            assert!(
                tick.steps
                    .iter()
                    .any(|step| matches!(step, Step::LoadRuleset { .. }))
            );
            assert!(machine.latch().is_none());
        }
        drop(machine);
        if reboot {
            fs::remove_dir_all(&run_root).unwrap();
        }
        let file = StateFile::open(&state_root, None).unwrap();
        assert!(!file.repair_state().armed);
        assert_eq!(
            file.repair_state().attempts_unix["safety:ruleset"],
            vec![1100; 3]
        );
        let scupper_sys::state::StateRead::Present(saved) = file.startup_read(&run_root).unwrap()
        else {
            unreachable!()
        };
        assert!(saved.quarantine.is_none());
        let mut restarted = Reconciler::new(
            rig.kernel.clone(),
            file,
            rig.log.handle.clone(),
            config(),
            rig.held.clone(),
            || (MonoTime(Duration::ZERO), 1100 + gap),
        )
        .unwrap();
        assert!(restarted.latch().is_none());
        restarted.tick();
        assert!(restarted.latch().is_none());
        rig.flush_rules();
        let tick = restarted.tick();
        assert_eq!(
            restarted.latch().is_some(),
            gap < 600,
            "gap={gap}, reboot={reboot}: {tick:?}"
        );
        if gap < 600 {
            assert!(!raises(&tick));
        } else {
            assert!(tick.failures.is_empty(), "{tick:?}");
            assert!(
                tick.steps
                    .iter()
                    .any(|step| matches!(step, Step::LoadRuleset { .. })),
                "{tick:?}"
            );
            assert_eq!(
                rig.kernel.model().forwarding_v4,
                Known::Value(1),
                "{tick:?}"
            );
        }
    }
}

#[test]
fn failed_restore_disarms_its_own_checkpoint_and_does_not_latch_on_restart() {
    let rig = Rig::new();
    let state_root = rig.root.join("durable");
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let file = StateFile::open(&state_root, Some(&guard)).unwrap();
    file.write(&guard, &rig.store.state()).unwrap();
    drop(guard);
    let mut machine = Reconciler::new(
        rig.kernel.clone(),
        file,
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1100),
    )
    .unwrap();
    rig.kernel.inject(Fault {
        step: StepKind::LoadRuleset,
        remaining: Some(1),
        partial: false,
    });
    rig.flush_rules();
    assert!(!machine.tick().complete);
    let file = StateFile::open(&state_root, None).unwrap();
    assert!(!file.repair_state().armed);
    assert!(file.repair_state().latch().is_none());
    assert!(!rig.root.join("latch-uncertain").exists());
    machine.tick();
    drop(machine);
    let restarted = Reconciler::new(
        rig.kernel.clone(),
        file,
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::ZERO), 1200),
    )
    .unwrap();
    assert!(restarted.latch().is_none());
}

#[test]
fn real_collector_separates_host_and_gateway_inventory_failures() {
    let rig = Rig::new();
    for host in [true, false] {
        let sys = CollectorSystem::default();
        sys.fail_host_links.set(host);
        sys.fail_netns_links.set(!host);
        let observation = observe_real(&rig, &sys);
        assert_eq!(observation.model.host_links_complete, !host);
        assert_eq!(observation.model.links_complete, host);
        let plan = scupper_core::planner::plan(
            &rig.machine.as_ref().unwrap().desired().unwrap(),
            &observation.model,
            &scupper_core::planner::Budgets::default(),
            None,
            &scupper_core::planner::Debounce::default(),
            MonoTime(Duration::ZERO),
        );
        assert_eq!(
            plan.steps.contains(&Step::LinkDown { name: "wg0".into() }),
            !host,
            "{plan:?}"
        );
    }
}

#[test]
fn failed_non_safety_checkpoint_does_not_block_forwarding_or_write_uncertainty() {
    use scupper_sys::{reconcile::StateStore, state::RepairState};
    use std::time::Instant;
    struct FailedCheckpoint(StateFile);
    impl StateStore for FailedCheckpoint {
        fn read(&self) -> io::Result<State> {
            StateStore::read(&self.0)
        }
        fn read_until(&self, deadline: Instant) -> io::Result<State> {
            StateStore::read_until(&self.0, deadline)
        }
        fn write(&self, guard: &scupper_sys::lock::WriterGuard, state: &State) -> io::Result<()> {
            self.0.write(guard, state)
        }
        fn repair_state(&self) -> Option<RepairState> {
            Some(self.0.repair_state())
        }
        fn write_repair_state(
            &self,
            _: &scupper_sys::lock::WriterGuard,
            _: &RepairState,
        ) -> io::Result<()> {
            Err(io::Error::other("full checkpoint disk"))
        }
    }
    let rig = Rig::new();
    let state_root = rig.root.join("durable");
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let file = StateFile::open(&state_root, Some(&guard)).unwrap();
    file.write(&guard, &rig.store.state()).unwrap();
    drop(guard);
    let mut machine = Reconciler::new(
        rig.kernel.clone(),
        FailedCheckpoint(file),
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1100),
    )
    .unwrap();
    machine.resume_existing();
    rig.kernel
        .mutate(|model| model.forwarding_v4 = Known::Value(0));
    let first = machine.tick();
    let second = machine.tick();
    assert!(raises(&first) || raises(&second), "{first:?} {second:?}");
    assert!(first.failures.is_empty() && second.failures.is_empty());
    assert!(machine.latch().is_none());
    assert!(!rig.root.join("latch-uncertain").exists());
}

#[test]
fn connect_clearance_uses_typed_uncertainty_instead_of_reason_words() {
    for uncertain in [false, true] {
        let mut rig = Rig::new();
        let mut state = rig.store.state();
        state.quarantine = Some(scupper_sys::state::Quarantine {
            reason: "persistence appears in an ordinary fighter reason".into(),
            object: "repair-history".into(),
            since_unix: 1000,
            uncertain,
        });
        let guard = WriterLock::acquire(&rig.root).unwrap();
        scupper_sys::reconcile::StateStore::write(&rig.store, &guard, &state).unwrap();
        drop(guard);
        rig.restart();
        let result = scupper_sys::daemon::admin::execute(
            rig.machine(),
            scupper_proto::Op::Connect { exit: None },
            0,
            None,
            |_| {
                Ok(scupper_core::verdict::v2::Report {
                    verdict: scupper_core::verdict::v2::Verdict::Protected {
                        exit: scupper_core::config::ExitId("ch1".into()),
                        exit_ip: "192.0.2.1".parse().unwrap(),
                    },
                    warnings: vec![],
                    at: 1100,
                    config_version: 1,
                })
            },
        );
        if uncertain {
            assert!(result.is_ok(), "{result:?}");
            assert!(rig.machine().latch().is_none());
        } else {
            assert_eq!(
                result.unwrap_err().code,
                scupper_proto::ApiErrorCode::Quarantined
            );
            assert!(rig.machine().latch().is_some());
        }
    }
}

#[test]
fn restored_attempts_keep_their_original_expiry_and_future_times_clamp_to_now() {
    // Each attempt ages independently; count-only history is expired. Future
    // timestamps count now, but do not extend the window beyond ten minutes.
    for (history, elapsed, latched) in [
        (
            r#"{"attempts":{"safety:ruleset":3},"armed":false,"quarantine":null}"#,
            0,
            false,
        ),
        (
            r#"{"attempts_unix":{"safety:ruleset":[1100,1100,1100]},"armed":false,"quarantine":null}"#,
            479,
            true,
        ),
        (
            r#"{"attempts_unix":{"safety:ruleset":[1100,1100,1100]},"armed":false,"quarantine":null}"#,
            480,
            false,
        ),
        (
            r#"{"attempts_unix":{"safety:ruleset":[1000,1100,1200]},"armed":false,"quarantine":null}"#,
            380,
            false,
        ),
        (
            r#"{"attempts_unix":{"safety:ruleset":[9999,9999,9999]},"armed":false,"quarantine":null}"#,
            599,
            true,
        ),
        (
            r#"{"attempts_unix":{"safety:ruleset":[9999,9999,9999]},"armed":false,"quarantine":null}"#,
            600,
            false,
        ),
    ] {
        let rig = Rig::new();
        let state_root = rig.root.join("durable");
        let guard = WriterLock::acquire(&rig.root).unwrap();
        let file = StateFile::open(&state_root, Some(&guard)).unwrap();
        file.write(&guard, &rig.store.state()).unwrap();
        fs::write(state_root.join("repair-state.json"), history).unwrap();
        drop(guard);
        let time = Cell::new(0);
        let mut machine = Reconciler::new(
            rig.kernel.clone(),
            file,
            rig.log.handle.clone(),
            rig.config(),
            rig.held.clone(),
            || (MonoTime(Duration::from_secs(time.get())), 1220 + time.get()),
        )
        .unwrap();
        time.set(elapsed);
        rig.flush_rules();
        let tick = machine.tick();
        assert_eq!(
            machine.latch().is_some(),
            latched,
            "elapsed={elapsed}, history={history}: {tick:?}"
        );
        if !latched {
            assert!(
                tick.steps
                    .iter()
                    .any(|step| matches!(step, Step::LoadRuleset { .. })),
                "{tick:?}"
            );
            assert!(tick.failures.is_empty(), "{tick:?}");
        }
    }
}

#[test]
fn repair_checkpoints_preserve_each_attempts_wall_timestamp_across_clock_steps() {
    let rig = Rig::new();
    let state_root = rig.root.join("durable");
    let guard = WriterLock::acquire(&rig.root).unwrap();
    let file = StateFile::open(&state_root, Some(&guard)).unwrap();
    file.write(&guard, &rig.store.state()).unwrap();
    drop(guard);
    let time = Cell::new((100, 1100));
    let mut machine = Reconciler::new(
        rig.kernel.clone(),
        file,
        rig.log.handle.clone(),
        rig.config(),
        rig.held.clone(),
        || {
            let (mono, unix) = time.get();
            (MonoTime(Duration::from_secs(mono)), unix)
        },
    )
    .unwrap();
    let mut expected = Vec::new();
    for (mono, unix) in [(100, 1100), (200, 1105), (300, 2000)] {
        time.set((mono, unix));
        rig.flush_rules();
        let tick = machine.tick();
        assert!(tick.failures.is_empty(), "{tick:?}");
        assert!(machine.latch().is_none());
        expected.push(unix);
        assert_eq!(
            StateFile::open(&state_root, None)
                .unwrap()
                .repair_state()
                .attempts_unix["safety:ruleset"],
            expected
        );
    }
}

#[test]
fn per_link_failure_redumps_once_and_positive_absence_avoids_d2() {
    for race in [1, 2, 3, 4, 5] {
        let rig = Rig::new();
        let sys = CollectorSystem::default();
        sys.per_link_race.set(race);
        let observed = observe_real(&rig, &sys);
        // One initial safety dump, exactly one safety re-dump, then phase B.
        assert_eq!(sys.link_dumps.get(), 3);
        let vanished = matches!(race, 1 | 5);
        assert_eq!(observed.safety_complete, vanished, "race {race}");
        assert_eq!(observed.model.links.contains_key("foreign0"), !vanished);
        if vanished {
            assert!(observed.model.links_complete);
            assert!(
                observed
                    .model
                    .links
                    .values()
                    .all(|l| l.tc_hooks != Known::Unknown)
            );
        } else {
            assert_eq!(observed.model.links["foreign0"].tc_hooks, Known::Unknown);
        }
        let d = desired();
        let p = scupper_core::planner::plan(
            &d,
            &observed.model,
            &scupper_core::planner::Budgets::default(),
            None,
            &scupper_core::planner::Debounce::default(),
            MonoTime(Duration::ZERO),
        );
        assert_eq!(
            p.steps.contains(&Step::LinkDown { name: "wg0".into() }),
            !vanished
        );
        assert_eq!(p.debounce.ingress_quarantined, !vanished);
        assert_eq!(
            p.steps.contains(&Step::Emit(
                scupper_core::planner::PlannerEvent::ObservationUnknown
            )),
            !vanished
        );
    }
}

#[test]
fn d2_recovery_raises_client_in_the_same_tick_and_events_identify_links() {
    let mut rig = Rig::new();
    rig.kernel.mutate(|m| {
        foreign(m);
        m.links.get_mut("foreign0").unwrap().tc_hooks = Known::Unknown;
    });
    let closed = rig.tick();
    assert!(
        closed
            .steps
            .contains(&Step::LinkDown { name: "wg0".into() })
    );
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(false));
    assert_ne!(
        rig.machine().verdict(),
        Some(scupper_proto::VerdictCode::Protected)
    );
    rig.kernel.mutate(|m| {
        m.links.remove("foreign0");
    });
    let recovered = rig.tick();
    assert!(
        recovered
            .steps
            .iter()
            .any(|s| matches!(s, Step::LinkUp { name, .. } if name == "wg0"))
    );
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(true));
    assert_eq!(
        rig.machine().verdict(),
        Some(scupper_proto::VerdictCode::Protected)
    );
    for report in [&closed, &recovered] {
        for step in &report.steps {
            if let Some(name) = step.link_name() {
                assert!(report.events.iter().any(|e| matches!(e, EventKind::Repair { kind, object: Some(object), .. } if *kind == StepKind::from(step) && object == name)));
            }
        }
    }
}

#[test]
fn complete_tick_cannot_report_protected_while_client_link_is_down_or_missing() {
    for missing in [false, true] {
        let mut rig = Rig::new();
        rig.kernel.mutate(|m| {
            if missing {
                m.links.remove("wg0");
            } else {
                m.links.get_mut("wg0").unwrap().up = Known::Value(false);
            }
        });
        let report = rig.tick(); // Availability repair is still debouncing.
        assert!(report.complete);
        assert_ne!(
            rig.machine().verdict(),
            Some(scupper_proto::VerdictCode::Protected)
        );
        assert_eq!(
            rig.machine().verdict(),
            Some(scupper_proto::VerdictCode::Degraded)
        );
    }
}

#[test]
fn failed_d2_link_up_keeps_forwarding_closed_and_names_the_failed_link() {
    let mut rig = Rig::new();
    rig.kernel.mutate(|m| {
        foreign(m);
        m.links.get_mut("foreign0").unwrap().tc_hooks = Known::Unknown;
    });
    rig.tick();
    rig.kernel.mutate(|m| {
        m.links.remove("foreign0");
    });
    rig.kernel.inject(Fault {
        step: StepKind::LinkUp,
        remaining: None,
        partial: false,
    });
    let report = rig.tick();
    assert!(
        report
            .failures
            .iter()
            .any(|(s, _)| matches!(s, Step::LinkUp { .. }))
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| matches!(s, Step::ForwardingOn { .. }))
    );
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(false));
    assert!(rig.kernel.model().forwarding_off());
    assert_ne!(
        rig.machine().verdict(),
        Some(scupper_proto::VerdictCode::Protected)
    );
    assert!(report.events.iter().any(|e| matches!(e, EventKind::Repair {
        kind: StepKind::LinkUp, object: Some(name), result: scupper_proto::Outcome::Failed, ..
    } if name == "wg0")));
}

#[test]
fn manual_client_repair_dispatches_recovery_and_unknown_inventory_cannot_use_old_cache() {
    let mut rig = Rig::new();
    rig.kernel
        .mutate(|m| m.links.get_mut("wg0").unwrap().up = Known::Value(false));
    let before = rig.kernel.session_recoveries();
    let steps = rig
        .machine()
        .apply_plan(false, Actor::Local { uid: 0 })
        .unwrap();
    assert!(steps.contains(&StepKind::LinkUp));
    assert_eq!(
        rig.kernel.session_recoveries(),
        before,
        "LinkUp requires a fresh next tick"
    );
    rig.tick();
    assert!(rig.kernel.session_recoveries() > before);
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(true));
    // The last cached state was healthy. Manual repair must replace it with
    // its fresh Unknown observation before deciding whether to send output.
    rig.kernel
        .timeouts(BTreeSet::from([ObservationItem::Tc("wg0".into())]));
    let before = rig.kernel.session_recoveries();
    rig.machine()
        .apply_plan(false, Actor::Local { uid: 0 })
        .unwrap();
    assert_eq!(rig.kernel.session_recoveries(), before);
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(false));
}

#[test]
fn link_down_timeout_after_effect_has_a_prior_session_checkpoint() {
    let mut rig = Rig::new();
    rig.kernel.mutate(|m| {
        foreign(m);
        m.links.get_mut("foreign0").unwrap().tc_hooks = Known::Unknown;
    });
    rig.kernel.inject(Fault {
        step: StepKind::LinkDown,
        remaining: None,
        partial: true,
    });
    let recoveries = rig.kernel.session_recoveries();
    let report = rig.tick();
    assert!(
        report
            .failures
            .iter()
            .any(|(s, _)| matches!(s, Step::LinkDown { name } if name == "wg0"))
    );
    assert_eq!(rig.kernel.model().links["wg0"].up, Known::Value(false));
    let history = rig.kernel.history();
    let checkpoint = rig.kernel.session_checkpoints();
    let down = history
        .iter()
        .position(|(s, _)| matches!(s, Step::LinkDown { name } if name == "wg0"))
        .unwrap();
    assert!(
        checkpoint.contains(&down),
        "checkpoint must precede the failed command"
    );
    assert_eq!(
        rig.kernel.session_recoveries(),
        recoveries,
        "failed plan cannot run recovery hook"
    );
}
