//! Third-round regressions for canonicalization, handoff and route continuity.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::{ExitId, GatewayId},
    failover::{ExitHealth, MonoTime, ProbeOutcome},
    planner::{Desired, Known, Step},
    render::{RouteTarget, VersionStamp},
    verdict::v2::Selection,
};
use scupper_proto::UnixSeconds;
use scupper_sys::{
    canon::{self, CanonCache},
    events::EventLog,
    lock::WriterGuard,
    netns::NetnsHandle,
    reconcile::{
        Config, Kernel, Observation, Reconciler, StepError,
        fake::{FakeKernel, MemoryStore},
    },
    state::State,
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
const RULES: &str = r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#;
fn root(name: &str) -> PathBuf {
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(
            || std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
            std::path::PathBuf::from,
        )
        .join("daemon-fix3-counterexamples")
        .join(format!("{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}
struct UpgradeSystem {
    cache: RefCell<CanonCache>,
    root: PathBuf,
    nft: PathBuf,
    live: String,
    delay: Duration,
}
impl System for UpgradeSystem {
    fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
        Some((&self.cache, &self.nft))
    }
    fn canon_run_root(&self) -> &Path {
        &self.root
    }
    fn canon_worker(&self) -> Option<Box<dyn System + Send>> {
        Some(Box::new(Self {
            cache: RefCell::default(),
            root: self.root.clone(),
            nft: self.nft.clone(),
            live: self.live.clone(),
            delay: self.delay,
        }))
    }
    fn run(&self, program: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        if program == Program::Unshare {
            std::thread::sleep(self.delay);
        }
        Ok(ExecOutput {
            status: Some(0),
            stdout: if program == Program::Unshare {
                RULES.into()
            } else {
                "nft v1".into()
            },
            stderr: String::new(),
        })
    }
    fn run_in(
        &self,
        _: ExecTarget<'_>,
        _: Program,
        _: &[String],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        Ok(ExecOutput {
            status: Some(0),
            stdout: self.live.clone(),
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        100
    }
}
fn upgrade_system(root: &Path) -> UpgradeSystem {
    let nft = root.join("nft");
    fs::write(&nft, b"nft 1.0.9").unwrap();
    UpgradeSystem {
        cache: RefCell::default(),
        root: root.to_path_buf(),
        nft,
        live: RULES.into(),
        delay: Duration::from_millis(200),
    }
}
fn upgrade_nft(system: &UpgradeSystem) {
    let staged = system.root.join("nft.dpkg-new");
    fs::write(&staged, b"nft 1.0.9-1ubuntu0.1").unwrap();
    fs::rename(&staged, &system.nft).unwrap();
}
#[test]
fn ce3_1_nft_upgrade_with_unchanged_live_ruleset_stays_verified() {
    let root = root("nft-upgrade");
    let system = upgrade_system(&root);
    let held = scupper_sys::netns::testing::handle().unwrap();
    canon::prepare_netns_ruleset(
        &system,
        &held,
        "rendered",
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let (want, live) = canon::netns_rulesets_safety(&system, &held, "rendered").unwrap();
    assert_eq!(want, live, "control: warm cache verifies");
    upgrade_nft(&system);
    canon::refresh_tool_facts(&system, Instant::now() + Duration::from_secs(61)).unwrap();
    let result = canon::netns_rulesets_safety(&system, &held, "rendered");
    std::thread::sleep(Duration::from_millis(300));
    let _ = fs::remove_dir_all(&root);
    assert!(
        result.as_ref().is_ok_and(|(want, live)| want == live),
        "tool upgrade changed verification: {result:?}"
    );
}
struct CacheKernel<'a> {
    fake: FakeKernel,
    system: &'a UpgradeSystem,
}
impl Kernel for CacheKernel<'_> {
    fn observe(&self, held: &NetnsHandle) -> Observation {
        let mut observed = self.fake.observe(held);
        if !canon::netns_rulesets_safety(self.system, held, "rendered")
            .is_ok_and(|(want, live)| want == live)
        {
            observed.model.ruleset = Known::Unknown;
            observed.safety_complete = false;
        }
        observed
    }
    fn observe_rest(
        &self,
        held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation {
        self.fake.observe_rest(held, safety, deadline)
    }
    fn execute(&self, step: &Step) -> Result<(), StepError> {
        self.fake.execute(step)
    }
    fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError> {
        self.fake.restore_name(held, guard)
    }
}
fn now() -> (MonoTime, u64) {
    (MonoTime(Duration::from_secs(100)), 100)
}
fn healthy(root: &Path) -> (FakeKernel, Config) {
    let site = support::site("ubuntu-24.04");
    let gateway = GatewayId("gw1".into());
    let stamp = VersionStamp {
        version: 1,
        sha256: [1; 32],
    };
    let target = RouteTarget::Exit(site.gateway(&gateway).unwrap().exits()[0].ifname().clone());
    let desired =
        Desired::new(&site, &gateway, &stamp, [7; 32], &target, &Selection::Auto).unwrap();
    (
        FakeKernel::new(desired),
        Config {
            site,
            gateway,
            stamp,
            fingerprint: [7; 32],
            run_root: root.to_path_buf(),
            lock_wait: Duration::from_millis(100),
        },
    )
}
#[test]
fn ce3_2_nft_upgrade_does_not_close_a_healthy_gateway() {
    let root = root("nft-upgrade-reconciler");
    let system = upgrade_system(&root);
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let held = Arc::new(scupper_sys::netns::testing::handle().unwrap());
    canon::prepare_netns_ruleset(
        &system,
        &held,
        "rendered",
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let mut machine = Reconciler::new(
        CacheKernel {
            fake: kernel.clone(),
            system: &system,
        },
        MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        }),
        log.handle.clone(),
        config,
        held,
        now,
    )
    .unwrap();
    machine.resume_existing();
    assert!(machine.tick().complete);
    assert_eq!(kernel.history(), []);
    upgrade_nft(&system);
    canon::refresh_tool_facts(&system, Instant::now() + Duration::from_secs(61)).unwrap();
    machine.tick();
    std::thread::sleep(Duration::from_millis(300));
    machine.tick();
    let history: Vec<Step> = kernel.history().into_iter().map(|(s, _)| s).collect();
    let _ = fs::remove_dir_all(&root);
    assert!(
        !history
            .iter()
            .any(|s| matches!(s, Step::ForwardingOff | Step::FlushConntrack)),
        "upgrade closed gateway: {history:?}"
    );
}
#[test]
fn ce3_3_resumed_exit_without_any_probe_success_does_not_stay_healthy() {
    let root = root("resume-unverified");
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let mut machine = Reconciler::new(
        kernel.clone(),
        MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        }),
        log.handle.clone(),
        config,
        Arc::new(scupper_sys::netns::testing::handle().unwrap()),
        now,
    )
    .unwrap();
    machine.resume_existing();
    let exit = ExitId("ch1".into());
    assert!(matches!(
        machine.health().get(&exit),
        Some(ExitHealth::Healthy {
            confirmed: false,
            ..
        })
    ));
    for _ in 0..10 {
        machine.submit_probe_outcomes(BTreeMap::from([(exit.clone(), ProbeOutcome::Failure)]));
        machine.tick();
    }
    let health = machine.health().get(&exit).cloned();
    let routed = machine
        .desired()
        .unwrap()
        .routes()
        .iter()
        .any(|(_, r)| *r != RouteTarget::Unreachable);
    let _ = fs::remove_dir_all(&root);
    assert!(
        !matches!(health, Some(ExitHealth::Healthy { .. })) || !routed,
        "unconfirmed failed path stayed healthy: {health:?}"
    );
}
#[test]
fn ce3_4_prepare_waits_out_a_foreign_pending_worker_until_its_deadline() {
    let root = root("prepare-foreign");
    let mut system = upgrade_system(&root);
    // A safety miss now waits up to one second. Keep this worker pending beyond it.
    system.delay = Duration::from_millis(1200);
    let held = scupper_sys::netns::testing::handle().unwrap();
    assert!(canon::netns_rulesets_safety(&system, &held, "old render").is_err());
    let started = Instant::now();
    let result = canon::prepare_netns_ruleset(
        &system,
        &held,
        "new render",
        Instant::now() + Duration::from_secs(3),
    );
    let waited = started.elapsed();
    std::thread::sleep(Duration::from_millis(300));
    let _ = fs::remove_dir_all(&root);
    assert!(
        result.is_ok(),
        "prepare gave up after {waited:?} with {result:?}"
    );
}

#[test]
fn l52_extra_main_route_through_exit_only_deletes_that_route() {
    use scupper_core::{planner::RouteKey, render::Family};
    let root = root("l52");
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let held = Arc::new(scupper_sys::netns::testing::handle().unwrap());
    let mut machine = Reconciler::new(
        kernel.clone(),
        MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        }),
        log.handle.clone(),
        config,
        held,
        now,
    )
    .unwrap();
    machine.resume_existing();
    machine.tick();
    let baseline = kernel.model();
    kernel.clear_history();
    let route = RouteKey {
        family: Family::V4,
        entry: scupper_core::parse::parse_ip_route(r#"[{"dst":"198.18.0.0/24","dev":"ex-ch1","table":"main","protocol":"boot","scope":"link"}]"#).unwrap().remove(0),
    };
    kernel.mutate(|model| model.extra_routes = Known::Value(vec![route.clone()]));
    for _ in 0..5 {
        assert!(machine.tick().complete);
    }
    let history: Vec<_> = kernel.history().into_iter().map(|(step, _)| step).collect();
    assert_eq!(history, [Step::RouteDelete { route }]);
    assert_eq!(
        kernel.model(),
        baseline,
        "route removal changed healthy kernel state"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resumed_health_is_unconfirmed_until_success_then_uses_common_mode_rules() {
    let root = root("confirmed");
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let mut machine = Reconciler::new(
        kernel.clone(),
        MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        }),
        log.handle.clone(),
        config,
        Arc::new(scupper_sys::netns::testing::handle().unwrap()),
        now,
    )
    .unwrap();
    machine.resume_existing();
    assert!(machine.tick().complete);
    assert_eq!(
        machine.verdict(),
        Some(scupper_proto::VerdictCode::Degraded)
    );
    let exit = ExitId("ch1".into());
    machine.submit_probe_outcomes(BTreeMap::from([(exit.clone(), ProbeOutcome::Inconclusive)]));
    machine.tick();
    assert!(matches!(
        machine.health().get(&exit),
        Some(ExitHealth::Healthy {
            confirmed: false,
            ..
        })
    ));
    machine.submit_probe_outcomes(BTreeMap::from([(exit.clone(), ProbeOutcome::Failure)]));
    machine.tick();
    assert!(machine.unconfirmed());
    assert_eq!(
        machine.verdict(),
        Some(scupper_proto::VerdictCode::Degraded)
    );
    machine.submit_probe_outcomes(BTreeMap::from([(exit.clone(), ProbeOutcome::Success)]));
    machine.tick();
    assert!(matches!(
        machine.health().get(&exit),
        Some(ExitHealth::Healthy {
            confirmed: true,
            ..
        })
    ));
    assert_eq!(
        machine.verdict(),
        Some(scupper_proto::VerdictCode::Protected)
    );
    for _ in 0..10 {
        machine.submit_probe_outcomes(BTreeMap::from([(exit.clone(), ProbeOutcome::Failure)]));
        machine.tick();
    }
    assert!(matches!(
        machine.health().get(&exit),
        Some(ExitHealth::Healthy {
            confirmed: true,
            ..
        })
    ));
    assert!(
        kernel.history().is_empty(),
        "common-mode semantics changed after confirmation"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_route_switch_flushes_once_before_handoff_and_normal_restart_does_not() {
    use scupper_core::verdict::v2::DefaultRouteObs;
    let root = root("route-crash");
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let held = Arc::new(scupper_sys::netns::testing::handle().unwrap());
    let store = MemoryStore::new(State {
        applied_version: Some(1),
        ..State::default()
    });
    let make = |config| {
        Reconciler::new(
            kernel.clone(),
            store.clone(),
            log.handle.clone(),
            config,
            held.clone(),
            now,
        )
        .unwrap()
    };
    let mut machine = make(config);
    machine.recover_route_switch().unwrap();
    machine.resume_existing();
    machine.tick();
    assert!(kernel.history().is_empty(), "normal start flushed");
    kernel.mutate(|model| {
        model.default_v4 = Known::Value(DefaultRouteObs::Unreachable);
        model.default_v6 = Known::Value(DefaultRouteObs::Unreachable);
    });
    machine.tick(); // Restore debounce.
    kernel.clear_history();
    let promoted_defaults = machine
        .desired()
        .unwrap()
        .routes()
        .iter()
        .filter(|(_, target)| *target != RouteTarget::Unreachable)
        .count();
    kernel.crash_after(promoted_defaults); // All exit defaults replaced, before flush.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| machine.tick())).is_err());
    assert!(
        kernel
            .history()
            .iter()
            .all(|(step, _)| matches!(step, Step::RouteReplace { .. })),
        "steps: {:?}",
        kernel
            .history()
            .iter()
            .map(|(step, _)| scupper_proto::StepKind::from(step))
            .collect::<Vec<_>>()
    );
    let marker = fs::read_to_string(root.join("route-switch")).unwrap();
    assert!(marker.contains("target=Exit") && marker.contains("time=100"));
    drop(machine);
    kernel.clear_history();
    let (_, config) = healthy(&root);
    let mut restarted = make(config);
    assert!(
        restarted.latch().is_none(),
        "an interrupted routine restore must recover without explicit clearance"
    );
    restarted.recover_route_switch().unwrap();
    assert!(!root.join("route-switch").exists());
    restarted.resume_existing();
    restarted.tick();
    assert_eq!(
        kernel
            .history()
            .iter()
            .map(|(step, _)| step.clone())
            .collect::<Vec<_>>(),
        [Step::FlushConntrack]
    );
    restarted.recover_route_switch().unwrap();
    assert_eq!(kernel.history().len(), 1, "recovery flushed more than once");
    drop(restarted);
    kernel.clear_history();
    let (_, config) = healthy(&root);
    let mut normal_restart = make(config);
    normal_restart.recover_route_switch().unwrap();
    normal_restart.resume_existing();
    normal_restart.tick();
    assert!(kernel.history().is_empty(), "normal restart flushed");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn handoff_refuses_a_busy_writer_lock_without_kernel_operations() {
    let root = root("handoff-lock");
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let mut machine = Reconciler::new(
        kernel.clone(),
        MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        }),
        log.handle.clone(),
        config,
        Arc::new(scupper_sys::netns::testing::handle().unwrap()),
        now,
    )
    .unwrap();
    let _guard = scupper_sys::lock::WriterLock::acquire(&root).unwrap();
    machine.resume_existing();
    assert!(
        machine
            .health()
            .values()
            .all(|health| *health == ExitHealth::Unknown)
    );
    assert_eq!(kernel.history(), []);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_only_pending_canon_keeps_verified_bytes_but_rejects_live_and_render_changes() {
    let root = root("pending-upgrade");
    let mut system = upgrade_system(&root);
    let held = scupper_sys::netns::testing::handle().unwrap();
    canon::prepare_netns_ruleset(
        &system,
        &held,
        "rendered",
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    canon::netns_rulesets_safety(&system, &held, "rendered").unwrap();
    upgrade_nft(&system);
    canon::refresh_tool_facts(&system, Instant::now() + Duration::from_secs(61)).unwrap();
    system.delay = Duration::from_millis(1500);
    let started = Instant::now();
    let (want, live) = canon::netns_rulesets_safety(&system, &held, "rendered").unwrap();
    assert_eq!(want, live);
    assert!(started.elapsed() < Duration::from_millis(1200));
    system.live = r#"{"nftables":[]}"#.into();
    assert!(canon::netns_rulesets_safety(&system, &held, "rendered").is_err());
    system.live = RULES.into();
    assert!(canon::netns_rulesets_safety(&system, &held, "different render").is_err());
    std::thread::sleep(Duration::from_secs(2));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_recovery_flush_retains_marker_until_a_successful_retry() {
    use scupper_sys::reconcile::fake::Fault;
    let root = root("flush-failure");
    let (kernel, config) = healthy(&root);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    let machine = Reconciler::new(
        kernel.clone(),
        MemoryStore::new(State {
            applied_version: Some(1),
            ..State::default()
        }),
        log.handle.clone(),
        config,
        Arc::new(scupper_sys::netns::testing::handle().unwrap()),
        now,
    )
    .unwrap();
    fs::write(root.join("route-switch"), b"target=exit\ntime=100\n").unwrap();
    kernel.inject(Fault {
        step: scupper_proto::StepKind::FlushConntrack,
        remaining: Some(1),
        partial: false,
    });
    assert!(machine.recover_route_switch().is_err());
    assert!(root.join("route-switch").exists());
    machine.recover_route_switch().unwrap();
    assert!(!root.join("route-switch").exists());
    assert_eq!(kernel.history().len(), 2);
    machine.recover_route_switch().unwrap();
    assert_eq!(kernel.history().len(), 2);
    fs::remove_dir_all(root).unwrap();
}
