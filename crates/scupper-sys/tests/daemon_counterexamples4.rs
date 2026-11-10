//! Fourth-round counterexamples for daemon continuity and containment.
#![cfg(feature = "testing")]
// Preserve the review fixtures' signatures and generic reconciler type.
#![allow(
    clippy::unwrap_used,
    clippy::unnecessary_wraps,
    clippy::type_complexity
)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    failover::MonoTime,
    planner::{Desired, Known, RouteKey, Step},
    render::{Family, RouteTarget, VersionStamp},
    verdict::v2::Selection,
};
use scupper_proto::{StepKind, UnixSeconds};
use scupper_sys::{
    canon::{self, CanonCache},
    events::EventLog,
    reconcile::{
        Config, Reconciler,
        fake::{FakeKernel, Fault, MemoryStore},
    },
    state::State,
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
fn root(name: &str) -> PathBuf {
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(
            || std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
            std::path::PathBuf::from,
        )
        .join("daemon-fix4-counterexamples")
        .join(format!("{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
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
fn machine(
    kernel: &FakeKernel,
    config: Config,
) -> Reconciler<FakeKernel, MemoryStore, fn() -> (MonoTime, u64)> {
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
        now as fn() -> (MonoTime, u64),
    )
    .unwrap();
    machine.resume_existing();
    assert!(machine.tick().complete);
    machine
}
fn route(json: &str) -> RouteKey {
    RouteKey {
        family: Family::V4,
        entry: scupper_core::parse::parse_ip_route(json).unwrap().remove(0),
    }
}

/// Unsafe extra routes still close, delete and recover without intervention.
#[test]
fn ce4_1_unsafe_extra_route_closes_then_reopens_by_itself() {
    let root = root("unsafe-extra");
    let (kernel, config) = healthy(&root);
    let mut machine = machine(&kernel, config);
    let baseline = kernel.model();
    kernel.clear_history();
    let extra = route(
        r#"[{"dst":"198.18.0.0/24","dev":"wg0","table":"main","protocol":"boot","scope":"link"}]"#,
    );
    kernel.mutate(|m| m.extra_routes = Known::Value(vec![extra.clone()]));
    for _ in 0..8 {
        machine.tick();
    }
    let history: Vec<Step> = kernel.history().into_iter().map(|(s, _)| s).collect();
    let _ = fs::remove_dir_all(&root);
    assert!(history.contains(&Step::RouteDelete { route: extra }));
    assert!(
        history.contains(&Step::ForwardingOff),
        "control: an unsafe extra route still closes: {history:?}"
    );
    let end = kernel.model();
    assert_eq!(
        (&end.forwarding_v4, &end.extra_routes, &end.default_v4),
        (
            &baseline.forwarding_v4,
            &baseline.extra_routes,
            &baseline.default_v4
        ),
        "gateway did not reopen after an unsafe extra route was deleted: {history:?}"
    );
}

/// A persistently failing delete must not cause reopen/flush cycles.
#[test]
fn ce4_2_undeletable_exit_route_does_not_flap_forwarding_and_flush() {
    let root = root("undeletable");
    let (kernel, config) = healthy(&root);
    let mut machine = machine(&kernel, config);
    kernel.clear_history();
    let extra = route(
        r#"[{"dst":"198.18.0.0/24","dev":"ex-ch1","table":"main","protocol":"boot","scope":"link"}]"#,
    );
    kernel.mutate(|m| m.extra_routes = Known::Value(vec![extra.clone()]));
    kernel.inject(Fault {
        step: StepKind::from(&Step::RouteDelete { route: extra }),
        remaining: None,
        partial: false,
    });
    for _ in 0..12 {
        machine.tick();
    }
    let history: Vec<Step> = kernel.history().into_iter().map(|(s, _)| s).collect();
    let flushes = history
        .iter()
        .filter(|s| matches!(s, Step::FlushConntrack))
        .count();
    let opens = history
        .iter()
        .filter(|s| matches!(s, Step::ForwardingOn { .. }))
        .count();
    let _ = fs::remove_dir_all(&root);
    assert!(
        flushes <= 1 && opens <= 1,
        "forwarding flapped: {opens} reopenings, {flushes} conntrack flushes in 12 ticks"
    );
}

const RULES: &str = r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#;
struct SlowFailSystem {
    cache: RefCell<CanonCache>,
    root: PathBuf,
    nft: PathBuf,
    upgraded: Cell<bool>,
}
struct Worker {
    root: PathBuf,
    nft: PathBuf,
    upgraded: bool,
}
fn unshare(upgraded: bool) -> Result<ExecOutput, ExecError> {
    if upgraded {
        std::thread::sleep(Duration::from_millis(1300));
        return Ok(ExecOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "nft: incompatible".into(),
        });
    }
    Ok(ExecOutput {
        status: Some(0),
        stdout: RULES.into(),
        stderr: String::new(),
    })
}
fn version() -> Result<ExecOutput, ExecError> {
    Ok(ExecOutput {
        status: Some(0),
        stdout: "nft v1".into(),
        stderr: String::new(),
    })
}
impl System for Worker {
    fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
        None
    }
    fn canon_run_root(&self) -> &Path {
        &self.root
    }
    fn run(&self, program: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        if program == Program::Unshare {
            unshare(self.upgraded)
        } else {
            version()
        }
    }
    fn run_in(
        &self,
        _: ExecTarget<'_>,
        _: Program,
        _: &[String],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        unreachable!()
    }
    fn now_unix_secs(&self) -> u64 {
        100
    }
}
struct WorkerWithPath {
    inner: Worker,
    cache: RefCell<CanonCache>,
}
impl System for WorkerWithPath {
    fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
        Some((&self.cache, &self.inner.nft))
    }
    fn canon_run_root(&self) -> &Path {
        self.inner.canon_run_root()
    }
    fn run(&self, p: Program, a: &[String], t: Duration) -> Result<ExecOutput, ExecError> {
        self.inner.run(p, a, t)
    }
    fn run_in(
        &self,
        _: ExecTarget<'_>,
        _: Program,
        _: &[String],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        unreachable!()
    }
    fn now_unix_secs(&self) -> u64 {
        100
    }
}
impl System for SlowFailSystem {
    fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
        Some((&self.cache, &self.nft))
    }
    fn canon_run_root(&self) -> &Path {
        &self.root
    }
    fn canon_worker(&self) -> Option<Box<dyn System + Send>> {
        Some(Box::new(WorkerWithPath {
            inner: Worker {
                root: self.root.clone(),
                nft: self.nft.clone(),
                upgraded: self.upgraded.get(),
            },
            cache: RefCell::default(),
        }))
    }
    fn run(&self, program: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        if program == Program::Unshare {
            unshare(self.upgraded.get())
        } else {
            version()
        }
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
            stdout: RULES.into(),
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        100
    }
}

/// A new pending worker cannot resurrect verification after a slow failure.
#[test]
fn ce4_3_failed_new_tool_canonicalization_is_not_followed_by_verified() {
    let root = root("slow-fail");
    let nft = root.join("nft");
    fs::write(&nft, b"nft 1.0.9").unwrap();
    let system = SlowFailSystem {
        cache: RefCell::default(),
        root: root.clone(),
        nft: nft.clone(),
        upgraded: Cell::new(false),
    };
    let held = scupper_sys::netns::testing::handle().unwrap();
    canon::prepare_netns_ruleset(
        &system,
        &held,
        "rendered",
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let ok = |r: &Result<(serde_json::Value, serde_json::Value), _>| {
        r.as_ref().is_ok_and(|(w, l)| w == l)
    };
    assert!(ok(&canon::netns_rulesets_safety(
        &system, &held, "rendered"
    )));
    let staged = root.join("nft.dpkg-new");
    fs::write(&staged, b"nft 1.0.9-1ubuntu0.1").unwrap();
    fs::rename(&staged, &nft).unwrap();
    system.upgraded.set(true);
    canon::refresh_tool_facts(&system, Instant::now() + Duration::from_secs(61)).unwrap();
    let first = canon::netns_rulesets_safety(&system, &held, "rendered");
    assert!(ok(&first), "keep rule during pending: {first:?}");
    std::thread::sleep(Duration::from_millis(500));
    let failed = canon::netns_rulesets_safety(&system, &held, "rendered");
    assert!(failed.is_err(), "worker error must surface: {failed:?}");
    let after = canon::netns_rulesets_safety(&system, &held, "rendered");
    std::thread::sleep(Duration::from_millis(1500));
    let _ = fs::remove_dir_all(&root);
    assert!(
        after.is_err(),
        "verified resurrected after the new tool failed: {after:?}"
    );
}

#[test]
fn ce4_4_exit_prefix_is_not_contained_when_the_desired_default_is_unreachable() {
    use scupper_core::planner::{KernelModel, safe};
    let site = support::site("ubuntu-24.04");
    let gateway = GatewayId("gw1".into());
    let stamp = VersionStamp {
        version: 1,
        sha256: [1; 32],
    };
    let closed = Desired::new(
        &site,
        &gateway,
        &stamp,
        [7; 32],
        &RouteTarget::Unreachable,
        &Selection::Auto,
    )
    .unwrap();
    assert!(
        closed
            .routes()
            .iter()
            .all(|(_, t)| *t == RouteTarget::Unreachable),
        "control: failover fail-closed desired state"
    );
    let mut m = KernelModel::desired(&closed);
    assert!(safe(&m, &closed), "control: closed baseline is safe");
    m.extra_routes = Known::Value(vec![route(
        r#"[{"dst":"0.0.0.0/1","dev":"ex-ch1","table":"main","scope":"link"}]"#,
    )]);
    assert!(
        !safe(&m, &closed),
        "a route via an exit that is not the desired default target counts as contained"
    );
}

#[test]
fn ce4_5_recovery_from_fail_closed_leaves_no_marker_and_next_start_does_not_flush() {
    use scupper_core::failover::{ExitHealth, ProbeOutcome};
    use std::{collections::BTreeMap, rc::Rc};
    let root = root("recovered-marker");
    let (kernel, config) = healthy(&root);
    let clock = Rc::new(Cell::new(100_u64));
    let make = |config: Config| {
        let clock = clock.clone();
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
            move || {
                let s = clock.get();
                (MonoTime(Duration::from_secs(s)), s)
            },
        )
        .unwrap();
        machine.recover_route_switch().unwrap();
        machine.resume_existing();
        machine
    };
    let exit = scupper_core::config::ExitId("ch1".into());
    let mut machine = make(config);
    machine.tick();
    kernel.handshake(exit.clone(), Some(Duration::from_secs(3600)));
    for _ in 0..3 {
        clock.set(clock.get() + 5);
        machine.tick();
    }
    assert!(
        matches!(machine.health().get(&exit), Some(ExitHealth::Down { .. })),
        "control: exit went down: {:?}",
        machine.health()
    );
    kernel.handshake(exit.clone(), Some(Duration::from_secs(5)));
    for _ in 0..12 {
        clock.set(clock.get() + 5);
        machine.submit_probe_outcomes(BTreeMap::from([(exit.clone(), ProbeOutcome::Success)]));
        machine.tick();
    }
    let routed = kernel.model().default_v4
        == Known::Value(scupper_core::verdict::v2::DefaultRouteObs::Dev(
            "ex-ch1".into(),
        ));
    assert!(
        routed,
        "control: recovered to the exit: {:?}",
        machine.health()
    );
    let marker_left = root.join("route-switch").exists();
    drop(machine);
    kernel.clear_history();
    let (_, config) = healthy(&root);
    let _restarted = make(config);
    let flushed = kernel
        .history()
        .iter()
        .any(|(step, _)| matches!(step, Step::FlushConntrack));
    let _ = fs::remove_dir_all(&root);
    assert!(
        !marker_left && !flushed,
        "marker left after recovery: {marker_left}; ordinary restart flushed conntrack: {flushed}"
    );
}

#[test]
fn interrupted_switch_recovery_audits_both_failed_and_successful_flushes() {
    use scupper_proto::{EventKind, Outcome};
    use scupper_sys::events::read_since;
    let root = root("recovery-audit");
    let (kernel, config) = healthy(&root);
    let log = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
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
    fs::write(root.join("route-switch"), b"interrupted").unwrap();
    kernel.inject(Fault {
        step: StepKind::FlushConntrack,
        remaining: Some(1),
        partial: false,
    });
    assert!(machine.recover_route_switch().is_err());
    assert!(root.join("route-switch").exists());
    machine.recover_route_switch().unwrap();
    assert!(!root.join("route-switch").exists());
    log.handle.flush_blocking(Duration::from_secs(5)).unwrap();
    let results: Vec<_> = read_since(&root, 0, None)
        .map(Result::unwrap)
        .filter_map(|event| match event.kind {
            EventKind::Repair {
                kind: StepKind::FlushConntrack,
                result,
                ..
            } => Some(result),
            _ => None,
        })
        .collect();
    assert_eq!(results, [Outcome::Failed, Outcome::Succeeded]);
    drop(machine);
    drop(log);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn l52b_prefix_through_unselected_unready_exit_closes_deletes_and_recovers() {
    let root = root("l52b");
    let (kernel, config) = healthy(&root);
    let mut machine = machine(&kernel, config);
    let baseline = kernel.model();
    let extra =
        route(r#"[{"dst":"198.18.0.0/24","dev":"ex-unready","table":"main","scope":"link"}]"#);
    kernel.mutate(|model| {
        let mut unready = model.links["ex-ch1"].clone();
        unready.ours = Known::Value(false);
        unready.up = Known::Value(false);
        unready.peers = Known::Value(vec![]);
        model.links.insert("ex-unready".into(), unready);
        model.extra_routes = Known::Value(vec![extra.clone()]);
    });
    kernel.clear_history();
    for _ in 0..8 {
        assert!(machine.tick().complete);
    }
    let steps: Vec<_> = kernel.history().into_iter().map(|(step, _)| step).collect();
    assert!(steps.contains(&Step::ForwardingOff));
    assert!(steps.contains(&Step::FlushConntrack));
    assert!(steps.contains(&Step::RouteDelete { route: extra }));
    let end = kernel.model();
    assert_eq!(end.forwarding_v4, Known::Value(1));
    assert_eq!(end.extra_routes, Known::Value(vec![]));
    assert_eq!(end.default_v4, baseline.default_v4);
    fs::remove_dir_all(root).unwrap();
}

/// A switch flush skipped after containment must not wait for a restart.
#[test]
fn f5_marker_debt_flushes_on_next_complete_tick_and_is_removed_once() {
    let root = root("marker-debt");
    let (kernel, config) = healthy(&root);
    let mut machine = machine(&kernel, config);
    kernel.clear_history();
    fs::write(root.join("route-switch"), b"interrupted switch").unwrap();
    kernel.observation_latency(Duration::ZERO, Duration::from_secs(21));
    assert!(!machine.tick().complete);
    assert!(root.join("route-switch").exists());
    kernel.observation_latency(Duration::ZERO, Duration::ZERO);
    kernel.inject(Fault {
        step: StepKind::FlushConntrack,
        remaining: Some(1),
        partial: false,
    });
    let failed = machine.tick();
    assert!(
        failed
            .failures
            .iter()
            .any(|(step, _)| *step == Step::FlushConntrack)
    );
    assert!(root.join("route-switch").exists());
    assert!(machine.tick().complete);
    assert!(!root.join("route-switch").exists());
    // The failed flush also held back forwarding restoration. Let its
    // independent recovery finish before checking the steady-state tick.
    for _ in 0..4 {
        assert!(machine.tick().complete);
    }
    kernel.clear_history();
    assert!(machine.tick().complete);
    assert!(
        !kernel
            .history()
            .iter()
            .any(|(step, _)| *step == Step::FlushConntrack)
    );
    fs::remove_dir_all(root).unwrap();
}

/// L52b uses a configured UP exit whose family has no desired exit default.
#[test]
fn f5_l52b_ipv6_prefix_on_owned_up_exit_closes_and_recovers() {
    let root = root("l52b-owned-v6");
    let (kernel, config) = healthy(&root);
    let mut machine = machine(&kernel, config);
    let baseline = kernel.model();
    let extra = RouteKey {
        family: Family::V6,
        entry: scupper_core::parse::parse_ip_route(
            r#"[{"dst":"2001:db8:52::/64","dev":"ex-ch1","table":"main","scope":"link"}]"#,
        )
        .unwrap()
        .remove(0),
    };
    assert_eq!(baseline.links["ex-ch1"].ours, Known::Value(true));
    assert_eq!(baseline.links["ex-ch1"].up, Known::Value(true));
    kernel.mutate(|model| model.extra_routes = Known::Value(vec![extra.clone()]));
    kernel.clear_history();
    for _ in 0..8 {
        assert!(machine.tick().complete);
    }
    let steps: Vec<_> = kernel.history().into_iter().map(|(step, _)| step).collect();
    assert!(steps.contains(&Step::ForwardingOff));
    assert!(steps.contains(&Step::FlushConntrack));
    assert!(steps.contains(&Step::RouteDelete { route: extra }));
    let end = kernel.model();
    assert_eq!(end.forwarding_v4, Known::Value(1));
    assert_eq!(end.extra_routes, Known::Value(vec![]));
    assert_eq!(end.default_v4, baseline.default_v4);
    assert_eq!(end.default_v6, baseline.default_v6);
    fs::remove_dir_all(root).unwrap();
}
